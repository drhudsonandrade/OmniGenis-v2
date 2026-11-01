"""Bounded kernel counters with dotted names and unchanged resource refusals."""
from copy import deepcopy
import os
import unittest

from reporting import _pdf_fixed_inspection_worker as worker
from tests.test_reporting_pdf_fixed_inspection_worker import KernelObservationFixture
from tests import test_reporting_pdf_supervisor_resource_scope as scope_tests


CPU_STAT = (
    b'usage_usec 17\nuser_usec 10\nsystem_usec 7\n'
    b'core_sched.force_idle_usec 0\nnr_periods 0\nnr_throttled 0\n'
    b'throttled_usec 0\nnr_bursts 0\nburst_usec 0\n'
)


class KernelEventKeyTests(unittest.TestCase):
    """Use independent records and real guard behavior, without native qualification."""

    def test_namespaced_cpu_counter_does_not_prevent_admission(self):
        """A valid kernel extension must not hide the required usage counter."""
        try:
            counters = worker._kernel_events(CPU_STAT, ('usage_usec',))
        except ValueError as error:
            self.fail(f'Valid namespaced CPU counter was rejected: {error}')
        self.assertEqual(counters, {
            'usage_usec': 17, 'user_usec': 10, 'system_usec': 7,
            'core_sched.force_idle_usec': 0, 'nr_periods': 0,
            'nr_throttled': 0, 'throttled_usec': 0, 'nr_bursts': 0,
            'burst_usec': 0,
        })

    def test_malformed_key_segments_are_refused(self):
        """Dotted names retain nonempty ASCII identifier segments and exact spelling."""
        for key in (b'', b'.', b'.counter', b'counter.', b'core..counter',
                    b'9counter', b'core.9counter', b'core.counter-name',
                    b'core/counter', b'core:counter', b'core\tcounter',
                    b'core counter', b'core.\x00counter', b'core.\xffcounter',
                    'core.c\u00f6unter'.encode('utf-8')):
            with self.subTest(key=key), self.assertRaises(ValueError):
                worker._kernel_events(b'usage_usec 17\n' + key + b' 0\n', ('usage_usec',))

    def test_duplicates_and_namespaced_substitutes_for_required_keys_are_refused(self):
        """A distinct dotted key cannot supply or overwrite an exact required field."""
        records = (
            CPU_STAT + b'core_sched.force_idle_usec 1\n',
            CPU_STAT + b'usage_usec 18\n',
            b'usage_usec.extra 17\ncore_sched.force_idle_usec 0\n',
            b'core_sched.usage_usec 17\n',
        )
        for record in records:
            with self.subTest(record=record), self.assertRaises(ValueError):
                worker._kernel_events(record, ('usage_usec',))

    def test_invalid_values_on_optional_dotted_keys_are_refused(self):
        """Optional counters receive the same unsigned canonical validation as required ones."""
        for value in (b'', b'-1', b'+1', b'00', b'01', b'1.0', b' 1', b'1 ',
                      b'1\r', b'1\t', b'18446744073709551616', b'9' * 21):
            with self.subTest(value=value), self.assertRaises(ValueError):
                worker._kernel_events(b'usage_usec 17\ncore_sched.force_idle_usec ' + value + b'\n',
                                      ('usage_usec',))

    def test_worker_guard_keeps_cpu_baseline_and_refusal_with_dotted_counter(self):
        """The admitted extension leaves the immutable baseline and exact allowance intact."""
        with KernelObservationFixture(worker) as fixture:
            path = fixture.CGROUP + '/cpu.stat'
            fixture.edit(path, CPU_STAT)
            try:
                guard = worker._open_kernel_admission(fixture.request_fd)
            except ValueError as error:
                self.fail(f'Valid kernel record prevented guard admission: {error}')
            try:
                self.assertEqual((guard.cpu_baseline_usec, guard.cpu_usage_usec), (17, 17))
                fixture.edit(path, CPU_STAT.replace(b'usage_usec 17\n', b'usage_usec 300000016\n'))
                guard.recheck()
                self.assertEqual((guard.cpu_baseline_usec, guard.cpu_usage_usec), (17, 300000016))
                fixture.edit(path, CPU_STAT.replace(b'usage_usec 17\n', b'usage_usec 300000017\n'))
                with self.assertRaises(ValueError):
                    guard.recheck()
                self.assertEqual((guard.cpu_baseline_usec, guard.cpu_usage_usec), (17, 300000016))
            finally:
                self.assertTrue(guard.close())
            self.assertEqual(fixture.active, {})
            fixture.real_fstat(fixture.request_fd)

    def test_dotted_event_extensions_preserve_continuity_and_atomic_commit(self):
        """Unknown names stay exact and observed; rejected resource snapshots cannot commit."""
        for filename, initial in (('memory.events', b'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n'),
                                  ('pids.events', b'max 0\n')):
            with self.subTest(filename=filename), KernelObservationFixture(worker) as fixture:
                path = fixture.CGROUP + '/' + filename
                fixture.edit(path, initial + b'extension.counter 5\n')
                try:
                    guard = worker._open_kernel_admission(fixture.request_fd)
                except ValueError as error:
                    self.fail(f'Valid namespaced event was rejected: {error}')
                try:
                    fixture.edit(path, initial + b'extension.counter 6\n')
                    guard.recheck()
                    accepted = deepcopy(guard.event_counters)
                    for invalid in (initial + b'extension.counter 5\n',
                                    initial + b'extension.other 7\n',
                                    initial.replace(b'max 0\n', b'max 1\n') + b'extension.counter 7\n',
                                    initial + b'extension.counter 7\nextension.counter 8\n'):
                        fixture.edit(path, invalid)
                        fixture.edit(fixture.CGROUP + '/cpu.stat', b'usage_usec 18\n')
                        with self.assertRaises(ValueError):
                            guard.recheck()
                        self.assertEqual(guard.event_counters, accepted)
                        self.assertEqual((guard.cpu_baseline_usec, guard.cpu_usage_usec), (17, 17))
                finally:
                    self.assertTrue(guard.close())
                self.assertEqual(fixture.active, {})
                fixture.real_fstat(fixture.request_fd)

    def test_public_supervisor_accepts_dotted_cpu_fields_in_both_wire_families(self):
        """A valid frame reaches the caller and owned FDs close despite the kernel extension."""
        harness = scope_tests.SupervisorResourceScopeTests()
        harness.setUp()
        def configure(fixture):
            """Supply an independently declared complete CPU observation before admission."""
            fixture.edit(fixture.CGROUP + '/cpu.stat', CPU_STAT)
        for native in (False, True):
            with self.subTest(native=native), harness.case(native) as (fd, context, profile, encoded, expected):
                before = os.fstat(fd)
                position = os.lseek(fd, 0, os.SEEK_CUR)
                with harness.kernel(configure) as fixture, harness.legacy.child(harness.writer(encoded)) as launches:
                    try:
                        result = harness.invoke(fd, context, profile)
                    except Exception as error:
                        self.fail(f'Valid selected inspection was rejected: {error}')
                    self.assertEqual(result, expected)
                    harness.assert_reaped(launches)
                    harness.assert_released(fixture)
                # A legitimate read can update atime; identity and offset must remain stable.
                after = os.fstat(fd)
                self.assertEqual((after.st_dev, after.st_ino, after.st_mode, after.st_size),
                                 (before.st_dev, before.st_ino, before.st_mode, before.st_size))
                self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), position)


if __name__ == '__main__':
    unittest.main()
