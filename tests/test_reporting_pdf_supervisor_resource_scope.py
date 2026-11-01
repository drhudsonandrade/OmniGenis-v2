"""Supervisor resource acceptance with real FDs and controlled kernel observations."""
from contextlib import ExitStack, contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import unittest
from unittest.mock import patch

from reporting import _pdf_fixed_inspection_worker as worker
from reporting import pdf_inspection_result_frame as frame
from reporting import pdf_request_descriptor as descriptor
from reporting import pdf_supervised_inspection as supervisor
from reporting.page_checkpoints import _json_bytes
from tests import test_reporting_pdf_fixed_inspection_worker as worker_tests
from tests import test_reporting_pdf_native_transport as native_tests
from tests import test_reporting_pdf_supervised_inspection as supervisor_tests


ROOT = Path(__file__).resolve().parents[1]
SELECTOR = 'OMNIGENIS_PDF_FIXED_KERNEL_ADMISSION_V1'


class SupervisorResourceScopeTests(unittest.TestCase):
    """Exercise parent acceptance; fixture observations do not qualify a host."""

    def setUp(self):
        """Compose existing typed fixtures without inheriting their test methods."""
        self.legacy = supervisor_tests.SupervisedInspectionTests()
        self.legacy.setUp()
        self.native = native_tests.PdfNativeTransportTests()
        self.native.setUp()

    @contextmanager
    def case(self, native=False):
        """Create a real sealed request and valid result before OS observations change."""
        if native:
            with self.native.request() as (fd, expected, args, _):
                context = self.native.context(expected, args)
                result = self.native.controlled_result()
                encoded = self.native.encode_result(result)
                yield fd, _json_bytes(context), supervisor.NATIVE_PROFILE_SHA256, encoded, result.to_bytes()
        else:
            with self.legacy.h.request() as (fd, expected, args, _):
                context = self.legacy.fixture.context(expected, args)
                encoded, result = self.legacy.synthetic_frame(context)
                yield fd, _json_bytes(context), supervisor.PROFILE_SHA256, encoded, result

    @contextmanager
    def kernel(self, configure=None):
        """Retain strict metadata reads while allowing the fixed child's DEVNULL open."""
        fixture = worker_tests.KernelObservationFixture(worker)
        original_open = fixture._open
        def open_observation(path, flags, mode=0o777, *, dir_fd=None):
            """Allow only subprocess's declared external read/write null device."""
            if os.fsdecode(path) == '/dev/null' and flags == os.O_RDWR and dir_fd is None:
                return fixture.real_open(path, flags, mode)
            return original_open(path, flags, mode, dir_fd=dir_fd)
        fixture._open = open_observation
        if configure is not None:
            configure(fixture)
        with fixture:
            yield fixture

    def invoke(self, fd, context, profile):
        """Call the existing public boundary with fixed independent expectations."""
        return supervisor.execute_supervised_pdf_inspection(fd, expected_context=context,
            expected_supervisor_profile_sha256=profile)

    def cpu(self, fixture, usage):
        """Set independent absolute usage; the declared baseline starts at seventeen."""
        fixture.edit(fixture.CGROUP + '/cpu.stat', f'usage_usec {usage}\n'.encode('ascii'))

    def assert_released(self, fixture):
        """Assert production released metadata descriptors before fixture rescue."""
        self.assertFalse(fixture.active)
        self.assertEqual(sorted(fixture.opened), sorted(fixture.closed))

    def assert_reaped(self, launches):
        """Prove production reap without poll or wait performing it for the test."""
        self.assertEqual(len(launches), 1)
        process = launches[0][2]
        self.assertIsNotNone(process.returncode)
        with self.assertRaises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)

    def writer(self, encoded):
        """Return a bounded child that consumes context and writes the exact valid frame."""
        return ('import sys; sys.stdin.buffer.read(); '
                f'sys.stdout.buffer.write(bytes.fromhex({encoded.hex()!r})); sys.stdout.buffer.flush()')

    def test_cpu_exhaustion_during_result_decode_refuses_both_families(self):
        """Withhold a valid result when parent decoding reaches the original CPU allowance."""
        decode = frame.decode_pdf_inspection_result_frame
        for native in (False, True):
            with self.subTest(native=native), self.case(native) as (fd, context, profile, encoded, expected):
                with self.kernel() as fixture, self.legacy.child(self.writer(encoded)) as launches:
                    def exhaust(packet, **options):
                        """Cross the independent allowance only after successful real decoding."""
                        result = decode(packet, **options)
                        self.assertEqual(result, expected)
                        self.assert_reaped(launches)
                        self.cpu(fixture, 300_000_017)
                        return result
                    with patch.object(frame, 'decode_pdf_inspection_result_frame', side_effect=exhaust):
                        with self.assertRaises(supervisor.PdfSupervisedInspectionError):
                            self.invoke(fd, context, profile)
                    self.assert_reaped(launches)
                    self.assert_released(fixture)


    def test_below_limit_preserves_complete_result_and_borrowed_request(self):
        """Accept the exact below-boundary result without consuming or closing borrowed input."""
        decode = frame.decode_pdf_inspection_result_frame
        for native in (False, True):
            with self.subTest(native=native), self.case(native) as (fd, context, profile, encoded, expected):
                original = os.fstat(fd)
                packet = os.pread(fd, original.st_size, 0)
                os.lseek(fd, 7, os.SEEK_SET)
                with self.kernel() as fixture, self.legacy.child(self.writer(encoded)) as launches:
                    def below(packet, **options):
                        """Leave exactly one microsecond below the declared exclusive allowance."""
                        result = decode(packet, **options)
                        self.cpu(fixture, 300_000_016)
                        return result
                    with patch.object(frame, 'decode_pdf_inspection_result_frame', side_effect=below):
                        self.assertEqual(self.invoke(fd, context, profile), expected)
                    self.assert_reaped(launches)
                    self.assertEqual(launches[0][2].returncode, 0)
                    self.assertTrue(launches[0][2].stdin.closed and launches[0][2].stdout.closed)
                    self.assertTrue(fixture.opened)
                    self.assert_released(fixture)
                    self.assertEqual(os.pread(fd, original.st_size, 0), packet)
                    self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), 7)
                    self.assertEqual((os.fstat(fd).st_dev, os.fstat(fd).st_ino),
                                     (original.st_dev, original.st_ino))
                    self.assertFalse(os.get_inheritable(fd))
                    for borrowed in (fd, fixture.request_fd, 2):
                        fixture.real_fstat(borrowed)

    def test_request_capture_exhaustion_prevents_launch(self):
        """Count capture CPU from parent admission and refuse before constructing any child."""
        read = descriptor.read_sealed_pdf_request
        for native in (False, True):
            with self.subTest(native=native), self.case(native) as (fd, context, profile, encoded, _):
                with self.kernel() as fixture, self.legacy.child(self.writer(encoded)) as launches:
                    captured = []
                    def exhaust(*args, **options):
                        """Retain real sealed capture and cross the absolute budget afterward."""
                        result = read(*args, **options)
                        captured.append(True)
                        self.cpu(fixture, 300_000_017)
                        return result
                    with patch.object(descriptor, 'read_sealed_pdf_request', side_effect=exhaust):
                        with self.assertRaises(supervisor.PdfSupervisedInspectionError):
                            self.invoke(fd, context, profile)
                    self.assertEqual(captured, [True])
                    self.assertEqual(launches, [])
                    self.assert_released(fixture)
                    fixture.real_fstat(fd)

    def test_original_cpu_baseline_spans_capture_and_decode(self):
        """Several individually small stage deltas cannot reset the invocation allowance."""
        read, decode = descriptor.read_sealed_pdf_request, frame.decode_pdf_inspection_result_frame
        for native in (False, True):
            with self.subTest(native=native), self.case(native) as (fd, context, profile, encoded, _):
                with self.kernel() as fixture, self.legacy.child(self.writer(encoded)) as launches:
                    stages = []
                    def capture(*args, **options):
                        """Spend two hundred CPU seconds during real request capture."""
                        result = read(*args, **options)
                        self.cpu(fixture, 200_000_017)
                        stages.append('capture')
                        return result
                    def finish(*args, **options):
                        """Spend the remaining hundred seconds after a valid decoded frame."""
                        result = decode(*args, **options)
                        self.cpu(fixture, 300_000_017)
                        stages.append('decode')
                        return result
                    with patch.object(descriptor, 'read_sealed_pdf_request', side_effect=capture), \
                         patch.object(frame, 'decode_pdf_inspection_result_frame', side_effect=finish):
                        with self.assertRaises(supervisor.PdfSupervisedInspectionError):
                            self.invoke(fd, context, profile)
                    self.assertEqual(stages, ['capture', 'decode'])
                    self.assert_reaped(launches)
                    self.assert_released(fixture)

    def test_resource_exhaustion_during_exchange_reaps_live_child(self):
        """An observed budget failure retires a still-live child before any fixture rescue."""
        with self.case() as (fd, context, profile, encoded, _):
            launches, injected = [], []
            def configure(fixture):
                """Change CPU only after reading actual stdout from the owned real child."""
                read = fixture._read
                def observe(slot, count):
                    """Keep all kernel and pipe reads real and inject only at the chosen stream."""
                    result = read(slot, count)
                    if (launches and not injected and result
                            and slot == launches[0][2].stdout.fileno()):
                        self.cpu(fixture, 300_000_017)
                        injected.append(True)
                    return result
                fixture._read = observe
            script = ('import os,sys,time;sys.stdin.buffer.read();'
                      f'data=bytes.fromhex({encoded.hex()!r});os.write(1,data[:1]);'
                      'time.sleep(5);sys.stdout.buffer.write(data[1:]);sys.stdout.buffer.flush()')
            with self.kernel(configure) as fixture, self.legacy.child(script) as launches:
                with self.assertRaises(supervisor.PdfSupervisedInspectionError):
                    self.invoke(fd, context, profile)
                self.assertEqual(injected, [True])
                self.assert_reaped(launches)
                self.assertEqual(launches[0][2].returncode, -signal.SIGKILL)
                self.assertTrue(launches[0][2].stdin.closed and launches[0][2].stdout.closed)
                self.assert_released(fixture)

    def test_resource_events_and_regression_after_decode_refuse(self):
        """Parent acceptance inherits memory, PID and CPU-continuity refusals after worker exit."""
        decode = frame.decode_pdf_inspection_result_frame
        cases = [('memory.events', worker_tests.KernelObservationFixture.MEMORY_EVENTS.replace(
                     b'oom_kill 0\n', b'oom_kill 1\n')),
                 ('pids.events', b'max 1\n'), ('cpu.stat', b'usage_usec 16\n')]
        for name, payload in cases:
            with self.subTest(record=name), self.case() as (fd, context, profile, encoded, _):
                with self.kernel() as fixture, self.legacy.child(self.writer(encoded)) as launches:
                    changed = []
                    def mutate(*args, **options):
                        """Alter an independently named resource record after genuine decoding."""
                        result = decode(*args, **options)
                        fixture.edit(fixture.CGROUP + '/' + name, payload)
                        changed.append(True)
                        return result
                    with patch.object(frame, 'decode_pdf_inspection_result_frame', side_effect=mutate):
                        with self.assertRaises(supervisor.PdfSupervisedInspectionError):
                            self.invoke(fd, context, profile)
                    self.assertEqual(changed, [True])
                    self.assert_reaped(launches)
                    self.assert_released(fixture)

    def test_late_observation_read_failure_withholds_result(self):
        """A failed CPU observation cannot inherit success from the valid earlier frame."""
        decode = frame.decode_pdf_inspection_result_frame
        with self.case() as (fd, context, profile, encoded, _):
            with self.kernel() as fixture, self.legacy.child(self.writer(encoded)) as launches:
                path = fixture.CGROUP + '/cpu.stat'
                def fail_next(*args, **options):
                    """Inject at the next precise CPU read, never the subprocess error pipe."""
                    result = decode(*args, **options)
                    occurrence = fixture.counts[('read', path)] + 1
                    fixture.fail_at = 'read', path, occurrence, OSError
                    return result
                with patch.object(frame, 'decode_pdf_inspection_result_frame', side_effect=fail_next):
                    with self.assertRaises(supervisor.PdfSupervisedInspectionError):
                        self.invoke(fd, context, profile)
                self.assertIsNotNone(fixture.fail_at)
                self.assertEqual(fixture.counts[('read', path)], fixture.fail_at[2])
                self.assert_reaped(launches)
                self.assert_released(fixture)

    def test_init_parent_is_supervisor_only_role(self):
        """Permit an otherwise protected parent-of-one controller while the worker still refuses."""
        with self.case() as (fd, context, profile, encoded, expected):
            with self.kernel() as fixture, self.legacy.child(self.writer(encoded)) as launches:
                fixture.parent = 1
                fixture.edit(fixture.PROC + '/status', fixture.STATUS.replace(b'PPid:\t7200\n', b'PPid:\t1\n'))
                with self.assertRaises(ValueError):
                    worker._open_kernel_admission(fixture.request_fd)
                self.assert_released(fixture)
                self.assertEqual(self.invoke(fd, context, profile), expected)
                self.assert_reaped(launches)
                self.assert_released(fixture)

    def test_invalid_credentials_refuse_before_launch(self):
        """The new supervisor role still rejects root, zero parent, unstable IDs and capabilities."""
        for invalid in ('root', 'root_group', 'parent_zero', 'unstable_ids', 'capability'):
            with self.subTest(invalid=invalid), self.case() as (fd, context, profile, encoded, _):
                with self.kernel() as fixture, self.legacy.child(self.writer(encoded)) as launches:
                    if invalid == 'root':
                        fixture.uids = (0, 0, 0)
                    elif invalid == 'root_group':
                        fixture.gids = (0, 0, 0)
                    elif invalid == 'parent_zero':
                        fixture.parent = 0
                        fixture.edit(fixture.PROC + '/status', fixture.STATUS.replace(b'PPid:\t7200\n', b'PPid:\t0\n'))
                    elif invalid == 'unstable_ids':
                        fixture.gids = (1000, 1001, 1000)
                    else:
                        fixture.edit(fixture.PROC + '/status', fixture.STATUS.replace(
                            b'CapEff:\t0000000000000000', b'CapEff:\t0000000000000001'))
                    with self.assertRaises(supervisor.PdfSupervisedInspectionError):
                        self.invoke(fd, context, profile)
                    self.assertEqual(launches, [])
                    self.assert_released(fixture)

    def test_absent_selector_performs_no_scope_observations(self):
        """An unselected resource policy preserves complete legacy and native transport."""
        for native in (False, True):
            with self.subTest(native=native), self.case(native) as (fd, context, profile, encoded, expected):
                with self.kernel() as fixture, self.legacy.child(self.writer(encoded)) as launches:
                    os.environ.pop(SELECTOR)
                    self.assertEqual(self.invoke(fd, context, profile), expected)
                    self.assertFalse(any(path == fixture.CGROUP or path.startswith(fixture.CGROUP + '/')
                                         for _, path in fixture.opened))
                    self.assert_reaped(launches)
                    self.assert_released(fixture)

    def test_profile_and_manifest_pin_scoped_nonclaims(self):
        """Declare the parent interval separately while preserving worker and wire identities."""
        profile = supervisor.supervisor_resource_scope_profile()
        self.assertEqual(profile['minimum_parent_pid'], 1)
        self.assertEqual(profile['worker_minimum_parent_pid_unchanged'], 2)
        self.assertEqual(profile['selector'], SELECTOR)
        self.assertEqual(profile['baseline'], 'ONE_SUCCESSFUL_SUPERVISOR_ADMISSION_BEFORE_CONTEXT')
        self.assertEqual(profile['interval_end'], 'AFTER_REQUEST_DUPLICATE_CLOSE_BEFORE_OBSERVATION_FD_CLOSE')
        self.assertEqual(profile['kernel_observation_policy_sha256'],
                         '4684c54f07c27aedd39113323d3fb9e0e8297d5958025f015d04031080006d01')
        self.assertEqual(supervisor.PROFILE_SHA256,
                         'd020c676e11207bdfd007dcd90488888bcebd6b1ee1285faa514b116d7c41095')
        self.assertEqual(supervisor.NATIVE_PROFILE_SHA256,
                         '7ac5ff687f95dc3f4b286b8d7b1209bcfc2296f1a7fc0df0cd0d82aef6d82a46')
        self.assertEqual(supervisor.RESOURCE_SCOPE_PROFILE_SHA256,
                         '850caba50614a648dfeaa0eb6e2511026c1f2d00d90c9bccfb7f76e2cee2b402')
        for name in ('continuous_enforcement', 'job_cgroup_exclusivity_verified',
                     'aggregate_job_resources_qualified', 'hard_job_deadline_qualified',
                     'arbitrary_descendant_cleanup_qualified', 'host_authenticated',
                     'default_pipeline_activated', 'service_installed', 'release_authorized'):
            self.assertIs(profile[name], False)
        manifest = json.loads((ROOT / 'reporting/pdf-supervisor-resource-scope.v1.json').read_text())
        self.assertEqual(manifest['profile'], profile)
        self.assertEqual(manifest['profile_sha256'], sha256(_json_bytes(profile)).hexdigest())
        self.assertEqual(set(manifest['source_sha256']),
                         {'reporting/_pdf_fixed_inspection_worker.py', 'reporting/pdf_supervised_inspection.py'})
        for name, digest in manifest['source_sha256'].items():
            self.assertEqual(sha256((ROOT / name).read_bytes()).hexdigest(), digest)
        self.assertTrue(manifest['observation_limitations'])

    def test_profile_or_selector_drift_prevents_result(self):
        """Neither initial invalid selection nor a changed final policy can accept a frame."""
        decode = frame.decode_pdf_inspection_result_frame
        for change in ('profile_before', 'selector_before', 'selector_after', 'kernel_pin_after'):
            with self.subTest(change=change), self.case() as (fd, context, profile, encoded, _):
                with self.kernel() as fixture, self.legacy.child(self.writer(encoded)) as launches, ExitStack() as stack:
                    if change == 'profile_before':
                        stack.enter_context(patch.object(supervisor, 'RESOURCE_SCOPE_PROFILE_SHA256', '0' * 64))
                    elif change == 'selector_before':
                        os.environ[SELECTOR] = '0'
                    else:
                        def drift(*args, **options):
                            """Change a selected policy only after producing a valid result."""
                            result = decode(*args, **options)
                            if change == 'selector_after':
                                os.environ.pop(SELECTOR)
                            else:
                                stack.enter_context(patch.object(worker, 'KERNEL_ADMISSION_PROFILE_SHA256', '0' * 64))
                            return result
                        stack.enter_context(patch.object(frame, 'decode_pdf_inspection_result_frame', side_effect=drift))
                    with self.assertRaises(supervisor.PdfSupervisedInspectionError):
                        self.invoke(fd, context, profile)
                    if change.endswith('_before'):
                        self.assertEqual(launches, [])
                    else:
                        self.assert_reaped(launches)
                    self.assert_released(fixture)

    def test_guard_close_uncertainty_withholds_valid_result(self):
        """A bounded retry may release an FD but cannot erase uncertain cleanup acceptance."""
        injected = []
        def configure(fixture):
            """Fail once only when closing the retained cgroup directory."""
            close = fixture._close
            def uncertain(fd):
                """Preserve ownership on the first failed close and allow finite cleanup."""
                if fixture.active.get(fd) == fixture.CGROUP and not injected:
                    injected.append(True)
                    raise OSError('controlled close fault')
                return close(fd)
            fixture._close = uncertain
        with self.case() as (fd, context, profile, encoded, _):
            with self.kernel(configure) as fixture, self.legacy.child(self.writer(encoded)) as launches:
                with self.assertRaises(supervisor.PdfSupervisedInspectionError):
                    self.invoke(fd, context, profile)
                self.assertEqual(injected, [True])
                self.assert_reaped(launches)
                self.assertEqual(launches[0][2].returncode, 0)
                self.assert_released(fixture)

    def test_last_checkpoint_follows_owned_request_close(self):
        """Include CPU spent closing the request duplicate while preserving the original FD."""
        close = descriptor._close_owned
        with self.case() as (fd, context, profile, encoded, _):
            with self.kernel() as fixture, self.legacy.child(self.writer(encoded)) as launches:
                injected = []
                def close_then_exhaust(slot, identity):
                    """Inject only after the supervisor's dispatched duplicate is really closed."""
                    close(slot, identity)
                    if launches and slot == launches[0][1]['pass_fds'][0]:
                        injected.append(True)
                        self.cpu(fixture, 300_000_017)
                with patch.object(descriptor, '_close_owned', side_effect=close_then_exhaust):
                    with self.assertRaises(supervisor.PdfSupervisedInspectionError):
                        self.invoke(fd, context, profile)
                self.assertEqual(injected, [True])
                self.assert_reaped(launches)
                self.assert_released(fixture)
                fixture.real_fstat(fd)

    def test_replaced_observation_fd_is_not_closed(self):
        """Refuse descriptor reuse without closing the replacement owned by the caller."""
        decode = frame.decode_pdf_inspection_result_frame
        with self.case() as (fd, context, profile, encoded, _):
            with self.kernel() as fixture, self.legacy.child(self.writer(encoded)) as launches:
                replaced = []
                def replace_slot(*args, **options):
                    """Replace one retained cgroup slot after the real child has finished."""
                    result = decode(*args, **options)
                    slots = [slot for slot, path in fixture.active.items() if path == fixture.CGROUP]
                    self.assertEqual(len(slots), 1)
                    os.dup2(fixture.request_fd, slots[0], inheritable=False)
                    replaced.append(slots[0])
                    return result
                with patch.object(frame, 'decode_pdf_inspection_result_frame', side_effect=replace_slot):
                    with self.assertRaises(supervisor.PdfSupervisedInspectionError):
                        self.invoke(fd, context, profile)
                self.assert_reaped(launches)
                self.assertEqual(len(replaced), 1)
                self.assertEqual(set(fixture.active), set(replaced))
                self.assertEqual(fixture.real_fstat(replaced[0]).st_ino,
                                 fixture.real_fstat(fixture.request_fd).st_ino)
                os.close(replaced[0])  # The test owns this replacement; the guard does not.
                self.assert_released(fixture)
                fixture.real_fstat(fd)

    def test_interrupted_acquisition_and_capture_release_observations(self):
        """Interruptions before child launch release every acquired observation descriptor."""
        read = descriptor.read_sealed_pdf_request
        for phase in ('admission', 'capture'):
            for failure in (KeyboardInterrupt, MemoryError):
                with self.subTest(phase=phase, failure=failure), self.case() as (fd, context, profile, encoded, _):
                    with self.kernel() as fixture, self.legacy.child(self.writer(encoded)) as launches, ExitStack() as stack:
                        if phase == 'admission':
                            fixture.fail_at = 'read', fixture.PROC + '/status', 1, failure
                        else:
                            def interrupt(*args, **options):
                                """Interrupt only after the normal bounded capture has completed."""
                                read(*args, **options)
                                raise failure('controlled interruption')
                            stack.enter_context(patch.object(descriptor, 'read_sealed_pdf_request', side_effect=interrupt))
                        expected = KeyboardInterrupt if failure is KeyboardInterrupt else supervisor.PdfSupervisedInspectionError
                        with self.assertRaises(expected):
                            self.invoke(fd, context, profile)
                        self.assertTrue(fixture.opened)
                        self.assertEqual(launches, [])
                        self.assert_released(fixture)
                        fixture.real_fstat(fd)
