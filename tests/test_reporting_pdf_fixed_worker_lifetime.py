"""Real direct-worker timer regressions; every signal mutation stays in a child."""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest

from reporting import _pdf_fixed_inspection_worker as worker
from reporting.page_checkpoints import _json_bytes
from tests import test_reporting_pdf_fixed_inspection_worker as prior


ROOT = Path(__file__).resolve().parents[1]


def lifetime_child(request_fd: int, report_fd: int, mode: str, inherited: str) -> int:
    """Exercise the real entrypoint with shortened real syscalls in a disposable child."""
    real_timer = signal.setitimer
    real_gettimer = signal.getitimer
    real_signal = signal.signal
    real_mask = signal.pthread_sigmask

    def report(event, **values):
        """Write bounded test observations to a separate anonymous file, never stdout."""
        os.write(report_fd, _json_bytes({'event': event, **values}) + b'\n')

    if inherited in ('ignored', 'both'):
        real_signal(signal.SIGALRM, signal.SIG_IGN)
    if inherited in ('blocked', 'both'):
        real_mask(signal.SIG_BLOCK, {signal.SIGALRM})
    if mode == 'existing_timer':
        real_timer(signal.ITIMER_REAL, 5)
    if mode.startswith('bound_'):
        worker.WORKER_WALL_SECONDS = {'bound_bool': True, 'bound_float': 300.0,
                                      'bound_larger': 301, 'bound_zero': 0}[mode]
    if mode == 'profile_pin':
        worker.WORKER_LIFETIME_PROFILE_SHA256 = '0' * 64
    if mode == 'profile_body':
        worker.worker_lifetime_profile = lambda: {'unexpected': True}
    if mode == 'structured_bound':
        worker.structured.ACCEPTANCE_NS = 301_000_000_000
    if mode == 'native_bound':
        worker.native.ACCEPTANCE_NS = 301_000_000_000

    def disposition(number, action):
        """Keep actual disposition changes and inject only the requested syscall failure."""
        report('disposition', number=int(number), default=action == signal.SIG_DFL)
        if mode == 'fail_disposition':
            raise OSError('test disposition failure')
        return real_signal(number, action)

    def mask(how, values):
        """Keep actual signal-mask changes and expose their ordering."""
        report('mask', how=int(how), signals=sorted(int(item) for item in values))
        if mode == 'fail_mask':
            raise OSError('test mask failure')
        return real_mask(how, values)

    def gettimer(which):
        """Observe the real preexisting timer unless this syscall is the fault target."""
        if mode == 'fail_observation':
            raise OSError('test observation failure')
        return real_gettimer(which)

    def arm(which, seconds, interval=0.0):
        """Record the exact production interval and shorten only this disposable timer."""
        report('arm', which=int(which), seconds=seconds, interval=interval)
        if mode == 'fail_arm':
            raise OSError('test timer failure')
        if mode == 'negative_control':
            return real_gettimer(which)
        shortened = 5.0 if mode == 'complete' else 0.4
        return real_timer(which, shortened if seconds else 0, interval)

    signal.signal = disposition
    signal.pthread_sigmask = mask
    signal.getitimer = gettimer
    signal.setitimer = arm
    original_admission = worker._open_kernel_admission
    original_read = worker._read_pipe
    original_write = worker._write_frame

    def read():
        """Expose readiness immediately before the production blocking context read."""
        report('context')
        return original_read()

    def admission(fd):
        """Observe ordering and supply cleanup only for isolated lifecycle-stage cases."""
        report('admission')
        if mode in ('output', 'cleanup', 'complete'):
            return SimpleNamespace(recheck=lambda: report('recheck'), close=close)
        return original_admission(fd)

    def close():
        """Keep a real pending alarm visible during owned-admission cleanup."""
        report('cleanup', remaining=real_gettimer(signal.ITIMER_REAL)[0])
        if mode == 'cleanup':
            signal.pause()
        return True

    def inspect(*args, **kwargs):
        """Replace unrelated native inspection while retaining the real lifecycle path."""
        report('work', remaining=real_gettimer(signal.ITIMER_REAL)[0])
        return SimpleNamespace(to_bytes=lambda: b'original')

    def encode(*args, **kwargs):
        """Produce finite test bytes without replacing production pipe handling."""
        report('encode', remaining=real_gettimer(signal.ITIMER_REAL)[0])
        return b'x' * 65536 if mode == 'output' else b'frame'

    def write(data, selected_native=False):
        """Expose readiness immediately before the production blocking frame write."""
        report('write', remaining=real_gettimer(signal.ITIMER_REAL)[0])
        return original_write(data, selected_native)

    worker._open_kernel_admission = admission
    worker._read_pipe = read
    worker._write_frame = write
    if mode in ('output', 'cleanup', 'complete'):
        worker.sealed.execute_sealed_pdf_inspection_job = inspect
        worker.frame.encode_pdf_inspection_result_frame = encode
        worker.frame.decode_pdf_inspection_result_frame = lambda *args, **kwargs: b'original'
    sys.argv = ['worker', str(request_fd), str(os.getppid())]
    status = worker._entrypoint()
    parent_signal = ctypes.c_int()
    library = ctypes.CDLL(None)
    if library.prctl(2, ctypes.byref(parent_signal), 0, 0, 0) != 0:
        raise RuntimeError('test parent-death observation failed')
    report('return', status=status, remaining=real_gettimer(signal.ITIMER_REAL)[0],
           parent_signal=parent_signal.value)
    return status


class FixedWorkerLifetimeTests(unittest.TestCase):
    """Observe termination before fixture rescue, with a live parent and real pipes."""

    def setUp(self):
        """Reuse the existing independently bound sealed request fixture."""
        self.fixture = prior.FixedInspectionWorkerTests()
        self.fixture.setUp()

    def probe(self, mode='read', inherited='default'):
        """Run the real worker entrypoint, keeping context or output blocked as selected."""
        with self.fixture.h.request() as (fd, expected, args, _), \
                tempfile.TemporaryFile() as observations:
            code = ('import sys;sys.path.insert(0,' + repr(str(ROOT)) + ');'
                    'from tests.test_reporting_pdf_fixed_worker_lifetime import lifetime_child;'
                    'raise SystemExit(lifetime_child(' + repr(fd) + ','
                    + repr(observations.fileno()) + ',' + repr(mode) + ','
                    + repr(inherited) + '))')
            process = subprocess.Popen([sys.executable, '-I', '-B', '-c', code],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                pass_fds=(fd, observations.fileno()), cwd=ROOT, pipesize=4096,
                env={'PATH': os.defpath, 'LANG': 'C.UTF-8'})
            try:
                if mode in ('output', 'cleanup', 'complete'):
                    context = _json_bytes(self.fixture.context(expected, args))
                    process.stdin.write(context)
                    process.stdin.close()
                try:
                    process.wait(timeout=3)
                    observed_exit = True
                except subprocess.TimeoutExpired:
                    observed_exit = False
                # Capture this before rescue: a fixture SIGKILL is never timer evidence.
                returncode = process.returncode
                events = [json.loads(line) for line in
                          os.pread(observations.fileno(), 16384, 0).splitlines()]
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=3)
                if not process.stdin.closed:
                    process.stdin.close()
                output = process.stdout.read(65537)
                errors = process.stderr.read(16384)
                process.stdout.close()
                process.stderr.close()
            self.assertEqual(errors, b'', errors.decode('utf-8', 'replace'))
            return {'exited': observed_exit, 'returncode': returncode,
                    'events': events, 'output': output}

    def assert_timer_exit(self, result, stage):
        """Require a real SIGALRM exit and the fixed production syscall arguments."""
        self.assertIn(stage, [item['event'] for item in result['events']])
        self.assertTrue(result['exited'], 'worker remained blocked until fixture rescue')
        self.assertEqual(result['returncode'], -signal.SIGALRM)
        attempts = [item for item in result['events'] if item['event'] == 'arm']
        self.assertEqual(attempts, [{'event': 'arm', 'which': int(signal.ITIMER_REAL),
                                    'seconds': 300, 'interval': 0.0}])

    def test_blocked_context_terminates_with_parent_alive(self):
        """Removing timer setup leaves this real read blocked until fixture rescue."""
        result = self.probe()
        self.assert_timer_exit(result, 'context')
        self.assertEqual(result['output'], b'')

    def test_ignored_and_blocked_alarm_are_repaired(self):
        """Inherited SIG_IGN or a blocked SIGALRM cannot neutralize the independent timer."""
        for inherited in ('ignored', 'blocked', 'both'):
            with self.subTest(inherited=inherited):
                result = self.probe(inherited=inherited)
                self.assert_timer_exit(result, 'context')
                self.assertEqual(result['output'], b'')

    def test_real_blocking_output_terminates_without_parent_drain(self):
        """A partial prefix does not turn a timer-terminated blocked write into success."""
        result = self.probe(mode='output')
        self.assert_timer_exit(result, 'write')
        self.assertGreater(len(result['output']), 0)
        self.assertLess(len(result['output']), 65536)
        self.assertNotIn('return', [item['event'] for item in result['events']])

    def test_cleanup_remains_inside_the_same_timer(self):
        """A complete frame does not authorize success when owned cleanup stalls."""
        result = self.probe(mode='cleanup')
        self.assert_timer_exit(result, 'cleanup')
        self.assertEqual(result['output'], b'frame')

    def test_disabling_only_the_timer_keeps_the_negative_control_alive(self):
        """The live parent and fixture do not themselves terminate a stalled worker."""
        result = self.probe(mode='negative_control')
        self.assertIn('context', [item['event'] for item in result['events']])
        self.assertFalse(result['exited'])
        self.assertIsNone(result['returncode'])
        self.assertEqual(result['output'], b'')

    def test_timer_setup_faults_refuse_before_admission_and_context(self):
        """Each failed timer observation or installation syscall forbids later work."""
        for mode in ('fail_observation', 'fail_disposition', 'fail_mask', 'fail_arm'):
            with self.subTest(mode=mode):
                result = self.probe(mode=mode)
                self.assertTrue(result['exited'], 'setup fault was ignored')
                self.assertEqual(result['returncode'], 70)
                self.assertEqual(result['output'], b'')
                names = [item['event'] for item in result['events']]
                self.assertNotIn('admission', names)
                self.assertNotIn('context', names)

    def test_existing_timer_is_refused_without_replacement(self):
        """An already armed shorter timer cannot be overwritten by the 300-second bound."""
        result = self.probe(mode='existing_timer')
        self.assertTrue(result['exited'], 'preexisting timer was ignored')
        self.assertEqual(result['returncode'], 70)
        self.assertEqual(result['output'], b'')
        self.assertEqual([item['event'] for item in result['events']], ['return'])
        self.assertGreater(result['events'][0]['remaining'], 0)
        self.assertLessEqual(result['events'][0]['remaining'], 5)

    def test_lifetime_policy_drift_refuses_before_admission(self):
        """Changing the bound, policy pin/body or either family allowance fails closed."""
        for mode in ('bound_bool', 'bound_float', 'bound_larger', 'bound_zero',
                     'profile_pin', 'profile_body', 'structured_bound', 'native_bound'):
            with self.subTest(mode=mode):
                result = self.probe(mode=mode)
                self.assertTrue(result['exited'], 'changed lifetime policy was ignored')
                self.assertEqual(result['returncode'], 70)
                self.assertEqual(result['output'], b'')
                self.assertEqual([item['event'] for item in result['events']], ['return'])

    def test_success_keeps_one_timer_through_work_write_cleanup_and_return(self):
        """Resetting or cancelling the timer in any later phase breaks the observed lifetime."""
        result = self.probe(mode='complete')
        self.assertTrue(result['exited'])
        self.assertEqual(result['returncode'], 0)
        self.assertEqual(result['output'], b'frame')
        events = result['events']
        arms = [item for item in events if item['event'] == 'arm']
        self.assertEqual(arms, [{'event': 'arm', 'which': int(signal.ITIMER_REAL),
                               'seconds': 300, 'interval': 0.0}])
        names = [item['event'] for item in events]
        self.assertLess(names.index('arm'), names.index('admission'))
        remaining = [item['remaining'] for item in events if 'remaining' in item]
        self.assertEqual(len(remaining), 5)
        self.assertTrue(all(value > 0 for value in remaining))
        self.assertEqual(remaining, sorted(remaining, reverse=True))
        self.assertEqual(events[-1]['parent_signal'], int(signal.SIGKILL))

    def test_manifest_pins_separate_lifetime_without_changing_wire_profiles(self):
        """Bind the checked lifecycle policy separately from unchanged legacy/native wire bytes."""
        from hashlib import sha256

        profile = getattr(worker, 'worker_lifetime_profile', None)
        self.assertTrue(callable(profile), 'independent worker lifetime policy is missing')
        record = json.loads((ROOT / 'reporting/pdf-fixed-inspection-worker.v1.json').read_text())
        self.assertEqual(record['lifetime_policy']['profile'], profile())
        self.assertEqual(record['lifetime_policy']['profile_sha256'],
                         sha256(_json_bytes(profile())).hexdigest())
        self.assertEqual(worker.WORKER_LIFETIME_PROFILE_SHA256,
                         record['lifetime_policy']['profile_sha256'])
        self.assertEqual(worker.PROFILE_SHA256,
                         '48701b4b85dc7f56d5ac1b5032bb71069c9d44189de3da265b59e94d3b3fead3')
        self.assertEqual(worker.NATIVE_PROFILE_SHA256,
                         '835e4c927283609888a2a1741ed26d93db2a324521239e8f51470fe1f8d87d6f')
        self.assertFalse(worker.worker_profile()['hard_job_deadline_enforced'])
        self.assertFalse(worker.worker_profile()['aggregate_job_resources_qualified'])


if __name__ == '__main__':
    unittest.main()
