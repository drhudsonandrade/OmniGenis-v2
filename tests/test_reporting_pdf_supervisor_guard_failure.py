"""Live-parent guard faults with owned children; not outer cgroup qualification.

Injected observer failures are control-path fixtures, not forged kernel evidence.
Every real child is checked before emergency fixture cleanup can rescue it.
"""
from contextlib import contextmanager
import io
import os
import select
import signal
import subprocess
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from reporting import pdf_supervised_inspection as supervisor
from reporting.page_checkpoints import _json_bytes
from tests import test_reporting_pdf_supervised_inspection as existing


class Guard:
    """Inject a narrow observation or close fault without claiming native admission."""

    def __init__(self, check=None, close_result=True, close_error=None):
        """Keep control calls visible to assertions made before fixture teardown."""
        self.check = check
        self.checks = 0
        self.closes = 0
        self.close_result = close_result
        self.close_error = close_error

    def recheck(self):
        """Run only the explicitly configured fault injection."""
        self.checks += 1
        if self.check is not None:
            self.check(self.checks)

    def close(self):
        """Return the configured close result or raise its independent failure."""
        self.closes += 1
        if self.close_error is not None:
            raise self.close_error
        return self.close_result


class SupervisorGuardFailureTests(unittest.TestCase):
    """A failed timing/observation guard cannot authorize result acceptance."""

    @contextmanager
    def child(self, *, exited=False):
        """Create one ready exclusively owned child and retain a pidfd for rescue."""
        script = 'import sys;print("READY",flush=True);' + (
            'sys.exit(0)' if exited else 'sys.stdin.buffer.read()')
        process = subprocess.Popen([sys.executable, '-I', '-B', '-c', script],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            start_new_session=True, close_fds=True)
        pidfd = os.pidfd_open(process.pid)
        try:
            self.assertTrue(select.select([process.stdout], [], [], 5)[0], 'child not ready')
            self.assertEqual(process.stdout.readline(), b'READY\n')
            if exited:
                self.assertTrue(select.select([pidfd], [], [], 5)[0], 'child not exited')
            yield process
        finally:
            # No success assertion relies on this rescue or on Popen.wait().
            if process.returncode is None:
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
            for stream in (process.stdin, process.stdout):
                stream.close()
            os.close(pidfd)

    def reaped(self, process, expected):
        """Prove production set the actual status and consumed the owned waitable child."""
        self.assertEqual(process.returncode, expected, 'production did not reap its child')
        with self.assertRaises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)
        self.assertTrue(process.stdin.closed and process.stdout.closed)

    def fixture(self):
        """Reuse the existing sealed request and independent result expectation fixture."""
        value = existing.SupervisedInspectionTests()
        value.setUp()
        return value

    def test_clock_read_failure_cannot_skip_live_child_retirement(self):
        """A failed cleanup clock remains refusal after safe signal and explicit reap."""
        with self.child() as child, patch.object(supervisor, 'monotonic_ns',
                side_effect=OSError('SYNTHETIC_GUARD_SECRET')):
            with self.assertRaises(supervisor._Refusal) as caught:
                supervisor._finish_child(child)
            self.assertEqual(str(caught.exception), 'cleanup_unresolved')
            self.reaped(child, -signal.SIGKILL)

    def test_clock_read_failure_still_reaps_already_exited_child(self):
        """An unavailable clock must not leave a completed owned child as a zombie."""
        with self.child(exited=True) as child, patch.object(supervisor, 'monotonic_ns',
                side_effect=OSError('clock unavailable')):
            with self.assertRaises(supervisor._Refusal):
                supervisor._finish_child(child)
            self.reaped(child, 0)

    def test_malformed_clock_never_accepts_exited_zero_status(self):
        """Malformed clock values cannot turn zero child exit into valid cleanup."""
        for value in (None, True, False, -1, '0', float('nan'), float('inf')):
            with self.subTest(type=type(value).__name__), self.child(exited=True) as child:
                with patch.object(supervisor, 'monotonic_ns', return_value=value):
                    with self.assertRaises(supervisor._Refusal):
                        supervisor._finish_child(child)
                self.reaped(child, 0)

    def test_regressing_cleanup_clock_refuses_after_reaping(self):
        """Reaping a completed child does not excuse a backwards guard clock."""
        with self.child(exited=True) as child, patch.object(supervisor, 'monotonic_ns',
                side_effect=[100, 99]):
            with self.assertRaises(supervisor._Refusal):
                supervisor._finish_child(child)
            self.reaped(child, 0)

    def test_clock_exception_after_initial_read_still_reaps(self):
        """A later failed time observation is sticky even after child completion."""
        with self.child(exited=True) as child, patch.object(supervisor, 'monotonic_ns',
                side_effect=[100, RuntimeError('clock failed')]):
            with self.assertRaises(supervisor._Refusal):
                supervisor._finish_child(child)
            self.reaped(child, 0)

    def test_frozen_clock_has_finite_poll_count_without_signalling_real_pid(self):
        """A finite iteration cap prevents a frozen guard from creating an endless wait."""
        child = SimpleNamespace(pid=42, args=['synthetic'], returncode=None,
                                stdin=io.BytesIO(), stdout=io.BytesIO())
        calls = []
        def pause(seconds):
            """Bound the negative fixture even before the production fix exists."""
            calls.append(seconds)
            if len(calls) > 500:
                raise RuntimeError('fixture loop stop')
        with patch.object(supervisor, 'monotonic_ns', return_value=100), \
             patch.object(supervisor, '_unreaped_exit', return_value=None), \
             patch.object(supervisor.os, 'killpg'), patch.object(supervisor.os, 'kill'), \
             patch.object(supervisor, 'sleep', side_effect=pause):
            with self.assertRaises(supervisor._Refusal):
                supervisor._finish_child(child)
        self.assertLessEqual(len(calls), 200)
        self.assertIsNone(child.returncode)
        self.assertTrue(child.stdin.closed and child.stdout.closed)

    def test_clock_failure_cannot_bypass_child_identity_proof(self):
        """No numeric signal or waitpid is permitted after definitive ownership loss."""
        child = SimpleNamespace(pid=42, args=['synthetic'], returncode=None,
                                stdin=io.BytesIO(), stdout=io.BytesIO())
        with patch.object(supervisor, 'monotonic_ns', side_effect=OSError('bad clock')), \
             patch.object(supervisor, '_unreaped_exit', side_effect=ChildProcessError('lost')), \
             patch.object(supervisor.os, 'killpg') as group, \
             patch.object(supervisor.os, 'kill') as direct, \
             patch.object(supervisor.os, 'waitpid') as reap:
            with self.assertRaises(supervisor._Refusal):
                supervisor._finish_child(child)
        group.assert_not_called(); direct.assert_not_called(); reap.assert_not_called()
        self.assertTrue(child.stdin.closed and child.stdout.closed)

    def test_healthy_cleanup_preserves_actual_zero_and_signal_exit(self):
        """The existing successful cleanup semantics remain unchanged for healthy clocks."""
        for exited, expected in ((True, 0), (False, -signal.SIGKILL)):
            with self.subTest(exited=exited), self.child(exited=exited) as child:
                self.assertEqual(supervisor._finish_child(child), expected)
                self.reaped(child, expected)

    def test_combined_time_and_group_signal_fault_still_reaps_live_child(self):
        """Failure of two independent guards cannot prevent direct owned-child retirement."""
        with self.child() as child, patch.object(supervisor, 'monotonic_ns',
                side_effect=OSError('clock failed')), \
             patch.object(supervisor.os, 'killpg', side_effect=PermissionError('group denied')):
            with self.assertRaises(supervisor._Refusal):
                supervisor._finish_child(child)
            self.reaped(child, -signal.SIGKILL)

    def test_guard_failure_and_broken_clock_still_close_transport(self):
        """The public boundary refuses and reaps before fixture rescue when both guards fail."""
        fixture = self.fixture(); broken = [False]
        def clock():
            """Keep the admission clock real until the observation fault is injected."""
            if broken[0]:
                raise OSError('SYNTHETIC_GUARD_SECRET')
            return time.monotonic_ns()
        def fail(number):
            """Simultaneously lose observer and cleanup time readings after launch."""
            if number == 2:
                broken[0] = True
                raise OSError('SYNTHETIC_GUARD_SECRET')
        guard = Guard(fail)
        with fixture.h.request() as (fd, expected, args, packet):
            raw = _json_bytes(fixture.fixture.context(expected, args))
            os.lseek(fd, 9, os.SEEK_SET)
            with patch.object(supervisor, 'monotonic_ns', side_effect=clock), \
                 patch.object(supervisor, '_open_resource_scope', return_value=guard), \
                 fixture.child('import sys;sys.stdin.buffer.read()') as launches:
                with self.assertRaises(supervisor.PdfSupervisedInspectionError) as caught:
                    fixture.invoke(fd, raw)
                self.assertEqual(str(caught.exception), 'pdf_supervised_inspection_cleanup_unresolved')
                self.assertEqual(len(launches), 1)
                self.reaped(launches[0][2], -signal.SIGKILL)
            self.assertEqual(guard.closes, 1)
            self.assertEqual(os.pread(fd, len(packet), 0), packet)
            self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), 9)

    def test_repeated_time_faults_do_not_leak_descriptors(self):
        """Repeated failed cleanup reports still retire each child and owned pipe."""
        before = len(os.listdir('/proc/self/fd'))
        for _ in range(3):
            with self.child() as child, patch.object(supervisor, 'monotonic_ns',
                    side_effect=OSError('clock failed')):
                with self.assertRaises(supervisor._Refusal):
                    supervisor._finish_child(child)
                self.reaped(child, -signal.SIGKILL)
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_guard_error_before_launch_preserves_request_and_closes_guard(self):
        """An admission recheck failure cannot spawn or consume the borrowed request."""
        fixture = self.fixture()
        def fail(_):
            """Inject a failed observer rather than an invented kernel measurement."""
            raise OSError('SYNTHETIC_GUARD_SECRET')
        guard = Guard(fail)
        with fixture.h.request() as (fd, expected, args, packet):
            raw = _json_bytes(fixture.fixture.context(expected, args))
            os.lseek(fd, 7, os.SEEK_SET)
            with patch.object(supervisor, '_open_resource_scope', return_value=guard), \
                 patch.object(supervisor.subprocess, 'Popen') as launch:
                with self.assertRaises(supervisor.PdfSupervisedInspectionError) as caught:
                    fixture.invoke(fd, raw)
                launch.assert_not_called()
            self.assertEqual(guard.closes, 1)
            self.assertNotIn('SYNTHETIC_GUARD_SECRET', str(caught.exception))
            self.assertEqual(os.pread(fd, len(packet), 0), packet)
            self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), 7)

    def test_transport_guard_failure_reaps_before_fixture_rescue(self):
        """I/O, allocation and value failures in a live observer retire its actual child."""
        fixture = self.fixture()
        for failure in (OSError('SYNTHETIC_GUARD_SECRET'), MemoryError(), ValueError()):
            def fail(number):
                """Permit prelaunch checking, then fail after a child exists."""
                if number == 2:
                    raise failure
            guard = Guard(fail)
            with self.subTest(failure=type(failure).__name__), fixture.h.request() as (fd, expected, args, packet):
                raw = _json_bytes(fixture.fixture.context(expected, args))
                with patch.object(supervisor, '_open_resource_scope', return_value=guard), \
                     fixture.child('import sys;sys.stdin.buffer.read()') as launches:
                    with self.assertRaises(supervisor.PdfSupervisedInspectionError) as caught:
                        fixture.invoke(fd, raw)
                    self.assertEqual(len(launches), 1)
                    self.reaped(launches[0][2], -signal.SIGKILL)
                self.assertEqual(guard.closes, 1)
                self.assertNotIn('SYNTHETIC_GUARD_SECRET', str(caught.exception))
                self.assertEqual(os.pread(fd, len(packet), 0), packet)

    def test_returned_guard_stall_cannot_extend_admission_deadline(self):
        """A guard that returns after the deadline cannot authorize a later launch."""
        fixture = self.fixture(); clocks = []
        real_clock = supervisor._Clock
        def create_clock():
            """Capture the existing monotonic budget without altering its profile."""
            value = real_clock(); clocks.append(value); return value
        def stall(_):
            """A bounded actual pause models return from a delayed guard, not preemption."""
            clocks[0].deadline = time.monotonic_ns() + 5_000_000
            time.sleep(0.02)
        guard = Guard(stall)
        with fixture.h.request() as (fd, expected, args, _):
            raw = _json_bytes(fixture.fixture.context(expected, args))
            with patch.object(supervisor, '_Clock', side_effect=create_clock), \
                 patch.object(supervisor, '_open_resource_scope', return_value=guard), \
                 patch.object(supervisor.subprocess, 'Popen') as launch:
                with self.assertRaises(supervisor.PdfSupervisedInspectionError):
                    fixture.invoke(fd, raw)
                launch.assert_not_called()
        self.assertEqual(guard.closes, 1)

    def test_guard_failure_after_decoding_withholds_complete_result(self):
        """Even an independently valid complete frame cannot outrun a final guard fault."""
        fixture = self.fixture()
        def fail(_):
            """Fail the observer after the real frame decoder has validated its input."""
            raise OSError('SYNTHETIC_GUARD_SECRET')
        guard = Guard(fail)
        with fixture.h.request() as (fd, expected, args, packet):
            context = fixture.fixture.context(expected, args)
            encoded, _ = fixture.synthetic_frame(context)
            with patch.object(supervisor, '_open_resource_scope', return_value=guard), \
                 patch.object(supervisor, '_exchange', return_value=encoded):
                with self.assertRaises(supervisor.PdfSupervisedInspectionError) as caught:
                    fixture.invoke(fd, _json_bytes(context))
            self.assertEqual(guard.checks, 1); self.assertEqual(guard.closes, 1)
            self.assertNotIn('SYNTHETIC_GUARD_SECRET', str(caught.exception))
            self.assertEqual(os.pread(fd, len(packet), 0), packet)

    def test_guard_close_exception_is_content_free_and_refuses_result(self):
        """An observer teardown exception cannot leak its text or release a valid result."""
        fixture = self.fixture(); guard = Guard(close_error=OSError('SYNTHETIC_GUARD_SECRET'))
        with fixture.h.request() as (fd, expected, args, _):
            context = fixture.fixture.context(expected, args); encoded, _ = fixture.synthetic_frame(context)
            with patch.object(supervisor, '_open_resource_scope', return_value=guard), \
                 patch.object(supervisor, '_exchange', return_value=encoded):
                with self.assertRaises(supervisor.PdfSupervisedInspectionError) as caught:
                    fixture.invoke(fd, _json_bytes(context))
            self.assertEqual(str(caught.exception), 'pdf_supervised_inspection_cleanup_unresolved')
            self.assertEqual(guard.closes, 1)

    def test_guard_close_requires_true_not_a_truthy_unknown_result(self):
        """Only an exact successful close outcome can release the already validated frame."""
        fixture = self.fixture()
        for value in (False, None, 1, 'closed', object()):
            guard = Guard(close_result=value)
            with self.subTest(type=type(value).__name__), fixture.h.request() as (fd, expected, args, _):
                context = fixture.fixture.context(expected, args); encoded, _ = fixture.synthetic_frame(context)
                with patch.object(supervisor, '_open_resource_scope', return_value=guard), \
                     patch.object(supervisor, '_exchange', return_value=encoded):
                    with self.assertRaises(supervisor.PdfSupervisedInspectionError):
                        fixture.invoke(fd, _json_bytes(context))
                self.assertEqual(guard.closes, 1)

    def test_interrupted_observer_still_reaps_child_and_closes_scope(self):
        """Cancellation propagates only after the live parent's cleanup path executes."""
        fixture = self.fixture()
        def interrupt(number):
            """Interrupt after child creation, without altering any native guard policy."""
            if number == 2:
                raise KeyboardInterrupt()
        guard = Guard(interrupt)
        with fixture.h.request() as (fd, expected, args, _):
            raw = _json_bytes(fixture.fixture.context(expected, args))
            with patch.object(supervisor, '_open_resource_scope', return_value=guard), \
                 fixture.child('import sys;sys.stdin.buffer.read()') as launches:
                with self.assertRaises(KeyboardInterrupt):
                    fixture.invoke(fd, raw)
                self.assertEqual(len(launches), 1)
                self.reaped(launches[0][2], -signal.SIGKILL)
            self.assertEqual(guard.closes, 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
