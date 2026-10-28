"""Real-child regressions for identity-preserving inspection cleanup on Linux."""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
import errno
import importlib
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


WRAPPERS = ("pdf_object_graph", "pdf_text_windows", "pdf_raster_windows", "pdf_validation")
REAL_KILLPG = os.killpg
REAL_KILL = os.kill
REAL_WAITID = os.waitid
REAL_WAITPID = os.waitpid
WAIT_FLAGS = os.WEXITED | os.WNOHANG | os.WNOWAIT
ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def real_child(script, *, pass_fds=()):
    """Pin test cleanup to a live child identity, including after a failed assertion."""
    process = subprocess.Popen(
        [sys.executable, "-I", "-B", "-c", script], start_new_session=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, pass_fds=pass_fds,
    )
    descriptor = os.pidfd_open(process.pid)
    try:
        yield process
    finally:
        try:
            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=3)
        os.close(descriptor)


def observe_exit(process):
    """Observe a real exit without releasing the PID or populating Popen.returncode."""
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        result = REAL_WAITID(os.P_PID, process.pid, WAIT_FLAGS)
        if result is not None:
            return result
        time.sleep(0.005)
    raise AssertionError("test child did not exit")


@contextmanager
def signal_observer(process, observations, *, group_error=None):
    """Record kernel ownership before each signal and suppress unsafe old behavior."""
    def send(kind, identifier, sig):
        if identifier != process.pid:
            raise AssertionError("unexpected signal target")
        try:
            status = REAL_WAITID(os.P_PID, process.pid, WAIT_FLAGS)
        except ChildProcessError:
            observations.append((kind, False, None))
            return
        observations.append((kind, True, None if status is None else status.si_status))
        if kind == "group" and group_error is not None:
            raise group_error
        (REAL_KILLPG if kind == "group" else REAL_KILL)(identifier, sig)

    with patch.object(os, "killpg", side_effect=lambda pid, sig: send("group", pid, sig)), \
         patch.object(os, "kill", side_effect=lambda pid, sig: send("child", pid, sig)):
        yield


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open"), "Linux pidfd required")
class InspectionChildLifecycleTests(unittest.TestCase):
    def assert_reaped(self, process):
        """Success and failure cleanup must release the direct child's wait state."""
        with self.assertRaises(ChildProcessError):
            REAL_WAITID(os.P_PID, process.pid, WAIT_FLAGS)

    def test_exited_child_identity_is_retained_through_every_group_signal(self):
        """Reaping before killpg loses authority for all three literal exit outcomes."""
        scripts = (("import os; os._exit(0)", 0),
                   ("import os; os._exit(7)", 7),
                   ("import os,signal; os.kill(os.getpid(), signal.SIGTERM)", -15))
        for name in WRAPPERS:
            module = importlib.import_module("reporting." + name)
            for script, expected in scripts:
                with self.subTest(wrapper=name, expected=expected), real_child(script) as process:
                    observe_exit(process)
                    observations = []
                    with signal_observer(process, observations):
                        result = module._wait(process)
                    self.assertEqual(result, expected)
                    self.assertEqual(process.returncode, expected)
                    self.assert_reaped(process)
                    self.assertTrue(observations, "original group was never cleaned")
                    self.assertTrue(all(owned for _, owned, _ in observations), observations)
                    self.assertIn(("group", True, abs(expected)), observations)

    def test_timeout_remains_a_failure_and_reaps_the_live_child(self):
        """Successful termination must not turn a wall timeout into accepted output."""
        for name in WRAPPERS:
            module = importlib.import_module("reporting." + name)
            with self.subTest(wrapper=name), real_child("import time; time.sleep(30)") as process:
                observations = []
                started = time.monotonic()
                with patch.object(module, "WALL_SECONDS", 0.05), signal_observer(process, observations):
                    with self.assertRaises(subprocess.TimeoutExpired):
                        module._wait(process)
                self.assertLess(time.monotonic() - started, 2.5)
                self.assertEqual(process.returncode, -9)
                self.assert_reaped(process)
                self.assertTrue(observations)
                self.assertTrue(all(owned for _, owned, _ in observations), observations)

    def test_external_reap_refuses_without_a_numeric_signal(self):
        """An already reaped child cannot authorize any group or direct PID signal."""
        for name in WRAPPERS:
            module = importlib.import_module("reporting." + name)
            with self.subTest(wrapper=name), real_child("import os; os._exit(0)") as process:
                process.wait(timeout=3)
                observations = []
                with signal_observer(process, observations):
                    with self.assertRaises(Exception):
                        module._wait(process)
                self.assertEqual(observations, [])

    def test_kernel_reap_without_popen_update_refuses_without_a_signal(self):
        """ECHILD must refuse even when the cached Popen returncode is still None."""
        for name in WRAPPERS:
            module = importlib.import_module("reporting." + name)
            with self.subTest(wrapper=name), real_child("import os; os._exit(0)") as process:
                observe_exit(process)
                os.waitpid(process.pid, 0)
                self.assertIsNone(process.returncode)
                observations = []
                with signal_observer(process, observations):
                    with self.assertRaises(ChildProcessError):
                        module._wait(process)
                self.assertEqual(observations, [])

    def test_unavailable_waitid_refuses_without_unknown_identity_signals(self):
        """A failed ownership primitive cannot authorize numeric cleanup signals."""
        module = importlib.import_module("reporting.pdf_object_graph")
        with real_child("import time; time.sleep(30)") as process:
            observations = []
            with patch.object(os, "waitid", side_effect=OSError(errno.ENOSYS, "unavailable")), \
                 patch.object(module, "WALL_SECONDS", 0.05), signal_observer(process, observations):
                with self.assertRaises(OSError):
                    module._wait(process)
            self.assertEqual(observations, [])
            self.assertIsNone(process.returncode)

    def test_mismatched_or_unknown_waitid_result_cannot_authorize_a_signal(self):
        """Only the exact child's recognized exit state may reserve signal authority."""
        module = importlib.import_module("reporting.pdf_object_graph")
        for mismatch in (True, False):
            with self.subTest(mismatch=mismatch), real_child("import time; time.sleep(30)") as process:
                result = os.waitid_result((process.pid + int(mismatch), os.getuid(),
                                           signal.SIGCHLD, 0,
                                           os.CLD_EXITED if mismatch else os.CLD_STOPPED))
                observations = []
                with patch.object(os, "waitid", return_value=result), signal_observer(process, observations):
                    with self.assertRaises(Exception):
                        module._wait(process)
                self.assertEqual(observations, [])

    def test_observation_error_still_cleans_up_if_ownership_can_be_proven(self):
        """An initial OS error must not skip independently provable child cleanup."""
        module = importlib.import_module("reporting.pdf_object_graph")
        failure = OSError(errno.EIO, "observation failed")
        first = True

        def observe(*args):
            nonlocal first
            if first:
                first = False
                raise failure
            return REAL_WAITID(*args)

        with real_child("import time; time.sleep(30)") as process:
            observations = []
            with patch.object(os, "waitid", side_effect=observe), signal_observer(process, observations):
                with self.assertRaises(OSError) as caught:
                    module._wait(process)
            self.assertIs(caught.exception, failure)
            self.assertEqual(process.returncode, -9)
            self.assert_reaped(process)
            self.assertTrue(observations)
            self.assertTrue(all(owned for _, owned, _ in observations), observations)

    def test_definitive_ownership_loss_permanently_revokes_signal_and_reap_authority(self):
        """A later valid numeric lookup cannot restore an identity declared lost."""
        module = importlib.import_module("reporting.pdf_object_graph")
        for stage in (1, 2, 3, 4):
            for fault in ("echild", "identity", "state"):
                with self.subTest(stage=stage, fault=fault), \
                     real_child("import os; os._exit(0)") as process:
                    observe_exit(process)
                    calls = 0
                    lost = False
                    operations_after_loss = []

                    def observe(*args):
                        nonlocal calls, lost
                        calls += 1
                        if calls == stage:
                            lost = True
                            if fault == "echild":
                                raise ChildProcessError(errno.ECHILD, "ownership lost")
                            return os.waitid_result((process.pid + int(fault == "identity"),
                                                     os.getuid(), signal.SIGCHLD, 0,
                                                     os.CLD_STOPPED if fault == "state" else os.CLD_EXITED))
                        return REAL_WAITID(*args)

                    def signal_group(pid, sig):
                        if lost:
                            operations_after_loss.append("group signal")
                            return
                        return REAL_KILLPG(pid, sig)

                    def signal_child(pid, sig):
                        if lost:
                            operations_after_loss.append("child signal")
                            return
                        return REAL_KILL(pid, sig)

                    def reap(pid, flags):
                        if lost:
                            operations_after_loss.append("reap")
                        return REAL_WAITPID(pid, flags)

                    with patch.object(os, "waitid", side_effect=observe), \
                         patch.object(os, "killpg", side_effect=signal_group), \
                         patch.object(os, "kill", side_effect=signal_child), \
                         patch.object(os, "waitpid", side_effect=reap):
                        with self.assertRaises(ChildProcessError):
                            module._wait(process)
                    self.assertTrue(lost, "fixture did not reach the intended observation")
                    self.assertEqual(operations_after_loss, [])
                    self.assertIsNone(process.returncode)
                    self.assertIsNotNone(REAL_WAITID(os.P_PID, process.pid, WAIT_FLAGS))

    def test_failed_group_signal_still_terminates_and_reaps_owned_live_child(self):
        """A group-signaling error must not skip independent direct-child cleanup."""
        for name in WRAPPERS:
            module = importlib.import_module("reporting." + name)
            with self.subTest(wrapper=name), real_child("import time; time.sleep(30)") as process:
                observations = []
                started = time.monotonic()
                with patch.object(module, "WALL_SECONDS", 0.05), \
                     signal_observer(process, observations, group_error=PermissionError("group refused")):
                    with self.assertRaises(Exception):
                        module._wait(process)
                self.assertLess(time.monotonic() - started, 2.5)
                self.assertEqual(process.returncode, -9)
                self.assert_reaped(process)
                self.assertTrue(all(owned for _, owned, _ in observations), observations)

    def test_failed_cleanup_never_returns_zero_even_after_successful_worker_exit(self):
        """Unresolved original-group cleanup must reject an otherwise successful exit."""
        for name in WRAPPERS:
            module = importlib.import_module("reporting." + name)
            with self.subTest(wrapper=name), real_child("import os; os._exit(0)") as process:
                observe_exit(process)
                observations = []
                with signal_observer(process, observations, group_error=PermissionError("group refused")):
                    with self.assertRaises(Exception):
                        module._wait(process)
                self.assert_reaped(process)
                self.assertTrue(all(owned for _, owned, _ in observations), observations)

    def test_original_group_descendant_is_terminated_before_leader_reap(self):
        """Killing only the exited direct child leaves the inherited group alive."""
        for name in WRAPPERS:
            with self.subTest(wrapper=name):
                script = (
                    "import sys; sys.path.insert(0, " + repr(str(ROOT)) + "); "
                    "sys.path.insert(0, " + repr(str(ROOT / "tests")) + "); "
                    "from test_reporting_pdf_process_lifecycle import descendant_probe; "
                    "import json; print(json.dumps(descendant_probe(" + repr(name) + ")))"
                )
                result = subprocess.run([sys.executable, "-I", "-B", "-c", script],
                                        capture_output=True, text=True, timeout=12)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout),
                                 {"exit": 0, "descendant_signal": 9, "owned": True, "reaped": True})



@contextmanager
def reap_observer(process, observations):
    """Check retained kernel ownership immediately before the product's final reap."""
    def reap(pid, flags):
        """Preserve kernel ECHILD while refusing an unowned numeric waitpid."""
        if pid != process.pid:
            raise AssertionError("unexpected reap target")
        try:
            REAL_WAITID(os.P_PID, pid, WAIT_FLAGS)
        except ChildProcessError:
            observations.append(False)
            raise
        observations.append(True)
        return REAL_WAITPID(pid, flags)
    with patch.object(os, "waitpid", side_effect=reap):
        yield


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open"), "Linux pidfd required")
class RendererChildLifecycleTests(unittest.TestCase):
    def test_real_exit_statuses_retain_ownership_through_signals_and_final_reap(self):
        """A renderer reap before group cleanup revokes numeric signal authority."""
        from reporting import adapters
        for script, expected in (("import os;os._exit(0)", 0),
                                 ("import os;os._exit(7)", 7),
                                 ("import os,signal;os.kill(os.getpid(),signal.SIGTERM)", -15)):
            with self.subTest(expected=expected), real_child(script) as process:
                observe_exit(process)
                signals, reaps = [], []
                with signal_observer(process, signals), reap_observer(process, reaps):
                    code = adapters._wait_pdf_render_worker(process, wall_seconds=1)
                self.assertEqual(code, expected)
                self.assertEqual(process.returncode, expected)
                self.assertTrue(signals)
                self.assertTrue(all(owned for _, owned, _ in signals), signals)
                self.assertEqual(reaps, [True])
                with self.assertRaises(ChildProcessError):
                    REAL_WAITID(os.P_PID, process.pid, WAIT_FLAGS)

    def test_external_kernel_reap_without_returncode_refuses_all_numeric_operations(self):
        """Popen's ECHILD-to-zero fallback cannot turn a released PID into success."""
        from reporting import adapters
        with real_child("import os;os._exit(0)") as process:
            observe_exit(process)
            REAL_WAITPID(process.pid, 0)
            self.assertIsNone(process.returncode)
            signals, reaps = [], []
            with signal_observer(process, signals), reap_observer(process, reaps):
                with self.assertRaisesRegex(RuntimeError, "^pdf_render_failed$"):
                    adapters._wait_pdf_render_worker(process)
            self.assertEqual(signals, [])
            self.assertEqual(reaps, [])
            self.assertIsNone(process.returncode)

    def test_unavailable_ownership_primitives_refuse_without_signals_or_reap(self):
        """Missing or unavailable waitid cannot certify renderer cleanup."""
        from reporting import adapters
        for error in (OSError(errno.ENOSYS, "PRIVATE"), AttributeError("PRIVATE")):
            with self.subTest(error=type(error).__name__), real_child("import os;os._exit(0)") as process:
                observe_exit(process)
                signals, reaps = [], []
                with patch.object(os, "waitid", side_effect=error), \
                     signal_observer(process, signals), reap_observer(process, reaps):
                    with self.assertRaisesRegex(RuntimeError, "^pdf_render_failed$"):
                        adapters._wait_pdf_render_worker(process)
                self.assertEqual(signals, [])
                self.assertEqual(reaps, [])

    def test_invalid_wall_budget_maps_to_fixed_renderer_refusal(self):
        """Helper budget validation must retain the renderer's fixed public failure."""
        from reporting import adapters
        with real_child("import os;os._exit(0)") as process:
            observe_exit(process)
            signals, reaps = [], []
            with signal_observer(process, signals), reap_observer(process, reaps):
                error = None
                try:
                    adapters._wait_pdf_render_worker(process, wall_seconds=-1)
                except Exception as caught:
                    error = caught
            self.assertIsInstance(error, RuntimeError)
            self.assertEqual(str(error), "pdf_render_failed")
            self.assertEqual(signals, [])
            self.assertEqual(reaps, [])

    def test_group_failure_preserves_independent_owned_child_cleanup(self):
        """A refused group signal still kills and reaps the owned direct renderer."""
        from reporting import adapters
        initial = OSError(errno.EIO, "PRIVATE initial observation")
        first = True
        def observe(*args):
            """Inject one transient observation fault, then expose kernel ownership."""
            nonlocal first
            if first:
                first = False
                raise initial
            return REAL_WAITID(*args)
        with real_child("import time;time.sleep(30)") as process:
            signals, reaps = [], []
            with patch.object(os, "waitid", side_effect=observe), \
                 signal_observer(process, signals, group_error=PermissionError("PRIVATE group")), \
                 reap_observer(process, reaps):
                error = None
                try:
                    adapters._wait_pdf_render_worker(process, wall_seconds=1)
                except Exception as caught:
                    error = caught
            self.assertIsInstance(error, RuntimeError)
            self.assertEqual(str(error), "pdf_render_failed")
            self.assertEqual(process.returncode, -9)
            self.assertIn(("child", True, None), signals)
            self.assertTrue(all(owned for _, owned, _ in signals), signals)
            self.assertEqual(reaps, [True])

    def test_timeout_refuses_after_owned_child_cleanup(self):
        """Successful cleanup cannot turn renderer timeout into a usable exit code."""
        from reporting import adapters
        with real_child("import time;time.sleep(30)") as process:
            signals, reaps = [], []
            with signal_observer(process, signals), reap_observer(process, reaps):
                with self.assertRaisesRegex(RuntimeError, "^pdf_render_failed$"):
                    adapters._wait_pdf_render_worker(process, wall_seconds=0.02)
            self.assertEqual(process.returncode, -9)
            self.assertTrue(signals)
            self.assertTrue(all(owned for _, owned, _ in signals), signals)
            self.assertEqual(reaps, [True])

    def test_definitive_ownership_loss_never_restores_numeric_authority(self):
        """A later real observation cannot undo an earlier ECHILD refusal."""
        from reporting import adapters
        for stage in (1, 2, 3, 4):
            with self.subTest(stage=stage), real_child("import os;os._exit(0)") as process:
                observe_exit(process)
                calls, lost = 0, False
                after_loss = []
                def observe(*args):
                    """Declare ownership lost at the selected lifecycle observation."""
                    nonlocal calls, lost
                    calls += 1
                    if calls == stage:
                        lost = True
                        raise ChildProcessError(errno.ECHILD, "ownership lost")
                    return REAL_WAITID(*args)
                def send(pid, sig):
                    """Record forbidden post-loss signals without sending them."""
                    if lost:
                        after_loss.append("signal")
                    else:
                        try:
                            REAL_WAITID(os.P_PID, pid, WAIT_FLAGS)
                        except ChildProcessError:
                            after_loss.append("unowned signal")
                            return
                        REAL_KILLPG(pid, sig)
                def reap(pid, flags):
                    """Record forbidden post-loss reap attempts without calling waitpid."""
                    if lost:
                        after_loss.append("reap")
                        return (0, 0)
                    return REAL_WAITPID(pid, flags)
                with patch.object(os, "waitid", side_effect=observe), \
                     patch.object(os, "killpg", side_effect=send), \
                     patch.object(os, "kill", side_effect=send), \
                     patch.object(os, "waitpid", side_effect=reap):
                    with self.assertRaisesRegex(RuntimeError, "^pdf_render_failed$"):
                        adapters._wait_pdf_render_worker(process)
                self.assertTrue(lost, "required ownership observation was skipped")
                self.assertEqual(after_loss, [])
                self.assertIsNone(process.returncode)

    def test_renderer_original_group_descendant_cleanup_and_timeout_refusal(self):
        """Product group cleanup, rather than pidfd fixture teardown, kills descendants."""
        for timeout in (False, True):
            with self.subTest(timeout=timeout):
                script = (
                    "import sys;sys.path.insert(0," + repr(str(ROOT)) + ");"
                    "sys.path.insert(0," + repr(str(ROOT / "tests")) + ");"
                    "from test_reporting_pdf_process_lifecycle import descendant_probe;"
                    "import json;print(json.dumps(descendant_probe('adapters', timeout=" + repr(timeout) + ")))"
                )
                result = subprocess.run([sys.executable, "-I", "-B", "-c", script],
                                        capture_output=True, text=True, timeout=12)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), {
                    "exit": "pdf_render_failed" if timeout else 0,
                    "descendant_signal": 9, "owned": True, "reaped": True,
                })


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open"), "Linux pidfd required")
class CleanupAllowanceTests(unittest.TestCase):
    def test_invalid_cleanup_allowance_rejects_before_any_process_operation(self):
        """Invalid cleanup budgets must fail validation before ownership or cleanup."""
        from reporting import _pdf_process_lifecycle as lifecycle
        invalid = (None, "5", [], object(), True, False, 0, -1, float("nan"),
                   float("inf"), -float("inf"), 10 ** 10000)
        for index, allowance in enumerate(invalid):
            with self.subTest(index=index), patch.object(lifecycle, "_observe") as observe, \
                 patch.object(os, "killpg") as group, patch.object(os, "kill") as child, \
                 patch.object(os, "waitpid") as reap:
                error = None
                try:
                    lifecycle.wait_owned_process_group(object(), wall_seconds=1,
                                                       cleanup_seconds=allowance)
                except Exception as caught:
                    error = caught
                self.assertIsInstance(error, ValueError)
                observe.assert_not_called()
                group.assert_not_called()
                child.assert_not_called()
                reap.assert_not_called()

    def run_delayed_observation(self, *, route, visible_at, group_cost=0, allowance=5):
        """Use a real retained child with controlled monotonic observation latency."""
        from reporting import _pdf_process_lifecycle as lifecycle, adapters
        clock, calls = [100.0], 0
        original_observe = lifecycle._observe
        def observe(process):
            """Delay only final-exit visibility while retaining actual child ownership."""
            nonlocal calls
            calls += 1
            result = original_observe(process)
            if calls <= 3 or clock[0] >= 100 + visible_at:
                return result
            return None
        def sleep(seconds):
            """Advance controlled monotonic time instead of sleeping real seconds."""
            clock[0] += seconds
        with real_child("import os;os._exit(7)") as process:
            observe_exit(process)
            signals = []
            def group(pid, sig):
                """Guard the real group signal and charge earlier cleanup work."""
                try:
                    REAL_WAITID(os.P_PID, pid, WAIT_FLAGS)
                except ChildProcessError:
                    signals.append(False)
                    return
                signals.append(True)
                REAL_KILLPG(pid, sig)
                clock[0] += group_cost
            with patch.object(lifecycle, "_observe", side_effect=observe), \
                 patch.object(lifecycle.time, "monotonic", side_effect=lambda: clock[0]), \
                 patch.object(lifecycle.time, "sleep", side_effect=sleep), \
                 patch.object(os, "killpg", side_effect=group):
                code, error = None, None
                try:
                    if route == "default":
                        code = lifecycle.wait_owned_process_group(process, wall_seconds=30)
                    elif route == "selected":
                        code = lifecycle.wait_owned_process_group(process, wall_seconds=30, cleanup_seconds=allowance)
                    else:
                        code = adapters._wait_pdf_render_worker(process)
                except Exception as caught:
                    error = caught
            return code, error, clock[0] - 100, signals

    def test_default_two_seconds_and_selected_five_seconds_have_distinct_outcomes(self):
        """A terminal observation at three seconds exceeds only the default budget."""
        code, error, elapsed, signals = self.run_delayed_observation(route="default", visible_at=3)
        self.assertIsNone(code)
        self.assertIsInstance(error, subprocess.TimeoutExpired)
        self.assertEqual(error.timeout, 2)
        self.assertAlmostEqual(elapsed, 2)
        self.assertEqual(signals, [True])
        for allowance in (5, 5.0):
            with self.subTest(allowance=allowance):
                code, error, elapsed, signals = self.run_delayed_observation(
                    route="selected", visible_at=3, allowance=allowance)
                self.assertIsNone(error)
                self.assertEqual(code, 7)
                self.assertGreaterEqual(elapsed, 3)
                self.assertLess(elapsed, 3.02)
                self.assertEqual(signals, [True])

    def test_renderer_five_second_cleanup_accepts_terminal_observation_after_two_seconds(self):
        """Renderer integration must preserve five seconds instead of inheriting two."""
        code, error, elapsed, signals = self.run_delayed_observation(route="renderer", visible_at=3)
        self.assertIsNone(error)
        self.assertEqual(code, 7)
        self.assertGreaterEqual(elapsed, 3)
        self.assertLess(elapsed, 3.02)
        self.assertEqual(signals, [True])

    def test_earlier_cleanup_work_reduces_final_observation_budget(self):
        """A four-second group operation leaves one second of the original five."""
        code, error, elapsed, signals = self.run_delayed_observation(
            route="selected", visible_at=6, group_cost=4)
        self.assertIsNone(code)
        self.assertIsInstance(error, subprocess.TimeoutExpired)
        self.assertEqual(error.timeout, 5)
        self.assertAlmostEqual(elapsed, 5)
        self.assertEqual(signals, [True])

def descendant_probe(name, *, timeout=False):
    """Reap an orphaned fixture descendant in a disposable test-only subreaper."""
    if ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) != 0:
        raise RuntimeError("test subreaper unavailable")
    module = importlib.import_module("reporting." + name)
    descriptor = None
    descendant_reaped = False
    with tempfile.TemporaryDirectory() as directory:
        marker, release = Path(directory) / "child", Path(directory) / "release"
        script = (
            "import os,time\nfrom pathlib import Path\nchild=os.fork()\n"
            "if child == 0:\n time.sleep(8);os._exit(0)\n"
            "Path(" + repr(str(marker)) + ").write_text(str(child))\n"
            "deadline=time.monotonic()+5\n"
            "while not Path(" + repr(str(release)) + ").exists():\n"
            " if time.monotonic()>deadline:os._exit(71)\n time.sleep(0.005)\n"
            + ("time.sleep(30)\n" if timeout else "os._exit(0)\n")
        )
        try:
            with real_child(script) as process:
                deadline = time.monotonic() + 3
                while not marker.exists() or not marker.read_text():
                    if time.monotonic() >= deadline:
                        raise AssertionError("descendant readiness missing")
                    time.sleep(0.005)
                descendant = int(marker.read_text())
                descriptor = os.pidfd_open(descendant)
                if os.getpgid(descendant) != process.pid:
                    raise AssertionError("fixture descendant escaped group")
                release.touch()
                if not timeout:
                    observe_exit(process)
                observations = []
                with signal_observer(process, observations):
                    if name == "adapters":
                        try:
                            result = module._wait_pdf_render_worker(process, wall_seconds=0.02 if timeout else 1)
                        except RuntimeError as error:
                            if str(error) != "pdf_render_failed":
                                raise
                            result = str(error)
                    else:
                        result = module._wait(process)
                reaped = False
                try:
                    REAL_WAITID(os.P_PID, process.pid, WAIT_FLAGS)
                except ChildProcessError:
                    reaped = True
                exit_signal = None
                if select.select([descriptor], [], [], 1)[0]:
                    status = REAL_WAITID(os.P_PIDFD, descriptor, os.WEXITED)
                    descendant_reaped = True
                    if status.si_code == os.CLD_KILLED:
                        exit_signal = status.si_status
                return {"exit": result, "descendant_signal": exit_signal,
                        "owned": bool(observations) and all(item[1] for item in observations),
                        "reaped": reaped}
        finally:
            if descriptor is not None:
                try:
                    if not descendant_reaped:
                        try:
                            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        if not select.select([descriptor], [], [], 3)[0]:
                            raise RuntimeError("test descendant cleanup unresolved")
                        REAL_WAITID(os.P_PIDFD, descriptor, os.WEXITED)
                finally:
                    os.close(descriptor)


if __name__ == "__main__":
    unittest.main(verbosity=2)
