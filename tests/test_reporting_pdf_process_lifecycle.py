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


def descendant_probe(name):
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
            "os._exit(0)\n"
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
                observe_exit(process)
                observations = []
                with signal_observer(process, observations):
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
