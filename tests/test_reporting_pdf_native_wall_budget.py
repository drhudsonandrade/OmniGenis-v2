"""Cumulative native deadlines at real launcher and owned-child wait boundaries."""
from contextlib import contextmanager
from hashlib import sha256
import os
import signal
import subprocess
import sys
import unittest
from unittest.mock import patch

from reporting import _pdf_native_launch_budget as budget
from reporting import pdf_object_graph as graph
from reporting import pdf_text_windows as text
from reporting import pdf_raster_windows as raster
from reporting.page_windows import plan_pdf_page_windows
from tests.test_reporting_pdf_native_launch_budget import launch_one, launch_specs


_REAL_POPEN = subprocess.Popen
_LAUNCHERS = ((graph, 0), (text, 21), (raster, 22))


class PdfNativeWallBudgetTests(unittest.TestCase):
    """Exercise real budget and lifecycle code with a deterministic clock only."""

    def setUp(self):
        self.pdf = b"%PDF-1.7\nSYNTHETIC_DEADLINE_BOUNDARY_ONLY\n"
        self.plan = plan_pdf_page_windows(
            pdf_sha256=sha256(self.pdf).hexdigest(), ir_sha256="b" * 64,
            page_count=1, admitted_page_budget=1, pages_per_window=16,
            inspector_profile_id="generated-pdf-text-window-v1")
        self.specs = launch_specs(self.plan)
        self.now = 0

    @contextmanager
    def scope(self):
        """Replace the external clock, retaining the real owner and launch ledger."""
        with patch.object(budget, "monotonic_ns", side_effect=lambda: self.now, create=True):
            with budget.NativeLaunchScope(self.plan, len(self.pdf)) as scope:
                yield scope

    @contextmanager
    def child(self, index, *, seconds=0.5):
        """Cross actual admission, substituting a sleeping command only at Popen."""
        def spawn(*args, **kwargs):
            return _REAL_POPEN(
                [sys.executable, "-I", "-c", f"import time; time.sleep({seconds!r})"],
                **kwargs)
        process = launch_one(self.specs[index], self.pdf, child=spawn)
        try:
            yield process
        finally:
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=2)

    def assert_reaped(self, process):
        """A wait failure must not leave the directly owned process unreaped."""
        self.assertIsNotNone(process.returncode)
        with self.assertRaises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)

    def test_expired_job_refuses_next_launch_before_popen(self):
        """The literal cumulative boundary rejects a fresh process attempt."""
        crossed = []
        with self.scope() as scope:
            self.now = 300_000_000_000
            with self.assertRaises(ValueError):
                launch_one(self.specs[0], self.pdf,
                           child=lambda *args, **kwargs: crossed.append(args))
            self.assertEqual(crossed, [])
            with self.assertRaises(ValueError):
                scope.require_complete()

    def test_expired_completed_schedule_cannot_be_accepted(self):
        """A complete attempt ledger still cannot return a late successful job."""
        with self.scope() as scope:
            for spec in self.specs:
                launch_one(spec, self.pdf)
            self.now = 300_000_000_000
            with self.assertRaises(ValueError):
                scope.complete_and_close()

    def test_each_wait_uses_only_the_shared_remaining_time(self):
        """Each concrete waiter kills/reaps a child at the remaining50ms budget."""
        for module, index in _LAUNCHERS:
            with self.subTest(launcher=module.__name__):
                self.now = 0
                with self.scope():
                    for spec in self.specs[:index]:
                        launch_one(spec, self.pdf)
                    with self.child(index) as process:
                        self.now = 299_950_000_000
                        with self.assertRaises(subprocess.TimeoutExpired):
                            module._wait(process)
                        self.assert_reaped(process)
                        self.assertEqual(process.returncode, -signal.SIGKILL)

    def test_expiry_after_spawn_still_cleans_and_reaps_each_child(self):
        """Deadline failure before waiting cannot bypass owned-child cleanup."""
        for module, index in _LAUNCHERS:
            with self.subTest(launcher=module.__name__):
                self.now = 0
                with self.scope():
                    for spec in self.specs[:index]:
                        launch_one(spec, self.pdf)
                    with self.child(index) as process:
                        self.now = 300_000_000_000
                        with self.assertRaises(ValueError):
                            module._wait(process)
                        self.assert_reaped(process)
                        self.assertEqual(process.returncode, -signal.SIGKILL)

    def test_successful_first_wait_does_not_reset_later_wait_budget(self):
        """Two individually short stages share the original cumulative deadline."""
        with self.scope():
            self.now = 295_000_000_000
            with self.child(0, seconds=0) as first:
                self.assertEqual(graph._wait(first), 0)
                self.assert_reaped(first)
            self.now = 299_950_000_000
            with self.child(1) as second:
                with self.assertRaises(subprocess.TimeoutExpired):
                    graph._wait(second)
                self.assert_reaped(second)


    def test_caller_coordinator_start_is_not_reset_by_scope_construction(self):
        """Construction late in a job retains the coordinator's original start."""
        self.now = 299_950_000_000
        with patch.object(budget, "monotonic_ns", side_effect=lambda: self.now):
            with budget.NativeLaunchScope(self.plan, len(self.pdf), started_ns=0):
                with self.child(0) as process:
                    with self.assertRaises(subprocess.TimeoutExpired):
                        graph._wait(process)
                    self.assert_reaped(process)

    def test_invalid_or_regressing_clock_poison_cannot_be_reset(self):
        """A later valid-looking clock cannot revive failed launch admission."""
        for invalid in (True, -1, 0, 1.5, "1"):
            with self.subTest(clock=invalid):
                self.now = 1
                with self.scope() as scope:
                    self.now = invalid
                    with self.assertRaises(ValueError):
                        launch_one(self.specs[0], self.pdf)
                    self.now = 1
                    with self.assertRaises(ValueError):
                        launch_one(self.specs[0], self.pdf)
                    with self.assertRaises(ValueError):
                        scope.complete_and_close()

    def test_clock_fault_after_spawn_still_cleans_owned_child(self):
        """Invalid and regressing observations cannot leak an already spawned child."""
        for invalid in (True, -1, 0, 1.5, "1"):
            with self.subTest(clock=invalid):
                self.now = 1
                with self.scope():
                    with self.child(0) as process:
                        self.now = invalid
                        with self.assertRaises(ValueError):
                            graph._wait(process)
                        self.assert_reaped(process)
                        self.assertEqual(process.returncode, -signal.SIGKILL)

    def test_clock_baseexception_after_spawn_still_cleans_owned_child(self):
        """An interrupted clock observation retains mandatory cleanup and failure."""
        with self.scope():
            with self.child(0) as process:
                with patch.object(budget, "monotonic_ns", side_effect=KeyboardInterrupt), \
                        self.assertRaises(KeyboardInterrupt):
                    graph._wait(process)
                self.assert_reaped(process)
                self.assertEqual(process.returncode, -signal.SIGKILL)

    def test_post_wait_deadline_refuses_completed_process(self):
        """A successful process cannot be accepted after wait/cleanup consumed the budget."""
        with self.scope():
            with self.child(0, seconds=0) as process:
                def clock():
                    return 300_000_000_000 if process.returncode is not None else 0
                with patch.object(budget, "monotonic_ns", side_effect=clock), \
                        self.assertRaises(ValueError):
                    graph._wait(process)
                self.assert_reaped(process)
                self.assertEqual(process.returncode, 0)

    def test_caught_wait_timeout_does_not_allow_later_launch(self):
        """Catching a timeout cannot continue the sequence with unused attempts."""
        with self.scope() as scope:
            with self.child(0) as process:
                self.now = 299_950_000_000
                with self.assertRaises(subprocess.TimeoutExpired):
                    graph._wait(process)
                self.assert_reaped(process)
            self.now = 299_960_000_000
            with self.assertRaises(ValueError):
                launch_one(self.specs[1], self.pdf)
            with self.assertRaises(ValueError):
                scope.complete_and_close()

    def test_shorter_stage_limit_remains_binding_for_every_waiter(self):
        """A large shared balance never expands an individual worker allowance."""
        for module, index in _LAUNCHERS:
            with self.subTest(launcher=module.__name__):
                self.now = 0
                with self.scope():
                    for spec in self.specs[:index]:
                        launch_one(spec, self.pdf)
                    with self.child(index) as process, patch.object(module, "WALL_SECONDS", 0.03):
                        with self.assertRaises(subprocess.TimeoutExpired) as caught:
                            module._wait(process)
                        self.assertEqual(caught.exception.timeout, 0.03)
                        self.assert_reaped(process)

    def test_standalone_success_does_not_require_native_clock(self):
        """Existing adapters outside a job retain successful owned-child behavior."""
        for module, index in _LAUNCHERS:
            with self.subTest(launcher=module.__name__), self.child(index, seconds=0) as process:
                with patch.object(budget, "monotonic_ns", side_effect=AssertionError("unexpected clock")):
                    self.assertEqual(module._wait(process), 0)
                self.assert_reaped(process)

    def test_standalone_timeout_keeps_stage_limit_and_cleanup(self):
        """No active job changes neither the stage deadline nor cleanup semantics."""
        for module, index in _LAUNCHERS:
            with self.subTest(launcher=module.__name__), self.child(index) as process:
                with patch.object(budget, "monotonic_ns", side_effect=AssertionError("unexpected clock")), \
                        patch.object(module, "WALL_SECONDS", 0.03):
                    with self.assertRaises(subprocess.TimeoutExpired) as caught:
                        module._wait(process)
                self.assertEqual(caught.exception.timeout, 0.03)
                self.assert_reaped(process)

    def test_invalid_start_never_leaves_an_active_scope(self):
        """Bad initial clocks fail before occupying the process-wide owner slot."""
        for invalid in (True, -1, 1.5, "1"):
            with self.subTest(clock=invalid):
                self.now = invalid
                with self.assertRaises(ValueError):
                    with self.scope():
                        self.fail("invalid clock activated a scope")
                budget.require_no_active_scope()
        self.now = 0
        with self.scope() as scope:
            for spec in self.specs:
                launch_one(spec, self.pdf)
            scope.complete_and_close()


if __name__ == "__main__":
    unittest.main()
