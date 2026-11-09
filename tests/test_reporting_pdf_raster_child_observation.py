"""Owned-child and malformed-record controls for optional raster observations."""
from __future__ import annotations

from copy import deepcopy
import importlib
import importlib.util
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch


class RasterChildObservationTests(unittest.TestCase):
    """Exercise real waits while keeping synthetic record controls explicit."""

    def setUp(self):
        """Missing implementation is an assertion before creating any children."""
        self.assertIsNotNone(importlib.util.find_spec('reporting._pdf_raster_child_observation'),
                             'raster child observation implementation missing')
        self.m = importlib.import_module('reporting._pdf_raster_child_observation')

    def child(self, code):
        """Create and eventually reap only this test's own unprivileged child."""
        p = subprocess.Popen([sys.executable, '-I', '-B', '-c', code],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        def clean():
            """Prevent failed assertions from leaving owned children alive."""
            if p.poll() is None:
                p.kill()
            p.wait(timeout=3)
        self.addCleanup(clean)
        return p

    def test_actual_success_and_nonzero_waits_reap_once(self):
        """Actual exit status, rather than a caller-supplied success value, is returned."""
        for status in (0, 7):
            p = self.child('raise SystemExit(' + str(status) + ')')
            self.assertEqual(self.m.wait_owned_raster_child(p, wall_seconds=2), status)
            self.assertEqual(p.returncode, status)
            with self.assertRaises(ChildProcessError):
                os.waitpid(p.pid, os.WNOHANG)

    def test_real_timeout_kills_and_reaps_only_owned_child(self):
        """The optional wait preserves timeout failure after exact-child cleanup."""
        p = self.child('import time; time.sleep(30)')
        with self.assertRaises(subprocess.TimeoutExpired):
            self.m.wait_owned_raster_child(p, wall_seconds=0.02)
        self.assertEqual(p.returncode, -9)
        self.assertFalse(Path('/proc', str(p.pid)).exists())

    def test_reaped_child_is_refused_without_signal(self):
        """A reused numeric PID cannot be signaled after child ownership is lost."""
        p = self.child('pass'); p.wait(timeout=3)
        with patch.object(self.m.os, 'kill', side_effect=AssertionError('signaled')):
            with self.assertRaises(ChildProcessError):
                self.m.wait_owned_raster_child(p, wall_seconds=1)

    def test_foreign_object_is_refused_before_wait_or_signal(self):
        """A Popen-shaped mock cannot supply actual waitable-child evidence."""
        with patch.object(self.m.os, 'waitid', side_effect=AssertionError('waited')):
            for p in (None, Mock(pid=os.getpid()), object()):
                with self.assertRaises(ValueError):
                    self.m.wait_owned_raster_child(p, wall_seconds=1)

    def test_invalid_wait_budget_has_no_process_side_effect(self):
        """Nonfinite, boolean, negative and excessive waits fail before child access."""
        with patch.object(self.m.os, 'waitid', side_effect=AssertionError('waited')):
            for value in (None, True, -1, float('inf'), float('nan'), '1', 9):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    self.m.wait_owned_raster_child(None, wall_seconds=value)

    def test_interrupt_preserves_identity_after_cleanup(self):
        """BaseException identity is retained and cannot leave a live owned child."""
        p = self.child('import time; time.sleep(30)')
        original = self.m._wait_for_exit
        failure = KeyboardInterrupt('synthetic interrupt'); calls = []
        def interrupted(child, deadline):
            """Interrupt only the first wait, retaining actual cleanup afterwards."""
            if not calls:
                calls.append(True)
                raise failure
            return original(child, deadline)
        with patch.object(self.m, '_wait_for_exit', side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.m.wait_owned_raster_child(p, wall_seconds=1)
        self.assertIs(caught.exception, failure)
        self.assertEqual(p.returncode, -9)

    def test_invalid_page_schedules_are_refused(self):
        """An observed window is exactly one to four consecutive physical pages."""
        for pages in ((), None, [1], (True,), (0,), (513,), (1, 3), (2, 1), (1, 2, 3, 4, 5)):
            with self.subTest(pages=pages), self.assertRaises(ValueError):
                self.m.RasterChildObservation(pages)

    def test_empty_ledger_cannot_finish(self):
        """A reservation without actual children is not a completed observation."""
        value = self.m.RasterChildObservation((1,))
        with self.assertRaises(ValueError):
            value.finish()

    def test_closed_ledger_cannot_restart(self):
        """Closing an unfinished observation cannot manufacture completed evidence."""
        value = self.m.RasterChildObservation((1,)); value.close(); value.close()
        with self.assertRaises(ValueError):
            value.finish()

    def test_foreign_pid_poisoning(self):
        """A different process cannot finish or revive an owned observation."""
        value = self.m.RasterChildObservation((1,))
        with patch.object(self.m.os, 'getpid', return_value=os.getpid() + 1):
            with self.assertRaises(ValueError):
                value.finish()
        with self.assertRaises(ValueError):
            value.finish()

    def test_foreign_thread_poisoning(self):
        """Ownership includes the original thread object, not just its numeric ID."""
        value = self.m.RasterChildObservation((1,)); errors = []
        def foreign():
            """Capture the actual rejection in a second thread."""
            try: value.finish()
            except ValueError as exc: errors.append(exc)
        t = threading.Thread(target=foreign); t.start(); t.join(timeout=2)
        self.assertFalse(t.is_alive()); self.assertEqual(len(errors), 1)
        with self.assertRaises(ValueError): value.finish()

    def test_unregistered_process_cannot_be_waited(self):
        """The observation layer must not adopt another process by coincidence."""
        value = self.m.RasterChildObservation((1,))
        p = self.child('import time; time.sleep(30)')
        with self.assertRaises(ValueError): value.wait(p, wall_seconds=1)
        self.assertIsNone(p.poll())

    def test_nonprocess_spawn_is_rejected(self):
        """A synthetic success object cannot satisfy native launch evidence."""
        value = self.m.RasterChildObservation((1,))
        with self.assertRaises(ValueError):
            value.record_spawn(Mock(pid=123), ['synthetic'])
        with self.assertRaises(ValueError): value.finish()

    def test_wrong_command_does_not_become_a_probe(self):
        """A real unrelated owned child is not the fixed version-probe operation."""
        value = self.m.RasterChildObservation((1,))
        p = self.child('pass')
        with self.assertRaises(ValueError): value.record_spawn(p, p.args)
        with self.assertRaises(ValueError): value.finish()

    def test_unobserved_budget_retains_legacy_constructor_and_completion(self):
        """Existing default attempt accounting is not changed into execution evidence."""
        from reporting._pdf_raster_launch_budget import RasterLaunchBudget
        b = RasterLaunchBudget((1,)); self.assertFalse(b.observing)
        b.consume_probe(); b.consume_page(1); b.require_complete(); b.close()

    def test_observed_budget_rejects_invalid_flags(self):
        """Only a real boolean opt-in can allocate process observation state."""
        from reporting._pdf_raster_launch_budget import RasterLaunchBudget
        for value in (1, 0, None, 'true'):
            with self.assertRaises(ValueError): RasterLaunchBudget((1,), observe_processes=value)

    def test_observed_budget_reservations_cannot_complete(self):
        """Consumed allowances alone do not establish launches or successful exits."""
        from reporting._pdf_raster_launch_budget import RasterLaunchBudget
        b = RasterLaunchBudget((1,), observe_processes=True)
        b.consume_probe()
        with self.assertRaises(ValueError): b.require_complete()
        b.close()


    def test_registration_error_cleans_created_real_probe(self):
        """A clock failure after actual spawn cannot leak the newly created probe."""
        from reporting._pdf_raster_launch_budget import RasterLaunchBudget
        from reporting import _pdf_raster_probe as probe
        b=RasterLaunchBudget((1,),observe_processes=True);self.addCleanup(b.close)
        created=[];original=subprocess.Popen
        def spawn(*args,**kwargs):
            """Retain actual child handles while leaving process creation real."""
            p=original(*args,**kwargs);created.append(p);return p
        with patch.object(probe.subprocess,'Popen',side_effect=spawn), \
             patch.object(self.m.RasterChildObservation,'_clock',side_effect=ValueError('clock')):
            with self.assertRaises(ValueError):probe._run_probe(launch_budget=b)
        self.assertEqual(len(created),1);self.assertIsNotNone(created[0].returncode)
        self.assertFalse(Path('/proc',str(created[0].pid)).exists())

    def test_reaped_registered_probe_refuses_without_signaling(self):
        """The observer must reject externally consumed status rather than infer zero."""
        from reporting._pdf_raster_launch_budget import RasterLaunchBudget
        from reporting import _pdf_raster_probe as probe
        b=RasterLaunchBudget((1,),observe_processes=True);self.addCleanup(b.close)
        with tempfile.TemporaryFile() as output:
            p=probe._start(output,launch_budget=b);p.wait(timeout=3)
            with patch.object(self.m.os,'kill',side_effect=AssertionError('signaled')):
                with self.assertRaises(ChildProcessError):b.wait_observed(p,wall_seconds=3)
        with self.assertRaises(ValueError):b.require_complete()

    def test_pending_probe_blocks_next_page_attempt(self):
        """A consumed probe may not authorize a page before its actual exit is recorded."""
        from reporting._pdf_raster_launch_budget import RasterLaunchBudget
        from reporting import _pdf_raster_probe as probe
        b=RasterLaunchBudget((1,),observe_processes=True);self.addCleanup(b.close)
        with tempfile.TemporaryFile() as output:
            p=probe._start(output,launch_budget=b)
            try:
                with self.assertRaises(ValueError):b.consume_page(1)
            finally:self.m.cleanup_created_child(p)
        with self.assertRaises(ValueError):b.require_complete()

    def test_duplicate_registration_poisons_and_reaps(self):
        """One real child cannot create a second observed launch record."""
        from reporting._pdf_raster_launch_budget import RasterLaunchBudget
        from reporting import _pdf_raster_probe as probe
        b=RasterLaunchBudget((1,),observe_processes=True);self.addCleanup(b.close)
        with tempfile.TemporaryFile() as output:
            p=probe._start(output,launch_budget=b)
            with self.assertRaises(ValueError):b.record_spawn(p,p.args)
            self.assertIsNotNone(p.returncode)
        with self.assertRaises(ValueError):b.require_complete()

    def test_real_page_failure_does_not_complete_observation(self):
        """A real invalid raster input consumes its attempt but cannot export success."""
        from reporting._pdf_raster_launch_budget import RasterLaunchBudget
        from reporting import _pdf_raster_probe as probe, _pdf_raster_window_worker as worker
        b=RasterLaunchBudget((1,),observe_processes=True);self.addCleanup(b.close)
        probe._run_probe(launch_budget=b)
        with tempfile.TemporaryDirectory() as td:
            source=Path(td)/'candidate.pdf';source.write_bytes(b'not a PDF')
            with self.assertRaises(ValueError):
                worker._raster_page('/usr/bin/pdftoppm',source,Path(td)/'page-1',1,launch_budget=b)
        with self.assertRaises(ValueError):b.require_complete()


    def test_budget_cannot_cleanup_an_unregistered_child(self):
        """A caller passing another owned child must not turn rejection into its termination."""
        from reporting._pdf_raster_launch_budget import RasterLaunchBudget
        b=RasterLaunchBudget((1,),observe_processes=True);self.addCleanup(b.close)
        p=self.child('import time; time.sleep(30)')
        with self.assertRaises(ValueError):b.wait_observed(p,wall_seconds=1)
        self.assertIsNone(p.poll(),'unregistered child was signaled during refusal')

    def test_foreign_thread_cannot_cleanup_a_registered_child(self):
        """Foreign-thread use poisons the ledger without acquiring cleanup authority."""
        from reporting._pdf_raster_launch_budget import RasterLaunchBudget
        b=RasterLaunchBudget((1,),observe_processes=True);self.addCleanup(b.close)
        p=self.child('import time; time.sleep(30)');errors=[]
        def foreign():
            """A second thread attempts a wait but must not signal the creator child."""
            try:b.wait_observed(p,wall_seconds=1)
            except ValueError as exc:errors.append(exc)
        t=threading.Thread(target=foreign);t.start();t.join(timeout=3)
        self.assertFalse(t.is_alive());self.assertEqual(len(errors),1)
        self.assertIsNone(p.poll(),'foreign thread acquired cleanup authority')


if __name__ == '__main__':
    unittest.main()
