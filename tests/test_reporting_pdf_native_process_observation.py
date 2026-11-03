"""Opt-in direct native child records distinguish intent, spawn and observed exit."""
from hashlib import sha256
import inspect
import json
import os
import subprocess
import unittest
from unittest.mock import patch

from reporting import _pdf_native_launch_budget as budget
from reporting import pdf_native_source_job as native
from reporting.page_windows import plan_pdf_page_windows
from reporting.pdf_content import _expected_content
from tests.test_reporting_pdf_native_launch_budget import launch_one, launch_specs, ROLES
from tests.test_reporting_pdf_source_inspection_job import generated_job_case

REAL_POPEN = subprocess.Popen


class NativeProcessObservationTests(unittest.TestCase):
    """Real lifecycle tests plus isolated fail-closed registration negatives."""

    def setUp(self):
        """Require the optional API before using existing synthetic request fixtures."""
        self.assertIn("observe_processes", inspect.signature(budget.NativeLaunchScope).parameters)
        self.pdf = b"%PDF-1.7\nSYNTHETIC_OBSERVATION_NEGATIVE_ONLY\n"
        self.plan = plan_pdf_page_windows(pdf_sha256=sha256(self.pdf).hexdigest(), ir_sha256="b"*64,
            page_count=1, admitted_page_budget=1, pages_per_window=16,
            inspector_profile_id="generated-pdf-text-window-v1")

    def scope(self, **kwargs):
        """Enable only the optional observation on the already admitted one-page plan."""
        return budget.NativeLaunchScope(self.plan, len(self.pdf), observe_processes=True, **kwargs)

    def test_flag_has_exact_boolean_type(self):
        """Coercible flags must not silently activate new process observation."""
        for value in (None, 0, 1, "true", [], object()):
            with self.subTest(value=type(value).__name__), self.assertRaises(ValueError):
                budget.NativeLaunchScope(self.plan, len(self.pdf), observe_processes=value)

    def test_default_scope_has_no_observation_claim(self):
        """Legacy reservations remain valid, but cannot be returned as observed children."""
        with budget.NativeLaunchScope(self.plan, len(self.pdf)) as scope:
            for spec in launch_specs(self.plan):
                launch_one(spec, self.pdf)
            scope.complete_and_close()
        with self.assertRaises(ValueError):
            scope.process_ledger()

    def test_unstarted_and_incomplete_scopes_cannot_return_success(self):
        """An unexecuted schedule or merely closed context never proves completed children."""
        scope = self.scope()
        with self.assertRaises(ValueError):
            scope.process_ledger()
        with scope:
            with self.assertRaises(ValueError):
                scope.process_ledger()
        with self.assertRaises(ValueError):
            scope.process_ledger()

    def test_failed_spawn_cannot_create_an_observed_child(self):
        """A Popen error consumes its attempt without inventing a successful process."""
        def fail(*args, **kwargs):
            raise OSError("synthetic creation failure")
        with self.scope() as scope:
            with self.assertRaises(OSError):
                launch_one(launch_specs(self.plan)[0], self.pdf, child=fail)
            with self.assertRaises(ValueError):
                scope.complete_and_close()
        with self.assertRaises(ValueError):
            scope.process_ledger()

    def test_nonprocess_return_is_not_spawn_evidence(self):
        """A test double or unrelated object cannot satisfy optional observed execution."""
        with self.scope() as scope:
            with self.assertRaises(ValueError):
                launch_one(launch_specs(self.plan)[0], self.pdf)
        with self.assertRaises(ValueError):
            scope.process_ledger()

    def test_real_nonzero_child_exit_prevents_success_ledger(self):
        """Run the actual fixed worker on invalid PDF bytes and retain no success claim."""
        with self.scope() as scope:
            process = launch_one(launch_specs(self.plan)[0], self.pdf, child=REAL_POPEN)
            code = budget.wait_native_process_group(process, wall_seconds=10)
            self.assertNotEqual(code, 0)
            self.assertEqual(process.returncode, code)
            with self.assertRaises(ValueError):
                scope.complete_and_close()
        with self.assertRaises(ValueError):
            scope.process_ledger()

    def test_registration_fault_reaps_the_real_owned_child(self):
        """A post-spawn observation fault must not leak an actually created child."""
        seen = []
        def create(*args, **kwargs):
            process = REAL_POPEN(*args, **kwargs)
            seen.append(process)
            return process
        with self.scope(), patch.object(budget.NativeLaunchScope, "_record_spawn", side_effect=ValueError("observation rejected")):
            with self.assertRaises(ValueError):
                launch_one(launch_specs(self.plan)[0], self.pdf, child=create)
        self.assertEqual(len(seen), 1)
        self.assertIsNotNone(seen[0].returncode)
        with self.assertRaises(ChildProcessError):
            os.waitpid(seen[0].pid, os.WNOHANG)

    def test_unknown_waitable_identity_cannot_certify_spawn(self):
        """Reject an inconsistent ownership observation without assuming a live PID is ours."""
        from types import SimpleNamespace
        seen = []
        def create(*args, **kwargs):
            process = REAL_POPEN(*args, **kwargs)
            seen.append(process)
            return process
        try:
            with self.scope(), patch.object(budget.os, "waitid", return_value=SimpleNamespace(si_pid=1, si_code=os.CLD_EXITED)):
                with self.assertRaises(ChildProcessError):
                    launch_one(launch_specs(self.plan)[0], self.pdf, child=create)
        finally:
            for process in seen:
                try:
                    budget.wait_owned_process_group(process, wall_seconds=0)
                except subprocess.TimeoutExpired:
                    pass
        self.assertTrue(seen)
        self.assertTrue(all(p.returncode is not None for p in seen))

    def test_wait_on_unknown_object_refuses_before_observation(self):
        """A foreign process object cannot be treated as the current admitted child."""
        with self.scope(), patch.object(budget, "wait_owned_process_group") as wait:
            with self.assertRaises(ValueError):
                budget.wait_native_process_group(object(), wall_seconds=1)
            wait.assert_not_called()

    def test_second_launch_cannot_hide_an_unwaited_child(self):
        """An observed child must finish through the existing wait before another spawn."""
        process = None
        try:
            with self.scope():
                process = launch_one(launch_specs(self.plan)[0], self.pdf, child=REAL_POPEN)
                with self.assertRaises(ValueError):
                    launch_one(launch_specs(self.plan)[1], self.pdf, child=REAL_POPEN)
        finally:
            if process is not None:
                try:
                    budget.wait_owned_process_group(process, wall_seconds=0)
                except subprocess.TimeoutExpired:
                    # A zero wait deliberately refuses after bounded cleanup.
                    pass
        self.assertIsNotNone(process.returncode)

    def test_wait_does_not_signal_an_unrelated_owned_child(self):
        """Observation binding refusal cannot clean a different still-running child."""
        import sys
        process = REAL_POPEN([sys.executable, "-I", "-c", "import time;time.sleep(10)"],
                            start_new_session=True, stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            with self.scope():
                with self.assertRaises(ValueError):
                    budget.wait_native_process_group(process, wall_seconds=1)
                self.assertIsNone(process.poll())
        finally:
            process.terminate()
            process.wait(timeout=5)

    def test_real_one_page_job_has_exact_direct_stage_ledger(self):
        """A real one-page chain records twenty-three completed direct children."""
        self.assert_real_case(1, 23, 2)

    def test_real_33_page_job_has_exact_multirange_window_ledger(self):
        """A real long chain records all text/raster windows without claiming their children."""
        self.assert_real_case(33, 33, 42)

    def assert_real_case(self, pages, attempts, reserved):
        """Use the unchanged real renderer/native chain, not substituted child results."""
        ir, pdf = generated_job_case(pages)
        observed = []
        original = budget.NativeLaunchScope
        def activate(*args, **kwargs):
            scope = original(*args, observe_processes=True, **kwargs)
            observed.append(scope)
            return scope
        with patch.object(native, "NativeLaunchScope", side_effect=activate):
            result = native.execute_pdf_native_source_job(
                presentation_ir=ir, pdf_bytes=pdf, expected_pdf_sha256=sha256(pdf).hexdigest(),
                expected_ir_sha256=_expected_content(ir)[0], page_count=pages, expected_language="en-US",
                namespace_id="synthetic-namespace", job_id="synthetic-observed-native-job",
                request_sha256="c"*64, expected_resource_profile_sha256=native.PROFILE_SHA256)
        self.assertEqual(len(observed), 1)
        ledger = observed[0].process_ledger()
        self.assertEqual(ledger["schema"], "native-direct-process-observation/v1")
        self.assertEqual(ledger["state"], "COMPLETE_DIRECT_CHILDREN_OBSERVED")
        self.assertEqual(ledger["observed_spawns"], attempts)
        self.assertEqual(ledger["observed_exits"], attempts)
        self.assertEqual(ledger["reserved_nested_attempts_not_observed"], reserved)
        self.assertEqual(ledger["declared_retries"], 0)
        self.assertFalse(ledger["descendants_qualified"])
        self.assertFalse(ledger["aggregate_job_resources_qualified"])
        self.assertFalse(ledger["release_authorized"])
        entries = ledger["processes"]
        self.assertEqual([e["worker"] for e in entries[:21]], ["_pdf_"+r+"_worker.py" for r in ROLES])
        expected_windows = [[i, start, min(start+width-1, pages)]
                            for width in (16, 4) for i, start in enumerate(range(1, pages+1, width))]
        self.assertEqual([e["window"] for e in entries[21:]], expected_windows)
        self.assertTrue(all(e["exit_code"] == 0 and e["parent_pid"] == os.getpid() and e["pid"] != os.getpid() for e in entries))
        self.assertTrue(all(e["spawn_monotonic_ns"] <= e["exit_monotonic_ns"] for e in entries))
        for entry in entries:
            self.assertEqual(len(entry["request_header_sha256"]), 64)
        digest = ledger.pop("ledger_sha256")
        self.assertEqual(digest, sha256(json.dumps(ledger, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest())
        entries[0]["pid"] = -1
        self.assertNotEqual(observed[0].process_ledger()["processes"][0]["pid"], -1)
        self.assertEqual(result.to_dict()["pdf_sha256"], sha256(pdf).hexdigest())


if __name__ == "__main__":
    unittest.main()
