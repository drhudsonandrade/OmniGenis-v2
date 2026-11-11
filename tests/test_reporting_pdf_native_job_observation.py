"""Explicit direct-child job observations without changing legacy results."""
from __future__ import annotations

from hashlib import sha256
import inspect
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from reporting import pdf_native_source_job as job
from reporting import _pdf_native_launch_budget as budget
from reporting.page_checkpoints import _json_bytes
from reporting.pdf_content import _expected_content
from tests import test_reporting_pdf_native_source_job as base_tests
from tests import test_reporting_pdf_source_inspection_job as source_tests


class NativeJobObservationTests(unittest.TestCase):
    """Only complete real direct launches may produce the optional sidecar."""

    fixtures = {}
    completed = {}

    def setUp(self):
        """Fail explicitly for the missing operation before any native fixture runs."""
        self.assertTrue(callable(getattr(job, "execute_observed_pdf_native_source_job", None)),
                        "explicit observed native-source job API is missing")
        self.helper = base_tests.PdfNativeSourceJobTests()
        self.helper.setUp()
        budget.require_no_active_scope()

    def args(self, pages=1, **changes):
        """Build exact expectations for one real generated synthetic candidate."""
        if pages not in self.fixtures:
            self.fixtures[pages] = source_tests.generated_job_case(pages)
        ir, pdf = self.fixtures[pages]
        return {**self.helper.args, "presentation_ir": json.loads(json.dumps(ir)),
                "pdf_bytes": pdf, "page_count": pages,
                "expected_pdf_sha256": sha256(pdf).hexdigest(),
                "expected_ir_sha256": _expected_content(ir)[0], **changes}

    def positive(self, pages=1):
        """Retain one actual native invocation per fixture, not a synthetic ledger."""
        if pages not in self.completed:
            pair = job.execute_observed_pdf_native_source_job(**self.args(pages))
            self.assertIs(type(pair), tuple)
            self.assertEqual(len(pair), 2)
            result, record = pair
            self.assertIs(type(result), job.PdfNativeSourceResult)
            self.assertIs(type(record), dict)
            for row in record["direct_process_ledger"]["processes"]:
                with self.assertRaises(ChildProcessError):
                    os.waitpid(row["pid"], os.WNOHANG)
            self.completed[pages] = result, _json_bytes(record)
        result, raw = self.completed[pages]
        return result, json.loads(raw)

    def test_real_one_33_and_64_pages_have_actual_complete_direct_records(self):
        """The real optional operation observes all direct spawns and successful reaps."""
        for pages in (1, 33, 64):
            with self.subTest(pages=pages):
                result, record = self.positive(pages)
                ledger = record["direct_process_ledger"]
                count = 21 + (pages + 15) // 16 + (pages + 3) // 4
                self.assertEqual(result.page_count, pages)
                self.assertEqual(record["state"], "COMPLETE_DIRECT_INSPECTION_JOB_OBSERVED")
                self.assertEqual(ledger["observed_spawns"], count)
                self.assertEqual(ledger["observed_exits"], count)
                self.assertEqual(len(ledger["processes"]), count)
                self.assertEqual([r["sequence"] for r in ledger["processes"]], list(range(count)))
                self.assertTrue(all(r["exit_code"] == 0 and type(r["exit_code"]) is int
                                    for r in ledger["processes"]))
                self.assertTrue(all(r["parent_pid"] == os.getpid() and r["pid"] > 1
                                    for r in ledger["processes"]))
                self.assertTrue(all(r["exit_monotonic_ns"] >= r["spawn_monotonic_ns"]
                                    for r in ledger["processes"]))

    def test_sidecar_binds_the_exact_result_document_plan_and_job(self):
        """A sidecar contains the actual result identity, not a caller-provided receipt."""
        result, record = self.positive()
        self.assertEqual(record["schema"], "native-source-job-process-observation/v1")
        self.assertEqual(record["inspection_sha256"], result.inspection_sha256)
        for name in ("pdf_sha256", "ir_sha256", "plan_sha256", "page_count", "namespace_id",
                     "job_id", "request_sha256", "resource_profile_sha256"):
            self.assertEqual(record[name], getattr(result, name), name)
        for row in record["direct_process_ledger"]["processes"]:
            for name in ("pdf_sha256", "ir_sha256", "page_count"):
                self.assertEqual(row[name], getattr(result, name))

    def test_window_records_retain_gap_free_stage_specific_ranges(self):
        """Text and raster observations retain their own complete window sequences."""
        _, record = self.positive(33)
        rows = record["direct_process_ledger"]["processes"]
        for kind, width in (("text_windows", 16), ("raster_windows", 4)):
            selected = [r for r in rows if r["kind"] == kind]
            self.assertEqual([r["window"] for r in selected],
                             [[i, first, min(first + width - 1, 33)]
                              for i, first in enumerate(range(1, 34, width))])
        self.assertEqual(len([r for r in rows if r["kind"] == "object_graph"]), 21)

    def test_sidecar_and_inner_ledger_digests_cover_detached_canonical_values(self):
        """Every detached byte representation can be checked without trusting its title."""
        _, record = self.positive()
        digest = record.pop("observation_sha256")
        self.assertEqual(sha256(_json_bytes(record)).hexdigest(), digest)
        ledger = record["direct_process_ledger"]
        nested = ledger.pop("ledger_sha256")
        self.assertEqual(sha256(_json_bytes(ledger)).hexdigest(), nested)

    def test_legacy_api_and_new_api_keep_the_same_ten_input_parameters(self):
        """No caller-selected executor, receipt, budget, tracing target or callback is added."""
        expected = set(self.helper.args)
        self.assertEqual(len(expected), 10)
        for function in (job.execute_pdf_native_source_job, job.execute_observed_pdf_native_source_job):
            self.assertEqual(set(inspect.signature(function).parameters), expected)
            self.assertTrue(all(p.kind == inspect.Parameter.KEYWORD_ONLY
                                for p in inspect.signature(function).parameters.values()))

    def test_legacy_result_bytes_are_unchanged_by_opt_in_observation(self):
        """The same real input yields the same legacy metadata, independent of observation."""
        observed, _ = self.positive()
        regular = job.execute_pdf_native_source_job(**self.args())
        self.assertIs(type(regular), job.PdfNativeSourceResult)
        self.assertEqual(regular.to_bytes(), observed.to_bytes())

    def test_legacy_path_never_requests_a_process_ledger(self):
        """Existing callers keep the original non-observing execution behavior."""
        with self.helper.mocked(), patch.object(budget.NativeLaunchScope, "process_ledger",
                side_effect=AssertionError("legacy call requested observation")):
            result = self.helper.run_job(page_count=1)
        self.assertIs(type(result), job.PdfNativeSourceResult)

    def test_opt_in_rejects_receipt_only_execution_without_launches(self):
        """Valid-looking child receipts cannot substitute for actually observed processes."""
        with self.helper.mocked(receipt_only=True), self.assertRaises(job.PdfNativeSourceJobError):
            job.execute_observed_pdf_native_source_job(**{**self.helper.args, "page_count": 1})
        budget.require_no_active_scope()

    def test_opt_in_rejects_synthetic_spawn_objects(self):
        """Non-observing test doubles never become actual observed launch evidence."""
        with self.helper.mocked(), self.assertRaises(job.PdfNativeSourceJobError):
            job.execute_observed_pdf_native_source_job(**{**self.helper.args, "page_count": 1})
        budget.require_no_active_scope()

    def test_invalid_admission_never_creates_an_observation_scope(self):
        """Unsupported inputs are refused before launching work or creating observation state."""
        cases = [{"pdf_bytes": None}, {"page_count": True}, {"page_count": 65},
                 {"expected_language": "pt-BR"}, {"expected_ir_sha256": "f" * 64},
                 {"request_sha256": "invalid"}, {"namespace_id": ""}]
        for changes in cases:
            with self.subTest(changes=changes), patch.object(job, "NativeLaunchScope",
                    side_effect=AssertionError("invalid input created scope")):
                with self.assertRaises(job.PdfNativeSourceJobError):
                    job.execute_observed_pdf_native_source_job(**{**self.helper.args, **changes})

    def test_all_existing_disables_apply_before_observed_execution(self):
        """The optional entry point must not bypass any inherited disable policy."""
        for flag in base_tests.DISABLES:
            with self.subTest(flag=flag), patch.dict(os.environ, {flag: "1"}), self.helper.mocked() as calls:
                with self.assertRaises(job.PdfNativeSourceJobError):
                    job.execute_observed_pdf_native_source_job(**self.helper.args)
                self.assertEqual(calls, [])

    def test_sidecar_export_failure_prevents_a_successful_pair(self):
        """An observer failure after real work must fail closed, not return only the result."""
        arguments = self.args()
        with patch.object(budget.NativeLaunchScope, "process_ledger",
                side_effect=OSError("SYNTHETIC_PRIVATE_FAILURE")):
            with self.assertRaisesRegex(job.PdfNativeSourceJobError,
                                        "^pdf_native_source_job_execution_failed$"):
                job.execute_observed_pdf_native_source_job(**arguments)
        budget.require_no_active_scope()

    def test_observation_export_baseexception_preserves_identity_and_clears_scope(self):
        """An interrupt remains an interrupt after real worker completion and scope cleanup."""
        failure = KeyboardInterrupt("synthetic interruption")
        arguments = self.args()
        with patch.object(budget.NativeLaunchScope, "process_ledger", side_effect=failure):
            with self.assertRaises(KeyboardInterrupt) as caught:
                job.execute_observed_pdf_native_source_job(**arguments)
        self.assertIs(caught.exception, failure)
        budget.require_no_active_scope()

    def test_sidecar_byte_ceiling_is_enforced_without_partial_return(self):
        """Exceeding the observation envelope does not relax the existing result ceiling."""
        self.assertEqual(job.MAX_OBSERVATION_BYTES, 65536)
        arguments = self.args()
        with patch.object(job, "MAX_OBSERVATION_BYTES", 1):
            with self.assertRaises(job.PdfNativeSourceJobError):
                job.execute_observed_pdf_native_source_job(**arguments)
        budget.require_no_active_scope()
        self.assertEqual(job.MAX_RESULT_BYTES, 304 * 1024)

    def test_detached_observation_cannot_mutate_the_retained_result(self):
        """Editing exported dictionaries cannot edit the sealed result or a future export."""
        result, record = self.positive()
        original = result.to_bytes()
        record["job_id"] = "foreign-job"
        record["direct_process_ledger"]["processes"].clear()
        self.assertEqual(result.to_bytes(), original)
        _, again = self.positive()
        self.assertNotEqual(again["job_id"], "foreign-job")
        self.assertEqual(len(again["direct_process_ledger"]["processes"]), 23)

    def test_sidecar_is_bounded_and_contains_no_source_or_pdf_content(self):
        """Observation metadata excludes input content and absolute worker locations."""
        _, record = self.positive(33)
        raw = _json_bytes(record)
        self.assertLessEqual(len(raw), 65536)
        self.assertNotIn(b"%PDF-1.7", raw)
        self.assertNotIn(str(Path(__file__).resolve().parents[1]).encode(), raw)
        self.assertNotIn(b"SYNTHETIC_CONTROL_FLOW_ONLY", raw)
        for row in record["direct_process_ledger"]["processes"]:
            self.assertEqual(Path(row["worker"]).name, row["worker"])

    def test_nonclaims_distinguish_reservations_from_real_direct_observations(self):
        """Direct-child data does not certify rendering, nested helpers or host resources."""
        _, record = self.positive(33)
        for name in ("generation_observed", "nested_processes_observed", "external_observer_measured",
                     "authenticated_worker_execution", "aggregate_job_resources_qualified",
                     "native_profile_qualified", "default_pipeline_activated", "release_authorized"):
            self.assertIs(record[name], False, name)
        ledger = record["direct_process_ledger"]
        self.assertEqual(ledger["reserved_nested_attempts_not_observed"], 42)
        self.assertEqual(ledger["declared_retries"], 0)
        self.assertFalse(ledger["descendants_qualified"])

    def test_result_mutation_during_sidecar_export_is_refused(self):
        """A changed retained result must not escape beside its earlier observation digest."""
        original = job._process_observation
        arguments = self.args()

        def mutate(result, scope):
            """Inject a retained-result mutation after the real observation is assembled."""
            record = original(result, scope)
            object.__setattr__(result, "job_id", "changed-after-observation")
            return record

        with patch.object(job, "_process_observation", side_effect=mutate):
            with self.assertRaises(job.PdfNativeSourceJobError):
                job.execute_observed_pdf_native_source_job(**arguments)
        budget.require_no_active_scope()

    def test_source_mutation_during_sidecar_export_is_refused(self):
        """Final source revalidation also covers work done while producing the sidecar."""
        original = job._process_observation
        arguments = self.args()

        def mutate(result, scope):
            """Change only this invocation's source after collecting actual observations."""
            record = original(result, scope)
            arguments["presentation_ir"]["report_id"] = "CHANGED-AFTER-OBSERVATION"
            return record

        with patch.object(job, "_process_observation", side_effect=mutate):
            with self.assertRaises(job.PdfNativeSourceJobError):
                job.execute_observed_pdf_native_source_job(**arguments)
        budget.require_no_active_scope()

    def test_disable_during_sidecar_export_is_refused(self):
        """A completed inspection does not authorize return after policy disables it."""
        original = job._process_observation
        arguments = self.args()

        def disable(result, scope):
            """Disable the unchanged profile immediately after constructing the sidecar."""
            record = original(result, scope)
            os.environ["OMNIGENIS_PDF_NATIVE_SOURCE_JOB_DISABLED"] = "1"
            return record

        with patch.dict(os.environ), patch.object(job, "_process_observation", side_effect=disable):
            with self.assertRaises(job.PdfNativeSourceJobError):
                job.execute_observed_pdf_native_source_job(**arguments)
        budget.require_no_active_scope()

    def test_existing_profile_and_limits_remain_unchanged(self):
        """Pin the current native dependency identity without activating or expanding resources."""
        self.assertEqual(job.PROFILE_SHA256,
                         "dd29be3ecc903308a9bbe8b44b1fdbb57e6b5d18e5dde6918738e4bce194038c")
        self.assertEqual(job.MAX_PAGES, 64)
        self.assertEqual(job.MAX_PDF_BYTES, 16 * 1024 * 1024)
        self.assertEqual(job.ACCEPTANCE_NS, 300_000_000_000)
        self.assertFalse(job.native_source_job_profile()["default_pipeline_activated"])


if __name__ == "__main__":
    unittest.main()
