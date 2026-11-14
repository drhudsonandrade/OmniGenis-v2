"""Actual generated-job direct-process observations preserve legacy candidates."""
from __future__ import annotations

from hashlib import sha256
import inspect
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from reporting import pdf_generated_source_job as job
from tests import test_reporting_pdf_generated_source_job as existing
from tests import test_reporting_pdf_native_source_job as native_tests


def canonical(value):
    """Independently encode the established deterministic metadata contract."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def reseal(record, key="observation_sha256"):
    """Rehash a deliberately modified test record without making it truthful."""
    record.pop(key, None)
    record[key] = sha256(canonical(record)).hexdigest()


class GeneratedJobObservationTests(unittest.TestCase):
    """Observed generation must use actual owned children and complete acceptance."""

    completed = {}

    def setUp(self):
        """Fail on missing behavior before constructing an expensive native case."""
        self.assertTrue(callable(getattr(job, "execute_observed_pdf_generated_source_job", None)),
                        "explicit observed generated-source job API is missing")
        self.helper = existing.GeneratedSourceJobTests()
        self.helper.setUp()

    def arguments(self, count=2, **changes):
        """Use known admitted synthetic sources rather than caller-provided receipts."""
        return self.helper.arguments(existing.source(count), **changes)

    def run_job(self, **changes):
        """Execute the real optional public boundary with independently bound inputs."""
        return job.execute_observed_pdf_generated_source_job(**self.arguments(**changes))

    def positive(self, count=2):
        """Retain one actual complete invocation for each small or natural long source."""
        if count not in type(self).completed:
            args = self.arguments(count)
            before = canonical(args["presentation_ir"])
            pair = job.execute_observed_pdf_generated_source_job(**args)
            self.assertIs(type(pair), tuple)
            self.assertEqual(len(pair), 2)
            result, record = pair
            self.assertIs(type(result), job.PdfGeneratedSourceResult)
            self.assertIs(type(record), dict)
            self.assertEqual(canonical(args["presentation_ir"]), before)
            for row in [record["render_process"], *record["native_observation"]["direct_process_ledger"]["processes"]]:
                with self.assertRaises(ChildProcessError):
                    os.waitpid(row["pid"], os.WNOHANG)
            type(self).completed[count] = result, canonical(record)
        result, raw = type(self).completed[count]
        return result, json.loads(raw)

    def rescue(self, process):
        """Retire only a test-owned child if a failing assertion exposed a regression."""
        if process.returncode is None:
            try:
                job._wait_pdf_render_worker(process, wall_seconds=0)
            except Exception:
                pass

    def assert_spawn_fault_reaped(self, failure):
        """Observe cleanup before the independent test rescue can mask a missing reap."""
        original = job._start_pdf_render_worker
        children = []

        def capture(*args, **kwargs):
            process = original(*args, **kwargs)
            children.append(process)
            self.addCleanup(self.rescue, process)
            return process

        expected = KeyboardInterrupt if isinstance(failure, KeyboardInterrupt) else job.PdfGeneratedSourceJobError
        with patch.object(job, "_start_pdf_render_worker", side_effect=capture), \
                patch.object(job, "_observe_render_spawn", side_effect=failure):
            with self.assertRaises(expected) as caught:
                self.run_job()
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)
        with self.assertRaises(ChildProcessError):
            os.waitpid(children[0].pid, os.WNOHANG)
        if isinstance(failure, KeyboardInterrupt):
            self.assertIs(caught.exception, failure)

    def test_actual_render_and_native_children_are_observed_for_short_and_long_source(self):
        """Natural generation must observe the renderer plus every direct inspector."""
        for count in (2, 1680):
            with self.subTest(count=count):
                result, record = self.positive(count)
                if count == 2:
                    self.assertEqual(result.page_count, 1)
                else:
                    self.assertGreater(result.page_count, 32)
                    self.assertLessEqual(result.page_count, 64)
                expected = 1 + 21 + (result.page_count + 15) // 16 + (result.page_count + 3) // 4
                self.assertEqual(record["observed_direct_spawns"], expected)
                self.assertEqual(record["observed_direct_exits"], expected)
                render = record["render_process"]
                self.assertEqual(render["kind"], "render")
                self.assertEqual(render["parent_pid"], os.getpid())
                self.assertGreater(render["pid"], 1)
                self.assertEqual(render["exit_code"], 0)
                self.assertGreaterEqual(render["exit_monotonic_ns"], render["spawn_monotonic_ns"])
                rows = record["native_observation"]["direct_process_ledger"]["processes"]
                self.assertEqual(len(rows), expected - 1)
                self.assertTrue(all(row["spawn_monotonic_ns"] >= render["exit_monotonic_ns"] for row in rows))
                self.assertTrue(all(row["parent_pid"] == os.getpid() and row["exit_code"] == 0 for row in rows))

    def test_stage_identity_and_worker_source_hashes_are_bound(self):
        """Render, native inspection and final result must identify the same source job."""
        result, record = self.positive()
        self.assertEqual(record["schema"], "generated-source-job-process-observation/v1")
        self.assertEqual(record["state"], "DIRECT_GENERATED_JOB_PROCESSES_OBSERVED")
        self.assertEqual(record["generated_result_sha256"], result.result_sha256)
        for key in ("ir_sha256", "html_sha256", "plan_sha256", "namespace_id", "job_id",
                    "request_sha256", "resource_profile_sha256"):
            self.assertEqual(record[key], getattr(result, key))
        self.assertEqual(record["pdf_sha256"], sha256(result.pdf_bytes).hexdigest())
        self.assertEqual(record["page_count"], result.page_count)
        row = record["render_process"]
        self.assertEqual(row["worker"], "_pdf_render_worker.py")
        worker = Path(job.__file__).with_name("_pdf_render_worker.py")
        self.assertEqual(row["worker_source_sha256"], sha256(worker.read_bytes()).hexdigest())
        self.assertEqual(row["request_header_sha256"], sha256(f"2 {result.html_sha256}\n".encode()).hexdigest())
        self.assertEqual(row["html_sha256"], result.html_sha256)
        self.assertEqual(row["pdf_sha256"], result.pdf_sha256)
        self.assertEqual(row["render_sha256"], result.expected_render_sha256)
        self.assertEqual(record["native_observation"]["inspection_sha256"], result.expected_inspection_sha256)

    def test_canonical_digests_cover_all_observation_layers(self):
        """Detached hashes bind the complete metadata, not only summary counts."""
        _, record = self.positive()
        for value, key in ((record, "observation_sha256"),
                           (record["render_process"], "observation_sha256"),
                           (record["native_observation"], "observation_sha256"),
                           (record["native_observation"]["direct_process_ledger"], "ledger_sha256")):
            detached = json.loads(canonical(value))
            digest = detached.pop(key)
            self.assertEqual(sha256(canonical(detached)).hexdigest(), digest)

    def test_complete_page_window_coverage_agrees_with_final_document(self):
        """Every observed text/raster window retains its exact final-artifact range."""
        result, record = self.positive(1680)
        rows = record["native_observation"]["direct_process_ledger"]["processes"]
        for kind, width in (("text_windows", 16), ("raster_windows", 4)):
            selected = [row for row in rows if row["kind"] == kind]
            self.assertEqual([row["window"] for row in selected],
                             [[i, first, min(first + width - 1, result.page_count)]
                              for i, first in enumerate(range(1, result.page_count + 1, width))])
            self.assertTrue(all(row["pdf_sha256"] == result.pdf_sha256 for row in selected))

    def test_legacy_results_and_pdf_bytes_remain_identical(self):
        """Observation must not rewrite the generated candidate or result wire."""
        observed, _ = self.positive()
        legacy = job.execute_pdf_generated_source_job(**self.arguments())
        self.assertIs(type(legacy), job.PdfGeneratedSourceResult)
        self.assertEqual(legacy.to_bytes(), observed.to_bytes())
        self.assertEqual(legacy.pdf_bytes, observed.pdf_bytes)

    def test_legacy_path_never_enables_observation(self):
        """Unchanged callers must not acquire the optional observation failure surface."""
        with patch.object(job, "_observe_render_spawn", side_effect=AssertionError("legacy observation")), \
                patch.object(job.native_source, "execute_observed_pdf_native_source_job",
                             side_effect=AssertionError("legacy native observation")):
            result = job.execute_pdf_generated_source_job(**self.arguments())
        self.assertIs(type(result), job.PdfGeneratedSourceResult)

    def test_public_inputs_do_not_accept_worker_budget_or_receipt(self):
        """The optional API retains the exact seven keyword-only source expectations."""
        expected = set(self.arguments())
        self.assertEqual(len(expected), 7)
        for function in (job.execute_pdf_generated_source_job, job.execute_observed_pdf_generated_source_job):
            parameters = inspect.signature(function).parameters
            self.assertEqual(set(parameters), expected)
            self.assertTrue(all(p.kind == inspect.Parameter.KEYWORD_ONLY for p in parameters.values()))
        for extra in ("pdf_bytes", "page_count", "worker", "observer", "receipt", "budget"):
            with self.subTest(extra=extra), self.assertRaises(TypeError):
                job.execute_observed_pdf_generated_source_job(**self.arguments(), **{extra: None})

    def test_all_inherited_disables_refuse_before_a_child_can_start(self):
        """Optional observation may not bypass any existing enablement policy."""
        for flag in ("OMNIGENIS_PDF_GENERATED_SOURCE_JOB_DISABLED", "OMNIGENIS_PDF_RENDERER_DISABLED", *native_tests.DISABLES):
            with self.subTest(flag=flag), patch.dict(os.environ, {flag: "1"}), \
                    patch.object(job, "_start_pdf_render_worker", side_effect=AssertionError("unexpected spawn")):
                with self.assertRaisesRegex(job.PdfGeneratedSourceJobError, "^pdf_generated_source_job_input_invalid$"):
                    self.run_job()

    def test_invalid_input_refuses_before_rendering(self):
        """Wrong source identity, locale or job expectation must consume no render child."""
        for changes in ({"expected_ir_sha256": "0" * 64}, {"expected_language": "pt-BR"},
                        {"namespace_id": ""}, {"job_id": ""}, {"expected_resource_profile_sha256": "0" * 64}):
            with self.subTest(changes=changes), \
                    patch.object(job, "_start_pdf_render_worker", side_effect=AssertionError("unexpected spawn")):
                with self.assertRaisesRegex(job.PdfGeneratedSourceJobError, "^pdf_generated_source_job_input_invalid$"):
                    self.run_job(**changes)

    def test_nonprocess_spawn_result_is_not_observed_or_signaled(self):
        """A success-looking foreign object must never reach owned-child waiting."""
        with patch.object(job, "_start_pdf_render_worker", return_value=object()), \
                patch.object(job, "_wait_pdf_render_worker") as wait:
            with self.assertRaises(job.PdfGeneratedSourceJobError):
                self.run_job()
        wait.assert_not_called()

    def test_spawn_observer_error_reaps_actual_child_before_return(self):
        """A failed observation after real creation cannot orphan the renderer."""
        self.assert_spawn_fault_reaped(OSError("synthetic observer fault"))

    def test_spawn_observer_interrupt_reaps_child_and_preserves_interrupt(self):
        """An interrupt must propagate only after the actual child is retired."""
        self.assert_spawn_fault_reaped(KeyboardInterrupt("synthetic observer interruption"))

    def test_render_failure_cannot_return_observed_success(self):
        """A nonzero renderer outcome stays a refusal after actual cleanup."""
        original = job._wait_pdf_render_worker

        def nonzero(process, **kwargs):
            original(process, **kwargs)
            return 1

        with patch.object(job, "_wait_pdf_render_worker", side_effect=nonzero):
            with self.assertRaises(job.PdfGeneratedSourceJobError):
                self.run_job()

    def corrupt_native(self, modifier):
        """Inject a changed record only after its genuine native job completed."""
        original = job.native_source.execute_observed_pdf_native_source_job

        def altered(**kwargs):
            result, record = original(**kwargs)
            modifier(record)
            return result, record

        with patch.object(job.native_source, "execute_observed_pdf_native_source_job", side_effect=altered):
            with self.assertRaises(job.PdfGeneratedSourceJobError):
                self.run_job()

    def test_changed_native_observation_digest_is_rejected(self):
        """Metadata mutation cannot cross the final generator with an old digest."""
        self.corrupt_native(lambda value: value.update(job_id="foreign-job"))

    def test_rehashed_foreign_native_identity_is_rejected(self):
        """A correct hash does not make another job's metadata applicable."""
        def change(value):
            value["job_id"] = "foreign-job"
            reseal(value)
        self.corrupt_native(change)

    def test_rehashed_wrong_native_counts_are_rejected(self):
        """Reserved or invented extra launches cannot inflate direct observations."""
        def change(value):
            value["direct_process_ledger"]["observed_spawns"] += 1
            reseal(value["direct_process_ledger"], "ledger_sha256")
            reseal(value)
        self.corrupt_native(change)

    def test_export_failure_after_completed_job_returns_no_pair(self):
        """Successful rendering/inspection cannot hide a failed observation export."""
        with patch.object(job, "_generated_process_observation", side_effect=OSError("SYNTHETIC_PRIVATE_FAILURE")):
            with self.assertRaisesRegex(job.PdfGeneratedSourceJobError, "^pdf_generated_source_job_execution_failed$"):
                self.run_job()

    def test_source_mutation_during_export_is_rejected(self):
        """The final source check must include time spent building the observation."""
        original = job._generated_process_observation
        arguments = self.arguments()
        def mutate(result, *records):
            value = original(result, *records)
            arguments["presentation_ir"]["report_id"] = "CHANGED-AFTER-OBSERVATION"
            return value
        with patch.object(job, "_generated_process_observation", side_effect=mutate):
            with self.assertRaises(job.PdfGeneratedSourceJobError):
                job.execute_observed_pdf_generated_source_job(**arguments)

    def test_result_mutation_during_export_is_rejected(self):
        """A retained result cannot change after the observation's result hash is bound."""
        original = job._generated_process_observation
        def mutate(result, *records):
            value = original(result, *records)
            object.__setattr__(result, "job_id", "changed-after-observation")
            return value
        with patch.object(job, "_generated_process_observation", side_effect=mutate):
            with self.assertRaises(job.PdfGeneratedSourceJobError):
                self.run_job()

    def test_disable_during_export_is_rejected(self):
        """A finished inspection never permits a return after the policy disables it."""
        original = job._generated_process_observation
        def disable(result, *records):
            value = original(result, *records)
            os.environ["OMNIGENIS_PDF_GENERATED_SOURCE_JOB_DISABLED"] = "1"
            return value
        with patch.dict(os.environ), patch.object(job, "_generated_process_observation", side_effect=disable):
            with self.assertRaises(job.PdfGeneratedSourceJobError):
                self.run_job()

    def test_sidecar_byte_limit_does_not_relax_result_budget(self):
        """Oversized observations are refused, not silently truncated or returned alone."""
        with patch.object(job, "MAX_OBSERVATION_BYTES", 1):
            with self.assertRaises(job.PdfGeneratedSourceJobError):
                self.run_job()
        result, record = self.positive(1680)
        self.assertLessEqual(len(canonical(record)), 98304)
        self.assertLessEqual(len(result.to_bytes()), 327680)

    def test_observation_is_detached_and_content_free(self):
        """Returned process data cannot mutate sealed bytes or expose input content."""
        result, record = self.positive()
        raw = canonical(record)
        self.assertNotIn(b"%PDF-", raw)
        self.assertNotIn(b"Observation 0001:", raw)
        self.assertNotIn(str(Path(job.__file__).resolve().parent).encode(), raw)
        before = result.to_bytes()
        record["render_process"]["pid"] = 0
        record["native_observation"]["direct_process_ledger"]["processes"].clear()
        self.assertEqual(result.to_bytes(), before)

    def test_direct_observation_does_not_claim_descendant_or_host_qualification(self):
        """Observed renderer/direct inspectors do not certify all helpers or release."""
        result, record = self.positive(1680)
        self.assertTrue(record["render_direct_child_observed"])
        for key in ("nested_processes_observed", "external_observer_measured", "whole_graph_observed",
                    "authenticated_worker_execution", "aggregate_job_resources_qualified",
                    "native_profile_qualified", "default_pipeline_activated", "release_authorized"):
            self.assertIs(record[key], False, key)
        self.assertEqual(record["declared_retries"], 0)
        ledger = record["native_observation"]["direct_process_ledger"]
        self.assertEqual(ledger["reserved_nested_attempts_not_observed"],
                         (result.page_count + 3) // 4 + result.page_count)
        self.assertLess(len(result.pdf_bytes), 8 * 1024 * 1024)

    def test_binary_identifier_observation_preserves_exact_candidate(self):
        """The original binary-ID source is observed once without rewriting its PDF."""
        arguments = self.arguments(count=1)
        before = canonical(arguments["presentation_ir"])
        default = existing.adapters.build_html_css_and_pdf_adapter(
            presentation_ir=arguments["presentation_ir"])
        self.assertTrue(default.passed, default.errors)
        original = job.native_source.execute_observed_pdf_native_source_job
        with patch.object(job.native_source, "execute_observed_pdf_native_source_job",
                          wraps=original) as native:
            try:
                result, record = job.execute_observed_pdf_generated_source_job(**arguments)
            except job.PdfGeneratedSourceJobError as exc:
                self.fail("valid binary-ID observation refused: " + str(exc))
        native.assert_called_once()
        self.assertEqual(result.pdf_bytes, default.pdf_bytes)
        self.assertEqual(record["pdf_sha256"], sha256(default.pdf_bytes).hexdigest())
        self.assertEqual(record["generated_result_sha256"], result.result_sha256)
        self.assertEqual(record["declared_retries"], 0)
        self.assertEqual(canonical(arguments["presentation_ir"]), before)

    def test_native_inspection_failure_is_not_repaired_or_retried(self):
        """An injected native failure still propagates without a successful pair."""
        with patch.object(job.native_source, "execute_observed_pdf_native_source_job",
                          side_effect=job.native_source.PdfNativeSourceJobError(
                              "pdf_native_source_job_execution_failed")) as native:
            with self.assertRaisesRegex(job.PdfGeneratedSourceJobError,
                                        "^pdf_generated_source_job_execution_failed$"):
                self.run_job(count=1)
        native.assert_called_once()


if __name__ == "__main__":
    unittest.main()
