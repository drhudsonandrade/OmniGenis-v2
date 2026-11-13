"""Actual direct-process observations belong to the same qualification attempt."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from hashlib import sha256
import inspect
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from reporting import pdf_generated_source_job as generated
from reporting import pdf_qualification_job as job
from reporting import _pdf_job_durable_receipt as receipts
from tests import test_reporting_pdf_generated_source_job as fixtures

MODE = "OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE"
DISABLE = "OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED"


class ObservedQualificationJobTests(unittest.TestCase):
    """Keep direct observations, computation completion and release distinct."""

    cases = {}

    def setUp(self):
        """Assert the missing API before creating any filesystem/native fixture."""
        self.assertTrue(callable(getattr(job, "execute_observed_receipted_pdf_generated_source_job", None)),
                        "observed receipted qualification API is missing")
        self.env = patch.dict(os.environ, {MODE: "qualification-only"})
        self.env.start()
        self.addCleanup(self.env.stop)
        os.environ.pop(DISABLE, None)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.run_id = "a" * 32
        self.helper = fixtures.GeneratedSourceJobTests()
        self.helper.setUp()

    def arguments(self, count=2, **changes):
        """Use independently bound synthetic inputs from the existing generator."""
        return {**self.helper.arguments(fixtures.source(count)),
                "receipt_directory": self.root, "run_id": self.run_id, **changes}

    def execute(self, **changes):
        """Exercise only the explicit fixed observed qualification entrypoint."""
        return job.execute_observed_receipted_pdf_generated_source_job(**self.arguments(**changes))

    def real_pair(self):
        """Reuse actual native results for isolated orchestration fault injection."""
        if 2 not in type(self).cases:
            type(self).cases[2] = generated.execute_observed_pdf_generated_source_job(
                **self.helper.arguments(fixtures.source(2)))
        result, observation = type(self).cases[2]
        return result, deepcopy(observation)

    def stored(self, run_id=None):
        """Read only the original v1 content-free computation receipt."""
        rid = run_id or self.run_id
        return self.root / rid / (rid + ".json")

    def patch_pair(self, pair=None):
        """Mock the fixed generator only for non-native orchestration failures."""
        return patch.object(generated, "execute_observed_pdf_generated_source_job",
                            return_value=self.real_pair() if pair is None else pair)

    def assert_failed(self, run_id=None):
        """A precommit failure cannot retain a successful result digest."""
        value = json.loads(self.stored(run_id).read_bytes())
        self.assertEqual(value["state"], "FAILED")
        self.assertIsNone(value["result_sha256"])
        self.assertIs(value["release_authorized"], False)

    def resign(self, record, field="observation_sha256"):
        """Rehash synthetic mutations to test semantic rather than hash-only checks."""
        record[field] = sha256(generated._json_bytes({k: v for k, v in record.items() if k != field})).hexdigest()

    def test_actual_short_and_long_attempts_bind_processes_and_durable_result(self):
        """Real generation and inspection produce matching result/observation/receipt."""
        for count in (2, 1680):
            rid = sha256(str(count).encode()).hexdigest()[:32]
            with self.subTest(count=count):
                result, observation, outcome = self.execute(count=count, run_id=rid)
                type(self).cases[count] = (result, deepcopy(observation))
                self.assertIs(type(result), generated.PdfGeneratedSourceResult)
                self.assertEqual(outcome["result_sha256"], result.result_sha256)
                self.assertEqual(observation["generated_result_sha256"], result.result_sha256)
                self.assertEqual(outcome["run_id"], rid)
                self.assertEqual(outcome, receipts.read_job_receipt(self.root / rid, rid, "SUCCEEDED", result.result_sha256))
                self.assertEqual(result.pdf_sha256, sha256(result.pdf_bytes).hexdigest())
                self.assertEqual(result.page_count, 1) if count == 2 else self.assertGreater(result.page_count, 32)
                expected = 22 + (result.page_count + 15) // 16 + (result.page_count + 3) // 4
                self.assertEqual(observation["observed_direct_spawns"], expected)
                self.assertEqual(observation["observed_direct_exits"], expected)
                render = observation["render_process"]
                rows = observation["native_observation"]["direct_process_ledger"]["processes"]
                self.assertEqual(render["parent_pid"], os.getpid())
                self.assertEqual(render["exit_code"], 0)
                self.assertTrue(all(row["parent_pid"] == os.getpid() and row["exit_code"] == 0 for row in rows))
                self.assertTrue(all(row["spawn_monotonic_ns"] >= render["exit_monotonic_ns"] for row in rows))
                for kind, width in (("text_windows", 16), ("raster_windows", 4)):
                    selected = [row for row in rows if row["kind"] == kind]
                    self.assertEqual([row["window"] for row in selected],
                                     [[i, start, min(start + width - 1, result.page_count)]
                                      for i, start in enumerate(range(1, result.page_count + 1, width))])
                self.assertEqual(list((self.root / rid).iterdir()), [self.stored(rid)])
                self.assertLessEqual(len(self.stored(rid).read_bytes()), receipts.MAX_RECEIPT_BYTES)

    def test_legacy_qualification_never_invokes_optional_observer(self):
        """The previous API preserves its pair and existing failure surface."""
        result, _ = self.real_pair()
        with patch.object(generated, "execute_pdf_generated_source_job", return_value=result) as legacy, \
             patch.object(generated, "execute_observed_pdf_generated_source_job", side_effect=AssertionError("observer called")):
            pair = job.execute_receipted_pdf_generated_source_job(**self.arguments())
        self.assertEqual(len(pair), 2)
        self.assertIs(pair[0], result)
        self.assertEqual(pair[1]["result_sha256"], result.result_sha256)
        self.assertEqual(legacy.call_count, 1)

    def test_observed_variant_uses_only_the_fixed_observed_generator(self):
        """No unobserved replay or second generator call fills a missing observation."""
        with self.patch_pair() as observed, \
             patch.object(generated, "execute_pdf_generated_source_job", side_effect=AssertionError("unobserved replay")):
            self.execute()
        self.assertEqual(observed.call_count, 1)

    def test_default_disable_and_unknown_policy_refuse_before_claim(self):
        """Invalid policy cannot allocate storage or consume any native execution."""
        for mode, disabled in ((None, None), ("qualification-only", "1"), ("supported", None)):
            with self.subTest(mode=mode, disabled=disabled), patch.dict(os.environ):
                os.environ.pop(MODE, None)
                os.environ.pop(DISABLE, None)
                if mode is not None: os.environ[MODE] = mode
                if disabled is not None: os.environ[DISABLE] = disabled
                with patch.object(generated, "execute_observed_pdf_generated_source_job") as run:
                    with self.assertRaises(job.PdfQualificationJobError): self.execute()
                run.assert_not_called()
                self.assertEqual(list(self.root.iterdir()), [])

    def test_inherited_disable_and_bad_input_precede_execution(self):
        """The optional operation inherits source/profile checks and generator disable."""
        with patch.object(generated, "execute_observed_pdf_generated_source_job") as run:
            for changes in ({"expected_ir_sha256": "0" * 64}, {"expected_language": "pt-BR"},
                            {"run_id": "../bad"}, {"expected_resource_profile_sha256": "0" * 64}):
                with self.subTest(changes=changes), self.assertRaises(job.PdfQualificationJobError):
                    self.execute(**changes)
            with patch.dict(os.environ, {"OMNIGENIS_PDF_GENERATED_SOURCE_JOB_DISABLED": "1"}):
                with self.assertRaises(job.PdfQualificationJobError): self.execute()
        run.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_existing_attempt_is_never_replayed(self):
        """Even a receiptless existing attempt blocks generation."""
        (self.root / self.run_id).mkdir(mode=0o700)
        with patch.object(generated, "execute_observed_pdf_generated_source_job") as run:
            with self.assertRaises(job.PdfQualificationJobError): self.execute()
        run.assert_not_called()
        self.assertEqual(list((self.root / self.run_id).iterdir()), [])

    def test_concurrent_same_id_has_one_observed_execution(self):
        """Exclusive admission also holds for the explicit observed path."""
        pair = self.real_pair()
        entered, release = threading.Event(), threading.Event()
        def blocked(**_arguments):
            entered.set()
            if not release.wait(10): raise RuntimeError("test release missing")
            return pair
        with patch.object(generated, "execute_observed_pdf_generated_source_job", side_effect=blocked) as run:
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(self.execute)
                try:
                    self.assertTrue(entered.wait(10))
                    with self.assertRaises(job.PdfQualificationJobError): self.execute()
                finally:
                    release.set()
                self.assertEqual(first.result(timeout=10)[2]["result_sha256"], pair[0].result_sha256)
            self.assertEqual(run.call_count, 1)

    def test_malformed_generated_pair_records_failed(self):
        """Success-shaped but incomplete producer values are not accepted."""
        result, observation = self.real_pair()
        for i, pair in enumerate((None, [result, observation], (result,), (result, observation, {}), (object(), observation))):
            rid = sha256(str(i).encode()).hexdigest()[:32]
            with self.subTest(index=i), patch.object(generated, "execute_observed_pdf_generated_source_job", return_value=pair):
                with self.assertRaises(job.PdfQualificationJobError): self.execute(run_id=rid)
            self.assert_failed(rid)

    def test_missing_wrong_type_and_oversized_observations_refuse(self):
        """Only bounded observation dictionaries can reach computation completion."""
        result, observation = self.real_pair()
        oversized = {**observation, "extra": "x" * generated.MAX_OBSERVATION_BYTES}
        for i, value in enumerate((None, [], "record", oversized)):
            rid = sha256(str(i).encode()).hexdigest()[:32]
            with self.subTest(index=i), self.patch_pair((result, value)):
                with self.assertRaises(job.PdfQualificationJobError): self.execute(run_id=rid)
            self.assert_failed(rid)

    def test_mutated_observation_digest_refuses(self):
        """A changed ledger cannot retain the old top-level digest."""
        result, observation = self.real_pair()
        observation["observed_direct_spawns"] += 1
        with self.patch_pair((result, observation)), self.assertRaises(job.PdfQualificationJobError):
            self.execute()
        self.assert_failed()

    def test_rehashed_foreign_result_binding_refuses(self):
        """A valid digest cannot bind another result to the current attempt."""
        result, observation = self.real_pair()
        observation["generated_result_sha256"] = "0" * 64
        self.resign(observation)
        with self.patch_pair((result, observation)), self.assertRaises(job.PdfQualificationJobError):
            self.execute()
        self.assert_failed()

    def test_rehashed_unknown_fields_and_scope_claims_refuse(self):
        """Unknown fields or promoted native claims do not become accepted metadata."""
        result, original = self.real_pair()
        for i, changes in enumerate(({"extra": "metadata"}, {"whole_graph_observed": True},
                                     {"release_authorized": True}, {"observed_direct_exits": True})):
            observation = {**deepcopy(original), **changes}
            self.resign(observation)
            rid = sha256(str(i).encode()).hexdigest()[:32]
            with self.subTest(changes=changes), self.patch_pair((result, observation)):
                with self.assertRaises(job.PdfQualificationJobError): self.execute(run_id=rid)
            self.assert_failed(rid)

    def test_rehashed_foreign_native_and_render_evidence_refuses(self):
        """Each internally returned stage still needs the exact result identity."""
        result, observation = self.real_pair()
        observation["native_observation"]["job_id"] = "different-job"
        self.resign(observation["native_observation"])
        self.resign(observation)
        with self.patch_pair((result, observation)), self.assertRaises(job.PdfQualificationJobError):
            self.execute()
        self.assert_failed()

    def test_valid_pair_for_other_context_refuses(self):
        """A sealed but foreign job result cannot be recorded for caller expectations."""
        with self.patch_pair(), self.assertRaises(job.PdfQualificationJobError):
            self.execute(job_id="different-job")
        self.assert_failed()

    def test_generator_error_records_failed_without_private_text(self):
        """Error details and candidate content never enter the bounded receipt."""
        with patch.object(generated, "execute_observed_pdf_generated_source_job", side_effect=ValueError("private source detail")):
            with self.assertRaisesRegex(job.PdfQualificationJobError, '^pdf_qualification_job_execution_failed$'):
                self.execute()
        self.assert_failed()
        self.assertNotIn(b"private source detail", self.stored().read_bytes())

    def test_observation_interrupt_preserves_original_interrupt_and_failed_record(self):
        """An interrupted observed attempt remains an interruption after bookkeeping."""
        interrupt = KeyboardInterrupt("synthetic interruption")
        with patch.object(generated, "execute_observed_pdf_generated_source_job", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt) as caught: self.execute()
        self.assertIs(caught.exception, interrupt)
        self.assert_failed()

    def test_disable_during_observed_generation_records_failed(self):
        """Policy revoked after generation rejects the observed result pair."""
        pair = self.real_pair()
        def revoke(**_arguments):
            os.environ[DISABLE] = "1"
            return pair
        with patch.object(generated, "execute_observed_pdf_generated_source_job", side_effect=revoke):
            with self.assertRaises(job.PdfQualificationJobError): self.execute()
        self.assert_failed()

    def test_source_change_during_generation_records_failed(self):
        """Observed generation does not weaken original-source identity checks."""
        arguments = self.arguments()
        pair = self.real_pair()
        def mutate(**_arguments):
            arguments["presentation_ir"]["report_id"] = "CHANGED"
            return pair
        with patch.object(generated, "execute_observed_pdf_generated_source_job", side_effect=mutate):
            with self.assertRaises(job.PdfQualificationJobError):
                job.execute_observed_receipted_pdf_generated_source_job(**arguments)
        self.assert_failed()

    def test_observation_mutation_during_commit_returns_no_triple(self):
        """Postcommit mutation cannot return a ledger no longer bound to completion."""
        result, observation = self.real_pair()
        persist = job._persist
        def mutate(*args):
            outcome = persist(*args)
            observation["job_id"] = "changed-after-commit"
            self.resign(observation)
            return outcome
        with self.patch_pair((result, observation)), patch.object(job, "_persist", side_effect=mutate):
            with self.assertRaisesRegex(job.PdfQualificationJobError, '^pdf_qualification_job_completion_unverified$'):
                self.execute()
        self.assertEqual(json.loads(self.stored().read_bytes())["state"], "SUCCEEDED")

    def test_result_mutation_during_commit_returns_no_triple(self):
        """A changed sealed result cannot be returned with its earlier observation."""
        result, observation = self.real_pair()
        result = deepcopy(result)
        persist = job._persist
        def mutate(*args):
            outcome = persist(*args)
            object.__setattr__(result, "job_id", "changed-after-commit")
            return outcome
        with self.patch_pair((result, observation)), patch.object(job, "_persist", side_effect=mutate):
            with self.assertRaises(job.PdfQualificationJobError): self.execute()
        self.assertEqual(json.loads(self.stored().read_bytes())["state"], "SUCCEEDED")

    def test_disable_after_commit_preserves_evidence_but_returns_no_triple(self):
        """Disable affects returned evidence without rewriting committed computation."""
        persist = job._persist
        def revoke(*args):
            outcome = persist(*args)
            os.environ[DISABLE] = "1"
            return outcome
        with self.patch_pair(), patch.object(job, "_persist", side_effect=revoke):
            with self.assertRaisesRegex(job.PdfQualificationJobError, '^pdf_qualification_job_completion_unverified$'):
                self.execute()
        self.assertEqual(json.loads(self.stored().read_bytes())["state"], "SUCCEEDED")

    def test_success_storage_failure_is_unverified_without_retry(self):
        """An uncertain persistence failure does not become FAILED or a repeated job."""
        with self.patch_pair() as run, patch.object(job, "_persist", side_effect=OSError("storage error")) as persist:
            with self.assertRaisesRegex(job.PdfQualificationJobError, '^pdf_qualification_job_completion_unverified$'):
                self.execute()
        self.assertEqual(run.call_count, 1)
        self.assertEqual(persist.call_count, 1)
        self.assertFalse(self.stored().exists())

    def test_failure_storage_error_does_not_invent_completion(self):
        """A failed execution with failed recording remains unverified."""
        with patch.object(generated, "execute_observed_pdf_generated_source_job", side_effect=ValueError("execution")), \
             patch.object(job, "_persist", side_effect=OSError("storage")):
            with self.assertRaisesRegex(job.PdfQualificationJobError, '^pdf_qualification_job_completion_unverified$'):
                self.execute()
        self.assertFalse(self.stored().exists())

    def test_readback_error_preserves_computation_without_returned_ledger(self):
        """A successful file write alone does not permit returning the observed triple."""
        with self.patch_pair(), patch.object(receipts, "read_job_receipt", side_effect=OSError("readback")):
            with self.assertRaises(job.PdfQualificationJobError): self.execute()
        self.assertEqual(json.loads(self.stored().read_bytes())["state"], "SUCCEEDED")

    def test_run_directory_replacement_does_not_receive_success(self):
        """The observed path retains the original exclusive directory identity."""
        pair = self.real_pair()
        def replace(**_arguments):
            (self.root / self.run_id).rename(self.root / "old-run")
            (self.root / self.run_id).mkdir(mode=0o700)
            return pair
        with patch.object(generated, "execute_observed_pdf_generated_source_job", side_effect=replace):
            with self.assertRaises(job.PdfQualificationJobError): self.execute()
        self.assertFalse(self.stored().exists())

    def test_returned_observation_is_detached(self):
        """Mutating a returned observation does not alter the producer or durable file."""
        result, observation = self.real_pair()
        original = deepcopy(observation)
        with self.patch_pair((result, observation)):
            _, detached, outcome = self.execute()
        detached["native_observation"]["job_id"] = "changed"
        self.assertEqual(observation, original)
        self.assertEqual(json.loads(self.stored().read_bytes()), outcome)

    def test_only_computation_receipt_is_persisted(self):
        """The receipt neither stores nor promises recovery of the process observation."""
        with self.patch_pair():
            result, observation, outcome = self.execute()
        raw = self.stored().read_bytes()
        self.assertEqual(set(outcome), {"schema", "run_id", "state", "result_sha256", "release_authorized"})
        self.assertNotIn(b"process", raw)
        self.assertNotIn(b"%PDF", raw)
        self.assertEqual(outcome["result_sha256"], observation["generated_result_sha256"])
        self.assertEqual(len(list((self.root / self.run_id).iterdir())), 1)
        self.assertIs(outcome["release_authorized"], False)
        self.assertEqual(result.result_sha256, outcome["result_sha256"])

    def test_recovery_after_console_error_never_reexecutes(self):
        """Original outcome recovery needs only trusted expected computation metadata."""
        with self.patch_pair(): result, _, outcome = self.execute()
        class BrokenConsole:
            def write(self, _text):
                raise OSError("synthetic console error")
        with self.assertRaises(OSError): print("completed", file=BrokenConsole())
        with patch.object(generated, "execute_observed_pdf_generated_source_job", side_effect=AssertionError("replay")):
            recovered = job.read_qualification_job_outcome(receipt_directory=self.root, run_id=self.run_id,
                                                           state="SUCCEEDED", result_sha256=result.result_sha256)
        self.assertEqual(recovered, outcome)

    def test_no_whole_graph_or_release_claims_added(self):
        """Observed direct children remain distinct from nested/native qualification."""
        with self.patch_pair(): _, observation, outcome = self.execute()
        for key in ("nested_processes_observed", "external_observer_measured", "whole_graph_observed",
                    "authenticated_worker_execution", "aggregate_job_resources_qualified",
                    "native_profile_qualified", "default_pipeline_activated", "release_authorized"):
            self.assertIs(observation[key], False)
        self.assertIs(outcome["release_authorized"], False)

    def test_api_has_only_existing_job_inputs_and_explicit_local_run(self):
        """No caller callback, execution function, budget or observation is admitted."""
        signature = inspect.signature(job.execute_observed_receipted_pdf_generated_source_job)
        self.assertEqual(set(signature.parameters), set(self.arguments()))
        self.assertTrue(all(p.kind is inspect.Parameter.KEYWORD_ONLY for p in signature.parameters.values()))

    def test_owned_descriptors_close_after_observed_success(self):
        """Returned observations do not keep private storage descriptors live."""
        pair = self.real_pair()
        opened = []
        real_open = os.open
        def capture(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            opened.append(fd)
            return fd
        with self.patch_pair(pair), patch.object(os, "open", side_effect=capture): self.execute()
        self.assertTrue(opened)
        for fd in set(opened):
            with self.assertRaises(OSError): os.fstat(fd)


if __name__ == "__main__":
    unittest.main()
