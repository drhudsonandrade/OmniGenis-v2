"""Qualification-only generation has durable, exclusive, nonrelease outcomes."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from hashlib import sha256
import importlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from reporting import _pdf_job_durable_receipt as receipts
from reporting import pdf_generated_source_job as generated
from tests import test_reporting_pdf_generated_source_job as existing

MODE = "OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE"
DISABLE = "OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED"


class QualificationGeneratedJobTests(unittest.TestCase):
    """Distinguish computation completion from returned bytes and release authority."""

    real_results = {}

    def setUp(self):
        """Fail on the missing operation before creating filesystem/native fixtures."""
        self.assertIsNotNone(importlib.util.find_spec("reporting.pdf_qualification_job"),
                             "qualification durable job module is missing")
        self.job = importlib.import_module("reporting.pdf_qualification_job")
        self.assertTrue(callable(getattr(self.job, "execute_receipted_pdf_generated_source_job", None)))
        self.env = patch.dict(os.environ, {MODE: "qualification-only"})
        self.env.start()
        self.addCleanup(self.env.stop)
        os.environ.pop(DISABLE, None)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.run_id = "a" * 32
        self.helper = existing.GeneratedSourceJobTests()
        self.helper.setUp()

    def arguments(self, count=2, **changes):
        """Use the unchanged generator's independently pinned synthetic request."""
        return {**self.helper.arguments(existing.source(count)),
                "receipt_directory": self.root, "run_id": self.run_id, **changes}

    def execute(self, **changes):
        """Call only the new fixed-operation entrypoint, without callbacks."""
        return self.job.execute_receipted_pdf_generated_source_job(**self.arguments(**changes))

    def recover(self, state="SUCCEEDED", result_sha256=None, **changes):
        """Supply the expected outcome; never discover success by executing again."""
        return self.job.read_qualification_job_outcome(**{
            "receipt_directory": self.root, "run_id": self.run_id,
            "state": state, "result_sha256": result_sha256, **changes})

    def real_result(self):
        """Reuse one genuinely generated result for isolated orchestration faults."""
        if 2 not in type(self).real_results:
            type(self).real_results[2] = generated.execute_pdf_generated_source_job(
                **self.helper.arguments(existing.source(2)))
        return type(self).real_results[2]

    def stored(self, run_id=None):
        """Locate only the exact run's content-free receipt."""
        rid = run_id or self.run_id
        return self.root / rid / (rid + ".json")

    def fake_generation(self, result=None):
        """Mock only fixed generation when testing orchestration, not native claims."""
        return patch.object(generated, "execute_pdf_generated_source_job",
                            return_value=self.real_result() if result is None else result)

    def test_actual_short_and_long_generation_has_exact_durable_outcome(self):
        """Both real jobs persist and re-read the digest of the unchanged result."""
        for count in (2, 1200):
            rid = sha256(str(count).encode()).hexdigest()[:32]
            result, outcome = self.execute(count=count, run_id=rid)
            self.assertIs(type(result), generated.PdfGeneratedSourceResult)
            type(self).real_results[count] = result
            self.assertEqual(outcome, receipts.read_job_receipt(self.root / rid, rid,
                                                               "SUCCEEDED", result.result_sha256))
            self.assertEqual(outcome["result_sha256"], result.result_sha256)
            self.assertIs(outcome["release_authorized"], False)
            self.assertEqual(result.pdf_sha256, sha256(result.pdf_bytes).hexdigest())
            self.assertEqual(result.page_count, 1) if count == 2 else self.assertGreater(result.page_count, 32)
            self.assertLessEqual(len(self.stored(rid).read_bytes()), receipts.MAX_RECEIPT_BYTES)
            for key in ("aggregate_job_resources_qualified", "hard_job_deadline_enforced",
                        "default_pipeline_activated", "release_authorized"):
                self.assertIs(result.to_dict()[key], False)
            self.assertEqual(self.recover(run_id=rid, result_sha256=result.result_sha256), outcome)

    def test_default_disabled_and_unknown_configuration_do_not_claim_or_execute(self):
        """Disabled or invalid opt-in refuses before storage or native work."""
        for mode, disabled in [(None, None), ("qualification-only", "1"),
                               ("supported", None), ("qualification-only", "true")]:
            with self.subTest(mode=mode, disabled=disabled), patch.dict(os.environ):
                os.environ.pop(MODE, None)
                os.environ.pop(DISABLE, None)
                if mode is not None: os.environ[MODE] = mode
                if disabled is not None: os.environ[DISABLE] = disabled
                with patch.object(generated, "execute_pdf_generated_source_job") as run:
                    with self.assertRaises(self.job.PdfQualificationJobError): self.execute()
                run.assert_not_called()
                self.assertEqual(list(self.root.iterdir()), [])

    def test_inherited_generator_disable_refuses_before_claim(self):
        """Qualification opt-in cannot bypass the generator's existing disable policy."""
        for flag in ("OMNIGENIS_PDF_GENERATED_SOURCE_JOB_DISABLED", "OMNIGENIS_PDF_RENDERER_DISABLED"):
            with self.subTest(flag=flag), patch.dict(os.environ, {flag: "1"}), \
                    patch.object(generated, "execute_pdf_generated_source_job") as run:
                with self.assertRaises(self.job.PdfQualificationJobError): self.execute()
                run.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_invalid_source_or_expected_identity_refuses_before_claim(self):
        """Input admission precedes even the durable claim directory."""
        cases = [{"expected_ir_sha256": "0" * 64}, {"expected_language": "pt-BR"},
                 {"namespace_id": ""}, {"job_id": ""}, {"request_sha256": "X" * 64},
                 {"expected_resource_profile_sha256": "0" * 64}, {"presentation_ir": {}}]
        for changes in cases:
            with self.subTest(changes=changes), patch.object(generated, "execute_pdf_generated_source_job") as run:
                with self.assertRaises(self.job.PdfQualificationJobError): self.execute(**changes)
                run.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_invalid_run_ids_and_directory_types_are_refused(self):
        """No alternate run name or coercion may escape the private directory."""
        for rid in (None, True, "../escape", "A" * 32, "a" * 31, "a" * 33):
            with self.subTest(rid=rid), self.assertRaises(self.job.PdfQualificationJobError):
                self.execute(run_id=rid)
        for directory in (str(self.root), None, Path("relative"), self.root / ".." / self.root.name):
            with self.subTest(directory=directory), self.assertRaises(self.job.PdfQualificationJobError):
                self.execute(receipt_directory=directory)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_nonprivate_and_symlink_receipt_directories_refused(self):
        """Untrusted storage cannot consume a generated job."""
        self.root.chmod(0o755)
        with self.assertRaises(self.job.PdfQualificationJobError): self.execute()
        self.root.chmod(0o700)
        real = self.root / "real"
        real.mkdir(mode=0o700)
        alias = self.root / "alias"
        alias.symlink_to(real, target_is_directory=True)
        with self.assertRaises(self.job.PdfQualificationJobError):
            self.execute(receipt_directory=alias)
        self.assertEqual(list(real.iterdir()), [])

    def test_preexisting_unknown_or_terminal_attempt_never_executes_again(self):
        """A claim is single-use whether the outcome is missing, failed or successful."""
        claimed = self.root / self.run_id
        claimed.mkdir(mode=0o700)
        with patch.object(generated, "execute_pdf_generated_source_job") as run:
            with self.assertRaises(self.job.PdfQualificationJobError): self.execute()
            receipts.write_job_receipt(claimed, self.run_id, "FAILED", None)
            with self.assertRaises(self.job.PdfQualificationJobError): self.execute()
            run.assert_not_called()
        self.assertEqual(self.recover("FAILED", None)["state"], "FAILED")

    def test_preexisting_run_symlink_is_not_followed(self):
        """An existing run alias is neither replaced nor used for storage."""
        target = self.root / "target"
        target.mkdir(mode=0o700)
        (self.root / self.run_id).symlink_to(target, target_is_directory=True)
        with patch.object(generated, "execute_pdf_generated_source_job") as run:
            with self.assertRaises(self.job.PdfQualificationJobError): self.execute()
            run.assert_not_called()
        self.assertEqual(list(target.iterdir()), [])

    def test_concurrent_same_run_id_admits_only_one_generation(self):
        """Exclusive creation prevents two simultaneous calls from starting the job."""
        result = self.real_result()
        entered, release = threading.Event(), threading.Event()
        def wait_for_release(**_arguments):
            entered.set()
            if not release.wait(10): raise RuntimeError("test release missing")
            return result
        with patch.object(generated, "execute_pdf_generated_source_job", side_effect=wait_for_release) as run:
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(self.execute)
                try:
                    self.assertTrue(entered.wait(10))
                    with self.assertRaises(self.job.PdfQualificationJobError): self.execute()
                finally:
                    release.set()
                self.assertEqual(first.result(timeout=10)[1]["result_sha256"], result.result_sha256)
            self.assertEqual(run.call_count, 1)

    def test_computation_error_records_failed_without_private_exception_text(self):
        """A failed generation returns no result and persists no input or exception text."""
        with patch.object(generated, "execute_pdf_generated_source_job", side_effect=OSError("PRIVATE_TEST_DETAIL")):
            with self.assertRaisesRegex(self.job.PdfQualificationJobError, "^pdf_qualification_job_execution_failed$"):
                self.execute()
        raw = self.stored().read_bytes()
        self.assertNotIn(b"PRIVATE_TEST_DETAIL", raw)
        self.assertIsNone(self.recover("FAILED", None)["result_sha256"])

    def test_real_native_refusal_has_failed_outcome(self):
        """The real generator's inherited one-observation refusal cannot become success."""
        with self.assertRaises(self.job.PdfQualificationJobError): self.execute(count=1)
        self.assertEqual(self.recover("FAILED", None)["state"], "FAILED")

    def test_interrupted_computation_preserves_interrupt_and_failed_record(self):
        """Cleanup can persist failure without converting an interrupt into success."""
        interruption = KeyboardInterrupt("synthetic interruption")
        with patch.object(generated, "execute_pdf_generated_source_job", side_effect=interruption):
            with self.assertRaises(KeyboardInterrupt) as caught: self.execute()
        self.assertIs(caught.exception, interruption)
        self.assertEqual(self.recover("FAILED", None)["state"], "FAILED")

    def test_wrong_result_type_records_failure(self):
        """Success-shaped foreign objects are not accepted as generated results."""
        with self.fake_generation(object()):
            with self.assertRaises(self.job.PdfQualificationJobError): self.execute()
        self.assertEqual(self.recover("FAILED", None)["state"], "FAILED")

    def test_valid_result_from_another_context_is_not_persisted_as_success(self):
        """A valid seal alone cannot bind another job's result to this attempt."""
        with self.fake_generation():
            with self.assertRaises(self.job.PdfQualificationJobError): self.execute(job_id="another-job")
        self.assertEqual(self.recover("FAILED", None)["state"], "FAILED")

    def test_changed_result_seal_is_refused(self):
        """An altered retained result is invalid even when its concrete type matches."""
        result = deepcopy(self.real_result())
        object.__setattr__(result, "job_id", "changed-after-seal")
        with self.fake_generation(result):
            with self.assertRaises(self.job.PdfQualificationJobError): self.execute()
        self.assertEqual(self.recover("FAILED", None)["state"], "FAILED")

    def test_source_mutation_during_generation_records_failure(self):
        """The outer caller source is rechecked after the fixed generation completes."""
        arguments = self.arguments()
        result = self.real_result()
        def mutate(**_arguments):
            arguments["presentation_ir"]["report_id"] = "CHANGED"
            return result
        with patch.object(generated, "execute_pdf_generated_source_job", side_effect=mutate):
            with self.assertRaises(self.job.PdfQualificationJobError):
                self.job.execute_receipted_pdf_generated_source_job(**arguments)
        self.assertEqual(self.recover("FAILED", None)["state"], "FAILED")

    def test_disable_during_generation_records_failed_cleanup_only(self):
        """Revocation prevents success; terminal failure cleanup does not publish output."""
        result = self.real_result()
        def revoke(**_arguments):
            os.environ[DISABLE] = "1"
            return result
        with patch.object(generated, "execute_pdf_generated_source_job", side_effect=revoke):
            with self.assertRaises(self.job.PdfQualificationJobError): self.execute()
        self.assertEqual(json.loads(self.stored().read_bytes())["state"], "FAILED")
        with self.assertRaises(self.job.PdfQualificationJobError): self.recover("FAILED", None)

    def test_claim_sync_failure_prevents_generation(self):
        """No job starts unless its exclusive directory claim was synced."""
        with patch.object(self.job.os, "fsync", side_effect=OSError("synthetic sync failure")), \
                patch.object(generated, "execute_pdf_generated_source_job") as run:
            with self.assertRaises(self.job.PdfQualificationJobError): self.execute()
            run.assert_not_called()
        self.assertFalse(self.stored().exists())

    def test_success_persistence_failure_is_unknown_and_never_retried(self):
        """A storage failure does not manufacture FAILED or automatically reexecute."""
        with self.fake_generation() as run, \
                patch.object(receipts, "write_job_receipt", side_effect=OSError("synthetic storage failure")):
            with self.assertRaisesRegex(self.job.PdfQualificationJobError, "^pdf_qualification_job_completion_unverified$"):
                self.execute()
            self.assertEqual(run.call_count, 1)
        self.assertFalse(self.stored().exists())
        with patch.object(generated, "execute_pdf_generated_source_job") as run:
            with self.assertRaises(self.job.PdfQualificationJobError): self.execute()
            run.assert_not_called()

    def test_failure_persistence_failure_remains_unverified(self):
        """A missing durable failure record cannot be represented as verified failure."""
        with patch.object(generated, "execute_pdf_generated_source_job", side_effect=ValueError("failed")), \
                patch.object(receipts, "write_job_receipt", side_effect=OSError("storage")):
            with self.assertRaisesRegex(self.job.PdfQualificationJobError, "^pdf_qualification_job_completion_unverified$"):
                self.execute()
        self.assertFalse(self.stored().exists())

    def test_readback_failure_returns_no_pair_but_preserves_committed_computation(self):
        """A committed success is not a delivered result when readback fails."""
        expected = self.real_result().result_sha256
        with self.fake_generation(), patch.object(receipts, "read_job_receipt", side_effect=OSError("readback")):
            with self.assertRaisesRegex(self.job.PdfQualificationJobError, "^pdf_qualification_job_completion_unverified$"):
                self.execute()
        self.assertEqual(self.recover(result_sha256=expected)["result_sha256"], expected)

    def test_terminal_output_error_does_not_require_generation_replay(self):
        """A committed result is recoverable independently of later optional printing."""
        with self.fake_generation(): result, outcome = self.execute()
        class BrokenOutput:
            def write(self, _text):
                raise OSError("synthetic console EIO")
        with self.assertRaises(OSError): print("completed", file=BrokenOutput())
        with patch.object(generated, "execute_pdf_generated_source_job", side_effect=AssertionError("reexecuted")):
            self.assertEqual(self.recover(result_sha256=result.result_sha256), outcome)

    def test_disable_after_commit_returns_no_pair_and_does_not_erase_evidence(self):
        """A durable computation record never overrides a later disabled return boundary."""
        expected = self.real_result().result_sha256
        original = receipts.write_job_receipt
        def write_then_revoke(*args, **kwargs):
            value = original(*args, **kwargs)
            os.environ[DISABLE] = "1"
            return value
        with self.fake_generation(), patch.object(receipts, "write_job_receipt", side_effect=write_then_revoke):
            with self.assertRaises(self.job.PdfQualificationJobError): self.execute()
        self.assertEqual(json.loads(self.stored().read_bytes())["result_sha256"], expected)
        self.assertIs(json.loads(self.stored().read_bytes())["release_authorized"], False)
        with self.assertRaises(self.job.PdfQualificationJobError): self.recover(result_sha256=expected)

    def test_source_mutation_during_commit_returns_no_pair(self):
        """Final source validation includes persistence time, not only native work."""
        arguments = self.arguments()
        original = receipts.write_job_receipt
        def mutate(*args, **kwargs):
            value = original(*args, **kwargs)
            arguments["presentation_ir"]["report_id"] = "CHANGED-DURING-COMMIT"
            return value
        with self.fake_generation(), patch.object(receipts, "write_job_receipt", side_effect=mutate):
            with self.assertRaises(self.job.PdfQualificationJobError):
                self.job.execute_receipted_pdf_generated_source_job(**arguments)

    def test_replaced_run_directory_does_not_receive_success(self):
        """An owned descriptor cannot authorize writes into a replacement run directory."""
        result = self.real_result()
        def replace(**_arguments):
            current = self.root / self.run_id
            current.rename(self.root / "old-attempt")
            current.mkdir(mode=0o700)
            return result
        with patch.object(generated, "execute_pdf_generated_source_job", side_effect=replace):
            with self.assertRaises(self.job.PdfQualificationJobError): self.execute()
        self.assertEqual(list((self.root / self.run_id).iterdir()), [])
        self.assertEqual(list((self.root / "old-attempt").iterdir()), [])

    def test_replaced_parent_directory_is_refused(self):
        """Moving the claimed storage root cannot redirect completion to a new root."""
        parent = self.root / "live"
        parent.mkdir(mode=0o700)
        result = self.real_result()
        def replace(**_arguments):
            parent.rename(self.root / "old")
            parent.mkdir(mode=0o700)
            (parent / self.run_id).mkdir(mode=0o700)
            return result
        with patch.object(generated, "execute_pdf_generated_source_job", side_effect=replace):
            with self.assertRaises(self.job.PdfQualificationJobError): self.execute(receipt_directory=parent)
        self.assertEqual(list((parent / self.run_id).iterdir()), [])

    def test_recovery_wrong_hash_state_missing_and_disabled_refuse(self):
        """Recovery accepts expected evidence only and never repairs or creates it."""
        result = self.real_result()
        with self.fake_generation(): self.execute()
        for state, digest in [("SUCCEEDED", "0" * 64), ("FAILED", None), ("UNKNOWN", None)]:
            with self.subTest(state=state), self.assertRaises(self.job.PdfQualificationJobError):
                self.recover(state, digest)
        with self.assertRaises(self.job.PdfQualificationJobError):
            self.recover(run_id="c" * 32, result_sha256=result.result_sha256)
        os.environ[DISABLE] = "1"
        with patch.object(receipts, "read_job_receipt", side_effect=AssertionError("disabled read")):
            with self.assertRaises(self.job.PdfQualificationJobError):
                self.recover(result_sha256=result.result_sha256)

    def test_recovery_rechecks_policy_after_read(self):
        """A valid receipt does not escape after its optional surface is disabled."""
        with self.fake_generation(): result, _ = self.execute()
        original = receipts.read_job_receipt
        def revoke(*args, **kwargs):
            value = original(*args, **kwargs)
            os.environ[DISABLE] = "1"
            return value
        with patch.object(receipts, "read_job_receipt", side_effect=revoke):
            with self.assertRaises(self.job.PdfQualificationJobError):
                self.recover(result_sha256=result.result_sha256)

    def test_returned_receipt_is_detached_and_content_free(self):
        """Only the original v1 receipt is stored, without PDF, source or observation content."""
        with self.fake_generation(): result, outcome = self.execute()
        raw = self.stored().read_bytes()
        outcome["release_authorized"] = True
        self.assertIs(self.recover(result_sha256=result.result_sha256)["release_authorized"], False)
        self.assertEqual(set(json.loads(raw)), {"schema", "run_id", "state", "result_sha256", "release_authorized"})
        self.assertNotIn(b"%PDF-", raw)
        self.assertNotIn(b"Observation", raw)
        self.assertNotIn(str(self.root).encode(), raw)
        self.assertEqual(self.stored().stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.root / self.run_id).stat().st_mode & 0o777, 0o700)

    def test_public_operation_has_no_callback_executor_or_receipt_input(self):
        """Only fixed generation inputs and a bounded local persistence identity are accepted."""
        parameters = inspect.signature(self.job.execute_receipted_pdf_generated_source_job).parameters
        self.assertEqual(set(parameters), set(self.arguments()))
        self.assertEqual(len(parameters), 9)
        self.assertTrue(all(p.kind is inspect.Parameter.KEYWORD_ONLY for p in parameters.values()))
        for name in ("worker", "callback", "executor", "result", "receipt", "budget"):
            with self.subTest(name=name), self.assertRaises(TypeError):
                self.job.execute_receipted_pdf_generated_source_job(**self.arguments(), **{name: None})

    def test_owned_descriptors_closed_after_success_and_failure(self):
        """The durable wrapper leaves no owned parent/run/file descriptors open."""
        result = self.real_result()
        for i, failure in enumerate((None, ValueError("synthetic error"))):
            opened = []
            original = os.open
            def capture(*args, **kwargs):
                fd = original(*args, **kwargs)
                opened.append(fd)
                return fd
            with patch.object(self.job.os, "open", side_effect=capture), \
                    patch.object(generated, "execute_pdf_generated_source_job", return_value=result, side_effect=failure):
                if failure is None: self.execute(run_id=str(i) * 32)
                else:
                    with self.assertRaises(self.job.PdfQualificationJobError): self.execute(run_id=str(i) * 32)
            self.assertTrue(opened)
            for fd in set(opened):
                with self.assertRaises(OSError): os.fstat(fd)

    def test_existing_low_level_receipt_apis_remain_independent(self):
        """The new optional consumer does not change existing writer/readback policy."""
        os.environ[DISABLE] = "1"
        path = receipts.write_job_receipt(self.root, self.run_id, "FAILED", None)
        self.assertEqual(receipts.read_job_receipt(self.root, self.run_id, "FAILED", None)["state"], "FAILED")
        self.assertEqual(path.parent, self.root)


if __name__ == "__main__":
    unittest.main()
