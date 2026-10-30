"""Synthetic, fail-closed tests for opt-in full-document resource preflight."""
from hashlib import sha256
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from reporting import document_plan as subject
from reporting import pdf_candidate_qa as qa
from reporting import pdf_inspection_job as job
from reporting import pdf_text_windows as text
from reporting import pdf_raster_windows as raster
from reporting import _pdf_text_window_worker as text_worker
from reporting import _pdf_raster_window_worker as raster_worker
from reporting import _pdf_raster_executor as raster_executor
from reporting import _pdf_raster_probe as raster_probe

ROOT = Path(__file__).resolve().parents[1]
PDF = b"%PDF-1.7\n% synthetic preflight-only bytes\n"
IR_SHA = "a" * 64
REQUEST_SHA = "b" * 64


class PdfDocumentPreflightTests(unittest.TestCase):
    """Preflight may plan and defer but must never execute or claim native coverage."""

    def preflight(self, pdf=PDF, pages=33, **overrides):
        """Build a pinned synthetic preflight with controlled overrides."""
        args = dict(pdf_bytes=pdf, expected_pdf_sha256=sha256(pdf).hexdigest(),
                    expected_ir_sha256=IR_SHA, declared_page_count=pages,
                    namespace_id="tenant-alpha", job_id="report-alpha",
                    request_sha256=REQUEST_SHA,
                    expected_preflight_profile_sha256=subject.PROFILE_SHA256)
        args.update(overrides)
        return subject.build_pdf_document_preflight(**args)

    def test_profile_is_fixed_and_defers_all_execution(self):
        """Retain exact upstream budgets and explicitly unqualified claims."""
        profile = subject.document_preflight_profile()
        self.assertEqual(profile["existing_qa_max_pages"], qa.MAX_PAGES)
        self.assertEqual(profile["existing_qa_max_pdf_bytes"], qa.MAX_PDF_BYTES)
        self.assertEqual(profile["current_job_max_pages"], job.MAX_PAGES)
        self.assertEqual(profile["current_job_max_invocations"], job.MAX_INVOCATIONS)
        self.assertEqual(profile["text_window_width"], job.TEXT_WIDTH)
        self.assertEqual(profile["raster_window_width"], job.RASTER_WIDTH)
        self.assertEqual(profile["planning_page_ceiling"], text.MAX_DOCUMENT_PAGES)
        self.assertEqual(profile["max_staged_pdf_bytes"], 32 * 1024 * 1024)
        for key in ("native_executor_activated", "whole_pdf_safety_qualified",
                    "aggregate_job_resources_qualified", "release_authorized",
                    "actual_pdf_page_count_verified"):
            self.assertIs(profile[key], False)
        self.assertIsNot(profile, subject.document_preflight_profile())
        profile["max_staged_pdf_bytes"] = 999
        self.assertEqual(subject.document_preflight_profile()["max_staged_pdf_bytes"], 32 * 1024 * 1024)

    def test_33_64_129_300_pages_keep_every_declared_window_without_claiming_inspection(self):
        """Cover every declared page without certifying the actual PDF."""
        for count in (33, 64, 129, 300):
            with self.subTest(pages=count):
                result = self.preflight(pages=count)
                data = result.to_dict()
                self.assertEqual(data["declared_page_count"], count)
                self.assertEqual(data["text_pages_planned"], count)
                self.assertEqual(data["raster_pages_planned"], count)
                self.assertEqual(data["text_window_count"], (count + job.TEXT_WIDTH - 1) // job.TEXT_WIDTH)
                self.assertEqual(data["raster_window_count"], (count + job.RASTER_WIDTH - 1) // job.RASTER_WIDTH)
                self.assertEqual(data["planned_inspector_invocations"],
                                 4 + data["text_window_count"] + data["raster_window_count"])
                self.assertEqual(data["budget_class"], "LONG_DOCUMENT_STAGING")
                self.assertEqual(data["execution_decision"], "DEFERRED_NOT_QUALIFIED")
                self.assertFalse(data["whole_pdf_safety_qualified"])
                self.assertFalse(data["actual_pdf_page_count_verified"])
                self.assertFalse(data["worker_results_authenticated"])
                self.assertFalse(data["release_authorized"])
                self.assertEqual(result.text_plan.windows[0].first_page, 1)
                self.assertEqual(result.text_plan.windows[-1].last_page, count)
                self.assertEqual(result.raster_plan.windows[-1].last_page, count)

    def test_current_32_page_envelope_still_grants_no_execution(self):
        """Even a legacy-size candidate is metadata-only at this boundary."""
        data = self.preflight(pages=32).to_dict()
        self.assertEqual(data["budget_class"], "EXISTING_QA_ENVELOPE")
        self.assertEqual(data["execution_decision"], "DEFERRED_NOT_QUALIFIED")
        self.assertFalse(data["default_pipeline_activated"])

    def test_larger_than_eight_mib_is_planned_without_silently_dropping_bytes(self):
        """Preserve the complete candidate digest beyond the old byte cap."""
        pdf = b"%PDF-1.7\n" + b"x" * (qa.MAX_PDF_BYTES - 8)
        self.assertGreater(len(pdf), qa.MAX_PDF_BYTES)
        original = sha256(pdf).hexdigest()
        data = self.preflight(pdf=pdf, pages=33).to_dict()
        self.assertEqual(data["pdf_byte_count"], len(pdf))
        self.assertEqual(data["pdf_sha256"], original)
        self.assertEqual(sha256(pdf).hexdigest(), original)
        self.assertEqual(data["budget_class"], "LONG_DOCUMENT_STAGING")

    def test_wrong_digest_and_context_fail_closed(self):
        """Refuse corrupted digests and noncanonical job metadata."""
        for overrides in (
            {"expected_pdf_sha256": "0" * 64},
            {"expected_ir_sha256": "A" * 64},
            {"request_sha256": "z" * 64},
            {"namespace_id": ""}, {"job_id": ""}, {"declared_page_count": True},
            {"declared_page_count": 33.0}, {"declared_page_count": "33"},
            {"namespace_id": None}, {"job_id": 7},
            {"expected_preflight_profile_sha256": "0" * 64},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises(subject.PdfDocumentPreflightError):
                    self.preflight(**overrides)

    def test_non_bytes_candidate_types_fail_closed_with_matching_digest(self):
        """Reject candidate type coercion even with the correct byte digest."""
        digest = sha256(PDF).hexdigest()
        for pdf in (bytearray(PDF), PDF.decode("ascii")):
            with self.subTest(candidate_type=type(pdf).__name__):
                with self.assertRaises(subject.PdfDocumentPreflightError):
                    subject.build_pdf_document_preflight(
                        pdf_bytes=pdf, expected_pdf_sha256=digest,
                        expected_ir_sha256=IR_SHA, declared_page_count=33,
                        namespace_id="tenant-alpha", job_id="report-alpha",
                        request_sha256=REQUEST_SHA,
                        expected_preflight_profile_sha256=subject.PROFILE_SHA256,
                    )

    def test_exact_legacy_and_staging_byte_boundaries(self):
        """Keep inclusive limits and the byte-based budget class exact."""
        prefix = b"%PDF-1.7\n"
        legacy = prefix + b"x" * (qa.MAX_PDF_BYTES - len(prefix))
        self.assertEqual(len(legacy), qa.MAX_PDF_BYTES)
        data = self.preflight(pdf=legacy, pages=32).to_dict()
        self.assertEqual(data["pdf_byte_count"], qa.MAX_PDF_BYTES)
        self.assertEqual(data["budget_class"], "EXISTING_QA_ENVELOPE")
        over_legacy = legacy + b"x"
        data = self.preflight(pdf=over_legacy, pages=32).to_dict()
        self.assertEqual(data["pdf_byte_count"], qa.MAX_PDF_BYTES + 1)
        self.assertEqual(data["budget_class"], "LONG_DOCUMENT_STAGING")

        ceiling = prefix + b"x" * (subject.MAX_STAGED_PDF_BYTES - len(prefix))
        self.assertEqual(len(ceiling), subject.MAX_STAGED_PDF_BYTES)
        data = self.preflight(pdf=ceiling, pages=33).to_dict()
        self.assertEqual(data["pdf_byte_count"], subject.MAX_STAGED_PDF_BYTES)
        self.assertEqual(data["budget_class"], "LONG_DOCUMENT_STAGING")
        with self.assertRaises(subject.PdfDocumentPreflightError):
            self.preflight(pdf=ceiling + b"x", pages=33)

    def test_zero_over_ceiling_non_pdf_and_oversized_bytes_fail_whole(self):
        """Reject invalid inputs without returning truncated plans."""
        for pages in (0, -1, text.MAX_DOCUMENT_PAGES + 1):
            with self.subTest(pages=pages), self.assertRaises(subject.PdfDocumentPreflightError):
                self.preflight(pages=pages)
        with self.assertRaises(subject.PdfDocumentPreflightError):
            self.preflight(pdf=b"NOT A PDF", pages=33)
        with self.assertRaises(subject.PdfDocumentPreflightError):
            self.preflight(pdf=b"%PDF-1.7" + b"x" * (subject.MAX_STAGED_PDF_BYTES + 1), pages=33)

    def test_mutation_and_missing_or_duplicate_windows_cannot_be_resealed(self):
        """Reject post-construction edits and incomplete window coverage."""
        receipt = self.preflight(pages=33)
        stable = receipt.preflight_sha256
        self.assertEqual(receipt.preflight_sha256, stable)
        self.assertEqual(receipt.to_dict(), receipt.to_dict())
        object.__setattr__(receipt, "declared_page_count", 32)
        with self.assertRaises(subject.PdfDocumentPreflightError):
            receipt.to_dict()
        receipt = self.preflight(pages=33)
        object.__setattr__(receipt.text_plan, "windows", receipt.text_plan.windows[:-1])
        with self.assertRaises(subject.PdfDocumentPreflightError):
            receipt.to_dict()
        receipt = self.preflight(pages=33)
        object.__setattr__(receipt.raster_plan, "windows", receipt.raster_plan.windows[:-1] +
                           (receipt.raster_plan.windows[-2],))
        with self.assertRaises(subject.PdfDocumentPreflightError):
            receipt.to_dict()

    def test_forged_cross_job_metadata_cannot_be_reused(self):
        """Bind the preflight checksum to its original job identity."""
        original = self.preflight(pages=33)
        other = self.preflight(pages=33, job_id="report-beta")
        self.assertNotEqual(original.preflight_sha256, other.preflight_sha256)
        self.assertNotEqual(original.to_dict()["job_id"], other.to_dict()["job_id"])
        object.__setattr__(original, "job_id", "report-beta")
        with self.assertRaises(subject.PdfDocumentPreflightError):
            original.to_dict()

    def test_no_native_command_or_filesystem_read_is_dispatched(self):
        """Planning does not spawn subprocesses or read unrelated host files."""
        with patch("subprocess.Popen", side_effect=AssertionError("unexpected child")), \
             patch("os.system", side_effect=AssertionError("unexpected shell")), \
             patch.object(Path, "open", side_effect=AssertionError("unexpected file read")):
            result = self.preflight(pages=33)
            self.assertEqual(result.to_dict()["status"], "STAGED_UNQUALIFIED")

    def test_exact_five_hundred_twelve_page_boundary_is_declared_not_measured(self):
        """The finite staging ceiling never certifies actual PDF pages."""
        result = self.preflight(pages=text.MAX_DOCUMENT_PAGES)
        data = result.to_dict()
        self.assertEqual(data["text_pages_planned"], text.MAX_DOCUMENT_PAGES)
        self.assertEqual(data["raster_pages_planned"], text.MAX_DOCUMENT_PAGES)
        self.assertEqual(data["execution_decision"], "DEFERRED_NOT_QUALIFIED")
        self.assertFalse(data["actual_pdf_page_count_verified"])

    def test_disable_and_upstream_limit_drift_are_fail_closed(self):
        """A disable switch or imported-policy drift invalidates planning."""
        with patch.dict("os.environ", {"OMNIGENIS_PDF_DOCUMENT_PREFLIGHT_DISABLED": "1"}):
            with self.assertRaises(subject.PdfDocumentPreflightError):
                self.preflight()
        with patch.object(qa, "MAX_PAGES", qa.MAX_PAGES + 1):
            with self.assertRaises(subject.PdfDocumentPreflightError):
                self.preflight()

    def test_native_window_worker_drift_invalidates_new_and_cached_preflight(self):
        """Reject stale staged budgets and tool identity without executing workers."""
        cached = self.preflight(pages=33)
        stable_sha = cached.preflight_sha256
        changes = (
            (text, "EXTRACTOR_VERSION", "999.0"),
            (text, "PROTOCOL_VERSION", text.PROTOCOL_VERSION + 1),
            (text, "IDENTITY_FIELDS", ("unreviewed_field",)),
            (text_worker, "HEADER_BYTES", text_worker.HEADER_BYTES + 1),
            (text, "MAX_PDF_BYTES", text.MAX_PDF_BYTES + 1),
            (text, "CPU_SECONDS", text.CPU_SECONDS + 1),
            (text, "RESULT_BYTES", text.RESULT_BYTES + 1),
            (raster, "TOOL_SHA256", "0" * 64),
            (raster, "TOOL_VERSION", "unreviewed"),
            (raster, "PROTOCOL_VERSION", raster.PROTOCOL_VERSION + 1),
            (raster_worker, "DPI", raster_worker.DPI + 1),
            (raster_worker, "MAX_PNG_BYTES", raster_worker.MAX_PNG_BYTES + 1),
            (raster, "PARSER_VERSION", "999.0"),
            (raster, "MAX_WINDOW_PAGES", raster.MAX_WINDOW_PAGES + 1),
            (raster, "MAX_TOTAL_PIXELS", raster.MAX_TOTAL_PIXELS + 1),
            (raster, "MIN_EDGE_MARGIN_PX", raster.MIN_EDGE_MARGIN_PX + 1),
            (raster, "MEMORY_BYTES", raster.MEMORY_BYTES + 1),
            (raster, "WALL_SECONDS", raster.WALL_SECONDS + 1),
            (raster_worker, "PAGE_WALL_SECONDS", raster_worker.PAGE_WALL_SECONDS + 1),
            (raster, "FILE_BYTES", raster.FILE_BYTES + 1),
            (raster_executor, "TOOL_PATH", "/unreviewed/pdftoppm"),
            (raster_executor, "MAX_EXECUTABLE_BYTES", raster_executor.MAX_EXECUTABLE_BYTES + 1),
            (raster_executor, "FILE_BYTES", raster_executor.FILE_BYTES + 1),
            (raster_executor, "OPEN_FILES", raster_executor.OPEN_FILES + 1),
            (raster_executor, "CPU_SECONDS", raster_executor.CPU_SECONDS + 1),
            (raster_executor, "MEMORY_BYTES", raster_executor.MEMORY_BYTES + 1),
            (raster_executor, "PAGE_WALL_SECONDS", raster_executor.PAGE_WALL_SECONDS + 1),
            (raster_probe, "WALL_SECONDS", raster_probe.WALL_SECONDS + 1),
            (raster_probe, "OUTPUT_BYTES", raster_probe.OUTPUT_BYTES + 1),
            (raster_probe, "OPEN_FILES", raster_probe.OPEN_FILES + 1),
            (raster_probe, "MEMORY_BYTES", raster_probe.MEMORY_BYTES + 1),
            (raster_probe, "TOOL_PATH", "/unreviewed/pdftoppm"),
            (raster_probe, "TOOL_VERSION", "unreviewed"),
            (raster_probe, "TOOL_SHA256", "0" * 64),
        )
        for module, name, replacement in changes:
            with self.subTest(worker=module.__name__, limit=name), \
                 patch.object(module, name, replacement):
                with self.assertRaisesRegex(
                    subject.PdfDocumentPreflightError, "pdf_document_preflight_input_invalid"
                ):
                    self.preflight(pages=33)
                with self.assertRaisesRegex(
                    subject.PdfDocumentPreflightError, "pdf_document_preflight_invalid"
                ):
                    cached.to_dict()
        self.assertEqual(cached.preflight_sha256, stable_sha)

    def test_manifest_matches_exact_current_profile_and_no_dependency_change(self):
        """Compare published declarative claims against the live profile."""
        manifest = json.loads((ROOT / "reporting/pdf-document-preflight.v1.json").read_text())
        self.assertEqual(manifest["profile"], subject.document_preflight_profile())
        self.assertEqual(manifest["profile_sha256"], subject.PROFILE_SHA256)
        self.assertFalse(manifest["default_pipeline_activated"])
        self.assertFalse(manifest["release_authorized"])


if __name__ == "__main__":
    unittest.main()
