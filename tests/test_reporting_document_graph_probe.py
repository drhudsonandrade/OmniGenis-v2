"""Native and adversarial tests for the opt-in preflight-to-graph bridge."""
from __future__ import annotations

from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from reporting import document_plan as preflight
from reporting import document_graph_probe as subject
from reporting import pdf_object_graph as graph
from tests.test_reporting_pdf_text_windows import fixture_pdf

ROOT = Path(__file__).resolve().parents[1]
IR_SHA = "a" * 64
REQUEST_SHA = "b" * 64


class PdfDocumentGraphProbeTests(unittest.TestCase):
    """Verify native happy paths, exact identity, and fail-before-launch behavior."""

    def planned(self, pdf: bytes, pages: int = 33, job: str = "report-alpha"):
        """Build a sealed preflight with one independently computed PDF digest."""
        return preflight.build_pdf_document_preflight(
            pdf_bytes=pdf, expected_pdf_sha256=sha256(pdf).hexdigest(),
            expected_ir_sha256=IR_SHA, declared_page_count=pages,
            namespace_id="tenant-alpha", job_id=job,
            request_sha256=REQUEST_SHA,
            expected_preflight_profile_sha256=preflight.PROFILE_SHA256)

    def probe(self, pdf: bytes, pages: int = 33, **kwargs):
        """Exercise the public graph bridge with trusted preflight expectations."""
        document = self.planned(pdf, pages=pages)
        args = dict(document=document, pdf_bytes=pdf,
                    expected_preflight_sha256=document.preflight_sha256,
                    expected_probe_profile_sha256=subject.PROFILE_SHA256)
        args.update(kwargs)
        return subject.inspect_pdf_document_preflight_graph(**args)

    def test_actual_native_graph_for_33_64_129_300_pages(self):
        """Observe exact physical counts from four real full-document parses."""
        for count in (33, 64, 129, 300):
            with self.subTest(pages=count):
                pdf = fixture_pdf(count)
                observation = self.probe(pdf, pages=count)
                record = observation.to_dict()
                self.assertEqual(record["declared_page_count"], count)
                self.assertEqual(record["pdf_sha256"], sha256(pdf).hexdigest())
                self.assertEqual(record["pdf_byte_count"], len(pdf))
                self.assertEqual(record["object_graph_inspection_sha256"],
                                 observation.inspection.inspection_sha256)
                self.assertGreaterEqual(record["effective_object_count"], count)
                self.assertTrue(record["physical_page_count_matched_by_graph_observation"])
                self.assertEqual(record["status"], "LOCAL_UNSIGNED_GRAPH_PAGE_COUNT_MATCH")
                self.assertEqual(record["probe_sha256"], observation.probe_sha256)
                self.assertFalse(record["worker_results_authenticated"])
                self.assertFalse(record["whole_pdf_safety_qualified"])
                self.assertFalse(record["aggregate_job_resources_qualified"])
                self.assertFalse(record["release_authorized"])
                self.assertFalse(record["default_pipeline_activated"])

    def test_declared_page_count_must_match_real_pdf(self):
        """Reject native parser counts that disagree with the sealed preflight."""
        pdf = fixture_pdf(33)
        for declared in (32, 34, 64):
            with self.subTest(declared=declared):
                with self.assertRaises(subject.PdfDocumentGraphProbeError):
                    self.probe(pdf, pages=declared)

    def test_wrong_candidate_digest_or_cross_job_plan_rejected_without_worker(self):
        """Prove digest, job and profile refusals occur before worker dispatch."""
        pdf = fixture_pdf(33)
        doc = self.planned(pdf)
        other = self.planned(pdf, job="report-beta")
        for overrides in (
            {"document": doc, "pdf_bytes": pdf + b"\nchanged"},
            {"document": doc, "pdf_bytes": fixture_pdf(34)},
            {"document": other, "expected_preflight_sha256": doc.preflight_sha256},
            {"document": doc, "expected_preflight_sha256": "0" * 64},
            {"document": doc, "expected_probe_profile_sha256": "0" * 64},
        ):
            with self.subTest(overrides=tuple(overrides)), \
                 patch.object(graph, "inspect_pdf_object_graph") as worker:
                with self.assertRaises(subject.PdfDocumentGraphProbeError):
                    self.probe(pdf, **overrides)
                worker.assert_not_called()

    def test_staged_candidate_over_eight_mib_never_reaches_native_worker(self):
        """Defer an admitted large candidate without launching the 8-MiB worker."""
        small = fixture_pdf(33)
        pdf = small + b"\n% comment\n" + b"x" * (graph.MAX_PDF_BYTES + 1 - len(small))
        self.assertGreater(len(pdf), graph.MAX_PDF_BYTES)
        doc = self.planned(pdf)
        self.assertEqual(doc.budget_class, "LONG_DOCUMENT_STAGING")
        with patch.object(graph, "inspect_pdf_object_graph") as worker:
            with self.assertRaises(subject.PdfDocumentGraphProbeError):
                self.probe(pdf, document=doc)
            worker.assert_not_called()

    def test_pdf_action_on_last_page_is_rejected(self):
        """Reject a prohibited action even when it occurs on the final page."""
        from pypdf import PdfWriter
        from pypdf.generic import DictionaryObject, NameObject
        writer = PdfWriter(clone_from=BytesIO(fixture_pdf(33)))
        writer.pdf_header = "%PDF-1.7"
        writer.pages[-1][NameObject("/AA")] = DictionaryObject()
        stream = BytesIO()
        writer.write(stream)
        with self.assertRaises(subject.PdfDocumentGraphProbeError):
            self.probe(stream.getvalue())

    def test_synthetic_header_is_not_a_native_pdf(self):
        """Treat a plausible PDF header alone as insufficient native evidence."""
        with self.assertRaises(subject.PdfDocumentGraphProbeError):
            self.probe(b"%PDF-1.7\ninvalid synthetic content")

    def test_no_native_32_mib_resource_admission_or_default_activation(self):
        """Keep the native budget distinct from larger inert staging."""
        profile = subject.document_graph_probe_profile()
        self.assertEqual(profile["max_pdf_bytes"], graph.MAX_PDF_BYTES)
        self.assertEqual(profile["max_pages"], graph.MAX_DOCUMENT_PAGES)
        self.assertLess(profile["max_pdf_bytes"], preflight.MAX_STAGED_PDF_BYTES)
        self.assertFalse(profile["aggregate_job_resources_qualified"])
        self.assertFalse(profile["release_authorized"])
        self.assertFalse(profile["default_pipeline_activated"])
        profile["max_pages"] = 10000
        self.assertEqual(subject.document_graph_probe_profile()["max_pages"], 512)

    def test_disable_and_profile_drift_reject_prelaunch(self):
        """Refuse a disabled or drifted profile without invoking the worker."""
        pdf = fixture_pdf(33)
        with patch.dict("os.environ", {"OMNIGENIS_PDF_PREFLIGHT_GRAPH_PROBE_DISABLED": "1"}):
            with patch.object(graph, "inspect_pdf_object_graph") as worker:
                with self.assertRaises(subject.PdfDocumentGraphProbeError):
                    self.probe(pdf)
                worker.assert_not_called()
        with patch.object(graph, "MAX_PDF_BYTES", graph.MAX_PDF_BYTES + 1), \
             patch.object(graph, "inspect_pdf_object_graph") as worker:
            with self.assertRaises(subject.PdfDocumentGraphProbeError):
                self.probe(pdf)
            worker.assert_not_called()

    def test_mutated_document_or_graph_receipt_cannot_be_resealed(self):
        """Reject tampering with either nested object after the receipt seal."""
        pdf = fixture_pdf(33)
        r = self.probe(pdf)
        stable = r.to_dict()
        self.assertEqual(r.to_dict(), stable)
        object.__setattr__(r.inspection, "object_count", r.inspection.object_count + 1)
        with self.assertRaises(subject.PdfDocumentGraphProbeError):
            r.to_dict()
        r2 = self.probe(pdf)
        object.__setattr__(r2.document, "job_id", "foreign-job")
        with self.assertRaises(subject.PdfDocumentGraphProbeError):
            r2.to_dict()

    def test_constructed_unsigned_receipts_are_never_portable_proof(self):
        """Keep nonclaims false even when a caller constructs a matching receipt."""
        pdf = fixture_pdf(33)
        doc = self.planned(pdf)
        claimed = graph.PdfObjectGraphInspection(
            pdf_sha256=doc.pdf_sha256, ir_sha256=doc.ir_sha256,
            plan_sha256=doc.text_plan.plan_sha256,
            page_count=doc.declared_page_count, object_count=300)
        bound = subject.PdfDocumentGraphProbe(
            document=doc, inspection=claimed,
            expected_preflight_sha256=doc.preflight_sha256,
            probe_profile_sha256=subject.PROFILE_SHA256)
        result = bound.to_dict()
        self.assertFalse(result["worker_results_authenticated"])
        self.assertFalse(result["whole_pdf_safety_qualified"])
        self.assertEqual(result["conformance_scope"], "SAME_EXACT_PDF_AND_IR_EFFECTIVE_GRAPH_ONLY")

    def test_unqualified_source_and_report_gates_are_unchanged(self):
        """Leave historical revisions, all-page coverage and release unqualified."""
        pdf = fixture_pdf(33)
        r = self.probe(pdf)
        self.assertFalse(r.to_dict()["all_file_revisions_inspected"])
        self.assertFalse(r.to_dict()["opaque_stream_payloads_inspected"])
        self.assertFalse(r.to_dict()["text_and_raster_coverage_verified"])
        self.assertFalse(r.to_dict()["long_document_resource_class_qualified"])
        self.assertFalse(r.to_dict()["release_authorized"])

    def test_manifest_is_exact_to_pin_and_nonclaims(self):
        """Bind the checked-in manifest to the actual runtime resource limits."""
        manifest = json.loads((ROOT / "reporting/pdf-document-graph-probe.v1.json").read_text())
        self.assertEqual(manifest["profile"], subject.document_graph_probe_profile())
        self.assertEqual(manifest["profile_sha256"], subject.PROFILE_SHA256)
        self.assertFalse(manifest["default_pipeline_activated"])
        self.assertFalse(manifest["release_authorized"])


if __name__ == "__main__":
    unittest.main()
