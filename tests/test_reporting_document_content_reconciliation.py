"""Adversarial contract for one optional bound normalized full-PDF text receipt."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from reporting import document_plan as preflight
from reporting import document_graph_probe as graph_bridge
from reporting import document_inspection_reconciliation as prior
from reporting import document_content_reconciliation as subject
from reporting import pdf_document_content as native_content
from reporting.pdf_content import _expected_content
from tests.test_reporting_document_inspection_reconciliation import (
    ingredients, synthetic_bundle,
)
from tests.test_reporting_pdf_document_content import generated_case

ROOT = Path(__file__).resolve().parents[1]
TEXT_SHA = "6" * 64
REQUEST_SHA = "c" * 64
RESOURCE_SHA = "d" * 64


def synthetic_inputs(pages: int = 33, *, namespace: str = "synthetic-namespace",
                     job: str = "synthetic-job") -> dict:
    """Type-valid unsigned synthetic receipts expose binder behavior, not real work."""
    old = ingredients(pages, namespace=namespace, job=job)
    bundle = prior.bind_pdf_document_inspection_reconciliation(**old)
    plan = bundle.document.text_plan
    content = native_content.PdfDocumentContentInspection(
        pdf_sha256=plan.pdf_sha256, ir_sha256=plan.ir_sha256,
        plan_sha256=plan.plan_sha256, page_count=pages,
        expected_text_sha256=TEXT_SHA, extracted_text_sha256=TEXT_SHA,
        inspected_pages=pages, decoded_bytes=pages * 64,
        text_chars=pages * 16, text_bytes=pages * 16,
    )
    return dict(document_inspection=bundle, document_content=content,
                expected_document_inspection_sha256=bundle.reconciliation_sha256,
                expected_content_inspection_sha256=content.inspection_sha256,
                expected_source_text_sha256=TEXT_SHA,
                expected_reconciliation_profile_sha256=subject.PROFILE_SHA256)


def native_inputs(pages: int) -> dict:
    """Use the actual unmodified 33/64-page text worker on one native candidate."""
    ir, pdf = generated_case(pages)
    ir_sha, expected_text_sha = _expected_content(ir)
    doc = preflight.build_pdf_document_preflight(
        pdf_bytes=pdf, expected_pdf_sha256=sha256(pdf).hexdigest(),
        expected_ir_sha256=ir_sha, declared_page_count=pages,
        namespace_id="synthetic-namespace", job_id="synthetic-job",
        request_sha256=REQUEST_SHA,
        expected_preflight_profile_sha256=preflight.PROFILE_SHA256,
    )
    pages_bundle = synthetic_bundle(doc, resource_sha=RESOURCE_SHA)
    observation = graph_bridge.PdfDocumentGraphProbe(
        document=doc, inspection=pages_bundle.object_inspection,
        expected_preflight_sha256=doc.preflight_sha256,
        probe_profile_sha256=graph_bridge.PROFILE_SHA256,
    )
    prior_bundle = prior.bind_pdf_document_inspection_reconciliation(
        document=doc, graph_observation=observation, inspections=pages_bundle,
        expected_preflight_sha256=doc.preflight_sha256,
        expected_graph_probe_sha256=observation.probe_sha256,
        expected_bundle_sha256=pages_bundle.bundle_sha256,
        expected_resource_profile_sha256=RESOURCE_SHA,
        expected_reconciliation_profile_sha256=prior.PROFILE_SHA256,
    )
    actual = native_content.inspect_pdf_document_content(
        presentation_ir=ir, pdf_bytes=pdf, plan=doc.text_plan,
        expected_plan_sha256=doc.text_plan.plan_sha256,
        expected_ir_sha256=ir_sha, expected_language="en-US",
    )
    assert actual.inspected_pages == pages
    return dict(document_inspection=prior_bundle, document_content=actual,
                expected_document_inspection_sha256=prior_bundle.reconciliation_sha256,
                expected_content_inspection_sha256=actual.inspection_sha256,
                expected_source_text_sha256=expected_text_sha,
                expected_reconciliation_profile_sha256=subject.PROFILE_SHA256)


class DocumentContentReconciliationTests(unittest.TestCase):
    """Never promote unsigned text equality into clinical or full-document release."""

    def bind(self, args: dict, **change):
        return subject.bind_pdf_document_content_reconciliation(**{**args, **change})

    def test_native_thirty_three_and_sixty_four_page_job_text_binding(self):
        """One native all-page text digest must match the same job's sealed plan."""
        for count in (33, 64):
            with self.subTest(pages=count):
                args = native_inputs(count)
                result = self.bind(args)
                record = result.to_dict()
                self.assertEqual(record["status"], "DOCUMENT_CONTENT_RECONCILED_UNSIGNED")
                self.assertEqual(record["declared_page_count"], count)
                self.assertEqual(record["inspected_text_pages"], count)
                self.assertEqual(record["source_text_sha256"], args["expected_source_text_sha256"])
                self.assertEqual(record["source_text_sha256"],
                                 args["document_content"].extracted_text_sha256)
                self.assertEqual(record["reconciliation_sha256"], result.reconciliation_sha256)
                self.assertFalse(record["worker_results_authenticated"])
                self.assertFalse(record["release_authorized"])

    def test_synthetic_complete_declared_thirty_three_and_sixty_four(self):
        """Pure binding requires no worker if already supplied receipts are consistent."""
        for pages in (33, 64):
            with self.subTest(pages=pages):
                record = self.bind(synthetic_inputs(pages)).to_dict()
                self.assertEqual(record["declared_page_count"], pages)
                self.assertEqual(record["inspected_text_pages"], pages)
                self.assertTrue(record["unsigned_normalized_text_digest_agreement"])

    def test_wrong_independent_digest_pins_rejected(self):
        """Trusted caller pins cannot be inferred from unsigned nested receipts."""
        args = synthetic_inputs()
        for name in ("expected_document_inspection_sha256",
                     "expected_content_inspection_sha256",
                     "expected_source_text_sha256",
                     "expected_reconciliation_profile_sha256"):
            for wrong in ("f" * 64, "F" * 64, True, None):
                with self.subTest(field=name, wrong=wrong), \
                     self.assertRaises(subject.PdfDocumentContentReconciliationError):
                    self.bind(args, **{name: wrong})

    def test_foreign_job_even_with_identical_candidate_is_not_bound(self):
        """Another job's parent cannot replace an independently pinned original."""
        args = synthetic_inputs()
        for foreign in (synthetic_inputs(job="foreign-job"),
                        synthetic_inputs(namespace="foreign-tenant")):
            with self.subTest(foreign=foreign["document_inspection"].document.job_id), \
                 self.assertRaises(subject.PdfDocumentContentReconciliationError):
                self.bind(args, document_inspection=foreign["document_inspection"])

    def test_different_pdf_ir_or_physical_pages_rejected(self):
        """Re-pinning a foreign child cannot override the base PDF/IR/plan identity."""
        args = synthetic_inputs()
        foreign = synthetic_inputs(34)
        with self.assertRaises(subject.PdfDocumentContentReconciliationError):
            self.bind(args, document_content=foreign["document_content"],
                      expected_content_inspection_sha256=foreign["expected_content_inspection_sha256"])
        prior_pdf = args["document_content"]
        for name, value in (("pdf_sha256", "e" * 64),
                            ("ir_sha256", "e" * 64),
                            ("plan_sha256", "e" * 64)):
            fields = {key: getattr(prior_pdf, key) for key in (
                "pdf_sha256", "ir_sha256", "plan_sha256", "page_count",
                "expected_text_sha256", "extracted_text_sha256", "inspected_pages",
                "decoded_bytes", "text_chars", "text_bytes")}
            fields[name] = value
            foreign_content = native_content.PdfDocumentContentInspection(**fields)
            with self.subTest(name=name), \
                 self.assertRaises(subject.PdfDocumentContentReconciliationError):
                self.bind(args, document_content=foreign_content,
                          expected_content_inspection_sha256=foreign_content.inspection_sha256)

    def test_staged_65_129_300_page_cases_cannot_be_promoted(self):
        """512-page planning is not a license to widen the 64-page native text class."""
        current = synthetic_inputs()
        valid_content = current["document_content"]
        for pages in (65, 129, 300):
            base = prior.bind_pdf_document_inspection_reconciliation(**ingredients(pages))
            with self.subTest(pages=pages), \
                 self.assertRaises(subject.PdfDocumentContentReconciliationError):
                self.bind(current, document_inspection=base,
                          expected_document_inspection_sha256=base.reconciliation_sha256)
        with self.assertRaises(native_content.PdfDocumentContentError):
            native_content.PdfDocumentContentInspection(
                pdf_sha256=valid_content.pdf_sha256, ir_sha256=valid_content.ir_sha256,
                plan_sha256=valid_content.plan_sha256, page_count=65,
                expected_text_sha256=TEXT_SHA, extracted_text_sha256=TEXT_SHA,
                inspected_pages=65, decoded_bytes=65*64, text_chars=65*16,
                text_bytes=65*16)

    def test_change_after_sealing_does_not_reseal_or_return_metadata(self):
        """A mutated content count or parent job must invalidate the existing digest."""
        for kind in ("content", "parent"):
            args = synthetic_inputs()
            result = self.bind(args)
            if kind == "content":
                object.__setattr__(args["document_content"], "text_chars", 0)
            else:
                object.__setattr__(args["document_inspection"].document,
                                   "job_id", "mutated-job")
            with self.subTest(kind=kind), \
                 self.assertRaises(subject.PdfDocumentContentReconciliationError):
                result.to_dict()

    def test_serialized_lookalikes_are_not_sealed_instances(self):
        """A dictionary with copied child fields cannot replace the typed receipt."""
        args = synthetic_inputs()
        for field in ("document_inspection", "document_content"):
            wrong = getattr(args[field], "to_dict")()
            with self.subTest(field=field), \
                 self.assertRaises(subject.PdfDocumentContentReconciliationError):
                self.bind(args, **{field: wrong})

    def test_pure_binder_never_executes_workers(self):
        """No native parsing, retry or pipeline activation is added to metadata binding."""
        args = synthetic_inputs()
        with patch.object(native_content, "_run_worker",
                          side_effect=AssertionError("must not run")):
            result = self.bind(args).to_dict()
        self.assertFalse(result["default_pipeline_activated"])
        self.assertEqual(result["execution_decision"], "DEFERRED_NOT_QUALIFIED")

    def test_opt_in_profile_disable_or_drift_fails_closed(self):
        """Unsupported locale, page budget, or opt-out never becomes a valid profile."""
        args = synthetic_inputs()
        with patch.dict("os.environ", {
            "OMNIGENIS_PDF_DOCUMENT_CONTENT_RECONCILIATION_DISABLED": "1"}):
            with self.assertRaises(subject.PdfDocumentContentReconciliationError):
                self.bind(args)
        for attr, wrong in (("MAX_DOCUMENT_PAGES", 65), ("MAX_PDF_BYTES", 8388609),
                            ("LANGUAGE", "pt-BR")):
            with self.subTest(field=attr), patch.object(native_content, attr, wrong), \
                 self.assertRaises(subject.PdfDocumentContentReconciliationError):
                self.bind(args)

    def test_unsigned_nonclinical_claims_remain_explicit(self):
        """Normalized text cannot silently become semantic, visual or PDF/UA certification."""
        record = self.bind(synthetic_inputs()).to_dict()
        for flag in ("worker_results_authenticated", "source_storage_authenticated",
                     "scientific_equivalence_verified", "visible_glyphs_verified",
                     "all_file_revisions_inspected", "whole_pdf_safety_qualified",
                     "finding_completeness_verified", "accessibility_qualified",
                     "aggregate_job_resources_qualified", "release_authorized",
                     "default_pipeline_activated"):
            with self.subTest(flag=flag):
                self.assertFalse(record[flag])
        self.assertEqual(record["release_authorization"], "NOT_ESTABLISHED")

    def test_manifest_matches_runtime_and_original_limits(self):
        """Manifest metadata must not increase an upstream native resource envelope."""
        manifest = json.loads((ROOT / "reporting/pdf-document-content-reconciliation.v1.json").read_text())
        profile = subject.document_content_reconciliation_profile()
        self.assertEqual(manifest["profile"], profile)
        self.assertEqual(manifest["profile_sha256"], subject.PROFILE_SHA256)
        self.assertEqual(profile["max_bound_pages"], 64)
        self.assertEqual(profile["max_bound_pdf_bytes"], 16777216)
        self.assertFalse(profile["release_authorized"])
        self.assertFalse(manifest["default_pipeline_activated"])


if __name__ == "__main__":
    unittest.main()
