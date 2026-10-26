"""Adversarial boundary for opt-in whole-declared-document raster geometry summary.

This summarizes existing unsigned native-window observations; it neither runs
rasterizers nor certifies visible equivalence, PDF/UA or report release.
"""
from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
import unittest
from unittest.mock import patch

from reporting import document_content_reconciliation as content_api
from reporting import document_raster_coverage as subject
from reporting import pdf_raster_windows as native_raster
from tests.test_reporting_document_content_reconciliation import synthetic_inputs

ROOT = Path(__file__).resolve().parents[1]


def inputs(pages: int = 33, **identity) -> dict:
    """Use the existing sealed 33/64-page full-text/document receipt boundary."""
    content = content_api.bind_pdf_document_content_reconciliation(
        **synthetic_inputs(pages, **identity))
    return {
        "document_content": content,
        "expected_document_content_sha256": content.reconciliation_sha256,
        "expected_raster_checkpoint_sha256": (
            content.document_inspection.inspections.raster_checkpoint.checkpoint_sha256),
        "expected_coverage_profile_sha256": subject.PROFILE_SHA256,
    }


def varied_inputs(pages: int = 9, *, pixels=(1200, 400, 1500),
                  margins=(7, 3, 11), seed="first") -> tuple[dict, list]:
    """Reseal an independent typed chain with nonuniform complete windows.

    The last interval covers one physical page, not another full four pages.
    This test-only construction never promotes its unsigned receipts to fact.
    """
    from reporting import document_inspection_reconciliation as prior
    from reporting import pdf_document_content as text_api
    from reporting import pdf_inspection_bundle as bundle_api
    from reporting.page_checkpoints import PageWindowCheckpoint
    from tests.test_reporting_document_inspection_reconciliation import ingredients

    old = ingredients(pages)
    doc = old["document"]
    original_bundle = old["inspections"]
    assert len(doc.raster_plan.windows) == len(pixels) == len(margins)
    receipts = []
    for span, total, margin in zip(doc.raster_plan.windows, pixels, margins, strict=True):
        receipts.append(native_raster.PdfRasterWindowInspection(
            pdf_sha256=doc.pdf_sha256, ir_sha256=doc.ir_sha256,
            plan_sha256=doc.raster_plan.plan_sha256,
            page_count=pages, window_index=span.index,
            first_page=span.first_page, last_page=span.last_page,
            raster_sha256=sha256(f"{seed}:{span.index}".encode()).hexdigest(),
            total_pixels=total, min_edge_margin_px=margin))
    checkpoint = PageWindowCheckpoint(
        plan=doc.raster_plan, namespace_id=doc.namespace_id,
        job_id=doc.job_id, request_sha256=doc.request_sha256,
        resource_profile_sha256=old["expected_resource_profile_sha256"],
        observations=tuple(receipt.to_observation() for receipt in receipts))
    bundled = bundle_api.bind_pdf_inspection_bundle(
        text_checkpoint=original_bundle.text_checkpoint,
        raster_checkpoint=checkpoint,
        text_inspections=original_bundle.text_inspections,
        raster_inspections=tuple(receipts),
        object_inspection=original_bundle.object_inspection,
        expected_text_checkpoint_sha256=original_bundle.text_checkpoint.checkpoint_sha256,
        expected_raster_checkpoint_sha256=checkpoint.checkpoint_sha256,
        expected_object_inspection_sha256=original_bundle.object_inspection.inspection_sha256)
    prior_bound = prior.bind_pdf_document_inspection_reconciliation(**{
        **old, "inspections": bundled,
        "expected_bundle_sha256": bundled.bundle_sha256})
    text = text_api.PdfDocumentContentInspection(
        pdf_sha256=doc.pdf_sha256, ir_sha256=doc.ir_sha256,
        plan_sha256=doc.text_plan.plan_sha256, page_count=pages,
        expected_text_sha256="6" * 64, extracted_text_sha256="6" * 64,
        inspected_pages=pages, decoded_bytes=64 * pages,
        text_chars=16 * pages, text_bytes=16 * pages)
    content = content_api.bind_pdf_document_content_reconciliation(
        document_inspection=prior_bound, document_content=text,
        expected_document_inspection_sha256=prior_bound.reconciliation_sha256,
        expected_content_inspection_sha256=text.inspection_sha256,
        expected_source_text_sha256="6" * 64,
        expected_reconciliation_profile_sha256=content_api.PROFILE_SHA256)
    prepared = {
        "document_content": content,
        "expected_document_content_sha256": content.reconciliation_sha256,
        "expected_raster_checkpoint_sha256": checkpoint.checkpoint_sha256,
        "expected_coverage_profile_sha256": subject.PROFILE_SHA256,
    }
    window_values = [
        {"index": span.index, "first_page": span.first_page,
         "last_page": span.last_page, "raster_sha256": receipt.raster_sha256,
         "observation_sha256": receipt.observation_sha256,
         "total_pixels": total, "min_edge_margin_px": margin}
        for span, receipt, total, margin in zip(
            doc.raster_plan.windows, receipts, pixels, margins, strict=True)
    ]
    return prepared, window_values


class DocumentRasterCoverageTests(unittest.TestCase):
    def bind(self, prepared: dict, **updates):
        return subject.bind_pdf_document_raster_coverage(**{**prepared, **updates})

    def test_complete_one_thirty_three_and_sixty_four_page_geometry(self):
        """Missing a physical page or wrong page sum must change observable totals."""
        for pages, windows in ((1, 1), (33, 9), (64, 16)):
            with self.subTest(pages=pages):
                prepared = inputs(pages)
                receipt = self.bind(prepared)
                observed = receipt.to_dict()
                self.assertEqual(observed["status"], "COMPLETE_RASTER_GEOMETRY_METADATA_BOUND")
                self.assertEqual(observed["declared_page_count"], pages)
                self.assertEqual(observed["raster_window_count"], windows)
                self.assertEqual(observed["inspected_physical_pages"], pages)
                self.assertEqual(observed["raster_total_pixels"], pages * 100)
                self.assertEqual(observed["minimum_window_edge_margin_px"], 2)
                self.assertTrue(observed["complete_declared_raster_window_coverage"])
                self.assertEqual(observed["raster_checkpoint_sha256"],
                                 prepared["expected_raster_checkpoint_sha256"])
                self.assertEqual(observed["content_reconciliation_sha256"],
                                 prepared["expected_document_content_sha256"])
                self.assertEqual(observed["coverage_sha256"], receipt.coverage_sha256)
                self.assertEqual(len(observed["raster_window_metadata_commitment_sha256"]), 64)
                self.assertFalse(observed["worker_results_authenticated"])
                self.assertFalse(observed["release_authorized"])

    def test_real_native_thirty_three_page_raster_windows_are_summarized(self):
        """Use existing actual raster/text/graph workers, with a synthetic source-text pin."""
        from reporting import document_graph_probe as graph_api
        from reporting import document_inspection_reconciliation as prior
        from reporting import pdf_document_content as native_content
        from reporting import pdf_inspection_bundle as bundle_api
        from tests.test_reporting_pdf_inspection_bundle import native_inputs
        from tests.test_reporting_document_inspection_reconciliation import planned
        from tests.test_reporting_pdf_text_windows import fixture_pdf

        original = native_inputs(33)
        doc = planned(fixture_pdf(33), 33)
        bundled = bundle_api.bind_pdf_inspection_bundle(**original)
        observation = graph_api.PdfDocumentGraphProbe(
            document=doc, inspection=original["object_inspection"],
            expected_preflight_sha256=doc.preflight_sha256,
            probe_profile_sha256=graph_api.PROFILE_SHA256)
        bound = prior.bind_pdf_document_inspection_reconciliation(
            document=doc, graph_observation=observation, inspections=bundled,
            expected_preflight_sha256=doc.preflight_sha256,
            expected_graph_probe_sha256=observation.probe_sha256,
            expected_bundle_sha256=bundled.bundle_sha256,
            expected_resource_profile_sha256="d" * 64,
            expected_reconciliation_profile_sha256=prior.PROFILE_SHA256)
        text = native_content.PdfDocumentContentInspection(
            pdf_sha256=doc.pdf_sha256, ir_sha256=doc.ir_sha256,
            plan_sha256=doc.text_plan.plan_sha256, page_count=33,
            expected_text_sha256="6" * 64, extracted_text_sha256="6" * 64,
            inspected_pages=33, decoded_bytes=2112, text_chars=528, text_bytes=528)
        content = content_api.bind_pdf_document_content_reconciliation(
            document_inspection=bound, document_content=text,
            expected_document_inspection_sha256=bound.reconciliation_sha256,
            expected_content_inspection_sha256=text.inspection_sha256,
            expected_source_text_sha256="6" * 64,
            expected_reconciliation_profile_sha256=content_api.PROFILE_SHA256)
        observed = subject.bind_pdf_document_raster_coverage(
            document_content=content,
            expected_document_content_sha256=content.reconciliation_sha256,
            expected_raster_checkpoint_sha256=bundled.raster_checkpoint.checkpoint_sha256,
            expected_coverage_profile_sha256=subject.PROFILE_SHA256).to_dict()
        self.assertEqual(observed["raster_window_count"], 9)
        self.assertEqual(observed["inspected_physical_pages"], 33)
        self.assertGreater(observed["raster_total_pixels"], 0)
        self.assertGreaterEqual(observed["minimum_window_edge_margin_px"], 2)
        self.assertFalse(observed["worker_results_authenticated"])

    def test_exact_job_and_document_identities_retained(self):
        """The aggregate must not drop its parent tenant/job, PDF or IR identity."""
        prepared = inputs()
        child = prepared["document_content"].to_dict()
        observed = self.bind(prepared).to_dict()
        for key in ("namespace_id", "job_id", "request_sha256", "pdf_sha256",
                    "ir_sha256", "source_text_sha256", "declared_page_count"):
            with self.subTest(key=key):
                self.assertEqual(observed[key], child[key])

    def test_deterministic_detached_receipt_and_ordered_commitment(self):
        """The same complete windows cannot hash differently by process order."""
        prepared = inputs()
        first = self.bind(prepared)
        second = self.bind(prepared)
        self.assertEqual(first.to_dict(), second.to_dict())
        detached = first.to_dict()
        detached["raster_total_pixels"] = 0
        self.assertEqual(first.to_dict()["raster_total_pixels"], 3300)
        self.assertEqual(first.coverage_sha256, second.coverage_sha256)

    def test_nonuniform_geometry_exact_minimum_and_commitment_framing(self):
        """The middle window defines the min, and the final window is short."""
        prepared, windows = varied_inputs()
        observed = self.bind(prepared).to_dict()
        self.assertEqual(observed["declared_page_count"], 9)
        self.assertEqual(observed["raster_window_count"], 3)
        self.assertEqual(observed["raster_total_pixels"], 3100)
        self.assertEqual(observed["minimum_window_edge_margin_px"], 3)
        self.assertEqual((windows[-1]["first_page"], windows[-1]["last_page"]), (9, 9))
        self.assertEqual(observed["raster_windows"], windows)
        frame = {
            "profile_id": subject.PROFILE_ID,
            "raster_window_plan_sha256": observed["raster_window_plan_sha256"],
            "windows": windows,
        }
        expected = sha256(json.dumps(frame, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False, allow_nan=False).encode()).hexdigest()
        self.assertEqual(observed["raster_window_metadata_commitment_sha256"], expected)

    def test_ordered_metadata_commitment_changes_for_independent_valid_chains(self):
        """Plan, digest, pixel total and margin are committed, not a static token."""
        base, _ = varied_inputs()
        base_record = self.bind(base).to_dict()
        for change in ({"pixels": (1201, 400, 1500)},
                       {"margins": (7, 4, 11)}, {"seed": "second"}):
            prepared, _ = varied_inputs(**change)
            record = self.bind(prepared).to_dict()
            with self.subTest(change=change):
                self.assertNotEqual(record["raster_window_metadata_commitment_sha256"],
                                    base_record["raster_window_metadata_commitment_sha256"])
        longer, _ = varied_inputs(10)
        other = self.bind(longer).to_dict()
        self.assertNotEqual(other["raster_window_plan_sha256"],
                            base_record["raster_window_plan_sha256"])
        self.assertNotEqual(other["raster_window_metadata_commitment_sha256"],
                            base_record["raster_window_metadata_commitment_sha256"])

    def test_wrong_independent_pins_never_repin_nested_objects(self):
        """A caller cannot infer independently expected digests from children."""
        prepared = inputs()
        for key in ("expected_document_content_sha256",
                    "expected_raster_checkpoint_sha256",
                    "expected_coverage_profile_sha256"):
            for wrong in ("f" * 64, "F" * 64, None, True):
                with self.subTest(key=key, wrong=wrong), \
                     self.assertRaises(subject.PdfDocumentRasterCoverageError):
                    self.bind(prepared, **{key: wrong})

    def test_foreign_namespace_or_job_cannot_replace_sealed_parent(self):
        """Same page class in another case must not satisfy the original job pin."""
        prepared = inputs()
        for foreign in (inputs(job="another-job"), inputs(namespace="other-tenant")):
            with self.subTest(foreign=foreign["document_content"].to_dict()["job_id"]), \
                 self.assertRaises(subject.PdfDocumentRasterCoverageError):
                self.bind(prepared, document_content=foreign["document_content"])

    def test_foreign_pdf_ir_or_window_plan_rejected(self):
        """Different physical page counts entail a different PDF or plan identity."""
        prepared, foreign = inputs(33), inputs(34)
        with self.assertRaises(subject.PdfDocumentRasterCoverageError):
            self.bind(prepared, document_content=foreign["document_content"],
                      expected_document_content_sha256=foreign["expected_document_content_sha256"])
        with self.assertRaises(subject.PdfDocumentRasterCoverageError):
            self.bind(prepared, expected_raster_checkpoint_sha256=
                      foreign["expected_raster_checkpoint_sha256"])

    def test_staged_65_129_300_pages_cannot_enter_the_native_64_page_profile(self):
        """Complete staging above 64 does not confer native full-text/raster admission."""
        from reporting import document_inspection_reconciliation as prior
        from tests.test_reporting_document_inspection_reconciliation import ingredients

        existing = synthetic_inputs(33)
        for count in (65, 129, 300):
            parent = prior.bind_pdf_document_inspection_reconciliation(**ingredients(count))
            with self.subTest(count=count), \
                 self.assertRaises(content_api.PdfDocumentContentReconciliationError):
                content_api.bind_pdf_document_content_reconciliation(**{
                    **existing, "document_inspection": parent,
                    "expected_document_inspection_sha256": parent.reconciliation_sha256,
                })

    def test_reordered_or_dropped_raster_windows_fail_closed(self):
        """Gap, duplicate or out-of-order native raster receipts invalidate exposure."""
        for mutation in ("drop", "reverse", "duplicate"):
            prepared = inputs()
            coverage = self.bind(prepared)
            bundle = prepared["document_content"].document_inspection.inspections
            original = bundle.raster_inspections
            changed = (original[:-1] if mutation == "drop" else
                       tuple(reversed(original)) if mutation == "reverse" else
                       (original[0],) + original[:-1])
            object.__setattr__(bundle, "raster_inspections", changed)
            with self.subTest(mutation=mutation), \
                 self.assertRaises(subject.PdfDocumentRasterCoverageError):
                coverage.to_dict()

    def test_native_window_metric_mutation_after_sealing_is_refused(self):
        """A replaced native pixel count cannot silently update a sealed summary."""
        prepared = inputs()
        coverage = self.bind(prepared)
        native = prepared["document_content"].document_inspection.inspections.raster_inspections[0]
        object.__setattr__(native, "total_pixels", 0)
        with self.assertRaises(subject.PdfDocumentRasterCoverageError):
            coverage.to_dict()

    def test_outer_receipt_mutation_fails_and_does_not_reseal(self):
        """A frozen object changed through object.__setattr__ loses its authority."""
        prepared = inputs()
        coverage = self.bind(prepared)
        object.__setattr__(coverage, "expected_raster_checkpoint_sha256", "f" * 64)
        with self.assertRaises(subject.PdfDocumentRasterCoverageError):
            coverage.to_dict()

    def test_native_ir_plan_mutation_and_explicit_resealing_fail_closed(self):
        """Tampering upstream identity cannot be converted to a new parent seal."""
        for field in ("ir_sha256", "plan_sha256"):
            prepared = inputs()
            coverage = self.bind(prepared)
            native = prepared["document_content"].document_inspection.inspections.raster_inspections[0]
            object.__setattr__(native, field, "f" * 64)
            with self.subTest(field=field):
                for expose in (coverage.to_dict, lambda: coverage.coverage_sha256,
                               coverage.__post_init__):
                    with self.assertRaises(subject.PdfDocumentRasterCoverageError):
                        expose()

    def test_dictionary_lookalikes_are_not_sealed_child_types(self):
        """Copied JSON does not become a live native receipt identity."""
        prepared = inputs()
        wrong = prepared["document_content"].to_dict()
        with self.assertRaises(subject.PdfDocumentRasterCoverageError):
            self.bind(prepared, document_content=wrong)

    def test_opt_in_disable_or_resource_profile_drift_fails_closed(self):
        """A changed page width, page limit, budget or opt-out cancels admission."""
        prepared = inputs()
        with patch.dict("os.environ", {"OMNIGENIS_PDF_DOCUMENT_RASTER_COVERAGE_DISABLED": "1"}):
            with self.assertRaises(subject.PdfDocumentRasterCoverageError):
                self.bind(prepared)
        for key, wrong in (("MAX_DOCUMENT_PAGES", 65), ("MAX_WINDOW_PAGES", 5),
                           ("MAX_PDF_BYTES", 8388609), ("MIN_EDGE_MARGIN_PX", 1)):
            with self.subTest(field=key), patch.object(native_raster, key, wrong), \
                 self.assertRaises(subject.PdfDocumentRasterCoverageError):
                self.bind(prepared)

    def test_native_worker_disable_revokes_existing_receipt(self):
        """Turning off the underlying raster inspector revokes derived exposure."""
        prepared = inputs()
        coverage = self.bind(prepared)
        with patch.dict("os.environ", {"OMNIGENIS_PDF_RASTER_WINDOWS_DISABLED": "1"}):
            with self.assertRaises(subject.PdfDocumentRasterCoverageError):
                self.bind(prepared)
            with self.assertRaises(subject.PdfDocumentRasterCoverageError):
                coverage.to_dict()

    def test_pure_summary_never_starts_a_worker_or_activates_release(self):
        """Only supplied existing receipts are examined, with no native raster invocation."""
        prepared = inputs()
        with patch.object(native_raster, "inspect_pdf_raster_window",
                          side_effect=AssertionError("cannot start worker")):
            observed = self.bind(prepared).to_dict()
        for flag in ("worker_results_authenticated", "source_storage_authenticated",
                     "whole_document_visual_equivalence_verified", "visible_glyphs_verified",
                     "whole_pdf_safety_qualified", "finding_completeness_verified",
                     "accessibility_qualified", "aggregate_job_resources_qualified",
                     "default_pipeline_activated", "release_authorized"):
            with self.subTest(flag=flag):
                self.assertFalse(observed[flag])
        self.assertEqual(observed["release_authorization"], "NOT_ESTABLISHED")

    def test_manifest_pins_original_worker_limits_and_runtime_profile(self):
        """An opt-in profile cannot claim capacity wider than the actual native worker."""
        manifest = json.loads((ROOT / "reporting/pdf-document-raster-coverage.v1.json").read_text())
        profile = subject.document_raster_coverage_profile()
        self.assertEqual(manifest["profile"], profile)
        self.assertEqual(manifest["profile_sha256"], subject.PROFILE_SHA256)
        self.assertEqual(profile["max_bound_pages"], 64)
        self.assertEqual(profile["max_bound_pdf_bytes"], 8388608)
        self.assertEqual(profile["raster_window_pages"], 4)
        self.assertFalse(profile["release_authorized"])
        self.assertFalse(manifest["default_pipeline_activated"])


if __name__ == "__main__":
    unittest.main()
