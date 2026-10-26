"""Exact-job adversarial and native checks for optional document receipt binding."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from reporting import document_plan as preflight
from reporting import document_graph_probe as graph_bridge
from reporting import document_inspection_reconciliation as subject
from reporting import pdf_inspection_bundle as bundle_api
from reporting import pdf_object_graph as graph
from reporting import pdf_text_windows as text_windows
from reporting import pdf_raster_windows as raster_windows
from reporting.page_checkpoints import PageWindowCheckpoint
from tests.test_reporting_pdf_text_windows import fixture_pdf

ROOT = Path(__file__).resolve().parents[1]
IR_SHA = "b" * 64
REQUEST_SHA = "c" * 64
RESOURCE_SHA = "d" * 64


def planned(pdf: bytes, pages: int, *, namespace: str = "synthetic-namespace",
            job: str = "synthetic-job") -> preflight.PdfDocumentPreflight:
    """Create one sealed document workload from actual finite PDF candidate bytes."""
    return preflight.build_pdf_document_preflight(
        pdf_bytes=pdf, expected_pdf_sha256=sha256(pdf).hexdigest(),
        expected_ir_sha256=IR_SHA, declared_page_count=pages,
        namespace_id=namespace, job_id=job, request_sha256=REQUEST_SHA,
        expected_preflight_profile_sha256=preflight.PROFILE_SHA256)


def synthetic_bundle(document: preflight.PdfDocumentPreflight,
                     *, resource_sha: str = RESOURCE_SHA) -> bundle_api.PdfInspectionBundle:
    """Fabricate valid unsigned receipts solely to exercise binding negatives."""
    streams = []
    for kind, plan in (("text", document.text_plan), ("raster", document.raster_plan)):
        receipts = []
        for span in plan.windows:
            pages = span.last_page - span.first_page + 1
            fields = dict(pdf_sha256=plan.pdf_sha256, ir_sha256=plan.ir_sha256,
                          plan_sha256=plan.plan_sha256, page_count=plan.page_count,
                          window_index=span.index, first_page=span.first_page,
                          last_page=span.last_page)
            digest = sha256(f"synthetic:{kind}:{span.index}".encode()).hexdigest()
            if kind == "text":
                receipt = text_windows.PdfTextWindowInspection(**fields,
                    text_sha256=digest, text_bytes=16 * pages,
                    text_chars=8 * pages, decoded_bytes=32 * pages)
            else:
                receipt = raster_windows.PdfRasterWindowInspection(**fields,
                    raster_sha256=digest, total_pixels=100 * pages, min_edge_margin_px=2)
            receipts.append(receipt)
        checkpoint = PageWindowCheckpoint(
            plan=plan, namespace_id=document.namespace_id, job_id=document.job_id,
            request_sha256=document.request_sha256, resource_profile_sha256=resource_sha,
            observations=tuple(item.to_observation() for item in receipts))
        streams.append((checkpoint, tuple(receipts)))
    graph_receipt = graph.PdfObjectGraphInspection(
        pdf_sha256=document.pdf_sha256, ir_sha256=document.ir_sha256,
        plan_sha256=document.text_plan.plan_sha256,
        page_count=document.declared_page_count, object_count=4 * document.declared_page_count)
    text, raster = streams
    return bundle_api.bind_pdf_inspection_bundle(
        text_checkpoint=text[0], raster_checkpoint=raster[0],
        text_inspections=text[1], raster_inspections=raster[1],
        object_inspection=graph_receipt,
        expected_text_checkpoint_sha256=text[0].checkpoint_sha256,
        expected_raster_checkpoint_sha256=raster[0].checkpoint_sha256,
        expected_object_inspection_sha256=graph_receipt.inspection_sha256)


def ingredients(pages: int = 33, *, namespace: str = "synthetic-namespace",
                job: str = "synthetic-job") -> dict:
    """Bind mutually consistent typed unsigned fixtures to a real PDF digest."""
    doc = planned(fixture_pdf(pages), pages, namespace=namespace, job=job)
    bundled = synthetic_bundle(doc)
    graph_record = graph_bridge.PdfDocumentGraphProbe(
        document=doc, inspection=bundled.object_inspection,
        expected_preflight_sha256=doc.preflight_sha256,
        probe_profile_sha256=graph_bridge.PROFILE_SHA256)
    return dict(document=doc, graph_observation=graph_record, inspections=bundled,
                expected_preflight_sha256=doc.preflight_sha256,
                expected_graph_probe_sha256=graph_record.probe_sha256,
                expected_bundle_sha256=bundled.bundle_sha256,
                expected_resource_profile_sha256=RESOURCE_SHA,
                expected_reconciliation_profile_sha256=subject.PROFILE_SHA256)


class DocumentInspectionReconciliationTests(unittest.TestCase):
    """Require exact preflight, graph and complete window evidence by job/bytes."""

    def bind(self, args: dict, **updates):
        """Call the sole public entry point with caller-controlled expectation pins."""
        return subject.bind_pdf_document_inspection_reconciliation(**{**args, **updates})

    def test_real_candidate_declared_windows_33_64_129_300(self):
        """Reconcile complete distinct text/raster intervals at several lengths."""
        for pages in (33, 64, 129, 300):
            with self.subTest(pages=pages):
                receipt = self.bind(ingredients(pages))
                record = receipt.to_dict()
                self.assertEqual(record["declared_page_count"], pages)
                self.assertEqual(record["text_pages_represented_by_unsigned_receipts"], pages)
                self.assertEqual(record["raster_pages_represented_by_unsigned_receipts"], pages)
                self.assertEqual(record["status"], "EXACT_DOCUMENT_INSPECTION_METADATA_BOUND")
                self.assertEqual(record["execution_decision"], "DEFERRED_NOT_QUALIFIED")
                self.assertEqual(record["reconciliation_sha256"], receipt.reconciliation_sha256)
                self.assertFalse(record["worker_results_authenticated"])
                self.assertFalse(record["whole_pdf_safety_qualified"])
                self.assertFalse(record["aggregate_job_resources_qualified"])
                self.assertFalse(record["release_authorized"])

    def test_native_full_33_page_receipts_reconcile_without_new_worker(self):
        """Bind existing real native text/raster/graph receipts to one preflight."""
        from tests.test_reporting_pdf_inspection_bundle import native_inputs
        existing = native_inputs(33)
        document = planned(fixture_pdf(33), 33)
        bundled = bundle_api.bind_pdf_inspection_bundle(**existing)
        observation = graph_bridge.PdfDocumentGraphProbe(
            document=document, inspection=existing["object_inspection"],
            expected_preflight_sha256=document.preflight_sha256,
            probe_profile_sha256=graph_bridge.PROFILE_SHA256)
        args = ingredients()
        receipt = self.bind(args, document=document, graph_observation=observation,
                            inspections=bundled, expected_preflight_sha256=document.preflight_sha256,
                            expected_graph_probe_sha256=observation.probe_sha256,
                            expected_bundle_sha256=bundled.bundle_sha256)
        self.assertEqual(receipt.to_dict()["declared_page_count"], 33)

    def test_cross_job_or_namespace_same_pdf_never_binds(self):
        """The same report bytes cannot substitute evidence from a different job."""
        first = ingredients()
        for change in ({"job": "foreign-job"}, {"namespace": "foreign-tenant"}):
            with self.subTest(change=change):
                foreign = ingredients(**change)
                with self.assertRaises(subject.PdfDocumentInspectionReconciliationError):
                    self.bind(first, document=foreign["document"])
                with self.assertRaises(subject.PdfDocumentInspectionReconciliationError):
                    self.bind(first, inspections=foreign["inspections"],
                              expected_bundle_sha256=foreign["expected_bundle_sha256"])

    def test_different_pdf_or_page_count_rejected(self):
        """Graph and complete window receipts must describe the same full candidate."""
        first = ingredients()
        foreign = ingredients(34)
        with self.assertRaises(subject.PdfDocumentInspectionReconciliationError):
            self.bind(first, inspections=foreign["inspections"],
                      expected_bundle_sha256=foreign["expected_bundle_sha256"])
        with self.assertRaises(subject.PdfDocumentInspectionReconciliationError):
            self.bind(first, graph_observation=foreign["graph_observation"],
                      expected_graph_probe_sha256=foreign["expected_graph_probe_sha256"])

    def test_every_independent_hash_pin_is_required(self):
        """No internally computed child hash can replace the trusted caller pin."""
        args = ingredients()
        for field in ("expected_preflight_sha256", "expected_graph_probe_sha256",
                      "expected_bundle_sha256", "expected_resource_profile_sha256",
                      "expected_reconciliation_profile_sha256"):
            for wrong in ("f" * 64, "F" * 64, None, True):
                with self.subTest(field=field, wrong=wrong), \
                     self.assertRaises(subject.PdfDocumentInspectionReconciliationError):
                    self.bind(args, **{field: wrong})

    def test_resource_profile_disagreement_rejected(self):
        """Even re-pinned complete observations cannot alter the job resource class."""
        args = ingredients()
        foreign = synthetic_bundle(args["document"], resource_sha="e" * 64)
        with self.assertRaises(subject.PdfDocumentInspectionReconciliationError):
            self.bind(args, inspections=foreign, expected_bundle_sha256=foreign.bundle_sha256)

    def test_missing_or_duplicate_window_fails_even_after_new_pin(self):
        """An incomplete or duplicate checkpoint never becomes full coverage metadata."""
        for mode in ("missing", "duplicate"):
            args = ingredients()
            checkpoint = args["inspections"].raster_checkpoint
            windows = checkpoint.observations
            changed = windows[:-1] if mode == "missing" else (windows[0],) + windows[:-1]
            object.__setattr__(checkpoint, "observations", changed)
            with self.subTest(mode=mode), \
                 self.assertRaises(subject.PdfDocumentInspectionReconciliationError):
                self.bind(args)

    def test_mutation_after_sealing_cannot_be_reused(self):
        """Revalidation rejects changed nested graph, checkpoint or request metadata."""
        for which in ("object", "job", "text"):
            args = ingredients()
            receipt = self.bind(args)
            if which == "object":
                graph_record = args["inspections"].object_inspection
                object.__setattr__(graph_record, "object_count", graph_record.object_count + 1)
            elif which == "job":
                object.__setattr__(args["document"], "job_id", "changed-job")
            else:
                checkpoint = args["inspections"].text_checkpoint
                object.__setattr__(checkpoint, "observations", checkpoint.observations[:-1])
            with self.subTest(which=which), \
                 self.assertRaises(subject.PdfDocumentInspectionReconciliationError):
                receipt.to_dict()

    def test_dictionary_substitution_fails_closed(self):
        """Untrusted serialized lookalikes do not qualify as sealed child types."""
        args = ingredients()
        for field in ("document", "graph_observation", "inspections"):
            replacement = getattr(args[field], "to_dict")()
            with self.subTest(field=field), \
                 self.assertRaises(subject.PdfDocumentInspectionReconciliationError):
                self.bind(args, **{field: replacement})

    def test_pure_binding_never_launches_native_inspection(self):
        """A metadata-only call does not silently run workers or enable service."""
        args = ingredients()
        with patch.object(graph, "inspect_pdf_object_graph") as native_graph, \
             patch.object(text_windows, "inspect_pdf_text_window") as native_text, \
             patch.object(raster_windows, "inspect_pdf_raster_window") as native_raster:
            record = self.bind(args).to_dict()
            native_graph.assert_not_called()
            native_text.assert_not_called()
            native_raster.assert_not_called()
        self.assertFalse(record["default_pipeline_activated"])
        self.assertEqual(record["execution_decision"], "DEFERRED_NOT_QUALIFIED")

    def test_disabled_or_drifted_profile_refuses(self):
        """Optional reconciliation remains off when declared profiles change."""
        args = ingredients()
        with patch.dict("os.environ", {
            "OMNIGENIS_PDF_DOCUMENT_INSPECTION_RECONCILIATION_DISABLED": "1"}):
            with self.assertRaises(subject.PdfDocumentInspectionReconciliationError):
                self.bind(args)
        with patch.object(graph, "MAX_PDF_BYTES", graph.MAX_PDF_BYTES + 1):
            with self.assertRaises(subject.PdfDocumentInspectionReconciliationError):
                self.bind(args)

    def test_oversize_preflight_does_not_mint_graph_or_document_receipt(self):
        """A staged 8+ MiB PDF is not a new native resource qualification."""
        small = fixture_pdf(33)
        pdf = small + b"\n" + b"x" * (graph.MAX_PDF_BYTES + 1 - len(small))
        self.assertGreater(len(pdf), graph.MAX_PDF_BYTES)
        document = planned(pdf, 33)
        self.assertEqual(document.budget_class, "LONG_DOCUMENT_STAGING")
        forged = graph.PdfObjectGraphInspection(
            pdf_sha256=document.pdf_sha256, ir_sha256=document.ir_sha256,
            plan_sha256=document.text_plan.plan_sha256, page_count=33, object_count=132)
        with self.assertRaises(graph_bridge.PdfDocumentGraphProbeError):
            graph_bridge.PdfDocumentGraphProbe(document=document, inspection=forged,
                expected_preflight_sha256=document.preflight_sha256,
                probe_profile_sha256=graph_bridge.PROFILE_SHA256)

    def test_claims_stay_unsigned_and_nonclinical(self):
        """Complete declared page receipts are not full document or clinical proof."""
        record = self.bind(ingredients()).to_dict()
        for flag in ("worker_results_authenticated", "historical_file_revisions_inspected",
                     "opaque_stream_payloads_inspected", "whole_pdf_safety_qualified",
                     "semantic_text_or_raster_equivalence_verified", "finding_completeness_verified",
                     "aggregate_job_resources_qualified", "accessibility_qualified",
                     "long_document_resource_class_qualified", "release_authorized"):
            with self.subTest(flag=flag):
                self.assertFalse(record[flag])

    def test_manifest_matches_runtime_profile_and_existing_budgets(self):
        """The checked-in manifest is not permission to increase worker budgets."""
        manifest = json.loads((ROOT / "reporting/pdf-document-inspection-reconciliation.v1.json").read_text())
        self.assertEqual(manifest["profile"], subject.document_inspection_reconciliation_profile())
        self.assertEqual(manifest["profile_sha256"], subject.PROFILE_SHA256)
        self.assertEqual(manifest["profile"]["max_bound_pdf_bytes"], graph.MAX_PDF_BYTES)
        self.assertEqual(manifest["profile"]["max_bound_pages"], graph.MAX_DOCUMENT_PAGES)
        self.assertFalse(manifest["release_authorized"])


if __name__ == "__main__":
    unittest.main()
