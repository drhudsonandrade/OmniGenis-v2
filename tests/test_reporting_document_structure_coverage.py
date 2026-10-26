"""Closed unsigned ED-04 document/structure join; never PDF/UA or report release."""
from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import importlib
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from reporting import document_raster_coverage as raster_api
from reporting import pdf_document_metadata as metadata_api
from reporting import pdf_document_content as native_content_api
from reporting import pdf_inspection_set as set_api
from reporting import pdf_page_tags as tags_api
from reporting import pdf_mcid_coverage as mcid_api
from reporting import pdf_structure_tree as tree_api
from reporting.page_checkpoints import _json_bytes
from reporting.pdf_document_metadata import PdfDocumentMetadataInspection
from reporting.pdf_page_tags import PdfPageTagInspection
from reporting.pdf_mcid_coverage import PdfMcidCoverageInspection
from tests.test_reporting_document_raster_coverage import inputs as raster_inputs

ROOT = Path(__file__).resolve().parents[1]


def synthetic_inputs(pages: int = 33, *, namespace: str = "synthetic-namespace",
                     job: str = "synthetic-job") -> dict:
    """All metadata is synthetic and unsigned: it does not prove real execution."""
    coverage = raster_api.bind_pdf_document_raster_coverage(
        **raster_inputs(pages, namespace=namespace, job=job))
    page_bundle = coverage.document_content.document_inspection.inspections
    text_plan = page_bundle.text_checkpoint.plan
    identity = {name: getattr(text_plan, name)
                for name in ("pdf_sha256", "ir_sha256", "plan_sha256", "page_count")}
    metadata = PdfDocumentMetadataInspection(**identity)
    tags = PdfPageTagInspection(**identity, tagged_pages=pages,
                                 parent_tree_entries=pages)
    mcids = PdfMcidCoverageInspection(**identity, matched_mcids=pages + 1,
                                     decoded_bytes=100 * pages, inspected_pages=pages)
    inspection_set = set_api.bind_pdf_inspection_set(
        page_bundle=page_bundle, document_metadata=metadata,
        page_tags=tags, mcid_coverage=mcids,
        expected_page_bundle_sha256=page_bundle.bundle_sha256,
        expected_metadata_sha256=metadata.inspection_sha256,
        expected_page_tags_sha256=tags.inspection_sha256,
        expected_mcid_sha256=mcids.inspection_sha256, expected_language="en-US")
    structural = tree_api.PdfStructureTreeInspection(
        **identity, structure_elements=4 * pages + 4, mapped_mcids=pages + 1,
        max_tree_depth=2, traversal_visits=5 * pages + 5,
        inspected_pages=pages)
    return dict(document_raster_coverage=coverage, inspection_set=inspection_set,
                structure_tree=structural,
                expected_raster_coverage_sha256=coverage.coverage_sha256,
                expected_inspection_set_sha256=inspection_set.inspection_set_sha256,
                expected_structure_tree_sha256=structural.inspection_sha256,
                expected_coverage_profile_sha256=subject().PROFILE_SHA256)


def subject():
    """Allow strict TDD RED assertion before the optional implementation exists."""
    return importlib.import_module("reporting.document_structure_coverage")


class PdfDocumentStructureCoverageTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("reporting.document_structure_coverage"),
                             "document structural coverage binder is missing")
        self.m = subject()
        self.args = synthetic_inputs()

    def bind(self, args=None, **changes):
        return self.m.bind_pdf_document_structure_coverage(**{**(args or self.args), **changes})

    def test_all_three_sealed_inputs_bind_full_one_thirty_three_sixty_four_page_jobs(self):
        for pages in (1, 33, 64):
            with self.subTest(pages=pages):
                args = synthetic_inputs(pages)
                result = self.bind(args)
                record = result.to_dict()
                self.assertEqual(record["status"], "COMPLETE_DOCUMENT_STRUCTURAL_LINKAGE_METADATA_BOUND")
                self.assertEqual(record["declared_page_count"], pages)
                self.assertEqual(record["inspected_structural_pages"], pages)
                self.assertEqual(record["tagged_pages"], pages)
                self.assertEqual(record["parent_tree_entries"], pages)
                self.assertEqual(record["matched_mcids"], pages + 1)
                self.assertEqual(record["mapped_mcids"], pages + 1)
                self.assertEqual(record["raster_coverage_sha256"],
                                 args["expected_raster_coverage_sha256"])
                self.assertEqual(record["inspection_set_sha256"],
                                 args["expected_inspection_set_sha256"])
                self.assertEqual(record["structure_tree_sha256"],
                                 args["expected_structure_tree_sha256"])
                self.assertEqual(record["coverage_sha256"], result.coverage_sha256)
                self.assertEqual(record["language"], "en-US")
                self.assertFalse(record["worker_results_authenticated"])
                self.assertFalse(record["pdf_ua_qualified"])
                self.assertFalse(record["release_authorized"])

    def test_one_page_native_full_chain_reconciles_actual_structural_results(self):
        """Existing guarded inspectors execute before pure join; never by the join."""
        from reporting import document_content_reconciliation as content_api
        from reporting import document_graph_probe as graph_api
        from reporting import document_inspection_reconciliation as inspection_api
        from reporting import document_plan as preflight_api
        from reporting import pdf_document_content as content_worker
        from reporting import pdf_inspection_bundle as bundle_api
        from reporting import pdf_document_metadata as metadata_worker
        from reporting import pdf_page_tags as tags_worker
        from reporting import pdf_mcid_coverage as mcid_worker
        from reporting import pdf_object_graph as graph_worker
        from reporting import pdf_raster_windows as raster_worker
        from reporting import pdf_text_windows as text_worker
        from reporting.pdf_content import _expected_content
        from tests.test_reporting_pdf_document_content import generated_case
        from tests.test_reporting_pdf_inspection_bundle import packaged

        ir, pdf = generated_case(1)
        ir_sha, source_text_sha = _expected_content(ir)
        doc = preflight_api.build_pdf_document_preflight(
            pdf_bytes=pdf, expected_pdf_sha256=sha256(pdf).hexdigest(),
            expected_ir_sha256=ir_sha, declared_page_count=1,
            namespace_id="synthetic-namespace", job_id="synthetic-job",
            request_sha256="c" * 64,
            expected_preflight_profile_sha256=preflight_api.PROFILE_SHA256)
        text_plan, raster_plan = doc.text_plan, doc.raster_plan
        text = text_worker.inspect_pdf_text_window(
            pdf_bytes=pdf, plan=text_plan, window_index=0,
            expected_plan_sha256=text_plan.plan_sha256)
        raster = raster_worker.inspect_pdf_raster_window(
            pdf_bytes=pdf, plan=raster_plan, window_index=0,
            expected_plan_sha256=raster_plan.plan_sha256)
        graph = graph_worker.inspect_pdf_object_graph(
            pdf_bytes=pdf, plan=text_plan, expected_plan_sha256=text_plan.plan_sha256)
        bundle = bundle_api.bind_pdf_inspection_bundle(**packaged(
            text_plan, raster_plan, (text,), (raster,), graph))
        probe = graph_api.PdfDocumentGraphProbe(
            document=doc, inspection=graph,
            expected_preflight_sha256=doc.preflight_sha256,
            probe_profile_sha256=graph_api.PROFILE_SHA256)
        inspected = inspection_api.bind_pdf_document_inspection_reconciliation(
            document=doc, graph_observation=probe, inspections=bundle,
            expected_preflight_sha256=doc.preflight_sha256,
            expected_graph_probe_sha256=probe.probe_sha256,
            expected_bundle_sha256=bundle.bundle_sha256,
            expected_resource_profile_sha256="d" * 64,
            expected_reconciliation_profile_sha256=inspection_api.PROFILE_SHA256)
        content = content_worker.inspect_pdf_document_content(
            presentation_ir=ir, pdf_bytes=pdf, plan=text_plan,
            expected_plan_sha256=text_plan.plan_sha256,
            expected_ir_sha256=ir_sha, expected_language="en-US")
        content_bound = content_api.bind_pdf_document_content_reconciliation(
            document_inspection=inspected, document_content=content,
            expected_document_inspection_sha256=inspected.reconciliation_sha256,
            expected_content_inspection_sha256=content.inspection_sha256,
            expected_source_text_sha256=source_text_sha,
            expected_reconciliation_profile_sha256=content_api.PROFILE_SHA256)
        coverage = raster_api.bind_pdf_document_raster_coverage(
            document_content=content_bound,
            expected_document_content_sha256=content_bound.reconciliation_sha256,
            expected_raster_checkpoint_sha256=bundle.raster_checkpoint.checkpoint_sha256,
            expected_coverage_profile_sha256=raster_api.PROFILE_SHA256)
        native_args = dict(pdf_bytes=pdf, plan=text_plan,
                           expected_plan_sha256=text_plan.plan_sha256,
                           expected_language="en-US")
        metadata = metadata_worker.inspect_pdf_document_metadata(**native_args)
        tags = tags_worker.inspect_pdf_page_tag_parents(**native_args)
        mcids = mcid_worker.inspect_pdf_mcid_coverage(**native_args)
        tree = tree_api.inspect_pdf_structure_tree(**native_args)
        self.assertEqual(tree.mapped_mcids, mcids.matched_mcids)
        inspected_set = set_api.bind_pdf_inspection_set(
            page_bundle=bundle, document_metadata=metadata, page_tags=tags,
            mcid_coverage=mcids, expected_page_bundle_sha256=bundle.bundle_sha256,
            expected_metadata_sha256=metadata.inspection_sha256,
            expected_page_tags_sha256=tags.inspection_sha256,
            expected_mcid_sha256=mcids.inspection_sha256, expected_language="en-US")
        joined = self.bind(document_raster_coverage=coverage,
                           inspection_set=inspected_set, structure_tree=tree,
                           expected_raster_coverage_sha256=coverage.coverage_sha256,
                           expected_inspection_set_sha256=inspected_set.inspection_set_sha256,
                           expected_structure_tree_sha256=tree.inspection_sha256)
        self.assertEqual(joined.to_dict()["mapped_mcids"], tree.mapped_mcids)
        self.assertFalse(joined.to_dict()["release_authorized"])

    def test_all_expected_independent_pins_fail_closed(self):
        for role in ("expected_raster_coverage_sha256", "expected_inspection_set_sha256",
                     "expected_structure_tree_sha256", "expected_coverage_profile_sha256"):
            for invalid in (None, True, "", "F" * 64, "f" * 64):
                with self.subTest(role=role, invalid=invalid), \
                        self.assertRaises(self.m.PdfDocumentStructureCoverageError):
                    self.bind(**{role: invalid})

    def test_wrong_types_or_missing_child_never_become_success_metadata(self):
        for role in ("document_raster_coverage", "inspection_set", "structure_tree"):
            for invalid in (None, {}, True, self.args[role].to_dict()):
                with self.subTest(role=role), \
                        self.assertRaises(self.m.PdfDocumentStructureCoverageError):
                    self.bind(**{role: invalid})

    def test_foreign_job_and_pdf_ir_plan_and_count_rejected_even_if_repinned(self):
        for foreign in (synthetic_inputs(job="foreign-job"),
                        synthetic_inputs(namespace="foreign-tenant"),
                        synthetic_inputs(34)):
            with self.subTest(other=foreign["inspection_set"].inspection_set_sha256):
                with self.assertRaises(self.m.PdfDocumentStructureCoverageError):
                    self.bind(inspection_set=foreign["inspection_set"],
                              expected_inspection_set_sha256=foreign["expected_inspection_set_sha256"])
                # Native structure evidence carries no authenticated job ID.
                # Same-PDF re-use cannot be distinguished as execution origin.
                if foreign["structure_tree"].page_count == self.args["structure_tree"].page_count:
                    observed = self.bind(structure_tree=foreign["structure_tree"],
                        expected_structure_tree_sha256=foreign["expected_structure_tree_sha256"])
                    self.assertFalse(observed.to_dict()["worker_results_authenticated"])
                else:
                    with self.assertRaises(self.m.PdfDocumentStructureCoverageError):
                        self.bind(structure_tree=foreign["structure_tree"],
                            expected_structure_tree_sha256=foreign["expected_structure_tree_sha256"])
        for field in ("pdf_sha256", "ir_sha256", "plan_sha256"):
            changed = replace(self.args["structure_tree"], **{field: "e" * 64})
            with self.subTest(field=field), \
                    self.assertRaises(self.m.PdfDocumentStructureCoverageError):
                self.bind(structure_tree=changed,
                          expected_structure_tree_sha256=changed.inspection_sha256)

    def test_different_complete_bundle_or_full_text_parent_rejected(self):
        from tests.test_reporting_document_raster_coverage import varied_inputs
        prepared, _ = varied_inputs(9, seed="new-window-geometry")
        altered_raster = raster_api.bind_pdf_document_raster_coverage(**prepared)
        other = synthetic_inputs(9)
        self.assertEqual(altered_raster.to_dict()["pdf_sha256"],
                         other["document_raster_coverage"].to_dict()["pdf_sha256"])
        self.assertNotEqual(altered_raster.coverage_sha256,
                            other["document_raster_coverage"].coverage_sha256)
        with self.assertRaises(self.m.PdfDocumentStructureCoverageError):
            self.bind(other, document_raster_coverage=altered_raster,
                      expected_raster_coverage_sha256=altered_raster.coverage_sha256)
        # Different source/job identities cannot override even same PDF bytes.
        different = synthetic_inputs(job="different-job")
        with self.assertRaises(self.m.PdfDocumentStructureCoverageError):
            self.bind(inspection_set=different["inspection_set"],
                      expected_inspection_set_sha256=different["expected_inspection_set_sha256"])

    def test_mcid_cross_inspector_disagreement_rejected_even_when_rehashed(self):
        before = self.args["structure_tree"]
        changed = replace(before, mapped_mcids=before.mapped_mcids + 1,
                          traversal_visits=before.traversal_visits + 1)
        with self.assertRaises(self.m.PdfDocumentStructureCoverageError):
            self.bind(structure_tree=changed,
                      expected_structure_tree_sha256=changed.inspection_sha256)

    def test_rehashed_mcid_receipt_disagreement_cannot_repin_existing_structure(self):
        old = self.args["inspection_set"]
        changed = replace(old.mcid_coverage,
                          matched_mcids=old.mcid_coverage.matched_mcids + 1)
        updated_set = set_api.bind_pdf_inspection_set(
            page_bundle=old.page_bundle, document_metadata=old.document_metadata,
            page_tags=old.page_tags, mcid_coverage=changed,
            expected_page_bundle_sha256=old.page_bundle.bundle_sha256,
            expected_metadata_sha256=old.document_metadata.inspection_sha256,
            expected_page_tags_sha256=old.page_tags.inspection_sha256,
            expected_mcid_sha256=changed.inspection_sha256, expected_language="en-US")
        with self.assertRaises(self.m.PdfDocumentStructureCoverageError):
            self.bind(inspection_set=updated_set,
                      expected_inspection_set_sha256=updated_set.inspection_set_sha256)

    def test_no_staged_long_document_promotion_or_unsupported_locale(self):
        for count in (65, 129, 300):
            # Existing upstream 64-page native coverage already refuses such
            # dimensions. This successor must never manufacture a bypass.
            with self.assertRaises(native_content_api.PdfDocumentContentError):
                synthetic_inputs(count)
        original = self.args["inspection_set"]
        with self.assertRaises(set_api.PdfInspectionSetError):
            set_api.bind_pdf_inspection_set(
                page_bundle=original.page_bundle,
                document_metadata=original.document_metadata,
                page_tags=original.page_tags, mcid_coverage=original.mcid_coverage,
                expected_page_bundle_sha256=original.page_bundle.bundle_sha256,
                expected_metadata_sha256=original.document_metadata.inspection_sha256,
                expected_page_tags_sha256=original.page_tags.inspection_sha256,
                expected_mcid_sha256=original.mcid_coverage.inspection_sha256,
                expected_language="pt-BR")
        altered = dict(self.args)
        altered["expected_coverage_profile_sha256"] = "1" * 64
        with self.assertRaises(self.m.PdfDocumentStructureCoverageError):
            self.bind(altered)

    def test_mutated_original_nested_receipts_rejected_on_readback(self):
        original = self.bind()
        object.__setattr__(self.args["structure_tree"], "mapped_mcids", 0)
        with self.assertRaises(self.m.PdfDocumentStructureCoverageError):
            original.to_dict()
        with self.assertRaises(self.m.PdfDocumentStructureCoverageError):
            self.bind()

    def test_profile_disabled_and_native_profile_drift_fail_closed(self):
        with patch.dict(os.environ, {"OMNIGENIS_PDF_DOCUMENT_STRUCTURE_COVERAGE_DISABLED": "1"}):
            with self.assertRaises(self.m.PdfDocumentStructureCoverageError):
                self.bind()
        with patch.object(tree_api, "PROFILE_ID", "other-tree-profile"):
            with self.assertRaises(self.m.PdfDocumentStructureCoverageError):
                self.bind()
        for module, name in ((tree_api, "POLICY_ID"),
                             (metadata_api, "METADATA_PROFILE_ID"),
                             (tags_api, "POLICY_ID"), (mcid_api, "POLICY_ID")):
            with self.subTest(policy=name, module=module.__name__), \
                    patch.object(module, name, "unreviewed-policy"):
                with self.assertRaises(self.m.PdfDocumentStructureCoverageError):
                    self.bind()
        for key in ("OMNIGENIS_PDF_DOCUMENT_METADATA_DISABLED",
                    "OMNIGENIS_PDF_PAGE_TAGS_DISABLED",
                    "OMNIGENIS_PDF_MCID_COVERAGE_DISABLED",
                    "OMNIGENIS_PDF_STRUCTURE_TREE_DISABLED"):
            with self.subTest(disable=key), patch.dict(os.environ, {key: "1"}):
                with self.assertRaises(self.m.PdfDocumentStructureCoverageError):
                    self.bind()

    def test_detached_determinism_and_source_unchanged_no_new_workers(self):
        first = self.bind()
        second = self.bind()
        self.assertEqual(first.to_dict(), second.to_dict())
        detached = first.to_dict()
        detached["mapped_mcids"] = 98765
        self.assertNotEqual(first.to_dict()["mapped_mcids"], detached["mapped_mcids"])
        with patch("subprocess.Popen", side_effect=AssertionError("new worker forbidden")), \
                patch("socket.socket", side_effect=AssertionError("network forbidden")):
            self.assertEqual(first.to_dict(), self.bind().to_dict())
        self.assertFalse(first.to_dict()["default_pipeline_activated"])
        self.assertFalse(first.to_dict()["source_storage_authenticated"])
        self.assertFalse(first.to_dict()["whole_pdf_safety_qualified"])
        self.assertFalse(first.to_dict()["aggregate_job_resources_qualified"])
        self.assertFalse(first.to_dict()["finding_completeness_verified"])

    def test_profile_manifest_is_exact_stable_export_and_no_public_private_source(self):
        path = ROOT / "reporting/pdf-document-structure-coverage.v1.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["profile"], self.m.document_structure_coverage_profile())
        self.assertEqual(manifest["profile_sha256"], self.m.PROFILE_SHA256)
        self.assertEqual(sha256(_json_bytes(manifest["profile"])).hexdigest(),
                         self.m.PROFILE_SHA256)
        self.assertFalse(self.m.document_structure_coverage_profile()["release_authorized"])


if __name__ == "__main__":
    unittest.main()
