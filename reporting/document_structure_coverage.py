"""Opt-in exact-document structural metadata linkage over existing unsigned receipts.

The previously complete declared page/raster/source-text chain and the exact
inspection set must share a page bundle. A separately guarded forward structure
tree result must match that set's MCID/ParentTree result and current text plan.
This pure local join never runs a worker or authenticates any unsigned receipt.
No PDF/UA, visual, source/storage, security, resource or release claim follows.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
import os

from reporting.bindings import _digest
from reporting.page_checkpoints import _json_bytes
from reporting import document_raster_coverage as raster_api
from reporting import pdf_document_metadata as metadata_api
from reporting import pdf_inspection_set as set_api
from reporting import pdf_mcid_coverage as mcid_api
from reporting import pdf_page_tags as tags_api
from reporting import pdf_structure_tree as tree_api


PROFILE_ID = "generated-pdf-document-structure-coverage-v1"
_PARENT_PROFILE_SHA256 = raster_api.PROFILE_SHA256
_MAX_PAGES = 64
_MAX_PDF_BYTES = 8 * 1024 * 1024
_LANGUAGE = "en-US"
_DISABLE = "OMNIGENIS_PDF_DOCUMENT_STRUCTURE_COVERAGE_DISABLED"
_DEPENDENCY_DISABLES = (
    "OMNIGENIS_PDF_DOCUMENT_METADATA_DISABLED",
    "OMNIGENIS_PDF_PAGE_TAGS_DISABLED",
    "OMNIGENIS_PDF_MCID_COVERAGE_DISABLED",
    "OMNIGENIS_PDF_STRUCTURE_TREE_DISABLED",
)
_NATIVE_PAGES = (512, 512, 512, 64)


class PdfDocumentStructureCoverageError(ValueError):
    """No invalid, stale or unsupported unsigned structure set becomes a receipt."""


def document_structure_coverage_profile() -> dict:
    """Expose pinned finite old native capabilities, not a newly admitted worker."""
    natives = (metadata_api, tags_api, mcid_api, tree_api)
    return {
        "schema_version": "1.0.0", "profile_id": PROFILE_ID,
        "parent_raster_profile_sha256": _PARENT_PROFILE_SHA256,
        "inspection_set_profile_id": set_api.PROFILE_ID,
        "document_metadata_profile_id": metadata_api.PROFILE_ID,
        "document_metadata_policy_id": metadata_api.METADATA_PROFILE_ID,
        "page_tags_profile_id": tags_api.PROFILE_ID,
        "page_tags_policy_id": tags_api.POLICY_ID,
        "mcid_coverage_profile_id": mcid_api.PROFILE_ID,
        "mcid_coverage_policy_id": mcid_api.POLICY_ID,
        "structure_tree_profile_id": tree_api.PROFILE_ID,
        "structure_tree_parser_version": tree_api.PARSER_VERSION,
        "structure_tree_policy_id": tree_api.POLICY_ID,
        "language": _LANGUAGE,
        "max_bound_pages": min(_MAX_PAGES, *(n.MAX_DOCUMENT_PAGES for n in natives)),
        "max_bound_pdf_bytes": min(_MAX_PDF_BYTES, *(n.MAX_PDF_BYTES for n in natives)),
        "cross_inspector_mcid_count_agreement_required": True,
        "reconciliation_scope": "EXACT_DECLARED_PAGE_STRUCTURAL_LINKAGE_METADATA_ONLY",
        "worker_results_authenticated": False,
        "source_storage_authenticated": False,
        "all_file_revisions_inspected": False,
        "visible_content_equivalence_verified": False,
        "semantic_tag_roles_qualified": False,
        "reading_order_verified": False,
        "pdf_ua_qualified": False,
        "whole_pdf_safety_qualified": False,
        "aggregate_job_resources_qualified": False,
        "default_pipeline_activated": False,
        "release_authorized": False,
    }


PROFILE_SHA256 = sha256(_json_bytes(document_structure_coverage_profile())).hexdigest()


def _profile(expected: str) -> None:
    """Refuse disabled or drifted dependencies, including any loosened native ceiling."""
    _digest(expected)
    natives = (metadata_api, tags_api, mcid_api, tree_api)
    if (expected != PROFILE_SHA256 or os.environ.get(_DISABLE) == "1"
            or any(os.environ.get(key) == "1" for key in _DEPENDENCY_DISABLES)
            or raster_api.PROFILE_SHA256 != _PARENT_PROFILE_SHA256
            or tuple(n.MAX_DOCUMENT_PAGES for n in natives) != _NATIVE_PAGES
            or any(n.MAX_PDF_BYTES != _MAX_PDF_BYTES for n in natives)
            or tree_api.LANGUAGE != _LANGUAGE
            or sha256(_json_bytes(document_structure_coverage_profile())).hexdigest()
               != PROFILE_SHA256):
        raise ValueError("document structural coverage profile unavailable")


@dataclass(frozen=True, slots=True, repr=False)
class PdfDocumentStructureCoverage:
    """Sealed exact-job derivative of real typed receipts, never a signature."""

    document_raster_coverage: raster_api.PdfDocumentRasterCoverage
    inspection_set: set_api.PdfInspectionSet
    structure_tree: tree_api.PdfStructureTreeInspection
    expected_raster_coverage_sha256: str
    expected_inspection_set_sha256: str
    expected_structure_tree_sha256: str
    expected_coverage_profile_sha256: str
    _sealed_sha256: str = field(init=False, repr=False, compare=False)

    def _record(self) -> dict:
        """Recheck typed parents and reject source/job/plan/count cross-family drift."""
        _profile(self.expected_coverage_profile_sha256)
        for expected in (self.expected_raster_coverage_sha256,
                         self.expected_inspection_set_sha256,
                         self.expected_structure_tree_sha256):
            _digest(expected)
        if (type(self.document_raster_coverage) is not raster_api.PdfDocumentRasterCoverage
                or type(self.inspection_set) is not set_api.PdfInspectionSet
                or type(self.structure_tree) is not tree_api.PdfStructureTreeInspection):
            raise ValueError("document structural receipt type mismatch")
        raster = self.document_raster_coverage.to_dict()
        inspections = self.inspection_set.to_dict()
        tree = self.structure_tree.to_dict()
        if (raster["coverage_sha256"] != self.expected_raster_coverage_sha256
                or self.inspection_set.inspection_set_sha256 != self.expected_inspection_set_sha256):
            raise ValueError("document structural caller digest mismatch")
        if tree_api.PARSER_VERSION != inspections["document_receipts"]["metadata"]["record"]["parser_version"]:
            raise ValueError("structural PDF parser version mismatch")
        if tree_api.PARSER_VERSION != tree["parser_version"]:
            raise ValueError("structural parser version mismatch")
        if (self.structure_tree.inspection_sha256 != self.expected_structure_tree_sha256
                or raster["status"] != "COMPLETE_RASTER_GEOMETRY_METADATA_BOUND"
                or inspections["status"] != "INSPECTION_SET_METADATA_BOUND"
                or tree["status"] != tree_api.STATUS
                or inspections["language"] != _LANGUAGE
                or tree["language"] != _LANGUAGE
                or tree["policy_id"] != tree_api.POLICY_ID):
            raise ValueError("document structural pins, status or locale mismatch")

        original_bundle = (self.document_raster_coverage.document_content
                           .document_inspection.inspections)
        if (inspections["page_bundle_sha256"] != original_bundle.bundle_sha256
                or inspections["page_bundle"]["object_graph_sha256"]
                   != original_bundle.object_inspection.inspection_sha256):
            raise ValueError("structural observations bound to foreign page bundle")
        for key in ("namespace_id", "job_id", "request_sha256",
                    "pdf_sha256", "ir_sha256"):
            if inspections[key] != raster[key]:
                raise ValueError("foreign structure job or candidate")
        count = raster["declared_page_count"]
        if (type(count) is not int or not 1 <= count <= _MAX_PAGES
                or raster["pdf_byte_count"] > _MAX_PDF_BYTES
                or raster["inspected_physical_pages"] != count
                or inspections["page_count"] != count
                or tree["page_count"] != count or tree["inspected_pages"] != count
                or inspections["page_bundle"]["text_stream"]["represented_pages"] != count
                or inspections["page_bundle"]["raster_stream"]["represented_pages"] != count
                or tree["pdf_sha256"] != raster["pdf_sha256"]
                or tree["ir_sha256"] != raster["ir_sha256"]):
            raise ValueError("structural physical page/source plan mismatch")
        text_plan = inspections["page_bundle"]["text_stream"]["plan_sha256"]
        parent_plan = self.document_raster_coverage.document_content.document_inspection.document.text_plan.plan_sha256
        if tree["plan_sha256"] != text_plan or text_plan != parent_plan:
            raise ValueError("structural text plan mismatch")
        roles = inspections["document_receipts"]
        meta, tags, mcids = (roles[role]["record"] for role in
                              ("metadata", "page_tags", "mcid_coverage"))
        if (meta["profile_id"] != metadata_api.PROFILE_ID
                or meta["metadata_profile_id"] != metadata_api.METADATA_PROFILE_ID
                or tags["profile_id"] != tags_api.PROFILE_ID
                or mcids["profile_id"] != mcid_api.PROFILE_ID
                or tags["policy_id"] != tags_api.POLICY_ID
                or mcids["policy_id"] != mcid_api.POLICY_ID
                or tree["profile_id"] != tree_api.PROFILE_ID
                or any(r["plan_sha256"] != text_plan for r in (meta, tags, mcids))
                or tags["tagged_pages"] != count
                or tags["parent_tree_entries"] != count
                or mcids["inspected_pages"] != count
                or mcids["matched_mcids"] != tree["mapped_mcids"]
                or tree["forward_reverse_linkage_verified"] is not True):
            raise ValueError("document structural page/MCID/tree disagreement")

        return {
            "schema_version": "1.0.0", "profile_id": PROFILE_ID,
            "coverage_profile_sha256": self.expected_coverage_profile_sha256,
            "status": "COMPLETE_DOCUMENT_STRUCTURAL_LINKAGE_METADATA_BOUND",
            "conformance_scope": "CURRENT_EN_US_DECLARED_DOCUMENT_STRUCTURAL_METADATA_ONLY",
            "language": _LANGUAGE,
            "namespace_id": raster["namespace_id"], "job_id": raster["job_id"],
            "request_sha256": raster["request_sha256"],
            "pdf_sha256": raster["pdf_sha256"], "ir_sha256": raster["ir_sha256"],
            "declared_page_count": count, "pdf_byte_count": raster["pdf_byte_count"],
            "source_text_sha256": raster["source_text_sha256"],
            "text_window_plan_sha256": text_plan,
            "raster_coverage_sha256": self.expected_raster_coverage_sha256,
            "inspection_set_sha256": self.expected_inspection_set_sha256,
            "structure_tree_sha256": self.expected_structure_tree_sha256,
            "inspected_structural_pages": tree["inspected_pages"],
            "tagged_pages": tags["tagged_pages"],
            "parent_tree_entries": tags["parent_tree_entries"],
            "matched_mcids": mcids["matched_mcids"],
            "mapped_mcids": tree["mapped_mcids"],
            "structure_elements": tree["structure_elements"],
            "max_tree_depth": tree["max_tree_depth"],
            "structure_traversal_visits": tree["traversal_visits"],
            "declared_page_structural_reference_agreement": True,
            "worker_results_authenticated": False,
            "source_storage_authenticated": False,
            "whole_pdf_safety_qualified": False,
            "all_file_revisions_inspected": False,
            "visible_content_equivalence_verified": False,
            "semantic_tag_roles_qualified": False,
            "reading_order_verified": False,
            "pdf_ua_qualified": False,
            "finding_completeness_verified": False,
            "aggregate_job_resources_qualified": False,
            "default_pipeline_activated": False,
            "release_authorized": False,
            "release_authorization": "NOT_ESTABLISHED",
        }

    def __post_init__(self) -> None:
        """Seal initially valid input; mutations never reseal an existing instance."""
        try:
            digest = sha256(_json_bytes(self._record())).hexdigest()
            if hasattr(self, "_sealed_sha256") and self._sealed_sha256 != digest:
                raise ValueError("document structure coverage mutated")
            object.__setattr__(self, "_sealed_sha256", digest)
        except Exception:
            raise PdfDocumentStructureCoverageError(
                "pdf_document_structure_coverage_invalid") from None

    def to_dict(self) -> dict:
        """Detach only the original metadata, after all retained children revalidate."""
        try:
            record = self._record()
            if sha256(_json_bytes(record)).hexdigest() != self._sealed_sha256:
                raise ValueError("document structure coverage mutated")
            return json.loads(_json_bytes({**record, "coverage_sha256": self._sealed_sha256}))
        except Exception:
            raise PdfDocumentStructureCoverageError(
                "pdf_document_structure_coverage_invalid") from None

    @property
    def coverage_sha256(self) -> str:
        """Deterministic local checksum; no authentication or acceptance signature."""
        self.to_dict()
        return self._sealed_sha256


def bind_pdf_document_structure_coverage(
    *, document_raster_coverage: raster_api.PdfDocumentRasterCoverage,
    inspection_set: set_api.PdfInspectionSet,
    structure_tree: tree_api.PdfStructureTreeInspection,
    expected_raster_coverage_sha256: str,
    expected_inspection_set_sha256: str,
    expected_structure_tree_sha256: str,
    expected_coverage_profile_sha256: str,
) -> PdfDocumentStructureCoverage:
    """Bind original typed receipts only, with independent closed caller pins."""
    return PdfDocumentStructureCoverage(
        document_raster_coverage=document_raster_coverage,
        inspection_set=inspection_set, structure_tree=structure_tree,
        expected_raster_coverage_sha256=expected_raster_coverage_sha256,
        expected_inspection_set_sha256=expected_inspection_set_sha256,
        expected_structure_tree_sha256=expected_structure_tree_sha256,
        expected_coverage_profile_sha256=expected_coverage_profile_sha256,
    )
