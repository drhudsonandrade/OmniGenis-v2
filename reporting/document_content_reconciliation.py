"""Optional exact-job binding of unsigned normalized full-document text evidence.

The previous document reconciliation binds declared text/raster ranges and the
effective object graph to one job. This additive metadata-only boundary pins an
existing native whole-document text receipt to that same PDF, IR and text plan.
It never launches workers or authenticates source storage/results. The receipt
must fit the selected native 64-page/16-MiB file class; decoded-text bounds and
scientific/clinical release requirements are separate.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
import os

from reporting._pdf_document_byte_budget import MAX_PDF_BYTES as _MAX_PDF_BYTES
from reporting.bindings import _digest
from reporting.page_checkpoints import _json_bytes
from reporting import document_inspection_reconciliation as prior
from reporting import pdf_document_content as native_content
from reporting import pdf_object_graph as object_graph


PROFILE_ID = "generated-pdf-document-content-reconciliation-v1"
_MAX_PAGES = 64
_LANGUAGE = "en-US"
_DISABLE = "OMNIGENIS_PDF_DOCUMENT_CONTENT_RECONCILIATION_DISABLED"


class PdfDocumentContentReconciliationError(ValueError):
    """No invalid, stale or unauthorized unsigned join produces a receipt."""


def document_content_reconciliation_profile() -> dict:
    """Pin existing independent native limits without creating an execution class."""
    return {
        "schema_version": "1.0.0", "profile_id": PROFILE_ID,
        "document_inspection_profile_sha256": prior.PROFILE_SHA256,
        "native_content_profile_id": native_content.PROFILE_ID,
        "native_content_policy_id": native_content.POLICY_ID,
        "native_content_parser_version": native_content.PARSER_VERSION,
        "language": native_content.LANGUAGE,
        "normalization": "IGNORE_CR_LF_FORM_FEED_ONLY",
        "max_bound_pdf_bytes": min(object_graph.MAX_PDF_BYTES, native_content.MAX_PDF_BYTES),
        "max_bound_pages": min(object_graph.MAX_DOCUMENT_PAGES,
                               native_content.MAX_DOCUMENT_PAGES),
        "worker_results_authenticated": False,
        "source_storage_authenticated": False,
        "scientific_equivalence_verified": False,
        "aggregate_job_resources_qualified": False,
        "default_pipeline_activated": False,
        "release_authorized": False,
    }


PROFILE_SHA256 = sha256(_json_bytes(document_content_reconciliation_profile())).hexdigest()


def _profile(expected: str) -> None:
    """Refuse disabled or drifted dependencies, including any expanded native limit."""
    _digest(expected)
    if (expected != PROFILE_SHA256 or os.environ.get(_DISABLE) == "1"
            or os.environ.get("OMNIGENIS_PDF_DOCUMENT_CONTENT_DISABLED") == "1"
            or native_content.MAX_DOCUMENT_PAGES != _MAX_PAGES
            or native_content.MAX_PDF_BYTES != _MAX_PDF_BYTES
            or native_content.LANGUAGE != _LANGUAGE
            or object_graph.MAX_PDF_BYTES != _MAX_PDF_BYTES
            or sha256(_json_bytes(document_content_reconciliation_profile())).hexdigest()
            != PROFILE_SHA256):
        raise ValueError("document source content profile unavailable")


@dataclass(frozen=True, slots=True, repr=False)
class PdfDocumentContentReconciliation:
    """One sealed unsigned source-text agreement, not execution attestation."""

    document_inspection: prior.PdfDocumentInspectionReconciliation
    document_content: native_content.PdfDocumentContentInspection
    expected_document_inspection_sha256: str
    expected_content_inspection_sha256: str
    expected_source_text_sha256: str
    expected_reconciliation_profile_sha256: str
    _sealed_sha256: str = field(init=False, repr=False, compare=False)

    def _record(self) -> dict:
        """Recheck both typed receipts and all shared exact job/source identities."""
        _profile(self.expected_reconciliation_profile_sha256)
        for expected in (self.expected_document_inspection_sha256,
                         self.expected_content_inspection_sha256,
                         self.expected_source_text_sha256):
            _digest(expected)
        if (type(self.document_inspection) is not prior.PdfDocumentInspectionReconciliation
                or type(self.document_content) is not native_content.PdfDocumentContentInspection):
            raise ValueError("document content receipt types invalid")

        bound = self.document_inspection.to_dict()
        document = self.document_inspection.document.to_dict()
        content = self.document_content.to_dict()
        if (bound["reconciliation_sha256"] != self.expected_document_inspection_sha256
                or self.document_content.inspection_sha256 != self.expected_content_inspection_sha256
                or content["expected_text_sha256"] != self.expected_source_text_sha256
                or content["extracted_text_sha256"] != self.expected_source_text_sha256):
            raise ValueError("document content trusted pin mismatch")

        for key in ("pdf_sha256", "ir_sha256"):
            if content[key] != bound[key] or document[key] != bound[key]:
                raise ValueError("document content candidate bytes mismatch")
        count = bound["declared_page_count"]
        if (type(count) is not int or not 1 <= count <= _MAX_PAGES
                or document["declared_page_count"] != count
                or content["page_count"] != count
                or content["inspected_pages"] != count
                or bound["text_pages_represented_by_unsigned_receipts"] != count
                or bound["raster_pages_represented_by_unsigned_receipts"] != count
                or document["pdf_byte_count"] > _MAX_PDF_BYTES
                or content["plan_sha256"] != document["text_window_plan_sha256"]
                or content["parser_version"] != native_content.PARSER_VERSION
                or content["language"] != _LANGUAGE
                or content["policy_id"] != native_content.POLICY_ID
                or content["normalization"] != "IGNORE_CR_LF_FORM_FEED_ONLY"
                or content["normalized_text_equivalence_verified"] is not True):
            raise ValueError("document content exact plan or native profile mismatch")

        return {
            "schema_version": "1.0.0", "profile_id": PROFILE_ID,
            "reconciliation_profile_sha256": self.expected_reconciliation_profile_sha256,
            "status": "DOCUMENT_CONTENT_RECONCILED_UNSIGNED",
            "conformance_scope": "CURRENT_EN_US_SEMANTIC_SECTION_NORMALIZED_TEXT_ONLY",
            "namespace_id": bound["namespace_id"], "job_id": bound["job_id"],
            "request_sha256": bound["request_sha256"],
            "resource_profile_sha256": bound["resource_profile_sha256"],
            "pdf_sha256": bound["pdf_sha256"], "ir_sha256": bound["ir_sha256"],
            "declared_page_count": count, "pdf_byte_count": document["pdf_byte_count"],
            "text_window_plan_sha256": document["text_window_plan_sha256"],
            "document_inspection_sha256": self.expected_document_inspection_sha256,
            "document_content_sha256": self.expected_content_inspection_sha256,
            "source_text_sha256": self.expected_source_text_sha256,
            "inspected_text_pages": content["inspected_pages"],
            "unsigned_normalized_text_digest_agreement": True,
            "budget_class": bound["budget_class"],
            "execution_decision": bound["execution_decision"],
            "worker_results_authenticated": False,
            "source_storage_authenticated": False,
            "scientific_equivalence_verified": False,
            "visible_glyphs_verified": False,
            "all_file_revisions_inspected": False,
            "whole_pdf_safety_qualified": False,
            "finding_completeness_verified": False,
            "accessibility_qualified": False,
            "aggregate_job_resources_qualified": False,
            "default_pipeline_activated": False,
            "release_authorized": False,
            "release_authorization": "NOT_ESTABLISHED",
        }

    def __post_init__(self) -> None:
        """Seal valid metadata once; never reseal a mutated input or instance."""
        try:
            digest = sha256(_json_bytes(self._record())).hexdigest()
            if hasattr(self, "_sealed_sha256") and self._sealed_sha256 != digest:
                raise ValueError("document content reconciliation mutated")
            object.__setattr__(self, "_sealed_sha256", digest)
        except Exception:
            raise PdfDocumentContentReconciliationError(
                "pdf_document_content_reconciliation_invalid") from None

    def to_dict(self) -> dict:
        """Return detached metadata only after rechecking original nested evidence."""
        try:
            record = self._record()
            if sha256(_json_bytes(record)).hexdigest() != self._sealed_sha256:
                raise ValueError("document content reconciliation mutated")
            return json.loads(_json_bytes({**record,
                "reconciliation_sha256": self._sealed_sha256}))
        except Exception:
            raise PdfDocumentContentReconciliationError(
                "pdf_document_content_reconciliation_invalid") from None

    @property
    def reconciliation_sha256(self) -> str:
        """Deterministic local metadata digest, never a signature."""
        self.to_dict()
        return self._sealed_sha256


def bind_pdf_document_content_reconciliation(
    *, document_inspection: prior.PdfDocumentInspectionReconciliation,
    document_content: native_content.PdfDocumentContentInspection,
    expected_document_inspection_sha256: str, expected_content_inspection_sha256: str,
    expected_source_text_sha256: str, expected_reconciliation_profile_sha256: str,
) -> PdfDocumentContentReconciliation:
    """Join existing unsigned metadata without executing or admitting new work."""
    return PdfDocumentContentReconciliation(
        document_inspection=document_inspection, document_content=document_content,
        expected_document_inspection_sha256=expected_document_inspection_sha256,
        expected_content_inspection_sha256=expected_content_inspection_sha256,
        expected_source_text_sha256=expected_source_text_sha256,
        expected_reconciliation_profile_sha256=expected_reconciliation_profile_sha256,
    )
