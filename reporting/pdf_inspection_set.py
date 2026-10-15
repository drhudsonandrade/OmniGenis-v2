"""Bind existing page, metadata, tag and MCID receipts to one exact job/document.

This optional pure boundary joins supplied unsigned observations. It does not
run inspectors, read a PDF, persist checkpoints, admit an execution profile or
authenticate a job. Matching expected hashes establish metadata agreement only;
they never establish scientific correctness, full accessibility or release.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json

from reporting.page_checkpoints import _json_bytes
from reporting.pdf_inspection_bundle import PdfInspectionBundle, MAX_BUNDLE_BYTES, _pin
from reporting.pdf_document_metadata import PdfDocumentMetadataInspection, LANGUAGE, PARSER_VERSION
from reporting.pdf_page_tags import PdfPageTagInspection
from reporting.pdf_mcid_coverage import PdfMcidCoverageInspection

PROFILE_ID = "bound-pdf-inspection-set-v1"
MAX_SET_BYTES = MAX_BUNDLE_BYTES + 16 * 1024
_CONTEXT = ("namespace_id", "job_id", "request_sha256", "resource_profile_sha256")
_DOCUMENT = ("pdf_sha256", "ir_sha256", "page_count")


class PdfInspectionSetError(ValueError):
    """Content-free rejection; no incomplete set produces successful metadata."""


@dataclass(frozen=True, slots=True, repr=False)
class PdfInspectionSet:
    """One sealed unsigned collection, never an execution attestation or release permit."""

    page_bundle: PdfInspectionBundle
    document_metadata: PdfDocumentMetadataInspection
    page_tags: PdfPageTagInspection
    mcid_coverage: PdfMcidCoverageInspection
    expected_page_bundle_sha256: str
    expected_metadata_sha256: str
    expected_page_tags_sha256: str
    expected_mcid_sha256: str
    expected_language: str
    _sealed_sha256: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate direct construction and forbid silently resealing a changed instance."""
        try:
            digest = hashlib.sha256(self._validated_bytes()).hexdigest()
            if hasattr(self, "_sealed_sha256") and self._sealed_sha256 != digest:
                raise ValueError("inspection set changed after binding")
            object.__setattr__(self, "_sealed_sha256", digest)
        except Exception:
            raise PdfInspectionSetError("pdf_inspection_set_invalid") from None

    def _validated_bytes(self) -> bytes:
        """Capture revalidated records and require exact per-role pins and document identity."""
        for pin in (self.expected_page_bundle_sha256, self.expected_metadata_sha256,
                    self.expected_page_tags_sha256, self.expected_mcid_sha256):
            _pin(pin)
        if type(self.expected_language) is not str or self.expected_language != LANGUAGE:
            raise ValueError("inspection set locale not qualified")
        if type(self.page_bundle) is not PdfInspectionBundle:
            raise ValueError("exact page bundle type required")
        page_bytes = self.page_bundle.to_bytes()
        if hashlib.sha256(page_bytes).hexdigest() != self.expected_page_bundle_sha256:
            raise ValueError("inspection set page bundle pin mismatch")
        pages = json.loads(page_bytes)
        identity = {key: pages[key] for key in _DOCUMENT}
        identity["plan_sha256"] = pages["text_stream"]["plan_sha256"]
        receipts = {}
        for role, item, expected, cls in (
            ("metadata", self.document_metadata, self.expected_metadata_sha256, PdfDocumentMetadataInspection),
            ("page_tags", self.page_tags, self.expected_page_tags_sha256, PdfPageTagInspection),
            ("mcid_coverage", self.mcid_coverage, self.expected_mcid_sha256, PdfMcidCoverageInspection),
        ):
            if type(item) is not cls:
                raise ValueError("inspection set receipt role mismatch")
            record = item.to_dict()
            if (any(record[key] != value for key, value in identity.items())
                    or record["language"] != self.expected_language
                    or record["parser_version"] != PARSER_VERSION):
                raise ValueError("inspection set document/profile mismatch")
            if hashlib.sha256(_json_bytes(record)).hexdigest() != expected:
                raise ValueError("inspection set receipt pin mismatch")
            receipts[role] = {"inspection_sha256": expected, "record": record}
        record = {
            "schema_version": "1.0.0", "profile_id": PROFILE_ID,
            "status": "INSPECTION_SET_METADATA_BOUND", "language": self.expected_language,
            **{key: pages[key] for key in (*_CONTEXT, *_DOCUMENT)},
            "inspection_dimensions": ["text", "raster", "object_graph", "document_metadata", "page_tags", "mcid_linkage"],
            "page_bundle_sha256": self.expected_page_bundle_sha256,
            "page_bundle": pages, "document_receipts": receipts,
            "native_execution_performed": False, "worker_results_authenticated": False,
            "whole_pdf_safety_qualified": False, "finding_completeness_verified": False,
            "text_equivalence_verified": False, "accessibility_qualified": False,
            "aggregate_job_resources_qualified": False, "release_authorized": False,
            "release_authorization": "NOT_ESTABLISHED",
        }
        payload = _json_bytes(record)
        if len(payload) > MAX_SET_BYTES:
            raise ValueError("inspection set metadata byte budget exceeded")
        return payload

    def to_bytes(self) -> bytes:
        """Expose only the exact sealed representation, rechecking every retained input."""
        try:
            payload = self._validated_bytes()
            if hashlib.sha256(payload).hexdigest() != self._sealed_sha256:
                raise ValueError("inspection set changed after binding")
            return payload
        except Exception:
            raise PdfInspectionSetError("pdf_inspection_set_invalid") from None

    def to_dict(self) -> dict:
        """Return detached hashes/counts and unchanged conservative child scope statements."""
        return json.loads(self.to_bytes())

    @property
    def inspection_set_sha256(self) -> str:
        """Hash exact metadata bytes; this digest is neither a signature nor authorization."""
        return hashlib.sha256(self.to_bytes()).hexdigest()


def bind_pdf_inspection_set(
    *, page_bundle: PdfInspectionBundle, document_metadata: PdfDocumentMetadataInspection,
    page_tags: PdfPageTagInspection, mcid_coverage: PdfMcidCoverageInspection,
    expected_page_bundle_sha256: str, expected_metadata_sha256: str,
    expected_page_tags_sha256: str, expected_mcid_sha256: str, expected_language: str,
) -> PdfInspectionSet:
    """Reconcile six supplied inspection dimensions under independently resolved job pins.

    The page-bundle expectation must come from the caller's trusted job context.
    Later document receipts bind its text plan; its separate raster plan retains
    its complete page coverage. This function does not run missing inspections,
    authenticate expectations or promote any document to a release state.
    """
    return PdfInspectionSet(page_bundle=page_bundle, document_metadata=document_metadata,
        page_tags=page_tags, mcid_coverage=mcid_coverage,
        expected_page_bundle_sha256=expected_page_bundle_sha256,
        expected_metadata_sha256=expected_metadata_sha256,
        expected_page_tags_sha256=expected_page_tags_sha256,
        expected_mcid_sha256=expected_mcid_sha256, expected_language=expected_language)
