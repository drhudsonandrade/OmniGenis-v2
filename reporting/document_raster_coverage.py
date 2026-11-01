"""Optional complete-page raster geometry summary over existing unsigned receipts.

The source/document parent already binds every declared inspection interval.
This derivative rechecks the real typed raster-window metadata, adds finite
document-wide geometry accounting and a clearly labeled ordered commitment.
It never executes a worker, authenticates a result or authorizes report release.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
import os

from reporting._pdf_document_byte_budget import MAX_PDF_BYTES as _MAX_BYTES
from reporting.bindings import _digest
from reporting.page_checkpoints import _json_bytes
from reporting import document_content_reconciliation as content_api
from reporting import document_inspection_reconciliation as inspection_api
from reporting import pdf_inspection_bundle as bundle_api
from reporting import pdf_raster_windows as raster


PROFILE_ID = "generated-pdf-document-raster-coverage-v1"
_PARENT_PROFILE_SHA256 = content_api.PROFILE_SHA256
_MAX_PAGES = 64
_WINDOW_PAGES = 4
_RASTER_MAX_DOCUMENT_PAGES = 512
_RASTER_MAX_PIXELS_PER_PAGE = 4_000_000
_RASTER_MAX_WINDOW_PIXELS = 16_000_000
_MIN_EDGE_MARGIN_PX = 2
_DISABLE = "OMNIGENIS_PDF_DOCUMENT_RASTER_COVERAGE_DISABLED"


class PdfDocumentRasterCoverageError(ValueError):
    """Refuse invalid, mutated or unsupported unsigned raster summaries."""


def document_raster_coverage_profile() -> dict:
    """Pin exact upstream limits without creating a new execution profile."""
    return {
        "schema_version": "1.0.0", "profile_id": PROFILE_ID,
        "parent_content_profile_sha256": _PARENT_PROFILE_SHA256,
        "native_raster_profile_id": raster.PROFILE_ID,
        "native_raster_parser_version": raster.PARSER_VERSION,
        "native_raster_pillow_version": raster.PILLOW_VERSION,
        "native_raster_tool_sha256": raster.TOOL_SHA256,
        "language": "en-US",
        "max_bound_pages": min(_MAX_PAGES, raster.MAX_DOCUMENT_PAGES),
        "max_bound_pdf_bytes": min(_MAX_BYTES, raster.MAX_PDF_BYTES),
        "raster_window_pages": raster.MAX_WINDOW_PAGES,
        "max_raster_pixels_per_page": raster.MAX_PIXELS_PER_PAGE,
        "max_raster_pixels_per_window": raster.MAX_TOTAL_PIXELS,
        "min_edge_margin_px": raster.MIN_EDGE_MARGIN_PX,
        "ordered_digest_kind": "RASTER_WINDOW_METADATA_ONLY_NOT_FULL_IMAGE",
        "worker_results_authenticated": False,
        "source_storage_authenticated": False,
        "whole_document_visual_equivalence_verified": False,
        "full_accessibility_qualified": False,
        "aggregate_job_resources_qualified": False,
        "default_pipeline_activated": False,
        "release_authorized": False,
    }


PROFILE_SHA256 = sha256(_json_bytes(document_raster_coverage_profile())).hexdigest()


def _profile(expected: str) -> None:
    """Refuse disabled/drifted native classes, including broadened page budgets."""
    _digest(expected)
    if (expected != PROFILE_SHA256
            or os.environ.get(_DISABLE) == "1"
            or os.environ.get("OMNIGENIS_PDF_RASTER_WINDOWS_DISABLED") == "1"
            or content_api.PROFILE_SHA256 != _PARENT_PROFILE_SHA256
            or raster.MAX_DOCUMENT_PAGES != _RASTER_MAX_DOCUMENT_PAGES
            or raster.MAX_PDF_BYTES != _MAX_BYTES
            or raster.MAX_WINDOW_PAGES != _WINDOW_PAGES
            or raster.MAX_PIXELS_PER_PAGE != _RASTER_MAX_PIXELS_PER_PAGE
            or raster.MAX_TOTAL_PIXELS != _RASTER_MAX_WINDOW_PIXELS
            or raster.MIN_EDGE_MARGIN_PX != _MIN_EDGE_MARGIN_PX
            or sha256(_json_bytes(document_raster_coverage_profile())).hexdigest()
               != PROFILE_SHA256):
        raise ValueError("document raster coverage profile unavailable")


@dataclass(frozen=True, slots=True, repr=False)
class PdfDocumentRasterCoverage:
    """One sealed local aggregate of already-bound unsigned raster intervals."""

    document_content: content_api.PdfDocumentContentReconciliation
    expected_document_content_sha256: str
    expected_raster_checkpoint_sha256: str
    expected_coverage_profile_sha256: str
    _sealed_sha256: str = field(init=False, repr=False, compare=False)

    def _record(self) -> dict:
        """Revalidate the complete source job and every original native interval."""
        _profile(self.expected_coverage_profile_sha256)
        _digest(self.expected_document_content_sha256)
        _digest(self.expected_raster_checkpoint_sha256)
        if type(self.document_content) is not content_api.PdfDocumentContentReconciliation:
            raise ValueError("content reconciliation type invalid")
        content = self.document_content.to_dict()
        if content["reconciliation_sha256"] != self.expected_document_content_sha256:
            raise ValueError("content reconciliation caller pin mismatch")
        document_inspection = self.document_content.document_inspection
        if type(document_inspection) is not inspection_api.PdfDocumentInspectionReconciliation:
            raise ValueError("document inspection type invalid")
        inspected = document_inspection.to_dict()
        declared = document_inspection.document.to_dict()
        bundle = document_inspection.inspections
        if type(bundle) is not bundle_api.PdfInspectionBundle:
            raise ValueError("inspection bundle type invalid")
        inventory = bundle.to_dict()
        stream = inventory["raster_stream"]
        checkpoint = bundle.raster_checkpoint
        if (stream["checkpoint_sha256"] != self.expected_raster_checkpoint_sha256
                or checkpoint.checkpoint_sha256 != self.expected_raster_checkpoint_sha256
                or stream["plan_sha256"] != declared["raster_window_plan_sha256"]
                or inspected["inspection_bundle_sha256"] != bundle.bundle_sha256
                or content["document_inspection_sha256"] != document_inspection.reconciliation_sha256):
            raise ValueError("raster/document content trusted pin mismatch")
        count = content["declared_page_count"]
        if (type(count) is not int or not 1 <= count <= _MAX_PAGES
                or content["pdf_byte_count"] > _MAX_BYTES
                or declared["declared_page_count"] != count
                or inspected["declared_page_count"] != count
                or inventory["page_count"] != count
                or inspected["raster_pages_represented_by_unsigned_receipts"] != count
                or stream["represented_pages"] != count
                or content["inspected_text_pages"] != count
                or content["status"] != "DOCUMENT_CONTENT_RECONCILED_UNSIGNED"):
            raise ValueError("raster source profile/physical count mismatch")
        for field in ("pdf_sha256", "ir_sha256", "namespace_id", "job_id",
                      "request_sha256"):
            if any(record[field] != content[field] for record in (inspected, declared)):
                raise ValueError("foreign raster document or job")
        for field in ("pdf_sha256", "ir_sha256"):
            if inventory[field] != content[field]:
                raise ValueError("foreign raster native bundle")
        native_receipts = bundle.raster_inspections
        spans = stream["receipts"]
        expected_windows = (count + _WINDOW_PAGES - 1) // _WINDOW_PAGES
        if (type(native_receipts) is not tuple or type(spans) is not list
                or len(native_receipts) != len(spans)
                or len(native_receipts) != expected_windows):
            raise ValueError("incomplete raster window inventory")
        windows = []
        next_page = 1
        total_pixels = 0
        min_margin = None
        for index, (receipt, span) in enumerate(zip(native_receipts, spans, strict=True)):
            if type(receipt) is not raster.PdfRasterWindowInspection or type(span) is not dict:
                raise ValueError("untrusted raster receipt type")
            native = receipt.to_dict()
            first = native["first_page"]
            last = native["last_page"]
            width = last - first + 1
            if (native["window_index"] != index or span["index"] != index
                    or first != next_page or first != span["first_page"]
                    or last != span["last_page"] or not 1 <= width <= _WINDOW_PAGES
                    or last != min(count, first + _WINDOW_PAGES - 1)
                    or native["page_count"] != count
                    or native["pdf_sha256"] != content["pdf_sha256"]
                    or native["ir_sha256"] != content["ir_sha256"]
                    or native["plan_sha256"] != stream["plan_sha256"]
                    or receipt.observation_sha256 != span["observation_sha256"]):
                raise ValueError("raster interval, identity or digest mismatch")
            total_pixels += native["total_pixels"]
            if total_pixels > count * _RASTER_MAX_PIXELS_PER_PAGE:
                raise ValueError("global raster pixel count outside bounded profile")
            min_margin = (native["min_edge_margin_px"] if min_margin is None else
                          min(min_margin, native["min_edge_margin_px"]))
            windows.append({
                "index": index, "first_page": first, "last_page": last,
                "raster_sha256": native["raster_sha256"],
                "observation_sha256": span["observation_sha256"],
                "total_pixels": native["total_pixels"],
                "min_edge_margin_px": native["min_edge_margin_px"],
            })
            next_page = last + 1
        if (next_page != count + 1 or min_margin is None
                or min_margin < _MIN_EDGE_MARGIN_PX
                or total_pixels > expected_windows * _RASTER_MAX_WINDOW_PIXELS):
            raise ValueError("incomplete global raster geometry")
        framed = {
            "profile_id": PROFILE_ID,
            "raster_window_plan_sha256": stream["plan_sha256"],
            "windows": windows,
        }
        commitment = sha256(_json_bytes(framed)).hexdigest()
        return {
            "schema_version": "1.0.0", "profile_id": PROFILE_ID,
            "coverage_profile_sha256": self.expected_coverage_profile_sha256,
            "status": "COMPLETE_RASTER_GEOMETRY_METADATA_BOUND",
            "conformance_scope": "DECLARED_COMPLETE_RASTER_WINDOW_GEOMETRY_ONLY",
            "namespace_id": content["namespace_id"], "job_id": content["job_id"],
            "request_sha256": content["request_sha256"],
            "pdf_sha256": content["pdf_sha256"], "ir_sha256": content["ir_sha256"],
            "declared_page_count": count, "pdf_byte_count": content["pdf_byte_count"],
            "source_text_sha256": content["source_text_sha256"],
            "content_reconciliation_sha256": self.expected_document_content_sha256,
            "raster_checkpoint_sha256": self.expected_raster_checkpoint_sha256,
            "raster_window_plan_sha256": stream["plan_sha256"],
            "raster_window_count": len(windows), "inspected_physical_pages": count,
            "raster_total_pixels": total_pixels,
            "minimum_window_edge_margin_px": min_margin,
            "raster_window_metadata_commitment_sha256": commitment,
            "raster_windows": windows,
            "complete_declared_raster_window_coverage": True,
            "budget_class": content["budget_class"],
            "execution_decision": content["execution_decision"],
            "worker_results_authenticated": False,
            "source_storage_authenticated": False,
            "whole_document_visual_equivalence_verified": False,
            "visible_glyphs_verified": False,
            "whole_pdf_safety_qualified": False,
            "finding_completeness_verified": False,
            "accessibility_qualified": False,
            "aggregate_job_resources_qualified": False,
            "default_pipeline_activated": False,
            "release_authorized": False,
            "release_authorization": "NOT_ESTABLISHED",
        }

    def __post_init__(self) -> None:
        try:
            computed = sha256(_json_bytes(self._record())).hexdigest()
            if hasattr(self, "_sealed_sha256") and computed != self._sealed_sha256:
                raise ValueError("raster coverage receipt mutated")
            object.__setattr__(self, "_sealed_sha256", computed)
        except Exception:
            raise PdfDocumentRasterCoverageError("pdf_document_raster_coverage_invalid") from None

    def to_dict(self) -> dict:
        """Return detached unsigned metrics only after rechecking nested evidence."""
        try:
            record = self._record()
            if sha256(_json_bytes(record)).hexdigest() != self._sealed_sha256:
                raise ValueError("raster coverage receipt mutated")
            return json.loads(_json_bytes({**record, "coverage_sha256": self._sealed_sha256}))
        except Exception:
            raise PdfDocumentRasterCoverageError("pdf_document_raster_coverage_invalid") from None

    @property
    def coverage_sha256(self) -> str:
        """Deterministic local metadata checksum, never a worker signature."""
        self.to_dict()
        return self._sealed_sha256


def bind_pdf_document_raster_coverage(
    *, document_content: content_api.PdfDocumentContentReconciliation,
    expected_document_content_sha256: str,
    expected_raster_checkpoint_sha256: str,
    expected_coverage_profile_sha256: str,
) -> PdfDocumentRasterCoverage:
    """Bind existing unsigned geometry; perform no native inspection or admission."""
    return PdfDocumentRasterCoverage(
        document_content=document_content,
        expected_document_content_sha256=expected_document_content_sha256,
        expected_raster_checkpoint_sha256=expected_raster_checkpoint_sha256,
        expected_coverage_profile_sha256=expected_coverage_profile_sha256,
    )
