"""Bind complete text/raster receipt inventories and effective-graph metadata.

This pure boundary reconciles supplied unsigned objects with independently
resolved checkpoint and graph digests. It does not run or authenticate workers,
read PDFs, persist checkpoints, admit resource use, verify finding completeness
or authorize report delivery. A caller capable of fabricating all objects and
expected hashes can fabricate matching metadata; this is not an attestation.
Existing native workers, default limits and release gates remain unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json

from reporting.bindings import _digest
from reporting.page_checkpoints import PageWindowCheckpoint, _json_bytes
from reporting.page_windows import PageWindowPlan
from reporting.pdf_object_graph import PdfObjectGraphInspection
from reporting.pdf_text_windows import (
    MAX_DOCUMENT_PAGES, MAX_WINDOW_PAGES as TEXT_WINDOW_PAGES,
    PROFILE_ID as TEXT_PROFILE, PdfTextWindowInspection,
)
from reporting.pdf_raster_windows import (
    MAX_WINDOW_PAGES as RASTER_WINDOW_PAGES, PROFILE_ID as RASTER_PROFILE,
    PdfRasterWindowInspection,
)

PROFILE_ID = "complete-pdf-inspection-metadata-v1"
MAX_BUNDLE_BYTES = 256 * 1024
_CONTEXT_FIELDS = ("namespace_id", "job_id", "request_sha256", "resource_profile_sha256")
_DOCUMENT_FIELDS = ("pdf_sha256", "ir_sha256", "page_count")


class PdfInspectionBundleError(ValueError):
    """Content-free rejection; incomplete inputs never produce a combined inventory."""


def _pin(value: object) -> None:
    """Accept only an independently supplied canonical native SHA-256 string."""
    if type(value) is not str:
        raise ValueError("inspection pin type")
    _digest(value)


def _validate_stream(checkpoint: object, receipts: object, expected_digest: str,
                     profile: str, width: int, receipt_type: type) -> None:
    """Bind every typed receipt to one complete checkpoint with finite native-profile limits."""
    if (type(checkpoint) is not PageWindowCheckpoint or type(receipts) is not tuple
            or len(receipts) > MAX_DOCUMENT_PAGES):
        raise ValueError("inspection stream type or count")
    plan = checkpoint.plan
    if (type(plan) is not PageWindowPlan or type(plan.page_count) is not int
            or not 1 <= plan.page_count <= MAX_DOCUMENT_PAGES
            or type(plan.pages_per_window) is not int or not 1 <= plan.pages_per_window <= width
            or plan.inspector_profile_id != profile):
        raise ValueError("inspection stream profile")
    checkpoint.__post_init__()
    if checkpoint.checkpoint_sha256 != expected_digest or len(receipts) != plan.window_count:
        raise ValueError("inspection checkpoint pin or coverage")
    checkpoint.as_complete_ledger()
    for observation, receipt in zip(checkpoint.observations, receipts, strict=True):
        if type(receipt) is not receipt_type:
            raise ValueError("inspection receipt type")
        receipt.__post_init__()
        if (any(getattr(receipt, key) != getattr(plan, key) for key in _DOCUMENT_FIELDS)
                or receipt.to_observation() != observation):
            raise ValueError("inspection receipt binding")


def _stream_record(checkpoint: PageWindowCheckpoint, expected_digest: str) -> dict:
    """Return an ordered digest inventory, not a composite text or image content hash."""
    observations = checkpoint.observations
    return {"profile_id": checkpoint.plan.inspector_profile_id,
            "checkpoint_sha256": expected_digest,
            "plan_sha256": checkpoint.plan.plan_sha256,
            "window_count": len(observations),
            "represented_pages": sum(item.last_page - item.first_page + 1 for item in observations),
            "receipts": [{"index": item.index, "first_page": item.first_page,
                          "last_page": item.last_page,
                          "observation_sha256": item.observation_sha256} for item in observations]}


@dataclass(frozen=True, slots=True, repr=False)
class PdfInspectionBundle:
    """An exact unsigned reconciliation, never native execution or release evidence by itself."""

    text_checkpoint: PageWindowCheckpoint
    raster_checkpoint: PageWindowCheckpoint
    text_inspections: tuple[PdfTextWindowInspection, ...]
    raster_inspections: tuple[PdfRasterWindowInspection, ...]
    object_inspection: PdfObjectGraphInspection
    expected_text_checkpoint_sha256: str
    expected_raster_checkpoint_sha256: str
    expected_object_inspection_sha256: str
    _sealed_sha256: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate public construction and seal the complete current metadata representation."""
        try:
            data = self._validated_bytes()
            computed = hashlib.sha256(data).hexdigest()
            if hasattr(self, "_sealed_sha256") and self._sealed_sha256 != computed:
                raise ValueError("inspection bundle changed")
            object.__setattr__(self, "_sealed_sha256", computed)
        except Exception:
            raise PdfInspectionBundleError("pdf_inspection_bundle_invalid") from None

    def _validate(self) -> None:
        """Enforce independent pins, complete per-profile coverage and common job/document identity."""
        for value in (self.expected_text_checkpoint_sha256, self.expected_raster_checkpoint_sha256,
                      self.expected_object_inspection_sha256):
            _pin(value)
        _validate_stream(self.text_checkpoint, self.text_inspections,
                         self.expected_text_checkpoint_sha256, TEXT_PROFILE,
                         TEXT_WINDOW_PAGES, PdfTextWindowInspection)
        _validate_stream(self.raster_checkpoint, self.raster_inspections,
                         self.expected_raster_checkpoint_sha256, RASTER_PROFILE,
                         RASTER_WINDOW_PAGES, PdfRasterWindowInspection)
        text, raster = self.text_checkpoint, self.raster_checkpoint
        if (any(getattr(text, key) != getattr(raster, key) for key in _CONTEXT_FIELDS)
                or any(getattr(text.plan, key) != getattr(raster.plan, key) for key in _DOCUMENT_FIELDS)):
            raise ValueError("inspection job or document mismatch")
        graph = self.object_inspection
        if type(graph) is not PdfObjectGraphInspection:
            raise ValueError("inspection graph type")
        graph.__post_init__()
        if (graph.inspection_sha256 != self.expected_object_inspection_sha256
                or graph.plan_sha256 != text.plan.plan_sha256
                or any(getattr(graph, key) != getattr(text.plan, key) for key in _DOCUMENT_FIELDS)):
            raise ValueError("inspection graph binding")

    def _record(self) -> dict:
        """Construct a closed content-free inventory retaining all unqualified dimensions."""
        text = self.text_checkpoint
        return {"schema_version": "1.0.0", "profile_id": PROFILE_ID,
                "status": "COMPLETE_INSPECTION_METADATA_BOUND",
                "coverage_scope": "EXACT_TEXT_AND_RASTER_RECEIPT_RANGES_ONLY",
                **{key: getattr(text, key) for key in _CONTEXT_FIELDS},
                **{key: getattr(text.plan, key) for key in _DOCUMENT_FIELDS},
                "text_stream": _stream_record(text, self.expected_text_checkpoint_sha256),
                "raster_stream": _stream_record(self.raster_checkpoint, self.expected_raster_checkpoint_sha256),
                "object_graph_sha256": self.expected_object_inspection_sha256,
                "object_graph_scope": "EFFECTIVE_TRAILER_REACHABLE_OBJECTS_ONLY",
                "object_count": self.object_inspection.object_count,
                "native_execution_performed": False, "worker_results_authenticated": False,
                "whole_pdf_safety_qualified": False, "finding_completeness_verified": False,
                "text_equivalence_verified": False, "accessibility_qualified": False,
                "aggregate_job_resources_qualified": False, "release_authorized": False,
                "release_authorization": "NOT_ESTABLISHED"}

    def _validated_bytes(self) -> bytes:
        """Revalidate all retained objects and reject excessive canonical output before exposure."""
        self._validate()
        payload = _json_bytes(self._record())
        if len(payload) > MAX_BUNDLE_BYTES:
            raise ValueError("inspection metadata byte budget")
        return payload

    def to_bytes(self) -> bytes:
        """Return exactly the originally bound canonical metadata, rejecting subsequent mutation."""
        try:
            payload = self._validated_bytes()
            if hashlib.sha256(payload).hexdigest() != self._sealed_sha256:
                raise ValueError("inspection bundle changed")
            return payload
        except Exception:
            raise PdfInspectionBundleError("pdf_inspection_bundle_invalid") from None

    def to_dict(self) -> dict:
        """Return a fully detached record without PDF bytes, report text, rasters or file paths."""
        return json.loads(self.to_bytes())

    @property
    def bundle_sha256(self) -> str:
        """Hash exact revalidated bundle bytes; the digest is not a signature or authorization."""
        return hashlib.sha256(self.to_bytes()).hexdigest()


def bind_pdf_inspection_bundle(
    *, text_checkpoint: PageWindowCheckpoint, raster_checkpoint: PageWindowCheckpoint,
    text_inspections: tuple[PdfTextWindowInspection, ...],
    raster_inspections: tuple[PdfRasterWindowInspection, ...],
    object_inspection: PdfObjectGraphInspection,
    expected_text_checkpoint_sha256: str, expected_raster_checkpoint_sha256: str,
    expected_object_inspection_sha256: str,
) -> PdfInspectionBundle:
    """Reconcile complete supplied metadata against independently resolved checkpoint/graph pins.

    The graph receipt must bind the text plan; the raster plan remains separate.
    Both complete checkpoint hashes must come from the caller's trusted job state.
    This function neither authenticates that state nor runs missing inspections.
    """
    return PdfInspectionBundle(text_checkpoint=text_checkpoint, raster_checkpoint=raster_checkpoint,
        text_inspections=text_inspections, raster_inspections=raster_inspections,
        object_inspection=object_inspection,
        expected_text_checkpoint_sha256=expected_text_checkpoint_sha256,
        expected_raster_checkpoint_sha256=expected_raster_checkpoint_sha256,
        expected_object_inspection_sha256=expected_object_inspection_sha256)
