"""Optional exact-PDF graph probe for an already sealed document preflight.

The current, unchanged 8-MiB native graph worker checks physical page count
and the reachable effective-object graph for a subset of staged documents.
This narrow bridge does not expand the 32-page default QA or 64-page job, does
not admit a 32-MiB native class, and does not certify an aggregate supervisor,
historical PDF revisions, worker provenance or final-report release.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
import os

from reporting.bindings import _digest
from reporting.page_checkpoints import _json_bytes
from reporting import document_plan as preflight
from reporting import pdf_object_graph as graph

PROFILE_ID = "generated-pdf-preflight-graph-probe-v1"
_DISABLE = "OMNIGENIS_PDF_PREFLIGHT_GRAPH_PROBE_DISABLED"


class PdfDocumentGraphProbeError(ValueError):
    """Content-free refusal: never expose a partial or unbound observation."""


def document_graph_probe_profile() -> dict:
    """Pin native execution to the existing smaller graph-worker resource class."""
    return {
        "schema_version": "1.0.0", "profile_id": PROFILE_ID,
        "preflight_profile_sha256": preflight.PROFILE_SHA256,
        "graph_profile_id": graph.PROFILE_ID,
        "graph_policy_id": graph.POLICY_ID,
        "parser_version": graph.PARSER_VERSION,
        "max_pdf_bytes": graph.MAX_PDF_BYTES,
        "max_pages": min(preflight.MAX_STAGED_PAGES, graph.MAX_DOCUMENT_PAGES),
        "max_object_visits": graph.MAX_VISITS,
        "per_worker_cpu_seconds": graph.CPU_SECONDS,
        "per_worker_memory_bytes": graph.MEMORY_BYTES,
        "per_worker_open_files": graph.OPEN_FILES,
        "per_worker_wall_seconds": graph.WALL_SECONDS,
        "graph_inspection_scope": "EFFECTIVE_TRAILER_REACHABLE_OBJECTS_ONLY",
        "whole_file_revision_safety_qualified": False,
        "worker_results_authenticated": False,
        "aggregate_job_resources_qualified": False,
        "default_pipeline_activated": False,
        "release_authorized": False,
    }


PROFILE_SHA256 = sha256(_json_bytes(document_graph_probe_profile())).hexdigest()


def _profile(expected: str) -> None:
    """Refuse changed upstream budgets or a disabled optional inspection."""
    _digest(expected)
    if (expected != PROFILE_SHA256
            or os.environ.get(_DISABLE) == "1"
            or sha256(_json_bytes(document_graph_probe_profile())).hexdigest() != PROFILE_SHA256
            or graph.MAX_PDF_BYTES > preflight.MAX_STAGED_PDF_BYTES
            or graph.MAX_DOCUMENT_PAGES < preflight.MAX_STAGED_PAGES):
        raise ValueError("document graph probe profile unavailable")


@dataclass(frozen=True, slots=True, repr=False)
class PdfDocumentGraphProbe:
    """Revalidated local unsigned graph observation, not a portable attestation."""

    document: preflight.PdfDocumentPreflight
    inspection: graph.PdfObjectGraphInspection
    expected_preflight_sha256: str
    probe_profile_sha256: str
    _sealed_sha256: str = field(init=False, repr=False, compare=False)

    def _record(self) -> dict:
        _profile(self.probe_profile_sha256)
        _digest(self.expected_preflight_sha256)
        if (type(self.document) is not preflight.PdfDocumentPreflight
                or type(self.inspection) is not graph.PdfObjectGraphInspection):
            raise ValueError("graph probe receipt types invalid")
        planned = self.document.to_dict()
        inspected = self.inspection.to_dict()
        if (planned["preflight_sha256"] != self.expected_preflight_sha256
                or planned["pdf_byte_count"] > graph.MAX_PDF_BYTES
                or planned["declared_page_count"] > graph.MAX_DOCUMENT_PAGES
                or inspected["pdf_sha256"] != planned["pdf_sha256"]
                or inspected["ir_sha256"] != planned["ir_sha256"]
                or inspected["page_count"] != planned["declared_page_count"]
                or inspected["plan_sha256"] != planned["text_window_plan_sha256"]
                or inspected["profile_id"] != graph.PROFILE_ID
                or inspected["policy_id"] != graph.POLICY_ID):
            raise ValueError("graph probe identity or resource mismatch")
        return {
            "schema_version": "1.0.0", "profile_id": PROFILE_ID,
            "probe_profile_sha256": self.probe_profile_sha256,
            "status": "LOCAL_UNSIGNED_GRAPH_PAGE_COUNT_MATCH",
            "conformance_scope": "SAME_EXACT_PDF_AND_IR_EFFECTIVE_GRAPH_ONLY",
            "namespace_id": planned["namespace_id"],
            "job_id": planned["job_id"],
            "request_sha256": planned["request_sha256"],
            "pdf_sha256": planned["pdf_sha256"],
            "ir_sha256": planned["ir_sha256"],
            "pdf_byte_count": planned["pdf_byte_count"],
            "declared_page_count": planned["declared_page_count"],
            "preflight_sha256": planned["preflight_sha256"],
            "text_window_plan_sha256": planned["text_window_plan_sha256"],
            "raster_window_plan_sha256": planned["raster_window_plan_sha256"],
            "object_graph_inspection_sha256": self.inspection.inspection_sha256,
            "effective_object_count": inspected["object_count"],
            "physical_page_count_matched_by_graph_observation": True,
            "all_file_revisions_inspected": False,
            "opaque_stream_payloads_inspected": False,
            "worker_results_authenticated": False,
            "whole_pdf_safety_qualified": False,
            "aggregate_job_resources_qualified": False,
            "long_document_resource_class_qualified": False,
            "text_and_raster_coverage_verified": False,
            "default_pipeline_activated": False,
            "release_authorized": False,
            "release_authorization": "NOT_ESTABLISHED",
        }

    def __post_init__(self) -> None:
        try:
            computed = sha256(_json_bytes(self._record())).hexdigest()
            if hasattr(self, "_sealed_sha256") and self._sealed_sha256 != computed:
                raise ValueError("graph probe changed")
            object.__setattr__(self, "_sealed_sha256", computed)
        except Exception:
            raise PdfDocumentGraphProbeError("pdf_document_graph_probe_invalid") from None

    def to_dict(self) -> dict:
        try:
            record = self._record()
            if sha256(_json_bytes(record)).hexdigest() != self._sealed_sha256:
                raise ValueError("graph probe changed")
            return json.loads(_json_bytes({**record, "probe_sha256": self._sealed_sha256}))
        except Exception:
            raise PdfDocumentGraphProbeError("pdf_document_graph_probe_invalid") from None

    @property
    def probe_sha256(self) -> str:
        self.to_dict()
        return self._sealed_sha256


def inspect_pdf_document_preflight_graph(
    *, document: preflight.PdfDocumentPreflight, pdf_bytes: object,
    expected_preflight_sha256: str, expected_probe_profile_sha256: str,
) -> PdfDocumentGraphProbe:
    """Run only the existing graph worker against the complete pinned candidate.

    An over-8-MiB candidate remains a valid *preflight* but is deferred at this
    native step. A parser mismatch, action violation, malformed PDF or changed
    job/window digest refuses the entire observation with no partial receipt.
    """
    try:
        _profile(expected_probe_profile_sha256)
        _digest(expected_preflight_sha256)
        if type(document) is not preflight.PdfDocumentPreflight or type(pdf_bytes) is not bytes:
            raise ValueError("graph probe input types invalid")
        plan = document.to_dict()
        if (plan["preflight_sha256"] != expected_preflight_sha256
                or plan["pdf_byte_count"] != len(pdf_bytes)
                or not 0 < len(pdf_bytes) <= graph.MAX_PDF_BYTES
                or sha256(pdf_bytes).hexdigest() != plan["pdf_sha256"]):
            raise ValueError("graph probe complete candidate invalid")
        observed = graph.inspect_pdf_object_graph(
            pdf_bytes=pdf_bytes, plan=document.text_plan,
            expected_plan_sha256=plan["text_window_plan_sha256"])
        if document.preflight_sha256 != expected_preflight_sha256:
            raise ValueError("graph probe preflight drift during inspection")
        return PdfDocumentGraphProbe(
            document=document, inspection=observed,
            expected_preflight_sha256=expected_preflight_sha256,
            probe_profile_sha256=expected_probe_profile_sha256)
    except Exception:
        raise PdfDocumentGraphProbeError("pdf_document_graph_probe_rejected") from None
