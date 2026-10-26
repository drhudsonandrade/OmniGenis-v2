"""Optional exact-document binding of existing unsigned inspection receipts.

The current page-window bundle already requires complete declared text/raster
receipt inventories. This additive boundary reconciles that bundle and the
effective graph probe against the same sealed document preflight and job.
It neither launches native workers nor authenticates their outputs, and never
qualifies historical revisions, aggregate budgets, accessibility or release.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
import os

from reporting.bindings import _digest
from reporting.page_checkpoints import _json_bytes
from reporting import document_plan as preflight
from reporting import document_graph_probe as graph_probe
from reporting import pdf_inspection_bundle as inspection_bundle
from reporting import pdf_object_graph as graph


PROFILE_ID = "generated-pdf-document-inspection-reconciliation-v1"
_DISABLE = "OMNIGENIS_PDF_DOCUMENT_INSPECTION_RECONCILIATION_DISABLED"


class PdfDocumentInspectionReconciliationError(ValueError):
    """Refuse an incomplete or inconsistent unsigned document evidence set."""


def document_inspection_reconciliation_profile() -> dict:
    """Pin the existing bounded profiles without widening native admission."""
    return {
        "schema_version": "1.0.0", "profile_id": PROFILE_ID,
        "preflight_profile_sha256": preflight.PROFILE_SHA256,
        "graph_probe_profile_sha256": graph_probe.PROFILE_SHA256,
        "inspection_bundle_profile_id": inspection_bundle.PROFILE_ID,
        "max_bound_pdf_bytes": graph.MAX_PDF_BYTES,
        "max_bound_pages": graph.MAX_DOCUMENT_PAGES,
        "receipts_authenticated": False,
        "all_file_revisions_inspected": False,
        "aggregate_job_resources_qualified": False,
        "default_pipeline_activated": False,
        "release_authorized": False,
    }


PROFILE_SHA256 = sha256(_json_bytes(document_inspection_reconciliation_profile())).hexdigest()


def _profile(expected: str) -> None:
    """Refuse profile drift or explicitly disabled optional reconciliation."""
    _digest(expected)
    if (expected != PROFILE_SHA256 or os.environ.get(_DISABLE) == "1"
            or sha256(_json_bytes(document_inspection_reconciliation_profile())).hexdigest()
            != PROFILE_SHA256
            or graph.MAX_PDF_BYTES > preflight.MAX_STAGED_PDF_BYTES
            or graph.MAX_DOCUMENT_PAGES != preflight.MAX_STAGED_PAGES):
        raise ValueError("document inspection reconciliation profile unavailable")


@dataclass(frozen=True, slots=True, repr=False)
class PdfDocumentInspectionReconciliation:
    """One sealed metadata agreement, never a transferable execution attestation."""

    document: preflight.PdfDocumentPreflight
    graph_observation: graph_probe.PdfDocumentGraphProbe
    inspections: inspection_bundle.PdfInspectionBundle
    expected_preflight_sha256: str
    expected_graph_probe_sha256: str
    expected_bundle_sha256: str
    expected_resource_profile_sha256: str
    expected_reconciliation_profile_sha256: str
    _sealed_sha256: str = field(init=False, repr=False, compare=False)

    def _record(self) -> dict:
        """Revalidate both typed child receipts and every shared identity field."""
        _profile(self.expected_reconciliation_profile_sha256)
        for value in (self.expected_preflight_sha256, self.expected_graph_probe_sha256,
                      self.expected_bundle_sha256, self.expected_resource_profile_sha256):
            _digest(value)
        if (type(self.document) is not preflight.PdfDocumentPreflight
                or type(self.graph_observation) is not graph_probe.PdfDocumentGraphProbe
                or type(self.inspections) is not inspection_bundle.PdfInspectionBundle):
            raise ValueError("document inspection receipt types invalid")

        planned = self.document.to_dict()
        graph_record = self.graph_observation.to_dict()
        bundled = self.inspections.to_dict()
        if (planned["preflight_sha256"] != self.expected_preflight_sha256
                or graph_record["probe_sha256"] != self.expected_graph_probe_sha256
                or self.inspections.bundle_sha256 != self.expected_bundle_sha256
                or graph_record["preflight_sha256"] != planned["preflight_sha256"]
                or bundled["resource_profile_sha256"] != self.expected_resource_profile_sha256
                or planned["pdf_byte_count"] > graph.MAX_PDF_BYTES):
            raise ValueError("document inspection expected identity mismatch")

        for key, other in (("pdf_sha256", "pdf_sha256"), ("ir_sha256", "ir_sha256"),
                           ("namespace_id", "namespace_id"), ("job_id", "job_id"),
                           ("request_sha256", "request_sha256")):
            if planned[key] != bundled[other] or graph_record[key] != planned[key]:
                raise ValueError("document inspection job or candidate mismatch")
        if (bundled["page_count"] != planned["declared_page_count"]
                or graph_record["declared_page_count"] != planned["declared_page_count"]
                or bundled["object_graph_sha256"] != graph_record["object_graph_inspection_sha256"]
                or bundled["object_count"] != graph_record["effective_object_count"]):
            raise ValueError("document inspection measured graph mismatch")

        for kind in ("text", "raster"):
            stream = bundled[kind + "_stream"]
            if (stream["plan_sha256"] != planned[kind + "_window_plan_sha256"]
                    or stream["window_count"] != planned[kind + "_window_count"]
                    or stream["represented_pages"] != planned["declared_page_count"]
                    or len(stream["receipts"]) != stream["window_count"]):
                raise ValueError("document inspection declared range mismatch")

        return {
            "schema_version": "1.0.0", "profile_id": PROFILE_ID,
            "reconciliation_profile_sha256": self.expected_reconciliation_profile_sha256,
            "status": "EXACT_DOCUMENT_INSPECTION_METADATA_BOUND",
            "conformance_scope": "COMPLETE_DECLARED_RANGE_RECEIPTS_AND_EFFECTIVE_GRAPH_ONLY",
            "namespace_id": planned["namespace_id"], "job_id": planned["job_id"],
            "request_sha256": planned["request_sha256"],
            "resource_profile_sha256": self.expected_resource_profile_sha256,
            "pdf_sha256": planned["pdf_sha256"], "ir_sha256": planned["ir_sha256"],
            "declared_page_count": planned["declared_page_count"],
            "pdf_byte_count": planned["pdf_byte_count"],
            "budget_class": planned["budget_class"],
            "execution_decision": planned["execution_decision"],
            "current_job_invocation_limit_exceeded": planned["current_job_invocation_limit_exceeded"],
            "current_job_pdf_budget_exceeded": planned["current_job_pdf_budget_exceeded"],
            "current_job_page_budget_exceeded": planned["current_job_page_budget_exceeded"],
            "preflight_sha256": self.expected_preflight_sha256,
            "graph_probe_sha256": self.expected_graph_probe_sha256,
            "inspection_bundle_sha256": self.expected_bundle_sha256,
            "text_window_count": planned["text_window_count"],
            "raster_window_count": planned["raster_window_count"],
            "text_pages_represented_by_unsigned_receipts": bundled["text_stream"]["represented_pages"],
            "raster_pages_represented_by_unsigned_receipts": bundled["raster_stream"]["represented_pages"],
            "effective_object_count": bundled["object_count"],
            "physical_page_count_match_claimed_by_local_graph_probe": True,
            "worker_results_authenticated": False,
            "historical_file_revisions_inspected": False,
            "opaque_stream_payloads_inspected": False,
            "whole_pdf_safety_qualified": False,
            "semantic_text_or_raster_equivalence_verified": False,
            "finding_completeness_verified": False,
            "aggregate_job_resources_qualified": False,
            "accessibility_qualified": False,
            "long_document_resource_class_qualified": False,
            "default_pipeline_activated": False,
            "release_authorized": False,
            "release_authorization": "NOT_ESTABLISHED",
        }

    def __post_init__(self) -> None:
        """Seal the complete metadata, rejecting construction and later mutation."""
        try:
            digest = sha256(_json_bytes(self._record())).hexdigest()
            if hasattr(self, "_sealed_sha256") and self._sealed_sha256 != digest:
                raise ValueError("document inspection reconciliation changed")
            object.__setattr__(self, "_sealed_sha256", digest)
        except Exception:
            raise PdfDocumentInspectionReconciliationError(
                "pdf_document_inspection_reconciliation_invalid") from None

    def to_dict(self) -> dict:
        """Return only detached metadata after revalidating all nested receipts."""
        try:
            record = self._record()
            if sha256(_json_bytes(record)).hexdigest() != self._sealed_sha256:
                raise ValueError("document inspection reconciliation changed")
            return json.loads(_json_bytes({**record, "reconciliation_sha256": self._sealed_sha256}))
        except Exception:
            raise PdfDocumentInspectionReconciliationError(
                "pdf_document_inspection_reconciliation_invalid") from None

    @property
    def reconciliation_sha256(self) -> str:
        """A local deterministic metadata digest, never authentication."""
        self.to_dict()
        return self._sealed_sha256


def bind_pdf_document_inspection_reconciliation(
    *, document: preflight.PdfDocumentPreflight,
    graph_observation: graph_probe.PdfDocumentGraphProbe,
    inspections: inspection_bundle.PdfInspectionBundle,
    expected_preflight_sha256: str, expected_graph_probe_sha256: str,
    expected_bundle_sha256: str, expected_resource_profile_sha256: str,
    expected_reconciliation_profile_sha256: str,
) -> PdfDocumentInspectionReconciliation:
    """Join already supplied unsigned receipts without executing or admitting work."""
    return PdfDocumentInspectionReconciliation(
        document=document, graph_observation=graph_observation, inspections=inspections,
        expected_preflight_sha256=expected_preflight_sha256,
        expected_graph_probe_sha256=expected_graph_probe_sha256,
        expected_bundle_sha256=expected_bundle_sha256,
        expected_resource_profile_sha256=expected_resource_profile_sha256,
        expected_reconciliation_profile_sha256=expected_reconciliation_profile_sha256,
    )
