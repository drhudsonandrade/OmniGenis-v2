"""Opt-in finite preflight for one complete declared generated-PDF workload.

This is an inert full-document planning boundary, not a new native executor.
It binds actual PDF bytes to a caller-pinned digest and preserves exact declared
page windows for both existing inspection dimensions. Declared page count is
never confused with measured PDF pages. A larger workload is *deferred* until a
separately reviewed whole-file parser, aggregate supervisor and resource class
are qualified. Neither admission, deployment nor release is granted here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import os

from reporting.bindings import _digest, _identity
from reporting.page_checkpoints import _json_bytes
from reporting.page_windows import PageWindowPlan, plan_pdf_page_windows
from reporting import pdf_candidate_qa as qa
from reporting import pdf_inspection_job as job
from reporting import pdf_text_windows as text_windows
from reporting import pdf_raster_windows as raster_windows
from reporting import _pdf_text_window_worker as text_worker
from reporting import _pdf_raster_window_worker as raster_worker

PROFILE_ID = "generated-pdf-document-preflight-v1"
MAX_STAGED_PAGES = text_windows.MAX_DOCUMENT_PAGES
MAX_STAGED_PDF_BYTES = 32 * 1024 * 1024
TEXT_WIDTH = job.TEXT_WIDTH
RASTER_WIDTH = job.RASTER_WIDTH
TEXT_PROFILE = text_windows.PROFILE_ID
RASTER_PROFILE = raster_windows.PROFILE_ID
_DISABLE = "OMNIGENIS_PDF_DOCUMENT_PREFLIGHT_DISABLED"


class PdfDocumentPreflightError(ValueError):
    """Fixed content-free refusal, never an incomplete plan."""


def document_preflight_profile() -> dict:
    """Describe finite planning bounds without implying tested runtime capacity."""
    return {
        "schema_version": "1.0.0", "profile_id": PROFILE_ID,
        "existing_qa_max_pages": qa.MAX_PAGES,
        "existing_qa_max_pdf_bytes": qa.MAX_PDF_BYTES,
        "existing_qa_profile_id": qa.PROFILE_ID,
        "current_job_max_pages": job.MAX_PAGES,
        "current_job_max_pdf_bytes": job.MAX_PDF_BYTES,
        "current_job_max_invocations": job.MAX_INVOCATIONS,
        "current_job_profile_sha256": job.PROFILE_SHA256,
        "text_window_width": TEXT_WIDTH, "raster_window_width": RASTER_WIDTH,
        "text_window_profile_id": TEXT_PROFILE, "raster_window_profile_id": RASTER_PROFILE,
        "native_window_worker_envelopes": {
            "text": {
                "profile_id": text_windows.PROFILE_ID,
                "protocol_version": text_windows.PROTOCOL_VERSION,
                "identity_fields": list(text_windows.IDENTITY_FIELDS),
                "extractor_version": text_windows.EXTRACTOR_VERSION,
                "header_bytes": text_worker.HEADER_BYTES,
                "max_pdf_bytes": text_windows.MAX_PDF_BYTES,
                "max_document_pages": text_windows.MAX_DOCUMENT_PAGES,
                "max_window_pages": text_windows.MAX_WINDOW_PAGES,
                "max_text_bytes": text_windows.MAX_TEXT_BYTES,
                "max_decoded_bytes": text_windows.MAX_DECODED_BYTES,
                "cpu_seconds": text_windows.CPU_SECONDS,
                "wall_seconds": text_windows.WALL_SECONDS,
                "memory_bytes": text_windows.MEMORY_BYTES,
                "open_files": text_windows.OPEN_FILES,
                "result_bytes": text_windows.RESULT_BYTES,
            },
            "raster": {
                "profile_id": raster_windows.PROFILE_ID,
                "protocol_version": raster_windows.PROTOCOL_VERSION,
                "identity_fields": list(raster_windows.IDENTITY_FIELDS),
                "parser_version": raster_windows.PARSER_VERSION,
                "pillow_version": raster_windows.PILLOW_VERSION,
                "tool_version": raster_windows.TOOL_VERSION,
                "tool_sha256": raster_windows.TOOL_SHA256,
                "dpi": raster_worker.DPI,
                "max_pdf_bytes": raster_windows.MAX_PDF_BYTES,
                "max_png_bytes": raster_worker.MAX_PNG_BYTES,
                "max_document_pages": raster_windows.MAX_DOCUMENT_PAGES,
                "max_window_pages": raster_windows.MAX_WINDOW_PAGES,
                "max_total_pixels": raster_windows.MAX_TOTAL_PIXELS,
                "max_pixels_per_page": raster_windows.MAX_PIXELS_PER_PAGE,
                "min_edge_margin_px": raster_windows.MIN_EDGE_MARGIN_PX,
                "cpu_seconds": raster_windows.CPU_SECONDS,
                "wall_seconds": raster_windows.WALL_SECONDS,
                "page_wall_seconds": raster_worker.PAGE_WALL_SECONDS,
                "memory_bytes": raster_windows.MEMORY_BYTES,
                "open_files": raster_windows.OPEN_FILES,
                "file_bytes": raster_windows.FILE_BYTES,
                "result_bytes": raster_windows.RESULT_BYTES,
            },
        },
        "planning_page_ceiling": MAX_STAGED_PAGES,
        "max_staged_pdf_bytes": MAX_STAGED_PDF_BYTES,
        "new_class_proven_by_measurement": False,
        "native_executor_activated": False,
        "actual_pdf_page_count_verified": False,
        "whole_pdf_safety_qualified": False,
        "aggregate_job_resources_qualified": False,
        "default_pipeline_activated": False,
        "release_authorized": False,
    }


PROFILE_SHA256 = sha256(_json_bytes(document_preflight_profile())).hexdigest()


def _profile(expected: object) -> None:
    """Fail closed on a disabled or changed finite upstream contract."""
    _digest(expected)
    if (expected != PROFILE_SHA256
            or os.environ.get(_DISABLE) == "1"
            or sha256(_json_bytes(document_preflight_profile())).hexdigest() != PROFILE_SHA256
            or TEXT_WIDTH != job.TEXT_WIDTH or RASTER_WIDTH != job.RASTER_WIDTH
            or TEXT_PROFILE != text_windows.PROFILE_ID
            or RASTER_PROFILE != raster_windows.PROFILE_ID
            or MAX_STAGED_PAGES != text_windows.MAX_DOCUMENT_PAGES):
        raise ValueError("document preflight profile unavailable")


def _finite(value: object, lower: int, upper: int) -> None:
    """Reject bool, negative, huge or noncanonical measurements without coercion."""
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError("document preflight budget invalid")


@dataclass(frozen=True, slots=True, repr=False)
class PdfDocumentPreflight:
    """Job-bound immutable declared workload with no execution authority."""

    pdf_sha256: str
    ir_sha256: str
    namespace_id: str
    job_id: str
    request_sha256: str
    declared_page_count: int
    pdf_byte_count: int
    text_plan: PageWindowPlan
    raster_plan: PageWindowPlan
    budget_class: str
    preflight_profile_sha256: str
    _sealed_sha256: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Reject construction drift, window substitution and metadata mutation."""
        try:
            record = self._record()
            computed = sha256(_json_bytes(record)).hexdigest()
            if hasattr(self, "_sealed_sha256") and computed != self._sealed_sha256:
                raise ValueError("document preflight mutated after sealing")
            object.__setattr__(self, "_sealed_sha256", computed)
        except Exception:
            raise PdfDocumentPreflightError("pdf_document_preflight_invalid") from None

    def _record(self) -> dict:
        """Revalidate every nested span before producing complete detached metadata."""
        _profile(self.preflight_profile_sha256)
        for digest in (self.pdf_sha256, self.ir_sha256, self.request_sha256):
            _digest(digest)
        for identity in (self.namespace_id, self.job_id):
            _identity(identity)
        _finite(self.declared_page_count, 1, MAX_STAGED_PAGES)
        _finite(self.pdf_byte_count, len(b"%PDF-1.7"), MAX_STAGED_PDF_BYTES)
        if type(self.text_plan) is not PageWindowPlan or type(self.raster_plan) is not PageWindowPlan:
            raise ValueError("document preflight plan types invalid")
        self.text_plan.__post_init__()
        self.raster_plan.__post_init__()
        expected_class = ("EXISTING_QA_ENVELOPE"
            if self.declared_page_count <= qa.MAX_PAGES and self.pdf_byte_count <= qa.MAX_PDF_BYTES
            else "LONG_DOCUMENT_STAGING")
        if type(self.budget_class) is not str or self.budget_class != expected_class:
            raise ValueError("document preflight resource class inconsistent")
        for plan, width, inspector in (
            (self.text_plan, TEXT_WIDTH, TEXT_PROFILE),
            (self.raster_plan, RASTER_WIDTH, RASTER_PROFILE),
        ):
            if (plan.pdf_sha256 != self.pdf_sha256
                    or plan.ir_sha256 != self.ir_sha256
                    or plan.page_count != self.declared_page_count
                    or plan.admitted_page_budget != self.declared_page_count
                    or plan.pages_per_window != width
                    or plan.inspector_profile_id != inspector
                    or not plan.windows or plan.windows[0].first_page != 1
                    or plan.windows[-1].last_page != self.declared_page_count):
                raise ValueError("document preflight plan identity or coverage invalid")
        planned_calls = 4 + self.text_plan.window_count + self.raster_plan.window_count
        return {
            "schema_version": "1.0.0", "profile_id": PROFILE_ID,
            "preflight_profile_sha256": self.preflight_profile_sha256,
            "status": "STAGED_UNQUALIFIED",
            "conformance_scope": "EXACT_BYTES_AND_DECLARED_WINDOWS_PRECHECK_ONLY",
            "namespace_id": self.namespace_id, "job_id": self.job_id,
            "request_sha256": self.request_sha256,
            "pdf_sha256": self.pdf_sha256, "ir_sha256": self.ir_sha256,
            "pdf_byte_count": self.pdf_byte_count,
            "declared_page_count": self.declared_page_count,
            "budget_class": self.budget_class,
            "execution_decision": "DEFERRED_NOT_QUALIFIED",
            "text_window_count": self.text_plan.window_count,
            "raster_window_count": self.raster_plan.window_count,
            "text_pages_planned": sum(w.last_page - w.first_page + 1 for w in self.text_plan.windows),
            "raster_pages_planned": sum(w.last_page - w.first_page + 1 for w in self.raster_plan.windows),
            "text_window_plan_sha256": self.text_plan.plan_sha256,
            "raster_window_plan_sha256": self.raster_plan.plan_sha256,
            "text_windows": [w.to_dict() for w in self.text_plan.windows],
            "raster_windows": [w.to_dict() for w in self.raster_plan.windows],
            "planned_inspector_invocations": planned_calls,
            "current_job_invocation_limit_exceeded": planned_calls > job.MAX_INVOCATIONS,
            "current_job_pdf_budget_exceeded": self.pdf_byte_count > job.MAX_PDF_BYTES,
            "current_job_page_budget_exceeded": self.declared_page_count > job.MAX_PAGES,
            "actual_pdf_page_count_verified": False,
            "worker_results_authenticated": False,
            "whole_pdf_safety_qualified": False,
            "aggregate_job_resources_qualified": False,
            "native_executor_activated": False,
            "default_pipeline_activated": False,
            "release_authorized": False,
            "release_authorization": "NOT_ESTABLISHED",
        }

    @property
    def preflight_sha256(self) -> str:
        """Expose only the retained canonical metadata digest, not a signature."""
        return sha256(_json_bytes(self._checked())).hexdigest()

    def _checked(self) -> dict:
        """Reject any changed field before an output or digest can be reused."""
        try:
            record = self._record()
            if sha256(_json_bytes(record)).hexdigest() != self._sealed_sha256:
                raise ValueError("document preflight fields changed")
            return record
        except Exception:
            raise PdfDocumentPreflightError("pdf_document_preflight_invalid") from None

    def to_dict(self) -> dict:
        """Return detached complete window metadata without a final-file claim."""
        record = self._checked()
        return {**record, "preflight_sha256": self._sealed_sha256}


def build_pdf_document_preflight(
    *, pdf_bytes: object, expected_pdf_sha256: str, expected_ir_sha256: str,
    declared_page_count: int, namespace_id: str, job_id: str,
    request_sha256: str, expected_preflight_profile_sha256: str,
) -> PdfDocumentPreflight:
    """Bind exact candidate bytes and complete *declared* windows before any work.

    These expectations must be obtained from trusted immutable job state.
    A matching digest does not authenticate the source or measure PDF pages.
    Workloads beyond this finite planning class fail whole, never truncate.
    This function neither runs a native worker nor changes legacy QA limits.
    """
    try:
        _profile(expected_preflight_profile_sha256)
        if (type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b"%PDF-1.7")
                or not len(b"%PDF-1.7") <= len(pdf_bytes) <= MAX_STAGED_PDF_BYTES):
            raise ValueError("candidate bytes outside planning envelope")
        _finite(declared_page_count, 1, MAX_STAGED_PAGES)
        _digest(expected_pdf_sha256)
        _digest(expected_ir_sha256)
        _digest(request_sha256)
        _identity(namespace_id)
        _identity(job_id)
        if sha256(pdf_bytes).hexdigest() != expected_pdf_sha256:
            raise ValueError("candidate digest does not match independent expectation")
        plans = tuple(plan_pdf_page_windows(pdf_sha256=expected_pdf_sha256,
            ir_sha256=expected_ir_sha256, page_count=declared_page_count,
            admitted_page_budget=declared_page_count, pages_per_window=width,
            inspector_profile_id=profile)
            for width, profile in ((TEXT_WIDTH, TEXT_PROFILE), (RASTER_WIDTH, RASTER_PROFILE)))
        budget = ("EXISTING_QA_ENVELOPE"
            if declared_page_count <= qa.MAX_PAGES and len(pdf_bytes) <= qa.MAX_PDF_BYTES
            else "LONG_DOCUMENT_STAGING")
        result = PdfDocumentPreflight(pdf_sha256=expected_pdf_sha256,
            ir_sha256=expected_ir_sha256, namespace_id=namespace_id,
            job_id=job_id, request_sha256=request_sha256,
            declared_page_count=declared_page_count, pdf_byte_count=len(pdf_bytes),
            text_plan=plans[0], raster_plan=plans[1], budget_class=budget,
            preflight_profile_sha256=expected_preflight_profile_sha256)
        result.to_dict()
        return result
    except Exception:
        raise PdfDocumentPreflightError("pdf_document_preflight_input_invalid") from None
