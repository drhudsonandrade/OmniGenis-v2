"""Optional finite sequential execution of the existing PDF inspection adapters.

The coordinator accepts one exact document and primitive job context, not caller
supplied receipts. It invokes the existing guarded workers once in fixed order
and returns only the complete existing unsigned inspection set. No default
renderer, scientific contract, durable checkpoint or release path is activated.

The elapsed limit is an acceptance deadline checked between synchronous calls
and before return, not hard preemption of an in-flight adapter. Each adapter
retains its own reviewed process guards. Aggregate CPU/RSS, supervisor death,
arbitrary descendants and full report qualification remain outside this scope.
"""
from __future__ import annotations

from hashlib import sha256
import os
import sys
from time import monotonic_ns

from reporting.page_checkpoints import PageWindowCheckpoint, _json_bytes, _validate_context
from reporting.page_windows import PageWindowPlan, plan_pdf_page_windows
from reporting.pdf_inspection_bundle import bind_pdf_inspection_bundle, _pin
from reporting.pdf_inspection_set import PdfInspectionSet, bind_pdf_inspection_set
from reporting.pdf_object_graph import PdfObjectGraphInspection, inspect_pdf_object_graph
from reporting.pdf_document_metadata import PdfDocumentMetadataInspection, inspect_pdf_document_metadata
from reporting.pdf_page_tags import PdfPageTagInspection, inspect_pdf_page_tag_parents
from reporting.pdf_mcid_coverage import PdfMcidCoverageInspection, inspect_pdf_mcid_coverage
from reporting.pdf_text_windows import (
    PdfTextWindowInspection, inspect_pdf_text_window, PROFILE_ID as TEXT_PROFILE,
)
from reporting.pdf_raster_windows import (
    PdfRasterWindowInspection, inspect_pdf_raster_window, PROFILE_ID as RASTER_PROFILE,
)

PROFILE_ID = 'sequential-pdf-inspection-job-v1'
MAX_PAGES = 64
MAX_PDF_BYTES = 8 * 1024 * 1024
TEXT_WIDTH = 16
RASTER_WIDTH = 4
MAX_INVOCATIONS = 24
ACCEPTANCE_NS = 300 * 1000 * 1000 * 1000
LANGUAGE = 'en-US'
_DISABLE = 'OMNIGENIS_PDF_INSPECTION_JOB_DISABLED'
_IDENTITY = ('pdf_sha256', 'ir_sha256', 'plan_sha256', 'page_count')


class PdfInspectionJobError(ValueError):
    """Content-free job rejection; failed or incomplete work returns no inspection set."""


def inspection_job_profile() -> dict:
    """Return detached fixed admission limits, not an expanded renderer capability."""
    return {'schema_version': '1.0.0', 'profile_id': PROFILE_ID,
            'language': LANGUAGE, 'pdf_version': '1.7',
            'max_pages': MAX_PAGES, 'max_pdf_bytes': MAX_PDF_BYTES,
            'text_window_pages': TEXT_WIDTH, 'raster_window_pages': RASTER_WIDTH,
            'max_inspector_invocations': MAX_INVOCATIONS,
            'acceptance_deadline_ns': ACCEPTANCE_NS,
            'retries': 0, 'persistent_checkpoints': False,
            'hard_job_deadline_enforced': False,
            'aggregate_job_resources_qualified': False,
            'release_authorized': False}


PROFILE_SHA256 = sha256(_json_bytes(inspection_job_profile())).hexdigest()


def _profile(expected: str) -> None:
    """Require the exact original profile and fail closed on disabling or runtime drift."""
    _pin(expected)
    if (sys.platform != 'linux' or os.environ.get(_DISABLE) == '1'
            or expected != PROFILE_SHA256
            or sha256(_json_bytes(inspection_job_profile())).hexdigest() != PROFILE_SHA256):
        raise ValueError('inspection job profile unavailable')


class _Budget:
    """Bound invocation count and elapsed acceptance without claiming OS preemption."""

    def __init__(self, planned_calls: int, profile_sha256: str) -> None:
        """Start a private monotonic clock only after finite input admission."""
        if type(planned_calls) is not int or not 1 <= planned_calls <= MAX_INVOCATIONS:
            raise ValueError('inspection job invocation budget')
        self.planned = planned_calls
        self.calls = 0
        self.profile_sha256 = profile_sha256
        self.start = monotonic_ns()
        if type(self.start) is not int or self.start < 0:
            raise ValueError('inspection job clock invalid')
        self.previous = self.start

    def check(self) -> None:
        """Reject deadline expiry, a regressing clock or changed profile before exposure."""
        _profile(self.profile_sha256)
        current = monotonic_ns()
        if (type(current) is not int or current < self.previous
                or current - self.start >= ACCEPTANCE_NS):
            raise ValueError('inspection job acceptance deadline')
        self.previous = current

    def invoke(self, function, **kwargs):
        """Invoke one fixed internal adapter once; never retry or keep a late result."""
        self.check()
        if self.calls >= self.planned:
            raise ValueError('inspection job invocation overflow')
        self.calls += 1
        result = function(**kwargs)
        self.check()
        return result

    def complete(self) -> None:
        """Completion needs every admitted invocation and an unexpired acceptance check."""
        self.check()
        if self.calls != self.planned:
            raise ValueError('inspection job invocation coverage incomplete')


def _accept(receipt: object, cls: type, plan: PageWindowPlan, index: int | None = None):
    """Revalidate exact native receipt type, document/plan and selected page interval."""
    if type(receipt) is not cls:
        raise ValueError('inspection job receipt type mismatch')
    receipt.__post_init__()
    if any(getattr(receipt, key) != getattr(plan, key) for key in _IDENTITY):
        raise ValueError('inspection job receipt identity mismatch')
    if index is not None:
        span = plan.windows[index]
        if (receipt.window_index != span.index or receipt.first_page != span.first_page
                or receipt.last_page != span.last_page):
            raise ValueError('inspection job window receipt mismatch')
    return receipt


def execute_pdf_inspection_job(
    *, pdf_bytes: object, expected_pdf_sha256: str, expected_ir_sha256: str,
    page_count: int, expected_language: str, namespace_id: str, job_id: str,
    request_sha256: str, expected_resource_profile_sha256: str,
) -> PdfInspectionSet:
    """Run every existing inspector for one admitted job, then bind the complete set.

    The caller owns trusted job/PDF/IR/request expectations. This routine neither
    authenticates the caller nor compares report text to scientific source data.
    Returned pins are captured from this invocation's checked worker results;
    they are not evidence of an independent cryptographic execution attestor.
    No partial result or checkpoint is persisted or returned after failure.
    """
    try:
        _profile(expected_resource_profile_sha256)
        if (type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b'%PDF-1.7')
                or len(pdf_bytes) > MAX_PDF_BYTES
                or type(page_count) is not int or not 1 <= page_count <= MAX_PAGES
                or type(expected_language) is not str or expected_language != LANGUAGE):
            raise ValueError('inspection job input domain')
        for value in (expected_pdf_sha256, expected_ir_sha256, request_sha256):
            _pin(value)
        if type(namespace_id) is not str or type(job_id) is not str:
            raise ValueError('inspection job context type')
        _validate_context(namespace_id, job_id, request_sha256, expected_resource_profile_sha256)
        if sha256(pdf_bytes).hexdigest() != expected_pdf_sha256:
            raise ValueError('inspection job document hash mismatch')
        context = dict(namespace_id=namespace_id, job_id=job_id,
                       request_sha256=request_sha256,
                       resource_profile_sha256=expected_resource_profile_sha256)
        plans = tuple(plan_pdf_page_windows(pdf_sha256=expected_pdf_sha256,
            ir_sha256=expected_ir_sha256, page_count=page_count,
            admitted_page_budget=page_count, pages_per_window=width,
            inspector_profile_id=profile) for width, profile in
            ((TEXT_WIDTH, TEXT_PROFILE), (RASTER_WIDTH, RASTER_PROFILE)))
        text, raster = plans
        text_checkpoint = PageWindowCheckpoint(plan=text, observations=(), **context)
        raster_checkpoint = PageWindowCheckpoint(plan=raster, observations=(), **context)
        planned = 4 + text.window_count + raster.window_count
        budget = _Budget(planned, expected_resource_profile_sha256)
    except Exception:
        raise PdfInspectionJobError('pdf_inspection_job_input_invalid') from None
    try:
        common = dict(pdf_bytes=pdf_bytes, plan=text, expected_plan_sha256=text.plan_sha256)
        graph = _accept(budget.invoke(inspect_pdf_object_graph, **common),
                        PdfObjectGraphInspection, text)
        document = {**common, 'expected_language': LANGUAGE}
        metadata = _accept(budget.invoke(inspect_pdf_document_metadata, **document),
                           PdfDocumentMetadataInspection, text)
        tags = _accept(budget.invoke(inspect_pdf_page_tag_parents, **document),
                       PdfPageTagInspection, text)
        mcids = _accept(budget.invoke(inspect_pdf_mcid_coverage, **document),
                        PdfMcidCoverageInspection, text)
        texts = []
        for index in range(text.window_count):
            item = _accept(budget.invoke(inspect_pdf_text_window, **common,
                           window_index=index), PdfTextWindowInspection, text, index)
            texts.append(item)
            text_checkpoint = text_checkpoint.append_observations((item.to_observation(),))
        rasters = []
        for index in range(raster.window_count):
            item = _accept(budget.invoke(inspect_pdf_raster_window,
                pdf_bytes=pdf_bytes, plan=raster, expected_plan_sha256=raster.plan_sha256,
                window_index=index), PdfRasterWindowInspection, raster, index)
            rasters.append(item)
            raster_checkpoint = raster_checkpoint.append_observations((item.to_observation(),))
        budget.complete()
        bundle = bind_pdf_inspection_bundle(
            text_checkpoint=text_checkpoint, raster_checkpoint=raster_checkpoint,
            text_inspections=tuple(texts), raster_inspections=tuple(rasters),
            object_inspection=graph,
            expected_text_checkpoint_sha256=text_checkpoint.checkpoint_sha256,
            expected_raster_checkpoint_sha256=raster_checkpoint.checkpoint_sha256,
            expected_object_inspection_sha256=graph.inspection_sha256)
        result = bind_pdf_inspection_set(page_bundle=bundle, document_metadata=metadata,
            page_tags=tags, mcid_coverage=mcids,
            expected_page_bundle_sha256=bundle.bundle_sha256,
            expected_metadata_sha256=metadata.inspection_sha256,
            expected_page_tags_sha256=tags.inspection_sha256,
            expected_mcid_sha256=mcids.inspection_sha256, expected_language=LANGUAGE)
        if type(result) is not PdfInspectionSet:
            raise ValueError('inspection job combined result type')
        result.to_bytes()
        budget.complete()
        return result
    except Exception:
        raise PdfInspectionJobError('pdf_inspection_job_execution_failed') from None
