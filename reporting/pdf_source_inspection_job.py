"""Optional source-text comparison followed by the six existing PDF inspections.

Only one captured current semantic-section source and one immutable PDF are
used. No worker, renderer, original profile or release route is changed. All
results remain unsigned; this wrapper is not an execution authenticator.
The post-admission deadline checks acceptance between synchronous stages and
before return, not hard preemption or aggregate process resource accounting.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
import os
import sys
from time import monotonic_ns

from reporting import pdf_inspection_job as legacy
from reporting.pdf_inspection_job import execute_pdf_inspection_job
from reporting.pdf_document_content import (
    PdfDocumentContentInspection, inspect_pdf_document_content,
    PROFILE_ID as CONTENT_PROFILE, POLICY_ID as CONTENT_POLICY,
)
from reporting.pdf_candidate_qa import _snapshot_ir
from reporting.pdf_content import _expected_content
from reporting.page_checkpoints import _json_bytes, _validate_context
from reporting.page_windows import plan_pdf_page_windows
from reporting.pdf_inspection_bundle import _pin
from reporting.pdf_inspection_set import PdfInspectionSet

PROFILE_ID = 'source-aware-pdf-inspection-job-v1'
INNER_PROFILE_SHA256 = legacy.PROFILE_SHA256
MAX_PAGES = 64
MAX_PDF_BYTES = 8 * 1024 * 1024
MAX_RESULT_BYTES = 280 * 1024
MAX_INVOCATIONS = 25
ACCEPTANCE_NS = 300 * 1000 * 1000 * 1000
LANGUAGE = 'en-US'
_DISABLE = 'OMNIGENIS_PDF_SOURCE_INSPECTION_JOB_DISABLED'


class PdfSourceInspectionJobError(ValueError):
    """Fixed content-free rejection; no failed stage exposes a partial result."""


def source_inspection_job_profile() -> dict:
    """Detach the exact outer profile while retaining a separate pinned inner profile."""
    return {'schema_version': '1.0.0', 'profile_id': PROFILE_ID,
            'language': LANGUAGE, 'pdf_version': '1.7', 'max_pages': MAX_PAGES,
            'max_pdf_bytes': MAX_PDF_BYTES, 'max_result_bytes': MAX_RESULT_BYTES,
            'max_inspector_invocations': MAX_INVOCATIONS,
            'acceptance_deadline_ns': ACCEPTANCE_NS,
            'inspection_job_profile_sha256': INNER_PROFILE_SHA256,
            'content_profile_id': CONTENT_PROFILE, 'content_policy_id': CONTENT_POLICY,
            'source_capture': 'EXISTING_BOUNDED_NATIVE_JSON_SNAPSHOT',
            'retries': 0, 'persistent_checkpoints': False,
            'hard_job_deadline_enforced': False,
            'aggregate_job_resources_qualified': False, 'release_authorized': False}


PROFILE_SHA256 = sha256(_json_bytes(source_inspection_job_profile())).hexdigest()


def _profile(expected: str) -> None:
    """Reject explicit disable, foreign expected profiles and changed runtime contracts."""
    _pin(expected)
    if (sys.platform != 'linux' or os.environ.get(_DISABLE) == '1'
            or expected != PROFILE_SHA256
            or sha256(_json_bytes(source_inspection_job_profile())).hexdigest() != PROFILE_SHA256
            or legacy.PROFILE_SHA256 != INNER_PROFILE_SHA256
            or sha256(_json_bytes(legacy.inspection_job_profile())).hexdigest() != INNER_PROFILE_SHA256):
        raise ValueError('source inspection profile unavailable')


@dataclass(frozen=True, slots=True, repr=False)
class PdfSourceInspectionResult:
    """Sealed unsigned source/inspection metadata, never an authenticated release permit."""

    inspection_set: PdfInspectionSet
    document_content: PdfDocumentContentInspection
    expected_set_sha256: str
    expected_content_sha256: str
    expected_text_sha256: str
    pdf_sha256: str
    ir_sha256: str
    page_count: int
    namespace_id: str
    job_id: str
    request_sha256: str
    resource_profile_sha256: str
    _sealed_sha256: str = field(init=False, repr=False, compare=False)

    def _validated_bytes(self) -> bytes:
        """Require both exact typed results, independent pins and the complete invocation identity."""
        for digest in (self.expected_set_sha256, self.expected_content_sha256,
                       self.expected_text_sha256, self.pdf_sha256, self.ir_sha256,
                       self.request_sha256, self.resource_profile_sha256):
            _pin(digest)
        if (type(self.namespace_id) is not str or type(self.job_id) is not str
                or type(self.page_count) is not int or not 1 <= self.page_count <= MAX_PAGES
                or self.resource_profile_sha256 != PROFILE_SHA256
                or type(self.inspection_set) is not PdfInspectionSet
                or type(self.document_content) is not PdfDocumentContentInspection):
            raise ValueError('source inspection result type or profile')
        _validate_context(self.namespace_id, self.job_id, self.request_sha256,
                          self.resource_profile_sha256)
        set_bytes = self.inspection_set.to_bytes()
        content_bytes = self.document_content.to_bytes()
        if (sha256(set_bytes).hexdigest() != self.expected_set_sha256
                or sha256(content_bytes).hexdigest() != self.expected_content_sha256):
            raise ValueError('source inspection result pin mismatch')
        record, content = json.loads(set_bytes), json.loads(content_bytes)
        identity = {'pdf_sha256': self.pdf_sha256, 'ir_sha256': self.ir_sha256,
                    'page_count': self.page_count}
        if (any(record[k] != v or content[k] != v for k, v in identity.items())
                or record['language'] != LANGUAGE or content['language'] != LANGUAGE
                or content['plan_sha256'] != record['page_bundle']['text_stream']['plan_sha256']
                or content['expected_text_sha256'] != self.expected_text_sha256
                or content['extracted_text_sha256'] != self.expected_text_sha256
                or record['resource_profile_sha256'] != INNER_PROFILE_SHA256
                or any(record[k] != getattr(self, k) for k in
                       ('namespace_id', 'job_id', 'request_sha256'))):
            raise ValueError('source inspection document context mismatch')
        result = {'schema_version': '1.0.0', 'profile_id': PROFILE_ID,
                  'status': 'SOURCE_AND_INSPECTION_RESULTS_BOUND', **identity,
                  'namespace_id': self.namespace_id, 'job_id': self.job_id,
                  'request_sha256': self.request_sha256,
                  'resource_profile_sha256': self.resource_profile_sha256,
                  'inspection_job_profile_sha256': INNER_PROFILE_SHA256,
                  'language': LANGUAGE, 'expected_text_sha256': self.expected_text_sha256,
                  'inspection_set_sha256': self.expected_set_sha256,
                  'content_inspection_sha256': self.expected_content_sha256,
                  'inspection_set': record, 'document_content': content,
                  'inspection_dimensions': record['inspection_dimensions'] + ['normalized_source_text'],
                  'normalized_text_equivalence_verified': True,
                  'worker_results_authenticated': False, 'scientific_equivalence_verified': False,
                  'visible_glyphs_verified': False, 'full_accessibility_qualified': False,
                  'finding_completeness_verified': False, 'aggregate_job_resources_qualified': False,
                  'release_authorized': False, 'release_authorization': 'NOT_ESTABLISHED'}
        data = _json_bytes(result)
        if len(data) > MAX_RESULT_BYTES:
            raise ValueError('source inspection result byte budget')
        return data

    def __post_init__(self) -> None:
        """Validate direct metadata construction and reject in-place resealing."""
        try:
            digest = sha256(self._validated_bytes()).hexdigest()
            if hasattr(self, '_sealed_sha256') and digest != self._sealed_sha256:
                raise ValueError('source inspection result changed')
            object.__setattr__(self, '_sealed_sha256', digest)
        except Exception:
            raise PdfSourceInspectionJobError('pdf_source_inspection_result_invalid') from None

    def to_bytes(self) -> bytes:
        """Revalidate retained child objects and expose only the original complete representation."""
        try:
            data = self._validated_bytes()
            if sha256(data).hexdigest() != self._sealed_sha256:
                raise ValueError('source inspection result changed')
            return data
        except Exception:
            raise PdfSourceInspectionJobError('pdf_source_inspection_result_invalid') from None

    def to_dict(self) -> dict:
        """Return detached content-free metadata with the original unqualified scope flags."""
        return json.loads(self.to_bytes())

    @property
    def inspection_sha256(self) -> str:
        """Hash sealed metadata; this digest is not a cryptographic execution signature."""
        return sha256(self.to_bytes()).hexdigest()


def execute_pdf_source_inspection_job(
    *, presentation_ir: object, pdf_bytes: object, expected_pdf_sha256: str,
    expected_ir_sha256: str, page_count: int, expected_language: str,
    namespace_id: str, job_id: str, request_sha256: str,
    expected_resource_profile_sha256: str,
) -> PdfSourceInspectionResult:
    """Compare whole source text first, then execute the existing six-inspector job.

    Expected source/job identities remain the caller's trust responsibility.
    Bounded source capture uses existing native-JSON rules; persistent concurrent
    changes are checked after each outer stage. Concurrent mutate-and-restore
    behavior is unsupported. No caller receipt, executor or resume state is accepted.
    The outer deadline does not preempt the inner synchronous job; that job retains
    all its own per-adapter limits and independent disable switch.
    """
    try:
        _profile(expected_resource_profile_sha256)
        if (type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b'%PDF-1.7')
                or len(pdf_bytes) > MAX_PDF_BYTES or type(page_count) is not int
                or not 1 <= page_count <= MAX_PAGES or type(expected_language) is not str
                or expected_language != LANGUAGE or type(namespace_id) is not str
                or type(job_id) is not str):
            raise ValueError('source inspection input type or domain')
        for digest in (expected_pdf_sha256, expected_ir_sha256, request_sha256):
            _pin(digest)
        _validate_context(namespace_id, job_id, request_sha256, expected_resource_profile_sha256)
        captured = _snapshot_ir(presentation_ir)
        source_bytes = _json_bytes(captured)
        ir_digest, expected_text = _expected_content(captured)
        if (captured.get('locale_id') != LANGUAGE or ir_digest != expected_ir_sha256
                or sha256(pdf_bytes).hexdigest() != expected_pdf_sha256):
            raise ValueError('source inspection exact input mismatch')
        plan = plan_pdf_page_windows(pdf_sha256=expected_pdf_sha256,
            ir_sha256=expected_ir_sha256, page_count=page_count, admitted_page_budget=page_count,
            pages_per_window=legacy.TEXT_WIDTH, inspector_profile_id=legacy.TEXT_PROFILE)
        started = previous = monotonic_ns()
        if type(started) is not int or started < 0:
            raise ValueError('source inspection clock invalid')
    except Exception:
        raise PdfSourceInspectionJobError('pdf_source_inspection_job_input_invalid') from None

    def check() -> None:
        """Check acceptance, both source snapshots and disabling between fixed outer stages."""
        nonlocal previous
        _profile(expected_resource_profile_sha256)
        current = monotonic_ns()
        if (type(current) is not int or current < previous or current - started >= ACCEPTANCE_NS
                or _json_bytes(_snapshot_ir(presentation_ir)) != source_bytes
                or _json_bytes(_snapshot_ir(captured)) != source_bytes):
            raise ValueError('source inspection source or acceptance changed')
        previous = current

    try:
        check()
        content = inspect_pdf_document_content(presentation_ir=captured, pdf_bytes=pdf_bytes,
            plan=plan, expected_plan_sha256=plan.plan_sha256,
            expected_ir_sha256=expected_ir_sha256, expected_language=LANGUAGE)
        check()
        if type(content) is not PdfDocumentContentInspection:
            raise ValueError('source inspection text receipt type')
        values = content.to_dict()
        if (any(values[k] != getattr(plan, k) for k in
                ('pdf_sha256', 'ir_sha256', 'plan_sha256', 'page_count'))
                or values['expected_text_sha256'] != expected_text
                or values['extracted_text_sha256'] != expected_text):
            raise ValueError('source inspection text receipt mismatch')
        inspections = execute_pdf_inspection_job(pdf_bytes=pdf_bytes,
            expected_pdf_sha256=expected_pdf_sha256, expected_ir_sha256=expected_ir_sha256,
            page_count=page_count, expected_language=LANGUAGE, namespace_id=namespace_id,
            job_id=job_id, request_sha256=request_sha256,
            expected_resource_profile_sha256=INNER_PROFILE_SHA256)
        check()
        if type(inspections) is not PdfInspectionSet:
            raise ValueError('source inspection set type')
        result = PdfSourceInspectionResult(inspection_set=inspections, document_content=content,
            expected_set_sha256=inspections.inspection_set_sha256,
            expected_content_sha256=content.inspection_sha256, expected_text_sha256=expected_text,
            pdf_sha256=expected_pdf_sha256, ir_sha256=expected_ir_sha256, page_count=page_count,
            namespace_id=namespace_id, job_id=job_id, request_sha256=request_sha256,
            resource_profile_sha256=expected_resource_profile_sha256)
        result.to_bytes()
        check()
        return result
    except Exception:
        raise PdfSourceInspectionJobError('pdf_source_inspection_job_execution_failed') from None
