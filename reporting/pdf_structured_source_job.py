"""Optional composition of forward structure and existing source-aware inspections.

The original adapters, workers, resource profiles and default renderer remain
unchanged. One immutable candidate and one bounded native-JSON source snapshot
feed both stages. Matching sealed unsigned observations is not authenticated
execution, semantic accessibility, aggregate supervision or release authority.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
import os
import sys
from time import monotonic_ns

from reporting import pdf_source_inspection_job as source
from reporting import pdf_structure_tree as structure
from reporting.pdf_source_inspection_job import (
    PdfSourceInspectionResult, execute_pdf_source_inspection_job,
)
from reporting.pdf_structure_tree import PdfStructureTreeInspection, inspect_pdf_structure_tree
from reporting.pdf_candidate_qa import _snapshot_ir
from reporting.pdf_content import _expected_content
from reporting.page_checkpoints import _json_bytes, _validate_context
from reporting.page_windows import plan_pdf_page_windows
from reporting.pdf_inspection_bundle import _pin

PROFILE_ID = 'structured-source-pdf-inspection-job-v1'
SOURCE_PROFILE_SHA256 = source.PROFILE_SHA256
MAX_PAGES = 64
MAX_PDF_BYTES = 8 * 1024 * 1024
MAX_RESULT_BYTES = 288 * 1024
MAX_INVOCATIONS = 26
ACCEPTANCE_NS = 300 * 1000 * 1000 * 1000
LANGUAGE = 'en-US'
_DISABLES = ('OMNIGENIS_PDF_STRUCTURED_SOURCE_JOB_DISABLED',
            'OMNIGENIS_PDF_STRUCTURE_TREE_DISABLED',
            'OMNIGENIS_PDF_SOURCE_INSPECTION_JOB_DISABLED',
            'OMNIGENIS_PDF_INSPECTION_JOB_DISABLED')


class PdfStructuredSourceJobError(ValueError):
    """Fixed content-free failure, without a partial successful combined result."""


def structured_source_job_profile() -> dict:
    """Detach the finite outer contract and preserve the distinct original child profiles."""
    return {'schema_version': '1.0.0', 'profile_id': PROFILE_ID,
            'language': LANGUAGE, 'pdf_version': '1.7', 'max_pages': MAX_PAGES,
            'max_pdf_bytes': MAX_PDF_BYTES, 'max_result_bytes': MAX_RESULT_BYTES,
            'max_inspector_invocations': MAX_INVOCATIONS,
            'acceptance_deadline_ns': ACCEPTANCE_NS,
            'source_job_profile_sha256': SOURCE_PROFILE_SHA256,
            'structure_profile_id': structure.PROFILE_ID,
            'structure_policy_id': structure.POLICY_ID,
            'structure_parser_version': structure.PARSER_VERSION,
            'structure_limits': {'pages': structure.MAX_DOCUMENT_PAGES,
                'pdf_bytes': structure.MAX_PDF_BYTES, 'result_bytes': structure.RESULT_BYTES,
                'tree_visits': structure.MAX_TREE_VISITS, 'tree_depth': structure.MAX_TREE_DEPTH,
                'memory_bytes': structure.MEMORY_BYTES, 'cpu_seconds': structure.CPU_SECONDS,
                'open_files': structure.OPEN_FILES},
            'source_capture': 'EXISTING_BOUNDED_NATIVE_JSON_SNAPSHOT',
            'retries': 0, 'persistent_checkpoints': False,
            'hard_job_deadline_enforced': False,
            'aggregate_job_resources_qualified': False, 'release_authorized': False}


PROFILE_SHA256 = sha256(_json_bytes(structured_source_job_profile())).hexdigest()


def _profile(expected: str) -> None:
    """Reject drift or disabling in any prerequisite before work and final acceptance."""
    _pin(expected)
    if (sys.platform != 'linux' or any(os.environ.get(key) == '1' for key in _DISABLES)
            or expected != PROFILE_SHA256
            or sha256(_json_bytes(structured_source_job_profile())).hexdigest() != PROFILE_SHA256
            or source.PROFILE_SHA256 != SOURCE_PROFILE_SHA256):
        raise ValueError('structured source profile unavailable')
    source._profile(SOURCE_PROFILE_SHA256)


@dataclass(frozen=True, slots=True, repr=False)
class PdfStructuredSourceResult:
    """Sealed unsigned agreement of source, forward structure and the complete existing job."""

    source_inspection: PdfSourceInspectionResult
    structure_tree: PdfStructureTreeInspection
    expected_source_sha256: str
    expected_structure_sha256: str
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
        """Revalidate independent child pins, every document/job binding and shared MCID counts."""
        for value in (self.expected_source_sha256, self.expected_structure_sha256,
                      self.expected_text_sha256, self.pdf_sha256, self.ir_sha256,
                      self.request_sha256, self.resource_profile_sha256):
            _pin(value)
        if (type(self.page_count) is not int or not 1 <= self.page_count <= MAX_PAGES
                or type(self.namespace_id) is not str or type(self.job_id) is not str
                or self.resource_profile_sha256 != PROFILE_SHA256
                or type(self.source_inspection) is not PdfSourceInspectionResult
                or type(self.structure_tree) is not PdfStructureTreeInspection):
            raise ValueError('structured source result type or profile')
        _validate_context(self.namespace_id, self.job_id, self.request_sha256,
                          self.resource_profile_sha256)
        source_bytes = self.source_inspection.to_bytes()
        tree_bytes = self.structure_tree.to_bytes()
        if (sha256(source_bytes).hexdigest() != self.expected_source_sha256
                or sha256(tree_bytes).hexdigest() != self.expected_structure_sha256):
            raise ValueError('structured source child pin mismatch')
        original, tree = json.loads(source_bytes), json.loads(tree_bytes)
        identity = {'pdf_sha256': self.pdf_sha256, 'ir_sha256': self.ir_sha256,
                    'page_count': self.page_count}
        content = original['document_content']
        inspections = original['inspection_set']
        if (any(original[key] != value or tree[key] != value for key, value in identity.items())
                or original['language'] != LANGUAGE or tree['language'] != LANGUAGE
                or original['resource_profile_sha256'] != SOURCE_PROFILE_SHA256
                or any(original[key] != getattr(self, key) for key in
                       ('namespace_id', 'job_id', 'request_sha256'))
                or tree['plan_sha256'] != content['plan_sha256']
                or tree['plan_sha256'] != inspections['page_bundle']['text_stream']['plan_sha256']
                or original['expected_text_sha256'] != self.expected_text_sha256
                or content['extracted_text_sha256'] != self.expected_text_sha256
                or tree['mapped_mcids'] != inspections['document_receipts']['mcid_coverage']['record']['matched_mcids']):
            raise ValueError('structured source child identity or count disagreement')
        result = {'schema_version': '1.0.0', 'profile_id': PROFILE_ID,
                  'status': 'SOURCE_AND_FORWARD_STRUCTURE_RESULTS_BOUND', **identity,
                  'namespace_id': self.namespace_id, 'job_id': self.job_id,
                  'request_sha256': self.request_sha256,
                  'resource_profile_sha256': self.resource_profile_sha256,
                  'source_job_profile_sha256': SOURCE_PROFILE_SHA256,
                  'language': LANGUAGE, 'expected_text_sha256': self.expected_text_sha256,
                  'source_inspection_sha256': self.expected_source_sha256,
                  'structure_inspection_sha256': self.expected_structure_sha256,
                  'source_inspection': original, 'structure_tree': tree,
                  'inspection_dimensions': original['inspection_dimensions'] + ['forward_structure_linkage'],
                  'normalized_text_equivalence_verified': True,
                  'forward_reverse_linkage_verified': True,
                  'worker_results_authenticated': False, 'scientific_equivalence_verified': False,
                  'semantic_roles_qualified': False, 'reading_order_verified': False,
                  'visible_glyphs_verified': False, 'full_accessibility_qualified': False,
                  'finding_completeness_verified': False, 'aggregate_job_resources_qualified': False,
                  'release_authorized': False, 'release_authorization': 'NOT_ESTABLISHED'}
        data = _json_bytes(result)
        if len(data) > MAX_RESULT_BYTES:
            raise ValueError('structured source result byte budget')
        return data

    def __post_init__(self) -> None:
        """Seal direct metadata construction without allowing changed objects to be resealed."""
        try:
            digest = sha256(self._validated_bytes()).hexdigest()
            if hasattr(self, '_sealed_sha256') and self._sealed_sha256 != digest:
                raise ValueError('structured source result changed')
            object.__setattr__(self, '_sealed_sha256', digest)
        except Exception:
            raise PdfStructuredSourceJobError('pdf_structured_source_result_invalid') from None

    def to_bytes(self) -> bytes:
        """Expose only the original complete representation after rechecking retained children."""
        try:
            data = self._validated_bytes()
            if sha256(data).hexdigest() != self._sealed_sha256:
                raise ValueError('structured source result changed')
            return data
        except Exception:
            raise PdfStructuredSourceJobError('pdf_structured_source_result_invalid') from None

    def to_dict(self) -> dict:
        """Return detached content-free metadata with all original qualification limits."""
        return json.loads(self.to_bytes())

    @property
    def inspection_sha256(self) -> str:
        """Hash the sealed metadata without implying an execution signature or authority."""
        return sha256(self.to_bytes()).hexdigest()


def execute_pdf_structured_source_job(
    *, presentation_ir: object, pdf_bytes: object, expected_pdf_sha256: str,
    expected_ir_sha256: str, page_count: int, expected_language: str,
    namespace_id: str, job_id: str, request_sha256: str,
    expected_resource_profile_sha256: str,
) -> PdfStructuredSourceResult:
    """Run forward linkage first, then the unchanged source-aware inspection job.

    The caller owns trusted source and job expectations. The existing native-JSON
    snapshot is bounded, not an atomic transaction on a concurrently mutating
    object. Persistent changes are rejected after each outer stage; concurrent
    mutate-and-restore behavior remains unsupported. The elapsed acceptance check
    does not interrupt synchronous children or enforce an aggregate CPU/RSS bound.
    No caller receipts, retries, custom executors or persistent state are accepted.
    """
    try:
        _profile(expected_resource_profile_sha256)
        if (type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b'%PDF-1.7')
                or len(pdf_bytes) > MAX_PDF_BYTES or type(page_count) is not int
                or not 1 <= page_count <= MAX_PAGES or type(expected_language) is not str
                or expected_language != LANGUAGE or type(namespace_id) is not str
                or type(job_id) is not str):
            raise ValueError('structured source input type or domain')
        for value in (expected_pdf_sha256, expected_ir_sha256, request_sha256):
            _pin(value)
        _validate_context(namespace_id, job_id, request_sha256, expected_resource_profile_sha256)
        captured = _snapshot_ir(presentation_ir)
        source_bytes = _json_bytes(captured)
        ir_digest, expected_text = _expected_content(captured)
        if (captured.get('locale_id') != LANGUAGE or ir_digest != expected_ir_sha256
                or sha256(pdf_bytes).hexdigest() != expected_pdf_sha256):
            raise ValueError('structured source exact input mismatch')
        plan = plan_pdf_page_windows(pdf_sha256=expected_pdf_sha256,
            ir_sha256=expected_ir_sha256, page_count=page_count, admitted_page_budget=page_count,
            pages_per_window=source.legacy.TEXT_WIDTH, inspector_profile_id=source.legacy.TEXT_PROFILE)
        started = previous = monotonic_ns()
        if type(started) is not int or started < 0:
            raise ValueError('structured source clock invalid')
    except Exception:
        raise PdfStructuredSourceJobError('pdf_structured_source_job_input_invalid') from None

    def check() -> None:
        """Check acceptance, prerequisite profiles and both captured/original source views."""
        nonlocal previous
        _profile(expected_resource_profile_sha256)
        current = monotonic_ns()
        if (type(current) is not int or current < previous or current - started >= ACCEPTANCE_NS
                or _json_bytes(_snapshot_ir(presentation_ir)) != source_bytes
                or _json_bytes(_snapshot_ir(captured)) != source_bytes):
            raise ValueError('structured source acceptance or input changed')
        previous = current

    try:
        check()
        tree = inspect_pdf_structure_tree(pdf_bytes=pdf_bytes, plan=plan,
            expected_plan_sha256=plan.plan_sha256, expected_language=LANGUAGE)
        check()
        if type(tree) is not PdfStructureTreeInspection:
            raise ValueError('structured source tree type')
        record = tree.to_dict()
        if any(record[key] != getattr(plan, key) for key in
               ('pdf_sha256', 'ir_sha256', 'plan_sha256', 'page_count')):
            raise ValueError('structured source tree identity')
        original = execute_pdf_source_inspection_job(presentation_ir=captured, pdf_bytes=pdf_bytes,
            expected_pdf_sha256=expected_pdf_sha256, expected_ir_sha256=expected_ir_sha256,
            page_count=page_count, expected_language=LANGUAGE, namespace_id=namespace_id,
            job_id=job_id, request_sha256=request_sha256,
            expected_resource_profile_sha256=SOURCE_PROFILE_SHA256)
        check()
        if type(original) is not PdfSourceInspectionResult:
            raise ValueError('structured source child type')
        result = PdfStructuredSourceResult(source_inspection=original, structure_tree=tree,
            expected_source_sha256=original.inspection_sha256,
            expected_structure_sha256=tree.inspection_sha256, expected_text_sha256=expected_text,
            pdf_sha256=expected_pdf_sha256, ir_sha256=expected_ir_sha256, page_count=page_count,
            namespace_id=namespace_id, job_id=job_id, request_sha256=request_sha256,
            resource_profile_sha256=expected_resource_profile_sha256)
        result.to_bytes()
        check()
        return result
    except Exception:
        raise PdfStructuredSourceJobError('pdf_structured_source_job_execution_failed') from None
