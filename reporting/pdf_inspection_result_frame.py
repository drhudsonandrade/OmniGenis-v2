"""Opt-in bounded transport for the existing complete sealed PDF inspection result.

This contract carries the original result bytes; it does not reconstruct a trusted
result object, authenticate the sender, supervise a process tree, enforce a hard
deadline, authorize a release or alter any existing child admission. An external
qualified controller must supply independent job expectations and reject incomplete
or unauthenticated worker execution. No process, filesystem or network is accessed.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
import struct

from reporting import pdf_snapshot_inspection as snapshot
from reporting import pdf_structured_source_job as structured
from reporting.bindings import _digest
from reporting.page_checkpoints import (
    _json_bytes, _reject_constant, _unique_object, _validate_context,
)
from reporting.pdf_structured_source_job import PdfStructuredSourceResult

PROFILE_ID = 'complete-pdf-inspection-result-frame-v1'
MAGIC = b'OGPDFRS1'
HEADER = struct.Struct('>8sI32s')
MAX_RESULT_BYTES = structured.MAX_RESULT_BYTES
MAX_FRAME_BYTES = HEADER.size + MAX_RESULT_BYTES
RESOURCE_PROFILE_SHA256 = structured.PROFILE_SHA256
SOURCE_JOB_PROFILE_SHA256 = structured.SOURCE_PROFILE_SHA256
_DISABLE = 'OMNIGENIS_PDF_INSPECTION_RESULT_FRAME_DISABLED'
_RESULT_KEYS = frozenset((
    'schema_version', 'profile_id', 'status', 'pdf_sha256', 'ir_sha256',
    'page_count', 'language', 'namespace_id', 'job_id', 'request_sha256',
    'resource_profile_sha256', 'source_job_profile_sha256',
    'source_inspection_sha256', 'structure_inspection_sha256',
    'source_inspection', 'structure_tree', 'expected_text_sha256',
    'inspection_dimensions', 'normalized_text_equivalence_verified',
    'forward_reverse_linkage_verified', 'worker_results_authenticated',
    'scientific_equivalence_verified', 'semantic_roles_qualified',
    'reading_order_verified', 'visible_glyphs_verified',
    'full_accessibility_qualified', 'finding_completeness_verified',
    'aggregate_job_resources_qualified', 'release_authorized',
    'release_authorization',
))
_DIMENSIONS = ('text', 'raster', 'object_graph', 'document_metadata',
               'page_tags', 'mcid_linkage', 'normalized_source_text',
               'forward_structure_linkage')


class PdfInspectionResultFrameError(ValueError):
    """Content-free failure; no partial frame is an accepted result."""


def result_frame_profile() -> dict:
    """Describe only fixed lossless result transport, without promoting authority."""
    return {'schema_version': '1.0.0', 'profile_id': PROFILE_ID,
            'magic': MAGIC.decode('ascii'), 'header_format': HEADER.format,
            'header_bytes': HEADER.size, 'result_encoding': 'EXACT_ORIGINAL_CANONICAL_JSON_BYTES',
            'result_profile_sha256': RESOURCE_PROFILE_SHA256,
            'source_job_profile_sha256': SOURCE_JOB_PROFILE_SHA256,
            'max_result_bytes': MAX_RESULT_BYTES, 'max_frame_bytes': MAX_FRAME_BYTES,
            'original_result_type': 'PdfStructuredSourceResult',
            'reconstructed_typed_result': False, 'sender_authenticated': False,
            'aggregate_job_resources_qualified': False, 'hard_job_deadline_enforced': False,
            'new_executor_activated': False, 'default_pipeline_activated': False,
            'release_authorized': False}


PROFILE_SHA256 = sha256(_json_bytes(result_frame_profile())).hexdigest()


def _profile(expected: str) -> None:
    """Enforce both original dependency identity and the new fixed frame pin."""
    _digest(expected)
    if (os.environ.get(_DISABLE) == '1'
            or expected != PROFILE_SHA256
            or sha256(_json_bytes(result_frame_profile())).hexdigest() != PROFILE_SHA256
            or RESOURCE_PROFILE_SHA256 != structured.PROFILE_SHA256
            or SOURCE_JOB_PROFILE_SHA256 != structured.SOURCE_PROFILE_SHA256
            or MAX_RESULT_BYTES != structured.MAX_RESULT_BYTES):
        raise ValueError('result frame profile unavailable')
    structured._profile(RESOURCE_PROFILE_SHA256)


def _expected(
    *, expected_pdf_sha256: str, expected_ir_sha256: str,
    expected_page_count: int, expected_language: str,
    expected_namespace_id: str, expected_job_id: str,
    expected_request_sha256: str, expected_resource_profile_sha256: str,
) -> dict:
    """Require independent literal job/document/profile expectations, not packet claims."""
    for value in (expected_pdf_sha256, expected_ir_sha256,
                  expected_request_sha256, expected_resource_profile_sha256):
        _digest(value)
    if (type(expected_page_count) is not int
            or not 1 <= expected_page_count <= structured.MAX_PAGES
            or type(expected_language) is not str
            or expected_language != structured.LANGUAGE
            or expected_resource_profile_sha256 != RESOURCE_PROFILE_SHA256):
        raise ValueError('result frame job domain invalid')
    _validate_context(expected_namespace_id, expected_job_id,
                      expected_request_sha256, expected_resource_profile_sha256)
    return dict(pdf_sha256=expected_pdf_sha256, ir_sha256=expected_ir_sha256,
                page_count=expected_page_count, language=expected_language,
                namespace_id=expected_namespace_id, job_id=expected_job_id,
                request_sha256=expected_request_sha256,
                resource_profile_sha256=expected_resource_profile_sha256,
                source_job_profile_sha256=SOURCE_JOB_PROFILE_SHA256)


def _record(data: bytes, expected: dict) -> dict:
    """Check bounded canonical bytes, both child hashes and explicit original bindings.

    This is an unsigned transport check, not reconstruction or independent
    authentication of native worker receipts or scientific conclusions.
    """
    if type(data) is not bytes or not 0 < len(data) <= MAX_RESULT_BYTES:
        raise ValueError('result frame body budget')
    snapshot._scan_json_budget(data)
    record = json.loads(data.decode('utf-8'), object_pairs_hook=_unique_object,
                        parse_constant=_reject_constant)
    if type(record) is not dict or set(record) != _RESULT_KEYS or _json_bytes(record) != data:
        raise ValueError('result frame canonical fields')
    if (record['schema_version'] != '1.0.0'
            or record['profile_id'] != structured.PROFILE_ID
            or record['status'] != 'SOURCE_AND_FORWARD_STRUCTURE_RESULTS_BOUND'
            or any(record.get(key) != value for key, value in expected.items())
            or record['release_authorization'] != 'NOT_ESTABLISHED'
            or record['inspection_dimensions'] != list(_DIMENSIONS)
            or record['normalized_text_equivalence_verified'] is not True
            or record['forward_reverse_linkage_verified'] is not True):
        raise ValueError('result frame original identity changed')
    for key in ('worker_results_authenticated', 'scientific_equivalence_verified',
                'semantic_roles_qualified', 'reading_order_verified',
                'visible_glyphs_verified', 'full_accessibility_qualified',
                'finding_completeness_verified', 'aggregate_job_resources_qualified',
                'release_authorized'):
        if record[key] is not False:
            raise ValueError('result frame unsupported qualification')
    source, tree = record['source_inspection'], record['structure_tree']
    if type(source) is not dict or type(tree) is not dict:
        raise ValueError('result frame child types')
    if (sha256(_json_bytes(source)).hexdigest() != record['source_inspection_sha256']
            or sha256(_json_bytes(tree)).hexdigest() != record['structure_inspection_sha256']):
        raise ValueError('result frame child identity mismatch')
    for field in ('pdf_sha256', 'ir_sha256', 'page_count', 'language'):
        if source.get(field) != expected[field] or tree.get(field) != expected[field]:
            raise ValueError('result frame child document mismatch')
    for field in ('namespace_id', 'job_id', 'request_sha256'):
        if source.get(field) != expected[field]:
            raise ValueError('result frame child job mismatch')
    if (source.get('resource_profile_sha256') != SOURCE_JOB_PROFILE_SHA256
            or source.get('expected_text_sha256') != record['expected_text_sha256']):
        raise ValueError('result frame source binding mismatch')
    for child in (source, tree):
        if (child.get('release_authorization') != 'NOT_ESTABLISHED'
                or any(child.get(key) is not False for key in
                       ('aggregate_job_resources_qualified', 'release_authorized',
                        'worker_results_authenticated', 'scientific_equivalence_verified',
                        'full_accessibility_qualified'))):
            raise ValueError('result frame child claimed unsupported authority')
    if (source.get('inspection_dimensions') != list(_DIMENSIONS[:-1])
            or source.get('finding_completeness_verified') is not False
            or source.get('normalized_text_equivalence_verified') is not True
            or tree.get('forward_reverse_linkage_verified') is not True):
        raise ValueError('result frame child scope mismatch')
    content = source.get('document_content')
    inspections = source.get('inspection_set')
    if type(content) is not dict or type(inspections) is not dict:
        raise ValueError('result frame child structure invalid')
    if (content['extracted_text_sha256'] != record['expected_text_sha256']
            or tree['plan_sha256'] != content['plan_sha256']
            or tree['plan_sha256'] != inspections['page_bundle']['text_stream']['plan_sha256']
            or tree['mapped_mcids'] != inspections['document_receipts']['mcid_coverage']['record']['matched_mcids']):
        raise ValueError('result frame child linkage mismatch')
    return record


def encode_pdf_inspection_result_frame(
    result: object, *, expected_pdf_sha256: str, expected_ir_sha256: str,
    expected_page_count: int, expected_language: str,
    expected_namespace_id: str, expected_job_id: str,
    expected_request_sha256: str, expected_resource_profile_sha256: str,
    expected_frame_profile_sha256: str,
) -> bytes:
    """Encode exact existing typed result bytes, without reclassifying their meaning."""
    try:
        _profile(expected_frame_profile_sha256)
        bound = _expected(expected_pdf_sha256=expected_pdf_sha256,
                          expected_ir_sha256=expected_ir_sha256,
                          expected_page_count=expected_page_count,
                          expected_language=expected_language,
                          expected_namespace_id=expected_namespace_id,
                          expected_job_id=expected_job_id,
                          expected_request_sha256=expected_request_sha256,
                          expected_resource_profile_sha256=expected_resource_profile_sha256)
        if type(result) is not PdfStructuredSourceResult:
            raise ValueError('typed original result required')
        raw = result.to_bytes()
        _record(raw, bound)
        frame = HEADER.pack(MAGIC, len(raw), sha256(raw).digest()) + raw
        _profile(expected_frame_profile_sha256)
        return frame
    except Exception:
        raise PdfInspectionResultFrameError('pdf_inspection_result_frame_invalid') from None


def decode_pdf_inspection_result_frame(
    packet_bytes: object, *, expected_pdf_sha256: str, expected_ir_sha256: str,
    expected_page_count: int, expected_language: str,
    expected_namespace_id: str, expected_job_id: str,
    expected_request_sha256: str, expected_resource_profile_sha256: str,
    expected_frame_profile_sha256: str,
) -> bytes:
    """Return exact bound body bytes, never a worker-authenticated or released object."""
    try:
        _profile(expected_frame_profile_sha256)
        bound = _expected(expected_pdf_sha256=expected_pdf_sha256,
                          expected_ir_sha256=expected_ir_sha256,
                          expected_page_count=expected_page_count,
                          expected_language=expected_language,
                          expected_namespace_id=expected_namespace_id,
                          expected_job_id=expected_job_id,
                          expected_request_sha256=expected_request_sha256,
                          expected_resource_profile_sha256=expected_resource_profile_sha256)
        if (type(packet_bytes) is not bytes
                or not HEADER.size < len(packet_bytes) <= MAX_FRAME_BYTES):
            raise ValueError('result frame envelope type')
        magic, size, digest = HEADER.unpack_from(packet_bytes)
        if (magic != MAGIC or not 0 < size <= MAX_RESULT_BYTES
                or HEADER.size + size != len(packet_bytes)):
            raise ValueError('result frame length')
        raw = packet_bytes[HEADER.size:]
        if sha256(raw).digest() != digest:
            raise ValueError('result frame body changed')
        _record(raw, bound)
        _profile(expected_frame_profile_sha256)
        return raw
    except Exception:
        raise PdfInspectionResultFrameError('pdf_inspection_result_frame_invalid') from None
