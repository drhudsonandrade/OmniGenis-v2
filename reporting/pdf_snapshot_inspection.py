"""Opt-in immutable source transport for the existing complete PDF inspection job.

Only independently pinned canonical UTF-8 native-JSON bytes are admitted. An
unsealed mutable dictionary is not accepted or copied at this API boundary.
The caller must obtain the source and expectations through its authenticated
upstream artifact transaction; matching bytes do not authenticate that source.

Independent pins select either the original structured job or the combined
native-source job. Both retain their existing result types, inspectors and
limits. This adds no release, scientific, aggregate-resource or hard-deadline
qualification and does not change the default rendering route.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os

from reporting import pdf_candidate_qa as qa
from reporting import pdf_native_source_job as native
from reporting import pdf_structured_source_job as structured
from reporting.bindings import _digest
from reporting.page_checkpoints import (
    _json_bytes, _reject_constant, _unique_object, _validate_context,
)
from reporting.pdf_content import _expected_content
from reporting.pdf_native_source_job import (
    PdfNativeSourceResult, execute_pdf_native_source_job,
)
from reporting.pdf_structured_source_job import (
    PdfStructuredSourceResult, execute_pdf_structured_source_job,
)

PROFILE_ID = 'immutable-presentation-source-v1'
NATIVE_PROFILE_ID = 'immutable-presentation-source-v2'
MAX_SOURCE_BYTES = qa.MAX_PDF_BYTES
MAX_JSON_DEPTH = qa._MAX_JSON_DEPTH
MAX_JSON_NODES = qa._MAX_JSON_NODES
MAX_INTEGER_BITS = qa._MAX_INTEGER_BITS
STRUCTURED_PROFILE_SHA256 = structured.PROFILE_SHA256
NATIVE_RESOURCE_PROFILE_SHA256 = native.PROFILE_SHA256
_DISABLE = 'OMNIGENIS_PDF_SNAPSHOT_INSPECTION_DISABLED'


class PdfSnapshotInspectionError(ValueError):
    """Fixed content-free admission or execution failure with no partial result."""


def snapshot_source_profile() -> dict:
    """Detach the immutable-source contract without replacing the child resource profile."""
    return {'schema_version': '1.0.0', 'profile_id': PROFILE_ID,
            'max_source_bytes': MAX_SOURCE_BYTES, 'max_json_depth': MAX_JSON_DEPTH,
            'max_json_nodes': MAX_JSON_NODES, 'max_integer_bits': MAX_INTEGER_BITS,
            'source_type': 'EXACT_IMMUTABLE_BYTES',
            'source_encoding': 'EXISTING_CANONICAL_SORTED_COMPACT_UTF8_NATIVE_JSON',
            'json_budget_scan': 'CONTAINERS_KEYS_AND_SCALARS_BEFORE_STANDARD_DECODER',
            'structured_job_profile_sha256': STRUCTURED_PROFILE_SHA256,
            'returned_result_type': 'PdfStructuredSourceResult',
            'source_storage_authenticated': False, 'hard_job_deadline_enforced': False,
            'aggregate_job_resources_qualified': False, 'release_authorized': False}


PROFILE_SHA256 = sha256(_json_bytes(snapshot_source_profile())).hexdigest()


def native_snapshot_source_profile() -> dict:
    """Bind the same immutable-source admission to the complete native-source job."""
    profile = snapshot_source_profile()
    del profile['structured_job_profile_sha256']
    profile.update(schema_version='2.0.0', profile_id=NATIVE_PROFILE_ID,
                   native_source_job_profile_sha256=NATIVE_RESOURCE_PROFILE_SHA256,
                   returned_result_type='PdfNativeSourceResult')
    return profile


NATIVE_PROFILE_SHA256 = sha256(_json_bytes(native_snapshot_source_profile())).hexdigest()


def _profile(source_pin: str, resource_pin: str) -> bool:
    """Require both independent pins and preserve every existing prerequisite switch."""
    _digest(source_pin)
    _digest(resource_pin)
    if (os.environ.get(_DISABLE) == '1'
            or (qa.MAX_PDF_BYTES, qa._MAX_JSON_DEPTH, qa._MAX_JSON_NODES, qa._MAX_INTEGER_BITS)
            != (MAX_SOURCE_BYTES, MAX_JSON_DEPTH, MAX_JSON_NODES, MAX_INTEGER_BITS)):
        raise ValueError('snapshot profile unavailable')
    if source_pin == PROFILE_SHA256:
        if (sha256(_json_bytes(snapshot_source_profile())).hexdigest() != PROFILE_SHA256
                or resource_pin != STRUCTURED_PROFILE_SHA256
                or structured.PROFILE_SHA256 != STRUCTURED_PROFILE_SHA256):
            raise ValueError('snapshot profile unavailable')
        structured._profile(resource_pin)
        return False
    if source_pin == NATIVE_PROFILE_SHA256:
        if (sha256(_json_bytes(native_snapshot_source_profile())).hexdigest() != NATIVE_PROFILE_SHA256
                or resource_pin != NATIVE_RESOURCE_PROFILE_SHA256
                or native.PROFILE_SHA256 != NATIVE_RESOURCE_PROFILE_SHA256):
            raise ValueError('snapshot profile unavailable')
        native._profile(resource_pin)
        return True
    raise ValueError('snapshot profile unavailable')


def _scan_json_budget(data: bytes) -> None:
    """Bound raw nesting and node starts before allocating a decoded JSON graph.

    This is only a linear allocation-budget precheck, not a JSON parser. Strings
    and escapes hide structural punctuation. The standard strict decoder and
    existing bounded native-object validator still establish actual validity.
    """
    nodes = depth = 0
    quoted = escaped = primitive = False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
            continue
        if byte in (32, 9, 10, 13, 44, 58):
            primitive = False
            continue
        if byte in (125, 93):
            depth -= 1
            primitive = False
            if depth < 0:
                raise ValueError('snapshot JSON nesting')
            continue
        if byte in (123, 91, 34) or not primitive:
            nodes += 1
            if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
                raise ValueError('snapshot JSON budget')
        if byte in (123, 91):
            depth += 1
            primitive = False
        elif byte == 34:
            quoted = True
            primitive = False
        else:
            primitive = True
    if quoted or depth != 0:
        raise ValueError('snapshot JSON envelope')


def _decode_source(data: bytes) -> dict:
    """Reuse duplicate/nonfinite checks and exact canonical encoding without repairs."""
    record = json.loads(data.decode('utf-8'), object_pairs_hook=_unique_object,
                        parse_constant=_reject_constant)
    captured = qa._snapshot_ir(record)
    if _json_bytes(captured) != data:
        raise ValueError('snapshot source not exact canonical JSON')
    return captured


def execute_pdf_snapshot_inspection_job(
    *, presentation_ir_bytes: object, expected_ir_sha256: str,
    pdf_bytes: object, expected_pdf_sha256: str, page_count: int,
    expected_language: str, namespace_id: str, job_id: str, request_sha256: str,
    expected_source_profile_sha256: str, expected_resource_profile_sha256: str,
) -> PdfStructuredSourceResult | PdfNativeSourceResult:
    """Inspect one immutable source through the independently pinned fixed job.

    The source pin qualifies this admission encoding only. The independent
    resource pin and returned sealed result keep their original job identity.
    The native family requires its own source pin; mixed families never fall back.
    No caller receipts, mutable-source factory, storage handle, executor, retry,
    checkpoint, source refresh or report publication is introduced.

    JSON decoding remains parent-local under finite byte/node/depth admission;
    these bounds are not hard total-memory or total-time supervision. PDF parsing
    stays in the existing guarded child processes. The source must already have
    been sealed upstream; this function does not implement that transaction.
    """
    try:
        selected_native = _profile(expected_source_profile_sha256, expected_resource_profile_sha256)
        resource = native if selected_native else structured
        if (type(presentation_ir_bytes) is not bytes
                or not 0 < len(presentation_ir_bytes) <= MAX_SOURCE_BYTES
                or type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b'%PDF-1.7')
                or len(pdf_bytes) > resource.MAX_PDF_BYTES
                or type(page_count) is not int or not 1 <= page_count <= resource.MAX_PAGES
                or type(expected_language) is not str or expected_language != resource.LANGUAGE):
            raise ValueError('snapshot input type or budget')
        for value in (expected_ir_sha256, expected_pdf_sha256, request_sha256):
            _digest(value)
        _validate_context(namespace_id, job_id, request_sha256, expected_resource_profile_sha256)
        if (sha256(presentation_ir_bytes).hexdigest() != expected_ir_sha256
                or sha256(pdf_bytes).hexdigest() != expected_pdf_sha256):
            raise ValueError('snapshot byte identity mismatch')
        _scan_json_budget(presentation_ir_bytes)
        captured = _decode_source(presentation_ir_bytes)
        ir_digest, expected_text = _expected_content(captured)
        if ir_digest != expected_ir_sha256 or captured.get('locale_id') != expected_language:
            raise ValueError('snapshot source profile mismatch')
    except Exception:
        raise PdfSnapshotInspectionError('pdf_snapshot_inspection_input_invalid') from None

    try:
        execute = execute_pdf_native_source_job if selected_native else execute_pdf_structured_source_job
        result = execute(
            presentation_ir=captured, expected_ir_sha256=expected_ir_sha256,
            pdf_bytes=pdf_bytes, expected_pdf_sha256=expected_pdf_sha256,
            page_count=page_count, expected_language=expected_language,
            namespace_id=namespace_id, job_id=job_id, request_sha256=request_sha256,
            expected_resource_profile_sha256=expected_resource_profile_sha256)
        _profile(expected_source_profile_sha256, expected_resource_profile_sha256)
        if _json_bytes(qa._snapshot_ir(captured)) != presentation_ir_bytes:
            raise ValueError('snapshot decoded source changed')
        result_type = PdfNativeSourceResult if selected_native else PdfStructuredSourceResult
        if type(result) is not result_type:
            raise ValueError('snapshot result type')
        record = result.to_dict()
        expected = {'pdf_sha256': expected_pdf_sha256, 'ir_sha256': expected_ir_sha256,
                    'page_count': page_count, 'language': expected_language,
                    'namespace_id': namespace_id, 'job_id': job_id,
                    'request_sha256': request_sha256, 'expected_text_sha256': expected_text,
                    'resource_profile_sha256': expected_resource_profile_sha256}
        if any(record[key] != value for key, value in expected.items()):
            raise ValueError('snapshot result identity mismatch')
        _profile(expected_source_profile_sha256, expected_resource_profile_sha256)
        return result
    except Exception:
        raise PdfSnapshotInspectionError('pdf_snapshot_inspection_execution_failed') from None
