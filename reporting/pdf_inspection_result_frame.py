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
from reporting import pdf_native_source_job as native
from reporting import pdf_tounicode_width_coverage as width
from reporting import pdf_inspection_job as legacy
from reporting.bindings import _digest
from reporting.page_checkpoints import (
    _json_bytes, _reject_constant, _unique_object, _validate_context,
)
from reporting.pdf_structured_source_job import PdfStructuredSourceResult
from reporting.pdf_native_source_job import PdfNativeSourceResult
from reporting.page_windows import plan_pdf_page_windows

PROFILE_ID = 'complete-pdf-inspection-result-frame-v1'
MAGIC = b'OGPDFRS1'
HEADER = struct.Struct('>8sI32s')
MAX_RESULT_BYTES = structured.MAX_RESULT_BYTES
MAX_FRAME_BYTES = HEADER.size + MAX_RESULT_BYTES
RESOURCE_PROFILE_SHA256 = structured.PROFILE_SHA256
SOURCE_JOB_PROFILE_SHA256 = structured.SOURCE_PROFILE_SHA256
NATIVE_PROFILE_ID = 'complete-pdf-inspection-result-frame-v2'
NATIVE_MAGIC = b'OGPDFRS2'
NATIVE_MAX_RESULT_BYTES = native.MAX_RESULT_BYTES
NATIVE_MAX_FRAME_BYTES = HEADER.size + NATIVE_MAX_RESULT_BYTES
NATIVE_RESOURCE_PROFILE_SHA256 = native.PROFILE_SHA256
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
_NATIVE_RESULT_KEYS = frozenset((
    'schema_version', 'profile_id', 'status', 'pdf_sha256', 'ir_sha256',
    'plan_sha256', 'page_count', 'language', 'namespace_id', 'job_id',
    'request_sha256', 'resource_profile_sha256', 'native_width_profile_sha256',
    'structured_source_job_profile_sha256', 'expected_text_sha256',
    'native_inspection_sha256', 'structured_inspection_sha256',
    'native_inspection', 'structured_inspection', 'inspection_dimensions',
    'shared_input_bindings_verified', 'same_font_explicit_width_coverage_verified',
    'normalized_text_equivalence_verified', 'forward_reverse_linkage_verified',
    'release_authorization',
)) | frozenset(native._nonclaims())
_NATIVE_WIDTH_KEYS = frozenset((
    'schema_version', 'profile_id', 'policy_id', 'status', 'parser_version',
    'language', 'profile_sha256', 'previous_tounicode_bfchar_sources_profile_sha256',
    'pdf_sha256', 'ir_sha256', 'plan_sha256', 'page_count', 'tounicode_stream_count',
    'cid_width_font_count', 'bfchar_source_count', 'bfchar_covered_source_count',
    'explicit_cid_width_count', 'same_font_explicit_width_coverage_valid',
    'prior_tounicode_bfchar_sources_sha256', 'release_authorization',
)) | frozenset(width._nonclaims())


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


def native_result_frame_profile() -> dict:
    """Bind the complete native composition to a distinct, independently selected frame."""
    result = result_frame_profile()
    del result['source_job_profile_sha256']
    return {**result, 'schema_version': '2.0.0', 'profile_id': NATIVE_PROFILE_ID,
            'magic': NATIVE_MAGIC.decode('ascii'),
            'result_profile_sha256': NATIVE_RESOURCE_PROFILE_SHA256,
            'native_width_profile_sha256': native.NATIVE_PROFILE_SHA256,
            'structured_source_job_profile_sha256': native.STRUCTURED_PROFILE_SHA256,
            'max_result_bytes': NATIVE_MAX_RESULT_BYTES,
            'max_frame_bytes': NATIVE_MAX_FRAME_BYTES,
            'original_result_type': 'PdfNativeSourceResult',
            'independent_text_plan_binding_required': True}


NATIVE_PROFILE_SHA256 = sha256(_json_bytes(native_result_frame_profile())).hexdigest()


def _profile(expected: str) -> bool:
    """Enforce both original dependency identity and the new fixed frame pin."""
    _digest(expected)
    if expected == NATIVE_PROFILE_SHA256:
        if (os.environ.get(_DISABLE) == '1'
                or sha256(_json_bytes(native_result_frame_profile())).hexdigest() != NATIVE_PROFILE_SHA256
                or NATIVE_RESOURCE_PROFILE_SHA256 != native.PROFILE_SHA256
                or RESOURCE_PROFILE_SHA256 != native.STRUCTURED_PROFILE_SHA256
                or RESOURCE_PROFILE_SHA256 != structured.PROFILE_SHA256
                or SOURCE_JOB_PROFILE_SHA256 != structured.SOURCE_PROFILE_SHA256
                or MAX_RESULT_BYTES != structured.MAX_RESULT_BYTES
                or NATIVE_MAX_RESULT_BYTES != native.MAX_RESULT_BYTES
                or NATIVE_MAX_FRAME_BYTES != HEADER.size + NATIVE_MAX_RESULT_BYTES):
            raise ValueError('native result frame profile unavailable')
        native._profile(NATIVE_RESOURCE_PROFILE_SHA256)
        return True
    if (os.environ.get(_DISABLE) == '1'
            or expected != PROFILE_SHA256
            or sha256(_json_bytes(result_frame_profile())).hexdigest() != PROFILE_SHA256
            or RESOURCE_PROFILE_SHA256 != structured.PROFILE_SHA256
            or SOURCE_JOB_PROFILE_SHA256 != structured.SOURCE_PROFILE_SHA256
            or MAX_RESULT_BYTES != structured.MAX_RESULT_BYTES):
        raise ValueError('result frame profile unavailable')
    structured._profile(RESOURCE_PROFILE_SHA256)
    return False


def _expected(
    *, expected_pdf_sha256: str, expected_ir_sha256: str,
    expected_page_count: int, expected_language: str,
    expected_namespace_id: str, expected_job_id: str,
    expected_request_sha256: str, expected_resource_profile_sha256: str,
    selected_native: bool = False,
) -> dict:
    """Require independent literal job/document/profile expectations, not packet claims."""
    for value in (expected_pdf_sha256, expected_ir_sha256,
                  expected_request_sha256, expected_resource_profile_sha256):
        _digest(value)
    if (type(expected_page_count) is not int
            or not 1 <= expected_page_count <= structured.MAX_PAGES
            or type(expected_language) is not str
            or expected_language != structured.LANGUAGE
            or expected_resource_profile_sha256 != (
                NATIVE_RESOURCE_PROFILE_SHA256 if selected_native else RESOURCE_PROFILE_SHA256)):
        raise ValueError('result frame job domain invalid')
    _validate_context(expected_namespace_id, expected_job_id,
                      expected_request_sha256, expected_resource_profile_sha256)
    result = dict(pdf_sha256=expected_pdf_sha256, ir_sha256=expected_ir_sha256,
                page_count=expected_page_count, language=expected_language,
                namespace_id=expected_namespace_id, job_id=expected_job_id,
                request_sha256=expected_request_sha256,
                resource_profile_sha256=expected_resource_profile_sha256)
    if selected_native:
        plan = plan_pdf_page_windows(
            pdf_sha256=expected_pdf_sha256, ir_sha256=expected_ir_sha256,
            page_count=expected_page_count, admitted_page_budget=expected_page_count,
            pages_per_window=legacy.TEXT_WIDTH, inspector_profile_id=legacy.TEXT_PROFILE)
        result['plan_sha256'] = plan.plan_sha256
    else:
        result['source_job_profile_sha256'] = SOURCE_JOB_PROFILE_SHA256
    return result


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


def _native_width_record(record: object, expected: dict) -> None:
    """Validate the unsigned native child without constructing a trusted receipt."""
    if type(record) is not dict or set(record) != _NATIVE_WIDTH_KEYS:
        raise ValueError('native width result fields')
    width._identity({key: record[key] for key in
                     ('pdf_sha256', 'ir_sha256', 'plan_sha256', 'page_count')})
    fixed = {'schema_version': '1.0.0', 'profile_id': width.PROFILE_ID,
             'policy_id': width.POLICY_ID, 'status': width.STATUS,
             'parser_version': width.PARSER_VERSION, 'language': width.LANGUAGE,
             'profile_sha256': native.NATIVE_PROFILE_SHA256,
             'previous_tounicode_bfchar_sources_profile_sha256': width.previous.PROFILE_SHA256,
             'release_authorization': 'NOT_ESTABLISHED'}
    fixed.update({key: expected[key] for key in
                  ('pdf_sha256', 'ir_sha256', 'plan_sha256', 'page_count')})
    if any(type(record[key]) is not type(value) or record[key] != value
           for key, value in fixed.items()):
        raise ValueError('native width result identity')
    _digest(record['prior_tounicode_bfchar_sources_sha256'])
    counts = ('tounicode_stream_count', 'cid_width_font_count', 'bfchar_source_count',
              'bfchar_covered_source_count', 'explicit_cid_width_count')
    if (any(type(record[key]) is not int for key in counts)
            or not 1 <= record['tounicode_stream_count'] <= 32 * expected['page_count']
            or record['cid_width_font_count'] != record['tounicode_stream_count']
            or not 1 <= record['bfchar_source_count'] <= width.MAX_BFCHAR_RECORDS
            or record['bfchar_covered_source_count'] != record['bfchar_source_count']
            or not record['bfchar_source_count'] <= record['explicit_cid_width_count']
               <= width.MAX_CID_WIDTH_VALUES_PER_FONT * record['cid_width_font_count']
            or record['same_font_explicit_width_coverage_valid'] is not True
            or any(record[key] is not False for key in width._nonclaims())):
        raise ValueError('native width result counts or scope')


def _native_field_types(record: dict) -> None:
    """Keep integer page identities and inherited nonclaims strict at every child depth."""
    pending = [record]
    nonclaims = frozenset(native._nonclaims()) | frozenset((
        'native_execution_performed', 'whole_pdf_safety_qualified',
        'text_equivalence_verified', 'accessibility_qualified',
        'all_streams_or_revisions_inspected', 'full_struct_tree_verified',
        'semantic_tags_qualified', 'whole_visual_content_covered',
        'all_metadata_channels_inspected', 'semantic_tag_tree_verified',
        'all_marked_content_covered', 'visible_content_covered',
    ))
    while pending:
        value = pending.pop()
        if type(value) is dict:
            for key, item in value.items():
                if key == 'page_count' and type(item) is not int:
                    raise ValueError('native result page identity type')
                if key in nonclaims and item is not False:
                    raise ValueError('native result child unsupported qualification')
                if key == 'release_authorization' and (
                        type(item) is not str or item != 'NOT_ESTABLISHED'):
                    raise ValueError('native result child release authorization')
                if key.endswith('_sha256'):
                    _digest(item)
                if type(item) in (dict, list):
                    pending.append(item)
        elif type(value) is list:
            pending.extend(value)


def _native_record(data: bytes, expected: dict) -> dict:
    """Bind both complete children and the independently derived plan to one native job."""
    if type(data) is not bytes or not 0 < len(data) <= NATIVE_MAX_RESULT_BYTES:
        raise ValueError('native result frame body budget')
    snapshot._scan_json_budget(data)
    record = json.loads(data.decode('utf-8'), object_pairs_hook=_unique_object,
                        parse_constant=_reject_constant)
    if (type(record) is not dict or set(record) != _NATIVE_RESULT_KEYS
            or _json_bytes(record) != data):
        raise ValueError('native result canonical fields')
    fixed = {'schema_version': '1.0.0', 'profile_id': native.PROFILE_ID,
             'status': 'NATIVE_AND_STRUCTURED_SOURCE_RESULTS_BOUND',
             'native_width_profile_sha256': native.NATIVE_PROFILE_SHA256,
             'structured_source_job_profile_sha256': native.STRUCTURED_PROFILE_SHA256,
             'release_authorization': 'NOT_ESTABLISHED', **expected}
    if (any(type(record[key]) is not type(value) or record[key] != value
            for key, value in fixed.items())
            or record['inspection_dimensions'] != list(_DIMENSIONS) +
                ['native_tounicode_same_font_explicit_width_coverage']
            or any(record[key] is not True for key in
                   ('shared_input_bindings_verified', 'same_font_explicit_width_coverage_verified',
                    'normalized_text_equivalence_verified', 'forward_reverse_linkage_verified'))):
        raise ValueError('native result identity or scope')
    _native_field_types(record)
    first, second = record['native_inspection'], record['structured_inspection']
    if type(first) is not dict or type(second) is not dict:
        raise ValueError('native result child types')
    if (sha256(_json_bytes(first)).hexdigest() != record['native_inspection_sha256']
            or sha256(_json_bytes(second)).hexdigest() != record['structured_inspection_sha256']):
        raise ValueError('native result child digest')
    _native_width_record(first, expected)
    child_expected = {key: value for key, value in expected.items() if key != 'plan_sha256'}
    child_expected.update(resource_profile_sha256=RESOURCE_PROFILE_SHA256,
                          source_job_profile_sha256=SOURCE_JOB_PROFILE_SHA256)
    _record(_json_bytes(second), child_expected)
    original = second['source_inspection']
    tree = second['structure_tree']
    for child in (second, original, tree):
        for key in ('pdf_sha256', 'ir_sha256', 'page_count', 'language'):
            if type(child[key]) is not type(expected[key]) or child[key] != expected[key]:
                raise ValueError('native result structured child identity')
    plans = (first['plan_sha256'], tree['plan_sha256'],
             original['document_content']['plan_sha256'],
             original['inspection_set']['page_bundle']['text_stream']['plan_sha256'])
    if (any(value != expected['plan_sha256'] for value in plans)
            or second['expected_text_sha256'] != record['expected_text_sha256']):
        raise ValueError('native result text or independent plan mismatch')
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
        selected_native = _profile(expected_frame_profile_sha256)
        bound = _expected(expected_pdf_sha256=expected_pdf_sha256,
                          expected_ir_sha256=expected_ir_sha256,
                          expected_page_count=expected_page_count,
                          expected_language=expected_language,
                          expected_namespace_id=expected_namespace_id,
                          expected_job_id=expected_job_id,
                          expected_request_sha256=expected_request_sha256,
                          expected_resource_profile_sha256=expected_resource_profile_sha256,
                          selected_native=selected_native)
        if type(result) is not (PdfNativeSourceResult if selected_native else PdfStructuredSourceResult):
            raise ValueError('typed original result required')
        raw = result.to_bytes()
        (_native_record if selected_native else _record)(raw, bound)
        magic = NATIVE_MAGIC if selected_native else MAGIC
        frame = HEADER.pack(magic, len(raw), sha256(raw).digest()) + raw
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
        selected_native = _profile(expected_frame_profile_sha256)
        bound = _expected(expected_pdf_sha256=expected_pdf_sha256,
                          expected_ir_sha256=expected_ir_sha256,
                          expected_page_count=expected_page_count,
                          expected_language=expected_language,
                          expected_namespace_id=expected_namespace_id,
                          expected_job_id=expected_job_id,
                          expected_request_sha256=expected_request_sha256,
                          expected_resource_profile_sha256=expected_resource_profile_sha256,
                          selected_native=selected_native)
        max_result = NATIVE_MAX_RESULT_BYTES if selected_native else MAX_RESULT_BYTES
        max_frame = NATIVE_MAX_FRAME_BYTES if selected_native else MAX_FRAME_BYTES
        expected_magic = NATIVE_MAGIC if selected_native else MAGIC
        if (type(packet_bytes) is not bytes
                or not HEADER.size < len(packet_bytes) <= max_frame):
            raise ValueError('result frame envelope type')
        magic, size, digest = HEADER.unpack_from(packet_bytes)
        if (magic != expected_magic or not 0 < size <= max_result
                or HEADER.size + size != len(packet_bytes)):
            raise ValueError('result frame length')
        raw = packet_bytes[HEADER.size:]
        if sha256(raw).digest() != digest:
            raise ValueError('result frame body changed')
        (_native_record if selected_native else _record)(raw, bound)
        _profile(expected_frame_profile_sha256)
        return raw
    except Exception:
        raise PdfInspectionResultFrameError('pdf_inspection_result_frame_invalid') from None
