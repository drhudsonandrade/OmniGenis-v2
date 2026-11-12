"""Explicit source-bound technical pagination with finite same-PDF convergence.

The generated index and internal references are ordinary semantic IR content.
Locations refer to normalized source-text intervals on actual physical pages,
not visual bounding boxes. All supplied findings remain intact. Only a converged
candidate passes the existing complete native/source inspection and private store.

This opt-in successor does not activate scientific interpretation, clinical or
FINAL publication, authenticated rights/consent, accessibility, visual semantics,
aggregate whole-job resources, checkpoint resume or crash durability. Its parent
elapsed acceptance interval does not preempt Python work or storage syscalls.
Recovery requires independently trusted complete-result and PDF expectations;
stored observations are not independently authenticated historical execution.
"""
from __future__ import annotations

from bisect import bisect_right
from copy import deepcopy
from hashlib import sha256
import os
from pathlib import Path
import stat
import sys
import tempfile
import time

from reporting import _pdf_final_locations_worker as locations
from reporting import _pdf_job_durable_receipt as receipts
from reporting import pdf_bound_raster_candidate as previous
from reporting import pdf_candidate_store as storage
from reporting import pdf_generated_source_job as generated
from reporting import pdf_native_source_job as native
from reporting import pdf_object_graph as graph
from reporting import pdf_raster_render as raster
from reporting import pdf_raster_resources as resource_module
from reporting.requests import BoundReportRequest

PROFILE_ID = 'source-bound-final-document-candidate-v1'
PARENT_PROFILE_SHA256 = '1e9f841f6303920c5142c7f6abf4a5990a518dc8970a7a2060483c511af97b67'
MAX_LAYOUT_PASSES = 4
MAX_FINDINGS = 128
MAX_COMPONENTS = 9
ACCEPTANCE_NS = 600 * 1000 * 1000 * 1000
INDEX_ID = 'technical-document-index'
FINDINGS_ID = 'verified-source-interpretations'
ITEM_KEY = 'canonical_interpretation.items'
_DISABLE = 'OMNIGENIS_PDF_FINAL_DOCUMENT_DISABLED'
_NONCLAIMS = {
    'release_authorized': False, 'supported_execution': False,
    'upstream_authorization_validated': False, 'resource_rights_authenticated': False,
    'resource_source_authenticated': False, 'aggregate_job_resources_qualified': False,
    'default_pipeline_activated': False, 'visual_semantics_verified': False,
    'accessibility_qualified': False, 'persistent_recovery_qualified': False,
}


class PdfFinalDocumentError(ValueError):
    """A fixed content-free refusal with no partial candidate or location evidence."""


def _require(condition: bool) -> None:
    """Reject an unestablished invariant without echoing private input."""
    if not condition:
        raise ValueError('final document invariant unverified')


def _hash(value: object) -> str:
    """Bind the complete canonical value, including an explicitly unresolved map."""
    return sha256(generated._json_bytes(value)).hexdigest()


def _location_limits() -> dict:
    """Retain the existing confined parser's finite operating-system limits."""
    return {'memory_bytes': locations.MEMORY_BYTES, 'cpu_seconds': locations.CPU_SECONDS,
            'file_bytes': locations.RESULT_BYTES, 'open_files': locations.OPEN_FILES}


def final_document_profile() -> dict:
    """Declare a separate finite composition without changing inherited profiles."""
    return {'schema_version': '1.0.0', 'profile_id': PROFILE_ID,
        'parent_candidate_profile_sha256': PARENT_PROFILE_SHA256,
        'render_profile_sha256': previous.RENDER_PROFILE_SHA256,
        'native_profile_sha256': previous.NATIVE_PROFILE_SHA256,
        'locale_id': 'en-US', 'max_layout_passes': MAX_LAYOUT_PASSES,
        'max_findings': MAX_FINDINGS, 'max_components': MAX_COMPONENTS,
        'max_pages': 64, 'max_pdf_bytes': storage.MAX_PDF_BYTES,
        'max_manifest_bytes': storage.MAX_MANIFEST_BYTES,
        'acceptance_deadline_ns': ACCEPTANCE_NS, 'hard_job_deadline_enforced': False,
        'convergence': 'COMPLETE_PHYSICAL_PAGE_MAP_EQUALS_PRINTED_INPUT_MAP',
        'page_location_semantics': 'NORMALIZED_SOURCE_UTF8_INTERVALS',
        'normalization': 'IGNORE_CR_LF_FORM_FEED_ONLY',
        'index_component_id': INDEX_ID, 'retries': 0, 'orchestration_attempts': 1,
        'active_pdf_actions_enabled': False,
        'location_worker': {'profile_id': locations.PROFILE_ID,
            'policy_id': locations.POLICY_ID, 'parser_version': locations.PARSER_VERSION,
            'protocol_version': locations.PROTOCOL_VERSION, 'limits': _location_limits(),
            'wall_seconds': locations.WALL_SECONDS,
            'max_decoded_bytes': locations.MAX_DECODED_BYTES,
            'max_text_chars': locations.MAX_TEXT_CHARS,
            'max_pages': locations.MAX_DOCUMENT_PAGES,
            'max_pdf_bytes': locations.MAX_PDF_BYTES,
            'partition_framing': 'ASCII_PAGE_NUMBER_COLON_BYTE_LENGTH_COLON_UTF8'},
        **_NONCLAIMS}


PROFILE_SHA256 = '1af6e60d9409bd9c8fb635a01b05e7d60715340f6f421332b3137f841c010dc7'
STORAGE_SCHEMA = 'source-bound-final-document-private-store/v1'
STORAGE_PROFILE_ID = 'source-bound-final-document-private-store-v1'


def final_document_storage_profile() -> dict:
    """Pin a single claimed orchestration and exact private recovery, not publication."""
    return {'schema_version': '1.0.0', 'profile_id': STORAGE_PROFILE_ID,
        'candidate_profile_sha256': PROFILE_SHA256, 'orchestration_attempts': 1,
        'max_layout_passes': MAX_LAYOUT_PASSES, 'retries': 0,
        'max_pdf_bytes': storage.MAX_PDF_BYTES, 'max_manifest_bytes': storage.MAX_MANIFEST_BYTES,
        'receipt_schema': receipts.SCHEMA,
        'recovery_mode': 'EXPLICIT_EXACT_CURRENT_PRIVATE_BUNDLE',
        'storage_deadline_enforced': False, 'power_loss_durability_qualified': False,
        **_NONCLAIMS}


STORAGE_PROFILE_SHA256 = '42ade56489d026cd3b87581115dae6da19efb26d6fd0a0a77c6d8748f028b767'


def _profile(expected: str) -> None:
    """Require explicit activation and unchanged current source/render/native policies."""
    resource_module._digest(expected)
    _require(expected == PROFILE_SHA256 and _hash(final_document_profile()) == PROFILE_SHA256
             and os.environ.get(_DISABLE) != '1')
    previous._profile(PARENT_PROFILE_SHA256)


def _storage_profile(expected: str) -> None:
    """Validate the successor storage identity and the complete opt-in chain."""
    resource_module._digest(expected)
    _require(expected == STORAGE_PROFILE_SHA256
             and _hash(final_document_storage_profile()) == STORAGE_PROFILE_SHA256)
    _profile(PROFILE_SHA256)


def _inputs(*, bound_request: BoundReportRequest, resources: resource_module.RasterBundle,
            expected_request_sha256: str, expected_resources_sha256: str,
            expected_resource_profile_sha256: str) -> tuple[dict, dict]:
    """Reuse the validated original source and resource projection without changing it."""
    _profile(expected_resource_profile_sha256)
    ir, _, source = previous._prepare(bound_request=bound_request, resources=resources,
        expected_request_sha256=expected_request_sha256,
        expected_resources_sha256=expected_resources_sha256,
        expected_resource_profile_sha256=PARENT_PROFILE_SHA256)
    _require(source['finding_count'] <= MAX_FINDINGS
             and len(ir['components']) < MAX_COMPONENTS
             and INDEX_ID not in [c['component_id'] for c in ir['components']])
    return ir, source


def _prepared_bytes(**arguments) -> bytes:
    """Snapshot complete original IR and bindings for later equality checks."""
    ir, source = _inputs(**arguments)
    return generated._json_bytes({'original_ir': ir, 'source_projection': source})


def _finding_ids(ir: dict) -> list[str]:
    """Read only the original typed finding section, never an index appearance."""
    sections = [c for c in ir['components'] if c['component_id'] == FINDINGS_ID]
    _require(len(sections) == 1 and set(sections[0]['content']) == {ITEM_KEY})
    items = sections[0]['content'][ITEM_KEY]
    _require(type(items) is list and len(items) <= MAX_FINDINGS)
    ids = [item['canonical_variant_id'] for item in items]
    _require(all(type(value) is str and value for value in ids) and len(ids) == len(set(ids)))
    return ids


def _map_grammar(page_map: dict, original_ir: dict) -> None:
    """Require exactly the known ordered targets and native physical page ranges."""
    _require(type(page_map) is dict and set(page_map) == {'page_count', 'sections', 'findings'})
    count = page_map['page_count']
    _require(type(count) is int and 1 <= count <= 64)
    sections, findings = page_map['sections'], page_map['findings']
    _require(type(sections) is list and type(findings) is list
        and all(type(v) is dict for v in sections + findings)
        and [v.get('component_id') for v in sections] ==
            [INDEX_ID] + [c['component_id'] for c in original_ir['components']]
        and [v.get('finding_id') for v in findings] == _finding_ids(original_ir))
    for record in sections + findings:
        keys = {'component_id', 'first_page', 'last_page'}
        if record in findings:
            keys.add('finding_id')
            _require(record['component_id'] == FINDINGS_ID)
        _require(set(record) == keys
            and type(record['first_page']) is int and type(record['last_page']) is int
            and 1 <= record['first_page'] <= record['last_page'] <= count)


def _compose(original_ir: dict, resources: resource_module.RasterBundle,
             page_map: dict | None) -> tuple[dict, str, dict]:
    """Put passive page references into actual IR before compiling fixed HTML."""
    ids = _finding_ids(original_ir)
    if page_map is not None:
        _map_grammar(page_map, original_ir)
    sections = []
    for position, component in enumerate(original_ir['components'], 1):
        found = page_map['sections'][position] if page_map is not None else None
        sections.append({'component_id': component['component_id'], 'title': component['title'],
            'first_page': found['first_page'] if found else None,
            'last_page': found['last_page'] if found else None})
    findings = []
    for position, identity in enumerate(ids):
        found = page_map['findings'][position] if page_map is not None else None
        findings.append({'finding_id': identity,
            'first_page': found['first_page'] if found else None,
            'last_page': found['last_page'] if found else None})
    index = {'component_id': INDEX_ID, 'component_type': 'semantic-section',
        'title': 'Document index and internal references', 'state': 'PRESENT',
        'content': {'purpose': 'Internal page references for this technical candidate.',
            'page_count': page_map['page_count'] if page_map is not None else None,
            'sections': sections, 'findings': findings}}
    ir = deepcopy(original_ir); ir['components'].insert(0, index)
    ir = generated._capture_adapter_ir(ir)
    _require(len(ir['components']) <= MAX_COMPONENTS and generated._validate_ir(ir)
             and ir['components'][1:] == original_ir['components'])
    html, identifiers = previous._bounded_semantic_html(ir)
    _require(identifiers == [c['component_id'] for c in ir['components']])
    for position, asset in enumerate(resources.assets, 1):
        marker = '<section data-component="qualification-raster-' + str(position) + '">'
        _require(html.count(marker) == 1)
        style = ('break-before:page;min-height:750px;background-repeat:no-repeat;'
                 'background-position:center bottom;background-size:512px 512px;'
                 "background-image:url('" + asset.uri + "')")
        html = html.replace(marker, marker[:-1] + ' style="' + style + '">')
    raw = html.encode('utf-8')
    _require(0 < len(raw) <= raster.worker.HTML_BYTES)
    ir_sha, text_sha = generated._expected_content(ir)
    return ir, html, {'ir_sha256': ir_sha, 'expected_text_sha256': text_sha,
        'html_sha256': sha256(raw).hexdigest(), 'index_sha256': _hash(index)}


def prepare_final_document_candidate(*, bound_request: BoundReportRequest,
        resources: resource_module.RasterBundle, expected_request_sha256: str,
        expected_resources_sha256: str, expected_resource_profile_sha256: str
) -> tuple[dict, str, dict]:
    """Return detached initial content with explicitly unresolved page references."""
    try:
        original, source = _inputs(bound_request=bound_request, resources=resources,
            expected_request_sha256=expected_request_sha256,
            expected_resources_sha256=expected_resources_sha256,
            expected_resource_profile_sha256=expected_resource_profile_sha256)
        ir, html, composition = _compose(original, resources, None)
        return ir, html, {'schema': PROFILE_ID, 'profile_sha256': PROFILE_SHA256,
            'source_projection': source, 'composition': composition,
            'page_numbers_resolved': False, **_NONCLAIMS}
    except Exception:
        raise PdfFinalDocumentError('pdf_final_document_input_invalid') from None


def _stream_and_spans(ir: dict) -> tuple[bytes, dict]:
    """Serialize exact source intervals without ambiguous searches for repeated values."""
    _, expected = generated._expected_content(ir)
    stream = bytearray(locations.normalize_stream(ir['report_id']).encode('utf-8'))
    sections = []; findings = []
    for component in ir['components']:
        start = len(stream)
        for key in ('title', 'state'):
            stream.extend(locations.normalize_stream(component[key]).encode('utf-8'))
        content_start = len(stream)
        payload = generated._json_bytes(component['content'])
        if component['component_id'] == FINDINGS_ID:
            _require(set(component['content']) == {ITEM_KEY})
            assembled = bytearray(b'{' + generated._json_bytes(ITEM_KEY) + b':[')
            for position, item in enumerate(component['content'][ITEM_KEY]):
                if position:
                    assembled.extend(b',')
                begin = content_start + len(assembled)
                assembled.extend(generated._json_bytes(item))
                findings.append({'finding_id': item['canonical_variant_id'],
                    'component_id': FINDINGS_ID, 'start': begin,
                    'end': content_start + len(assembled)})
            assembled.extend(b']}')
            _require(bytes(assembled) == payload)
        stream.extend(payload)
        sections.append({'component_id': component['component_id'], 'start': start, 'end': len(stream)})
    raw = bytes(stream)
    _require(sha256(raw).hexdigest() == expected
             and [v['finding_id'] for v in findings] == _finding_ids(ir))
    return raw, {'sections': sections, 'findings': findings}


def _location_counts(found: dict, pages: int) -> None:
    """Reject incomplete partitions, nonnative counts and out-of-class receipts."""
    keys = {'status', 'inspected_pages', 'decoded_bytes', 'text_chars', 'text_bytes',
            'text_sha256', 'page_byte_lengths', 'page_partition_sha256'}
    _require(type(found) is dict and set(found) == keys and found['status'] == locations.STATUS)
    _require(type(pages) is int and 1 <= pages <= locations.MAX_DOCUMENT_PAGES)
    for key in ('inspected_pages', 'decoded_bytes', 'text_chars', 'text_bytes'):
        _require(type(found[key]) is int)
    _require(found['inspected_pages'] == pages
        and 0 < found['decoded_bytes'] <= locations.MAX_DECODED_BYTES
        and pages <= found['text_chars'] <= locations.MAX_TEXT_CHARS
        and pages <= found['text_bytes'] <= 4 * found['text_chars'])
    lengths = found['page_byte_lengths']
    _require(type(lengths) is list and len(lengths) == pages
        and all(type(v) is int and 0 < v <= found['text_bytes'] for v in lengths)
        and sum(lengths) == found['text_bytes'])
    for key in ('text_sha256', 'page_partition_sha256'):
        resource_module._digest(found[key])


def _decode_locations(raw: bytes, identity: dict) -> dict:
    """Validate one closed canonical response before using any location counts."""
    locations._identity(identity)
    _require(type(raw) is bytes and 0 < len(raw) <= locations.RESULT_BYTES)
    record = storage._decode(raw)
    _require(set(record) == {'protocol_version', 'profile_id', 'policy_id', 'parser_version',
                            'identity', 'limits', 'inspection'}
        and type(record['protocol_version']) is int
        and record['protocol_version'] == locations.PROTOCOL_VERSION
        and record['profile_id'] == locations.PROFILE_ID
        and record['policy_id'] == locations.POLICY_ID
        and record['parser_version'] == locations.PARSER_VERSION)
    locations._identity(record['identity'])
    _require(record['identity'] == identity and type(record['limits']) is dict
        and set(record['limits']) == set(_location_limits())
        and all(type(v) is int for v in record['limits'].values())
        and record['limits'] == _location_limits())
    _location_counts(record['inspection'], identity['page_count'])
    return record


def _run_locations(pdf: bytes, identity: dict, *,
                   observe_processes: bool = False) -> bytes | tuple[bytes, dict]:
    """Launch one fixed confined stage outside the unchanged native job schedule."""
    _require(type(observe_processes) is bool)
    generated.require_no_active_scope()
    locations._identity(identity)
    _require(type(pdf) is bytes and 0 < len(pdf) <= locations.MAX_PDF_BYTES
             and sha256(pdf).hexdigest() == identity['pdf_sha256'])
    if observe_processes:
        from reporting import _pdf_final_document_observation as observation
    with tempfile.TemporaryFile() as request, tempfile.TemporaryFile() as response:
        fds = request.fileno(), response.fileno()
        infos = [os.fstat(fd) for fd in fds]
        _require(all(stat.S_ISREG(s.st_mode) and s.st_nlink == 0 and s.st_uid == os.geteuid()
                     for s in infos)
            and (infos[0].st_dev, infos[0].st_ino) != (infos[1].st_dev, infos[1].st_ino)
            and infos[1].st_size == 0)
        header = ' '.join([str(locations.PROTOCOL_VERSION),
                           *(str(identity[k]) for k in locations.IDENTITY_FIELDS)])
        request.write(header.encode('ascii') + b'\n'); request.write(pdf); request.flush()
        worker = Path(__file__).resolve().with_name('_pdf_final_locations_worker.py')
        command = [sys.executable, '-I', '-B', str(worker),
                   str(fds[0]), str(fds[1]), str(os.getpid())]
        process = graph._start(command, fds)
        observed = None
        if observe_processes:
            observed = observation.capture_spawn(process, command, 'locations')
        code = graph._wait(process)
        if observe_processes:
            observed = observation.observe_exit(process, observed, code)
        _require(code == 0 and 0 < os.fstat(response.fileno()).st_size <= locations.RESULT_BYTES)
        response.seek(0)
        raw = response.read(locations.RESULT_BYTES + 1)
        if observe_processes:
            observed = observation.locations_record(observed, identity, _decode_locations(raw, identity))
            return raw, observed
        return raw


def _resolve_locations(ir: dict, found: dict, pages: int) -> dict:
    """Match the complete ordered page partition and resolve exact source intervals."""
    _location_counts(found, pages)
    stream, spans = _stream_and_spans(ir)
    _require(len(stream) == found['text_bytes'] and sha256(stream).hexdigest() == found['text_sha256'])
    partition = sha256(); ends = []; position = 0
    for number, size in enumerate(found['page_byte_lengths'], 1):
        part = stream[position:position + size]
        part.decode('utf-8')
        _require(len(part) == size)
        partition.update(f'{number}:{size}:'.encode('ascii')); partition.update(part)
        position += size; ends.append(position)
    _require(position == len(stream) and partition.hexdigest() == found['page_partition_sha256'])
    result = {'page_count': pages, 'sections': [], 'findings': []}
    for kind in ('sections', 'findings'):
        for span in spans[kind]:
            _require(0 <= span['start'] < span['end'] <= len(stream))
            result[kind].append({k: v for k, v in span.items() if k not in ('start', 'end')} | {
                'first_page': bisect_right(ends, span['start']) + 1,
                'last_page': bisect_right(ends, span['end'] - 1) + 1})
    return result


def _render_record(record: dict, composition: dict, source: dict, pdf: bytes | None = None) -> None:
    """Require exact current render metadata, with actual bytes for the returned PDF."""
    _require(type(record) is dict)
    pages, size = record.get('page_count'), record.get('pdf_bytes')
    _require(type(pages) is int and 1 <= pages <= 64
             and type(size) is int and 0 < size <= storage.MAX_PDF_BYTES)
    resource_module._digest(record.get('pdf_sha256'))
    expected = {'profile_id': raster.PROFILE_ID, 'profile_sha256': previous.RENDER_PROFILE_SHA256,
        'html_sha256': composition['html_sha256'], 'resources_sha256': source['resources_sha256'],
        'pdf_sha256': record['pdf_sha256'], 'pdf_bytes': size, 'page_count': pages,
        'resource_count': source['resource_count'], 'qualification_only': True,
        'release_authorized': False, 'aggregate_job_resources_qualified': False,
        'content_equivalence_verified': False, 'visual_semantics_verified': False,
        'accessibility_qualified': False}
    _require(generated._json_bytes(record) == generated._json_bytes(expected))
    if pdf is not None:
        candidate = raster.RasterPdfCandidate(pdf, composition['html_sha256'],
            source['resources_sha256'], pages, source['resource_count'])
        _require(generated._json_bytes(candidate.to_dict()) == generated._json_bytes(record))


def _location_identity(render: dict, composition: dict, source: dict, number: int) -> dict:
    """Bind the fixed location operation to its actual pass, request and artifact."""
    plan = {'profile_sha256': PROFILE_SHA256, 'pass_number': number,
        'request_sha256': source['request_sha256'], 'resources_sha256': source['resources_sha256'],
        'ir_sha256': composition['ir_sha256'], 'html_sha256': composition['html_sha256'],
        'pdf_sha256': render['pdf_sha256'], 'page_count': render['page_count']}
    return {'pdf_sha256': render['pdf_sha256'], 'ir_sha256': composition['ir_sha256'],
            'plan_sha256': _hash(plan), 'page_count': render['page_count']}


def _layout_record(passes: list, page_map: dict) -> dict:
    """Record only completed observations; no missing pass is manufactured."""
    return {'schema': 'final-document-layout-proof/v1', 'max_passes': MAX_LAYOUT_PASSES,
        'pass_count': len(passes), 'render_invocations': len(passes),
        'location_invocations': len(passes), 'native_inspection_invocations': 1,
        'passes': deepcopy(passes), 'final_page_map': deepcopy(page_map), 'converged': True}


def _binding(source: dict, composition: dict, render: dict,
             native_raw: bytes, layout: dict) -> dict:
    """Bind all final document evidence while retaining release/resource nonclaims."""
    return {'schema': PROFILE_ID, 'profile_sha256': PROFILE_SHA256,
        'source_projection': deepcopy(source), 'composition': deepcopy(composition),
        'pdf_sha256': render['pdf_sha256'], 'pdf_bytes': render['pdf_bytes'],
        'page_count': render['page_count'], 'finding_count': source['finding_count'],
        'render_result_sha256': _hash(render), 'native_inspection_sha256': sha256(native_raw).hexdigest(),
        'layout': deepcopy(layout), 'page_numbers_resolved': True,
        'completed_reporting_steps': ['BOUND_SOURCE_PROJECTION', 'FINITE_PRINTED_PAGE_CONVERGENCE',
                                      'SAME_ARTIFACT_NATIVE_INSPECTION'], **_NONCLAIMS}


def _native_record(record: dict, render: dict, composition: dict, source: dict) -> bytes:
    """Check complete final context; generation additionally requires the native seal."""
    _require(type(record) is dict)
    identity = {'schema_version': '1.0.0', 'profile_id': native.PROFILE_ID,
        'status': 'NATIVE_AND_STRUCTURED_SOURCE_RESULTS_BOUND',
        'pdf_sha256': render['pdf_sha256'], 'ir_sha256': composition['ir_sha256'],
        'page_count': render['page_count'], 'namespace_id': source['namespace_id'],
        'job_id': source['job_id'], 'request_sha256': source['request_sha256'],
        'resource_profile_sha256': previous.NATIVE_PROFILE_SHA256, 'language': 'en-US',
        'expected_text_sha256': composition['expected_text_sha256'],
        'normalized_text_equivalence_verified': True,
        'release_authorization': 'NOT_ESTABLISHED', **native._nonclaims()}
    keys = set(identity) | {'plan_sha256', 'native_width_profile_sha256',
        'structured_source_job_profile_sha256', 'native_inspection_sha256',
        'structured_inspection_sha256', 'native_inspection', 'structured_inspection',
        'inspection_dimensions', 'shared_input_bindings_verified',
        'same_font_explicit_width_coverage_verified', 'forward_reverse_linkage_verified'}
    _require(set(record) == keys and all(type(record.get(k)) is type(v) and record[k] == v
                                       for k, v in identity.items()))
    raw = generated._json_bytes(record)
    _require(0 < len(raw) <= native.MAX_RESULT_BYTES)
    return raw


def _execute_final_document_candidate(*, bound_request: BoundReportRequest,
        resources: resource_module.RasterBundle, expected_request_sha256: str,
        expected_resources_sha256: str, expected_resource_profile_sha256: str,
        observe_processes: bool
) -> tuple[raster.RasterPdfCandidate, native.PdfNativeSourceResult, dict, dict | None]:
    """Converge within four passes, then inspect and return only the final exact pair."""
    arguments = dict(bound_request=bound_request, resources=resources,
        expected_request_sha256=expected_request_sha256,
        expected_resources_sha256=expected_resources_sha256,
        expected_resource_profile_sha256=expected_resource_profile_sha256)
    try:
        _require(type(observe_processes) is bool)
        prepared = _prepared_bytes(**arguments); source_data = storage._decode(prepared)
        original, source = source_data['original_ir'], source_data['source_projection']
        started = previous_time = time.monotonic_ns()
        _require(type(started) is int and started >= 0)
    except Exception:
        raise PdfFinalDocumentError('pdf_final_document_input_invalid') from None

    def check() -> None:
        """Refuse persistent source/policy drift and late acceptance between stages."""
        nonlocal previous_time
        _require(_prepared_bytes(**arguments) == prepared)
        now = time.monotonic_ns()
        _require(type(now) is int and now >= previous_time and now - started < ACCEPTANCE_NS)
        previous_time = now

    try:
        page_map = None; passes = []; process_rows = []
        for number in range(1, MAX_LAYOUT_PASSES + 1):
            check()
            ir, html, composition = _compose(original, resources, page_map)
            ir_raw = generated._json_bytes(ir)
            render_arguments = dict(html=html, expected_html_sha256=composition['html_sha256'],
                                    resources=resources, expected_resources_sha256=expected_resources_sha256)
            if observe_processes:
                rendered, render_observation = raster.render_observed_preloaded_raster_pdf(**render_arguments)
            else:
                rendered = raster.render_preloaded_raster_pdf(**render_arguments)
            check(); _require(type(rendered) is raster.RasterPdfCandidate)
            pdf = rendered.pdf_bytes; render = rendered.to_dict(); render_raw = generated._json_bytes(render)
            _render_record(render, composition, source, pdf)
            identity = _location_identity(render, composition, source, number)
            if observe_processes:
                location_raw, location_observation = _run_locations(pdf, identity, observe_processes=True)
                process_rows.append({'pass_number':number,'render':render_observation,
                                     'locations':location_observation})
            else:
                location_raw = _run_locations(pdf, identity)
            receipt = _decode_locations(location_raw, identity)
            check()
            measured = _resolve_locations(ir, receipt['inspection'], rendered.page_count)
            _map_grammar(measured, original)
            converged = page_map is not None and measured == page_map
            passes.append({'pass_number': number, 'input_page_map_sha256': _hash(page_map),
                'composition': deepcopy(composition), 'render_result': deepcopy(render),
                'location_receipt': deepcopy(receipt), 'output_page_map_sha256': _hash(measured),
                'converged': converged})
            _require(generated._json_bytes(ir) == ir_raw and rendered.pdf_bytes == pdf
                     and generated._json_bytes(rendered.to_dict()) == render_raw)
            page_map = measured
            if converged:
                break
        _require(converged)
        check()
        inspect = (native.execute_raster_observed_pdf_native_source_job if observe_processes
                   else native.execute_pdf_native_source_job)
        inspected = inspect(presentation_ir=ir, pdf_bytes=pdf,
            expected_pdf_sha256=render['pdf_sha256'], expected_ir_sha256=composition['ir_sha256'],
            page_count=rendered.page_count, expected_language='en-US',
            namespace_id=source['namespace_id'], job_id=source['job_id'],
            request_sha256=expected_request_sha256,
            expected_resource_profile_sha256=previous.NATIVE_PROFILE_SHA256)
        native_observation = None
        if observe_processes:
            _require(type(inspected) is tuple and len(inspected) == 2)
            inspected, native_observation = inspected
            from reporting._pdf_raster_job_observation import validate_native
            native_observation = validate_native(inspected, native_observation)
        check(); _require(type(inspected) is native.PdfNativeSourceResult)
        native_raw = inspected.to_bytes()
        _require(_native_record(inspected.to_dict(), render, composition, source) == native_raw)
        binding = _binding(source, composition, render, native_raw, _layout_record(passes, page_map))
        _require(generated._json_bytes(ir) == ir_raw and rendered.pdf_bytes == pdf
                 and generated._json_bytes(rendered.to_dict()) == render_raw
                 and inspected.to_bytes() == native_raw)
        check()
        observation = ({'layout_processes':process_rows,'native_observation':native_observation}
                       if observe_processes else None)
        return rendered, inspected, binding, observation
    except Exception:
        raise PdfFinalDocumentError('pdf_final_document_execution_unverified') from None


def execute_final_document_candidate(*, bound_request: BoundReportRequest,
        resources: resource_module.RasterBundle, expected_request_sha256: str,
        expected_resources_sha256: str, expected_resource_profile_sha256: str
) -> tuple[raster.RasterPdfCandidate, native.PdfNativeSourceResult, dict]:
    """Preserve the original result-only convergence and native inspection contract."""
    rendered, inspected, binding, _ = _execute_final_document_candidate(bound_request=bound_request,
        resources=resources, expected_request_sha256=expected_request_sha256,
        expected_resources_sha256=expected_resources_sha256,
        expected_resource_profile_sha256=expected_resource_profile_sha256, observe_processes=False)
    return rendered, inspected, binding


def _checked_layout(layout: dict, original: dict, source: dict,
                    resources: resource_module.RasterBundle, pdf: bytes) -> tuple[dict, dict]:
    """Validate accepted observation structure without rerendering historical PDFs."""
    keys = {'schema', 'max_passes', 'pass_count', 'render_invocations', 'location_invocations',
            'native_inspection_invocations', 'passes', 'final_page_map', 'converged'}
    _require(type(layout) is dict and set(layout) == keys and type(layout['passes']) is list)
    passes = layout['passes']; _require(2 <= len(passes) <= MAX_LAYOUT_PASSES)
    page_map = None
    for number, record in enumerate(passes, 1):
        _require(type(record) is dict and set(record) == {'pass_number', 'input_page_map_sha256',
            'composition', 'render_result', 'location_receipt', 'output_page_map_sha256', 'converged'})
        ir, _, composition = _compose(original, resources, page_map)
        render = record['render_result']
        _render_record(render, composition, source, pdf if number == len(passes) else None)
        identity = _location_identity(render, composition, source, number)
        receipt = _decode_locations(generated._json_bytes(record['location_receipt']), identity)
        measured = _resolve_locations(ir, receipt['inspection'], render['page_count'])
        _map_grammar(measured, original)
        converged = page_map is not None and page_map == measured
        expected = {'pass_number': number, 'input_page_map_sha256': _hash(page_map),
            'composition': composition, 'render_result': render, 'location_receipt': receipt,
            'output_page_map_sha256': _hash(measured), 'converged': converged}
        _require(generated._json_bytes(record) == generated._json_bytes(expected)
                 and converged == (number == len(passes)))
        page_map = measured
    _require(generated._json_bytes(layout) == generated._json_bytes(_layout_record(passes, page_map)))
    return composition, render


def _stored_manifest(result: dict, pdf: bytes, run_id: str, prepared: bytes,
                     resources: resource_module.RasterBundle,
                     result_sha256: str, pdf_sha256: str) -> dict:
    """Bind the complete new composition and exact bytes to independent expectations."""
    for digest in (result_sha256, pdf_sha256):
        resource_module._digest(digest)
    _require(type(pdf) is bytes and 0 < len(pdf) <= storage.MAX_PDF_BYTES
        and sha256(pdf).hexdigest() == pdf_sha256 and type(result) is dict
        and set(result) == {'render_result', 'native_inspection', 'binding'}
        and type(result['binding']) is dict)
    result_raw = generated._json_bytes(result)
    _require(len(result_raw) <= storage.MAX_MANIFEST_BYTES and sha256(result_raw).hexdigest() == result_sha256)
    inputs = storage._decode(prepared); source = inputs['source_projection']
    layout = result['binding'].get('layout')
    composition, render = _checked_layout(layout, inputs['original_ir'], source, resources, pdf)
    _require(generated._json_bytes(render) == generated._json_bytes(result['render_result']))
    native_raw = _native_record(result['native_inspection'], render, composition, source)
    _require(generated._json_bytes(result['binding']) ==
             generated._json_bytes(_binding(source, composition, render, native_raw, layout)))
    manifest = {'schema': STORAGE_SCHEMA, 'state': 'STORED_PRIVATE_CANDIDATE', 'run_id': run_id,
        'storage_profile_sha256': STORAGE_PROFILE_SHA256, 'result_sha256': result_sha256,
        'pdf_sha256': pdf_sha256, 'pdf_bytes': len(pdf), 'page_count': render['page_count'],
        'result': result, 'release_authorized': False, 'supported_execution': False,
        'default_pipeline_activated': False}
    _require(len(generated._json_bytes(manifest)) <= storage.MAX_MANIFEST_BYTES)
    return manifest


def _storage_admit(arguments: dict, directory: Path, run_id: str, profile: str) -> bytes:
    """Validate the independent source and private root before claiming an attempt."""
    _storage_profile(profile); _require(isinstance(directory, Path))
    receipts._receipt_bytes(run_id, 'FAILED', None)
    prepared = _prepared_bytes(**arguments)
    fd = receipts._open_private_directory(directory)
    try:
        receipts._private_directory_identity(fd)
    finally:
        os.close(fd)
    return prepared


def _storage_unchanged(arguments: dict, prepared: bytes, profile: str) -> None:
    """Keep current source/resource/profile expectations fixed through every handoff."""
    _storage_profile(profile)
    _require(_prepared_bytes(**arguments) == prepared)


def _read_stored(arguments: dict, directory: Path, run_id: str, prepared: bytes,
                 result_sha256: str, pdf_sha256: str, profile: str) -> tuple[bytes, dict]:
    """Recover one closed bundle without native work, writes or new execution claims."""
    with previous.bound_source.qualification._run_directory(directory, run_id, create=False) as (run, check):
        fd = receipts._open_private_directory(run)
        try:
            identity = receipts._private_directory_identity(fd)
            names = storage._DATA_NAMES | {run_id + '.json'}
            _require(set(os.listdir(fd)) == names)
            identities = storage._bundle_identities(fd, run_id)
            receipt = receipts.read_job_receipt(run, run_id, 'SUCCEEDED', result_sha256)
            raw = storage._read_data(fd, 'manifest.json', storage.MAX_MANIFEST_BYTES)
            pdf = storage._read_data(fd, 'candidate.pdf', storage.MAX_PDF_BYTES)
            stored = storage._decode(raw)
            manifest = _stored_manifest(stored.get('result'), pdf, run_id, prepared,
                arguments['resources'], result_sha256, pdf_sha256)
            _require(generated._json_bytes(manifest) == raw
                and storage._read_data(fd, 'manifest.json', storage.MAX_MANIFEST_BYTES) == raw
                and storage._read_data(fd, 'candidate.pdf', storage.MAX_PDF_BYTES) == pdf
                and receipts.read_job_receipt(run, run_id, 'SUCCEEDED', result_sha256) == receipt
                and set(os.listdir(fd)) == names and storage._bundle_identities(fd, run_id) == identities
                and receipts._private_directory_identity(fd) == identity)
            _storage_unchanged(arguments, prepared, profile)
            _require(set(os.listdir(fd)) == names and storage._bundle_identities(fd, run_id) == identities
                and receipts._private_directory_identity(fd) == identity)
            check()
            return pdf, manifest
        finally:
            os.close(fd)


def _execute_stored_final_document_candidate(*, bound_request: BoundReportRequest,
        resources: resource_module.RasterBundle, expected_request_sha256: str,
        expected_resources_sha256: str, expected_resource_profile_sha256: str,
        expected_storage_profile_sha256: str, directory: Path, run_id: str,
        observe_processes: bool
) -> tuple[bytes, dict, dict | None]:
    """Claim once before layout and commit only the converged complete private result.

    Each data/receipt handoff retains the writer's original descriptor identity.
    An incomplete attempt remains consumed; a lost successful response requires
    separate trusted output expectations for explicit recovery. No repair occurs.
    """
    arguments = dict(bound_request=bound_request, resources=resources,
        expected_request_sha256=expected_request_sha256,
        expected_resources_sha256=expected_resources_sha256,
        expected_resource_profile_sha256=expected_resource_profile_sha256)
    try:
        _require(type(observe_processes) is bool)
        if observe_processes:
            from reporting import _pdf_final_document_observation as observation
            from reporting._pdf_raster_job_observation import validate_native
            _require(callable(validate_native))
            started_ns = observation._integer(observation.monotonic_ns())
        prepared = _storage_admit(arguments, directory, run_id, expected_storage_profile_sha256)
        with previous.bound_source.qualification._run_directory(directory, run_id, create=True) as (run, check):
            fd = receipts._open_private_directory(run)
            try:
                identity = receipts._private_directory_identity(fd)
                _require(not os.listdir(fd)); check()
                execution_observation = None
                if observe_processes:
                    rendered, inspected, binding, execution_observation = _execute_final_document_candidate(
                        **arguments, observe_processes=True)
                else:
                    rendered, inspected, binding = execute_final_document_candidate(**arguments)
                _require(type(rendered) is raster.RasterPdfCandidate
                         and type(inspected) is native.PdfNativeSourceResult)
                pdf = rendered.pdf_bytes
                render_raw = generated._json_bytes(rendered.to_dict())
                native_raw = inspected.to_bytes(); binding_raw = generated._json_bytes(binding)
                result = {'render_result': storage._decode(render_raw),
                          'native_inspection': storage._decode(native_raw),
                          'binding': storage._decode(binding_raw)}
                result_sha = _hash(result); pdf_sha = sha256(pdf).hexdigest()
                manifest = _stored_manifest(result, pdf, run_id, prepared, resources, result_sha, pdf_sha)
                manifest_raw = generated._json_bytes(manifest)
                limits = {'candidate.pdf': storage.MAX_PDF_BYTES, 'manifest.json': storage.MAX_MANIFEST_BYTES,
                          run_id + '.json': receipts.MAX_RECEIPT_BYTES}
                written = {}

                def pin(name: str, original: tuple[int, ...]) -> None:
                    """Keep the writer's descriptor identity rather than adopting a replacement."""
                    _require(name in limits and name not in written
                        and storage._file_identity(os.stat(name, dir_fd=fd,
                            follow_symlinks=False), limits[name]) == original)
                    written[name] = original

                def unchanged() -> None:
                    """Recheck source, sealed outputs and all original members through return."""
                    _storage_unchanged(arguments, prepared, expected_storage_profile_sha256)
                    _require(rendered.pdf_bytes == pdf
                        and generated._json_bytes(rendered.to_dict()) == render_raw
                        and inspected.to_bytes() == native_raw
                        and generated._json_bytes(binding) == binding_raw
                        and receipts._private_directory_identity(fd) == identity
                        and set(os.listdir(fd)) == set(written)
                        and all(storage._file_identity(os.stat(name, dir_fd=fd,
                            follow_symlinks=False), limits[name]) == original
                            for name, original in written.items()))
                    check()

                unchanged()
                for name, data in (('candidate.pdf', pdf), ('manifest.json', manifest_raw)):
                    pin(name, previous._write_stored_data(fd, name, data, limits[name]))
                os.fsync(fd)
                _require(set(os.listdir(fd)) == storage._DATA_NAMES
                    and storage._read_data(fd, 'candidate.pdf', storage.MAX_PDF_BYTES) == pdf
                    and storage._read_data(fd, 'manifest.json', storage.MAX_MANIFEST_BYTES) == manifest_raw)
                unchanged()
                pin(run_id + '.json', previous._write_stored_receipt(run, run_id, 'SUCCEEDED', result_sha))
                unchanged()
                recovered_pdf, recovered_manifest = _read_stored(arguments, directory, run_id,
                    prepared, result_sha, pdf_sha, expected_storage_profile_sha256)
                _require(recovered_pdf == pdf and generated._json_bytes(recovered_manifest) == manifest_raw)
                unchanged()
                observed = None
                if observe_processes:
                    verified_ns = observation._integer(observation.monotonic_ns())
                    _require(type(execution_observation) is dict and set(execution_observation) ==
                             {'layout_processes','native_observation'})
                    observed = observation.compose_stored_observation(rendered=rendered, inspected=inspected,
                        binding=binding, **execution_observation, pdf=recovered_pdf, manifest=recovered_manifest,
                        started_ns=started_ns, verified_ns=verified_ns)
                    unchanged()
                return recovered_pdf, recovered_manifest, observed
            finally:
                os.close(fd)
    except Exception:
        raise PdfFinalDocumentError('pdf_final_document_store_execution_unverified') from None


def execute_stored_final_document_candidate(*, bound_request: BoundReportRequest,
        resources: resource_module.RasterBundle, expected_request_sha256: str,
        expected_resources_sha256: str, expected_resource_profile_sha256: str,
        expected_storage_profile_sha256: str, directory: Path, run_id: str
) -> tuple[bytes, dict]:
    """Preserve the original private pair, public execution seam and stored schema."""
    pdf, manifest, _ = _execute_stored_final_document_candidate(bound_request=bound_request,
        resources=resources, expected_request_sha256=expected_request_sha256,
        expected_resources_sha256=expected_resources_sha256,
        expected_resource_profile_sha256=expected_resource_profile_sha256,
        expected_storage_profile_sha256=expected_storage_profile_sha256,
        directory=directory, run_id=run_id, observe_processes=False)
    return pdf, manifest


def execute_observed_stored_final_document_candidate(*, bound_request: BoundReportRequest,
        resources: resource_module.RasterBundle, expected_request_sha256: str,
        expected_resources_sha256: str, expected_resource_profile_sha256: str,
        expected_storage_profile_sha256: str, directory: Path, run_id: str
) -> tuple[bytes, dict, dict]:
    """Observe all declared layout/native children through the same complete store.

    Only successful exact storage/readback returns a PDF, unchanged manifest
    and bounded unsigned sidecar. Failed optional composition returns no triple;
    already committed bytes retain the original explicit recovery contract.
    No aggregate enforcement, authenticated execution, arbitrary descendants,
    durable sidecar, supported profile or FINAL publication is established.
    """
    pdf, manifest, observed = _execute_stored_final_document_candidate(bound_request=bound_request,
        resources=resources, expected_request_sha256=expected_request_sha256,
        expected_resources_sha256=expected_resources_sha256,
        expected_resource_profile_sha256=expected_resource_profile_sha256,
        expected_storage_profile_sha256=expected_storage_profile_sha256,
        directory=directory, run_id=run_id, observe_processes=True)
    _require(type(observed) is dict)
    return pdf, manifest, observed


def read_stored_final_document_candidate(*, bound_request: BoundReportRequest,
        resources: resource_module.RasterBundle, expected_request_sha256: str,
        expected_resources_sha256: str, expected_resource_profile_sha256: str,
        expected_storage_profile_sha256: str, directory: Path, run_id: str,
        expected_result_sha256: str, expected_pdf_sha256: str
) -> tuple[bytes, dict]:
    """Read exact accepted bytes with independent source/result/PDF expectations.

    This validates present consistency of retained evidence, not authenticated
    execution history or durability. It performs no rendering, inspection, repair,
    write, retry or publication, and never selects a profile from stored data.
    """
    arguments = dict(bound_request=bound_request, resources=resources,
        expected_request_sha256=expected_request_sha256,
        expected_resources_sha256=expected_resources_sha256,
        expected_resource_profile_sha256=expected_resource_profile_sha256)
    try:
        resource_module._digest(expected_result_sha256); resource_module._digest(expected_pdf_sha256)
        prepared = _storage_admit(arguments, directory, run_id, expected_storage_profile_sha256)
        return _read_stored(arguments, directory, run_id, prepared,
            expected_result_sha256, expected_pdf_sha256, expected_storage_profile_sha256)
    except Exception:
        raise PdfFinalDocumentError('pdf_final_document_store_recovery_unverified') from None
