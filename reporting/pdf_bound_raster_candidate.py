"""Explicit request-bound raster candidates using existing confined reporting stages.

The caller provides an actual bound request and exact preloaded PNG bundle, never
HTML, CSS, a renderer callback or resource budgets. Original source components,
ordered findings and observed reporting methodology are preserved. Resources are
separate decorative qualification appendices, not additional scientific findings.

Digests establish consistency, not scientific correctness, authenticated rights,
consent or source origin. The original candidate operation does not activate the default pipeline,
a supported executor, publication or clinical interpretation. An explicit private
roundtrip below stores the complete raster/native/source binding without final
release, power-loss durability or aggregate resource qualification.
The acceptance interval is a post-admission elapsed-time check, not aggregate
resource enforcement or preemption. Hostile same-owner mutate-and-restore between
checks remains outside the boundary. No retry, fallback or PDF rewrite occurs.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from html import escape
from pathlib import Path
from secrets import token_hex
import os
import time

from reporting import adapters
from reporting import _pdf_job_durable_receipt as receipts
from reporting import pdf_candidate_store as storage
from reporting import pdf_bound_candidate as bound_source
from reporting import pdf_generated_source_job as generated
from reporting import pdf_native_source_job as native
from reporting import pdf_raster_render as raster
from reporting import pdf_raster_resources as resource_module
from reporting.requests import BoundReportRequest

PROFILE_ID = 'bound-preloaded-raster-candidate-v1'
GENERATED_PROFILE_SHA256 = '715565991ace46902d9d969071dda2f5de640a2a67ccf8f8c3460f18e22c53b3'
NATIVE_PROFILE_SHA256 = 'ff0bdfd9cbaa75651dddcf0aa72e1d72e4b5282dde15973558b4ff258e6e39da'
RENDER_PROFILE_SHA256 = '5391bdae627341ce95c351093bfc2a6dc2575e48203f9ee4bd4581c6ec1eb0de'
ACCEPTANCE_NS = 330 * 1000 * 1000 * 1000
MAX_JSON_LINE_CODEPOINTS = 60
_DISABLE = 'OMNIGENIS_PDF_BOUND_RASTER_DISABLED'
_NONCLAIMS = {
    'release_authorized': False, 'supported_execution': False,
    'upstream_authorization_validated': False, 'resource_rights_authenticated': False,
    'resource_source_authenticated': False, 'aggregate_job_resources_qualified': False,
    'default_pipeline_activated': False, 'visual_semantics_verified': False,
    'accessibility_qualified': False, 'persistent_recovery_qualified': False,
}


class PdfBoundRasterError(ValueError):
    """A fixed refusal without source text, private identities or partial candidate bytes."""


def _require(condition: bool) -> None:
    """Refuse an unestablished invariant without reflecting the rejected input."""
    if not condition:
        raise ValueError('bound raster invariant unverified')


def bound_raster_candidate_profile() -> dict:
    """Describe one finite qualification composition with no caller-selectable limits."""
    return {'schema_version': '1.0.0', 'profile_id': PROFILE_ID,
        'source_projection': 'technical-assembly-v1', 'locale_id': 'en-US',
        'generated_profile_sha256': GENERATED_PROFILE_SHA256,
        'native_profile_sha256': NATIVE_PROFILE_SHA256,
        'render_profile_sha256': RENDER_PROFILE_SHA256,
        'max_pages': 64, 'max_pdf_bytes': 16 * 1024 * 1024,
        'max_resources': 3, 'acceptance_deadline_ns': ACCEPTANCE_NS,
        'max_json_physical_line_codepoints': MAX_JSON_LINE_CODEPOINTS,
        'source_text_transformation': 'INSERT_PHYSICAL_LF_ONLY_BEFORE_HTML_ESCAPE',
        'source_sections_preserved': 5, 'resource_purpose': 'DECORATIVE_QUALIFICATION_ONLY',
        'retries': 0, 'hard_job_deadline_enforced': False, **_NONCLAIMS}


PROFILE_SHA256 = '298ae124f78eaa74976993d662e81b5ffb07996a49ab0e608e4d065056a50949'


def _profile(expected: str) -> None:
    """Recheck the exact new profile and every inherited opt-in and policy chain."""
    resource_module._digest(expected)
    _require(expected == PROFILE_SHA256
        and sha256(generated._json_bytes(bound_raster_candidate_profile())).hexdigest() == PROFILE_SHA256
        and os.environ.get(_DISABLE) != '1')
    bound_source.qualification._require_policy()
    generated._profile(GENERATED_PROFILE_SHA256)
    native._profile(NATIVE_PROFILE_SHA256)
    raster._require_policy()
    _require(raster.profile_sha256() == RENDER_PROFILE_SHA256)
    generated.require_no_active_scope()



def _bounded_semantic_html(ir: dict) -> tuple[str, list[str]]:
    """Break canonical JSON text physically without deleting any source code point.

    The native text contract ignores only CR/LF/form-feed introduced by physical
    layout. Canonical JSON escapes source control characters, so inserting LF
    between fixed code-point slices does not change any represented JSON value.
    HTML escaping is applied after slicing to avoid splitting character entities.
    The existing adapter's labels, order and semantic sections are unchanged.
    """
    html, _, identifiers = adapters._semantic_html(ir)
    pieces = html.split('<pre>')
    _require(len(pieces) == len(ir['components']) + 1)
    output = [pieces[0]]
    for component, remainder in zip(ir['components'], pieces[1:]):
        payload, separator, tail = remainder.partition('</pre>')
        original = generated._json_bytes(component['content']).decode('utf-8')
        _require(separator == '</pre>' and payload == escape(original))
        physical = '\n'.join(original[i:i + MAX_JSON_LINE_CODEPOINTS]
                             for i in range(0, len(original), MAX_JSON_LINE_CODEPOINTS))
        _require(physical.replace('\n', '') == original)
        output.extend(('<pre>', escape(physical), '</pre>', tail))
    return ''.join(output), identifiers


def _prepare(*, bound_request: BoundReportRequest, resources: resource_module.RasterBundle,
             expected_request_sha256: str, expected_resources_sha256: str,
             expected_resource_profile_sha256: str) -> tuple[dict, str, dict]:
    """Build the source-preserving projection and fixed decorative resource markup."""
    _profile(expected_resource_profile_sha256)
    for digest in (expected_request_sha256, expected_resources_sha256):
        resource_module._digest(digest)
    _require(type(bound_request) is BoundReportRequest and type(resources) is resource_module.RasterBundle)
    BoundReportRequest.__post_init__(bound_request)
    _require(bound_request.request.request_sha256 == expected_request_sha256)
    resource_bytes = resources.to_bytes()
    _require(sha256(resource_bytes).hexdigest() == expected_resources_sha256)
    original, source_binding = bound_source._prepare(bound_request, GENERATED_PROFILE_SHA256,
                                                      'technical-assembly-v1')
    ir = deepcopy(original['presentation_ir'])
    _require(len(ir['components']) == 5)
    section_inventory = []
    for i, asset in enumerate(resources.assets, 1):
        component_id = 'qualification-raster-' + str(i)
        ir['components'].append({'component_id': component_id, 'component_type': 'semantic-section',
            'title': 'Decorative qualification resource ' + str(i), 'state': 'PRESENT',
            'content': {'purpose': 'Decorative technical qualification only; no scientific interpretation.',
                        'resource': asset.metadata()}})
        section_inventory.append({'component_id': component_id, 'asset_id': asset.asset_id,
                                  'resource_sha256': asset.expected_sha256})
    ir = generated._capture_adapter_ir(ir)
    _require(generated._validate_ir(ir) and ir['components'][:5] == original['presentation_ir']['components'])
    html, component_ids = _bounded_semantic_html(ir)
    _require(component_ids == [c['component_id'] for c in ir['components']])
    for asset, section in zip(resources.assets, section_inventory):
        marker = '<section data-component="' + section['component_id'] + '">'
        _require(html.count(marker) == 1)
        style = ('break-before:page;min-height:750px;background-repeat:no-repeat;'
                 'background-position:center bottom;background-size:512px 512px;'
                 "background-image:url('" + asset.uri + "')")
        html = html.replace(marker, marker[:-1] + ' style="' + style + '">')
    encoded_html = html.encode('utf-8')
    _require(0 < len(encoded_html) <= raster.worker.HTML_BYTES)
    ir_sha256, text_sha256 = generated._expected_content(ir)
    binding = {'schema': PROFILE_ID, 'conformance_scope': 'BOUND_SOURCE_AND_DECORATIVE_CANDIDATE_ONLY',
        'request_sha256': expected_request_sha256,
        'namespace_id': original['namespace_id'], 'job_id': original['job_id'],
        'source_ir_sha256': original['expected_ir_sha256'], 'ir_sha256': ir_sha256,
        'expected_text_sha256': text_sha256, 'html_sha256': sha256(encoded_html).hexdigest(),
        'resources_sha256': expected_resources_sha256,
        'resource_profile_sha256': expected_resource_profile_sha256,
        'render_profile_sha256': RENDER_PROFILE_SHA256, 'native_profile_sha256': NATIVE_PROFILE_SHA256,
        'finding_count': source_binding['finding_count'], 'resource_count': len(resources.assets),
        'resource_sections': section_inventory, 'source_projection': deepcopy(source_binding),
        'original_source_components_preserved': True, **_NONCLAIMS}
    bound_source._unchanged(bound_request, original, source_binding, 'technical-assembly-v1')
    _require(resources.to_bytes() == resource_bytes
             and bound_request.request.request_sha256 == expected_request_sha256)
    _profile(expected_resource_profile_sha256)
    return ir, html, binding


def prepare_bound_raster_candidate(*, bound_request: BoundReportRequest,
        resources: resource_module.RasterBundle, expected_request_sha256: str,
        expected_resources_sha256: str, expected_resource_profile_sha256: str) -> tuple[dict, str, dict]:
    """Return detached private projection and metadata without generating any PDF.

    Its HTML is derived entirely from validated source data and fixed markup.
    This is not an interface for user HTML, URLs, style programs or callbacks.
    """
    try:
        return _prepare(bound_request=bound_request, resources=resources,
            expected_request_sha256=expected_request_sha256,
            expected_resources_sha256=expected_resources_sha256,
            expected_resource_profile_sha256=expected_resource_profile_sha256)
    except Exception:
        raise PdfBoundRasterError('pdf_bound_raster_input_invalid') from None


def execute_bound_raster_candidate(*, bound_request: BoundReportRequest,
        resources: resource_module.RasterBundle, expected_request_sha256: str,
        expected_resources_sha256: str, expected_resource_profile_sha256: str
) -> tuple[raster.RasterPdfCandidate, native.PdfNativeSourceResult, dict]:
    """Render once, inspect those exact bytes once and return only a fully bound pair.

    The inherited worker deadlines and sandbox remain unchanged. The outer
    330-second interval rejects late acceptance but does not preempt Python work
    or enforce whole-job resources. Persistent input changes are revalidated at
    stage boundaries. No incomplete pair, retry, storage or release is returned.
    """
    arguments = dict(bound_request=bound_request, resources=resources,
        expected_request_sha256=expected_request_sha256,
        expected_resources_sha256=expected_resources_sha256,
        expected_resource_profile_sha256=expected_resource_profile_sha256)
    try:
        ir, html, binding = _prepare(**arguments)
        projection_bytes = generated._json_bytes(ir)
        binding_bytes = generated._json_bytes(binding)
        started = previous = time.monotonic_ns()
        _require(type(started) is int and started >= 0)
    except Exception:
        raise PdfBoundRasterError('pdf_bound_raster_input_invalid') from None

    def check() -> None:
        """Rebuild the current source/resource projection and check the finite elapsed interval."""
        nonlocal previous
        current_ir, current_html, current_binding = _prepare(**arguments)
        _require(generated._json_bytes(current_ir) == projection_bytes and current_html == html
                 and generated._json_bytes(current_binding) == binding_bytes
                 and generated._json_bytes(generated._capture_adapter_ir(ir)) == projection_bytes
                 and generated._json_bytes(binding) == binding_bytes)
        now = time.monotonic_ns()
        _require(type(now) is int and now >= previous and now - started < ACCEPTANCE_NS)
        previous = now

    try:
        check()
        rendered = raster.render_preloaded_raster_pdf(html=html, expected_html_sha256=binding['html_sha256'],
            resources=resources, expected_resources_sha256=expected_resources_sha256)
        check()
        _require(type(rendered) is raster.RasterPdfCandidate)
        render_record = rendered.to_dict()
        render_bytes = generated._json_bytes(render_record)
        _require(render_record['html_sha256'] == binding['html_sha256']
            and render_record['resources_sha256'] == expected_resources_sha256
            and render_record['resource_count'] == binding['resource_count']
            and render_record['profile_sha256'] == RENDER_PROFILE_SHA256)
        pdf = rendered.pdf_bytes
        _require(sha256(pdf).hexdigest() == render_record['pdf_sha256'])
        inspected = native.execute_pdf_native_source_job(presentation_ir=ir, pdf_bytes=pdf,
            expected_pdf_sha256=render_record['pdf_sha256'], expected_ir_sha256=binding['ir_sha256'],
            page_count=rendered.page_count, expected_language='en-US', namespace_id=binding['namespace_id'],
            job_id=binding['job_id'], request_sha256=expected_request_sha256,
            expected_resource_profile_sha256=NATIVE_PROFILE_SHA256)
        check()
        _require(type(inspected) is native.PdfNativeSourceResult)
        inspection_bytes = inspected.to_bytes()
        result = inspected.to_dict()
        expected = {'pdf_sha256': render_record['pdf_sha256'], 'ir_sha256': binding['ir_sha256'],
            'page_count': rendered.page_count, 'namespace_id': binding['namespace_id'],
            'job_id': binding['job_id'], 'request_sha256': expected_request_sha256,
            'resource_profile_sha256': NATIVE_PROFILE_SHA256,
            'expected_text_sha256': binding['expected_text_sha256']}
        _require(all(result.get(key) == value for key, value in expected.items())
            and result['normalized_text_equivalence_verified'] is True
            and generated._json_bytes(rendered.to_dict()) == render_bytes
            and rendered.pdf_bytes == pdf)
        final_binding = deepcopy(binding)
        final_binding.update(pdf_sha256=render_record['pdf_sha256'], pdf_bytes=len(pdf),
            page_count=rendered.page_count, render_result_sha256=sha256(render_bytes).hexdigest(),
            native_inspection_sha256=sha256(inspection_bytes).hexdigest(),
            completed_reporting_steps=['BOUND_SOURCE_PROJECTION', 'CONFINED_RASTER_RENDER',
                                       'SAME_ARTIFACT_NATIVE_INSPECTION'])
        check()
        _require(inspected.to_bytes() == inspection_bytes and rendered.pdf_bytes == pdf
                 and generated._json_bytes(rendered.to_dict()) == render_bytes)
        return rendered, inspected, final_binding
    except Exception:
        raise PdfBoundRasterError('pdf_bound_raster_execution_unverified') from None


STORAGE_SCHEMA = 'bound-preloaded-raster-private-store/v1'
STORAGE_PROFILE_ID = 'bound-preloaded-raster-private-store-v1'


def bound_raster_storage_profile() -> dict:
    """Declare a separate private-file roundtrip without changing candidate admission."""
    return {'schema_version': '1.0.0', 'profile_id': STORAGE_PROFILE_ID,
        'candidate_profile_sha256': PROFILE_SHA256,
        'max_pdf_bytes': storage.MAX_PDF_BYTES,
        'max_manifest_bytes': storage.MAX_MANIFEST_BYTES,
        'receipt_schema': receipts.SCHEMA, 'generation_attempts': 1, 'retries': 0,
        'recovery_mode': 'EXPLICIT_EXACT_CURRENT_PRIVATE_BUNDLE',
        'storage_deadline_enforced': False, 'power_loss_durability_qualified': False,
        **_NONCLAIMS}


STORAGE_PROFILE_SHA256 = '4b485b288a1f302d76935643776a8b30e417873afbae5bc45eb4bbd28572ae68'


def _storage_profile(expected: str) -> None:
    """Require the unchanged candidate chain and the exact finite storage declaration."""
    resource_module._digest(expected)
    _require(expected == STORAGE_PROFILE_SHA256
        and sha256(generated._json_bytes(bound_raster_storage_profile())).hexdigest()
            == STORAGE_PROFILE_SHA256)
    _profile(PROFILE_SHA256)


def _storage_admit(arguments: dict, directory: Path, run_id: str,
                   storage_profile_sha256: str) -> bytes:
    """Capture current source expectations before claiming a private local attempt."""
    _storage_profile(storage_profile_sha256)
    _require(isinstance(directory, Path))
    receipts._receipt_bytes(run_id, 'FAILED', None)
    _, _, binding = _prepare(**arguments)
    fd = receipts._open_private_directory(directory)
    try:
        receipts._private_directory_identity(fd)
    finally:
        os.close(fd)
    return generated._json_bytes(binding)


def _storage_unchanged(arguments: dict, prepared: bytes, storage_profile_sha256: str) -> None:
    """Reject observed source, resource or policy drift without rebuilding native output."""
    _storage_profile(storage_profile_sha256)
    _require(generated._json_bytes(_prepare(**arguments)[2]) == prepared)


def _stored_manifest(result: dict, pdf: bytes, run_id: str, prepared: bytes,
                     result_sha256: str, pdf_sha256: str) -> dict:
    """Bind a closed raster result to independent current inputs and exact stored bytes."""
    for value in (result_sha256, pdf_sha256):
        resource_module._digest(value)
    _require(type(result) is dict
        and set(result) == {'render_result', 'native_inspection', 'binding'}
        and type(pdf) is bytes and 0 < len(pdf) <= storage.MAX_PDF_BYTES
        and sha256(pdf).hexdigest() == pdf_sha256)
    result_raw = generated._json_bytes(result)
    _require(len(result_raw) <= storage.MAX_MANIFEST_BYTES
        and sha256(result_raw).hexdigest() == result_sha256)
    source = storage._decode(prepared)
    render_record = result['render_result']
    native_record = result['native_inspection']
    binding = result['binding']
    _require(type(render_record) is dict and type(native_record) is dict and type(binding) is dict)
    # Reconstruct only the sealed render metadata, never a rewritten or reinspected PDF.
    rendered = raster.RasterPdfCandidate(pdf, source['html_sha256'],
        source['resources_sha256'], render_record.get('page_count'), source['resource_count'])
    _require(generated._json_bytes(rendered.to_dict()) == generated._json_bytes(render_record))
    native_raw = generated._json_bytes(native_record)
    _require(0 < len(native_raw) <= native.MAX_RESULT_BYTES)
    identity = {'schema_version': '1.0.0', 'profile_id': native.PROFILE_ID,
        'status': 'NATIVE_AND_STRUCTURED_SOURCE_RESULTS_BOUND',
        'pdf_sha256': pdf_sha256, 'ir_sha256': source['ir_sha256'],
        'page_count': rendered.page_count, 'namespace_id': source['namespace_id'],
        'job_id': source['job_id'], 'request_sha256': source['request_sha256'],
        'resource_profile_sha256': NATIVE_PROFILE_SHA256, 'language': 'en-US',
        'expected_text_sha256': source['expected_text_sha256'],
        'normalized_text_equivalence_verified': True,
        'release_authorization': 'NOT_ESTABLISHED', **native._nonclaims()}
    _require(all(type(native_record.get(key)) is type(value) and native_record[key] == value
                 for key, value in identity.items()))
    expected_binding = {**source, 'pdf_sha256': pdf_sha256, 'pdf_bytes': len(pdf),
        'page_count': rendered.page_count,
        'render_result_sha256': sha256(generated._json_bytes(render_record)).hexdigest(),
        'native_inspection_sha256': sha256(native_raw).hexdigest(),
        'completed_reporting_steps': ['BOUND_SOURCE_PROJECTION', 'CONFINED_RASTER_RENDER',
                                      'SAME_ARTIFACT_NATIVE_INSPECTION']}
    _require(generated._json_bytes(binding) == generated._json_bytes(expected_binding))
    manifest = {'schema': STORAGE_SCHEMA, 'state': 'STORED_PRIVATE_CANDIDATE',
        'run_id': run_id, 'storage_profile_sha256': STORAGE_PROFILE_SHA256,
        'result_sha256': result_sha256, 'pdf_sha256': pdf_sha256,
        'pdf_bytes': len(pdf), 'page_count': rendered.page_count,
        'result': result, 'release_authorized': False,
        'supported_execution': False, 'default_pipeline_activated': False}
    _require(len(generated._json_bytes(manifest)) <= storage.MAX_MANIFEST_BYTES)
    return manifest


def _read_stored(arguments: dict, directory: Path, run_id: str, prepared: bytes,
                 result_sha256: str, pdf_sha256: str, storage_profile_sha256: str
) -> tuple[bytes, dict]:
    """Read one closed committed bundle with transaction-wide named identity checks."""
    with bound_source.qualification._run_directory(directory, run_id, create=False) as (run, check):
        fd = receipts._open_private_directory(run)
        try:
            identity = receipts._private_directory_identity(fd)
            names = storage._DATA_NAMES | {run_id + '.json'}
            _require(set(os.listdir(fd)) == names)
            identities = storage._bundle_identities(fd, run_id)
            outcome = receipts.read_job_receipt(run, run_id, 'SUCCEEDED', result_sha256)
            raw = storage._read_data(fd, 'manifest.json', storage.MAX_MANIFEST_BYTES)
            pdf = storage._read_data(fd, 'candidate.pdf', storage.MAX_PDF_BYTES)
            document = storage._decode(raw)
            manifest = _stored_manifest(document.get('result'), pdf, run_id, prepared,
                                        result_sha256, pdf_sha256)
            _require(generated._json_bytes(manifest) == raw
                and storage._read_data(fd, 'manifest.json', storage.MAX_MANIFEST_BYTES) == raw
                and storage._read_data(fd, 'candidate.pdf', storage.MAX_PDF_BYTES) == pdf
                and receipts.read_job_receipt(run, run_id, 'SUCCEEDED', result_sha256) == outcome
                and set(os.listdir(fd)) == names
                and storage._bundle_identities(fd, run_id) == identities
                and receipts._private_directory_identity(fd) == identity)
            _storage_unchanged(arguments, prepared, storage_profile_sha256)
            _require(set(os.listdir(fd)) == names
                and storage._bundle_identities(fd, run_id) == identities
                and receipts._private_directory_identity(fd) == identity)
            check()
            return pdf, manifest
        finally:
            os.close(fd)



def _write_stored_file(directory_fd: int, name: str, data: bytes, limit: int,
                       *, commit: bool = False) -> tuple[int, ...]:
    """Retain the synced writer identity; preserve incomplete attempts on failure."""
    _require(type(data) is bytes and 0 < len(data) <= limit)
    staged = '.' + name + '.' + token_hex(16) + '.tmp' if commit else name
    fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                 | os.O_CLOEXEC, 0o600, dir_fd=directory_fd)
    try:
        os.fchmod(fd, 0o600)
        position = 0
        while position < len(data):
            remaining = min(65536, len(data) - position)
            written = os.write(fd, memoryview(data)[position:position + remaining])
            _require(type(written) is int and 0 < written <= remaining)
            position += written
        os.fsync(fd)
        original = storage._file_identity(os.fstat(fd), limit)
        _require(original[6] == len(data)
            and storage._file_identity(os.stat(staged, dir_fd=directory_fd,
                follow_symlinks=False), limit) == original)
        if commit:
            # Keep the original descriptor open through exclusive receipt publication.
            os.link(staged, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd,
                    follow_symlinks=False)
            os.fsync(directory_fd)
            linked = os.fstat(fd)
            _require(linked.st_nlink == 2
                and (linked.st_dev, linked.st_ino) == original[:2])
            for linked_name in (staged, name):
                current = os.stat(linked_name, dir_fd=directory_fd, follow_symlinks=False)
                _require(current.st_nlink == 2
                    and (current.st_dev, current.st_ino) == original[:2])
            os.unlink(staged, dir_fd=directory_fd)
            os.fsync(directory_fd)
        identity = storage._file_identity(os.fstat(fd), limit)
        # Linking changes ctime; every other admitted field must remain identical.
        _require((identity[:-1] == original[:-1] if commit else identity == original)
            and storage._file_identity(os.stat(name, dir_fd=directory_fd,
                follow_symlinks=False), limit) == identity)
        return identity
    finally:
        os.close(fd)


def _write_stored_data(directory_fd: int, name: str, data: bytes,
                       limit: int) -> tuple[int, ...]:
    """Create a bounded data member and return its descriptor-derived identity."""
    _require(name in storage._DATA_NAMES)
    return _write_stored_file(directory_fd, name, data, limit)


def _write_stored_receipt(directory: Path, run_id: str, state: str,
                          result_sha256: str) -> tuple[int, ...]:
    """Commit the unchanged canonical receipt and return the original file identity."""
    data = receipts._receipt_bytes(run_id, state, result_sha256)
    fd = receipts._open_private_directory(directory)
    try:
        directory_identity = receipts._private_directory_identity(fd)
        identity = _write_stored_file(fd, run_id + '.json', data,
                                     receipts.MAX_RECEIPT_BYTES, commit=True)
        _require(receipts._private_directory_identity(fd) == directory_identity)
        return identity
    finally:
        os.close(fd)


def execute_stored_bound_raster_candidate(*, bound_request: BoundReportRequest,
        resources: resource_module.RasterBundle, expected_request_sha256: str,
        expected_resources_sha256: str, expected_resource_profile_sha256: str,
        expected_storage_profile_sha256: str, directory: Path, run_id: str
) -> tuple[bytes, dict]:
    """Generate once and return only the exactly committed and read-back private candidate.

    The run is claimed before rendering. Existing complete or incomplete attempts
    refuse before native work; recovery is a separate explicit operation. Files are
    bounded, create-only and synced before the receipt commits the complete result.
    Failures preserve consumed attempts and return no candidate. A postcommit
    failure may leave a bundle recoverable with separately retained expectations.
    This API exposes output digests only on complete success. If a failed or lost
    first response leaves no independently retained trusted output expectations,
    recovery remains unverified; stored hashes cannot replace that trust anchor.

    This qualifies neither power-loss durability nor aggregate resources, supported
    execution, consent or final publication. The existing renderer's elapsed
    acceptance check does not preempt storage syscalls or impose a whole-job limit.
    """
    arguments = dict(bound_request=bound_request, resources=resources,
        expected_request_sha256=expected_request_sha256,
        expected_resources_sha256=expected_resources_sha256,
        expected_resource_profile_sha256=expected_resource_profile_sha256)
    try:
        prepared = _storage_admit(arguments, directory, run_id, expected_storage_profile_sha256)
        with bound_source.qualification._run_directory(directory, run_id, create=True) as (run, check):
            fd = receipts._open_private_directory(run)
            try:
                identity = receipts._private_directory_identity(fd)
                _require(not os.listdir(fd))
                check()
                rendered, inspected, binding = execute_bound_raster_candidate(**arguments)
                _require(type(rendered) is raster.RasterPdfCandidate
                         and type(inspected) is native.PdfNativeSourceResult)
                pdf = rendered.pdf_bytes
                render_raw = generated._json_bytes(rendered.to_dict())
                native_raw = inspected.to_bytes()
                binding_raw = generated._json_bytes(binding)
                result = {'render_result': storage._decode(render_raw),
                    'native_inspection': storage._decode(native_raw),
                    'binding': storage._decode(binding_raw)}
                result_sha256 = sha256(generated._json_bytes(result)).hexdigest()
                pdf_sha256 = sha256(pdf).hexdigest()
                manifest = _stored_manifest(result, pdf, run_id, prepared, result_sha256, pdf_sha256)
                manifest_raw = generated._json_bytes(manifest)
                limits = {'candidate.pdf': storage.MAX_PDF_BYTES,
                    'manifest.json': storage.MAX_MANIFEST_BYTES,
                    run_id + '.json': receipts.MAX_RECEIPT_BYTES}
                written_identities = {}

                def pin_written(name: str, original: tuple[int, ...]) -> None:
                    """Require the writer's descriptor identity; never adopt a named replacement."""
                    _require(name in limits and name not in written_identities)
                    _require(storage._file_identity(os.stat(name, dir_fd=fd,
                        follow_symlinks=False), limits[name]) == original)
                    written_identities[name] = original

                def unchanged() -> None:
                    """Keep both original sealed outputs and current input projection fixed."""
                    _storage_unchanged(arguments, prepared, expected_storage_profile_sha256)
                    _require(rendered.pdf_bytes == pdf
                        and generated._json_bytes(rendered.to_dict()) == render_raw
                        and inspected.to_bytes() == native_raw
                        and generated._json_bytes(binding) == binding_raw
                        and receipts._private_directory_identity(fd) == identity)
                    _require(set(os.listdir(fd)) == set(written_identities)
                        and all(storage._file_identity(os.stat(name, dir_fd=fd,
                            follow_symlinks=False), limits[name]) == original
                            for name, original in written_identities.items()))
                    check()

                unchanged()
                _require(not os.listdir(fd))
                for name, data in (('candidate.pdf', pdf), ('manifest.json', manifest_raw)):
                    original = _write_stored_data(fd, name, data, limits[name])
                    pin_written(name, original)
                os.fsync(fd)
                _require(set(os.listdir(fd)) == storage._DATA_NAMES
                    and storage._read_data(fd, 'candidate.pdf', storage.MAX_PDF_BYTES) == pdf
                    and storage._read_data(fd, 'manifest.json', storage.MAX_MANIFEST_BYTES) == manifest_raw)
                unchanged()
                original_receipt = _write_stored_receipt(run, run_id, 'SUCCEEDED', result_sha256)
                pin_written(run_id + '.json', original_receipt)
                unchanged()
                recovered_pdf, recovered_manifest = _read_stored(arguments, directory, run_id,
                    prepared, result_sha256, pdf_sha256, expected_storage_profile_sha256)
                _require(recovered_pdf == pdf
                    and generated._json_bytes(recovered_manifest) == manifest_raw)
                unchanged()
                return recovered_pdf, recovered_manifest
            finally:
                os.close(fd)
    except Exception:
        raise PdfBoundRasterError('pdf_bound_raster_store_execution_unverified') from None


def read_stored_bound_raster_candidate(*, bound_request: BoundReportRequest,
        resources: resource_module.RasterBundle, expected_request_sha256: str,
        expected_resources_sha256: str, expected_resource_profile_sha256: str,
        expected_storage_profile_sha256: str, directory: Path, run_id: str,
        expected_result_sha256: str, expected_pdf_sha256: str
) -> tuple[bytes, dict]:
    """Recover exact private bytes using independent original input and output expectations.

    This performs no write, native work, repair, retry or publication. The current
    original request/resource projection and policies must still match. The complete
    result digest must come from separately retained trusted evidence, never from
    this bundle itself. Hash agreement establishes consistency, not authenticated
    execution, historical fsync, reboot survival, scientific correctness or consent.
    """
    arguments = dict(bound_request=bound_request, resources=resources,
        expected_request_sha256=expected_request_sha256,
        expected_resources_sha256=expected_resources_sha256,
        expected_resource_profile_sha256=expected_resource_profile_sha256)
    try:
        resource_module._digest(expected_result_sha256)
        resource_module._digest(expected_pdf_sha256)
        prepared = _storage_admit(arguments, directory, run_id, expected_storage_profile_sha256)
        return _read_stored(arguments, directory, run_id, prepared,
            expected_result_sha256, expected_pdf_sha256, expected_storage_profile_sha256)
    except Exception:
        raise PdfBoundRasterError('pdf_bound_raster_store_recovery_unverified') from None
