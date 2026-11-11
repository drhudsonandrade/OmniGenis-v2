"""Explicit request-bound raster candidates using existing confined reporting stages.

The caller provides an actual bound request and exact preloaded PNG bundle, never
HTML, CSS, a renderer callback or resource budgets. Original source components,
ordered findings and observed reporting methodology are preserved. Resources are
separate decorative qualification appendices, not additional scientific findings.

Digests establish consistency, not scientific correctness, authenticated rights,
consent or source origin. The operation does not activate the default pipeline,
a supported executor, persistent recovery, publication or clinical interpretation.
The acceptance interval is a post-admission elapsed-time check, not aggregate
resource enforcement or preemption. Hostile same-owner mutate-and-restore between
checks remains outside the boundary. No retry, fallback or PDF rewrite occurs.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from html import escape
import os
import time

from reporting import adapters
from reporting import pdf_bound_candidate as bound_source
from reporting import pdf_generated_source_job as generated
from reporting import pdf_native_source_job as native
from reporting import pdf_raster_render as raster
from reporting import pdf_raster_resources as resource_module
from reporting.requests import BoundReportRequest

PROFILE_ID = 'bound-preloaded-raster-candidate-v1'
GENERATED_PROFILE_SHA256 = '9560a6cf2cfe0c3662a826d8804c0e328d2ccf95ae41fd6328a9143905a7d410'
NATIVE_PROFILE_SHA256 = 'dd29be3ecc903308a9bbe8b44b1fdbb57e6b5d18e5dde6918738e4bce194038c'
RENDER_PROFILE_SHA256 = '0ea42861783822c1c6c343ec0688a401fbd262045402c34d1aad429162778419'
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


PROFILE_SHA256 = '1e9f841f6303920c5142c7f6abf4a5990a518dc8970a7a2060483c511af97b67'


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
