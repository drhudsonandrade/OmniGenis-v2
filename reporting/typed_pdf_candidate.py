"""Opt-in same-PDF typed text and complete raster-geometry candidate.

This operation owns generation and every inspection stage. It returns private
PDF bytes only after their exact source association and all raster windows pass.
The unsigned metadata does not authenticate execution or establish visual
semantics, glyph correctness, accessibility, aggregate resources or release.
"""
from __future__ import annotations

from dataclasses import InitVar, dataclass, field
from hashlib import sha256
import json
import os
from pathlib import Path

from jsonschema import Draft202012Validator

from reporting._pdf_native_launch_budget import require_no_active_scope
from reporting.adapters import (
    FIXED_FONT_STYLE_ID, GENERATED_PDF_AUTHOR, GENERATED_PDF_PRODUCT,
    _FIXED_SEMANTIC_CSS,
)
from reporting.page_windows import (
    BoundPageWindowLedger, bind_pdf_page_window_evidence, plan_pdf_page_windows,
)
from reporting.pdf_generated_source_job import (
    PdfRenderedCandidate, RENDER_PROFILE_SHA256, _render_profile,
    render_pdf_candidate,
)
from reporting.pdf_raster_windows import (
    PdfRasterWindowInspection, inspect_pdf_raster_window,
)
from reporting.pdf_typed_observation import (
    TypedPdfObservation, _DIGEST, _loads, _profile as _observer_profile,
    observe_typed_pdf,
)
from reporting.typed_html import (
    TypedHtmlValidation, capture_typed_document, prepare_typed_html,
)
from reporting.typed_pdf_association import TypedPdfAssociation, associate_typed_pdf
from reporting.typed_pdf_source import TypedPdfSourceExpectation, prepare_typed_pdf_source

PROFILE_ID = 'typed-pdf-candidate-v1'
STATUS = 'TYPED_CANDIDATE_INSPECTED'
MAX_PDF_BYTES = 16777216
MAX_PAGES = 64
MAX_EVIDENCE_BYTES = 65536
RASTER_WIDTH = 4
RASTER_PROFILE_ID = 'generated-pdf-raster-window-v1'
OBSERVER_PROFILE_SHA256 = '36c205e0a99c57ba11afeb0663904240746d1ae6cfdb94ad1ce6df8c62637efa'
PASSIVE_POLICY = 'EFFECTIVE_GRAPH_DENIALS_WITH_VERIFIED_TABLE_ATTRIBUTES_ONLY'
ROOT = Path(__file__).resolve().parents[1]
_PROFILE_FILE = ROOT / 'reporting/pdf-typed-candidate.v1.json'
_SCHEMA_FILE = ROOT / 'schemas/report-typed-pdf-candidate.v1.schema.json'
_RASTER_FIELDS = ('pdf_sha256', 'ir_sha256', 'plan_sha256', 'page_count',
                  'window_index', 'first_page', 'last_page', 'raster_sha256',
                  'total_pixels', 'min_edge_margin_px')
_SOURCE_FILES = (
    'reporting/pdf-typed-observation.v1.json',
    'reporting/typed_pdf_association.py',
    'reporting/typed_pdf_candidate.py',
    'reporting/typed_pdf_source.py',
    'schemas/report-typed-pdf-association.v1.schema.json',
    'schemas/report-typed-pdf-candidate.v1.schema.json',
    'schemas/report-typed-pdf-source.v1.schema.json',
)
_DISABLE_FLAGS = (
    'OMNIGENIS_TYPED_PDF_CANDIDATE_DISABLED',
    'OMNIGENIS_PDF_RENDERER_DISABLED',
    'OMNIGENIS_TYPED_PDF_OBSERVATION_DISABLED',
    'OMNIGENIS_PDF_RASTER_WINDOWS_DISABLED',
)
_NONCLAIMS = (
    'source_authenticity_verified', 'rendered_glyphs_verified',
    'visual_semantics_verified', 'reading_order_verified',
    'accessibility_qualified', 'scientific_equivalence_verified',
    'all_file_revisions_inspected', 'opaque_stream_payloads_inspected',
    'whole_pdf_safety_qualified', 'aggregate_job_resources_qualified',
    'worker_results_authenticated', 'default_pipeline_activated',
    'release_authorized',
)


class TypedPdfCandidateError(ValueError):
    """Fixed content-free refusal; no partial PDF is an accepted candidate."""


def _require(condition: bool) -> None:
    """Reject invalid conjunctions without exposing report contents."""
    if not condition:
        raise ValueError('typed candidate boundary refused')


def _canonical(value: object) -> bytes:
    """Encode bounded native metadata with a fixed ASCII JSON representation."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _digest(value: object) -> None:
    """Require canonical native SHA-256 strings without coercion."""
    _require(type(value) is str and _DIGEST.fullmatch(value) is not None)


def _profile_contract() -> dict:
    """Closed composition, inheriting unchanged worker and runtime contracts."""
    return {
        'schema_version': '1.0.0', 'profile_id': PROFILE_ID,
        'input_profile_id': 'typed-report-projection-v1', 'locale_id': 'en-US',
        'source_profile_id': 'typed-report-pdf-source-v1',
        'association_profile_id': 'typed-report-pdf-association-v1',
        'observer_profile_sha256': OBSERVER_PROFILE_SHA256,
        'render_profile_sha256': RENDER_PROFILE_SHA256,
        'raster_profile_id': RASTER_PROFILE_ID,
        'font_style_id': FIXED_FONT_STYLE_ID,
        'html_wrapper_id': 'fixed-lato-typed-prewrap-v1',
        'literal_text_policy': 'SOURCE_LITERAL_UTF8_NO_NORMALIZATION',
        'passive_policy': PASSIVE_POLICY,
        'raster_scope': 'ALL_PHYSICAL_PAGES_NONBLANK_GEOMETRY_AND_EDGE_MARGIN_ONLY',
        'process_schedule': 'DECLARED_2_PLUS_2_WINDOWS_PLUS_PAGES',
        'limits': {'pdf_bytes': MAX_PDF_BYTES, 'pages': MAX_PAGES,
                   'source_units': 20000, 'evidence_bytes': MAX_EVIDENCE_BYTES,
                   'raster_pages_per_window': RASTER_WIDTH, 'raster_windows': 16,
                   'native_retries': 0},
        'disable_flags': list(_DISABLE_FLAGS),
        'default_pipeline_activated': False,
        'aggregate_job_resources_qualified': False,
        'release_authorized': False,
    }


def _profile(expected_sha256: object) -> str:
    """Check the closed manifest and both source closures before exposing bytes."""
    _digest(expected_sha256)
    _require(not any(os.environ.get(key) == '1' for key in _DISABLE_FLAGS))
    _require(not _PROFILE_FILE.is_symlink() and _PROFILE_FILE.stat().st_size <= 65536)
    with _PROFILE_FILE.open('rb') as stream:
        raw = stream.read(65537)
    _require(0 < len(raw) <= 65536)
    profile = _loads(raw.decode('ascii'))
    contract = _profile_contract()
    _require(type(profile) is dict and set(profile) == set(contract) | {'source_sha256'})
    sources = profile['source_sha256']
    _require(type(sources) is dict and set(sources) == set(_SOURCE_FILES))
    _require(_canonical({k: v for k, v in profile.items() if k != 'source_sha256'})
             == _canonical(contract))
    for name, expected in sources.items():
        _digest(expected)
        path = ROOT / name
        _require(not path.is_symlink() and path.resolve().is_relative_to(ROOT)
                 and sha256(path.read_bytes()).hexdigest() == expected)
    _require(_observer_profile() == OBSERVER_PROFILE_SHA256)
    _render_profile()
    actual = sha256(_canonical(profile)).hexdigest()
    _require(actual == expected_sha256)
    return actual


def _render_html(typed: str) -> str:
    """Use only the already validated inert body and the existing fixed wrapper."""
    prefix = ('<!doctype html><html lang="en-US"><head><meta charset="utf-8">'
              '<title>OmniGenis</title></head><body>')
    suffix = '</body></html>'
    _require(type(typed) is str and typed.startswith(prefix) and typed.endswith(suffix))
    body = typed[len(prefix):-len(suffix)]
    _require('<body' not in body and '</body' not in body)
    html = ('<!doctype html><html lang="en-US"><head><meta charset="utf-8">'
            f'<title>{GENERATED_PDF_PRODUCT}</title>'
            f'<meta name="author" content="{GENERATED_PDF_AUTHOR}">'
            f'<meta name="generator" content="{GENERATED_PDF_PRODUCT}">'
            f'<meta name="omnigenis-font-style" content="{FIXED_FONT_STYLE_ID}">'
            f'<style>{_FIXED_SEMANTIC_CSS}'
            'h1,h2,p,caption,th,td{white-space:pre-wrap}</style></head><body>'
            + body + suffix)
    _require(len(html) <= 67108864 and len(html.encode('utf-8')) <= 67108864)
    return html


def _raster_snapshot(row: dict) -> PdfRasterWindowInspection:
    """Own primitive receipt fields before another producer can alter its result."""
    result = PdfRasterWindowInspection(**{key: row[key] for key in _RASTER_FIELDS})
    _require(result.to_dict() == row)
    return result


def _validate_evidence(payload: bytes, pdf: bytes) -> dict:
    """Re-admit closed metadata and complete coverage; never authenticate execution."""
    _require(type(payload) is bytes and 0 < len(payload) <= MAX_EVIDENCE_BYTES)
    _require(type(pdf) is bytes and 0 < len(pdf) <= MAX_PDF_BYTES
             and pdf.startswith(b'%PDF-1.7'))
    value = _loads(payload.decode('ascii'))
    _require(type(value) is dict and _canonical(value) == payload)
    _profile(value['profile_sha256'])
    schema = _loads(_SCHEMA_FILE.read_text(encoding='ascii'))
    Draft202012Validator(schema).validate(value)
    _require(value['pdf_sha256'] == sha256(pdf).hexdigest()
             and value['pdf_byte_count'] == len(pdf)
             and value['observer_profile_sha256'] == OBSERVER_PROFILE_SHA256
             and all(type(flag) is bool for flag in value['claims'].values()))
    pages = value['page_count']
    plan = plan_pdf_page_windows(
        pdf_sha256=value['pdf_sha256'], ir_sha256=value['ir_sha256'],
        page_count=pages, admitted_page_budget=pages,
        pages_per_window=RASTER_WIDTH, inspector_profile_id=RASTER_PROFILE_ID)
    _require(plan.plan_sha256 == value['raster_window_plan_sha256']
             and plan.window_count == value['raster_window_count']
             and len(value['raster_windows']) == plan.window_count)
    receipts = []
    for window, row in zip(plan.windows, value['raster_windows'], strict=True):
        receipt = _raster_snapshot(row)
        expected = {
            'pdf_sha256': value['pdf_sha256'], 'ir_sha256': value['ir_sha256'],
            'plan_sha256': plan.plan_sha256, 'page_count': pages,
            'window_index': window.index, 'first_page': window.first_page,
            'last_page': window.last_page, 'profile_id': RASTER_PROFILE_ID,
        }
        _require(all(row[key] == item for key, item in expected.items()))
        receipts.append(receipt)
    ledger = bind_pdf_page_window_evidence(
        plan=plan, observations=tuple(item.to_observation() for item in receipts))
    _require(sha256(_canonical(ledger.to_dict())).hexdigest() == value['raster_ledger_sha256']
             and sum(item.inspected_pages for item in receipts)
             == value['raster_inspected_pages'] == pages)
    windows = plan.window_count
    _require(value['declared_process_schedule'] == {
        'renderer': 1, 'typed_observer': 1, 'raster_workers': windows,
        'raster_version_probes': windows, 'raster_page_executors': pages,
        'total': 2 + 2 * windows + pages, 'execution_authenticated': False,
    })
    return value


def _execute(presentation_ir, expected_ir_sha256,
             expected_source_expectation_sha256, expected_profile_sha256) -> tuple[bytes, bytes]:
    """Capture once and own every complete fixed stage of the same private PDF."""
    require_no_active_scope()
    profile_sha = _profile(expected_profile_sha256)
    _digest(expected_ir_sha256)
    _digest(expected_source_expectation_sha256)
    doc = capture_typed_document(presentation_ir, expected_ir_sha256)
    source = prepare_typed_pdf_source(
        presentation_ir=doc, expected_ir_sha256=expected_ir_sha256)
    _require(type(source) is TypedPdfSourceExpectation
             and source.expectation_sha256 == expected_source_expectation_sha256)
    manifest = source.to_dict()
    _require(0 < len(manifest['units']) <= 20000)
    typed, html_proof = prepare_typed_html(
        presentation_ir=doc, expected_ir_sha256=expected_ir_sha256)
    _require(type(html_proof) is TypedHtmlValidation
             and html_proof.ir_sha256 == expected_ir_sha256
             and html_proof.html_sha256 == sha256(typed.encode('utf-8')).hexdigest())
    typed_html_sha = html_proof.html_sha256
    html = _render_html(typed)
    html_sha = sha256(html.encode('utf-8')).hexdigest()

    require_no_active_scope()
    rendered = render_pdf_candidate(html, html_sha)
    _require(type(rendered) is PdfRenderedCandidate)
    pdf = object.__getattribute__(rendered, '_pdf_bytes')
    _require(type(pdf) is bytes and 0 < len(pdf) <= MAX_PDF_BYTES
             and pdf.startswith(b'%PDF-1.7'))
    pdf_sha = sha256(pdf).hexdigest()
    render_data = rendered.to_dict()
    _require(render_data['html_sha256'] == html_sha
             and render_data['pdf_sha256'] == pdf_sha
             and render_data['pdf_byte_count'] == len(pdf)
             and render_data['profile_sha256'] == RENDER_PROFILE_SHA256)
    pages = render_data['page_count']
    render_sha = sha256(_canonical(render_data)).hexdigest()

    require_no_active_scope()
    observed = observe_typed_pdf(pdf_bytes=pdf, expected_pdf_sha256=pdf_sha)
    _require(type(observed) is TypedPdfObservation)
    payload = object.__getattribute__(observed, '_payload')
    _require(type(payload) is bytes and 0 < len(payload) <= 4194304)
    # Reconstruct the closed bounded trace, including its reverse structure and
    # decoded text, before using either its counts or declared digests.
    admitted = TypedPdfObservation(payload)
    _require(observed.observation_sha256 == admitted.observation_sha256)
    physical = admitted.summary()
    observation_sha = admitted.observation_sha256
    _require(physical['pdf_sha256'] == pdf_sha
             and physical['pdf_byte_count'] == len(pdf)
             and physical['page_count'] == pages
             and type(pages) is int and 1 <= pages <= MAX_PAGES
             and physical['profile_sha256'] == OBSERVER_PROFILE_SHA256)

    associated = associate_typed_pdf(
        presentation_ir=doc, expected_ir_sha256=expected_ir_sha256,
        expected_source_expectation_sha256=expected_source_expectation_sha256,
        observation=admitted, expected_observation_sha256=observation_sha,
        expected_pdf_sha256=pdf_sha)
    _require(type(associated) is TypedPdfAssociation)
    association_bytes = object.__getattribute__(associated, '_serialized')
    _require(type(association_bytes) is bytes and 0 < len(association_bytes) <= 4194304)
    _require(sha256(association_bytes).hexdigest() == associated.association_sha256)
    association_sha = sha256(association_bytes).hexdigest()
    association = associated.summary()
    bindings = ('ir_sha256', 'request_sha256', 'source_binding_sha256',
                'plan_sha256', 'ledger_sha256', 'content_sha256', 'section_states_sha256')
    _require(all(association[key] == manifest[key] for key in bindings)
             and association['source_expectation_sha256'] == expected_source_expectation_sha256
             and association['observation_sha256'] == observation_sha
             and association['observer_profile_sha256'] == OBSERVER_PROFILE_SHA256
             and association['pdf_sha256'] == pdf_sha
             and association['pdf_byte_count'] == len(pdf)
             and association['page_count'] == pages
             and association['source_counts'] == manifest['counts'])
    _require({k for k, value in association['claims'].items() if value is True}
             == {'literal_hashes_matched', 'complete_physical_coverage',
                 'unique_mapping_within_profile'}
             and all(type(value) is bool for value in association['claims'].values()))

    plan = plan_pdf_page_windows(
        pdf_sha256=pdf_sha, ir_sha256=expected_ir_sha256, page_count=pages,
        admitted_page_budget=pages, pages_per_window=RASTER_WIDTH,
        inspector_profile_id=RASTER_PROFILE_ID)
    _require(1 <= plan.window_count <= 16)
    plan_sha = plan.plan_sha256
    inspections = []
    for window in plan.windows:
        plan.__post_init__()
        _require(plan.plan_sha256 == plan_sha)
        require_no_active_scope()
        receipt = inspect_pdf_raster_window(
            pdf_bytes=pdf, plan=plan, window_index=window.index,
            expected_plan_sha256=plan_sha)
        _require(type(receipt) is PdfRasterWindowInspection)
        row = receipt.to_dict()
        expected = {
            'pdf_sha256': pdf_sha, 'ir_sha256': expected_ir_sha256,
            'plan_sha256': plan.plan_sha256, 'page_count': pages,
            'window_index': window.index, 'first_page': window.first_page,
            'last_page': window.last_page, 'profile_id': RASTER_PROFILE_ID,
        }
        # The generic ledger omits IR and total page count from each observation.
        # Compare the complete native receipt before that narrower projection.
        _require(all(row[key] == value for key, value in expected.items()))
        inspections.append(_raster_snapshot(row))
    ledger = bind_pdf_page_window_evidence(
        plan=plan, observations=tuple(item.to_observation() for item in inspections))
    _require(type(ledger) is BoundPageWindowLedger and ledger.plan is plan)
    ledger_data = ledger.to_dict()
    windows = [item.to_dict() for item in inspections]
    inspected_pages = sum(item.inspected_pages for item in inspections)
    _require(inspected_pages == pages and len(windows) == plan.window_count)

    result = {
        'schema_version': '1.0.0', 'profile_id': PROFILE_ID, 'status': STATUS,
        'conformance_scope': 'EXACT_TYPED_TEXT_AND_ALL_PAGE_RASTER_GEOMETRY_ONLY',
        'profile_sha256': profile_sha, **{key: manifest[key] for key in bindings},
        'source_expectation_sha256': expected_source_expectation_sha256,
        'typed_html_sha256': typed_html_sha, 'html_sha256': html_sha,
        'render_result_sha256': render_sha,
        'observer_profile_sha256': OBSERVER_PROFILE_SHA256,
        'observation_sha256': observation_sha,
        'association_sha256': association_sha,
        'pdf_sha256': pdf_sha, 'pdf_byte_count': len(pdf), 'page_count': pages,
        'source_counts': manifest['counts'], 'passive_policy': PASSIVE_POLICY,
        'raster_window_plan_sha256': plan.plan_sha256,
        'raster_ledger_sha256': sha256(_canonical(ledger_data)).hexdigest(),
        'raster_window_count': len(windows), 'raster_inspected_pages': inspected_pages,
        'raster_windows': windows,
        'declared_process_schedule': {
            'renderer': 1, 'typed_observer': 1, 'raster_workers': len(windows),
            'raster_version_probes': len(windows), 'raster_page_executors': pages,
            'total': 2 + 2 * len(windows) + pages, 'execution_authenticated': False,
        },
        'claims': {
            'literal_source_associated': True,
            'effective_typed_graph_policy_checked': True,
            'all_pages_raster_geometry_inspected': True,
            **{key: False for key in _NONCLAIMS},
        },
        'release_authorization': 'NOT_ESTABLISHED',
    }
    serialized = _canonical(result)
    _require(len(serialized) <= MAX_EVIDENCE_BYTES)
    require_no_active_scope()
    _require(_validate_evidence(serialized, pdf)['profile_sha256'] == profile_sha)
    return pdf, serialized


@dataclass(frozen=True, slots=True, repr=False)
class TypedPdfCandidate:
    """Immutable private candidate; direct construction runs the entire boundary."""

    presentation_ir: InitVar[object]
    expected_ir_sha256: InitVar[object]
    expected_source_expectation_sha256: InitVar[object]
    expected_profile_sha256: InitVar[object]
    _pdf_bytes: bytes = field(init=False, repr=False)
    _payload: bytes = field(init=False, repr=False)
    _sealed_sha256: str = field(init=False, repr=False)

    def __post_init__(self, presentation_ir, expected_ir_sha256,
                      expected_source_expectation_sha256, expected_profile_sha256):
        """Execute admission instead of accepting caller-provided success records."""
        try:
            _require(not hasattr(self, '_payload'))
            pdf, payload = _execute(presentation_ir, expected_ir_sha256,
                                    expected_source_expectation_sha256,
                                    expected_profile_sha256)
            object.__setattr__(self, '_pdf_bytes', pdf)
            object.__setattr__(self, '_payload', payload)
            object.__setattr__(self, '_sealed_sha256', sha256(payload).hexdigest())
        except Exception:
            raise TypedPdfCandidateError('typed_pdf_candidate_refused') from None

    def _checked(self) -> bytes:
        """Check bounded retained bytes and source/profile pins without native replay."""
        try:
            _require(type(self._pdf_bytes) is bytes
                     and 0 < len(self._pdf_bytes) <= MAX_PDF_BYTES
                     and self._pdf_bytes.startswith(b'%PDF-1.7'))
            _require(type(self._payload) is bytes and 0 < len(self._payload) <= MAX_EVIDENCE_BYTES)
            _digest(self._sealed_sha256)
            _require(sha256(self._payload).hexdigest() == self._sealed_sha256)
            _validate_evidence(self._payload, self._pdf_bytes)
            return self._payload
        except Exception:
            raise TypedPdfCandidateError('typed_pdf_candidate_refused') from None

    @property
    def pdf_bytes(self) -> bytes:
        """Return private content only after complete construction and retained checks."""
        self._checked()
        return self._pdf_bytes

    def to_bytes(self) -> bytes:
        """Return bounded content-free canonical metadata."""
        return self._checked()

    def to_dict(self) -> dict:
        """Return detached unsigned metadata, never PDF content or the private trace."""
        return json.loads(self._checked())

    @property
    def candidate_sha256(self) -> str:
        """Identify local evidence; a digest never authenticates native execution."""
        return sha256(self._checked()).hexdigest()

    def __repr__(self) -> str:
        """Keep private content and source identifiers out of implicit formatting."""
        return 'TypedPdfCandidate()'


def prepare_typed_pdf_candidate(
    *, presentation_ir: object, expected_ir_sha256: object,
    expected_source_expectation_sha256: object, expected_profile_sha256: object,
) -> TypedPdfCandidate:
    """Run the fixed complete composition without caller artifacts or PASS flags."""
    return TypedPdfCandidate(presentation_ir, expected_ir_sha256,
                             expected_source_expectation_sha256, expected_profile_sha256)
