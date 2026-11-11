"""Explicit request-to-candidate binding under the existing qualification policy.

The admitted source is the existing canonical interpretation v1 envelope encoded
as canonical integer-only JSON. Its declarations are preserved, not scientifically
reverified. The complete ordered item inventory reaches the existing report family
and generated-PDF API; selection and upstream exclusions are unsupported here.

Request identity and control references remain upstream assertions. The canonical
envelope has no case/sample identity to authenticate. Evidence snapshot bytes are
hash-bound but their membership is not inspected. No supported executor, default
pipeline, whole-job resource qualification or final release is established.

Each outer attempt is consumed before generation. Its computation receipt and a
separate nested private candidate commit independently. Any failure withholds the
return value, preserves evidence and requires explicit inspection/recovery, never
automatic rerendering. Recovery needs independent expected result and PDF digests.
Hostile same-owner mutation between observed checks remains outside this boundary.

The default source-only-v1 mode retains its original projection and recovery.
Explicit technical-assembly-v1 adds a bound methodology record for observed
reporting steps only. Unavailable upstream science/assay/QC remains unavailable.
Recovery requires the same caller-selected mode; stored data cannot select it.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import re

from reporting import _pdf_job_durable_receipt as receipts
from reporting import pdf_candidate_store as storage
from reporting import pdf_generated_source_job as generated
from reporting import pdf_qualification_job as qualification
from reporting.bindings import MAX_SNAPSHOT_BYTES, _digest
from reporting.compiler import compile_report_pack
from reporting.completeness import (FindingProjection, SectionAvailability,
                                    validate_report_completeness)
from reporting.contracts import REPORT_ID, validate_rpt01_contracts
from reporting.families import build_report_family_view_model
from reporting.localization import localize_presentation_ir
from reporting.pdf_candidate_qa import _snapshot_ir
from reporting.presentation import build_presentation_ir
from reporting.requests import BoundReportRequest
from reporting.viewmodel import build_report_view_model_and_release_bundle

_ROOT = Path(__file__).resolve().parent
_FAMILY_SHA256 = '14a0999a68b70ad83b9111b04283752444173255a573460e38cb3224fb8afbaa'
_CONTRACT_FILES = {'catalog': 'catalog.v1.json',
    'section_contracts': 'sections/e1a-small-variant-report.v1.json',
    'intended_use': 'intended-use/e1a-small-variant-report.v1.json',
    'report_capability_manifest': 'capabilities/e1a-small-variant-report.v1.json'}
_SECTIONS = ('identity-and-provenance', 'verified-source-interpretations',
             'unresolved-evidence-conflicts', 'limitations-and-not-assessed',
             'sources-and-versioning')
_SEMANTICS = (('identity', 'provenance'), ('items',), ('conflicts',),
              ('limitations',), ('provenance',))
_ITEM_STRINGS = frozenset(('canonical_variant_id', 'operational_status',
    'interpretation_status', 'source_name', 'source_classification', 'source_review_status',
    'source_vcv_accession', 'evidence_snapshot_id', 'evidence_sha256', 'evidence_checked_at',
    'evidence_freshness_status', 'local_classification_status', 'acmg_amp_status',
    'clingen_vcep_status', 'gene_disease_validity_status', 'actionability_status',
    'personal_relevance_status', 'diagnosis_status', 'treatment_status'))
_ITEM_INTS = frozenset(('source_variation_id', 'source_vcv_version', 'source_submission_count'))
_ITEM_ARRAYS = frozenset(('condition_names', 'condition_references'))
_VARIANT_ID = re.compile(r'omnigenis:small-variant:v1:sha256:[0-9a-f]{64}')
_RULE_IDS = ('CANONICAL_MODEL_BINDING', 'EVIDENCE_SNAPSHOT_BINDING',
             'INTERPRETATION_CARDINALITY', 'EVIDENCE_FRESHNESS', 'INTERPRETATION_PROJECTION')
_NONCLAIMS = {'upstream_authorization_validated': False,
    'evidence_membership_validated': False, 'supported_execution': False,
    'release_authorized': False, 'default_pipeline_activated': False,
    'aggregate_job_resources_qualified': False}


class PdfBoundCandidateError(ValueError):
    """Expose only a fixed refusal code, never content, paths or partial results."""


def _require(condition: bool) -> None:
    """Reject an unestablished structural condition without retaining its values."""
    if not condition:
        raise ValueError('bound candidate validation failed')


def _parse(raw: bytes, *, canonical: bool = False) -> dict:
    """Capture bounded JSON without duplicate keys, floats or byte normalization."""
    def unique(pairs):
        """Reject duplicate keys before their earlier values can be discarded."""
        result = {}
        for key, value in pairs:
            _require(key not in result)
            result[key] = value
        return result

    def reject_number(_value):
        """The current producer has no floating-point or nonfinite output fields."""
        raise ValueError('unsupported source number')

    _require(type(raw) is bytes and 0 < len(raw) <= MAX_SNAPSHOT_BYTES)
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                       parse_float=reject_number, parse_constant=reject_number)
    captured = _snapshot_ir(value)
    _require(not canonical or generated._json_bytes(captured) == raw)
    return captured


def _source(bound: BoundReportRequest) -> dict:
    """Admit existing declared source structure without recalculating its science."""
    value = _parse(bound.sources.canonical_result_bytes, canonical=True)
    constants = {'capability_id': 'canonical-interpretation-object',
        'capability_version': '1.0.0', 'canonical_status': 'INTERPRETATION_OBJECT_VERIFIED',
        'availability': 'AVAILABLE', 'executor_id': 'omnigenis.python-stdlib',
        'executor_version': '1.0.0', 'adapter_version': None, 'model_id': None,
        'resource_release': None, 'reference_bundle': None,
        'execution_profile': 'canonical-interpretation-object-e1a-v1'}
    _require(set(value) == set(constants) | {
        'canonical_payload', 'limitations', 'raw_artifact_refs', 'provenance_refs'})
    _require(all(value[key] == expected for key, expected in constants.items()))
    for key in ('limitations', 'raw_artifact_refs', 'provenance_refs'):
        _require(type(value[key]) is list and all(type(v) is str for v in value[key]))
    payload = value['canonical_payload']
    _require(type(payload) is dict and set(payload) == {'artifact_kind',
        'canonical_model_source_vcf_sha256', 'canonical_model_normalization_output_sha256',
        'evidence_source_registry_id', 'as_of_date', 'interpretation_item_count',
        'items', 'rules', 'errors'})
    _require(payload['artifact_kind'] == 'CANONICAL_INTERPRETATION' and payload['errors'] == [])
    _require(payload['canonical_model_source_vcf_sha256'] ==
             bound.request.source_binding.input_artifact.sha256)
    _digest(payload['canonical_model_normalization_output_sha256'])
    _require(type(payload['evidence_source_registry_id']) is str and
             type(payload['as_of_date']) is str)
    rules = payload['rules']
    _require(type(rules) is list and len(rules) == len(_RULE_IDS))
    for rule, rule_id in zip(rules, _RULE_IDS):
        _require(type(rule) is dict and set(rule) == {'rule_id', 'status', 'detail'}
                 and rule['rule_id'] == rule_id and rule['status'] == 'PASS'
                 and type(rule['detail']) is str)
    items = payload['items']
    _require(type(items) is list and type(payload['interpretation_item_count']) is int
             and payload['interpretation_item_count'] == len(items))
    for item in items:
        _require(type(item) is dict and set(item) == _ITEM_STRINGS | _ITEM_INTS |
                 _ITEM_ARRAYS | {'source_conflict', 'local_classification'})
        _require(all(type(item[key]) is str for key in _ITEM_STRINGS))
        _require(all(type(item[key]) is int for key in _ITEM_INTS))
        _require(type(item['source_conflict']) is bool and
                 (item['local_classification'] is None or type(item['local_classification']) is str))
        _require(all(type(item[key]) is list and all(type(v) is str for v in item[key])
                     for key in _ITEM_ARRAYS))
        _require(_VARIANT_ID.fullmatch(item['canonical_variant_id']) is not None)
        _digest(item['evidence_sha256'])
    ids = tuple(item['canonical_variant_id'] for item in items)
    _require(ids == bound.plan.expected_finding_ids and len(set(ids)) == len(ids))
    _require(value['raw_artifact_refs'] == [item['evidence_sha256'] for item in items])
    return value


def _technical_methodology(bound: BoundReportRequest, document: dict) -> dict:
    """Record only request/source/inventory checks already completed by this consumer.

    The source declares VCF provenance and an evidence cutoff, not proof of an
    upstream assay or executor run. The record is deterministic reporting metadata,
    not an authenticated upstream execution record or release authorization. Later
    rendering and persistence are not prematurely labelled completed here.
    """
    refs = bound.request.source_binding
    payload = document['canonical_payload']
    record = {
        'schema': 'technical-report-assembly-execution-v1',
        'conformance_scope': 'OBSERVED_REPORT_BINDING_AND_INVENTORY_VALIDATION_ONLY',
        'request_sha256': bound.request.request_sha256,
        'source_binding_sha256': refs.binding_sha256,
        'input_artifact_sha256': refs.input_artifact.sha256,
        'canonical_result_sha256': refs.canonical_result.sha256,
        'evidence_snapshot_sha256': refs.evidence_snapshot.sha256,
        'reference_bundle_sha256': refs.reference_bundle_sha256,
        'declared_upstream_input_format': 'VCF',
        'declared_evidence_cutoff': payload['as_of_date'],
        'declared_finding_count': len(payload['items']),
        'completed_reporting_steps': ['REQUEST_SNAPSHOT_BINDING',
            'CANONICAL_SOURCE_BYTE_INTEGRITY', 'DECLARED_FINDING_INVENTORY_ACCOUNTING'],
        'scientific_operations_executed_by_report_job': [],
        'upstream_scientific_execution_verified': False,
        'release_authorized': False,
    }
    for field in ('upstream_execution_record', 'laboratory', 'assay', 'quality',
                  'callable_scope', 'requested_scientific_capabilities',
                  'performed_scientific_capabilities'):
        record[field] = {'availability': 'NOT_AVAILABLE'}
    return {
        'title': 'Methodology',
        'brief': (
            'The technical reporting job validated the bound request, immutable '
            'source bytes and complete declared finding inventory. It projects '
            'supplied canonical interpretations and does not execute sequencing '
            'or variant analysis. The supplied result declares VCF provenance. '
            'Laboratory, assay, upstream execution, quality and callable-scope '
            'records are not available to this reporting boundary. A missing '
            'reported finding does not establish a negative result. Evidence '
            'timing and reference identity are preserved from bound source '
            'metadata without refresh or independent scientific verification.'),
        'execution_record': record,
        'execution_record_sha256': sha256(generated._json_bytes(record)).hexdigest(),
    }


def _prepare(bound: BoundReportRequest, profile: str,
             methodology_profile: str = 'source-only-v1') -> tuple[dict, dict]:
    """Derive exact native arguments and metadata from a revalidated actual request."""
    qualification._require_policy()
    _require(type(methodology_profile) is str and methodology_profile in (
        'source-only-v1', 'technical-assembly-v1'))
    _require(type(bound) is BoundReportRequest)
    BoundReportRequest.__post_init__(bound)
    _require(not bound.plan.upstream_exclusions and bound.plan.expected_section_ids == _SECTIONS
             and bound.plan.required_section_ids == _SECTIONS)
    generated.require_no_active_scope()
    generated._profile(profile)
    request = bound.request
    generated._validate_context(request.source_binding.identity.namespace_id,
                                request.request_id, request.request_sha256, profile)
    document = _source(bound)
    documents = {key: _parse((_ROOT / path).read_bytes())
                 for key, path in _CONTRACT_FILES.items()}
    contracts = validate_rpt01_contracts(report_id=REPORT_ID, **documents)
    _require(contracts.passed and contracts.bundle_sha256 == request.report_contract_bundle_sha256
             and contracts.intended_use.intended_use_id == request.intended_use_id)
    _require(tuple(s.section_id for s in contracts.sections) == _SECTIONS
             and all(s.required for s in contracts.sections))
    _require(tuple(s.required_semantic_inputs for s in contracts.sections) == tuple(
        tuple('canonical_interpretation.' + name for name in names) for names in _SEMANTICS))
    family_raw = (_ROOT / 'families.v1.json').read_bytes()
    _require(sha256(family_raw).hexdigest() == _FAMILY_SHA256)
    locale_raw = (_ROOT / 'locales/en-US.v1.json').read_bytes()
    _require(request.locale_id == 'en-US' and sha256(locale_raw).hexdigest() == request.locale_pack.sha256)
    locale = _parse(locale_raw)
    payload = document['canonical_payload']
    assembly = {'identity': request.source_binding.identity.to_dict(), 'items': payload['items'],
        'conflicts': {'availability': 'NOT_ASSESSED',
                      'assembly_reason': 'AGGREGATE_CONFLICT_CONTRACT_NOT_SUPPLIED'},
        'limitations': document['limitations'],
        'provenance': {'source_binding': request.source_binding.to_dict(),
            'source_envelope': {k: v for k, v in document.items() if k != 'canonical_payload'},
            'source_payload_metadata': {k: v for k, v in payload.items() if k != 'items'},
            'binding_scope': dict(_NONCLAIMS)}}
    if methodology_profile == 'technical-assembly-v1':
        assembly['provenance']['methodology'] = _technical_methodology(bound, document)
    compiled = compile_report_pack(report_id=REPORT_ID, **documents, canonical_interpretation=assembly)
    refs = request.source_binding
    view = build_report_view_model_and_release_bundle(compiled_report_pack=compiled,
        artifact_ids=[refs.input_artifact.artifact_id, refs.canonical_result.artifact_id,
                      refs.evidence_snapshot.artifact_id])
    family = build_report_family_view_model(family_catalog=_parse(family_raw),
        report_capability_manifest=documents['report_capability_manifest'], rpt03_result=view)
    _require(family.passed and family.family_id == 'e1a-small-variant')
    presentation = build_presentation_ir(report_view_model=family.family_view_model['report_view_model'])
    _require(presentation.passed)
    localized = localize_presentation_ir(presentation_ir=presentation.to_dict()['presentation_ir'],
                                         locale_id=request.locale_id)
    _require(localized.passed)
    ir = localized.to_dict()['localized_ir']
    expected_components = []
    for section, names in zip(contracts.sections, _SEMANTICS):
        content = {'canonical_interpretation.' + name: assembly[name] for name in names}
        present = any(value not in (None, '', [], {}, ()) for value in content.values())
        expected_components.append({'component_id': section.section_id, 'component_type': 'semantic-section',
            'title': locale['labels'][section.section_id],
            'state': 'PRESENT' if present else section.empty_state_policy, 'content': content})
    _require(generated._json_bytes(ir) == generated._json_bytes({
        'report_id': REPORT_ID, 'locale_id': request.locale_id, 'components': expected_components}))
    ir = generated._capture_adapter_ir(ir)
    _require(generated._validate_ir(ir))
    ir_sha256 = generated._expected_content(ir)[0]
    _require(ir_sha256 == localized.localized_ir_sha256)
    ledger = validate_report_completeness(sources=bound.sources, plan=bound.plan,
        projection_source_binding_sha256=refs.binding_sha256,
        projection_plan_sha256=bound.plan.plan_sha256,
        represented=tuple(FindingProjection(item['canonical_variant_id'], _SECTIONS[1], (_SECTIONS[1],))
                          for item in payload['items']),
        section_states=tuple(SectionAvailability(section, 'PRESENT') for section in _SECTIONS))
    binding = {'schema': 'bound-qualification-pdf-candidate-v1',
        'conformance_scope': 'SUPPLIED_REQUEST_SOURCE_INVENTORY_AND_PRIVATE_CANDIDATE_ONLY',
        'request_sha256': request.request_sha256, 'source_binding_sha256': refs.binding_sha256,
        'canonical_result_sha256': refs.canonical_result.sha256,
        'evidence_snapshot_sha256': refs.evidence_snapshot.sha256,
        'completeness_plan_sha256': bound.plan.plan_sha256, 'ledger_sha256': ledger.ledger_sha256,
        'report_contract_bundle_sha256': contracts.bundle_sha256, 'family_id': family.family_id,
        'family_catalog_sha256': _FAMILY_SHA256, 'family_view_model_sha256': family.family_view_model_sha256,
        'locale_pack_sha256': request.locale_pack.sha256, 'ir_sha256': ir_sha256,
        'resource_profile_sha256': profile, 'finding_count': len(payload['items']),
        'declared_source_inventory_accounted': True, **_NONCLAIMS}
    if methodology_profile == 'technical-assembly-v1':
        binding.update(schema='bound-qualification-pdf-candidate-v2',
            methodology_profile=methodology_profile,
            methodology_record_sha256=assembly['provenance']['methodology']['execution_record_sha256'])
    arguments = dict(presentation_ir=ir, expected_ir_sha256=ir_sha256,
        expected_language=request.locale_id, namespace_id=refs.identity.namespace_id,
        job_id=request.request_id, request_sha256=request.request_sha256,
        expected_resource_profile_sha256=profile)
    return arguments, binding


def _unchanged(bound: BoundReportRequest, arguments: dict, binding: dict,
               methodology_profile: str = 'source-only-v1') -> None:
    """Rebuild current policy, request and file bindings before a successful return."""
    current_arguments, current_binding = _prepare(
        bound, arguments['expected_resource_profile_sha256'], methodology_profile)
    _require(generated._json_bytes(current_arguments) == generated._json_bytes(arguments)
             and generated._json_bytes(current_binding) == generated._json_bytes(binding))


def _expectations(arguments: dict, result_sha256: str, pdf_sha256: str) -> dict:
    """Keep storage context derived from the request, never from a stored manifest."""
    return {key: arguments[key] for key in ('namespace_id', 'job_id', 'request_sha256',
        'expected_ir_sha256', 'expected_resource_profile_sha256')} | {
        'expected_result_sha256': result_sha256, 'expected_pdf_sha256': pdf_sha256}


def execute_bound_qualification_pdf_candidate(
    bound_request: BoundReportRequest, *, directory: Path, run_id: str,
    expected_resource_profile_sha256: str, methodology_profile: str = 'source-only-v1',
) -> tuple[generated.PdfGeneratedSourceResult, dict, dict, dict]:
    """Generate once and return result, observation, binding and stored manifest.

    The existing outer run contains its computation receipt and a private
    ``candidate`` parent for the separately committed candidate bundle. Success
    requires exact readback and current request/policy checks. Observation and
    binding metadata are returned detached; only existing store metadata persists.
    A computation SUCCEEDED receipt alone never establishes candidate persistence.
    The optional methodology mode records prior reporting checks, not upstream
    science or future rendering/storage success; its exact record is bound by IR.
    """
    try:
        arguments, binding = _prepare(
            bound_request, expected_resource_profile_sha256, methodology_profile)
        captured, source_bytes = qualification._admit(arguments, directory, run_id)
    except Exception:
        raise PdfBoundCandidateError('pdf_bound_candidate_input_invalid') from None
    try:
        result, observation, outcome = qualification.execute_raster_observed_receipted_pdf_generated_source_job(
            **arguments, receipt_directory=directory, run_id=run_id)
        result_sha = qualification._completed_digest(result, arguments, captured, source_bytes)
        observation_bytes = qualification._observation_bytes(result, observation, observe_raster_children=True)
        expected = _expectations(arguments, result_sha, result.pdf_sha256)
        _unchanged(bound_request, arguments, binding, methodology_profile)
        with qualification._run_directory(directory, run_id, create=False) as (run, check):
            _require(receipts.read_job_receipt(run, run_id, 'SUCCEEDED', result_sha) == outcome)
            fd = receipts._open_private_directory(run)
            try:
                check()
                os.mkdir('candidate', mode=0o700, dir_fd=fd)
                os.fsync(fd)
                check()
                manifest = storage.persist_qualification_pdf_candidate(candidate=result,
                    directory=run / 'candidate', run_id=run_id, **expected)
                pdf, recovered = storage.read_qualification_pdf_candidate(
                    directory=run / 'candidate', run_id=run_id, **expected)
                _require(pdf == result.pdf_bytes and recovered == manifest)
                _require(receipts.read_job_receipt(run, run_id, 'SUCCEEDED', result_sha) == outcome)
                _unchanged(bound_request, arguments, binding, methodology_profile)
                _require(qualification._completed_digest(result, arguments, captured, source_bytes) == result_sha
                         and qualification._observation_bytes(result, observation,
                             observe_raster_children=True) == observation_bytes)
                check()
            finally:
                os.close(fd)
        return result, json.loads(observation_bytes), deepcopy(binding), deepcopy(manifest)
    except Exception:
        raise PdfBoundCandidateError('pdf_bound_candidate_execution_unverified') from None


def read_bound_qualification_pdf_candidate(
    bound_request: BoundReportRequest, *, directory: Path, run_id: str,
    expected_result_sha256: str, expected_pdf_sha256: str, expected_resource_profile_sha256: str,
    methodology_profile: str = 'source-only-v1',
) -> tuple[bytes, dict, dict]:
    """Read the exact candidate and rebuild its binding without generating or writing.

    Expected digests must come from separately retained evidence. Missing or partial
    storage refuses. This does not reconstruct process observations, authenticate
    source identity or establish historical sync, reboot survival or release.
    The caller must repeat the original methodology mode; no fallback is inferred.
    """
    try:
        arguments, binding = _prepare(
            bound_request, expected_resource_profile_sha256, methodology_profile)
        qualification._admit(arguments, directory, run_id)
        expected = _expectations(arguments, expected_result_sha256, expected_pdf_sha256)
        with qualification._run_directory(directory, run_id, create=False) as (run, check):
            outcome = receipts.read_job_receipt(run, run_id, 'SUCCEEDED', expected_result_sha256)
            pdf, manifest = storage.read_qualification_pdf_candidate(
                directory=run / 'candidate', run_id=run_id, **expected)
            _unchanged(bound_request, arguments, binding, methodology_profile)
            _require(receipts.read_job_receipt(run, run_id, 'SUCCEEDED', expected_result_sha256) == outcome)
            check()
            return pdf, deepcopy(manifest), deepcopy(binding)
    except Exception:
        raise PdfBoundCandidateError('pdf_bound_candidate_recovery_unverified') from None
