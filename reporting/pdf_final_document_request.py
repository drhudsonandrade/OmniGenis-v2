"""Bound caller snapshots for one explicit complete technical-document operation.

The fixed frame carries both upstream request/source assertions, the complete
plan and exact immutable source/resource bytes. Independent caller expectations
bind integrity, not origin, consent, scientific validity or release authority.
The existing canonical-result admission rule remains required; opaque evidence
bytes are never decoded or rewritten by this transport.

The consumer admits the complete frame before invoking the existing observed
private store once. Output paths and run identity remain separate caller inputs.
No host admission, aggregate enforcement, supported executor, retry, new storage
format, scientific activation or FINAL publication is established here. Explicit
recovery remains the existing reader with independently trusted output digests.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import struct

from reporting import pdf_final_document_candidate as final
from reporting import pdf_raster_resources as raster_resources
from reporting.bindings import (
    BoundReportSources, MAX_SNAPSHOT_BYTES, ReportArtifactBinding,
    ReportSourceBinding, ReportSourceIdentity, _digest,
)
from reporting.completeness import ReportCompletenessPlan
from reporting.requests import BoundReportRequest, ReportRequestSnapshot
from reporting.workflow import ConsentStatus, ReviewState

SCHEMA = 'source-bound-final-document-request/v1'
CANDIDATE_PROFILE_SHA256 = '93b440c41d025cc39645ddc66764577fad414fbb3b471662afb89d2763f39ab7'
STORAGE_PROFILE_SHA256 = 'bc9c3fb920cc2ab6ce8f784ff54f1cf544b999fda082f4edac99979d1d315368'
_MAGIC = b'OFD1'
_HEADER_BYTES = 8
_VERSION = '1.0.0'
_SECTIONS = final.previous.bound_source._SECTIONS
_SEGMENTS = ('canonical_result', 'evidence_snapshot', 'resources')
_SEGMENT_LIMITS = (MAX_SNAPSHOT_BYTES, MAX_SNAPSHOT_BYTES,
                   raster_resources.MAX_BUNDLE_BYTES)
_IDENTITY_FIELDS = ('namespace_id', 'case_id', 'subject_id', 'sample_id',
                    'analysis_id', 'analysis_revision', 'specimen_id')
_REFERENCE_FIELDS = frozenset(('artifact_id', 'sha256'))
_SOURCE_FIELDS = frozenset(('schema_version', 'report_id', 'identity',
    'input_artifact', 'canonical_result', 'evidence_snapshot', 'reference_bundle_sha256'))
_REQUEST_FIELDS = frozenset(('schema_version', 'request_id', 'requester_id',
    'source_binding', 'completeness_plan_sha256', 'report_contract_bundle_sha256',
    'locale_id', 'intended_use_id', 'locale_pack', 'policy_record', 'consent_status',
    'consent_record', 'review_state', 'review_record'))
_PLAN_FIELDS = frozenset(('schema_version', 'source_binding_sha256',
    'expected_finding_ids', 'expected_section_ids', 'required_section_ids',
    'upstream_exclusions'))
_FRAME_FIELDS = frozenset(('schema', 'request', 'resolved_request',
    'expected_source_binding', 'resolved_source_binding', 'plan',
    'resource_profile_sha256', 'storage_profile_sha256', 'segments'))


class PdfFinalDocumentRequestError(ValueError):
    """A fixed content-free refusal without caller data or partial results."""


def _require(condition: bool) -> None:
    """Reject an unestablished invariant without reflecting its input."""
    if not condition:
        raise PdfFinalDocumentRequestError('pdf_final_document_request_invalid')


def _canonical(value: object) -> bytes:
    """Use the unchanged reporting compact UTF-8 JSON representation."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def _metadata(request: dict, resolved_request: dict, expected_source: dict,
              resolved_source: dict, plan: dict, segments: dict,
              resource_profile: str, storage_profile: str) -> dict:
    """Keep the fixed transport roles explicit and independent of storage paths."""
    return {'schema': SCHEMA, 'request': request, 'resolved_request': resolved_request,
        'expected_source_binding': expected_source, 'resolved_source_binding': resolved_source,
        'plan': plan, 'resource_profile_sha256': resource_profile,
        'storage_profile_sha256': storage_profile, 'segments': segments}


def _maximum_metadata_bytes() -> int:
    """Derive the closed metadata ceiling from existing identifier and scope bounds.

    The existing binding grammar allows 256 ASCII bytes per identifier. Four
    complete source bindings, two ready request snapshots, the fixed section
    lists and at most the existing complete-operation finding count are retained.
    Maximum segment sizes contribute their exact decimal widths. This is a
    structural encoding bound, not a second workload or source-content policy.
    """
    digest = 'f' * 64
    def identity(role: str) -> str:
        """Use distinct maximum-width inherited identifiers in the bound shape."""
        return role.ljust(256, 'x')
    def reference(role: str) -> dict:
        """Account for every ready request's distinct artifact role."""
        return {'artifact_id': identity(role), 'sha256': digest}
    source = {'schema_version': _VERSION, 'report_id': 'e1a-small-variant-report',
        'identity': {key: identity(key) for key in _IDENTITY_FIELDS},
        'input_artifact': reference('input'), 'canonical_result': reference('canonical'),
        'evidence_snapshot': reference('evidence'), 'reference_bundle_sha256': digest}
    request = {'schema_version': _VERSION, 'request_id': identity('request'),
        'requester_id': identity('requester'), 'source_binding': source,
        'completeness_plan_sha256': digest, 'report_contract_bundle_sha256': digest,
        'locale_id': 'en-US', 'intended_use_id': 'e1a-technical-validation',
        'locale_pack': reference('locale'), 'policy_record': reference('policy'),
        'consent_status': 'VERIFIED', 'consent_record': reference('consent'),
        'review_state': 'APPROVED', 'review_record': reference('review')}
    plan = {'schema_version': _VERSION, 'source_binding_sha256': digest,
        'expected_finding_ids': [identity('finding-' + str(index))
                                 for index in range(final.MAX_FINDINGS)],
        'expected_section_ids': list(_SECTIONS), 'required_section_ids': list(_SECTIONS),
        'upstream_exclusions': []}
    segments = {name: {'bytes': limit, 'sha256': digest}
                for name, limit in zip(_SEGMENTS, _SEGMENT_LIMITS)}
    return len(_canonical(_metadata(request, request, source, source, plan,
                                    segments, digest, digest)))


MAX_METADATA_BYTES = _maximum_metadata_bytes()
MAX_REQUEST_BYTES = _HEADER_BYTES + MAX_METADATA_BYTES + sum(_SEGMENT_LIMITS)


def _record(value: object, fields) -> dict:
    """Reject missing and unknown keys before explicit domain reconstruction."""
    _require(type(value) is dict and set(value) == set(fields))
    return value


def _versioned(value: object, fields) -> dict:
    """Retain the existing exact schema version instead of accepting aliases."""
    record = _record(value, fields)
    _require(type(record['schema_version']) is str and record['schema_version'] == _VERSION)
    return record


def _reference(value: object) -> ReportArtifactBinding:
    """Reconstruct the existing strict identifier/digest reference."""
    record = _record(value, _REFERENCE_FIELDS)
    return ReportArtifactBinding(record['artifact_id'], record['sha256'])


def _optional_reference(value: object) -> ReportArtifactBinding | None:
    """Preserve explicit absence; workflow admission decides whether it is ready."""
    return None if value is None else _reference(value)


def _source_binding(value: object) -> ReportSourceBinding:
    """Reconstruct every source role without coercion or dynamic field dispatch."""
    record = _versioned(value, _SOURCE_FIELDS)
    identity = _record(record['identity'], _IDENTITY_FIELDS)
    return ReportSourceBinding(
        ReportSourceIdentity(identity['namespace_id'], identity['case_id'],
            identity['subject_id'], identity['sample_id'], identity['analysis_id'],
            identity['analysis_revision'], identity['specimen_id']),
        _reference(record['input_artifact']), _reference(record['canonical_result']),
        _reference(record['evidence_snapshot']), record['reference_bundle_sha256'],
        report_id=record['report_id'])


def _request(value: object) -> ReportRequestSnapshot:
    """Use existing request and administrative workflow validation unchanged."""
    record = _versioned(value, _REQUEST_FIELDS)
    _require(type(record['consent_status']) is str and type(record['review_state']) is str)
    return ReportRequestSnapshot(request_id=record['request_id'],
        requester_id=record['requester_id'], source_binding=_source_binding(record['source_binding']),
        completeness_plan_sha256=record['completeness_plan_sha256'],
        report_contract_bundle_sha256=record['report_contract_bundle_sha256'],
        locale_pack=_reference(record['locale_pack']), policy_record=_reference(record['policy_record']),
        consent_status=ConsentStatus(record['consent_status']),
        consent_record=_optional_reference(record['consent_record']),
        review_state=ReviewState(record['review_state']),
        review_record=_optional_reference(record['review_record']),
        locale_id=record['locale_id'], intended_use_id=record['intended_use_id'])


def _plan(value: object) -> ReportCompletenessPlan:
    """Admit only the existing complete-operation inventory and fixed sections."""
    record = _versioned(value, _PLAN_FIELDS)
    findings = record['expected_finding_ids']
    _require(type(findings) is list and len(findings) <= final.MAX_FINDINGS)
    for field in ('expected_section_ids', 'required_section_ids'):
        _require(type(record[field]) is list and record[field] == list(_SECTIONS))
    _require(type(record['upstream_exclusions']) is list and not record['upstream_exclusions'])
    return ReportCompletenessPlan(record['source_binding_sha256'], tuple(findings),
        tuple(record['expected_section_ids']), tuple(record['required_section_ids']), ())


def _plan_scope(plan: ReportCompletenessPlan) -> None:
    """Bound retained typed inputs before their metadata can be materialized."""
    _require(type(plan) is ReportCompletenessPlan and plan.schema_version == _VERSION
        and type(plan.expected_finding_ids) is tuple
        and len(plan.expected_finding_ids) <= final.MAX_FINDINGS
        and type(plan.expected_section_ids) is tuple and plan.expected_section_ids == _SECTIONS
        and type(plan.required_section_ids) is tuple and plan.required_section_ids == _SECTIONS
        and type(plan.upstream_exclusions) is tuple and not plan.upstream_exclusions)


def _profiles(resource_profile: str, storage_profile: str) -> None:
    """Select the pinned old profiles and retain their inherited disable chain."""
    _digest(resource_profile)
    _digest(storage_profile)
    _require(resource_profile == CANDIDATE_PROFILE_SHA256
             and storage_profile == STORAGE_PROFILE_SHA256)
    final._storage_profile(storage_profile)


def _unique(pairs) -> dict:
    """Reject duplicate JSON keys before any earlier value can be discarded."""
    result = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def _invalid_number(_value):
    """Reject floating-point and nonfinite metadata without reflecting its text."""
    raise PdfFinalDocumentRequestError('pdf_final_document_request_invalid')


def _decode(request_bytes: bytes, *, expected_envelope_sha256: str,
            expected_request_sha256: str, expected_resources_sha256: str,
            expected_resource_profile_sha256: str,
            expected_storage_profile_sha256: str) -> tuple[BoundReportRequest,
                                                          raster_resources.RasterBundle]:
    """Validate bounded framing before reconstructing or projecting any request."""
    for digest in (expected_envelope_sha256, expected_request_sha256,
                   expected_resources_sha256, expected_resource_profile_sha256,
                   expected_storage_profile_sha256):
        _digest(digest)
    _require(type(request_bytes) is bytes and _HEADER_BYTES <= len(request_bytes) <= MAX_REQUEST_BYTES
             and request_bytes[:4] == _MAGIC)
    size = struct.unpack_from('>I', request_bytes, 4)[0]
    _require(0 < size <= MAX_METADATA_BYTES and _HEADER_BYTES + size < len(request_bytes))
    _require(sha256(request_bytes).hexdigest() == expected_envelope_sha256)
    raw_metadata = request_bytes[_HEADER_BYTES:_HEADER_BYTES + size]
    metadata = _record(json.loads(raw_metadata, object_pairs_hook=_unique,
        parse_float=_invalid_number, parse_constant=_invalid_number), _FRAME_FIELDS)
    _require(metadata['schema'] == SCHEMA and _canonical(metadata) == raw_metadata)
    segments = _record(metadata['segments'], _SEGMENTS)
    counts = []
    for name, limit in zip(_SEGMENTS, _SEGMENT_LIMITS):
        segment = _record(segments[name], ('bytes', 'sha256'))
        count = segment['bytes']
        _require(type(count) is int and 0 < count <= limit)
        _digest(segment['sha256'])
        counts.append(count)
    _require(_HEADER_BYTES + size + sum(counts) == len(request_bytes))
    _require(segments['resources']['sha256'] == expected_resources_sha256)
    _require(metadata['resource_profile_sha256'] == expected_resource_profile_sha256
             and metadata['storage_profile_sha256'] == expected_storage_profile_sha256)
    _profiles(expected_resource_profile_sha256, expected_storage_profile_sha256)
    position = _HEADER_BYTES + size
    parts = []
    for name, count in zip(_SEGMENTS, counts):
        raw = request_bytes[position:position + count]
        _require(sha256(raw).hexdigest() == segments[name]['sha256'])
        parts.append(raw)
        position += count
    plan = _plan(metadata['plan'])
    sources = BoundReportSources(_source_binding(metadata['expected_source_binding']),
        _source_binding(metadata['resolved_source_binding']), parts[0], parts[1])
    bound = BoundReportRequest(_request(metadata['request']),
        _request(metadata['resolved_request']), sources, plan)
    _require(bound.request.request_sha256 == expected_request_sha256)
    resources = raster_resources.read_bundle(parts[2], expected_sha256=expected_resources_sha256)
    # Existing complete projection checks canonical source syntax, full inventory,
    # actual contract/locale pins, qualification policy and every inherited flag.
    # It creates no attempt directory and launches no renderer or native child.
    final._inputs(bound_request=bound, resources=resources,
        expected_request_sha256=expected_request_sha256,
        expected_resources_sha256=expected_resources_sha256,
        expected_resource_profile_sha256=expected_resource_profile_sha256)
    return bound, resources


def encode_final_document_request(*, bound_request: BoundReportRequest,
        resources: raster_resources.RasterBundle, expected_resource_profile_sha256: str,
        expected_storage_profile_sha256: str) -> bytes:
    """Capture an exact admitted request without normalizing its source bytes."""
    try:
        _require(type(bound_request) is BoundReportRequest
                 and type(resources) is raster_resources.RasterBundle)
        _plan_scope(bound_request.plan)
        BoundReportRequest.__post_init__(bound_request)
        _profiles(expected_resource_profile_sha256, expected_storage_profile_sha256)
        parts = (bound_request.sources.canonical_result_bytes,
                 bound_request.sources.evidence_snapshot_bytes, resources.to_bytes())
        segments = {name: {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
                    for name, raw in zip(_SEGMENTS, parts)}
        metadata = _metadata(bound_request.request.to_dict(), bound_request.resolved_request.to_dict(),
            bound_request.sources.expected_binding.to_dict(),
            bound_request.sources.resolved_binding.to_dict(), bound_request.plan.to_dict(),
            segments, expected_resource_profile_sha256, expected_storage_profile_sha256)
        raw_metadata = _canonical(metadata)
        _require(0 < len(raw_metadata) <= MAX_METADATA_BYTES)
        raw = _MAGIC + struct.pack('>I', len(raw_metadata)) + raw_metadata + b''.join(parts)
        # Reconstruct the captured frame before returning it. This validates its
        # exact bytes rather than assuming that retained mutable aliases stayed
        # consistent throughout capture. Same-owner hostile execution is not an
        # authenticated boundary or a supported host-admission mechanism.
        _decode(raw, expected_envelope_sha256=sha256(raw).hexdigest(),
            expected_request_sha256=sha256(_canonical(metadata['request'])).hexdigest(),
            expected_resources_sha256=segments['resources']['sha256'],
            expected_resource_profile_sha256=expected_resource_profile_sha256,
            expected_storage_profile_sha256=expected_storage_profile_sha256)
        return raw
    except Exception:
        raise PdfFinalDocumentRequestError('pdf_final_document_request_capture_invalid') from None


def decode_final_document_request(request_bytes: bytes, *, expected_envelope_sha256: str,
        expected_request_sha256: str, expected_resources_sha256: str,
        expected_resource_profile_sha256: str, expected_storage_profile_sha256: str
) -> tuple[BoundReportRequest, raster_resources.RasterBundle]:
    """Decode one immutable snapshot against independently retained expectations."""
    try:
        return _decode(request_bytes, expected_envelope_sha256=expected_envelope_sha256,
            expected_request_sha256=expected_request_sha256,
            expected_resources_sha256=expected_resources_sha256,
            expected_resource_profile_sha256=expected_resource_profile_sha256,
            expected_storage_profile_sha256=expected_storage_profile_sha256)
    except Exception:
        raise PdfFinalDocumentRequestError('pdf_final_document_request_invalid') from None


def execute_stored_final_document_request(request_bytes: bytes, *, expected_envelope_sha256: str,
        expected_request_sha256: str, expected_resources_sha256: str,
        expected_resource_profile_sha256: str, expected_storage_profile_sha256: str,
        directory: Path, run_id: str) -> tuple[bytes, dict, dict]:
    """Admit the complete packet before one fixed existing stored operation.

    The inherited store owns claims, receipt-last commit and explicit recovery.
    Failure returns no partial success and causes no automatic retry or cleanup
    of a candidate that the existing store may already have committed.
    """
    try:
        bound, resources = _decode(request_bytes,
            expected_envelope_sha256=expected_envelope_sha256,
            expected_request_sha256=expected_request_sha256,
            expected_resources_sha256=expected_resources_sha256,
            expected_resource_profile_sha256=expected_resource_profile_sha256,
            expected_storage_profile_sha256=expected_storage_profile_sha256)
        return final.execute_observed_stored_final_document_candidate(
            bound_request=bound, resources=resources,
            expected_request_sha256=expected_request_sha256,
            expected_resources_sha256=expected_resources_sha256,
            expected_resource_profile_sha256=expected_resource_profile_sha256,
            expected_storage_profile_sha256=expected_storage_profile_sha256,
            directory=directory, run_id=run_id)
    except Exception:
        raise PdfFinalDocumentRequestError('pdf_final_document_request_execution_unverified') from None
