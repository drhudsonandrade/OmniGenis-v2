"""Opt-in immutable request snapshots over existing reporting boundaries.

Expected and resolved metadata must come from authenticated upstream resolution.
This module binds their exact identities and sealed source/plan references. It
cannot authenticate the caller, validate control-artifact contents, establish
scientific completeness, qualify a locale/resource, or grant report release.
Consent and review states remain upstream assertions under the existing workflow.

Request identity is deterministic, not an idempotent storage or delivery service.
The initial profile keeps the existing technical report and en-US locale only.
No source bytes are decoded, rewritten, fetched or rendered. Source and plan
admission budgets remain enforced; oversized inputs fail rather than truncate.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json

from reporting.bindings import (
    BoundReportSources, ReportArtifactBinding, ReportBindingError,
    ReportSourceBinding, ReportSourceIdentity, _digest, _identity,
)
from reporting.completeness import ReportCompletenessError, ReportCompletenessPlan
from reporting.workflow import (
    ConsentStatus, ReviewState, WorkflowError, build_reporting_workflow,
)


class ReportRequestError(ValueError):
    """A fixed error code without source contents, identities or partial results."""


def _identifier(value: object) -> None:
    """Reuse the existing bounded identifier grammar without normalization."""
    try:
        _identity(value)
    except ReportBindingError:
        raise ReportRequestError('invalid_request_identifier') from None


def _sha256(value: object) -> None:
    """Require an exact canonical digest, never an uppercase or padded alias."""
    try:
        _digest(value)
    except ReportBindingError:
        raise ReportRequestError('invalid_request_digest') from None


def _reference(value: object) -> None:
    """Revalidate an actual immutable artifact reference, including direct inputs."""
    if type(value) is not ReportArtifactBinding:
        raise ReportRequestError('request_artifact_reference_required')
    try:
        ReportArtifactBinding.__post_init__(value)
    except ReportBindingError:
        raise ReportRequestError('invalid_request_artifact_reference') from None


def _source(value: object) -> None:
    """Check exact nested source metadata; its assertions still require an issuer."""
    if type(value) is not ReportSourceBinding:
        raise ReportRequestError('request_source_binding_required')
    try:
        ReportSourceBinding.__post_init__(value)
        if type(value.identity) is not ReportSourceIdentity:
            raise ReportBindingError('source_identity_required')
        ReportSourceIdentity.__post_init__(value.identity)
    except ReportBindingError:
        raise ReportRequestError('invalid_request_source_binding') from None
    if type(value.schema_version) is not str or value.schema_version != '1.0.0':
        raise ReportRequestError('request_source_version_not_supported')
    for reference in (value.input_artifact, value.canonical_result, value.evidence_snapshot):
        _reference(reference)


@dataclass(frozen=True, slots=True, repr=False)
class ReportRequestSnapshot:
    """Job-private request, control and profile metadata, not an approval grant.

    Unready consent/review states may be retained in a snapshot but cannot bind a
    usable request. A profile digest alone does not qualify its actual contents.
    """

    request_id: str
    requester_id: str
    source_binding: ReportSourceBinding
    completeness_plan_sha256: str
    report_contract_bundle_sha256: str
    locale_pack: ReportArtifactBinding
    policy_record: ReportArtifactBinding
    consent_status: ConsentStatus
    consent_record: ReportArtifactBinding | None
    review_state: ReviewState
    review_record: ReportArtifactBinding | None
    locale_id: str = 'en-US'
    intended_use_id: str = 'e1a-technical-validation'
    schema_version: str = field(default='1.0.0', init=False)

    def __post_init__(self) -> None:
        """Validate fixed-size metadata and preserve the existing workflow rules."""
        _identifier(self.request_id)
        _identifier(self.requester_id)
        _source(self.source_binding)
        _sha256(self.completeness_plan_sha256)
        _sha256(self.report_contract_bundle_sha256)
        if type(self.locale_id) is not str or self.locale_id != 'en-US':
            raise ReportRequestError('request_locale_not_supported')
        if type(self.intended_use_id) is not str or self.intended_use_id != 'e1a-technical-validation':
            raise ReportRequestError('request_intended_use_not_supported')
        if type(self.schema_version) is not str or self.schema_version != '1.0.0':
            raise ReportRequestError('request_schema_version_not_supported')
        if type(self.consent_status) is not ConsentStatus or type(self.review_state) is not ReviewState:
            raise ReportRequestError('request_workflow_enum_required')
        _reference(self.locale_pack)
        _reference(self.policy_record)
        for reference in (self.consent_record, self.review_record):
            if reference is not None:
                _reference(reference)
        if self.review_state is ReviewState.APPROVED and self.review_record is None:
            raise ReportRequestError('approved_review_reference_required')
        self._workflow()
        references = (self.source_binding.input_artifact, self.source_binding.canonical_result,
                      self.source_binding.evidence_snapshot, self.locale_pack, self.policy_record,
                      self.consent_record, self.review_record)
        ids = tuple(value.artifact_id for value in references if value is not None)
        if len(ids) != len(set(ids)):
            raise ReportRequestError('duplicate_request_artifact_role')

    def _workflow(self):
        """Use existing administrative invariants without exposing release_ready."""
        identity = self.source_binding.identity
        consent = self.consent_record
        try:
            return build_reporting_workflow(case_id=identity.case_id, sample_id=identity.sample_id,
                consent_status=self.consent_status, review_state=self.review_state,
                consent_record_id=consent.artifact_id if consent is not None else None,
                consent_record_sha256=consent.sha256 if consent is not None else None)
        except WorkflowError:
            raise ReportRequestError('request_workflow_invalid') from None

    def to_dict(self) -> dict[str, object]:
        """Return detached job-private metadata, never a source or policy payload."""
        return {
            'schema_version': self.schema_version,
            'request_id': self.request_id, 'requester_id': self.requester_id,
            'source_binding': self.source_binding.to_dict(),
            'completeness_plan_sha256': self.completeness_plan_sha256,
            'report_contract_bundle_sha256': self.report_contract_bundle_sha256,
            'locale_id': self.locale_id, 'intended_use_id': self.intended_use_id,
            'locale_pack': self.locale_pack.to_dict(), 'policy_record': self.policy_record.to_dict(),
            'consent_status': self.consent_status.value,
            'consent_record': self.consent_record.to_dict() if self.consent_record is not None else None,
            'review_state': self.review_state.value,
            'review_record': self.review_record.to_dict() if self.review_record is not None else None,
        }

    @property
    def request_sha256(self) -> str:
        """Hash all captured metadata using the established reporting encoding."""
        encoded = json.dumps(self.to_dict(), sort_keys=True, separators=(',', ':'),
                             ensure_ascii=False, allow_nan=False).encode('utf-8')
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class BoundReportRequest:
    """Consistent request/source/plan snapshot with no final-release authority."""

    request: ReportRequestSnapshot
    resolved_request: ReportRequestSnapshot
    sources: BoundReportSources
    plan: ReportCompletenessPlan

    def __post_init__(self) -> None:
        """Reject mismatches and unready states on every construction path."""
        if type(self.request) is not ReportRequestSnapshot or type(self.resolved_request) is not ReportRequestSnapshot:
            raise ReportRequestError('report_request_snapshot_required')
        ReportRequestSnapshot.__post_init__(self.request)
        ReportRequestSnapshot.__post_init__(self.resolved_request)
        if self.request != self.resolved_request:
            raise ReportRequestError('report_request_snapshot_mismatch')
        if type(self.sources) is not BoundReportSources or type(self.plan) is not ReportCompletenessPlan:
            raise ReportRequestError('request_bound_sources_and_plan_required')
        try:
            BoundReportSources.__post_init__(self.sources)
            ReportCompletenessPlan.__post_init__(self.plan)
        except (ReportBindingError, ReportCompletenessError):
            raise ReportRequestError('request_source_or_plan_invalid') from None
        if self.request.source_binding != self.sources.expected_binding:
            raise ReportRequestError('request_source_binding_mismatch')
        if self.plan.source_binding_sha256 != self.request.source_binding.binding_sha256:
            raise ReportRequestError('request_plan_source_mismatch')
        if self.plan.plan_sha256 != self.request.completeness_plan_sha256:
            raise ReportRequestError('request_completeness_plan_mismatch')
        if not self.request._workflow().release_ready:
            raise ReportRequestError('request_workflow_not_ready')

    def to_dict(self) -> dict[str, object]:
        """Expose content-free binding evidence, not a publish/delivery decision."""
        return {
            'status': 'BOUND', 'conformance_scope': 'REPORT_REQUEST_SNAPSHOT_BINDING_ONLY',
            'release_authorization': 'NOT_ESTABLISHED', 'upstream_authorization_validated': False,
            'request_sha256': self.request.request_sha256,
            'source_binding_sha256': self.request.source_binding.binding_sha256,
            'completeness_plan_sha256': self.plan.plan_sha256,
        }


def bind_report_request(
    *, request: ReportRequestSnapshot, resolved_request: ReportRequestSnapshot,
    sources: BoundReportSources, plan: ReportCompletenessPlan,
) -> BoundReportRequest:
    """Bind exact upstream snapshots without storage, rendering or release side effects."""
    return BoundReportRequest(request, resolved_request, sources, plan)
