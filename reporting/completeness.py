"""Opt-in source-bound accounting for a declared logical report projection.

Expected inventories, section requirements and exclusion-policy references must
come from authenticated, qualified upstream assembly. This module checks their
structural accounting; it does not extract an inventory from opaque source bytes,
authenticate policy issuers, decide scientific inclusion, inspect component
contents, or verify a rendered document. It cannot authorize report release.

Every declared finding is represented once or explicitly excluded upstream.
Required sections must be PRESENT in this initial profile; critical-section
waivers are not implemented. Optional absence remains explicit. Source order and
original immutable result/evidence bytes are preserved. Existing reporting APIs
and renderer profiles remain unchanged until an explicit integration is qualified.

Finite metadata-reference and identifier-byte budgets reject oversized input
whole. They are not editorial top-N rules and never truncate findings or pages.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json

from reporting.bindings import (
    BoundReportSources, ReportArtifactBinding, ReportBindingError, _digest, _identity,
)

MAX_LEDGER_REFERENCES = 100_000
MAX_LEDGER_IDENTIFIER_BYTES = 8 * 1024 * 1024
_AVAILABILITY = frozenset({"PRESENT", "NOT_MEASURED", "NOT_AVAILABLE",
                           "NOT_APPLICABLE", "BLOCKED", "UNKNOWN"})


class ReportCompletenessError(ValueError):
    """A fixed content-free code; no partial accounting evidence is returned."""


def _id(value: object) -> None:
    """Reuse the reporting boundary's exact bounded identifier grammar."""
    try:
        _identity(value)
    except ReportBindingError:
        raise ReportCompletenessError("invalid_accounting_identifier") from None


def _sha(value: object) -> None:
    """Require a canonical lowercase digest without normalization."""
    try:
        _digest(value)
    except ReportBindingError:
        raise ReportCompletenessError("invalid_accounting_digest") from None


def _admit_identifiers(*groups: tuple[str, ...]) -> None:
    """Bound immutable metadata before iterating or creating lookup collections."""
    if any(type(group) is not tuple for group in groups):
        raise ReportCompletenessError("immutable_accounting_tuple_required")
    if sum(len(group) for group in groups) > MAX_LEDGER_REFERENCES:
        raise ReportCompletenessError("accounting_budget_exceeded")
    size = 0
    for group in groups:
        for value in group:
            _id(value)
            size += len(value)  # The shared grammar admits ASCII identifiers only.
            if size > MAX_LEDGER_IDENTIFIER_BYTES:
                raise ReportCompletenessError("accounting_budget_exceeded")


def _records(value: object, kind: type) -> None:
    """Reject mutable iterables, subclasses and foreign records without coercion."""
    if type(value) is not tuple:
        raise ReportCompletenessError("immutable_accounting_tuple_required")
    if len(value) > MAX_LEDGER_REFERENCES:
        raise ReportCompletenessError("accounting_budget_exceeded")
    for item in value:
        if type(item) is not kind:
            raise ReportCompletenessError("typed_accounting_record_required")


def _hash(value: dict[str, object]) -> str:
    """Use the existing reporting canonical metadata encoding, not source recoding."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class FindingProjection:
    """One counted finding and its declared stable logical component references."""

    finding_id: str
    section_id: str
    component_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        """Require unique immutable locators; existence is verified downstream."""
        _id(self.finding_id)
        _id(self.section_id)
        _admit_identifiers(self.component_ids)
        if not self.component_ids or len(set(self.component_ids)) != len(self.component_ids):
            raise ReportCompletenessError("invalid_finding_component_references")

    def to_dict(self) -> dict[str, object]:
        """Return detached locator metadata for a job-private ledger."""
        return {"finding_id": self.finding_id, "section_id": self.section_id,
                "component_ids": list(self.component_ids)}


@dataclass(frozen=True, slots=True, repr=False)
class UpstreamFindingExclusion:
    """An explicit upstream disposition reference, not a locally approved policy."""

    finding_id: str
    policy_record: ReportArtifactBinding
    reason_code: str

    def __post_init__(self) -> None:
        """Retain exact policy identity and reason without interpreting either."""
        _id(self.finding_id)
        _id(self.reason_code)
        if type(self.policy_record) is not ReportArtifactBinding:
            raise ReportCompletenessError("exclusion_policy_reference_required")
        try:
            ReportArtifactBinding.__post_init__(self.policy_record)
        except ReportBindingError:
            raise ReportCompletenessError("invalid_exclusion_policy_reference") from None

    def to_dict(self) -> dict[str, object]:
        """Expose only the declared decision reference, never its private contents."""
        return {"finding_id": self.finding_id, "policy_record": self.policy_record.to_dict(),
                "reason_code": self.reason_code}


@dataclass(frozen=True, slots=True, repr=False)
class SectionAvailability:
    """An explicit source-defined section state and, for absence, a reason."""

    section_id: str
    availability: str
    reason_code: str | None = None

    def __post_init__(self) -> None:
        """Reject unknown enums, silent null absence and contradictory reasons."""
        _id(self.section_id)
        if type(self.availability) is not str or self.availability not in _AVAILABILITY:
            raise ReportCompletenessError("invalid_section_availability")
        if self.availability == "PRESENT":
            if self.reason_code is not None:
                raise ReportCompletenessError("contradictory_section_reason")
        else:
            _id(self.reason_code)

    def to_dict(self) -> dict[str, object]:
        """Preserve original availability; absence is not an inferred negative."""
        return {"section_id": self.section_id, "availability": self.availability,
                "reason_code": self.reason_code}


@dataclass(frozen=True, slots=True, repr=False)
class ReportCompletenessPlan:
    """Ordered expectations pinned to one exact source binding by upstream assembly.

    Expected finding IDs include both represented and upstream-excluded findings.
    This declaration does not prove that all scientific source records were listed.
    """

    source_binding_sha256: str
    expected_finding_ids: tuple[str, ...]
    expected_section_ids: tuple[str, ...]
    required_section_ids: tuple[str, ...]
    upstream_exclusions: tuple[UpstreamFindingExclusion, ...] = ()
    schema_version: str = field(default="1.0.0", init=False)

    def __post_init__(self) -> None:
        """Require a bounded, unambiguous source plan with explicit exclusions."""
        _sha(self.source_binding_sha256)
        _admit_identifiers(self.expected_finding_ids, self.expected_section_ids,
                           self.required_section_ids)
        _records(self.upstream_exclusions, UpstreamFindingExclusion)
        exclusion_ids = tuple(item.finding_id for item in self.upstream_exclusions)
        _admit_identifiers(self.expected_finding_ids, self.expected_section_ids,
            self.required_section_ids, exclusion_ids,
            tuple(item.policy_record.artifact_id for item in self.upstream_exclusions),
            tuple(item.policy_record.sha256 for item in self.upstream_exclusions),
            tuple(item.reason_code for item in self.upstream_exclusions))
        for item in self.upstream_exclusions:
            UpstreamFindingExclusion.__post_init__(item)
        groups = (self.expected_finding_ids, self.expected_section_ids,
                  self.required_section_ids, exclusion_ids)
        if any(len(set(values)) != len(values) for values in groups):
            raise ReportCompletenessError("duplicate_accounting_expectation")
        if not self.expected_section_ids:
            raise ReportCompletenessError("expected_sections_required")
        if not set(self.required_section_ids) <= set(self.expected_section_ids):
            raise ReportCompletenessError("unknown_required_section")
        if not set(exclusion_ids) <= set(self.expected_finding_ids):
            raise ReportCompletenessError("unknown_upstream_exclusion")

    def to_dict(self) -> dict[str, object]:
        """Return detached expectation metadata for private artifact storage."""
        return {"schema_version": self.schema_version,
                "source_binding_sha256": self.source_binding_sha256,
                "expected_finding_ids": list(self.expected_finding_ids),
                "expected_section_ids": list(self.expected_section_ids),
                "required_section_ids": list(self.required_section_ids),
                "upstream_exclusions": [item.to_dict() for item in self.upstream_exclusions]}

    @property
    def plan_sha256(self) -> str:
        """Bind ordered expectations and every upstream exclusion reference."""
        return _hash(self.to_dict())


@dataclass(frozen=True, slots=True, repr=False)
class ReportProjectionLedger:
    """Validated declared accounting, never proof of scientific or PDF completeness."""

    sources: BoundReportSources
    plan: ReportCompletenessPlan
    projection_source_binding_sha256: str
    projection_plan_sha256: str
    represented: tuple[FindingProjection, ...]
    section_states: tuple[SectionAvailability, ...]

    def __post_init__(self) -> None:
        """Enforce source, plan, order and complete accounting on every constructor."""
        if type(self.sources) is not BoundReportSources or type(self.plan) is not ReportCompletenessPlan:
            raise ReportCompletenessError("bound_sources_and_plan_required")
        try:
            BoundReportSources.__post_init__(self.sources)
        except ReportBindingError:
            raise ReportCompletenessError("source_integrity_invalid") from None
        ReportCompletenessPlan.__post_init__(self.plan)
        _sha(self.projection_source_binding_sha256)
        _sha(self.projection_plan_sha256)
        binding = self.sources.expected_binding.binding_sha256
        if binding != self.plan.source_binding_sha256 or binding != self.projection_source_binding_sha256:
            raise ReportCompletenessError("completeness_source_binding_mismatch")
        if self.projection_plan_sha256 != self.plan.plan_sha256:
            raise ReportCompletenessError("completeness_plan_mismatch")
        _records(self.represented, FindingProjection)
        _records(self.section_states, SectionAvailability)
        findings = tuple(item.finding_id for item in self.represented)
        sections = tuple(item.section_id for item in self.section_states)
        _admit_identifiers(findings, sections,
            tuple(item.section_id for item in self.represented),
            tuple(item.reason_code for item in self.section_states if item.reason_code is not None),
            *(item.component_ids for item in self.represented))
        for item in self.represented:
            FindingProjection.__post_init__(item)
        for item in self.section_states:
            SectionAvailability.__post_init__(item)
        if len(set(findings)) != len(findings):
            raise ReportCompletenessError("duplicate_finding_projection")
        if not set(findings) <= set(self.plan.expected_finding_ids):
            raise ReportCompletenessError("unknown_finding_projection")
        excluded = {item.finding_id for item in self.plan.upstream_exclusions}
        if set(findings) & excluded:
            raise ReportCompletenessError("excluded_finding_projected")
        expected = tuple(item for item in self.plan.expected_finding_ids if item not in excluded)
        if set(findings) != set(expected):
            raise ReportCompletenessError("finding_projection_incomplete")
        if findings != expected:
            raise ReportCompletenessError("finding_projection_order_mismatch")
        if len(set(sections)) != len(sections):
            raise ReportCompletenessError("duplicate_section_projection")
        if not set(sections) <= set(self.plan.expected_section_ids):
            raise ReportCompletenessError("unknown_section_projection")
        if set(sections) != set(self.plan.expected_section_ids):
            raise ReportCompletenessError("section_projection_incomplete")
        if sections != self.plan.expected_section_ids:
            raise ReportCompletenessError("section_projection_order_mismatch")
        present = {item.section_id for item in self.section_states if item.availability == "PRESENT"}
        if any(item.availability in {"BLOCKED", "UNKNOWN"} for item in self.section_states):
            raise ReportCompletenessError("unresolved_section_availability")
        if not set(self.plan.required_section_ids) <= present:
            raise ReportCompletenessError("required_section_not_present")
        if any(item.section_id not in present for item in self.represented):
            raise ReportCompletenessError("finding_section_not_present")

    def _counts(self) -> dict[str, int]:
        """Derive all totals from the exact records already verified together."""
        return {"expected_findings": len(self.plan.expected_finding_ids),
                "represented_findings": len(self.represented),
                "upstream_excluded_findings": len(self.plan.upstream_exclusions),
                "expected_sections": len(self.plan.expected_section_ids),
                "required_sections": len(self.plan.required_section_ids),
                "present_required_sections": len(self.plan.required_section_ids)}

    def to_dict(self) -> dict[str, object]:
        """Return detached job-private ledger metadata; never return source payloads."""
        return {"schema_version": "1.0.0", "report_id": self.sources.expected_binding.report_id,
                "status": "ACCOUNTED", "conformance_scope": "DECLARED_PROJECTION_ACCOUNTING_ONLY",
                "release_authorization": "NOT_ESTABLISHED", "source_inventory_validated": False,
                "rendered_content_validated": False,
                "source_binding_sha256": self.projection_source_binding_sha256,
                "plan_sha256": self.projection_plan_sha256, "plan": self.plan.to_dict(),
                "represented": [item.to_dict() for item in self.represented],
                "section_states": [item.to_dict() for item in self.section_states],
                "counts": self._counts()}

    @property
    def ledger_sha256(self) -> str:
        """Hash the complete ordered ledger and truthful validation scope."""
        return _hash(self.to_dict())

    def summary(self) -> dict[str, object]:
        """Return content-free evidence suitable for diagnostics, not a release flag."""
        return {"status": "ACCOUNTED", "conformance_scope": "DECLARED_PROJECTION_ACCOUNTING_ONLY",
                "release_authorization": "NOT_ESTABLISHED", "source_inventory_validated": False,
                "rendered_content_validated": False, "ledger_sha256": self.ledger_sha256,
                "source_binding_sha256": self.projection_source_binding_sha256,
                "plan_sha256": self.projection_plan_sha256, "counts": self._counts()}


def validate_report_completeness(
    *, sources: BoundReportSources, plan: ReportCompletenessPlan,
    projection_source_binding_sha256: str, projection_plan_sha256: str,
    represented: tuple[FindingProjection, ...], section_states: tuple[SectionAvailability, ...],
) -> ReportProjectionLedger:
    """Verify declared logical accounting without selecting findings or releasing a PDF."""
    return ReportProjectionLedger(sources, plan, projection_source_binding_sha256,
                                  projection_plan_sha256, represented, section_states)
