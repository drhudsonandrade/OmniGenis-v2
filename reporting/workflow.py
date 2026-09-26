"""RPT-09 case/sample/consent/review-state workflow contract.

This module binds administrative workflow state to explicit case and sample
identities. Consent verification is an upstream assertion: RPT-09 records its
identity and digest but does not decide legal or scientific consent scope.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

ROADMAP_ID = "RPT-09"


class WorkflowError(ValueError):
    """The reporting workflow state is malformed or unsupported."""


class ConsentStatus(StrEnum):
    """Status supplied by the upstream consent authority."""

    NOT_VERIFIED = "NOT_VERIFIED"
    VERIFIED = "VERIFIED"
    WITHDRAWN = "WITHDRAWN"


class ReviewState(StrEnum):
    """Explicit human-review lifecycle state for the reporting workflow."""

    PENDING = "PENDING"
    IN_REVIEW = "IN_REVIEW"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


@dataclass(frozen=True)
class ReportingWorkflow:
    """Immutable administrative state bound to one case and one sample."""

    roadmap_id: str
    case_id: str
    sample_id: str
    consent_status: ConsentStatus
    consent_record_id: str | None
    consent_record_sha256: str | None
    review_state: ReviewState
    release_ready: bool

    def to_dict(self) -> dict[str, Any]:
        """Return a deterministic JSON-compatible representation."""
        payload = asdict(self)
        payload["consent_status"] = self.consent_status.value
        payload["review_state"] = self.review_state.value
        return payload


def _required_identity(value: object, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise WorkflowError(f"{field} must be non-empty")
    return text


def _enum_value(enum_type: type[StrEnum], value: object, field: str) -> StrEnum:
    try:
        return enum_type(str(value))
    except ValueError as exc:
        allowed = [item.value for item in enum_type]
        raise WorkflowError(f"{field} must be one of {allowed}") from exc


def _sha256(value: object, field: str) -> str:
    text = str(value or "").strip().lower()
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise WorkflowError(f"{field} must be a 64-character hexadecimal SHA-256")
    return text


def build_reporting_workflow(
    *,
    case_id: object,
    sample_id: object,
    consent_status: ConsentStatus | str,
    review_state: ReviewState | str,
    consent_record_id: object | None = None,
    consent_record_sha256: object | None = None,
) -> ReportingWorkflow:
    """Build fail-closed RPT-09 administrative workflow state."""
    bound_case_id = _required_identity(case_id, "case_id")
    bound_sample_id = _required_identity(sample_id, "sample_id")
    bound_consent = _enum_value(ConsentStatus, consent_status, "consent_status")
    bound_review = _enum_value(ReviewState, review_state, "review_state")

    record_id: str | None = None
    record_sha256: str | None = None
    if bound_consent is ConsentStatus.VERIFIED:
        record_id = _required_identity(consent_record_id, "consent_record_id")
        record_sha256 = _sha256(consent_record_sha256, "consent_record_sha256")
    elif consent_record_id is not None or consent_record_sha256 is not None:
        raise WorkflowError(
            "consent record identity is only accepted when consent_status is VERIFIED"
        )

    return ReportingWorkflow(
        roadmap_id=ROADMAP_ID,
        case_id=bound_case_id,
        sample_id=bound_sample_id,
        consent_status=bound_consent,
        consent_record_id=record_id,
        consent_record_sha256=record_sha256,
        review_state=bound_review,
        release_ready=(
            bound_consent is ConsentStatus.VERIFIED
            and bound_review is ReviewState.APPROVED
        ),
    )
