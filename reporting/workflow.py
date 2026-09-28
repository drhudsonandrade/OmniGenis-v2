"""RPT-09 case/sample/consent/review-state workflow contract.

This module binds administrative workflow state to explicit case and sample
identities. Consent verification is an upstream assertion: RPT-09 records its
identity and digest but does not decide legal or scientific consent scope.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
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
    consent_status: ConsentStatus | str
    consent_record_id: str | None
    consent_record_sha256: str | None
    review_state: ReviewState | str
    release_ready: bool = field(init=False)

    def __post_init__(self) -> None:
        """Normalize inputs and enforce fail-closed workflow invariants."""
        if self.roadmap_id != ROADMAP_ID:
            raise WorkflowError(f"roadmap_id must be {ROADMAP_ID!r}")

        bound_case_id = _required_identity(self.case_id, "case_id")
        bound_sample_id = _required_identity(self.sample_id, "sample_id")
        bound_consent = _enum_value(ConsentStatus, self.consent_status, "consent_status")
        bound_review = _enum_value(ReviewState, self.review_state, "review_state")

        record_id: str | None = None
        record_sha256: str | None = None
        if bound_consent is ConsentStatus.VERIFIED:
            record_id = _required_identity(self.consent_record_id, "consent_record_id")
            record_sha256 = _sha256(
                self.consent_record_sha256,
                "consent_record_sha256",
            )
        elif self.consent_record_id is not None or self.consent_record_sha256 is not None:
            raise WorkflowError(
                "consent record identity is only accepted when consent_status is VERIFIED"
            )

        object.__setattr__(self, "case_id", bound_case_id)
        object.__setattr__(self, "sample_id", bound_sample_id)
        object.__setattr__(self, "consent_status", bound_consent)
        object.__setattr__(self, "consent_record_id", record_id)
        object.__setattr__(self, "consent_record_sha256", record_sha256)
        object.__setattr__(self, "review_state", bound_review)
        object.__setattr__(
            self,
            "release_ready",
            bound_consent is ConsentStatus.VERIFIED
            and bound_review is ReviewState.APPROVED,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a deterministic JSON-compatible representation."""
        payload = asdict(self)
        payload["consent_status"] = self.consent_status.value
        payload["review_state"] = self.review_state.value
        return payload


def _required_identity(value: object, field: str) -> str:
    """Normalize a required identity field or fail closed when it is empty."""
    text = str(value or "").strip()
    if not text:
        raise WorkflowError(f"{field} must be non-empty")
    return text


def _enum_value(enum_type: type[StrEnum], value: object, field: str) -> StrEnum:
    """Normalize a controlled workflow state or reject unsupported values."""
    try:
        return enum_type(str(value))
    except ValueError as exc:
        allowed = [item.value for item in enum_type]
        raise WorkflowError(f"{field} must be one of {allowed}") from exc


def _sha256(value: object, field: str) -> str:
    """Normalize and validate a hexadecimal SHA-256 identity."""
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
    return ReportingWorkflow(
        roadmap_id=ROADMAP_ID,
        case_id=case_id,
        sample_id=sample_id,
        consent_status=consent_status,
        consent_record_id=consent_record_id,
        consent_record_sha256=consent_record_sha256,
        review_state=review_state,
    )
