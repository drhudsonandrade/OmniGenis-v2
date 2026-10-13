"""Exact job-bound checkpoint transport for partial page-window metadata.

A checkpoint records a contiguous prefix of externally asserted observations.
It does not authenticate those observations, prove PDF inspection, persist data,
launch workers or grant release authority. The caller owns private storage and
must independently resolve the expected job, request, resource profile, plan and
checkpoint digest. A matching hash alone is not storage or tenant authentication.
Existing rendering limits and complete-ledger qualification remain unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json

from reporting.bindings import ReportBindingError, _digest, _identity
from reporting.page_windows import (
    MAX_WINDOWS, BoundPageWindowLedger, PageWindowError, PageWindowPlan,
    WindowObservation, WindowSpan, bind_pdf_page_window_evidence,
)

SCHEMA_VERSION = "1.0.0"
PROFILE_ID = "job-bound-page-checkpoint-v1"
MAX_CHECKPOINT_BYTES = 1024 * 1024
_OBSERVATION_FIELDS = frozenset((
    "index", "first_page", "last_page", "pdf_sha256", "plan_sha256",
    "inspector_profile_id", "observation_sha256",
))


class PageCheckpointError(ValueError):
    """Fixed, content-free rejection of unbound or malformed checkpoint metadata."""


def _validate_context(namespace_id: object, job_id: object,
                      request_sha256: object, resource_profile_sha256: object) -> None:
    """Reuse the established opaque identity and exact lowercase digest grammar."""
    try:
        _identity(namespace_id)
        _identity(job_id)
        _digest(request_sha256)
        _digest(resource_profile_sha256)
    except ReportBindingError:
        raise PageCheckpointError("checkpoint_context_invalid") from None


def _validate_plan(plan: object) -> None:
    """Require and revalidate the existing exact plan type before reading its data."""
    if type(plan) is not PageWindowPlan:
        raise PageCheckpointError("checkpoint_plan_required")
    try:
        plan.__post_init__()
    except (PageWindowError, AttributeError, TypeError):
        raise PageCheckpointError("checkpoint_plan_invalid") from None


def _json_bytes(value: object) -> bytes:
    """Serialize only validated metadata using the established canonical encoding."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject repeated JSON field names rather than applying last-value wins."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PageCheckpointError("checkpoint_duplicate_json_key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    """Reject nonfinite JSON extensions without returning their untrusted spelling."""
    raise PageCheckpointError("checkpoint_nonfinite_json")


@dataclass(frozen=True, slots=True, repr=False)
class PageWindowCheckpoint:
    """Immutable job-owned metadata prefix, never evidence of native completion."""

    plan: PageWindowPlan
    namespace_id: str
    job_id: str
    request_sha256: str
    resource_profile_sha256: str
    observations: tuple[WindowObservation, ...]

    def __post_init__(self) -> None:
        """Enforce native types, bounded counts and every exact prefix binding."""
        _validate_context(self.namespace_id, self.job_id, self.request_sha256,
                          self.resource_profile_sha256)
        if type(self.observations) is not tuple or len(self.observations) > MAX_WINDOWS:
            raise PageCheckpointError("checkpoint_observation_budget_or_type_invalid")
        _validate_plan(self.plan)
        if len(self.observations) > self.plan.window_count:
            raise PageCheckpointError("checkpoint_prefix_overflow")
        prefix = self.plan.windows[:len(self.observations)]
        for span, observation in zip(prefix, self.observations, strict=True):
            if type(observation) is not WindowObservation:
                raise PageCheckpointError("checkpoint_observation_type_invalid")
            try:
                observation.__post_init__()
            except (PageWindowError, AttributeError, TypeError):
                raise PageCheckpointError("checkpoint_observation_invalid") from None
            if (
                observation.index != span.index
                or observation.first_page != span.first_page
                or observation.last_page != span.last_page
                or observation.pdf_sha256 != self.plan.pdf_sha256
                or observation.plan_sha256 != self.plan.plan_sha256
                or observation.inspector_profile_id != self.plan.inspector_profile_id
            ):
                raise PageCheckpointError("checkpoint_prefix_binding_mismatch")

    @property
    def remaining_windows(self) -> tuple[WindowSpan, ...]:
        """Return the unrecorded suffix, without implying earlier windows were checked."""
        self.__post_init__()
        return self.plan.windows[len(self.observations):]

    def to_dict(self) -> dict[str, object]:
        """Detach the canonical transport record with explicit unqualified guarantees."""
        self.__post_init__()
        return {
            "schema_version": SCHEMA_VERSION,
            "profile_id": PROFILE_ID,
            "status": "STAGED_UNQUALIFIED",
            "conformance_scope": "EXACT_JOB_PLAN_AND_PREFIX_METADATA_ONLY",
            "namespace_id": self.namespace_id,
            "job_id": self.job_id,
            "request_sha256": self.request_sha256,
            "resource_profile_sha256": self.resource_profile_sha256,
            "pdf_sha256": self.plan.pdf_sha256,
            "ir_sha256": self.plan.ir_sha256,
            "window_plan_sha256": self.plan.plan_sha256,
            "inspector_profile_id": self.plan.inspector_profile_id,
            "page_count": self.plan.page_count,
            "admitted_page_budget": self.plan.admitted_page_budget,
            "pages_per_window": self.plan.pages_per_window,
            "window_count": self.plan.window_count,
            "recorded_window_count": len(self.observations),
            "observations": [item.to_dict() for item in self.observations],
            "worker_results_authenticated": False,
            "checkpoint_storage_authenticated": False,
            "native_resume_performed": False,
            "whole_pdf_safety_qualified": False,
            "release_authorization": "NOT_ESTABLISHED",
        }

    def to_bytes(self) -> bytes:
        """Return canonical UTF-8 within a finite admission bound, never a truncation."""
        payload = _json_bytes(self.to_dict())
        if len(payload) > MAX_CHECKPOINT_BYTES:
            raise PageCheckpointError("checkpoint_byte_budget_exceeded")
        return payload

    @property
    def checkpoint_sha256(self) -> str:
        """Hash the current validated record; external storage must pin this separately."""
        return hashlib.sha256(self.to_bytes()).hexdigest()

    def append_observations(
        self, observations: tuple[WindowObservation, ...],
    ) -> PageWindowCheckpoint:
        """Return a new contiguous prefix without replacing or mutating retained data."""
        self.__post_init__()
        if type(observations) is not tuple:
            raise PageCheckpointError("checkpoint_append_tuple_required")
        if len(observations) > self.plan.window_count - len(self.observations):
            raise PageCheckpointError("checkpoint_append_overflow")
        return replace(self, observations=self.observations + observations)

    def as_complete_ledger(self) -> BoundPageWindowLedger:
        """Delegate complete metadata to the existing ledger; reject an incomplete prefix."""
        self.__post_init__()
        if len(self.observations) != self.plan.window_count:
            raise PageCheckpointError("checkpoint_prefix_incomplete")
        return bind_pdf_page_window_evidence(plan=self.plan, observations=self.observations)


def resume_page_checkpoint(
    *, checkpoint_bytes: object, expected_checkpoint_sha256: object,
    expected_plan: PageWindowPlan, namespace_id: str, job_id: str,
    expected_request_sha256: str, expected_resource_profile_sha256: str,
) -> PageWindowCheckpoint:
    """Restore only exact canonical bytes bound to independently resolved expectations.

    This function does not locate the latest checkpoint, enforce monotonic storage
    versions, reauthorize a job or execute pending work. Storage must authenticate
    the pinned digest and reject rollback before supplying these expected values.
    """
    if type(checkpoint_bytes) is not bytes or not 0 < len(checkpoint_bytes) <= MAX_CHECKPOINT_BYTES:
        raise PageCheckpointError("checkpoint_bytes_or_budget_invalid")
    try:
        _digest(expected_checkpoint_sha256)
    except ReportBindingError:
        raise PageCheckpointError("checkpoint_expected_digest_invalid") from None
    _validate_context(namespace_id, job_id, expected_request_sha256,
                      expected_resource_profile_sha256)
    _validate_plan(expected_plan)
    if hashlib.sha256(checkpoint_bytes).hexdigest() != expected_checkpoint_sha256:
        raise PageCheckpointError("checkpoint_digest_mismatch")
    try:
        record = json.loads(checkpoint_bytes.decode("utf-8"),
                            object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise PageCheckpointError("checkpoint_json_invalid") from None
    if type(record) is not dict or type(record.get("observations")) is not list:
        raise PageCheckpointError("checkpoint_record_invalid")
    values = record["observations"]
    if len(values) > expected_plan.window_count:
        raise PageCheckpointError("checkpoint_prefix_overflow")
    observations: list[WindowObservation] = []
    for value in values:
        if type(value) is not dict or value.keys() != _OBSERVATION_FIELDS:
            raise PageCheckpointError("checkpoint_observation_fields_invalid")
        try:
            observations.append(WindowObservation(**value))
        except (PageWindowError, TypeError):
            raise PageCheckpointError("checkpoint_observation_invalid") from None
    checkpoint = PageWindowCheckpoint(
        plan=expected_plan, namespace_id=namespace_id, job_id=job_id,
        request_sha256=expected_request_sha256,
        resource_profile_sha256=expected_resource_profile_sha256,
        observations=tuple(observations),
    )
    if checkpoint.to_bytes() != checkpoint_bytes:
        raise PageCheckpointError("checkpoint_context_or_encoding_mismatch")
    return checkpoint
