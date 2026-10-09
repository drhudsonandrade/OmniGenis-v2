"""Opt-in identity and byte-integrity binding for sealed report sources.

Callers must obtain expected metadata and sealed artifacts through authenticated
upstream resolution. Comparing matching metadata and hashes does not establish
origin, ownership, JSON/schema validity, scientific validation, consent, or release
authority. This module does not implement the storage transaction that seals data.

Canonical result and evidence bytes are deliberately opaque: they are neither
decoded nor re-serialized, so scientific values retain their original precision.
The finite per-snapshot admission budget is not an editorial page or finding
limit. Oversized sources are rejected whole, never truncated. Existing reporting
APIs and renderer profiles are unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re

from reporting.contracts import REPORT_ID

MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")
_DIGEST = re.compile(r"[0-9a-f]{64}")


class ReportBindingError(ValueError):
    """A fixed diagnostic code with no source payload or identity values."""


def _identity(value: object) -> None:
    """Require a bounded opaque identifier without coercion or normalization."""
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ReportBindingError("invalid_source_identity")


def _digest(value: object) -> None:
    """Require exact lowercase SHA-256 notation, not a normalized hint."""
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ReportBindingError("invalid_artifact_digest")


@dataclass(frozen=True, slots=True, repr=False)
class ReportSourceIdentity:
    """Explicit ownership/context tuple supplied by upstream source resolution."""

    namespace_id: str
    case_id: str
    subject_id: str
    sample_id: str
    analysis_id: str
    analysis_revision: str
    specimen_id: str | None

    def __post_init__(self) -> None:
        """Reject missing or coerced identities, including direct construction."""
        for value in (self.namespace_id, self.case_id, self.subject_id,
                      self.sample_id, self.analysis_id, self.analysis_revision):
            _identity(value)
        if self.specimen_id is not None:
            _identity(self.specimen_id)

    def to_dict(self) -> dict[str, str | None]:
        """Return detached metadata; an unknown specimen remains explicit."""
        return {
            "namespace_id": self.namespace_id, "case_id": self.case_id,
            "subject_id": self.subject_id, "sample_id": self.sample_id,
            "analysis_id": self.analysis_id, "analysis_revision": self.analysis_revision,
            "specimen_id": self.specimen_id,
        }


@dataclass(frozen=True, slots=True, repr=False)
class ReportArtifactBinding:
    """Artifact identifier and exact digest from a sealed upstream reference."""

    artifact_id: str
    sha256: str

    def __post_init__(self) -> None:
        """Validate references without reading files or contacting providers."""
        _identity(self.artifact_id)
        _digest(self.sha256)

    def to_dict(self) -> dict[str, str]:
        """Return detached reference metadata, never artifact content."""
        return {"artifact_id": self.artifact_id, "sha256": self.sha256}


@dataclass(frozen=True, slots=True, repr=False)
class ReportSourceBinding:
    """Versioned, single-sample source context for the existing technical report."""

    identity: ReportSourceIdentity
    input_artifact: ReportArtifactBinding
    canonical_result: ReportArtifactBinding
    evidence_snapshot: ReportArtifactBinding
    reference_bundle_sha256: str
    report_id: str = REPORT_ID
    schema_version: str = field(default="1.0.0", init=False)

    def __post_init__(self) -> None:
        """Require strict nested types and distinguish all three artifact roles."""
        if type(self.identity) is not ReportSourceIdentity:
            raise ReportBindingError("report_source_identity_required")
        references = (self.input_artifact, self.canonical_result, self.evidence_snapshot)
        if any(type(value) is not ReportArtifactBinding for value in references):
            raise ReportBindingError("report_artifact_binding_required")
        if len({value.artifact_id for value in references}) != len(references):
            raise ReportBindingError("duplicate_artifact_identity")
        _digest(self.reference_bundle_sha256)
        if type(self.report_id) is not str or self.report_id != REPORT_ID:
            raise ReportBindingError("report_id_not_supported")

    def to_dict(self) -> dict[str, object]:
        """Expose the closed metadata schema without sharing mutable containers."""
        return {
            "schema_version": self.schema_version, "report_id": self.report_id,
            "identity": self.identity.to_dict(),
            "input_artifact": self.input_artifact.to_dict(),
            "canonical_result": self.canonical_result.to_dict(),
            "evidence_snapshot": self.evidence_snapshot.to_dict(),
            "reference_bundle_sha256": self.reference_bundle_sha256,
        }

    @property
    def binding_sha256(self) -> str:
        """Hash metadata with the established compact sorted UTF-8 JSON encoding."""
        encoded = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class BoundReportSources:
    """Exact source bytes retained only after identity and digest agreement."""

    expected_binding: ReportSourceBinding
    resolved_binding: ReportSourceBinding
    canonical_result_bytes: bytes
    evidence_snapshot_bytes: bytes

    def __post_init__(self) -> None:
        """Enforce admission on direct construction as well as the public factory."""
        if (type(self.expected_binding) is not ReportSourceBinding
                or type(self.resolved_binding) is not ReportSourceBinding):
            raise ReportBindingError("report_source_binding_required")
        if self.expected_binding != self.resolved_binding:
            raise ReportBindingError("report_source_binding_mismatch")
        snapshots = (self.canonical_result_bytes, self.evidence_snapshot_bytes)
        for data in snapshots:
            if type(data) is not bytes or not data:
                raise ReportBindingError("immutable_snapshot_bytes_required")
            if len(data) > MAX_SNAPSHOT_BYTES:
                raise ReportBindingError("report_source_budget_exceeded")
        for role, data in zip(("canonical_result", "evidence_snapshot"), snapshots):
            if hashlib.sha256(data).hexdigest() != getattr(self.expected_binding, role).sha256:
                raise ReportBindingError(role + "_digest_mismatch")

    def to_dict(self) -> dict[str, object]:
        """Return integrity evidence only, with neither payloads nor release claims."""
        return {
            "status": "BOUND", "conformance_scope": "REPORT_SOURCE_INTEGRITY_ONLY",
            "release_authorization": "NOT_ESTABLISHED",
            "binding_sha256": self.expected_binding.binding_sha256,
            "report_id": self.expected_binding.report_id,
            "canonical_result_sha256": self.expected_binding.canonical_result.sha256,
            "canonical_result_size_bytes": len(self.canonical_result_bytes),
            "evidence_snapshot_sha256": self.expected_binding.evidence_snapshot.sha256,
            "evidence_snapshot_size_bytes": len(self.evidence_snapshot_bytes),
        }


def bind_report_sources(
    *, expected_binding: ReportSourceBinding, resolved_binding: ReportSourceBinding,
    canonical_result_bytes: bytes, evidence_snapshot_bytes: bytes,
) -> BoundReportSources:
    """Bind immutable upstream sources without parsing, copying or authorizing them."""
    return BoundReportSources(expected_binding, resolved_binding,
                              canonical_result_bytes, evidence_snapshot_bytes)
