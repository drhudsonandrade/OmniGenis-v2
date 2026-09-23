"""Deterministic artifact integrity gate for clean-target artifacts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib

CAPABILITY_ID = "artifact-integrity-gate"
CAPABILITY_VERSION = "1.0.0"

RULE_MANIFEST = "ARTIFACT_MANIFEST_CONTRACT"
RULE_SHA256 = "ARTIFACT_CONTENT_SHA256"
RULE_SIZE = "ARTIFACT_SIZE_BYTES"

_REQUIRED_FIELDS = frozenset(
    {
        "schema_version",
        "artifact_id",
        "artifact_kind",
        "media_type",
        "sha256",
        "size_bytes",
        "producer_execution_profile_id",
        "parent_artifact_ids",
    }
)
_ALLOWED_FIELDS = _REQUIRED_FIELDS
_HEX = frozenset("0123456789abcdef")


@dataclass(frozen=True)
class ArtifactRuleResult:
    """One independently traceable artifact-gate rule result."""

    rule_id: str
    status: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "status": self.status,
            "detail": self.detail,
        }
@dataclass(frozen=True)
class ArtifactGateResult:
    """Tool-neutral deterministic result for the artifact integrity gate."""

    artifact_id: str | None
    actual_sha256: str
    actual_size_bytes: int
    rules: tuple[ArtifactRuleResult, ...]

    @property
    def passed(self) -> bool:
        return all(rule.status == "PASS" for rule in self.rules)

    def to_dict(self) -> dict[str, object]:
        return {
            "capability_id": CAPABILITY_ID,
            "capability_version": CAPABILITY_VERSION,
            "canonical_status": "PASS" if self.passed else "FAIL",
            "canonical_payload": {
                "artifact_id": self.artifact_id,
                "actual_sha256": self.actual_sha256,
                "actual_size_bytes": self.actual_size_bytes,
                "rules": [rule.to_dict() for rule in self.rules],
            },
            "availability": "AVAILABLE",
            "limitations": [
                "No filename or extension trust.",
                "No artifact promotion or cache attestation.",
                "No reference identity or scientific interpretation.",
            ],
            "executor_id": "omnigenis.python-stdlib",
            "executor_version": CAPABILITY_VERSION,
            "adapter_version": None,
            "model_id": None,
            "resource_release": None,
            "reference_bundle": None,
            "execution_profile": "artifact-integrity-gate-v1",
            "raw_artifact_refs": [],
            "provenance_refs": ["ArtifactManifest-v1.0.0"],
        }


def _is_nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HEX for character in value)
    )


def _is_nonnegative_json_integer(value: object) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value >= 0
    if isinstance(value, float):
        return value >= 0 and value.is_integer()
    return False


def _manifest_errors(manifest: Mapping[str, object]) -> tuple[str, ...]:
    errors: list[str] = []
    keys = set(manifest)
    missing = sorted(_REQUIRED_FIELDS - keys)
    extra = sorted((repr(key) for key in keys - _ALLOWED_FIELDS))
    if missing:
        errors.append("missing_fields:" + ",".join(missing))
    if extra:
        errors.append("unexpected_fields:" + ",".join(extra))

    if manifest.get("schema_version") != "1.0.0":
        errors.append("schema_version")

    for field in (
        "artifact_id",
        "artifact_kind",
        "media_type",
        "producer_execution_profile_id",
    ):
        if not _is_nonempty_string(manifest.get(field)):
            errors.append(field)

    if not _is_sha256(manifest.get("sha256")):
        errors.append("sha256")

    size = manifest.get("size_bytes")
    if not _is_nonnegative_json_integer(size):
        errors.append("size_bytes")

    parents = manifest.get("parent_artifact_ids")
    if not isinstance(parents, list):
        errors.append("parent_artifact_ids")
    else:
        if any(not _is_nonempty_string(parent) for parent in parents):
            errors.append("parent_artifact_ids")
        elif len(parents) != len(set(parents)):
            errors.append("parent_artifact_ids_unique")

    return tuple(dict.fromkeys(errors))


def _rule(rule_id: str, passed: bool, detail: str) -> ArtifactRuleResult:
    return ArtifactRuleResult(rule_id, "PASS" if passed else "FAIL", detail)


def verify_artifact_bytes(
    manifest: Mapping[str, object],
    data: bytes,
) -> ArtifactGateResult:
    """Verify manifest contract, SHA-256 identity, and exact byte size."""
    actual_sha256 = hashlib.sha256(data).hexdigest()
    actual_size = len(data)

    if not isinstance(manifest, Mapping):
        manifest_errors = ("manifest_not_mapping",)
        safe_manifest: Mapping[str, object] = {}
    else:
        safe_manifest = manifest
        manifest_errors = _manifest_errors(safe_manifest)
    manifest_ok = not manifest_errors
    manifest_rule = _rule(
        RULE_MANIFEST,
        manifest_ok,
        "manifest_contract_valid"
        if manifest_ok
        else "manifest_contract_invalid:" + ";".join(manifest_errors),
    )

    expected_sha = safe_manifest.get("sha256")
    sha_ok = _is_sha256(expected_sha) and expected_sha == actual_sha256
    sha_rule = _rule(
        RULE_SHA256,
        sha_ok,
        "sha256_match" if sha_ok else "sha256_mismatch_or_invalid",
    )

    expected_size = safe_manifest.get("size_bytes")
    size_type_ok = _is_nonnegative_json_integer(expected_size)
    size_ok = size_type_ok and expected_size == actual_size
    size_rule = _rule(
        RULE_SIZE,
        size_ok,
        "size_match" if size_ok else "size_mismatch_or_invalid",
    )

    artifact_id = safe_manifest.get("artifact_id")
    return ArtifactGateResult(
        artifact_id=artifact_id if _is_nonempty_string(artifact_id) else None,
        actual_sha256=actual_sha256,
        actual_size_bytes=actual_size,
        rules=(manifest_rule, sha_rule, size_rule),
    )
