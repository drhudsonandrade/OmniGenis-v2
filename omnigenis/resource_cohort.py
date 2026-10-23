"""Bounded integrity admission for preloaded, quarantined source snapshots.

Expected declarations and review references must come from independently
authenticated upstream resolution. Matching declarations, transfer claims and
hashes does not authenticate the provider, legal review, compatibility review,
retrieval event or scientific content. Normalization profiles are recorded, not
executed. The result always remains QUARANTINED and cannot authorize activation.

This pure boundary performs no network, filesystem, registry update or resource
promotion. It returns metadata only and retains no downloaded payload. Its small
snapshot budget is an admission profile, not a finding or report-length limit;
an oversized cohort is rejected whole. Acquisition budgets and atomic persistent
promotion require their own reviewed implementation.
"""
from __future__ import annotations

from dataclasses import InitVar, dataclass, field
from datetime import datetime
import hashlib
import json
import re

SCHEMA_VERSION = "1.0.0"
PROFILE_ID = "quarantined-resource-cohort-v1"
MAX_RESOURCE_COUNT = 32
MAX_RESOURCE_BYTES = 5 * 1024 * 1024
MAX_COHORT_BYTES = 16 * 1024 * 1024
MEDIA_TYPES = frozenset({
    "application/json", "application/xml", "text/tab-separated-values",
})
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_UNPINNED = frozenset({"latest", "current", "unknown", "not_available"})
_MANIFEST_KEYS = frozenset({
    "schema_version", "profile_id", "cohort_id", "source_registry",
    "reference_profile_id", "compatibility_review", "resources",
})
_RESOURCE_KEYS = frozenset({
    "resource_id", "source_id", "source_revision", "reference_profile_id",
    "normalization_profile_id", "media_type", "sha256", "size_bytes",
    "rights_status", "rights_review",
})
_IDENTITY_FIELDS = (
    "resource_id", "source_id", "source_revision",
    "reference_profile_id", "normalization_profile_id",
)


class ResourceCohortError(ValueError):
    """Fixed diagnostic code without source bytes or identifiers."""


def _identity(value: object) -> None:
    """Accept bounded opaque pinned identifiers without coercion."""
    if (type(value) is not str or _ID.fullmatch(value) is None
            or value.lower() in _UNPINNED):
        raise ResourceCohortError("resource_identity_invalid")


def _digest(value: object) -> None:
    """Require exact lowercase SHA-256 notation."""
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ResourceCohortError("resource_digest_invalid")


def _closed(value: object, keys: frozenset[str]) -> None:
    """Require an ordinary closed dictionary at a metadata boundary."""
    if type(value) is not dict or value.keys() != keys:
        raise ResourceCohortError("resource_contract_invalid")


def _reference(value: object) -> dict[str, str]:
    """Copy a reference; presence is not authentication of its authority."""
    _closed(value, frozenset({"artifact_id", "sha256"}))
    _identity(value["artifact_id"])
    _digest(value["sha256"])
    return {"artifact_id": value["artifact_id"], "sha256": value["sha256"]}


def _validate_manifest(document: object) -> dict[str, object]:
    """Build detached metadata and enforce all inventory admission limits."""
    _closed(document, _MANIFEST_KEYS)
    if (type(document["schema_version"]) is not str
            or document["schema_version"] != SCHEMA_VERSION
            or type(document["profile_id"]) is not str
            or document["profile_id"] != PROFILE_ID):
        raise ResourceCohortError("resource_profile_not_supported")
    _identity(document["cohort_id"])
    _identity(document["reference_profile_id"])
    registry = _reference(document["source_registry"])
    compatibility = _reference(document["compatibility_review"])
    if registry["artifact_id"] == compatibility["artifact_id"]:
        raise ResourceCohortError("resource_evidence_roles_ambiguous")
    supplied = document["resources"]
    if type(supplied) is not list or not 1 <= len(supplied) <= MAX_RESOURCE_COUNT:
        raise ResourceCohortError("resource_inventory_budget_exceeded")
    resources = []
    seen = set()
    evidence = {
        registry["artifact_id"]: registry["sha256"],
        compatibility["artifact_id"]: compatibility["sha256"],
    }
    total = 0
    for item in supplied:
        _closed(item, _RESOURCE_KEYS)
        for key in _IDENTITY_FIELDS:
            _identity(item[key])
        if item["resource_id"] in seen:
            raise ResourceCohortError("duplicate_resource_identity")
        seen.add(item["resource_id"])
        if item["reference_profile_id"] != document["reference_profile_id"]:
            raise ResourceCohortError("resource_reference_mismatch")
        if type(item["media_type"]) is not str or item["media_type"] not in MEDIA_TYPES:
            raise ResourceCohortError("resource_media_not_supported")
        _digest(item["sha256"])
        size = item["size_bytes"]
        if type(size) is not int or not 1 <= size <= MAX_RESOURCE_BYTES:
            raise ResourceCohortError("resource_inventory_budget_exceeded")
        total += size
        if total > MAX_COHORT_BYTES:
            raise ResourceCohortError("resource_inventory_budget_exceeded")
        if type(item["rights_status"]) is not str or item["rights_status"] != "STAGING_ALLOWED":
            raise ResourceCohortError("resource_rights_review_required")
        rights = _reference(item["rights_review"])
        if rights["artifact_id"] in (registry["artifact_id"], compatibility["artifact_id"]):
            raise ResourceCohortError("resource_evidence_roles_ambiguous")
        previous = evidence.setdefault(rights["artifact_id"], rights["sha256"])
        if previous != rights["sha256"]:
            raise ResourceCohortError("resource_evidence_digest_conflict")
        resources.append({
            **{key: item[key] for key in _IDENTITY_FIELDS},
            "media_type": item["media_type"], "sha256": item["sha256"],
            "size_bytes": size, "rights_status": item["rights_status"],
            "rights_review": rights,
        })
    return {
        "schema_version": SCHEMA_VERSION, "profile_id": PROFILE_ID,
        "cohort_id": document["cohort_id"], "source_registry": registry,
        "reference_profile_id": document["reference_profile_id"],
        "compatibility_review": compatibility,
        "resources": sorted(resources, key=lambda item: item["resource_id"]),
    }


@dataclass(frozen=True, slots=True, repr=False, init=False)
class ResourceCohortManifest:
    """Immutable expected metadata, with no mutable latest-pointer semantics."""

    _canonical_bytes: bytes

    def __init__(self, document: object) -> None:
        """Validate and detach every field before freezing canonical JSON."""
        normalized = _validate_manifest(document)
        encoded = json.dumps(
            normalized, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
        object.__setattr__(self, "_canonical_bytes", encoded)

    def to_dict(self) -> dict[str, object]:
        """Return detached metadata rather than a shared mutable graph."""
        return json.loads(self._canonical_bytes)

    @property
    def manifest_sha256(self) -> str:
        """Identify the exact canonical declaration, including review pins."""
        return hashlib.sha256(self._canonical_bytes).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class ResourceDownload:
    """Supplied acquisition claims and immutable bytes, not a trusted receipt."""

    cohort_id: str
    resource_id: str
    source_id: str
    source_revision: str
    reference_profile_id: str
    normalization_profile_id: str
    media_type: str
    status_code: int
    complete: bool
    retrieved_at: str
    payload: bytes

    def __post_init__(self) -> None:
        """Reject unbounded or coerced values without interpreting content."""
        for key in ("cohort_id", *_IDENTITY_FIELDS):
            _identity(getattr(self, key))
        if type(self.media_type) is not str or self.media_type not in MEDIA_TYPES:
            raise ResourceCohortError("resource_media_not_supported")
        if type(self.status_code) is not int or not 100 <= self.status_code <= 599:
            raise ResourceCohortError("resource_transfer_status_invalid")
        if type(self.complete) is not bool:
            raise ResourceCohortError("resource_transfer_status_invalid")
        if (type(self.retrieved_at) is not str
                or _TIMESTAMP.fullmatch(self.retrieved_at) is None):
            raise ResourceCohortError("resource_retrieval_time_invalid")
        try:
            datetime.strptime(self.retrieved_at, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            raise ResourceCohortError("resource_retrieval_time_invalid") from None
        if type(self.payload) is not bytes or not self.payload:
            raise ResourceCohortError("immutable_resource_bytes_required")
        if len(self.payload) > MAX_RESOURCE_BYTES:
            raise ResourceCohortError("resource_inventory_budget_exceeded")


@dataclass(frozen=True, slots=True, repr=False)
class QuarantinedResourceCohort:
    """All-or-nothing byte-integrity evidence; never an activated resource."""

    expected_manifest: ResourceCohortManifest
    downloads: InitVar[tuple[ResourceDownload, ...]]
    _receipts: tuple[tuple[str, str, int, str], ...] = field(init=False)

    def __post_init__(self, downloads: tuple[ResourceDownload, ...]) -> None:
        """Check all identities and budgets before hashing any payload."""
        if type(self.expected_manifest) is not ResourceCohortManifest:
            raise ResourceCohortError("typed_resource_manifest_required")
        manifest = _validate_manifest(self.expected_manifest.to_dict())
        resources = manifest["resources"]
        if type(downloads) is not tuple or len(downloads) != len(resources):
            raise ResourceCohortError("resource_transfer_inventory_mismatch")
        received = {}
        total = 0
        for download in downloads:
            if type(download) is not ResourceDownload:
                raise ResourceCohortError("typed_resource_download_required")
            ResourceDownload.__post_init__(download)
            if download.resource_id in received:
                raise ResourceCohortError("resource_transfer_inventory_mismatch")
            received[download.resource_id] = download
            total += len(download.payload)
        if total > MAX_COHORT_BYTES:
            raise ResourceCohortError("resource_inventory_budget_exceeded")
        if set(received) != {item["resource_id"] for item in resources}:
            raise ResourceCohortError("resource_transfer_inventory_mismatch")
        for resource in resources:
            download = received[resource["resource_id"]]
            if download.status_code != 200 or not download.complete:
                raise ResourceCohortError("resource_transfer_not_complete")
            if (download.cohort_id != manifest["cohort_id"]
                    or any(getattr(download, key) != resource[key]
                           for key in (*_IDENTITY_FIELDS, "media_type"))):
                raise ResourceCohortError("resource_transfer_identity_mismatch")
            if len(download.payload) != resource["size_bytes"]:
                raise ResourceCohortError("resource_size_mismatch")
        receipts = []
        for resource in resources:
            download = received[resource["resource_id"]]
            if hashlib.sha256(download.payload).hexdigest() != resource["sha256"]:
                raise ResourceCohortError("resource_digest_mismatch")
            receipts.append((
                resource["resource_id"], resource["sha256"],
                resource["size_bytes"], download.retrieved_at,
            ))
        object.__setattr__(self, "_receipts", tuple(receipts))

    def to_dict(self) -> dict[str, object]:
        """Expose only integrity metadata and explicit non-authorization."""
        return {
            "schema_version": SCHEMA_VERSION, "profile_id": PROFILE_ID,
            "status": "QUARANTINED", "integrity_scope": "DECLARED_BYTES_ONLY",
            "activation_authorization": "NOT_ESTABLISHED",
            "scientific_validity": "NOT_ESTABLISHED",
            "rights_authentication": "NOT_ESTABLISHED",
            "manifest_sha256": self.expected_manifest.manifest_sha256,
            "cohort_id": self.expected_manifest.to_dict()["cohort_id"],
            "resource_count": len(self._receipts),
            "total_bytes": sum(item[2] for item in self._receipts),
            "resources": [
                {"resource_id": item[0], "sha256": item[1],
                 "size_bytes": item[2], "retrieved_at": item[3]}
                for item in self._receipts
            ],
        }


def quarantine_resource_cohort(
    *, expected_manifest: ResourceCohortManifest,
    downloads: tuple[ResourceDownload, ...],
) -> QuarantinedResourceCohort:
    """Check a complete pinned inventory without activating or persisting it."""
    return QuarantinedResourceCohort(expected_manifest, downloads)
