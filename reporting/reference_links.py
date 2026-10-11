"""Closed staging-only HTTPS source reference candidates for future editorial PDFs.

Exact, conservative URI spelling, manifest digests and source/policy references
are checked without opening a connection or resolving a host. The declared host
set is caller-supplied metadata, NOT an authenticated approved source registry.
This module cannot establish rights, scientific relevance, host trust, link
safety in PDF, renderer activation or artifact release.

No URL fetcher, PDF action allowlist or existing renderer is modified.
Real citations may require a separately qualified richer URI profile.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re

from reporting.bindings import ReportArtifactBinding, ReportBindingError, _digest, _identity

SCHEMA_VERSION = "1.0.0"
PROFILE_ID = "staged-https-reference-candidates-v1"
MAX_REFERENCES = 128
MAX_HOSTS = 16
MAX_URL_BYTES = 2048
MAX_TOTAL_URI_BYTES = 256 * 1024

_URI = re.compile(r"https://(?P<host>[a-z0-9.-]+)(?P<path>/[A-Za-z0-9._~/-]*)?\Z", re.ASCII)
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)
_TOP_LEVEL = re.compile(r"[a-z]{2,24}\Z", re.ASCII)
_RESTRICTED_ENDINGS = frozenset(("local", "localhost", "internal", "onion", "arpa", "lan"))


class ReferenceCandidateError(ValueError):
    """Content-free error: no candidate may be mistaken for an active link."""


def _id(value: object) -> None:
    try:
        _identity(value)
    except ReportBindingError:
        raise ReferenceCandidateError("reference_identifier_invalid") from None


def _sha(value: object) -> None:
    try:
        _digest(value)
    except ReportBindingError:
        raise ReferenceCandidateError("reference_digest_invalid") from None


def _reference(value: object) -> None:
    if type(value) is not ReportArtifactBinding:
        raise ReferenceCandidateError("reference_snapshot_required")
    try:
        ReportArtifactBinding.__post_init__(value)
    except ReportBindingError:
        raise ReferenceCandidateError("reference_snapshot_invalid") from None


def _hostname(host: object) -> None:
    """Admit only explicitly spelled, non-IP ASCII DNS-form names."""
    if type(host) is not str or not 4 <= len(host) <= 253:
        raise ReferenceCandidateError("reference_hostname_invalid")
    if not host.isascii() or host != host.lower() or host.endswith("."):
        raise ReferenceCandidateError("reference_hostname_invalid")
    labels = host.split(".")
    if len(labels) < 2 or not _TOP_LEVEL.fullmatch(labels[-1]):
        raise ReferenceCandidateError("reference_hostname_invalid")
    if labels[-1] in _RESTRICTED_ENDINGS:
        raise ReferenceCandidateError("reference_hostname_invalid")
    if any(not _HOST_LABEL.fullmatch(item) or item.startswith("xn--") for item in labels):
        raise ReferenceCandidateError("reference_hostname_invalid")
    if labels[0] in ("localhost", "localdomain"):
        raise ReferenceCandidateError("reference_hostname_invalid")


def _uri(value: object, expected_host: object) -> str:
    """Validate before hashing, accepting only non-ambiguous, inert HTTPS spelling."""
    if type(value) is not str or not 9 <= len(value) <= MAX_URL_BYTES:
        raise ReferenceCandidateError("reference_url_invalid")
    if not value.isascii():
        raise ReferenceCandidateError("reference_url_invalid")
    match = _URI.fullmatch(value)
    if not match:
        raise ReferenceCandidateError("reference_url_invalid")
    host = match.group("host")
    _hostname(host)
    if type(expected_host) is not str or expected_host != host:
        raise ReferenceCandidateError("reference_host_mismatch")
    path = match.group("path") or ""
    if "//" in path or any(x in (".", "..", "") for x in path.split("/")[1:] if x or path.endswith("/")):
        # An empty segment anywhere except a single terminal slash is unsupported.
        if "//" in path or any(p in (".", "..") for p in path.split("/")):
            raise ReferenceCandidateError("reference_path_ambiguous")
    if any(segment in (".", "..") for segment in path.split("/")):
        raise ReferenceCandidateError("reference_path_ambiguous")
    return host


def _canonical_digest(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class ReferenceCandidate:
    """One pinned public citation candidate, not a PDF-safe hyperlink."""

    reference_id: str
    href: str
    host_name: str
    href_sha256: str
    source_reference: ReportArtifactBinding
    policy_reference: ReportArtifactBinding

    def __post_init__(self) -> None:
        _id(self.reference_id)
        _uri(self.href, self.host_name)
        _sha(self.href_sha256)
        _reference(self.source_reference)
        _reference(self.policy_reference)
        if self.source_reference.artifact_id == self.policy_reference.artifact_id:
            raise ReferenceCandidateError("ambiguous_reference_authority")
        if hashlib.sha256(self.href.encode("ascii")).hexdigest() != self.href_sha256:
            raise ReferenceCandidateError("reference_href_digest_mismatch")

    def _binding(self) -> dict[str, object]:
        """Return private manifest metadata; includes literal URL only for hashing."""
        return {"reference_id": self.reference_id, "href": self.href,
                "host_name": self.host_name, "href_sha256": self.href_sha256,
                "source_reference": self.source_reference.to_dict(),
                "policy_reference": self.policy_reference.to_dict()}

    def _receipt(self) -> dict[str, str]:
        """Do not expose a usable URL in a staging receipt."""
        return {"reference_id": self.reference_id, "href_sha256": self.href_sha256,
                "host_sha256": hashlib.sha256(self.host_name.encode("ascii")).hexdigest(),
                "source_reference_sha256": self.source_reference.sha256,
                "policy_reference_sha256": self.policy_reference.sha256}


@dataclass(frozen=True, slots=True, repr=False)
class StagedReferenceCatalog:
    """Bounded list and declared hosts, never a source authority or DNS registry."""

    references: tuple[ReferenceCandidate, ...]
    declared_hosts: tuple[str, ...]
    locale_id: str = "en-US"
    schema_version: str = field(default=SCHEMA_VERSION, init=False)
    profile_id: str = field(default=PROFILE_ID, init=False)

    def __post_init__(self) -> None:
        if type(self.schema_version) is not str or self.schema_version != SCHEMA_VERSION:
            raise ReferenceCandidateError("reference_schema_unsupported")
        if type(self.profile_id) is not str or self.profile_id != PROFILE_ID:
            raise ReferenceCandidateError("reference_profile_unsupported")
        if type(self.locale_id) is not str or self.locale_id != "en-US":
            raise ReferenceCandidateError("reference_locale_unsupported")
        if (type(self.references) is not tuple or type(self.declared_hosts) is not tuple
                or not 1 <= len(self.references) <= MAX_REFERENCES
                or not 1 <= len(self.declared_hosts) <= MAX_HOSTS):
            raise ReferenceCandidateError("reference_inventory_budget_exceeded")
        for host in self.declared_hosts:
            _hostname(host)
        if len(set(self.declared_hosts)) != len(self.declared_hosts):
            raise ReferenceCandidateError("duplicate_declared_host")
        total_bytes = 0
        ids: set[str] = set()
        urls: set[str] = set()
        for link in self.references:
            if type(link) is not ReferenceCandidate:
                raise ReferenceCandidateError("typed_reference_required")
            ReferenceCandidate.__post_init__(link)
            total_bytes += len(link.href)
            if total_bytes > MAX_TOTAL_URI_BYTES:
                raise ReferenceCandidateError("reference_inventory_budget_exceeded")
            if link.host_name not in self.declared_hosts:
                raise ReferenceCandidateError("reference_host_not_declared")
            if link.reference_id in ids or link.href in urls:
                raise ReferenceCandidateError("duplicate_reference_identity")
            ids.add(link.reference_id)
            urls.add(link.href)

    @property
    def catalog_sha256(self) -> str:
        self.__post_init__()
        payload = {"schema_version": SCHEMA_VERSION, "profile_id": PROFILE_ID,
                   "locale_id": self.locale_id,
                   "declared_hosts": list(self.declared_hosts),
                   "references": [r._binding() for r in self.references]}
        return _canonical_digest(payload)


@dataclass(frozen=True, slots=True, repr=False)
class BoundReferenceCandidates:
    """Exact expected/resolved manifests; only inert, URL-free evidence is returned."""

    expected_catalog: StagedReferenceCatalog
    resolved_catalog: StagedReferenceCatalog
    expected_catalog_sha256: str

    def __post_init__(self) -> None:
        if type(self.expected_catalog) is not StagedReferenceCatalog or type(self.resolved_catalog) is not StagedReferenceCatalog:
            raise ReferenceCandidateError("typed_reference_catalog_required")
        StagedReferenceCatalog.__post_init__(self.expected_catalog)
        StagedReferenceCatalog.__post_init__(self.resolved_catalog)
        _sha(self.expected_catalog_sha256)
        if self.expected_catalog != self.resolved_catalog:
            raise ReferenceCandidateError("reference_catalog_binding_mismatch")
        if self.expected_catalog.catalog_sha256 != self.expected_catalog_sha256:
            raise ReferenceCandidateError("expected_catalog_digest_mismatch")

    def to_dict(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "schema_version": SCHEMA_VERSION,
            "profile_id": PROFILE_ID,
            "status": "STAGED_UNQUALIFIED",
            "conformance_scope": "HTTPS_CANDIDATE_SYNTAX_AND_BINDING_ONLY",
            "catalog_sha256": self.expected_catalog_sha256,
            "reference_count": len(self.expected_catalog.references),
            "declared_host_count": len(self.expected_catalog.declared_hosts),
            "references": [link._receipt() for link in self.expected_catalog.references],
            "source_authenticity_verified": False,
            "source_relevance_reviewed": False,
            "source_rights_verified": False,
            "host_policy_authenticated": False,
            "pdf_annotation_profile_qualified": False,
            "renderer_activated": False,
            "links_activated": False,
            "network_access_performed": False,
            "release_authorization": "NOT_ESTABLISHED",
        }


def bind_reference_candidates(
    *, expected_catalog: StagedReferenceCatalog,
    resolved_catalog: StagedReferenceCatalog,
    expected_catalog_sha256: str,
) -> BoundReferenceCandidates:
    """Never follow links or authorize PDF / clinical delivery."""
    return BoundReferenceCandidates(expected_catalog, resolved_catalog, expected_catalog_sha256)
