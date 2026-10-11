"""Staging-only byte integrity for the frozen report's two editorial assets.

The caller supplies independently resolved expected metadata, sealed upstream
source/rights references and preloaded opaque bytes. Equality and a SHA-256 match
do not authenticate source or legal authority, sanitize SVG/PNG, check dimensions,
or qualify a font, renderer, reference link or report release. Real brand assets
are deliberately NOT imported into product code by this module.

No path, URL, filesystem, XML/image parser or network operation is performed.
The returned receipt retains no source bytes and cannot be used as a renderer
resource. A future security/rights-qualified resolver must implement activation
through its own explicit reviewed contract; this profile remains opt-in disabled.
"""
from __future__ import annotations

from dataclasses import InitVar, dataclass, field
import hashlib
import json

from reporting.bindings import ReportArtifactBinding, ReportBindingError, _digest, _identity

PROFILE_ID = "staged-editorial-brand-assets-v1"
SCHEMA_VERSION = "1.0.0"
MEDIA_BY_ROLE = {
    "brand-logo": "image/svg+xml",
    "dna-illustration": "image/png",
}
MAX_ASSET_COUNT = 2
MAX_SINGLE_ASSET_BYTES = 4 * 1024 * 1024
MAX_TOTAL_ASSET_BYTES = 8 * 1024 * 1024
MAX_DECLARED_DIMENSION_PX = 16_384


class AssetRegistryError(ValueError):
    """Content-free staging failure; no asset or release is authorized."""


def _id(value: object) -> None:
    try:
        _identity(value)
    except ReportBindingError:
        raise AssetRegistryError("asset_identity_invalid") from None


def _sha(value: object) -> None:
    try:
        _digest(value)
    except ReportBindingError:
        raise AssetRegistryError("asset_digest_invalid") from None


def _reference(value: object) -> None:
    if type(value) is not ReportArtifactBinding:
        raise AssetRegistryError("sealed_reference_required")
    try:
        ReportArtifactBinding.__post_init__(value)
    except ReportBindingError:
        raise AssetRegistryError("sealed_reference_invalid") from None


def _integer(value: object, maximum: int) -> None:
    if type(value) is not int or not 1 <= value <= maximum:
        raise AssetRegistryError("asset_admission_invalid")


@dataclass(frozen=True, slots=True, repr=False)
class AssetDeclaration:
    """Metadata and upstream references, not a license or sanitized image."""

    asset_id: str
    role: str
    media_type: str
    sha256: str
    size_bytes: int
    declared_width_px: int
    declared_height_px: int
    source_reference: ReportArtifactBinding
    rights_reference: ReportArtifactBinding

    def __post_init__(self) -> None:
        _id(self.asset_id)
        if type(self.role) is not str or self.role not in MEDIA_BY_ROLE:
            raise AssetRegistryError("asset_role_not_supported")
        if type(self.media_type) is not str or self.media_type != MEDIA_BY_ROLE[self.role]:
            raise AssetRegistryError("asset_media_not_supported")
        _sha(self.sha256)
        _integer(self.size_bytes, MAX_SINGLE_ASSET_BYTES)
        _integer(self.declared_width_px, MAX_DECLARED_DIMENSION_PX)
        _integer(self.declared_height_px, MAX_DECLARED_DIMENSION_PX)
        _reference(self.source_reference)
        _reference(self.rights_reference)
        if self.source_reference.sha256 != self.sha256:
            raise AssetRegistryError("source_asset_digest_mismatch")
        if self.source_reference.artifact_id == self.rights_reference.artifact_id:
            raise AssetRegistryError("ambiguous_source_and_rights_reference")

    def to_dict(self) -> dict[str, object]:
        return {
            "asset_id": self.asset_id,
            "role": self.role,
            "media_type": self.media_type,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "declared_width_px": self.declared_width_px,
            "declared_height_px": self.declared_height_px,
            "source_reference": self.source_reference.to_dict(),
            "rights_reference": self.rights_reference.to_dict(),
        }


def _canonical_digest(value: object) -> str:
    """Preserve the project's canonical compact sorted JSON encoding."""
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class AssetManifest:
    """Exactly specified but unqualified frozen-editorial asset inventory."""

    assets: tuple[AssetDeclaration, ...]
    schema_version: str = field(default=SCHEMA_VERSION, init=False)
    profile_id: str = field(default=PROFILE_ID, init=False)

    def __post_init__(self) -> None:
        if type(self.schema_version) is not str or self.schema_version != SCHEMA_VERSION:
            raise AssetRegistryError("asset_schema_version_not_supported")
        if type(self.profile_id) is not str or self.profile_id != PROFILE_ID:
            raise AssetRegistryError("asset_profile_not_supported")
        if type(self.assets) is not tuple or not 1 <= len(self.assets) <= MAX_ASSET_COUNT:
            raise AssetRegistryError("asset_inventory_budget_exceeded")
        for asset in self.assets:
            if type(asset) is not AssetDeclaration:
                raise AssetRegistryError("typed_asset_declaration_required")
            AssetDeclaration.__post_init__(asset)
        roles = tuple(a.role for a in self.assets)
        ids = tuple(a.asset_id for a in self.assets)
        if len(roles) != len(set(roles)) or len(ids) != len(set(ids)):
            raise AssetRegistryError("duplicate_asset_role_or_identity")
        if sum(a.size_bytes for a in self.assets) > MAX_TOTAL_ASSET_BYTES:
            raise AssetRegistryError("asset_inventory_budget_exceeded")

    def to_dict(self) -> dict[str, object]:
        return {"schema_version": self.schema_version, "profile_id": self.profile_id,
                "assets": [asset.to_dict() for asset in self.assets]}

    @property
    def manifest_sha256(self) -> str:
        self.__post_init__()
        return _canonical_digest(self.to_dict())


@dataclass(frozen=True, slots=True, repr=False)
class BoundAssetInventory:
    """Validate preloaded bytes and discard them, retaining only a receipt."""

    expected_manifest: AssetManifest
    resolved_manifest: AssetManifest
    supplied_bytes: InitVar[tuple[bytes, ...]]
    _total_bytes: int = field(init=False, repr=False)

    def __post_init__(self, supplied_bytes: tuple[bytes, ...]) -> None:
        if type(self.expected_manifest) is not AssetManifest or type(self.resolved_manifest) is not AssetManifest:
            raise AssetRegistryError("typed_asset_manifest_required")
        AssetManifest.__post_init__(self.expected_manifest)
        AssetManifest.__post_init__(self.resolved_manifest)
        if self.expected_manifest != self.resolved_manifest:
            raise AssetRegistryError("asset_manifest_identity_mismatch")
        items = self.expected_manifest.assets
        if type(supplied_bytes) is not tuple or len(supplied_bytes) != len(items):
            raise AssetRegistryError("asset_byte_inventory_mismatch")
        total = 0
        for declaration, payload in zip(items, supplied_bytes):
            if type(payload) is not bytes or not payload:
                raise AssetRegistryError("immutable_asset_bytes_required")
            size = len(payload)
            if size > MAX_SINGLE_ASSET_BYTES or size != declaration.size_bytes:
                raise AssetRegistryError("asset_byte_size_mismatch")
            total += size
            if total > MAX_TOTAL_ASSET_BYTES:
                raise AssetRegistryError("asset_inventory_budget_exceeded")
            if hashlib.sha256(payload).hexdigest() != declaration.sha256:
                raise AssetRegistryError("asset_byte_digest_mismatch")
        object.__setattr__(self, "_total_bytes", total)

    def to_dict(self) -> dict[str, object]:
        """Return detached metadata only; no source bytes or false qualification."""
        return {
            "schema_version": SCHEMA_VERSION,
            "profile_id": PROFILE_ID,
            "status": "PINNED_UNQUALIFIED",
            "conformance_scope": "OPAQUE_ASSET_BYTE_INTEGRITY_ONLY",
            "manifest_sha256": self.expected_manifest.manifest_sha256,
            "asset_count": len(self.expected_manifest.assets),
            "total_bytes": self._total_bytes,
            "assets": [asset.to_dict() for asset in self.expected_manifest.assets],
            "source_bytes_retained": False,
            "rights_verified": False,
            "media_sanitized": False,
            "dimensions_verified": False,
            "renderer_activated": False,
            "font_profile_qualified": False,
            "links_activated": False,
            "release_authorization": "NOT_ESTABLISHED",
        }


def bind_staged_asset_inventory(
    *, expected_manifest: AssetManifest, resolved_manifest: AssetManifest,
    supplied_bytes: tuple[bytes, ...],
) -> BoundAssetInventory:
    """Hash-only admission, never brand import, parse, fetch or publication."""
    return BoundAssetInventory(expected_manifest, resolved_manifest, supplied_bytes)
