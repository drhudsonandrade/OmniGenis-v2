"""Read and inspect staged assets beneath an independently pinned directory FD.

The trusted storage owner supplies a directory descriptor and its sealed identity,
plus independently expected/resolved immutable asset manifests. Only SHA-256
basenames are opened; callers cannot provide a filename, URL or relative path.
This function does not establish tenant authority, approve source rights, promote
resources or enable the PDF renderer. It returns the existing unqualified receipt.

Supported profile: local POSIX descriptor-relative I/O with no-follow opens.
Metadata checks detect observed changes, not every possible concurrent writer.
The storage owner must seal inputs and control the directory before calling this
boundary. Read-only permission bits are not a claim of filesystem immutability.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import re
import stat

from reporting.asset_registry import (
    AssetManifest, AssetRegistryError, BoundAssetInventory,
    MAX_TOTAL_ASSET_BYTES, bind_staged_asset_inventory,
)
from reporting.png_inspection import (
    MAX_ENCODED_BYTES as MAX_PNG_BYTES, PngInspectionError, inspect_staged_png,
)
from reporting.svg_inspection import (
    MAX_ENCODED_BYTES as MAX_SVG_BYTES, SvgInspectionError, inspect_staged_svg,
)

_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_READ_CHUNK_BYTES = 64 * 1024
_DESCRIPTOR_IO_SUPPORTED = (
    os.name == "posix"
    and all(hasattr(os, name) for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC", "geteuid"))
    and os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and os.stat in os.supports_follow_symlinks
)


class AssetFileResolutionError(ValueError):
    """Fixed content-free error; failed resolution never returns partial assets."""


def _reject(reason: str) -> None:
    raise AssetFileResolutionError(reason)


@dataclass(frozen=True, slots=True, repr=False)
class AssetDirectoryIdentity:
    """Host-private identity supplied by storage, not inferred from a pathname."""

    device_id: int
    inode_id: int
    owner_uid: int

    def __post_init__(self) -> None:
        for value, low, high in ((self.device_id, 0, 2**64 - 1),
                                 (self.inode_id, 1, 2**64 - 1),
                                 (self.owner_uid, 0, 2**32 - 1)):
            if type(value) is not int or not low <= value <= high:
                _reject("asset_directory_identity_invalid")


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    # Reading may change atime; it is intentionally excluded.
    return (value.st_dev, value.st_ino, value.st_uid, value.st_gid,
            value.st_mode, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def _directory_stat(fd: int, expected: AssetDirectoryIdentity) -> os.stat_result:
    current = os.fstat(fd)
    if (not stat.S_ISDIR(current.st_mode) or current.st_nlink < 1
            or (current.st_dev, current.st_ino, current.st_uid)
            != (expected.device_id, expected.inode_id, expected.owner_uid)
            or current.st_uid != os.geteuid() or stat.S_IMODE(current.st_mode) & 0o022):
        _reject("asset_directory_identity_or_permissions_invalid")
    return current


def _read_asset(root_fd: int, name: str, size: int,
                directory: AssetDirectoryIdentity) -> bytes:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    fd = os.open(name, flags, dir_fd=root_fd)
    try:
        before = os.fstat(fd)
        mode = stat.S_IMODE(before.st_mode)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != directory.owner_uid
                or before.st_dev != directory.device_id
                or not mode & 0o400 or mode & 0o7333
                or before.st_size != size):
            _reject("asset_file_type_identity_or_size_invalid")
        parts: list[bytes] = []
        remaining = size + 1
        while remaining:
            piece = os.read(fd, min(_READ_CHUNK_BYTES, remaining))
            if not piece:
                break
            parts.append(piece)
            remaining -= len(piece)
        raw = b"".join(parts)
        if len(raw) != size:
            _reject("asset_file_read_length_mismatch")
        after = os.fstat(fd)
        entry = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if _stat_identity(before) != _stat_identity(after) or _stat_identity(after) != _stat_identity(entry):
            _reject("asset_file_changed_during_read")
        return raw
    finally:
        os.close(fd)


def resolve_staged_asset_files(
    *, directory_fd: int, expected_directory: AssetDirectoryIdentity,
    expected_manifest: AssetManifest, resolved_manifest: AssetManifest,
    expected_manifest_sha256: str,
) -> BoundAssetInventory:
    """Read all admitted files, check existing media profiles, return metadata only.

    The caller's descriptor is borrowed, duplicated and never closed here. No
    whole-directory enumeration, fallback filename, external fetch or promotion.
    """
    if not _DESCRIPTOR_IO_SUPPORTED:
        _reject("asset_descriptor_profile_unsupported")
    if type(directory_fd) is not int or not 0 <= directory_fd <= 2**31 - 1:
        _reject("asset_directory_descriptor_invalid")
    if type(expected_directory) is not AssetDirectoryIdentity:
        _reject("asset_directory_identity_required")
    expected_directory.__post_init__()
    if type(expected_manifest_sha256) is not str or not _DIGEST.fullmatch(expected_manifest_sha256):
        _reject("asset_expected_manifest_digest_invalid")
    if type(expected_manifest) is not AssetManifest or type(resolved_manifest) is not AssetManifest:
        _reject("typed_asset_manifests_required")
    try:
        expected_manifest.__post_init__()
        resolved_manifest.__post_init__()
        if expected_manifest != resolved_manifest or expected_manifest.manifest_sha256 != expected_manifest_sha256:
            _reject("asset_manifest_binding_mismatch")
        if sum(asset.size_bytes for asset in expected_manifest.assets) > MAX_TOTAL_ASSET_BYTES:
            _reject("asset_file_inventory_budget_exceeded")
        for asset in expected_manifest.assets:
            limit = MAX_SVG_BYTES if asset.role == "brand-logo" else MAX_PNG_BYTES
            if asset.size_bytes > limit:
                _reject("asset_media_read_budget_exceeded")
    except AssetRegistryError:
        raise AssetFileResolutionError("asset_manifest_invalid") from None

    try:
        held_root = os.dup(directory_fd)
        try:
            initial_root = _directory_stat(held_root, expected_directory)
            contents = tuple(_read_asset(held_root, asset.sha256, asset.size_bytes, expected_directory)
                             for asset in expected_manifest.assets)
            inventory = bind_staged_asset_inventory(
                expected_manifest=expected_manifest, resolved_manifest=resolved_manifest,
                supplied_bytes=contents,
            )
            for expected, resolved, raw in zip(expected_manifest.assets, resolved_manifest.assets, contents):
                expected_single = AssetManifest((expected,))
                resolved_single = AssetManifest((resolved,))
                if expected.role == "brand-logo":
                    inspect_staged_svg(expected_manifest=expected_single,
                                       resolved_manifest=resolved_single, svg_bytes=raw)
                else:
                    inspect_staged_png(expected_manifest=expected_single,
                                       resolved_manifest=resolved_single, png_bytes=raw)
            if (expected_manifest.manifest_sha256 != expected_manifest_sha256
                    or resolved_manifest.manifest_sha256 != expected_manifest_sha256):
                _reject("asset_manifest_changed_during_resolution")
            if _stat_identity(initial_root) != _stat_identity(_directory_stat(held_root, expected_directory)):
                _reject("asset_directory_changed_during_resolution")
            return inventory
        finally:
            os.close(held_root)
    except OSError:
        raise AssetFileResolutionError("asset_descriptor_io_failed") from None
    except (AssetRegistryError, PngInspectionError, SvgInspectionError):
        raise AssetFileResolutionError("asset_bytes_or_media_inspection_failed") from None
