"""Bounded, non-activating PNG structure preflight for the staged DNA artwork.

The supplied PNG is an independently resolved, immutable staged asset bound by
existing exact-byte manifests. Reject unsupported/ancillary chunks, CRC errors,
ambiguous framing and inflated scanline budgets before exposing metadata.

This proves only bounded PNG container, zlib and scanline-filter structure.
It does NOT decode/reconstruct pixel values, sanitize artwork, verify visual
identity or copyright, grant access to a renderer, or authorize report release.
The original bytes are never persisted or returned by this inspector.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct
import zlib

from reporting.asset_registry import (
    AssetManifest, AssetRegistryError, bind_staged_asset_inventory,
)

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
MAX_ENCODED_BYTES = 4 * 1024 * 1024
MAX_PIXEL_COUNT = 4_000_000
MAX_SCANLINE_BYTES = 16 * 1024 * 1024
MAX_CHUNKS = 1024
SCHEMA_VERSION = "1.0.0"
INSPECTION_PROFILE = "staged-png-structure-v1"


class PngInspectionError(ValueError):
    """A fixed diagnostic category that never echoes source content."""


def _reject(reason: str) -> None:
    raise PngInspectionError(reason)


@dataclass(frozen=True, slots=True, repr=False)
class PngInspectionReceipt:
    """Immutable content-free syntax evidence, not a safe or promoted image."""

    asset_id: str
    asset_manifest_sha256: str
    input_sha256: str
    encoded_size_bytes: int
    width_px: int
    height_px: int
    pixel_count: int
    color_type: int
    channels: int
    scanline_bytes: int
    idat_chunk_count: int
    chunk_count: int

    def __post_init__(self) -> None:
        if not isinstance(self.asset_id, str) or not self.asset_id:
            _reject("png_receipt_identity_invalid")
        if any(type(x) is not str or len(x) != 64 or any(c not in "0123456789abcdef" for c in x)
               for x in (self.asset_manifest_sha256, self.input_sha256)):
            _reject("png_receipt_digest_invalid")
        if self.color_type not in (2, 6) or type(self.color_type) is not int:
            _reject("png_receipt_color_invalid")
        if self.channels != (3 if self.color_type == 2 else 4):
            _reject("png_receipt_channels_invalid")
        for value, cap in ((self.width_px, 16384), (self.height_px, 16384),
                           (self.encoded_size_bytes, MAX_ENCODED_BYTES),
                           (self.pixel_count, MAX_PIXEL_COUNT),
                           (self.scanline_bytes, MAX_SCANLINE_BYTES),
                           (self.chunk_count, MAX_CHUNKS),
                           (self.idat_chunk_count, MAX_CHUNKS - 2)):
            if type(value) is not int or not 1 <= value <= cap:
                _reject("png_receipt_bounds_invalid")
        if (self.pixel_count != self.width_px * self.height_px
                or self.scanline_bytes != self.height_px * (1 + self.width_px * self.channels)
                or self.idat_chunk_count + 2 != self.chunk_count):
            _reject("png_receipt_structure_invalid")

    def to_dict(self) -> dict[str, object]:
        """Only an inert receipt; deliberately no decoded image or source bytes."""
        return {
            "schema_version": SCHEMA_VERSION,
            "profile_id": INSPECTION_PROFILE,
            "status": "PNG_STRUCTURALLY_INSPECTED_UNQUALIFIED",
            "conformance_scope": "PNG_CHUNK_CRC_ZLIB_FILTER_STRUCTURE_ONLY",
            "asset_id": self.asset_id,
            "asset_manifest_sha256": self.asset_manifest_sha256,
            "input_sha256": self.input_sha256,
            "encoded_size_bytes": self.encoded_size_bytes,
            "width_px": self.width_px,
            "height_px": self.height_px,
            "pixel_count": self.pixel_count,
            "color_type": self.color_type,
            "channels": self.channels,
            "bit_depth": 8,
            "interlaced": False,
            "scanline_bytes": self.scanline_bytes,
            "idat_chunk_count": self.idat_chunk_count,
            "chunk_count": self.chunk_count,
            "original_bytes_retained": False,
            "image_pixels_decoded": False,
            "image_sanitized": False,
            "metadata_qualified": False,
            "rights_verified": False,
            "source_authenticated": False,
            "renderer_activated": False,
            "asset_activated": False,
            "full_os_sandbox_claim": False,
            "release_authorization": "NOT_ESTABLISHED",
        }


def inspect_staged_png(
    *, expected_manifest: AssetManifest, resolved_manifest: AssetManifest,
    png_bytes: bytes,
) -> PngInspectionReceipt:
    """Reject malformed and over-budget preloaded PNG without side effects."""
    if type(png_bytes) is not bytes or not 8 <= len(png_bytes) <= MAX_ENCODED_BYTES:
        _reject("png_encoded_budget_or_type_invalid")
    if type(expected_manifest) is not AssetManifest or type(resolved_manifest) is not AssetManifest:
        _reject("png_typed_manifest_required")
    try:
        bind_staged_asset_inventory(
            expected_manifest=expected_manifest,
            resolved_manifest=resolved_manifest,
            supplied_bytes=(png_bytes,),
        )
    except AssetRegistryError:
        _reject("png_source_binding_failed")
    asset = expected_manifest.assets[0]
    if asset.role != "dna-illustration" or asset.media_type != "image/png":
        _reject("png_media_role_not_admitted")
    if not png_bytes.startswith(PNG_SIGNATURE):
        _reject("png_signature_invalid")

    position = len(PNG_SIGNATURE)
    chunks = idat_count = 0
    stage = "ihdr"
    payload_parts: list[bytes] = []
    width = height = channels = scanline_bytes = 0

    while position < len(png_bytes):
        chunks += 1
        if chunks > MAX_CHUNKS or len(png_bytes) - position < 12:
            _reject("png_chunk_count_or_header_invalid")
        chunk_len = struct.unpack_from(">I", png_bytes, position)[0]
        if chunk_len > MAX_ENCODED_BYTES or chunk_len > len(png_bytes) - position - 12:
            _reject("png_chunk_length_invalid")
        kind = png_bytes[position + 4:position + 8]
        payload = png_bytes[position + 8:position + 8 + chunk_len]
        stored_crc = struct.unpack_from(">I", png_bytes, position + 8 + chunk_len)[0]
        if zlib.crc32(kind + payload) & 0xffffffff != stored_crc:
            _reject("png_chunk_crc_invalid")
        position += 12 + chunk_len

        if stage == "ihdr":
            if kind != b"IHDR" or len(payload) != 13:
                _reject("png_ihdr_required")
            width, height, depth, color_type, comp, filtering, interlace = struct.unpack(">IIBBBBB", payload)
            if (depth != 8 or color_type not in (2, 6)
                    or comp != 0 or filtering != 0 or interlace != 0):
                _reject("png_ihdr_profile_unsupported")
            channels = 3 if color_type == 2 else 4
            if (not 1 <= width <= 16384 or not 1 <= height <= 16384
                    or width * height > MAX_PIXEL_COUNT):
                _reject("png_dimension_budget_exceeded")
            if width != asset.declared_width_px or height != asset.declared_height_px:
                _reject("png_declared_geometry_mismatch")
            scanline_bytes = height * (1 + width * channels)
            if scanline_bytes > MAX_SCANLINE_BYTES:
                _reject("png_scanline_budget_exceeded")
            stage = "idat"
        elif kind == b"IDAT" and stage == "idat":
            if not payload:
                _reject("png_idat_empty")
            payload_parts.append(payload)
            idat_count += 1
            if sum(len(value) for value in payload_parts) > MAX_ENCODED_BYTES:
                _reject("png_compressed_budget_exceeded")
        elif kind == b"IEND" and stage == "idat":
            if payload or idat_count == 0 or position != len(png_bytes):
                _reject("png_iend_invalid")
            stage = "complete"
            break
        else:
            _reject("png_unapproved_chunk_or_order")

    if stage != "complete" or idat_count == 0 or chunks != idat_count + 2:
        _reject("png_incomplete_stream")
    compressed = b"".join(payload_parts)
    try:
        decoder = zlib.decompressobj()
        inflated = decoder.decompress(compressed, scanline_bytes + 1)
    except zlib.error:
        _reject("png_deflate_invalid")
    if (len(inflated) != scanline_bytes or not decoder.eof
            or decoder.unused_data or decoder.unconsumed_tail):
        _reject("png_deflate_or_scanline_length_invalid")
    stride = 1 + width * channels
    if any(inflated[row * stride] > 4 for row in range(height)):
        _reject("png_scanline_filter_invalid")
    return PngInspectionReceipt(
        asset_id=asset.asset_id,
        asset_manifest_sha256=expected_manifest.manifest_sha256,
        input_sha256=hashlib.sha256(png_bytes).hexdigest(),
        encoded_size_bytes=len(png_bytes),
        width_px=width, height_px=height, pixel_count=width * height,
        color_type=color_type, channels=channels,
        scanline_bytes=scanline_bytes, idat_chunk_count=idat_count,
        chunk_count=chunks,
    )
