"""Synthetic strict PNG structure tests for an inert editorial media gate."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from io import BytesIO
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import socket
import struct
import subprocess
import unittest
from unittest.mock import patch
import zlib

from jsonschema import Draft202012Validator
from reporting.asset_registry import AssetDeclaration, AssetManifest
from reporting.bindings import ReportArtifactBinding

ROOT = Path(__file__).resolve().parents[1]
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def chunk(kind: bytes, payload: bytes, *, flip_crc: bool = False) -> bytes:
    checksum = zlib.crc32(kind + payload) & 0xffffffff
    if flip_crc:
        checksum ^= 1
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", checksum)


def png(*, width: int = 2, height: int = 2, color: int = 6, depth: int = 8,
        comp: int = 0, filtering: int = 0, interlace: int = 0,
        raw_filter: int = 0, scanlines: bytes | None = None,
        compressed: bytes | None = None, before: tuple[bytes, ...] = (),
        between: tuple[bytes, ...] = (), after: tuple[bytes, ...] = (),
        split_idat: bool = False, ihdr_override: bytes | None = None) -> bytes:
    channels = 3 if color == 2 else 4
    ihdr = struct.pack(">IIBBBBB", width, height, depth, color, comp, filtering, interlace)
    if ihdr_override is not None:
        ihdr = ihdr_override
    if scanlines is None:
        scanlines = (bytes([raw_filter]) + b"\x01" * (width * channels)) * height
    if compressed is None:
        compressed = zlib.compress(scanlines)
    idats = ((chunk(b"IDAT", compressed[:len(compressed)//2]),
              chunk(b"IDAT", compressed[len(compressed)//2:]))
             if split_idat else (chunk(b"IDAT", compressed),))
    return PNG_SIGNATURE + chunk(b"IHDR", ihdr) + b"".join(before) + idats[0] + b"".join(between) + b"".join(idats[1:]) + b"".join(after) + chunk(b"IEND", b"")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class PngPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertIsNotNone(importlib.util.find_spec("reporting.png_inspection"),
                             "offline staged PNG inspector is absent")
        self.m = importlib.import_module("reporting.png_inspection")
        self.good = png()
        self.exp = self.manifest(self.good)
        self.res = self.manifest(self.good)

    def declaration(self, raw: bytes, *, width: int = 2, height: int = 2,
                    role: str = "dna-illustration", media: str = "image/png") -> AssetDeclaration:
        digest = sha(raw)
        return AssetDeclaration("SYNTHETIC-DNA", role, media, digest, len(raw), width, height,
                                ReportArtifactBinding("SOURCE-DNA", digest),
                                ReportArtifactBinding("RIGHTS-DNA", "7"*64))

    def manifest(self, raw: bytes, **changes: object) -> AssetManifest:
        return AssetManifest((self.declaration(raw, **changes),))

    def inspect(self, data: bytes | None = None, *, expected: AssetManifest | None = None,
                resolved: AssetManifest | None = None):
        raw = self.good if data is None else data
        if expected is None:
            expected = self.exp if data is None else self.manifest(raw)
        if resolved is None:
            resolved = self.res if data is None else self.manifest(raw)
        return self.m.inspect_staged_png(
            expected_manifest=expected, resolved_manifest=resolved, png_bytes=raw)

    def reject(self, raw: bytes):
        with self.assertRaises(self.m.PngInspectionError):
            if not raw:
                self.inspect(raw, expected=self.exp, resolved=self.res)
            else:
                self.inspect(raw)

    def test_one_synthetic_rgba_png_is_scanned_and_not_released(self):
        receipt = self.inspect().to_dict()
        self.assertEqual((receipt["width_px"], receipt["height_px"]), (2, 2))
        self.assertEqual(receipt["color_type"], 6)
        self.assertEqual(receipt["pixel_count"], 4)
        self.assertEqual(receipt["status"], "PNG_STRUCTURALLY_INSPECTED_UNQUALIFIED")

    def test_synthetic_rgb_png(self):
        receipt = self.inspect(png(color=2)).to_dict()
        self.assertEqual((receipt["color_type"], receipt["channels"]), (2, 3))

    def test_contiguous_split_idat_is_accepted(self):
        self.assertEqual(self.inspect(png(split_idat=True)).to_dict()["idat_chunk_count"], 2)

    def test_valid_scanline_filters_zero_through_four(self):
        for value in range(5):
            with self.subTest(filter=value):
                self.assertEqual(self.inspect(png(raw_filter=value)).to_dict()["height_px"], 2)

    def test_receipt_does_not_retain_or_echo_source_bytes(self):
        receipt = self.inspect()
        serialized = repr(receipt.to_dict()) + repr(receipt)
        self.assertNotIn("IDAT", serialized)
        self.assertNotIn(repr(self.good), serialized)
        self.assertFalse(hasattr(receipt, "png_bytes"))
        self.assertEqual(receipt.to_dict()["original_bytes_retained"], False)

    def test_inspection_does_not_claim_full_media_sanitization(self):
        evidence = self.inspect().to_dict()
        for name in ("image_pixels_decoded","image_sanitized","metadata_qualified",
                     "rights_verified","source_authenticated","renderer_activated",
                     "asset_activated","full_os_sandbox_claim"):
            self.assertIs(evidence[name], False, name)
        self.assertEqual(evidence["release_authorization"], "NOT_ESTABLISHED")

    def test_asset_manifest_and_exact_original_digest_are_bound(self):
        e=self.inspect().to_dict()
        self.assertEqual(e["input_sha256"],sha(self.good))
        self.assertEqual(e["asset_manifest_sha256"],self.exp.manifest_sha256)

    def test_expected_and_independent_resolved_manifests_must_match(self):
        altered= self.manifest(self.good)
        object.__setattr__(altered.assets[0], "asset_id", "FOREIGN")
        with self.assertRaises(self.m.PngInspectionError):
            self.inspect(resolved=altered)

    def test_stale_source_bytes_fail_digest_even_for_valid_png(self):
        with self.assertRaises(self.m.PngInspectionError):
            self.inspect(png(color=2), expected=self.exp, resolved=self.res)

    def test_only_png_dna_role_is_admitted(self):
        for role,media in (("brand-logo","image/svg+xml"),):
            with self.subTest(role=role):
                data=b'<svg xmlns="http://www.w3.org/2000/svg"/>'
                self.reject(data) if media == "image/png" else None
                manifest=self.manifest(data,role=role,media=media)
                with self.assertRaises(self.m.PngInspectionError):
                    self.inspect(data,expected=manifest,resolved=manifest)

    def test_reject_bytearray_memoryview_and_lists(self):
        for content in (bytearray(self.good),memoryview(self.good),[self.good]):
            with self.subTest(kind=type(content)):
                with self.assertRaises(self.m.PngInspectionError):
                    self.inspect(content,expected=self.exp,resolved=self.res)

    def test_reject_signature_or_non_png_payload(self):
        for data in (b"", b"GIF89a", b"\x00"*20, b"\x89PNG\r\n\x1b\n"+self.good[8:]):
            with self.subTest(len=len(data)):
                self.reject(data)

    def test_reject_ihdr_checksum_corruption(self):
        broken=bytearray(self.good);broken[29]^=1
        self.reject(bytes(broken))

    def test_reject_wrong_idat_crc(self):
        start=8+25
        broken=bytearray(self.good)
        broken[start+8]^=1
        self.reject(bytes(broken))

    def test_reject_broken_ihdr_payload_length(self):
        self.reject(png(ihdr_override=b"ABC"))

    def test_reject_zero_dimensions_and_large_declared_width(self):
        for width,height in ((0,2),(2,0),(16_385,1),(1,16_385)):
            with self.subTest(size=(width,height)):
                self.reject(png(width=width,height=height))

    def test_reject_pixel_budget_before_decompressing(self):
        self.reject(png(width=16_384,height=16_384,scanlines=b"\x00"))

    def test_reject_mismatched_declared_dimensions(self):
        manifest=self.manifest(self.good,width=4,height=2)
        with self.assertRaises(self.m.PngInspectionError):
            self.inspect(expected=manifest,resolved=manifest)

    def test_bit_depth_is_exactly_eight(self):
        for depth in (1,2,4,16):
            with self.subTest(depth=depth):
                self.reject(png(depth=depth))

    def test_unsupported_palette_grayscale_and_others_are_blocked(self):
        for c in (0,3,4,1):
            with self.subTest(color=c):
                self.reject(png(color=c))

    def test_interlaced_image_is_explicitly_unsupported(self):
        self.reject(png(interlace=1))

    def test_nonzero_compression_and_filter_methods_are_blocked(self):
        self.reject(png(comp=1))
        self.reject(png(filtering=1))

    def test_metadata_chunks_are_rejected_before_decode(self):
        for key,payload in ((b"tEXt",b"name\x00private"),(b"iTXt",b"XMP"),
                            (b"eXIf",b"metadata"),(b"iCCP",b"profile\x00x"),
                            (b"gAMA",b"\x00\x00\xb1\x8f")):
            with self.subTest(key=key):
                self.reject(png(before=(chunk(key,payload),)))

    def test_unknown_critical_chunk_rejected(self):
        self.reject(png(before=(chunk(b"PLTE",b"\x00\x00\x00"),)))

    def test_idat_before_ihdr_is_rejected(self):
        self.reject(PNG_SIGNATURE+chunk(b"IDAT",zlib.compress(b"x"))+chunk(b"IHDR",struct.pack(">IIBBBBB",2,2,8,6,0,0,0))+chunk(b"IEND",b""))

    def test_duplicate_ihdr_rejected(self):
        self.reject(png(before=(chunk(b"IHDR",struct.pack(">IIBBBBB",2,2,8,6,0,0,0)),)))

    def test_empty_idat_and_missing_idat_rejected(self):
        self.reject(png(compressed=b""))
        self.reject(PNG_SIGNATURE+chunk(b"IHDR",struct.pack(">IIBBBBB",2,2,8,6,0,0,0))+chunk(b"IEND",b""))

    def test_non_contiguous_idat_and_extraneous_chunk_blocked(self):
        self.reject(png(split_idat=True,between=(chunk(b"tEXt",b"x"),)))

    def test_corrupted_chunk_length_rejected(self):
        raw=bytearray(self.good);raw[8:12]=struct.pack(">I",9999999)
        self.reject(bytes(raw))

    def test_truncated_chunk_data_rejected(self):
        self.reject(self.good[:-3])
        self.reject(self.good[:20])

    def test_nonempty_iend_rejected(self):
        self.reject(self.good[:-12]+chunk(b"IEND",b"x"))

    def test_trailing_bytes_or_duplicate_iend_rejected(self):
        self.reject(self.good+b"junk")
        self.reject(self.good+chunk(b"IEND",b""))

    def test_extra_idat_after_iend_is_rejected(self):
        self.reject(self.good+chunk(b"IDAT",b"x"))

    def test_invalid_zlib_stream_rejected(self):
        self.reject(png(compressed=b"not_zlib"))

    def test_truncated_zlib_stream_rejected(self):
        compressed=zlib.compress(b"\x00"+b"\x01"*8)
        self.reject(png(compressed=compressed[:-2]))

    def test_zlib_bomb_more_than_declared_scanline_bytes_rejected(self):
        self.reject(png(compressed=zlib.compress(b"\x00"*400_000)))

    def test_zlib_unused_trailing_compressed_data_rejected(self):
        self.reject(png(compressed=zlib.compress((b"\x00"+b"\x01"*8)*2)+b"hidden"))

    def test_scanline_byte_count_exact_no_short_or_extra_data(self):
        self.reject(png(scanlines=b"\x00"+b"\x01"*8))
        self.reject(png(scanlines=(b"\x00"+b"\x01"*8)*2+b"x"))

    def test_invalid_filter_byte_rejected(self):
        self.reject(png(raw_filter=5))

    def test_encoded_input_budget_precedes_crc_and_hashing(self):
        with patch.object(self.m,"MAX_ENCODED_BYTES",len(self.good)-1):
            with patch.object(self.m.zlib,"crc32",side_effect=AssertionError("CRC SHOULD NOT RUN")):
                with self.assertRaises(self.m.PngInspectionError):
                    self.inspect()

    def test_total_idat_chunk_count_budget(self):
        with patch.object(self.m,"MAX_CHUNKS",2):
            self.reject(self.good)

    def test_zlib_decompressed_budget_is_finite(self):
        with patch.object(self.m,"MAX_SCANLINE_BYTES",12):
            self.reject(self.good)

    def test_no_disk_network_subprocess_or_new_font_use(self):
        with patch.object(socket,"getaddrinfo",side_effect=AssertionError("DNS forbidden")),\
             patch.object(subprocess,"Popen",side_effect=AssertionError("process forbidden")),\
             patch.object(Path,"read_bytes",side_effect=AssertionError("filesystem forbidden")):
            self.assertEqual(self.inspect().to_dict()["pixel_count"],4)

    def test_origins_bytes_and_declared_manifest_remain_unchanged(self):
        before=(sha(self.good),self.exp.manifest_sha256)
        self.inspect()
        self.assertEqual(before,(sha(self.good),self.exp.manifest_sha256))

    def test_content_free_error_message(self):
        raw=self.good+b"PRIVATE_SENTINEL"
        with self.assertRaises(self.m.PngInspectionError) as cm:
            self.inspect(raw)
        self.assertNotIn("PRIVATE_SENTINEL",str(cm.exception))

    def test_immutable_receipt_and_detached_export(self):
        x=self.inspect()
        with self.assertRaises(FrozenInstanceError):
            x.width_px=10
        d=x.to_dict()
        d["asset_id"]="tampered"
        self.assertEqual(x.to_dict()["asset_id"],"SYNTHETIC-DNA")

    def test_schema_is_closed_and_matches_actual_receipt(self):
        schema=json.loads((ROOT/"schemas/report-png-inspection.v1.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        self.assertFalse(list(Draft202012Validator(schema).iter_errors(self.inspect().to_dict())))

    def test_schema_rejects_false_qualification_and_unknown_fields(self):
        schema=json.loads((ROOT/"schemas/report-png-inspection.v1.schema.json").read_text())
        validator=Draft202012Validator(schema)
        for key,value in (("image_sanitized",True),("rights_verified",True),
                          ("renderer_activated",True),("release_authorization","AUTHORIZED"),
                          ("arbitrary_url","https://evil.invalid")):
            with self.subTest(key=key):
                sample={**self.inspect().to_dict(),key:value}
                self.assertTrue(list(validator.iter_errors(sample)))

    def test_legacy_renderer_rejects_inert_inspection_evidence(self):
        from reporting.adapters import build_html_css_and_pdf_adapter
        result=build_html_css_and_pdf_adapter(presentation_ir=self.inspect().to_dict())
        self.assertFalse(result.passed)
        self.assertIsNone(result.pdf_bytes)


if __name__ == "__main__":
    unittest.main()
