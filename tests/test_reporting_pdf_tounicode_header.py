"""TDD: confined native ToUnicode Flate header checks without decompression."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
from hashlib import sha256
from io import BytesIO
import importlib
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from pypdf import PdfReader
from pypdf.generic import NameObject, NumberObject

from reporting.page_windows import plan_pdf_page_windows
from reporting.pdf_text_windows import PROFILE_ID as TEXT_PROFILE
from tests.test_reporting_pdf_source_inspection_job import generated_job_case


_PDFS: dict[int, bytes] = {}


def matching_plan(pdf: bytes, pages: int):
    return plan_pdf_page_windows(
        pdf_sha256=sha256(pdf).hexdigest(), ir_sha256="a" * 64,
        page_count=pages, admitted_page_budget=pages,
        pages_per_window=16, inspector_profile_id=TEXT_PROFILE,
    )


class PdfToUnicodeHeaderTests(unittest.TestCase):
    """Admission never decompresses or interprets Unicode CMap mappings."""

    @classmethod
    def setUpClass(cls):
        for pages in (1, 33, 64):
            _PDFS[pages] = generated_job_case(pages)[1]

    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("reporting.pdf_tounicode_header"),
            "native ToUnicode raw Flate-header admission is not implemented",
        )
        self.m = importlib.import_module("reporting.pdf_tounicode_header")
        self.worker = importlib.import_module("reporting._pdf_tounicode_header_worker")
        self.pdf = _PDFS[1]
        self.plan = matching_plan(self.pdf, 1)

    def inspect(self, **changed):
        args = {
            "pdf_bytes": self.pdf, "plan": self.plan,
            "expected_plan_sha256": self.plan.plan_sha256,
            "expected_language": "en-US",
        }
        return self.m.inspect_pdf_tounicode_header(**{**args, **changed})

    def reader(self, pages=1):
        return PdfReader(BytesIO(_PDFS[pages]), strict=True)

    def cmaps(self, reader):
        page = reader.get_object(reader.pages[0].indirect_reference)
        resources = reader.get_object(page.raw_get("/Resources"))
        fonts = reader.get_object(resources.raw_get("/Font"))
        return [
            reader.get_object(reader.get_object(ref).raw_get("/ToUnicode"))
            for ref in fonts.values()
        ]

    def verify(self, reader, pages=1):
        return self.worker._verify_tounicode_headers(
            reader, expected_pages=pages,
            direct_count=len(reader.xref[0]),
            compressed_count=len(reader.xref_objStm),
        )

    def test_generated_one_thirty_three_sixty_four_raw_flate_headers(self):
        for pages in (1, 33, 64):
            with self.subTest(pages=pages):
                pdf = _PDFS[pages]
                plan = matching_plan(pdf, pages)
                receipt = self.inspect(
                    pdf_bytes=pdf, plan=plan,
                    expected_plan_sha256=plan.plan_sha256,
                )
                row = receipt.to_dict()
                self.assertEqual(row["status"], "TOUNICODE_FLATE_HEADER_ADMITTED")
                self.assertEqual(row["tounicode_stream_count"], 3)
                self.assertEqual(row["tounicode_checked_header_count"], 3)
                self.assertTrue(row["tounicode_headers_native"])
                self.assertEqual(row["pdf_sha256"], sha256(pdf).hexdigest())
                self.assertEqual(row["page_count"], pages)
                self.assertEqual(len(row["prior_cid_widths_sha256"]), 64)
                for key in (
                    "tounicode_decoded", "unicode_mappings_audited",
                    "glyph_widths_audited", "font_programs_audited",
                    "reading_order_verified", "pdf_ua_qualified",
                    "release_authorized", "default_pipeline_activated",
                    "worker_results_authenticated",
                ):
                    self.assertIs(row[key], False, key)

    def test_native_bad_cmf_flg_and_truncated_raw_zlib_headers_rejected(self):
        # This mutation passes the predecessor's raw stream/Filter checks:
        # the new verifier must reject it without calling decompress().
        for prefix in (b"\x00\x00", b"\x88\x1c", b"\x78\x00", b"\x78\x20", b"\x78"):
            with self.subTest(prefix=prefix.hex()):
                reader = self.reader()
                cmap = self.cmaps(reader)[0]
                original = cmap._data
                cmap._data = prefix if len(prefix) == 1 else prefix + original[2:]
                with self.assertRaises(ValueError):
                    self.verify(reader)

    def test_unchanged_raw_streams_prove_three_headers_even_on_many_pages(self):
        for pages in (1, 33, 64):
            with self.subTest(pages=pages):
                self.assertEqual(
                    self.verify(self.reader(pages), pages),
                    {
                        "tounicode_stream_count": 3,
                        "tounicode_checked_header_count": 3,
                        "tounicode_headers_native": True,
                    },
                )

    def test_predecessor_font_shape_filter_or_index_change_rejected(self):
        reader = self.reader()
        self.cmaps(reader)[0][NameObject("/Filter")] = NameObject("/LZWDecode")
        with self.assertRaises(ValueError):
            self.verify(reader)
        reader = self.reader()
        self.cmaps(reader)[0]._data = bytearray(self.cmaps(reader)[0]._data)
        with self.assertRaises(ValueError):
            self.verify(reader)
        reader = self.reader()
        page = reader.get_object(reader.pages[0].indirect_reference)
        resources = reader.get_object(page.raw_get("/Resources"))
        font = reader.get_object(next(iter(reader.get_object(resources.raw_get("/Font")).values())))
        cid = reader.get_object(font.raw_get("/DescendantFonts")[0])
        cid.raw_get("/W")[1][0] = NumberObject(0)
        with self.assertRaises(ValueError):
            self.verify(reader)
        reader = self.reader()
        reader.xref[0].pop(next(iter(reader.xref[0])))
        with self.assertRaises(ValueError):
            self.verify(reader)

    def test_manifest_profile_and_disabled_configuration_fail_closed(self):
        path = Path(__file__).resolve().parents[1] / "reporting/pdf-tounicode-header.v1.json"
        self.assertEqual(json.loads(path.read_text()), self.m.tounicode_header_profile())
        self.assertEqual(
            sha256(self.m._canonical(self.m.tounicode_header_profile())).hexdigest(),
            self.m.PROFILE_SHA256,
        )
        self.assertEqual(self.m.PROFILE_SHA256, self.m._FIXED_PROFILE_SHA256)
        self.assertEqual(
            self.m.previous.PROFILE_SHA256,
            self.m.tounicode_header_profile()["previous_cid_widths_profile_sha256"],
        )
        with patch.dict(os.environ, {self.m._DISABLE: "1"}):
            with self.assertRaises(self.m.PdfToUnicodeHeaderError):
                self.inspect()

    def test_input_mismatched_pdf_sealed_plan_or_language_fails_before_worker(self):
        with patch.object(self.m, "_run_worker") as child:
            for changed in (
                {"pdf_bytes": bytearray(self.pdf)},
                {"pdf_bytes": _PDFS[33]},
                {"pdf_bytes": b"invalid"},
                {"plan": object()},
                {"expected_plan_sha256": "f" * 64},
                {"expected_language": "pt-BR"},
            ):
                with self.subTest(changed=sorted(changed)):
                    with self.assertRaises(self.m.PdfToUnicodeHeaderError):
                        self.inspect(**changed)
            child.assert_not_called()

    def test_receipt_immutable_content_free_and_checksum_bound(self):
        receipt = self.inspect()
        self.assertNotIn(self.pdf[:64], receipt.to_bytes())
        self.assertEqual(receipt.inspection_sha256, sha256(receipt.to_bytes()).hexdigest())
        with self.assertRaises(FrozenInstanceError):
            receipt.tounicode_stream_count = 9
        object.__setattr__(receipt, "tounicode_checked_header_count", 2)
        with self.assertRaises(self.m.PdfToUnicodeHeaderError):
            receipt.to_bytes()

    def test_malformed_child_protocol_and_mismatched_ancestor_rejected(self):
        ancestor = self.m.previous.inspect_pdf_cid_widths(
            pdf_bytes=self.pdf, plan=self.plan,
            expected_plan_sha256=self.plan.plan_sha256,
            expected_language="en-US",
        )
        identity = self.m._identity_from_plan(self.plan)
        raw = self.m._run_worker(self.pdf, identity)
        record = json.loads(raw)
        record["inspection"]["tounicode_stream_count"] = 4
        with self.assertRaises(self.m.PdfToUnicodeHeaderError):
            self.m._decode(self.m._canonical(record), identity, ancestor)
        record["inspection"]["tounicode_stream_count"] = 3
        record["inspection"]["unexpected"] = True
        with self.assertRaises(self.m.PdfToUnicodeHeaderError):
            self.m._decode(self.m._canonical(record), identity, ancestor)


if __name__ == "__main__":
    unittest.main()
