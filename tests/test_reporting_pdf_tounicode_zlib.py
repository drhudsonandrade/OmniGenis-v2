"""TDD for opt-in bounded zlib completion of native ToUnicode CMaps."""
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
import zlib

from pypdf import PdfReader
from reporting.page_windows import plan_pdf_page_windows
from reporting.pdf_text_windows import PROFILE_ID as TEXT_PROFILE
from tests.test_reporting_pdf_source_inspection_job import generated_job_case


def matching_plan(pdf: bytes, pages: int):
    return plan_pdf_page_windows(
        pdf_sha256=sha256(pdf).hexdigest(), ir_sha256="a" * 64,
        page_count=pages, admitted_page_budget=pages,
        pages_per_window=16, inspector_profile_id=TEXT_PROFILE,
    )


class PdfToUnicodeZlibTests(unittest.TestCase):
    """A successful transport check makes no Unicode or PDF/UA assertion."""

    @classmethod
    def setUpClass(cls):
        cls.pdfs = {pages: generated_job_case(pages)[1]
                    for pages in (1, 33, 64)}

    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("reporting.pdf_tounicode_zlib"),
            "native ToUnicode zlib completion checker is not implemented",
        )
        self.m = importlib.import_module("reporting.pdf_tounicode_zlib")
        self.worker = importlib.import_module("reporting._pdf_tounicode_zlib_worker")
        self.pdf = self.pdfs[1]
        self.plan = matching_plan(self.pdf, 1)

    def inspect(self, **changed):
        args = {
            "pdf_bytes": self.pdf, "plan": self.plan,
            "expected_plan_sha256": self.plan.plan_sha256,
            "expected_language": "en-US",
        }
        return self.m.inspect_pdf_tounicode_zlib(**{**args, **changed})

    def reader(self, pages=1):
        return PdfReader(BytesIO(self.pdfs[pages]), strict=True)

    @staticmethod
    def cmaps(reader):
        page = reader.get_object(reader.pages[0].indirect_reference)
        resources = reader.get_object(page.raw_get("/Resources"))
        fonts = reader.get_object(resources.raw_get("/Font"))
        return [
            reader.get_object(reader.get_object(ref).raw_get("/ToUnicode"))
            for ref in fonts.values()
        ]

    def verify(self, reader, pages=1):
        return self.worker._verify_tounicode_zlib(
            reader, expected_pages=pages,
            direct_count=len(reader.xref[0]),
            compressed_count=len(reader.xref_objStm),
        )

    def test_generated_one_thirty_three_sixty_four_complete_zlib(self):
        for pages in (1, 33, 64):
            with self.subTest(pages=pages):
                pdf = self.pdfs[pages]
                plan = matching_plan(pdf, pages)
                receipt = self.inspect(
                    pdf_bytes=pdf, plan=plan,
                    expected_plan_sha256=plan.plan_sha256,
                )
                result = receipt.to_dict()
                self.assertEqual(result["status"], "TOUNICODE_ZLIB_COMPLETION_ADMITTED")
                self.assertEqual(result["tounicode_stream_count"], 3)
                self.assertEqual(result["tounicode_completed_stream_count"], 3)
                self.assertIs(result["tounicode_zlib_complete"], True)
                self.assertEqual(result["pdf_sha256"], sha256(pdf).hexdigest())
                self.assertEqual(result["page_count"], pages)
                self.assertEqual(len(result["prior_tounicode_header_sha256"]), 64)
                for key in (
                    "unicode_mappings_audited", "cmap_syntax_audited",
                    "glyph_widths_audited", "font_programs_audited",
                    "reading_order_verified", "pdf_ua_qualified",
                    "release_authorized", "default_pipeline_activated",
                    "worker_results_authenticated",
                ):
                    self.assertIs(result[key], False, key)

    def test_corrupt_adler32_truncated_trailing_and_invalid_deflate(self):
        reader = self.reader()
        raw = self.cmaps(reader)[0]._data
        variants = (
            raw[:-1], raw + b"junk",
            raw[:-1] + bytes([raw[-1] ^ 1]),
            raw[:2] + b"not-deflate" + raw[-4:],
        )
        for mutated in variants:
            with self.subTest(length=len(mutated), suffix=mutated[-8:].hex()):
                current = self.reader()
                self.cmaps(current)[0]._data = mutated
                with self.assertRaises(ValueError):
                    self.verify(current)

    def test_bounded_decompression_and_aggregate_budget(self):
        reader = self.reader()
        self.cmaps(reader)[0]._data = zlib.compress(
            b"A" * (self.worker.MAX_DECODED_CMAP_BYTES + 1)
        )
        with self.assertRaises(ValueError):
            self.verify(reader)
        reader = self.reader()
        for cmap in self.cmaps(reader):
            cmap._data = zlib.compress(b"B" * 200000)
        with self.assertRaises(ValueError):
            self.verify(reader)

    def test_prior_header_and_cid_evidence_remain_mandatory(self):
        reader = self.reader()
        self.cmaps(reader)[0]._data = b"\x00\x00" + self.cmaps(reader)[0]._data[2:]
        with self.assertRaises(ValueError):
            self.verify(reader)
        reader = self.reader()
        page = reader.get_object(reader.pages[0].indirect_reference)
        fonts = reader.get_object(reader.get_object(page.raw_get("/Resources")).raw_get("/Font"))
        font = reader.get_object(next(iter(fonts.values())))
        descendant = reader.get_object(font.raw_get("/DescendantFonts")[0])
        from pypdf.generic import NumberObject
        descendant.raw_get("/W")[1][0] = NumberObject(0)
        with self.assertRaises(ValueError):
            self.verify(reader)

    def test_corrupt_generated_pdf_parent_accepts_but_new_child_rejects(self):
        """A syntactically valid zlib header must not mask Adler-32 damage."""
        raw = self.cmaps(self.reader())[0]._data
        offset = self.pdf.index(raw)
        altered_raw = raw[:-1] + bytes([raw[-1] ^ 1])
        altered = self.pdf[:offset] + altered_raw + self.pdf[offset + len(raw):]
        plan = matching_plan(altered, 1)
        args = {
            "pdf_bytes": altered, "plan": plan,
            "expected_plan_sha256": plan.plan_sha256,
            "expected_language": "en-US",
        }
        self.assertTrue(
            self.m.previous.inspect_pdf_tounicode_header(**args).tounicode_headers_native
        )
        with self.assertRaises(self.m.PdfToUnicodeZlibError):
            self.m.inspect_pdf_tounicode_zlib(**args)

    def test_manifest_profile_and_explicit_disable_fail_closed(self):
        source = Path(__file__).resolve().parents[1] / "reporting/pdf-tounicode-zlib.v1.json"
        self.assertEqual(json.loads(source.read_text()), self.m.tounicode_zlib_profile())
        self.assertEqual(
            sha256(self.m._canonical(self.m.tounicode_zlib_profile())).hexdigest(),
            self.m.PROFILE_SHA256,
        )
        self.assertEqual(self.m.PROFILE_SHA256, self.m._FIXED_PROFILE_SHA256)
        self.assertEqual(
            self.m.previous.PROFILE_SHA256,
            self.m.tounicode_zlib_profile()["previous_tounicode_header_profile_sha256"],
        )
        with patch.dict(os.environ, {self.m._DISABLE: "1"}):
            with self.assertRaises(self.m.PdfToUnicodeZlibError):
                self.inspect()

    def test_input_identity_or_language_rejected_before_worker(self):
        with patch.object(self.m, "_run_worker") as child:
            for changed in (
                {"pdf_bytes": bytearray(self.pdf)},
                {"pdf_bytes": self.pdfs[33]},
                {"pdf_bytes": b"invalid"},
                {"plan": object()},
                {"expected_plan_sha256": "f" * 64},
                {"expected_language": "pt-BR"},
            ):
                with self.subTest(changed=sorted(changed)):
                    with self.assertRaises(self.m.PdfToUnicodeZlibError):
                        self.inspect(**changed)
            child.assert_not_called()

    def test_sealed_receipt_content_free_and_immutable(self):
        receipt = self.inspect()
        self.assertEqual(receipt.inspection_sha256, sha256(receipt.to_bytes()).hexdigest())
        self.assertNotIn(b"begincmap", receipt.to_bytes().lower())
        with self.assertRaises(FrozenInstanceError):
            receipt.tounicode_completed_stream_count = 9
        object.__setattr__(receipt, "tounicode_completed_stream_count", 2)
        with self.assertRaises(self.m.PdfToUnicodeZlibError):
            receipt.to_bytes()

    def test_child_protocol_rejects_count_and_extra_key(self):
        ancestor = self.m.previous.inspect_pdf_tounicode_header(
            pdf_bytes=self.pdf, plan=self.plan,
            expected_plan_sha256=self.plan.plan_sha256,
            expected_language="en-US",
        )
        identity = self.m._identity_from_plan(self.plan)
        record = json.loads(self.m._run_worker(self.pdf, identity))
        record["inspection"]["tounicode_completed_stream_count"] = 2
        with self.assertRaises(self.m.PdfToUnicodeZlibError):
            self.m._decode(self.m._canonical(record), identity, ancestor)
        record["inspection"]["tounicode_completed_stream_count"] = 3
        record["inspection"]["unexpected"] = True
        with self.assertRaises(self.m.PdfToUnicodeZlibError):
            self.m._decode(self.m._canonical(record), identity, ancestor)


if __name__ == "__main__":
    unittest.main()
