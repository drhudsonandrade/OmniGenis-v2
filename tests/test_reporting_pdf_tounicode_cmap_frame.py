"""Opt-in tests for bounded native ToUnicode bfchar CMap framing."""
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
    """Create an exact digest-bound window plan for synthetic generated PDF."""
    return plan_pdf_page_windows(
        pdf_sha256=sha256(pdf).hexdigest(), ir_sha256="a" * 64,
        page_count=pages, admitted_page_budget=pages,
        pages_per_window=16, inspector_profile_id=TEXT_PROFILE,
    )


class PdfToUnicodeCmapFrameTests(unittest.TestCase):
    """Accept only a small native bfchar framing grammar, not Unicode meaning."""

    @classmethod
    def setUpClass(cls):
        """Create real renderer-produced PDFs containing three native CMaps."""
        cls.pdfs = {pages: generated_job_case(pages)[1]
                    for pages in (1, 33, 64)}

    def setUp(self):
        """Require the opt-in module before constructing a receipt."""
        self.assertIsNotNone(
            importlib.util.find_spec("reporting.pdf_tounicode_cmap_frame"),
            "native ToUnicode CMap bfchar framing checker missing",
        )
        self.m = importlib.import_module("reporting.pdf_tounicode_cmap_frame")
        self.worker = importlib.import_module(
            "reporting._pdf_tounicode_cmap_frame_worker",
        )
        self.pdf = self.pdfs[1]
        self.plan = matching_plan(self.pdf, 1)

    def inspect(self, **changed):
        """Run public admission with complete defaults or specified changes."""
        args = {
            "pdf_bytes": self.pdf, "plan": self.plan,
            "expected_plan_sha256": self.plan.plan_sha256,
            "expected_language": "en-US",
        }
        return self.m.inspect_pdf_tounicode_cmap_frame(**{**args, **changed})

    def reader(self, pages=1):
        """Construct an independently parsed strict synthetic PDF fixture."""
        return PdfReader(BytesIO(self.pdfs[pages]), strict=True)

    @staticmethod
    def cmaps(reader):
        """Access native ToUnicode stream objects in a synthetic PDF."""
        page = reader.get_object(reader.pages[0].indirect_reference)
        resources = reader.get_object(page.raw_get("/Resources"))
        fonts = reader.get_object(resources.raw_get("/Font"))
        return [
            reader.get_object(reader.get_object(ref).raw_get("/ToUnicode"))
            for ref in fonts.values()
        ]

    def verify(self, reader, pages=1):
        """Run worker-side native framing with exact predecessor counts."""
        return self.worker._verify_tounicode_cmap_frame(
            reader, expected_pages=pages,
            direct_count=len(reader.xref[0]),
            compressed_count=len(reader.xref_objStm),
        )

    def mutate_first(self, before: bytes, after: bytes):
        """Replace one token in a synthetic CMap and keep zlib intact."""
        reader = self.reader()
        cmap = self.cmaps(reader)[0]
        data = zlib.decompress(cmap._data)
        self.assertIn(before, data)
        cmap._data = zlib.compress(data.replace(before, after, 1))
        return reader

    def test_generated_one_thirty_three_sixty_four_native_bfchar_frames(self):
        """Count native bfchar records without interpreting Unicode mappings."""
        for pages in (1, 33, 64):
            with self.subTest(pages=pages):
                pdf = self.pdfs[pages]
                plan = matching_plan(pdf, pages)
                receipt = self.inspect(
                    pdf_bytes=pdf, plan=plan,
                    expected_plan_sha256=plan.plan_sha256,
                )
                result = receipt.to_dict()
                self.assertEqual(result["status"], "TOUNICODE_CMAP_FRAME_ADMITTED")
                self.assertEqual(result["tounicode_stream_count"], 3)
                self.assertEqual(result["cmap_framed_stream_count"], 3)
                self.assertEqual(result["cmap_bfchar_block_count"], 3)
                self.assertEqual(result["cmap_bfchar_record_count"], {1: 50, 33: 68, 64: 68}[pages])
                self.assertIs(result["cmap_native_bfchar_frame_valid"], True)
                self.assertEqual(result["pdf_sha256"], sha256(pdf).hexdigest())
                self.assertEqual(len(result["prior_tounicode_zlib_sha256"]), 64)
                for key in (
                    "cmap_syntax_audited", "unicode_mappings_audited",
                    "font_programs_audited", "glyph_widths_audited",
                    "reading_order_verified", "pdf_ua_qualified",
                    "worker_results_authenticated", "default_pipeline_activated",
                    "release_authorized",
                ):
                    self.assertIs(result[key], False, key)

    def test_wrong_native_prolog_footer_codespace_and_operators_fail(self):
        """Reject changed native tokens, forbidden grammar and extra content."""
        variants = (
            (b"begincmap\n", b"begincMax\n"),
            (b"endcmap\n", b"endcMax\n"),
            (b"/CMapType 2 def", b"/CMapType 3 def"),
            (b"/Ordering (UCS)", b"/Ordering (Other)"),
            (b"<0000> <ffff>", b"<0000> <fffe>"),
            (b"1 begincodespacerange", b"2 begincodespacerange"),
            (b"endbfchar\n", b"endbfrange\n"),
            (b"beginbfchar\n", b"beginbfrange\n"),
            (b"end\nend", b"end\nend\nextra"),
            (b"12 dict begin", b"13 dict begin"),
        )
        for before, after in variants:
            with self.subTest(before=before, after=after):
                with self.assertRaises(ValueError):
                    self.verify(self.mutate_first(before, after))

    def test_bfchar_counts_hex_rows_and_ascii_shape_fail_closed(self):
        """Reject malformed rows and block counts even with valid zlib."""
        variants = (
            (b"24 beginbfchar", b"23 beginbfchar"),
            (b"24 beginbfchar", b"25 beginbfchar"),
            (b"24 beginbfchar", b"0 beginbfchar"),
            (b"24 beginbfchar", b"101 beginbfchar"),
            (b"<0036> <0053>", b"<G036> <0053>"),
            (b"<0036> <0053>", b"<0036> <005>"),
            (b"<0036> <0053>", b"<0036> <0053> extra"),
            (b"<0036> <0053>", b"<0036> <0053>\n\t"),
            (b"<0036> <0053>", b"<0036> <0053>\r"),
            (b"<0036> <0053>", b"<0036> <0053>\x00"),
            (b"<0036> <0053>", b"<0036> <0053>\xff"),
        )
        for before, after in variants:
            with self.subTest(before=before, after=after):
                with self.assertRaises(ValueError):
                    self.verify(self.mutate_first(before, after))

    def test_multiple_native_bfchar_blocks_are_counted_exactly(self):
        """Admit repeated native blocks with canonical decimal row counts."""
        reader = self.reader()
        cmap = self.cmaps(reader)[0]
        data = zlib.decompress(cmap._data)
        prefix, remainder = data.split(b"24 beginbfchar\n", 1)
        records, suffix = remainder.split(b"endbfchar\n", 1)
        rows = records.splitlines(keepends=True)
        self.assertEqual(len(rows), 24)
        modified = (
            prefix + b"10 beginbfchar\n" + b"".join(rows[:10]) +
            b"endbfchar\n14 beginbfchar\n" + b"".join(rows[10:]) +
            b"endbfchar\n" + suffix
        )
        cmap._data = zlib.compress(modified)
        result = self.verify(reader)
        self.assertEqual(result["cmap_bfchar_block_count"], 4)
        self.assertEqual(result["cmap_bfchar_record_count"], 50)

    def test_valid_hex_row_is_not_a_unicode_semantic_approval(self):
        """Preserve the explicit nonclaim by admitting well-shaped changed values."""
        reader = self.mutate_first(b"<0036> <0053>", b"<0036> <0000>")
        result = self.verify(reader)
        self.assertEqual(result["cmap_bfchar_record_count"], 50)
        self.assertIs(result["cmap_native_bfchar_frame_valid"], True)

    def test_bfchar_block_count_remains_finite(self):
        """Reject over-budget but syntactically valid repeated native blocks."""
        reader = self.reader()
        cmap = self.cmaps(reader)[0]
        data = zlib.decompress(cmap._data)
        prefix, remainder = data.split(b"24 beginbfchar\n", 1)
        _, suffix = remainder.split(b"endbfchar\n", 1)
        block = b"1 beginbfchar\n<0001> <0041>\nendbfchar\n"
        cmap._data = zlib.compress(
            prefix + block * (self.worker.MAX_BFCHAR_BLOCKS + 1) + suffix
        )
        with self.assertRaises(ValueError):
            self.verify(reader)

    def test_ancestor_integrity_and_decompression_budgets_still_required(self):
        """Do not bypass bounded Adler-32 or native CID-width prerequisites."""
        reader = self.reader()
        cmap = self.cmaps(reader)[0]
        cmap._data = cmap._data[:-1]
        with self.assertRaises(ValueError):
            self.verify(reader)
        reader = self.reader()
        self.cmaps(reader)[0]._data = zlib.compress(b"A" * 262145)
        with self.assertRaises(ValueError):
            self.verify(reader)

    def test_manifest_frozen_profile_and_opt_out(self):
        """Check canonical profile bytes and explicit environment disable."""
        path = Path(__file__).resolve().parents[1] / (
            "reporting/pdf-tounicode-cmap-frame.v1.json"
        )
        self.assertEqual(json.loads(path.read_text()), self.m.tounicode_cmap_frame_profile())
        self.assertEqual(self.m.PROFILE_SHA256, self.m._FIXED_PROFILE_SHA256)
        self.assertEqual(
            self.m.previous.PROFILE_SHA256,
            self.m.tounicode_cmap_frame_profile()[
                "previous_tounicode_zlib_profile_sha256"
            ],
        )
        with patch.dict(os.environ, {self.m._DISABLE: "1"}):
            with self.assertRaises(self.m.PdfToUnicodeCmapFrameError):
                self.inspect()

    def test_invalid_identity_and_language_rejected_before_child(self):
        """Fail before spawning a sandbox on mismatched source binding."""
        with patch.object(self.m, "_run_worker") as child:
            for changed in (
                {"pdf_bytes": bytearray(self.pdf)},
                {"pdf_bytes": self.pdfs[33]},
                {"pdf_bytes": b"not-pdf"},
                {"plan": object()},
                {"expected_plan_sha256": "f" * 64},
                {"expected_language": "pt-BR"},
            ):
                with self.subTest(changed=sorted(changed)):
                    with self.assertRaises(self.m.PdfToUnicodeCmapFrameError):
                        self.inspect(**changed)
            child.assert_not_called()

    def test_content_free_receipt_and_checksum_seal(self):
        """Do not return decoded CMap text and detect object mutation."""
        receipt = self.inspect()
        data = receipt.to_bytes()
        self.assertEqual(receipt.inspection_sha256, sha256(data).hexdigest())
        self.assertNotIn(b"begincmap", data.lower())
        self.assertNotIn(b"Adobe-Identity", data)
        with self.assertRaises(FrozenInstanceError):
            receipt.cmap_bfchar_record_count = 100
        object.__setattr__(receipt, "cmap_bfchar_record_count", 1)
        with self.assertRaises(self.m.PdfToUnicodeCmapFrameError):
            receipt.to_bytes()

    def test_child_protocol_rejects_extra_field_and_count_inconsistency(self):
        """Bind strict child schema, predecessor digest and exact counts."""
        prior = self.m.previous.inspect_pdf_tounicode_zlib(
            pdf_bytes=self.pdf, plan=self.plan,
            expected_plan_sha256=self.plan.plan_sha256,
            expected_language="en-US",
        )
        identity = self.m._identity_from_plan(self.plan)
        record = json.loads(self.m._run_worker(self.pdf, identity))
        record["inspection"]["cmap_bfchar_record_count"] = 0
        with self.assertRaises(self.m.PdfToUnicodeCmapFrameError):
            self.m._decode(self.m._canonical(record), identity, prior)
        record["inspection"]["cmap_bfchar_record_count"] = 50
        record["inspection"]["undocumented"] = True
        with self.assertRaises(self.m.PdfToUnicodeCmapFrameError):
            self.m._decode(self.m._canonical(record), identity, prior)


if __name__ == "__main__":
    unittest.main()
