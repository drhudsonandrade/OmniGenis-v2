"""Closed opt-in structural UTF-16BE checks for generated ToUnicode bfchar targets."""
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
    """Bind real renderer bytes to the existing immutable page-window plan."""
    return plan_pdf_page_windows(
        pdf_sha256=sha256(pdf).hexdigest(), ir_sha256="a" * 64,
        page_count=pages, admitted_page_budget=pages,
        pages_per_window=16, inspector_profile_id=TEXT_PROFILE,
    )


class PdfToUnicodeUtf16beTargetsTests(unittest.TestCase):
    """Check code-unit shape only, never glyph meaning or PDF/UA."""

    @classmethod
    def setUpClass(cls):
        """Generate bounded real PDFs with native bfchar ToUnicode resources."""
        cls.pdfs = {n: generated_job_case(n)[1] for n in (1, 33, 64)}

    def setUp(self):
        """Require the new independent opt-in module."""
        self.assertIsNotNone(
            importlib.util.find_spec("reporting.pdf_tounicode_utf16be_targets"),
            "generated ToUnicode UTF-16BE target checker missing",
        )
        self.m = importlib.import_module("reporting.pdf_tounicode_utf16be_targets")
        self.w = importlib.import_module(
            "reporting._pdf_tounicode_utf16be_targets_worker"
        )
        self.pdf = self.pdfs[1]
        self.plan = matching_plan(self.pdf, 1)

    def inspect(self, **changed):
        """Inspect bytes using exact supported identity."""
        args = {
            "pdf_bytes": self.pdf,
            "plan": self.plan,
            "expected_plan_sha256": self.plan.plan_sha256,
            "expected_language": "en-US",
        }
        return self.m.inspect_pdf_tounicode_utf16be_targets(**{**args, **changed})

    def reader(self):
        """Parse real renderer fixture independently."""
        return PdfReader(BytesIO(self.pdf), strict=True)

    @staticmethod
    def cmaps(reader):
        """Return raw native ToUnicode objects, not text extraction."""
        page = reader.get_object(reader.pages[0].indirect_reference)
        fonts = reader.get_object(
            reader.get_object(page.raw_get("/Resources")).raw_get("/Font")
        )
        return [
            reader.get_object(reader.get_object(ref).raw_get("/ToUnicode"))
            for ref in fonts.values()
        ]

    def mutate(self, before: bytes, after: bytes):
        """Change one decoded generated row, then recompress valid zlib."""
        reader = self.reader()
        cmap = self.cmaps(reader)[0]
        decoded = zlib.decompress(cmap._data)
        self.assertIn(before, decoded)
        cmap._data = zlib.compress(decoded.replace(before, after, 1))
        return reader

    def verify(self, reader):
        """Run structural worker verification for an already parsed PDF."""
        return self.w._verify_utf16be_targets(reader, expected_pages=1)

    def test_generated_single_and_multipage_target_shape(self):
        """Admit bounded native output and publish no decoded characters."""
        for pages in (1, 33, 64):
            with self.subTest(pages=pages):
                pdf = self.pdfs[pages]
                plan = matching_plan(pdf, pages)
                receipt = self.inspect(
                    pdf_bytes=pdf, plan=plan,
                    expected_plan_sha256=plan.plan_sha256,
                )
                result = receipt.to_dict()
                self.assertEqual(result["status"], "TOUNICODE_UTF16BE_TARGETS_ADMITTED")
                self.assertEqual(result["tounicode_stream_count"], 3)
                self.assertEqual(result["cmap_framed_stream_count"], 3)
                self.assertEqual(result["utf16be_target_count"], {1: 50, 33: 68, 64: 68}[pages])
                self.assertGreaterEqual(result["utf16be_code_unit_count"], result["utf16be_target_count"])
                self.assertGreaterEqual(result["utf16be_scalar_count"], result["utf16be_target_count"])
                self.assertLessEqual(result["utf16be_scalar_count"], result["utf16be_code_unit_count"])
                self.assertEqual(
                    result["utf16be_code_unit_count"] - result["utf16be_scalar_count"],
                    result["utf16be_surrogate_pair_count"],
                )
                self.assertIs(result["cmap_utf16be_scalar_shape_valid"], True)
                self.assertEqual(result["pdf_sha256"], sha256(pdf).hexdigest())
                self.assertEqual(len(result["prior_tounicode_cmap_frame_sha256"]), 64)
                for key in (
                    "cmap_syntax_audited", "unicode_mappings_audited",
                    "glyph_meanings_verified", "glyph_widths_audited",
                    "reading_order_verified", "pdf_ua_qualified",
                    "worker_results_authenticated", "default_pipeline_activated",
                    "release_authorized",
                ):
                    self.assertIs(result[key], False)

    def test_unpaired_and_misordered_surrogates_fail_closed(self):
        """Reject isolated high/low surrogate and malformed pair sequences."""
        variants = (
            b"<D800>", b"<DC00>", b"<D8000041>", b"<0041DC00>",
            b"<D800D800>", b"<D83D0041>", b"<D800D800DC00>",
            b"<D83DDE00DC00>",
        )
        for target in variants:
            with self.subTest(target=target):
                reader = self.mutate(
                    b"<0036> <0053>", b"<0036> " + target
                )
                with self.assertRaises(ValueError):
                    self.verify(reader)

    def test_valid_surrogate_pair_and_multiple_scalars(self):
        """Accept BMP and non-BMP scalar code-unit sequences without meaning checks."""
        baseline = self.verify(self.reader())
        emoji = self.verify(self.mutate(
            b"<0036> <0053>", b"<0036> <D83DDE00>",
        ))
        self.assertEqual(emoji["utf16be_target_count"], baseline["utf16be_target_count"])
        self.assertEqual(emoji["utf16be_code_unit_count"], baseline["utf16be_code_unit_count"] + 1)
        self.assertEqual(emoji["utf16be_scalar_count"], baseline["utf16be_scalar_count"])
        self.assertEqual(emoji["utf16be_surrogate_pair_count"], baseline["utf16be_surrogate_pair_count"] + 1)
        two = self.verify(self.mutate(
            b"<0036> <0053>", b"<0036> <00410042>",
        ))
        self.assertEqual(two["utf16be_scalar_count"], baseline["utf16be_scalar_count"] + 1)
        self.assertEqual(two["utf16be_surrogate_pair_count"], baseline["utf16be_surrogate_pair_count"])

    def test_codepoints_do_not_prove_correct_mapping(self):
        """Admit U+0000 as well-shaped while explicitly declining semantic approval."""
        result = self.verify(self.mutate(
            b"<0036> <0053>", b"<0036> <0000>",
        ))
        self.assertTrue(result["cmap_utf16be_scalar_shape_valid"])
        self.assertFalse(self.m.tounicode_utf16be_targets_profile()["unicode_mappings_audited"])

    def test_inherit_frame_zlib_and_row_envelopes(self):
        """A new child must not bypass parent framing or compressed-stream policy."""
        with self.assertRaises(ValueError):
            self.verify(self.mutate(b"begincmap\n", b"beginCMAP\n"))
        with self.assertRaises(ValueError):
            self.verify(self.mutate(b"<0036> <0053>", b"<0036> <" + b"0041" * 17 + b">"))
        reader = self.reader()
        self.cmaps(reader)[0]._data = self.cmaps(reader)[0]._data[:-1]
        with self.assertRaises(ValueError):
            self.verify(reader)

    def test_profile_pin_default_off_and_invalid_input(self):
        """Check versioned manifest and fail before child on invalid source."""
        manifest = Path(__file__).resolve().parents[1] / (
            "reporting/pdf-tounicode-utf16be-targets.v1.json"
        )
        self.assertEqual(json.loads(manifest.read_text()), self.m.tounicode_utf16be_targets_profile())
        self.assertEqual(self.m.PROFILE_SHA256, self.m._FIXED_PROFILE_SHA256)
        self.assertEqual(
            self.m.previous.PROFILE_SHA256,
            self.m.tounicode_utf16be_targets_profile()[
                "previous_tounicode_cmap_frame_profile_sha256"
            ],
        )
        with patch.dict(os.environ, {self.m._DISABLE: "1"}):
            with self.assertRaises(self.m.PdfToUnicodeUtf16beTargetsError):
                self.inspect()
        with patch.object(self.m, "_run_worker") as child:
            for bad in (
                {"pdf_bytes": bytearray(self.pdf)},
                {"pdf_bytes": self.pdfs[33]},
                {"expected_plan_sha256": "0" * 64},
                {"expected_language": "pt-BR"},
                {"plan": object()},
            ):
                with self.subTest(bad=sorted(bad)):
                    with self.assertRaises(self.m.PdfToUnicodeUtf16beTargetsError):
                        self.inspect(**bad)
            child.assert_not_called()

    def test_receipt_is_content_free_and_mutation_detected(self):
        """Output counts/digests only; SHA-256 is not an independent signature."""
        receipt = self.inspect()
        data = receipt.to_bytes()
        self.assertEqual(sha256(data).hexdigest(), receipt.inspection_sha256)
        self.assertNotIn(b"begincmap", data)
        self.assertNotIn(b"D83D", data)
        with self.assertRaises(FrozenInstanceError):
            receipt.utf16be_code_unit_count = 7
        object.__setattr__(receipt, "utf16be_code_unit_count", 7)
        with self.assertRaises(self.m.PdfToUnicodeUtf16beTargetsError):
            receipt.to_bytes()

    def test_child_protocol_rejects_extra_keys_wrong_counts(self):
        """Type-check bounded child envelope before creating a sealed receipt."""
        parent = self.m.previous.inspect_pdf_tounicode_cmap_frame(
            pdf_bytes=self.pdf, plan=self.plan,
            expected_plan_sha256=self.plan.plan_sha256,
            expected_language="en-US",
        )
        identity = self.m._identity_from_plan(self.plan)
        record = json.loads(self.m._run_worker(self.pdf, identity))
        record["inspection"]["utf16be_surrogate_pair_count"] = -1
        with self.assertRaises(self.m.PdfToUnicodeUtf16beTargetsError):
            self.m._decode(self.m._canonical(record), identity, parent)
        record["inspection"]["utf16be_surrogate_pair_count"] = 0
        record["inspection"]["extra"] = "not allowed"
        with self.assertRaises(self.m.PdfToUnicodeUtf16beTargetsError):
            self.m._decode(self.m._canonical(record), identity, parent)


if __name__ == "__main__":
    unittest.main()
