"""Same-font explicit CID-width coverage in the opt-in generated PDF profile."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
from hashlib import sha256
from io import BytesIO
import importlib
import importlib.util
import json
import os
from pathlib import Path
import re
import unittest
from unittest.mock import patch
import zlib

from pypdf import PdfReader
from pypdf.generic import ArrayObject, NameObject, NumberObject
from reporting import _pdf_tounicode_cmap_frame_worker as frame
from tests.test_reporting_pdf_source_inspection_job import generated_job_case
from tests.test_reporting_pdf_tounicode_utf16be_targets import matching_plan


class PdfToUnicodeWidthCoverageTests(unittest.TestCase):
    """A font must not borrow another font's explicit width entries."""

    @classmethod
    def setUpClass(cls):
        cls.pdfs = {n: generated_job_case(n)[1] for n in (1, 33, 64)}

    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("reporting.pdf_tounicode_width_coverage"),
            "same-font explicit CID-width coverage checker missing",
        )
        self.m = importlib.import_module("reporting.pdf_tounicode_width_coverage")
        self.w = importlib.import_module("reporting._pdf_tounicode_width_coverage_worker")
        self.pdf = self.pdfs[1]
        self.plan = matching_plan(self.pdf, 1)

    def inspect(self, **changed):
        args = {
            "pdf_bytes": self.pdf, "plan": self.plan,
            "expected_plan_sha256": self.plan.plan_sha256,
            "expected_language": "en-US",
        }
        return self.m.inspect_pdf_tounicode_width_coverage(**{**args, **changed})

    def reader(self):
        return PdfReader(BytesIO(self.pdf), strict=True)

    def fonts(self, reader):
        page = reader.get_object(reader.pages[0].indirect_reference)
        resources = reader.get_object(page.raw_get("/Resources"))
        return [reader.get_object(ref) for ref in
                reader.get_object(resources.raw_get("/Font")).values()]

    def source_codes(self, reader, font):
        cmap = reader.get_object(font.raw_get("/ToUnicode"))
        decoded = zlib.decompress(cmap._data)
        body = decoded[len(frame._NATIVE_PREFIX):-len(frame._NATIVE_SUFFIX)]
        return [int(code, 16) for code in re.findall(
            rb"(?m)^<([0-9a-fA-F]{4})> <(?:[0-9a-fA-F]{4}){1,16}>$", body
        )]

    def width_values(self, reader, font):
        cid = reader.get_object(font.raw_get("/DescendantFonts")[0])
        value = cid.raw_get("/W")
        return {int(value[i]) + j: width
                for i in range(0, len(value), 2)
                for j, width in enumerate(value[i + 1])}

    def replace_source(self, reader, font, new_code, *, row_index=0):
        cmap = reader.get_object(font.raw_get("/ToUnicode"))
        decoded = zlib.decompress(cmap._data)
        body = decoded[len(frame._NATIVE_PREFIX):-len(frame._NATIVE_SUFFIX)]
        rows = list(re.finditer(
            rb"(?m)^<[0-9a-fA-F]{4}> <(?:[0-9a-fA-F]{4}){1,16}>$", body
        ))
        self.assertGreater(len(rows), row_index)
        start = rows[row_index].start()
        body = body[:start] + f"<{new_code:04X}>".encode("ascii") + body[start + 6:]
        cmap._data = zlib.compress(frame._NATIVE_PREFIX + body + frame._NATIVE_SUFFIX)

    def set_width_values(self, reader, font, values):
        cid = reader.get_object(font.raw_get("/DescendantFonts")[0])
        pairs = []
        for code, width in sorted(values.items()):
            pairs.extend((NumberObject(code), ArrayObject([width])))
        cid[NameObject("/W")] = ArrayObject(pairs)

    def verify(self, reader):
        return self.w._verify_width_coverage(reader, expected_pages=1)

    def assert_prior_admits(self, reader):
        result = self.w.previous._verify_bfchar_sources(reader, expected_pages=1)
        self.assertTrue(result["cmap_bfchar_source_uniqueness_valid"])

    def test_real_renderer_one_33_64_pages_and_content_free_receipt(self):
        for pages, expected in ((1, 50), (33, 68), (64, 68)):
            with self.subTest(pages=pages):
                pdf = self.pdfs[pages]
                plan = matching_plan(pdf, pages)
                receipt = self.inspect(pdf_bytes=pdf, plan=plan,
                                       expected_plan_sha256=plan.plan_sha256)
                result = receipt.to_dict()
                self.assertEqual(result["status"], "TOUNICODE_WIDTH_COVERAGE_ADMITTED")
                self.assertEqual(result["tounicode_stream_count"], 3)
                self.assertEqual(result["cid_width_font_count"], 3)
                self.assertEqual(result["bfchar_source_count"], expected)
                self.assertEqual(result["bfchar_covered_source_count"], expected)
                self.assertEqual(result["explicit_cid_width_count"], expected)
                self.assertIs(result["same_font_explicit_width_coverage_valid"], True)
                self.assertEqual(result["pdf_sha256"], sha256(pdf).hexdigest())
                self.assertEqual(len(result["prior_tounicode_bfchar_sources_sha256"]), 64)
                self.assertNotIn(b"begincmap", receipt.to_bytes())
                self.assertNotIn(b"<0036>", receipt.to_bytes())
                for key in (
                    "cmap_syntax_audited", "unicode_mappings_audited",
                    "glyph_meanings_verified", "glyph_widths_audited",
                    "font_programs_audited", "reading_order_verified",
                    "pdf_ua_qualified", "worker_results_authenticated",
                    "aggregate_job_resources_qualified", "default_pipeline_activated",
                    "release_authorized",
                ):
                    self.assertIs(result[key], False)

    def test_reject_unique_source_without_same_font_explicit_width(self):
        reader = self.reader()
        font = self.fonts(reader)[0]
        self.assertNotIn(65535, self.width_values(reader, font))
        self.replace_source(reader, font, 65535)
        self.assert_prior_admits(reader)
        with self.assertRaises(ValueError):
            self.verify(reader)

    def test_reject_source_covered_only_by_different_font(self):
        reader = self.reader()
        fonts = self.fonts(reader)
        own = self.width_values(reader, fonts[0])
        other = set().union(*(set(self.width_values(reader, f)) for f in fonts[1:]))
        foreign = sorted(other - set(own))
        self.assertTrue(foreign, "fixture requires a font-local width difference")
        self.replace_source(reader, fonts[0], foreign[0])
        self.assert_prior_admits(reader)
        with self.assertRaises(ValueError):
            self.verify(reader)

    def test_reject_missing_explicit_width_despite_inherited_default_width(self):
        reader = self.reader()
        font = self.fonts(reader)[0]
        code = self.source_codes(reader, font)[0]
        widths = self.width_values(reader, font)
        del widths[code]
        self.set_width_values(reader, font, widths)
        self.assert_prior_admits(reader)
        with self.assertRaises(ValueError):
            self.verify(reader)

    def test_extra_explicit_width_does_not_require_reverse_cmap_coverage(self):
        reader = self.reader()
        font = self.fonts(reader)[0]
        widths = self.width_values(reader, font)
        widths[65535] = NumberObject(1000)
        self.set_width_values(reader, font, widths)
        result = self.verify(reader)
        self.assertEqual(result["bfchar_covered_source_count"], 50)
        self.assertEqual(result["explicit_cid_width_count"], 51)

    def test_upper_cid_with_explicit_width_preserves_nonsemantic_scope(self):
        reader = self.reader()
        font = self.fonts(reader)[0]
        widths = self.width_values(reader, font)
        widths[65535] = NumberObject(1000)
        self.set_width_values(reader, font, widths)
        self.replace_source(reader, font, 65535)
        result = self.verify(reader)
        self.assertEqual(result["bfchar_covered_source_count"], 50)
        self.assertEqual(result["explicit_cid_width_count"], 51)
        self.assertTrue(result["same_font_explicit_width_coverage_valid"])

    def test_same_source_in_different_fonts_is_permitted(self):
        reader = self.reader()
        sets = [set(self.source_codes(reader, f)) for f in self.fonts(reader)]
        self.assertTrue(any(a & b for i, a in enumerate(sets) for b in sets[i + 1:]))
        self.assertEqual(self.verify(reader)["bfchar_covered_source_count"], 50)

    def test_inherited_duplicate_source_remains_rejected(self):
        reader = self.reader()
        font = self.fonts(reader)[0]
        codes = self.source_codes(reader, font)
        self.replace_source(reader, font, codes[0], row_index=1)
        with self.assertRaises(ValueError):
            self.verify(reader)

    def test_profile_disabled_and_invalid_identity_fail_before_execution(self):
        manifest = Path(__file__).resolve().parents[1] / (
            "reporting/pdf-tounicode-width-coverage.v1.json"
        )
        self.assertEqual(json.loads(manifest.read_text()),
                         self.m.tounicode_width_coverage_profile())
        self.assertEqual(self.m.PROFILE_SHA256, self.m._FIXED_PROFILE_SHA256)
        with patch.dict(os.environ, {self.m._DISABLE: "1"}):
            with self.assertRaisesRegex(self.m.PdfToUnicodeWidthCoverageError, "input_invalid"):
                self.inspect()
        for bad in (
            {"pdf_bytes": bytearray(self.pdf)}, {"pdf_bytes": self.pdfs[33]},
            {"expected_plan_sha256": "0" * 64}, {"expected_language": "pt-BR"},
            {"plan": object()},
        ):
            with self.subTest(bad=sorted(bad)):
                with self.assertRaisesRegex(self.m.PdfToUnicodeWidthCoverageError, "input_invalid"):
                    self.inspect(**bad)

    def test_receipt_checksum_detects_structurally_valid_count_mutation(self):
        receipt = self.inspect()
        self.assertEqual(receipt.inspection_sha256, sha256(receipt.to_bytes()).hexdigest())
        with self.assertRaises(FrozenInstanceError):
            receipt.bfchar_source_count = 1
        object.__setattr__(receipt, "bfchar_source_count", 1)
        object.__setattr__(receipt, "bfchar_covered_source_count", 1)
        self.assertEqual(receipt._record()["bfchar_source_count"], 1)
        with self.assertRaises(self.m.PdfToUnicodeWidthCoverageError):
            receipt.to_bytes()

    def test_child_protocol_rejects_counts_types_extra_keys_and_identity_drift(self):
        parent = self.m.previous.inspect_pdf_tounicode_bfchar_sources(
            pdf_bytes=self.pdf, plan=self.plan,
            expected_plan_sha256=self.plan.plan_sha256, expected_language="en-US",
        )
        identity = self.m._identity_from_plan(self.plan)
        data = self.m._run_worker(self.pdf, identity)
        baseline = json.loads(data)
        for delta in (
            {"bfchar_covered_source_count": 49},
            {"bfchar_source_count": True},
            {"cid_width_font_count": 2},
            {"explicit_cid_width_count": 49},
            {"same_font_explicit_width_coverage_valid": 1},
            {"extra": "unexpected"},
        ):
            record = json.loads(data)
            record["inspection"].update(delta)
            with self.subTest(delta=delta):
                with self.assertRaises(self.m.PdfToUnicodeWidthCoverageError):
                    self.m._decode(self.m._canonical(record), identity, parent)
        baseline["identity"]["pdf_sha256"] = "0" * 64
        with self.assertRaises(self.m.PdfToUnicodeWidthCoverageError):
            self.m._decode(self.m._canonical(baseline), identity, parent)


if __name__ == "__main__":
    unittest.main()
