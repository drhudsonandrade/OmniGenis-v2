"""Native opt-in ToUnicode bfchar source uniqueness, not mapping meaning."""
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
from tests.test_reporting_pdf_source_inspection_job import generated_job_case
from tests.test_reporting_pdf_tounicode_utf16be_targets import matching_plan


class PdfToUnicodeBfcharSourcesTests(unittest.TestCase):
    """Source uniqueness is scoped separately to each generated font CMap."""

    @classmethod
    def setUpClass(cls):
        cls.pdfs = {n: generated_job_case(n)[1] for n in (1, 33, 64)}

    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("reporting.pdf_tounicode_bfchar_sources"),
            "bounded native bfchar source checker missing",
        )
        self.m = importlib.import_module("reporting.pdf_tounicode_bfchar_sources")
        self.w = importlib.import_module("reporting._pdf_tounicode_bfchar_sources_worker")
        self.pdf = self.pdfs[1]
        self.plan = matching_plan(self.pdf, 1)

    def inspect(self, **changed):
        args = {
            "pdf_bytes": self.pdf, "plan": self.plan,
            "expected_plan_sha256": self.plan.plan_sha256,
            "expected_language": "en-US",
        }
        return self.m.inspect_pdf_tounicode_bfchar_sources(**{**args, **changed})

    def reader(self):
        return PdfReader(BytesIO(self.pdf), strict=True)

    def cmaps(self, reader):
        page = reader.get_object(reader.pages[0].indirect_reference)
        fonts = reader.get_object(
            reader.get_object(page.raw_get("/Resources")).raw_get("/Font")
        )
        return [
            reader.get_object(reader.get_object(ref).raw_get("/ToUnicode"))
            for ref in fonts.values()
        ]

    def alter_row(self, *, duplicate: bool, same_target: bool = False):
        reader = self.reader()
        cmap = self.cmaps(reader)[0]
        decoded = zlib.decompress(cmap._data)
        native_prefix = self.w.previous.previous._NATIVE_PREFIX
        self.assertTrue(decoded.startswith(native_prefix))
        body = decoded[len(native_prefix):]
        rows = list(re.finditer(
            rb"(?m)^<[0-9a-fA-F]{4}> <(?:[0-9a-fA-F]{4}){1,16}>$", body
        ))
        self.assertGreaterEqual(len(rows), 2)
        first, second = rows[:2]
        source = body[first.start():first.start() + 6]
        if duplicate:
            target = (
                body[first.start() + 6:first.end()]
                if same_target else body[second.start() + 6:second.end()]
            )
            replacement = source + target
            slot = second
        else:
            existing = {body[row.start():row.start() + 6] for row in rows}
            self.assertNotIn(b"<FFFF>", existing)
            replacement = b"<FFFF>" + body[first.start() + 6:first.end()]
            slot = first
        cmap._data = zlib.compress(
            native_prefix + body[:slot.start()] + replacement + body[slot.end():]
        )
        return reader

    def verify(self, reader):
        return self.w._verify_bfchar_sources(reader, expected_pages=1)

    def test_real_renderer_one_33_64_pages(self):
        for pages in (1, 33, 64):
            with self.subTest(pages=pages):
                pdf = self.pdfs[pages]
                plan = matching_plan(pdf, pages)
                receipt = self.inspect(
                    pdf_bytes=pdf, plan=plan,
                    expected_plan_sha256=plan.plan_sha256,
                )
                result = receipt.to_dict()
                self.assertEqual(result["status"], "TOUNICODE_BFCHAR_SOURCES_ADMITTED")
                self.assertEqual(result["bfchar_source_count"], {1: 50, 33: 68, 64: 68}[pages])
                self.assertEqual(
                    result["bfchar_unique_source_count"], result["bfchar_source_count"]
                )
                self.assertEqual(result["tounicode_stream_count"], 3)
                self.assertIs(result["cmap_bfchar_source_uniqueness_valid"], True)
                self.assertEqual(result["pdf_sha256"], sha256(pdf).hexdigest())
                self.assertEqual(len(result["prior_tounicode_utf16be_targets_sha256"]), 64)
                for key in (
                    "cmap_syntax_audited", "unicode_mappings_audited",
                    "glyph_meanings_verified", "glyph_widths_audited",
                    "reading_order_verified", "pdf_ua_qualified",
                    "worker_results_authenticated", "default_pipeline_activated",
                    "release_authorized",
                ):
                    self.assertIs(result[key], False)

    def test_reject_same_source_with_distinct_target(self):
        reader = self.alter_row(duplicate=True)
        self.w.previous._verify_utf16be_targets(reader, expected_pages=1)
        with self.assertRaises(ValueError):
            self.verify(reader)

    def test_reject_same_source_with_identical_target(self):
        reader = self.alter_row(duplicate=True, same_target=True)
        self.w.previous._verify_utf16be_targets(reader, expected_pages=1)
        with self.assertRaises(ValueError):
            self.verify(reader)

    def test_distinct_sources_not_required_to_sort_or_mean_anything(self):
        result = self.verify(self.alter_row(duplicate=False))
        self.assertEqual(result["bfchar_source_count"], 50)
        self.assertEqual(result["bfchar_unique_source_count"], 50)
        self.assertTrue(result["cmap_bfchar_source_uniqueness_valid"])

    def test_identical_sources_across_different_fonts_are_permitted(self):
        """The uniqueness scope is a single font CMap, not the document."""
        reader = self.reader()
        prefix = self.w.previous.previous._NATIVE_PREFIX
        source_sets = []
        for cmap in self.cmaps(reader):
            decoded = zlib.decompress(cmap._data)
            self.assertTrue(decoded.startswith(prefix))
            body = decoded[len(prefix):]
            values = set(re.findall(
                rb"(?m)^<([0-9a-fA-F]{4})> <(?:[0-9a-fA-F]{4}){1,16}>$",
                body,
            ))
            source_sets.append(values)
        self.assertGreaterEqual(len(source_sets), 2)
        self.assertTrue(any(
            source_sets[i] & source_sets[j]
            for i in range(len(source_sets))
            for j in range(i + 1, len(source_sets))
        ))
        self.assertEqual(self.verify(reader)["bfchar_unique_source_count"], 50)

    def test_reject_malformed_source_in_inherited_native_frame(self):
        reader = self.reader()
        cmap = self.cmaps(reader)[0]
        decoded = zlib.decompress(cmap._data)
        self.assertIn(b"<0036> <0053>", decoded)
        cmap._data = zlib.compress(
            decoded.replace(b"<0036> <0053>", b"<10000> <0053>", 1)
        )
        with self.assertRaises(ValueError):
            self.verify(reader)
        reader = self.reader()
        self.cmaps(reader)[0]._data = self.cmaps(reader)[0]._data[:-1]
        with self.assertRaises(ValueError):
            self.verify(reader)

    def test_profile_is_pinned_default_off_and_rejects_bad_identity(self):
        path = Path(__file__).resolve().parents[1] / (
            "reporting/pdf-tounicode-bfchar-sources.v1.json"
        )
        self.assertEqual(
            json.loads(path.read_text()), self.m.tounicode_bfchar_sources_profile()
        )
        self.assertEqual(self.m.PROFILE_SHA256, self.m._FIXED_PROFILE_SHA256)
        self.assertEqual(
            self.m.previous.PROFILE_SHA256,
            self.m.tounicode_bfchar_sources_profile()[
                "previous_tounicode_utf16be_targets_profile_sha256"
            ],
        )
        with patch.dict(os.environ, {self.m._DISABLE: "1"}):
            with self.assertRaises(self.m.PdfToUnicodeBfcharSourcesError):
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
                    with self.assertRaises(self.m.PdfToUnicodeBfcharSourcesError):
                        self.inspect(**bad)
            child.assert_not_called()

    def test_content_free_checksum_seal_detects_structural_mutation(self):
        receipt = self.inspect()
        data = receipt.to_bytes()
        self.assertEqual(receipt.inspection_sha256, sha256(data).hexdigest())
        self.assertNotIn(b"begincmap", data)
        self.assertNotIn(b"<0036>", data)
        with self.assertRaises(FrozenInstanceError):
            receipt.bfchar_source_count = 7
        object.__setattr__(receipt, "bfchar_source_count", 7)
        object.__setattr__(receipt, "bfchar_unique_source_count", 7)
        self.assertEqual(receipt._record()["bfchar_source_count"], 7)
        with self.assertRaises(self.m.PdfToUnicodeBfcharSourcesError):
            receipt.to_bytes()

    def test_child_protocol_rejects_invalid_counts_and_extra_keys(self):
        parent = self.m.previous.inspect_pdf_tounicode_utf16be_targets(
            pdf_bytes=self.pdf, plan=self.plan,
            expected_plan_sha256=self.plan.plan_sha256,
            expected_language="en-US",
        )
        identity = self.m._identity_from_plan(self.plan)
        record = json.loads(self.m._run_worker(self.pdf, identity))
        record["inspection"]["bfchar_unique_source_count"] = -1
        with self.assertRaises(self.m.PdfToUnicodeBfcharSourcesError):
            self.m._decode(self.m._canonical(record), identity, parent)
        record["inspection"]["bfchar_unique_source_count"] = (
            record["inspection"]["bfchar_source_count"]
        )
        record["inspection"]["extra"] = "not allowed"
        with self.assertRaises(self.m.PdfToUnicodeBfcharSourcesError):
            self.m._decode(self.m._canonical(record), identity, parent)


if __name__ == "__main__":
    unittest.main()
