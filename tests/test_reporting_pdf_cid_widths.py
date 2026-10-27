"""TDD: native generated CID width array envelope, not glyph validation."""
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
from pypdf.generic import (
    ArrayObject, BooleanObject, FloatObject, IndirectObject, NameObject,
    NumberObject, TextStringObject,
)

from reporting.page_windows import plan_pdf_page_windows
from reporting.pdf_text_windows import PROFILE_ID as TEXT_PROFILE
from tests.test_reporting_pdf_source_inspection_job import generated_job_case


_CASES: dict[int, bytes] = {}


def cid_plan(pdf: bytes, pages: int):
    return plan_pdf_page_windows(
        pdf_sha256=sha256(pdf).hexdigest(), ir_sha256="a" * 64,
        page_count=pages, admitted_page_budget=pages,
        pages_per_window=16, inspector_profile_id=TEXT_PROFILE,
    )


class PdfCidWidthTests(unittest.TestCase):
    """Check opt-in width arrays on actual generated PDF object trees."""

    @classmethod
    def setUpClass(cls):
        for count in (1, 33, 64):
            _CASES[count] = generated_job_case(count)[1]

    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("reporting.pdf_cid_widths"),
            "opt-in generated CID width envelope module missing",
        )
        self.m = importlib.import_module("reporting.pdf_cid_widths")
        self.worker = importlib.import_module("reporting._pdf_cid_widths_worker")
        self.pdf = _CASES[1]
        self.plan = cid_plan(self.pdf, 1)

    def inspect(self, **changed):
        args = {
            "pdf_bytes": self.pdf, "plan": self.plan,
            "expected_plan_sha256": self.plan.plan_sha256,
            "expected_language": "en-US",
        }
        return self.m.inspect_pdf_cid_widths(**{**args, **changed})

    def reader(self, count=1):
        return PdfReader(BytesIO(_CASES[count]), strict=True)

    def widths(self, reader):
        native = reader.get_object(reader.pages[0].indirect_reference)
        resources = reader.get_object(native.raw_get("/Resources"))
        fonts = reader.get_object(resources.raw_get("/Font"))
        font = reader.get_object(fonts.raw_get(next(iter(fonts))))
        cid = reader.get_object(font.raw_get("/DescendantFonts")[0])
        return cid.raw_get("/W")

    def verify(self, reader, count=1):
        return self.worker._verify_cid_widths(
            reader, expected_pages=count,
            direct_count=len(reader.xref[0]),
            compressed_count=len(reader.xref_objStm),
        )

    def test_generated_one_thirty_three_sixty_four_native_width_envelopes(self):
        expected = {1: (3, 35, 50), 33: (3, 34, 68), 64: (3, 34, 68)}
        for count, (fonts, pairs, values) in expected.items():
            with self.subTest(pages=count):
                pdf = _CASES[count]
                plan = cid_plan(pdf, count)
                receipt = self.inspect(
                    pdf_bytes=pdf, plan=plan,
                    expected_plan_sha256=plan.plan_sha256,
                )
                row = receipt.to_dict()
                self.assertEqual(row["status"], "CID_WIDTHS_ENVELOPE_ADMITTED")
                self.assertEqual(row["pdf_sha256"], sha256(pdf).hexdigest())
                self.assertEqual(row["page_count"], count)
                self.assertEqual(row["cid_width_font_count"], fonts)
                self.assertEqual(row["cid_width_pair_count"], pairs)
                self.assertEqual(row["cid_width_value_count"], values)
                self.assertTrue(row["cid_ranges_strictly_ascending"])
                self.assertTrue(row["cid_widths_natively_bounded"])
                self.assertEqual(len(row["prior_font_descriptor_sha256"]), 64)
                for key in (
                    "decoded_contents_audited", "font_programs_audited",
                    "glyph_widths_audited", "tounicode_decoded",
                    "reading_order_verified", "pdf_ua_qualified",
                    "release_authorized", "default_pipeline_activated",
                    "worker_results_authenticated",
                ):
                    self.assertIs(row[key], False, key)

    def test_manifest_exactly_matches_checksum_bound_opt_in_profile(self):
        manifest = Path(__file__).resolve().parents[1] / "reporting/pdf-cid-widths.v1.json"
        self.assertTrue(manifest.is_file())
        profile = self.m.cid_widths_profile()
        self.assertEqual(json.loads(manifest.read_text(encoding="utf-8")), profile)
        self.assertEqual(sha256(self.m._canonical(profile)).hexdigest(), self.m.PROFILE_SHA256)
        self.assertEqual(self.m.PROFILE_SHA256, self.m._FIXED_PROFILE_SHA256)
        self.assertEqual(
            self.m.previous.PROFILE_SHA256,
            profile["previous_font_descriptor_profile_sha256"],
        )

    def test_out_of_order_overlapping_and_out_of_range_cids_rejected(self):
        for case in ("negative", "over_max", "overlap", "reverse", "range_overrun"):
            with self.subTest(case=case):
                reader = self.reader()
                widths = self.widths(reader)
                if case == "negative":
                    widths[0] = NumberObject(-1)
                elif case == "over_max":
                    widths[0] = NumberObject(65536)
                elif case == "overlap":
                    widths[2] = NumberObject(3)
                elif case == "reverse":
                    widths[2] = NumberObject(2)
                else:
                    widths[10] = NumberObject(65535)  # This run has two widths.
                with self.assertRaises(ValueError):
                    self.verify(reader)

    def test_unbounded_nonfinite_or_non_native_width_values_rejected(self):
        for case in (
            "zero", "negative", "too_large", "nan", "infinite",
            "text", "boolean", "indirect", "invalid_negative_float",
        ):
            with self.subTest(case=case):
                reader = self.reader()
                widths = self.widths(reader)
                if case == "zero":
                    value = NumberObject(0)
                elif case == "negative":
                    value = NumberObject(-2)
                elif case == "too_large":
                    value = NumberObject(16385)
                elif case == "nan":
                    value = FloatObject(float("nan"))
                elif case == "infinite":
                    value = FloatObject(float("inf"))
                elif case == "text":
                    value = TextStringObject("260")
                elif case == "boolean":
                    value = BooleanObject(True)
                elif case == "indirect":
                    value = reader.pages[0].indirect_reference
                else:
                    value = FloatObject(-1.5)
                widths[1][0] = value
                with self.assertRaises(ValueError):
                    self.verify(reader)

    def test_native_finite_fractional_width_allowed_without_glyph_claim(self):
        reader = self.reader()
        self.widths(reader)[1][0] = FloatObject(260.5)
        result = self.verify(reader)
        self.assertEqual(result["cid_width_value_count"], 50)
        self.assertTrue(result["cid_widths_natively_bounded"])

    def test_raw_array_shape_and_nested_budget_rejected(self):
        for case in (
            "top_empty", "top_odd", "nested_empty", "nested_large",
            "range_form", "cid_float", "cid_indirect", "cid_text",
        ):
            with self.subTest(case=case):
                reader = self.reader()
                native = reader.get_object(reader.pages[0].indirect_reference)
                resources = reader.get_object(native.raw_get("/Resources"))
                fonts = reader.get_object(resources.raw_get("/Font"))
                font = reader.get_object(fonts.raw_get(next(iter(fonts))))
                cid = reader.get_object(font.raw_get("/DescendantFonts")[0])
                array = cid.raw_get("/W")
                if case == "top_empty":
                    cid[NameObject("/W")] = ArrayObject()
                elif case == "top_odd":
                    array.append(NumberObject(101))
                elif case == "nested_empty":
                    array[1] = ArrayObject()
                elif case == "nested_large":
                    array[1] = ArrayObject([NumberObject(500)] * 4097)
                elif case == "range_form":
                    cid[NameObject("/W")] = ArrayObject([
                        NumberObject(3), NumberObject(5), NumberObject(260),
                    ])
                elif case == "cid_float":
                    array[0] = FloatObject(3.0)
                elif case == "cid_indirect":
                    array[0] = reader.pages[0].indirect_reference
                else:
                    array[0] = TextStringObject("3")
                with self.assertRaises(ValueError):
                    self.verify(reader)

    def test_native_width_index_drift_rejected(self):
        reader = self.reader()
        self.assertEqual(self.verify(reader)["cid_width_font_count"], 3)
        reader.xref[0].pop(next(iter(reader.xref[0])))
        with self.assertRaises(ValueError):
            self.verify(reader)

    def test_input_plan_language_and_disabled_profile_fail_before_child(self):
        with patch.object(self.m, "_run_worker") as worker:
            for changed in (
                {"pdf_bytes": bytearray(self.pdf)},
                {"pdf_bytes": _CASES[33]},
                {"pdf_bytes": b"not-a-pdf"},
                {"plan": object()},
                {"expected_plan_sha256": "f" * 64},
                {"expected_language": "pt-BR"},
            ):
                with self.subTest(changed=sorted(changed)):
                    with self.assertRaises(self.m.PdfCidWidthsError):
                        self.inspect(**changed)
            worker.assert_not_called()
        with patch.dict(os.environ, {"OMNIGENIS_PDF_CID_WIDTHS_DISABLED": "1"}):
            with patch.object(self.m, "_run_worker") as worker:
                with self.assertRaises(self.m.PdfCidWidthsError):
                    self.inspect()
                worker.assert_not_called()

    def test_exact_parent_document_identity_even_when_font_counts_agree(self):
        identity = self.worker._identity_from_plan(self.plan)
        raw = self.m._run_worker(self.pdf, identity)
        foreign_pdf = _CASES[33]
        foreign_plan = cid_plan(foreign_pdf, 33)
        ancestor = self.m.previous.inspect_pdf_font_descriptor(
            pdf_bytes=foreign_pdf, plan=foreign_plan,
            expected_plan_sha256=foreign_plan.plan_sha256,
            expected_language="en-US",
        )
        self.assertEqual(ancestor.font_descriptor_envelope_count, 3)
        self.assertNotEqual(ancestor.pdf_sha256, identity["pdf_sha256"])
        with self.assertRaises(self.m.PdfCidWidthsError):
            self.m._decode(raw, identity, ancestor)

    def test_child_protocol_forgery_duplicate_keys_and_scope_claims_fail(self):
        identity = self.worker._identity_from_plan(self.plan)
        raw = self.m._run_worker(self.pdf, identity)
        base = json.loads(raw)
        mutated: list[bytes] = []

        def mutate(edit):
            row = json.loads(json.dumps(base))
            edit(row)
            mutated.append(json.dumps(row).encode("ascii"))

        mutate(lambda row: row.update({"protocol_version": True}))
        mutate(lambda row: row["identity"].update({"pdf_sha256": "f" * 64}))
        mutate(lambda row: row["limits"].update({"cpu_seconds": 0}))
        mutate(lambda row: row["inspection"].update({"cid_width_font_count": 0}))
        mutate(lambda row: row["inspection"].update({"cid_ranges_strictly_ascending": False}))
        mutate(lambda row: row["inspection"].update({"cid_widths_natively_bounded": False}))
        mutate(lambda row: row["inspection"].update({"extra": 1}))
        mutated.extend((
            raw.replace(b'"status":', b'"status":"forged","status":', 1),
            raw + b"\xff", raw + b"x" * (self.m.RESULT_BYTES + 1),
        ))
        for altered in mutated:
            with self.subTest(length=len(altered)):
                with patch.object(self.m, "_run_worker", return_value=altered):
                    with self.assertRaises(self.m.PdfCidWidthsError):
                        self.inspect()

    def test_inflight_plan_change_and_local_receipt_immutability(self):
        normal = self.m._run_worker

        def mutate_plan(pdf, identity):
            raw = normal(pdf, identity)
            object.__setattr__(self.plan, "ir_sha256", "f" * 64)
            return raw

        with patch.object(self.m, "_run_worker", side_effect=mutate_plan):
            with self.assertRaises(self.m.PdfCidWidthsError):
                self.inspect()
        self.plan = cid_plan(self.pdf, 1)

        def disable_after_child(pdf, identity):
            raw = normal(pdf, identity)
            os.environ["OMNIGENIS_PDF_CID_WIDTHS_DISABLED"] = "1"
            return raw

        with patch.dict(os.environ):
            with patch.object(self.m, "_run_worker", side_effect=disable_after_child):
                with self.assertRaises(self.m.PdfCidWidthsError):
                    self.inspect()
        receipt = self.inspect()
        self.assertEqual(receipt.inspection_sha256, sha256(receipt.to_bytes()).hexdigest())
        with self.assertRaises(FrozenInstanceError):
            receipt.cid_width_font_count = 0
        object.__setattr__(receipt, "cid_width_font_count", 0)
        with self.assertRaises(self.m.PdfCidWidthsError):
            receipt.to_dict()


if __name__ == "__main__":
    unittest.main()
