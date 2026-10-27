"""TDD: opt-in generated FontDescriptor/FontFile2 native envelope."""
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
    ArrayObject, DecodedStreamObject, FloatObject, IndirectObject, NameObject, NumberObject,
    TextStringObject,
)
from reporting.page_windows import plan_pdf_page_windows
from reporting.pdf_text_windows import PROFILE_ID as TEXT_PROFILE
from tests.test_reporting_pdf_source_inspection_job import generated_job_case

_CASES = {}


def descriptor_plan(pdf: bytes, pages: int):
    return plan_pdf_page_windows(
        pdf_sha256=sha256(pdf).hexdigest(), ir_sha256="a" * 64,
        page_count=pages, admitted_page_budget=pages,
        pages_per_window=16, inspector_profile_id=TEXT_PROFILE,
    )


class PdfFontDescriptorTests(unittest.TestCase):
    """Exercise actual generated font descriptors without decoding font data."""

    @classmethod
    def setUpClass(cls):
        for count in (1, 33, 64):
            _CASES[count] = generated_job_case(count)[1]

    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("reporting.pdf_font_descriptor"),
            "opt-in generated FontDescriptor envelope module missing",
        )
        self.m = importlib.import_module("reporting.pdf_font_descriptor")
        self.worker = importlib.import_module("reporting._pdf_font_descriptor_worker")
        self.pdf = _CASES[1]
        self.plan = descriptor_plan(self.pdf, 1)

    def inspect(self, **changed):
        kwargs = {
            "pdf_bytes": self.pdf, "plan": self.plan,
            "expected_plan_sha256": self.plan.plan_sha256,
            "expected_language": "en-US",
        }
        return self.m.inspect_pdf_font_descriptor(**{**kwargs, **changed})

    def reader(self, count=1):
        return PdfReader(BytesIO(_CASES[count]), strict=True)

    def font_descriptor(self, reader):
        native = reader.get_object(reader.pages[0].indirect_reference)
        resources = reader.get_object(native.raw_get("/Resources"))
        fonts = reader.get_object(resources.raw_get("/Font"))
        font = reader.get_object(fonts.raw_get(next(iter(fonts))))
        cid = reader.get_object(font.raw_get("/DescendantFonts")[0])
        descriptor_ref = cid.raw_get("/FontDescriptor")
        return cid, descriptor_ref, reader.get_object(descriptor_ref)

    def verify(self, reader, count=1):
        return self.worker._verify_font_descriptor(
            reader, expected_pages=count,
            direct_count=len(reader.xref[0]),
            compressed_count=len(reader.xref_objStm),
        )

    def test_generated_one_thirty_three_sixty_four_font_envelopes(self):
        for count in (1, 33, 64):
            with self.subTest(pages=count):
                pdf = _CASES[count]
                plan = descriptor_plan(pdf, count)
                receipt = self.inspect(
                    pdf_bytes=pdf, plan=plan,
                    expected_plan_sha256=plan.plan_sha256,
                )
                row = receipt.to_dict()
                self.assertEqual(row["status"], "FONT_DESCRIPTOR_ENVELOPE_ADMITTED")
                self.assertEqual(row["pdf_sha256"], sha256(pdf).hexdigest())
                self.assertEqual(row["page_count"], count)
                self.assertEqual(row["font_descriptor_envelope_count"], 3)
                self.assertEqual(row["font_file2_raw_stream_count"], 3)
                self.assertTrue(row["descriptor_names_match"])
                self.assertTrue(row["descriptor_metrics_bounded"])
                self.assertTrue(row["font_file2_streams_indexed"])
                self.assertEqual(len(row["prior_resource_leaves_sha256"]), 64)
                for key in (
                    "font_programs_audited", "glyph_widths_audited",
                    "tounicode_decoded", "pdf_ua_qualified",
                    "reading_order_verified", "release_authorized",
                    "default_pipeline_activated", "worker_results_authenticated",
                ):
                    self.assertIs(row[key], False, key)

    def test_versioned_manifest_exactly_matches_checksum_bound_profile(self):
        manifest = Path(__file__).resolve().parents[1] / "reporting/pdf-font-descriptor.v1.json"
        profile = self.m.font_descriptor_profile()
        self.assertEqual(json.loads(manifest.read_text(encoding="utf-8")), profile)
        self.assertEqual(sha256(self.m._canonical(profile)).hexdigest(), self.m.PROFILE_SHA256)
        self.assertEqual(self.m.PROFILE_SHA256, self.m._FIXED_PROFILE_SHA256)
        self.assertEqual(
            self.m.previous.PROFILE_SHA256,
            profile["previous_resource_leaves_profile_sha256"],
        )

    def test_fontfile2_invalid_flate_header_is_rejected(self):
        reader = self.reader()
        _cid, _descriptor_ref, descriptor = self.font_descriptor(reader)
        embedded = reader.get_object(descriptor.raw_get("/FontFile2"))
        embedded._data = b"not-a-zlib-stream"
        with self.assertRaises(ValueError):
            self.verify(reader)

    def test_decoded_stream_object_masquerading_as_raw_flated_font_rejected(self):
        stream = DecodedStreamObject()
        stream[NameObject("/Filter")] = NameObject("/FlateDecode")
        stream[NameObject("/Length1")] = NumberObject(256)
        stream._data = b"\x78\xda" + b"valid-header-fake-stream"
        with self.assertRaises(ValueError):
            self.worker._raw_fontfile2(stream)

    def test_descriptor_exact_keys_base_name_and_native_family_rejected(self):
        for case in (
            "missing", "extra", "type", "name", "name_type", "family_type",
            "family_empty", "family_ws", "family_control", "flags_type",
            "flags_zero", "flags_large",
        ):
            with self.subTest(case=case):
                reader = self.reader()
                _cid, _ref, desc = self.font_descriptor(reader)
                if case == "missing":
                    del desc["/StemH"]
                elif case == "extra":
                    desc[NameObject("/Unexpected")] = NumberObject(1)
                elif case == "type":
                    desc[NameObject("/Type")] = NameObject("/Font")
                elif case == "name":
                    desc[NameObject("/FontName")] = NameObject("/DIFFERENT+Font")
                elif case == "name_type":
                    desc[NameObject("/FontName")] = TextStringObject(
                        str(desc.raw_get("/FontName")),
                    )
                elif case == "family_type":
                    desc[NameObject("/FontFamily")] = NameObject("/Other")
                elif case == "family_empty":
                    desc[NameObject("/FontFamily")] = TextStringObject("")
                elif case == "family_ws":
                    desc[NameObject("/FontFamily")] = TextStringObject(" font ")
                elif case == "family_control":
                    desc[NameObject("/FontFamily")] = TextStringObject("font\n")
                elif case == "flags_type":
                    desc[NameObject("/Flags")] = FloatObject(4.0)
                elif case == "flags_zero":
                    desc[NameObject("/Flags")] = NumberObject(0)
                else:
                    desc[NameObject("/Flags")] = NumberObject(65536)
                with self.assertRaises(ValueError):
                    self.verify(reader)

    def test_descriptor_bounding_box_and_metrics_rejected(self):
        for case in (
            "bbox_short", "bbox_shape", "bbox_inverted", "bbox_string",
            "bbox_nan", "bbox_inf", "bbox_large", "angle_large",
            "ascent_negative", "descent_positive", "cap_zero",
            "stem_v_zero", "stem_h_zero", "metric_indirect",
        ):
            with self.subTest(case=case):
                reader = self.reader()
                _cid, ref, desc = self.font_descriptor(reader)
                box = desc.raw_get("/FontBBox")
                if case == "bbox_short":
                    box.pop()
                elif case == "bbox_shape":
                    desc[NameObject("/FontBBox")] = NumberObject(1)
                elif case == "bbox_inverted":
                    box[2] = box[0]
                elif case == "bbox_string":
                    box[0] = TextStringObject("0")
                elif case == "bbox_nan":
                    box[0] = FloatObject(float("nan"))
                elif case == "bbox_inf":
                    box[0] = FloatObject(float("inf"))
                elif case == "bbox_large":
                    box[0] = NumberObject(-20000)
                elif case == "angle_large":
                    desc[NameObject("/ItalicAngle")] = NumberObject(361)
                elif case == "ascent_negative":
                    desc[NameObject("/Ascent")] = NumberObject(-1)
                elif case == "descent_positive":
                    desc[NameObject("/Descent")] = NumberObject(1)
                elif case == "cap_zero":
                    desc[NameObject("/CapHeight")] = NumberObject(0)
                elif case == "stem_v_zero":
                    desc[NameObject("/StemV")] = NumberObject(0)
                elif case == "stem_h_zero":
                    desc[NameObject("/StemH")] = NumberObject(0)
                else:
                    desc[NameObject("/Ascent")] = ref
                with self.assertRaises(ValueError):
                    self.verify(reader)

    def test_fontfile2_reference_alias_and_unindexed_rejected(self):
        for case in (
            "direct", "generation", "foreign", "alias_descriptor",
            "alias_tounicode", "alias_font", "duplicate",
        ):
            with self.subTest(case=case):
                reader = self.reader()
                _cid, desc_ref, desc = self.font_descriptor(reader)
                ref = desc.raw_get("/FontFile2")
                fonts = reader.get_object(
                    reader.get_object(
                        reader.get_object(reader.pages[0].indirect_reference)
                        .raw_get("/Resources"),
                    ).raw_get("/Font"),
                )
                font_ref = fonts.raw_get(next(iter(fonts)))
                font = reader.get_object(font_ref)
                if case == "direct":
                    desc[NameObject("/FontFile2")] = reader.get_object(ref)
                elif case == "generation":
                    desc[NameObject("/FontFile2")] = IndirectObject(ref.idnum, 1, reader)
                elif case == "foreign":
                    desc[NameObject("/FontFile2")] = IndirectObject(ref.idnum, 0, self.reader())
                elif case == "alias_descriptor":
                    desc[NameObject("/FontFile2")] = desc_ref
                elif case == "alias_tounicode":
                    desc[NameObject("/FontFile2")] = font.raw_get("/ToUnicode")
                elif case == "alias_font":
                    desc[NameObject("/FontFile2")] = font_ref
                else:
                    second_ref = list(fonts.values())[1]
                    second_font = reader.get_object(second_ref)
                    second_cid = reader.get_object(second_font.raw_get("/DescendantFonts")[0])
                    second_desc = reader.get_object(second_cid.raw_get("/FontDescriptor"))
                    second_desc[NameObject("/FontFile2")] = ref
                with self.assertRaises(ValueError):
                    self.verify(reader)

    def test_fontfile2_native_stream_shape_rejected(self):
        for case in (
            "filter", "filter_array", "length_type", "length_zero",
            "length_over", "raw_empty", "raw_tiny", "raw_wrong_type",
            "extra_key", "missing_key", "zlib_dictionary_bit",
        ):
            with self.subTest(case=case):
                reader = self.reader()
                _cid, _ref, desc = self.font_descriptor(reader)
                stream = reader.get_object(desc.raw_get("/FontFile2"))
                if case == "filter":
                    stream[NameObject("/Filter")] = NameObject("/ASCII85Decode")
                elif case == "filter_array":
                    stream[NameObject("/Filter")] = ArrayObject([NameObject("/FlateDecode")])
                elif case == "length_type":
                    stream[NameObject("/Length1")] = FloatObject(10.0)
                elif case == "length_zero":
                    stream[NameObject("/Length1")] = NumberObject(0)
                elif case == "length_over":
                    stream[NameObject("/Length1")] = NumberObject(8 * 1024 * 1024 + 1)
                elif case == "raw_empty":
                    stream._data = b""
                elif case == "raw_tiny":
                    stream._data = b"\x78\x9c"
                elif case == "raw_wrong_type":
                    stream._data = bytearray(stream._data)
                elif case == "extra_key":
                    stream[NameObject("/Unexpected")] = NumberObject(1)
                elif case == "missing_key":
                    del stream["/Length1"]
                else:
                    # Invalid FDICT bit; even a valid FCHECK cannot enable it.
                    stream._data = b"\x78\x20" + stream._data[2:]
                with self.assertRaises(ValueError):
                    self.verify(reader)

    def test_raw_header_envelope_does_not_claim_decoded_font_program(self):
        reader = self.reader()
        _cid, _ref, desc = self.font_descriptor(reader)
        stream = reader.get_object(desc.raw_get("/FontFile2"))
        stream._data = stream._data[:2] + b"intentionally-not-a-decoded-font"
        self.assertEqual(self.verify(reader)["font_file2_raw_stream_count"], 3)

    def test_native_xref_drift_rejected(self):
        reader = self.reader()
        self.assertEqual(self.verify(reader)["font_descriptor_envelope_count"], 3)
        reader.xref[0].pop(next(iter(reader.xref[0])))
        with self.assertRaises(ValueError):
            self.verify(reader)

    def test_input_language_plan_and_disable_rejected_before_child(self):
        with patch.object(self.m, "_run_worker") as child:
            for changes in (
                {"pdf_bytes": bytearray(self.pdf)},
                {"pdf_bytes": _CASES[33]},
                {"pdf_bytes": b"invalid"},
                {"plan": object()},
                {"expected_plan_sha256": "f" * 64},
                {"expected_language": "pt-BR"},
            ):
                with self.subTest(changes=sorted(changes)):
                    with self.assertRaises(self.m.PdfFontDescriptorError):
                        self.inspect(**changes)
            child.assert_not_called()
        with patch.dict(os.environ, {"OMNIGENIS_PDF_FONT_DESCRIPTOR_DISABLED": "1"}):
            with patch.object(self.m, "_run_worker") as child:
                with self.assertRaises(self.m.PdfFontDescriptorError):
                    self.inspect()
                child.assert_not_called()

    def test_child_wire_forgery_identity_limit_duplicate_and_extra_rejected(self):
        identity = self.worker._identity_from_plan(self.plan)
        raw = self.m._run_worker(self.pdf, identity)
        base = json.loads(raw)
        mutated = []

        def tamper(change):
            row = json.loads(json.dumps(base))
            change(row)
            mutated.append(json.dumps(row).encode("ascii"))

        tamper(lambda x: x.update({"protocol_version": True}))
        tamper(lambda x: x["identity"].update({"pdf_sha256": "f" * 64}))
        tamper(lambda x: x["limits"].update({"cpu_seconds": 0}))
        tamper(lambda x: x["inspection"].update({"font_descriptor_envelope_count": 0}))
        tamper(lambda x: x["inspection"].update({"descriptor_metrics_bounded": False}))
        tamper(lambda x: x["inspection"].update({"unexpected": 1}))
        mutated.extend((
            raw.replace(b'"status":', b'"status":"forged","status":', 1),
            raw + b"\xff", raw + b"x" * (self.m.RESULT_BYTES + 1),
        ))
        for candidate in mutated:
            with self.subTest(length=len(candidate)):
                with patch.object(self.m, "_run_worker", return_value=candidate):
                    with self.assertRaises(self.m.PdfFontDescriptorError):
                        self.inspect()

    def test_child_cannot_attach_different_document_ancestor_receipt(self):
        identity = self.worker._identity_from_plan(self.plan)
        raw = self.m._run_worker(self.pdf, identity)
        foreign_pdf = _CASES[33]
        foreign_plan = descriptor_plan(foreign_pdf, 33)
        foreign_ancestor = self.m.previous.inspect_pdf_resource_leaves(
            pdf_bytes=foreign_pdf, plan=foreign_plan,
            expected_plan_sha256=foreign_plan.plan_sha256,
            expected_language="en-US",
        )
        self.assertNotEqual(identity["pdf_sha256"], foreign_ancestor.pdf_sha256)
        self.assertEqual(foreign_ancestor.font_binding_count, 3)
        with self.assertRaises(self.m.PdfFontDescriptorError):
            self.m._decode(raw, identity, foreign_ancestor)

    def test_inflight_plan_disabled_profile_and_immutable_receipt(self):
        normal = self.m._run_worker

        def mutate_plan(pdf, identity):
            row = normal(pdf, identity)
            object.__setattr__(self.plan, "ir_sha256", "f" * 64)
            return row

        with patch.object(self.m, "_run_worker", side_effect=mutate_plan):
            with self.assertRaises(self.m.PdfFontDescriptorError):
                self.inspect()
        self.plan = descriptor_plan(self.pdf, 1)

        def disable_midflight(pdf, identity):
            row = normal(pdf, identity)
            os.environ["OMNIGENIS_PDF_FONT_DESCRIPTOR_DISABLED"] = "1"
            return row

        with patch.dict(os.environ):
            with patch.object(self.m, "_run_worker", side_effect=disable_midflight):
                with self.assertRaises(self.m.PdfFontDescriptorError):
                    self.inspect()
        receipt = self.inspect()
        self.assertEqual(receipt.inspection_sha256, sha256(receipt.to_bytes()).hexdigest())
        with self.assertRaises(FrozenInstanceError):
            receipt.font_descriptor_envelope_count = 0
        object.__setattr__(receipt, "font_descriptor_envelope_count", 0)
        with self.assertRaises(self.m.PdfFontDescriptorError):
            receipt.to_dict()


if __name__ == "__main__":
    unittest.main()
