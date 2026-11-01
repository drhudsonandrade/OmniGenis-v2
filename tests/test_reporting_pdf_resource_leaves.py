"""TDD: opt-in generated PDF Type0/Lab resource-leaf identity admission."""
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
    ArrayObject, DictionaryObject, FloatObject, IndirectObject, NameObject,
    NumberObject, TextStringObject,
)
from reporting.page_windows import plan_pdf_page_windows
from reporting.pdf_text_windows import PROFILE_ID as TEXT_PROFILE
from tests.test_reporting_pdf_source_inspection_job import generated_job_case

ROOT = Path(__file__).resolve().parents[1]
_CASES = {}


def resource_plan(pdf: bytes, count: int):
    return plan_pdf_page_windows(
        pdf_sha256=sha256(pdf).hexdigest(), ir_sha256="a" * 64,
        page_count=count, admitted_page_budget=count,
        pages_per_window=16, inspector_profile_id=TEXT_PROFILE,
    )


class PdfResourceLeavesTests(unittest.TestCase):
    """Prove generated native font/Lab reference roles, never font semantics."""

    @classmethod
    def setUpClass(cls):
        for count in (1, 33, 64):
            _CASES[count] = generated_job_case(count)[1]

    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("reporting.pdf_resource_leaves"),
            "opt-in generated resource-leaves module missing",
        )
        self.m = importlib.import_module("reporting.pdf_resource_leaves")
        self.worker = importlib.import_module("reporting._pdf_resource_leaves_worker")
        self.pdf = _CASES[1]
        self.plan = resource_plan(self.pdf, 1)

    def inspect(self, **changes):
        kwargs = {
            "pdf_bytes": self.pdf, "plan": self.plan,
            "expected_plan_sha256": self.plan.plan_sha256,
            "expected_language": "en-US",
        }
        return self.m.inspect_pdf_resource_leaves(**{**kwargs, **changes})

    def reader(self, count=1):
        return PdfReader(BytesIO(_CASES[count]), strict=True)

    def native(self, reader, index=0):
        return reader.get_object(reader.pages[index].indirect_reference)

    def resources(self, reader):
        return reader.get_object(self.native(reader).raw_get("/Resources"))

    def fonts(self, reader):
        return reader.get_object(self.resources(reader).raw_get("/Font"))

    def font(self, reader):
        fonts = self.fonts(reader)
        key = next(iter(fonts))
        ref = fonts.raw_get(key)
        return key, ref, reader.get_object(ref)

    def descendant(self, reader):
        _key, _ref, font = self.font(reader)
        child = font.raw_get("/DescendantFonts")[0]
        return font, child, reader.get_object(child)

    def verify(self, reader, count=1):
        return self.worker._verify_resource_leaves(
            reader, expected_pages=count,
            direct_count=len(reader.xref[0]),
            compressed_count=len(reader.xref_objStm),
        )

    def test_generated_one_thirty_three_sixty_four_native_resource_leaves(self):
        for count in (1, 33, 64):
            with self.subTest(pages=count):
                pdf = _CASES[count]
                plan = resource_plan(pdf, count)
                receipt = self.inspect(
                    pdf_bytes=pdf, plan=plan,
                    expected_plan_sha256=plan.plan_sha256,
                )
                row = receipt.to_dict()
                self.assertEqual(row["status"], "RESOURCE_LEAVES_ADMITTED")
                self.assertEqual(row["pdf_sha256"], sha256(pdf).hexdigest())
                self.assertEqual(row["page_count"], count)
                self.assertEqual(row["resource_dictionary_count"], 1)
                self.assertEqual(row["font_binding_count"], 3)
                self.assertEqual(row["cid_descendant_reference_count"], 3)
                self.assertEqual(row["tounicode_stream_reference_count"], 3)
                self.assertEqual(row["lab_color_space_count"], 2)
                self.assertTrue(row["font_reference_roles_disjoint"])
                self.assertTrue(row["type0_cid_links_match"])
                self.assertTrue(row["lab_color_presets_match"])
                self.assertTrue(row["tounicode_raw_streams_indexed"])
                self.assertEqual(len(row["prior_page_surface_sha256"]), 64)
                for key in (
                    "decoded_contents_audited", "font_programs_audited",
                    "glyph_widths_audited", "tounicode_decoded",
                    "reading_order_verified", "pdf_ua_qualified",
                    "all_file_revisions_inspected", "worker_results_authenticated",
                    "aggregate_job_resources_qualified", "default_pipeline_activated",
                    "release_authorized",
                ):
                    self.assertIs(row[key], False, key)

    def test_font_category_missing_extra_and_name_grammar_rejected(self):
        for case in ("empty", "extra", "lowercase", "not_dictionary"):
            with self.subTest(case=case):
                reader = self.reader()
                fonts = self.fonts(reader)
                if case == "empty":
                    fonts.clear()
                elif case == "extra":
                    fonts[NameObject("/Foo")] = next(iter(fonts.values()))
                elif case == "lowercase":
                    fonts[NameObject("/abcxyz")] = fonts.pop(next(iter(fonts)))
                else:
                    self.resources(reader)[NameObject("/Font")] = NumberObject(3)
                with self.assertRaises(ValueError):
                    self.verify(reader)

    def test_font_reference_direct_generation_foreign_duplicate_alias_rejected(self):
        for case in ("direct", "generation", "foreign", "duplicate", "page_alias"):
            with self.subTest(case=case):
                reader = self.reader()
                fonts = self.fonts(reader)
                keys = list(fonts)
                ref = fonts.raw_get(keys[0])
                if case == "direct":
                    fonts[keys[0]] = reader.get_object(ref)
                elif case == "generation":
                    fonts[keys[0]] = IndirectObject(ref.idnum, 1, reader)
                elif case == "foreign":
                    fonts[keys[0]] = IndirectObject(ref.idnum, 0, self.reader())
                elif case == "duplicate":
                    fonts[keys[1]] = ref
                else:
                    fonts[keys[0]] = self.native(reader).raw_get("/Contents")
                with self.assertRaises(ValueError):
                    self.verify(reader)

    def test_type0_native_font_shape_subtype_encoding_base_and_keys_rejected(self):
        for case in ("type", "subtype", "encoding", "base", "extra", "descendants_missing"):
            with self.subTest(case=case):
                reader = self.reader()
                _key, _ref, font = self.font(reader)
                if case == "type":
                    font[NameObject("/Type")] = NameObject("/XObject")
                elif case == "subtype":
                    font[NameObject("/Subtype")] = NameObject("/Type1")
                elif case == "encoding":
                    font[NameObject("/Encoding")] = NameObject("/WinAnsiEncoding")
                elif case == "base":
                    font[NameObject("/BaseFont")] = NameObject("/Other+Font")
                elif case == "extra":
                    font[NameObject("/Unexpected")] = NumberObject(9)
                else:
                    del font["/DescendantFonts"]
                with self.assertRaises(ValueError):
                    self.verify(reader)

    def test_tounicode_reference_filter_raw_and_alias_rejected(self):
        for case in ("direct", "generation", "font_alias", "filter", "raw_empty", "extra"):
            with self.subTest(case=case):
                reader = self.reader()
                _key, font_ref, font = self.font(reader)
                ref = font.raw_get("/ToUnicode")
                if case == "direct":
                    font[NameObject("/ToUnicode")] = reader.get_object(ref)
                elif case == "generation":
                    font[NameObject("/ToUnicode")] = IndirectObject(ref.idnum, 1, reader)
                elif case == "font_alias":
                    font[NameObject("/ToUnicode")] = font_ref
                else:
                    cmap = reader.get_object(ref)
                    if case == "filter":
                        cmap[NameObject("/Filter")] = NameObject("/ASCII85Decode")
                    elif case == "raw_empty":
                        cmap._data = b""
                    else:
                        cmap[NameObject("/Unexpected")] = NumberObject(1)
                with self.assertRaises(ValueError):
                    self.verify(reader)

    def test_cid_descendant_direct_count_generation_alias_rejected(self):
        for case in ("direct", "empty", "multiple", "generation", "cmap_alias"):
            with self.subTest(case=case):
                reader = self.reader()
                font, child_ref, child = self.descendant(reader)
                arr = font.raw_get("/DescendantFonts")
                if case == "direct":
                    arr[0] = child
                elif case == "empty":
                    arr.clear()
                elif case == "multiple":
                    arr.append(child_ref)
                elif case == "generation":
                    arr[0] = IndirectObject(child_ref.idnum, 1, reader)
                else:
                    arr[0] = font.raw_get("/ToUnicode")
                with self.assertRaises(ValueError):
                    self.verify(reader)

    def test_cid_linkage_system_identity_width_and_descriptor_rejected(self):
        for case in (
            "subtype", "base", "system", "supplement", "widths",
            "descriptor_direct", "descriptor_generation", "descriptor_alias",
            "descriptor_type", "extra",
        ):
            with self.subTest(case=case):
                reader = self.reader()
                font, _child_ref, cid = self.descendant(reader)
                descriptor = cid.raw_get("/FontDescriptor")
                if case == "subtype":
                    cid[NameObject("/Subtype")] = NameObject("/CIDFontType0")
                elif case == "base":
                    cid[NameObject("/BaseFont")] = NameObject("/Different+Font")
                elif case == "system":
                    cid["/CIDSystemInfo"][NameObject("/Ordering")] = TextStringObject("Other")
                elif case == "supplement":
                    cid["/CIDSystemInfo"][NameObject("/Supplement")] = NumberObject(1)
                elif case == "widths":
                    cid[NameObject("/W")] = NumberObject(0)
                elif case == "descriptor_direct":
                    cid[NameObject("/FontDescriptor")] = reader.get_object(descriptor)
                elif case == "descriptor_generation":
                    cid[NameObject("/FontDescriptor")] = IndirectObject(descriptor.idnum, 1, reader)
                elif case == "descriptor_alias":
                    cid[NameObject("/FontDescriptor")] = font.raw_get("/ToUnicode")
                elif case == "descriptor_type":
                    reader.get_object(descriptor)[NameObject("/Type")] = NameObject("/Catalog")
                else:
                    cid[NameObject("/Unexpected")] = NumberObject(3)
                with self.assertRaises(ValueError):
                    self.verify(reader)

    def test_lab_color_space_shape_whitepoint_and_range_rejected(self):
        for case in (
            "missing", "extra", "name", "array", "lab", "whitepoint",
            "range", "nan", "extra_option",
        ):
            with self.subTest(case=case):
                reader = self.reader()
                colors = reader.get_object(self.resources(reader).raw_get("/ColorSpace"))
                value = colors.raw_get("/lab-d50")
                if case == "missing":
                    del colors["/lab-d50"]
                elif case == "extra":
                    colors[NameObject("/RGB")] = ArrayObject()
                elif case == "name":
                    colors[NameObject("/lab-d50")] = NameObject("/Lab")
                elif case == "array":
                    value.pop()
                elif case == "lab":
                    value[0] = NameObject("/DeviceRGB")
                elif case == "whitepoint":
                    value[1][NameObject("/WhitePoint")] = ArrayObject([
                        NumberObject(1), NumberObject(1), NumberObject(1),
                    ])
                elif case == "range":
                    value[1][NameObject("/Range")] = ArrayObject([
                        NumberObject(-128), NumberObject(128),
                        NumberObject(-125), NumberObject(125),
                    ])
                elif case == "nan":
                    value[1][NameObject("/WhitePoint")][0] = FloatObject(float("nan"))
                else:
                    value[1][NameObject("/Surplus")] = NumberObject(1)
                with self.assertRaises(ValueError):
                    self.verify(reader)

    def test_font_descriptor_cannot_alias_catalog_info_or_pages_root(self):
        for role in ("catalog", "info", "pages_root"):
            with self.subTest(role=role):
                reader = self.reader()
                _font, _cid_ref, cid = self.descendant(reader)
                catalog_ref = reader.trailer.raw_get("/Root")
                targets = {
                    "catalog": catalog_ref,
                    "info": reader.trailer.raw_get("/Info"),
                    "pages_root": reader.get_object(catalog_ref).raw_get("/Pages"),
                }
                cid[NameObject("/FontDescriptor")] = targets[role]
                with self.assertRaises(ValueError):
                    self.verify(reader)

    def test_native_parser_xref_drift_rejected(self):
        reader = self.reader()
        self.assertEqual(self.verify(reader)["font_binding_count"], 3)
        reader.xref[0].pop(next(iter(reader.xref[0])))
        with self.assertRaises(ValueError):
            self.verify(reader)

    def test_bad_plan_language_and_disabled_profile_reject_before_worker(self):
        with patch.object(self.m, "_run_worker") as child:
            for changed in (
                {"pdf_bytes": bytearray(self.pdf)},
                {"pdf_bytes": _CASES[33]},
                {"pdf_bytes": b"invalid"},
                {"plan": object()},
                {"expected_plan_sha256": "f" * 64},
                {"expected_language": "pt-BR"},
            ):
                with self.subTest(changed=sorted(changed)):
                    with self.assertRaises(self.m.PdfResourceLeavesError):
                        self.inspect(**changed)
            child.assert_not_called()
        with patch.dict(os.environ, {"OMNIGENIS_PDF_RESOURCE_LEAVES_DISABLED": "1"}):
            with patch.object(self.m, "_run_worker") as child:
                with self.assertRaises(self.m.PdfResourceLeavesError):
                    self.inspect()
                child.assert_not_called()

    def test_child_protocol_identity_limits_forgery_and_noncano_rejected(self):
        identity = self.worker._identity_from_plan(self.plan)
        raw = self.m._run_worker(self.pdf, identity)
        base = json.loads(raw)
        mutations = []
        def tamper(change):
            row = json.loads(json.dumps(base))
            change(row)
            mutations.append(json.dumps(row).encode("ascii"))
        tamper(lambda x: x.update({"protocol_version": True}))
        tamper(lambda x: x["identity"].update({"pdf_sha256": "f" * 64}))
        tamper(lambda x: x["limits"].update({"memory_bytes": 0}))
        tamper(lambda x: x["inspection"].update({"font_binding_count": 0}))
        tamper(lambda x: x["inspection"].update({"lab_color_presets_match": False}))
        tamper(lambda x: x["inspection"].update({"unexpected": 1}))
        mutations.extend((
            raw.replace(b'"status":', b'"status":"forged","status":', 1),
            raw + b"\xff", raw + b"x" * (self.m.RESULT_BYTES + 1),
        ))
        for candidate in mutations:
            with self.subTest(length=len(candidate)):
                with patch.object(self.m, "_run_worker", return_value=candidate):
                    with self.assertRaises(self.m.PdfResourceLeavesError):
                        self.inspect()

    def test_inflight_plan_disable_and_receipt_mutation_rejected(self):
        normal = self.m._run_worker
        def change_plan(pdf, identity):
            result = normal(pdf, identity)
            object.__setattr__(self.plan, "ir_sha256", "f" * 64)
            return result
        with patch.object(self.m, "_run_worker", side_effect=change_plan):
            with self.assertRaises(self.m.PdfResourceLeavesError):
                self.inspect()
        self.plan = resource_plan(self.pdf, 1)
        flag = "OMNIGENIS_PDF_RESOURCE_LEAVES_DISABLED"
        def disable_during(pdf, identity):
            result = normal(pdf, identity)
            os.environ[flag] = "1"
            return result
        with patch.dict(os.environ):
            with patch.object(self.m, "_run_worker", side_effect=disable_during):
                with self.assertRaises(self.m.PdfResourceLeavesError):
                    self.inspect()
        receipt = self.inspect()
        self.assertEqual(receipt.inspection_sha256, sha256(receipt.to_bytes()).hexdigest())
        with self.assertRaises(FrozenInstanceError):
            receipt.font_binding_count = 0
        object.__setattr__(receipt, "font_binding_count", 0)
        with self.assertRaises(self.m.PdfResourceLeavesError):
            receipt.to_dict()

    def test_parent_does_not_parse_native_pdf(self):
        with patch("pypdf.PdfReader", side_effect=AssertionError("parent parsed")):
            self.assertEqual(self.inspect().font_binding_count, 3)

    def test_profile_manifest_and_nonclaims_are_pinned(self):
        """Pin the selected finite profile, dependency identities and unqualified claims."""
        manifest = json.loads((ROOT / "reporting/pdf-resource-leaves.v1.json").read_text())
        profile = self.m.resource_leaves_profile()
        self.assertEqual(manifest, profile)
        self.assertEqual(profile["parser_version"], "6.19.0")
        self.assertEqual(profile["max_pages"], 64)
        self.assertEqual(profile["max_pdf_bytes"], 16 * 1024 * 1024)
        for flag in (
            "font_programs_audited", "glyph_widths_audited",
            "tounicode_decoded", "pdf_ua_qualified", "release_authorized",
            "default_pipeline_activated",
        ):
            self.assertFalse(profile[flag])


if __name__ == "__main__":
    unittest.main()
