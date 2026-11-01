"""TDD: bounded generated PDF native page surface/resource parity, opt-in only."""
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
from pypdf.generic import ArrayObject, IndirectObject, NameObject, NumberObject
from reporting.page_windows import plan_pdf_page_windows
from reporting.pdf_text_windows import PROFILE_ID as TEXT_PROFILE
from tests.test_reporting_pdf_source_inspection_job import generated_job_case

ROOT = Path(__file__).resolve().parents[1]
_CASES = {}


def page_plan(pdf: bytes, count: int):
    return plan_pdf_page_windows(
        pdf_sha256=sha256(pdf).hexdigest(), ir_sha256="a" * 64,
        page_count=count, admitted_page_budget=count,
        pages_per_window=16, inspector_profile_id=TEXT_PROFILE,
    )


class PdfPageSurfaceTests(unittest.TestCase):
    """Require physical page/content/resource identity, never semantic PDF/UA."""

    @classmethod
    def setUpClass(cls):
        for count in (1, 33, 64):
            _CASES[count] = generated_job_case(count)[1]

    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("reporting.pdf_page_surface"),
            "generated page-surface module missing",
        )
        self.m = importlib.import_module("reporting.pdf_page_surface")
        self.worker = importlib.import_module("reporting._pdf_page_surface_worker")
        self.pdf = _CASES[1]
        self.plan = page_plan(self.pdf, 1)

    def inspect(self, **changes):
        kwargs = {
            "pdf_bytes": self.pdf, "plan": self.plan,
            "expected_plan_sha256": self.plan.plan_sha256,
            "expected_language": "en-US",
        }
        return self.m.inspect_pdf_page_surface(**{**kwargs, **changes})

    def reader(self, count=1):
        return PdfReader(BytesIO(_CASES[count]), strict=True)

    def native(self, reader, index=0):
        return reader.get_object(reader.pages[index].indirect_reference)

    def verify(self, reader, count=1):
        return self.worker._verify_page_surface(
            reader, expected_pages=count,
            direct_count=len(reader.xref[0]),
            compressed_count=len(reader.xref_objStm),
        )

    def test_generated_one_thirty_three_sixty_four_page_surfaces(self):
        for count in (1, 33, 64):
            with self.subTest(count=count):
                pdf = _CASES[count]
                plan = page_plan(pdf, count)
                receipt = self.inspect(
                    pdf_bytes=pdf, plan=plan, expected_plan_sha256=plan.plan_sha256,
                )
                row = receipt.to_dict()
                self.assertEqual(row["status"], "PAGE_SURFACE_ADMITTED")
                self.assertEqual(row["pdf_sha256"], sha256(pdf).hexdigest())
                self.assertEqual(row["page_count"], count)
                self.assertEqual(row["page_dictionary_count"], count)
                self.assertEqual(row["content_stream_count"], count)
                self.assertEqual(row["resource_reference_count"], count)
                self.assertEqual(row["distinct_resource_objects"], 1)
                self.assertTrue(row["boxes_match"])
                self.assertTrue(row["content_references_indexed"])
                self.assertTrue(row["resource_references_indexed"])
                self.assertTrue(row["structure_slots_contiguous"])
                self.assertEqual(len(row["prior_trailer_catalog_sha256"]), 64)
                for flag in (
                    "decoded_contents_audited", "inner_resources_audited",
                    "reading_order_verified", "pdf_ua_qualified",
                    "worker_results_authenticated", "aggregate_job_resources_qualified",
                    "default_pipeline_activated", "release_authorized",
                ):
                    self.assertFalse(row[flag])

    def test_page_missing_extra_and_wrong_type_rejected(self):
        for case in ("no_contents", "extra_annots", "wrong_type"):
            with self.subTest(case=case):
                reader = self.reader()
                page = self.native(reader)
                if case == "no_contents":
                    del page["/Contents"]
                elif case == "extra_annots":
                    page[NameObject("/Annots")] = ArrayObject()
                else:
                    page[NameObject("/Type")] = NameObject("/Pages")
                with self.assertRaises(ValueError):
                    self.verify(reader)

    def test_contents_direct_wrong_generation_alias_and_duplicate_rejected(self):
        for case in ("direct", "generation", "alias", "duplicate"):
            with self.subTest(case=case):
                count = 33 if case == "duplicate" else 1
                reader = self.reader(count)
                page = self.native(reader)
                contents = page.raw_get("/Contents")
                if case == "direct":
                    page[NameObject("/Contents")] = contents.get_object()
                elif case == "generation":
                    page[NameObject("/Contents")] = IndirectObject(contents.idnum, 1, reader)
                elif case == "alias":
                    page[NameObject("/Contents")] = page.raw_get("/Resources")
                else:
                    self.native(reader, 1)[NameObject("/Contents")] = contents
                with self.assertRaises(ValueError):
                    self.verify(reader, count)

    def test_contents_native_filter_payload_and_key_shape_rejected(self):
        for case in ("filter", "empty_raw", "surplus"):
            with self.subTest(case=case):
                reader = self.reader()
                stream = reader.get_object(self.native(reader).raw_get("/Contents"))
                if case == "filter":
                    stream[NameObject("/Filter")] = NameObject("/ASCII85Decode")
                elif case == "empty_raw":
                    stream._data = b""
                else:
                    stream[NameObject("/Extra")] = NumberObject(1)
                with self.assertRaises(ValueError):
                    self.verify(reader)

    def test_resources_direct_wrong_generation_and_role_alias_rejected(self):
        for case in ("direct", "generation", "alias"):
            with self.subTest(case=case):
                reader = self.reader()
                page = self.native(reader)
                resources = page.raw_get("/Resources")
                if case == "direct":
                    page[NameObject("/Resources")] = resources.get_object()
                elif case == "generation":
                    page[NameObject("/Resources")] = IndirectObject(resources.idnum, 1, reader)
                else:
                    page[NameObject("/Resources")] = page.raw_get("/Contents")
                with self.assertRaises(ValueError):
                    self.verify(reader)

    def test_resource_outer_categories_and_nested_refs_rejected(self):
        for case in ("missing_font", "extra", "font_direct", "color_generation", "gstate_number"):
            with self.subTest(case=case):
                reader = self.reader()
                resources = reader.get_object(self.native(reader).raw_get("/Resources"))
                if case == "missing_font":
                    del resources["/Font"]
                elif case == "extra":
                    resources[NameObject("/Extra")] = NumberObject(1)
                elif case == "font_direct":
                    resources[NameObject("/Font")] = resources.raw_get("/Font").get_object()
                elif case == "color_generation":
                    old = resources.raw_get("/ColorSpace")
                    resources[NameObject("/ColorSpace")] = IndirectObject(old.idnum, 1, reader)
                else:
                    resources[NameObject("/ExtGState")] = NumberObject(1)
                with self.assertRaises(ValueError):
                    self.verify(reader)

    def test_bad_boxes_nonmatching_and_degenerate_refused(self):
        for case in ("short", "negative", "degenerate", "mismatch", "huge"):
            with self.subTest(case=case):
                reader = self.reader()
                page = self.native(reader)
                if case == "short":
                    page[NameObject("/MediaBox")] = ArrayObject(
                        [NumberObject(0), NumberObject(0), NumberObject(100)],
                    )
                elif case == "negative":
                    page[NameObject("/TrimBox")] = ArrayObject(
                        [NumberObject(-1), NumberObject(0), NumberObject(100), NumberObject(100)],
                    )
                elif case == "degenerate":
                    page[NameObject("/MediaBox")] = ArrayObject(
                        [NumberObject(0), NumberObject(0), NumberObject(0), NumberObject(100)],
                    )
                elif case == "mismatch":
                    page[NameObject("/BleedBox")] = ArrayObject(
                        [NumberObject(0), NumberObject(0), NumberObject(100), NumberObject(100)],
                    )
                else:
                    page[NameObject("/TrimBox")] = ArrayObject(
                        [NumberObject(0), NumberObject(0), NumberObject(50000), NumberObject(50000)],
                    )
                with self.assertRaises(ValueError):
                    self.verify(reader)

    def test_tabs_and_structure_slot_policy_refused(self):
        for case in ("tabs", "negative_slot", "duplicate_slot", "gap_slot"):
            with self.subTest(case=case):
                count = 33 if case in ("duplicate_slot", "gap_slot") else 1
                reader = self.reader(count)
                page = self.native(reader)
                if case == "tabs":
                    page[NameObject("/Tabs")] = NameObject("/R")
                elif case == "negative_slot":
                    page[NameObject("/StructParents")] = NumberObject(-1)
                elif case == "duplicate_slot":
                    self.native(reader, 1)[NameObject("/StructParents")] = NumberObject(0)
                else:
                    self.native(reader, 1)[NameObject("/StructParents")] = NumberObject(999)
                with self.assertRaises(ValueError):
                    self.verify(reader, count)

    def test_parser_xref_index_divergence_refused(self):
        reader = self.reader()
        self.assertTrue(self.verify(reader)["boxes_match"])
        reader.xref[0].pop(next(iter(reader.xref[0])))
        with self.assertRaises(ValueError):
            self.verify(reader)

    def test_bad_inputs_and_disabled_profile_fail_before_worker(self):
        with patch.object(self.m, "_run_worker") as child:
            for case in (
                {"pdf_bytes": bytearray(self.pdf)},
                {"pdf_bytes": _CASES[33]},
                {"pdf_bytes": b"invalid"},
                {"plan": object()},
                {"expected_plan_sha256": "f" * 64},
                {"expected_language": "pt-BR"},
            ):
                with self.subTest(fields=sorted(case)):
                    with self.assertRaises(self.m.PdfPageSurfaceError):
                        self.inspect(**case)
            child.assert_not_called()
        with patch.dict(os.environ, {"OMNIGENIS_PDF_PAGE_SURFACE_DISABLED": "1"}):
            with patch.object(self.m, "_run_worker") as child:
                with self.assertRaises(self.m.PdfPageSurfaceError):
                    self.inspect()
                child.assert_not_called()

    def test_forged_worker_wire_duplicate_and_budget_refused(self):
        identity = self.worker._identity_from_plan(self.plan)
        original = self.m._run_worker(self.pdf, identity)
        base = json.loads(original)
        variants = []
        def tamper(change):
            row = json.loads(json.dumps(base))
            change(row)
            variants.append(json.dumps(row).encode("ascii"))
        tamper(lambda x: x.update({"protocol_version": False}))
        tamper(lambda x: x["identity"].update({"pdf_sha256": "f" * 64}))
        tamper(lambda x: x["limits"].update({"cpu_seconds": 0}))
        tamper(lambda x: x["inspection"].update({"page_dictionary_count": 0}))
        tamper(lambda x: x["inspection"].update({"boxes_match": False}))
        tamper(lambda x: x["inspection"].update({"unexpected": 1}))
        variants.extend((
            original.replace(b'"status":', b'"status":"forged","status":', 1),
            original + b"\xff", original + b"x" * (self.m.RESULT_BYTES + 1),
        ))
        for candidate in variants:
            with self.subTest(size=len(candidate)):
                with patch.object(self.m, "_run_worker", return_value=candidate):
                    with self.assertRaises(self.m.PdfPageSurfaceError):
                        self.inspect()

    def test_inflight_mutation_disable_and_receipt_tamper_refused(self):
        normal = self.m._run_worker
        def mutate(pdf, identity):
            value = normal(pdf, identity)
            object.__setattr__(self.plan, "ir_sha256", "f" * 64)
            return value
        with patch.object(self.m, "_run_worker", side_effect=mutate):
            with self.assertRaises(self.m.PdfPageSurfaceError):
                self.inspect()
        self.plan = page_plan(self.pdf, 1)
        flag = "OMNIGENIS_PDF_PAGE_SURFACE_DISABLED"
        def disable(pdf, identity):
            value = normal(pdf, identity)
            os.environ[flag] = "1"
            return value
        with patch.dict(os.environ):
            with patch.object(self.m, "_run_worker", side_effect=disable):
                with self.assertRaises(self.m.PdfPageSurfaceError):
                    self.inspect()
        receipt = self.inspect()
        self.assertEqual(receipt.inspection_sha256, sha256(receipt.to_bytes()).hexdigest())
        with self.assertRaises(FrozenInstanceError):
            receipt.content_stream_count = 0
        object.__setattr__(receipt, "content_stream_count", 0)
        with self.assertRaises(self.m.PdfPageSurfaceError):
            receipt.to_dict()

    def test_parent_does_not_parse_current_pdf(self):
        with patch("pypdf.PdfReader", side_effect=AssertionError("parent parsed")):
            self.assertEqual(self.inspect().page_count, 1)

    def test_manifest_exact_profile_and_restricted_claims(self):
        """Pin the selected finite profile, dependency identities and unqualified claims."""
        manifest = json.loads((ROOT / "reporting/pdf-page-surface.v1.json").read_text())
        profile = self.m.page_surface_profile()
        self.assertEqual(manifest, profile)
        self.assertEqual(profile["max_pages"], 64)
        self.assertEqual(profile["max_pdf_bytes"], 16 * 1024 * 1024)
        self.assertFalse(profile["decoded_contents_audited"])
        self.assertFalse(profile["pdf_ua_qualified"])
        self.assertFalse(profile["default_pipeline_activated"])
        self.assertFalse(profile["release_authorized"])


if __name__ == "__main__":
    unittest.main()
