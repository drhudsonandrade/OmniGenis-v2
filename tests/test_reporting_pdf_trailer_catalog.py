"""TDD: bounded generated-PDF trailer/catalog parity, opt-in only."""
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
from pypdf.generic import ArrayObject, IndirectObject, NameObject, NumberObject, TextStringObject
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


class PdfTrailerCatalogTests(unittest.TestCase):
    """Prove exact native generated trailer ownership, not arbitrary PDF safety."""

    @classmethod
    def setUpClass(cls):
        for count in (1, 33, 64):
            _CASES[count] = generated_job_case(count)[1]

    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("reporting.pdf_trailer_catalog"),
            "generated PDF trailer/catalog module missing",
        )
        self.m = importlib.import_module("reporting.pdf_trailer_catalog")
        self.worker = importlib.import_module("reporting._pdf_trailer_catalog_worker")
        self.pdf = _CASES[1]
        self.plan = page_plan(self.pdf, 1)

    def inspect(self, **changes):
        call = {
            "pdf_bytes": self.pdf, "plan": self.plan,
            "expected_plan_sha256": self.plan.plan_sha256,
            "expected_language": "en-US",
        }
        return self.m.inspect_pdf_trailer_catalog(**{**call, **changes})

    def reader(self):
        return PdfReader(BytesIO(self.pdf), strict=True)

    def verify(self, reader, count=1):
        return self.worker._verify_trailer_catalog(
            reader, expected_pages=count,
            direct_count=len(reader.xref[0]),
            compressed_count=len(reader.xref_objStm),
        )

    def test_generated_one_thirty_three_sixty_four_page_catalogs_are_exact(self):
        for count in (1, 33, 64):
            with self.subTest(count=count):
                pdf = _CASES[count]
                plan = page_plan(pdf, count)
                receipt = self.inspect(
                    pdf_bytes=pdf, plan=plan,
                    expected_plan_sha256=plan.plan_sha256,
                )
                row = receipt.to_dict()
                self.assertEqual(row["status"], "TRAILER_CATALOG_ADMITTED")
                self.assertEqual(row["pdf_sha256"], sha256(pdf).hexdigest())
                self.assertEqual(row["page_count"], count)
                self.assertEqual(row["catalog_page_count"], count)
                self.assertEqual(row["indexed_page_refs"], count)
                self.assertTrue(row["xref_trailer_values_match"])
                self.assertTrue(row["flat_page_tree_consistent"])
                self.assertGreater(row["root_object_number"], 0)
                self.assertGreater(row["info_object_number"], 0)
                self.assertGreater(row["pages_root_object_number"], 0)
                self.assertEqual(len(row["prior_xref_resolution_sha256"]), 64)
                for unavailable in (
                    "all_file_revisions_inspected", "opaque_payloads_audited",
                    "reading_order_verified", "pdf_ua_qualified",
                    "worker_results_authenticated", "aggregate_job_resources_qualified",
                    "default_pipeline_activated", "release_authorized",
                ):
                    self.assertFalse(row[unavailable])

    def test_trailer_missing_surplus_and_direct_root_are_refused(self):
        for problem in ("missing_root", "missing_id", "surplus", "direct_root"):
            with self.subTest(problem=problem):
                reader = self.reader()
                if problem == "missing_root":
                    del reader.trailer["/Root"]
                elif problem == "missing_id":
                    del reader.trailer["/ID"]
                elif problem == "surplus":
                    reader.trailer[NameObject("/Extra")] = NumberObject(1)
                else:
                    reader.trailer[NameObject("/Root")] = reader.root_object
                with self.assertRaises(ValueError):
                    self.verify(reader)

    def test_trailer_and_physical_xref_root_info_parity_is_required(self):
        for problem in ("trailer_root", "xref_root", "trailer_info", "xref_info"):
            with self.subTest(problem=problem):
                reader = self.reader()
                size = len(reader.xref[0]) + len(reader.xref_objStm) + 1
                xref = reader.get_object(IndirectObject(size - 1, 0, reader))
                pages = reader.root_object.raw_get("/Pages")
                root = reader.trailer.raw_get("/Root")
                if problem == "trailer_root":
                    reader.trailer[NameObject("/Root")] = pages
                elif problem == "xref_root":
                    xref[NameObject("/Root")] = pages
                elif problem == "trailer_info":
                    reader.trailer[NameObject("/Info")] = root
                else:
                    xref[NameObject("/Info")] = root
                with self.assertRaises(ValueError):
                    self.verify(reader)

    def test_malformed_id_size_and_indirect_generations_are_refused(self):
        for problem in ("id_length", "id_type", "size", "root_generation", "info_alias"):
            with self.subTest(problem=problem):
                reader = self.reader()
                if problem == "id_length":
                    reader.trailer[NameObject("/ID")] = ArrayObject(
                        [TextStringObject("short"), TextStringObject("short")],
                    )
                elif problem == "id_type":
                    reader.trailer[NameObject("/ID")] = TextStringObject("bad")
                elif problem == "size":
                    reader.trailer[NameObject("/Size")] = NumberObject(1)
                elif problem == "root_generation":
                    root = reader.trailer.raw_get("/Root")
                    reader.trailer[NameObject("/Root")] = IndirectObject(root.idnum, 1, reader)
                else:
                    root = reader.trailer.raw_get("/Root")
                    reader.trailer[NameObject("/Info")] = root
                with self.assertRaises(ValueError):
                    self.verify(reader)

    def test_catalog_pages_count_type_duplicate_and_parent_are_refused(self):
        for problem in ("count", "type", "duplicate", "parent", "kids_empty"):
            with self.subTest(problem=problem):
                reader = self.reader()
                root = reader.root_object
                pages_ref = root.raw_get("/Pages")
                pages = pages_ref.get_object()
                if problem == "count":
                    pages[NameObject("/Count")] = NumberObject(0)
                elif problem == "type":
                    pages[NameObject("/Type")] = NameObject("/Page")
                elif problem == "duplicate":
                    pages[NameObject("/Kids")] = ArrayObject(
                        [pages.raw_get("/Kids")[0], pages.raw_get("/Kids")[0]],
                    )
                elif problem == "parent":
                    kid = pages.raw_get("/Kids")[0].get_object()
                    kid[NameObject("/Parent")] = reader.trailer.raw_get("/Root")
                else:
                    pages[NameObject("/Kids")] = ArrayObject()
                with self.assertRaises(ValueError):
                    self.verify(reader)

    def test_parser_index_divergence_is_refused(self):
        reader = self.reader()
        self.assertTrue(self.verify(reader)["flat_page_tree_consistent"])
        reader.xref[0].pop(next(iter(reader.xref[0])))
        with self.assertRaises(ValueError):
            self.verify(reader)

    def test_invalid_identity_and_locale_fail_before_child(self):
        with patch.object(self.m, "_run_worker") as child:
            for change in (
                {"pdf_bytes": bytearray(self.pdf)},
                {"pdf_bytes": _CASES[33]},
                {"pdf_bytes": b"not a PDF"},
                {"plan": object()},
                {"expected_plan_sha256": "f" * 64},
                {"expected_language": "pt-BR"},
            ):
                with self.subTest(keys=sorted(change)):
                    with self.assertRaises(self.m.PdfTrailerCatalogError):
                        self.inspect(**change)
            child.assert_not_called()

    def test_disabled_profile_before_and_during_child_refused(self):
        key = "OMNIGENIS_PDF_TRAILER_CATALOG_DISABLED"
        with patch.dict(os.environ, {key: "1"}):
            with patch.object(self.m, "_run_worker") as child:
                with self.assertRaises(self.m.PdfTrailerCatalogError):
                    self.inspect()
                child.assert_not_called()
        normal = self.m._run_worker
        def disable_after(pdf, identity):
            result = normal(pdf, identity)
            os.environ[key] = "1"
            return result
        with patch.dict(os.environ):
            with patch.object(self.m, "_run_worker", side_effect=disable_after):
                with self.assertRaises(self.m.PdfTrailerCatalogError):
                    self.inspect()

    def test_forged_child_wire_duplicate_keys_and_budget_refused(self):
        identity = self.worker._identity_from_plan(self.plan)
        wire = self.m._run_worker(self.pdf, identity)
        base = json.loads(wire)
        variants = []
        def corrupt(fn):
            row = json.loads(json.dumps(base))
            fn(row)
            variants.append(json.dumps(row).encode("ascii"))
        corrupt(lambda x: x.update({"protocol_version": False}))
        corrupt(lambda x: x["identity"].update({"pdf_sha256": "f" * 64}))
        corrupt(lambda x: x["limits"].update({"cpu_seconds": 0}))
        corrupt(lambda x: x["inspection"].update({"catalog_page_count": 0}))
        corrupt(lambda x: x["inspection"].update({"flat_page_tree_consistent": False}))
        corrupt(lambda x: x["inspection"].update({"unexpected": "yes"}))
        variants.extend((
            wire.replace(b'"status":', b'"status":"forged","status":', 1),
            wire + b"\xff",
            wire + b"x" * (self.m.RESULT_BYTES + 1),
        ))
        for candidate in variants:
            with self.subTest(size=len(candidate)):
                with patch.object(self.m, "_run_worker", return_value=candidate):
                    with self.assertRaises(self.m.PdfTrailerCatalogError):
                        self.inspect()

    def test_parent_never_parses_pdf(self):
        with patch("pypdf.PdfReader", side_effect=AssertionError("parent parsed")):
            self.assertEqual(self.inspect().page_count, 1)

    def test_inflight_plan_mutation_is_refused(self):
        native = self.m._run_worker
        def tamper(pdf, identity):
            result = native(pdf, identity)
            object.__setattr__(self.plan, "ir_sha256", "f" * 64)
            return result
        with patch.object(self.m, "_run_worker", side_effect=tamper):
            with self.assertRaises(self.m.PdfTrailerCatalogError):
                self.inspect()

    def test_immutable_unsigned_receipt_resists_tamper(self):
        receipt = self.inspect()
        self.assertEqual(receipt.inspection_sha256, sha256(receipt.to_bytes()).hexdigest())
        with self.assertRaises(FrozenInstanceError):
            receipt.catalog_page_count = 0
        object.__setattr__(receipt, "catalog_page_count", 0)
        with self.assertRaises(self.m.PdfTrailerCatalogError):
            receipt.to_dict()

    def test_manifest_matches_strict_profile_and_limits(self):
        """Pin the selected finite profile, dependency identities and unqualified claims."""
        saved = json.loads((ROOT / "reporting/pdf-trailer-catalog.v1.json").read_text())
        profile = self.m.trailer_catalog_profile()
        self.assertEqual(saved, profile)
        self.assertEqual(profile["max_pages"], 64)
        self.assertEqual(profile["max_pdf_bytes"], 16 * 1024 * 1024)
        self.assertFalse(profile["pdf_ua_qualified"])
        self.assertFalse(profile["release_authorized"])
        self.assertFalse(profile["default_pipeline_activated"])


if __name__ == "__main__":
    unittest.main()
