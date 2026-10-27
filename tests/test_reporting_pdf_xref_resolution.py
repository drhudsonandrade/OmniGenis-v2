"""Opt-in generated PDF XRef parser-resolution parity; no release claim."""
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
from reporting.page_windows import plan_pdf_page_windows
from reporting.pdf_text_windows import PROFILE_ID as TEXT_PROFILE
from tests.test_reporting_pdf_source_inspection_job import generated_job_case
from tests.test_reporting_pdf_xref_entries import mutate_last_xref_stream

ROOT = Path(__file__).resolve().parents[1]
_CASES = {}


def page_plan(pdf: bytes, count: int):
    return plan_pdf_page_windows(
        pdf_sha256=sha256(pdf).hexdigest(), ir_sha256="a" * 64,
        page_count=count, admitted_page_budget=count,
        pages_per_window=16, inspector_profile_id=TEXT_PROFILE,
    )


class PdfXrefResolutionTests(unittest.TestCase):
    """Require the strict parser's complete physical XRef mapping to agree."""

    @classmethod
    def setUpClass(cls):
        for count in (1, 33, 64):
            _CASES[count] = generated_job_case(count)[1]

    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("reporting.pdf_xref_resolution"),
            "generated XRef parser-resolution parity module is missing",
        )
        self.m = importlib.import_module("reporting.pdf_xref_resolution")
        self.worker = importlib.import_module("reporting._pdf_xref_resolution_worker")
        self.pdf = _CASES[1]
        self.plan = page_plan(self.pdf, 1)

    def inspect(self, **changes):
        call = {
            "pdf_bytes": self.pdf,
            "plan": self.plan,
            "expected_plan_sha256": self.plan.plan_sha256,
            "expected_language": "en-US",
        }
        return self.m.inspect_pdf_xref_resolution(**{**call, **changes})

    def test_generated_one_thirty_three_sixty_four_page_maps_resolve_completely(self):
        expected_counts = {1: (10, 31), 33: (42, 319), 64: (73, 532)}
        for pages, expected in expected_counts.items():
            with self.subTest(pages=pages):
                pdf = _CASES[pages]
                plan = page_plan(pdf, pages)
                receipt = self.inspect(
                    pdf_bytes=pdf, plan=plan,
                    expected_plan_sha256=plan.plan_sha256,
                )
                row = receipt.to_dict()
                self.assertEqual(
                    (row["direct_objects_resolved"], row["compressed_objects_resolved"]),
                    expected,
                )
                self.assertEqual(row["parser_direct_entries"], expected[0])
                self.assertEqual(row["parser_compressed_entries"], expected[1])
                self.assertTrue(row["parser_xref_mapping_consistent"])
                self.assertTrue(row["all_indexed_objects_resolved"])
                self.assertEqual(row["pdf_sha256"], sha256(pdf).hexdigest())
                self.assertEqual(row["page_count"], pages)
                self.assertEqual(row["status"], "XREF_PARSER_RESOLUTION_ADMITTED")
                self.assertEqual(len(row["prior_xref_entries_sha256"]), 64)
                for unproved in (
                    "all_file_revisions_inspected", "opaque_payloads_audited",
                    "pdf_ua_qualified", "reading_order_verified",
                    "worker_results_authenticated", "aggregate_job_resources_qualified",
                    "default_pipeline_activated", "release_authorized",
                ):
                    self.assertFalse(row[unproved])

    def test_reader_direct_object_offset_divergence_refused(self):
        reader = PdfReader(BytesIO(self.pdf), strict=True)
        direct = dict(reader.xref[0])
        compressed = dict(reader.xref_objStm)
        self.worker._verify_parser_maps(reader, direct, compressed)
        object_id = next(iter(direct))
        reader.xref[0][object_id] += 1
        with self.assertRaises(ValueError):
            self.worker._verify_parser_maps(reader, direct, compressed)

    def test_reader_compressed_owner_or_index_divergence_refused(self):
        for corruption in ("owner", "index", "missing", "surplus"):
            with self.subTest(corruption=corruption):
                reader = PdfReader(BytesIO(self.pdf), strict=True)
                direct = dict(reader.xref[0])
                compressed = dict(reader.xref_objStm)
                object_id = next(iter(compressed))
                owner, index = compressed[object_id]
                if corruption == "owner":
                    reader.xref_objStm[object_id] = (owner + 1, index)
                elif corruption == "index":
                    reader.xref_objStm[object_id] = (owner, index + 1)
                elif corruption == "missing":
                    reader.xref_objStm.pop(object_id)
                else:
                    reader.xref_objStm[9999] = (owner, index)
                with self.assertRaises(ValueError):
                    self.worker._verify_parser_maps(reader, direct, compressed)

    def test_parser_extra_generation_and_free_entry_refused(self):
        reader = PdfReader(BytesIO(self.pdf), strict=True)
        direct = dict(reader.xref[0])
        compressed = dict(reader.xref_objStm)
        reader.xref[1] = {1: 9}
        with self.assertRaises(ValueError):
            self.worker._verify_parser_maps(reader, direct, compressed)
        reader.xref.pop(1)
        reader.xref_free_entry[0] = {0: 1}
        with self.assertRaises(ValueError):
            self.worker._verify_parser_maps(reader, direct, compressed)

    def test_unresolvable_indexed_compressed_object_refused(self):
        reader = PdfReader(BytesIO(self.pdf), strict=True)
        direct = dict(reader.xref[0])
        compressed = dict(reader.xref_objStm)
        with patch.object(reader, "get_object", side_effect=ValueError("invalid")):
            with self.assertRaises(ValueError):
                self.worker._verify_parser_maps(reader, direct, compressed)

    def test_broken_prior_xref_map_blocks_child(self):
        invalid = mutate_last_xref_stream(
            self.pdf, lambda raw: raw[:-5] + b"\x01\x00\x08\x00\x00",
        )
        plan = page_plan(invalid, 1)
        with patch.object(self.m, "_run_worker") as child:
            with self.assertRaises(self.m.PdfXrefResolutionError):
                self.inspect(pdf_bytes=invalid, plan=plan,
                             expected_plan_sha256=plan.plan_sha256)
            child.assert_not_called()

    def test_wrong_identity_and_locale_fail_without_child(self):
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
                    with self.assertRaises(self.m.PdfXrefResolutionError):
                        self.inspect(**change)
            child.assert_not_called()

    def test_disabled_profile_before_or_during_child_refused(self):
        key = "OMNIGENIS_PDF_XREF_RESOLUTION_DISABLED"
        with patch.dict(os.environ, {key: "1"}):
            with patch.object(self.m, "_run_worker") as child:
                with self.assertRaises(self.m.PdfXrefResolutionError):
                    self.inspect()
                child.assert_not_called()
        normal = self.m._run_worker
        def disable_after(pdf, identity):
            wire = normal(pdf, identity)
            os.environ[key] = "1"
            return wire
        with patch.dict(os.environ):
            with patch.object(self.m, "_run_worker", side_effect=disable_after):
                with self.assertRaises(self.m.PdfXrefResolutionError):
                    self.inspect()

    def test_forged_or_duplicate_child_wire_fails_closed(self):
        identity = self.worker._identity_from_plan(self.plan)
        wire = self.m._run_worker(self.pdf, identity)
        base = json.loads(wire)
        variations = []
        def mutate(fn):
            obj = json.loads(json.dumps(base))
            fn(obj)
            variations.append(json.dumps(obj).encode("ascii"))
        mutate(lambda x: x.update({"protocol_version": False}))
        mutate(lambda x: x.update({"profile_id": "unknown"}))
        mutate(lambda x: x["identity"].update({"pdf_sha256": "f" * 64}))
        mutate(lambda x: x["limits"].update({"cpu_seconds": 0}))
        mutate(lambda x: x["inspection"].update({"direct_objects_resolved": True}))
        mutate(lambda x: x["inspection"].update({"compressed_objects_resolved": 0}))
        mutate(lambda x: x["inspection"].update({"unexpected": "yes"}))
        variations.extend([
            wire.replace(b'"status":', b'"status":"forged","status":', 1),
            wire + b"\xff",
            wire + b"x" * (self.m.RESULT_BYTES + 1),
        ])
        for candidate in variations:
            with self.subTest(size=len(candidate)):
                with patch.object(self.m, "_run_worker", return_value=candidate):
                    with self.assertRaises(self.m.PdfXrefResolutionError):
                        self.inspect()

    def test_parent_cannot_use_unconfined_pdf_parser(self):
        with patch("pypdf.PdfReader", side_effect=AssertionError("parent PDF parse")):
            self.assertEqual(self.inspect().page_count, 1)

    def test_inflight_plan_mutation_fails_closed(self):
        original = self.m._run_worker
        def change_plan(pdf, identity):
            result = original(pdf, identity)
            object.__setattr__(self.plan, "ir_sha256", "f" * 64)
            return result
        with patch.object(self.m, "_run_worker", side_effect=change_plan):
            with self.assertRaises(self.m.PdfXrefResolutionError):
                self.inspect()

    def test_checksum_receipt_is_immutable_but_unsigned(self):
        receipt = self.inspect()
        self.assertEqual(receipt.inspection_sha256, sha256(receipt.to_bytes()).hexdigest())
        with self.assertRaises(FrozenInstanceError):
            receipt.parser_direct_entries = 0
        object.__setattr__(receipt, "parser_direct_entries", 0)
        with self.assertRaises(self.m.PdfXrefResolutionError):
            receipt.to_dict()

    def test_manifest_matches_exact_bounded_profile(self):
        saved = json.loads((ROOT / "reporting/pdf-xref-resolution.v1.json").read_text())
        profile = self.m.xref_resolution_profile()
        self.assertEqual(saved, profile)
        self.assertEqual(profile["max_pages"], 64)
        self.assertEqual(profile["max_pdf_bytes"], 8 * 1024 * 1024)
        self.assertFalse(profile["opaque_payloads_audited"])
        self.assertFalse(profile["default_pipeline_activated"])
        self.assertFalse(profile["release_authorized"])


if __name__ == "__main__":
    unittest.main()
