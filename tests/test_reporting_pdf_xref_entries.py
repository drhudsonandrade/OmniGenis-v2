"""Opt-in generated PDF XRef entry-map consistency; no release or PDF/UA claim."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
from hashlib import sha256
import importlib
import importlib.util
import json
import os
from pathlib import Path
import re
import unittest
from unittest.mock import patch
import zlib

from pypdf import PdfWriter
from io import BytesIO
from reporting.page_windows import plan_pdf_page_windows
from reporting.pdf_single_revision import inspect_pdf_single_revision
from reporting.pdf_text_windows import PROFILE_ID as TEXT_PROFILE
from tests.test_reporting_pdf_document_content import changed_pdf
from tests.test_reporting_pdf_source_inspection_job import generated_job_case
from tests.test_reporting_pdf_structure_tree import structure
from pypdf.generic import DictionaryObject, NameObject

ROOT = Path(__file__).resolve().parents[1]
_CASES = None


def page_plan(pdf: bytes, pages: int):
    return plan_pdf_page_windows(
        pdf_sha256=sha256(pdf).hexdigest(), ir_sha256="a" * 64,
        page_count=pages, admitted_page_budget=pages,
        pages_per_window=16, inspector_profile_id=TEXT_PROFILE,
    )


def mutate_last_xref_stream(pdf: bytes, transform):
    """Modify the actual final encoded XRef payload; preserve startxref offset."""
    marker = re.search(rb"\nstartxref\n([0-9]+)\n%%EOF\n\Z", pdf)
    if marker is None:
        raise AssertionError("fixture does not have one terminal XRef pointer")
    pos = int(marker.group(1))
    head = re.search(rb"stream\n", pdf[pos:pos + 500])
    if head is None:
        raise AssertionError("fixture has no final XRef stream")
    start = pos + head.end()
    header = pdf[pos:start]
    match = re.search(rb"/Length\s+(\d+)", header)
    if match is None:
        raise AssertionError("fixture has no direct encoded length")
    original_size = int(match.group(1))
    raw = zlib.decompress(pdf[start:start + original_size])
    changed = transform(raw)
    if changed == raw:
        raise AssertionError("mutation did not alter xref records")
    encoded = zlib.compress(changed)
    updated_header = (
        header[:match.start(1)] + str(len(encoded)).encode("ascii")
        + header[match.end(1):]
    )
    out = pdf[:pos] + updated_header + encoded + pdf[start + original_size:]
    assert out != pdf
    return out


class PdfXrefEntriesTests(unittest.TestCase):
    """Reject entry-map inconsistencies that prior XRef-marker gates can miss."""

    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("reporting.pdf_xref_entries"),
            "generated PDF XRef entry-map implementation not present",
        )
        self.m = importlib.import_module("reporting.pdf_xref_entries")
        self.worker = importlib.import_module("reporting._pdf_xref_entries_worker")
        global _CASES
        if _CASES is None:
            _CASES = {n: generated_job_case(n)[1] for n in (1, 33, 64)}
        self.pdf = _CASES[1]
        self.plan = page_plan(self.pdf, 1)

    def inspect(self, **changes):
        fields = dict(
            pdf_bytes=self.pdf, plan=self.plan,
            expected_plan_sha256=self.plan.plan_sha256,
            expected_language="en-US",
        )
        return self.m.inspect_pdf_xref_entries(**{**fields, **changes})

    def test_exact_generated_one_thirty_three_sixty_four_page_map_counts(self):
        counts = {
            1: (42, 1, 10, 31, 1, 210),
            33: (362, 1, 42, 319, 1, 1810),
            64: (606, 1, 73, 532, 1, 3030),
        }
        for pages, expected in counts.items():
            with self.subTest(pages=pages):
                pdf = _CASES[pages]
                plan = page_plan(pdf, pages)
                receipt = self.inspect(
                    pdf_bytes=pdf, plan=plan,
                    expected_plan_sha256=plan.plan_sha256,
                )
                info = receipt.to_dict()
                got = tuple(info[k] for k in (
                    "xref_entry_count", "free_entry_count", "direct_entry_count",
                    "compressed_entry_count", "object_stream_count",
                    "decoded_entry_bytes",
                ))
                self.assertEqual(got, expected)
                self.assertEqual(info["direct_headers_verified"], expected[2])
                self.assertEqual(info["object_stream_indices_verified"], expected[3])
                self.assertEqual(info["page_count"], pages)
                self.assertEqual(info["pdf_sha256"], sha256(pdf).hexdigest())
                self.assertEqual(info["status"], "XREF_ENTRY_MAP_ADMITTED")
                self.assertTrue(info["xref_entry_map_consistent"])
                self.assertEqual(len(info["prior_single_revision_sha256"]), 64)
                for field in (
                    "all_file_revisions_inspected", "opaque_payloads_audited",
                    "pdf_ua_qualified", "reading_order_verified",
                    "aggregate_job_resources_qualified", "default_pipeline_activated",
                    "release_authorized", "worker_results_authenticated",
                ):
                    self.assertFalse(info[field])

    def test_surplus_or_truncated_decoded_xref_entries_pass_prior_but_fail_new(self):
        for name, transform in (
            ("surplus", lambda raw: raw + b"\0" * 5),
            ("truncated", lambda raw: raw[:-5]),
        ):
            with self.subTest(kind=name):
                pdf = mutate_last_xref_stream(self.pdf, transform)
                plan = page_plan(pdf, 1)
                prior = inspect_pdf_single_revision(
                    pdf_bytes=pdf, plan=plan,
                    expected_plan_sha256=plan.plan_sha256,
                    expected_language="en-US",
                )
                self.assertEqual(prior.xref_marker_pairs, 1)
                with self.assertRaises(self.m.PdfXrefEntriesError):
                    self.inspect(pdf_bytes=pdf, plan=plan,
                                 expected_plan_sha256=plan.plan_sha256)

    def test_self_entry_wrong_physical_offset_passes_prior_but_fails_new(self):
        candidate = mutate_last_xref_stream(
            self.pdf, lambda raw: raw[:-5] + b"\x01\x00\x08\x00\x00")
        plan = page_plan(candidate, 1)
        prior = inspect_pdf_single_revision(
            pdf_bytes=candidate, plan=plan,
            expected_plan_sha256=plan.plan_sha256,
            expected_language="en-US")
        self.assertEqual(prior.xref_object_number, 41)
        with self.assertRaises(self.m.PdfXrefEntriesError):
            self.inspect(pdf_bytes=candidate, plan=plan,
                         expected_plan_sha256=plan.plan_sha256)

    def test_unsupported_xref_type_rejected_natively(self):
        candidate = mutate_last_xref_stream(
            self.pdf, lambda raw: raw[:5] + b"\x03" + raw[6:])
        identity = self.worker._identity_from_plan(page_plan(candidate, 1))
        with self.assertRaises(ValueError):
            self.worker._inspect(candidate, identity)

    def test_prerequisite_refuses_genuine_second_revision_before_worker(self):
        writer = PdfWriter(fileobj=BytesIO(self.pdf), incremental=True)
        writer.add_metadata({"/Subject": "synthetic-xref-increment"})
        out = BytesIO()
        writer.write(out)
        candidate = out.getvalue()
        plan = page_plan(candidate, 1)
        with patch.object(self.m, "_run_worker") as child:
            with self.assertRaises(self.m.PdfXrefEntriesError):
                self.inspect(pdf_bytes=candidate, plan=plan,
                             expected_plan_sha256=plan.plan_sha256)
            child.assert_not_called()

    def test_prior_role_edge_error_cannot_be_bypassed(self):
        def invalid(writer):
            root = structure(writer)[1]
            root[NameObject("/RoleMap")] = DictionaryObject({
                NameObject("/Custom"): NameObject("/Span"),
            })
        candidate = changed_pdf(self.pdf, invalid)
        plan = page_plan(candidate, 1)
        with patch.object(self.m, "_run_worker") as child:
            with self.assertRaises(self.m.PdfXrefEntriesError):
                self.inspect(pdf_bytes=candidate, plan=plan,
                             expected_plan_sha256=plan.plan_sha256)
            child.assert_not_called()

    def test_invalid_input_fails_without_child(self):
        """Reject malformed inputs and over-budget candidates before launching workers."""
        overflow = b"%PDF-1.7" + b"x" * 16777209
        overflow_plan = page_plan(overflow, 1)
        with patch.object(self.m, "_run_worker") as child:
            variants = (
                {"pdf_bytes": bytearray(self.pdf)},
                {"pdf_bytes": b"not-a-pdf"},
                {"pdf_bytes": _CASES[33]},
                {"pdf_bytes": overflow, "plan": overflow_plan, "expected_plan_sha256": overflow_plan.plan_sha256},
                {"plan": {}},
                {"expected_plan_sha256": "f" * 64},
                {"expected_language": "pt-BR"},
            )
            for change in variants:
                with self.subTest(fields=sorted(change)):
                    with self.assertRaises(self.m.PdfXrefEntriesError):
                        self.inspect(**change)
            child.assert_not_called()

    def test_disable_before_and_during_native_result_fails_closed(self):
        key = "OMNIGENIS_PDF_XREF_ENTRIES_DISABLED"
        with patch.dict(os.environ, {key: "1"}), patch.object(self.m, "_run_worker") as child:
            with self.assertRaises(self.m.PdfXrefEntriesError):
                self.inspect()
            child.assert_not_called()
        original = self.m._run_worker

        def disable_after(pdf, identity):
            wire = original(pdf, identity)
            os.environ[key] = "1"
            return wire

        with patch.dict(os.environ), patch.object(
            self.m, "_run_worker", side_effect=disable_after,
        ):
            with self.assertRaises(self.m.PdfXrefEntriesError):
                self.inspect()

    def test_forged_worker_envelopes_and_duplicate_keys_rejected(self):
        identity = self.worker._identity_from_plan(self.plan)
        valid_wire = self.m._run_worker(self.pdf, identity)
        clean = json.loads(valid_wire)
        variants = []
        def modify(fn):
            row = json.loads(json.dumps(clean))
            fn(row)
            variants.append(json.dumps(row).encode("ascii"))
        modify(lambda x: x.update({"extra": True}))
        modify(lambda x: x.update({"protocol_version": -2}))
        modify(lambda x: x["limits"].update({"memory_bytes": False}))
        modify(lambda x: x["identity"].update({"pdf_sha256": "0" * 64}))
        modify(lambda x: x["inspection"].update({"xref_entry_count": True}))
        modify(lambda x: x["inspection"].update({"direct_entry_count": -1}))
        modify(lambda x: x["inspection"].update({"object_stream_count": 100}))
        modify(lambda x: x["inspection"].update({"unexpected": 1}))
        modify(lambda x: x.update({"parser_version": "unverified"}))
        variants.extend([
            valid_wire.replace(b'"profile_id":', b'"profile_id":"spoof","profile_id":', 1),
            valid_wire + b"\xff",
            valid_wire + b"x" * (self.m.RESULT_BYTES + 1),
        ])
        for wire in variants:
            with self.subTest(length=len(wire)):
                with patch.object(self.m, "_run_worker", return_value=wire):
                    with self.assertRaises(self.m.PdfXrefEntriesError):
                        self.inspect()

    def test_parent_process_never_parses_pdf(self):
        with patch("pypdf.PdfReader", side_effect=AssertionError("parent parse prohibited")):
            self.assertEqual(self.inspect().page_count, 1)

    def test_inflight_plan_mutation_fails_identity_recheck(self):
        original = self.m._run_worker

        def mutate(pdf, identity):
            wire = original(pdf, identity)
            object.__setattr__(self.plan, "ir_sha256", "f" * 64)
            return wire

        with patch.object(self.m, "_run_worker", side_effect=mutate):
            with self.assertRaises(self.m.PdfXrefEntriesError):
                self.inspect()

    def test_sealed_metadata_receipt_cannot_be_modified(self):
        receipt = self.inspect()
        self.assertEqual(receipt.inspection_sha256, sha256(receipt.to_bytes()).hexdigest())
        with self.assertRaises(FrozenInstanceError):
            receipt.xref_entry_count = 0
        object.__setattr__(receipt, "xref_entry_count", 0)
        with self.assertRaises(self.m.PdfXrefEntriesError):
            receipt.to_dict()

    def test_manifest_is_exact_and_claims_are_bounded(self):
        """Pin the selected finite profile, dependency identities and unqualified claims."""
        saved = json.loads((ROOT / "reporting/pdf-xref-entries.v1.json").read_text())
        profile = self.m.xref_entries_profile()
        self.assertEqual(saved, profile)
        self.assertEqual(profile["max_pages"], 64)
        self.assertEqual(profile["max_pdf_bytes"], 16 * 1024 * 1024)
        self.assertFalse(profile["release_authorized"])
        self.assertFalse(profile["all_file_revisions_inspected"])


if __name__ == "__main__":
    unittest.main()
