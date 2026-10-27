"""Opt-in generated PDF single-xref admission; no PDF/UA or revision audit claim."""
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

from pypdf import PdfWriter
from pypdf.generic import DictionaryObject, NameObject
from reporting.page_windows import plan_pdf_page_windows
from reporting.pdf_structure_role_edges import inspect_pdf_structure_role_edges
from reporting.pdf_text_windows import PROFILE_ID as TEXT_PROFILE
from tests.test_reporting_pdf_document_content import changed_pdf
from tests.test_reporting_pdf_source_inspection_job import generated_job_case
from tests.test_reporting_pdf_structure_tree import structure


ROOT = Path(__file__).resolve().parents[1]


class PdfSingleRevisionTests(unittest.TestCase):
    """A genuine second xref update must fail even when role adjacency passes."""

    cases = None

    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("reporting.pdf_single_revision"),
            "single-xref admission module is missing",
        )
        self.m = importlib.import_module("reporting.pdf_single_revision")
        self.worker = importlib.import_module("reporting._pdf_single_revision_worker")
        if self.__class__.cases is None:
            self.__class__.cases = {n: generated_job_case(n)[1] for n in (1, 33, 64)}
        self.pdf = self.cases[1]
        self.plan = self.plan_for(self.pdf, 1)

    @staticmethod
    def plan_for(pdf, pages):
        return plan_pdf_page_windows(
            pdf_sha256=sha256(pdf).hexdigest(), ir_sha256="a" * 64,
            page_count=pages, admitted_page_budget=pages,
            pages_per_window=16, inspector_profile_id=TEXT_PROFILE,
        )

    def inspect(self, **changes):
        values = dict(pdf_bytes=self.pdf, plan=self.plan,
                      expected_plan_sha256=self.plan.plan_sha256,
                      expected_language="en-US")
        return self.m.inspect_pdf_single_revision(**{**values, **changes})

    def updated(self):
        writer = PdfWriter(fileobj=BytesIO(self.pdf), incremental=True)
        writer.add_metadata({"/Subject": "synthetic-incremental-only"})
        out = BytesIO()
        writer.write(out)
        candidate = out.getvalue()
        return candidate, self.plan_for(candidate, 1)

    def test_native_generated_one_thirty_three_sixty_four_page_single_xref(self):
        for pages, pdf in self.cases.items():
            with self.subTest(pages=pages):
                plan = self.plan_for(pdf, pages)
                receipt = self.inspect(
                    pdf_bytes=pdf, plan=plan,
                    expected_plan_sha256=plan.plan_sha256,
                )
                data = receipt.to_dict()
                xref_offset = int(pdf.rsplit(b"startxref\n", 1)[1].split(b"\n", 1)[0])
                self.assertEqual(data["xref_offset"], xref_offset)
                self.assertEqual(pdf.count(b"startxref"), 1)
                self.assertEqual(pdf.count(b"%%EOF"), 1)
                self.assertEqual(data["xref_marker_pairs"], 1)
                self.assertEqual(data["page_count"], pages)
                self.assertEqual(data["pdf_sha256"], sha256(pdf).hexdigest())
                self.assertEqual(data["status"], "SINGLE_XREF_REVISION_ADMITTED")
                self.assertTrue(data["single_xref_revision_admitted"])
                self.assertEqual(data["language"], "en-US")
                self.assertGreater(data["xref_object_number"], 0)
                self.assertEqual(len(data["role_edge_inspection_sha256"]), 64)
                for name in (
                    "all_file_revisions_inspected", "opaque_payloads_audited",
                    "pdf_ua_qualified", "reading_order_verified",
                    "aggregate_job_resources_qualified", "default_pipeline_activated",
                    "release_authorized",
                ):
                    self.assertFalse(data[name])

    def test_real_incremental_update_passes_prior_gate_but_is_rejected(self):
        candidate, plan = self.updated()
        self.assertEqual(candidate.count(b"startxref"), 2)
        self.assertEqual(candidate.count(b"%%EOF"), 2)
        prior = inspect_pdf_structure_role_edges(
            pdf_bytes=candidate, plan=plan,
            expected_plan_sha256=plan.plan_sha256, expected_language="en-US",
        )
        self.assertEqual(prior.structure_elements, 10)
        with self.assertRaises(self.m.PdfSingleRevisionError):
            self.inspect(
                pdf_bytes=candidate, plan=plan,
                expected_plan_sha256=plan.plan_sha256,
            )

    def test_native_worker_rejects_forged_offset_and_extra_markers(self):
        data = self.pdf
        match = re.search(rb"\nstartxref\n([0-9]+)\n%%EOF\n\Z", data)
        self.assertIsNotNone(match)
        wrong = data[:match.start(1)] + str(int(match.group(1)) + 1).encode() + data[match.end(1):]
        malformed = (
            wrong, data + b"TRAILING", data + b"\n%%EOF\n",
            data + b"\nstartxref\n1\n%%EOF\n",
            data.replace(b"/Type /XRef", b"/Type /Test", 1),
        )
        for pdf in malformed:
            with self.subTest(mutated_sha256=sha256(pdf).hexdigest()):
                identity = self.worker._identity_from_plan(self.plan_for(pdf, 1))
                with self.assertRaises(ValueError):
                    self.worker._inspect(pdf, identity)

    def test_invalid_input_fails_before_any_native_worker(self):
        with patch.object(self.m, "_run_worker") as worker:
            for change in (
                dict(pdf_bytes=bytearray(self.pdf)),
                dict(pdf_bytes=b"not_pdf"),
                dict(pdf_bytes=self.cases[33]),
                dict(expected_plan_sha256="f" * 64),
                dict(expected_language="pt-BR"),
                dict(plan={}),
                dict(pdf_bytes=b"%PDF-1.7" + b"x" * (8 * 1024 * 1024)),
            ):
                with self.subTest(fields=sorted(change)):
                    with self.assertRaises(self.m.PdfSingleRevisionError):
                        self.inspect(**change)
            worker.assert_not_called()

    def test_role_edge_prerequisite_cannot_be_bypassed(self):
        def changed(writer):
            root = structure(writer)[1]
            root[NameObject("/RoleMap")] = DictionaryObject({
                NameObject("/Custom"): NameObject("/Span"),
            })
        pdf = changed_pdf(self.pdf, changed)
        plan = self.plan_for(pdf, 1)
        with patch.object(self.m, "_run_worker") as worker:
            with self.assertRaises(self.m.PdfSingleRevisionError):
                self.inspect(
                    pdf_bytes=pdf, plan=plan,
                    expected_plan_sha256=plan.plan_sha256,
                )
            worker.assert_not_called()

    def test_disable_before_and_during_child_fails_closed(self):
        key = "OMNIGENIS_PDF_SINGLE_REVISION_DISABLED"
        with patch.dict(os.environ, {key: "1"}), patch.object(self.m, "_run_worker") as run:
            with self.assertRaises(self.m.PdfSingleRevisionError):
                self.inspect()
            run.assert_not_called()
        original = self.m._run_worker
        def disable_after(pdf, identity):
            wire = original(pdf, identity)
            os.environ[key] = "1"
            return wire
        with patch.dict(os.environ), patch.object(
            self.m, "_run_worker", side_effect=disable_after,
        ):
            with self.assertRaises(self.m.PdfSingleRevisionError):
                self.inspect()

    def test_forged_worker_response_and_duplicate_keys_are_rejected(self):
        identity = self.worker._identity_from_plan(self.plan)
        clean = json.loads(self.m._run_worker(self.pdf, identity))
        variants = []
        def change(fn):
            item = json.loads(json.dumps(clean))
            fn(item)
            variants.append(item)
        change(lambda x: x.update({"unexpected": True}))
        change(lambda x: x.update({"protocol_version": -1}))
        change(lambda x: x["identity"].update({"pdf_sha256": "f" * 64}))
        change(lambda x: x["limits"].update({"memory_bytes": True}))
        change(lambda x: x["inspection"].update({"xref_offset": True}))
        change(lambda x: x["inspection"].update({"xref_object_number": 0}))
        change(lambda x: x["inspection"].update({"xref_marker_pairs": 2}))
        change(lambda x: x["inspection"].update({"unknown": 1}))
        change(lambda x: x.update({"parser_version": "unverified"}))
        for value in variants:
            with self.subTest(value=value.get("profile_id")):
                with patch.object(self.m, "_run_worker", return_value=json.dumps(value).encode("ascii")):
                    with self.assertRaises(self.m.PdfSingleRevisionError):
                        self.inspect()
        wire = self.m._run_worker(self.pdf, identity)
        for forged in (
            wire.replace(b'"profile_id":', b'"profile_id":"spoof","profile_id":', 1),
            wire + b"\xff", wire + b"x" * (self.m.RESULT_BYTES + 1),
        ):
            with patch.object(self.m, "_run_worker", return_value=forged):
                with self.assertRaises(self.m.PdfSingleRevisionError):
                    self.inspect()

    def test_parent_cannot_parse_pdf(self):
        with patch("pypdf.PdfReader", side_effect=AssertionError("parent reader forbidden")):
            self.assertEqual(self.inspect().page_count, 1)

    def test_changed_plan_during_worker_is_rejected(self):
        actual = self.m._run_worker
        def mutate(pdf, identity):
            result = actual(pdf, identity)
            object.__setattr__(self.plan, "ir_sha256", "f" * 64)
            return result
        with patch.object(self.m, "_run_worker", side_effect=mutate):
            with self.assertRaises(self.m.PdfSingleRevisionError):
                self.inspect()

    def test_sealed_receipt_cannot_be_mutated(self):
        receipt = self.inspect()
        self.assertEqual(receipt.inspection_sha256, sha256(receipt.to_bytes()).hexdigest())
        with self.assertRaises(FrozenInstanceError):
            receipt.xref_offset = 2
        object.__setattr__(receipt, "xref_offset", 2)
        with self.assertRaises(self.m.PdfSingleRevisionError):
            receipt.to_dict()

    def test_manifest_has_single_profile_and_no_release_claims(self):
        manifest = json.loads((ROOT / "reporting/pdf-single-revision.v1.json").read_text())
        profile = self.m.single_revision_profile()
        self.assertEqual(manifest, profile)
        self.assertEqual(profile["max_pages"], 64)
        self.assertEqual(profile["max_pdf_bytes"], 8 * 1024 * 1024)
        self.assertEqual(profile["parser_version"], "6.19.0")
        self.assertFalse(profile["all_file_revisions_inspected"])
        self.assertFalse(profile["release_authorized"])


if __name__ == "__main__":
    unittest.main()
