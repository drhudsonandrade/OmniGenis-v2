"""Synthetic TDD checks for an inert, bounded PDF page-window ledger."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import hashlib
import ast
import importlib
import importlib.util
import json
from pathlib import Path
import socket
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
PDF_SHA = "a" * 64
IR_SHA = "b" * 64


def digest(payload: bytes) -> str:
    """Hash deterministic synthetic fixture bytes for metadata-only test claims."""
    return hashlib.sha256(payload).hexdigest()


class PageWindowLedgerTests(unittest.TestCase):
    def setUp(self):
        """Create a fresh synthetic 33-page declaration with three bounded windows."""
        self.assertIsNotNone(
            importlib.util.find_spec("reporting.page_windows"),
            "inert PDF page-window contract is missing",
        )
        self.m = importlib.import_module("reporting.page_windows")
        self.plan = self.m.plan_pdf_page_windows(
            pdf_sha256=PDF_SHA, ir_sha256=IR_SHA, page_count=33,
            admitted_page_budget=300, pages_per_window=16,
            inspector_profile_id="synthetic-window-raster-v1",
        )

    def observations(self, plan=None):
        """Build synthetic observation identifiers without invoking a PDF worker."""
        plan = self.plan if plan is None else plan
        return tuple(
            self.m.WindowObservation(
                index=span.index, first_page=span.first_page,
                last_page=span.last_page, pdf_sha256=plan.pdf_sha256,
                plan_sha256=plan.plan_sha256,
                inspector_profile_id=plan.inspector_profile_id,
                observation_sha256=digest(f"synthetic:{span.index}".encode()),
            ) for span in plan.windows
        )

    def bind(self, plan=None, observations=None):
        """Exercise the public evidence binder with explicit fixture overrides."""
        plan = self.plan if plan is None else plan
        return self.m.bind_pdf_page_window_evidence(
            plan=plan,
            observations=self.observations(plan) if observations is None else observations,
        )

    def test_changed_functions_have_docstrings(self):
        """Require descriptive documentation for each function in the changed modules."""
        for relative in ("reporting/page_windows.py", "tests/test_reporting_page_windows.py"):
            with self.subTest(path=relative):
                tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
                missing = [node.name for node in ast.walk(tree)
                           if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                           and not ast.get_docstring(node)]
                self.assertEqual(missing, [], "Every changed function requires a docstring")

    def test_33_page_plan_covers_every_page_without_truncation(self):
        """Account for both full windows and the final single-page remainder."""
        self.assertEqual(
            [(w.index, w.first_page, w.last_page) for w in self.plan.windows],
            [(0, 1, 16), (1, 17, 32), (2, 33, 33)],
        )
        self.assertEqual(self.plan.page_count, 33)
        self.assertEqual(self.plan.window_count, 3)

    def test_64_129_and_300_pages_are_windowed_completely(self):
        """Preserve every declared page across multiple synthetic workload sizes."""
        for count in (64, 129, 300):
            with self.subTest(count=count):
                plan = self.m.plan_pdf_page_windows(
                    pdf_sha256=PDF_SHA, ir_sha256=IR_SHA, page_count=count,
                    admitted_page_budget=count, pages_per_window=16,
                    inspector_profile_id="synthetic-window-raster-v1",
                )
                pages = [p for w in plan.windows for p in range(w.first_page, w.last_page + 1)]
                self.assertEqual(pages, list(range(1, count + 1)))
                self.assertEqual(self.bind(plan).to_dict()["window_count"], len(plan.windows))

    def test_one_page_and_exact_boundary(self):
        """Handle minimal and exact-window workloads without empty trailing spans."""
        for count in (1, 16, 32):
            plan = self.m.plan_pdf_page_windows(
                pdf_sha256=PDF_SHA, ir_sha256=IR_SHA, page_count=count,
                admitted_page_budget=count, pages_per_window=16,
                inspector_profile_id="synthetic-window-raster-v1",
            )
            self.assertEqual(plan.windows[0].first_page, 1)
            self.assertEqual(plan.windows[-1].last_page, count)

    def test_empty_and_unadmitted_jobs_are_rejected_not_truncated(self):
        """Reject empty or over-budget declarations instead of returning partial plans."""
        for count, admitted in ((0, 300), (301, 300), (300, 0), (32769, 32769)):
            with self.subTest(count=count, admitted=admitted):
                with self.assertRaises(self.m.PageWindowError):
                    self.m.plan_pdf_page_windows(
                        pdf_sha256=PDF_SHA, ir_sha256=IR_SHA, page_count=count,
                        admitted_page_budget=admitted, pages_per_window=16,
                        inspector_profile_id="synthetic-window-raster-v1",
                    )

    def test_bools_floats_and_strings_cannot_be_page_counts(self):
        """Reject count lookalikes rather than coercing them to page identities."""
        for value in (True, False, 1.0, "33", None, -1):
            with self.subTest(value=value):
                with self.assertRaises(self.m.PageWindowError):
                    self.m.plan_pdf_page_windows(
                        pdf_sha256=PDF_SHA, ir_sha256=IR_SHA, page_count=value,
                        admitted_page_budget=300, pages_per_window=16,
                        inspector_profile_id="synthetic-window-raster-v1",
                    )

    def test_window_budget_is_finite_and_strict(self):
        """Enforce both per-window bounds and the aggregate window-count budget."""
        for width in (0, -1, True, 33, "16", 1.0):
            with self.subTest(width=width):
                with self.assertRaises(self.m.PageWindowError):
                    self.m.plan_pdf_page_windows(
                        pdf_sha256=PDF_SHA, ir_sha256=IR_SHA, page_count=33,
                        admitted_page_budget=300, pages_per_window=width,
                        inspector_profile_id="synthetic-window-raster-v1",
                    )
        with self.assertRaises(self.m.PageWindowError):
            self.m.plan_pdf_page_windows(
                pdf_sha256=PDF_SHA, ir_sha256=IR_SHA, page_count=1025,
                admitted_page_budget=1025, pages_per_window=1,
                inspector_profile_id="synthetic-window-raster-v1",
            )

    def test_sha_and_inspector_inputs_are_strict(self):
        """Reject malformed digests and unsafe inspector identifier spellings."""
        for bad_pdf, bad_ir, bad_profile in (
            ("A" * 64, IR_SHA, "synthetic-v1"),
            (PDF_SHA, "0" * 63, "synthetic-v1"),
            (PDF_SHA, IR_SHA, ""),
            (PDF_SHA, IR_SHA, "embedded/path"),
        ):
            with self.subTest(bad_pdf=bad_pdf, bad_ir=bad_ir, bad_profile=bad_profile):
                with self.assertRaises(self.m.PageWindowError):
                    self.m.plan_pdf_page_windows(
                        pdf_sha256=bad_pdf, ir_sha256=bad_ir, page_count=33,
                        admitted_page_budget=300, pages_per_window=16,
                        inspector_profile_id=bad_profile,
                    )

    def test_valid_observations_bind_exact_plan_and_digest(self):
        """Bind all synthetic observations to the declared PDF and complete plan."""
        receipt = self.bind()
        record = receipt.to_dict()
        self.assertEqual(record["window_count"], 3)
        self.assertEqual(record["page_count"], 33)
        self.assertEqual(record["window_plan_sha256"], self.plan.plan_sha256)
        self.assertEqual(record["pdf_sha256"], PDF_SHA)
        self.assertEqual(len(record["observations"]), 3)
        self.assertEqual(record["coverage_scope"], "DECLARED_RANGES_COMPLETE_ONLY")

    def test_missing_duplicate_reordered_or_extra_window_rejected(self):
        """Reject every tested deviation from the exact ordered observation set."""
        obs = self.observations()
        for values in (obs[:-1], obs + (obs[-1],), obs[::-1], (obs[0], obs[0], obs[2])):
            with self.subTest(count=len(values)):
                with self.assertRaises(self.m.PageWindowError):
                    self.bind(observations=values)

    def test_foreign_pdf_or_plan_observation_rejected(self):
        """Reject altered range, ordinal, digest or inspector-profile bindings."""
        obs = self.observations()
        for change in (
            {"pdf_sha256": "c" * 64},
            {"plan_sha256": "d" * 64},
            {"inspector_profile_id": "different-v1"},
            {"first_page": 2},
            {"last_page": 31},
            {"index": 9},
        ):
            with self.subTest(change=change):
                altered = replace(obs[1], **change)
                with self.assertRaises(self.m.PageWindowError):
                    self.bind(observations=(obs[0], altered, obs[2]))

    def test_bad_observation_hash_or_type_rejected(self):
        """Require canonical observation digests and an immutable tuple container."""
        obs = self.observations()
        for value in ("not-digest", True, "D" * 64, None):
            with self.subTest(value=value):
                with self.assertRaises(self.m.PageWindowError):
                    replace(obs[0], observation_sha256=value)
        with self.assertRaises(self.m.PageWindowError):
            self.bind(observations=[*obs])

    def test_direct_constructor_cannot_bypass_completeness(self):
        """Apply the same completeness invariants to direct dataclass construction."""
        obs = self.observations()
        with self.assertRaises(self.m.PageWindowError):
            self.m.BoundPageWindowLedger(plan=self.plan, observations=obs[:-1])
        with self.assertRaises(self.m.PageWindowError):
            replace(self.plan, windows=self.plan.windows[:-1])

    def test_structures_are_frozen_and_detached(self):
        """Prevent ordinary mutation and isolate exported dictionaries from the ledger."""
        receipt = self.bind()
        with self.assertRaises(FrozenInstanceError):
            receipt.plan = None
        with self.assertRaises(FrozenInstanceError):
            self.plan.page_count = 1
        copy = receipt.to_dict()
        copy["observations"][0]["first_page"] = 999
        self.assertEqual(receipt.to_dict()["observations"][0]["first_page"], 1)

    def test_deterministic_repeat_has_same_digest(self):
        """Produce identical plan and observation identities for equivalent inputs."""
        other = self.m.plan_pdf_page_windows(
            pdf_sha256=PDF_SHA, ir_sha256=IR_SHA, page_count=33,
            admitted_page_budget=300, pages_per_window=16,
            inspector_profile_id="synthetic-window-raster-v1",
        )
        self.assertEqual(self.plan.plan_sha256, other.plan_sha256)
        self.assertEqual(self.bind().to_dict()["observations_sha256"],
                         self.bind(other).to_dict()["observations_sha256"])

    def test_receipt_does_not_claim_native_or_release_success(self):
        """Keep all runtime-verification and release-authority claims unestablished."""
        payload = self.bind().to_dict()
        for key in (
            "worker_results_authenticated", "whole_pdf_safety_qualified",
            "raster_pages_validated", "renderer_activated", "release_authorized",
        ):
            self.assertIs(payload[key], False)
        self.assertEqual(payload["release_authorization"], "NOT_ESTABLISHED")
        self.assertEqual(payload["status"], "STAGED_UNQUALIFIED")
        self.assertNotIn("PASS", json.dumps(payload))

    def test_no_pdf_bytes_or_runtime_io_required(self):
        """Bind fixture metadata without connecting to a network or supplying PDF bytes."""
        with patch.object(socket, "create_connection", side_effect=AssertionError("network")):
            payload = self.bind().to_dict()
        self.assertNotIn("pdf_bytes", json.dumps(payload))
        self.assertNotIn("file_path", json.dumps(payload))
        self.assertEqual(payload["pdf_sha256"], PDF_SHA)

    def test_receipt_is_closed_under_2020_12_schema(self):
        """Accept actual receipts while rejecting extra fields and false qualification."""
        schema_path = ROOT / "schemas" / "report-page-window-ledger.v1.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        record = self.bind().to_dict()
        self.assertEqual(list(validator.iter_errors(record)), [])
        for changed in (
            {**record, "unsafe_file": "/tmp/example"},
            {**record, "release_authorized": True},
            {**record, "status": "PASS"},
        ):
            self.assertTrue(list(validator.iter_errors(changed)))
        bad = json.loads(json.dumps(record))
        bad["observations"][0]["unknown"] = True
        self.assertTrue(list(validator.iter_errors(bad)))

    def test_maximum_declared_workload_is_finite(self):
        """Account for the maximum admitted metadata workload with 1,024 windows."""
        plan = self.m.plan_pdf_page_windows(
            pdf_sha256=PDF_SHA, ir_sha256=IR_SHA, page_count=32768,
            admitted_page_budget=32768, pages_per_window=32,
            inspector_profile_id="synthetic-window-raster-v1",
        )
        self.assertEqual(plan.window_count, 1024)
        self.assertEqual(plan.windows[-1].last_page, 32768)
        self.assertEqual(self.bind(plan).to_dict()["window_count"], 1024)


if __name__ == "__main__":
    unittest.main()
