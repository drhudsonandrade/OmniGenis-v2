"""Synthetic metadata negatives and real native coverage for combined PDF receipts."""
from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError, replace
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import patch

from reporting.page_checkpoints import PageWindowCheckpoint, resume_page_checkpoint
from reporting.page_windows import plan_pdf_page_windows
from reporting.pdf_object_graph import PdfObjectGraphInspection, inspect_pdf_object_graph
from reporting.pdf_text_windows import PdfTextWindowInspection, inspect_pdf_text_window, PROFILE_ID as TEXT_PROFILE
from reporting.pdf_raster_windows import PdfRasterWindowInspection, inspect_pdf_raster_window, PROFILE_ID as RASTER_PROFILE

ROOT = Path(__file__).resolve().parents[1]


def digest(data: bytes) -> str:
    """Compute deterministic fixture metadata identity, not worker authentication."""
    return hashlib.sha256(data).hexdigest()


def checkpoint(plan, receipts) -> PageWindowCheckpoint:
    """Create one explicit synthetic job checkpoint from typed receipt projections."""
    return PageWindowCheckpoint(plan=plan, namespace_id="synthetic-namespace", job_id="synthetic-job",
        request_sha256="c" * 64, resource_profile_sha256="d" * 64,
        observations=tuple(item.to_observation() for item in receipts))


def packaged(text_plan, raster_plan, texts, rasters, graph) -> dict:
    """Supply three independently stored fixture hashes to the public binding boundary."""
    text_cp, raster_cp = checkpoint(text_plan, texts), checkpoint(raster_plan, rasters)
    return dict(text_checkpoint=text_cp, raster_checkpoint=raster_cp,
        text_inspections=texts, raster_inspections=rasters, object_inspection=graph,
        expected_text_checkpoint_sha256=text_cp.checkpoint_sha256,
        expected_raster_checkpoint_sha256=raster_cp.checkpoint_sha256,
        expected_object_inspection_sha256=graph.inspection_sha256)


def synthetic_inputs(pages=33, text_width=16, raster_width=4) -> dict:
    """Fabricate unsigned typed metadata for negative tests; no native process runs here."""
    plans = [plan_pdf_page_windows(pdf_sha256="a" * 64, ir_sha256="b" * 64,
        page_count=pages, admitted_page_budget=pages, pages_per_window=width,
        inspector_profile_id=profile) for width, profile in
        ((text_width, TEXT_PROFILE), (raster_width, RASTER_PROFILE))]
    streams = []
    for plan, kind in zip(plans, ("text", "raster"), strict=True):
        items = []
        for span in plan.windows:
            identity = dict(pdf_sha256=plan.pdf_sha256, ir_sha256=plan.ir_sha256,
                plan_sha256=plan.plan_sha256, page_count=pages, window_index=span.index,
                first_page=span.first_page, last_page=span.last_page)
            count = span.last_page - span.first_page + 1
            hashed = digest(f"synthetic:{kind}:{span.index}".encode())
            if kind == "text":
                item = PdfTextWindowInspection(**identity, text_sha256=hashed,
                    text_bytes=16 * count, text_chars=8 * count, decoded_bytes=32 * count)
            else:
                item = PdfRasterWindowInspection(**identity, raster_sha256=hashed,
                    total_pixels=100 * count, min_edge_margin_px=2)
            items.append(item)
        streams.append(tuple(items))
    graph = PdfObjectGraphInspection(pdf_sha256=plans[0].pdf_sha256, ir_sha256=plans[0].ir_sha256,
        plan_sha256=plans[0].plan_sha256, page_count=pages, object_count=4 * pages)
    return packaged(*plans, *streams, graph)


def native_inputs(pages=33) -> dict:
    """Run the existing guarded inspectors over every page of one synthetic final PDF."""
    from tests.test_reporting_pdf_text_windows import fixture_pdf
    pdf = fixture_pdf(pages)
    plans = [plan_pdf_page_windows(pdf_sha256=digest(pdf), ir_sha256="b" * 64,
        page_count=pages, admitted_page_budget=pages, pages_per_window=width,
        inspector_profile_id=profile) for width, profile in ((16, TEXT_PROFILE), (4, RASTER_PROFILE))]
    texts = tuple(inspect_pdf_text_window(pdf_bytes=pdf, plan=plans[0], window_index=i,
        expected_plan_sha256=plans[0].plan_sha256) for i in range(plans[0].window_count))
    rasters = tuple(inspect_pdf_raster_window(pdf_bytes=pdf, plan=plans[1], window_index=i,
        expected_plan_sha256=plans[1].plan_sha256) for i in range(plans[1].window_count))
    graph = inspect_pdf_object_graph(pdf_bytes=pdf, plan=plans[0], expected_plan_sha256=plans[0].plan_sha256)
    return packaged(*plans, texts, rasters, graph)


class PdfInspectionBundleTests(unittest.TestCase):
    """Require complete exact native-receipt metadata without creating release authority."""

    def setUp(self):
        """Every test requires the missing implementation before its own boundary assertions."""
        self.assertIsNotNone(importlib.util.find_spec("reporting.pdf_inspection_bundle"),
                             "combined PDF inspection binder is missing")
        self.m = importlib.import_module("reporting.pdf_inspection_bundle")
        self.args = synthetic_inputs()

    def bind(self, **changes):
        """Call the public keyword-only boundary with independently alterable inputs."""
        return self.m.bind_pdf_inspection_bundle(**{**self.args, **changes})

    def repin(self, role, value):
        """Explicitly repin changed synthetic checkpoint data to exercise cross-stream checks."""
        return {role + "_checkpoint": value,
                "expected_" + role + "_checkpoint_sha256": value.checkpoint_sha256}

    def test_complete_independent_window_sizes(self):
        """Three text windows and nine raster windows represent all thirty-three pages."""
        data = self.bind().to_dict()
        self.assertEqual(data["status"], "COMPLETE_INSPECTION_METADATA_BOUND")
        self.assertEqual(data["page_count"], 33)
        for role, windows in (("text", 3), ("raster", 9)):
            stream = data[role + "_stream"]
            self.assertEqual((stream["window_count"], stream["represented_pages"]), (windows, 33))
            self.assertEqual([p for x in stream["receipts"] for p in
                range(x["first_page"], x["last_page"] + 1)], list(range(1, 34)))

    def test_real_native_complete_document_and_restored_checkpoints(self):
        """Actual text, raster and effective-graph results bind after exact checkpoint transport."""
        values = native_inputs()
        for role in ("text", "raster"):
            cp = values[role + "_checkpoint"]
            restored = resume_page_checkpoint(checkpoint_bytes=cp.to_bytes(),
                expected_checkpoint_sha256=cp.checkpoint_sha256, expected_plan=cp.plan,
                namespace_id=cp.namespace_id, job_id=cp.job_id,
                expected_request_sha256=cp.request_sha256,
                expected_resource_profile_sha256=cp.resource_profile_sha256)
            values[role + "_checkpoint"] = restored
        result = self.m.bind_pdf_inspection_bundle(**values)
        data = result.to_dict()
        self.assertEqual(data["page_count"], 33)
        self.assertEqual(data["text_stream"]["window_count"], 3)
        self.assertEqual(data["raster_stream"]["window_count"], 9)
        self.assertEqual(data["object_graph_sha256"], values["object_inspection"].inspection_sha256)
        self.assertFalse(data["release_authorized"])

    def test_single_page_and_exact_window_boundary(self):
        """One-page and exact-width metadata do not create an empty trailing range."""
        for count in (1, 4, 16, 32, 64, 129, 300):
            with self.subTest(count=count):
                data = self.m.bind_pdf_inspection_bundle(**synthetic_inputs(count)).to_dict()
                self.assertEqual(data["page_count"], count)
                self.assertEqual(data["raster_stream"]["receipts"][-1]["last_page"], count)

    def test_complete_checkpoint_required_for_both_streams(self):
        """A valid partial checkpoint cannot be promoted into a complete combined inventory."""
        for role in ("text", "raster"):
            cp = self.args[role + "_checkpoint"]
            partial = replace(cp, observations=cp.observations[:-1])
            with self.assertRaises(self.m.PdfInspectionBundleError):
                self.bind(**self.repin(role, partial), **{role + "_inspections": self.args[role + "_inspections"][:-1]})

    def test_empty_receipts_are_not_coverage(self):
        """No generic empty-success record satisfies either required inspection family."""
        for role in ("text", "raster"):
            with self.assertRaises(self.m.PdfInspectionBundleError): self.bind(**{role + "_inspections": ()})

    def test_missing_or_extra_receipts_rejected(self):
        """The receipt count must match the entire pinned checkpoint, not a subset or superset."""
        for role in ("text", "raster"):
            values = self.args[role + "_inspections"]
            for changed in (values[:-1], values + (values[-1],)):
                with self.assertRaises(self.m.PdfInspectionBundleError): self.bind(**{role + "_inspections": changed})

    def test_reordered_and_duplicate_receipts_rejected(self):
        """The binder rejects order changes rather than sorting or filling a missing range."""
        for role in ("text", "raster"):
            values = self.args[role + "_inspections"]
            for changed in (values[::-1], (values[0],) + values[:-1]):
                with self.assertRaises(self.m.PdfInspectionBundleError): self.bind(**{role + "_inspections": changed})

    def test_native_tuple_types_are_required(self):
        """Lists and generators cannot execute or change during metadata binding."""
        for role in ("text", "raster"):
            values = self.args[role + "_inspections"]
            for changed in (list(values), iter(values), None, {"status": "PASS"}):
                with self.assertRaises(self.m.PdfInspectionBundleError): self.bind(**{role + "_inspections": changed})

    def test_receipt_types_cannot_be_crossed(self):
        """Raster, text, graph and generic observations are not interchangeable evidence."""
        for role, other in (("text", "raster"), ("raster", "text")):
            own = self.args[role + "_inspections"]
            for wrong in (self.args[other + "_inspections"][0], self.args["object_inspection"],
                          own[0].to_observation(), own[0].to_dict()):
                with self.assertRaises(self.m.PdfInspectionBundleError):
                    self.bind(**{role + "_inspections": (wrong,) + own[1:]})

    def test_checkpoint_types_cannot_be_replaced_by_dictionaries(self):
        """Only a revalidated existing checkpoint class can contribute a pinned plan."""
        for role in ("text", "raster"):
            for value in (None, self.args[role + "_checkpoint"].to_dict()):
                with self.assertRaises(self.m.PdfInspectionBundleError): self.bind(**{role + "_checkpoint": value})

    def test_all_independent_expected_hashes_are_required(self):
        """Wrong, uppercase, non-string and missing pins never self-authorize the supplied data."""
        for key in ("expected_text_checkpoint_sha256", "expected_raster_checkpoint_sha256", "expected_object_inspection_sha256"):
            for value in ("f" * 64, "A" * 64, "", None, True):
                with self.subTest(key=key, value=value), self.assertRaises(self.m.PdfInspectionBundleError):
                    self.bind(**{key: value})

    def test_namespace_job_request_and_resource_must_match(self):
        """Even freshly repinned checkpoints must describe the same exact job context."""
        cp = self.args["raster_checkpoint"]
        for key, value in (("namespace_id", "other-namespace"), ("job_id", "other-job"),
                           ("request_sha256", "e" * 64), ("resource_profile_sha256", "e" * 64)):
            with self.subTest(key=key), self.assertRaises(self.m.PdfInspectionBundleError):
                self.bind(**self.repin("raster", replace(cp, **{key: value})))

    def test_plan_profiles_are_role_specific(self):
        """The two independent profiles cannot be swapped even for identical page ranges."""
        with self.assertRaises(self.m.PdfInspectionBundleError):
            self.bind(**self.repin("text", self.args["raster_checkpoint"]))

    def test_foreign_pdf_and_ir_receipt_identities_rejected(self):
        """Generic observation digests do not replace per-receipt PDF and IR checks."""
        for role in ("text", "raster"):
            values = self.args[role + "_inspections"]
            for key in ("pdf_sha256", "ir_sha256"):
                changed = (replace(values[0], **{key: "e" * 64}),) + values[1:]
                with self.assertRaises(self.m.PdfInspectionBundleError): self.bind(**{role + "_inspections": changed})

    def test_wrong_physical_count_cannot_hide_in_generic_observation(self):
        """A repinned observation still requires the native receipt's actual declared count."""
        values = self.args["text_inspections"]
        altered = (replace(values[0], page_count=34),) + values[1:]
        cp = checkpoint(self.args["text_checkpoint"].plan, altered)
        with self.assertRaises(self.m.PdfInspectionBundleError):
            self.bind(text_inspections=altered, **self.repin("text", cp))

    def test_wrong_ir_cannot_hide_in_recomputed_observation_hash(self):
        """The receipt IR must match the plan even after its observation digest is repinned."""
        values = self.args["raster_inspections"]
        altered = (replace(values[0], ir_sha256="e" * 64),) + values[1:]
        cp = checkpoint(self.args["raster_checkpoint"].plan, altered)
        with self.assertRaises(self.m.PdfInspectionBundleError):
            self.bind(raster_inspections=altered, **self.repin("raster", cp))

    def test_changed_receipt_payload_rejected_by_checkpoint_digest(self):
        """Changing valid native count/hash metadata cannot retain its old observation pin."""
        values = self.args["text_inspections"]
        changed = (replace(values[0], text_sha256="e" * 64),) + values[1:]
        with self.assertRaises(self.m.PdfInspectionBundleError): self.bind(text_inspections=changed)

    def test_graph_requires_exact_text_plan_and_document(self):
        """A graph result is separate evidence pinned specifically to the authoritative text plan."""
        graph = self.args["object_inspection"]
        for changes in ({"plan_sha256": self.args["raster_checkpoint"].plan.plan_sha256},
                        {"pdf_sha256": "e" * 64}, {"ir_sha256": "e" * 64}, {"page_count": 34}):
            altered = replace(graph, **changes)
            with self.assertRaises(self.m.PdfInspectionBundleError):
                self.bind(object_inspection=altered, expected_object_inspection_sha256=altered.inspection_sha256)

    def test_graph_is_mandatory_and_not_a_generic_pass(self):
        """No absent, dictionary or window-shaped result can replace the graph inspection."""
        for value in (None, {"status": "PASS"}, self.args["text_inspections"][0]):
            with self.assertRaises(self.m.PdfInspectionBundleError): self.bind(object_inspection=value)

    def test_plan_mutation_is_detected_before_serialization(self):
        """An illicit change to a frozen plan cannot preserve its checkpoint identity."""
        object.__setattr__(self.args["text_checkpoint"].plan, "page_count", 34)
        with self.assertRaises(self.m.PdfInspectionBundleError): self.bind()

    def test_nested_receipt_mutation_after_binding_is_detected(self):
        """Serialization revalidates retained objects instead of returning stale successful metadata."""
        bundle = self.bind()
        object.__setattr__(self.args["text_inspections"][0], "text_sha256", "e" * 64)
        for getter in (bundle.to_bytes, bundle.to_dict, lambda: bundle.bundle_sha256):
            with self.assertRaises(self.m.PdfInspectionBundleError): getter()

    def test_latched_digest_rejects_repinned_in_place_changes(self):
        """A previously bound instance cannot be silently repurposed into another valid record."""
        bundle = self.bind()
        graph = replace(self.args["object_inspection"], object_count=133)
        object.__setattr__(bundle, "object_inspection", graph)
        object.__setattr__(bundle, "expected_object_inspection_sha256", graph.inspection_sha256)
        with self.assertRaises(self.m.PdfInspectionBundleError): bundle.to_bytes()

    def test_frozen_and_detached_output(self):
        """Returned dictionaries do not alias either the bundle or its typed receipts."""
        bundle = self.bind()
        with self.assertRaises(FrozenInstanceError): bundle.text_checkpoint = None
        output = bundle.to_dict(); output["text_stream"]["receipts"][0]["first_page"] = 999
        self.assertEqual(bundle.to_dict()["text_stream"]["receipts"][0]["first_page"], 1)
        self.assertNotIn("synthetic-job", repr(bundle))

    def test_deterministic_bytes_and_digest(self):
        """Canonical serialization is repeatable and the digest hashes exactly those bytes."""
        first, second = self.bind(), self.bind()
        self.assertEqual(first.to_bytes(), second.to_bytes())
        self.assertEqual(first.bundle_sha256, digest(first.to_bytes()))
        self.assertEqual(json.loads(first.to_bytes()), first.to_dict())

    def test_output_limit_rejects_instead_of_truncating(self):
        """A metadata resource failure does not produce partial bytes or a smaller inventory."""
        with patch.object(self.m, "MAX_BUNDLE_BYTES", 16):
            with self.assertRaises(self.m.PdfInspectionBundleError): self.bind()

    def test_maximum_metadata_cardinality_is_finite(self):
        """Synthetic one-page receipt inventories remain complete at the admitted metadata ceiling."""
        data = self.m.bind_pdf_inspection_bundle(**synthetic_inputs(512, 1, 1))
        self.assertLessEqual(len(data.to_bytes()), 256 * 1024)
        self.assertEqual(data.to_dict()["text_stream"]["window_count"], 512)
        self.assertEqual(data.to_dict()["raster_stream"]["window_count"], 512)

    def test_no_execution_io_or_network_in_the_binder(self):
        """This boundary only binds supplied metadata and cannot launch or persist a job."""
        with patch.object(subprocess, "Popen", side_effect=AssertionError("execution")), \
             patch.object(os, "open", side_effect=AssertionError("filesystem")), \
             patch.object(socket, "socket", side_effect=AssertionError("network")):
            self.assertEqual(self.bind().to_dict()["page_count"], 33)

    def test_no_authentication_science_or_release_claims(self):
        """Complete metadata must not imply execution proof, full document quality or delivery."""
        data = self.bind().to_dict()
        for key in ("native_execution_performed", "worker_results_authenticated",
                    "whole_pdf_safety_qualified", "finding_completeness_verified",
                    "text_equivalence_verified", "accessibility_qualified",
                    "aggregate_job_resources_qualified", "release_authorized"):
            self.assertIs(data[key], False)
        self.assertEqual(data["release_authorization"], "NOT_ESTABLISHED")
        self.assertNotIn("PASS", json.dumps(data))

    def test_direct_constructor_does_not_bypass_validation(self):
        """Public dataclass construction enforces the same incomplete-input rejection."""
        with self.assertRaises(self.m.PdfInspectionBundleError):
            self.m.PdfInspectionBundle(**{**self.args, "text_inspections": ()})

    def test_over_limit_document_rejected_before_checkpoint_walk(self):
        """A larger declared plan cannot extend the native metadata admission ceiling."""
        old = self.args["text_checkpoint"]
        plan = plan_pdf_page_windows(pdf_sha256="a" * 64, ir_sha256="b" * 64,
            page_count=513, admitted_page_budget=513, pages_per_window=16,
            inspector_profile_id=TEXT_PROFILE)
        cp = replace(old, plan=plan, observations=())
        changes = self.repin("text", cp)
        with patch.object(PageWindowCheckpoint, "__post_init__", side_effect=AssertionError("walk")) as walk:
            with self.assertRaises(self.m.PdfInspectionBundleError): self.bind(**changes)
        walk.assert_not_called()

    def test_per_stream_width_not_expanded(self):
        """The binder cannot accept widths exceeding either existing native profile."""
        for role, width in (("text", 32), ("raster", 8)):
            cp = self.args[role + "_checkpoint"]
            plan = plan_pdf_page_windows(pdf_sha256="a" * 64, ir_sha256="b" * 64,
                page_count=33, admitted_page_budget=33, pages_per_window=width,
                inspector_profile_id=cp.plan.inspector_profile_id)
            bad = replace(cp, plan=plan, observations=())
            changes = self.repin(role, bad)
            with patch.object(self.m, "_stream_record", side_effect=AssertionError("serialize")) as serialize:
                with self.assertRaises(self.m.PdfInspectionBundleError): self.bind(**changes)
            serialize.assert_not_called()

    def test_coherent_foreign_raster_document_is_rejected(self):
        """Individually valid receipts and checkpoint pins still cannot join a different PDF or IR."""
        for key in ("pdf_sha256", "ir_sha256"):
            cp = self.args["raster_checkpoint"]
            plan = replace(cp.plan, **{key: "e" * 64})
            receipts = tuple(replace(r, plan_sha256=plan.plan_sha256, **{key: "e" * 64})
                             for r in self.args["raster_inspections"])
            new_cp = checkpoint(plan, receipts)
            with self.assertRaises(self.m.PdfInspectionBundleError):
                self.bind(raster_inspections=receipts, **self.repin("raster", new_cp))

    def test_receipt_count_bound_precedes_individual_validation(self):
        """Overlarge tuples fail before evaluating their repeated native receipt objects."""
        values = (self.args["text_inspections"][0],) * 513
        with patch.object(PdfTextWindowInspection, "__post_init__", side_effect=AssertionError("receipt")) as verify:
            with self.assertRaises(self.m.PdfInspectionBundleError): self.bind(text_inspections=values)
        verify.assert_not_called()

    def test_receipt_subclasses_cannot_override_binding(self):
        """Only exact native receipt classes are admitted, not caller-defined replacements."""
        class Replacement(PdfTextWindowInspection):
            """Synthetic subclass used only to verify exact-type rejection."""
        original = self.args["text_inspections"][0]
        fields = {key: getattr(original, key) for key in original.__dataclass_fields__}
        wrong = Replacement(**fields)
        with self.assertRaises(self.m.PdfInspectionBundleError):
            self.bind(text_inspections=(wrong,) + self.args["text_inspections"][1:])

    def test_fixed_errors_do_not_echo_untrusted_context(self):
        """Malformed nested context is never included in exception text or a partial bundle."""
        object.__setattr__(self.args["text_checkpoint"], "job_id", "PRIVATE-SENTINEL\ninvalid")
        with self.assertRaises(self.m.PdfInspectionBundleError) as caught: self.bind()
        self.assertEqual(str(caught.exception), "pdf_inspection_bundle_invalid")
        self.assertNotIn("PRIVATE-SENTINEL", str(caught.exception))

    def test_all_new_functions_have_docstrings(self):
        """Every new Python function explains its boundary before external review."""
        for path in (ROOT / "reporting/pdf_inspection_bundle.py", Path(__file__)):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.assertTrue(ast.get_docstring(node), f"{path.name}:{node.name}")


if __name__ == "__main__":
    unittest.main()
