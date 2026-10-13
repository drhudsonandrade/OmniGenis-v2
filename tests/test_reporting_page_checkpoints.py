"""Synthetic exact-identity resumption tests for partial window metadata."""
from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError, replace
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator
from reporting.page_windows import WindowObservation, plan_pdf_page_windows

ROOT = Path(__file__).resolve().parents[1]


def digest(value: bytes) -> str:
    """Hash only explicitly synthetic fixture bytes."""
    return hashlib.sha256(value).hexdigest()


def encode(value: object) -> bytes:
    """Use sorted compact UTF-8 for independently constructed test records."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


class PageCheckpointTests(unittest.TestCase):
    """Exercise metadata recovery without executing or qualifying PDF workers."""

    def setUp(self):
        """Require the new boundary and prepare an independent three-window plan."""
        self.assertIsNotNone(importlib.util.find_spec("reporting.page_checkpoints"),
                             "job-bound page checkpoint boundary is missing")
        self.m = importlib.import_module("reporting.page_checkpoints")
        self.plan = plan_pdf_page_windows(
            pdf_sha256=digest(b"synthetic pdf"), ir_sha256=digest(b"synthetic ir"),
            page_count=33, admitted_page_budget=300, pages_per_window=16,
            inspector_profile_id="synthetic-inspector-v1")
        self.context = dict(namespace_id="synthetic-namespace", job_id="synthetic-job",
                            request_sha256=digest(b"synthetic request"),
                            resource_profile_sha256=digest(b"synthetic resources"))

    def observations(self, plan=None):
        """Create distinct declared observations; these are not worker evidence."""
        plan = self.plan if plan is None else plan
        return tuple(WindowObservation(
            index=w.index, first_page=w.first_page, last_page=w.last_page,
            pdf_sha256=plan.pdf_sha256, plan_sha256=plan.plan_sha256,
            inspector_profile_id=plan.inspector_profile_id,
            observation_sha256=digest(f"synthetic window {w.index}".encode()))
            for w in plan.windows)

    def checkpoint(self, count=1, **changes):
        """Capture a declared prefix with exact job and resource metadata."""
        args = dict(plan=self.plan, observations=self.observations()[:count], **self.context)
        args.update(changes)
        return self.m.PageWindowCheckpoint(**args)

    def resume(self, payload=None, **changes):
        """Supply all independently expected identity and digest bindings."""
        payload = self.checkpoint().to_bytes() if payload is None else payload
        expected = changes.pop("expected_checkpoint_sha256", None)
        if expected is None:
            expected = digest(payload)
        args = dict(checkpoint_bytes=payload, expected_checkpoint_sha256=expected,
                    expected_plan=self.plan, namespace_id=self.context["namespace_id"],
                    job_id=self.context["job_id"],
                    expected_request_sha256=self.context["request_sha256"],
                    expected_resource_profile_sha256=self.context["resource_profile_sha256"])
        args.update(changes)
        return self.m.resume_page_checkpoint(**args)

    def test_partial_resume_preserves_bytes_and_remaining_windows(self):
        """An exact checkpoint returns only the unrecorded suffix as pending metadata."""
        original = self.checkpoint()
        resumed = self.resume(original.to_bytes())
        self.assertEqual(resumed.to_bytes(), original.to_bytes())
        self.assertEqual(resumed.checkpoint_sha256, digest(original.to_bytes()))
        self.assertEqual(resumed.remaining_windows, self.plan.windows[1:])
        self.assertEqual(resumed.to_dict()["recorded_window_count"], 1)

    def test_empty_checkpoint_keeps_every_window_pending(self):
        """Zero recorded observations is a valid initial state, not completeness."""
        c = self.checkpoint(0)
        self.assertEqual(self.resume(c.to_bytes()).remaining_windows, self.plan.windows)
        with self.assertRaises(self.m.PageCheckpointError):
            c.as_complete_ledger()

    def test_complete_checkpoint_reuses_existing_inert_ledger(self):
        """A complete prefix can feed the old ledger without claiming native PASS."""
        c = self.checkpoint(3)
        self.assertEqual(self.resume(c.to_bytes()).remaining_windows, ())
        ledger = c.as_complete_ledger().to_dict()
        self.assertEqual(ledger["status"], "STAGED_UNQUALIFIED")
        self.assertEqual(ledger["window_count"], 3)
        self.assertFalse(ledger["worker_results_authenticated"])

    def test_partial_checkpoint_cannot_be_a_complete_ledger(self):
        """A nonempty incomplete prefix remains blocked from full range accounting."""
        with self.assertRaises(self.m.PageCheckpointError):
            self.checkpoint(2).as_complete_ledger()

    def test_append_retains_old_snapshot_and_exact_prefix(self):
        """Extending progress creates a new immutable value, leaving prior bytes intact."""
        c = self.checkpoint()
        before = c.to_bytes()
        updated = c.append_observations(self.observations()[1:])
        self.assertEqual(c.to_bytes(), before)
        self.assertEqual(updated.remaining_windows, ())
        self.assertNotEqual(updated.checkpoint_sha256, c.checkpoint_sha256)
        self.assertEqual(updated.observations, self.observations())

    def test_empty_append_is_stable(self):
        """An empty update changes neither the declared progress nor its digest."""
        c = self.checkpoint()
        self.assertEqual(c.append_observations(()).to_bytes(), c.to_bytes())

    def test_replayed_gap_and_reordered_append_are_rejected(self):
        """Duplicates and noncontiguous progress cannot skip an unrecorded window."""
        c = self.checkpoint()
        obs = self.observations()
        for extra in ((obs[0],), (obs[2],), (obs[2], obs[1]), obs, list(obs[1:])):
            with self.subTest(extra_type=type(extra).__name__):
                with self.assertRaises(self.m.PageCheckpointError):
                    c.append_observations(extra)
        self.assertEqual(c.observations, obs[:1])

    def test_constructor_rejects_nonprefix_or_mutable_observations(self):
        """Direct construction enforces the same typed ordered-prefix constraint."""
        obs = self.observations()
        for values in ((obs[1],), (obs[0], obs[2]), obs[::-1], obs + (obs[2],), list(obs)):
            with self.subTest(kind=type(values).__name__):
                with self.assertRaises(self.m.PageCheckpointError):
                    self.checkpoint(observations=values)

    def test_foreign_observation_fields_are_rejected(self):
        """Every retained observation must bind the same plan, PDF, profile and range."""
        first = self.observations()[0]
        for change in ({"pdf_sha256": "a" * 64}, {"plan_sha256": "b" * 64},
                       {"inspector_profile_id": "different-v1"}, {"first_page": 2},
                       {"last_page": 15}, {"index": 1}):
            with self.subTest(change=change):
                with self.assertRaises(self.m.PageCheckpointError):
                    self.checkpoint(observations=(replace(first, **change),))

    def test_cross_namespace_job_request_and_resource_resume_rejected(self):
        """Identical page data cannot cross independent job or resource bindings."""
        for field, value in (("namespace_id", "other-namespace"), ("job_id", "other-job"),
                             ("expected_request_sha256", "c" * 64),
                             ("expected_resource_profile_sha256", "d" * 64)):
            with self.subTest(field=field):
                with self.assertRaises(self.m.PageCheckpointError):
                    self.resume(**{field: value})

    def test_changed_pdf_ir_budget_and_inspector_plan_rejected(self):
        """A recalculated but different plan does not resume an old checkpoint."""
        for change in ({"pdf_sha256": "c" * 64}, {"ir_sha256": "d" * 64},
                       {"admitted_page_budget": 301}, {"inspector_profile_id": "other-v1"}):
            with self.subTest(change=change):
                with self.assertRaises(self.m.PageCheckpointError):
                    self.resume(expected_plan=replace(self.plan, **change))
        other = plan_pdf_page_windows(
            pdf_sha256=self.plan.pdf_sha256, ir_sha256=self.plan.ir_sha256,
            page_count=33, admitted_page_budget=300, pages_per_window=8,
            inspector_profile_id=self.plan.inspector_profile_id)
        with self.assertRaises(self.m.PageCheckpointError):
            self.resume(expected_plan=other)

    def test_stale_checkpoint_digest_rejects_newer_progress(self):
        """An externally pinned digest cannot silently select another checkpoint."""
        old, new = self.checkpoint(), self.checkpoint(2)
        with self.assertRaises(self.m.PageCheckpointError):
            self.resume(new.to_bytes(), expected_checkpoint_sha256=old.checkpoint_sha256)

    def test_altered_serialized_job_metadata_rejected_even_with_new_hash(self):
        """Rehashing changed data does not override independent expected identity."""
        for key in ("namespace_id", "job_id", "request_sha256", "resource_profile_sha256",
                    "pdf_sha256", "ir_sha256", "window_plan_sha256", "inspector_profile_id"):
            record = self.checkpoint().to_dict()
            record[key] = "different" if not key.endswith("sha256") else "0" * 64
            with self.subTest(key=key):
                with self.assertRaises(self.m.PageCheckpointError):
                    self.resume(encode(record))

    def test_corrupted_record_counts_and_flags_cannot_claim_completion(self):
        """Counts, type lookalikes and status flags must match canonical output exactly."""
        for key, value in (("recorded_window_count", 3), ("window_count", True),
                           ("page_count", 33.0), ("status", "PASS"),
                           ("worker_results_authenticated", True),
                           ("native_resume_performed", True),
                           ("release_authorization", "FINAL")):
            record = self.checkpoint().to_dict()
            record[key] = value
            with self.subTest(key=key):
                with self.assertRaises(self.m.PageCheckpointError):
                    self.resume(encode(record))

    def test_unknown_root_and_observation_fields_are_rejected(self):
        """A valid digest cannot authorize protocol extensions or extra metadata."""
        root = self.checkpoint().to_dict()
        root["unknown"] = 1
        with self.assertRaises(self.m.PageCheckpointError):
            self.resume(encode(root))
        nested = self.checkpoint().to_dict()
        nested["observations"][0]["unknown"] = 1
        with self.assertRaises(self.m.PageCheckpointError):
            self.resume(encode(nested))

    def test_missing_required_fields_are_rejected(self):
        """No required checkpoint identity, evidence or scope field is guessed."""
        original = self.checkpoint().to_dict()
        for field in original:
            record = dict(original)
            del record[field]
            with self.subTest(field=field):
                with self.assertRaises(self.m.PageCheckpointError):
                    self.resume(encode(record))

    def test_duplicate_json_keys_rejected(self):
        """Duplicate names remain invalid even when their repeated values agree."""
        raw = self.checkpoint().to_bytes()
        for value in (raw.replace(b'{', b'{"status":"STAGED_UNQUALIFIED",', 1),
                      raw.replace(b'"index":0', b'"index":0,"index":0', 1)):
            with self.assertRaises(self.m.PageCheckpointError):
                self.resume(value)

    def test_noncanonical_whitespace_encoding_and_nonfinite_json_rejected(self):
        """Only canonical UTF-8 checkpoint bytes are admitted, without normalization."""
        raw = self.checkpoint().to_bytes()
        for value in (raw + b"\n", b"\xef\xbb\xbf" + raw, raw.decode().encode("utf-16"),
                      raw.replace(b'"recorded_window_count":1', b'"recorded_window_count":NaN'),
                      raw.replace(b'"recorded_window_count":1', b'"recorded_window_count":Infinity')):
            with self.subTest(length=len(value)):
                with self.assertRaises(self.m.PageCheckpointError):
                    self.resume(value)

    def test_malformed_deep_and_nonobject_json_fail_with_fixed_errors(self):
        """Parser exceptions never expose untrusted checkpoint contents."""
        for value in (b'{"PRIVATE_PAYLOAD":', b"[]", b"null", b"true", b"\xff",
                      b"[" * 2000 + b"0" + b"]" * 2000):
            with self.assertRaises(self.m.PageCheckpointError) as error:
                self.resume(value)
            self.assertNotIn("PRIVATE_PAYLOAD", str(error.exception))
            self.assertLess(len(str(error.exception)), 100)

    def test_byte_budget_precedes_hash_and_json_parsing(self):
        """Oversized raw input is rejected before either expensive conversion step."""
        raw = b"x" * (self.m.MAX_CHECKPOINT_BYTES + 1)
        expected = digest(raw)
        with patch.object(self.m.hashlib, "sha256", side_effect=AssertionError("hash")), \
                patch.object(self.m.json, "loads", side_effect=AssertionError("parse")):
            with self.assertRaises(self.m.PageCheckpointError):
                self.resume(raw, expected_checkpoint_sha256=expected)

    def test_mutable_and_subclass_byte_inputs_rejected(self):
        """Only exact immutable bytes can be an integrity-bound snapshot."""
        raw = self.checkpoint().to_bytes()
        subclass = type("ForeignBytes", (bytes,), {})
        for value in (bytearray(raw), memoryview(raw), subclass(raw), raw.decode()):
            with self.subTest(kind=type(value).__name__):
                with self.assertRaises(self.m.PageCheckpointError):
                    self.m.resume_page_checkpoint(
                        checkpoint_bytes=value, expected_checkpoint_sha256=digest(raw),
                        expected_plan=self.plan, namespace_id=self.context["namespace_id"],
                        job_id=self.context["job_id"],
                        expected_request_sha256=self.context["request_sha256"],
                        expected_resource_profile_sha256=self.context["resource_profile_sha256"])

    def test_job_identity_and_digest_types_are_strict(self):
        """No normalization, traversal-shaped identity or truth-like digest is admitted."""
        for field, value in (("namespace_id", "../other"), ("job_id", ""),
                             ("job_id", True), ("request_sha256", "A" * 64),
                             ("resource_profile_sha256", None)):
            with self.subTest(field=field):
                with self.assertRaises(self.m.PageCheckpointError):
                    self.checkpoint(**{field: value})

    def test_expected_plan_and_observation_classes_are_exact(self):
        """Mappings and subclasses cannot supply unreviewed validation behavior."""
        for value in (None, self.plan.to_dict()):
            with self.assertRaises(self.m.PageCheckpointError):
                self.checkpoint(plan=value)
            with self.assertRaises(self.m.PageCheckpointError):
                self.resume(expected_plan=value)
        with self.assertRaises(self.m.PageCheckpointError):
            self.checkpoint(observations=(self.observations()[0].to_dict(),))

    def test_snapshots_are_frozen_and_exports_detached(self):
        """Returned metadata cannot mutate a captured prefix or its identities."""
        c = self.checkpoint()
        before = c.to_bytes()
        with self.assertRaises(FrozenInstanceError):
            c.job_id = "other"
        exported = c.to_dict()
        exported["observations"].clear()
        self.assertEqual(c.to_bytes(), before)
        self.assertNotIn("synthetic-job", repr(c))

    def test_mutated_nested_plan_is_revalidated(self):
        """A retained exact-type plan cannot use a stale private digest after tampering."""
        c = self.checkpoint()
        object.__setattr__(self.plan, "ir_sha256", "f" * 64)
        with self.assertRaises(self.m.PageCheckpointError):
            c.to_bytes()
        with self.assertRaises(self.m.PageCheckpointError):
            c.remaining_windows

    def test_roundtrip_and_progress_for_large_declared_plans(self):
        """Declared 64, 129 and 300 page workloads preserve every planned window."""
        for count in (64, 129, 300):
            plan = plan_pdf_page_windows(
                pdf_sha256=self.plan.pdf_sha256, ir_sha256=self.plan.ir_sha256,
                page_count=count, admitted_page_budget=count, pages_per_window=16,
                inspector_profile_id=self.plan.inspector_profile_id)
            obs = self.observations(plan)
            c = self.checkpoint(plan=plan, observations=obs[:1])
            restored = self.resume(c.to_bytes(), expected_plan=plan)
            complete = restored.append_observations(obs[1:]).as_complete_ledger()
            self.assertEqual(complete.to_dict()["page_count"], count)

    def test_maximum_window_count_and_identifier_width_fit_byte_budget(self):
        """The accepted metadata envelope supports existing maximum-range plans."""
        plan = plan_pdf_page_windows(
            pdf_sha256=self.plan.pdf_sha256, ir_sha256=self.plan.ir_sha256,
            page_count=32768, admitted_page_budget=32768, pages_per_window=32,
            inspector_profile_id="s" * 256)
        c = self.checkpoint(plan=plan, observations=self.observations(plan))
        raw = c.to_bytes()
        self.assertLess(len(raw), self.m.MAX_CHECKPOINT_BYTES)
        restored = self.resume(raw, expected_plan=plan)
        self.assertEqual(len(restored.observations), 1024)
        self.assertEqual(restored.remaining_windows, ())

    def test_codec_performs_no_filesystem_network_or_process_work(self):
        """Snapshot recovery remains a pure metadata operation, not job execution."""
        raw = self.checkpoint().to_bytes()
        with patch("builtins.open", side_effect=AssertionError("file")), \
                patch("socket.create_connection", side_effect=AssertionError("network")), \
                patch("subprocess.run", side_effect=AssertionError("process")):
            c = self.resume(raw)
            c.append_observations(self.observations()[1:]).as_complete_ledger()

    def test_checkpoint_never_claims_storage_worker_or_release_authority(self):
        """Even complete metadata keeps all unimplemented guarantees explicitly false."""
        for count in (0, 1, 3):
            record = self.checkpoint(count).to_dict()
            for field in ("worker_results_authenticated", "checkpoint_storage_authenticated",
                          "native_resume_performed", "whole_pdf_safety_qualified"):
                self.assertIs(record[field], False)
            self.assertEqual(record["status"], "STAGED_UNQUALIFIED")
            self.assertEqual(record["release_authorization"], "NOT_ESTABLISHED")

    def test_existing_pdf_adapter_does_not_accept_checkpoint_as_report(self):
        """A checkpoint cannot turn into a PDF input or activate the legacy renderer."""
        from reporting.adapters import build_html_css_and_pdf_adapter
        result = build_html_css_and_pdf_adapter(presentation_ir=self.checkpoint().to_dict())
        self.assertFalse(result.passed)

    def test_additive_schema_is_closed_and_matches_every_prefix(self):
        """Canonical schema accepts real outputs and rejects extra or changed guarantees."""
        schema = json.loads((ROOT / "schemas/report-page-checkpoint.v1.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        for count in (0, 1, 3):
            self.assertEqual(list(validator.iter_errors(self.checkpoint(count).to_dict())), [])
        record = self.checkpoint().to_dict()
        for invalid in ({**record, "unknown": 1}, {**record, "native_resume_performed": True}):
            self.assertTrue(list(validator.iter_errors(invalid)))
        record["observations"][0]["unknown"] = 1
        self.assertTrue(list(validator.iter_errors(record)))

    def test_changed_functions_have_docstrings(self):
        """Every new function and test documents its role and guarantee boundary."""
        for name in ("reporting/page_checkpoints.py", "tests/test_reporting_page_checkpoints.py"):
            tree = ast.parse((ROOT / name).read_text())
            missing = [n.name for n in ast.walk(tree)
                       if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                       and ast.get_docstring(n) is None]
            self.assertEqual(missing, [], name)


if __name__ == "__main__":
    unittest.main()
