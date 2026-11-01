"""Synthetic native and adversarial tests for the opt-in effective-object graph."""
from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError, replace
import hashlib
import importlib
import importlib.util
from io import BytesIO
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tests.test_reporting_pdf_text_windows import fixture_pdf, digest

ROOT = Path(__file__).resolve().parents[1]
ENGINE = "generated-pdf-effective-object-graph-v1"
STATUS = "PASSIVE_EFFECTIVE_GRAPH_INSPECTED"


def changed_pdf(change, count=33):
    """Apply one synthetic structural change without introducing external assets."""
    from pypdf import PdfWriter
    writer = PdfWriter(clone_from=BytesIO(fixture_pdf(count)))
    writer.pdf_header = "%PDF-1.7"
    change(writer)
    out = BytesIO()
    writer.write(out)
    return out.getvalue()


class PdfObjectGraphTests(unittest.TestCase):
    """Require real isolated execution and exact rejection at every metadata boundary."""

    def setUp(self):
        """Fail for the missing implementation before preparing a native fixture."""
        self.assertIsNotNone(importlib.util.find_spec("reporting.pdf_object_graph"),
                             "bounded effective-object graph inspection is missing")
        self.m = importlib.import_module("reporting.pdf_object_graph")
        self.w = importlib.import_module("reporting._pdf_object_graph_worker")
        self.p = importlib.import_module("reporting.page_windows")
        self.pdf = fixture_pdf(33)
        self.plan = self.make_plan(self.pdf, 33)

    def make_plan(self, pdf, count):
        """Retain the independent text-window plan rather than replacing its inspector."""
        return self.p.plan_pdf_page_windows(
            pdf_sha256=digest(pdf), ir_sha256="b" * 64, page_count=count,
            admitted_page_budget=count, pages_per_window=16,
            inspector_profile_id="generated-pdf-text-window-v1")

    def inspect(self, **changes):
        """Invoke the public adapter with independently sealed plan expectations."""
        args = dict(pdf_bytes=self.pdf, plan=self.plan,
                    expected_plan_sha256=self.plan.plan_sha256)
        args.update(changes)
        return self.m.inspect_pdf_object_graph(**args)

    def identity(self):
        """Construct the expected closed global-document identity independently."""
        return dict(pdf_sha256=digest(self.pdf), ir_sha256="b" * 64,
                    plan_sha256=self.plan.plan_sha256, page_count=33)

    def response(self):
        """Build synthetic protocol metadata, never actual worker verification evidence."""
        return {"protocol_version": 1, "profile_id": ENGINE,
                "policy_id": "passive-report-pdf-v1", "parser_version": "6.19.0",
                "identity": self.identity(),
                "limits": {"memory_bytes": 268435456, "cpu_seconds": 5,
                           "file_bytes": 4096, "open_files": 128},
                "inspection": {"status": STATUS, "object_count": 1000}}

    def decode(self, record):
        """Feed a synthetic response to the actual closed protocol decoder."""
        return self.m._decode(json.dumps(record).encode("ascii"), self.identity())

    def assert_native_rejected(self, pdf, count=33):
        """Require failure without any receipt for a structurally changed real PDF."""
        plan = self.make_plan(pdf, count)
        with self.assertRaises(self.m.PdfObjectGraphError):
            self.inspect(pdf_bytes=pdf, plan=plan, expected_plan_sha256=plan.plan_sha256)

    def test_native_long_documents_cover_the_complete_effective_graph(self):
        """Real 33/64/129/300/512-page documents use one complete graph traversal each."""
        for count in (33, 64, 129, 300, 512):
            with self.subTest(pages=count):
                raw = fixture_pdf(count)
                plan = self.make_plan(raw, count)
                r = self.inspect(pdf_bytes=raw, plan=plan, expected_plan_sha256=plan.plan_sha256)
                self.assertEqual((r.page_count, r.pdf_sha256), (count, digest(raw)))
                self.assertGreaterEqual(r.object_count, count)
                self.assertLessEqual(r.object_count, 20000)

    def test_late_page_actions_are_rejected(self):
        """A forbidden action on the final page cannot hide beyond the legacy page limit."""
        from pypdf.generic import NameObject, DictionaryObject
        for count in (33, 129, 512):
            pdf = changed_pdf(lambda w: w.pages[-1].__setitem__(NameObject("/AA"), DictionaryObject()), count)
            self.assert_native_rejected(pdf, count)

    def test_root_open_action_and_uri_action_are_rejected(self):
        """Document-level actions remain forbidden without evaluating any action payload."""
        from pypdf.generic import NameObject, DictionaryObject, TextStringObject
        for kind in ("/URI", "/JavaScript", "/Launch", "/GoToR"):
            action = DictionaryObject({NameObject("/S"): NameObject(kind),
                                       NameObject("/URI"): TextStringObject("https://example.invalid")})
            self.assert_native_rejected(changed_pdf(lambda w: w._root_object.__setitem__(NameObject("/OpenAction"), action)))

    def test_document_name_tree_and_outline_actions_are_rejected(self):
        """Non-page references use the same complete trailer-reachable traversal."""
        from pypdf.generic import NameObject, DictionaryObject
        for key in ("/Names", "/Outlines", "/StructTreeRoot"):
            branch = DictionaryObject({NameObject("/A"): DictionaryObject()})
            self.assert_native_rejected(changed_pdf(lambda w: w._root_object.__setitem__(NameObject(key), w._add_object(branch))))

    def test_attachments_forms_and_media_are_rejected(self):
        """Existing attachment, form and media exclusions are reused without weakening."""
        from pypdf.generic import NameObject, DictionaryObject
        for key in ("/EmbeddedFiles", "/AcroForm", "/RichMediaContent"):
            self.assert_native_rejected(changed_pdf(lambda w: w._root_object.__setitem__(NameObject(key), DictionaryObject())))

    def test_external_stream_reference_is_rejected(self):
        """External stream filenames are detected as objects, never opened by the adapter."""
        from pypdf.generic import NameObject, DecodedStreamObject, TextStringObject
        stream = DecodedStreamObject()
        stream.set_data(b"synthetic")
        stream[NameObject("/F")] = TextStringObject("untrusted-synthetic-name")
        self.assert_native_rejected(changed_pdf(lambda w: w.pages[-1].__setitem__(NameObject("/Contents"), w._add_object(stream))))

    def test_escaped_action_name_is_decoded_before_policy(self):
        """A syntactically escaped JavaScript discriminator cannot bypass object inspection."""
        from pypdf.generic import NameObject, DictionaryObject
        raw = changed_pdf(lambda w: w._root_object.__setitem__(NameObject("/XYZQ"), DictionaryObject()))
        self.assertIn(b"/XYZQ", raw)
        escaped = raw.replace(b"/XYZQ", b"/J#53")
        from pypdf import PdfReader
        self.assertIn("/JS", PdfReader(BytesIO(escaped), strict=True).root_object)
        self.assert_native_rejected(escaped)

    def test_harmless_action_like_strings_remain_data(self):
        """Words inside scalar text or opaque stream bytes are not executed dictionary keys."""
        from pypdf.generic import NameObject, TextStringObject
        raw = changed_pdf(lambda w: w._root_object.__setitem__(NameObject("/Synthetic"), TextStringObject("/JS /Launch /EmbeddedFiles")))
        plan = self.make_plan(raw, 33)
        self.assertEqual(self.inspect(pdf_bytes=raw, plan=plan, expected_plan_sha256=plan.plan_sha256).page_count, 33)

    def test_graph_budget_overflow_is_not_partial_success(self):
        """The existing 20,000-visit/pending budget is not widened for long documents."""
        from pypdf.generic import NameObject, ArrayObject, NumberObject
        raw = changed_pdf(lambda w: w._root_object.__setitem__(NameObject("/Synthetic"), ArrayObject([NumberObject(1)] * 20001)))
        self.assert_native_rejected(raw)

    def test_depth_overflow_and_bad_discriminator_fail_closed(self):
        """Deep reachable structures and non-name action discriminators are rejected."""
        from pypdf.generic import NameObject, ArrayObject, NumberObject
        nested = NumberObject(1)
        for _ in range(70):
            nested = ArrayObject([nested])
        self.assert_native_rejected(changed_pdf(lambda w: w._root_object.__setitem__(NameObject("/Synthetic"), nested)))
        self.assert_native_rejected(changed_pdf(lambda w: w._root_object.__setitem__(NameObject("/S"), NumberObject(1))))

    def test_unreferenced_objects_are_explicitly_outside_scope(self):
        """Unused objects do not change the effective graph; receipts do not claim raw-byte scans."""
        from pypdf.generic import NameObject, DictionaryObject
        raw = changed_pdf(lambda w: w._add_object(DictionaryObject({NameObject("/JS"): DictionaryObject()})))
        plan = self.make_plan(raw, 33)
        r = self.inspect(pdf_bytes=raw, plan=plan, expected_plan_sha256=plan.plan_sha256).to_dict()
        self.assertEqual(r["inspection_scope"], "EFFECTIVE_TRAILER_REACHABLE_OBJECTS_ONLY")
        self.assertIs(r["all_file_revisions_inspected"], False)
        self.assertIs(r["opaque_stream_payloads_inspected"], False)

    def test_effective_graph_cycles_are_bounded(self):
        """Revisiting an already seen effective object does not recurse indefinitely."""
        from pypdf.generic import NameObject, DictionaryObject
        def cycle(w):
            """Attach an inert self-referencing dictionary as synthetic graph data."""
            obj = DictionaryObject()
            ref = w._add_object(obj)
            obj[NameObject("/SyntheticSelf")] = ref
            w._root_object[NameObject("/Synthetic")] = ref
        raw = changed_pdf(cycle)
        plan = self.make_plan(raw, 33)
        self.assertGreater(self.inspect(pdf_bytes=raw, plan=plan, expected_plan_sha256=plan.plan_sha256).object_count, 33)

    def test_encrypted_and_malformed_pdf_fail_native(self):
        """Expected digests do not authorize encrypted or malformed PDF input."""
        self.assert_native_rejected(fixture_pdf(33, encrypted=True))
        self.assert_native_rejected(b"%PDF-1.7\nsynthetic malformed data")

    def test_physical_page_count_must_match_plan(self):
        """The parser's actual page count is bound to the independently supplied plan."""
        plan = self.make_plan(self.pdf, 32)
        with self.assertRaises(self.m.PdfObjectGraphError):
            self.inspect(plan=plan, expected_plan_sha256=plan.plan_sha256)


    def test_input_budget_and_native_type_prevent_launch(self):
        """Mutable bytes and data above sixteen MiB cannot create a worker request."""
        overflow = b"%PDF-1.7" + b"x" * 16777209
        plan = self.make_plan(overflow, 33)
        with patch.object(self.m, "_run_worker") as worker:
            for raw in (None, bytearray(self.pdf), memoryview(self.pdf), b"not pdf"):
                with self.assertRaises(self.m.PdfObjectGraphError):
                    self.inspect(pdf_bytes=raw)
            with self.assertRaises(self.m.PdfObjectGraphError):
                self.inspect(pdf_bytes=overflow, plan=plan, expected_plan_sha256=plan.plan_sha256)
            worker.assert_not_called()

    def test_foreign_pdf_plan_and_digest_prevent_launch(self):
        """Foreign, mutable or stale plan identities cannot start the native inspector."""
        with patch.object(self.m, "_run_worker", side_effect=AssertionError("unexpected launch")):
            for changes in ({"pdf_bytes": self.pdf + b"\n"}, {"plan": None}, {"expected_plan_sha256": "c" * 64}, {"expected_plan_sha256": True}):
                with self.assertRaises(self.m.PdfObjectGraphError):
                    self.inspect(**changes)
            plan = self.make_plan(self.pdf, 513)
            with self.assertRaises(self.m.PdfObjectGraphError):
                self.inspect(plan=plan, expected_plan_sha256=plan.plan_sha256)

    def test_mutated_plan_is_revalidated(self):
        """A changed frozen plan cannot retain its earlier digest across preflight."""
        object.__setattr__(self.plan, "ir_sha256", "c" * 64)
        with self.assertRaises(self.m.PdfObjectGraphError):
            self.inspect()

    def test_disable_and_unsupported_platform_fail_before_io(self):
        """An explicit disable switch or unsupported platform never falls back."""
        with patch.dict(os.environ, {"OMNIGENIS_PDF_OBJECT_GRAPH_DISABLED": "1"}):
            with self.assertRaises(self.m.PdfObjectGraphError):
                self.inspect()
        with patch.object(self.m.sys, "platform", "unsupported"):
            with self.assertRaises(self.m.PdfObjectGraphError):
                self.inspect()

    def test_protocol_exact_shape_and_foreign_identity_rejected(self):
        """Unknown or absent fields and foreign identity metadata never yield a receipt."""
        for key in self.response():
            r = self.response()
            del r[key]
            with self.assertRaises(self.m.PdfObjectGraphError):
                self.decode(r)
        for section in (None, "identity", "limits", "inspection"):
            r = self.response()
            (r if section is None else r[section])["unknown"] = True
            with self.assertRaises(self.m.PdfObjectGraphError):
                self.decode(r)
        for key in ("pdf_sha256", "ir_sha256", "plan_sha256"):
            r = self.response()
            r["identity"][key] = "d" * 64
            with self.assertRaises(self.m.PdfObjectGraphError):
                self.decode(r)

    def test_protocol_versions_policy_and_limits_must_be_exact(self):
        """Only the inspected passive policy and declared process limits are accepted."""
        for key, value in (("protocol_version", True), ("protocol_version", 2), ("profile_id", "other"), ("policy_id", "other"), ("parser_version", "other")):
            r = self.response()
            r[key] = value
            with self.assertRaises(self.m.PdfObjectGraphError):
                self.decode(r)
        for key in self.response()["limits"]:
            for value in (True, 0, "5"):
                r = self.response()
                r["limits"][key] = value
                with self.assertRaises(self.m.PdfObjectGraphError):
                    self.decode(r)

    def test_protocol_counts_and_success_spelling_are_strict(self):
        """Truth-like counts, empty coverage and generic success cannot satisfy the protocol."""
        for value in (True, "1000", 1000.0, 0, 32, 20001, None):
            r = self.response()
            r["inspection"]["object_count"] = value
            with self.assertRaises(self.m.PdfObjectGraphError):
                self.decode(r)
        for value in ("PASS", "BLOCKED", True, None):
            r = self.response()
            r["inspection"]["status"] = value
            with self.assertRaises(self.m.PdfObjectGraphError):
                self.decode(r)
        r = self.response()
        r["identity"]["page_count"] = True
        with self.assertRaises(self.m.PdfObjectGraphError):
            self.decode(r)

    def test_protocol_duplicate_nonfinite_deep_and_oversized_json_rejected(self):
        """Malformed wire data is rejected with no payload echoed in diagnostics."""
        raw = json.dumps(self.response()).encode("ascii")
        for data in (raw.replace(b'"protocol_version": 1', b'"protocol_version": 1, "protocol_version": 1'),
                     b"NaN", b"[]", b"[" * 1500, b"x" * 4097, bytearray(raw), b"\xff"):
            with self.assertRaises(self.m.PdfObjectGraphError) as caught:
                self.m._decode(data, self.identity())
            self.assertEqual(str(caught.exception), "pdf_object_graph_protocol_invalid")

    def test_receipt_is_frozen_detached_and_unqualified(self):
        """Successful effective-object inspection is not whole-report or release qualification."""
        r = self.inspect()
        with self.assertRaises(FrozenInstanceError):
            r.object_count = 1
        data = r.to_dict()
        data["pdf_sha256"] = "e" * 64
        self.assertEqual(r.to_dict()["pdf_sha256"], digest(self.pdf))
        for key in ("worker_results_authenticated", "whole_pdf_safety_qualified", "aggregate_job_resources_qualified", "release_authorized"):
            self.assertIs(r.to_dict()[key], False)
        self.assertEqual(r.to_dict()["release_authorization"], "NOT_ESTABLISHED")
        self.assertFalse(hasattr(r, "to_observation"))

    def test_receipt_direct_constructor_does_not_bypass_validation(self):
        """Public metadata constructors enforce finite counts and canonical digests."""
        r = self.decode(self.response())
        for changes in ({"object_count": True}, {"object_count": 20001}, {"pdf_sha256": "A" * 64}, {"page_count": 0}):
            with self.assertRaises(self.m.PdfObjectGraphError):
                replace(r, **changes)

    def test_host_does_not_parse_or_mutate_pdf(self):
        """Only the isolated child opens the parser; original PDF bytes remain unchanged."""
        original = digest(self.pdf)
        with patch("pypdf.PdfReader", side_effect=AssertionError("host parse")):
            r = self.inspect()
        self.assertEqual(r.pdf_sha256, original)
        self.assertEqual(digest(self.pdf), original)

    def test_parser_and_policy_pins_are_not_downgraded(self):
        """A changed parser or shared policy envelope requires explicit profile review."""
        with patch.object(self.w, "version", return_value="other"):
            with self.assertRaises(ValueError):
                self.w._inspect(self.pdf, self.identity())
        with patch.object(self.w.safety, "MAX_VISITS", 20001):
            with self.assertRaises(ValueError):
                self.w._inspect(self.pdf, self.identity())

    def test_worker_guards_precede_request_read(self):
        """Failure of either kernel guard stops before any candidate request is read."""
        for guard in ("enforce_pdf_landlock", "enforce_pdf_network_filter"):
            with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as result:
                with patch.object(self.w, "_limits", return_value={}), patch.object(self.w, "_lifetime"), patch.object(self.w, "enforce_pdf_landlock"), patch.object(self.w, "enforce_pdf_network_filter"), patch.object(self.w, guard, side_effect=RuntimeError("synthetic")), patch.object(self.w, "_read_request") as reader:
                    code = self.w.main(["worker", str(source.fileno()), str(result.fileno()), str(os.getpid())])
                    self.assertNotEqual(code, 0)
                    reader.assert_not_called()

    def test_worker_rejects_aliased_or_named_protocol_files(self):
        """Only two distinct anonymous regular objects may be inherited."""
        with tempfile.TemporaryFile() as source, tempfile.NamedTemporaryFile() as named:
            self.assertNotEqual(self.w.main(["worker", str(source.fileno()), str(source.fileno()), str(os.getpid())]), 0)
            self.assertNotEqual(self.w.main(["worker", str(source.fileno()), str(named.fileno()), str(os.getpid())]), 0)
            self.assertNotEqual(self.w.main(["worker", "-1", "3", str(os.getpid())]), 0)

    def test_real_worker_rejects_wrong_parent(self):
        """The actual isolated process cannot claim startup with a foreign parent PID."""
        with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as result:
            process = self.m._start([sys.executable, "-I", str(Path(self.w.__file__)), str(source.fileno()), str(result.fileno()), "1"], (source.fileno(), result.fileno()))
            self.assertNotEqual(self.m._wait(process), 0)
            self.assertEqual(os.fstat(result.fileno()).st_size, 0)

    def test_timeout_reaps_a_real_stalled_worker(self):
        """The host timeout terminates and reaps its owned independent process."""
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True)
        with patch.object(self.m, "WALL_SECONDS", 0.05):
            with self.assertRaises(subprocess.TimeoutExpired):
                self.m._wait(process)
        self.assertIsNotNone(process.returncode)

    def test_isolated_launch_has_only_declared_descriptors(self):
        """No shell, inherited PYTHONPATH or unrelated descriptor enters the worker."""
        with patch.object(self.m.subprocess, "Popen") as start:
            self.m._start(["synthetic"], (10, 11))
        args = start.call_args.kwargs
        self.assertFalse(args["shell"])
        self.assertTrue(args["close_fds"])
        self.assertEqual(args["pass_fds"], (10, 11))
        self.assertNotIn("PYTHONPATH", args["env"])

    def test_failed_execution_returns_no_receipt_or_exception_payload(self):
        """Worker failures expose only a fixed diagnostic, never parser text or a partial result."""
        with patch.object(self.m, "_run_worker", side_effect=OSError("synthetic private diagnostic")):
            with self.assertRaises(self.m.PdfObjectGraphError) as caught:
                self.inspect()
        self.assertEqual(str(caught.exception), "pdf_object_graph_execution_failed")

    def test_native_calls_do_not_leak_parent_descriptors(self):
        """Repeated success and failure do not retain anonymous parent handles."""
        before = len(os.listdir("/proc/self/fd"))
        for _ in range(3):
            self.inspect()
            self.assert_native_rejected(b"%PDF-1.7 invalid")
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_legacy_defaults_and_same_input_policy_remain_unchanged(self):
        """The original 32-page safety route is unchanged and still rejects long PDFs."""
        from reporting import _pdf_safety_worker as old
        self.assertEqual((old.MAX_PAGES, old.MAX_PDF_BYTES, old.MAX_VISITS, old.MAX_DEPTH), (32, 8388608, 20000, 64))
        self.assertEqual(old.inspect_document(self.pdf)["status"], "BLOCKED")
        raw = fixture_pdf(1)
        plan = self.make_plan(raw, 1)
        self.assertEqual(old.inspect_document(raw)["object_count"], self.inspect(pdf_bytes=raw, plan=plan, expected_plan_sha256=plan.plan_sha256).object_count)

    def test_manifest_matches_limits_and_existing_policy_source(self):
        """The internal manifest pins actual budgets, policy bytes, provenance and exclusions."""
        record = json.loads((ROOT / "reporting/pdf-object-graph-engine.v1.json").read_text())
        self.assertEqual(record["profile_id"], ENGINE)
        self.assertEqual(record["parser_version"], "6.19.0")
        self.assertEqual(record["policy_source_sha256"], digest((ROOT / "reporting/_pdf_safety_worker.py").read_bytes()))
        self.assertEqual(record["resource_budget"], {"pdf_bytes": 16777216, "pages": 512, "object_visits": 20000, "graph_depth": 64, "memory_bytes": 268435456, "cpu_seconds": 5, "wall_seconds": 10, "open_files": 128, "result_bytes": 4096})
        self.assertFalse(record["default_pipeline_activated"])
        self.assertFalse(record["whole_report_qualified"])

    def test_request_header_digest_and_integer_grammar_are_closed(self):
        """Altered hashes, extra fields and noncanonical counts cannot enter parsing."""
        identity = self.identity()
        header = " ".join(["1", *(str(identity[k]) for k in self.w.IDENTITY_FIELDS)]).encode("ascii")
        payload = header + b"\n" + self.pdf
        for raw in (payload.replace(b" 33\n", b" 033\n", 1),
                    payload.replace(b" 33\n", b" true\n", 1),
                    b"2" + payload[1:], payload.replace(b" 33\n", b" 33 extra\n", 1),
                    payload + b"x", b"x" * 257 + b"\n" + self.pdf):
            with tempfile.TemporaryFile() as request:
                request.write(raw)
                request.flush()
                with self.assertRaises(ValueError):
                    self.w._read_request(request.fileno())

    def test_request_file_budget_and_mutation_are_rejected(self):
        """An oversized or observably mutated request fails before effective-object evaluation."""
        with tempfile.TemporaryFile() as request:
            request.truncate(self.w.MAX_PDF_BYTES + self.w.HEADER_BYTES + 1)
            with self.assertRaisesRegex(ValueError, "^object graph request budget$"):
                self.w._read_request(request.fileno())
        identity = self.identity()
        header = " ".join(["1", *(str(identity[k]) for k in self.w.IDENTITY_FIELDS)])
        with tempfile.TemporaryFile() as request:
            request.write(header.encode() + b"\n" + self.pdf)
            request.flush()
            old = os.fstat(request.fileno())
            from types import SimpleNamespace
            changed = SimpleNamespace(**{k: getattr(old, k) for k in
                ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")})
            changed.st_size += 1
            with patch.object(self.w.os, "fstat", side_effect=[old, changed]):
                with self.assertRaises(ValueError):
                    self.w._read_request(request.fileno())

    def test_nonzero_exit_and_empty_result_are_never_success(self):
        """Native failure and a missing result cannot manufacture an inspected object count."""
        for code in (0, 70):
            with patch.object(self.m, "_start"), patch.object(self.m, "_wait", return_value=code):
                with self.assertRaises(self.m.PdfObjectGraphError):
                    self.inspect()

    def test_native_reply_reports_the_actual_process_limits(self):
        """A real isolated worker reports the exact limits it enforced before parsing."""
        raw = self.m._run_worker(self.pdf, self.identity())
        record = json.loads(raw)
        self.assertEqual(record["limits"], self.response()["limits"])
        self.assertEqual(record["inspection"]["status"], STATUS)
        self.assertEqual(record["identity"], self.identity())

    def test_plan_changed_during_execution_is_not_reused(self):
        """Even valid wire evidence cannot be accepted after its retained plan changes."""
        raw = json.dumps(self.response()).encode("ascii")
        def changed(*args):
            """Inject plan tampering after request admission and before result reconciliation."""
            object.__setattr__(self.plan, "ir_sha256", "e" * 64)
            return raw
        with patch.object(self.m, "_run_worker", side_effect=changed):
            with self.assertRaises(self.m.PdfObjectGraphError):
                self.inspect()

    def test_blank_page_is_graph_data_not_text_qualification(self):
        """A passive blank page passes only the object dimension, never text completeness."""
        raw = fixture_pdf(33, blank=33)
        plan = self.make_plan(raw, 33)
        r = self.inspect(pdf_bytes=raw, plan=plan, expected_plan_sha256=plan.plan_sha256)
        self.assertEqual(r.page_count, 33)
        self.assertFalse(r.to_dict()["text_equivalence_verified"])
        from reporting.pdf_text_windows import inspect_pdf_text_window, PdfTextWindowError
        with self.assertRaises(PdfTextWindowError):
            inspect_pdf_text_window(pdf_bytes=raw, plan=plan, window_index=2,
                                    expected_plan_sha256=plan.plan_sha256)

    def test_receipt_digest_is_deterministic_and_content_free(self):
        """Repeated real inspection exports identical metadata without page or source text."""
        first = self.inspect()
        second = self.inspect()
        self.assertEqual(first.inspection_sha256, second.inspection_sha256)
        self.assertNotIn("SYNTHETIC-PAGE", json.dumps(first.to_dict()))
        expected = json.dumps(first.to_dict(), sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertEqual(first.inspection_sha256, hashlib.sha256(expected).hexdigest())

    def test_all_changed_functions_have_docstrings(self):
        """Every new Python function documents its scope and behavior from the first review."""
        for path in (Path(self.m.__file__), Path(self.w.__file__), Path(__file__)):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.assertTrue(ast.get_docstring(node), (path.name, node.name))


if __name__ == "__main__":
    unittest.main()
