"""Synthetic native and negative controls for bounded PDF text-window inspection."""
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
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[1]
ENGINE = "generated-pdf-text-window-v1"


def digest(data: bytes) -> str:
    """Hash synthetic fixture bytes without any normalization."""
    return hashlib.sha256(data).hexdigest()


def fixture_pdf(count: int, *, blank: int | None = None, encrypted: bool = False) -> bytes:
    """Generate independent numbered text pages using only the existing parser package."""
    from pypdf import PdfWriter
    from pypdf.generic import NameObject, DictionaryObject, DecodedStreamObject
    writer = PdfWriter()
    writer.pdf_header = "%PDF-1.7"
    font = writer._add_object(DictionaryObject({
        NameObject("/Type"): NameObject("/Font"),
        NameObject("/Subtype"): NameObject("/Type1"),
        NameObject("/BaseFont"): NameObject("/Helvetica"),
    }))
    for number in range(1, count + 1):
        page = writer.add_blank_page(width=595, height=842)
        if number == blank:
            continue
        page[NameObject("/Resources")] = DictionaryObject({
            NameObject("/Font"): DictionaryObject({NameObject("/F1"): font})})
        stream = DecodedStreamObject()
        stream.set_data(f"BT /F1 12 Tf 50 750 Td (SYNTHETIC-PAGE-{number}) Tj ET".encode())
        page[NameObject("/Contents")] = writer._add_object(stream)
    if encrypted:
        writer.encrypt("synthetic-password")
    output = BytesIO()
    writer.write(output)
    return output.getvalue()


def text_digest(first: int, last: int) -> str:
    """Independently frame expected physical-page labels and UTF-8 byte lengths."""
    result = hashlib.sha256()
    for number in range(first, last + 1):
        raw = f"SYNTHETIC-PAGE-{number}".encode()
        result.update(f"{number}:{len(raw)}:".encode("ascii"))
        result.update(raw)
    return result.hexdigest()


class PdfTextWindowTests(unittest.TestCase):
    """Exercise real workers while keeping malformed-response controls deterministic."""

    def setUp(self):
        """Require the new boundary before creating any native synthetic workload."""
        self.assertIsNotNone(importlib.util.find_spec("reporting.pdf_text_windows"),
                             "bounded native PDF text-window inspection is missing")
        self.m = importlib.import_module("reporting.pdf_text_windows")
        self.w = importlib.import_module("reporting._pdf_text_window_worker")
        self.p = importlib.import_module("reporting.page_windows")
        self.pdf = fixture_pdf(33)
        self.plan = self.make_plan(self.pdf, 33)

    def make_plan(self, pdf, count, width=16, profile=ENGINE):
        """Bind an exact synthetic PDF to a finite existing window plan."""
        return self.p.plan_pdf_page_windows(
            pdf_sha256=digest(pdf), ir_sha256="b" * 64, page_count=count,
            admitted_page_budget=count, pages_per_window=width, inspector_profile_id=profile)

    def inspect(self, **changes):
        """Invoke the public adapter with independently pinned test expectations."""
        args = dict(pdf_bytes=self.pdf, plan=self.plan, window_index=0,
                    expected_plan_sha256=self.plan.plan_sha256)
        args.update(changes)
        return self.m.inspect_pdf_text_window(**args)

    def identity(self):
        """Build the independent expected wire identity for the first selected interval."""
        return dict(pdf_sha256=digest(self.pdf), ir_sha256="b" * 64,
                    plan_sha256=self.plan.plan_sha256, page_count=33,
                    window_index=0, first_page=1, last_page=16)

    def response(self):
        """Return explicitly synthetic wire metadata for negative protocol tests."""
        return {"protocol_version": 1, "profile_id": ENGINE,
                "identity": self.identity(),
                "limits": {"memory_bytes": 268435456, "cpu_seconds": 5,
                           "file_bytes": 4096, "open_files": 128},
                "inspection": {"status": "WINDOW_TEXT_INSPECTED", "text_sha256": "c" * 64,
                               "text_bytes": 320, "text_chars": 320,
                               "decoded_bytes": 1024, "inspected_pages": 16}}

    def decode(self, record):
        """Test closed wire validation independently from actual worker execution."""
        return self.m._decode(json.dumps(record).encode(), self.identity())

    def test_native_first_and_last_window(self):
        """A real guarded child inspects exactly the selected inclusive physical pages."""
        first = self.inspect()
        last = self.inspect(window_index=2)
        self.assertEqual(first.text_sha256, text_digest(1, 16))
        self.assertEqual(last.text_sha256, text_digest(33, 33))
        self.assertEqual((first.inspected_pages, last.inspected_pages), (16, 1))
        self.assertEqual(last.to_observation().index, 2)
        self.assertEqual(last.to_observation().plan_sha256, self.plan.plan_sha256)

    def test_real_large_documents_have_exact_tail_evidence(self):
        """Native extraction covers tail pages of 64, 129, 300 and 512-page fixtures."""
        for count in (64, 129, 300, 512):
            with self.subTest(pages=count):
                pdf = fixture_pdf(count)
                plan = self.make_plan(pdf, count)
                span = plan.windows[-1]
                result = self.inspect(pdf_bytes=pdf, plan=plan,
                                      expected_plan_sha256=plan.plan_sha256,
                                      window_index=span.index)
                self.assertEqual(result.text_sha256, text_digest(span.first_page, count))
                self.assertEqual(result.page_count, count)

    def test_all_windows_feed_existing_checkpoint_without_qualifying_release(self):
        """All 33 real pages can populate the existing exact checkpoint/ledger contracts."""
        from reporting.page_checkpoints import PageWindowCheckpoint, resume_page_checkpoint
        checkpoint = PageWindowCheckpoint(self.plan, "synthetic", "job-1", "d" * 64,
                                          "e" * 64, ())
        for span in self.plan.windows:
            result = self.inspect(window_index=span.index)
            checkpoint = checkpoint.append_observations((result.to_observation(),))
        restored = resume_page_checkpoint(
            checkpoint_bytes=checkpoint.to_bytes(),
            expected_checkpoint_sha256=checkpoint.checkpoint_sha256,
            expected_plan=self.plan, namespace_id="synthetic", job_id="job-1",
            expected_request_sha256="d" * 64, expected_resource_profile_sha256="e" * 64)
        self.assertEqual(restored.remaining_windows, ())
        self.assertFalse(restored.as_complete_ledger().to_dict()["release_authorized"])

    def test_legacy_whole_document_policy_remains_closed(self):
        """Window evidence never bypasses the unchanged whole-file 32-page policy."""
        from reporting.pdf_safety import validate_pdf_object_safety
        self.assertEqual(self.inspect(window_index=2).inspected_pages, 1)
        legacy = validate_pdf_object_safety(pdf_bytes=self.pdf, expected_pdf_sha256=digest(self.pdf))
        self.assertFalse(legacy.passed)

    def test_receipt_contains_no_extracted_text_or_release_claim(self):
        """The transport exports hashes/counts only and preserves unqualified guarantees."""
        record = self.inspect(window_index=2).to_dict()
        self.assertEqual(record["status"], "WINDOW_TEXT_INSPECTED")
        for key in ("whole_pdf_safety_qualified", "scientific_equivalence_verified",
                    "aggregate_job_resources_qualified", "release_authorized"):
            self.assertIs(record[key], False)
        self.assertNotIn("SYNTHETIC-PAGE", json.dumps(record))
        self.assertEqual(record["release_authorization"], "NOT_ESTABLISHED")

    def test_receipt_is_frozen_and_detached(self):
        """Mutating serialized data cannot alter retained inspection metadata."""
        result = self.inspect(window_index=2)
        with self.assertRaises(FrozenInstanceError):
            result.page_count = 1
        copy = result.to_dict()
        copy["page_count"] = 1
        self.assertEqual(result.to_dict()["page_count"], 33)
        self.assertEqual(result.observation_sha256, digest(self.m._canonical(result.to_dict())))

    def test_invalid_plan_and_index_types_prevent_launch(self):
        """Booleans, strings, missing types and foreign ordinals cannot launch a worker."""
        for changes in ({"plan": None}, {"window_index": True}, {"window_index": -1},
                        {"window_index": 3}, {"window_index": "0"}):
            with self.subTest(changes=changes), patch.object(self.m, "_run_worker") as run:
                with self.assertRaises(self.m.PdfTextWindowError):
                    self.inspect(**changes)
                run.assert_not_called()

    def test_foreign_plan_pdf_and_inspector_prevent_launch(self):
        """Independent expected digests and the declared inspector must all match."""
        foreign = self.make_plan(self.pdf, 33, profile="foreign-v1")
        for changes in ({"expected_plan_sha256": "a" * 64}, {"pdf_bytes": self.pdf + b"x"},
                        {"plan": foreign, "expected_plan_sha256": foreign.plan_sha256}):
            with self.subTest(changes=list(changes)), patch.object(self.m, "_run_worker") as run:
                with self.assertRaises(self.m.PdfTextWindowError):
                    self.inspect(**changes)
                run.assert_not_called()

    def test_mutated_plan_is_rejected(self):
        """A mutated frozen plan cannot reuse its retained digest."""
        object.__setattr__(self.plan, "ir_sha256", "a" * 64)
        with self.assertRaises(self.m.PdfTextWindowError):
            self.inspect()


    def test_native_type_and_byte_budget_preflight(self):
        """Mutable or oversized inputs fail before opening protocol files or subprocesses."""
        class BytesChild(bytes):
            """Synthetic subclass disallowed at the immutable input boundary."""
        overflow = b"%PDF-1.7" + b"x" * 16777209
        plan = self.make_plan(overflow, 33)
        with patch.object(self.m, "_run_worker") as run:
            for raw in (bytearray(self.pdf), BytesChild(self.pdf), b"x"):
                with self.subTest(kind=type(raw).__name__):
                    with self.assertRaises(self.m.PdfTextWindowError):
                        self.inspect(pdf_bytes=raw)
            with self.assertRaises(self.m.PdfTextWindowError):
                self.inspect(pdf_bytes=overflow, plan=plan, expected_plan_sha256=plan.plan_sha256)
            run.assert_not_called()

    def test_page_and_window_admission_limits_prevent_launch(self):
        """No large constant silently widens the explicitly bounded internal class."""
        for count, width in ((513, 16), (33, 32)):
            plan = self.make_plan(self.pdf, count, width)
            with patch.object(self.m, "_run_worker") as run:
                with self.assertRaises(self.m.PdfTextWindowError):
                    self.inspect(plan=plan, expected_plan_sha256=plan.plan_sha256)
                run.assert_not_called()

    def test_actual_page_count_mismatch_fails_native(self):
        """The worker measures the final page count rather than trusting the declaration."""
        plan = self.make_plan(self.pdf, 34)
        with self.assertRaises(self.m.PdfTextWindowError):
            self.inspect(plan=plan, expected_plan_sha256=plan.plan_sha256)

    def test_blank_selected_page_is_not_silently_skipped(self):
        """Missing selected text causes whole-window rejection without partial evidence."""
        pdf = fixture_pdf(33, blank=33)
        plan = self.make_plan(pdf, 33)
        with self.assertRaises(self.m.PdfTextWindowError):
            self.inspect(pdf_bytes=pdf, plan=plan, expected_plan_sha256=plan.plan_sha256, window_index=2)

    def test_encrypted_and_malformed_documents_fail_native(self):
        """A correct expected digest cannot authorize invalid or encrypted PDF contents."""
        for pdf in (fixture_pdf(33, encrypted=True), b"%PDF-1.7\nnot-a-pdf"):
            plan = self.make_plan(pdf, 33)
            with self.subTest(size=len(pdf)), self.assertRaises(self.m.PdfTextWindowError):
                self.inspect(pdf_bytes=pdf, plan=plan, expected_plan_sha256=plan.plan_sha256)

    def test_disable_and_platform_fail_before_launch(self):
        """Unavailable or explicitly disabled execution has no permissive fallback."""
        with patch.dict(os.environ, {"OMNIGENIS_PDF_TEXT_WINDOWS_DISABLED": "1"}), \
                patch.object(self.m, "_run_worker") as run:
            with self.assertRaises(self.m.PdfTextWindowError):
                self.inspect()
            run.assert_not_called()
        with patch.object(self.m.sys, "platform", "unsupported"):
            with self.assertRaises(self.m.PdfTextWindowError):
                self.inspect()

    def test_host_does_not_parse_or_modify_pdf(self):
        """Actual parsing occurs only in the isolated child; original bytes remain identical."""
        original = digest(self.pdf)
        with patch("pypdf.PdfReader", side_effect=AssertionError("host parser forbidden")):
            result = self.inspect(window_index=2)
        self.assertEqual(result.pdf_sha256, original)
        self.assertEqual(digest(self.pdf), original)

    def test_protocol_rejects_unknown_or_missing_fields(self):
        """Every protocol object is closed, including nested identity and limits."""
        for where in (None, "identity", "limits", "inspection"):
            record = self.response()
            target = record if where is None else record[where]
            target["unexpected"] = True
            with self.subTest(where=where), self.assertRaises(self.m.PdfTextWindowError):
                self.decode(record)
        record = self.response()
        del record["inspection"]["text_sha256"]
        with self.assertRaises(self.m.PdfTextWindowError):
            self.decode(record)

    def test_protocol_rejects_stale_or_foreign_identity(self):
        """A success from another PDF, IR, plan or page interval is not reusable."""
        for key in self.identity():
            record = self.response()
            record["identity"][key] = "d" * 64 if key.endswith("sha256") else 9
            with self.subTest(key=key), self.assertRaises(self.m.PdfTextWindowError):
                self.decode(record)

    def test_protocol_rejects_booleans_and_invalid_counts(self):
        """Truth-like scalars never satisfy integer resource or coverage fields."""
        for part, key in (("identity", "window_index"), ("limits", "cpu_seconds"),
                          ("inspection", "inspected_pages"), ("inspection", "text_chars")):
            record = self.response()
            record[part][key] = True
            with self.subTest(part=part, key=key), self.assertRaises(self.m.PdfTextWindowError):
                self.decode(record)
        for key, value in (("inspected_pages", 15), ("text_bytes", 0),
                           ("decoded_bytes", 8 * 1024 * 1024 + 1),
                           ("text_chars", 321), ("text_sha256", "A" * 64)):
            record = self.response()
            record["inspection"][key] = value
            with self.subTest(key=key), self.assertRaises(self.m.PdfTextWindowError):
                self.decode(record)

    def test_protocol_rejects_unknown_versions_status_and_limits(self):
        """Generic PASS or changed limits cannot replace this exact worker protocol."""
        for field, value in (("protocol_version", True), ("protocol_version", 2), ("profile_id", "other")):
            record = self.response()
            record[field] = value
            with self.assertRaises(self.m.PdfTextWindowError):
                self.decode(record)
        for field, value in (("status", "PASS"), ("status", "BLOCKED")):
            record = self.response()
            record["inspection"][field] = value
            with self.assertRaises(self.m.PdfTextWindowError):
                self.decode(record)
        record = self.response()
        record["limits"]["memory_bytes"] += 1
        with self.assertRaises(self.m.PdfTextWindowError):
            self.decode(record)

    def test_protocol_duplicate_keys_nonfinite_and_oversize_rejected(self):
        """Malformed, duplicate, deeply nested or oversized responses remain failures."""
        raw = json.dumps(self.response()).encode()
        bad = raw.replace(b'"window_index": 0', b'"window_index": 0, "window_index": 0')
        for payload in (b"", b"x", b"[NaN]", b"[" * 5000, b" " * 4097, bad):
            with self.subTest(size=len(payload)), self.assertRaises(self.m.PdfTextWindowError):
                self.m._decode(payload, self.identity())

    def test_failures_never_return_window_observations(self):
        """A failed process route exposes only a fixed diagnostic and no parser details."""
        with patch.object(self.m, "_run_worker", side_effect=OSError("private-value")):
            with self.assertRaises(self.m.PdfTextWindowError) as caught:
                self.inspect()
        self.assertNotIn("private-value", str(caught.exception))

    def test_timeout_kills_and_reaps_owned_worker(self):
        """The supervisor reaps a deliberately stalled independent process on timeout."""
        child = subprocess.Popen([sys.executable, "-I", "-c", "import time;time.sleep(30)"],
                                 start_new_session=True)
        with patch.object(self.m, "WALL_SECONDS", 0.02):
            with self.assertRaises(subprocess.TimeoutExpired):
                self.m._wait(child)
        self.assertIsNotNone(child.returncode)

    def test_start_is_isolated_and_inherits_only_protocol_descriptors(self):
        """No shell, caller PYTHONPATH or arbitrary file descriptor enters the worker."""
        with patch.object(self.m.subprocess, "Popen", return_value=Mock()) as start:
            self.m._start(["python", "-I", "worker"], (10, 11))
        args = start.call_args.kwargs
        self.assertEqual(args["pass_fds"], (10, 11))
        self.assertTrue(args["close_fds"])
        self.assertTrue(args["start_new_session"])
        self.assertNotIn("PYTHONPATH", args["env"])
        self.assertFalse(args.get("shell", False))

    def test_worker_guard_failure_precedes_request_read(self):
        """Unavailable confinement prevents reading or inspecting candidate bytes."""
        with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as result:
            source.write(b"synthetic"); source.flush()
            with patch.object(self.w, "_limits", return_value=self.response()["limits"]), \
                    patch.object(self.w, "_lifetime"), \
                    patch.object(self.w, "enforce_pdf_landlock", side_effect=RuntimeError("guard")), \
                    patch.object(self.w, "_read_request") as read:
                code = self.w.main(["worker", str(source.fileno()), str(result.fileno()), str(os.getpid())])
            self.assertNotEqual(code, 0)
            read.assert_not_called()
            self.assertEqual(os.fstat(result.fileno()).st_size, 0)

    def test_worker_rejects_alias_and_named_descriptors(self):
        """Protocol files must be distinct anonymous regular objects."""
        with tempfile.TemporaryFile() as source, tempfile.NamedTemporaryFile() as named:
            for argv in (["worker"], ["worker", str(source.fileno()), str(source.fileno()), "1"],
                         ["worker", str(source.fileno()), str(named.fileno()), str(os.getpid())]):
                self.assertNotEqual(self.w.main(argv), 0)

    def test_missing_parent_is_rejected_by_real_worker(self):
        """A native child cannot claim valid startup with a foreign parent PID."""
        with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as result:
            p = subprocess.run([sys.executable, "-I", str(ROOT / "reporting/_pdf_text_window_worker.py"),
                                str(source.fileno()), str(result.fileno()), "1"],
                               pass_fds=(source.fileno(), result.fileno()), timeout=5,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual((p.stdout, p.stderr), (b"", b""))

    def test_worker_parser_and_content_budgets_fail_closed(self):
        """The parser version and selected decoded/text sizes are fixed contracts."""
        with patch.object(self.w, "version", return_value="0.0.0"):
            with self.assertRaises(ValueError):
                self.w._extract(self.pdf, self.identity())
        with patch.object(self.w, "MAX_DECODED_BYTES", 8):
            with self.assertRaises(ValueError):
                self.w._extract(self.pdf, self.identity())
        with patch.object(self.w, "MAX_TEXT_BYTES", 8):
            with self.assertRaises(ValueError):
                self.w._extract(self.pdf, self.identity())

    def test_repeated_native_calls_preserve_parent_descriptors(self):
        """Successful and rejected jobs leave no owned anonymous descriptor behind."""
        before = len(os.listdir("/proc/self/fd"))
        for _ in range(3):
            self.inspect(window_index=2)
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_manifest_matches_implementation_and_existing_pins(self):
        """The new internal profile records exact limits without upgrading dependencies."""
        profile = json.loads((ROOT / "reporting/pdf-text-window-engine.v1.json").read_text())
        self.assertEqual(profile["profile_id"], ENGINE)
        self.assertEqual(profile["parser_version"], "6.19.0")
        self.assertEqual(profile["budget"], {
            "pdf_bytes": self.w.MAX_PDF_BYTES, "document_pages": self.w.MAX_DOCUMENT_PAGES,
            "window_pages": self.w.MAX_WINDOW_PAGES, "decoded_bytes": self.w.MAX_DECODED_BYTES,
            "text_bytes": self.w.MAX_TEXT_BYTES, "memory_bytes": self.w.MEMORY_BYTES,
            "cpu_seconds": self.w.CPU_SECONDS, "wall_seconds": self.w.WALL_SECONDS,
            "open_files": self.w.OPEN_FILES, "result_bytes": self.w.RESULT_BYTES})
        self.assertFalse(profile["default_pipeline_activated"])
        self.assertFalse(profile["whole_document_qualification"])

    def test_all_changed_functions_have_docstrings(self):
        """Every changed Python function retains explicit documentation from the first review."""
        for relative in ("reporting/pdf_text_windows.py", "reporting/_pdf_text_window_worker.py",
                         "tests/test_reporting_pdf_text_windows.py"):
            tree = ast.parse((ROOT / relative).read_text())
            missing = [n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                       and not ast.get_docstring(n)]
            self.assertEqual(missing, [], relative)


    def test_request_header_is_closed_and_canonical(self):
        """Canonical request parsing rejects foreign bytes, dimensions and header syntax."""
        expected = self.identity()
        header = " ".join(["1", *(str(expected[k]) for k in self.w.IDENTITY_FIELDS)]).encode() + b"\n"
        with tempfile.TemporaryFile() as source:
            source.write(header + self.pdf); source.flush()
            identity, raw = self.w._read_request(source.fileno())
        self.assertEqual(identity, expected)
        self.assertEqual(raw, self.pdf)
        bad_headers = [header.replace(b"1 ", b"2 ", 1), header[:-1],
                       header.replace(b" 33 0 1 16\n", b" 33 00 1 16\n"),
                       header.replace(b" 33 0 1 16\n", b" 33 0 0 16\n"),
                       header.replace(b" 33 0 1 16\n", b" 33 0 1 17\n"),
                       header.replace(b" 33 0 1 16\n", b" 513 0 1 16\n"),
                       header.replace(digest(self.pdf).encode(), b"a" * 64, 1),
                       b"x" * 513 + b"\n"]
        for malformed in bad_headers:
            with tempfile.TemporaryFile() as source:
                source.write(malformed + self.pdf); source.flush()
                with self.assertRaises(ValueError):
                    self.w._read_request(source.fileno())

    def test_request_budget_and_changed_descriptor_metadata_rejected(self):
        """Oversized and observably changed anonymous requests cannot reach the parser."""
        with tempfile.TemporaryFile() as source:
            source.truncate(self.w.MAX_PDF_BYTES + self.w.HEADER_BYTES + 1)
            with self.assertRaises(ValueError):
                self.w._read_request(source.fileno())
        expected = self.identity()
        header = " ".join(["1", *(str(expected[k]) for k in self.w.IDENTITY_FIELDS)]).encode() + b"\n"
        with tempfile.TemporaryFile() as source:
            source.write(header + self.pdf); source.flush()
            before = os.fstat(source.fileno())
            changed = Mock(wraps=before)
            for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"):
                setattr(changed, key, getattr(before, key))
            changed.st_mtime_ns += 1
            with patch.object(self.w.os, "fstat", side_effect=[before, changed]):
                with self.assertRaises(ValueError):
                    self.w._read_request(source.fileno())

    def test_network_guard_failure_precedes_request_read(self):
        """The existing network guard is mandatory even after filesystem confinement."""
        with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as result:
            source.write(b"synthetic"); source.flush()
            with patch.object(self.w, "_limits", return_value=self.response()["limits"]), \
                    patch.object(self.w, "_lifetime"), \
                    patch.object(self.w, "enforce_pdf_landlock"), \
                    patch.object(self.w, "enforce_pdf_network_filter", side_effect=RuntimeError("guard")), \
                    patch.object(self.w, "_read_request") as read:
                code = self.w.main(["worker", str(source.fileno()), str(result.fileno()), str(os.getpid())])
            self.assertNotEqual(code, 0)
            read.assert_not_called()
            self.assertEqual(os.fstat(result.fileno()).st_size, 0)

    def test_nonzero_and_missing_response_are_rejected(self):
        """Native exit failure and empty protocol output cannot become inspected evidence."""
        for code in (0, 7):
            with patch.object(self.m, "_start", return_value=Mock()), \
                    patch.object(self.m, "_wait", return_value=code):
                with self.assertRaises(self.m.PdfTextWindowError):
                    self.inspect()

    def test_selected_unicode_and_line_breaks_are_not_normalized(self):
        """Digest framing preserves every extracted code point including CR, LF and FF."""
        text = "A\r\n\u03b2\f "
        page = Mock()
        page.get_contents.return_value.get_data.return_value = b"synthetic-stream"
        page.extract_text.return_value = text
        reader = Mock(is_encrypted=False, pages=[page] * 33)
        identity = self.identity(); identity.update(window_index=2, first_page=33, last_page=33)
        with patch("pypdf.PdfReader", return_value=reader):
            result = self.w._extract(self.pdf, identity)
        raw = text.encode("utf-8")
        self.assertEqual(result["text_sha256"], digest(f"33:{len(raw)}:".encode() + raw))
        self.assertEqual((result["text_bytes"], result["text_chars"]), (len(raw), len(text)))

    def test_actual_extracted_unicode_is_preserved(self):
        """A native WinAnsi text page retains its accented character in the UTF-8 digest."""
        from pypdf import PdfWriter
        from pypdf.generic import NameObject, DictionaryObject, DecodedStreamObject
        writer = PdfWriter(); writer.pdf_header = "%PDF-1.7"
        page = writer.add_blank_page(width=595, height=842)
        font = writer._add_object(DictionaryObject({NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/Type1"), NameObject("/BaseFont"): NameObject("/Helvetica"),
            NameObject("/Encoding"): NameObject("/WinAnsiEncoding")}))
        page[NameObject("/Resources")] = DictionaryObject({NameObject("/Font"): DictionaryObject({NameObject("/F1"): font})})
        stream = DecodedStreamObject(); stream.set_data(b"BT /F1 12 Tf 50 750 Td (Caf\\351) Tj ET")
        page[NameObject("/Contents")] = writer._add_object(stream)
        output = BytesIO(); writer.write(output); pdf = output.getvalue()
        plan = self.make_plan(pdf, 1)
        result = self.inspect(pdf_bytes=pdf, plan=plan, expected_plan_sha256=plan.plan_sha256)
        raw = "Caf\u00e9".encode("utf-8")
        self.assertEqual(result.text_sha256, digest(f"1:{len(raw)}:".encode() + raw))

    def test_native_result_can_be_persisted_as_exact_current_checkpoint(self):
        """A real text observation composes with the existing storage and head coordinator."""
        from reporting.page_checkpoints import PageWindowCheckpoint
        from reporting.checkpoint_files import CheckpointDirectoryIdentity
        from reporting.checkpoint_head import advance_checkpoint_head, load_current_checkpoint
        base = PageWindowCheckpoint(self.plan, "synthetic", "job-1", "d" * 64, "e" * 64, ())
        result = self.inspect()
        target = base.append_observations((result.to_observation(),))
        with tempfile.TemporaryDirectory() as name:
            os.chmod(name, 0o700)
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                info = os.fstat(fd)
                root = CheckpointDirectoryIdentity(info.st_dev, info.st_ino, info.st_uid,
                                                  "synthetic", "job-1", "d" * 64, "e" * 64)
                advance_checkpoint_head(directory_fd=fd, expected_directory=root, checkpoint=base,
                    expected_checkpoint_sha256=base.checkpoint_sha256,
                    expected_previous_checkpoint_sha256=None)
                advance_checkpoint_head(directory_fd=fd, expected_directory=root, checkpoint=target,
                    expected_checkpoint_sha256=target.checkpoint_sha256,
                    expected_previous_checkpoint_sha256=base.checkpoint_sha256)
                restored = load_current_checkpoint(directory_fd=fd, expected_directory=root,
                    expected_plan=self.plan, expected_checkpoint_sha256=target.checkpoint_sha256)
                self.assertEqual(restored.to_bytes(), target.to_bytes())
                self.assertEqual(len(restored.remaining_windows), 2)
            finally:
                os.close(fd)

    def test_guarded_worker_limits_match_live_kernel_values(self):
        """A separate process applies and reports the actual native resource limits."""
        code = ("import json;from reporting._pdf_text_window_worker import _limits;"
                "print(json.dumps(_limits()))")
        p = subprocess.run([sys.executable, "-B", "-c", code], cwd=ROOT,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(p.returncode, 0)
        self.assertEqual(json.loads(p.stdout), self.response()["limits"])

    def test_direct_receipt_invalid_counts_are_rejected(self):
        """Reconstruction cannot use a direct constructor to bypass count/type checks."""
        result = self.decode(self.response())
        for changes in ({"first_page": 0}, {"text_chars": True}, {"decoded_bytes": 0},
                        {"text_bytes": 1048577}, {"text_sha256": "X" * 64}):
            with self.subTest(changes=changes), self.assertRaises(self.m.PdfTextWindowError):
                replace(result, **changes)


if __name__ == "__main__":
    unittest.main()
