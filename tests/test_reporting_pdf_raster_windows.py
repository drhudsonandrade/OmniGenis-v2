"""Synthetic native and negative controls for exact PDF raster-window inspection."""
from __future__ import annotations

import ast
from contextlib import contextmanager
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
from unittest.mock import Mock, patch

from tests.test_reporting_pdf_text_windows import fixture_pdf, digest

ROOT = Path(__file__).resolve().parents[1]
ENGINE = "generated-pdf-raster-window-v1"


def changed_pdf(raw, change):
    """Apply a test-only page mutation to a detached synthetic PDF."""
    from pypdf import PdfReader, PdfWriter
    writer = PdfWriter(clone_from=PdfReader(BytesIO(raw)))
    writer.pdf_header = "%PDF-1.7"
    change(writer)
    out = BytesIO()
    writer.write(out)
    return out.getvalue()


def dense_fixture(count=4):
    """Generate bounded synthetic vector density without patient text or external assets."""
    from pypdf.generic import NameObject, DecodedStreamObject
    def fill(writer):
        """Place many small interior shapes on each independently generated page."""
        for page in writer.pages:
            stream = DecodedStreamObject()
            stream.set_data("\n".join(f"{50 + (i % 40) * 10} {50 + (i // 40) * 10} 3 3 re f" for i in range(1600)).encode())
            page[NameObject("/Contents")] = writer._add_object(stream)
    return changed_pdf(fixture_pdf(count), fill)


class PdfRasterWindowTests(unittest.TestCase):
    """Check real guarded raster work and fail-closed protocol/geometry boundaries."""

    def setUp(self):
        """Require the new boundary before any synthetic native work is attempted."""
        self.assertIsNotNone(importlib.util.find_spec("reporting.pdf_raster_windows"),
                             "bounded native PDF raster-window inspection is missing")
        self.m = importlib.import_module("reporting.pdf_raster_windows")
        self.w = importlib.import_module("reporting._pdf_raster_window_worker")
        self.p = importlib.import_module("reporting.page_windows")
        self.pdf = fixture_pdf(33)
        self.plan = self.make_plan(self.pdf, 33)

    def make_plan(self, pdf, count, width=4, profile=ENGINE):
        """Construct a finite independently pinned synthetic raster plan."""
        return self.p.plan_pdf_page_windows(pdf_sha256=digest(pdf), ir_sha256="b" * 64,
            page_count=count, admitted_page_budget=count, pages_per_window=width,
            inspector_profile_id=profile)

    def inspect(self, **changes):
        """Invoke the opt-in adapter using the exact test plan and PDF."""
        values = dict(pdf_bytes=self.pdf, plan=self.plan, window_index=0,
                      expected_plan_sha256=self.plan.plan_sha256)
        values.update(changes)
        return self.m.inspect_pdf_raster_window(**values)

    def identity(self):
        """Return independent protocol expectations for the first selected window."""
        return dict(pdf_sha256=digest(self.pdf), ir_sha256="b" * 64,
                    plan_sha256=self.plan.plan_sha256, page_count=33,
                    window_index=0, first_page=1, last_page=4)

    def response(self):
        """Produce explicitly synthetic wire metadata for isolated rejection tests."""
        return {"protocol_version": 1, "profile_id": ENGINE, "identity": self.identity(),
                "limits": dict(self.m._LIMITS), "inspection": {
                    "status": "WINDOW_RASTER_INSPECTED", "raster_sha256": "c" * 64,
                    "inspected_pages": 4, "total_pixels": 4 * 891662,
                    "min_edge_margin_px": 20}}

    def decode(self, value):
        """Decode one independently encoded synthetic response."""
        return self.m._decode(json.dumps(value).encode("ascii"), self.identity())

    @contextmanager
    def protocol(self):
        """Borrow real anonymous protocol files and a private supervisor directory."""
        with tempfile.TemporaryDirectory(prefix="omnigenis-pdf-visual-supervisor-", dir="/tmp") as td:
            fd = os.open(td, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                with tempfile.TemporaryFile() as request, tempfile.TemporaryFile() as result:
                    yield request, result, fd, td
            finally:
                os.close(fd)

    def test_native_first_and_last_window(self):
        """Real guarded raster calls cover the selected initial and last physical pages."""
        first = self.inspect()
        last = self.inspect(window_index=8)
        self.assertEqual((first.first_page, first.last_page, first.inspected_pages), (1, 4, 4))
        self.assertEqual((last.first_page, last.last_page, last.inspected_pages), (33, 33, 1))
        self.assertGreater(first.total_pixels, last.total_pixels)
        self.assertGreaterEqual(last.min_edge_margin_px, 2)

    def test_all_33_pages_feed_complete_existing_ledger(self):
        """Nine real raster windows account for all 33 pages without omissions."""
        receipts = [self.inspect(window_index=i) for i in range(self.plan.window_count)]
        observations = tuple(r.to_observation() for r in receipts)
        ledger = self.p.bind_pdf_page_window_evidence(plan=self.plan, observations=observations)
        self.assertEqual(sum(r.inspected_pages for r in receipts), 33)
        self.assertEqual(ledger.to_dict()["window_count"], 9)
        self.assertFalse(ledger.to_dict()["release_authorized"])

    def test_native_tail_of_large_documents(self):
        """Native tail rasterization covers 64, 129, 300 and 512-page fixtures."""
        for count in (64, 129, 300, 512):
            with self.subTest(count=count):
                pdf = fixture_pdf(count)
                plan = self.make_plan(pdf, count)
                result = self.inspect(pdf_bytes=pdf, plan=plan, window_index=plan.window_count - 1,
                                      expected_plan_sha256=plan.plan_sha256)
                self.assertEqual(result.last_page, count)
                self.assertEqual(result.page_count, count)

    def test_same_small_candidate_matches_legacy_raster_digest(self):
        """The exact same small PDF retains the previous RGB page-hash convention."""
        from reporting.pdf_visual import validate_pdf_visual_geometry
        pdf = fixture_pdf(3)
        plan = self.make_plan(pdf, 3)
        result = self.inspect(pdf_bytes=pdf, plan=plan, expected_plan_sha256=plan.plan_sha256)
        legacy = validate_pdf_visual_geometry(pdf_bytes=pdf, expected_pdf_sha256=digest(pdf))
        self.assertTrue(legacy.passed, legacy.errors)
        self.assertEqual(result.raster_sha256, legacy.raster_sha256)
        self.assertEqual(result.total_pixels, legacy.total_pixels)
        self.assertEqual(result.min_edge_margin_px, legacy.min_edge_margin_px)

    def test_repeated_native_inspection_is_deterministic(self):
        """Repeated identical native input produces identical detached metadata."""
        self.assertEqual(self.inspect(window_index=8).to_dict(), self.inspect(window_index=8).to_dict())

    def test_blank_selected_page_is_rejected(self):
        """One blank page prevents partial window success."""
        pdf = fixture_pdf(33, blank=4)
        plan = self.make_plan(pdf, 33)
        with self.assertRaises(self.m.PdfRasterWindowError):
            self.inspect(pdf_bytes=pdf, plan=plan, expected_plan_sha256=plan.plan_sha256)

    def test_unselected_blank_page_is_not_claimed_inspected(self):
        """A last-window receipt makes no assertion about a blank page outside its range."""
        pdf = fixture_pdf(33, blank=1)
        plan = self.make_plan(pdf, 33)
        result = self.inspect(pdf_bytes=pdf, plan=plan, window_index=8,
                              expected_plan_sha256=plan.plan_sha256)
        self.assertEqual(result.inspected_pages, 1)
        self.assertFalse(result.to_dict()["whole_pdf_safety_qualified"])

    def test_edge_contact_is_rejected(self):
        """An opaque shape touching a selected page edge is not silently accepted."""
        from pypdf.generic import NameObject, DecodedStreamObject
        def change(writer):
            """Place a black rectangle directly on a synthetic media-box boundary."""
            stream = DecodedStreamObject(); stream.set_data(b"0 0 10 10 re f")
            writer.pages[0][NameObject("/Contents")] = writer._add_object(stream)
        pdf = changed_pdf(fixture_pdf(1), change)
        plan = self.make_plan(pdf, 1)
        with self.assertRaises(self.m.PdfRasterWindowError):
            self.inspect(pdf_bytes=pdf, plan=plan, expected_plan_sha256=plan.plan_sha256)

    def test_unsupported_rotation_crop_origin_and_scale_rejected(self):
        """Unqualified page transforms cannot be normalized into a successful geometry claim."""
        from pypdf.generic import NameObject, NumberObject, RectangleObject
        changes = [lambda w: w.pages[0].rotate(90),
                   lambda w: w.pages[0].__setitem__(NameObject("/CropBox"), RectangleObject([0, 0, 500, 700])),
                   lambda w: w.pages[0].__setitem__(NameObject("/MediaBox"), RectangleObject([10, 0, 605, 842])),
                   lambda w: w.pages[0].__setitem__(NameObject("/UserUnit"), NumberObject(2))]
        for change in changes:
            pdf = changed_pdf(fixture_pdf(1), change); plan = self.make_plan(pdf, 1)
            with self.assertRaises(self.m.PdfRasterWindowError):
                self.inspect(pdf_bytes=pdf, plan=plan, expected_plan_sha256=plan.plan_sha256)

    def test_excessive_page_geometry_rejected_before_native_raster(self):
        """Expected pixel admission precedes the native raster subprocess."""
        from pypdf.generic import NameObject, RectangleObject
        pdf = changed_pdf(fixture_pdf(1), lambda w: w.pages[0].__setitem__(
            NameObject("/MediaBox"), RectangleObject([0, 0, 10000, 10000])))
        identity = {**self.identity(), "pdf_sha256": digest(pdf), "page_count": 1,
                    "last_page": 1}
        with tempfile.TemporaryDirectory() as td, patch.object(self.w, "_raster_page", side_effect=AssertionError("native")):
            with self.assertRaises((ValueError, OverflowError)):
                self.w._inspect(pdf, identity, Path(td))

    def test_physical_page_count_mismatch_fails_native(self):
        """The parser measures final page count rather than trusting the plan alone."""
        plan = self.make_plan(self.pdf, 34)
        with self.assertRaises(self.m.PdfRasterWindowError):
            self.inspect(plan=plan, expected_plan_sha256=plan.plan_sha256)

    def test_malformed_and_encrypted_documents_fail_native(self):
        """Correct expected digests cannot authorize invalid or encrypted PDF contents."""
        for pdf in (b"%PDF-1.7\ninvalid", fixture_pdf(33, encrypted=True)):
            plan = self.make_plan(pdf, 33)
            with self.assertRaises(self.m.PdfRasterWindowError):
                self.inspect(pdf_bytes=pdf, plan=plan, expected_plan_sha256=plan.plan_sha256)

    def test_input_types_and_byte_budget_prevent_launch(self):
        """Mutable, invalid-header and oversized inputs fail before filesystem preparation."""
        with patch.object(self.m, "_run_worker", side_effect=AssertionError("launch")):
            for pdf in (bytearray(self.pdf), None, "%PDF-1.7", b"%PDF-1.6\n", b"%PDF-1.7" + b"x" * (8 * 1024 * 1024)):
                with self.assertRaises(self.m.PdfRasterWindowError): self.inspect(pdf_bytes=pdf)

    def test_foreign_digests_and_plan_profile_prevent_launch(self):
        """Only exact sealed PDF/IR/plan identities and the raster inspector are admitted."""
        other = self.make_plan(self.pdf, 33, profile="generated-pdf-text-window-v1")
        with patch.object(self.m, "_run_worker", side_effect=AssertionError("launch")):
            for args in ({"expected_plan_sha256": "f" * 64}, {"pdf_bytes": self.pdf + b"\n"},
                         {"plan": other, "expected_plan_sha256": other.plan_sha256}, {"plan": None}):
                with self.assertRaises(self.m.PdfRasterWindowError): self.inspect(**args)

    def test_page_and_window_budgets_and_indices_are_strict(self):
        """Document and per-window limits are enforced independently before launch."""
        with patch.object(self.m, "_run_worker", side_effect=AssertionError("launch")):
            for value in (True, -1, 9, 0.0, "0", None):
                with self.assertRaises(self.m.PdfRasterWindowError): self.inspect(window_index=value)
            for plan in (self.make_plan(self.pdf, 513), self.make_plan(self.pdf, 33, width=5)):
                with self.assertRaises(self.m.PdfRasterWindowError):
                    self.inspect(plan=plan, expected_plan_sha256=plan.plan_sha256)

    def test_mutated_plan_is_revalidated(self):
        """An illicit mutation of a frozen plan cannot reuse its earlier digest."""
        object.__setattr__(self.plan, "page_count", 34)
        with self.assertRaises(self.m.PdfRasterWindowError): self.inspect()

    def test_disabled_and_unsupported_platform_fail_before_io(self):
        """Disabled or unsupported execution has no permissive fallback."""
        with patch.object(self.m, "_run_worker", side_effect=AssertionError("launch")):
            with patch.dict(os.environ, {"OMNIGENIS_PDF_RASTER_WINDOWS_DISABLED": "1"}):
                with self.assertRaises(self.m.PdfRasterWindowError): self.inspect()
            with patch.object(self.m.sys, "platform", "unsupported"):
                with self.assertRaises(self.m.PdfRasterWindowError): self.inspect()

    def test_protocol_shapes_are_closed(self):
        """Root and nested protocol objects reject missing and unknown fields."""
        for location in (None, "identity", "limits", "inspection"):
            for unknown in (True, False):
                record = self.response(); obj = record if location is None else record[location]
                if unknown: obj["unexpected"] = 1
                else: obj.pop(next(iter(obj)))
                with self.assertRaises(self.m.PdfRasterWindowError): self.decode(record)

    def test_protocol_foreign_identities_rejected(self):
        """Evidence from another PDF, plan or physical interval cannot be reused."""
        for key in self.identity():
            record = self.response(); old = record["identity"][key]
            record["identity"][key] = "d" * 64 if isinstance(old, str) else old + 1
            with self.assertRaises(self.m.PdfRasterWindowError): self.decode(record)

    def test_protocol_versions_limits_and_status_are_exact(self):
        """Generic success or different resource limits cannot satisfy this wire contract."""
        for key, value in (("protocol_version", True), ("protocol_version", 2), ("profile_id", "other")):
            record = self.response(); record[key] = value
            with self.assertRaises(self.m.PdfRasterWindowError): self.decode(record)
        for key in self.m._LIMITS:
            record = self.response(); record["limits"][key] += 1
            with self.assertRaises(self.m.PdfRasterWindowError): self.decode(record)
        record = self.response(); record["inspection"]["status"] = "PASS"
        with self.assertRaises(self.m.PdfRasterWindowError): self.decode(record)

    def test_protocol_coverage_pixels_and_margin_are_consistent(self):
        """Truth-like, partial, excessive and contradictory geometry evidence is rejected."""
        for key, values in {
            "inspected_pages": [True, 0, 3, 5], "total_pixels": [True, 0, 10, 16000001],
            "min_edge_margin_px": [True, 0, 1, 1001], "raster_sha256": [None, "A" * 64, "x"],
        }.items():
            for value in values:
                record = self.response(); record["inspection"][key] = value
                with self.assertRaises(self.m.PdfRasterWindowError): self.decode(record)

    def test_protocol_duplicate_nonfinite_deep_and_oversize_rejected(self):
        """Malformed or oversized replies yield a fixed content-free diagnostic."""
        good = json.dumps(self.response()).encode()
        for raw in (b"", good[:-1] + b',"protocol_version":1}', good.replace(b'"total_pixels": 3566648', b'"total_pixels": NaN'),
                    b"[" * 2000 + b"]" * 2000, b"x" * 4097, b"\xff"):
            with self.assertRaises(self.m.PdfRasterWindowError): self.m._decode(raw, self.identity())

    def test_receipt_is_frozen_detached_and_unqualified(self):
        """Unsigned receipt metadata cannot claim global or semantic release authority."""
        result = self.decode(self.response()); copy = result.to_dict(); copy["total_pixels"] = 0
        self.assertGreater(result.total_pixels, 0)
        with self.assertRaises(FrozenInstanceError): result.page_count = 0
        for key in ("worker_results_authenticated", "whole_pdf_safety_qualified", "semantic_visual_equivalence_verified", "aggregate_job_resources_qualified", "release_authorized"):
            self.assertIs(result.to_dict()[key], False)
        self.assertEqual(result.to_dict()["release_authorization"], "NOT_ESTABLISHED")
        self.assertNotIn("pixels_bytes", result.to_dict())

    def test_direct_receipt_constructor_validates_counts(self):
        """Public constructors cannot bypass exact native scalar restrictions."""
        result = self.decode(self.response())
        for change in ({"total_pixels": True}, {"min_edge_margin_px": 1}, {"raster_sha256": "bad"}):
            with self.assertRaises(self.m.PdfRasterWindowError): replace(result, **change)

    def test_native_receipt_can_be_persisted_without_release(self):
        """Actual raster evidence composes with exact checkpoint storage and current head."""
        from reporting.page_checkpoints import PageWindowCheckpoint
        from reporting.checkpoint_files import CheckpointDirectoryIdentity
        from reporting.checkpoint_head import advance_checkpoint_head, load_current_checkpoint
        result = self.inspect()
        empty = PageWindowCheckpoint(self.plan, "synthetic-ns", "synthetic-job", "c" * 64, "d" * 64, ())
        partial = empty.append_observations((result.to_observation(),))
        with tempfile.TemporaryDirectory() as td:
            fd = os.open(td, os.O_RDONLY | os.O_DIRECTORY)
            try:
                st = os.fstat(fd)
                directory = CheckpointDirectoryIdentity(st.st_dev, st.st_ino, st.st_uid,
                    empty.namespace_id, empty.job_id, empty.request_sha256, empty.resource_profile_sha256)
                for checkpoint, previous in ((empty, None), (partial, empty.checkpoint_sha256)):
                    advance_checkpoint_head(directory_fd=fd, expected_directory=directory,
                        checkpoint=checkpoint, expected_checkpoint_sha256=checkpoint.checkpoint_sha256,
                        expected_previous_checkpoint_sha256=previous)
                restored = load_current_checkpoint(directory_fd=fd, expected_directory=directory,
                    expected_plan=self.plan, expected_checkpoint_sha256=partial.checkpoint_sha256)
                self.assertEqual(restored.to_bytes(), partial.to_bytes())
                self.assertEqual(restored.to_dict()["release_authorization"], "NOT_ESTABLISHED")
            finally: os.close(fd)

    def test_worker_guards_precede_request_read(self):
        """Either missing kernel guard prevents candidate bytes from being read."""
        for guard in ("enforce_pdf_landlock", "enforce_pdf_network_filter"):
            with self.protocol() as (request, result, fd, td), patch.dict(os.environ, {"TMPDIR": td}), \
                 patch.object(self.w, "_limits", return_value=dict(self.m._LIMITS)), \
                 patch.object(self.w, "_lifetime"), patch.object(self.w, "enforce_pdf_landlock"), \
                 patch.object(self.w, "enforce_pdf_network_filter"), \
                 patch.object(self.w, guard, side_effect=OSError("private")), \
                 patch.object(self.w, "_read_request", side_effect=AssertionError("read")):
                self.assertNotEqual(self.w.main(["worker", str(request.fileno()), str(result.fileno()), str(fd), str(os.getpid())]), 0)
                self.assertEqual(os.fstat(result.fileno()).st_size, 0)

    def test_scratch_identity_is_independently_pinned(self):
        """A different directory with valid permissions cannot replace the inherited pin."""
        with self.protocol() as (_, _, fd, td):
            with patch.dict(os.environ, {"TMPDIR": td}): self.assertEqual(self.w._open_scratch(fd), Path(td))
            with tempfile.TemporaryDirectory(prefix="omnigenis-pdf-visual-supervisor-", dir="/tmp") as other, patch.dict(os.environ, {"TMPDIR": other}):
                with self.assertRaises((ValueError, RuntimeError)): self.w._open_scratch(fd)

    def test_scratch_symlink_and_shared_mode_are_rejected(self):
        """Named scratch cannot be a symlink or group/world-accessible directory."""
        with self.protocol() as (_, _, fd, td), tempfile.TemporaryDirectory() as links:
            link = Path(links) / "link"; link.symlink_to(td)
            with patch.dict(os.environ, {"TMPDIR": str(link)}):
                with self.assertRaises((ValueError, RuntimeError)): self.w._open_scratch(fd)
            os.chmod(td, 0o755)
            try:
                with patch.dict(os.environ, {"TMPDIR": td}):
                    with self.assertRaises((ValueError, RuntimeError)): self.w._open_scratch(fd)
            finally: os.chmod(td, 0o700)

    def test_named_or_alias_protocol_fds_are_rejected(self):
        """The worker accepts only distinct anonymous request/result files plus a directory."""
        with self.protocol() as (request, result, fd, td), tempfile.NamedTemporaryFile() as named:
            for a, b in ((request.fileno(), request.fileno()), (named.fileno(), result.fileno())):
                self.assertNotEqual(self.w.main(["worker", str(a), str(b), str(fd), str(os.getpid())]), 0)

    def test_timeout_terminates_and_reaps_owned_worker(self):
        """A real stalled independent process is reaped after the supervisor timeout."""
        proc = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)"], start_new_session=True)
        with patch.object(self.m, "WALL_SECONDS", 0.05):
            with self.assertRaises(subprocess.TimeoutExpired): self.m._wait(proc)
        self.assertIsNotNone(proc.returncode)

    def test_native_failures_return_no_observation_or_private_details(self):
        """Underlying exceptions or missing replies cannot become successful raster metadata."""
        for failure in (OSError("private-system-detail"), ValueError("private-parser-detail")):
            with patch.object(self.m, "_run_worker", side_effect=failure):
                with self.assertRaises(self.m.PdfRasterWindowError) as caught: self.inspect()
                self.assertNotIn("private", str(caught.exception))
        with patch.object(self.m, "_run_worker", return_value=b""):
            with self.assertRaises(self.m.PdfRasterWindowError): self.inspect()

    def test_png_dimensions_are_checked_before_decode(self):
        """Unexpected dimensions are rejected before allocating decoded RGB pixels."""
        from PIL import Image
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "page.png"; Image.new("RGB", (20, 20), "black").save(path)
            with patch.object(Image.Image, "load", side_effect=AssertionError("pixel-decode")):
                with self.assertRaises(ValueError): self.w._read_raster(path, (30, 30))

    def test_png_symlinks_and_multiple_links_are_rejected(self):
        """Raster files must be regular, single-link owned outputs rather than redirected data."""
        from PIL import Image
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "page.png"; Image.new("RGB", (20, 20), "white").save(path)
            link = Path(td) / "other.png"; link.symlink_to(path)
            with self.assertRaises((ValueError, OSError)): self.w._read_raster(link, (20, 20))
            link.unlink(); os.link(path, link)
            with self.assertRaises(ValueError): self.w._read_raster(path, (20, 20))

    def test_png_encoded_size_is_bounded_before_image_open(self):
        """Oversized output cannot enter Pillow decoding."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "page.png"
            with path.open("wb") as f: f.truncate(16 * 1024 * 1024 + 1)
            with self.assertRaises(ValueError): self.w._read_raster(path, (20, 20))

    def test_repeat_native_calls_leave_parent_fds_unchanged(self):
        """Success and failed calls release every owned parent protocol descriptor."""
        before = len(os.listdir("/proc/self/fd"))
        self.inspect(window_index=8)
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_no_host_parser_or_native_protocol_fd_inheritance(self):
        """Parsing runs only in the isolated child and native raster inherits no protocol files."""
        import pypdf
        with patch.object(pypdf, "PdfReader", side_effect=AssertionError("host parser")):
            self.inspect(window_index=8)
        with tempfile.TemporaryDirectory() as td, patch.object(self.w.subprocess, "run", return_value=Mock(returncode=0)) as native:
            self.w._raster_page("/usr/bin/pdftoppm", Path(td) / "candidate.pdf", Path(td) / "page", 3)
            self.assertIs(native.call_args.kwargs["close_fds"], True)
            command = native.call_args.args[0]
            self.assertEqual(command[:2], [sys.executable, "-I"])
            self.assertEqual(Path(command[2]).name, "_pdf_raster_executor.py")
            self.assertEqual(command[3], str(os.getpid()))
            self.assertNotIn("pass_fds", native.call_args.kwargs)
            self.assertFalse(native.call_args.kwargs.get("shell", False))

    def test_legacy_default_whole_file_limit_is_preserved(self):
        """The new optional result does not override the previous whole-file policy."""
        from reporting._pdf_safety_worker import inspect_document, MAX_PAGES
        self.assertEqual(MAX_PAGES, 32)
        self.assertEqual(inspect_document(self.pdf)["status"], "BLOCKED")
        self.assertEqual(self.inspect(window_index=8).to_dict()["status"], "WINDOW_RASTER_INSPECTED")

    def test_manifest_pins_existing_executors_and_limits(self):
        """The new internal profile records exact existing versions and finite budgets."""
        manifest = json.loads((ROOT / "reporting/pdf-raster-window-engine.v1.json").read_text())
        legacy = json.loads((ROOT / "reporting/pdf-visual-engine.v1.json").read_text())
        self.assertEqual(manifest["profile_id"], ENGINE)
        self.assertEqual(manifest["binary_sha256"], legacy["binary_sha256"])
        self.assertEqual(manifest["package_version"], legacy["package_version"])
        self.assertEqual(manifest["resource_budget"]["document_pages"], 512)
        self.assertEqual(manifest["resource_budget"]["window_pages"], 4)
        for path, sha in manifest["reused_source_sha256"].items():
            self.assertEqual(digest((ROOT / path).read_bytes()), sha)
        self.assertFalse(manifest["default_pipeline_activated"])

    def test_all_changed_functions_have_docstrings(self):
        """Every new Python function has explicit documentation before external review."""
        for path in (ROOT / "reporting/pdf_raster_windows.py", ROOT / "reporting/_pdf_raster_window_worker.py", Path(__file__)):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.assertTrue(ast.get_docstring(node), f"{path.name}:{node.name}")


    def test_dense_graphical_window_is_inspected_without_text_claim(self):
        """A bounded dense vector fixture is rasterized without claiming text equivalence."""
        pdf = dense_fixture(); plan = self.make_plan(pdf, 4)
        result = self.inspect(pdf_bytes=pdf, plan=plan, expected_plan_sha256=plan.plan_sha256)
        self.assertEqual(result.inspected_pages, 4)
        self.assertFalse(result.to_dict()["semantic_visual_equivalence_verified"])

    def test_startup_environment_and_three_fds_are_closed(self):
        """Only explicit protocol/scratch descriptors and the narrow environment enter startup."""
        command = [sys.executable, "-I", "worker.py", "10", "11", "12", "100"]
        with patch.dict(os.environ, {"PYTHONPATH": "/untrusted-example"}), patch.object(self.m.subprocess, "Popen") as start:
            self.m._start(command, (10, 11, 12), "/tmp/synthetic-example")
        args, kwargs = start.call_args
        self.assertEqual(args[0], command)
        self.assertEqual(kwargs["pass_fds"], (10, 11, 12))
        self.assertEqual(set(kwargs["env"]), {"PATH", "LANG", "TMPDIR"})
        self.assertTrue(kwargs["close_fds"])
        self.assertTrue(kwargs["start_new_session"])
        self.assertIs(kwargs["shell"], False)

    def test_real_worker_rejects_invalid_parent(self):
        """A real isolated worker with an invalid parent cannot emit an inspection receipt."""
        with self.protocol() as (request, result, fd, td):
            identity = self.identity()
            header = " ".join(["1", *(str(identity[k]) for k in self.w.IDENTITY_FIELDS)])
            request.write(header.encode() + b"\n" + self.pdf); request.flush()
            child = subprocess.run([sys.executable, "-I", str(ROOT / "reporting/_pdf_raster_window_worker.py"),
                str(request.fileno()), str(result.fileno()), str(fd), "1"],
                pass_fds=(request.fileno(), result.fileno(), fd), close_fds=True,
                env={"PATH": os.defpath, "LANG": "C.UTF-8", "TMPDIR": td},
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            self.assertNotEqual(child.returncode, 0)
            self.assertEqual(os.fstat(result.fileno()).st_size, 0)

    def test_library_and_native_executor_pins_fail_closed(self):
        """A changed parser, image library or raster executable cannot reuse this profile."""
        with tempfile.TemporaryDirectory() as td:
            with patch.object(self.w, "version", return_value="unsupported"):
                with self.assertRaises(ValueError): self.w._inspect(self.pdf, self.identity(), Path(td))
            for identity in (("wrong", self.w.TOOL_SHA256, "/usr/bin/pdftoppm"),
                             (self.w.TOOL_VERSION, "0" * 64, "/usr/bin/pdftoppm")):
                with patch.object(self.w, "_tool_identity", return_value=identity), patch.object(self.w, "_raster_page", side_effect=AssertionError("raster")):
                    with self.assertRaises(ValueError): self.w._inspect(self.pdf, self.identity(), Path(td))

    def test_png_changed_during_decode_is_rejected(self):
        """Real raster-file mutation during pixel decoding cannot receive acknowledgment."""
        from PIL import Image
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "page.png"
            image = Image.new("RGB", (20, 20), "white"); image.putpixel((10, 10), (0, 0, 0)); image.save(path); image.close()
            original = Image.Image.convert
            def mutate(image, *args, **kwargs):
                """Append bytes after real conversion to simulate observed concurrent mutation."""
                result = original(image, *args, **kwargs)
                with path.open("ab") as f: f.write(b"mutation")
                return result
            with patch.object(Image.Image, "convert", mutate):
                with self.assertRaises(ValueError): self.w._read_raster(path, (20, 20))

    def test_native_raster_nonzero_and_timeout_are_failures(self):
        """Failed or timed-out native raster commands cannot be mistaken for PNG completion."""
        with tempfile.TemporaryDirectory() as td:
            source, prefix = Path(td) / "candidate.pdf", Path(td) / "page"
            with patch.object(self.w.subprocess, "run", return_value=Mock(returncode=2)):
                with self.assertRaises(ValueError): self.w._raster_page("pdftoppm", source, prefix, 1)
            with patch.object(self.w.subprocess, "run", side_effect=subprocess.TimeoutExpired("pdftoppm", 8)):
                with self.assertRaises(subprocess.TimeoutExpired): self.w._raster_page("pdftoppm", source, prefix, 1)

    def test_live_supervisor_cleans_owned_scratch_on_success_and_failure(self):
        """The live supervisor removes its own scratch after normal and failed native work."""
        original = self.m._start; paths = []
        def observed(command, fds, scratch):
            """Record only the synthetic scratch path while preserving actual process startup."""
            paths.append(scratch)
            return original(command, fds, scratch)
        before = len(os.listdir("/proc/self/fd"))
        with patch.object(self.m, "_start", observed):
            self.inspect(window_index=8)
            pdf = fixture_pdf(33, blank=4); plan = self.make_plan(pdf, 33)
            with self.assertRaises(self.m.PdfRasterWindowError):
                self.inspect(pdf_bytes=pdf, plan=plan, expected_plan_sha256=plan.plan_sha256)
        self.assertEqual(len(paths), 2)
        self.assertTrue(all(not Path(path).exists() for path in paths))
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)


if __name__ == "__main__":
    unittest.main()
