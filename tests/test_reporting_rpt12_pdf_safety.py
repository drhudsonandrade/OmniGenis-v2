"""Synthetic contract tests for the passive-report PDF object policy."""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import FrozenInstanceError
import errno
import hashlib
import importlib
import importlib.util
from io import BytesIO
import json
import os
import signal
import subprocess
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from pypdf import PdfReader, PdfWriter
from pypdf.generic import (
    ArrayObject, DictionaryObject, NameObject, NullObject, NumberObject,
    TextStringObject, DecodedStreamObject, IndirectObject,
)
from reporting import pdf_safety
from reporting.adapters import build_html_css_and_pdf_adapter


def digest(data: bytes) -> str:
    """Bind a synthetic candidate to its exact bytes."""
    return hashlib.sha256(data).hexdigest()


def source_ir() -> dict:
    """Return inert localized report text with no personal or genomic data."""
    return {"report_id": "synthetic-passive-report", "locale_id": "en-US", "components": [
        {"component_id": "summary", "component_type": "semantic-section", "title": "Summary",
         "state": "PRESENT", "content": {"text": "SYNTHETIC-ONLY"}},
    ]}


def render(ir: dict) -> bytes:
    """Obtain real candidate bytes through the existing public adapter."""
    result = build_html_css_and_pdf_adapter(presentation_ir=ir)
    if not result.passed:
        raise AssertionError(result.errors)
    return result.pdf_bytes


def serialized(writer: PdfWriter) -> bytes:
    """Serialize a generated fixture in memory, without opening its actions."""
    stream = BytesIO()
    writer.write(stream)
    return stream.getvalue()


def blank(*, pages: int = 1, encrypted: bool = False) -> bytes:
    """Create a structural fixture independently of the production renderer."""
    writer = PdfWriter()
    for _ in range(pages):
        writer.add_blank_page(width=612, height=792)
    if encrypted:
        writer.encrypt("synthetic-test-only")
    return serialized(writer)


class PdfObjectSafetyTests(unittest.TestCase):
    """Check policy decisions against real direct and indirect PDF objects."""

    @classmethod
    def setUpClass(cls):
        """Render a passive baseline once; no mutated PDF is displayed or executed."""
        cls.pdf = render(source_ir())

    def setUp(self):
        """Expose a missing implementation as an explicit contract failure."""
        self.assertIsNotNone(importlib.util.find_spec("reporting.pdf_safety"),
                             "Passive PDF object policy is not implemented")
        self.module = importlib.import_module("reporting.pdf_safety")

    def check(self, pdf=None, **overrides):
        """Run the real resource-limited worker with a fresh candidate identity."""
        data = self.pdf if pdf is None else pdf
        args = {"pdf_bytes": data, "expected_pdf_sha256": digest(data)}
        args.update(overrides)
        return self.module.validate_pdf_object_safety(**args)

    def writer(self):
        """Clone only the synthetic passive baseline for negative mutations."""
        writer = PdfWriter()
        writer.clone_document_from_reader(PdfReader(BytesIO(self.pdf), strict=True))
        return writer

    def test_real_candidate_passes_with_content_free_bound_evidence(self):
        """A passive report yields bounded evidence, never a release authorization."""
        result = self.check()
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(result.pdf_sha256, digest(self.pdf))
        self.assertGreater(result.object_count, 0)
        self.assertEqual(result.page_count, 1)
        record = result.to_dict()
        self.assertEqual(record["policy_id"], "passive-report-pdf-v1")
        self.assertEqual(record["conformance_scope"], "REACHABLE_PDF_OBJECT_POLICY_ONLY")
        self.assertEqual(record["release_authorization"], "NOT_ESTABLISHED")
        self.assertNotIn("SYNTHETIC-ONLY", json.dumps(record))
        self.assertEqual(record, self.check().to_dict())

    def test_existing_canonical_pipeline_remains_passive(self):
        """Compiler, localized model, outline and tagged output satisfy this profile."""
        from tests.test_reporting_rpt08_html_pdf_conformance import Rpt08HtmlPdfConformanceTests
        scenario = Rpt08HtmlPdfConformanceTests(); scenario.setUp()
        result = self.check(render(scenario.presentation))
        self.assertTrue(result.passed, result.errors)

    def test_action_keys_fail_even_when_empty_or_indirect(self):
        """Conservative action exclusions depend on object keys, not payload truthiness."""
        for key in ("/OpenAction", "/AA", "/A", "/JS", "/JavaScript"):
            for indirect in (False, True):
                with self.subTest(key=key, indirect=indirect):
                    writer = self.writer()
                    value = NullObject()
                    writer.root_object[NameObject(key)] = writer._add_object(value) if indirect else value
                    result = self.check(serialized(writer))
                    self.assertFalse(result.passed)
                    self.assertIn("pdf_actions_forbidden", result.errors)

    def test_nested_page_and_unknown_actions_are_blocked(self):
        """Unknown actions and additional page actions cannot hide in nested arrays."""
        for subtype in ("/JavaScript", "/Launch", "/URI", "/GoToR", "/UnknownAction"):
            with self.subTest(subtype=subtype):
                writer = self.writer()
                action = DictionaryObject({NameObject("/S"): NameObject(subtype)})
                annotation = DictionaryObject({NameObject("/Type"): NameObject("/Annot"),
                    NameObject("/Subtype"): NameObject("/Link"), NameObject("/A"): writer._add_object(action)})
                writer.pages[0][NameObject("/Annots")] = ArrayObject([writer._add_object(annotation)])
                result = self.check(serialized(writer))
                self.assertFalse(result.passed)
                self.assertIn("pdf_actions_forbidden", result.errors)

    def test_javascript_name_tree_is_detected(self):
        """The dependency's real JavaScript-name-tree encoding is rejected."""
        from pypdf.actions import JavaScript
        writer = self.writer(); writer.add_open_action(JavaScript("void 0;"))
        result = self.check(serialized(writer))
        self.assertFalse(result.passed)
        self.assertIn("pdf_actions_forbidden", result.errors)

    def test_attachments_and_associated_file_relationships_are_blocked(self):
        """Real attachments and empty associated-file declarations fail closed."""
        writer = self.writer(); writer.add_attachment("synthetic.bin", b"fixture")
        self.assertIn("pdf_embedded_files_forbidden", self.check(serialized(writer)).errors)
        for key in ("/AF", "/EF", "/EmbeddedFiles"):
            with self.subTest(key=key):
                writer = self.writer(); writer.pages[0][NameObject(key)] = ArrayObject()
                self.assertIn("pdf_embedded_files_forbidden", self.check(serialized(writer)).errors)

    def test_forms_and_interactive_media_are_blocked(self):
        """Empty form declarations and media annotations remain outside the profile."""
        for key in ("/AcroForm", "/XFA"):
            with self.subTest(key=key):
                writer = self.writer(); writer.root_object[NameObject(key)] = DictionaryObject()
                self.assertIn("pdf_forms_forbidden", self.check(serialized(writer)).errors)
        for subtype in ("/RichMedia", "/Screen", "/Movie", "/Sound", "/3D", "/Widget", "/FileAttachment"):
            with self.subTest(subtype=subtype):
                writer = self.writer()
                annot = DictionaryObject({NameObject("/Type"): NameObject("/Annot"), NameObject("/Subtype"): NameObject(subtype)})
                writer.pages[0][NameObject("/Annots")] = ArrayObject([writer._add_object(annot)])
                self.assertFalse(self.check(serialized(writer)).passed)

    def test_external_stream_is_rejected_without_loading_it(self):
        """A stream backed by an external file is rejected from its dictionary alone."""
        writer = self.writer(); stream = DecodedStreamObject(); stream.set_data(b"q Q")
        stream[NameObject("/F")] = TextStringObject("https://example.invalid/synthetic")
        writer.pages[0][NameObject("/Contents")] = writer._add_object(stream)
        result = self.check(serialized(writer))
        self.assertFalse(result.passed)
        self.assertIn("pdf_external_stream_forbidden", result.errors)
        self.assertNotIn("example.invalid", json.dumps(result.to_dict()))

    def test_plain_report_text_is_not_mistaken_for_an_action(self):
        """Action names appearing in the rendered text have no execution semantics."""
        ir = source_ir(); ir["components"][0]["content"]["text"] = "/JS /JavaScript /OpenAction /A are plain words"
        result = self.check(render(ir))
        self.assertTrue(result.passed, result.errors)

    def test_shared_cycles_terminate_and_do_not_hide_actions(self):
        """Reused references terminate while every reachable dictionary is inspected."""
        for hazardous in (False, True):
            with self.subTest(hazardous=hazardous):
                writer = self.writer(); node = DictionaryObject(); ref = writer._add_object(node)
                node[NameObject("/Cycle")] = ref
                if hazardous:
                    node[NameObject("/AA")] = DictionaryObject()
                writer.root_object[NameObject("/SyntheticGraph")] = ArrayObject([ref, ref])
                result = self.check(serialized(writer))
                self.assertEqual(result.passed, not hazardous, result.errors)

    def test_missing_reference_and_malformed_discriminators_fail(self):
        """Broken references and non-name dictionary types cannot look like a pass."""
        writer = self.writer()
        writer.root_object[NameObject("/SyntheticGraph")] = IndirectObject(999999, 0, writer)
        self.assertFalse(self.check(serialized(writer)).passed)
        writer = self.writer()
        writer.root_object[NameObject("/Type")] = TextStringObject("/Catalog")
        self.assertFalse(self.check(serialized(writer)).passed)

    def test_bad_identity_blocks_before_worker(self):
        """Only the exact canonical candidate digest can authorize inspection."""
        for expected, error in (("0" * 64, "pdf_digest_mismatch"), (None, "expected_pdf_digest_invalid"),
                                ("G" * 64, "expected_pdf_digest_invalid")):
            with self.subTest(expected=expected), patch.object(self.module, "_run_worker") as child:
                result = self.check(expected_pdf_sha256=expected)
                self.assertFalse(result.passed)
                self.assertIn(error, result.errors)
                child.assert_not_called()

    def test_malformed_encrypted_and_zero_page_candidates_are_blocked(self):
        """Structural failures are not counted as a passive-object attestation."""
        for pdf in (b"%PDF-1.7\nbroken", blank(pages=0), blank(encrypted=True)):
            with self.subTest(length=len(pdf)):
                self.assertFalse(self.check(pdf).passed)

    def test_byte_page_graph_and_depth_budgets_fail_closed(self):
        """A resource limit produces BLOCKED rather than an incomplete clean scan."""
        from reporting import _pdf_safety_worker as worker
        candidates = [b"%PDF-1.7\n" + b"0" * worker.MAX_PDF_BYTES, blank(pages=worker.MAX_PAGES + 1)]
        writer = self.writer()
        writer.root_object[NameObject("/SyntheticGraph")] = ArrayObject([NumberObject(i) for i in range(worker.MAX_VISITS + 1)])
        candidates.append(serialized(writer))
        writer = self.writer(); node = DictionaryObject()
        for _ in range(worker.MAX_DEPTH + 1):
            node = DictionaryObject({NameObject("/Child"): writer._add_object(node)})
        writer.root_object[NameObject("/SyntheticGraph")] = writer._add_object(node)
        candidates.append(serialized(writer))
        for pdf in candidates:
            with self.subTest(size=len(pdf)):
                result = self.check(pdf)
                self.assertFalse(result.passed)
                self.assertIn("pdf_safety_budget_exceeded", result.errors)

    def test_worker_failures_are_not_success(self):
        """Timeout, process failure and malformed replies cannot produce PASS."""
        for exc in (OSError("synthetic"), subprocess.TimeoutExpired("synthetic", 10)):
            with self.subTest(kind=type(exc).__name__), patch.object(self.module, "_run_worker", side_effect=exc):
                self.assertFalse(self.check().passed)
        for code, data in ((-9, b""), (0, b"not JSON"), (0, b'{"status":"PASS"}'), (0, b"x" * 4097)):
            with self.subTest(code=code, length=len(data)), patch.object(self.module, "_run_worker", return_value=subprocess.CompletedProcess([], code, data)):
                self.assertFalse(self.check().passed)

    def test_worker_success_requires_exact_identity_and_integer_counts(self):
        """A claimed worker success must satisfy the complete bounded protocol."""
        template = {"status": "PASS", "pdf_sha256": digest(self.pdf), "page_count": 1, "object_count": 10, "errors": []}
        changes = ({"pdf_sha256": "0" * 64}, {"page_count": True}, {"object_count": 0},
                   {"status": "SKIPPED"}, {"errors": ["unknown"]}, {"extra": "unexpected"})
        for change in changes:
            with self.subTest(change=change):
                record = {**template, **change}
                with patch.object(self.module, "_run_worker", return_value=subprocess.CompletedProcess([], 0, json.dumps(record).encode())):
                    result = self.check()
                self.assertFalse(result.passed)
                self.assertIn("pdf_safety_worker_invalid_response", result.errors)

    def test_public_evidence_is_immutable_and_needs_success_proof(self):
        """The public constructor rejects incomplete success-looking evidence."""
        with self.assertRaises(ValueError):
            self.module.PdfSafetyValidation(None, None, None, ())
        result = self.check(); self.assertTrue(result.passed, result.errors)
        with self.assertRaises(FrozenInstanceError):
            result.page_count = 50
        data = result.to_dict(); data["errors"].append("mutated")
        self.assertEqual(result.errors, ())

    def test_extractor_version_is_pinned(self):
        """An unactivated parser version cannot yield a policy pass."""
        from reporting import _pdf_safety_worker as worker
        with patch.object(worker, "version", return_value="0.0.0"):
            result = worker.inspect_document(self.pdf)
        self.assertEqual(result["errors"], ["pdf_safety_parser_version_mismatch"])


_SAFETY_REAL_POPEN = subprocess.Popen
_SAFETY_REAL_KILL = os.kill
_SAFETY_REAL_WAITID = getattr(os, "waitid", None)
_SAFETY_REAL_WAITPID = os.waitpid
_SAFETY_WAIT_FLAGS = (getattr(os, "WEXITED", 0) | getattr(os, "WNOHANG", 0)
                      | getattr(os, "WNOWAIT", 0))


def _safety_response(pdf, *, blocked=False, size=None):
    """Build content-free synthetic protocol bytes at a chosen byte boundary."""
    record = {
        "status": "BLOCKED" if blocked else "PASS",
        "pdf_sha256": None if blocked else hashlib.sha256(pdf).hexdigest(),
        "page_count": None if blocked else 1,
        "object_count": None if blocked else 10,
        "errors": ["pdf_safety_worker_unavailable"] if blocked else [],
    }
    response = json.dumps(record, sort_keys=True).encode("ascii") + b"\n"
    if size is not None:
        if len(response) > size:
            raise AssertionError("synthetic safety response exceeds requested size")
        response = response.ljust(size, b" ")
    return response


def _safety_emit_script(response, *, exit_code=0):
    """Drain synthetic input and emit the chosen bytes before a literal exit."""
    return (
        "import os,sys\n"
        "sys.stdin.buffer.read()\n"
        "sys.stdout.buffer.write(" + repr(response) + ")\n"
        "sys.stdout.buffer.flush()\n"
        "os._exit(" + str(exit_code) + ")\n"
    )


def _safety_owned_stream(probe, name, descriptor):
    """Match only the current open pipe, excluding Popen's startup error pipe."""
    if probe.process is None:
        return False
    stream = getattr(probe.process, name)
    return stream is not None and not stream.closed and descriptor == stream.fileno()


@contextmanager
def _safety_child_probe(script, *, wall_seconds=2, after_launch=None):
    """Substitute one disposable direct child and forbid all process-group signals.

    The safety launcher retains its existing inherited process group. The test
    therefore never forwards killpg. Numeric direct signals are forwarded only
    while the real kernel still recognizes the fixture's owned child. A pidfd
    provides independent cleanup after either product failure or assertion.
    """
    probe = SimpleNamespace(process=None, pidfd=None, signals=[], group_signals=[],
                            command=None, launch_options=None)

    def launch(command, *args, **kwargs):
        """Preserve launch options while replacing only the executable fixture."""
        if probe.process is not None:
            raise AssertionError("safety fixture expected exactly one direct child")
        if kwargs.get("start_new_session", False):
            raise AssertionError("safety transport cannot create a new session")
        if kwargs.get("process_group", -1) not in (-1, None):
            raise AssertionError("safety transport cannot change its process group")
        probe.command = command
        probe.launch_options = dict(kwargs)
        process = _SAFETY_REAL_POPEN(
            [sys.executable, "-I", "-B", "-c", script], *args, **kwargs
        )
        probe.process = process
        probe.pidfd = os.pidfd_open(process.pid)
        if after_launch is not None:
            after_launch(probe)
        return process

    def direct_signal(identifier, signum):
        """Suppress any numeric signal after the fixture loses child ownership."""
        if probe.process is None or identifier != probe.process.pid:
            raise AssertionError("numeric signal does not target the owned safety child")
        try:
            _SAFETY_REAL_WAITID(os.P_PID, identifier, _SAFETY_WAIT_FLAGS)
        except ChildProcessError:
            probe.signals.append(False)
            return
        probe.signals.append(True)
        return _SAFETY_REAL_KILL(identifier, signum)

    def group_signal(identifier, signum):
        """Never allow a fixture to signal the caller's inherited process group."""
        probe.group_signals.append((identifier, signum))
        raise AssertionError("safety transport must not signal any process group")

    try:
        with patch.object(pdf_safety.subprocess, "Popen", side_effect=launch), \
             patch.object(pdf_safety, "WALL_SECONDS", wall_seconds), \
             patch.object(os, "kill", side_effect=direct_signal), \
             patch.object(os, "killpg", side_effect=group_signal):
            yield probe
    finally:
        try:
            if probe.pidfd is not None:
                try:
                    signal.pidfd_send_signal(probe.pidfd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if probe.process is not None:
                probe.process.wait(timeout=3)
        finally:
            if probe.pidfd is not None:
                os.close(probe.pidfd)
            if probe.process is not None:
                for stream in (probe.process.stdin, probe.process.stdout, probe.process.stderr):
                    if stream is not None:
                        stream.close()


@unittest.skipUnless(
    sys.platform == "linux" and hasattr(os, "pidfd_open")
    and hasattr(signal, "pidfd_send_signal"), "Linux pidfd required"
)
class SafetyWorkerTransportTests(unittest.TestCase):
    """Exercise the existing public safety contract through real bounded pipes."""

    pdf = b"%PDF-SYNTHETIC-SAFETY-TRANSPORT"

    def validate(self, pdf=None):
        """Call only the established public API with exact synthetic identity."""
        data = self.pdf if pdf is None else pdf
        return pdf_safety.validate_pdf_object_safety(
            pdf_bytes=data, expected_pdf_sha256=hashlib.sha256(data).hexdigest()
        )

    def assert_retired(self, probe):
        """Require product reap before fixture cleanup without any group signal."""
        self.assertIsNotNone(probe.process)
        self.assertEqual(probe.group_signals, [])
        self.assertTrue(all(probe.signals), probe.signals)
        with self.assertRaises(ChildProcessError):
            _SAFETY_REAL_WAITID(os.P_PID, probe.process.pid, _SAFETY_WAIT_FLAGS)

    def assert_refusal(self, result, error):
        """Reject partial counts and private exception details on every failure."""
        self.assertEqual(result.errors, (error,))
        self.assertFalse(result.passed)
        self.assertIsNone(result.page_count)
        self.assertIsNone(result.object_count)
        self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(result.to_dict()))

    def test_exact_response_budget_preserves_existing_success_protocol(self):
        """Exactly 4096 bytes is accepted without altering the direct-child launch."""
        response = _safety_response(self.pdf, size=4096)
        with _safety_child_probe(_safety_emit_script(response)) as probe:
            result = self.validate()
            self.assertTrue(result.passed, result.errors)
            self.assertEqual((result.page_count, result.object_count), (1, 10))
            self.assertEqual(probe.command, [
                sys.executable, "-I", str(pdf_safety._WORKER), str(os.getpid())
            ])
            self.assertEqual(probe.launch_options.get("stderr"), subprocess.DEVNULL)
            self.assert_retired(probe)

    def test_one_overflow_byte_refuses_an_otherwise_valid_response(self):
        """A JSON value plus padding cannot exceed the existing 4096-byte cap."""
        response = _safety_response(self.pdf, size=4097)
        with _safety_child_probe(_safety_emit_script(response)) as probe:
            self.assert_refusal(self.validate(), "pdf_safety_worker_invalid_response")
            self.assert_retired(probe)

    def test_overflow_is_refused_before_a_live_writer_closes_stdout(self):
        """A 4097-byte live response is a protocol failure rather than a timeout."""
        response = _safety_response(self.pdf, size=4097)
        script = (
            "import sys,time\n"
            "sys.stdout.buffer.write(" + repr(response) + ")\n"
            "sys.stdout.buffer.flush()\n"
            "time.sleep(30)\n"
        )
        with _safety_child_probe(script, wall_seconds=0.3) as probe:
            started = time.monotonic()
            self.assert_refusal(self.validate(), "pdf_safety_worker_invalid_response")
            self.assertLess(time.monotonic() - started, 2.5)
            self.assert_retired(probe)

    def test_parent_collects_at_most_one_overflow_byte(self):
        """A controlled larger response must not first accumulate in the parent."""
        real_read = os.read
        response = _safety_response(self.pdf, size=65536)
        with _safety_child_probe(_safety_emit_script(response)) as probe:
            collected = []

            def read(descriptor, count):
                """Count real stdout bytes only, preserving all other reads."""
                owned = _safety_owned_stream(probe, "stdout", descriptor)
                data = real_read(descriptor, count)
                if owned:
                    collected.append(len(data))
                return data

            with patch.object(os, "read", side_effect=read):
                result = self.validate()
            self.assert_refusal(result, "pdf_safety_worker_invalid_response")
            self.assertTrue(collected, "fixture did not observe any stdout collection")
            self.assertEqual(sum(collected), 4097)
            self.assert_retired(probe)

    def test_duplex_overflow_does_not_wait_for_large_input_consumption(self):
        """A full 4096-byte output pipe cannot strand a simultaneous input write."""
        pdf = b"%PDF-" + b"D" * (1024 * 1024 - 5)
        response = _safety_response(pdf, size=4097)
        script = (
            "import fcntl,sys,time\n"
            "fcntl.fcntl(1,fcntl.F_SETPIPE_SZ,4096)\n"
            "sys.stdout.buffer.write(" + repr(response) + ")\n"
            "sys.stdout.buffer.flush()\n"
            "time.sleep(30)\n"
        )
        with _safety_child_probe(script, wall_seconds=0.3) as probe:
            self.assert_refusal(self.validate(pdf), "pdf_safety_worker_invalid_response")
            self.assert_retired(probe)

    def test_response_before_complete_input_preserves_all_input_bytes(self):
        """Successful duplex exchange still delivers the full exact input."""
        pdf = b"%PDF-" + b"I" * (1024 * 1024 - 5)
        response = _safety_response(pdf, size=4096)
        script = (
            "import hashlib,os,sys\n"
            "sys.stdout.buffer.write(" + repr(response) + ")\n"
            "sys.stdout.buffer.flush()\n"
            "data=sys.stdin.buffer.read()\n"
            "os._exit(0 if hashlib.sha256(data).hexdigest()=="
            + repr(hashlib.sha256(pdf).hexdigest()) + " else 7)\n"
        )
        with _safety_child_probe(script) as probe:
            result = self.validate(pdf)
            self.assertTrue(result.passed, result.errors)
            self.assert_retired(probe)

    def test_unread_stdin_has_a_finite_timeout_and_direct_child_cleanup(self):
        """Maximum admitted input cannot leave a blocked producer waiting forever."""
        pdf = b"%PDF-" + b"T" * (8 * 1024 * 1024 - 5)
        with _safety_child_probe("import time;time.sleep(30)", wall_seconds=0.2) as probe:
            started = time.monotonic()
            self.assert_refusal(self.validate(pdf), "pdf_safety_worker_timeout")
            self.assertLess(time.monotonic() - started, 2.5)
            self.assert_retired(probe)

    def test_stdout_eof_does_not_accept_a_still_running_worker(self):
        """The parent must observe actual exit after response EOF."""
        script = "import os,time\nos.close(1)\ntime.sleep(30)\n"
        with _safety_child_probe(script, wall_seconds=0.2) as probe:
            self.assert_refusal(self.validate(), "pdf_safety_worker_timeout")
            self.assert_retired(probe)

    def test_early_blocked_response_survives_input_broken_pipe(self):
        """A worker refusing input admission may close stdin and return BLOCKED."""
        pdf = b"%PDF-" + b"B" * (1024 * 1024 - 5)
        response = _safety_response(pdf, blocked=True)
        script = (
            "import os,sys\nos.close(0)\n"
            "sys.stdout.buffer.write(" + repr(response) + ")\n"
            "sys.stdout.buffer.flush()\n"
        )
        with _safety_child_probe(script) as probe:
            self.assert_refusal(self.validate(pdf), "pdf_safety_worker_unavailable")
            self.assert_retired(probe)

    def test_success_looking_response_cannot_hide_nonzero_exit(self):
        """Complete response fields do not replace successful worker execution."""
        script = _safety_emit_script(_safety_response(self.pdf), exit_code=7)
        with _safety_child_probe(script) as probe:
            self.assert_refusal(self.validate(), "pdf_safety_worker_failed")
            self.assert_retired(probe)

    def test_empty_malformed_and_truncated_responses_remain_invalid(self):
        """Malformed responses within the byte budget retain protocol refusal."""
        for response in (b"", b"not-json", b'{"status":"PASS"', b'{"status":"PASS"}'):
            with self.subTest(response=response), _safety_child_probe(
                _safety_emit_script(response)
            ) as probe:
                self.assert_refusal(self.validate(), "pdf_safety_worker_invalid_response")
                self.assert_retired(probe)

    def test_fragmented_response_preserves_public_evidence(self):
        """Transport read boundaries cannot alter the complete JSON response."""
        response = _safety_response(self.pdf)
        script = (
            "import os,sys\nsys.stdin.buffer.read()\n"
            "data=" + repr(response) + "\n"
            "for offset in range(0,len(data),7):\n"
            "    os.write(1,data[offset:offset+7])\n"
        )
        with _safety_child_probe(script) as probe:
            result = self.validate()
            self.assertTrue(result.passed, result.errors)
            self.assertEqual((result.page_count, result.object_count), (1, 10))
            self.assert_retired(probe)

    def test_short_writes_and_temporary_not_ready_reads_are_retried(self):
        """Nonblocking readiness changes preserve exact input and output bytes."""
        pdf = b"%PDF-" + b"P" * (65536 - 5)
        response = _safety_response(pdf)
        script = (
            "import hashlib,os,sys\n"
            "data=sys.stdin.buffer.read()\n"
            "if hashlib.sha256(data).hexdigest()!="
            + repr(hashlib.sha256(pdf).hexdigest()) + ":os._exit(7)\n"
            "sys.stdout.buffer.write(" + repr(response) + ")\n"
            "sys.stdout.buffer.flush()\n"
        )
        real_read, real_write = os.read, os.write
        with _safety_child_probe(script) as probe:
            injected = {"write_not_ready": False, "short_write": False, "read_not_ready": False}

            def write(descriptor, data):
                """Inject one would-block and one real partial input write."""
                if _safety_owned_stream(probe, "stdin", descriptor):
                    if not injected["write_not_ready"]:
                        injected["write_not_ready"] = True
                        raise BlockingIOError(errno.EAGAIN, "synthetic readiness change")
                    if not injected["short_write"]:
                        injected["short_write"] = True
                        return real_write(descriptor, data[:7])
                return real_write(descriptor, data)

            def read(descriptor, count):
                """Inject one would-block only after the owned output is readable."""
                if (_safety_owned_stream(probe, "stdout", descriptor)
                        and not injected["read_not_ready"]):
                    injected["read_not_ready"] = True
                    raise BlockingIOError(errno.EAGAIN, "synthetic readiness change")
                return real_read(descriptor, count)

            with patch.object(os, "write", side_effect=write), \
                 patch.object(os, "read", side_effect=read):
                result = self.validate(pdf)
            self.assertTrue(result.passed, result.errors)
            self.assertTrue(all(injected.values()), injected)
            self.assert_retired(probe)

    def test_cancellation_during_pipe_read_preserves_exception_and_cleans_child(self):
        """Cancellation remains primary after terminating the direct child."""
        real_read = os.read
        for cancellation in (KeyboardInterrupt("SYNTHETIC"), SystemExit(13)):
            with self.subTest(kind=type(cancellation).__name__), _safety_child_probe(
                "import os,time\nos.write(1,b'x')\ntime.sleep(30)\n"
            ) as probe:
                injected = []

                def read(descriptor, count):
                    """Deliver the original cancellation once at the owned stdout."""
                    if not injected and _safety_owned_stream(probe, "stdout", descriptor):
                        injected.append(True)
                        raise cancellation
                    return real_read(descriptor, count)

                with patch.object(os, "read", side_effect=read):
                    with self.assertRaises(type(cancellation)) as caught:
                        self.validate()
                self.assertIs(caught.exception, cancellation)
                self.assertEqual(injected, [True])
                self.assert_retired(probe)

    def test_cancellation_at_first_postlaunch_clock_cleans_owned_child(self):
        """The first post-launch deadline calculation is covered by cleanup."""
        real_clock = time.monotonic
        for cancellation in (KeyboardInterrupt("SYNTHETIC"), SystemExit(13)):
            with self.subTest(kind=type(cancellation).__name__), _safety_child_probe(
                "import time;time.sleep(30)", wall_seconds=0.2
            ) as probe:
                injected = []

                def clock():
                    """Inject once after Popen returned a captured test child."""
                    if not injected and probe.process is not None:
                        injected.append(True)
                        raise cancellation
                    return real_clock()

                with patch.object(time, "monotonic", side_effect=clock):
                    with self.assertRaises(type(cancellation)) as caught:
                        self.validate()
                self.assertIs(caught.exception, cancellation)
                self.assertEqual(injected, [True])
                self.assert_retired(probe)

    def test_pipe_setup_failure_is_sanitized_after_direct_child_cleanup(self):
        """A configuration failure after launch preserves the unavailable result."""
        real_set_blocking = os.set_blocking
        with _safety_child_probe("import time;time.sleep(30)", wall_seconds=0.2) as probe:
            injected = []

            def configure(descriptor, blocking):
                """Fail the first configuration of either owned transport pipe."""
                if (not injected and (_safety_owned_stream(probe, "stdin", descriptor)
                                      or _safety_owned_stream(probe, "stdout", descriptor))):
                    injected.append(True)
                    raise OSError(errno.EIO, "SYNTHETIC_PRIVATE_SETUP")
                return real_set_blocking(descriptor, blocking)

            with patch.object(os, "set_blocking", side_effect=configure):
                result = self.validate()
            self.assertEqual(injected, [True])
            self.assert_refusal(result, "pdf_safety_worker_unavailable")
            self.assert_retired(probe)

    def test_pipe_read_error_is_sanitized_after_direct_child_cleanup(self):
        """Unexpected read errors cannot leak details or leave the child running."""
        real_read = os.read
        with _safety_child_probe("import os,time\nos.write(1,b'x')\ntime.sleep(30)\n") as probe:
            injected = []

            def read(descriptor, count):
                """Raise one synthetic I/O error from the owned output descriptor."""
                if not injected and _safety_owned_stream(probe, "stdout", descriptor):
                    injected.append(True)
                    raise OSError(errno.EIO, "SYNTHETIC_PRIVATE_READ")
                return real_read(descriptor, count)

            with patch.object(os, "read", side_effect=read):
                result = self.validate()
            self.assertEqual(injected, [True])
            self.assert_refusal(result, "pdf_safety_worker_unavailable")
            self.assert_retired(probe)

    def test_pipe_write_error_is_sanitized_after_direct_child_cleanup(self):
        """Unexpected write errors retain the original unavailable error mapping."""
        real_write = os.write
        with _safety_child_probe("import time;time.sleep(30)") as probe:
            injected = []

            def write(descriptor, data):
                """Raise one synthetic I/O error from the owned input descriptor."""
                if not injected and _safety_owned_stream(probe, "stdin", descriptor):
                    injected.append(True)
                    raise OSError(errno.EIO, "SYNTHETIC_PRIVATE_WRITE")
                return real_write(descriptor, data)

            with patch.object(os, "write", side_effect=write):
                result = self.validate()
            self.assertEqual(injected, [True])
            self.assert_refusal(result, "pdf_safety_worker_unavailable")
            self.assert_retired(probe)

    def test_external_reap_refuses_success_without_retrying_a_signal(self):
        """A valid response cannot attest success after genuine ownership loss."""
        response = _safety_response(self.pdf)
        script = (
            "import os,sys\n"
            "sys.stdout.buffer.write(" + repr(response) + ")\n"
            "sys.stdout.buffer.flush()\n"
            "os._exit(0)\n"
        )

        def reap_before_return(probe):
            """Reap a waitable child without updating Popen's cached return code."""
            deadline = time.monotonic() + 2
            while _SAFETY_REAL_WAITID(os.P_PID, probe.process.pid, _SAFETY_WAIT_FLAGS) is None:
                if time.monotonic() >= deadline:
                    self.fail("synthetic worker did not exit before external-reap deadline")
                time.sleep(0.005)
            pid, status = _SAFETY_REAL_WAITPID(probe.process.pid, os.WNOHANG)
            self.assertEqual(pid, probe.process.pid)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            self.assertIsNone(probe.process.returncode)
            probe.kill_attempt = injected.enter_context(patch.object(probe.process, "kill"))

        with _safety_child_probe(script, after_launch=reap_before_return) as probe, \
             ExitStack() as injected:
            self.assert_refusal(self.validate(), "pdf_safety_worker_unavailable")
            probe.kill_attempt.assert_not_called()
            self.assertEqual(probe.signals, [])
            self.assertIsNone(probe.process.returncode)
            self.assert_retired(probe)

    def test_direct_kill_failure_still_attempts_finite_reap(self):
        """A failed signal must retain the primary refusal and independently reap."""
        response = _safety_response(self.pdf, size=4097)
        script = (
            "import os,sys,time\n"
            "sys.stdout.buffer.write(" + repr(response) + ")\n"
            "sys.stdout.buffer.flush()\n"
            "time.sleep(0.15)\n"
            "os._exit(0)\n"
        )
        wait_timeouts = []

        def fail_kill_and_observe_wait(probe):
            """Fail only this child's kill and keep its real finite wait available."""
            real_wait = probe.process.wait

            def wait(timeout=None):
                """Reject implicit unbounded waits before delegating to the kernel."""
                wait_timeouts.append(timeout)
                self.assertIsInstance(timeout, (int, float))
                self.assertGreater(timeout, 0)
                self.assertLessEqual(timeout, 2)
                return real_wait(timeout=timeout)

            probe.kill_attempt = injected.enter_context(patch.object(
                probe.process, "kill",
                side_effect=OSError(errno.EPERM, "SYNTHETIC_PRIVATE_KILL"),
            ))
            injected.enter_context(patch.object(probe.process, "wait", side_effect=wait))

        with _safety_child_probe(script, after_launch=fail_kill_and_observe_wait) as probe, \
             ExitStack() as injected:
            self.assert_refusal(self.validate(), "pdf_safety_worker_invalid_response")
            probe.kill_attempt.assert_called_once_with()
            self.assertTrue(wait_timeouts, "signal failure skipped the independent reap")
            self.assertEqual(probe.signals, [])
            self.assert_retired(probe)

    def test_cleanup_wait_timeout_preserves_original_cancellation(self):
        """A cleanup timeout cannot replace cancellation or imply child retirement."""
        real_read = os.read
        for cancellation in (KeyboardInterrupt("SYNTHETIC"), SystemExit(13)):
            wait_timeouts = []
            read_failures = []

            def fail_cleanup_wait(probe):
                """Inject a finite reap timeout only for the captured direct child."""
                def wait(timeout=None):
                    """Record the bounded attempt without attesting any exit status."""
                    wait_timeouts.append(timeout)
                    self.assertIsInstance(timeout, (int, float))
                    self.assertGreater(timeout, 0)
                    self.assertLessEqual(timeout, 2)
                    raise subprocess.TimeoutExpired(probe.process.args, timeout)

                injected.enter_context(patch.object(probe.process, "wait", side_effect=wait))

            with self.subTest(kind=type(cancellation).__name__), _safety_child_probe(
                "import os,time\nos.write(1,b'x')\ntime.sleep(30)\n",
                after_launch=fail_cleanup_wait,
            ) as probe, ExitStack() as injected:
                def read(descriptor, count):
                    """Deliver the exact cancellation once from the owned output pipe."""
                    if not read_failures and _safety_owned_stream(probe, "stdout", descriptor):
                        read_failures.append(True)
                        raise cancellation
                    return real_read(descriptor, count)

                with patch.object(os, "read", side_effect=read):
                    with self.assertRaises(type(cancellation)) as caught:
                        self.validate()
                self.assertIs(caught.exception, cancellation)
                self.assertEqual(read_failures, [True])
                self.assertTrue(wait_timeouts, "cancellation skipped the finite reap attempt")
                self.assertEqual(probe.group_signals, [])
                self.assertTrue(all(probe.signals), probe.signals)
                # No retirement assertion is made while wait is deliberately faulty.
                # ExitStack restores wait before the fixture's independent pidfd cleanup.
            with self.assertRaises(ChildProcessError):
                _SAFETY_REAL_WAITID(os.P_PID, probe.process.pid, _SAFETY_WAIT_FLAGS)


if __name__ == "__main__":
    unittest.main()
