"""Contract and regression tests for bounded PDF text content verification."""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
from copy import deepcopy
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

from pypdf import PdfWriter
from pypdf.generic import DecodedStreamObject, NameObject

from reporting import pdf_content
from reporting.adapters import build_html_css_and_pdf_adapter


def digest(data: bytes) -> str:
    """Compute the declared content identity of one synthetic artifact."""
    return hashlib.sha256(data).hexdigest()


def ir_digest(ir: object) -> str:
    """Use the existing localization canonical JSON encoding for fixture identity."""
    return digest(json.dumps(ir, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8"))


def synthetic_ir() -> dict:
    """Return multiple distinguishable sections without any real genomic data."""
    return {
        "report_id": "synthetic-content-report", "locale_id": "en-US",
        "components": [
            {"component_id": "summary", "component_type": "semantic-section",
             "title": "Summary", "state": "PRESENT",
             "content": {"label": "SYNTHETIC-CONTENT-ONLY", "value": 1.25}},
            {"component_id": "limitations", "component_type": "semantic-section",
             "title": "Limitations", "state": "PRESENT",
             "content": {"limitations": ["Synthetic fixture only"]}},
        ],
    }


def render(ir: dict) -> bytes:
    """Exercise the real public adapter rather than simulate extracted PDF text."""
    result = build_html_css_and_pdf_adapter(presentation_ir=ir)
    if not result.passed:
        raise AssertionError(result.errors)
    return result.pdf_bytes


def blank_pdf(*, pages: int = 1, encrypted: bool = False) -> bytes:
    """Serialize synthetic blank or encrypted PDF bytes in memory only."""
    writer = PdfWriter()
    for _ in range(pages):
        writer.add_blank_page(width=612, height=792)
    if encrypted:
        writer.encrypt("synthetic-test-password")
    stream = BytesIO()
    writer.write(stream)
    return stream.getvalue()


class Rpt12PdfContentTests(unittest.TestCase):
    """Bind expected report content to independently parsed candidate bytes."""

    @classmethod
    def setUpClass(cls):
        """Render one stable synthetic candidate for the boundary test cases."""
        cls.ir = synthetic_ir()
        cls.pdf = render(cls.ir)

    def setUp(self):
        """Fail explicitly while the requested verification contract is absent."""
        self.assertIsNotNone(importlib.util.find_spec("reporting.pdf_content"),
                             "PDF text content verification is not implemented")
        self.module = importlib.import_module("reporting.pdf_content")

    def check(self, **overrides):
        """Run the real gate with independently bound expected input and candidate."""
        args = {"presentation_ir": self.ir, "expected_ir_sha256": ir_digest(self.ir),
                "pdf_bytes": self.pdf, "expected_pdf_sha256": digest(self.pdf)}
        args.update(overrides)
        return self.module.validate_pdf_text_content(**args)

    def test_generated_pdf_matches_exact_localized_input(self):
        """A freshly rendered candidate verifies without being promoted to FINAL."""
        result = self.check()
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(result.ir_sha256, ir_digest(self.ir))
        self.assertEqual(result.pdf_sha256, digest(self.pdf))
        self.assertEqual(result.expected_text_sha256, result.extracted_text_sha256)
        self.assertEqual(result.to_dict()["conformance_scope"], "PDF_TEXT_CONTENT_ONLY")
        self.assertEqual(result.to_dict()["release_authorization"], "NOT_ESTABLISHED")

    def test_existing_canonical_pipeline_roundtrip(self):
        """The actual compiler, view model and localization fixture verifies end to end."""
        from tests import test_reporting_rpt08_html_pdf_conformance as fixture
        scenario = fixture.Rpt08HtmlPdfConformanceTests()
        scenario.setUp()
        pdf = render(scenario.presentation)
        result = self.check(presentation_ir=scenario.presentation,
                            expected_ir_sha256=ir_digest(scenario.presentation),
                            pdf_bytes=pdf, expected_pdf_sha256=digest(pdf))
        self.assertTrue(result.passed, result.errors)

    def test_wrapped_payload_preserves_spaces_and_json_escapes(self):
        """Physical wraps may disappear, but semantic JSON spaces and escapes may not."""
        ir = deepcopy(self.ir)
        ir["components"][0]["content"]["text"] = "A  B " + "alpha beta gamma " * 25 + "\nquoted \"text\""
        pdf = render(ir)
        result = self.check(presentation_ir=ir, expected_ir_sha256=ir_digest(ir),
                            pdf_bytes=pdf, expected_pdf_sha256=digest(pdf))
        self.assertTrue(result.passed, result.errors)

    def test_omission_duplication_reordering_and_changed_values_fail(self):
        """A valid new digest cannot hide changed report text from the expected IR."""
        changes = []
        ir = deepcopy(self.ir); ir["components"].pop(); changes.append(ir)
        ir = deepcopy(self.ir); ir["components"].reverse(); changes.append(ir)
        ir = deepcopy(self.ir); ir["components"][0]["content"]["value"] = 12.5; changes.append(ir)
        ir = deepcopy(self.ir); ir["report_id"] = "another-report"; changes.append(ir)
        ir = deepcopy(self.ir); ir["components"][0]["state"] = "NOT_ASSESSED"; changes.append(ir)
        ir = deepcopy(self.ir); extra = deepcopy(ir["components"][0]); extra["component_id"] = "duplicate"; ir["components"].append(extra); changes.append(ir)
        for index, changed in enumerate(changes):
            with self.subTest(index=index):
                pdf = render(changed)
                result = self.check(pdf_bytes=pdf, expected_pdf_sha256=digest(pdf))
                self.assertFalse(result.passed)
                self.assertIn("pdf_text_content_mismatch", result.errors)

    def test_semantic_spaces_are_not_folded(self):
        """Double spaces in a JSON value remain distinguishable from a single space."""
        original = deepcopy(self.ir); original["components"][0]["content"]["label"] = "A  B"
        changed = deepcopy(original); changed["components"][0]["content"]["label"] = "A B"
        pdf = render(changed)
        result = self.check(presentation_ir=original, expected_ir_sha256=ir_digest(original),
                            pdf_bytes=pdf, expected_pdf_sha256=digest(pdf))
        self.assertFalse(result.passed)
        self.assertIn("pdf_text_content_mismatch", result.errors)

    def test_digest_errors_block_before_extraction(self):
        """Bad or mismatched identities cannot reach the parser process."""
        cases = [({"expected_pdf_sha256": "0" * 64}, "pdf_digest_mismatch"),
                 ({"expected_ir_sha256": "0" * 64}, "presentation_ir_digest_mismatch"),
                 ({"expected_pdf_sha256": None}, "expected_pdf_digest_invalid"),
                 ({"expected_ir_sha256": "not-a-digest"}, "expected_ir_digest_invalid")]
        for overrides, error in cases:
            with self.subTest(error=error), patch.object(self.module.subprocess, "Popen") as call:
                result = self.check(**overrides)
                self.assertFalse(result.passed)
                self.assertIn(error, result.errors)
                call.assert_not_called()

    def test_malformed_unlocalized_or_noncanonical_input_fails(self):
        """Only JSON-compatible localized semantic sections are an expected source."""
        invalid = [None, {}, {**self.ir, "locale_id": "pt-BR"},
                   {**self.ir, "locale_id": []}, {**self.ir, "components": []}]
        repeated = deepcopy(self.ir); repeated["components"][1]["component_id"] = "summary"; invalid.append(repeated)
        nonfinite = deepcopy(self.ir); nonfinite["components"][0]["content"]["value"] = float("nan"); invalid.append(nonfinite)
        for ir in invalid:
            with self.subTest(ir=repr(ir)):
                result = self.check(presentation_ir=ir)
                self.assertFalse(result.passed)
                self.assertIn("presentation_ir_invalid", result.errors)

    def test_encrypted_malformed_and_zero_page_candidates_fail(self):
        """Unreadable content never receives a content-equivalence attestation."""
        for pdf, error in [(blank_pdf(encrypted=True), "encrypted_pdf_forbidden"),
                           (b"%PDF-1.7\nbroken", "pdf_content_structure_invalid"),
                           (blank_pdf(pages=0), "pdf_content_structure_invalid")]:
            with self.subTest(error=error):
                result = self.check(pdf_bytes=pdf, expected_pdf_sha256=digest(pdf))
                self.assertFalse(result.passed)
                self.assertIn(error, result.errors)

    def test_blank_page_is_not_treated_as_verified_text(self):
        """Empty or image-only text extraction cannot satisfy a report manifest."""
        pdf = blank_pdf()
        result = self.check(pdf_bytes=pdf, expected_pdf_sha256=digest(pdf))
        self.assertFalse(result.passed)
        self.assertIn("pdf_content_text_missing", result.errors)

    def test_byte_and_page_budgets_fail_closed(self):
        """Oversized candidates are rejected rather than partly inspected."""
        from reporting import _pdf_content_worker as worker
        for pdf in (b"%PDF-1.7\n" + b"0" * worker.MAX_PDF_BYTES,
                    blank_pdf(pages=worker.MAX_PAGES + 1)):
            with self.subTest(size=len(pdf)):
                result = self.check(pdf_bytes=pdf, expected_pdf_sha256=digest(pdf))
                self.assertFalse(result.passed)
                self.assertIn("pdf_content_budget_exceeded", result.errors)

    def test_decoded_stream_budget_is_checked_before_text_parsing(self):
        """A small compressed input cannot bypass the decoded-content budget."""
        from reporting import _pdf_content_worker as worker
        writer = PdfWriter(); page = writer.add_blank_page(width=612, height=792)
        stream = DecodedStreamObject()
        stream.set_data(b"q\n" * (worker.MAX_DECODED_BYTES // 2 + 1))
        page[NameObject("/Contents")] = writer._add_object(stream.flate_encode())
        data = BytesIO(); writer.write(data); pdf = data.getvalue()
        self.assertLess(len(pdf), worker.MAX_PDF_BYTES)
        result = self.check(pdf_bytes=pdf, expected_pdf_sha256=digest(pdf))
        self.assertFalse(result.passed)
        self.assertIn("pdf_content_budget_exceeded", result.errors)

    def test_timeout_and_failed_worker_are_not_passes(self):
        """Unavailable, timed-out or invalid worker results stay blocked."""
        scenarios = [(subprocess.TimeoutExpired("synthetic-worker", 10), "pdf_content_worker_timeout"),
                     (OSError("synthetic failure"), "pdf_content_worker_unavailable")]
        for exc, error in scenarios:
            with self.subTest(error=error), patch.object(self.module, "_run_worker", side_effect=exc):
                result = self.check()
                self.assertFalse(result.passed)
                self.assertIn(error, result.errors)
        for returncode, data in [(-9, b""), (0, b"not JSON"), (0, b'{"status":"PASS"}')]:
            with self.subTest(returncode=returncode), patch.object(self.module, "_run_worker", return_value=subprocess.CompletedProcess([], returncode, data)):
                self.assertFalse(self.check().passed)

    def test_evidence_is_immutable_and_contains_no_report_text(self):
        """The public validation record retains digests, not extracted personal text."""
        result = self.check(); self.assertTrue(result.passed, result.errors)
        exposed = result.to_dict()
        self.assertNotIn("SYNTHETIC-CONTENT-ONLY", json.dumps(exposed))
        self.assertNotIn("synthetic-content-report", json.dumps(exposed))
        exposed["errors"].append("tampered")
        self.assertEqual(result.errors, ())
        with self.assertRaises(FrozenInstanceError):
            result.page_count = 999

    def test_public_result_cannot_claim_pass_without_evidence(self):
        """An empty success-looking record violates the result constructor invariant."""
        with self.assertRaises(ValueError):
            self.module.PdfContentValidation(None, None, None, None, None, ())

    def test_actual_multipage_output_preserves_content_order(self):
        """All generated pages contribute to one complete ordered content digest."""
        ir = deepcopy(self.ir)
        ir["components"] = []
        for index in range(20):
            ir["components"].append({
                "component_id": f"section-{index}", "component_type": "semantic-section",
                "title": f"Synthetic section {index}", "state": "PRESENT",
                "content": {"index": index, "text": "alpha beta gamma " * 14},
            })
        pdf = render(ir)
        result = self.check(presentation_ir=ir, expected_ir_sha256=ir_digest(ir),
                            pdf_bytes=pdf, expected_pdf_sha256=digest(pdf))
        self.assertTrue(result.passed, result.errors)
        self.assertGreater(result.page_count, 1)

    def test_canonical_source_rejects_json_key_and_shape_coercion(self):
        """Expected source identities cannot silently coerce non-JSON key or array types."""
        for payload in ({1: "synthetic"}, {"items": ("synthetic",)}):
            with self.subTest(payload=repr(payload)):
                ir = deepcopy(self.ir)
                ir["components"][0]["content"] = payload
                result = self.check(presentation_ir=ir, expected_ir_sha256=ir_digest(ir))
                self.assertFalse(result.passed)
                self.assertIn("presentation_ir_invalid", result.errors)

    def test_extractor_version_drift_is_rejected(self):
        """The worker uses only the already activated pypdf version."""
        from reporting import _pdf_content_worker as worker
        with patch.object(worker, "version", return_value="0.0.0"):
            result = worker.extract_document(self.pdf)
        self.assertEqual(result["errors"], ["pdf_content_extractor_version_mismatch"])


_CONTENT_TEXT_DIGEST = hashlib.sha256(
    b'synthetic-content-reportSummaryPRESENT'
    b'{"label":"SYNTHETIC-CONTENT-ONLY","value":1.25}'
    b'LimitationsPRESENT{"limitations":["Synthetic fixture only"]}'
).hexdigest()


_CONTENT_REAL_POPEN = subprocess.Popen
_CONTENT_REAL_KILL = os.kill
_CONTENT_REAL_WAITID = getattr(os, "waitid", None)
_CONTENT_REAL_WAITPID = os.waitpid
_CONTENT_WAIT_FLAGS = (getattr(os, "WEXITED", 0) | getattr(os, "WNOHANG", 0)
                      | getattr(os, "WNOWAIT", 0))


def _content_response(pdf, *, blocked=False, size=None):
    """Build content-free synthetic protocol bytes at a chosen byte boundary."""
    record = {
        "status": "BLOCKED" if blocked else "PASS",
        "pdf_sha256": None if blocked else hashlib.sha256(pdf).hexdigest(),
        "page_count": None if blocked else 1,
        "text_sha256": None if blocked else _CONTENT_TEXT_DIGEST,
        "errors": ["pdf_content_structure_invalid"] if blocked else [],
    }
    response = json.dumps(record, sort_keys=True).encode("ascii") + b"\n"
    if size is not None:
        if len(response) > size:
            raise AssertionError("synthetic content response exceeds requested size")
        response = response.ljust(size, b" ")
    return response


def _content_emit_script(response, *, exit_code=0):
    """Drain synthetic input and emit the chosen bytes before a literal exit."""
    return (
        "import os,sys\n"
        "sys.stdin.buffer.read()\n"
        "sys.stdout.buffer.write(" + repr(response) + ")\n"
        "sys.stdout.buffer.flush()\n"
        "os._exit(" + str(exit_code) + ")\n"
    )


def _content_owned_stream(probe, name, descriptor):
    """Match only the current open pipe, excluding Popen's startup error pipe."""
    if probe.process is None:
        return False
    stream = getattr(probe.process, name)
    return stream is not None and not stream.closed and descriptor == stream.fileno()


@contextmanager
def _content_child_probe(script, *, wall_seconds=2, after_launch=None):
    """Substitute one disposable direct child and forbid all process-group signals.

    The content launcher retains its existing inherited process group. The test
    therefore never forwards killpg. Numeric direct signals are forwarded only
    while the real kernel still recognizes the fixture's owned child. A pidfd
    provides independent cleanup after either product failure or assertion.
    """
    probe = SimpleNamespace(process=None, pidfd=None, signals=[], group_signals=[],
                            command=None, launch_options=None)

    def launch(command, *args, **kwargs):
        """Preserve launch options while replacing only the executable fixture."""
        if probe.process is not None:
            raise AssertionError("content fixture expected exactly one direct child")
        if kwargs.get("start_new_session", False):
            raise AssertionError("content transport cannot create a new session")
        if kwargs.get("process_group", -1) not in (-1, None):
            raise AssertionError("content transport cannot change its process group")
        probe.command = command
        probe.launch_options = dict(kwargs)
        process = _CONTENT_REAL_POPEN(
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
            raise AssertionError("numeric signal does not target the owned content child")
        try:
            _CONTENT_REAL_WAITID(os.P_PID, identifier, _CONTENT_WAIT_FLAGS)
        except ChildProcessError:
            probe.signals.append(False)
            return
        probe.signals.append(True)
        return _CONTENT_REAL_KILL(identifier, signum)

    def group_signal(identifier, signum):
        """Never allow a fixture to signal the caller's inherited process group."""
        probe.group_signals.append((identifier, signum))
        raise AssertionError("content transport must not signal any process group")

    try:
        with patch.object(pdf_content.subprocess, "Popen", side_effect=launch), \
             patch.object(pdf_content, "WALL_SECONDS", wall_seconds), \
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
class ContentWorkerTransportTests(unittest.TestCase):
    """Exercise the existing public content contract through real bounded pipes."""

    pdf = b"%PDF-SYNTHETIC-CONTENT-TRANSPORT"

    def validate(self, pdf=None):
        """Call only the established public API with exact synthetic identity."""
        data = self.pdf if pdf is None else pdf
        ir = synthetic_ir()
        result = pdf_content.validate_pdf_text_content(
            presentation_ir=ir, expected_ir_sha256=ir_digest(ir),
            pdf_bytes=data, expected_pdf_sha256=hashlib.sha256(data).hexdigest(),
        )
        self.assertEqual(result.ir_sha256, ir_digest(ir))
        self.assertEqual(result.pdf_sha256, hashlib.sha256(data).hexdigest())
        self.assertEqual(result.expected_text_sha256, _CONTENT_TEXT_DIGEST)
        self.assertEqual(result.to_dict()["release_authorization"], "NOT_ESTABLISHED")
        return result

    def assert_retired(self, probe):
        """Require product reap before fixture cleanup without any group signal."""
        self.assertIsNotNone(probe.process)
        self.assertEqual(probe.group_signals, [])
        self.assertTrue(all(probe.signals), probe.signals)
        with self.assertRaises(ChildProcessError):
            _CONTENT_REAL_WAITID(os.P_PID, probe.process.pid, _CONTENT_WAIT_FLAGS)

    def assert_refusal(self, result, error):
        """Reject partial counts and private exception details on every failure."""
        self.assertEqual(result.errors, (error,))
        self.assertFalse(result.passed)
        self.assertIsNone(result.page_count)
        self.assertIsNone(result.extracted_text_sha256)
        self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(result.to_dict()))

    def test_exact_response_budget_preserves_existing_success_protocol(self):
        """Exactly 4096 bytes is accepted without altering the direct-child launch."""
        response = _content_response(self.pdf, size=4096)
        with _content_child_probe(_content_emit_script(response)) as probe:
            result = self.validate()
            self.assertTrue(result.passed, result.errors)
            self.assertEqual((result.page_count, result.extracted_text_sha256), (1, _CONTENT_TEXT_DIGEST))
            self.assertEqual(probe.command, [
                sys.executable, "-I", str(pdf_content._WORKER), str(os.getpid())
            ])
            self.assertEqual(probe.launch_options.get("stderr"), subprocess.DEVNULL)
            self.assert_retired(probe)

    def test_one_overflow_byte_refuses_an_otherwise_valid_response(self):
        """A JSON value plus padding cannot exceed the existing 4096-byte cap."""
        response = _content_response(self.pdf, size=4097)
        with _content_child_probe(_content_emit_script(response)) as probe:
            self.assert_refusal(self.validate(), "pdf_content_worker_invalid_response")
            self.assert_retired(probe)

    def test_overflow_is_refused_before_a_live_writer_closes_stdout(self):
        """A 4097-byte live response is a protocol failure rather than a timeout."""
        response = _content_response(self.pdf, size=4097)
        script = (
            "import sys,time\n"
            "sys.stdout.buffer.write(" + repr(response) + ")\n"
            "sys.stdout.buffer.flush()\n"
            "time.sleep(30)\n"
        )
        with _content_child_probe(script, wall_seconds=0.3) as probe:
            started = time.monotonic()
            self.assert_refusal(self.validate(), "pdf_content_worker_invalid_response")
            self.assertLess(time.monotonic() - started, 2.5)
            self.assert_retired(probe)

    def test_parent_collects_at_most_one_overflow_byte(self):
        """A controlled larger response must not first accumulate in the parent."""
        real_read = os.read
        response = _content_response(self.pdf, size=65536)
        with _content_child_probe(_content_emit_script(response)) as probe:
            collected = []

            def read(descriptor, count):
                """Count real stdout bytes only, preserving all other reads."""
                owned = _content_owned_stream(probe, "stdout", descriptor)
                data = real_read(descriptor, count)
                if owned:
                    collected.append(len(data))
                return data

            with patch.object(os, "read", side_effect=read):
                result = self.validate()
            self.assert_refusal(result, "pdf_content_worker_invalid_response")
            self.assertTrue(collected, "fixture did not observe any stdout collection")
            self.assertEqual(sum(collected), 4097)
            self.assert_retired(probe)

    def test_duplex_overflow_does_not_wait_for_large_input_consumption(self):
        """A full 4096-byte output pipe cannot strand a simultaneous input write."""
        pdf = b"%PDF-" + b"D" * (1024 * 1024 - 5)
        response = _content_response(pdf, size=4097)
        script = (
            "import fcntl,sys,time\n"
            "fcntl.fcntl(1,fcntl.F_SETPIPE_SZ,4096)\n"
            "sys.stdout.buffer.write(" + repr(response) + ")\n"
            "sys.stdout.buffer.flush()\n"
            "time.sleep(30)\n"
        )
        with _content_child_probe(script, wall_seconds=0.3) as probe:
            self.assert_refusal(self.validate(pdf), "pdf_content_worker_invalid_response")
            self.assert_retired(probe)

    def test_response_before_complete_input_preserves_all_input_bytes(self):
        """Successful duplex exchange still delivers the full exact input."""
        pdf = b"%PDF-" + b"I" * (1024 * 1024 - 5)
        response = _content_response(pdf, size=4096)
        script = (
            "import hashlib,os,sys\n"
            "sys.stdout.buffer.write(" + repr(response) + ")\n"
            "sys.stdout.buffer.flush()\n"
            "data=sys.stdin.buffer.read()\n"
            "os._exit(0 if hashlib.sha256(data).hexdigest()=="
            + repr(hashlib.sha256(pdf).hexdigest()) + " else 7)\n"
        )
        with _content_child_probe(script) as probe:
            result = self.validate(pdf)
            self.assertTrue(result.passed, result.errors)
            self.assert_retired(probe)

    def test_unread_stdin_has_a_finite_timeout_and_direct_child_cleanup(self):
        """Maximum admitted input cannot leave a blocked producer waiting forever."""
        pdf = b"%PDF-" + b"T" * (8 * 1024 * 1024 - 5)
        with _content_child_probe("import time;time.sleep(30)", wall_seconds=0.2) as probe:
            started = time.monotonic()
            self.assert_refusal(self.validate(pdf), "pdf_content_worker_timeout")
            self.assertLess(time.monotonic() - started, 2.5)
            self.assert_retired(probe)

    def test_stdout_eof_does_not_accept_a_still_running_worker(self):
        """The parent must observe actual exit after response EOF."""
        script = "import os,time\nos.close(1)\ntime.sleep(30)\n"
        with _content_child_probe(script, wall_seconds=0.2) as probe:
            self.assert_refusal(self.validate(), "pdf_content_worker_timeout")
            self.assert_retired(probe)

    def test_early_blocked_response_survives_input_broken_pipe(self):
        """A worker refusing input admission may close stdin and return BLOCKED."""
        pdf = b"%PDF-" + b"B" * (1024 * 1024 - 5)
        response = _content_response(pdf, blocked=True)
        script = (
            "import os,sys\nos.close(0)\n"
            "sys.stdout.buffer.write(" + repr(response) + ")\n"
            "sys.stdout.buffer.flush()\n"
        )
        with _content_child_probe(script) as probe:
            self.assert_refusal(self.validate(pdf), "pdf_content_structure_invalid")
            self.assert_retired(probe)

    def test_success_looking_response_cannot_hide_nonzero_exit(self):
        """Complete response fields do not replace successful worker execution."""
        script = _content_emit_script(_content_response(self.pdf), exit_code=7)
        with _content_child_probe(script) as probe:
            self.assert_refusal(self.validate(), "pdf_content_worker_failed")
            self.assert_retired(probe)

    def test_empty_malformed_and_truncated_responses_remain_invalid(self):
        """Malformed responses within the byte budget retain protocol refusal."""
        for response in (b"", b"not-json", b'{"status":"PASS"', b'{"status":"PASS"}'):
            with self.subTest(response=response), _content_child_probe(
                _content_emit_script(response)
            ) as probe:
                self.assert_refusal(self.validate(), "pdf_content_worker_invalid_response")
                self.assert_retired(probe)

    def test_fragmented_response_preserves_public_evidence(self):
        """Transport read boundaries cannot alter the complete JSON response."""
        response = _content_response(self.pdf)
        script = (
            "import os,sys\nsys.stdin.buffer.read()\n"
            "data=" + repr(response) + "\n"
            "for offset in range(0,len(data),7):\n"
            "    os.write(1,data[offset:offset+7])\n"
        )
        with _content_child_probe(script) as probe:
            result = self.validate()
            self.assertTrue(result.passed, result.errors)
            self.assertEqual((result.page_count, result.extracted_text_sha256), (1, _CONTENT_TEXT_DIGEST))
            self.assert_retired(probe)

    def test_short_writes_and_temporary_not_ready_reads_are_retried(self):
        """Nonblocking readiness changes preserve exact input and output bytes."""
        pdf = b"%PDF-" + b"P" * (65536 - 5)
        response = _content_response(pdf)
        script = (
            "import hashlib,os,sys\n"
            "data=sys.stdin.buffer.read()\n"
            "if hashlib.sha256(data).hexdigest()!="
            + repr(hashlib.sha256(pdf).hexdigest()) + ":os._exit(7)\n"
            "sys.stdout.buffer.write(" + repr(response) + ")\n"
            "sys.stdout.buffer.flush()\n"
        )
        real_read, real_write = os.read, os.write
        with _content_child_probe(script) as probe:
            injected = {"write_not_ready": False, "short_write": False, "read_not_ready": False}

            def write(descriptor, data):
                """Inject one would-block and one real partial input write."""
                if _content_owned_stream(probe, "stdin", descriptor):
                    if not injected["write_not_ready"]:
                        injected["write_not_ready"] = True
                        raise BlockingIOError(errno.EAGAIN, "synthetic readiness change")
                    if not injected["short_write"]:
                        injected["short_write"] = True
                        return real_write(descriptor, data[:7])
                return real_write(descriptor, data)

            def read(descriptor, count):
                """Inject one would-block only after the owned output is readable."""
                if (_content_owned_stream(probe, "stdout", descriptor)
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
            with self.subTest(kind=type(cancellation).__name__), _content_child_probe(
                "import os,time\nos.write(1,b'x')\ntime.sleep(30)\n"
            ) as probe:
                injected = []

                def read(descriptor, count):
                    """Deliver the original cancellation once at the owned stdout."""
                    if not injected and _content_owned_stream(probe, "stdout", descriptor):
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
            with self.subTest(kind=type(cancellation).__name__), _content_child_probe(
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
        with _content_child_probe("import time;time.sleep(30)", wall_seconds=0.2) as probe:
            injected = []

            def configure(descriptor, blocking):
                """Fail the first configuration of either owned transport pipe."""
                if (not injected and (_content_owned_stream(probe, "stdin", descriptor)
                                      or _content_owned_stream(probe, "stdout", descriptor))):
                    injected.append(True)
                    raise OSError(errno.EIO, "SYNTHETIC_PRIVATE_SETUP")
                return real_set_blocking(descriptor, blocking)

            with patch.object(os, "set_blocking", side_effect=configure):
                result = self.validate()
            self.assertEqual(injected, [True])
            self.assert_refusal(result, "pdf_content_worker_unavailable")
            self.assert_retired(probe)

    def test_pipe_read_error_is_sanitized_after_direct_child_cleanup(self):
        """Unexpected read errors cannot leak details or leave the child running."""
        real_read = os.read
        with _content_child_probe("import os,time\nos.write(1,b'x')\ntime.sleep(30)\n") as probe:
            injected = []

            def read(descriptor, count):
                """Raise one synthetic I/O error from the owned output descriptor."""
                if not injected and _content_owned_stream(probe, "stdout", descriptor):
                    injected.append(True)
                    raise OSError(errno.EIO, "SYNTHETIC_PRIVATE_READ")
                return real_read(descriptor, count)

            with patch.object(os, "read", side_effect=read):
                result = self.validate()
            self.assertEqual(injected, [True])
            self.assert_refusal(result, "pdf_content_worker_unavailable")
            self.assert_retired(probe)

    def test_pipe_write_error_is_sanitized_after_direct_child_cleanup(self):
        """Unexpected write errors retain the original unavailable error mapping."""
        real_write = os.write
        with _content_child_probe("import time;time.sleep(30)") as probe:
            injected = []

            def write(descriptor, data):
                """Raise one synthetic I/O error from the owned input descriptor."""
                if not injected and _content_owned_stream(probe, "stdin", descriptor):
                    injected.append(True)
                    raise OSError(errno.EIO, "SYNTHETIC_PRIVATE_WRITE")
                return real_write(descriptor, data)

            with patch.object(os, "write", side_effect=write):
                result = self.validate()
            self.assertEqual(injected, [True])
            self.assert_refusal(result, "pdf_content_worker_unavailable")
            self.assert_retired(probe)

    def test_external_reap_refuses_success_without_retrying_a_signal(self):
        """A valid response cannot attest success after genuine ownership loss."""
        response = _content_response(self.pdf)
        script = (
            "import os,sys\n"
            "sys.stdout.buffer.write(" + repr(response) + ")\n"
            "sys.stdout.buffer.flush()\n"
            "os._exit(0)\n"
        )

        def reap_before_return(probe):
            """Reap a waitable child without updating Popen's cached return code."""
            deadline = time.monotonic() + 2
            while _CONTENT_REAL_WAITID(os.P_PID, probe.process.pid, _CONTENT_WAIT_FLAGS) is None:
                if time.monotonic() >= deadline:
                    self.fail("synthetic worker did not exit before external-reap deadline")
                time.sleep(0.005)
            pid, status = _CONTENT_REAL_WAITPID(probe.process.pid, os.WNOHANG)
            self.assertEqual(pid, probe.process.pid)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            self.assertIsNone(probe.process.returncode)
            probe.kill_attempt = injected.enter_context(patch.object(probe.process, "kill"))

        with _content_child_probe(script, after_launch=reap_before_return) as probe, \
             ExitStack() as injected:
            self.assert_refusal(self.validate(), "pdf_content_worker_unavailable")
            probe.kill_attempt.assert_not_called()
            self.assertEqual(probe.signals, [])
            self.assertIsNone(probe.process.returncode)
            self.assert_retired(probe)

    def test_direct_kill_failure_still_attempts_finite_reap(self):
        """A failed signal must retain the primary refusal and independently reap."""
        response = _content_response(self.pdf, size=4097)
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

        with _content_child_probe(script, after_launch=fail_kill_and_observe_wait) as probe, \
             ExitStack() as injected:
            self.assert_refusal(self.validate(), "pdf_content_worker_invalid_response")
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

            with self.subTest(kind=type(cancellation).__name__), _content_child_probe(
                "import os,time\nos.write(1,b'x')\ntime.sleep(30)\n",
                after_launch=fail_cleanup_wait,
            ) as probe, ExitStack() as injected:
                def read(descriptor, count):
                    """Deliver the exact cancellation once from the owned output pipe."""
                    if not read_failures and _content_owned_stream(probe, "stdout", descriptor):
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
                _CONTENT_REAL_WAITID(os.P_PID, probe.process.pid, _CONTENT_WAIT_FLAGS)

    def test_caller_exception_does_not_hide_successful_worker_close_failure(self):
        """A caller's handled exception cannot turn local pipe-cleanup failure into PASS."""
        script = _content_emit_script(_content_response(self.pdf))
        for close_error in (OSError(errno.EIO, "SYNTHETIC_PRIVATE_CLOSE"),
                            ValueError("SYNTHETIC_PRIVATE_CLOSE")):
            close_attempts = []
            close_failures = []

            def observe_pipe_closure(probe):
                """Inject a late close error only after the real worker exits successfully."""
                for name in ("stdin", "stdout"):
                    stream = getattr(probe.process, name)
                    real_close = stream.close

                    def close(name=name, real_close=real_close):
                        """Close the actual descriptor and observe both final cleanup attempts."""
                        successful_exit = probe.process.returncode == 0
                        if successful_exit:
                            close_attempts.append(name)
                        real_close()
                        if successful_exit and name == "stdin" and not close_failures:
                            close_failures.append(close_error)
                            raise close_error

                    injected.enter_context(patch.object(stream, "close", side_effect=close))

            with self.subTest(error=type(close_error).__name__), _content_child_probe(
                script, after_launch=observe_pipe_closure,
            ) as probe, ExitStack() as injected:
                try:
                    raise RuntimeError("SYNTHETIC_CALLER_HANDLED_EXCEPTION")
                except RuntimeError:
                    try:
                        result = self.validate()
                    except ValueError as error:
                        self.fail("late pipe-close failure escaped the public validator: " + type(error).__name__)
                self.assertEqual(close_failures, [close_error])
                self.assertEqual(set(close_attempts), {"stdin", "stdout"})
                self.assertTrue(probe.process.stdin.closed)
                self.assertTrue(probe.process.stdout.closed)
                self.assertEqual(probe.process.returncode, 0)
                self.assert_retired(probe)
                self.assert_refusal(result, "pdf_content_worker_unavailable")


    def test_work_deadline_is_shared_with_final_exit_wait(self):
        """Time used receiving output is not renewed while waiting for exit."""
        response = _content_response(self.pdf)
        script = (
            "import os,sys,time\n"
            "sys.stdin.buffer.read()\n"
            "time.sleep(0.15)\n"
            "sys.stdout.buffer.write(" + repr(response) + ")\n"
            "sys.stdout.buffer.flush()\n"
            "os.close(1)\n"
            "time.sleep(0.22)\n"
        )
        with _content_child_probe(script, wall_seconds=0.3) as probe:
            started = time.monotonic()
            self.assert_refusal(self.validate(), "pdf_content_worker_timeout")
            self.assertLess(time.monotonic() - started, 2.5)
            self.assert_retired(probe)

    def test_valid_mismatching_text_retains_extracted_evidence(self):
        """A parsed mismatch retains its digest and pages without disclosing text."""
        record = json.loads(_content_response(self.pdf))
        record["text_sha256"] = "0" * 64
        response = json.dumps(record).encode("ascii")
        with _content_child_probe(_content_emit_script(response)) as probe:
            result = self.validate()
            self.assertFalse(result.passed)
            self.assertEqual(result.errors, ("pdf_text_content_mismatch",))
            self.assertEqual(result.extracted_text_sha256, "0" * 64)
            self.assertEqual(result.page_count, 1)
            self.assertEqual(result.expected_text_sha256, _CONTENT_TEXT_DIGEST)
            self.assertNotIn("SYNTHETIC-CONTENT-ONLY", json.dumps(result.to_dict()))
            self.assert_retired(probe)


if __name__ == "__main__":
    unittest.main()
