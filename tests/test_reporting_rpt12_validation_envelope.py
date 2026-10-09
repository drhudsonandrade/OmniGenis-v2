"""Exercise process-bound validation of existing generated PDF candidates."""

from __future__ import annotations

import builtins
import hashlib
import json
import os
from pathlib import Path
import signal
import select
import subprocess
import sys
import tempfile
import time
from io import BytesIO
import unittest
from unittest.mock import patch

from reporting import adapters, pdf_candidate_qa as qa
from reporting import pdf_validation as boundary
from reporting import _pdf_validation_worker as worker
from reporting.pdf_qa import GENERATED_PDF_AUTHOR, GENERATED_PDF_METADATA_PROFILE


def observe_worker_exit(pidfd: int, timeout: float) -> bool:
    """Wait for the exact kernel process handle; timeout alone is not exit."""
    return bool(select.select([pidfd], [], [], timeout)[0])


def cleanup_observed_worker(pidfd: int) -> None:
    """Signal only an identity-verified child; allow concurrent disappearance."""
    try:
        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
    except ProcessLookupError:
        pass


class ValidationEnvelopeTests(unittest.TestCase):
    """Keep PDF parsing outside the native host without changing its decisions."""

    @classmethod
    def setUpClass(cls):
        """Generate the existing supported synthetic report once."""
        from test_reporting_rpt08_html_pdf_conformance import Rpt08HtmlPdfConformanceTests
        fixture = Rpt08HtmlPdfConformanceTests()
        fixture.setUp()
        result = fixture.adapt()
        if not result.passed:
            raise AssertionError(result.errors)
        cls.pdf = result.pdf_bytes
        cls.digest = result.pdf_sha256
        cls.ir = fixture.presentation
        cls.real_import = staticmethod(builtins.__import__)

    def forbid_host_parser(self, name, globals=None, locals=None, fromlist=(), level=0):
        """Fail a native host import; a subprocess has its own import machinery."""
        if name == "pypdf" or name.startswith("pypdf."):
            raise AssertionError("PDF parser executed in hosting process")
        return self.real_import(name, globals, locals, fromlist, level)

    def test_native_structure_does_not_parse_pdf_in_host(self):
        """The native compatibility check must run after crossing the boundary."""
        with patch("builtins.__import__", side_effect=self.forbid_host_parser):
            adapters._validate_pdf_structure(self.pdf, expected_language="en-US")

    def test_candidate_metadata_does_not_parse_pdf_in_host(self):
        """The fixed QA metadata stage must run in the limited worker."""
        with patch("builtins.__import__", side_effect=self.forbid_host_parser):
            result = qa.validate_pdf_candidate(
                pdf_bytes=self.pdf, expected_pdf_sha256=self.digest,
                expected_author=GENERATED_PDF_AUTHOR, expected_language="en-US",
                metadata_profile=GENERATED_PDF_METADATA_PROFILE,
            )
        self.assertTrue(result.passed, result.errors)

    def test_candidate_accessibility_does_not_parse_pdf_in_host(self):
        """The fixed QA accessibility stage must run in the limited worker."""
        with patch("builtins.__import__", side_effect=self.forbid_host_parser):
            result = qa.validate_pdf_accessibility_structure(
                pdf_bytes=self.pdf, expected_language="en-US",
            )
        self.assertTrue(result.passed, result.errors)

    def metadata_record(self):
        """Build the smallest declared success protocol for parser-negative tests."""
        return {"protocol_version": worker.PROTOCOL_VERSION,
                "profile_id": worker.PROFILE_ID, "operation": "metadata",
                "pdf_sha256": self.digest, "limits": dict(boundary._LIMITS),
                "decision": {"errors": [], "page_count": 1}}

    def decode(self, record):
        """Decode one synthetic protocol result without invoking a PDF parser."""
        return boundary._decode(json.dumps(record).encode("ascii"), "metadata", self.digest)

    def cleanup_process(self, process):
        """Always clean up a test-owned process and its inherited group."""
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.fail("test process did not terminate")

    @staticmethod
    def process_running(pid):
        """Treat either Linux disappearance error as a terminated process."""
        try:
            state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
        except (FileNotFoundError, ProcessLookupError):
            return False
        return state != "Z"

    def test_native_size_rejected_before_hashing(self):
        """Oversized candidates must not be hashed by the native wrapper."""
        with patch.object(boundary, "PDF_BYTES", 32), patch.object(boundary.hashlib, "sha256") as digest:
            with self.assertRaises(RuntimeError):
                boundary.validate_native_structure(b"%PDF-1.7" + b"x" * 40, expected_language="en-US")
        digest.assert_not_called()

    def test_bounded_results_match_existing_validators_on_supported_pdf(self):
        """The boundary changes execution location, not passing result semantics."""
        from reporting import pdf_qa, pdf_accessibility
        args = dict(pdf_bytes=self.pdf, expected_pdf_sha256=self.digest,
                    expected_author=GENERATED_PDF_AUTHOR, expected_language="en-US",
                    metadata_profile=GENERATED_PDF_METADATA_PROFILE)
        self.assertEqual(boundary.validate_generated_metadata(**args).to_dict(),
                         pdf_qa.validate_pdf_candidate(**args).to_dict())
        access = dict(pdf_bytes=self.pdf, expected_language="en-US")
        self.assertEqual(boundary.validate_generated_accessibility(**access).to_dict(),
                         pdf_accessibility.validate_pdf_accessibility_structure(**access).to_dict())

    def test_rejected_metadata_never_returns_arbitrary_values(self):
        """A modified PDF can produce fixed rejection codes, not its raw metadata."""
        from pypdf import PdfWriter
        writer = PdfWriter(clone_from=BytesIO(self.pdf))
        writer.add_metadata({"/Author": "PRIVATE-METADATA-SENTINEL"})
        stream = BytesIO(); writer.write(stream); pdf = stream.getvalue()
        result = boundary.validate_generated_metadata(
            pdf_bytes=pdf, expected_pdf_sha256=hashlib.sha256(pdf).hexdigest(),
            expected_author=GENERATED_PDF_AUTHOR, expected_language="en-US",
            metadata_profile=GENERATED_PDF_METADATA_PROFILE,
        )
        self.assertFalse(result.passed)
        self.assertEqual(dict(result.metadata), {})
        self.assertIsNone(result.page_count)
        self.assertNotIn("PRIVATE-METADATA", json.dumps(result.to_dict()))

    def test_native_structure_preserves_invalid_pdf_rejection(self):
        """The old malformed-candidate error remains a fixed native failure."""
        with self.assertRaisesRegex(RuntimeError, "^pdf_engine_invalid_output$"):
            adapters._validate_pdf_structure(b"%PDF-1.7\nbroken", expected_language="en-US")

    def test_digest_mismatch_cannot_start_a_worker(self):
        """Reject a foreign digest before any parser subprocess is created."""
        with patch.object(boundary, "_start") as start:
            with self.assertRaisesRegex(RuntimeError, "pdf_validation_digest_mismatch"):
                boundary._run("metadata", self.pdf, "0" * 64)
        start.assert_not_called()

    def test_invalid_size_or_type_cannot_start_a_worker(self):
        """The entry boundary rejects non-native and out-of-budget PDF inputs."""
        for value in (None, bytearray(self.pdf), b"garbage"):
            with self.subTest(type=type(value).__name__), patch.object(boundary, "_start") as start:
                with self.assertRaisesRegex(RuntimeError, "pdf_validation_input_invalid"):
                    boundary._run("metadata", value, self.digest)
                start.assert_not_called()
        with patch.object(boundary, "PDF_BYTES", 8), patch.object(boundary, "_start") as start:
            with self.assertRaisesRegex(RuntimeError, "pdf_validation_input_invalid"):
                boundary._run("metadata", self.pdf, self.digest)
        start.assert_not_called()

    def test_no_profile_or_locale_expansion(self):
        """Other locales and metadata profiles remain unsupported by this adapter."""
        for changes in ({"expected_language": "pt-BR"}, {"expected_author": "Other"},
                        {"metadata_profile": None}):
            args = dict(pdf_bytes=self.pdf, expected_pdf_sha256=self.digest,
                        expected_author=GENERATED_PDF_AUTHOR, expected_language="en-US",
                        metadata_profile=GENERATED_PDF_METADATA_PROFILE)
            args.update(changes)
            with self.subTest(changes=changes), patch.object(boundary, "_start") as start:
                with self.assertRaisesRegex(RuntimeError, "pdf_validation_profile_invalid"):
                    boundary.validate_generated_metadata(**args)
                start.assert_not_called()

    def test_disable_withholds_native_candidate_and_recovers(self):
        """Disabling validation withholds artifacts; re-enabling preserves output."""
        with patch.object(adapters, "_render_pdf", return_value=self.pdf):
            with patch.dict(os.environ, {"OMNIGENIS_PDF_VALIDATION_DISABLED": "1"}):
                failed = adapters.build_html_css_and_pdf_adapter(presentation_ir=self.ir)
            recovered = adapters.build_html_css_and_pdf_adapter(presentation_ir=self.ir)
        self.assertFalse(failed.passed)
        self.assertIsNone(failed.pdf_bytes)
        self.assertIsNone(failed.pdf_sha256)
        self.assertIsNone(failed.conformance)
        self.assertTrue(recovered.passed, recovered.errors)
        self.assertEqual(recovered.pdf_bytes, self.pdf)
        self.assertEqual(recovered.pdf_sha256, self.digest)

    def test_entire_native_route_has_no_host_pdf_parser(self):
        """Every native PDF parser call crosses a child-process boundary."""
        with patch.object(adapters, "_render_pdf", return_value=self.pdf), patch(
            "builtins.__import__", side_effect=self.forbid_host_parser,
        ):
            result = adapters.build_html_css_and_pdf_adapter(presentation_ir=self.ir)
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(result.pdf_sha256, self.digest)

    def test_duplicate_json_names_are_rejected(self):
        """Repeated keys cannot override an earlier protocol decision."""
        data = json.dumps(self.metadata_record()).replace('"protocol_version": 1',
                    '"protocol_version": 0, "protocol_version": 1').encode("ascii")
        with self.assertRaisesRegex(RuntimeError, "^pdf_validation_failed$"):
            boundary._decode(data, "metadata", self.digest)
        data = json.dumps(self.metadata_record()).replace('"page_count": 1',
                    '"page_count": 0, "page_count": 1').encode("ascii")
        with self.assertRaisesRegex(RuntimeError, "^pdf_validation_failed$"):
            boundary._decode(data, "metadata", self.digest)

    def test_protocol_versions_and_limits_are_exact_integers(self):
        """Bool and float lookalikes cannot certify versions or resource limits."""
        for value in (True, 1.0, "1"):
            record = self.metadata_record(); record["protocol_version"] = value
            with self.subTest(value=value), self.assertRaisesRegex(RuntimeError, "pdf_validation_failed"):
                self.decode(record)
        for key in boundary._LIMITS:
            record = self.metadata_record(); record["limits"][key] = float(record["limits"][key])
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, "pdf_validation_failed"):
                self.decode(record)

    def test_foreign_operation_profile_and_digest_are_rejected(self):
        """A response for another invocation cannot authorize this candidate."""
        for key, value in (("operation", "structure"), ("profile_id", "foreign"),
                           ("pdf_sha256", "0" * 64)):
            record = self.metadata_record(); record[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, "pdf_validation_failed"):
                self.decode(record)

    def test_unexpected_fields_and_errors_are_rejected(self):
        """Unapproved values are never projected as public validation evidence."""
        for mutation in (lambda r: r.update(detail="PRIVATE-DETAIL"),
                         lambda r: r["decision"].update(metadata={"/Author": "PRIVATE"}),
                         lambda r: r["decision"].update(errors=["PRIVATE-ERROR"])):
            record = self.metadata_record(); mutation(record)
            with self.assertRaisesRegex(RuntimeError, "^pdf_validation_failed$"):
                self.decode(record)

    def test_invalid_page_count_and_blocked_evidence_are_rejected(self):
        """Metadata success requires a positive bounded integer page count."""
        for value in (True, 1.0, 0, None, boundary.MAX_PAGES + 1):
            record = self.metadata_record(); record["decision"]["page_count"] = value
            with self.subTest(value=value), self.assertRaisesRegex(RuntimeError, "pdf_validation_failed"):
                self.decode(record)
        record = self.metadata_record(); record["decision"]["errors"] = ["pdf_structure_invalid"]
        with self.assertRaisesRegex(RuntimeError, "pdf_validation_failed"):
            self.decode(record)

    def test_protocol_size_and_malformed_json_are_rejected(self):
        """Response parsing itself has a fixed byte budget and closed errors."""
        for value in (b"not-json", b"x" * (worker.RESULT_BYTES + 1), b"[]", b"\xff"):
            with self.subTest(size=len(value)), self.assertRaisesRegex(RuntimeError, "pdf_validation_failed"):
                boundary._decode(value, "metadata", self.digest)

    def test_anonymous_storage_descriptors_close_after_success(self):
        """No protocol pathname or inherited descriptor survives a finished call."""
        original = boundary._start; observed = []
        def observe(command, fds):
            for fd in fds:
                self.assertEqual(os.fstat(fd).st_nlink, 0)
            observed.extend(fds)
            return original(command, fds)
        with patch.object(boundary, "_start", side_effect=observe):
            self.assertEqual(boundary._run("metadata", self.pdf, self.digest)["errors"], [])
        self.assertEqual(len(observed), 2)
        for fd in observed:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_storage_and_spawn_errors_do_not_disclose_os_details(self):
        """Failures to allocate or launch return a single fixed public error."""
        for target in ("_start", "tempfile.TemporaryFile"):
            owner, name = (boundary, target) if "." not in target else (boundary.tempfile, "TemporaryFile")
            with self.subTest(target=target), patch.object(owner, name, side_effect=OSError("PRIVATE-OS-DETAIL")):
                with self.assertRaisesRegex(RuntimeError, "^pdf_validation_failed$"):
                    boundary._run("metadata", self.pdf, self.digest)

    def test_timeout_reaps_owned_process(self):
        """A stalled validation process is terminated instead of returning success."""
        original = boundary._start; captured = []
        def stalled(command, fds):
            process = original([sys.executable, "-c", "import time;time.sleep(20)"], fds)
            self.addCleanup(self.cleanup_process, process); captured.append(process)
            return process
        with patch.object(boundary, "_start", side_effect=stalled), patch.object(boundary, "WALL_SECONDS", 0.1):
            with self.assertRaisesRegex(RuntimeError, "^pdf_validation_failed$"):
                boundary._run("metadata", self.pdf, self.digest)
        self.assertIsNotNone(captured[0].returncode)

    def test_crash_cannot_become_a_validation_success(self):
        """An unsuccessful child with no result always blocks its caller."""
        original = boundary._start
        def crashed(command, fds):
            process = original([sys.executable, "-c", "raise SystemExit(7)"], fds)
            self.addCleanup(self.cleanup_process, process)
            return process
        with patch.object(boundary, "_start", side_effect=crashed):
            with self.assertRaisesRegex(RuntimeError, "^pdf_validation_failed$"):
                boundary._run("metadata", self.pdf, self.digest)

    def test_actual_kernel_limits_are_applied(self):
        """The worker reports limits obtained from the kernel, not just constants."""
        code = "from reporting._pdf_validation_worker import _limits;import json;print(json.dumps(_limits()))"
        result = subprocess.run([sys.executable, "-c", code], cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True, timeout=5, check=True)
        self.assertEqual(json.loads(result.stdout), boundary._LIMITS)

    def test_independent_timer_interrupts_blocked_native_code(self):
        """The OS timer enforces elapsed time even without a Python callback."""
        code = ("import ctypes,os;from reporting import _pdf_validation_worker as w;"
                "w.WALL_SECONDS=0.1;w._lifetime(os.getppid());ctypes.CDLL(None).sleep(20)")
        result = subprocess.run([sys.executable, "-c", code], cwd=Path(__file__).resolve().parents[1],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
        self.assertEqual(result.returncode, -signal.SIGALRM)

    def parent_death_observed(self, *, guarded: bool) -> bool:
        """Observe a pinned child before releasing its parent, then clean up separately."""
        child = """import os,signal,sys,time
from reporting import _pdf_validation_worker as worker
if sys.argv[1] == "guarded":
    worker.WALL_SECONDS = 20
    worker._lifetime(os.getppid())
else:
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.setitimer(signal.ITIMER_REAL, 20)
print("READY", flush=True)
time.sleep(20)
"""
        parent_code = """import json,os,select,subprocess,sys
from pathlib import Path
child = subprocess.Popen([sys.executable, "-u", "-c", sys.argv[1], sys.argv[2]],
    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    start_new_session=True)
try:
    if not select.select([child.stdout], [], [], 5)[0] or child.stdout.readline() != b"READY\\n":
        raise RuntimeError("worker readiness failed")
    start = Path(f"/proc/{child.pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
    assert child.poll() is None
    print(json.dumps({"pid": child.pid, "start": start}), flush=True)
    if sys.stdin.buffer.read(1) == b"X":
        os._exit(0)
finally:
    if child.poll() is None:
        child.kill()
    child.wait(timeout=3)
    child.stdout.close()
"""
        parent = subprocess.Popen(
            [sys.executable, "-u", "-c", parent_code, child,
             "guarded" if guarded else "unguarded"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            cwd=Path(__file__).resolve().parents[1],
        )
        pidfd = None
        identity_verified = False
        try:
            self.assertTrue(select.select([parent.stdout], [], [], 5)[0],
                            "parent did not report a ready worker")
            record = json.loads(parent.stdout.readline(512))
            self.assertIs(type(record["pid"]), int)
            self.assertGreater(record["pid"], 1)
            pidfd = os.pidfd_open(record["pid"])
            start = Path(f"/proc/{record['pid']}/stat").read_text().rsplit(")", 1)[1].split()[19]
            self.assertEqual(start, record["start"], "worker identity changed before observation")
            self.assertFalse(observe_worker_exit(pidfd, 0), "worker exited before its parent")
            identity_verified = True
            parent.stdin.write(b"X")
            parent.stdin.flush()
            self.assertEqual(parent.wait(timeout=3), 0)
            return observe_worker_exit(pidfd, 3)
        finally:
            try:
                try:
                    parent.stdin.close()
                except BrokenPipeError:
                    pass
                try:
                    parent.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    parent.kill()
                    parent.wait(timeout=3)
                parent.stdout.close()
            finally:
                if pidfd is not None:
                    try:
                        if identity_verified:
                            cleanup_observed_worker(pidfd)
                            self.assertTrue(observe_worker_exit(pidfd, 3),
                                            "test-owned worker did not terminate during cleanup")
                    finally:
                        os.close(pidfd)

    def test_worker_terminates_when_parent_exits(self):
        """The unchanged kernel guard ends the observed child before its fallback timer."""
        self.assertTrue(self.parent_death_observed(guarded=True),
                        "validation worker survived parent death")

    def test_parent_death_observation_does_not_poll_recycled_pids(self):
        """The lifecycle proof cannot depend on a bare PID after parent exit."""
        result = subprocess.CompletedProcess([], 0, stdout="123456789\n", stderr="")
        with patch.object(subprocess, "run", return_value=result), \
                patch.object(self, "process_running", side_effect=AssertionError("PID-only observation")), \
                patch.object(os, "killpg", side_effect=AssertionError("unpinned group cleanup")):
            self.test_worker_terminates_when_parent_exits()

    def test_parent_death_probe_rejects_an_unguarded_child(self):
        """Cleanup must not turn a surviving unguarded worker into proof of exit."""
        probe = getattr(self, "parent_death_observed", None)
        self.assertTrue(callable(probe), "exact-child parent-death probe is missing")
        self.assertFalse(probe(guarded=False))

    def test_observed_child_cleanup_preserves_real_errors(self):
        """Disappearance is idempotent; permission failures remain test failures."""
        cleanup = globals().get("cleanup_observed_worker")
        self.assertTrue(callable(cleanup), "pidfd cleanup is missing")
        with patch.object(signal, "pidfd_send_signal", side_effect=ProcessLookupError) as send:
            cleanup(123)
        send.assert_called_once_with(123, signal.SIGKILL)
        with patch.object(signal, "pidfd_send_signal", side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                cleanup(123)

    def test_observed_exit_requires_readiness_not_just_a_deadline(self):
        """Elapsed waiting alone never establishes that the observed child exited."""
        import select
        observe = globals().get("observe_worker_exit")
        self.assertTrue(callable(observe), "pidfd observer is missing")
        with patch.object(select, "select", return_value=([], [], [])):
            self.assertFalse(observe(123, 0.01))
        with patch.object(select, "select", return_value=([123], [], [])):
            self.assertTrue(observe(123, 0.01))

    def test_parent_death_probe_closes_its_process_descriptor(self):
        """A successful lifecycle check must not retain the kernel process handle."""
        probe = getattr(self, "parent_death_observed", None)
        self.assertTrue(callable(probe), "exact-child parent-death probe is missing")
        opened = []
        original = os.pidfd_open
        def record(pid, flags=0):
            """Retain descriptor numbers for post-probe close verification."""
            fd = original(pid, flags)
            opened.append(fd)
            return fd
        with patch.object(os, "pidfd_open", side_effect=record):
            self.assertTrue(probe(guarded=True))
        self.assertEqual(len(opened), 1)
        with self.assertRaises(OSError):
            os.fstat(opened[0])

    def test_manifest_matches_actual_budgets(self):
        """Declared limits match the code without claiming an OS sandbox."""
        manifest = json.loads((Path(__file__).resolve().parents[1] / "reporting/pdf-engine.v1.json").read_text())
        limits = manifest["postvalidation_envelope"]
        for key, value in {"pdf_bytes":worker.PDF_BYTES, "memory_bytes":worker.MEMORY_BYTES,
                           "cpu_seconds":worker.CPU_SECONDS, "wall_seconds":worker.WALL_SECONDS,
                           "result_bytes":worker.RESULT_BYTES, "open_files":worker.OPEN_FILES}.items():
            self.assertEqual(limits[key], value)
        self.assertFalse(limits["os_sandbox_claimed"])
        self.assertFalse(limits["total_operation_budget_claimed"])

    def test_worker_rejects_tampered_request_identity(self):
        """Worker-side hashing rejects tampering even after host preflight."""
        with tempfile.TemporaryFile() as request:
            request.write(b"1 metadata " + b"0" * 64 + b"\n" + self.pdf)
            request.flush()
            with self.assertRaisesRegex(ValueError, "validation digest mismatch"):
                worker._read_request(request.fileno())

    def test_worker_rejects_unknown_operation_and_oversized_request(self):
        """The worker accepts neither dynamic operations nor an oversized payload."""
        with tempfile.TemporaryFile() as request:
            request.write(f"1 other {self.digest}\n".encode() + self.pdf)
            request.flush()
            with self.assertRaisesRegex(ValueError, "unsupported validation operation"):
                worker._read_request(request.fileno())
            with patch.object(worker, "PDF_BYTES", 8):
                with self.assertRaisesRegex(ValueError, "invalid validation request size"):
                    worker._read_request(request.fileno())

    def test_worker_rejects_named_or_aliased_descriptors_before_setup(self):
        """Only distinct anonymous regular files may cross the worker boundary."""
        with tempfile.NamedTemporaryFile() as named, tempfile.TemporaryFile() as anonymous:
            with patch.object(worker, "_limits") as limits:
                self.assertEqual(worker.main(["worker", str(named.fileno()),
                                              str(anonymous.fileno()), str(os.getpid())]), 64)
                limits.assert_not_called()
            alias = os.dup(anonymous.fileno())
            try:
                with patch.object(worker, "_limits") as limits:
                    self.assertEqual(worker.main(["worker", str(alias),
                                                  str(anonymous.fileno()), str(os.getpid())]), 64)
                    limits.assert_not_called()
            finally:
                os.close(alias)

    def test_contradictory_accessibility_success_is_rejected(self):
        """Success cannot carry missing tags or integer Boolean substitutes."""
        for value in (False, 1, None):
            record = self.metadata_record(); record["operation"] = "accessibility"
            record["decision"] = {"errors": [], "marked": value, "struct_tree_root": True}
            with self.subTest(value=value), self.assertRaisesRegex(RuntimeError, "pdf_validation_failed"):
                boundary._decode(json.dumps(record).encode(), "accessibility", self.digest)

    def test_unsupported_platform_is_fail_closed(self):
        """Unvalidated platforms cannot silently run outside the Linux envelope."""
        with patch.object(boundary.sys, "platform", "unsupported"), patch.object(boundary, "_start") as start:
            with self.assertRaisesRegex(RuntimeError, "^pdf_validation_unavailable$"):
                boundary._run("metadata", self.pdf, self.digest)
        start.assert_not_called()

    def test_kernel_address_limit_rejects_excess_allocation(self):
        """A separate constrained process cannot allocate beyond its memory budget."""
        code = ("from reporting._pdf_validation_worker import _limits,MEMORY_BYTES;_limits();\n"
                "try:\n x=bytearray(MEMORY_BYTES*2)\nexcept MemoryError:\n print('LIMITED')\n")
        result = subprocess.run([sys.executable, "-c", code], cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True, timeout=5, check=True)
        self.assertEqual(result.stdout.strip(), "LIMITED")

    def test_safe_path_mode_imports_only_the_pinned_worker_root(self):
        """Keep safe-path mode enabled while explicitly locating the trusted module."""
        with patch.dict(os.environ, {"PYTHONSAFEPATH": "1", "PYTHONPATH": ""}):
            result = boundary._run("metadata", self.pdf, self.digest)
            self.assertEqual(os.environ["PYTHONSAFEPATH"], "1")
            self.assertEqual(os.environ["PYTHONPATH"], "")
        self.assertEqual(result["errors"], [])

    def test_worker_environment_matches_existing_renderer_allowlist(self):
        """Copy only approved environment values without changing the hosting process."""
        values = {"PYTHONSAFEPATH": "1", "PYTHONPATH": "synthetic-foreign-path",
                  "PYTHONHOME": "synthetic-foreign-home", "LANG": "C.UTF-8",
                  "VALIDATION_TEST_SENTINEL": "must-not-be-forwarded"}
        with patch.dict(os.environ, values), patch.object(boundary.subprocess, "Popen") as launch:
            boundary._start([sys.executable, "-I", str(Path(worker.__file__).resolve())], (3, 4))
            self.assertEqual(os.environ["PYTHONPATH"], "synthetic-foreign-path")
            self.assertEqual(os.environ["PYTHONSAFEPATH"], "1")
        child = launch.call_args.kwargs["env"]
        self.assertEqual(child["LANG"], "C.UTF-8")
        self.assertTrue(set(child).issubset({"PATH", "HOME", "LANG", "LC_ALL",
                         "LC_CTYPE", "TZ", "FONTCONFIG_FILE", "FONTCONFIG_PATH"}))
        for name in ("PYTHONPATH", "PYTHONHOME", "PYTHONSAFEPATH", "VALIDATION_TEST_SENTINEL"):
            self.assertNotIn(name, child)


    def test_inherited_python_home_cannot_replace_the_validator_runtime(self):
        """A foreign Python home is ignored rather than selecting a different runtime."""
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"PYTHONHOME": directory,
                                        "PYTHONPATH": directory, "PYTHONSAFEPATH": "1"}):
                result = boundary._run("metadata", self.pdf, self.digest)
                self.assertEqual(os.environ["PYTHONHOME"], directory)
            self.assertEqual(result["errors"], [])

    def test_native_worker_is_launched_with_isolated_python(self):
        """The real validation request uses an explicit script with isolated startup."""
        with patch.object(boundary, "_start", wraps=boundary._start) as start:
            result = boundary._run("metadata", self.pdf, self.digest)
        command = start.call_args.args[0]
        self.assertEqual(command[:3], [sys.executable, "-I", str(Path(worker.__file__).resolve())])
        self.assertEqual(result["errors"], [])

    def test_python_startup_hooks_are_not_loaded_from_foreign_path(self):
        """Untrusted startup hooks cannot run before the fixed validation worker."""
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "startup-loaded"
            (Path(directory) / "sitecustomize.py").write_text(
                f"from pathlib import Path;Path({str(marker)!r}).write_text('unexpected')")
            with patch.dict(os.environ, {"PYTHONPATH": directory, "PYTHONSAFEPATH": "1"}):
                result = boundary._run("metadata", self.pdf, self.digest)
            self.assertFalse(marker.exists())
            self.assertEqual(result["errors"], [])


if __name__ == "__main__":
    unittest.main()
