"""Verify the bounded native PDF renderer execution envelope."""

from __future__ import annotations

import hashlib
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from reporting import adapters


ROOT = Path(__file__).resolve().parents[1]


class RendererEnvelopeTests(unittest.TestCase):
    @staticmethod
    def process_running(pid):
        """Observe a test-owned process while tolerating concurrent kernel removal."""
        try:
            state = Path(f"/proc/{pid}/stat").read_text().split()[2]
        except (FileNotFoundError, ProcessLookupError):
            return False
        return state != "Z"

    @staticmethod
    def cleanup_process(process):
        """Always stop and reap test-owned processes even after an assertion fails."""
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)

    def test_manifest_declares_enforced_renderer_envelope(self):
        """Verify manifest declares enforced renderer envelope."""
        manifest = json.loads(
            (ROOT / "reporting" / "pdf-engine.v1.json").read_text(encoding="utf-8")
        )
        envelope = manifest["execution_envelope"]
        self.assertEqual(envelope["protocol_version"], 1)
        self.assertEqual(envelope["html_bytes"], 64 * 1024 * 1024)
        self.assertEqual(envelope["pdf_bytes"], 8 * 1024 * 1024)
        self.assertEqual(envelope["memory_bytes"], 1024 * 1024 * 1024)
        self.assertEqual(envelope["cpu_seconds"], 20)
        self.assertEqual(envelope["wall_seconds"], 30)
        self.assertEqual(envelope["open_files"], 128)
        self.assertEqual(envelope["result_bytes"], 64 * 1024)
        self.assertEqual(envelope["process_boundary"], "subprocess")
        self.assertFalse(envelope["os_sandbox_claimed"])
        self.assertEqual(envelope["disable_environment"], "OMNIGENIS_PDF_RENDERER_DISABLED=1")

    def test_renderer_disable_path_fails_closed(self):
        """Verify renderer disable path fails closed."""
        with patch.dict(os.environ, {"OMNIGENIS_PDF_RENDERER_DISABLED": "1"}):
            with self.assertRaisesRegex(RuntimeError, "pdf_engine_unavailable"):
                adapters._render_pdf("<!doctype html><html></html>", "0" * 64)

    def test_renderer_disable_path_withholds_candidate_at_adapter_boundary(self):
        """Verify renderer disable path withholds candidate at adapter boundary."""
        presentation_ir = {
            "report_id": "synthetic-report",
            "locale_id": "en-US",
            "components": [
                {
                    "component_id": "summary",
                    "component_type": "semantic-section",
                    "title": "Summary",
                    "state": "PRESENT",
                    "content": {},
                }
            ],
        }
        with patch.dict(os.environ, {"OMNIGENIS_PDF_RENDERER_DISABLED": "1"}):
            result = adapters.build_html_css_and_pdf_adapter(
                presentation_ir=presentation_ir
            )
        self.assertFalse(result.passed)
        self.assertEqual(result.pdf_reason, "pdf_engine_unavailable")
        self.assertIsNone(result.pdf_bytes)
        self.assertIsNone(result.pdf_sha256)
        self.assertIsNone(result.conformance)
        self.assertIsNotNone(result.html)

    def test_parent_html_limit_fails_before_worker_start(self):
        """Verify parent html limit fails before worker start."""
        with (
            patch.object(adapters, "PDF_RENDER_MAX_HTML_BYTES", 64),
            patch.object(adapters, "_start_pdf_render_worker") as start,
        ):
            with self.assertRaisesRegex(RuntimeError, "pdf_render_input_too_large"):
                adapters._render_pdf("x" * 65, hashlib.sha256(b"x" * 65).hexdigest())
        start.assert_not_called()

    def run_worker_request(self, html, digest):
        """Exercise the real worker with anonymous descriptors and its parent PID."""
        from reporting import _pdf_render_worker as worker
        with (tempfile.TemporaryFile() as request, tempfile.TemporaryFile() as pdf,
              tempfile.TemporaryFile() as result):
            fds = (request.fileno(), pdf.fileno(), result.fileno())
            request.write(f"{worker.PROTOCOL_VERSION} {digest}\n".encode() + html.encode())
            request.flush()
            request.seek(0)
            completed = subprocess.run([
                sys.executable, "-I", str(ROOT / "reporting" / "_pdf_render_worker.py"),
                *(str(fd) for fd in fds), str(os.getpid()),
            ], pass_fds=fds, cwd=ROOT, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=10, check=False)
            self.assertEqual(completed.returncode, 0)
            result.seek(0)
            pdf.seek(0)
            return json.loads(result.read()), pdf.read()

    def test_worker_applies_limits_and_preserves_deterministic_pdf(self):
        """Two real native renders keep exact PDF bytes and enforced limits."""
        from reporting import _pdf_render_worker as worker
        html = "<!doctype html><html><body><p>bounded-render</p></body></html>"
        digest = hashlib.sha256(html.encode()).hexdigest()
        outputs = []
        for _ in range(2):
            record, data = self.run_worker_request(html, digest)
            self.assertEqual(record["status"], "PASS")
            self.assertEqual(record["limits"], {
                "memory_bytes": worker.MEMORY_BYTES, "cpu_seconds": worker.CPU_SECONDS,
                "file_bytes": worker.PDF_BYTES, "open_files": worker.OPEN_FILES,
            })
            self.assertTrue(data.startswith(b"%PDF-1.7"))
            self.assertEqual(record["pdf_sha256"], hashlib.sha256(data).hexdigest())
            outputs.append(data)
        self.assertEqual(outputs[0], outputs[1])

    def test_worker_error_response_is_fixed_and_content_free(self):
        """Verify worker error response is fixed and content free."""
        error = adapters._decode_pdf_render_result(
            json.dumps(
                {
                    "protocol_version": 1,
                    "status": "FAIL",
                    "error": "pdf_engine_unavailable",
                    "limits": {
                        "memory_bytes": adapters.PDF_RENDER_MEMORY_BYTES,
                        "cpu_seconds": adapters.PDF_RENDER_CPU_SECONDS,
                        "file_bytes": adapters.PDF_RENDER_MAX_PDF_BYTES,
                        "open_files": adapters.PDF_RENDER_OPEN_FILES,
                    },
                }
            ).encode("utf-8"),
            expected_pdf_path=None,
        )
        self.assertEqual(error, (None, "pdf_engine_unavailable"))

        private_detail = {
            "protocol_version": 1,
            "status": "FAIL",
            "error": "pdf_engine_unavailable",
            "limits": {
                "memory_bytes": adapters.PDF_RENDER_MEMORY_BYTES,
                "cpu_seconds": adapters.PDF_RENDER_CPU_SECONDS,
                "file_bytes": adapters.PDF_RENDER_MAX_PDF_BYTES,
                "open_files": adapters.PDF_RENDER_OPEN_FILES,
            },
            "detail": "PRIVATE-DETAIL",
        }
        with self.assertRaisesRegex(RuntimeError, "pdf_render_failed"):
            adapters._decode_pdf_render_result(
                json.dumps(private_detail).encode("ascii"), expected_pdf_path=None
            )

    def test_timeout_kills_renderer_process_group(self):
        """Verify timeout kills renderer process group."""
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "child.pid"
            script = (
                "import pathlib,subprocess,sys,time;"
                "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
                f"pathlib.Path({str(pid_file)!r}).write_text(str(p.pid));"
                "time.sleep(60)"
            )
            process = adapters._start_pdf_render_worker(
                [sys.executable, "-c", script],
                env=os.environ.copy(),
            )
            self.addCleanup(self.cleanup_process, process)
            deadline = time.monotonic() + 3
            while not pid_file.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(pid_file.exists())
            child_pid = int(pid_file.read_text())

            with self.assertRaisesRegex(RuntimeError, "pdf_render_failed"):
                adapters._wait_pdf_render_worker(process, wall_seconds=0.2)

            def child_running():
                return self.process_running(child_pid)

            deadline = time.monotonic() + 3
            while child_running() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertFalse(child_running())

    def test_crashed_worker_cleans_residual_descendant(self):
        """Verify crashed worker cleans residual descendant."""
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "child.pid"
            script = (
                "import pathlib,subprocess,sys;"
                "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
                f"pathlib.Path({str(pid_file)!r}).write_text(str(p.pid));"
                "raise SystemExit(7)"
            )
            process = adapters._start_pdf_render_worker(
                [sys.executable, "-c", script],
                env=os.environ.copy(),
            )
            self.addCleanup(self.cleanup_process, process)
            deadline = time.monotonic() + 3
            while not pid_file.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(pid_file.exists())
            child_pid = int(pid_file.read_text())

            self.assertEqual(
                adapters._wait_pdf_render_worker(process, wall_seconds=2), 7
            )

            def child_running():
                return self.process_running(child_pid)

            deadline = time.monotonic() + 3
            while child_running() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertFalse(child_running())

    def test_worker_crash_and_malformed_result_cannot_be_success(self):
        """Verify worker crash and malformed result cannot be success."""
        process = adapters._start_pdf_render_worker(
            [sys.executable, "-c", "raise SystemExit(7)"],
            env=os.environ.copy(),
        )
        self.assertEqual(adapters._wait_pdf_render_worker(process, wall_seconds=2), 7)
        with self.assertRaisesRegex(RuntimeError, "pdf_render_failed"):
            adapters._decode_pdf_render_result(
                b"not-json", expected_pdf_path=None
            )

    def test_worker_rejects_digest_mismatch_without_pdf_output(self):
        """Incorrect request identity never returns candidate bytes."""
        record, pdf = self.run_worker_request("<!doctype html><html></html>", "0" * 64)
        self.assertEqual(record["status"], "FAIL")
        self.assertEqual(record["error"], "pdf_render_protocol_invalid")
        self.assertEqual(pdf, b"")

    def test_parent_rejects_oversized_worker_output_before_read(self):
        """Verify parent rejects oversized worker output before read."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.pdf"
            path.write_bytes(b"%PDF-1.7\n" + b"x" * 64)
            record = json.dumps(
                {
                    "protocol_version": 1,
                    "status": "PASS",
                    "pdf_bytes": path.stat().st_size,
                    "pdf_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "limits": {
                        "memory_bytes": adapters.PDF_RENDER_MEMORY_BYTES,
                        "cpu_seconds": adapters.PDF_RENDER_CPU_SECONDS,
                        "file_bytes": adapters.PDF_RENDER_MAX_PDF_BYTES,
                        "open_files": adapters.PDF_RENDER_OPEN_FILES,
                    },
                }
            ).encode("ascii")
            with patch.object(adapters, "PDF_RENDER_MAX_PDF_BYTES", 32):
                with self.assertRaisesRegex(RuntimeError, "pdf_render_failed"):
                    adapters._decode_pdf_render_result(
                        record, expected_pdf_path=path
                    )


    def test_protocol_rejects_duplicate_fields_and_boolean_version(self):
        """Ambiguous metadata cannot become a successful protocol result."""
        limits = adapters._PDF_RENDER_LIMITS
        for version in (True, 1.0):
            data = json.dumps({"protocol_version": version, "status": "FAIL",
                               "error": "pdf_engine_unavailable", "limits": limits}).encode()
            with self.subTest(version=version):
                with self.assertRaisesRegex(RuntimeError, "pdf_render_failed"):
                    adapters._decode_pdf_render_result(data, expected_pdf_path=None)
        data = (b'{"protocol_version":1,"status":"PASS","status":"FAIL",'
                b'"error":"pdf_engine_unavailable","limits":' + json.dumps(limits).encode() + b'}')
        with self.assertRaisesRegex(RuntimeError, "pdf_render_failed"):
            adapters._decode_pdf_render_result(data, expected_pdf_path=None)

    def test_protocol_rejects_noninteger_resource_claims(self):
        """Equal-valued floats do not certify integer kernel resource limits."""
        limits = dict(adapters._PDF_RENDER_LIMITS)
        limits["cpu_seconds"] = float(limits["cpu_seconds"])
        data = json.dumps({"protocol_version": 1, "status": "FAIL",
                           "error": "pdf_engine_unavailable", "limits": limits}).encode()
        with self.assertRaisesRegex(RuntimeError, "pdf_render_failed"):
            adapters._decode_pdf_render_result(data, expected_pdf_path=None)

    def test_spawn_failure_is_fixed_and_content_free(self):
        """The native boundary does not expose OS exception details."""
        html = "<html></html>"
        with patch.object(adapters, "_start_pdf_render_worker", side_effect=OSError("PRIVATE-SPAWN")):
            with self.assertRaisesRegex(RuntimeError, "^pdf_render_failed$"):
                adapters._render_pdf(html, hashlib.sha256(html.encode()).hexdigest())

    def test_native_render_does_not_import_engine_in_parent(self):
        """Native libraries must load only inside the bounded child."""
        import builtins
        original = builtins.__import__
        def guard(name, *args, **kwargs):
            if name == "weasyprint" or name.startswith("weasyprint."):
                raise AssertionError("parent loaded native renderer")
            return original(name, *args, **kwargs)
        html = "<!doctype html><html><body>isolated fixture</body></html>"
        with patch("builtins.__import__", side_effect=guard):
            pdf = adapters._render_pdf(html, hashlib.sha256(html.encode()).hexdigest())
        self.assertTrue(pdf.startswith(b"%PDF-1.7"))

    def test_html_escaping_budget_preserves_supported_input_headroom(self):
        """HTML escaping can exceed an IR budget without widening the IR."""
        from reporting import _pdf_render_worker as worker
        self.assertGreaterEqual(worker.HTML_BYTES, 6 * 8 * 1024 * 1024 + 4096)

    def test_worker_lifetime_ends_when_launching_parent_exits(self):
        """A blocked worker cannot outlive its launching process indefinitely."""
        child_code = (
            "import os,sys,time;from reporting import _pdf_render_worker as w;"
            "w._arm_worker_lifetime(int(sys.argv[1]));"
            "print('READY',flush=True);time.sleep(60)"
        )
        parent_code = (
            "import os,subprocess,sys;"
            "p=subprocess.Popen([sys.executable,'-c',sys.argv[1],str(os.getpid())],"
            "stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True,text=True);"
            "ready=p.stdout.readline();"
            "print(str(p.pid)+':'+ready.strip(),flush=True);os._exit(0)"
        )
        completed = subprocess.run([sys.executable, "-c", parent_code, child_code],
                                   cwd=ROOT, capture_output=True, text=True, timeout=8)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        pid_text, ready = completed.stdout.strip().split(":", 1)
        pid = int(pid_text)
        self.assertEqual(ready, "READY")
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if not self.process_running(pid):
                return
            time.sleep(0.02)
        self.fail("worker survived parent exit")


    def test_native_protocol_uses_only_anonymous_temporary_files(self):
        """Parent death cannot leave named request or candidate artifacts."""
        original = adapters._start_pdf_render_worker
        observed = []
        def observe(command, *, env, pass_fds=()):
            observed.append(pass_fds)
            self.assertEqual(len(pass_fds), 3)
            for fd in pass_fds:
                self.assertEqual(os.fstat(fd).st_nlink, 0)
            return original(command, env=env, pass_fds=pass_fds)
        html = "<html><body>anonymous fixture</body></html>"
        with patch.object(adapters, "_start_pdf_render_worker", side_effect=observe):
            pdf = adapters._render_pdf(html, hashlib.sha256(html.encode()).hexdigest())
        self.assertTrue(observed)
        self.assertTrue(pdf.startswith(b"%PDF-1.7"))

    def test_temporary_file_failure_is_fixed(self):
        """Failure to allocate protocol storage withholds private OS details."""
        html = "<html></html>"
        with patch.object(adapters.tempfile, "TemporaryFile", side_effect=OSError("PRIVATE-TEMP")):
            with self.assertRaisesRegex(RuntimeError, "^pdf_render_failed$"):
                adapters._render_pdf(html, hashlib.sha256(html.encode()).hexdigest())


    def test_worker_timer_interrupts_a_blocked_native_call(self):
        """The independent OS timer terminates a native sleep without Python callbacks."""
        code = (
            "import os,ctypes;from reporting import _pdf_render_worker as w;"
            "w.WALL_SECONDS=0.15;w._arm_worker_lifetime(os.getppid());"
            "ctypes.CDLL(None).sleep(60)"
        )
        completed = subprocess.run([sys.executable, "-c", code], cwd=ROOT,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        self.assertEqual(completed.returncode, -signal.SIGALRM)

    def test_parent_identity_race_fails_closed(self):
        """An already changed parent prevents lifecycle setup and rendering."""
        code = (
            "import os;from reporting import _pdf_render_worker as w;"
            "w._arm_worker_lifetime(os.getpid())"
        )
        completed = subprocess.run([sys.executable, "-c", code], cwd=ROOT,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        self.assertNotEqual(completed.returncode, 0)

    def test_valid_ir_html_expansion_remains_inside_renderer_budget(self):
        """A valid escaped IR exceeding 8 MiB of HTML is not silently rejected."""
        from reporting import _pdf_render_worker as worker
        ir = {"report_id": "synthetic-report", "locale_id": "en-US", "components": [{
            "component_id": "summary", "component_type": "semantic-section",
            "title": "Summary", "state": "PRESENT", "content": {"text": '"' * 1300000},
        }]}
        observed = []
        def capture(html, digest):
            observed.append(len(html.encode()))
            with tempfile.TemporaryFile() as request:
                request.write(f"1 {digest}\n".encode() + html.encode())
                request.flush()
                decoded, actual = worker._read_request(request.fileno())
            self.assertEqual(decoded, html)
            self.assertEqual(actual, digest)
            raise RuntimeError("pdf_render_failed")
        with patch.object(adapters, "_render_pdf", side_effect=capture):
            result = adapters.build_html_css_and_pdf_adapter(presentation_ir=ir)
        self.assertEqual(result.pdf_reason, "pdf_render_failed")
        self.assertEqual(len(observed), 1)
        self.assertGreater(observed[0], 8 * 1024 * 1024)
        self.assertLess(observed[0], worker.HTML_BYTES)

    def test_spawn_failure_closes_all_protocol_descriptors(self):
        """Failed native startup does not retain request or candidate handles."""
        count = len(os.listdir("/proc/self/fd"))
        html = "<html></html>"
        with patch.object(adapters, "_start_pdf_render_worker", side_effect=OSError("fixture")):
            with self.assertRaisesRegex(RuntimeError, "^pdf_render_failed$"):
                adapters._render_pdf(html, hashlib.sha256(html.encode()).hexdigest())
        self.assertEqual(len(os.listdir("/proc/self/fd")), count)


    def test_process_disappears_during_proc_read_is_not_running(self):
        """Both Linux disappearance errors mean the test-owned process is gone."""
        for error in (FileNotFoundError(), ProcessLookupError()):
            with self.subTest(error=type(error).__name__):
                with patch.object(Path, "read_text", side_effect=error):
                    self.assertFalse(self.process_running(123456))


if __name__ == "__main__":
    unittest.main()
