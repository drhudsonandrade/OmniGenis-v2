"""Verify the bounded native PDF renderer execution envelope."""

from __future__ import annotations

import hashlib
import json
import os
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
    def test_manifest_declares_enforced_renderer_envelope(self):
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

    def test_renderer_disable_path_fails_closed(self):
        with patch.dict(os.environ, {"OMNIGENIS_PDF_RENDERER_DISABLED": "1"}):
            with self.assertRaisesRegex(RuntimeError, "pdf_engine_unavailable"):
                adapters._render_pdf("<!doctype html><html></html>", "0" * 64)

    def test_parent_html_limit_fails_before_worker_start(self):
        with (
            patch.object(adapters, "PDF_RENDER_MAX_HTML_BYTES", 64),
            patch.object(adapters, "_start_pdf_render_worker") as start,
        ):
            with self.assertRaisesRegex(RuntimeError, "pdf_render_input_too_large"):
                adapters._render_pdf("x" * 65, hashlib.sha256(b"x" * 65).hexdigest())
        start.assert_not_called()

    def test_worker_applies_limits_and_preserves_deterministic_pdf(self):
        from reporting import _pdf_render_worker as worker

        html = "<!doctype html><html><body><p>bounded-render</p></body></html>"
        digest = hashlib.sha256(html.encode("utf-8")).hexdigest()
        outputs = []
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            for index in range(2):
                request = directory / f"request-{index}.json"
                pdf = directory / f"output-{index}.pdf"
                result = directory / f"result-{index}.json"
                request.write_bytes(
                    f"{worker.PROTOCOL_VERSION} {digest}\n".encode("ascii")
                    + html.encode("utf-8")
                )
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "reporting._pdf_render_worker",
                        str(request),
                        str(pdf),
                        str(result),
                    ],
                    cwd=ROOT,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0)
                record = json.loads(result.read_text(encoding="utf-8"))
                self.assertEqual(record["status"], "PASS")
                self.assertEqual(
                    record["limits"],
                    {
                        "memory_bytes": worker.MEMORY_BYTES,
                        "cpu_seconds": worker.CPU_SECONDS,
                        "file_bytes": worker.PDF_BYTES,
                        "open_files": worker.OPEN_FILES,
                    },
                )
                data = pdf.read_bytes()
                self.assertTrue(data.startswith(b"%PDF-1.7"))
                self.assertEqual(record["pdf_sha256"], hashlib.sha256(data).hexdigest())
                outputs.append(data)
        self.assertEqual(outputs[0], outputs[1])

    def test_worker_error_response_is_fixed_and_content_free(self):
        error = adapters._decode_pdf_render_result(
            json.dumps(
                {
                    "protocol_version": 1,
                    "status": "FAIL",
                    "error": "pdf_engine_unavailable",
                }
            ).encode("utf-8"),
            expected_pdf_path=None,
        )
        self.assertEqual(error, (None, "pdf_engine_unavailable"))

        with self.assertRaisesRegex(RuntimeError, "pdf_render_failed"):
            adapters._decode_pdf_render_result(
                b'{"protocol_version":1,"status":"FAIL","error":"PRIVATE-DETAIL"}',
                expected_pdf_path=None,
            )

    def test_timeout_kills_renderer_process_group(self):
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
            deadline = time.monotonic() + 3
            while not pid_file.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(pid_file.exists())
            child_pid = int(pid_file.read_text())

            with self.assertRaisesRegex(RuntimeError, "pdf_render_failed"):
                adapters._wait_pdf_render_worker(process, wall_seconds=0.2)

            def child_running():
                try:
                    state = Path(f"/proc/{child_pid}/stat").read_text().split()[2]
                except FileNotFoundError:
                    return False
                return state != "Z"

            deadline = time.monotonic() + 3
            while child_running() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertFalse(child_running())

    def test_worker_crash_and_malformed_result_cannot_be_success(self):
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
        from reporting import _pdf_render_worker as worker

        html = "<!doctype html><html></html>"
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            request = directory / "request.bin"
            pdf = directory / "candidate.pdf"
            result = directory / "result.json"
            request.write_bytes(
                f"{worker.PROTOCOL_VERSION} {'0' * 64}\n".encode("ascii")
                + html.encode("utf-8")
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "reporting._pdf_render_worker",
                    str(request),
                    str(pdf),
                    str(result),
                ],
                cwd=ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
            self.assertEqual(completed.returncode, 0)
            record = json.loads(result.read_text(encoding="utf-8"))
            self.assertEqual(record["status"], "FAIL")
            self.assertEqual(record["error"], "pdf_render_protocol_invalid")
            self.assertFalse(pdf.exists())

    def test_parent_rejects_oversized_worker_output_before_read(self):
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


if __name__ == "__main__":
    unittest.main()
