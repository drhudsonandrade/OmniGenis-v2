"""Bound the generated-PDF raster worker to its launching parent and elapsed budget."""
from __future__ import annotations

from contextlib import ExitStack
import ctypes
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import resource
import select
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from reporting import _pdf_visual_worker as worker
from reporting import _pdf_render_worker as lifetime
from reporting import _pdf_process_sandbox as guards
from reporting import pdf_visual
from reporting.adapters import build_html_css_and_pdf_adapter

ROOT = Path(__file__).resolve().parents[1]


def synthetic_pdf() -> bytes:
    """Produce deterministic public synthetic bytes, never a real report."""
    rendered = build_html_css_and_pdf_adapter(presentation_ir={
        "report_id": "visual-worker-lifecycle-fixture",
        "locale_id": "en-US",
        "components": [{
            "component_id": "summary", "component_type": "semantic-section",
            "title": "Summary", "state": "PRESENT",
            "content": {"text": "SYNTHETIC_ONLY"},
        }],
    })
    if not rendered.passed:
        raise AssertionError(rendered.errors)
    return rendered.pdf_bytes


STALLED_WORKER = '''import ctypes,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from reporting import _pdf_visual_worker as worker
worker.WALL_SECONDS=float(sys.argv[3])
def blocked_native(pdf):
    os.write(1,b"READY\\n")
    while True:
        ctypes.CDLL(None).pause()
worker.inspect_visual_geometry=blocked_native
worker.main(int(sys.argv[2]))
'''


def process_identity(pid: int):
    """Allow a test-owned process to disappear without relying on PID reuse."""
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
        return fields[0], fields[19]
    except (FileNotFoundError, ProcessLookupError):
        return None


class VisualRasterLifecycleTests(unittest.TestCase):
    """Verify real disposable child lifetimes and fail-closed setup."""

    def mocked_main(self, failure=None):
        events = []
        stream = Mock(spec=["read"])
        stream.read.side_effect = lambda *a: events.append("read") or b"%PDF-SYNTHETIC"
        output = StringIO()
        def limit(*a):
            events.append("limit")
            if failure == "resource":
                raise OSError("SYNTHETIC_PRIVATE_RESOURCE_DETAIL")
        def bind(*a):
            events.append("lifetime")
            if failure == "lifetime":
                raise RuntimeError("SYNTHETIC_PRIVATE_LIFETIME_DETAIL")
        def timer(*a):
            events.append("timer")
            if failure == "timer":
                raise OSError("SYNTHETIC_PRIVATE_TIMER_DETAIL")
        parser = Mock(side_effect=lambda b: events.append("parse") or {"status":"PASS"})
        with tempfile.TemporaryDirectory(
            prefix="omnigenis-pdf-visual-supervisor-", dir="/tmp"
        ) as scratch, ExitStack() as stack:
            def trusted():
                events.append("scratch")
                return Path(scratch), os.open(scratch, os.O_PATH | os.O_DIRECTORY)
            for target, name, replacement in (
                (resource, "setrlimit", limit),
                (lifetime, "_arm_worker_lifetime", bind),
                (signal, "setitimer", timer),
                (worker, "_open_trusted_scratch", trusted),
                (guards, "enforce_pdf_landlock", Mock(side_effect=lambda *a, **kw: events.append("landlock"))),
                (guards, "enforce_pdf_network_filter", Mock(side_effect=lambda: events.append("seccomp"))),
                (worker, "inspect_visual_geometry", parser),
                (sys, "stdin", SimpleNamespace(buffer=stream)),
                (sys, "stdout", output),
            ):
                stack.enter_context(patch.object(target, name, replacement))
            worker.main(os.getpid())
        return json.loads(output.getvalue()), events, stream, parser

    def test_resource_lifetime_timer_input_and_native_order(self):
        """All admission and lifetime prerequisites run before candidate reads."""
        record, events, stream, parser = self.mocked_main()
        self.assertEqual(record, {"status":"PASS"})
        self.assertEqual(events, ["limit"] * 5 + ["lifetime", "timer", "scratch",
                                  "landlock", "seccomp", "read", "parse"])
        stream.read.assert_called_once_with(worker.MAX_PDF_BYTES + 1)
        parser.assert_called_once_with(b"%PDF-SYNTHETIC")

    def test_lifetime_and_timer_failures_block_without_input_or_error_leaks(self):
        """No fallback to unrestricted raster parsing after setup failure."""
        for failure in ("resource", "lifetime", "timer"):
            with self.subTest(failure=failure):
                record, events, stream, parser = self.mocked_main(failure=failure)
                self.assertEqual(record["status"], "BLOCKED")
                self.assertEqual(record["errors"], ["pdf_visual_worker_unavailable"])
                self.assertIsNone(record["pdf_sha256"])
                self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(record))
                stream.read.assert_not_called()
                parser.assert_not_called()
                if failure == "resource":
                    self.assertNotIn("lifetime", events)
                if failure == "lifetime":
                    self.assertNotIn("timer", events)

    def test_invalid_or_missing_parent_identity_fails_closed_in_actual_worker(self):
        """Missing, malformed or stale PID never permits candidate inspection."""
        for args in ([], ["not-a-pid"], ["0"], ["1"], [str(os.getpid()+1)], ["1", "2"]):
            with self.subTest(args=args):
                child = subprocess.run(
                    [sys.executable, "-I", str(ROOT / "reporting/_pdf_visual_worker.py"), *args],
                    input=b"%PDF-SYNTHETIC", capture_output=True, timeout=4, cwd=ROOT,
                )
                self.assertEqual(child.returncode, 0, child.stderr[-300:])
                record = json.loads(child.stdout)
                self.assertEqual(record["errors"], ["pdf_visual_worker_unavailable"])
                self.assertIsNone(record["pdf_sha256"])

    def test_public_launcher_supplies_its_actual_parent_identity(self):
        """The caller binds the PID without changing the raster evidence protocol."""
        pdf = synthetic_pdf()
        true_popen = subprocess.Popen
        with patch.object(pdf_visual.subprocess, "Popen", wraps=true_popen) as launch:
            result = pdf_visual.validate_pdf_visual_geometry(
                pdf_bytes=pdf, expected_pdf_sha256=hashlib.sha256(pdf).hexdigest()
            )
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(launch.call_args.args[0], [
            sys.executable, "-I", str(Path(worker.__file__)), str(os.getpid())
        ])
        self.assertEqual(launch.call_args.kwargs["start_new_session"], True)

    def test_independent_timer_terminates_blocked_native_code(self):
        """A kernel SIGALRM interrupts native code without a Python callback."""
        with tempfile.TemporaryDirectory(
            prefix="omnigenis-pdf-visual-supervisor-", dir="/tmp"
        ) as scratch:
            child = subprocess.run(
                [sys.executable, "-I", "-c", STALLED_WORKER, str(ROOT),
                 str(os.getpid()), "0.25"],
                input=b"%PDF-SYNTHETIC", capture_output=True, timeout=4,
                cwd=ROOT, env=dict(os.environ, TMPDIR=scratch),
            )
        self.assertEqual(child.stdout, b"READY\n", child.stderr[-300:])
        self.assertEqual(child.returncode, -signal.SIGALRM)

    def test_parent_death_terminates_ready_worker_before_its_timer(self):
        """A parent exiting without cleanup cannot leave this worker running."""
        parent_code = '''import json,os,select,subprocess,sys
child=subprocess.Popen([sys.executable,"-I","-c",sys.argv[1],sys.argv[2],str(os.getpid()),"20"],
                       stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
if not select.select([child.stdout],[],[],4)[0] or child.stdout.readline()!=b"READY\\n":
    child.kill();child.wait()
    print(json.dumps({"ready":False,"pid":child.pid}),flush=True)
    sys.exit(2)
print(json.dumps({"ready":True,"pid":child.pid}),flush=True)
sys.stdin.buffer.read(1)
os._exit(0)
'''
        child_pid = None
        identity = None
        scratch = tempfile.TemporaryDirectory(
            prefix="omnigenis-pdf-visual-supervisor-", dir="/tmp"
        )
        parent = subprocess.Popen(
            [sys.executable, "-I", "-c", parent_code, STALLED_WORKER, str(ROOT)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=ROOT, env=dict(os.environ, TMPDIR=scratch.name),
        )
        try:
            self.assertTrue(select.select([parent.stdout], [], [], 5)[0])
            record = json.loads(parent.stdout.readline())
            child_pid = record["pid"]
            self.assertTrue(record["ready"])
            identity = process_identity(child_pid)
            self.assertIsNotNone(identity)
            self.assertNotEqual(identity[0], "Z")
            parent.stdin.write(b"X")
            parent.stdin.flush()
            self.assertEqual(parent.wait(timeout=3), 0)
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                current = process_identity(child_pid)
                if current is None or current[0] == "Z":
                    break
                time.sleep(0.01)
            current = process_identity(child_pid)
            self.assertTrue(current is None or current[0] == "Z", "orphan raster worker survived")
        finally:
            if parent.poll() is None:
                parent.kill()
            parent.wait(timeout=3)
            for stream in (parent.stdin, parent.stdout, parent.stderr):
                stream.close()
            if child_pid is not None and identity is not None:
                current = process_identity(child_pid)
                if current is not None and current[0] != "Z" and current[1] == identity[1]:
                    try:
                        os.kill(child_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            scratch.cleanup()

    def test_manifest_limits_truthful_lifecycle_claims(self):
        """Worker lifetime is not arbitrary-descendant cleanup or an OS sandbox."""
        manifest = json.loads((ROOT/"reporting/pdf-visual-engine.v1.json").read_text())
        item = manifest["worker_lifecycle"]
        self.assertEqual(item["parent_identity"], "explicit launching process PID")
        self.assertEqual(item["parent_death_signal"], "SIGKILL; bound to launching thread")
        self.assertEqual(item["independent_wall_seconds"], 30)
        self.assertEqual(item["timer"], "ITIMER_REAL / SIGALRM default action")
        self.assertFalse(item["startup_before_registration_covered"])
        self.assertFalse(item["arbitrary_descendant_cleanup_claimed"])
        self.assertFalse(item["os_sandbox_claimed"])
        self.assertFalse(item["aggregate_resource_closure_claimed"])
        self.assertFalse(item["raster_executor_inherits_parent_death_signal"])
        self.assertTrue(item["resource_limits_unchanged"])

    def test_isolated_helper_import_ignores_untrusted_pythonpath(self):
        """Only the resolved worker sibling can provide the lifetime helper."""
        with tempfile.TemporaryDirectory(prefix="omnigenis-visual-import-") as td:
            root = Path(td)
            marker = root / "untrusted-import-ran"
            malicious = "from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('SYNTHETIC')\n"
            (root / "_pdf_render_worker.py").write_text(malicious)
            (root / "sitecustomize.py").write_text(malicious)
            with tempfile.TemporaryDirectory(
                prefix="omnigenis-pdf-visual-supervisor-", dir="/tmp"
            ) as scratch:
                env = dict(os.environ, PYTHONPATH=str(root), PYTHONHOME=str(root),
                           TMPDIR=scratch)
                child = subprocess.run(
                    [sys.executable, "-I", str(ROOT/"reporting/_pdf_visual_worker.py"),
                     str(os.getpid())],
                    input=b"%PDF-SYNTHETIC", capture_output=True, timeout=5, cwd=root, env=env,
                )
            self.assertEqual(child.returncode, 0, child.stderr[-300:])
            self.assertFalse(marker.exists())
            self.assertNotIn("pdf_visual_worker_unavailable",
                             json.dumps(json.loads(child.stdout)))


if __name__ == "__main__":
    unittest.main()
