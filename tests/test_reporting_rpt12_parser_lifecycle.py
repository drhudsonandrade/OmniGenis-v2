"""Prove explicit parent binding and independent deadlines for auxiliary parsers."""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import importlib
from io import StringIO
import json
import os
from pathlib import Path
import resource
import select
import signal
import subprocess
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from reporting import _pdf_process_sandbox as guards
from reporting import _pdf_render_worker as lifetime
from reporting import pdf_content, pdf_safety
from reporting.adapters import build_html_css_and_pdf_adapter

ROOT = Path(__file__).resolve().parents[1]
WORKERS = (
    ("_pdf_content_worker", "extract_document", "pdf_content_worker_unavailable"),
    ("_pdf_safety_worker", "inspect_document", "pdf_safety_worker_unavailable"),
)


def process_identity(pid: int) -> tuple[str, str] | None:
    """Read state and start time, allowing a test-owned process to disappear."""
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
        return fields[0], fields[19]
    except (FileNotFoundError, ProcessLookupError):
        return None


# This code executes only in disposable test children; no real PDF or network data.
STALLED_PARSER = '''import ctypes,importlib,os,sys
sys.path.insert(0,sys.argv[1])
worker=importlib.import_module("reporting."+sys.argv[2])
parent=int(sys.argv[3])
if len(sys.argv)>4:
    worker.WALL_SECONDS=float(sys.argv[4])
libc=ctypes.CDLL(None)
def stalled(data):
    """Announce completed guards and block in native code, not a Python handler."""
    os.write(1,b"READY\\n")
    while True:
        libc.pause()
name="extract_document" if sys.argv[2]=="_pdf_content_worker" else "inspect_document"
setattr(worker,name,stalled)
worker.main(parent)
'''


class ParserLifecycleTests(unittest.TestCase):
    """Exercise only test-owned children; never attach kernel guards to the host."""

    def _mock_main(self, name: str, parser: str, failure: str | None = None):
        """Observe admission ordering with all irreversible operations mocked."""
        module = importlib.import_module("reporting." + name)
        events = []
        source = Mock(spec=["read"])
        source.read.side_effect = lambda *a: events.append("read") or b"%PDF-SYNTHETIC"
        output = StringIO()
        limits = Mock(side_effect=lambda *a: events.append("limit"))
        bind = Mock(side_effect=lambda *a: events.append("lifetime"))
        timer = Mock(side_effect=lambda *a: events.append("timer"))
        landlock = Mock(side_effect=lambda *a: events.append("landlock"))
        seccomp = Mock(side_effect=lambda *a: events.append("seccomp"))
        parse = Mock(side_effect=lambda *a: events.append("parse") or {"status": "PASS"})
        if failure == "lifetime":
            bind.side_effect = RuntimeError("SYNTHETIC_PRIVATE_LIFECYCLE_DETAIL")
        if failure == "timer":
            timer.side_effect = OSError("SYNTHETIC_PRIVATE_TIMER_DETAIL")
        with ExitStack() as stack:
            for obj, attr, replacement in (
                (resource, "setrlimit", limits),
                (lifetime, "_arm_worker_lifetime", bind),
                (signal, "setitimer", timer),
                (guards, "enforce_pdf_landlock", landlock),
                (guards, "enforce_pdf_network_filter", seccomp),
                (module, parser, parse),
                (sys, "stdin", SimpleNamespace(buffer=source)),
                (sys, "stdout", output),
            ):
                stack.enter_context(patch.object(obj, attr, replacement))
            module.main(os.getpid())
        return json.loads(output.getvalue()), events, source, parse, bind, timer, landlock, seccomp

    def test_lifecycle_and_timer_precede_guards_input_and_parser(self):
        """The original ten-second budget becomes independently kernel-enforced."""
        for name, parser, _ in WORKERS:
            with self.subTest(worker=name):
                record, events, source, parse, bind, timer, _, _ = self._mock_main(name, parser)
                self.assertEqual(record, {"status": "PASS"})
                self.assertEqual(events, ["limit", "limit", "limit", "lifetime", "timer",
                                          "landlock", "seccomp", "read", "parse"])
                bind.assert_called_once_with(os.getpid())
                timer.assert_called_once_with(signal.ITIMER_REAL, 10)
                source.read.assert_called_once_with(8 * 1024 * 1024 + 1)
                parse.assert_called_once_with(b"%PDF-SYNTHETIC")

    def test_lifetime_registration_failure_never_reads_or_parses_input(self):
        """No unrestricted fallback or exception text after failed parent binding."""
        for name, parser, error in WORKERS:
            with self.subTest(worker=name):
                record, _, source, parse, _, timer, landlock, seccomp = self._mock_main(name, parser, "lifetime")
                self.assertEqual(record["errors"], [error])
                self.assertEqual(record["status"], "BLOCKED")
                self.assertIsNone(record["pdf_sha256"])
                self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(record))
                for method in (source.read, parse, timer, landlock, seccomp):
                    method.assert_not_called()

    def test_timer_failure_never_reads_or_parses_input(self):
        """An independent timer is mandatory, even with a supervisor timeout."""
        for name, parser, error in WORKERS:
            with self.subTest(worker=name):
                record, _, source, parse, bind, _, landlock, seccomp = self._mock_main(name, parser, "timer")
                self.assertEqual(record["errors"], [error])
                self.assertIsNone(record["pdf_sha256"])
                self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(record))
                bind.assert_called_once_with(os.getpid())
                for method in (source.read, parse, landlock, seccomp):
                    method.assert_not_called()

    def test_missing_invalid_or_changed_parent_fails_closed_at_real_entrypoint(self):
        """Missing or wrong launch identity cannot create candidate evidence."""
        for name, _, error in WORKERS:
            for arguments in ([], ["not-a-pid"], ["0"], ["1"], [str(os.getpid() + 1)], ["1", "2"]):
                with self.subTest(worker=name, arguments=arguments):
                    child = subprocess.run(
                        [sys.executable, "-I", str(ROOT / "reporting" / (name + ".py")), *arguments],
                        input=b"%PDF-SYNTHETIC", capture_output=True, timeout=3, cwd=ROOT,
                    )
                    self.assertEqual(child.returncode, 0, child.stderr[-300:])
                    record = json.loads(child.stdout)
                    self.assertEqual(record["errors"], [error])
                    self.assertIsNone(record["pdf_sha256"])

    def test_launchers_pass_their_actual_pid_without_changing_evidence_protocol(self):
        """The caller binds identity at spawn, not by inferring it in an orphan."""
        ir = {"report_id": "synthetic-lifecycle-report", "locale_id": "en-US", "components": [{
            "component_id": "summary", "component_type": "semantic-section", "title": "Summary",
            "state": "PRESENT", "content": {"text": "SYNTHETIC_ONLY"},
        }]}
        result = build_html_css_and_pdf_adapter(presentation_ir=ir)
        self.assertTrue(result.passed, result.errors)
        digest = hashlib.sha256(json.dumps(ir, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        for name, parser, _ in WORKERS:
            with self.subTest(worker=name):
                worker = importlib.import_module("reporting." + name)
                expected = getattr(worker, parser)(result.pdf_bytes)
                self.assertEqual(expected["status"], "PASS")
                fake = SimpleNamespace(returncode=0, stdout=json.dumps(expected).encode())
                with patch.object(subprocess, "run", return_value=fake) as launch:
                    if name == "_pdf_content_worker":
                        accepted = pdf_content.validate_pdf_text_content(
                            presentation_ir=ir, expected_ir_sha256=digest,
                            pdf_bytes=result.pdf_bytes, expected_pdf_sha256=result.pdf_sha256,
                        )
                    else:
                        accepted = pdf_safety.validate_pdf_object_safety(
                            pdf_bytes=result.pdf_bytes, expected_pdf_sha256=result.pdf_sha256,
                        )
                self.assertTrue(accepted.passed, accepted.errors)
                self.assertEqual(launch.call_args.args[0], [sys.executable, "-I", str(Path(worker.__file__)), str(os.getpid())])
                self.assertEqual(launch.call_args.kwargs["timeout"], 10)

    def test_independent_timer_interrupts_blocked_native_parser(self):
        """A shortened fixture timer terminates native code while the parent lives."""
        for name, _, _ in WORKERS:
            with self.subTest(worker=name):
                child = subprocess.run(
                    [sys.executable, "-I", "-c", STALLED_PARSER, str(ROOT), name, str(os.getpid()), "0.25"],
                    input=b"%PDF-SYNTHETIC", capture_output=True, timeout=3, cwd=ROOT,
                )
                self.assertEqual(child.stdout, b"READY\n", child.stderr[-300:])
                self.assertEqual(child.returncode, -signal.SIGALRM)

    def test_parent_exit_terminates_ready_native_parser_before_its_deadline(self):
        """After a readiness handshake, the launching parent exits without cleanup."""
        parent_code = '''import json,os,select,subprocess,sys
code=sys.argv[1]
child=subprocess.Popen([sys.executable,"-I","-c",code,sys.argv[2],sys.argv[3],str(os.getpid())],
                       stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
ready=select.select([child.stdout],[],[],3)[0]
if not ready or child.stdout.readline()!=b"READY\\n":
    child.kill();child.wait()
    print(json.dumps({"ready":False,"pid":child.pid}),flush=True)
    sys.exit(2)
print(json.dumps({"ready":True,"pid":child.pid}),flush=True)
sys.stdin.buffer.read(1)
os._exit(0)
'''
        for name, _, _ in WORKERS:
            with self.subTest(worker=name):
                child_pid = None
                identity = None
                parent = subprocess.Popen(
                    [sys.executable, "-I", "-c", parent_code, STALLED_PARSER, str(ROOT), name],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=ROOT,
                )
                try:
                    self.assertTrue(select.select([parent.stdout], [], [], 4)[0], "readiness timed out")
                    record = json.loads(parent.stdout.readline())
                    child_pid = record["pid"]
                    self.assertTrue(record["ready"])
                    identity = process_identity(child_pid)
                    self.assertIsNotNone(identity)
                    self.assertNotEqual(identity[0], "Z")
                    parent.stdin.write(b"X")
                    parent.stdin.flush()
                    self.assertEqual(parent.wait(timeout=2), 0)
                    deadline = time.monotonic() + 2
                    while time.monotonic() < deadline:
                        current = process_identity(child_pid)
                        if current is None or current[0] == "Z":
                            break
                        time.sleep(0.01)
                    current = process_identity(child_pid)
                    self.assertTrue(current is None or current[0] == "Z", "orphan worker survived")
                finally:
                    if parent.poll() is None:
                        parent.kill()
                    parent.wait(timeout=3)
                    for stream in (parent.stdin, parent.stdout, parent.stderr):
                        stream.close()
                    # Never signal a recycled PID; compare the observed process start time.
                    if child_pid is not None and identity is not None:
                        current = process_identity(child_pid)
                        if current is not None and current[0] != "Z" and current[1] == identity[1]:
                            try:
                                os.kill(child_pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass

    def test_manifest_distinguishes_parent_binding_from_complete_operation_limits(self):
        """No complete-process-tree, startup, raster or release guarantee is invented."""
        manifest = json.loads((ROOT / "reporting/pdf-engine.v1.json").read_text())
        item = manifest["process_local_sandbox"]["auxiliary_parser_workers"]["lifecycle"]
        self.assertEqual(item["parent_identity"], "explicit launching process PID")
        self.assertEqual(item["parent_death_signal"], "SIGKILL; bound to launching thread")
        self.assertEqual(item["independent_wall_seconds"], 10)
        self.assertEqual(item["timer"], "ITIMER_REAL / SIGALRM default action")
        self.assertFalse(item["arbitrary_descendant_cleanup_claimed"])
        self.assertFalse(item["startup_before_registration_covered"])
        self.assertFalse(item["aggregate_resource_closure_claimed"])
        self.assertFalse(item["visual_raster_worker_covered"])


if __name__ == "__main__":
    unittest.main()
