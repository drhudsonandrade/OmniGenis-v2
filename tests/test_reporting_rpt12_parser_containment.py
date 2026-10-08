"""Verify mandatory Linux guards at both existing auxiliary PDF parser boundaries."""
from __future__ import annotations

import ast
from contextlib import ExitStack
import importlib
from io import StringIO
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from reporting import _pdf_process_sandbox as guards
from reporting import _pdf_render_worker as lifetime
from reporting.adapters import build_html_css_and_pdf_adapter

ROOT = Path(__file__).resolve().parents[1]
WORKERS = (
    ("_pdf_content_worker", "extract_document", "pdf_content_worker_unavailable"),
    ("_pdf_safety_worker", "inspect_document", "pdf_safety_worker_unavailable"),
)


def synthetic_pdf() -> bytes:
    """Create only a generated, synthetic report using the supported public adapter."""
    result = build_html_css_and_pdf_adapter(presentation_ir={
        "report_id": "synthetic-parser-guard-report", "locale_id": "en-US",
        "components": [{
            "component_id": "summary", "component_type": "semantic-section",
            "title": "Summary", "state": "PRESENT",
            "content": {"text": "SYNTHETIC_ONLY"},
        }],
    })
    if not result.passed:
        raise AssertionError(result.errors)
    return result.pdf_bytes


class ParserContainmentTests(unittest.TestCase):
    """Keep input, parsing semantics and the host separate from child restrictions."""

    def _mock_main(self, name, parser_name, failure=None, platform="linux"):
        """Observe entrypoint ordering without applying irreversible host restrictions."""
        worker = importlib.import_module("reporting." + name)
        events = []
        source = Mock(spec=["read"])
        source.read.side_effect = lambda *args: events.append("read") or b"%PDF-SYNTHETIC"
        output = StringIO()
        limits = Mock(side_effect=lambda *args: events.append("limit"))
        landlock = Mock(side_effect=lambda *args: events.append("landlock"))
        network = Mock(side_effect=lambda: events.append("seccomp"))
        parser = Mock(side_effect=lambda data: events.append("parse") or {"status": "PASS"})
        if failure == "limits":
            limits.side_effect = OSError("SYNTHETIC_PRIVATE_LIMIT_DETAIL")
        elif failure == "landlock":
            landlock.side_effect = RuntimeError("SYNTHETIC_PRIVATE_GUARD_DETAIL")
        elif failure == "seccomp":
            network.side_effect = RuntimeError("SYNTHETIC_PRIVATE_GUARD_DETAIL")
        with ExitStack() as stack:
            stack.enter_context(patch.object(lifetime, "_arm_worker_lifetime", Mock()))
            stack.enter_context(patch.object(signal, "setitimer", Mock()))
            stack.enter_context(patch.object(resource, "setrlimit", limits))
            stack.enter_context(patch.object(guards, "enforce_pdf_landlock", landlock))
            stack.enter_context(patch.object(guards, "enforce_pdf_network_filter", network))
            stack.enter_context(patch.object(worker, parser_name, parser))
            stack.enter_context(patch.object(sys, "platform", platform))
            stack.enter_context(patch.object(sys, "stdin", SimpleNamespace(buffer=source)))
            stack.enter_context(patch.object(sys, "stdout", output))
            worker.main(os.getpid())
        return worker, json.loads(output.getvalue()), events, source, parser, landlock, network

    def test_manifest_declares_only_the_two_new_guarded_entrypoints(self):
        """Scope, protocol and unchanged resource budgets remain explicit."""
        manifest = json.loads((ROOT / "reporting/pdf-engine.v1.json").read_text())
        extra = manifest["process_local_sandbox"]["auxiliary_parser_workers"]
        self.assertEqual(extra["workers"], [name + ".py" for name, _, _ in WORKERS])
        self.assertEqual(extra["guard_order"], ["landlock", "seccomp"])
        self.assertEqual(extra["boundary"], "before candidate stdin read and parser invocation")
        self.assertEqual(extra["memory_bytes"], 256 * 1024 * 1024)
        self.assertEqual(extra["cpu_seconds"], 5)
        self.assertEqual(extra["supervisor_wall_seconds"], 10)
        self.assertTrue(extra["fail_closed"])
        self.assertFalse(extra["parser_semantics_changed"])
        self.assertFalse(extra["new_dependency"])
        self.assertFalse(extra["full_os_sandbox_claimed"])
        self.assertFalse(extra["aggregate_resource_closure_claimed"])
        self.assertFalse(extra["visual_raster_worker_covered"])

    def test_each_main_enforces_guards_before_reading_candidate_input(self):
        """Source wiring is in each actual main, not only an unused helper."""
        for name, parser, _ in WORKERS:
            with self.subTest(worker=name):
                source = ast.parse((ROOT / "reporting" / (name + ".py")).read_text())
                main = next(n for n in source.body if isinstance(n, ast.FunctionDef) and n.name == "main")
                calls = list(n for n in ast.walk(main) if isinstance(n, ast.Call))
                line = {}
                for function in ("enforce_pdf_landlock", "enforce_pdf_network_filter", parser):
                    selected = [n.lineno for n in calls if isinstance(n.func, ast.Name) and n.func.id == function]
                    self.assertEqual(len(selected), 1)
                    line[function] = selected[0]
                reads = [n.lineno for n in calls if isinstance(n.func, ast.Attribute) and n.func.attr == "read"]
                self.assertEqual(len(reads), 1)
                self.assertLess(line["enforce_pdf_landlock"], line["enforce_pdf_network_filter"])
                self.assertLess(line["enforce_pdf_network_filter"], reads[0])
                self.assertLess(line["enforce_pdf_network_filter"], line[parser])

    def test_landlock_failure_withholds_input_and_parser_execution(self):
        """Unavailable filesystem protection cannot silently produce parser evidence."""
        for name, parser, error in WORKERS:
            with self.subTest(worker=name):
                _, record, _, read, evaluate, _, network = self._mock_main(name, parser, "landlock")
                self.assertEqual(record["status"], "BLOCKED")
                self.assertEqual(record["errors"], [error])
                self.assertIsNone(record["pdf_sha256"])
                self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(record))
                read.assert_not_called()
                evaluate.assert_not_called()
                network.assert_not_called()

    def test_seccomp_failure_withholds_input_and_parser_execution(self):
        """Network-filter setup failure must not fall back to unrestricted parsing."""
        for name, parser, error in WORKERS:
            with self.subTest(worker=name):
                _, record, _, read, evaluate, landlock, network = self._mock_main(name, parser, "seccomp")
                self.assertEqual(record["status"], "BLOCKED")
                self.assertEqual(record["errors"], [error])
                self.assertIsNone(record["pdf_sha256"])
                self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(record))
                landlock.assert_called_once()
                network.assert_called_once()
                read.assert_not_called()
                evaluate.assert_not_called()

    def test_resource_failure_never_reaches_guard_or_input(self):
        """The preexisting resource admission remains a mandatory first boundary."""
        for name, parser, error in WORKERS:
            with self.subTest(worker=name):
                _, record, _, read, evaluate, landlock, network = self._mock_main(name, parser, "limits")
                self.assertEqual(record["errors"], [error])
                read.assert_not_called()
                evaluate.assert_not_called()
                landlock.assert_not_called()
                network.assert_not_called()

    def test_resource_guard_input_parser_order_and_budgets(self):
        """All prerequisites complete before bounded input and unchanged parsing."""
        for name, parser, _ in WORKERS:
            with self.subTest(worker=name):
                worker, record, events, source, evaluate, _, _ = self._mock_main(name, parser)
                self.assertEqual(record, {"status": "PASS"})
                self.assertEqual(events, ["limit", "limit", "limit", "landlock", "seccomp", "read", "parse"])
                source.read.assert_called_once_with(worker.MAX_PDF_BYTES + 1)
                evaluate.assert_called_once_with(b"%PDF-SYNTHETIC")
                self.assertEqual((worker.MEMORY_BYTES, worker.CPU_SECONDS, worker.WALL_SECONDS),
                                 (256 * 1024 * 1024, 5, 10))

    def test_unsupported_platform_remains_a_closed_failure(self):
        """Unsupported execution hosts cannot skip required protection and parse."""
        for name, parser, error in WORKERS:
            with self.subTest(worker=name):
                _, record, _, source, evaluate, _, _ = self._mock_main(name, parser, platform="darwin")
                self.assertEqual(record["errors"], [error])
                source.read.assert_not_called()
                evaluate.assert_not_called()

    def test_real_main_boundaries_deny_unapproved_paths_and_new_sockets(self):
        """Real kernel controls execute in disposable children, never the test host."""
        script = '''import errno,importlib,json,os,socket,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
worker=importlib.import_module("reporting."+sys.argv[2])
def probe(data):
    """Measure only synthetic path and socket denials after the real main guards."""
    result={"input_exact":data==b"%PDF-SYNTHETIC","approved_read":bool(Path(worker.__file__).read_bytes())}
    try:
        Path(sys.argv[4]).read_bytes()
        result["unapproved_read_denied"]=False
    except OSError as exc:
        result["unapproved_read_denied"]=exc.errno in (errno.EPERM,errno.EACCES)
    try:
        fd=os.open(worker.__file__,os.O_WRONLY|os.O_CLOEXEC)
        os.close(fd)
        result["source_write_denied"]=False
    except OSError as exc:
        result["source_write_denied"]=exc.errno in (errno.EPERM,errno.EACCES)
    for label,family,kind in (("tcp",socket.AF_INET,socket.SOCK_STREAM),("udp",socket.AF_INET,socket.SOCK_DGRAM),("unix",socket.AF_UNIX,socket.SOCK_STREAM)):
        try:
            value=socket.socket(family,kind)
        except OSError as exc:
            result[label+"_denied"]=exc.errno==errno.EPERM
        else:
            value.close()
            result[label+"_denied"]=False
    return result
setattr(worker,sys.argv[3],probe)
worker.main(int(sys.argv[5]))
'''
        with tempfile.TemporaryDirectory(prefix="omnigenis-parser-guard-") as directory:
            forbidden = Path(directory) / "unapproved-synthetic.txt"
            forbidden.write_text("SYNTHETIC_PRIVATE_SENTINEL", encoding="utf-8")
            for name, parser, _ in WORKERS:
                with self.subTest(worker=name):
                    child = subprocess.run(
                        [sys.executable, "-I", "-c", script, str(ROOT), name, parser, str(forbidden), str(os.getpid())],
                        input=b"%PDF-SYNTHETIC", capture_output=True, timeout=10, cwd=ROOT,
                    )
                    self.assertEqual(child.returncode, 0, child.stderr[-400:])
                    self.assertEqual(json.loads(child.stdout), {
                        "input_exact": True, "approved_read": True,
                        "unapproved_read_denied": True, "source_write_denied": True,
                        "tcp_denied": True, "udp_denied": True, "unix_denied": True,
                    })
            self.assertEqual(forbidden.read_text(), "SYNTHETIC_PRIVATE_SENTINEL")

    def test_isolated_script_protocol_matches_the_unchanged_parser(self):
        """Actual -I worker processes retain the exact parser evidence for a synthetic PDF."""
        pdf = synthetic_pdf()
        for name, parser, _ in WORKERS:
            with self.subTest(worker=name):
                worker = importlib.import_module("reporting." + name)
                expected = getattr(worker, parser)(pdf)
                self.assertEqual(expected["status"], "PASS")
                child = subprocess.run(
                    [sys.executable, "-I", str(ROOT / "reporting" / (name + ".py")), str(os.getpid())],
                    input=pdf, capture_output=True, timeout=10, cwd=ROOT,
                )
                self.assertEqual(child.returncode, 0, child.stderr[-400:])
                self.assertEqual(json.loads(child.stdout), expected)

    def test_isolated_startup_ignores_untrusted_python_import_paths(self):
        """Only the resolved worker sibling may supply the mandatory guard module."""
        pdf = synthetic_pdf()
        with tempfile.TemporaryDirectory(prefix="omnigenis-parser-import-") as directory:
            root = Path(directory)
            marker = root / "untrusted-import-ran"
            malicious = "from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('SYNTHETIC')\n"
            (root / "_pdf_process_sandbox.py").write_text(malicious)
            (root / "_pdf_render_worker.py").write_text(malicious)
            (root / "sitecustomize.py").write_text(malicious)
            environment = dict(os.environ, PYTHONPATH=str(root), PYTHONHOME=str(root))
            for name, parser, _ in WORKERS:
                with self.subTest(worker=name):
                    worker = importlib.import_module("reporting." + name)
                    child = subprocess.run(
                        [sys.executable, "-I", str(ROOT / "reporting" / (name + ".py")), str(os.getpid())],
                        input=pdf, capture_output=True, timeout=10, cwd=root, env=environment,
                    )
                    self.assertEqual(child.returncode, 0, child.stderr[-400:])
                    self.assertEqual(json.loads(child.stdout), getattr(worker, parser)(pdf))
                    self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
