"""Prove narrow Landlock/seccomp confinement of the generated-PDF raster worker."""
from __future__ import annotations

from contextlib import ExitStack
import errno
import importlib
from io import StringIO
import json
import os
from pathlib import Path
import resource
import signal
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from reporting import _pdf_process_sandbox as guards
from reporting import _pdf_visual_worker as worker
from reporting import _pdf_render_worker as lifetime
from reporting import pdf_visual
from reporting.adapters import build_html_css_and_pdf_adapter

ROOT = Path(__file__).resolve().parents[1]
VISUAL = ROOT / "reporting" / "pdf-visual-engine.v1.json"
SUPERVISOR_PREFIX = "omnigenis-pdf-visual-supervisor-"


def sample_pdf():
    """Create only deterministic, synthetic report input."""
    result = build_html_css_and_pdf_adapter(presentation_ir={
        "report_id": "synthetic-visual-sandbox",
        "locale_id": "en-US",
        "components": [{
            "component_id": "summary", "component_type": "semantic-section",
            "title": "Summary", "state": "PRESENT",
            "content": {"text": "SYNTHETIC_ONLY"},
        }],
    })
    if not result.passed:
        raise AssertionError(result.errors)
    return result.pdf_bytes


class VisualRasterConfinementTests(unittest.TestCase):
    """Never apply irreversible kernel guards to this test host."""

    def test_manifest_declares_narrow_scratch_and_network_scope(self):
        manifest = json.loads(VISUAL.read_text())
        profile = manifest["process_local_sandbox"]
        self.assertEqual(profile["filesystem_profile"], guards.PROFILE_ID)
        self.assertEqual(profile["network_profile"], guards.NETWORK_PROFILE_ID)
        self.assertEqual(profile["scratch_directory_prefix"], SUPERVISOR_PREFIX)
        self.assertEqual(profile["scratch_parent"], "/tmp")
        self.assertEqual(profile["scratch_mode"], "0700")
        self.assertTrue(profile["kernel_enforced"])
        self.assertTrue(profile["fail_closed"])
        self.assertFalse(profile["full_os_sandbox_claimed"])
        self.assertFalse(profile["aggregate_resources_claimed"])
        self.assertFalse(profile["inherited_descriptor_revocation_claimed"])
        self.assertFalse(profile["arbitrary_descendant_cleanup_claimed"])
        self.assertFalse(profile["new_external_dependency"])
        self.assertEqual(profile["guard_order"], ["landlock", "seccomp"])
        self.assertEqual(profile["scope"], "visual worker and its spawned raster executable")

    def test_trusted_scratch_root_requires_owner_private_direct_child_of_tmp(self):
        self.assertTrue(hasattr(worker, "_open_trusted_scratch"))
        with tempfile.TemporaryDirectory(prefix=SUPERVISOR_PREFIX, dir="/tmp") as correct:
            with patch.dict(os.environ, {"TMPDIR": correct}):
                path, fd = worker._open_trusted_scratch()
            try:
                self.assertEqual(path, Path(correct))
                self.assertTrue(stat.S_ISDIR(os.fstat(fd).st_mode))
                self.assertEqual(stat.S_IMODE(os.fstat(fd).st_mode), 0o700)
            finally:
                os.close(fd)
            os.chmod(correct, 0o755)
            with patch.dict(os.environ, {"TMPDIR": correct}):
                with self.assertRaises((RuntimeError, OSError, ValueError)):
                    worker._open_trusted_scratch()
        with tempfile.TemporaryDirectory(prefix="wrong-visual-prefix-", dir="/tmp") as other:
            with patch.dict(os.environ, {"TMPDIR": other}):
                with self.assertRaises((RuntimeError, OSError, ValueError)):
                    worker._open_trusted_scratch()
            with tempfile.TemporaryDirectory(prefix=SUPERVISOR_PREFIX, dir="/tmp") as correct:
                link = Path(other) / (SUPERVISOR_PREFIX + "link")
                link.symlink_to(correct, target_is_directory=True)
                with patch.dict(os.environ, {"TMPDIR": str(link)}):
                    with self.assertRaises((RuntimeError, OSError, ValueError)):
                        worker._open_trusted_scratch()

    def test_all_setup_guards_precede_candidate_input_and_parser(self):
        self.assertTrue(hasattr(worker, "_open_trusted_scratch"))
        events = []
        input_stream = Mock()
        input_stream.read.side_effect = lambda *a: events.append("read") or b"%PDF-SYNTHETIC"
        output_stream = StringIO()
        fd = os.open("/tmp", os.O_PATH | os.O_DIRECTORY)
        try:
            with tempfile.TemporaryDirectory(prefix=SUPERVISOR_PREFIX, dir="/tmp") as scratch:
                with ExitStack() as stack:
                    for obj, name, replacement in (
                        (resource, "setrlimit", Mock(side_effect=lambda *a: events.append("limit"))),
                        (lifetime, "_arm_worker_lifetime", Mock(side_effect=lambda *a: events.append("lifetime"))),
                        (signal, "setitimer", Mock(side_effect=lambda *a: events.append("timer"))),
                        (worker, "_open_trusted_scratch", Mock(side_effect=lambda: (events.append("scratch") or Path(scratch), os.dup(fd)))),
                        (guards, "enforce_pdf_landlock", Mock(side_effect=lambda *a, **kw: events.append("landlock"))),
                        (guards, "enforce_pdf_network_filter", Mock(side_effect=lambda: events.append("seccomp"))),
                        (worker, "inspect_visual_geometry", Mock(side_effect=lambda data: events.append("parse") or {"status": "PASS"})),
                        (sys, "stdin", SimpleNamespace(buffer=input_stream)),
                        (sys, "stdout", output_stream),
                    ):
                        stack.enter_context(patch.object(obj, name, replacement))
                    worker.main(os.getpid())
            self.assertEqual(json.loads(output_stream.getvalue()), {"status": "PASS"})
            self.assertEqual(events, ["limit"] * 5 + ["lifetime", "timer", "scratch",
                              "landlock", "seccomp", "read", "parse"])
            input_stream.read.assert_called_once_with(worker.MAX_PDF_BYTES + 1)
        finally:
            os.close(fd)

    def test_kernel_guard_failure_blocks_without_reading_untrusted_pdf(self):
        self.assertTrue(hasattr(worker, "_open_trusted_scratch"))
        for failing in ("landlock", "seccomp"):
            with self.subTest(failing=failing):
                source = Mock()
                output = StringIO()
                with tempfile.TemporaryDirectory(prefix=SUPERVISOR_PREFIX, dir="/tmp") as scratch:
                    with ExitStack() as stack:
                        for obj, name, replacement in (
                            (resource, "setrlimit", Mock()),
                            (lifetime, "_arm_worker_lifetime", Mock()),
                            (signal, "setitimer", Mock()),
                            (worker, "_open_trusted_scratch", Mock(return_value=(Path(scratch), os.open(scratch, os.O_PATH | os.O_DIRECTORY)))),
                            (guards, "enforce_pdf_landlock", Mock(side_effect=RuntimeError("PRIVATE_SYNTHETIC_DETAIL") if failing == "landlock" else None)),
                            (guards, "enforce_pdf_network_filter", Mock(side_effect=RuntimeError("PRIVATE_SYNTHETIC_DETAIL") if failing == "seccomp" else None)),
                            (worker, "inspect_visual_geometry", Mock()),
                            (sys, "stdin", SimpleNamespace(buffer=source)),
                            (sys, "stdout", output),
                        ):
                            stack.enter_context(patch.object(obj, name, replacement))
                        worker.main(os.getpid())
                result = json.loads(output.getvalue())
                self.assertEqual(result["errors"], ["pdf_visual_worker_unavailable"])
                self.assertIsNone(result["pdf_sha256"])
                self.assertNotIn("PRIVATE_SYNTHETIC_DETAIL", output.getvalue())
                source.read.assert_not_called()

    def test_real_kernel_denies_unapproved_paths_network_and_child_sockets(self):
        """Probe real kernel restrictions inside disposable worker, not host."""
        script = '''import errno,importlib,json,os,socket,subprocess,sys,tempfile
from pathlib import Path
sys.path.insert(0,sys.argv[1])
worker=importlib.import_module("reporting._pdf_visual_worker")
def probe(pdf):
    root=Path(tempfile.gettempdir())
    item=root/"allowed-synthetic.txt"
    item.write_text("SYNTHETIC_ONLY")
    allowed=item.read_text()=="SYNTHETIC_ONLY"
    item.unlink()
    result={"input_exact":pdf==b"%PDF-SYNTHETIC","scratch_write":allowed,
            "approved_read":bool(Path(worker.__file__).read_bytes())}
    with open("/dev/null","wb") as sink:
        result["devnull_writable"]=sink.write(b"SYNTHETIC_ONLY")==14
    try:
        Path(sys.argv[3]).read_bytes()
        result["unapproved_read_denied"]=False
    except OSError as exc:
        result["unapproved_read_denied"]=exc.errno in (errno.EACCES,errno.EPERM)
    try:
        Path(sys.argv[3]).write_text("FORBIDDEN")
        result["unapproved_write_denied"]=False
    except OSError as exc:
        result["unapproved_write_denied"]=exc.errno in (errno.EACCES,errno.EPERM)
    for label,family,kind in (("tcp",socket.AF_INET,socket.SOCK_STREAM),("udp",socket.AF_INET,socket.SOCK_DGRAM),("unix",socket.AF_UNIX,socket.SOCK_STREAM)):
        try:
            sock=socket.socket(family,kind)
            sock.close()
            result[label+"_denied"]=False
        except OSError as exc:
            result[label+"_denied"]=exc.errno==errno.EPERM
    child=subprocess.run([sys.executable,"-I","-c","import socket; socket.socket()"],
                         capture_output=True,text=True,timeout=3,check=False)
    result["child_socket_denied"]=child.returncode!=0 and "PermissionError: [Errno 1]" in child.stderr
    return result
worker.inspect_visual_geometry=probe
worker.main(os.getppid())
'''
        with tempfile.TemporaryDirectory(prefix=SUPERVISOR_PREFIX, dir="/tmp") as scratch:
            with tempfile.TemporaryDirectory(prefix="omnigenis-visual-denied-", dir="/tmp") as denied:
                forbidden = Path(denied) / "sentinel.txt"
                forbidden.write_text("SYNTHETIC_UNTRUSTED")
                env = dict(os.environ, TMPDIR=scratch)
                child = subprocess.run(
                    [sys.executable, "-I", "-c", script, str(ROOT), scratch, str(forbidden)],
                    input=b"%PDF-SYNTHETIC", capture_output=True, timeout=9, cwd=ROOT, env=env,
                )
                self.assertEqual(child.returncode, 0, child.stderr[-440:])
                self.assertEqual(json.loads(child.stdout), {
                    "input_exact": True, "scratch_write": True,
                    "approved_read": True, "devnull_writable": True,
                    "unapproved_read_denied": True,
                    "unapproved_write_denied": True,
                    "tcp_denied": True, "udp_denied": True,
                    "unix_denied": True, "child_socket_denied": True,
                })
                self.assertEqual(forbidden.read_text(), "SYNTHETIC_UNTRUSTED")

    def test_untrusted_tmpdir_fails_closed_before_candidate_read(self):
        """An arbitrary writable filesystem root must never be self-authorized."""
        env = dict(os.environ, TMPDIR="/tmp")
        result = subprocess.run(
            [sys.executable, "-I", str(ROOT / "reporting/_pdf_visual_worker.py"),
             str(os.getpid())],
            input=b"%PDF-SYNTHETIC", capture_output=True, timeout=7, cwd=ROOT, env=env,
        )
        self.assertEqual(result.returncode, 0, result.stderr[-300:])
        record = json.loads(result.stdout)
        self.assertEqual(record["errors"], ["pdf_visual_worker_unavailable"])
        self.assertIsNone(record["pdf_sha256"])

    def test_real_public_raster_parity_and_supervisor_scratch_boundary(self):
        """An actual trusted generated PDF still rasterizes after both OS guards."""
        pdf = sample_pdf()
        from hashlib import sha256
        result = pdf_visual.validate_pdf_visual_geometry(
            pdf_bytes=pdf, expected_pdf_sha256=sha256(pdf).hexdigest()
        )
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(result.pdf_sha256, sha256(pdf).hexdigest())
        self.assertEqual(result.page_count, 1)
        self.assertEqual(result.to_dict()["release_authorization"], "NOT_ESTABLISHED")


if __name__ == "__main__":
    unittest.main()
