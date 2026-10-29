"""Bound the generated-PDF raster worker to its launching parent and elapsed budget."""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import ctypes
import errno
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


_VISUAL_REAL_POPEN = subprocess.Popen
_VISUAL_REAL_KILLPG = os.killpg
_VISUAL_REAL_KILL = os.kill
_VISUAL_REAL_WAITID = os.waitid
_VISUAL_REAL_WAITPID = os.waitpid
_VISUAL_WAIT_FLAGS = os.WEXITED | os.WNOHANG | os.WNOWAIT


def _visual_response(pdf, *, blocked=False, size=None):
    """Build synthetic protocol bytes without invoking any raster executor."""
    record = {
        "status": "BLOCKED" if blocked else "PASS",
        "pdf_sha256": None if blocked else hashlib.sha256(pdf).hexdigest(),
        "page_count": None if blocked else 1,
        "raster_sha256": None if blocked else "1" * 64,
        "min_edge_margin_px": None if blocked else 2,
        "total_pixels": None if blocked else 100,
        "errors": ["pdf_visual_worker_unavailable"] if blocked else [],
    }
    response = json.dumps(record, sort_keys=True).encode("ascii") + b"\n"
    if size is not None:
        if len(response) > size:
            raise AssertionError("synthetic response exceeds its requested size")
        response = response.ljust(size, b" ")
    return response


def _visual_emit_script(response, *, exit_code=0):
    """Consume input and emit one explicit test response before exiting."""
    return (
        "import os,sys\n"
        "sys.stdin.buffer.read()\n"
        "sys.stdout.buffer.write(" + repr(response) + ")\n"
        "sys.stdout.buffer.flush()\n"
        "os._exit(" + str(exit_code) + ")\n"
    )


def _visual_observe_exit(process):
    """Wait for a test-owned exit while retaining its kernel wait state."""
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        result = _VISUAL_REAL_WAITID(os.P_PID, process.pid, _VISUAL_WAIT_FLAGS)
        if result is not None:
            return result
        time.sleep(0.005)
    raise AssertionError("disposable visual child did not exit")


@contextmanager
def _visual_child_probe(script, *, wall_seconds=2, before_return=None,
                        pass_fds=(), group_error=None):
    """Observe only owned signals and retain pidfds for independent test cleanup.

    The signal guard suppresses the former unsafe signal-after-reap behavior.
    Cleanup never sends a numeric PID or process-group signal after ownership
    loss. Extra pidfds are registered before a controlled descendant can exit.
    """
    probe = SimpleNamespace(process=None, pidfd=None, extra_pidfds=[], signals=[])

    def launch(_command, *args, **kwargs):
        if probe.process is not None:
            raise AssertionError("visual fixture expected exactly one direct child")
        if kwargs.get("start_new_session") is not True:
            raise AssertionError("visual worker must own a fresh process group")
        if pass_fds:
            kwargs["pass_fds"] = tuple(pass_fds)
        process = _VISUAL_REAL_POPEN(
            [sys.executable, "-I", "-B", "-c", script], *args, **kwargs
        )
        probe.process = process
        probe.pidfd = os.pidfd_open(process.pid)
        if before_return is not None:
            before_return(probe)
        return process

    def send(kind, identifier, signum):
        process = probe.process
        if process is None or identifier != process.pid:
            raise AssertionError("signal target is not the disposable visual child")
        try:
            _VISUAL_REAL_WAITID(os.P_PID, identifier, _VISUAL_WAIT_FLAGS)
        except ChildProcessError:
            probe.signals.append((kind, False))
            return
        probe.signals.append((kind, True))
        if kind == "group" and group_error is not None:
            raise group_error
        sender = _VISUAL_REAL_KILLPG if kind == "group" else _VISUAL_REAL_KILL
        return sender(identifier, signum)

    try:
        with patch.object(pdf_visual.subprocess, "Popen", side_effect=launch), \
             patch.object(pdf_visual, "WALL_SECONDS", wall_seconds), \
             patch.object(os, "killpg", side_effect=lambda pid, sig: send("group", pid, sig)), \
             patch.object(os, "kill", side_effect=lambda pid, sig: send("child", pid, sig)):
            yield probe
    finally:
        # The product signal patches have exited before this independent cleanup.
        descriptors = probe.extra_pidfds + ([probe.pidfd] if probe.pidfd is not None else [])
        try:
            for descriptor in descriptors:
                try:
                    signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if probe.process is not None:
                probe.process.wait(timeout=3)
        finally:
            for descriptor in descriptors:
                os.close(descriptor)
            if probe.process is not None:
                for stream in (probe.process.stdin, probe.process.stdout, probe.process.stderr):
                    if stream is not None:
                        stream.close()


class _RaiseOnRedundantVisualClose:
    """Fault only a redundant late close, after actual test-owned I/O is closed."""

    def __init__(self, stream, label, attempts, error):
        self._stream = stream
        self._label = label
        self._attempts = attempts
        self._error = error
        self._injected = False

    def __getattr__(self, name):
        return getattr(self._stream, name)

    def close(self):
        was_closed = self._stream.closed
        self._stream.close()
        if was_closed and not self._injected:
            self._injected = True
            self._attempts.append(self._label)
            raise self._error


@unittest.skipUnless(
    sys.platform == "linux" and hasattr(os, "pidfd_open")
    and hasattr(signal, "pidfd_send_signal"), "Linux pidfd required"
)
class VisualSupervisorPipeLifecycleTests(unittest.TestCase):
    """Exercise the public supervisor with bounded real disposable children."""

    pdf = b"%PDF-SYNTHETIC-VISUAL-LIFECYCLE"

    def validate(self, pdf=None):
        data = self.pdf if pdf is None else pdf
        return pdf_visual.validate_pdf_visual_geometry(
            pdf_bytes=data, expected_pdf_sha256=hashlib.sha256(data).hexdigest()
        )

    def assert_reaped(self, probe):
        with self.assertRaises(ChildProcessError):
            _VISUAL_REAL_WAITID(os.P_PID, probe.process.pid, _VISUAL_WAIT_FLAGS)

    def assert_owned_cleanup(self, probe):
        self.assertIn(("group", True), probe.signals, probe.signals)
        self.assertTrue(all(owned for _, owned in probe.signals), probe.signals)
        self.assert_reaped(probe)

    def test_exited_visual_child_is_waitable_at_every_group_signal(self):
        """Completion must not release the leader PID before original-group cleanup."""
        for action, expected in (
            ("os._exit(0)", 0),
            ("os._exit(7)", 7),
            ("os.kill(os.getpid(),signal.SIGTERM)", -signal.SIGTERM),
        ):
            script = "import os,signal,sys\nsys.stdin.buffer.read()\n" + action
            with self.subTest(expected=expected), _visual_child_probe(script) as probe:
                result = pdf_visual._run_worker(self.pdf)
                self.assertEqual(result.returncode, expected)
                self.assert_owned_cleanup(probe)

    def test_exited_visual_leader_does_not_leave_original_group_descendant(self):
        """A pinned same-group descendant must terminate before evidence is returned."""
        status_read, status_write = os.pipe()
        release_read, release_write = os.pipe()
        response = _visual_response(self.pdf)
        script = (
            "import os,sys,time\n"
            "descendant=os.fork()\n"
            "if descendant==0:\n"
            "    os.close(0);os.close(1)\n"
            "    time.sleep(30)\n"
            "    os._exit(0)\n"
            "os.write(" + str(status_write) + ",str(descendant).encode()+b'\\n')\n"
            "os.read(" + str(release_read) + ",1)\n"
            "sys.stdin.buffer.read()\n"
            "sys.stdout.buffer.write(" + repr(response) + ")\n"
            "sys.stdout.buffer.flush()\n"
            "os._exit(0)\n"
        )

        def pin_descendant(probe):
            self.assertTrue(select.select([status_read], [], [], 3)[0])
            descendant = int(os.read(status_read, 64).strip())
            descriptor = os.pidfd_open(descendant)
            probe.extra_pidfds.append(descriptor)
            self.assertEqual(os.getpgid(descendant), probe.process.pid)
            os.write(release_write, b"X")

        try:
            with _visual_child_probe(
                script, before_return=pin_descendant,
                pass_fds=(status_write, release_read),
            ) as probe:
                result = self.validate()
                self.assertTrue(result.passed, result.errors)
                self.assert_owned_cleanup(probe)
                self.assertTrue(select.select(probe.extra_pidfds, [], [], 2)[0],
                                "original-group descendant is still alive")
        finally:
            for descriptor in (status_read, status_write, release_read, release_write):
                os.close(descriptor)

    def test_exact_response_budget_preserves_valid_json_evidence(self):
        """Exactly 8192 bytes remains an accepted existing protocol boundary."""
        response = _visual_response(self.pdf, size=8192)
        with _visual_child_probe(_visual_emit_script(response)) as probe:
            result = self.validate()
            self.assertTrue(result.passed, result.errors)
            self.assert_owned_cleanup(probe)

    def test_one_byte_beyond_response_budget_is_refused(self):
        """A valid JSON prefix cannot authorize an oversized response."""
        response = _visual_response(self.pdf, size=8193)
        with _visual_child_probe(_visual_emit_script(response)) as probe:
            result = self.validate()
            self.assertEqual(result.errors, ("pdf_visual_worker_invalid_response",))
            self.assert_owned_cleanup(probe)

    def test_response_overflow_is_detected_without_waiting_for_eof(self):
        """An oversized response followed by a live writer is a protocol failure."""
        response = _visual_response(self.pdf, size=8193)
        script = (
            "import sys,time\n"
            "sys.stdout.buffer.write(" + repr(response) + ")\n"
            "sys.stdout.buffer.flush()\n"
            "time.sleep(30)\n"
        )
        with _visual_child_probe(script, wall_seconds=0.3) as probe:
            started = time.monotonic()
            result = self.validate()
            self.assertEqual(result.errors, ("pdf_visual_worker_invalid_response",))
            self.assertLess(time.monotonic() - started, 2.5)
            self.assert_owned_cleanup(probe)

    def test_unread_stdin_is_bounded_by_the_original_wall_deadline(self):
        """A worker that never reads cannot strand an eight-MiB write."""
        pdf = b"%PDF-" + b"S" * (8 * 1024 * 1024 - 5)
        with _visual_child_probe("import time;time.sleep(30)", wall_seconds=0.2) as probe:
            started = time.monotonic()
            result = self.validate(pdf)
            self.assertEqual(result.errors, ("pdf_visual_worker_timeout",))
            self.assertLess(time.monotonic() - started, 2.5)
            self.assert_owned_cleanup(probe)

    def test_duplex_transfer_handles_output_before_large_input_is_read(self):
        """A full output pipe and full input pipe must not deadlock each other."""
        pdf = b"%PDF-" + b"D" * (1024 * 1024 - 5)
        response = _visual_response(pdf, size=8192)
        script = (
            "import fcntl,hashlib,os,sys\n"
            "fcntl.fcntl(1,fcntl.F_SETPIPE_SZ,4096)\n"
            "sys.stdout.buffer.write(" + repr(response) + ")\n"
            "sys.stdout.buffer.flush()\n"
            "data=sys.stdin.buffer.read()\n"
            "os._exit(0 if hashlib.sha256(data).hexdigest()=="
            + repr(hashlib.sha256(pdf).hexdigest()) + " else 7)\n"
        )
        with _visual_child_probe(script) as probe:
            result = self.validate(pdf)
            self.assertTrue(result.passed, result.errors)
            self.assert_owned_cleanup(probe)

    def test_stdout_eof_cannot_accept_a_still_running_child(self):
        """A closed output descriptor does not establish completed execution."""
        script = "import os,time\nos.close(1)\ntime.sleep(30)\n"
        with _visual_child_probe(script, wall_seconds=0.2) as probe:
            result = self.validate()
            self.assertEqual(result.errors, ("pdf_visual_worker_timeout",))
            self.assert_owned_cleanup(probe)

    def test_early_blocked_response_survives_input_broken_pipe(self):
        """Failure before input admission retains its existing blocked protocol."""
        pdf = b"%PDF-" + b"B" * (1024 * 1024 - 5)
        response = _visual_response(pdf, blocked=True)
        script = (
            "import os,sys\nos.close(0)\n"
            "sys.stdout.buffer.write(" + repr(response) + ")\n"
            "sys.stdout.buffer.flush()\n"
        )
        with _visual_child_probe(script) as probe:
            result = self.validate(pdf)
            self.assertEqual(result.errors, ("pdf_visual_worker_unavailable",))
            self.assert_owned_cleanup(probe)

    def test_valid_looking_response_cannot_hide_nonzero_child_exit(self):
        """All response fields may be valid while the execution itself failed."""
        script = _visual_emit_script(_visual_response(self.pdf), exit_code=7)
        with _visual_child_probe(script) as probe:
            result = self.validate()
            self.assertEqual(result.errors, ("pdf_visual_worker_failed",))
            self.assertIsNone(result.page_count)
            self.assert_owned_cleanup(probe)

    def test_kernel_reap_without_popen_update_refuses_all_numeric_signals(self):
        """ECHILD cannot be normalized to a successful zero exit by Popen."""
        def release_identity(probe):
            _visual_observe_exit(probe.process)
            _VISUAL_REAL_WAITPID(probe.process.pid, 0)
            self.assertIsNone(probe.process.returncode)

        with _visual_child_probe("import os;os._exit(0)", before_return=release_identity) as probe:
            result = self.validate()
            self.assertEqual(result.errors, ("pdf_visual_worker_failed",))
            self.assertEqual(probe.signals, [])
            self.assert_reaped(probe)

    def test_unavailable_ownership_observation_refuses_numeric_signals(self):
        """Lack of the ownership primitive must never authorize a PID lookup signal."""
        response = _visual_response(self.pdf)
        with _visual_child_probe(_visual_emit_script(response)) as probe:
            with patch.object(os, "waitid", side_effect=OSError(errno.ENOSYS, "unavailable")):
                result = self.validate()
            self.assertEqual(result.errors, ("pdf_visual_worker_failed",))
            self.assertEqual(probe.signals, [])

    def test_group_cleanup_failure_refuses_valid_visual_evidence(self):
        """Successful output and exit cannot hide an unresolved cleanup operation."""
        response = _visual_response(self.pdf)
        with _visual_child_probe(
            _visual_emit_script(response), group_error=PermissionError("SYNTHETIC_PRIVATE")
        ) as probe:
            result = self.validate()
            self.assertEqual(result.errors, ("pdf_visual_worker_failed",))
            self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(result.to_dict()))
            self.assert_owned_cleanup(probe)

    def test_cancellation_during_pipe_read_still_cleans_and_reaps_child(self):
        """Cancellation remains the original exception after bounded owned cleanup."""
        real_read = os.read
        for cancellation in (KeyboardInterrupt("SYNTHETIC"), SystemExit(13)):
            with self.subTest(kind=type(cancellation).__name__), _visual_child_probe(
                "import os,time\nos.write(1,b'x')\ntime.sleep(30)\n"
            ) as probe:
                injected = []

                def read(descriptor, count):
                    if (not injected and probe.process is not None
                            and descriptor == probe.process.stdout.fileno()):
                        injected.append(True)
                        raise cancellation
                    return real_read(descriptor, count)

                with patch.object(os, "read", side_effect=read):
                    with self.assertRaises(type(cancellation)) as caught:
                        pdf_visual._run_worker(self.pdf)
                self.assertIs(caught.exception, cancellation)
                self.assertEqual(injected, [True])
                self.assert_owned_cleanup(probe)

    def test_pipe_configuration_failure_cleans_already_launched_child(self):
        """A setup error after launch cannot bypass child ownership cleanup."""
        real_set_blocking = os.set_blocking
        with _visual_child_probe("import time;time.sleep(30)", wall_seconds=0.2) as probe:
            injected = []

            def configure(descriptor, blocking):
                if (not injected and probe.process is not None
                        and descriptor in (probe.process.stdin.fileno(),
                                           probe.process.stdout.fileno())):
                    injected.append(True)
                    raise OSError(errno.EIO, "SYNTHETIC_PRIVATE_SETUP")
                return real_set_blocking(descriptor, blocking)

            with patch.object(os, "set_blocking", side_effect=configure):
                result = self.validate()
            self.assertEqual(injected, [True])
            self.assertEqual(result.errors, ("pdf_visual_worker_failed",))
            self.assertNotIn("SYNTHETIC_PRIVATE_SETUP", json.dumps(result.to_dict()))
            self.assert_owned_cleanup(probe)

    def test_pipe_read_failure_is_sanitized_after_owned_cleanup(self):
        """Transport I/O failures cannot leak details or retain the running child."""
        real_read = os.read
        with _visual_child_probe("import os,time\nos.write(1,b'x')\ntime.sleep(30)\n") as probe:
            injected = []

            def read(descriptor, count):
                if (not injected and probe.process is not None
                        and descriptor == probe.process.stdout.fileno()):
                    injected.append(True)
                    raise OSError(errno.EIO, "SYNTHETIC_PRIVATE_PIPE")
                return real_read(descriptor, count)

            with patch.object(os, "read", side_effect=read):
                result = self.validate()
            self.assertEqual(injected, [True])
            self.assertEqual(result.errors, ("pdf_visual_worker_failed",))
            self.assertNotIn("SYNTHETIC_PRIVATE_PIPE", json.dumps(result.to_dict()))
            self.assert_owned_cleanup(probe)

    def test_handled_caller_exception_cannot_mask_late_visual_pipe_close_error(self):
        """Actual successful child output is not PASS when either late close fails."""
        response = _visual_response(self.pdf)
        for error_type in (OSError, ValueError):
            attempts = []

            def wrap_streams(probe):
                process = probe.process
                for name in ("stdin", "stdout"):
                    setattr(
                        process, name,
                        _RaiseOnRedundantVisualClose(
                            getattr(process, name), name, attempts,
                            error_type("SYNTHETIC_PRIVATE_VISUAL_CLOSE"),
                        ),
                    )

            with self.subTest(error=error_type.__name__), _visual_child_probe(
                _visual_emit_script(response), before_return=wrap_streams
            ) as probe:
                try:
                    raise LookupError("SYNTHETIC_UNRELATED_CALLER")
                except LookupError:
                    result = self.validate()
                self.assertEqual(result.errors, ("pdf_visual_worker_failed",))
                self.assertFalse(result.passed)
                self.assertIsNone(result.raster_sha256)
                self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(result.to_dict()))
                self.assertEqual(attempts, ["stdin", "stdout"])
                self.assert_owned_cleanup(probe)

    def test_fragmented_response_preserves_the_exact_protocol_bytes(self):
        """A response is a byte stream, independent of individual read boundaries."""
        response = _visual_response(self.pdf)
        script = (
            "import os,sys\nsys.stdin.buffer.read()\n"
            "data=" + repr(response) + "\n"
            "for offset in range(0,len(data),7):\n"
            "    os.write(1,data[offset:offset+7])\n"
        )
        with _visual_child_probe(script) as probe:
            result = pdf_visual._run_worker(self.pdf)
            self.assertEqual(result.stdout, response)
            self.assertEqual(result.returncode, 0)
            self.assert_owned_cleanup(probe)

    def test_cancellation_at_first_postlaunch_deadline_cleans_owned_child(self):
        """The first supervisor clock operation is inside owned cleanup scope."""
        real_clock = time.monotonic
        for cancellation in (KeyboardInterrupt("SYNTHETIC"), SystemExit(13)):
            with self.subTest(kind=type(cancellation).__name__), _visual_child_probe(
                "import time;time.sleep(30)", wall_seconds=0.2
            ) as probe:
                injected = []

                def clock():
                    if not injected and probe.process is not None:
                        injected.append(True)
                        raise cancellation
                    return real_clock()

                with patch.object(time, "monotonic", side_effect=clock):
                    with self.assertRaises(type(cancellation)) as caught:
                        pdf_visual._run_worker(self.pdf)
                self.assertIs(caught.exception, cancellation)
                self.assertEqual(injected, [True])
                self.assert_owned_cleanup(probe)


if __name__ == "__main__":
    unittest.main()
