"""Synthetic native-exec and negative controls for direct raster-child lifetime."""
from __future__ import annotations

import ast
from contextlib import ExitStack
import ctypes
import errno
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
TOOL = "/usr/bin/pdftoppm"


def native_probe(mode: str, guarded: bool) -> dict:
    """Observe a pinned real native process in a disposable subreaper test process."""
    if ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) != 0:
        raise RuntimeError("test subreaper unavailable")
    with tempfile.TemporaryDirectory(prefix="omnigenis-pdf-visual-supervisor-", dir="/tmp") as td:
        root = Path(td) / "raster-window-probe"
        root.mkdir(mode=0o700)
        source = root / "candidate.pdf"
        os.mkfifo(source, mode=0o600)
        prefix = root / "page-1"
        parent_code = (
            "import os,subprocess,sys\n"
            "command=" + repr([sys.executable, "-I", str(ROOT / "reporting/_pdf_raster_executor.py")]) + "+[str(os.getpid())," + repr(TOOL) + "," + repr(str(source)) + "," + repr(str(prefix)) + ",'1']\n"
            if guarded else
            "import os,subprocess,sys\ncommand=" + repr([TOOL, "-f", "1", "-l", "1", "-singlefile", "-r", "96", "-png", str(source), str(prefix)]) + "\n"
        )
        parent_code += (
            "child=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True)\n"
            "print(child.pid,flush=True)\nsys.stdin.readline()\nos._exit(0)\n"
        )
        parent = subprocess.Popen([sys.executable, "-c", parent_code], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            env={"PATH": os.defpath, "LANG": "C.UTF-8", "TMPDIR": td}, close_fds=True)
        child_fd = None
        child_pid = None
        reaped = False
        observed = False
        signal_number = None
        started = time.monotonic()
        try:
            if not select.select([parent.stdout], [], [], 5)[0]:
                raise RuntimeError("test native identity missing")
            child_pid = int(parent.stdout.readline().strip())
            child_fd = os.pidfd_open(child_pid)
            deadline = time.monotonic() + 5
            while True:
                if select.select([child_fd], [], [], 0)[0]:
                    raise RuntimeError("test child exited before native exec")
                try:
                    native = Path(f"/proc/{child_pid}/exe").resolve(strict=True) == Path(TOOL).resolve(strict=True)
                except FileNotFoundError:
                    native = False
                if native:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("test native exec not observed")
                time.sleep(0.01)
            if mode == "parent-death":
                parent.stdin.write("\n"); parent.stdin.flush()
                parent.wait(timeout=3)
                observed = bool(select.select([child_fd], [], [], 2)[0])
            elif mode == "timer":
                observed = bool(select.select([child_fd], [], [], 10)[0])
                parent.stdin.write("\n"); parent.stdin.flush()
                parent.wait(timeout=3)
            else:
                raise ValueError("unknown test mode")
            if observed:
                _, status = os.waitpid(child_pid, 0)
                reaped = True
                signal_number = os.WTERMSIG(status) if os.WIFSIGNALED(status) else None
            return {"native_exec_observed": True, "exit_observed": observed,
                    "exit_signal": signal_number, "guarded": guarded,
                    "seconds": time.monotonic() - started}
        finally:
            if child_fd is not None:
                try:
                    signal.pidfd_send_signal(child_fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if parent.poll() is None:
                parent.kill()
            parent.wait(timeout=3)
            parent.stdin.close(); parent.stdout.close()
            if child_pid is not None and not reaped:
                os.waitpid(child_pid, 0)
            if child_fd is not None:
                os.close(child_fd)


class RasterExecutorLifecycleTests(unittest.TestCase):
    """Test fixed native admission, kernel lifetime and unchanged raster results."""

    def setUp(self):
        """Require the new helper before any test can report a passing boundary."""
        self.assertIsNotNone(importlib.util.find_spec("reporting._pdf_raster_executor"),
                             "direct raster executor lifetime helper is missing")
        self.e = importlib.import_module("reporting._pdf_raster_executor")
        self.w = importlib.import_module("reporting._pdf_raster_window_worker")

    def argv(self, **changes):
        """Produce synthetic lexical arguments without opening any candidate."""
        values = dict(parent=str(os.getpid()), tool=TOOL,
            source="/tmp/omnigenis-pdf-visual-supervisor-test/raster-window-test/candidate.pdf",
            prefix="/tmp/omnigenis-pdf-visual-supervisor-test/raster-window-test/page-1", page="1")
        values.update(changes)
        return ["executor", *[values[k] for k in ("parent", "tool", "source", "prefix", "page")]]

    def probe(self, mode, guarded=True):
        """Run lifecycle observation outside the unittest process with finite cleanup."""
        code = "import json;from tests.test_reporting_pdf_raster_lifecycle import native_probe;print(json.dumps(native_probe(" + repr(mode) + "," + repr(guarded) + ")))"
        result = subprocess.run([sys.executable, "-c", code], cwd=ROOT,
            capture_output=True, text=True, timeout=25, check=True)
        return json.loads(result.stdout)

    def test_direct_native_terminates_after_parent_death(self):
        """A pidfd-pinned Poppler process terminates after its live direct parent exits."""
        result = self.probe("parent-death")
        self.assertTrue(result["native_exec_observed"])
        self.assertTrue(result["exit_observed"])
        self.assertEqual(result["exit_signal"], signal.SIGKILL)

    def test_unguarded_native_negative_control_survives_parent(self):
        """The same stalled native executable without registration must fail the exit probe."""
        result = self.probe("parent-death", guarded=False)
        self.assertTrue(result["native_exec_observed"])
        self.assertFalse(result["exit_observed"])

    def test_kernel_timer_survives_actual_native_exec(self):
        """A live parent cannot prevent the independent timer from stopping blocked Poppler."""
        result = self.probe("timer")
        self.assertTrue(result["exit_observed"])
        self.assertEqual(result["exit_signal"], signal.SIGALRM)
        self.assertLess(result["seconds"], 12)

    def test_canonical_argument_binding(self):
        """Parent, executable, paths and physical page are bound without coercion."""
        parent, tool, source, prefix, page = self.e._parse(self.argv())
        self.assertEqual((parent, tool, page), (os.getpid(), TOOL, 1))
        self.assertEqual(source.name, "candidate.pdf")
        self.assertEqual(prefix.name, "page-1")

    def test_noncanonical_parent_and_page_rejected(self):
        """Leading zeros, signs, booleans and oversized fields never select native work."""
        for key, value in (("parent", "0"), ("parent", "1"), ("parent", "+42"),
                ("parent", "0042"), ("parent", "9" * 30), ("page", "0"),
                ("page", "513"), ("page", "01"), ("page", True), ("page", "1.0")):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.e._parse(self.argv(**{key: value}))

    def test_command_and_path_injection_rejected(self):
        """Only the fixed executable and absolute unambiguous path strings are accepted."""
        for changes in ({"tool": "pdftoppm"}, {"tool": "/bin/sh"},
                {"source": "relative.pdf"}, {"source": "/tmp/../candidate.pdf"},
                {"prefix": "/tmp/page\x00x"}, {"source": "/" + "a" * 4096}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.e._parse(self.argv(**changes))
        for args in ([], self.argv() + ["extra"], tuple(self.argv()), None):
            with self.assertRaises(ValueError): self.e._parse(args)

    def test_real_executable_descriptor_is_pinned_and_cloexec(self):
        """The exact installed binary is opened read-only and cannot leak through exec."""
        before = len(os.listdir("/proc/self/fd"))
        fd = self.e._open_executable(TOOL)
        try:
            self.assertFalse(os.get_inheritable(fd))
            self.assertEqual(hashlib.sha256(os.read(fd, 1024 * 1024)).hexdigest(), self.e.TOOL_SHA256)
        finally:
            os.close(fd)
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_wrong_binary_digest_rejected_without_fd_leak(self):
        """A different binary cannot be admitted even at the allowed executable path."""
        before = len(os.listdir("/proc/self/fd"))
        with patch.object(self.e, "TOOL_SHA256", "0" * 64):
            with self.assertRaises(ValueError): self.e._open_executable(TOOL)
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_executable_special_or_writable_mode_rejected(self):
        """Set-ID and group/world-writable binaries cannot clear or evade lifetime binding."""
        original = os.fstat
        for bits in (0o4000, 0o2000, 0o020, 0o002):
            def modified(fd, bits=bits):
                """Alter only observed metadata to exercise admission rejection."""
                info = original(fd)
                fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
                fields["st_mode"] |= bits
                return SimpleNamespace(**fields)
            with patch.object(self.e.os, "fstat", side_effect=modified):
                with self.assertRaises(ValueError): self.e._open_executable(TOOL)

    def test_file_capabilities_are_rejected(self):
        """File capabilities are not accepted because exec may clear the parent-death signal."""
        with patch.object(self.e.os, "getxattr", return_value=b"synthetic-capability"):
            with self.assertRaises(ValueError): self.e._open_executable(TOOL)

    def test_unknown_capability_read_error_fails_closed(self):
        """Only explicit absence of the capability xattr permits executable admission."""
        for number in (errno.EACCES, errno.ENOTSUP):
            with patch.object(self.e.os, "getxattr", side_effect=OSError(number, "synthetic")):
                with self.assertRaises(OSError): self.e._open_executable(TOOL)

    def test_observable_executable_mutation_rejected(self):
        """A file whose size or timestamps change during hashing is not executable evidence."""
        original = os.fstat; calls = 0
        def changed(fd):
            """Change a later metadata snapshot without changing the binary itself."""
            nonlocal calls
            calls += 1
            info = original(fd)
            fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
            if calls > 1: fields["st_mtime_ns"] += 1
            return SimpleNamespace(**fields)
        with patch.object(self.e.os, "fstat", side_effect=changed):
            with self.assertRaises(ValueError): self.e._open_executable(TOOL)

    def test_missing_descriptor_exec_is_not_a_path_fallback(self):
        """Unsupported descriptor-based execution must reject rather than search PATH."""
        with patch.object(self.e.os, "supports_fd", set()):
            with self.assertRaises(ValueError): self.e._open_executable(TOOL)

    def test_worker_command_routes_through_isolated_helper(self):
        """The actual raster call preserves native arguments behind the narrow launcher."""
        from reporting._pdf_raster_launch_budget import RasterLaunchBudget
        budget = RasterLaunchBudget((2,))
        budget.consume_probe()
        self.addCleanup(budget.close)
        with patch.object(self.w.subprocess, "run", return_value=Mock(returncode=0)) as call:
            self.w._raster_page(TOOL, Path("/tmp/candidate.pdf"), Path("/tmp/page-2"), 2,
                                launch_budget=budget)
        command = call.call_args.args[0]
        self.assertEqual(command[:2], [sys.executable, "-I"])
        self.assertEqual(Path(command[2]).name, "_pdf_raster_executor.py")
        self.assertEqual(command[3:], [str(os.getpid()), TOOL, "/tmp/candidate.pdf", "/tmp/page-2", "2"])
        self.assertEqual(call.call_args.kwargs["timeout"], 8)
        self.assertTrue(call.call_args.kwargs["close_fds"])
        self.assertNotIn("preexec_fn", call.call_args.kwargs)
        self.assertFalse(call.call_args.kwargs["shell"])

    def test_main_invalid_arguments_do_not_change_process_state(self):
        """Invalid command syntax returns usage failure before arming any lifecycle guard."""
        with patch.object(self.e, "_arm_lifetime") as guard:
            self.assertEqual(self.e.main(self.argv(page="01")), 64)
        guard.assert_not_called()

    def test_guard_failure_prevents_binary_open(self):
        """A missing parent-death registration cannot fall through to native exec."""
        with patch.object(self.e, "_arm_lifetime", side_effect=RuntimeError("unavailable")), \
             patch.object(self.e, "_open_executable") as opened:
            self.assertEqual(self.e.main(self.argv()), 70)
        opened.assert_not_called()

    def test_wrong_real_parent_is_rejected_silently(self):
        """The real isolated launcher rejects a parent mismatch without diagnostic payload."""
        result = subprocess.run([sys.executable, "-I", str(ROOT / "reporting/_pdf_raster_executor.py"),
            *self.argv(parent="2")[1:]], capture_output=True, timeout=4)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((result.stdout, result.stderr), (b"", b""))

    def test_scratch_and_page_paths_must_match(self):
        """The launcher does not accept a foreign output directory or page basename."""
        with tempfile.TemporaryDirectory(prefix="omnigenis-pdf-visual-supervisor-", dir="/tmp") as td:
            root = Path(td) / "raster-window-test"; root.mkdir(mode=0o700)
            with patch.dict(os.environ, {"TMPDIR": td}):
                for source, prefix in ((root / "other.pdf", root / "page-1"),
                        (root / "candidate.pdf", root / "page-2"),
                        (Path("/tmp/candidate.pdf"), root / "page-1")):
                    with self.assertRaises(ValueError): self.e._bind_scratch(source, prefix, 1)

    def test_scratch_descriptor_is_closed_by_caller(self):
        """Successful scratch binding exposes only one owned descriptor to close."""
        with tempfile.TemporaryDirectory(prefix="omnigenis-pdf-visual-supervisor-", dir="/tmp") as td:
            root = Path(td) / "raster-window-test"; root.mkdir(mode=0o700)
            with patch.dict(os.environ, {"TMPDIR": td}):
                path, fd = self.e._bind_scratch(root / "candidate.pdf", root / "page-1", 1)
            try: self.assertEqual(path, Path(td))
            finally: os.close(fd)

    def test_native_raster_result_is_unchanged(self):
        """The same actual two-page candidate retains legacy ordered raster evidence."""
        from tests.test_reporting_pdf_raster_windows import fixture_pdf
        from reporting.page_windows import plan_pdf_page_windows
        from reporting.pdf_raster_windows import inspect_pdf_raster_window, PROFILE_ID
        from reporting.pdf_visual import validate_pdf_visual_geometry
        pdf = fixture_pdf(2); digest = hashlib.sha256(pdf).hexdigest()
        plan = plan_pdf_page_windows(pdf_sha256=digest, ir_sha256="b" * 64,
            page_count=2, admitted_page_budget=2, pages_per_window=4, inspector_profile_id=PROFILE_ID)
        actual = inspect_pdf_raster_window(pdf_bytes=pdf, plan=plan, window_index=0,
            expected_plan_sha256=plan.plan_sha256)
        legacy = validate_pdf_visual_geometry(pdf_bytes=pdf, expected_pdf_sha256=digest)
        self.assertTrue(legacy.passed)
        self.assertEqual(actual.raster_sha256, legacy.raster_sha256)
        self.assertEqual(actual.total_pixels, legacy.total_pixels)

    def test_manifest_narrows_only_direct_child_lifetime(self):
        """The manifest records the launcher without claiming aggregate or arbitrary cleanup."""
        value = json.loads((ROOT / "reporting/pdf-raster-window-engine.v1.json").read_text())
        life = value["native_executor_lifecycle"]
        self.assertTrue(life["parent_death_survives_exec"])
        self.assertEqual(life["independent_wall_seconds"], 8)
        self.assertFalse(life["arbitrary_descendant_cleanup_claimed"])
        self.assertFalse(life["startup_before_registration_covered"])
        self.assertFalse(value["guards"]["aggregate_job_resources_qualified"])
        self.assertEqual(value["resource_budget"]["document_pages"], 512)
        self.assertEqual(value["resource_budget"]["pdf_bytes"], 8 * 1024 * 1024)
        self.assertEqual(life["launcher_sha256"], hashlib.sha256((ROOT / life["launcher_path"]).read_bytes()).hexdigest())


    def test_lifetime_order_and_fixed_timer(self):
        """The reviewed parent guard precedes the fixed per-page interval timer."""
        events = []
        with patch.object(self.e, "_arm_worker_lifetime", side_effect=lambda p: events.append(("parent", p))), \
             patch.object(self.e.signal, "setitimer", side_effect=lambda *a: events.append(("timer", *a))):
            self.e._arm_lifetime(42)
        self.assertEqual(events, [("parent", 42), ("timer", signal.ITIMER_REAL, 8)])

    def mocked_main(self, failure=None, stale_parent=False, guard_failure=None):
        """Exercise only host-safe mocked setup while retaining real owned descriptors."""
        with tempfile.TemporaryDirectory() as td, ExitStack() as stack:
            scratch_fd = os.open(td, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            binary_fd = os.open(TOOL, os.O_RDONLY | os.O_CLOEXEC)
            events = []
            stack.enter_context(patch.object(self.e, "_arm_lifetime", side_effect=lambda p: events.append("lifetime")))
            stack.enter_context(patch.object(self.e, "_limits", side_effect=lambda: events.append("limits")))
            stack.enter_context(patch.object(self.e, "_bind_scratch", return_value=(Path(td), scratch_fd)))
            for name in ("enforce_pdf_landlock", "enforce_pdf_network_filter"):
                stack.enter_context(patch.object(self.e, name,
                    side_effect=RuntimeError("guard") if guard_failure == name else None))
            opened = stack.enter_context(patch.object(self.e, "_open_executable", return_value=binary_fd))
            executable = stack.enter_context(patch.object(self.e.os, "execve", side_effect=failure))
            expected_parent = os.getpid()
            stack.enter_context(patch.object(self.e.os, "getppid",
                return_value=expected_parent + 1 if stale_parent else expected_parent))
            try:
                result = self.e.main(self.argv(parent=str(expected_parent)))
                return result, executable.call_args, opened.called, events
            finally:
                for descriptor in (scratch_fd, binary_fd):
                    try: os.close(descriptor)
                    except OSError as exc:
                        if exc.errno != errno.EBADF: raise

    def test_mocked_lifecycle_is_independent_of_test_runner_parent(self):
        """An orphaned test runner must not invalidate the simulated valid parent."""
        for observed_parent in (1, 4242):
            with self.subTest(observed_parent=observed_parent), \
                 patch.object(os, "getppid", return_value=observed_parent):
                result, call, opened, events = self.mocked_main(
                    failure=OSError("synthetic exec failure"))
                self.assertEqual(result, 70)
                self.assertTrue(opened)
                self.assertIsNotNone(call)
                self.assertEqual(events, ["lifetime", "limits"])
                self.assertEqual(os.getppid(), observed_parent)

    def test_exec_uses_checked_descriptor_fixed_arguments_and_environment(self):
        """No shell, environment loader injection or path re-open replaces the verified FD."""
        result, call, opened, events = self.mocked_main(failure=OSError("synthetic exec failure"))
        self.assertEqual(result, 70)
        self.assertTrue(opened)
        self.assertEqual(events, ["lifetime", "limits"])
        self.assertIs(type(call.args[0]), int)
        self.assertEqual(call.args[1][:9], [TOOL, "-f", "1", "-l", "1", "-singlefile", "-r", "96", "-png"])
        self.assertEqual(set(call.args[2]), {"PATH", "LANG", "TMPDIR"})
        self.assertEqual(call.args[2]["LANG"], "C.UTF-8")

    def test_stale_parent_prevents_exec_after_binary_checks(self):
        """A parent change observed immediately before exec has no native fallback."""
        result, call, opened, _ = self.mocked_main(stale_parent=True)
        self.assertEqual(result, 70)
        self.assertTrue(opened)
        self.assertIsNone(call)

    def test_reapplied_kernel_guards_are_mandatory(self):
        """Either unavailable process-local guard prevents binary admission and execution."""
        for guard in ("enforce_pdf_landlock", "enforce_pdf_network_filter"):
            result, call, opened, _ = self.mocked_main(guard_failure=guard)
            self.assertEqual(result, 70)
            self.assertFalse(opened)
            self.assertIsNone(call)

    def test_unexpected_exec_return_is_never_success(self):
        """A returning exec surrogate must not manufacture a successful exit code."""
        result, call, _, _ = self.mocked_main()
        self.assertEqual(result, 70)
        self.assertIsNotNone(call)

    def test_executable_size_budget_is_not_bypassed(self):
        """Even the correct binary is rejected when the declared read budget is exceeded."""
        with patch.object(self.e, "MAX_EXECUTABLE_BYTES", 32):
            with self.assertRaises(ValueError): self.e._open_executable(TOOL)

    def test_executable_symlink_is_rejected(self):
        """A matching binary reached through a symlink cannot replace the fixed descriptor."""
        with tempfile.TemporaryDirectory() as td:
            link = Path(td) / "pdftoppm"; link.symlink_to(TOOL)
            with patch.object(self.e, "TOOL_PATH", str(link)):
                with self.assertRaises(OSError): self.e._open_executable(str(link))

    def test_unsupported_platform_prevents_setup(self):
        """Non-Linux startup cannot invoke a partial lifetime or execution path."""
        with patch.object(self.e.sys, "platform", "unsupported"), patch.object(self.e, "_arm_lifetime") as arm:
            self.assertEqual(self.e.main(self.argv()), 64)
        arm.assert_not_called()

    def test_changed_functions_have_docstrings(self):
        """All touched Python functions have explicit documentation before review."""
        for name in ("reporting/_pdf_raster_executor.py", "reporting/_pdf_raster_window_worker.py",
                     "tests/test_reporting_pdf_raster_lifecycle.py"):
            for node in ast.walk(ast.parse((ROOT / name).read_text())):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.assertTrue(ast.get_docstring(node), f"{name}:{node.name}")


if __name__ == "__main__":
    unittest.main()
