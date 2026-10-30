"""Native version checks and explicit synthetic lifetime controls for the raster probe."""
from __future__ import annotations

import ast
from contextlib import ExitStack
import ctypes
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
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
TOOL = "/usr/bin/pdftoppm"


def native_lifetime_surrogate(mode: str, guarded: bool) -> dict:
    """Test the actual launcher guards with a test-only sleep exec, not PDF execution."""
    if ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) != 0:
        raise RuntimeError("test subreaper unavailable")
    child_code = (
        "import os,sys\nsys.path.insert(0," + repr(str(ROOT)) + ")\n"
        "from reporting import _pdf_raster_probe as m\n"
        "def substitute(fd):\n"
        "    'Test-only blocking native surrogate, never a production command.'\n"
        "    os.execve('/usr/bin/sleep',['sleep','20'],{'PATH':os.defpath,'LANG':'C.UTF-8'})\n"
        "m._exec_version=substitute\n"
        + ("m._arm_lifetime=lambda parent:None\n" if not guarded else "")
        + "raise SystemExit(m.main(['probe',str(os.getppid())]))\n"
    )
    parent_code = (
        "import os,subprocess,sys,tempfile\n"
        "with tempfile.TemporaryFile() as output:\n"
        "    child=subprocess.Popen(" + repr([sys.executable, "-I", "-c", child_code]) + ","
        "stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.STDOUT,close_fds=True)\n"
        "    print(child.pid,flush=True)\n    sys.stdin.readline()\n    os._exit(0)\n"
    )
    parent = subprocess.Popen([sys.executable, "-I", "-c", parent_code],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, close_fds=True, env={"PATH": os.defpath, "LANG": "C.UTF-8"})
    child_fd = child_pid = None
    reaped = False
    started = time.monotonic()
    try:
        if not select.select([parent.stdout], [], [], 5)[0]:
            raise RuntimeError("test child identity missing")
        child_pid = int(parent.stdout.readline().strip())
        child_fd = os.pidfd_open(child_pid)
        deadline = time.monotonic() + 5
        while True:
            if select.select([child_fd], [], [], 0)[0]:
                raise RuntimeError("test child exited before surrogate exec")
            try:
                native = Path(f"/proc/{child_pid}/exe").resolve(strict=True) == Path("/usr/bin/sleep").resolve(strict=True)
            except FileNotFoundError:
                native = False
            if native:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("test surrogate exec not observed")
            time.sleep(0.01)
        if mode == "parent-death":
            parent.stdin.write("\n"); parent.stdin.flush(); parent.wait(timeout=3)
            observed = bool(select.select([child_fd], [], [], 2)[0])
        elif mode == "timer":
            observed = bool(select.select([child_fd], [], [], 5)[0])
            parent.stdin.write("\n"); parent.stdin.flush(); parent.wait(timeout=3)
        else:
            raise ValueError("invalid test mode")
        sig = None
        if observed:
            _, status = os.waitpid(child_pid, 0)
            reaped = True
            sig = os.WTERMSIG(status) if os.WIFSIGNALED(status) else None
        return {"surrogate_exec_observed": True, "production_pdf_execution": False,
                "exit_observed": observed, "exit_signal": sig, "guarded": guarded,
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


class RasterVersionProbeTests(unittest.TestCase):
    """Keep real exact-version admission separate from synthetic blocked-exec controls."""

    def setUp(self):
        """Require the new boundary before any native or protocol test can pass."""
        self.assertIsNotNone(importlib.util.find_spec("reporting._pdf_raster_probe"),
                             "guarded raster version probe is missing")
        self.m = importlib.import_module("reporting._pdf_raster_probe")

    def probe(self, mode, guarded=True):
        """Keep subreaper changes and all child cleanup inside a disposable harness."""
        code = "import json;from tests.test_reporting_pdf_raster_probe import native_lifetime_surrogate;print(json.dumps(native_lifetime_surrogate(" + repr(mode) + "," + repr(guarded) + ")))"
        result = subprocess.run([sys.executable, "-c", code], cwd=ROOT,
                                capture_output=True, text=True, timeout=15, check=True)
        return json.loads(result.stdout)

    def mocked_main(self, **overrides):
        """Run successful setup with no irreversible guards applied to the test process."""
        defaults = {"_arm_lifetime": Mock(), "_limits": Mock(), "_validate_output": Mock(),
                    "enforce_pdf_landlock": Mock(), "enforce_pdf_network_filter": Mock(),
                    "_open_executable": Mock(return_value=99), "_exec_version": Mock()}
        defaults.update(overrides)
        with ExitStack() as stack:
            for key, value in defaults.items(): stack.enter_context(patch.object(self.m, key, value))
            stack.enter_context(patch.object(self.m.os, "getppid", return_value=123))
            stack.enter_context(patch.object(self.m.os, "close"))
            return self.m.main(["probe", "123"])

    def test_native_version_matches_exact_legacy_identity(self):
        """The actual guarded pdftoppm version query returns the same pinned identity."""
        from reporting._pdf_visual_worker import _tool_identity
        self.assertEqual(self.m._tool_identity(), _tool_identity())
        self.assertEqual(self.m._tool_identity(), (self.m.TOOL_VERSION, self.m.TOOL_SHA256, TOOL))

    def test_optional_worker_uses_new_probe_not_legacy_probe(self):
        """Only the optional raster worker imports the new closed identity operation."""
        from reporting import _pdf_raster_window_worker as worker, _pdf_visual_worker as legacy
        self.assertIs(worker._tool_identity, self.m._tool_identity)
        self.assertIsNot(legacy._tool_identity, self.m._tool_identity)

    def test_canonical_parent_only(self):
        """Only one canonical decimal parent identifier is accepted, never native arguments."""
        self.assertEqual(self.m._parse_parent(["probe", "123"]), 123)
        for args in ([], ["probe"], ["probe", "123", "-v"], ("probe", "123")):
            with self.assertRaises(ValueError): self.m._parse_parent(args)
        for value in (True, None, 123, "1", "0", "-1", "+123", "0123", " 123", "123\n", "１２３", "9" * 1000, "2147483648"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.m._parse_parent(["probe", value])

    def test_invalid_arguments_never_arm_guards(self):
        """Usage errors cannot change process limits or native lifetime state."""
        with patch.object(self.m, "_arm_lifetime") as arm:
            self.assertEqual(self.m.main(["probe", "-1"]), 64)
        arm.assert_not_called()

    def test_output_must_be_same_empty_anonymous_file(self):
        """The launcher cannot redirect native output to named files, devices or aliases."""
        with tempfile.TemporaryFile() as a, tempfile.TemporaryFile() as b:
            self.m._validate_output(a.fileno(), a.fileno())
            with self.assertRaises(ValueError): self.m._validate_output(a.fileno(), b.fileno())
            a.write(b"old"); a.flush()
            with self.assertRaises(ValueError): self.m._validate_output(a.fileno(), a.fileno())
        with tempfile.NamedTemporaryFile() as named:
            with self.assertRaises(ValueError): self.m._validate_output(named.fileno(), named.fileno())
        with open(os.devnull, "wb") as sink:
            with self.assertRaises(ValueError): self.m._validate_output(sink.fileno(), sink.fileno())

    def test_actual_launch_is_isolated_and_has_no_protocol_inheritance(self):
        """The fixed command and narrow environment contain no caller PDF or shell input."""
        from reporting._pdf_raster_launch_budget import RasterLaunchBudget
        budget = RasterLaunchBudget()
        self.addCleanup(budget.close)
        with tempfile.TemporaryFile() as output, patch.object(self.m.subprocess, "Popen") as start:
            self.m._start(output, launch_budget=budget)
            args = start.call_args
            self.assertEqual(args.args[0], [sys.executable, "-I", str(ROOT / "reporting/_pdf_raster_probe.py"), str(os.getpid())])
            self.assertEqual(args.kwargs["env"], {"PATH": os.defpath, "LANG": "C.UTF-8"})
            self.assertIs(args.kwargs["close_fds"], True)
            self.assertNotIn("pass_fds", args.kwargs)
            self.assertIs(args.kwargs["shell"], False)
            self.assertEqual(args.kwargs["stderr"], subprocess.STDOUT)
            self.assertIs(args.kwargs["stdout"], output)

    def test_version_output_is_closed_and_bounded(self):
        """Wrong versions, malformed text and excessive output cannot become identity evidence."""
        valid = ("pdftoppm version " + self.m.TOOL_VERSION + "\nCopyright example\n").encode()
        self.assertEqual(self.m._decode_version(valid)[0], self.m.TOOL_VERSION)
        for data in (b"", None, bytearray(valid), b"\xff", b"pdftoppm version 0.0\n", b"PASS", b" " + valid, b"\n" + valid, b"x" * 4097):
            with self.subTest(data=type(data)), self.assertRaises(ValueError): self.m._decode_version(data)

    def test_parent_and_timer_guards_precede_executable_read(self):
        """Any lifecycle or kernel-policy failure stops before binary admission."""
        for name in ("_arm_lifetime", "_limits", "_validate_output", "enforce_pdf_landlock", "enforce_pdf_network_filter"):
            opened = Mock()
            self.assertEqual(self.mocked_main(**{name: Mock(side_effect=RuntimeError("private")), "_open_executable": opened}), 70)
            opened.assert_not_called()

    def test_exact_descriptor_exec_has_no_fallback(self):
        """Only the admitted descriptor is executed with the fixed version argument."""
        with patch.object(self.m.os, "execve") as execute:
            self.m._exec_version(99)
            execute.assert_called_once_with(99, [TOOL, "-v"], {"PATH": os.defpath, "LANG": "C.UTF-8"})
        execute = Mock()
        self.assertEqual(self.mocked_main(_open_executable=Mock(side_effect=ValueError("bad digest")), _exec_version=execute), 70)
        execute.assert_not_called()
        self.assertEqual(self.mocked_main(), 70, "returned exec is not success")

    def test_kernel_timer_is_three_seconds(self):
        """The parent guard and independent elapsed timer are both mandatory."""
        with patch.object(self.m, "_arm_worker_lifetime") as arm, patch.object(self.m.signal, "setitimer") as timer:
            self.m._arm_lifetime(123)
            arm.assert_called_once_with(123)
            timer.assert_called_once_with(signal.ITIMER_REAL, 3)

    def test_resource_limits_are_finite_including_output(self):
        """Probe limits cap both output streams without increasing the current raster envelope."""
        import resource
        with patch.object(resource, "setrlimit") as limit:
            self.m._limits()
        calls = {call.args[0]: call.args[1] for call in limit.call_args_list}
        self.assertEqual(calls[resource.RLIMIT_AS], (512 * 1024 * 1024,) * 2)
        self.assertEqual(calls[resource.RLIMIT_CPU], (3, 3))
        self.assertEqual(calls[resource.RLIMIT_FSIZE], (4096, 4096))
        self.assertEqual(calls[resource.RLIMIT_NOFILE], (128, 128))
        self.assertEqual(calls[resource.RLIMIT_CORE], (0, 0))

    def test_read_output_checks_byte_count(self):
        """Empty or oversized files are rejected before unbounded allocation."""
        with tempfile.TemporaryFile() as output:
            with self.assertRaises(ValueError): self.m._read_output(output)
            output.write(b"x" * 4097); output.flush()
            with self.assertRaises(ValueError): self.m._read_output(output)

    def test_native_failure_and_partial_output_are_not_success(self):
        """Failed native invocations and arbitrary diagnostic messages remain fixed errors."""
        for reply in (b"", b"private native diagnostic", b"pdftoppm version 999\n"):
            with patch.object(self.m, "_run_probe", return_value=reply):
                with self.assertRaisesRegex(OSError, "^pdf_raster_version_probe_failed$"):
                    self.m._tool_identity()
        with patch.object(self.m, "_run_probe", side_effect=RuntimeError("private details")):
            with self.assertRaisesRegex(OSError, "^pdf_raster_version_probe_failed$"):
                self.m._tool_identity()

    def test_disable_prevents_probe_and_has_no_legacy_fallback(self):
        """Disabled or unsupported execution cannot return a version from another path."""
        with patch.dict(os.environ, {"OMNIGENIS_PDF_RASTER_WINDOWS_DISABLED": "1"}), patch.object(self.m, "_start") as start:
            with self.assertRaisesRegex(OSError, "unavailable"): self.m._tool_identity()
            start.assert_not_called()
        with patch.object(self.m.sys, "platform", "unsupported"):
            self.assertEqual(self.m.main(["probe", "123"]), 64)
            with self.assertRaisesRegex(OSError, "unavailable"): self.m._tool_identity()

    def test_native_calls_release_all_parent_descriptors(self):
        """Repeated real successful version probes leave no inherited or temporary handles."""
        before = len(os.listdir("/proc/self/fd"))
        for _ in range(3): self.m._tool_identity()
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_caller_timeout_kills_and_reaps_exact_child(self):
        """The caller retains a finite fallback even if child-side setup is unavailable."""
        proc = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(20)"], start_new_session=True)
        with patch.object(self.m, "WALL_SECONDS", 0.05):
            with self.assertRaises(subprocess.TimeoutExpired): self.m._wait(proc)
        self.assertIsNotNone(proc.returncode)

    def test_wrong_real_parent_produces_no_native_output(self):
        """The actual isolated version launcher rejects a stale parent before native exec."""
        with tempfile.TemporaryFile() as output:
            child = subprocess.run([sys.executable, "-I", str(ROOT / "reporting/_pdf_raster_probe.py"), "2"],
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, timeout=5, close_fds=True)
            self.assertNotEqual(child.returncode, 0)
            self.assertEqual(os.fstat(output.fileno()).st_size, 0)

    def test_parent_death_controls_test_only_native_surrogate(self):
        """A pidfd-pinned blocked surrogate exits by SIGKILL through the production guard path."""
        value = self.probe("parent-death")
        self.assertTrue(value["surrogate_exec_observed"])
        self.assertFalse(value["production_pdf_execution"])
        self.assertTrue(value["exit_observed"])
        self.assertEqual(value["exit_signal"], signal.SIGKILL)

    def test_unguarded_surrogate_is_a_real_negative_control(self):
        """Removing lifetime registration in the disposable test must not report child exit."""
        value = self.probe("parent-death", False)
        self.assertTrue(value["surrogate_exec_observed"])
        self.assertFalse(value["exit_observed"])

    def test_independent_timer_survives_test_only_native_exec(self):
        """The actual kernel timer ends a blocked surrogate while its direct parent stays alive."""
        value = self.probe("timer")
        self.assertTrue(value["exit_observed"])
        self.assertEqual(value["exit_signal"], signal.SIGALRM)

    def test_existing_native_raster_result_is_unchanged(self):
        """Real PDF pixels and the existing raster receipt remain identical for a small candidate."""
        from tests.test_reporting_pdf_text_windows import fixture_pdf
        from reporting.page_windows import plan_pdf_page_windows
        from reporting.pdf_raster_windows import inspect_pdf_raster_window, PROFILE_ID
        from reporting.pdf_visual import validate_pdf_visual_geometry
        pdf = fixture_pdf(2); digest = hashlib.sha256(pdf).hexdigest()
        plan = plan_pdf_page_windows(pdf_sha256=digest, ir_sha256="b" * 64, page_count=2,
            admitted_page_budget=2, pages_per_window=4, inspector_profile_id=PROFILE_ID)
        current = inspect_pdf_raster_window(pdf_bytes=pdf, plan=plan, window_index=0, expected_plan_sha256=plan.plan_sha256)
        previous = validate_pdf_visual_geometry(pdf_bytes=pdf, expected_pdf_sha256=digest)
        self.assertTrue(previous.passed)
        self.assertEqual((current.raster_sha256, current.total_pixels, current.min_edge_margin_px),
                         (previous.raster_sha256, previous.total_pixels, previous.min_edge_margin_px))

    def test_manifest_records_probe_without_expanding_qualification(self):
        """The new probe profile remains narrow and pins source and output budgets."""
        m = json.loads((ROOT / "reporting/pdf-raster-window-engine.v1.json").read_text())
        p = m["native_version_probe"]
        self.assertEqual(p["independent_wall_seconds"], 3)
        self.assertEqual(p["output_bytes"], 4096)
        self.assertTrue(p["parent_death_survives_exec"])
        self.assertFalse(p["startup_before_registration_covered"])
        self.assertFalse(p["arbitrary_descendant_cleanup_claimed"])
        self.assertFalse(m["guards"]["aggregate_job_resources_qualified"])
        self.assertEqual(p["launcher_sha256"], hashlib.sha256((ROOT / p["launcher_path"]).read_bytes()).hexdigest())

    def test_changed_functions_have_docstrings(self):
        """Every touched function describes its responsibility and verification boundary."""
        for path in (ROOT / "reporting/_pdf_raster_probe.py", Path(__file__)):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.assertTrue(ast.get_docstring(node), f"{path.name}:{node.name}")


    def test_changed_parent_before_exec_is_rejected(self):
        """A parent that disappears after setup cannot authorize descriptor execution."""
        execute = Mock()
        def changed_parent(tool):
            """Simulate a parent identity change immediately after binary admission."""
            self.m.os.getppid.return_value = 999
            return 99
        self.assertEqual(self.mocked_main(_open_executable=changed_parent, _exec_version=execute), 70)
        execute.assert_not_called()

    def test_changed_credentials_prevent_exec(self):
        """Real and effective credentials must still agree at the exec boundary."""
        execute = Mock()
        with patch.object(self.m.os, "getuid", return_value=os.geteuid() + 1):
            self.assertEqual(self.mocked_main(_exec_version=execute), 70)
        execute.assert_not_called()

    def test_nonzero_probe_does_not_read_partial_output(self):
        """Native failure cannot expose even a well-shaped partial version banner."""
        from reporting._pdf_raster_launch_budget import RasterLaunchBudget
        budget = RasterLaunchBudget()
        self.addCleanup(budget.close)
        with patch.object(self.m, "_start"), patch.object(self.m, "_wait", return_value=1), patch.object(self.m, "_read_output") as read:
            with self.assertRaises(ValueError): self.m._run_probe(launch_budget=budget)
            read.assert_not_called()

    def test_output_mutation_during_read_is_rejected(self):
        """Concurrent observable size or timestamp changes invalidate native output."""
        with tempfile.TemporaryFile() as output:
            output.write(b"version"); output.flush()
            wrapped = Mock(wraps=output)
            def mutate(size):
                """Alter the real file after reading to exercise identity reconciliation."""
                value = output.read(size)
                output.write(b"changed"); output.flush()
                return value
            wrapped.read.side_effect = mutate
            with self.assertRaises(ValueError): self.m._read_output(wrapped)

    def test_foreign_output_owner_is_rejected(self):
        """Anonymous output still requires the expected effective owner."""
        with tempfile.TemporaryFile() as output, patch.object(self.m.os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaises(ValueError): self.m._validate_output(output.fileno(), output.fileno())
            output.write(b"x"); output.flush()
            with self.assertRaises(ValueError): self.m._read_output(output)

    def test_actual_kernel_output_bound_prevents_extra_bytes(self):
        """A disposable writer cannot grow inherited output beyond the declared four KiB."""
        code = "import os,signal;from reporting._pdf_raster_probe import _limits;_limits();signal.signal(signal.SIGXFSZ,signal.SIG_DFL);os.write(1,b'x'*4096);os.write(1,b'x')"
        with tempfile.TemporaryFile() as output:
            child = subprocess.run([sys.executable, "-c", code], cwd=ROOT,
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL, timeout=5)
            self.assertEqual(child.returncode, -signal.SIGXFSZ)
            self.assertEqual(os.fstat(output.fileno()).st_size, 4096)

    def test_existing_disable_blocks_actual_raster_without_fallback(self):
        """The existing adapter disable switch withholds raster receipts without a probe fallback."""
        from tests.test_reporting_pdf_text_windows import fixture_pdf
        from reporting.page_windows import plan_pdf_page_windows
        from reporting.pdf_raster_windows import inspect_pdf_raster_window, PROFILE_ID, PdfRasterWindowError
        pdf = fixture_pdf(1)
        plan = plan_pdf_page_windows(pdf_sha256=hashlib.sha256(pdf).hexdigest(), ir_sha256="b" * 64,
            page_count=1, admitted_page_budget=1, pages_per_window=4, inspector_profile_id=PROFILE_ID)
        with patch.dict(os.environ, {"OMNIGENIS_PDF_RASTER_WINDOWS_DISABLED": "1"}):
            with self.assertRaises(PdfRasterWindowError):
                inspect_pdf_raster_window(pdf_bytes=pdf, plan=plan, window_index=0, expected_plan_sha256=plan.plan_sha256)


if __name__ == "__main__":
    unittest.main()
