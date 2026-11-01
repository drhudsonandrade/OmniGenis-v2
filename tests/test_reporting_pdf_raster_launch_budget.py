"""Exact window-local launch attempts, with real accounting at each process boundary."""
from __future__ import annotations

import ast
from contextlib import contextmanager
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
TOOL = "/usr/bin/pdftoppm"


class ProbeProcess:
    """Model only the waitable child returned by the substituted process primitive."""

    def __init__(self, *, status=0, timeout=False):
        """Keep the real caller's wait/kill/reap path available for failure controls."""
        self.returncode = None
        self.status = status
        self.timeout = timeout

    def wait(self, timeout):
        """Return the configured exit code or time out before the caller kills the child."""
        if self.timeout and self.returncode is None:
            raise subprocess.TimeoutExpired("synthetic-probe", timeout)
        self.returncode = self.status if self.returncode is None else self.returncode
        return self.returncode

    def kill(self):
        """Allow the production finally block to reap a timed-out synthetic child."""
        self.returncode = -9


class BudgetAssertions(unittest.TestCase):
    """Provide failure-first imports without replacing the concrete allowance under test."""

    def budget_class(self):
        """Make a missing implementation an explicit assertion, not an import error."""
        self.assertIsNotNone(importlib.util.find_spec("reporting._pdf_raster_launch_budget"),
                             "window-local raster launch allowance is missing")
        module = importlib.import_module("reporting._pdf_raster_launch_budget")
        self.assertTrue(hasattr(module, "RasterLaunchBudget"), "concrete raster allowance is missing")
        return module.RasterLaunchBudget

    def budget(self, pages=()):
        """Construct a real allowance and close it in its creator context after the test."""
        value = self.budget_class()(pages)
        self.addCleanup(value.close)
        return value

    def assert_poisoned(self, budget):
        """A caught protocol violation must not permit later completion or fresh work."""
        for operation in (budget.require_complete, budget.consume_probe,
                          lambda: budget.consume_page(2)):
            with self.assertRaises(ValueError):
                operation()

    def in_foreign_thread(self, operation):
        """Observe thread-local rejection without losing exceptions inside a test thread."""
        errors = []
        def invoke():
            """Record the actual foreign-thread operation's outcome for the creator."""
            try:
                operation()
            except Exception as exc:
                errors.append(exc)
        thread = threading.Thread(target=invoke)
        thread.start()
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1, "foreign thread used a creator-local allowance")
        self.assertIsInstance(errors[0], ValueError)


class RasterLaunchBudgetTests(BudgetAssertions):
    """Exercise the finite sequence independently of native output or worker receipts."""

    def test_standalone_allowance_admits_exactly_one_probe(self):
        """The empty compatibility schedule still requires and caps its one probe attempt."""
        budget = self.budget()
        budget.consume_probe()
        budget.require_complete()
        with self.assertRaises(ValueError):
            budget.consume_probe()
        self.assert_poisoned(budget)

    def test_exact_selected_schedules_complete(self):
        """One-page, two-page and maximum four-page schedules retain their exact order."""
        for pages in ((1,), (2, 3), (509, 510, 511, 512)):
            with self.subTest(pages=pages):
                budget = self.budget(pages)
                budget.consume_probe()
                for page in pages:
                    budget.consume_page(page)
                budget.require_complete()

    def test_invalid_selected_tuples_are_rejected(self):
        """Mutable, coerced, nonconsecutive and over-budget page schedules are not admitted."""
        cls = self.budget_class()
        for pages in (None, [2, 3], range(2, 4), (True,), (2.0,), ("2",), (0,),
                      (-1,), (513,), (2, 4), (3, 2), (2, 2), (1, 2, 3, 4, 5)):
            with self.subTest(pages=pages), self.assertRaises(ValueError):
                cls(pages)

    def test_page_before_probe_poisoning(self):
        """Catching an early page violation cannot restart the admitted sequence."""
        budget = self.budget((2, 3))
        with self.assertRaises(ValueError):
            budget.consume_page(2)
        self.assert_poisoned(budget)

    def test_second_probe_poisoning(self):
        """A duplicate version probe invalidates even a previously completed schedule."""
        budget = self.budget((2,))
        budget.consume_probe()
        budget.consume_page(2)
        with self.assertRaises(ValueError):
            budget.consume_probe()
        self.assert_poisoned(budget)

    def test_wrong_page_or_scalar_poisoning(self):
        """Wrong, early and truth-like pages cannot be corrected after catching rejection."""
        for page in (1, 3, 4, 0, True, 2.0, "2", None):
            with self.subTest(page=page):
                budget = self.budget((2, 3))
                budget.consume_probe()
                with self.assertRaises(ValueError):
                    budget.consume_page(page)
                self.assert_poisoned(budget)

    def test_repeated_and_excess_pages_poisoning(self):
        """Neither a repeated page nor another page after exhaustion is refundable."""
        for completed, forbidden in (((2,), 2), ((2, 3), 4)):
            budget = self.budget((2, 3))
            budget.consume_probe()
            for page in completed:
                budget.consume_page(page)
            with self.assertRaises(ValueError):
                budget.consume_page(forbidden)
            self.assert_poisoned(budget)

    def test_incomplete_completion_poisoning(self):
        """A premature success check invalidates rather than extending an incomplete run."""
        for completed in (None, (), (2,)):
            budget = self.budget((2, 3))
            if completed is not None:
                budget.consume_probe()
                for page in completed:
                    budget.consume_page(page)
            with self.assertRaises(ValueError):
                budget.require_complete()
            self.assert_poisoned(budget)

    def test_close_is_idempotent_and_prevents_every_operation(self):
        """Closure does not reset capacity or turn an incomplete schedule into success."""
        for complete in (False, True):
            budget = self.budget()
            if complete:
                budget.consume_probe()
            budget.close()
            budget.close()
            self.assert_poisoned(budget)

    def test_foreign_pid_poisoning_for_all_operations(self):
        """Every public state operation rejects a process different from its creator."""
        for method in ("consume_probe", "consume_page", "require_complete", "close"):
            budget = self.budget((2,))
            operation = (lambda: budget.consume_page(2)) if method == "consume_page" else getattr(budget, method)
            with patch("os.getpid", return_value=os.getpid() + 1), self.assertRaises(ValueError):
                operation()
            self.assert_poisoned(budget)

    def test_foreign_thread_poisoning_for_all_operations(self):
        """Even the same process cannot transfer an allowance to a second thread."""
        for method in ("consume_probe", "consume_page", "require_complete", "close"):
            budget = self.budget((2,))
            operation = (lambda: budget.consume_page(2)) if method == "consume_page" else getattr(budget, method)
            self.in_foreign_thread(operation)
            self.assert_poisoned(budget)


class RasterLaunchBoundaryTests(BudgetAssertions):
    """Keep the launch helpers and concrete state real; substitute only child creation."""

    def setUp(self):
        """Load the existing call sites even before the new allowance module exists."""
        self.probe = importlib.import_module("reporting._pdf_raster_probe")
        self.worker = importlib.import_module("reporting._pdf_raster_window_worker")

    def spawn_probe(self, *args, **kwargs):
        """Supply the complete bounded version response at the actual Popen boundary."""
        kwargs["stdout"].write(("pdftoppm version " + self.probe.TOOL_VERSION + "\n").encode())
        kwargs["stdout"].flush()
        return ProbeProcess()

    def page(self, number, **kwargs):
        """Reach the real executor boundary without preparing native PDF input."""
        return self.worker._raster_page(TOOL, Path("/tmp/candidate.pdf"),
                                        Path(f"/tmp/page-{number}"), number, **kwargs)

    def test_missing_start_allowance_never_reaches_popen(self):
        """The lowest probe launcher cannot silently mint its own fresh allowance."""
        with tempfile.TemporaryFile() as output, patch.object(self.probe.subprocess, "Popen") as spawn:
            with self.assertRaises((TypeError, ValueError)):
                self.probe._start(output)
            spawn.assert_not_called()

    def test_missing_run_probe_allowance_never_reaches_popen(self):
        """Only the top-level standalone identity operation may own a default allowance."""
        with patch.object(self.probe.subprocess, "Popen", side_effect=self.spawn_probe) as spawn:
            with self.assertRaises((TypeError, ValueError)):
                self.probe._run_probe()
            spawn.assert_not_called()

    def test_missing_page_allowance_never_reaches_run(self):
        """An unaccounted page invocation is rejected before starting an executor."""
        with patch.object(self.worker.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as spawn:
            with self.assertRaises((TypeError, ValueError)):
                self.page(2)
            spawn.assert_not_called()

    def test_foreign_and_subclass_allowances_never_spawn(self):
        """Duck typing or overridden accounting methods cannot replace the concrete allowance."""
        cls = self.budget_class()
        class BypassBudget(cls):
            """Demonstrate why launch sites require the exact concrete type."""
            def consume_probe(self):
                """Deliberately omit charging in a foreign implementation."""
            def consume_page(self, page):
                """Deliberately omit charging in a foreign implementation."""
        for foreign in (None, object(), Mock(), BypassBudget((2,))):
            with tempfile.TemporaryFile() as output, \
                 patch.object(self.probe.subprocess, "Popen") as popen, \
                 patch.object(self.worker.subprocess, "run") as run:
                for operation in (lambda: self.probe._start(output, launch_budget=foreign),
                                  lambda: self.probe._run_probe(launch_budget=foreign),
                                  lambda: self.page(2, launch_budget=foreign)):
                    with self.assertRaises(ValueError):
                        operation()
                popen.assert_not_called()
                run.assert_not_called()

    def test_exact_probe_and_page_schedule_reaches_primitives(self):
        """A single shared allowance authorizes one probe and the selected ordered pages only."""
        budget = self.budget((2, 3))
        with patch.object(self.probe.subprocess, "Popen", side_effect=self.spawn_probe) as popen, \
             patch.object(self.worker.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            self.probe._tool_identity(launch_budget=budget)
            self.assertEqual(self.page(2, launch_budget=budget), Path("/tmp/page-2.png"))
            self.assertEqual(self.page(3, launch_budget=budget), Path("/tmp/page-3.png"))
            budget.require_complete()
            self.assertEqual(popen.call_count, 1)
            self.assertEqual([call.args[0][7] for call in run.call_args_list], ["2", "3"])
            with self.assertRaises(ValueError):
                self.probe._run_probe(launch_budget=budget)
            self.assertEqual(popen.call_count, 1)

    def test_invalid_page_sequences_do_not_reach_run(self):
        """Early, repeated, extra and malformed pages are stopped by the actual executor helper."""
        cases = ((None, 2), ((), 1), ((), 3), ((), True), ((), 2.0),
                 ((), "2"), ((), None), ((2,), 2), ((2, 3), 4))
        for previous, forbidden in cases:
            with self.subTest(previous=previous, forbidden=forbidden):
                budget = self.budget((2, 3))
                with patch.object(self.probe.subprocess, "Popen", side_effect=self.spawn_probe), \
                     patch.object(self.worker.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
                    if previous is not None:
                        self.probe._run_probe(launch_budget=budget)
                        for page in previous:
                            self.page(page, launch_budget=budget)
                    admitted = run.call_count
                    with self.assertRaises(ValueError):
                        self.page(forbidden, launch_budget=budget)
                    self.assertEqual(run.call_count, admitted)
                    self.assert_poisoned(budget)

    def test_closed_allowances_do_not_reach_either_primitive(self):
        """Neither direct launch helper can reuse a closed allowance."""
        budget = self.budget((2,))
        budget.close()
        with tempfile.TemporaryFile() as output, patch.object(self.probe.subprocess, "Popen") as popen, \
             patch.object(self.worker.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                self.probe._start(output, launch_budget=budget)
            with self.assertRaises(ValueError):
                self.page(2, launch_budget=budget)
            popen.assert_not_called()
            run.assert_not_called()

    def test_foreign_pid_cannot_reach_either_primitive(self):
        """PID rejection happens before a probe or raster executor is spawned."""
        for page_launch in (False, True):
            budget = self.budget((2,))
            if page_launch:
                budget.consume_probe()
            with patch.object(self.probe.subprocess, "Popen") as popen, \
                 patch.object(self.worker.subprocess, "run") as run, \
                 patch("os.getpid", return_value=os.getpid() + 1):
                with self.assertRaises(ValueError):
                    if page_launch:
                        self.page(2, launch_budget=budget)
                    else:
                        self.probe._run_probe(launch_budget=budget)
                popen.assert_not_called()
                run.assert_not_called()
            self.assert_poisoned(budget)

    def test_foreign_thread_cannot_reach_either_primitive(self):
        """Thread rejection happens at both actual launch boundaries."""
        for page_launch in (False, True):
            budget = self.budget((2,))
            if page_launch:
                budget.consume_probe()
            operation = ((lambda: self.page(2, launch_budget=budget)) if page_launch
                         else lambda: self.probe._run_probe(launch_budget=budget))
            with patch.object(self.probe.subprocess, "Popen") as popen, \
                 patch.object(self.worker.subprocess, "run") as run:
                self.in_foreign_thread(operation)
                popen.assert_not_called()
                run.assert_not_called()
            self.assert_poisoned(budget)

    def test_probe_failures_are_charged_before_popen_without_refund(self):
        """Spawn errors, nonzero exits and timeouts cannot authorize a second probe attempt."""
        for failure, error in (("spawn", OSError), ("nonzero", ValueError),
                               ("timeout", subprocess.TimeoutExpired)):
            budget = self.budget()
            def start(*args, **kwargs):
                """Require the charge to be visible on entry to the actual primitive."""
                budget.require_complete()
                if failure == "spawn":
                    raise OSError("synthetic spawn failure")
                return ProbeProcess(status=2 if failure == "nonzero" else 0,
                                    timeout=failure == "timeout")
            with patch.object(self.probe.subprocess, "Popen", side_effect=start) as spawn:
                with self.assertRaises(error):
                    self.probe._run_probe(launch_budget=budget)
                budget.require_complete()
                with self.assertRaises(ValueError):
                    self.probe._run_probe(launch_budget=budget)
                self.assertEqual(spawn.call_count, 1)
                self.assert_poisoned(budget)

    def test_page_failures_are_charged_before_run_without_refund(self):
        """Every failed executor attempt remains spent before control returns to its caller."""
        for failure, error in (("spawn", OSError), ("nonzero", ValueError),
                               ("timeout", subprocess.TimeoutExpired)):
            budget = self.budget((2,))
            budget.consume_probe()
            def run(*args, **kwargs):
                """Observe the consumed last page before returning or raising from run."""
                budget.require_complete()
                if failure == "spawn":
                    raise OSError("synthetic spawn failure")
                if failure == "timeout":
                    raise subprocess.TimeoutExpired("synthetic-raster", 8)
                return subprocess.CompletedProcess([], 2)
            with patch.object(self.worker.subprocess, "run", side_effect=run) as spawn:
                with self.assertRaises(error):
                    self.page(2, launch_budget=budget)
                budget.require_complete()
                with self.assertRaises(ValueError):
                    self.page(2, launch_budget=budget)
                self.assertEqual(spawn.call_count, 1)
                self.assert_poisoned(budget)

    def test_launch_allowances_are_keyword_only(self):
        """Positional arguments cannot silently shift the fixed helper call contracts."""
        budget = self.budget((2,))
        with tempfile.TemporaryFile() as output, patch.object(self.probe.subprocess, "Popen") as popen, \
             patch.object(self.worker.subprocess, "run") as run:
            with self.assertRaises(TypeError):
                self.probe._start(output, budget)
            with self.assertRaises(TypeError):
                self.probe._run_probe(budget)
            with self.assertRaises(TypeError):
                self.worker._raster_page(TOOL, Path("/tmp/candidate.pdf"), Path("/tmp/page-2"), 2, budget)
            popen.assert_not_called()
            run.assert_not_called()


class RasterWorkerBudgetTests(BudgetAssertions):
    """Exercise real worker parsing, image inspection and helpers with synthetic child outputs."""

    def setUp(self):
        """Load existing production entry points independently from new allowance availability."""
        self.probe = importlib.import_module("reporting._pdf_raster_probe")
        self.worker = importlib.import_module("reporting._pdf_raster_window_worker")

    def candidate(self, pages):
        """Bind a real five-page fixture to an independently specified selected interval."""
        from tests.test_reporting_pdf_text_windows import fixture_pdf
        pdf = fixture_pdf(5)
        identity = dict(pdf_sha256=hashlib.sha256(pdf).hexdigest(), ir_sha256="b" * 64,
                        plan_sha256="c" * 64, page_count=5, window_index=0,
                        first_page=pages[0], last_page=pages[-1])
        return pdf, identity

    def png(self, prefix):
        """Write a bounded nonblank fixture matching the independently known PDF geometry."""
        from PIL import Image
        path = Path(str(prefix) + ".png")
        with Image.new("RGB", (794, 1123), "white") as image:
            image.putpixel((10, 10), (0, 0, 0))
            image.save(path)
        return path

    @contextmanager
    def processes(self, failure=None):
        """Substitute only process primitives and observe real close without replacing it."""
        cls = self.budget_class()
        events, closed = [], []
        real_close = cls.close
        def close(budget):
            """Retain closure semantics while recording the allowance owned by this call."""
            real_close(budget)
            closed.append(budget)
        def popen(*args, **kwargs):
            """Emit the fixed version banner through the actual caller-owned output file."""
            events.append(("probe", None))
            kwargs["stdout"].write(("pdftoppm version " + self.probe.TOOL_VERSION + "\n").encode())
            kwargs["stdout"].flush()
            return ProbeProcess(status=2 if failure == "probe" else 0)
        def run(command, **kwargs):
            """Produce only the selected page's raster fixture at the executor boundary."""
            events.append(("page", int(command[7])))
            if failure == "page":
                raise subprocess.TimeoutExpired(command, 8)
            self.png(Path(command[6]))
            return subprocess.CompletedProcess(command, 0)
        with patch.object(cls, "close", close), patch.object(self.probe.subprocess, "Popen", side_effect=popen), \
             patch.object(self.worker.subprocess, "run", side_effect=run):
            yield events, closed

    def test_worker_one_and_four_page_schedules_close(self):
        """Successful tail and full windows share one allowance and close it before return."""
        for pages in ((5,), (2, 3, 4, 5)):
            pdf, identity = self.candidate(pages)
            with tempfile.TemporaryDirectory() as td, self.processes() as (events, closed):
                result = self.worker._inspect(pdf, identity, Path(td))
                self.assertEqual(events, [("probe", None)] + [("page", n) for n in pages])
                self.assertEqual(result["status"], "WINDOW_RASTER_INSPECTED")
                self.assertEqual(result["inspected_pages"], len(pages))
                self.assertEqual(result["total_pixels"], len(pages) * 891662)
                self.assertEqual(result["min_edge_margin_px"], 10)
                self.assertEqual(len(closed), 1)
                self.assert_poisoned(closed[0])
                self.assertEqual(list(Path(td).iterdir()), [])

    def test_standalone_identity_closes_its_one_probe_allowance(self):
        """No-argument identity queries preserve their result and never retain reusable state."""
        with self.processes() as (events, closed):
            self.assertEqual(self.probe._tool_identity(),
                             (self.probe.TOOL_VERSION, self.probe.TOOL_SHA256, TOOL))
            self.assertEqual(events, [("probe", None)])
            self.assertEqual(len(closed), 1)
            self.assert_poisoned(closed[0])

    def test_standalone_failure_closes_its_allowance(self):
        """A failed compatibility probe closes its state and preserves the fixed error shape."""
        with self.processes("probe") as (events, closed):
            with self.assertRaisesRegex(OSError, "^pdf_raster_version_probe_failed$"):
                self.probe._tool_identity()
            self.assertEqual(events, [("probe", None)])
            self.assertEqual(len(closed), 1)
            self.assert_poisoned(closed[0])

    def test_standalone_identity_requires_its_probe_attempt(self):
        """A missing attempt cannot be replaced by a well-formed synthetic version banner."""
        reply = ("pdftoppm version " + self.probe.TOOL_VERSION + "\n").encode()
        with self.processes() as (events, closed), patch.object(self.probe, "_run_probe", return_value=reply):
            with self.assertRaisesRegex(OSError, "^pdf_raster_version_probe_failed$"):
                self.probe._tool_identity()
            self.assertEqual(events, [])
            self.assertEqual(len(closed), 1)

    def test_worker_failures_close_and_emit_no_success(self):
        """Probe failure, page timeout and a missing attempt cannot write any worker receipt."""
        pdf, identity = self.candidate((2, 3, 4, 5))
        for failure in ("probe", "page", "incomplete"):
            with self.subTest(failure=failure), \
                 tempfile.TemporaryDirectory(prefix="omnigenis-pdf-visual-supervisor-", dir="/tmp") as td, \
                 tempfile.TemporaryFile() as request, tempfile.TemporaryFile() as result, \
                 self.processes(failure) as (events, closed):
                header = " ".join(["1", *(str(identity[k]) for k in self.worker.IDENTITY_FIELDS)])
                request.write(header.encode() + b"\n" + pdf)
                request.flush()
                fd = os.open(td, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                real_page = self.worker._raster_page
                def page(tool, source, prefix, number, **kwargs):
                    """Inject one absent attempt; all other calls keep the real accounting path."""
                    if failure == "incomplete" and number == 5:
                        return self.png(prefix)
                    return real_page(tool, source, prefix, number, **kwargs)
                try:
                    with patch.dict(os.environ, {"TMPDIR": td}), \
                         patch.object(self.worker, "_limits", return_value={}), \
                         patch.object(self.worker, "_lifetime"), \
                         patch.object(self.worker, "enforce_pdf_landlock"), \
                         patch.object(self.worker, "enforce_pdf_network_filter"), \
                         patch.object(self.worker, "_raster_page", side_effect=page):
                        status = self.worker.main(["worker", str(request.fileno()), str(result.fileno()),
                                                   str(fd), str(os.getpid())])
                    self.assertEqual(status, 70)
                    self.assertEqual(os.fstat(result.fileno()).st_size, 0)
                    self.assertEqual(len(closed), 1)
                    self.assert_poisoned(closed[0])
                    self.assertEqual(list(Path(td).iterdir()), [])
                    expected_pages = [] if failure == "probe" else [2] if failure == "page" else [2, 3, 4]
                    self.assertEqual(events, [("probe", None)] + [("page", n) for n in expected_pages])
                finally:
                    os.close(fd)

    def test_manifest_pins_narrow_launch_accounting_sources(self):
        """Source-bound local attempt limits must not become aggregate execution qualification."""
        manifest = json.loads((ROOT / "reporting/pdf-raster-window-engine.v1.json").read_text())
        self.assertIn("native_launch_accounting", manifest, "runtime launch accounting is not declared")
        value = manifest["native_launch_accounting"]
        self.assertEqual(value["version_probe_attempts"], 1)
        self.assertEqual(value["maximum_selected_pages"], 4)
        self.assertEqual(value["retries"], 0)
        for key in ("refunds", "aggregate_job_resources_qualified", "cross_window_accounting",
                    "hostile_code_boundary", "authenticated_execution_evidence"):
            self.assertIs(value[key], False)
        for role in ("helper", "worker", "probe"):
            self.assertEqual(value[role + "_sha256"],
                             hashlib.sha256((ROOT / value[role + "_path"]).read_bytes()).hexdigest())
        self.assertFalse(manifest["guards"]["aggregate_job_resources_qualified"])
        self.assertFalse(manifest["default_pipeline_activated"])
        self.assertEqual(manifest["resource_budget"]["pdf_bytes"], 16 * 1024 * 1024)
        self.assertEqual(manifest["resource_budget"]["document_pages"], 512)

    def test_new_accounting_functions_and_classes_have_docstrings(self):
        """New state and tests document their exact local scope and failure behavior."""
        self.budget_class()
        for path in (ROOT / "reporting/_pdf_raster_launch_budget.py", Path(__file__)):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.assertTrue(ast.get_docstring(node), f"{path.name}:{node.name}")


if __name__ == "__main__":
    unittest.main()
