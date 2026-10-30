"""Independent native launch schedules exercised through concrete launchers."""
from contextlib import ExitStack
from hashlib import sha256
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from reporting import pdf_inspection_job as legacy
from reporting import pdf_object_graph as graph
from reporting import pdf_text_windows as text
from reporting import pdf_raster_windows as raster
from reporting import _pdf_native_launch_budget as budget
from reporting.page_windows import plan_pdf_page_windows

ROOT = Path(__file__).resolve().parents[1]
# This is a literal independently enumerated oracle, not the production schedule.
ROLES = (
    "structure_role_edges", "single_revision", "xref_entries", "xref_resolution",
    "trailer_catalog", "page_surface", "resource_leaves", "font_descriptor",
    "cid_widths", "tounicode_header", "tounicode_zlib", "tounicode_cmap_frame",
    "tounicode_utf16be_targets", "tounicode_bfchar_sources", "tounicode_width_coverage",
    "structure_tree", "document_content", "object_graph", "document_metadata",
    "page_tags", "mcid_coverage",
)


def launch_specs(plan):
    """Enumerate fixed roles then literal-width window ranges and exact headers."""
    common = f"1 {plan.pdf_sha256} {plan.ir_sha256} {plan.plan_sha256} {plan.page_count}"
    out = [("object_graph", role, (common + "\n").encode("ascii")) for role in ROLES]
    raster_plan = plan_pdf_page_windows(
        pdf_sha256=plan.pdf_sha256, ir_sha256=plan.ir_sha256,
        page_count=plan.page_count, admitted_page_budget=plan.page_count,
        pages_per_window=4, inspector_profile_id=legacy.RASTER_PROFILE)
    for kind, width, digest, role in (
        ("text_windows", 16, plan.plan_sha256, "text_window"),
        ("raster_windows", 4, raster_plan.plan_sha256, "raster_window"),
    ):
        for index, first in enumerate(range(1, plan.page_count + 1, width)):
            last = min(first + width - 1, plan.page_count)
            header = (f"1 {plan.pdf_sha256} {plan.ir_sha256} {digest} "
                      f"{plan.page_count} {index} {first} {last}\n").encode("ascii")
            out.append((kind, role, header))
    return tuple(out)


def launch_one(spec, pdf, *, child=None, swallow_spawn=False, alter=None):
    """Use real anonymous descriptors and real _start; replace external Popen only."""
    kind, role, header = spec
    module = {"object_graph": graph, "text_windows": text, "raster_windows": raster}[kind]
    with ExitStack() as stack:
        source = stack.enter_context(tempfile.TemporaryFile())
        result = stack.enter_context(tempfile.TemporaryFile())
        source.write(header + pdf)
        source.flush()
        fds = (source.fileno(), result.fileno())
        scratch = None
        if kind == "raster_windows":
            scratch = stack.enter_context(tempfile.TemporaryDirectory())
            scratch_fd = os.open(scratch, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            stack.callback(os.close, scratch_fd)
            fds += (scratch_fd,)
        command = [sys.executable, "-I", str(ROOT / "reporting" / f"_pdf_{role}_worker.py"),
                   *(str(fd) for fd in fds), str(os.getpid())]
        if alter:
            command, fds = alter(command, fds, source, result)
        before = source.tell()
        with patch.object(module.subprocess, "Popen", side_effect=child or fake_child):
            try:
                if scratch is None:
                    process = module._start(command, fds)
                else:
                    process = module._start(command, fds, scratch)
            except BaseException:
                if not swallow_spawn:
                    raise
                process = None
        if source.tell() != before:
            raise AssertionError("launcher admission moved the shared request offset")
        return process


def fake_child(*args, **kwargs):
    """Stand in only for external process creation; do not replace ledger hooks."""
    return object()


class PdfNativeLaunchBudgetTests(unittest.TestCase):
    """Real launcher admission with synthetic process boundaries, not execution proof."""

    def setUp(self):
        """Build a small declared PDF without invoking a parser or real process."""
        self.pdf = b"%PDF-1.7\nSYNTHETIC_BOUNDARY_ONLY\n"

    def plan(self, pages=64):
        """Use the existing admitted planner; expected roles/ranges stay independent."""
        return plan_pdf_page_windows(
            pdf_sha256=sha256(self.pdf).hexdigest(), ir_sha256="b" * 64,
            page_count=pages, admitted_page_budget=pages, pages_per_window=16,
            inspector_profile_id="generated-pdf-text-window-v1")

    def scope(self, plan):
        """Create only the production owner scope, never consume it from a fixture."""
        return budget.NativeLaunchScope(plan, len(self.pdf))

    def reject_at(self, index, *, alter=None, spec=None):
        """Prove wrong admission cannot cross Popen and poisons later completion/retry."""
        plan = self.plan()
        specs = launch_specs(plan)
        crossed = []

        def child(*args, **kwargs):
            """Observe the actual external boundary only if admission permits it."""
            crossed.append(args)
            return object()

        with self.scope(plan) as scope:
            for prior in specs[:index]:
                launch_one(prior, self.pdf)
            with self.assertRaises(ValueError):
                launch_one(spec or specs[index], self.pdf, alter=alter, child=child)
            self.assertEqual(crossed, [])
            with self.assertRaises(ValueError):
                scope.require_complete()
            with self.assertRaises(ValueError):
                launch_one(specs[index], self.pdf, child=child)
            self.assertEqual(crossed, [])

    def test_independent_one_33_64_schedules_and_composed_limits(self):
        """Every literal fixed role and range is admitted once, with hand-derived limits."""
        for pages, direct, reserved, ceiling in ((1, 23, 2, 25), (33, 33, 42, 75),
                                                 (64, 41, 80, 121)):
            plan = self.plan(pages)
            observed = []

            def child(command, **kwargs):
                """Record headers as they cross Popen, without claiming real processes."""
                header = os.pread(kwargs["pass_fds"][0], 256, 0).split(b"\n", 1)[0]
                observed.append((Path(command[2]).stem, header.decode("ascii").split()))
                return object()

            with self.subTest(pages=pages), self.scope(plan) as scope:
                for spec in launch_specs(plan):
                    launch_one(spec, self.pdf, child=child)
                scope.require_complete()
                self.assertEqual([name for name, fields in observed[:21]],
                                 ["_pdf_" + role + "_worker" for role in ROLES])
                text_ranges = [tuple(map(int, fields[5:])) for name, fields in observed
                               if name == "_pdf_text_window_worker"]
                raster_ranges = [tuple(map(int, fields[5:])) for name, fields in observed
                                 if name == "_pdf_raster_window_worker"]
                self.assertEqual(text_ranges, [(i, first, min(first + 15, pages))
                                 for i, first in enumerate(range(1, pages + 1, 16))])
                self.assertEqual(raster_ranges, [(i, first, min(first + 3, pages))
                                 for i, first in enumerate(range(1, pages + 1, 4))])
                child_reserve = sum(1 + last - first + 1 for i, first, last in raster_ranges)
                self.assertEqual((len(observed), child_reserve, len(observed) + child_reserve),
                                 (direct, reserved, ceiling))
                with self.assertRaises(ValueError):
                    launch_one(launch_specs(plan)[-1], self.pdf)
                with self.assertRaises(ValueError):
                    scope.require_complete()

    def test_every_fixed_role_and_window_cannot_be_omitted_or_reordered(self):
        """Skipping any of the 41 literal schedule entries refuses the very next launch."""
        specs = launch_specs(self.plan())
        for index in range(41):
            with self.subTest(index=index):
                self.reject_at(index, spec=specs[(index + 1) % 41])

    def test_every_prefix_is_incomplete_and_completion_poison_is_irreversible(self):
        """No prefix, including a receipt-only chain, grants final acceptance or resume."""
        plan = self.plan()
        specs = launch_specs(plan)
        for stop in range(41):
            with self.subTest(stop=stop), self.scope(plan) as scope:
                for spec in specs[:stop]:
                    launch_one(spec, self.pdf)
                with self.assertRaises(ValueError):
                    scope.require_complete()
                with self.assertRaises(ValueError):
                    launch_one(specs[stop], self.pdf)

    def test_wrong_interpreter_flags_worker_pid_and_canonical_fd_argv_reject(self):
        """Only exact resolved fixed argv reaches Popen; alternative spellings get no slot."""
        variants = ((0, "/usr/bin/not-the-interpreter"), (1, "-i"),
                    (2, str(ROOT / "reporting/_pdf_role_tokens_worker.py")),
                    (2, str(ROOT / "reporting/../reporting/_pdf_structure_role_edges_worker.py")),
                    (-1, str(os.getpid() + 1)), (3, "01"), (3, "+1"))
        for position, replacement in variants:
            def alter(command, fds, source, result):
                """Change one command component while preserving real request files."""
                command[position] = replacement
                return command, fds
            with self.subTest(position=position, replacement=replacement):
                self.reject_at(0, alter=alter)

    def test_wrong_launcher_kind_rejects_identical_worker_and_header(self):
        """A right script/header offered through a different concrete hook is rejected."""
        for index, kind in ((0, "text_windows"), (21, "object_graph"), (25, "text_windows")):
            old, role, header = launch_specs(self.plan())[index]
            with self.subTest(index=index):
                self.reject_at(index, spec=(kind, role, header))

    def test_fd_tuple_count_strict_integers_and_distinct_objects(self):
        """Booleans, lists, wrong counts and descriptor aliases cannot mint attempts."""
        for mode in ("bool", "list", "short", "extra", "duplicate", "negative", "same_inode"):
            def alter(command, fds, source, result):
                """Alter fd declarations without replacing the real launch hook."""
                if mode == "bool":
                    fds = (True, fds[1])
                elif mode == "list":
                    fds = list(fds)
                elif mode == "short":
                    fds = fds[:1]
                elif mode == "extra":
                    fds = fds + (9000,)
                elif mode == "duplicate":
                    fds = (fds[0], fds[0])
                elif mode == "negative":
                    fds = (-1, fds[1])
                else:
                    duplicate = os.dup(fds[0])
                    self.addCleanup(os.close, duplicate)
                    fds = (fds[0], duplicate)
                command[3:] = [*(str(fd) for fd in fds), str(os.getpid())]
                return command, fds
            with self.subTest(mode=mode):
                self.reject_at(0, alter=alter)

    def test_named_nonregular_nonowned_or_nonempty_result_files_reject(self):
        """Header contents alone cannot authorize linked, unowned or nonregular files."""
        with tempfile.NamedTemporaryFile() as named, tempfile.TemporaryDirectory() as directory:
            for mode in ("named", "directory", "foreign_uid", "result_nonempty"):
                def alter(command, fds, source, result):
                    """Keep content plausible while violating one required file property."""
                    if mode == "named":
                        named.seek(0)
                        named.write(launch_specs(self.plan())[0][2] + self.pdf)
                        named.flush()
                        fds = (named.fileno(), fds[1])
                    elif mode == "directory":
                        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                        self.addCleanup(os.close, fd)
                        fds = (fd, fds[1])
                    elif mode == "result_nonempty":
                        result.write(b"retained")
                        result.flush()
                    command[3:] = [*(str(fd) for fd in fds), str(os.getpid())]
                    return command, fds
                with self.subTest(mode=mode), ExitStack() as stack:
                    if mode == "foreign_uid":
                        stack.enter_context(patch.object(budget.os, "geteuid", return_value=os.getuid() + 1))
                    self.reject_at(0, alter=alter)

    def test_exact_protocol_pdf_ir_plan_page_and_window_headers(self):
        """Same-sized protocol/identity/range mutations cannot reuse any declared stage."""
        specs = launch_specs(self.plan())
        for index in (0, 21, 25):
            kind, role, header = specs[index]
            fields = header.decode("ascii").strip().split()
            for position in range(len(fields)):
                changed = list(fields)
                changed[position] = "e" * 64 if position in (1, 2, 3) else str(int(fields[position]) + 1)
                offered = (" ".join(changed) + "\n").encode("ascii")
                with self.subTest(index=index, position=position):
                    self.reject_at(index, spec=(kind, role, offered))
            with self.subTest(index=index, position="newline"):
                self.reject_at(index, spec=(kind, role, header[:-1] + b" "))

    def test_repeated_text_or_raster_window_cannot_expand_the_allowance(self):
        """Correct worker filenames do not permit duplicate window indices/ranges."""
        specs = launch_specs(self.plan())
        for index in (22, 26, 40):
            with self.subTest(index=index):
                self.reject_at(index, spec=specs[index - 1])

    def test_source_size_and_observable_descriptor_change_around_pread_reject(self):
        """Truncation, appended bytes and observable concurrent changes fail admission."""
        for mode in ("short", "long"):
            def alter(command, fds, source, result):
                """Change the bounded source size while keeping the exact header."""
                source.truncate(source.tell() - 1 if mode == "short" else source.tell() + 1)
                source.flush()
                return command, fds
            with self.subTest(mode=mode):
                self.reject_at(0, alter=alter)
        original = os.pread

        def mutate_after_read(fd, size, offset):
            """Introduce a visible mutation between the real read and second fstat."""
            data = original(fd, size, offset)
            os.ftruncate(fd, os.fstat(fd).st_size + 1)
            return data

        with patch.object(budget.os, "pread", side_effect=mutate_after_read):
            self.reject_at(0)

    def test_raster_scratch_fd_must_match_private_owned_directory(self):
        """A raster slot cannot pass a file, another directory or public scratch inode."""
        with tempfile.TemporaryDirectory() as other:
            for mode in ("file", "other", "mode"):
                def alter(command, fds, source, result):
                    """Violate one directory binding without altering raster protocol fields."""
                    if mode == "file":
                        fds = (*fds[:2], source.fileno())
                    elif mode == "other":
                        fd = os.open(other, os.O_PATH | os.O_DIRECTORY)
                        self.addCleanup(os.close, fd)
                        fds = (*fds[:2], fd)
                    else:
                        os.chmod(f"/proc/self/fd/{fds[2]}", 0o755)
                    command[3:] = [*(str(fd) for fd in fds), str(os.getpid())]
                    return command, fds
                with self.subTest(mode=mode):
                    self.reject_at(25, alter=alter)

    def test_failed_spawn_spends_and_poisons_each_concrete_launcher(self):
        """Spawn failure cannot retry, including a swallowed failure of the final slot."""
        class InterruptedSpawn(BaseException):
            """Exercise interrupt-like unwinding separately from ordinary OSError."""

        plan = self.plan(1)
        specs = launch_specs(plan)
        for index in (0, 21, 22):
            for failure in (OSError, InterruptedSpawn):
                crossed = []

                def fail(*args, **kwargs):
                    """Fail only after the real admission hook has consumed its slot."""
                    crossed.append(args)
                    raise failure()

                with self.subTest(index=index, failure=failure), self.scope(plan) as scope:
                    for spec in specs[:index]:
                        launch_one(spec, self.pdf)
                    launch_one(specs[index], self.pdf, child=fail, swallow_spawn=True)
                    self.assertEqual(len(crossed), 1)
                    with self.assertRaises(ValueError):
                        launch_one(specs[index], self.pdf, child=fail)
                    self.assertEqual(len(crossed), 1)
                    with self.assertRaises(ValueError):
                        scope.require_complete()

    def test_nonzero_timeout_and_malformed_results_still_fail_real_adapters(self):
        """Post-spawn error propagation stays in the existing adapters, not forged receipts."""
        plan = self.plan(1)
        specs = launch_specs(plan)
        raster_plan = plan_pdf_page_windows(
            pdf_sha256=plan.pdf_sha256, ir_sha256=plan.ir_sha256, page_count=1,
            admitted_page_budget=1, pages_per_window=4,
            inspector_profile_id="generated-pdf-raster-window-v1")
        for module, index, selected, function, error in (
            (graph, 17, plan, graph.inspect_pdf_object_graph, graph.PdfObjectGraphError),
            (text, 21, plan, text.inspect_pdf_text_window, text.PdfTextWindowError),
            (raster, 22, raster_plan, raster.inspect_pdf_raster_window, raster.PdfRasterWindowError),
        ):
            for mode in ("nonzero", "timeout", "malformed"):
                crossed = []

                def child(command, **kwargs):
                    """Provide malformed bytes only at the external child output boundary."""
                    crossed.append(command)
                    if mode == "malformed":
                        os.write(kwargs["pass_fds"][1], b"{")
                    return object()

                with self.subTest(module=module.__name__, mode=mode), self.scope(plan):
                    for spec in specs[:index]:
                        launch_one(spec, self.pdf)
                    options = dict(pdf_bytes=self.pdf, plan=selected,
                                   expected_plan_sha256=selected.plan_sha256)
                    if module is not graph:
                        options["window_index"] = 0
                    with patch.object(module.subprocess, "Popen", side_effect=child), \
                            patch.object(module, "_wait", return_value=1 if mode == "nonzero" else 0,
                                         side_effect=TimeoutError() if mode == "timeout" else None), \
                            self.assertRaises(error):
                        function(**options)
                    self.assertEqual(len(crossed), 1)

    def test_imported_shared_start_alias_stays_guarded(self):
        """An ancestry module's previously imported function cannot bypass admission."""
        from reporting.pdf_structure_role_edges import _start as ancestry_start
        plan = self.plan(1)
        crossed = []

        def child(*args, **kwargs):
            """Observe any unexpected external spawn through the imported alias."""
            crossed.append(args)
            return object()

        with self.scope(plan) as scope, patch.object(graph.subprocess, "Popen", side_effect=child):
            with self.assertRaises(ValueError):
                ancestry_start([sys.executable, "-I", "wrong.py"], ())
            with self.assertRaises(ValueError):
                scope.require_complete()
        self.assertEqual(crossed, [])

    def test_nested_activation_and_api_entry_poison_active_owner(self):
        """Caught nested activation or guard entry never forgives the outer scope."""
        plan = self.plan(1)
        for mode in ("activation", "entry"):
            with self.subTest(mode=mode), self.scope(plan) as scope:
                with self.assertRaises(ValueError):
                    if mode == "activation":
                        with self.scope(plan):
                            self.fail("nested activation admitted")
                    else:
                        budget.require_no_active_scope()
                with self.assertRaises(ValueError):
                    launch_one(launch_specs(plan)[0], self.pdf)
                with self.assertRaises(ValueError):
                    scope.require_complete()

    def test_foreign_thread_attempt_refuses_and_poisons_without_inherited_context(self):
        """The global slot detects another real thread and poisons owner completion."""
        plan = self.plan(1)
        errors = []
        crossed = []

        def child(*args, **kwargs):
            """Observe a forbidden foreign-thread Popen crossing if one occurs."""
            crossed.append(args)
            return object()

        def foreign():
            """Attempt a real launch from a thread with no shared context variable."""
            try:
                launch_one(launch_specs(plan)[0], self.pdf, child=child)
            except BaseException as error:
                errors.append(error)

        with self.scope(plan) as scope:
            thread = threading.Thread(target=foreign)
            thread.start()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive(), "foreign attempt blocked on the ledger lock")
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], ValueError)
            self.assertEqual(crossed, [])
            with self.assertRaises(ValueError):
                scope.require_complete()

    def test_foreign_pid_rejects_before_touching_an_inherited_lock(self):
        """Simulated fork state must refuse before an inherited locked mutex is touched."""
        plan = self.plan(1)

        class NeverEnter:
            """Make accidental lock acquisition an immediate error rather than a hang."""

            def __enter__(self):
                """Fail if foreign PID validation waits on an inherited mutex."""
                raise AssertionError("foreign PID touched inherited lock")

            def __exit__(self, *args):
                """Do not suppress any error from accidental acquisition."""
                return False

        with self.scope(plan) as scope:
            pid = os.getpid()
            with patch.object(budget.os, "getpid", return_value=pid + 1), \
                    patch.object(budget, "_LOCK", NeverEnter()):
                for operation in (budget.require_no_active_scope, scope.require_complete, scope.close):
                    with self.assertRaises(ValueError):
                        operation()
                with self.assertRaises(ValueError):
                    with budget.admit_launch("object_graph", [], ()):
                        self.fail("foreign PID launch admitted")
            with self.assertRaises(ValueError):
                scope.require_complete()

    def test_only_owner_can_close_and_stale_close_cannot_clear_new_job(self):
        """A foreign closer poisons but cannot clear; an old owner cannot clear a new slot."""
        plan = self.plan(1)
        errors = []

        def close_foreign(scope):
            """Catch the refusal from an exact other thread object."""
            try:
                scope.close()
            except BaseException as error:
                errors.append(error)

        with self.scope(plan) as first:
            thread = threading.Thread(target=close_foreign, args=(first,))
            thread.start()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(errors), 1)
            with self.assertRaises(ValueError):
                budget.require_no_active_scope()
        with self.scope(plan) as second:
            first.close()
            for spec in launch_specs(plan):
                launch_one(spec, self.pdf)
            second.require_complete()
        with self.assertRaises(ValueError):
            first.__enter__()

    def test_baseexception_cleanup_and_two_independent_jobs(self):
        """Interrupt-like unwinding clears ownership; later jobs get fresh finite schedules."""
        class InterruptedJob(BaseException):
            """Represent a non-Exception exit while a scope is active."""

        plan = self.plan(1)
        with self.assertRaises(InterruptedJob):
            with self.scope(plan):
                launch_one(launch_specs(plan)[0], self.pdf)
                raise InterruptedJob()
        budget.require_no_active_scope()
        for job in range(2):
            with self.subTest(job=job), self.scope(plan) as scope:
                for spec in launch_specs(plan):
                    launch_one(spec, self.pdf)
                scope.require_complete()

    def test_standalone_launcher_input_behavior_remains_unchanged(self):
        """With no job even arbitrary existing _start inputs pass unchanged to Popen."""
        for module in (graph, text, raster):
            crossed = []

            def child(command, **kwargs):
                """Observe unchanged standalone forwarding at the external boundary."""
                crossed.append((command, kwargs))
                return object()

            with self.subTest(module=module.__name__), \
                    patch.object(module.subprocess, "Popen", side_effect=child):
                if module is raster:
                    with tempfile.TemporaryDirectory() as scratch:
                        module._start(["legacy-arbitrary"], (), scratch)
                else:
                    module._start(["legacy-arbitrary"], ())
            self.assertEqual(crossed[0][0], ["legacy-arbitrary"])
            self.assertEqual(crossed[0][1]["pass_fds"], ())

    def test_policy_drives_real_schedule_width_and_launcher_bindings(self):
        """Policy roles/windows route through pinned launchers and earn exact admission."""
        manifest = json.loads((ROOT / "reporting/pdf-native-launch-budget.v1.json").read_text())
        policy = manifest["policy"]
        self.assertEqual(policy, budget.launch_budget_policy())
        plan = self.plan()
        specs = launch_specs(plan)
        policy_roles = list(policy["fixed_roles"])
        policy_roles += ["text_window"] * len(range(1, 65, policy["text_window_pages"]))
        policy_roles += ["raster_window"] * len(range(1, 65, policy["raster_window_pages"]))
        with self.scope(plan) as scope:
            for (kind, expected_role, header), role in zip(specs, policy_roles):
                path = policy["launchers"][kind]
                module = importlib.import_module(path[:-3].replace("/", "."))
                self.assertIs(module, {"object_graph": graph, "text_windows": text,
                                       "raster_windows": raster}[kind])
                launch_one((kind, role, header), self.pdf)
            scope.require_complete()
        self.assertEqual(policy["at_64_pages"], {
            "direct_attempts": 41, "reserved_raster_child_attempts": 80,
            "composed_attempt_ceiling": 121, "with_optional_fixed_supervisor": 122})
        for flag in ("aggregate_job_resources_qualified", "default_pipeline_activated", "release_authorized"):
            self.assertIs(policy[flag], False)
        required_sources = {
            "reporting/_pdf_native_launch_budget.py", "reporting/pdf_native_source_job.py",
            "reporting/pdf_object_graph.py", "reporting/pdf_text_windows.py",
            "reporting/pdf_raster_windows.py", "reporting/_pdf_raster_launch_budget.py",
            "reporting/_pdf_raster_probe.py", "reporting/_pdf_raster_window_worker.py"}
        self.assertEqual(set(manifest["source_sha256"]), required_sources)
        for path, digest in manifest["source_sha256"].items():
            self.assertEqual(sha256((ROOT / path).read_bytes()).hexdigest(), digest, path)
        coordinator = json.loads((ROOT / "reporting/pdf-native-source-job.v1.json").read_text())
        binding = coordinator["launch_attempt_budget_policy"]
        self.assertEqual(binding, {"path": "reporting/pdf-native-launch-budget.v1.json",
                         "policy_id": policy["policy_id"],
                         "sha256": sha256((ROOT / "reporting/pdf-native-launch-budget.v1.json").read_bytes()).hexdigest()})
