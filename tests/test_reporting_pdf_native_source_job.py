"""Exact-input composition of the existing native and structured PDF inspections."""
from __future__ import annotations

import ast
from contextlib import ExitStack, contextmanager
from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
from io import BytesIO
import importlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import zlib

from pypdf import PdfReader
from reporting import _pdf_tounicode_cmap_frame_worker as cmap_frame
from reporting import _pdf_native_launch_budget as launch_budget
from reporting import pdf_structured_source_job as structured
from reporting import pdf_tounicode_width_coverage as native
from reporting.page_windows import plan_pdf_page_windows
from reporting.pdf_content import _expected_content
from tests import test_reporting_pdf_source_inspection_job as source_tests
from tests import test_reporting_pdf_structured_source_job as structured_tests
from tests.test_reporting_pdf_native_launch_budget import launch_one, launch_specs


ROOT = Path(__file__).resolve().parents[1]
NATIVE = "inspect_pdf_tounicode_width_coverage"
STRUCTURED = "execute_pdf_structured_source_job"
DISABLES = (
    "OMNIGENIS_PDF_NATIVE_SOURCE_JOB_DISABLED",
    "OMNIGENIS_PDF_TOUNICODE_WIDTH_COVERAGE_DISABLED",
    "OMNIGENIS_PDF_STRUCTURE_ROLE_EDGES_DISABLED",
    "OMNIGENIS_PDF_STRUCTURED_SOURCE_JOB_DISABLED",
    "OMNIGENIS_PDF_SOURCE_INSPECTION_JOB_DISABLED",
    "OMNIGENIS_PDF_INSPECTION_JOB_DISABLED",
)


class PdfNativeSourceJobTests(unittest.TestCase):
    """Both existing chains must agree on one complete candidate and source job."""

    cases = None

    def setUp(self):
        """Assert the new boundary exists before generating or invoking native fixtures."""
        self.assertIsNotNone(
            importlib.util.find_spec("reporting.pdf_native_source_job"),
            "native source inspection composition is missing",
        )
        self.m = importlib.import_module("reporting.pdf_native_source_job")
        self.ir = {
            "report_id": "SYNTHETIC-NATIVE-SOURCE-JOB",
            "locale_id": "en-US",
            "components": [{
                "component_type": "semantic-section", "component_id": "summary",
                "title": "Synthetic summary", "state": "PRESENT",
                "content": {"value": 17},
            }],
        }
        self.pdf = b"%PDF-1.7\nSYNTHETIC_CONTROL_FLOW_ONLY\n"
        self.args = {
            "presentation_ir": self.ir, "pdf_bytes": self.pdf,
            "expected_pdf_sha256": sha256(self.pdf).hexdigest(),
            "expected_ir_sha256": _expected_content(self.ir)[0],
            "page_count": 33, "expected_language": "en-US",
            "namespace_id": "synthetic-namespace", "job_id": "synthetic-native-job",
            "request_sha256": "c" * 64,
            "expected_resource_profile_sha256": self.m.PROFILE_SHA256,
        }
        self.native_receipt = None
        self.stage_inputs = {}

    def run_job(self, **changes):
        """Invoke the public composition with independently specified source expectations."""
        return self.m.execute_pdf_native_source_job(**{**self.args, **changes})

    @classmethod
    def native_cases(cls):
        """Reuse the admitted renderer fixtures shared by both existing inspector families."""
        if cls.cases is None:
            cls.cases = {pages: source_tests.generated_job_case(pages)
                         for pages in (1, 33, 64)}
        return cls.cases

    def native_arguments(self, pages, ir=None, pdf=None):
        """Derive exact PDF and actual source digests without borrowing a synthetic test pin."""
        original_ir, original_pdf = self.native_cases()[pages]
        ir = original_ir if ir is None else ir
        pdf = original_pdf if pdf is None else pdf
        return {
            "presentation_ir": ir, "pdf_bytes": pdf, "page_count": pages,
            "expected_pdf_sha256": sha256(pdf).hexdigest(),
            "expected_ir_sha256": _expected_content(ir)[0],
        }

    def native_width_mismatch_pdf(self, pdf):
        """Change one bfchar source without rewriting the PDF or changing stream length."""
        reader = PdfReader(BytesIO(pdf), strict=True)
        page = reader.get_object(reader.pages[0].indirect_reference)
        resources = reader.get_object(page.raw_get("/Resources"))
        font_map = reader.get_object(resources.raw_get("/Font"))
        attempts = 0
        for reference in font_map.values():
            font = reader.get_object(reference)
            cmap = reader.get_object(font.raw_get("/ToUnicode"))
            compressed = cmap._data
            if pdf.count(compressed) != 1:
                continue
            decoded = zlib.decompress(compressed)
            self.assertTrue(decoded.startswith(cmap_frame._NATIVE_PREFIX))
            self.assertTrue(decoded.endswith(cmap_frame._NATIVE_SUFFIX))
            body = decoded[len(cmap_frame._NATIVE_PREFIX):-len(cmap_frame._NATIVE_SUFFIX)]
            rows = list(re.finditer(
                rb"(?m)^<([0-9a-fA-F]{4})> <(?:[0-9a-fA-F]{4}){1,16}>$", body
            ))
            self.assertTrue(rows, "fixture requires native bfchar records")
            sources = {int(row.group(1), 16) for row in rows}
            cid = reader.get_object(font.raw_get("/DescendantFonts")[0])
            widths = cid.raw_get("/W")
            explicit = {int(widths[index]) + offset
                        for index in range(0, len(widths), 2)
                        for offset in range(len(widths[index + 1]))}
            start, end = rows[0].span(1)
            for code in range(65535, -1, -1):
                if code in sources or code in explicit:
                    continue
                if attempts >= 4096:
                    self.fail("bounded fixture search found no equal-length native stream mutation")
                attempts += 1
                changed_body = body[:start] + f"{code:04X}".encode("ascii") + body[end:]
                changed = zlib.compress(cmap_frame._NATIVE_PREFIX + changed_body
                                        + cmap_frame._NATIVE_SUFFIX)
                if len(changed) != len(compressed):
                    continue
                self.assertNotIn(code, sources)
                self.assertNotIn(code, explicit)
                offset = pdf.index(compressed)
                candidate = pdf[:offset] + changed + pdf[offset + len(compressed):]
                self.assertEqual(len(candidate), len(pdf))
                self.assertNotEqual(candidate, pdf)
                self.assertEqual(candidate[:offset], pdf[:offset])
                self.assertEqual(candidate[offset + len(changed):], pdf[offset + len(compressed):])
                return candidate
        self.fail("fixture has no unique native ToUnicode stream for bounded mutation")

    @contextmanager
    def mocked(self, change=None, *, receipt_only=False, child=None, swallow_spawn=False):
        """Traverse real launchers, then synthesize unsigned child observations only."""
        calls = []
        helper = structured_tests.PdfStructuredSourceJobTests()
        helper.setUp()

        def native_stage(**values):
            """Produce typed unsigned control-flow data for the exact supplied text plan."""
            calls.append(NATIVE)
            self.stage_inputs[NATIVE] = values
            plan = values["plan"]
            if not receipt_only:
                for spec in launch_specs(plan)[:15]:
                    launch_one(spec, values["pdf_bytes"], child=child, swallow_spawn=swallow_spawn)
            identity = {key: getattr(plan, key) for key in
                        ("pdf_sha256", "ir_sha256", "plan_sha256", "page_count")}
            receipt = native.PdfToUnicodeWidthCoverage(
                **identity, tounicode_stream_count=3, cid_width_font_count=3,
                bfchar_source_count=50, bfchar_covered_source_count=50,
                explicit_cid_width_count=50, same_font_explicit_width_coverage_valid=True,
                prior_tounicode_bfchar_sources_sha256="a" * 64,
            )
            self.native_receipt = receipt
            return change(NATIVE, values, receipt) if change else receipt

        def structured_stage(**values):
            """Run the unchanged structured/source coordinators with typed mocked inspectors."""
            calls.append(STRUCTURED)
            self.stage_inputs[STRUCTURED] = values
            if not receipt_only:
                plan = self.stage_inputs[NATIVE]["plan"]
                for spec in launch_specs(plan)[15:]:
                    launch_one(spec, values["pdf_bytes"], child=child, swallow_spawn=swallow_spawn)
            receipt = structured.execute_pdf_structured_source_job(**values)
            return change(STRUCTURED, values, receipt) if change else receipt

        with helper.mocked(), \
             patch.object(self.m, NATIVE, side_effect=native_stage), \
             patch.object(self.m, STRUCTURED, side_effect=structured_stage):
            yield calls

    def test_exact_two_outer_stages_reuse_one_candidate_and_detached_source(self):
        """One, 33 and 64 pages use two outer stages without claiming two native processes."""
        for pages in (1, 33, 64):
            with self.subTest(pages=pages), self.mocked() as calls:
                result = self.run_job(page_count=pages)
            self.assertEqual(calls, [NATIVE, STRUCTURED])
            self.assertEqual(self.m.MAX_OUTER_STAGES, 2)
            native_input = self.stage_inputs[NATIVE]
            child_input = self.stage_inputs[STRUCTURED]
            self.assertEqual(native_input["pdf_bytes"], child_input["pdf_bytes"])
            self.assertEqual(native_input["expected_plan_sha256"],
                             native_input["plan"].plan_sha256)
            self.assertEqual(child_input["expected_resource_profile_sha256"],
                             structured.PROFILE_SHA256)
            self.assertIsNot(child_input["presentation_ir"], self.ir)
            self.assertIsNot(child_input["presentation_ir"]["components"], self.ir["components"])
            self.assertEqual(child_input["presentation_ir"], self.ir)
            self.assertEqual(result.to_dict()["page_count"], pages)

    def test_receipt_only_chain_cannot_return_native_success_without_launches(self):
        """Missing cumulative completion must reject otherwise valid unsigned receipts."""
        # Keep this fixture deliberately receipt-only: it exercises the public
        # coordinator's acceptance check, not a replacement budget helper.
        with self.mocked(receipt_only=True), self.assertRaises(self.m.PdfNativeSourceJobError):
            self.run_job()

    def test_invalid_nested_api_entry_poisons_outer_job_even_when_caught(self):
        """Entry ownership is checked before even invalid nested input admission."""
        def nested(stage, values, receipt):
            """Catch a deliberately invalid nested request without forgiving the outer job."""
            if stage == NATIVE:
                with self.assertRaises(self.m.PdfNativeSourceJobError):
                    self.run_job(pdf_bytes=None)
            return receipt

        with self.mocked(nested), self.assertRaises(self.m.PdfNativeSourceJobError):
            self.run_job(page_count=1)

    def test_swallowed_last_spawn_baseexception_cannot_complete_job(self):
        """Even the last consumed slot is poisoned when its Popen never returns."""
        class SpawnInterrupt(BaseException):
            """Represent interrupt-like failure at the external creation boundary."""

        attempts = []

        def fail_last(command, **kwargs):
            """Fail precisely the one-page schedule's final raster launch."""
            attempts.append(command)
            if len(attempts) == 23:
                raise SpawnInterrupt()
            return object()

        with self.mocked(child=fail_last, swallow_spawn=True), \
                self.assertRaises(self.m.PdfNativeSourceJobError):
            self.run_job(page_count=1)
        self.assertEqual(len(attempts), 23)

    def test_interrupt_like_stage_exit_clears_scope_before_unrelated_job(self):
        """Both coordinator stages unwind BaseException without leaking later job state."""
        class InterruptedJob(BaseException):
            """Represent an interrupt rather than an ordinary adapter failure."""

        for interrupted_stage in (NATIVE, STRUCTURED):
            def interrupt(stage, values, receipt):
                """Interrupt after actual synthetic launch traversal at the selected stage."""
                if stage == interrupted_stage:
                    raise InterruptedJob()
                return receipt
            with self.subTest(stage=interrupted_stage):
                with self.mocked(interrupt), self.assertRaises(InterruptedJob):
                    self.run_job(page_count=1)
                with self.mocked():
                    result = self.run_job(page_count=1)
                self.assertEqual(result.page_count, 1)

    def test_missing_launch_in_each_schedule_region_never_returns_a_result(self):
        """Unsigned positive child receipts cannot conceal omissions in any graph region."""
        real_launch = launch_one
        for missing in (0, 14, 15, 20, 21, 22):
            attempted = [0]

            def omit(spec, pdf, **kwargs):
                """Skip one actual boundary, keeping every unsigned child receipt unchanged."""
                index = attempted[0]
                attempted[0] += 1
                if index != missing:
                    return real_launch(spec, pdf, **kwargs)
                return None

            with self.subTest(missing=missing), self.mocked(), \
                    patch(__name__ + ".launch_one", side_effect=omit), \
                    self.assertRaises(self.m.PdfNativeSourceJobError):
                self.run_job(page_count=1)

    def test_scope_remains_active_through_final_clock_acceptance(self):
        """Nested entry during the last acceptance check still poisons final return."""
        calls = [0]

        def final_clock():
            """Try a caught invalid nested request at the fifth and final clock check."""
            calls[0] += 1
            if calls[0] == 5:
                with self.assertRaises(self.m.PdfNativeSourceJobError):
                    self.run_job(pdf_bytes=None)
            return 0

        with self.mocked(), patch.object(self.m, "monotonic_ns", side_effect=final_clock), \
                patch.object(launch_budget, "monotonic_ns", return_value=0), \
                self.assertRaises(self.m.PdfNativeSourceJobError):
            self.run_job(page_count=1)
        self.assertEqual(calls[0], 5)

    def terminal_foreign_attempt(self, timing):
        """Pause owner lifecycle only; keep original completion, cleanup and guards real."""
        ready = threading.Event()
        finished = threading.Event()
        unexpected = []
        spawned = []
        foreign_rejected = []
        owner_result = None
        owner_rejected = False
        clock_calls = [0]
        original_close = launch_budget.NativeLaunchScope.close

        def child(*args, **kwargs):
            """Observe only the foreign attempt actually crossing the Popen boundary."""
            spawned.append(args)
            return object()

        def foreign():
            """Attempt the real shared launcher from a real thread at the selected barrier."""
            try:
                if not ready.wait(timeout=5):
                    raise AssertionError("owner never reached terminal barrier")
                plan = self.stage_inputs[NATIVE]["plan"]
                try:
                    launch_one(launch_specs(plan)[0], self.pdf, child=child)
                except ValueError:
                    foreign_rejected.append(True)
            except BaseException as error:
                unexpected.append(error)
            finally:
                finished.set()

        def wait_for_foreign():
            """Let the foreign guard finish before the paused owner transition resumes."""
            ready.set()
            if not finished.wait(timeout=5):
                unexpected.append(AssertionError("foreign guard did not finish at terminal barrier"))

        def coordinated_close(scope):
            """Wrap timing around, but never replace, the original unconditional cleanup."""
            if timing == "before_cleanup":
                try:
                    wait_for_foreign()
                finally:
                    original_close(scope)
            else:
                original_close(scope)
                wait_for_foreign()

        def coordinated_clock():
            """Pause the last source/result/clock acceptance check before terminal acceptance."""
            clock_calls[0] += 1
            if clock_calls[0] == 5:
                wait_for_foreign()
            return 0

        with self.mocked():
            with ExitStack() as stack:
                if timing == "before_terminal":
                    stack.enter_context(patch.object(self.m, "monotonic_ns", side_effect=coordinated_clock))
                    stack.enter_context(patch.object(launch_budget, "monotonic_ns", return_value=0))
                else:
                    stack.enter_context(patch.object(launch_budget.NativeLaunchScope, "close",
                                                    new=coordinated_close))
                thread = threading.Thread(target=foreign, daemon=True)
                thread.start()
                try:
                    try:
                        owner_result = self.run_job(page_count=1)
                    except self.m.PdfNativeSourceJobError:
                        owner_rejected = True
                finally:
                    ready.set()
                    thread.join(timeout=5)
                self.assertFalse(thread.is_alive(), "foreign thread remained blocked")
        self.assertEqual(unexpected, [])
        self.assertEqual(len(foreign_rejected), int(not spawned))
        self.assertLessEqual(len(spawned), 1)
        launch_budget.require_no_active_scope()
        with self.mocked():
            subsequent = self.run_job(page_count=1)
        self.assertEqual(subsequent.page_count, 1)
        if owner_result is not None:
            self.assertEqual(owner_result.page_count, 1)
        self.assertEqual(owner_result is None, owner_rejected)
        if timing == "before_terminal":
            self.assertEqual(clock_calls[0], 5)
        return owner_rejected, bool(foreign_rejected), len(spawned)

    def test_terminal_foreign_refusal_cannot_coexist_with_owner_success(self):
        """A refused active-scope attempt after final validation must defeat owner success."""
        owner_rejected, foreign_rejected, spawned = self.terminal_foreign_attempt("before_cleanup")
        # This invariant deliberately allows the other legitimate linearization:
        # atomic acceptance already deactivated the job, so the foreign call is
        # standalone and both calls succeed. It must never be refused as active
        # while the owner nevertheless returns success.
        self.assertEqual(owner_rejected, foreign_rejected,
                         "foreign guard refused/poisoned an active job but owner returned success")
        self.assertEqual(spawned, 0 if foreign_rejected else 1)

    def test_foreign_attempt_before_terminal_acceptance_refuses_and_rejects_owner(self):
        """A real foreign call during the final check poisons before any acceptance point."""
        self.assertEqual(self.terminal_foreign_attempt("before_terminal"), (True, True, 0))

    def test_foreign_attempt_after_owner_cleanup_is_legitimately_standalone(self):
        """After real owner deactivation the unchanged standalone launcher may spawn."""
        self.assertEqual(self.terminal_foreign_attempt("after_cleanup"), (False, False, 1))

    def test_unexpected_actual_launcher_is_refused_before_popen(self):
        """An out-of-order shared launcher must not spawn during the native job."""
        from reporting import pdf_object_graph as graph

        attempted = []

        def child_boundary(*args, **kwargs):
            """Observe only actual attempts to cross the external child boundary."""
            attempted.append((args, kwargs))
            return object()

        def inject(stage, values, receipt):
            """Offer a valid request to the wrong first worker through the real launcher."""
            if stage == NATIVE:
                plan = values["plan"]
                header = (f"1 {plan.pdf_sha256} {plan.ir_sha256} "
                          f"{plan.plan_sha256} {plan.page_count}\n").encode("ascii")
                with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as result:
                    source.write(header + values["pdf_bytes"])
                    source.flush()
                    fds = source.fileno(), result.fileno()
                    command = [sys.executable, "-I",
                               str(ROOT / "reporting" / "_pdf_object_graph_worker.py"),
                               *(str(fd) for fd in fds), str(os.getpid())]
                    # A stage may swallow a rejected launch, but it must not
                    # recover the poisoned job or manufacture a successful result.
                    try:
                        graph._start(command, fds)
                    except ValueError:
                        pass
            return receipt

        rejected = False
        with self.mocked(inject), patch.object(graph.subprocess, "Popen", side_effect=child_boundary):
            try:
                self.run_job()
            except self.m.PdfNativeSourceJobError:
                rejected = True
        self.assertEqual(attempted, [], "unexpected native worker reached the real Popen boundary")
        self.assertTrue(rejected, "swallowed launch rejection must poison final job acceptance")

    def test_real_native_one_33_64_pages_without_parent_pdf_parsing(self):
        """Execute both real chains on identical final bytes with complete page coverage."""
        for pages, (ir, pdf) in self.native_cases().items():
            with self.subTest(pages=pages):
                before = json.dumps(ir, sort_keys=True)
                arguments = self.native_arguments(pages, ir=ir, pdf=pdf)
                with patch("pypdf.PdfReader", side_effect=AssertionError("parent parser forbidden")):
                    result = self.run_job(**arguments)
                data = result.to_dict()
                native_record = data["native_inspection"]
                child = data["structured_inspection"]
                bundle = child["source_inspection"]["inspection_set"]["page_bundle"]
                self.assertEqual(native_record["pdf_sha256"], sha256(pdf).hexdigest())
                self.assertEqual(native_record["ir_sha256"], _expected_content(ir)[0])
                self.assertEqual(native_record["plan_sha256"], data["plan_sha256"])
                self.assertEqual(child["structure_tree"]["plan_sha256"], data["plan_sha256"])
                self.assertEqual(bundle["text_stream"]["represented_pages"], pages)
                self.assertEqual(bundle["raster_stream"]["represented_pages"], pages)
                self.assertEqual(bundle["text_stream"]["plan_sha256"], data["plan_sha256"])
                self.assertTrue(data["shared_input_bindings_verified"])
                self.assertTrue(data["normalized_text_equivalence_verified"])
                self.assertTrue(data["forward_reverse_linkage_verified"])
                self.assertFalse(data["release_authorized"])
                self.assertEqual(json.dumps(ir, sort_keys=True), before)

    def test_real_invalid_native_width_relation_stops_before_structured_job(self):
        """A serialized width violation passes its real ancestor but not the composed job."""
        ir, original = self.native_cases()[1]
        pdf = self.native_width_mismatch_pdf(original)
        arguments = self.native_arguments(1, ir=ir, pdf=pdf)
        plan = plan_pdf_page_windows(
            pdf_sha256=arguments["expected_pdf_sha256"],
            ir_sha256=arguments["expected_ir_sha256"],
            page_count=1, admitted_page_budget=1,
            pages_per_window=structured.source.legacy.TEXT_WIDTH,
            inspector_profile_id=structured.source.legacy.TEXT_PROFILE,
        )
        prior = native.previous.inspect_pdf_tounicode_bfchar_sources(
            pdf_bytes=pdf, plan=plan, expected_plan_sha256=plan.plan_sha256,
            expected_language="en-US",
        )
        self.assertEqual(prior.pdf_sha256, arguments["expected_pdf_sha256"])
        self.assertEqual(prior.plan_sha256, plan.plan_sha256)
        with patch.object(self.m, NATIVE, wraps=native.inspect_pdf_tounicode_width_coverage) as first, \
             patch.object(self.m, STRUCTURED) as later:
            with self.assertRaisesRegex(self.m.PdfNativeSourceJobError,
                                        "pdf_native_source_job_execution_failed"):
                self.run_job(**arguments)
            first.assert_called_once()
            later.assert_not_called()

    def test_real_source_mismatch_is_not_excused_by_native_profile_success(self):
        """A passing native structural chain cannot replace comparison with the captured source."""
        original_ir, pdf = self.native_cases()[1]
        ir = json.loads(json.dumps(original_ir))
        ir["components"][0]["content"]["value"] = 999
        with patch.object(self.m, NATIVE, wraps=native.inspect_pdf_tounicode_width_coverage) as first, \
             patch.object(self.m, STRUCTURED, wraps=structured.execute_pdf_structured_source_job) as second:
            with self.assertRaises(self.m.PdfNativeSourceJobError):
                self.run_job(**self.native_arguments(1, ir=ir, pdf=pdf))
            first.assert_called_once()
            second.assert_called_once()

    def test_invalid_admission_prevents_both_stages(self):
        """Foreign identities, malformed context and unsupported inputs never start work."""
        variants = [
            {"pdf_bytes": bytearray(self.pdf)}, {"pdf_bytes": b"bad"},
            {"page_count": True}, {"page_count": 0}, {"page_count": 65},
            {"expected_pdf_sha256": "f" * 64}, {"expected_ir_sha256": "f" * 64},
            {"expected_language": "pt-BR"}, {"namespace_id": None}, {"job_id": ""},
            {"request_sha256": "unknown"},
            {"expected_resource_profile_sha256": structured.PROFILE_SHA256},
        ]
        for changed in variants:
            with self.subTest(changed=sorted(changed)), self.mocked() as calls:
                with self.assertRaises(self.m.PdfNativeSourceJobError):
                    self.run_job(**changed)
                self.assertEqual(calls, [])

    def test_source_and_pdf_admission_remains_bounded(self):
        """Cyclic, foreign-object and oversized inputs do not invoke either child."""
        cycle = {}
        cycle["cycle"] = cycle
        variants = [{"presentation_ir": value} for value in
                    (cycle, None, {"components": [object()]}, {"large": "x" * 8388609})]
        variants.append({"pdf_bytes": b"%PDF-1.7" + b"x" * 8388608})
        for changed in variants:
            with self.mocked() as calls:
                with self.assertRaises(self.m.PdfNativeSourceJobError):
                    self.run_job(**changed)
                self.assertEqual(calls, [])

    def test_each_stage_failure_is_content_free_and_never_retried(self):
        """Failure of either required chain returns no partial combined success."""
        for failed in (NATIVE, STRUCTURED):
            def fail(stage, values, receipt):
                """Inject one selected child failure without exposing its private text."""
                if stage == failed:
                    raise RuntimeError("SYNTHETIC_PRIVATE_ERROR")
                return receipt
            with self.subTest(stage=failed), self.mocked(fail) as calls:
                with self.assertRaises(self.m.PdfNativeSourceJobError) as caught:
                    self.run_job()
                self.assertEqual(calls, [NATIVE] if failed == NATIVE else [NATIVE, STRUCTURED])
                self.assertEqual(str(caught.exception), "pdf_native_source_job_execution_failed")
                self.assertNotIn("SYNTHETIC_PRIVATE_ERROR", str(caught.exception))

    def test_foreign_native_receipts_stop_before_structured_work(self):
        """Validly sealed receipts still need the exact admitted PDF, source, plan and pages."""
        changes = [None, {"pdf_sha256": "f" * 64}, {"ir_sha256": "f" * 64},
                   {"plan_sha256": "f" * 64}, {"page_count": 2}]
        for changed in changes:
            def foreign(stage, values, receipt):
                """Return a generic success or a structurally valid foreign native receipt."""
                if stage != NATIVE:
                    return receipt
                return {"status": "PASS"} if changed is None else replace(receipt, **changed)
            with self.subTest(changed=changed), self.mocked(foreign) as calls:
                with self.assertRaises(self.m.PdfNativeSourceJobError):
                    self.run_job()
                self.assertEqual(calls, [NATIVE])

    def test_foreign_structured_results_cannot_bind(self):
        """A complete internally consistent child for another candidate or job is rejected."""
        for field in ("pdf", "ir", "page_count", "namespace_id", "job_id", "request_sha256"):
            def foreign(stage, values, receipt):
                """Execute the mocked real child under one changed, internally valid expectation."""
                if stage != STRUCTURED:
                    return receipt
                alternate = dict(values)
                if field == "pdf":
                    alternate["pdf_bytes"] += b"FOREIGN_CANDIDATE"
                    alternate["expected_pdf_sha256"] = sha256(alternate["pdf_bytes"]).hexdigest()
                elif field == "ir":
                    alternate["presentation_ir"] = json.loads(json.dumps(values["presentation_ir"]))
                    alternate["presentation_ir"]["components"][0]["content"]["value"] = 19
                    alternate["expected_ir_sha256"] = _expected_content(alternate["presentation_ir"])[0]
                elif field == "page_count":
                    alternate[field] = 2
                else:
                    alternate[field] = "e" * 64 if field == "request_sha256" else "foreign-context"
                return structured.execute_pdf_structured_source_job(**alternate)
            with self.subTest(field=field), self.mocked(foreign):
                with self.assertRaises(self.m.PdfNativeSourceJobError):
                    self.run_job()

    def test_generic_structured_success_is_not_a_typed_result(self):
        """A success dictionary cannot replace the complete sealed structured child."""
        def generic(stage, values, receipt):
            """Replace only the last required result with an untyped status."""
            return {"status": "PASS"} if stage == STRUCTURED else receipt
        with self.mocked(generic):
            with self.assertRaises(self.m.PdfNativeSourceJobError):
                self.run_job()

    def test_native_digest_is_captured_before_second_stage_even_if_resealed(self):
        """Later code cannot replace the first result's accepted checksum with a new valid seal."""
        for reseal in (False, True):
            def mutate(stage, values, receipt):
                """Alter a still-valid native count while the second stage is completing."""
                if stage == STRUCTURED:
                    original = self.native_receipt
                    object.__setattr__(original, "explicit_cid_width_count",
                                       original.explicit_cid_width_count + 1)
                    if reseal:
                        object.__delattr__(original, "_sealed_sha256")
                        original.__post_init__()
                return receipt
            with self.subTest(reseal=reseal), self.mocked(mutate):
                with self.assertRaises(self.m.PdfNativeSourceJobError):
                    self.run_job()

    def test_plan_is_revalidated_and_original_digest_retained_after_native_stage(self):
        """A changed or validly resealed plan cannot launch the second stage."""
        for reseal in (False, True):
            def mutate(stage, values, receipt):
                """Change the window width, optionally constructing a different valid plan identity."""
                if stage != NATIVE:
                    return receipt
                plan = values["plan"]
                if not reseal:
                    object.__setattr__(plan, "pages_per_window", 8)
                    return receipt
                alternate = plan_pdf_page_windows(
                    pdf_sha256=plan.pdf_sha256, ir_sha256=plan.ir_sha256,
                    page_count=plan.page_count, admitted_page_budget=plan.page_count,
                    pages_per_window=8, inspector_profile_id=plan.inspector_profile_id,
                )
                object.__setattr__(plan, "pages_per_window", alternate.pages_per_window)
                object.__setattr__(plan, "windows", alternate.windows)
                object.__delattr__(plan, "_plan_sha256")
                plan.__post_init__()
                return replace(receipt, plan_sha256=plan.plan_sha256)
            with self.subTest(reseal=reseal), self.mocked(mutate) as calls:
                with self.assertRaises(self.m.PdfNativeSourceJobError):
                    self.run_job()
                self.assertEqual(calls, [NATIVE])

    def test_original_source_mutation_during_native_stage_prevents_second_stage(self):
        """A persistent caller-source change cannot be hidden by the detached child snapshot."""
        def mutate(stage, values, receipt):
            """Change the original caller object after producing the first receipt."""
            if stage == NATIVE:
                self.ir["components"][0]["content"]["value"] = 18
            return receipt
        with self.mocked(mutate) as calls:
            with self.assertRaises(self.m.PdfNativeSourceJobError):
                self.run_job()
            self.assertEqual(calls, [NATIVE])

    def test_detached_source_mutation_during_structured_stage_prevents_return(self):
        """The child may not alter the captured source and still receive final acceptance."""
        def mutate(stage, values, receipt):
            """Modify only the detached source after the mocked structured child finishes."""
            if stage == STRUCTURED:
                values["presentation_ir"]["report_id"] = "CHANGED-CAPTURED-SOURCE"
            return receipt
        original = json.dumps(self.ir, sort_keys=True)
        with self.mocked(mutate):
            with self.assertRaises(self.m.PdfNativeSourceJobError):
                self.run_job()
        self.assertEqual(json.dumps(self.ir, sort_keys=True), original)

    def test_original_source_mutation_during_final_stage_prevents_return(self):
        """A final valid child cannot excuse a persistent mutation outside its snapshot."""
        def mutate(stage, values, receipt):
            """Change the original source while leaving the child receipt valid."""
            if stage == STRUCTURED:
                self.ir["report_id"] = "CHANGED-ORIGINAL-SOURCE"
            return receipt
        with self.mocked(mutate):
            with self.assertRaises(self.m.PdfNativeSourceJobError):
                self.run_job()

    def test_prerequisite_disables_prevent_admission(self):
        """Outer, ancestor and existing child disable switches apply before any work."""
        for flag in DISABLES:
            with self.subTest(flag=flag), self.mocked() as calls, patch.dict(os.environ, {flag: "1"}):
                with self.assertRaises(self.m.PdfNativeSourceJobError):
                    self.run_job()
                self.assertEqual(calls, [])

    def test_disabling_after_first_stage_prevents_later_work(self):
        """Already completed native work does not authorize a now-disabled composition."""
        for flag in (DISABLES[0], DISABLES[1], DISABLES[3]):
            def disable(stage, values, receipt):
                """Disable the selected prerequisite as the first stage returns."""
                if stage == NATIVE:
                    os.environ[flag] = "1"
                return receipt
            with self.subTest(flag=flag), patch.dict(os.environ), self.mocked(disable) as calls:
                with self.assertRaises(self.m.PdfNativeSourceJobError):
                    self.run_job()
                self.assertEqual(calls, [NATIVE])

    def test_disabling_completed_native_stage_prevents_final_acceptance(self):
        """The native prerequisite remains binding after the structured child completes."""
        def disable(stage, values, receipt):
            """Disable the previously completed native stage during the second stage."""
            if stage == STRUCTURED:
                os.environ[DISABLES[1]] = "1"
            return receipt
        with patch.dict(os.environ), self.mocked(disable):
            with self.assertRaises(self.m.PdfNativeSourceJobError):
                self.run_job()

    def test_late_stage_results_fail_acceptance_without_claiming_preemption(self):
        """The outer deadline covers both synchronous stages and final acceptance."""
        for late_stage in (NATIVE, STRUCTURED):
            clock = [0]
            def expire(stage, values, receipt):
                """Move only the outer deterministic clock to its exact deadline."""
                if stage == late_stage:
                    clock[0] = self.m.ACCEPTANCE_NS
                return receipt
            with self.subTest(stage=late_stage), self.mocked(expire) as calls, \
                 patch.object(self.m, "monotonic_ns", side_effect=lambda: clock[0]), \
                 patch.object(launch_budget, "monotonic_ns", return_value=0):
                with self.assertRaises(self.m.PdfNativeSourceJobError):
                    self.run_job()
                self.assertEqual(calls, [NATIVE] if late_stage == NATIVE else [NATIVE, STRUCTURED])

    def test_launch_scope_uses_original_coordinator_start(self):
        """Scope construction cannot restart time already spent after job admission."""
        with self.mocked() as calls, patch.object(self.m, "monotonic_ns", return_value=0), \
                patch.object(launch_budget, "monotonic_ns", return_value=300_000_000_000):
            with self.assertRaises(self.m.PdfNativeSourceJobError):
                self.run_job(page_count=1)
        self.assertEqual(calls, [])

    def test_invalid_or_regressing_clock_prevents_work(self):
        """Boolean, negative and regressing admission clocks fail before the first stage."""
        for sequence in ([True], [-1], [10, 9]):
            with self.subTest(sequence=sequence), self.mocked() as calls, \
                 patch.object(self.m, "monotonic_ns", side_effect=sequence), \
                 patch.object(launch_budget, "monotonic_ns", return_value=10):
                with self.assertRaises(self.m.PdfNativeSourceJobError):
                    self.run_job()
                self.assertEqual(calls, [])

    def test_outer_and_child_profile_drift_prevents_admission(self):
        """Changed limits or child identities cannot retain the original admission authority."""
        variants = [(self.m, "MAX_PAGES", 65), (self.m, "MAX_OUTER_STAGES", 3),
                    (native, "PROFILE_SHA256", "f" * 64),
                    (structured, "PROFILE_SHA256", "f" * 64)]
        for module, field, value in variants:
            with self.subTest(module=module.__name__, field=field), self.mocked() as calls, \
                 patch.object(module, field, value):
                with self.assertRaises(self.m.PdfNativeSourceJobError):
                    self.run_job()
                self.assertEqual(calls, [])

    def test_public_api_has_only_the_existing_ten_primitive_parameters(self):
        """The caller cannot inject receipts, workers, retries, plans or resume state."""
        self.assertEqual(set(inspect.signature(self.m.execute_pdf_native_source_job).parameters),
                         set(self.args))
        self.assertEqual(len(self.args), 10)

    def test_result_is_frozen_detached_bounded_and_content_free(self):
        """Only sealed metadata and digests escape the composition."""
        with self.mocked():
            result = self.run_job()
        raw = result.to_bytes()
        self.assertEqual(result.inspection_sha256, sha256(raw).hexdigest())
        self.assertEqual(self.m.MAX_RESULT_BYTES, 304 * 1024)
        self.assertLessEqual(len(raw), self.m.MAX_RESULT_BYTES)
        self.assertNotIn(b"SYNTHETIC-NATIVE-SOURCE-JOB", raw)
        self.assertNotIn(b"SYNTHETIC_CONTROL_FLOW_ONLY", raw)
        self.assertNotIn(b"begincmap", raw)
        with self.assertRaises(FrozenInstanceError):
            result.page_count = 2
        detached = result.to_dict()
        detached["native_inspection"]["explicit_cid_width_count"] = 1
        self.assertEqual(result.to_bytes(), raw)

    def test_nested_replacement_and_repinning_cannot_reseal_final_result(self):
        """A different valid child and matching replacement pin still break the original seal."""
        with self.mocked():
            result = self.run_job()
        original = result.native_inspection
        alternate = replace(original, explicit_cid_width_count=original.explicit_cid_width_count + 1)
        object.__setattr__(result, "native_inspection", alternate)
        object.__setattr__(result, "expected_native_sha256", alternate.inspection_sha256)
        with self.assertRaises(self.m.PdfNativeSourceJobError):
            result.to_bytes()
        with self.assertRaises(self.m.PdfNativeSourceJobError):
            result.__post_init__()

    def test_direct_result_construction_requires_exact_child_and_context_bindings(self):
        """Independent pins and document/job fields remain mandatory for unsigned metadata."""
        with self.mocked():
            result = self.run_job()
        variants = [
            {"native_inspection": None}, {"structured_inspection": None},
            {"expected_native_sha256": "f" * 64}, {"expected_structured_sha256": "f" * 64},
            {"expected_text_sha256": "f" * 64}, {"pdf_sha256": "f" * 64},
            {"ir_sha256": "f" * 64}, {"plan_sha256": "f" * 64}, {"page_count": True},
            {"namespace_id": "foreign"}, {"job_id": "foreign"}, {"request_sha256": "e" * 64},
            {"resource_profile_sha256": structured.PROFILE_SHA256},
        ]
        for changed in variants:
            with self.subTest(changed=sorted(changed)):
                with self.assertRaises(self.m.PdfNativeSourceJobError):
                    replace(result, **changed)

    def test_child_profiles_and_qualification_limits_remain_distinct(self):
        """Shared bindings preserve every inherited limitation and distinct resource identity."""
        with self.mocked():
            data = self.run_job().to_dict()
        self.assertEqual(data["resource_profile_sha256"], self.m.PROFILE_SHA256)
        self.assertEqual(data["native_inspection"]["profile_sha256"], native.PROFILE_SHA256)
        child = data["structured_inspection"]
        self.assertEqual(child["resource_profile_sha256"], structured.PROFILE_SHA256)
        self.assertEqual(len({self.m.PROFILE_SHA256, native.PROFILE_SHA256, structured.PROFILE_SHA256}), 3)
        self.assertEqual(data["inspection_dimensions"][:-1], child["inspection_dimensions"])
        self.assertNotIn(data["inspection_dimensions"][-1], child["inspection_dimensions"])
        self.assertTrue(data["shared_input_bindings_verified"])
        self.assertTrue(data["normalized_text_equivalence_verified"])
        self.assertTrue(data["forward_reverse_linkage_verified"])
        unqualified = set(native._nonclaims()) | {
            "scientific_equivalence_verified", "semantic_roles_qualified", "visible_glyphs_verified",
            "full_accessibility_qualified", "finding_completeness_verified",
        }
        for name in sorted(unqualified):
            self.assertIs(data[name], False, name)
        self.assertEqual(data["release_authorization"], "NOT_ESTABLISHED")

    def test_manifest_pins_unchanged_sources_defaults_and_documented_functions(self):
        """The additive manifest preserves existing contracts and records the two-stage limit."""
        from reporting._pdf_safety_worker import MAX_PAGES
        manifest = json.loads((ROOT / "reporting/pdf-native-source-job.v1.json").read_text())
        self.assertEqual(manifest["profile"], self.m.native_source_job_profile())
        self.assertEqual(manifest["profile_sha256"], self.m.PROFILE_SHA256)
        self.assertEqual(manifest["profile"]["max_outer_stages"], 2)
        self.assertEqual(self.m.ACCEPTANCE_NS, 300 * 1000 * 1000 * 1000)
        self.assertEqual(MAX_PAGES, 32)
        self.assertFalse(manifest["default_pipeline_activated"])
        self.assertFalse(manifest["release_authorized"])
        for name, digest in manifest["reused_source_sha256"].items():
            self.assertEqual(sha256((ROOT / name).read_bytes()).hexdigest(), digest, name)
        before = self.m.native_source_job_profile()
        detached = self.m.native_source_job_profile()
        detached["max_pages"] = 512
        self.assertEqual(self.m.native_source_job_profile(), before)
        for name in ("reporting/pdf_native_source_job.py", "tests/test_reporting_pdf_native_source_job.py"):
            for node in ast.walk(ast.parse((ROOT / name).read_text())):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.assertTrue(ast.get_docstring(node), name + ":" + node.name)


if __name__ == "__main__":
    unittest.main()
