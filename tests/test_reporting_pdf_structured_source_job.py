"""Exact source and forward-structure composition with synthetic native controls."""
from __future__ import annotations

import ast
from contextlib import contextmanager, ExitStack
from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
import importlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from reporting import pdf_inspection_job as legacy
from reporting import pdf_source_inspection_job as source
from reporting.pdf_content import _expected_content
from reporting.pdf_document_content import PdfDocumentContentInspection
from reporting.pdf_structure_tree import PdfStructureTreeInspection
from reporting.pdf_mcid_coverage import inspect_pdf_mcid_coverage
from tests.test_reporting_pdf_inspection_job import STAGES, synthetic_receipt
from tests.test_reporting_pdf_source_inspection_job import generated_job_case
from tests.test_reporting_pdf_document_content import changed_pdf
from tests.test_reporting_pdf_structure_tree import structure

ROOT = Path(__file__).resolve().parents[1]
TREE = 'inspect_pdf_structure_tree'
CONTENT = 'inspect_pdf_document_content'
DISABLES = ('OMNIGENIS_PDF_STRUCTURED_SOURCE_JOB_DISABLED',
            'OMNIGENIS_PDF_STRUCTURE_TREE_DISABLED',
            'OMNIGENIS_PDF_SOURCE_INSPECTION_JOB_DISABLED',
            'OMNIGENIS_PDF_INSPECTION_JOB_DISABLED')


class PdfStructuredSourceJobTests(unittest.TestCase):
    """All eight observations must describe the same complete candidate and job."""

    cases = None

    def setUp(self):
        """The missing composition must be a RED assertion before native fixture work."""
        self.assertIsNotNone(importlib.util.find_spec('reporting.pdf_structured_source_job'),
                             'structured source inspection job is missing')
        self.m = importlib.import_module('reporting.pdf_structured_source_job')
        self.ir = {'report_id': 'SYNTHETIC-STRUCTURED-JOB', 'locale_id': 'en-US',
                   'components': [{'component_type': 'semantic-section', 'component_id': 'summary',
                     'title': 'Synthetic summary', 'state': 'PRESENT', 'content': {'value': 17}}]}
        self.pdf = b'%PDF-1.7\nSYNTHETIC_CONTROL_FLOW_ONLY\n'
        self.args = dict(presentation_ir=self.ir, pdf_bytes=self.pdf,
            expected_pdf_sha256=sha256(self.pdf).hexdigest(), expected_ir_sha256=_expected_content(self.ir)[0],
            page_count=33, expected_language='en-US', namespace_id='synthetic-namespace',
            job_id='synthetic-structured-job', request_sha256='c' * 64,
            expected_resource_profile_sha256=self.m.PROFILE_SHA256)

    def run_job(self, **changes):
        """Call the public boundary with independent input and job expectations."""
        return self.m.execute_pdf_structured_source_job(**{**self.args, **changes})

    @classmethod
    def native_cases(cls):
        """Generate only controlled synthetic files, with admitted 64-page bookmark shape."""
        if cls.cases is None:
            cls.cases = {n: generated_job_case(n) for n in (1, 33, 64)}
        return cls.cases

    @contextmanager
    def mocked(self, change=None):
        """Replace native boundaries only; execute both real coordinator implementations."""
        calls = []
        with ExitStack() as stack:
            def tree(**values):
                """Return typed unsigned control-flow data, not proof of native execution."""
                calls.append((TREE, None))
                p = values['plan']
                identity = {k: getattr(p, k) for k in ('pdf_sha256', 'ir_sha256', 'plan_sha256', 'page_count')}
                receipt = PdfStructureTreeInspection(**identity, structure_elements=p.page_count + 1,
                    mapped_mcids=p.page_count, max_tree_depth=2,
                    traversal_visits=2 * p.page_count + 1, inspected_pages=p.page_count)
                return change(TREE, values, receipt) if change else receipt
            def content(**values):
                """Bind the synthetic content receipt to the actual source projection."""
                calls.append((CONTENT, None))
                p = values['plan']
                identity = {k: getattr(p, k) for k in ('pdf_sha256', 'ir_sha256', 'plan_sha256', 'page_count')}
                expected = _expected_content(values['presentation_ir'])[1]
                receipt = PdfDocumentContentInspection(**identity, expected_text_sha256=expected,
                    extracted_text_sha256=expected, inspected_pages=p.page_count,
                    decoded_bytes=100 * p.page_count, text_chars=50 * p.page_count, text_bytes=50 * p.page_count)
                return change(CONTENT, values, receipt) if change else receipt
            def factory(stage):
                """Capture one unchanged native adapter role without replacing the job."""
                def provider(**values):
                    """Record one invocation and optionally inject a typed failure."""
                    calls.append((stage, values.get('window_index')))
                    receipt = synthetic_receipt(stage, values)
                    return change(stage, values, receipt) if change else receipt
                return provider
            stack.enter_context(patch.object(self.m, TREE, side_effect=tree))
            stack.enter_context(patch.object(source, CONTENT, side_effect=content))
            for name in STAGES:
                stack.enter_context(patch.object(legacy, name, side_effect=factory(name)))
            yield calls

    def test_exact_eight_dimension_order_and_finite_invocations(self):
        """Every 1/33/64-page job executes exactly 8/18/26 adapters, with no retry."""
        for pages, count in ((1, 8), (33, 18), (64, 26)):
            with self.subTest(pages=pages), self.mocked() as calls:
                result = self.run_job(page_count=pages)
            expected = [(TREE, None), (CONTENT, None)] + [(name, None) for name in STAGES[:4]]
            expected += [(STAGES[4], i) for i in range((pages + 15) // 16)]
            expected += [(STAGES[5], i) for i in range((pages + 3) // 4)]
            self.assertEqual(calls, expected)
            self.assertEqual(len(calls), count)
            self.assertEqual(result.to_dict()['page_count'], pages)

    def test_real_native_one_thirty_three_and_sixty_four_pages(self):
        """Run all eight real inspectors on the same final PDF and complete source."""
        for pages, (ir, pdf) in self.native_cases().items():
            with self.subTest(pages=pages):
                before = json.dumps(ir, sort_keys=True)
                result = self.run_job(presentation_ir=ir, pdf_bytes=pdf, page_count=pages,
                    expected_pdf_sha256=sha256(pdf).hexdigest(), expected_ir_sha256=_expected_content(ir)[0])
                data = result.to_dict()
                self.assertEqual(data['structure_tree']['mapped_mcids'], 3 * pages + 1)
                self.assertEqual(data['structure_tree']['inspected_pages'], pages)
                inner = data['source_inspection']['inspection_set']['page_bundle']
                self.assertEqual(inner['text_stream']['represented_pages'], pages)
                self.assertEqual(inner['raster_stream']['represented_pages'], pages)
                self.assertTrue(data['normalized_text_equivalence_verified'])
                self.assertTrue(data['forward_reverse_linkage_verified'])
                self.assertFalse(data['release_authorized'])
                self.assertEqual(json.dumps(ir, sort_keys=True), before)

    def test_forward_orphan_with_valid_reverse_map_stops_before_source_job(self):
        """An intact reverse MCID map cannot substitute for the missing forward branch."""
        ir, pdf = self.native_cases()[1]
        def remove(writer):
            """Delete a forward link without changing the reverse reference or text."""
            del structure(writer)[3]['/K'][0]
        candidate = changed_pdf(pdf, remove)
        from reporting.page_windows import plan_pdf_page_windows
        plan = plan_pdf_page_windows(pdf_sha256=sha256(candidate).hexdigest(),
            ir_sha256=_expected_content(ir)[0], page_count=1, admitted_page_budget=1,
            pages_per_window=16, inspector_profile_id=legacy.TEXT_PROFILE)
        self.assertEqual(inspect_pdf_mcid_coverage(pdf_bytes=candidate, plan=plan,
            expected_plan_sha256=plan.plan_sha256, expected_language='en-US').matched_mcids, 4)
        with patch.object(self.m, 'execute_pdf_source_inspection_job') as later:
            with self.assertRaises(self.m.PdfStructuredSourceJobError):
                self.run_job(presentation_ir=ir, pdf_bytes=candidate, page_count=1,
                    expected_pdf_sha256=sha256(candidate).hexdigest(), expected_ir_sha256=_expected_content(ir)[0])
            later.assert_not_called()

    def test_real_source_mismatch_cannot_pass_structural_success(self):
        """A valid tag tree never excuses actual source text that differs from the PDF."""
        ir, pdf = self.native_cases()[1]
        ir = json.loads(json.dumps(ir)); ir['components'][0]['content']['value'] = 999
        with self.assertRaises(self.m.PdfStructuredSourceJobError):
            self.run_job(presentation_ir=ir, pdf_bytes=pdf, page_count=1,
                expected_pdf_sha256=sha256(pdf).hexdigest(), expected_ir_sha256=_expected_content(ir)[0])

    def test_invalid_admission_prevents_every_adapter(self):
        """Wrong types, hashes, locale, namespace and profile never begin native work."""
        variants = [dict(pdf_bytes=bytearray(self.pdf)), dict(pdf_bytes=b'bad'),
            dict(page_count=True), dict(page_count=65), dict(page_count=0),
            dict(expected_pdf_sha256='f' * 64), dict(expected_ir_sha256='f' * 64),
            dict(expected_language='pt-BR'), dict(namespace_id=None), dict(job_id=''),
            dict(request_sha256='unknown'), dict(expected_resource_profile_sha256=source.PROFILE_SHA256)]
        for change in variants:
            with self.subTest(change=list(change)), self.mocked() as calls:
                with self.assertRaises(self.m.PdfStructuredSourceJobError): self.run_job(**change)
                self.assertEqual(calls, [])

    def test_bounded_source_and_pdf_sizes_remain_enforced(self):
        """Cycles, foreign objects and inputs beyond existing bounds never launch an adapter."""
        cycle = {}; cycle['cycle'] = cycle
        variants = [dict(presentation_ir=value) for value in
                    (cycle, None, {'components': [object()]}, {'large': 'x' * 8388609})]
        overflow = b'%PDF-1.7' + b'x' * 16777209
        variants.append(dict(pdf_bytes=overflow, expected_pdf_sha256=sha256(overflow).hexdigest()))
        for change in variants:
            with self.mocked() as calls:
                with self.assertRaises(self.m.PdfStructuredSourceJobError): self.run_job(**change)
                self.assertEqual(calls, [])

    def test_failure_in_each_dimension_returns_no_partial_result(self):
        """Every inspector failure stops execution without retry or raw exception disclosure."""
        for failed in (TREE, CONTENT, *STAGES):
            def fail(stage, values, receipt):
                """Reject exactly the selected test stage."""
                if stage == failed: raise RuntimeError('SYNTHETIC_PRIVATE_ERROR')
                return receipt
            with self.subTest(stage=failed), self.mocked(fail) as calls:
                with self.assertRaises(self.m.PdfStructuredSourceJobError) as caught: self.run_job()
                self.assertEqual(calls[-1][0], failed)
                self.assertEqual(sum(name == failed for name, _ in calls), 1)
                self.assertNotIn('SYNTHETIC_PRIVATE_ERROR', str(caught.exception))

    def test_foreign_tree_receipts_stop_before_source_comparison(self):
        """Sealed but foreign PDF, IR or plan metadata and generic success are rejected."""
        for field in (None, 'pdf_sha256', 'ir_sha256', 'plan_sha256'):
            def change(stage, values, receipt):
                """Return one wrong structural receipt while keeping its own seal valid."""
                if stage != TREE: return receipt
                return {'status': 'PASS'} if field is None else replace(receipt, **{field: 'f' * 64})
            with self.mocked(change) as calls:
                with self.assertRaises(self.m.PdfStructuredSourceJobError): self.run_job()
                self.assertEqual(calls, [(TREE, None)])

    def test_generic_source_result_is_not_trusted(self):
        """An unsigned success dictionary is not the required typed source inspection."""
        with self.mocked(), patch.object(self.m, 'execute_pdf_source_inspection_job', return_value={'status': 'PASS'}):
            with self.assertRaises(self.m.PdfStructuredSourceJobError): self.run_job()

    def test_foreign_source_job_context_is_rejected(self):
        """Even a valid sealed child for another request, namespace or job cannot bind."""
        for field in ('namespace_id', 'job_id', 'request_sha256'):
            def foreign(**values):
                """Execute the existing child coordinator under a different test identity."""
                values[field] = 'foreign-context' if field != 'request_sha256' else 'e' * 64
                return source.execute_pdf_source_inspection_job(**values)
            with self.mocked(), patch.object(self.m, 'execute_pdf_source_inspection_job', side_effect=foreign):
                with self.assertRaises(self.m.PdfStructuredSourceJobError): self.run_job()

    def test_mcid_counts_must_agree_across_independently_valid_children(self):
        """Structurally plausible counts cannot disagree with the parsed page MCID receipt."""
        def change(stage, values, receipt):
            """Create a valid but contradictory tree count, not malformed metadata."""
            return replace(receipt, mapped_mcids=receipt.mapped_mcids + 1,
                traversal_visits=receipt.traversal_visits + 1) if stage == TREE else receipt
        with self.mocked(change):
            with self.assertRaises(self.m.PdfStructuredSourceJobError): self.run_job()

    def test_original_source_mutation_after_tree_stops_source_job(self):
        """A source mutation during the first inspector cannot receive later acceptance."""
        def mutate(stage, values, receipt):
            """Change only the original caller-owned synthetic value."""
            if stage == TREE: self.ir['components'][0]['content']['value'] = 18
            return receipt
        with self.mocked(mutate) as calls:
            with self.assertRaises(self.m.PdfStructuredSourceJobError): self.run_job()
            self.assertEqual(calls, [(TREE, None)])

    def test_child_receives_detached_source_and_cannot_mutate_it(self):
        """The child receives a detached source, whose persistent changes remain rejected."""
        def mutate(**values):
            """Complete the real mocked child then alter only its retained source input."""
            self.assertIsNot(values['presentation_ir'], self.ir)
            self.assertIsNot(values['presentation_ir']['components'], self.ir['components'])
            result = source.execute_pdf_source_inspection_job(**values)
            values['presentation_ir']['report_id'] = 'CHANGED-SYNTHETIC'
            return result
        with self.mocked(), patch.object(self.m, 'execute_pdf_source_inspection_job', side_effect=mutate):
            with self.assertRaises(self.m.PdfStructuredSourceJobError): self.run_job()

    def test_original_source_mutation_during_final_child_stops_return(self):
        """A successful child cannot hide a changed original source outside its snapshot."""
        def mutate(stage, values, receipt):
            """Change the caller data after a native stage has produced its test receipt."""
            if stage == STAGES[-1]: self.ir['report_id'] = 'CHANGED-SYNTHETIC'
            return receipt
        with self.mocked(mutate):
            with self.assertRaises(self.m.PdfStructuredSourceJobError): self.run_job()

    def test_all_independent_disable_switches_prevent_admission(self):
        """Disabled prerequisites are not discovered only after other native work runs."""
        for flag in DISABLES:
            with self.subTest(flag=flag), self.mocked() as calls, patch.dict(os.environ, {flag: '1'}):
                with self.assertRaises(self.m.PdfStructuredSourceJobError): self.run_job()
                self.assertEqual(calls, [])

    def test_outer_disable_between_stages_stops_later_work(self):
        """Disabling the outer boundary discards an already completed structural receipt."""
        def disable(stage, values, receipt):
            """Disable the new composition after the first synthetic inspector returns."""
            if stage == TREE: os.environ[DISABLES[0]] = '1'
            return receipt
        with patch.dict(os.environ), self.mocked(disable) as calls:
            with self.assertRaises(self.m.PdfStructuredSourceJobError): self.run_job()
            self.assertEqual(calls, [(TREE, None)])

    def test_tree_disable_during_source_work_prevents_final_acceptance(self):
        """A prerequisite disabled after its execution invalidates the complete result."""
        def disable(stage, values, receipt):
            """Disable the already executed tree adapter while the later job is running."""
            if stage == CONTENT: os.environ[DISABLES[1]] = '1'
            return receipt
        with patch.dict(os.environ), self.mocked(disable):
            with self.assertRaises(self.m.PdfStructuredSourceJobError): self.run_job()

    def test_late_tree_result_stops_source_job(self):
        """The outer acceptance deadline rejects late work without claiming preemption."""
        clock = [0]
        def late(stage, values, receipt):
            """Advance only the outer deterministic clock after the first adapter."""
            if stage == TREE: clock[0] = self.m.ACCEPTANCE_NS
            return receipt
        with self.mocked(late) as calls, patch.object(self.m, 'monotonic_ns', side_effect=lambda: clock[0]):
            with self.assertRaises(self.m.PdfStructuredSourceJobError): self.run_job()
            self.assertEqual(calls, [(TREE, None)])

    def test_late_final_result_never_returns_success(self):
        """A complete inner result still cannot exceed the independent outer acceptance limit."""
        clock = [0]
        def late(stage, values, receipt):
            """Advance the outer clock while the final native dimension executes."""
            if stage == STAGES[-1]: clock[0] = self.m.ACCEPTANCE_NS
            return receipt
        with self.mocked(late), patch.object(self.m, 'monotonic_ns', side_effect=lambda: clock[0]):
            with self.assertRaises(self.m.PdfStructuredSourceJobError): self.run_job()

    def test_clock_type_and_regression_fail_closed(self):
        """Negative, Boolean and regressing clocks never start native work."""
        for sequence in ([True], [-1], [10, 9]):
            with self.mocked() as calls, patch.object(self.m, 'monotonic_ns', side_effect=sequence):
                with self.assertRaises(self.m.PdfStructuredSourceJobError): self.run_job()
                self.assertEqual(calls, [])

    def test_profile_is_detached_and_runtime_changes_are_rejected(self):
        """A changed resource contract cannot silently retain the original profile identity."""
        before = self.m.structured_source_job_profile()
        changed = self.m.structured_source_job_profile(); changed['max_pages'] = 512
        self.assertEqual(self.m.structured_source_job_profile(), before)
        with self.mocked() as calls, patch.object(self.m, 'MAX_PAGES', 512):
            with self.assertRaises(self.m.PdfStructuredSourceJobError): self.run_job()
            self.assertEqual(calls, [])

    def test_existing_source_profile_drift_is_rejected(self):
        """The new profile cannot excuse a changed old source-aware resource contract."""
        with self.mocked() as calls, patch.object(source, 'MAX_INVOCATIONS', 26):
            with self.assertRaises(self.m.PdfStructuredSourceJobError): self.run_job()
            self.assertEqual(calls, [])

    def test_no_pdf_parser_runs_in_parent_on_native_path(self):
        """The complete one-page job works while in-process PDF parsing is forbidden."""
        ir, pdf = self.native_cases()[1]
        with patch('pypdf.PdfReader', side_effect=AssertionError('parent parser forbidden')):
            result = self.run_job(presentation_ir=ir, pdf_bytes=pdf, page_count=1,
                expected_pdf_sha256=sha256(pdf).hexdigest(), expected_ir_sha256=_expected_content(ir)[0])
        self.assertTrue(result.to_dict()['forward_reverse_linkage_verified'])

    def test_public_api_has_no_caller_receipts_or_executor(self):
        """Only the fixed native execution path is exposed, not a receipt-injection API."""
        self.assertEqual(set(inspect.signature(self.m.execute_pdf_structured_source_job).parameters), set(self.args))

    def test_result_is_frozen_sealed_detached_bounded_and_content_free(self):
        """A complete immutable result exposes metadata only, within the declared byte bound."""
        with self.mocked(): result = self.run_job()
        data = result.to_bytes()
        self.assertEqual(result.inspection_sha256, sha256(data).hexdigest())
        self.assertLessEqual(len(data), 288 * 1024)
        self.assertNotIn(b'SYNTHETIC-STRUCTURED-JOB', data)
        with self.assertRaises(FrozenInstanceError): result.page_count = 2
        detached = result.to_dict(); detached['structure_tree']['mapped_mcids'] = 999
        self.assertEqual(result.to_bytes(), data)

    def test_nested_mutation_and_repinning_cannot_reseal(self):
        """Changing a retained valid child and its hash does not change the original seal."""
        with self.mocked(): result = self.run_job()
        alternate = replace(result.structure_tree, traversal_visits=result.structure_tree.traversal_visits + 1)
        object.__setattr__(result, 'structure_tree', alternate)
        object.__setattr__(result, 'expected_structure_sha256', alternate.inspection_sha256)
        with self.assertRaises(self.m.PdfStructuredSourceJobError): result.to_bytes()
        with self.assertRaises(self.m.PdfStructuredSourceJobError): result.__post_init__()

    def test_direct_constructor_requires_independent_exact_bindings(self):
        """Direct unsigned metadata construction still rejects missing or contradictory children."""
        with self.mocked(): result = self.run_job()
        for change in ({'structure_tree': None}, {'source_inspection': None},
                       {'expected_structure_sha256': 'f' * 64}, {'expected_source_sha256': 'f' * 64},
                       {'expected_text_sha256': 'f' * 64}, {'namespace_id': 'foreign'},
                       {'pdf_sha256': 'f' * 64}, {'page_count': True}):
            with self.assertRaises(self.m.PdfStructuredSourceJobError): replace(result, **change)

    def test_structure_and_source_profiles_remain_distinct(self):
        """The returned outer profile never substitutes for the unchanged source-job profile."""
        with self.mocked(): result = self.run_job()
        d = result.to_dict()
        self.assertEqual(d['resource_profile_sha256'], self.m.PROFILE_SHA256)
        self.assertEqual(d['source_inspection']['resource_profile_sha256'], source.PROFILE_SHA256)
        self.assertNotEqual(source.PROFILE_SHA256, self.m.PROFILE_SHA256)

    def test_unqualified_science_accessibility_and_release_remain_false(self):
        """Matching eight inspection dimensions is neither full accessibility nor release authority."""
        with self.mocked(): data = self.run_job().to_dict()
        for name in ('worker_results_authenticated', 'scientific_equivalence_verified',
                     'visible_glyphs_verified', 'full_accessibility_qualified', 'semantic_roles_qualified',
                     'reading_order_verified', 'finding_completeness_verified',
                     'aggregate_job_resources_qualified', 'release_authorized'):
            self.assertIs(data[name], False)
        self.assertEqual(data['release_authorization'], 'NOT_ESTABLISHED')

    def test_existing_graph_depth_budget_is_not_relaxed(self):
        """A 64-page original automatic bookmark chain still exceeds the old finite graph guard."""
        from tests.test_reporting_pdf_document_content import generated_case
        ir, pdf = generated_case(64)
        with self.assertRaises(self.m.PdfStructuredSourceJobError):
            self.run_job(presentation_ir=ir, pdf_bytes=pdf, page_count=64,
                expected_pdf_sha256=sha256(pdf).hexdigest(), expected_ir_sha256=_expected_content(ir)[0])

    def test_manifest_source_hashes_default_limits_and_docstrings(self):
        """The additive contract leaves every reused source and default renderer profile unchanged."""
        from reporting._pdf_safety_worker import MAX_PAGES
        manifest = json.loads((ROOT / 'reporting/pdf-structured-source-job.v1.json').read_text())
        self.assertEqual(MAX_PAGES, 32)
        self.assertEqual(manifest['profile'], self.m.structured_source_job_profile())
        self.assertEqual(manifest['profile_sha256'], self.m.PROFILE_SHA256)
        self.assertFalse(manifest['default_pipeline_activated'])
        self.assertFalse(manifest['release_authorized'])
        for name, digest in manifest['reused_source_sha256'].items():
            self.assertEqual(sha256((ROOT / name).read_bytes()).hexdigest(), digest)
        for name in ('reporting/pdf_structured_source_job.py', 'tests/test_reporting_pdf_structured_source_job.py'):
            for node in ast.walk(ast.parse((ROOT / name).read_text())):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.assertTrue(ast.get_docstring(node), name + ':' + node.name)


if __name__ == '__main__':
    unittest.main()
