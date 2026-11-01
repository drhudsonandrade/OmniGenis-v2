"""Seven-dimension source-aware execution with synthetic and native negative controls."""
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
from reporting.pdf_content import _expected_content
from reporting.pdf_document_content import PdfDocumentContentInspection
from tests.test_reporting_pdf_document_content import generated_case, changed_pdf
from tests.test_reporting_pdf_inspection_job import STAGES, synthetic_receipt

ROOT = Path(__file__).resolve().parents[1]
CONTENT = 'inspect_pdf_document_content'


def generated_job_case(pages):
    """Generate an admitted synthetic fixture; 64 pages omit automatic bookmark chains."""
    if pages != 64:
        return generated_case(pages)
    from weasyprint import HTML, CSS
    original = HTML.write_pdf
    def without_bookmarks(self, *args, **kwargs):
        """Change fixture generation only, preserving all actual source text and page tags."""
        kwargs['stylesheets'] = [CSS(string='h1,h2{bookmark-level:none}')]
        return original(self, *args, **kwargs)
    with patch.object(HTML, 'write_pdf', new=without_bookmarks):
        return generated_case(pages)


class PdfSourceInspectionJobTests(unittest.TestCase):
    """Require both actual source comparison and every preexisting inspection dimension."""

    cases = None

    def setUp(self):
        """Missing implementation is an explicit RED assertion before any native fixtures."""
        self.assertIsNotNone(importlib.util.find_spec('reporting.pdf_source_inspection_job'),
                             'source-aware PDF inspection job is missing')
        self.m = importlib.import_module('reporting.pdf_source_inspection_job')
        self.ir = {'report_id': 'SYNTHETIC-SOURCE-JOB', 'locale_id': 'en-US',
                   'components': [{'component_type': 'semantic-section', 'component_id': 'summary',
                     'title': 'Synthetic summary', 'state': 'PRESENT', 'content': {'value': 17}}]}
        self.pdf = b'%PDF-1.7\nSYNTHETIC_CONTROL_FLOW_ONLY\n'
        self.args = dict(presentation_ir=self.ir, pdf_bytes=self.pdf,
            expected_pdf_sha256=sha256(self.pdf).hexdigest(), expected_ir_sha256=_expected_content(self.ir)[0],
            page_count=33, expected_language='en-US', namespace_id='synthetic-namespace',
            job_id='synthetic-source-job', request_sha256='c' * 64,
            expected_resource_profile_sha256=self.m.PROFILE_SHA256)

    def run_job(self, **changes):
        """Invoke the public execution API with independently supplied primitive expectations."""
        return self.m.execute_pdf_source_inspection_job(**{**self.args, **changes})

    @classmethod
    def native_cases(cls):
        """Cache only synthetic immutable PDF fixtures and separately copied source data."""
        if cls.cases is None:
            cls.cases = {n: generated_job_case(n) for n in (1, 33, 64)}
        return cls.cases

    @contextmanager
    def mocked(self, change=None):
        """Fabricate child records for control-flow tests only, never native proof."""
        calls = []
        with ExitStack() as stack:
            def content(**values):
                """Produce a typed unsigned text-only synthetic response."""
                calls.append((CONTENT, None))
                plan = values['plan']
                identity = {k: getattr(plan, k) for k in ('pdf_sha256', 'ir_sha256', 'plan_sha256', 'page_count')}
                expected = _expected_content(values['presentation_ir'])[1]
                receipt = PdfDocumentContentInspection(**identity, expected_text_sha256=expected,
                    extracted_text_sha256=expected, inspected_pages=plan.page_count,
                    decoded_bytes=100 * plan.page_count, text_chars=50 * plan.page_count,
                    text_bytes=50 * plan.page_count)
                return change(CONTENT, values, receipt) if change else receipt
            stack.enter_context(patch.object(self.m, CONTENT, side_effect=content))
            def factory(stage):
                """Capture a single preexisting native stage name."""
                def provider(**values):
                    """Record the fake invocation, then optionally inject failure."""
                    calls.append((stage, values.get('window_index')))
                    receipt = synthetic_receipt(stage, values)
                    return change(stage, values, receipt) if change else receipt
                return provider
            for name in STAGES:
                stack.enter_context(patch.object(legacy, name, side_effect=factory(name)))
            yield calls

    def test_exact_seven_dimension_sequence_and_maximum_calls(self):
        """1/33/64-page plans require exactly 7/17/25 adapter invocations without retries."""
        for pages, total in ((1, 7), (33, 17), (64, 25)):
            with self.subTest(pages=pages), self.mocked() as calls:
                result = self.run_job(page_count=pages)
            expected = [(CONTENT, None)] + [(n, None) for n in STAGES[:4]]
            expected += [(STAGES[4], i) for i in range((pages + 15) // 16)]
            expected += [(STAGES[5], i) for i in range((pages + 3) // 4)]
            self.assertEqual(calls, expected)
            self.assertEqual(len(calls), total)
            self.assertEqual(result.to_dict()['page_count'], pages)

    def test_real_native_one_thirty_three_and_sixty_four_pages(self):
        """Run all seven unchanged inspectors on the same complete generated source/PDF."""
        for pages, (ir, pdf) in self.native_cases().items():
            with self.subTest(pages=pages):
                result = self.run_job(presentation_ir=ir, pdf_bytes=pdf, page_count=pages,
                    expected_pdf_sha256=sha256(pdf).hexdigest(), expected_ir_sha256=_expected_content(ir)[0])
                data = result.to_dict()
                self.assertEqual(data['page_count'], pages)
                self.assertTrue(data['normalized_text_equivalence_verified'])
                self.assertEqual(data['document_content']['expected_text_sha256'], _expected_content(ir)[1])
                self.assertEqual(data['inspection_set']['page_bundle']['text_stream']['represented_pages'], pages)
                self.assertEqual(data['inspection_set']['page_bundle']['raster_stream']['represented_pages'], pages)
                self.assertFalse(data['release_authorized'])

    def test_existing_graph_depth_limit_is_not_relaxed_for_sixty_four_pages(self):
        """A 64-page auto-bookmark chain exceeding existing graph depth remains rejected."""
        ir, pdf = generated_case(64)
        with patch.object(legacy, 'inspect_pdf_document_metadata') as later:
            with self.assertRaises(self.m.PdfSourceInspectionJobError):
                self.run_job(presentation_ir=ir, pdf_bytes=pdf, page_count=64,
                    expected_pdf_sha256=sha256(pdf).hexdigest(), expected_ir_sha256=_expected_content(ir)[0])
            later.assert_not_called()

    def test_invalid_admission_prevents_every_adapter(self):
        """Mutable bytes, false counts, wrong pins and unsupported context never launch work."""
        bad = [dict(pdf_bytes=bytearray(self.pdf)), dict(pdf_bytes=b'bad'), dict(page_count=True),
               dict(page_count=65), dict(page_count=0), dict(expected_pdf_sha256='f' * 64),
               dict(expected_ir_sha256='f' * 64), dict(expected_language='pt-BR'), dict(job_id=''),
               dict(namespace_id=None), dict(request_sha256='unknown'),
               dict(expected_resource_profile_sha256=legacy.PROFILE_SHA256)]
        for changes in bad:
            with self.subTest(changes=list(changes)), self.mocked() as calls:
                with self.assertRaises(self.m.PdfSourceInspectionJobError): self.run_job(**changes)
                self.assertEqual(calls, [])

    def test_bounded_native_source_capture_rejects_cycles_and_foreign_objects(self):
        """The existing bounded snapshot rejects cyclic, nonnative and unbounded source."""
        cycle = {}; cycle['cycle'] = cycle
        for source in (cycle, None, {'components': [object()]}, {'large': 'x' * 8388609}):
            with self.mocked() as calls:
                with self.assertRaises(self.m.PdfSourceInspectionJobError): self.run_job(presentation_ir=source)
                self.assertEqual(calls, [])

    def test_pdf_size_has_explicit_finite_ceiling(self):
        """An over-budget PDF is rejected before any existing adapter is invoked."""
        overflow = b'%PDF-1.7' + b'x' * 16777209
        with self.mocked() as calls:
            with self.assertRaises(self.m.PdfSourceInspectionJobError):
                self.run_job(pdf_bytes=overflow, expected_pdf_sha256=sha256(overflow).hexdigest())
            self.assertEqual(calls, [])

    def test_real_source_mismatch_stops_before_six_inspector_job(self):
        """A fresh source hash cannot excuse mismatch with an unchanged candidate PDF."""
        ir, pdf = self.native_cases()[1]
        changed = json.loads(json.dumps(ir)); changed['components'][0]['content']['value'] = 999
        with patch.object(self.m, 'execute_pdf_inspection_job') as inner:
            with self.assertRaises(self.m.PdfSourceInspectionJobError):
                self.run_job(presentation_ir=changed, pdf_bytes=pdf, page_count=1,
                    expected_pdf_sha256=sha256(pdf).hexdigest(), expected_ir_sha256=_expected_content(changed)[0])
            inner.assert_not_called()

    def test_real_omitted_duplicated_and_reordered_pages_never_reach_inner_job(self):
        """Rehashed malformed document sequences still fail source equality first."""
        ir, pdf = self.native_cases()[33]
        def rotate(writer):
            """Move one actual synthetic page without editing its contents."""
            page = writer.pages[0]; writer.remove_page(0); writer.add_page(page)
        variants = [(changed_pdf(pdf, lambda w: w.remove_page(32)), 32),
                    (changed_pdf(pdf, lambda w: w.add_page(w.pages[-1])), 34),
                    (changed_pdf(pdf, rotate), 33)]
        for candidate, pages in variants:
            with patch.object(self.m, 'execute_pdf_inspection_job') as inner:
                with self.assertRaises(self.m.PdfSourceInspectionJobError):
                    self.run_job(presentation_ir=ir, pdf_bytes=candidate, page_count=pages,
                        expected_pdf_sha256=sha256(candidate).hexdigest(), expected_ir_sha256=_expected_content(ir)[0])
                inner.assert_not_called()

    def test_failure_in_each_dimension_returns_no_partial_result(self):
        """Every required inspector can reject the job; no retry or later native call follows."""
        for failed in (CONTENT, *STAGES):
            def change(stage, values, receipt):
                """Inject one fixed failure at a selected stage."""
                if stage == failed: raise RuntimeError('SYNTHETIC-PRIVATE-ERROR')
                return receipt
            with self.subTest(stage=failed), self.mocked(change) as calls:
                with self.assertRaises(self.m.PdfSourceInspectionJobError) as error: self.run_job()
                self.assertEqual(calls[-1][0], failed)
                self.assertEqual(sum(stage == failed for stage, _ in calls), 1)
                self.assertNotIn('SYNTHETIC-PRIVATE-ERROR', str(error.exception))

    def test_wrong_content_type_and_identity_stop_before_inner_job(self):
        """Foreign plan/PDF/IR identities and generic success dictionaries are rejected."""
        for key in (None, 'pdf_sha256', 'ir_sha256', 'plan_sha256'):
            def change(stage, values, receipt):
                """Return one malformed but success-looking source result."""
                if stage != CONTENT: return receipt
                return {'status': 'PASS'} if key is None else replace(receipt, **{key: 'f' * 64})
            with self.mocked(change) as calls:
                with self.assertRaises(self.m.PdfSourceInspectionJobError): self.run_job()
                self.assertEqual(calls, [(CONTENT, None)])

    def test_foreign_matched_text_pair_cannot_replace_expected_source(self):
        """An internally equal digest pair must also match independent source projection."""
        def change(stage, values, receipt):
            """Forge only a different consistent synthetic text pair."""
            return replace(receipt, expected_text_sha256='f' * 64, extracted_text_sha256='f' * 64) if stage == CONTENT else receipt
        with self.mocked(change) as calls:
            with self.assertRaises(self.m.PdfSourceInspectionJobError): self.run_job()
            self.assertEqual(calls, [(CONTENT, None)])

    def test_foreign_inner_job_context_rejected_even_with_valid_seal(self):
        """A correctly sealed result for another job is not this invocation's result."""
        for field in ('namespace_id', 'job_id', 'request_sha256'):
            def foreign(**values):
                """Execute the actual inner coordinator under foreign synthetic context."""
                values[field] = 'foreign-job' if field != 'request_sha256' else 'e' * 64
                return legacy.execute_pdf_inspection_job(**values)
            with self.mocked(), patch.object(self.m, 'execute_pdf_inspection_job', side_effect=foreign):
                with self.assertRaises(self.m.PdfSourceInspectionJobError): self.run_job()

    def test_generic_inner_result_is_not_an_inspection_set(self):
        """The wrapper rejects generic success instead of trusting a child-looking object."""
        with self.mocked(), patch.object(self.m, 'execute_pdf_inspection_job', return_value={'status': 'PASS'}):
            with self.assertRaises(self.m.PdfSourceInspectionJobError): self.run_job()

    def test_source_is_detached_and_original_mutation_stops_next_stage(self):
        """Only a bounded snapshot reaches content validation; caller mutation invalidates the job."""
        def mutate(stage, values, receipt):
            """Change original source after confirming it is not the child snapshot."""
            if stage == CONTENT:
                self.assertIsNot(values['presentation_ir'], self.ir)
                self.assertIsNot(values['presentation_ir']['components'], self.ir['components'])
                self.ir['components'][0]['content']['value'] = 18
            return receipt
        with self.mocked(mutate) as calls:
            with self.assertRaises(self.m.PdfSourceInspectionJobError): self.run_job()
            self.assertEqual(calls, [(CONTENT, None)])

    def test_captured_source_mutation_is_also_rejected(self):
        """A modified detached child input cannot silently become a new accepted source."""
        def mutate(stage, values, receipt):
            """Mutate only the captured source after its synthetic content receipt."""
            if stage == CONTENT: values['presentation_ir']['components'][0]['content']['value'] = 18
            return receipt
        with self.mocked(mutate) as calls:
            with self.assertRaises(self.m.PdfSourceInspectionJobError): self.run_job()
            self.assertEqual(calls, [(CONTENT, None)])

    def test_source_mutation_during_inner_job_prevents_final_return(self):
        """A completed six-dimension inspection cannot hide changed caller source."""
        def mutate(stage, values, receipt):
            """Alter the original source while the inner coordinator is executing."""
            if stage == STAGES[0]: self.ir['report_id'] = 'CHANGED-SYNTHETIC'
            return receipt
        with self.mocked(mutate):
            with self.assertRaises(self.m.PdfSourceInspectionJobError): self.run_job()

    def test_disable_at_entry_prevents_all_work(self):
        """The optional source-aware job has its own fail-closed disable switch."""
        with self.mocked() as calls, patch.dict(os.environ, {'OMNIGENIS_PDF_SOURCE_INSPECTION_JOB_DISABLED': '1'}):
            with self.assertRaises(self.m.PdfSourceInspectionJobError): self.run_job()
            self.assertEqual(calls, [])

    def test_disable_between_outer_stages_discards_text_result(self):
        """Disabling after source comparison prevents entering the six-inspector job."""
        with patch.dict(os.environ, {}, clear=False):
            def disable(stage, values, receipt):
                """Set only the new outer kill switch after source comparison."""
                if stage == CONTENT: os.environ['OMNIGENIS_PDF_SOURCE_INSPECTION_JOB_DISABLED'] = '1'
                return receipt
            with self.mocked(disable) as calls:
                with self.assertRaises(self.m.PdfSourceInspectionJobError): self.run_job()
                self.assertEqual(calls, [(CONTENT, None)])

    def test_inner_disable_remains_effective(self):
        """The unchanged inner coordinator retains its independent per-call kill switch."""
        with patch.dict(os.environ, {'OMNIGENIS_PDF_INSPECTION_JOB_DISABLED': '1'}), self.mocked() as calls:
            with self.assertRaises(self.m.PdfSourceInspectionJobError): self.run_job()
            self.assertLessEqual(len(calls), 1)

    def test_late_source_response_is_rejected_without_starting_inner_job(self):
        """The acceptance deadline rejects a late response but does not claim preemption."""
        clock = [0]
        def late(stage, values, receipt):
            """Advance only the wrapper's deterministic test clock during a call."""
            if stage == CONTENT: clock[0] = self.m.ACCEPTANCE_NS
            return receipt
        with self.mocked(late) as calls, patch.object(self.m, 'monotonic_ns', side_effect=lambda: clock[0]):
            with self.assertRaises(self.m.PdfSourceInspectionJobError): self.run_job()
            self.assertEqual(calls, [(CONTENT, None)])

    def test_clock_regression_or_boolean_is_not_valid_time(self):
        """A malformed initial clock or regressing next reading rejects admission."""
        for sequence in ([True], [-1], [10, 9]):
            with self.mocked() as calls, patch.object(self.m, 'monotonic_ns', side_effect=sequence):
                with self.assertRaises(self.m.PdfSourceInspectionJobError): self.run_job()
                self.assertEqual(calls, [])

    def test_profile_is_detached_and_runtime_drift_is_rejected(self):
        """An altered returned profile or changed runtime cap cannot widen the fixed contract."""
        expected = self.m.source_inspection_job_profile()
        changed = self.m.source_inspection_job_profile(); changed['max_pages'] = 512
        self.assertEqual(self.m.source_inspection_job_profile(), expected)
        with patch.object(self.m, 'MAX_PAGES', 512), self.mocked() as calls:
            with self.assertRaises(self.m.PdfSourceInspectionJobError): self.run_job()
            self.assertEqual(calls, [])

    def test_public_execution_has_no_receipt_executor_or_resume_input(self):
        """There is no public API to substitute fabricated child results or callbacks."""
        args = set(inspect.signature(self.m.execute_pdf_source_inspection_job).parameters)
        self.assertEqual(args, set(self.args))
        self.assertTrue(args.isdisjoint({'receipt', 'executor', 'resume', 'retry', 'checkpoint'}))

    def test_native_path_has_no_pdf_parser_in_parent(self):
        """Source capture is in-process; untrusted PDF parsing remains inside existing workers."""
        ir, pdf = self.native_cases()[1]
        with patch('pypdf.PdfReader', side_effect=AssertionError('parent parser forbidden')):
            result = self.run_job(presentation_ir=ir, pdf_bytes=pdf, page_count=1,
                expected_pdf_sha256=sha256(pdf).hexdigest(), expected_ir_sha256=_expected_content(ir)[0])
        self.assertTrue(result.to_dict()['normalized_text_equivalence_verified'])

    def test_result_is_sealed_frozen_detached_and_content_free(self):
        """The returned composite has deterministic bounded bytes and no report text."""
        with self.mocked(): result = self.run_job()
        before = result.to_bytes()
        self.assertEqual(result.inspection_sha256, sha256(before).hexdigest())
        self.assertLessEqual(len(before), 280 * 1024)
        self.assertNotIn(b'SYNTHETIC-SOURCE-JOB', before)
        with self.assertRaises(FrozenInstanceError): result.page_count = 2
        data = result.to_dict(); data['inspection_set']['job_id'] = 'changed'
        self.assertEqual(result.to_bytes(), before)

    def test_nested_mutation_and_repinning_cannot_reseal_result(self):
        """A previously returned composite cannot be silently promoted with alternate valid evidence."""
        with self.mocked(): result = self.run_job()
        alternate = replace(result.document_content, text_chars=result.document_content.text_chars + 1)
        object.__setattr__(result, 'document_content', alternate)
        object.__setattr__(result, 'expected_content_sha256', alternate.inspection_sha256)
        with self.assertRaises(self.m.PdfSourceInspectionJobError): result.to_bytes()
        with self.assertRaises(self.m.PdfSourceInspectionJobError): result.__post_init__()

    def test_direct_constructor_still_requires_all_exact_bindings(self):
        """Direct metadata construction is not a bypass for missing or contradictory evidence."""
        with self.mocked(): result = self.run_job()
        for changes in ({'inspection_set': None}, {'expected_content_sha256': 'f' * 64},
                        {'expected_text_sha256': 'f' * 64}, {'namespace_id': 'foreign'},
                        {'pdf_sha256': 'f' * 64}, {'page_count': True}):
            with self.assertRaises(self.m.PdfSourceInspectionJobError): replace(result, **changes)

    def test_non_text_qualification_and_release_remain_false(self):
        """Seven compatible observations do not establish clinical, visual or release authority."""
        with self.mocked(): result = self.run_job()
        d = result.to_dict()
        for name in ('worker_results_authenticated', 'scientific_equivalence_verified',
                     'visible_glyphs_verified', 'full_accessibility_qualified',
                     'finding_completeness_verified', 'aggregate_job_resources_qualified', 'release_authorized'):
            self.assertIs(d[name], False)
        self.assertEqual(d['release_authorization'], 'NOT_ESTABLISHED')
        self.assertEqual(d['inspection_set']['resource_profile_sha256'], legacy.PROFILE_SHA256)
        self.assertEqual(d['resource_profile_sha256'], self.m.PROFILE_SHA256)

    def test_manifest_existing_limits_and_documentation_are_preserved(self):
        """Profile pins and docs preserve distinct inner/outer policies without default activation."""
        from reporting._pdf_content_worker import MAX_PAGES
        m = json.loads((ROOT / 'reporting/pdf-source-inspection-job.v1.json').read_text())
        self.assertEqual(MAX_PAGES, 32); self.assertEqual(legacy.MAX_PAGES, 64)
        self.assertEqual(m['profile'], self.m.source_inspection_job_profile())
        self.assertEqual(m['profile_sha256'], self.m.PROFILE_SHA256)
        self.assertFalse(m['default_pipeline_activated'])
        self.assertFalse(m['release_authorized'])
        for p in ('reporting/pdf_source_inspection_job.py', 'tests/test_reporting_pdf_source_inspection_job.py'):
            tree = ast.parse((ROOT / p).read_text())
            for n in ast.walk(tree):
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.assertTrue(ast.get_docstring(n), f'{p}:{n.name}')


if __name__ == '__main__':
    unittest.main()
