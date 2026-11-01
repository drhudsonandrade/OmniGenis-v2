"""Sequential native inspection jobs: exact binding, bounded work and no release."""
from __future__ import annotations

import ast
from contextlib import contextmanager, ExitStack
from dataclasses import replace
from hashlib import sha256
import importlib
import importlib.util
import inspect
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from reporting.pdf_inspection_set import PdfInspectionSet
from reporting.pdf_object_graph import PdfObjectGraphInspection
from reporting.pdf_document_metadata import PdfDocumentMetadataInspection
from reporting.pdf_page_tags import PdfPageTagInspection
from reporting.pdf_mcid_coverage import PdfMcidCoverageInspection
from reporting.pdf_text_windows import PdfTextWindowInspection
from reporting.pdf_raster_windows import PdfRasterWindowInspection

ROOT = Path(__file__).resolve().parents[1]
STAGES = ('inspect_pdf_object_graph', 'inspect_pdf_document_metadata',
          'inspect_pdf_page_tag_parents', 'inspect_pdf_mcid_coverage',
          'inspect_pdf_text_window', 'inspect_pdf_raster_window')


def native_pdf(pages):
    """Generate only synthetic controlled tagged files with no remote asset access."""
    from weasyprint import HTML
    from weasyprint.urls import URLFetcher
    from pypdf import PdfReader
    from io import BytesIO
    if pages not in (1, 33, 64):
        raise ValueError('unsupported native test size')
    html = ('<html lang="en-US"><head><title>OmniGenis</title>'
            '<meta name="author" content="Hudson Silva Andrade">'
            '<meta name="generator" content="OmniGenis"></head><body>'
            + ''.join('<p style="break-before:page">Synthetic job page %d</p>' % i
                      for i in range(1, pages + 1)) + '</body></html>')
    pdf = HTML(string=html, url_fetcher=URLFetcher(allowed_protocols=(),
               allow_redirects=False, fail_on_errors=True)).write_pdf(
                   pdf_variant='pdf/ua-1', pdf_version='1.7',
                   pdf_identifier=bytes.fromhex('a' * 64))
    assert len(PdfReader(BytesIO(pdf), strict=True).pages) == pages
    return pdf


def synthetic_receipt(stage, values):
    """Fabricate receipts only for control-flow tests; these are not native evidence."""
    plan = values['plan']
    identity = {key: getattr(plan, key) for key in
                ('pdf_sha256', 'ir_sha256', 'plan_sha256', 'page_count')}
    if stage == STAGES[0]:
        return PdfObjectGraphInspection(**identity, object_count=4 * plan.page_count)
    if stage == STAGES[1]:
        return PdfDocumentMetadataInspection(**identity)
    if stage == STAGES[2]:
        return PdfPageTagInspection(**identity, tagged_pages=plan.page_count,
                                    parent_tree_entries=plan.page_count)
    if stage == STAGES[3]:
        return PdfMcidCoverageInspection(**identity, matched_mcids=plan.page_count,
            inspected_pages=plan.page_count, decoded_bytes=100 * plan.page_count)
    span = plan.windows[values['window_index']]
    identity.update(window_index=span.index, first_page=span.first_page,
                    last_page=span.last_page)
    count = span.last_page - span.first_page + 1
    if stage == STAGES[4]:
        return PdfTextWindowInspection(**identity, text_sha256='e' * 64,
            text_chars=8 * count, text_bytes=16 * count, decoded_bytes=32 * count)
    return PdfRasterWindowInspection(**identity, raster_sha256='f' * 64,
        total_pixels=100 * count, min_edge_margin_px=2)


class PdfInspectionJobTests(unittest.TestCase):
    """Require ordered real invocation rather than accepting supplied successful records."""

    def setUp(self):
        """Make missing implementation a failing assertion in the RED run."""
        self.assertIsNotNone(importlib.util.find_spec('reporting.pdf_inspection_job'),
                             'sequential PDF inspection job is missing')
        self.m = importlib.import_module('reporting.pdf_inspection_job')
        self.pdf = b'%PDF-1.7\nSYNTHETIC_METADATA_ONLY_TEST\n'
        self.args = dict(pdf_bytes=self.pdf, expected_pdf_sha256=sha256(self.pdf).hexdigest(),
            expected_ir_sha256='b' * 64, page_count=33, expected_language='en-US',
            namespace_id='synthetic-namespace', job_id='synthetic-job',
            request_sha256='c' * 64, expected_resource_profile_sha256=self.m.PROFILE_SHA256)

    def run_job(self, **changes):
        """Call the public boundary with fully explicit primitive inputs."""
        return self.m.execute_pdf_inspection_job(**{**self.args, **changes})

    @contextmanager
    def mocked(self, *, change=None):
        """Replace every native adapter only for deterministic negative controls."""
        calls = []
        with ExitStack() as stack:
            def factory(stage):
                """Capture a single exact stage name for deterministic fake observations."""
                def provider(**values):
                    """Record attempted work and optionally inject a controlled failure."""
                    calls.append((stage, values.get('window_index')))
                    receipt = synthetic_receipt(stage, values)
                    return change(stage, values, receipt) if change else receipt
                return provider
            for name in STAGES:
                stack.enter_context(patch.object(self.m, name, side_effect=factory(name)))
            yield calls

    def test_native_one_thirty_three_and_sixty_four_pages(self):
        """Run all existing inspectors on each exact real synthetic final PDF."""
        for pages in (1, 33, 64):
            with self.subTest(pages=pages):
                pdf = native_pdf(pages)
                result = self.run_job(pdf_bytes=pdf, expected_pdf_sha256=sha256(pdf).hexdigest(),
                                      page_count=pages)
                self.assertIs(type(result), PdfInspectionSet)
                data = result.to_dict()
                self.assertEqual(data['page_count'], pages)
                self.assertEqual(data['pdf_sha256'], sha256(pdf).hexdigest())
                self.assertEqual(data['page_bundle']['text_stream']['represented_pages'], pages)
                self.assertEqual(data['page_bundle']['raster_stream']['represented_pages'], pages)
                self.assertEqual(data['resource_profile_sha256'], self.m.PROFILE_SHA256)
                self.assertFalse(data['release_authorized'])

    def test_exact_sequence_has_no_duplicate_or_omitted_invocation(self):
        """Thirty-three pages require four document calls, three text and nine raster calls."""
        with self.mocked() as calls:
            result = self.run_job()
        expected = [(n, None) for n in STAGES[:4]]
        expected += [(STAGES[4], i) for i in range(3)]
        expected += [(STAGES[5], i) for i in range(9)]
        self.assertEqual(calls, expected)
        self.assertEqual(result.to_dict()['page_count'], 33)

    def test_sixty_four_page_invocation_ceiling_is_exact(self):
        """A fabricated maximum job has twenty-four calls; larger jobs cannot launch."""
        with self.mocked() as calls:
            result = self.run_job(page_count=64)
        self.assertEqual(len(calls), 24)
        self.assertEqual(result.to_dict()['page_count'], 64)
        with self.mocked() as calls, self.assertRaises(self.m.PdfInspectionJobError):
            self.run_job(page_count=65)
        self.assertEqual(calls, [])

    def test_invalid_inputs_are_rejected_before_any_native_call(self):
        """No coercion of mutable bytes, booleans, bad digests or malformed context."""
        bad = [dict(pdf_bytes=bytearray(self.pdf)), dict(pdf_bytes=b'not-pdf'),
               dict(expected_pdf_sha256='d' * 64), dict(expected_pdf_sha256='A' * 64),
               dict(expected_ir_sha256=None), dict(page_count=True), dict(page_count='33'),
               dict(page_count=0), dict(page_count=512), dict(job_id=''),
               dict(namespace_id=None), dict(request_sha256='unknown')]
        for changes in bad:
            with self.subTest(changes=list(changes)), self.mocked() as calls:
                with self.assertRaises(self.m.PdfInspectionJobError):
                    self.run_job(**changes)
                self.assertEqual(calls, [])

    def test_oversized_pdf_is_not_a_partial_job(self):
        """The optional coordinator refuses bytes beyond its explicit sixteen-MiB class."""
        pdf = b'%PDF-1.7\n' + b'0' * 16777208
        with self.mocked() as calls, self.assertRaises(self.m.PdfInspectionJobError):
            self.run_job(pdf_bytes=pdf, expected_pdf_sha256=sha256(pdf).hexdigest())
        self.assertEqual(calls, [])

    def test_wrong_profile_and_unsupported_locale_never_fall_back(self):
        """Caller must explicitly identify this exact profile and the current locale."""
        for changes in (dict(expected_resource_profile_sha256='a' * 64),
                        dict(expected_resource_profile_sha256=True),
                        dict(expected_language='pt-BR'), dict(expected_language=None)):
            with self.mocked() as calls, self.assertRaises(self.m.PdfInspectionJobError):
                self.run_job(**changes)
            self.assertEqual(calls, [])

    def test_first_document_failure_stops_later_inspectors(self):
        """An early failure cannot trigger remaining work or a partial result."""
        def failure(stage, values, result):
            """Raise a synthetic private message at the initial graph boundary."""
            raise RuntimeError('SYNTHETIC_PRIVATE_FAILURE')
        with self.mocked(change=failure) as calls:
            with self.assertRaises(self.m.PdfInspectionJobError) as caught:
                self.run_job()
        self.assertEqual(calls, [(STAGES[0], None)])
        self.assertNotIn('SYNTHETIC_PRIVATE', str(caught.exception))

    def test_failure_at_every_dimension_never_retries(self):
        """Each distinct inspector can block the sequence without retries."""
        for blocked in STAGES:
            def fail(stage, values, receipt):
                """Inject a failure at exactly one selected adapter."""
                if stage == blocked:
                    raise RuntimeError('synthetic failure')
                return receipt
            with self.subTest(stage=blocked), self.mocked(change=fail) as calls:
                with self.assertRaises(self.m.PdfInspectionJobError):
                    self.run_job()
                self.assertEqual(calls[-1][0], blocked)
                self.assertEqual(sum(name == blocked for name, _ in calls), 1)

    def test_midwindow_failure_does_not_continue_to_raster(self):
        """A failed second text window does not retry or start pixel inspection."""
        def fail(stage, values, receipt):
            """Fail one specific synthetic text interval."""
            if stage == STAGES[4] and values['window_index'] == 1:
                raise TimeoutError('synthetic timeout')
            return receipt
        with self.mocked(change=fail) as calls, self.assertRaises(self.m.PdfInspectionJobError):
            self.run_job()
        self.assertEqual(calls[-1], (STAGES[4], 1))
        self.assertFalse(any(name == STAGES[5] for name, _ in calls))

    def test_untyped_and_foreign_receipts_fail_before_next_stage(self):
        """Generic PASS dictionaries and wrong document/IR/plan identities are not observations."""
        for field in (None, 'pdf_sha256', 'ir_sha256', 'plan_sha256'):
            def bad(stage, values, receipt):
                """Change only the first synthetic adapter response."""
                return {'status': 'PASS'} if field is None else replace(receipt, **{field: 'a' * 64})
            with self.mocked(change=bad) as calls, self.assertRaises(self.m.PdfInspectionJobError):
                self.run_job()
            self.assertEqual(len(calls), 1)

    def test_window_identity_is_checked_before_next_window(self):
        """An otherwise valid observation for a different window is rejected immediately."""
        def changed(stage, values, receipt):
            """Replace the first text result with another valid same-document interval."""
            if stage == STAGES[4] and values['window_index'] == 0:
                altered = {**values, 'window_index': 1}
                return synthetic_receipt(stage, altered)
            return receipt
        with self.mocked(change=changed) as calls, self.assertRaises(self.m.PdfInspectionJobError):
            self.run_job()
        self.assertEqual(calls[-1], (STAGES[4], 0))

    def test_deadline_exceeded_before_first_call_prevents_execution(self):
        """Deadline admission is checked after capture and before any adapter starts."""
        with self.mocked() as calls, patch.object(self.m, 'monotonic_ns',
                side_effect=[0, 300000000001]):
            with self.assertRaises(self.m.PdfInspectionJobError):
                self.run_job()
        self.assertEqual(calls, [])

    def test_deadline_exceeded_during_call_rejects_result_and_next_stage(self):
        """The acceptance deadline rejects a late return; it does not claim preemption."""
        clock = [0]
        def elapsed(stage, values, receipt):
            """Simulate elapsed time inside a synchronous adapter invocation."""
            clock[0] = 300000000000
            return receipt
        with self.mocked(change=elapsed) as calls, patch.object(self.m, 'monotonic_ns',
                side_effect=lambda: clock[0]):
            with self.assertRaises(self.m.PdfInspectionJobError):
                self.run_job()
        self.assertEqual(calls, [(STAGES[0], None)])

    def test_regressing_or_noninteger_clock_cannot_authorize_work(self):
        """Clock failure, regression and boolean readings fail closed."""
        for clock in ([10, 9], [True], [None], [-1]):
            with self.mocked() as calls, patch.object(self.m, 'monotonic_ns', side_effect=clock):
                with self.assertRaises(self.m.PdfInspectionJobError):
                    self.run_job()
            self.assertEqual(calls, [])

    def test_disable_at_start_prevents_any_native_call(self):
        """The coordinator can be disabled independently of every unchanged adapter."""
        with self.mocked() as calls, patch.dict('os.environ', {'OMNIGENIS_PDF_INSPECTION_JOB_DISABLED': '1'}):
            with self.assertRaises(self.m.PdfInspectionJobError):
                self.run_job()
        self.assertEqual(calls, [])

    def test_disable_between_calls_discards_completed_partial_work(self):
        """A changed disable setting cannot leave a successful partial inspection set."""
        import os
        def stop(stage, values, receipt):
            """Simulate disabling the job after one bounded adapter returns."""
            os.environ['OMNIGENIS_PDF_INSPECTION_JOB_DISABLED'] = '1'
            return receipt
        with patch.dict('os.environ', {}, clear=False), self.mocked(change=stop) as calls:
            with self.assertRaises(self.m.PdfInspectionJobError):
                self.run_job()
        self.assertEqual(len(calls), 1)

    def test_complete_result_retains_all_conservative_scope_flags(self):
        """Coordinating inspectors does not turn unsigned records into release evidence."""
        with self.mocked():
            data = self.run_job().to_dict()
        for flag in ('worker_results_authenticated', 'whole_pdf_safety_qualified',
                     'finding_completeness_verified', 'text_equivalence_verified',
                     'accessibility_qualified', 'aggregate_job_resources_qualified', 'release_authorized'):
            self.assertIs(data[flag], False)
        self.assertEqual(data['release_authorization'], 'NOT_ESTABLISHED')

    def test_job_namespace_request_and_profile_are_bound(self):
        """Only caller-supplied primitive job context is used for both in-memory checkpoints."""
        with self.mocked():
            data = self.run_job().to_dict()
        for field in ('namespace_id', 'job_id', 'request_sha256'):
            self.assertEqual(data[field], self.args[field])
        self.assertEqual(data['resource_profile_sha256'], self.m.PROFILE_SHA256)
        self.assertEqual(data['ir_sha256'], self.args['expected_ir_sha256'])

    def test_results_are_deterministic_detached_and_revalidated(self):
        """The new runner returns the existing sealed result, not cached mutable data."""
        with self.mocked():
            first, second = self.run_job(), self.run_job()
        self.assertEqual(first.to_bytes(), second.to_bytes())
        self.assertEqual(first.inspection_set_sha256, sha256(first.to_bytes()).hexdigest())
        output = first.to_dict()
        output['job_id'] = 'changed-output-only'
        self.assertEqual(first.to_dict()['job_id'], self.args['job_id'])
        object.__setattr__(first.mcid_coverage, 'matched_mcids', 0)
        with self.assertRaises(ValueError):
            first.to_bytes()

    def test_no_pdf_parser_runs_in_coordinator_process(self):
        """The actual one-page path parses untrusted PDF bytes only in existing workers."""
        from pypdf import PdfReader
        pdf = native_pdf(1)
        with patch.object(PdfReader, '__init__', side_effect=AssertionError('host parser')):
            result = self.run_job(pdf_bytes=pdf, expected_pdf_sha256=sha256(pdf).hexdigest(), page_count=1)
        self.assertEqual(result.to_dict()['page_count'], 1)

    def test_fake_receipts_are_not_a_public_runner_parameter(self):
        """The execution API has no injected executor, receipt, retry or resume escape."""
        params = inspect.signature(self.m.execute_pdf_inspection_job).parameters
        self.assertEqual(set(params), set(self.args))
        self.assertTrue(all(v.kind == inspect.Parameter.KEYWORD_ONLY for v in params.values()))

    def test_manifest_matches_profile_and_unchanged_dependencies(self):
        """The fixed optional profile is externally hash-pinnable and documents its limits."""
        manifest = json.loads((ROOT / 'reporting/pdf-inspection-job.v1.json').read_text())
        self.assertEqual(manifest['profile'], self.m.inspection_job_profile())
        self.assertEqual(manifest['profile_sha256'], self.m.PROFILE_SHA256)
        self.assertFalse(manifest['default_pipeline_activated'])
        self.assertFalse(manifest['release_authorized'])
        self.assertFalse(manifest['hard_job_deadline_enforced'])
        self.assertEqual(manifest['profile']['max_pages'], 64)
        self.assertEqual(manifest['profile']['max_inspector_invocations'], 24)
        for name, digest in manifest['reused_source_sha256'].items():
            self.assertEqual(sha256((ROOT / name).read_bytes()).hexdigest(), digest)

    def test_profile_values_are_detached_and_cannot_widen_execution(self):
        """Changing a returned profile does not change the pinned execution contract."""
        record = self.m.inspection_job_profile()
        record['max_pages'] = 512
        self.assertEqual(self.m.inspection_job_profile()['max_pages'], 64)
        with patch.object(self.m, 'MAX_PAGES', 512), self.mocked() as calls:
            with self.assertRaises(self.m.PdfInspectionJobError):
                self.run_job()
        self.assertEqual(calls, [])

    def test_default_limits_and_documentation_are_preserved(self):
        """No default activation or undocumented added functions accompany the runner."""
        from reporting._pdf_safety_worker import MAX_PAGES
        self.assertEqual(MAX_PAGES, 32)
        for relative in ('reporting/pdf_inspection_job.py', 'tests/test_reporting_pdf_inspection_job.py'):
            parsed = ast.parse((ROOT / relative).read_text())
            for node in ast.walk(parsed):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    self.assertIsNotNone(ast.get_docstring(node), (relative, node.name))


if __name__ == '__main__':
    unittest.main()
