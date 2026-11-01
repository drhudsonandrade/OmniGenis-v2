"""Bind real generated candidates to complete native/source inspection without release."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import importlib
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from reporting import adapters


ROOT = Path(__file__).resolve().parents[1]


def canonical(value):
    """Use the specified canonical JSON encoding for independent fixture identities."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def source(count=1):
    """Every observation is distinct, synthetic and explicitly required by the source."""
    return {'report_id': 'SYNTHETIC-GENERATED-SOURCE-JOB', 'locale_id': 'en-US',
            'components': [{'component_type': 'semantic-section', 'component_id': 'observations',
                'title': 'Synthetic technical observations', 'state': 'PRESENT',
                'content': {'observations': [
                    f'Observation {number:04d}: controlled synthetic technical finding {number:04d} with source identity preserved.'
                    for number in range(1, count + 1)]}}]}


def expected_text_digest(ir):
    """Independently enumerate the literal text contract, not the product's builder."""
    component = ir['components'][0]
    text = (ir['report_id'] + component['title'] + component['state']
            + canonical(component['content']).decode('utf-8'))
    text = text.replace('\r', '').replace('\n', '').replace('\f', '')
    return sha256(text.encode()).hexdigest()


class GeneratedSourceJobTests(unittest.TestCase):
    """No caller receipt, partial result or implicit release may cross this entrypoint."""

    _cases = {}
    _foreign = None

    def setUp(self):
        """Assert the missing public behavior before importing or generating fixtures."""
        self.assertIsNotNone(importlib.util.find_spec('reporting.pdf_generated_source_job'),
                             'generated source bridge module is missing')
        self.m = importlib.import_module('reporting.pdf_generated_source_job')
        self.assertTrue(callable(getattr(self.m, 'execute_pdf_generated_source_job', None)),
                        'generated source bridge entrypoint is missing')
        self.ir = source()

    def arguments(self, ir=None, **changes):
        """Bind an actual source and actual synthetic request, without invented receipt pins."""
        ir = deepcopy(self.ir) if ir is None else ir
        digest = sha256(canonical(ir)).hexdigest()
        request = {'namespace_id': 'synthetic-namespace', 'job_id': 'synthetic-generated-job',
                   'language': 'en-US', 'ir_sha256': digest,
                   'resource_profile_sha256': self.m.PROFILE_SHA256}
        return {'presentation_ir': ir, 'expected_ir_sha256': digest, 'expected_language': 'en-US',
                'namespace_id': request['namespace_id'], 'job_id': request['job_id'],
                'request_sha256': sha256(canonical(request)).hexdigest(),
                'expected_resource_profile_sha256': self.m.PROFILE_SHA256, **changes}

    def run_job(self, ir=None, **changes):
        """Exercise only the new public entrypoint with trusted independent expectations."""
        return self.m.execute_pdf_generated_source_job(**self.arguments(ir, **changes))

    def real_case(self, count=2):
        """Retain fixed admitted sources; one-observation /ID refusal has a separate test."""
        if count not in type(self)._cases:
            ir = source(count)
            before = canonical(ir)
            result = self.run_job(ir)
            self.assertEqual(canonical(ir), before)
            type(self)._cases[count] = (before, result)
        before, result = type(self)._cases[count]
        return json.loads(before), result

    def test_natural_long_candidate_uses_same_bytes_and_all_pages(self):
        """Real generation, not a patched renderer or PDF fixture, must cross the page boundary."""
        ir, result = self.real_case(1200)
        record = result.to_dict()
        self.assertEqual(record['status'], 'GENERATED_CANDIDATE_AND_NATIVE_SOURCE_BOUND')
        self.assertGreater(result.page_count, 32)
        self.assertLessEqual(result.page_count, 64)
        self.assertEqual(result.pdf_sha256, sha256(result.pdf_bytes).hexdigest())
        self.assertEqual(record['ir_sha256'], sha256(canonical(ir)).hexdigest())
        self.assertEqual(record['expected_text_sha256'], expected_text_digest(ir))
        native = record['native_inspection']
        self.assertEqual(native['pdf_sha256'], result.pdf_sha256)
        self.assertEqual(native['page_count'], result.page_count)
        self.assertEqual(native['ir_sha256'], record['ir_sha256'])
        self.assertEqual(native['expected_text_sha256'], expected_text_digest(ir))
        self.assertTrue(native['normalized_text_equivalence_verified'])
        bundle = native['structured_inspection']['source_inspection']['inspection_set']['page_bundle']
        for name in ('text_stream', 'raster_stream'):
            stream = bundle[name]
            self.assertEqual(stream['represented_pages'], result.page_count)
            pages = [page for item in stream['receipts']
                     for page in range(item['first_page'], item['last_page'] + 1)]
            self.assertEqual(pages, list(range(1, result.page_count + 1)))
        self.assertEqual(len(ir['components'][0]['content']['observations']), 1200)
        self.assertTrue(ir['components'][0]['content']['observations'][-1].startswith('Observation 1200:'))
        self.assertLess(len(result.pdf_bytes), 8 * 1024 * 1024,
                        'This case is page integration evidence, not an above-8-MiB qualification')

    def test_default_still_withholds_same_natural_long_source(self):
        """Adding the opt-in bridge cannot widen default 32-page readiness."""
        ir, _result = self.real_case(1200)
        default = adapters.build_html_css_and_pdf_adapter(presentation_ir=ir)
        self.assertFalse(default.passed)
        self.assertEqual(default.pdf_status, 'DISABLED')
        self.assertEqual(default.pdf_reason, 'pdf_candidate_qa_blocked')
        self.assertIsNone(default.pdf_bytes)
        self.assertIsNone(default.pdf_sha256)

    def test_default_small_candidate_and_optional_render_have_identical_pdf_bytes(self):
        """Shared HTML extraction must preserve legacy output for the existing small profile."""
        ir, result = self.real_case()
        default = adapters.build_html_css_and_pdf_adapter(presentation_ir=ir)
        self.assertTrue(default.passed, default.errors)
        self.assertEqual(default.pdf_bytes, result.pdf_bytes)
        self.assertEqual(default.html_sha256, result.to_dict()['html_sha256'])

    def test_default_ready_does_not_override_inherited_native_identifier_refusal(self):
        """The existing native subset can reject a valid in-budget default candidate."""
        from io import BytesIO
        from pypdf import PdfReader
        from pypdf.generic import ByteStringObject, TextStringObject
        ir = source(1)
        default = adapters.build_html_css_and_pdf_adapter(presentation_ir=ir)
        self.assertTrue(default.passed, default.errors)
        self.assertEqual(default.pdf_status, 'READY')
        ids = PdfReader(BytesIO(default.pdf_bytes), strict=True).trailer.raw_get('/ID')
        self.assertIs(type(ids[0]), ByteStringObject)
        self.assertIs(type(ids[1]), TextStringObject)
        self.assertEqual([len(value) for value in ids], [32, 32])
        with self.assertRaisesRegex(self.m.PdfGeneratedSourceJobError,
                                    '^pdf_generated_source_job_execution_failed$'):
            self.run_job(ir)

    def test_no_release_or_complete_qualification_is_added(self):
        """A true native PASS still cannot be presented as FINAL or whole-job qualification."""
        _ir, result = self.real_case()
        record = result.to_dict()
        for field in ('release_authorized', 'default_pipeline_activated',
                      'aggregate_job_resources_qualified', 'hard_job_deadline_enforced',
                      'full_accessibility_qualified', 'finding_completeness_verified',
                      'scientific_equivalence_verified', 'authenticated_worker_execution',
                      'semantic_roles_qualified', 'visible_glyphs_verified'):
            self.assertIn(field, record)
            self.assertIs(record[field], False, field)
        self.assertEqual(record['release_authorization'], 'NOT_ESTABLISHED')
        self.assertNotIn(b'Observation 0001:', result.to_bytes())
        self.assertNotIn(b'%PDF-', result.to_bytes())
        self.assertNotIn('pdf_bytes', record)
        self.assertNotIn('Observation', repr(result))

    def test_bad_expected_identity_fails_before_rendering(self):
        """Invalid source, locale, job or outer profile must not consume native work."""
        changes = [
            {'expected_ir_sha256': '0' * 64}, {'expected_ir_sha256': True},
            {'expected_language': 'pt-BR'}, {'expected_language': None},
            {'namespace_id': ''}, {'job_id': ''}, {'request_sha256': 'X' * 64},
            {'expected_resource_profile_sha256': '0' * 64},
        ]
        for change in changes:
            with self.subTest(change=change), patch.object(self.m, 'render_pdf_candidate') as render:
                with self.assertRaisesRegex(self.m.PdfGeneratedSourceJobError,
                                            '^pdf_generated_source_job_input_invalid$'):
                    self.run_job(**change)
            render.assert_not_called()

    def test_unsupported_or_oversized_source_fails_before_rendering(self):
        """The new output class cannot silently widen source, component or locale contracts."""
        cases = []
        ir = source(); ir['locale_id'] = 'fr-FR'; cases.append(ir)
        ir = source(); ir['components'][0]['component_type'] = 'document-title'; cases.append(ir)
        ir = source(); ir['components'].append(deepcopy(ir['components'][0])); cases.append(ir)
        ir = source(); ir['components'][0]['content']['value'] = 'x' * (8 * 1024 * 1024 + 1); cases.append(ir)
        ir = source(); ir['components'][0]['content']['value'] = float('nan'); cases.append(ir)
        for ir in cases:
            with self.subTest(locale=ir.get('locale_id')), patch.object(self.m, 'render_pdf_candidate') as render:
                try:
                    args = self.arguments(ir)
                except ValueError:  # NaN is deliberately not canonical JSON.
                    args = self.arguments(source())
                    args['presentation_ir'] = ir
                with self.assertRaisesRegex(self.m.PdfGeneratedSourceJobError,
                                            '^pdf_generated_source_job_input_invalid$'):
                    self.m.execute_pdf_generated_source_job(**args)
            render.assert_not_called()

    def test_all_disables_and_active_native_scope_refuse_before_render(self):
        """An optional bridge cannot bypass the inherited render/native enablement gates."""
        for variable in ('OMNIGENIS_PDF_GENERATED_SOURCE_JOB_DISABLED',
                         'OMNIGENIS_PDF_RENDERER_DISABLED', 'OMNIGENIS_PDF_NATIVE_SOURCE_JOB_DISABLED',
                         'OMNIGENIS_PDF_TOUNICODE_WIDTH_COVERAGE_DISABLED'):
            with self.subTest(variable=variable), patch.dict(os.environ, {variable: '1'}), \
                    patch.object(self.m, 'render_pdf_candidate') as render:
                with self.assertRaises(self.m.PdfGeneratedSourceJobError):
                    self.run_job()
            render.assert_not_called()
        with patch.object(self.m, 'require_no_active_scope', side_effect=ValueError('active')), \
                patch.object(self.m, 'render_pdf_candidate') as render:
            with self.assertRaises(self.m.PdfGeneratedSourceJobError):
                self.run_job()
        render.assert_not_called()

    def test_caller_cannot_supply_pdf_page_receipt_or_executor(self):
        """Only source expectations enter the public generating job."""
        for extra in ('pdf_bytes', 'page_count', 'receipt', 'executor', 'html', 'max_pdf_bytes'):
            with self.subTest(extra=extra), patch.object(self.m, 'render_pdf_candidate') as render:
                with self.assertRaises(TypeError):
                    self.m.execute_pdf_generated_source_job(**self.arguments(), **{extra: None})
            render.assert_not_called()

    def test_original_source_mutation_after_render_blocks_inspection(self):
        """The captured copy does not conceal a persistent mutation in the caller's source."""
        ir, genuine = self.real_case()
        def altered(*_args):
            ir['components'][0]['content']['observations'][0] = 'MUTATED'
            return genuine.rendered_candidate
        with patch.object(self.m, 'render_pdf_candidate', side_effect=altered), \
                patch.object(self.m, 'execute_pdf_native_source_job') as inspect:
            with self.assertRaises(self.m.PdfGeneratedSourceJobError):
                self.run_job(ir)
        inspect.assert_not_called()

    def test_success_looking_render_or_native_dict_cannot_create_candidate(self):
        """A status field is not a typed, sealed result."""
        ir, genuine = self.real_case()
        with patch.object(self.m, 'render_pdf_candidate', return_value={'status': 'PASS'}), \
                patch.object(self.m, 'execute_pdf_native_source_job') as inspect:
            with self.assertRaises(self.m.PdfGeneratedSourceJobError):
                self.run_job(ir)
        inspect.assert_not_called()
        with patch.object(self.m, 'render_pdf_candidate', return_value=genuine.rendered_candidate), \
                patch.object(self.m, 'execute_pdf_native_source_job', return_value={'status': 'PASS'}):
            with self.assertRaises(self.m.PdfGeneratedSourceJobError):
                self.run_job(ir)

    def test_wrong_render_html_identity_blocks_inspection(self):
        """Genuine PDF bytes with another sealed HTML identity are not this source's generation."""
        ir, genuine = self.real_case()
        wrong = replace(genuine.rendered_candidate, html_sha256='0' * 64)
        with patch.object(self.m, 'render_pdf_candidate', return_value=wrong), \
                patch.object(self.m, 'execute_pdf_native_source_job') as inspect:
            with self.assertRaises(self.m.PdfGeneratedSourceJobError):
                self.run_job(ir)
        inspect.assert_not_called()

    def test_forged_render_page_count_is_rejected_by_real_native_inspection(self):
        """Even internally consistent render metadata must match the physical final PDF."""
        ir, genuine = self.real_case()
        self.assertEqual(genuine.page_count, 1)
        wrong = replace(genuine.rendered_candidate, page_count=2)
        with patch.object(self.m, 'render_pdf_candidate', return_value=wrong):
            with self.assertRaises(self.m.PdfGeneratedSourceJobError):
                self.run_job(ir)

    def test_genuine_foreign_job_receipt_is_not_reused(self):
        """A real sealed inspection from another request is still foreign evidence."""
        ir, genuine = self.real_case()
        if type(self)._foreign is None:
            request = {'namespace_id': 'synthetic-namespace', 'job_id': 'synthetic-other-job',
                       'ir_sha256': sha256(canonical(ir)).hexdigest(), 'purpose': 'foreign-binding-test'}
            args = self.arguments(ir, job_id=request['job_id'],
                                  request_sha256=sha256(canonical(request)).hexdigest())
            args['pdf_bytes'] = genuine.pdf_bytes
            args['expected_pdf_sha256'] = genuine.pdf_sha256
            args['page_count'] = genuine.page_count
            args['expected_resource_profile_sha256'] = self.m.NATIVE_SOURCE_PROFILE_SHA256
            type(self)._foreign = self.m.execute_pdf_native_source_job(**args)
        foreign = type(self)._foreign
        self.assertEqual(foreign.to_dict()['job_id'], 'synthetic-other-job')
        foreign_context = {key: foreign.to_dict()[key]
                           for key in ('namespace_id', 'job_id', 'request_sha256')}
        cases = ({**foreign_context, 'namespace_id': 'synthetic-other-namespace'},
                 {**foreign_context, 'job_id': 'synthetic-generated-job'},
                 {**foreign_context, 'request_sha256': self.arguments(ir)['request_sha256']})
        for context in cases:
            with self.subTest(context=context), \
                    patch.object(self.m, 'render_pdf_candidate', return_value=genuine.rendered_candidate), \
                    patch.object(self.m, 'execute_pdf_native_source_job', return_value=foreign):
                with self.assertRaises(self.m.PdfGeneratedSourceJobError):
                    self.run_job(ir, **context)

    def test_retained_result_and_nested_bytes_cannot_be_resealed_or_exposed(self):
        """Serialization and the candidate byte accessor both recheck retained seals."""
        _ir, genuine = self.real_case()
        changed = replace(genuine)
        original = changed.job_id
        object.__setattr__(changed, 'job_id', 'synthetic-other-job')
        for read in (changed.to_dict, changed.to_bytes, changed.__post_init__, lambda: changed.pdf_bytes):
            with self.assertRaises(self.m.PdfGeneratedSourceJobError):
                read()
        object.__setattr__(changed, 'job_id', original)
        rendered = replace(genuine.rendered_candidate)
        object.__setattr__(rendered, '_pdf_bytes', rendered._pdf_bytes[:-1] + b'x')
        for read in (rendered.to_dict, rendered.__post_init__, lambda: rendered.pdf_bytes):
            with self.assertRaises(self.m.PdfGeneratedSourceJobError):
                read()
        for kind in ('rendered_candidate', 'native_inspection'):
            child = replace(getattr(genuine, kind))
            outer = replace(genuine, **{kind: child})
            field = 'html_sha256' if kind == 'rendered_candidate' else 'expected_text_sha256'
            object.__setattr__(child, field, '0' * 64)
            for read in (outer.to_dict, outer.__post_init__, lambda: outer.pdf_bytes):
                with self.subTest(kind=kind), self.assertRaises(self.m.PdfGeneratedSourceJobError):
                    read()

    def test_native_failure_and_post_render_disable_withhold_candidate(self):
        """A complete render never substitutes for the required native stage."""
        ir, genuine = self.real_case()
        with patch.object(self.m, 'render_pdf_candidate', return_value=genuine.rendered_candidate), \
                patch.object(self.m, 'execute_pdf_native_source_job', side_effect=RuntimeError('PRIVATE-CONTENT')):
            with self.assertRaisesRegex(self.m.PdfGeneratedSourceJobError,
                                        '^pdf_generated_source_job_execution_failed$'):
                self.run_job(ir)
        def disable(*_args):
            os.environ['OMNIGENIS_PDF_GENERATED_SOURCE_JOB_DISABLED'] = '1'
            return genuine.rendered_candidate
        with patch.dict(os.environ, {}), patch.object(self.m, 'render_pdf_candidate', side_effect=disable), \
                patch.object(self.m, 'execute_pdf_native_source_job') as inspect:
            with self.assertRaises(self.m.PdfGeneratedSourceJobError):
                self.run_job(ir)
        inspect.assert_not_called()

    def test_acceptance_deadline_cannot_be_recovered_by_render_success(self):
        """A late render result cannot consume the next stage or return a candidate."""
        ir, genuine = self.real_case()
        with patch.object(self.m, 'monotonic_ns', side_effect=(0, 0, 330000000000)), \
                patch.object(self.m, 'render_pdf_candidate', return_value=genuine.rendered_candidate), \
                patch.object(self.m, 'execute_pdf_native_source_job') as inspect:
            with self.assertRaises(self.m.PdfGeneratedSourceJobError):
                self.run_job(ir)
        inspect.assert_not_called()

    def test_natural_out_of_class_source_never_reaches_inspection(self):
        """Natural overflow is an explicit failure, not a truncated 64-page candidate."""
        with patch.object(self.m, 'execute_pdf_native_source_job') as inspect:
            with self.assertRaises(self.m.PdfGeneratedSourceJobError):
                self.run_job(source(2800))
        inspect.assert_not_called()

    def test_manifest_pins_profile_and_only_actual_source_dependencies(self):
        """Declared profile identity and reused-source bytes must describe the running code."""
        manifest = json.loads((ROOT / 'reporting/pdf-generated-source-job.v1.json').read_text())
        self.assertEqual(manifest['profile'], self.m.generated_source_job_profile())
        self.assertEqual(manifest['profile_sha256'], self.m.PROFILE_SHA256)
        self.assertEqual(manifest['integration_mode'], 'OPTIONAL_EXPLICIT_CALL_ONLY')
        self.assertFalse(manifest['release_authorized'])
        self.assertFalse(manifest['default_pipeline_activated'])
        self.assertEqual(manifest['profile']['max_pages'], 64)
        self.assertEqual(manifest['profile']['max_pdf_bytes'], 16777216)
        self.assertEqual(set(manifest['reused_source_sha256']), {
            'LICENSE', 'THIRD-PARTY-NOTICES.txt', 'requirements-reporting.lock',
            'reporting/adapters.py', 'reporting/_pdf_render_worker.py',
            'reporting/_pdf_process_lifecycle.py', 'reporting/_pdf_process_sandbox.py',
            'reporting/_pdf_native_launch_budget.py', 'reporting/pdf_native_source_job.py',
            'reporting/pdf-native-source-job.v1.json', 'reporting/pdf_generated_source_job.py',
            'reporting/pdf_candidate_qa.py', 'reporting/pdf_content.py',
            'reporting/pdf_inspection_job.py', 'reporting/pdf_inspection_bundle.py',
            'reporting/page_checkpoints.py', 'reporting/page_windows.py',
        })
        for relative, digest in manifest['reused_source_sha256'].items():
            self.assertEqual(sha256((ROOT / relative).read_bytes()).hexdigest(), digest, relative)


if __name__ == '__main__':
    unittest.main()
