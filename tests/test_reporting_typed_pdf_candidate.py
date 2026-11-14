"""Same-PDF typed candidate integration with synthetic native and failure controls."""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
import copy
import importlib
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator
from reporting.typed_pdf_source import prepare_typed_pdf_source
from reporting.pdf_typed_observation import TypedPdfObservation
from test_reporting_typed_pdf_source import digest
from test_reporting_typed_pdf_association import declarations

ROOT = Path(__file__).resolve().parents[1]
STAGES = ('render_pdf_candidate', 'observe_typed_pdf', 'associate_typed_pdf',
          'inspect_pdf_raster_window')


def encoded(value):
    """Independently encode the declared canonical metadata convention."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


class TypedPdfCandidateTests(unittest.TestCase):
    """Private candidates require complete real stages; unsigned evidence is narrow."""

    fixtures = {}

    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('reporting.typed_pdf_candidate'),
                             'complete same-PDF typed candidate is missing')
        self.m = importlib.import_module('reporting.typed_pdf_candidate')

    def inputs(self, source=None):
        source = declarations('empty') if source is None else source
        ir_sha = digest(source)
        expectation = prepare_typed_pdf_source(
            presentation_ir=source, expected_ir_sha256=ir_sha)
        profile = json.loads((ROOT / 'reporting/pdf-typed-candidate.v1.json').read_bytes())
        return dict(presentation_ir=source, expected_ir_sha256=ir_sha,
                    expected_source_expectation_sha256=expectation.expectation_sha256,
                    expected_profile_sha256=sha256(encoded(profile)).hexdigest())

    def case(self, name='empty'):
        if name not in self.fixtures:
            inputs = self.inputs(declarations(name))
            calls, outputs = [], {key: [] for key in STAGES}

            def observe_call(key, function):
                def call(*args, **kwargs):
                    calls.append((key, args, kwargs))
                    value = function(*args, **kwargs)
                    outputs[key].append(value)
                    return value
                return call

            with ExitStack() as stack:
                for key in STAGES:
                    stack.enter_context(patch.object(
                        self.m, key, side_effect=observe_call(key, getattr(self.m, key))))
                candidate = self.m.prepare_typed_pdf_candidate(**inputs)
            self.fixtures[name] = dict(inputs=inputs, candidate=candidate,
                                       calls=calls, outputs=outputs)
        return self.fixtures[name]

    def replay(self, *, name='empty', substitutions=None, constructor=False):
        """Substitute already captured synthetic receipts; do not repeat native jobs."""
        case = self.case(name)
        outputs = {key: list(value) for key, value in case['outputs'].items()}
        outputs.update(substitutions or {})
        with ExitStack() as stack:
            mocks = {key: stack.enter_context(patch.object(self.m, key, side_effect=value))
                     for key, value in outputs.items()}
            self.last_mocks = mocks
            operation = (self.m.TypedPdfCandidate if constructor
                         else self.m.prepare_typed_pdf_candidate)
            return operation(**copy.deepcopy(case['inputs']))

    def refused(self, **kwargs):
        with self.assertRaisesRegex(self.m.TypedPdfCandidateError,
                                    '^typed_pdf_candidate_refused$'):
            self.replay(**kwargs)

    def test_native_empty_table_completes_the_same_pdf(self):
        case = self.case()
        result = case['candidate'].to_dict()
        self.assertEqual(result['page_count'], 1)
        self.assertEqual(result['source_counts']['table_rows'], 0)
        self.assertEqual(result['pdf_sha256'], sha256(case['candidate'].pdf_bytes).hexdigest())
        self.assertEqual([c[0] for c in case['calls']], list(STAGES))
        for _, _, kwargs in case['calls'][1:2] + case['calls'][3:]:
            self.assertIs(kwargs['pdf_bytes'], case['candidate'].pdf_bytes)
        self.assertEqual(result['raster_inspected_pages'], 1)

    def test_native_split_row_covers_full_and_partial_windows(self):
        case = self.case('row')
        result = case['candidate'].to_dict()
        self.assertEqual(result['page_count'], 5)
        self.assertEqual([(r['first_page'], r['last_page'])
                          for r in result['raster_windows']], [(1, 4), (5, 5)])
        self.assertEqual(result['source_counts']['table_rows'], 1)
        self.assertEqual(result['raster_inspected_pages'], 5)
        self.assertEqual(result['raster_window_count'], 2)
        self.assertEqual([c[2]['window_index'] for c in case['calls']
                          if c[0] == 'inspect_pdf_raster_window'], [0, 1])
        self.assertEqual(result['declared_process_schedule']['total'], 11)
        self.assertFalse(result['declared_process_schedule']['execution_authenticated'])

    def test_native_96_rows_retains_every_finding(self):
        result = self.case('long')['candidate'].to_dict()
        self.assertEqual(result['source_counts']['table_rows'], 96)
        self.assertEqual(result['source_counts']['represented_findings'], 96)
        self.assertGreater(result['page_count'], 1)
        self.assertEqual(result['raster_inspected_pages'], result['page_count'])

    def test_native_literal_loss_refuses_before_any_raster(self):
        inputs = self.inputs(declarations('controls'))
        with patch.object(self.m, 'render_pdf_candidate',
                          wraps=self.m.render_pdf_candidate) as render, \
                patch.object(self.m, 'observe_typed_pdf',
                             wraps=self.m.observe_typed_pdf) as observe, \
                patch.object(self.m, 'associate_typed_pdf',
                             wraps=self.m.associate_typed_pdf) as associate, \
                patch.object(self.m, 'inspect_pdf_raster_window') as raster:
            with self.assertRaisesRegex(self.m.TypedPdfCandidateError,
                                        '^typed_pdf_candidate_refused$'):
                self.m.prepare_typed_pdf_candidate(**inputs)
        self.assertEqual((render.call_count, observe.call_count, associate.call_count), (1, 1, 1))
        raster.assert_not_called()

    def test_bad_input_digests_refuse_before_render(self):
        for field in ('expected_ir_sha256', 'expected_source_expectation_sha256',
                      'expected_profile_sha256'):
            for value in (None, True, '0' * 64, ' ' + 'a' * 64):
                with self.subTest(field=field, value=value):
                    inputs = self.inputs()
                    inputs[field] = value
                    with patch.object(self.m, 'render_pdf_candidate') as render:
                        with self.assertRaises(self.m.TypedPdfCandidateError):
                            self.m.prepare_typed_pdf_candidate(**inputs)
                    render.assert_not_called()

    def test_unsupported_locale_refuses_before_render(self):
        inputs = self.inputs()
        inputs['presentation_ir']['locale_id'] = 'pt-BR'
        inputs['expected_ir_sha256'] = digest(inputs['presentation_ir'])
        with patch.object(self.m, 'render_pdf_candidate') as render:
            with self.assertRaises(self.m.TypedPdfCandidateError):
                self.m.prepare_typed_pdf_candidate(**inputs)
        render.assert_not_called()

    def test_no_caller_pdf_html_receipts_or_pass_options(self):
        for field, value in (('pdf_bytes', b'%PDF-1.7'), ('html', '<h1>Injected</h1>'),
                             ('evidence', {'status': 'PASS'}), ('passed', True),
                             ('pages_per_window', 32), ('output_path', '/tmp/unused')):
            with self.subTest(field=field), patch.object(self.m, 'render_pdf_candidate') as render:
                with self.assertRaises(TypeError):
                    self.m.prepare_typed_pdf_candidate(**self.inputs(), **{field: value})
                render.assert_not_called()

    def test_all_declared_disable_flags_refuse_before_render(self):
        for flag in ('OMNIGENIS_TYPED_PDF_CANDIDATE_DISABLED',
                     'OMNIGENIS_PDF_RENDERER_DISABLED',
                     'OMNIGENIS_TYPED_PDF_OBSERVATION_DISABLED',
                     'OMNIGENIS_PDF_RASTER_WINDOWS_DISABLED'):
            with self.subTest(flag=flag), patch.dict(os.environ, {flag: '1'}), \
                    patch.object(self.m, 'render_pdf_candidate') as render:
                with self.assertRaises(self.m.TypedPdfCandidateError):
                    self.m.prepare_typed_pdf_candidate(**self.inputs())
                render.assert_not_called()

    def test_active_native_scope_guard_runs_before_render(self):
        with patch.object(self.m, 'require_no_active_scope',
                          side_effect=ValueError('blocked scope')) as guard, \
                patch.object(self.m, 'render_pdf_candidate') as render:
            with self.assertRaises(self.m.TypedPdfCandidateError):
                self.m.prepare_typed_pdf_candidate(**self.inputs())
        guard.assert_called_once()
        render.assert_not_called()

    def test_each_stage_failure_stops_without_retry(self):
        for index, stage in enumerate(STAGES):
            with self.subTest(stage=stage):
                self.refused(substitutions={stage: RuntimeError('PRIVATE-CONTENT')})
                self.assertEqual(self.last_mocks[stage].call_count, 1)
                for later in STAGES[index + 1:]:
                    self.last_mocks[later].assert_not_called()

    def test_final_raster_failure_exposes_no_partial_candidate(self):
        first = self.case('row')['outputs']['inspect_pdf_raster_window'][0]
        self.refused(name='row', substitutions={
            'inspect_pdf_raster_window': [first, RuntimeError('last window failure')]})
        self.assertEqual(self.last_mocks['inspect_pdf_raster_window'].call_count, 2)

    def test_render_html_identity_mismatch_refuses_before_observation(self):
        rendered = self.case()['outputs']['render_pdf_candidate'][0]
        self.refused(substitutions={'render_pdf_candidate': [replace(rendered, html_sha256='0' * 64)]})
        self.last_mocks['observe_typed_pdf'].assert_not_called()

    def test_render_page_count_mismatch_refuses_before_raster(self):
        rendered = self.case()['outputs']['render_pdf_candidate'][0]
        self.refused(substitutions={'render_pdf_candidate': [replace(rendered, page_count=2)]})
        self.last_mocks['inspect_pdf_raster_window'].assert_not_called()

    def test_foreign_observation_refuses_before_association(self):
        foreign = self.case('row')['outputs']['observe_typed_pdf'][0]
        self.refused(substitutions={'observe_typed_pdf': [foreign]})
        self.last_mocks['associate_typed_pdf'].assert_not_called()

    def test_oversized_forged_observation_refuses_before_association(self):
        forged = object.__new__(TypedPdfObservation)
        object.__setattr__(forged, '_payload', b' ' * (4194304 + 1))
        self.refused(substitutions={'observe_typed_pdf': [forged]})
        self.last_mocks['associate_typed_pdf'].assert_not_called()

    def test_wrong_stage_result_types_are_refused(self):
        for stage in STAGES:
            for bad in (True, None, {'status': 'PASS'}):
                with self.subTest(stage=stage, bad=bad):
                    self.refused(substitutions={stage: [bad]})

    def test_foreign_association_refuses_before_raster(self):
        foreign = self.case('row')['outputs']['associate_typed_pdf'][0]
        self.refused(substitutions={'associate_typed_pdf': [foreign]})
        self.last_mocks['inspect_pdf_raster_window'].assert_not_called()

    def test_raster_ir_and_page_count_are_checked_before_ledger_projection(self):
        receipt = self.case()['outputs']['inspect_pdf_raster_window'][0]
        for changes in ({'ir_sha256': '0' * 64}, {'page_count': 2}):
            with self.subTest(changes=changes):
                self.refused(substitutions={
                    'inspect_pdf_raster_window': [replace(receipt, **changes)]})

    def test_raster_pdf_and_plan_identity_must_match(self):
        receipt = self.case()['outputs']['inspect_pdf_raster_window'][0]
        for key in ('pdf_sha256', 'plan_sha256'):
            with self.subTest(key=key):
                self.refused(substitutions={
                    'inspect_pdf_raster_window': [replace(receipt, **{key: '0' * 64})]})

    def test_duplicate_and_reordered_raster_windows_refuse(self):
        first, last = self.case('row')['outputs']['inspect_pdf_raster_window']
        for receipts in ([first, first], [last, first]):
            with self.subTest(order=[x.window_index for x in receipts]):
                self.refused(name='row', substitutions={'inspect_pdf_raster_window': receipts})

    def test_missing_raster_window_refuses(self):
        first = self.case('row')['outputs']['inspect_pdf_raster_window'][0]
        self.refused(name='row', substitutions={'inspect_pdf_raster_window': [first]})

    def test_failed_binding_ledger_refuses_complete_result(self):
        with patch.object(self.m, 'bind_pdf_page_window_evidence',
                          side_effect=ValueError('missing range')):
            self.refused()

    def test_detached_metadata_and_frozen_result(self):
        candidate = self.case()['candidate']
        raw = candidate.to_bytes()
        exported = candidate.to_dict()
        exported['raster_windows'][0]['pdf_sha256'] = '0' * 64
        self.assertEqual(candidate.to_bytes(), raw)
        self.assertEqual(candidate.candidate_sha256, sha256(raw).hexdigest())
        with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
            candidate._pdf_bytes = b'changed'

    def test_retained_pdf_and_evidence_tampering_are_refused(self):
        original = self.case()['candidate']
        for slot, value in (('_pdf_bytes', original.pdf_bytes + b'\n'),
                            ('_payload', original.to_bytes() + b' ')):
            candidate = copy.copy(original)
            object.__setattr__(candidate, slot, value)
            with self.subTest(slot=slot), self.assertRaises(self.m.TypedPdfCandidateError):
                candidate.to_dict()

    def test_forged_unbounded_candidate_slots_are_refused(self):
        candidate = object.__new__(self.m.TypedPdfCandidate)
        object.__setattr__(candidate, '_pdf_bytes', b'%PDF-1.7')
        object.__setattr__(candidate, '_payload', b' ' * (65536 + 1))
        with self.assertRaises(self.m.TypedPdfCandidateError):
            candidate.to_bytes()

    def test_result_is_bounded_canonical_and_content_free(self):
        candidate = self.case('row')['candidate']
        raw = candidate.to_bytes()
        self.assertEqual(encoded(json.loads(raw)), raw)
        self.assertLessEqual(len(raw), 65536)
        for text in (b'SYNTHETIC-CASE', b'Technical report', b'NM_000001', b'R0000'):
            self.assertNotIn(text, raw)
            self.assertNotIn(text.decode(), repr(candidate))

    def test_narrow_claims_do_not_authorize_release(self):
        result = self.case()['candidate'].to_dict()
        positive = {'literal_source_associated', 'effective_typed_graph_policy_checked',
                    'all_pages_raster_geometry_inspected'}
        self.assertEqual({k for k, v in result['claims'].items() if v is True}, positive)
        self.assertTrue(all(type(v) is bool for v in result['claims'].values()))
        self.assertEqual(result['release_authorization'], 'NOT_ESTABLISHED')
        self.assertFalse(result['claims']['aggregate_job_resources_qualified'])
        self.assertFalse(result['claims']['visual_semantics_verified'])
        self.assertFalse(result['claims']['release_authorized'])

    def test_closed_schema_accepts_native_and_rejects_expanded_claims(self):
        schema = json.loads((ROOT / 'schemas/report-typed-pdf-candidate.v1.schema.json').read_bytes())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        valid = self.case()['candidate'].to_dict()
        self.assertEqual(list(validator.iter_errors(valid)), [])
        for field in ('release_authorized', 'visual_semantics_verified', 'accessibility_qualified'):
            expanded = copy.deepcopy(valid)
            expanded['claims'][field] = True
            self.assertTrue(list(validator.iter_errors(expanded)))
        expanded = dict(valid, unexpected=True)
        self.assertTrue(list(validator.iter_errors(expanded)))

    def test_separate_html_identities_and_all_upstream_digests(self):
        case = self.case()
        data = case['candidate'].to_dict()
        self.assertNotEqual(data['typed_html_sha256'], data['html_sha256'])
        self.assertEqual(data['ir_sha256'], case['inputs']['expected_ir_sha256'])
        self.assertEqual(data['source_expectation_sha256'],
                         case['inputs']['expected_source_expectation_sha256'])
        self.assertEqual(data['render_result_sha256'],
                         case['outputs']['render_pdf_candidate'][0].result_sha256)
        self.assertEqual(data['association_sha256'],
                         case['outputs']['associate_typed_pdf'][0].association_sha256)

    def test_direct_construction_runs_the_complete_boundary(self):
        candidate = self.replay(constructor=True)
        self.assertEqual(candidate.to_bytes(), self.case()['candidate'].to_bytes())
        self.assertEqual([self.last_mocks[key].call_count for key in STAGES], [1, 1, 1, 1])

    def forged(self, data, pdf=None):
        """Build bounded malformed retained evidence without claiming native execution."""
        pdf = self.case()['candidate'].pdf_bytes if pdf is None else pdf
        result = object.__new__(self.m.TypedPdfCandidate)
        payload = encoded(data)
        object.__setattr__(result, '_pdf_bytes', pdf)
        object.__setattr__(result, '_payload', payload)
        object.__setattr__(result, '_sealed_sha256', sha256(payload).hexdigest())
        return result

    def test_bounded_minimal_forged_candidate_is_refused(self):
        pdf = b'%PDF-1.7'
        data = {'pdf_sha256': sha256(pdf).hexdigest(), 'pdf_byte_count': len(pdf),
                'profile_sha256': self.inputs()['expected_profile_sha256']}
        candidate = self.forged(data, pdf)
        with self.assertRaises(self.m.TypedPdfCandidateError):
            candidate.pdf_bytes

    def test_rehashed_expanded_claims_and_extra_fields_are_refused(self):
        original = self.case()['candidate'].to_dict()
        for key in ('release_authorized', 'visual_semantics_verified', 'accessibility_qualified'):
            data = copy.deepcopy(original)
            data['claims'][key] = True
            with self.subTest(claim=key), self.assertRaises(self.m.TypedPdfCandidateError):
                self.forged(data).to_dict()
        data = dict(original, unexpected='PRIVATE-CONTENT')
        with self.assertRaises(self.m.TypedPdfCandidateError):
            self.forged(data).to_bytes()

    def test_rehashed_incomplete_or_foreign_raster_evidence_is_refused(self):
        original = self.case()['candidate'].to_dict()
        controls = []
        missing = copy.deepcopy(original)
        missing['raster_windows'] = []
        controls.append(missing)
        for key in ('ir_sha256', 'pdf_sha256', 'plan_sha256'):
            foreign = copy.deepcopy(original)
            foreign['raster_windows'][0][key] = '0' * 64
            controls.append(foreign)
        for data in controls:
            with self.subTest(windows=data['raster_windows']), \
                    self.assertRaises(self.m.TypedPdfCandidateError):
                self.forged(data).to_bytes()

    def test_rehashed_coverage_count_schedule_and_ledger_are_refused(self):
        original = self.case()['candidate'].to_dict()
        for key, value in (('raster_inspected_pages', 2),
                           ('raster_window_count', 2), ('raster_ledger_sha256', '0' * 64),
                           ('raster_window_plan_sha256', '0' * 64),
                           ('observer_profile_sha256', '0' * 64)):
            data = copy.deepcopy(original)
            data[key] = value
            with self.subTest(field=key), self.assertRaises(self.m.TypedPdfCandidateError):
                self.forged(data).to_dict()
        data = copy.deepcopy(original)
        data['declared_process_schedule']['total'] += 1
        with self.assertRaises(self.m.TypedPdfCandidateError):
            self.forged(data).to_dict()

    def test_profile_manifest_drift_refuses_before_render(self):
        from tempfile import TemporaryDirectory
        profile = json.loads((ROOT / 'reporting/pdf-typed-candidate.v1.json').read_bytes())
        profile['source_sha256']['reporting/typed_pdf_source.py'] = '0' * 64
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'changed.json'
            path.write_bytes(encoded(profile))
            with patch.object(self.m, '_PROFILE_FILE', path), \
                    patch.object(self.m, 'render_pdf_candidate') as render:
                with self.assertRaises(self.m.TypedPdfCandidateError):
                    self.m.prepare_typed_pdf_candidate(**self.inputs())
            render.assert_not_called()

    def test_disable_during_execution_withholds_whole_candidate(self):
        original = self.case()['outputs']['render_pdf_candidate'][0]

        def disable(*args, **kwargs):
            os.environ['OMNIGENIS_TYPED_PDF_CANDIDATE_DISABLED'] = '1'
            return original

        with patch.dict(os.environ):
            self.refused(substitutions={'render_pdf_candidate': disable})

    def test_render_evidence_is_captured_before_later_stage_mutation(self):
        case = self.case()
        rendered = copy.copy(case['outputs']['render_pdf_candidate'][0])
        expected = rendered.result_sha256

        def change_prior(*args, **kwargs):
            object.__setattr__(rendered, 'html_sha256', '0' * 64)
            return case['outputs']['observe_typed_pdf'][0]

        result = self.replay(substitutions={
            'render_pdf_candidate': [rendered], 'observe_typed_pdf': change_prior})
        self.assertEqual(result.to_dict()['render_result_sha256'], expected)

    def test_association_digest_is_captured_before_raster_mutation(self):
        case = self.case()
        associated = copy.copy(case['outputs']['associate_typed_pdf'][0])
        expected = associated.association_sha256

        def change_prior(*args, **kwargs):
            object.__setattr__(associated, 'association_sha256', '0' * 64)
            return case['outputs']['inspect_pdf_raster_window'][0]

        result = self.replay(substitutions={
            'associate_typed_pdf': [associated], 'inspect_pdf_raster_window': change_prior})
        self.assertEqual(result.to_dict()['association_sha256'], expected)

    def test_first_raster_receipt_is_detached_before_next_window(self):
        case = self.case('row')
        first, last = [copy.copy(x) for x in case['outputs']['inspect_pdf_raster_window']]

        def receipts(*args, **kwargs):
            if kwargs['window_index'] == 0:
                return first
            object.__setattr__(first, 'ir_sha256', '0' * 64)
            return last

        result = self.replay(name='row', substitutions={'inspect_pdf_raster_window': receipts})
        self.assertEqual(result.to_dict()['raster_windows'][0]['ir_sha256'],
                         case['inputs']['expected_ir_sha256'])

    def test_typed_html_digest_is_captured_before_render_mutation(self):
        from reporting.typed_html import prepare_typed_html
        case = self.case()
        html, proof = prepare_typed_html(
            presentation_ir=case['inputs']['presentation_ir'],
            expected_ir_sha256=case['inputs']['expected_ir_sha256'])
        expected = proof.html_sha256

        def change_prior(*args, **kwargs):
            object.__setattr__(proof, 'html_sha256', '0' * 64)
            return case['outputs']['render_pdf_candidate'][0]

        with patch.object(self.m, 'prepare_typed_html', return_value=(html, proof)):
            result = self.replay(substitutions={'render_pdf_candidate': change_prior})
        self.assertEqual(result.to_dict()['typed_html_sha256'], expected)


if __name__ == '__main__':
    unittest.main()
