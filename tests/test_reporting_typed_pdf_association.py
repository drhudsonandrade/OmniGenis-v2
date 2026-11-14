"""Literal association tests with synthetic native PDFs and closed protocol controls."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
from hashlib import sha256
import copy
import importlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator
from reporting.pdf_typed_observation import TypedPdfObservation, observe_typed_pdf
from reporting.typed_pdf_source import prepare_typed_pdf_source
from reporting.components import (
    FindingRow, FindingsTable, TableColumn, TextComponent,
    build_typed_report_projection, component_content_sha256,
)
from test_reporting_typed_projection import context
import test_reporting_typed_pdf_observation as native
from test_reporting_typed_pdf_source import document, digest

ROOT = Path(__file__).resolve().parents[1]


def encoded(value):
    """Independent canonical encoding for protocol controls and output checks."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def declarations(name):
    """Declare every expected literal before any rendering or observation."""
    if name == 'empty':
        return document(0)
    if name == 'one':
        return document(1, paragraph='Café ' + ' '.join(f'W{i:03d}' for i in range(120)),
                        labels=('Column', 'Column'),
                        cells=(' '.join(f'C{i:03d}' for i in range(80)),) * 2)
    if name == 'multiple':
        request, ledger = context(1, 'SYNTHETIC-CASE')
        columns = (TableColumn('variant', 'Variant'), TableColumn('value', 'Value'))
        parts = (
            TextComponent('title', 'identity', 'document_title', 'Technical report'),
            TextComponent('heading', 'findings', 'section_heading', 'Declared findings'),
            TextComponent('intro', 'findings', 'paragraph', 'Synthetic values only.'),
            FindingsTable('empty_table', 'findings', 'All declared synthetic findings',
                          columns, ()),
            FindingsTable('table', 'findings', 'All declared synthetic findings',
                          columns, (FindingRow('F0', ('NM_000001.1:c.1A>G',
                                                      '0.12345678901234567890'), ()),)),
        )
        return build_typed_report_projection(
            request=request, ledger=ledger,
            projection_request_sha256=request.request.request_sha256,
            expected_content_sha256=component_content_sha256(parts),
            components=parts).to_dict()
    if name == 'long':
        return document(96)
    if name == 'paragraph':
        return document(0, paragraph=' '.join(f'P{i:04d}' for i in range(2400)))
    if name == 'row':
        return document(1, paragraph='Synthetic split-row characterization.',
                        labels=('Column', 'Column'),
                        cells=(' '.join(f'R{i:04d}' for i in range(1600)),) * 2)
    if name == 'controls':
        return document(1, paragraph='Literal A  B\tC\r\nD\nE. ' + 'wrap ' * 80,
                        cells=('AB  CD EF GH IJ KL MN OP QR ST UV WX YZ ' * 8,
                               '0.12345678901234567890'))
    raise AssertionError('Unknown synthetic declaration')


def nodes_by_reference(data):
    return {tuple(n['reference']): n for n in data['trace']['nodes']}


def children(node, nodes):
    return [nodes[tuple(c['reference'])] for c in node['children']
            if c['kind'] == 'node']


def rebuild_structure(data):
    """Keep a controlled trace valid after changing native K order/shape."""
    trace = data['trace']
    nodes = nodes_by_reference(data)
    ordered = []

    def visit(ref):
        node = nodes[tuple(ref)]
        ordered.append(node)
        for i, child in enumerate(node['children']):
            child['ordinal'] = i
            if child['kind'] == 'node':
                visit(child['reference'])

    for ref in trace['root_children']:
        visit(ref)
    trace['nodes'] = ordered
    data['counts']['structure_nodes'] = len(ordered)
    data['counts']['structure_visits'] = (
        sum(len(p['mcid_owners']) for p in trace['pages'])
        + sum(1 + len(n['children']) for n in ordered))


def set_codes(data, page_index, run_index, codes):
    """Change declared protocol text, not an authenticated PDF observation."""
    page = data['trace']['pages'][page_index]
    run = page['runs'][run_index]
    font = next(f for f in data['trace']['fonts']
                if f['reference'] == run['font_reference'])
    cmap = dict(font['mapping'])
    text = ''.join(cmap[codes[i:i + 4]] for i in range(0, len(codes), 4))
    run['parts'] = [['codes', codes]]
    page['events'][run['operator_ordinal']]['operands'] = copy.deepcopy(run['parts'])
    run.update(text=text, utf8_bytes=len(text.encode('utf-8')),
               scalars=len(text), glyph_codes=len(codes) // 4)
    all_runs = [r for p in data['trace']['pages'] for r in p['runs']]
    data['counts']['decoded_text_bytes'] = sum(r['utf8_bytes'] for r in all_runs)
    data['counts']['text_scalars'] = sum(r['scalars'] for r in all_runs)
    data['counts']['glyph_codes'] = sum(r['glyph_codes'] for r in all_runs)


def runs_for_container(data, container):
    nodes = nodes_by_reference(data)
    page = next(p for p in data['trace']['pages']
                if p['reference'] == container['page_reference'])
    refs = {tuple(n['reference']) for n in children(container, nodes)}
    return page['index'], [r['ordinal'] for r in page['runs']
                           if tuple(r['structure_reference']) in refs]


def add_empty_span(data):
    """Add one internally consistent zero-text fragment inside a positive P."""
    trace = data['trace']
    nodes = nodes_by_reference(data)
    container = next(n for n in nodes.values() if n['role'] == '/P')
    page_index, indexes = runs_for_container(data, container)
    page = trace['pages'][page_index]
    prior = page['runs'][indexes[-1]]
    all_refs = ([trace['root_reference']]
                + [n['reference'] for n in trace['nodes']]
                + [p['reference'] for p in trace['pages']]
                + [p['contents_reference'] for p in trace['pages']]
                + [f[key] for f in trace['fonts']
                   for key in ('reference', 'cid_reference', 'cmap_reference')])
    ref = [max(r[0] for r in all_refs) + 1, 0]
    mcid = len(page['mcid_owners'])
    leaf = copy.deepcopy(nodes[tuple(prior['structure_reference'])])
    leaf.update(reference=ref, parent=container['reference'],
                children=[{'kind': 'mcid', 'ordinal': 0, 'value': mcid}])
    trace['nodes'].append(leaf)
    container['children'].append(
        {'kind': 'node', 'ordinal': len(container['children']), 'reference': ref})
    page['mcid_owners'].append({'mcid': mcid, 'structure_reference': ref})
    insertion = prior['operator_ordinal'] + 3
    ops = [('BDC', [mcid]), ('BT', []), ('Tm', prior['text_matrix']),
           ('Tf', [prior['font_resource'], prior['font_size']]),
           ('TJ', [['codes', '']]), ('ET', []), ('EMC', [])]
    page['events'][insertion:insertion] = [
        {'ordinal': 0, 'operator': op, 'operands': copy.deepcopy(args)}
        for op, args in ops]
    for i, event in enumerate(page['events']):
        event['ordinal'] = i
    for run in page['runs']:
        if run['operator_ordinal'] >= insertion:
            run['operator_ordinal'] += len(ops)
    empty = copy.deepcopy(prior)
    empty.update(mcid=mcid, structure_reference=ref,
                 operator_ordinal=insertion + 4, text='', utf8_bytes=0,
                 scalars=0, glyph_codes=0, parts=[['codes', '']])
    page['runs'].insert(indexes[-1] + 1, empty)
    for i, run in enumerate(page['runs']):
        run['ordinal'] = run['text_object'] = i
    data['counts']['mcids'] += 1
    data['counts']['operations'] += len(ops)
    rebuild_structure(data)


class TypedPdfAssociationTests(unittest.TestCase):
    """Acceptance concerns declared literal association, never artifact release."""

    fixtures = {}

    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('reporting.typed_pdf_association'),
                             'complete typed PDF literal association is missing')
        self.m = importlib.import_module('reporting.typed_pdf_association')

    def case(self, name='one'):
        if name not in self.fixtures:
            source = declarations(name)
            ir_sha = digest(source)
            expectation = prepare_typed_pdf_source(
                presentation_ir=source, expected_ir_sha256=ir_sha)
            # The expected source is sealed before the independent native work.
            expectation_sha = expectation.expectation_sha256
            with patch.object(native, 'document', return_value=source):
                pdf = native.native_fixture(0)
            pdf_sha = sha256(pdf).hexdigest()
            observation = observe_typed_pdf(pdf_bytes=pdf, expected_pdf_sha256=pdf_sha)
            self.fixtures[name] = {
                'source': source, 'ir_sha': ir_sha, 'expectation': expectation,
                'expectation_sha': expectation_sha, 'pdf': pdf, 'pdf_sha': pdf_sha,
                'observation': observation,
                'observation_sha': sha256(observation.to_bytes()).hexdigest(),
            }
        return self.fixtures[name]

    def args(self, name='one', *, source=None, observation=None):
        case = self.case(name)
        if source is None:
            source, ir_sha, expectation_sha = (
                case['source'], case['ir_sha'], case['expectation_sha'])
        else:
            ir_sha = digest(source)
            expectation_sha = prepare_typed_pdf_source(
                presentation_ir=source, expected_ir_sha256=ir_sha).expectation_sha256
        if observation is None:
            observation, observation_sha = case['observation'], case['observation_sha']
        else:
            observation_sha = sha256(observation.to_bytes()).hexdigest()
        return {
            'presentation_ir': source, 'expected_ir_sha256': ir_sha,
            'expected_source_expectation_sha256': expectation_sha,
            'observation': observation, 'expected_observation_sha256': observation_sha,
            'expected_pdf_sha256': case['pdf_sha'],
        }

    def associate(self, name='one', *, source=None, observation=None, **changes):
        return self.m.associate_typed_pdf(
            **{**self.args(name, source=source, observation=observation), **changes})

    def protocol(self, name, change):
        """Re-admit altered full protocol data, without claiming a new PDF run."""
        data = self.case(name)['observation'].to_dict()
        change(data)
        return TypedPdfObservation(encoded(data))

    def refused(self, name='one', *, source=None, observation=None, **changes):
        with self.assertRaises(self.m.TypedPdfAssociationError):
            self.associate(name, source=source, observation=observation, **changes)

    def test_complete_zero_row_table_has_no_invented_findings(self):
        data = self.associate('empty').to_dict()
        self.assertEqual(data['counts']['source_units'], 6)
        self.assertEqual(data['counts']['table_rows'], 0)
        self.assertEqual(data['counts']['represented_findings'], 0)
        self.assertEqual(data['counts']['table_segments'], 1)
        self.assertEqual(data['row_segments'], [])
        self.assertEqual(data['counts']['header_repetitions'], 0)
        self.assertEqual([u['source_unit_ordinal'] for u in data['units']], list(range(6)))

    def test_equal_headers_and_cells_keep_distinct_ordinal_ownership(self):
        data = self.associate().to_dict()
        units = data['units']
        self.assertEqual([u['source_unit_ordinal'] for u in units], list(range(8)))
        self.assertEqual(units[4]['text_sha256'], units[5]['text_sha256'])
        self.assertEqual(units[6]['text_sha256'], units[7]['text_sha256'])
        self.assertNotEqual(units[4]['occurrences'], units[5]['occurrences'])
        self.assertNotEqual(units[6]['occurrences'], units[7]['occurrences'])
        self.assertEqual(data['row_segments'][0]['source_unit_ordinals'], [6, 7])

    def test_wrapped_containers_match_without_inserting_whitespace(self):
        data = self.associate().to_dict()
        for ordinal in (2, 6, 7):
            occurrence = data['units'][ordinal]['occurrences'][0]
            self.assertEqual(len(occurrence['segments']), 1)
            self.assertGreater(len(occurrence['segments'][0]['fragments']), 1)
            self.assertEqual(data['units'][ordinal]['text_sha256'],
                             self.case()['expectation'].to_dict()['units'][ordinal]['text_sha256'])

    def test_three_page_table_accounts_for_every_row_and_repeated_header(self):
        data = self.associate('long').to_dict()
        self.assertEqual(data['counts']['source_units'], 198)
        self.assertEqual(data['counts']['table_rows'], 96)
        self.assertEqual(data['counts']['represented_findings'], 96)
        self.assertEqual(data['counts']['table_segments'], 3)
        self.assertEqual(data['counts']['row_segments'], 96)
        self.assertEqual(data['counts']['header_repetitions'], 4)
        self.assertEqual([r['row_ordinal'] for r in data['row_segments']], list(range(96)))
        for ordinal in (4, 5):
            self.assertEqual([o['kind'] for o in data['units'][ordinal]['occurrences']],
                             ['PRIMARY', 'REPEATED_TABLE_HEADER', 'REPEATED_TABLE_HEADER'])

    def test_actual_four_page_paragraph_keeps_one_logical_source_unit(self):
        data = self.associate('paragraph').to_dict()
        unit = data['units'][2]
        self.assertEqual(unit['utf8_bytes'], 14399)
        self.assertEqual(unit['scalars'], 14399)
        self.assertEqual(unit['text_sha256'],
                         '266f75ecbf98f7284be95760b8728fa5113176ac8a6aaf4f9cc76041dc79e61c')
        self.assertEqual([s['page_index'] for s in unit['occurrences'][0]['segments']],
                         [0, 1, 2, 3])
        self.assertEqual(data['counts']['source_units'], 6)

    def test_actual_five_page_dense_row_accumulates_each_column_separately(self):
        data = self.associate('row').to_dict()
        self.assertEqual(data['counts']['table_rows'], 1)
        self.assertEqual(data['counts']['row_segments'], 5)
        self.assertEqual(data['counts']['header_repetitions'], 8)
        self.assertEqual([r['row_ordinal'] for r in data['row_segments']], [0] * 5)
        self.assertEqual([r['segment_ordinal'] for r in data['row_segments']], list(range(5)))
        for ordinal in (6, 7):
            unit = data['units'][ordinal]
            self.assertEqual(unit['utf8_bytes'], 9599)
            self.assertEqual(unit['text_sha256'],
                             '30ce93e11de7e0c0a2ea1c3a397cee0524efa31bfe4586cfff04551e36e9aa83')
            self.assertEqual([s['page_index'] for s in unit['occurrences'][0]['segments']],
                             [0, 1, 2, 3, 4])
        self.assertNotEqual(data['units'][6]['occurrences'], data['units'][7]['occurrences'])

    def test_every_physical_fragment_is_owned_once_including_header_repeats(self):
        data = self.associate('long').to_dict()
        assigned = [(s['page_index'], f['run_ordinal'], f['mcid'], tuple(f['span_reference']))
                    for u in data['units'] for o in u['occurrences']
                    for s in o['segments'] for f in s['fragments']]
        observed = [(p['index'], r['ordinal'], r['mcid'], tuple(r['structure_reference']))
                    for p in self.case('long')['observation'].to_dict()['trace']['pages']
                    for r in p['runs']]
        self.assertEqual(len(assigned), len(set(assigned)))
        self.assertEqual(set(assigned), set(observed))
        self.assertEqual(data['counts']['physical_fragments'], len(observed))
        self.assertEqual(data['counts']['physical_nodes'],
                         self.case('long')['observation'].to_dict()['counts']['structure_nodes'])

    def test_all_source_context_and_physical_identity_bindings_survive(self):
        data = self.associate().to_dict()
        case = self.case()
        self.assertEqual(data['source_expectation_sha256'], case['expectation_sha'])
        self.assertEqual(data['observation_sha256'], case['observation_sha'])
        self.assertEqual(data['ir_sha256'], case['ir_sha'])
        self.assertEqual(data['pdf_sha256'], case['pdf_sha'])
        self.assertEqual(data['pdf_byte_count'], len(case['pdf']))
        for key in ('request_sha256', 'source_binding_sha256', 'plan_sha256',
                    'ledger_sha256', 'content_sha256'):
            self.assertEqual(data[key], case['source'][key])
        self.assertEqual(data['observer_profile_sha256'],
                         case['observation'].to_dict()['profile_sha256'])

    def test_result_is_deterministic_immutable_and_detached(self):
        result = self.associate()
        self.assertEqual(result.to_bytes(), self.associate().to_bytes())
        self.assertEqual(result.association_sha256, sha256(result.to_bytes()).hexdigest())
        self.assertEqual(result.to_bytes(), encoded(result.to_dict()))
        data = result.to_dict()
        data['units'].clear()
        self.assertEqual(len(result.to_dict()['units']), 8)
        with self.assertRaises(FrozenInstanceError):
            result.association_sha256 = '0' * 64

    def test_summary_and_failures_expose_no_report_text_or_source_identifiers(self):
        result = self.associate()
        summary = result.summary()
        self.assertNotIn('units', summary)
        self.assertNotIn('table_segments', summary)
        self.assertNotIn('row_segments', summary)
        exposed = json.dumps(summary) + repr(result)
        for secret in ('Technical report', 'SYNTHETIC-CASE', 'W000', 'C000', 'Column'):
            self.assertNotIn(secret, exposed)
        try:
            self.associate(expected_pdf_sha256='Technical report')
        except self.m.TypedPdfAssociationError as exc:
            self.assertNotIn('Technical report', str(exc))
            self.assertIsNone(exc.__cause__)
        else:
            self.fail('Invalid input was accepted')

    def test_claims_are_association_only_and_never_final(self):
        result = self.associate()
        data = result.to_dict()
        self.assertEqual(data['status'], 'LITERAL_SOURCE_ASSOCIATED')
        self.assertFalse(hasattr(result, 'passed'))
        positive = {'literal_hashes_matched', 'complete_physical_coverage',
                    'unique_mapping_within_profile'}
        self.assertEqual({k for k, v in data['claims'].items() if v}, positive)
        for key in ('source_authenticity_verified', 'historical_source_origin_verified',
                    'rendered_glyphs_verified', 'visual_layout_verified',
                    'reading_order_verified', 'accessibility_qualified',
                    'scientific_equivalence_verified', 'aggregate_job_resources_qualified',
                    'worker_results_authenticated', 'release_authorized'):
            self.assertIs(data['claims'][key], False)
        self.assertEqual(self.case()['observation'].to_dict()['source_association'],
                         'NOT_ESTABLISHED')

    def test_direct_constructor_runs_the_same_complete_admission(self):
        direct = self.m.TypedPdfAssociation(**self.args())
        self.assertEqual(direct.to_bytes(), self.associate().to_bytes())
        with self.assertRaises(self.m.TypedPdfAssociationError):
            self.m.TypedPdfAssociation(**{**self.args(), 'expected_pdf_sha256': '0' * 64})

    def test_schema_is_closed_at_every_mapping_boundary(self):
        schema = json.loads((ROOT / 'schemas/report-typed-pdf-association.v1.schema.json').read_text())
        validator = Draft202012Validator(schema)
        data = self.associate().to_dict()
        validator.validate(data)
        targets = [
            (), ('claims',), ('counts',), ('units', 0),
            ('units', 0, 'occurrences', 0),
            ('units', 0, 'occurrences', 0, 'segments', 0),
            ('units', 0, 'occurrences', 0, 'segments', 0, 'fragments', 0),
            ('table_segments', 0), ('row_segments', 0),
        ]
        for path in targets:
            with self.subTest(path=path):
                bad = copy.deepcopy(data)
                target = bad
                for key in path:
                    target = target[key]
                target['unexpected'] = True
                self.assertFalse(validator.is_valid(bad))
        bad = copy.deepcopy(data)
        bad['claims']['release_authorized'] = True
        self.assertFalse(validator.is_valid(bad))

    def test_wrong_or_malformed_expected_digests_refuse(self):
        for key in ('expected_ir_sha256', 'expected_source_expectation_sha256',
                    'expected_observation_sha256', 'expected_pdf_sha256'):
            for value in ('0' * 64, 'F' * 64, 'a' * 64 + '\n', True, b'a' * 64, None):
                with self.subTest(key=key, value_type=type(value).__name__):
                    self.refused(**{key: value})

    def test_foreign_source_context_cannot_reuse_the_expected_source_digest(self):
        foreign = declarations('one')
        foreign['report_id'] = 'FOREIGN-REPORT'
        self.refused(presentation_ir=foreign)

    def test_stale_expected_source_manifest_does_not_accept_resealed_new_text(self):
        source = document(1, paragraph='Different source', labels=('Column', 'Column'),
                          cells=('AB', 'AB'))
        args = self.args(source=source)
        args['expected_source_expectation_sha256'] = self.case()['expectation_sha']
        with self.assertRaises(self.m.TypedPdfAssociationError):
            self.m.associate_typed_pdf(**args)

    def test_hostile_observation_and_digest_types_are_rejected_without_hooks(self):
        invocations = []

        class Hostile:
            def __getattr__(self, name):
                invocations.append(('attribute', name))
                raise AssertionError('Untrusted attribute hook called')

            def __str__(self):
                invocations.append(('string', None))
                raise AssertionError('Untrusted string hook called')

        args = self.args()
        for key in ('observation', 'expected_observation_sha256'):
            with self.subTest(key=key):
                with self.assertRaises(self.m.TypedPdfAssociationError):
                    self.m.associate_typed_pdf(**{**args, key: Hostile()})
                self.assertEqual(invocations, [], 'Forbidden input hook executed')

    def test_forged_observation_is_reconstructed_not_trusted_as_a_valid_class(self):
        data = self.case()['observation'].to_dict()
        data['release_authorized'] = True
        raw = encoded(data)
        forged = object.__new__(TypedPdfObservation)
        object.__setattr__(forged, '_payload', raw)
        object.__setattr__(forged, 'observation_sha256', sha256(raw).hexdigest())
        args = self.args()
        args.update(observation=forged, expected_observation_sha256=sha256(raw).hexdigest())
        with self.assertRaises(self.m.TypedPdfAssociationError):
            self.m.associate_typed_pdf(**args)

    def test_observer_disable_path_also_refuses_new_association(self):
        args = self.args()
        with patch.dict('os.environ', {'OMNIGENIS_TYPED_PDF_OBSERVATION_DISABLED': '1'}):
            with self.assertRaises(self.m.TypedPdfAssociationError):
                self.m.associate_typed_pdf(**args)

    def test_association_performs_no_new_native_launch_or_render(self):
        args = self.args()
        with patch('subprocess.Popen', side_effect=AssertionError('Native launch forbidden')), \
             patch('reporting.pdf_typed_observation._run_worker',
                   side_effect=AssertionError('Observer launch forbidden')), \
             patch('reporting.pdf_generated_source_job.render_pdf_candidate',
                   side_effect=AssertionError('Render forbidden')):
            result = self.m.associate_typed_pdf(**args)
        self.assertEqual(result.to_dict()['counts']['source_units'], 8)

    def test_component_order_drift_refuses(self):
        def change(data):
            doc = next(n for n in data['trace']['nodes'] if n['role'] == '/Document')
            doc['children'][0], doc['children'][1] = doc['children'][1], doc['children'][0]
            rebuild_structure(data)
        self.refused(observation=self.protocol('one', change))

    def test_native_structure_and_stream_fragment_order_must_agree(self):
        def change(data):
            node = next(n for n in data['trace']['nodes'] if n['role'] == '/P')
            node['children'].reverse()
            rebuild_structure(data)
        self.refused(observation=self.protocol('one', change))

    def test_table_row_order_drift_refuses(self):
        def change(data):
            body = next(n for n in data['trace']['nodes'] if n['role'] == '/TBody')
            body['children'][0], body['children'][1] = body['children'][1], body['children'][0]
            rebuild_structure(data)
        self.refused('long', observation=self.protocol('long', change))

    def test_top_level_page_order_drift_refuses(self):
        def change(data):
            doc = next(n for n in data['trace']['nodes'] if n['role'] == '/Document')
            doc['children'][-1], doc['children'][-2] = doc['children'][-2], doc['children'][-1]
            rebuild_structure(data)
        self.refused('paragraph', observation=self.protocol('paragraph', change))

    def test_equal_header_labels_do_not_authorize_the_wrong_column_link(self):
        def change(data):
            headers = [n for n in data['trace']['nodes'] if n['role'] == '/TH']
            cell = next(n for n in data['trace']['nodes'] if n['role'] == '/TD')
            cell['headers'] = [headers[1]['native_id']]
        self.refused(observation=self.protocol('one', change))

    def test_continued_header_must_match_its_original_literal_independently(self):
        def change(data):
            header = next(n for n in data['trace']['nodes']
                          if n['role'] == '/TH' and n['page_reference'] == data['trace']['pages'][1]['reference'])
            page_index, indexes = runs_for_container(data, header)
            run = data['trace']['pages'][page_index]['runs'][indexes[0]]
            codes = ''.join(value for kind, value in run['parts'] if kind == 'codes')
            set_codes(data, page_index, indexes[0], codes[4:])
        self.refused('long', observation=self.protocol('long', change))

    def test_same_flattened_text_cannot_move_between_adjacent_cells(self):
        declared = declarations('one')
        original = declared['components'][-1]['rows'][0]['cells']
        self.assertEqual(original[0] + original[1],
                         (original[0] + original[1][0]) + original[1][1:])
        source = document(1, paragraph=declared['components'][2]['text'],
                          labels=('Column', 'Column'),
                          cells=(original[0] + original[1][0], original[1][1:]))
        self.refused(source=source)

    def test_missing_last_source_row_refuses_without_a_successful_prefix(self):
        self.refused('long', source=document(97))

    def test_extra_physical_row_refuses_without_a_successful_prefix(self):
        self.refused('long', source=document(95))

    def test_absent_literal_tab_cr_and_lf_cannot_be_rebuilt_from_positioning(self):
        self.refused('controls')

    def test_normalization_equivalent_unicode_is_not_literal_equivalence(self):
        declared = declarations('one')
        source = document(1, paragraph=declared['components'][2]['text'].replace(
            'Café', 'Cafe\u0301'), labels=('Column', 'Column'),
            cells=tuple(declared['components'][-1]['rows'][0]['cells']))
        self.refused(source=source)

    def test_zero_text_container_refuses(self):
        def change(data):
            node = next(n for n in data['trace']['nodes'] if n['role'] == '/P')
            page_index, indexes = runs_for_container(data, node)
            for index in indexes:
                set_codes(data, page_index, index, '')
        self.refused(observation=self.protocol('one', change))

    def test_zero_text_span_inside_a_positive_container_is_retained(self):
        observation = self.protocol('one', add_empty_span)
        result = self.associate(observation=observation).to_dict()
        before = self.associate().to_dict()
        self.assertEqual(result['counts']['source_units'], before['counts']['source_units'])
        self.assertEqual(result['counts']['physical_fragments'],
                         before['counts']['physical_fragments'] + 1)
        self.assertEqual(result['units'][2]['text_sha256'], before['units'][2]['text_sha256'])

    def test_empty_table_requires_an_explicit_body(self):
        def change(data):
            nodes = nodes_by_reference(data)
            table = next(n for n in nodes.values() if n['role'] == '/Table')
            table['children'] = [c for c in table['children']
                                 if nodes[tuple(c['reference'])]['role'] != '/TBody']
            rebuild_structure(data)
        self.refused('empty', observation=self.protocol('empty', change))

    def test_extra_empty_table_body_is_not_silently_ignored(self):
        def change(data):
            nodes = nodes_by_reference(data)
            table = next(n for n in nodes.values() if n['role'] == '/Table')
            body = copy.deepcopy(next(n for n in nodes.values() if n['role'] == '/TBody'))
            # All native structure object IDs follow fonts in this real fixture.
            ref = [max(n['reference'][0] for n in nodes.values()) + 1000, 0]
            body['reference'] = ref
            data['trace']['nodes'].append(body)
            table['children'].append({'kind': 'node', 'ordinal': 3, 'reference': ref})
            rebuild_structure(data)
        self.refused('empty', observation=self.protocol('empty', change))

    def test_dense_row_does_not_admit_a_column_that_finishes_early(self):
        declared = declarations('row')
        whole = declared['components'][-1]['rows'][0]['cells'][0]
        source = document(1, paragraph='Synthetic split-row characterization.',
                          labels=('Column', 'Column'), cells=(whole[:1680], whole))
        self.refused('row', source=source)

    def test_sparse_or_empty_carried_cell_refuses(self):
        def change(data):
            page = data['trace']['pages'][1]
            td = next(n for n in data['trace']['nodes']
                      if n['role'] == '/TD' and n['page_reference'] == page['reference'])
            page_index, indexes = runs_for_container(data, td)
            for index in indexes:
                set_codes(data, page_index, index, '')
        self.refused('row', observation=self.protocol('row', change))

    def test_source_unit_budget_refuses_the_whole_operation(self):
        args = self.args()
        with patch.object(self.m, 'MAX_SOURCE_UNITS', 7):
            with self.assertRaises(self.m.TypedPdfAssociationError):
                self.m.associate_typed_pdf(**args)

    def test_mapping_work_budget_refuses_the_whole_operation(self):
        args = self.args()
        with patch.object(self.m, 'MAX_MAPPING_ITEMS', 1):
            with self.assertRaises(self.m.TypedPdfAssociationError):
                self.m.associate_typed_pdf(**args)

    def test_canonical_output_budget_accepts_exact_size_then_refuses(self):
        args = self.args()
        result = self.m.associate_typed_pdf(**args)
        size = len(result.to_bytes())
        with patch.object(self.m, 'MAX_RESULT_BYTES', size):
            self.assertEqual(self.m.associate_typed_pdf(**args).to_bytes(), result.to_bytes())
        with patch.object(self.m, 'MAX_RESULT_BYTES', size - 1):
            with self.assertRaises(self.m.TypedPdfAssociationError):
                self.m.associate_typed_pdf(**args)

    def test_two_consecutive_logical_tables_remain_distinct_components(self):
        data = self.associate('multiple').to_dict()
        self.assertEqual(data['counts']['source_units'], 11)
        self.assertEqual(data['counts']['table_rows'], 1)
        self.assertEqual(data['counts']['table_segments'], 2)
        self.assertEqual(data['counts']['header_repetitions'], 0)
        self.assertEqual([(t['component_ordinal'], t['segment_ordinal'])
                          for t in data['table_segments']], [(3, 0), (4, 0)])
        self.assertEqual(data['row_segments'][0]['component_ordinal'], 4)

    def test_unexpected_second_logical_table_is_not_a_successful_prefix(self):
        self.refused('multiple', source=document(0))

    def test_forged_oversized_payload_refuses_before_observer_hashing_or_parsing(self):
        args = self.args()
        forged = object.__new__(TypedPdfObservation)
        object.__setattr__(forged, '_payload', b'not-an-observation')
        object.__setattr__(forged, 'observation_sha256', '0' * 64)
        args['observation'] = forged
        parsed = []
        hashed = []
        actual_loads = native.importlib.import_module('reporting.pdf_typed_observation')._loads
        actual_sha = native.importlib.import_module('reporting.pdf_typed_observation').sha256

        def loads(value):
            parsed.append(True)
            return actual_loads(value)

        def hashed_value(value=b''):
            hashed.append(True)
            return actual_sha(value)

        with patch.object(self.m, 'MAX_OBSERVATION_BYTES', 1), \
             patch('reporting.pdf_typed_observation._loads', side_effect=loads), \
             patch('reporting.pdf_typed_observation.sha256', side_effect=hashed_value):
            with self.assertRaises(self.m.TypedPdfAssociationError):
                self.m.associate_typed_pdf(**args)
        self.assertEqual(parsed, [], 'Oversized observation reached parsing')
        self.assertEqual(hashed, [], 'Oversized observation reached hashing')


if __name__ == '__main__':
    unittest.main()
