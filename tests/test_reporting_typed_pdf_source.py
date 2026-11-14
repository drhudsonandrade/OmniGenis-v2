"""Synthetic behavior tests for ordered, source-only PDF expectations."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator
from reporting.components import (
    FindingRow, FindingsTable, TableColumn, TextComponent,
    build_typed_report_projection, component_content_sha256,
)
from test_reporting_typed_projection import context

ROOT = Path(__file__).resolve().parents[1]
_UNSET = object()


def canonical(value):
    """Use the independently declared JSON encoding for test-side bindings."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def digest(value):
    """Pin a fixture before handing it to the feature under test."""
    return hashlib.sha256(canonical(value)).hexdigest()


def document(count=2, *, paragraph='Synthetic values only.', cells=None,
             labels=('Variant', 'Value'), tokens=(), case='SYNTHETIC-CASE'):
    """Build real sealed source contracts using synthetic declarations only."""
    request, ledger = context(count, case)
    rows = tuple(FindingRow(f, cells if cells is not None else
        (f'NM_000001.1:c.{i + 1}A>G', '0.12345678901234567890'), tokens)
        for i, f in enumerate(request.plan.expected_finding_ids))
    parts = (
        TextComponent('title', 'identity', 'document_title', 'Technical report'),
        TextComponent('heading', 'findings', 'section_heading', 'Declared findings'),
        TextComponent('intro', 'findings', 'paragraph', paragraph),
        FindingsTable('table', 'findings', 'All declared synthetic findings',
            (TableColumn('variant', labels[0]), TableColumn('value', labels[1])), rows),
    )
    return build_typed_report_projection(
        request=request, ledger=ledger,
        projection_request_sha256=request.request.request_sha256,
        expected_content_sha256=component_content_sha256(parts),
        components=parts).to_dict()


class TypedPdfSourceTests(unittest.TestCase):
    """Observe exact boundaries without claiming native PDF validation."""

    def setUp(self):
        """Report a missing feature as an explicit TDD assertion."""
        self.assertIsNotNone(importlib.util.find_spec('reporting.typed_pdf_source'),
                             'ordered typed PDF source expectation is missing')
        self.m = importlib.import_module('reporting.typed_pdf_source')

    def prepare(self, value=None, expected=_UNSET):
        """Exercise the public factory with an independently sealed fixture."""
        value = document() if value is None else value
        return self.m.prepare_typed_pdf_source(
            presentation_ir=value,
            expected_ir_sha256=digest(value) if expected is _UNSET else expected)

    def test_every_source_unit_has_its_exact_order_and_locator(self):
        data = self.prepare().to_dict()
        actual = [(u['ordinal'], u['kind'], u['component_ordinal'], u['component_id'],
                   u['row_ordinal'], u['column_ordinal'], u['finding_id'], u['column_id'])
                  for u in data['units']]
        self.assertEqual(actual, [
            (0, 'document_title', 0, 'title', None, None, None, None),
            (1, 'section_heading', 1, 'heading', None, None, None, None),
            (2, 'paragraph', 2, 'intro', None, None, None, None),
            (3, 'table_caption', 3, 'table', None, None, None, None),
            (4, 'table_header', 3, 'table', None, 0, None, 'variant'),
            (5, 'table_header', 3, 'table', None, 1, None, 'value'),
            (6, 'table_cell', 3, 'table', 0, 0, 'F0', 'variant'),
            (7, 'table_cell', 3, 'table', 0, 1, 'F0', 'value'),
            (8, 'table_cell', 3, 'table', 1, 0, 'F1', 'variant'),
            (9, 'table_cell', 3, 'table', 1, 1, 'F1', 'value'),
        ])
        self.assertEqual([u['section_id'] for u in data['units']],
                         ['identity'] + ['findings'] * 9)
        self.assertEqual(data['counts']['source_units'], 10)

    def test_unit_hashes_and_lengths_match_independent_literal_values(self):
        texts = ['Technical report', 'Declared findings', 'Synthetic values only.',
                 'All declared synthetic findings', 'Variant', 'Value',
                 'NM_000001.1:c.1A>G', '0.12345678901234567890',
                 'NM_000001.1:c.2A>G', '0.12345678901234567890']
        data = self.prepare().to_dict()
        for unit, literal in zip(data['units'], texts, strict=True):
            self.assertEqual(unit['text_sha256'], hashlib.sha256(literal.encode()).hexdigest())
            self.assertEqual(unit['utf8_bytes'], len(literal.encode()))
            self.assertEqual(unit['scalars'], len(literal))
            self.assertNotIn('text', unit)
        self.assertEqual(data['counts']['literal_utf8_bytes'],
                         sum(len(t.encode()) for t in texts))
        self.assertEqual(data['counts']['literal_scalars'], sum(map(len, texts)))

    def test_all_source_context_hashes_and_availability_are_bound(self):
        source = document()
        data = self.prepare(source).to_dict()
        self.assertEqual(data['ir_sha256'], digest(source))
        for key in ('request_sha256', 'source_binding_sha256', 'plan_sha256',
                    'ledger_sha256', 'content_sha256'):
            self.assertEqual(data[key], source[key])
        self.assertEqual(data['section_states_sha256'], digest(source['section_states']))
        self.assertEqual(data['counts']['not_present_sections'], 1)

    def test_preparation_never_claims_pdf_or_release_acceptance(self):
        proof = self.prepare()
        data = proof.to_dict()
        self.assertEqual(data['status'], 'PREPARED')
        self.assertEqual(data['conformance_scope'], 'ORDERED_TYPED_SOURCE_EXPECTATION_ONLY')
        self.assertEqual(data['physical_mapping'], 'NOT_ESTABLISHED')
        self.assertEqual(data['release_authorization'], 'NOT_ESTABLISHED')
        for key in ('rendered_content_validated', 'accessibility_validated',
                    'visual_layout_validated', 'source_semantics_validated'):
            self.assertIs(data[key], False)
        self.assertFalse(hasattr(proof, 'passed'))

    def test_flattened_equal_cells_keep_different_boundaries(self):
        a = self.prepare(document(1, cells=('AB', 'C')))
        b = self.prepare(document(1, cells=('A', 'BC')))
        self.assertNotEqual(a.to_dict()['units'], b.to_dict()['units'])
        self.assertNotEqual(a.expectation_sha256, b.expectation_sha256)

    def test_whitespace_cannot_move_between_cells(self):
        a = self.prepare(document(1, cells=('A ', 'B'))).to_dict()['units'][-2:]
        b = self.prepare(document(1, cells=('A', ' B'))).to_dict()['units'][-2:]
        self.assertNotEqual(a, b)

    def test_identical_text_retains_distinct_header_and_cell_identities(self):
        data = self.prepare(document(1, cells=('same', 'same'),
                                     labels=('same', 'same'))).to_dict()
        units = data['units'][4:]
        self.assertEqual(len({u['text_sha256'] for u in units}), 1)
        self.assertEqual(len({(u['kind'], u['row_ordinal'], u['column_ordinal'])
                              for u in units}), 4)
        self.assertEqual([u['column_id'] for u in units],
                         ['variant', 'value', 'variant', 'value'])

    def test_every_admitted_whitespace_and_unicode_value_remains_literal(self):
        values = ['A\rB', 'A\nB', 'A\r\nB', 'A\tB', ' A  B ',
                  'A\u00a0B', 'A\u2003B', 'é', 'e\u0301', 'αβ']
        observed = []
        for value in values:
            unit = self.prepare(document(paragraph=value)).to_dict()['units'][2]
            self.assertEqual(unit['text_sha256'], hashlib.sha256(value.encode()).hexdigest())
            self.assertEqual(unit['utf8_bytes'], len(value.encode()))
            self.assertEqual(unit['scalars'], len(value))
            observed.append(unit['text_sha256'])
        self.assertEqual(len(set(observed)), len(values))

    def test_long_decimal_and_row_scoped_tokens_have_no_invented_cell_owner(self):
        literal = '0.12345678901234567890'
        source = document(1, cells=(literal, literal), tokens=(literal,))
        data = self.prepare(source).to_dict()
        for unit in data['units'][-2:]:
            self.assertEqual(unit['text_sha256'], hashlib.sha256(literal.encode()).hexdigest())
            self.assertNotIn('protected_tokens', unit)
        self.assertEqual(data['ir_sha256'], digest(source))

    def test_empty_one_and_long_tables_are_complete_without_repeated_headers(self):
        for count in (0, 1, 96, 5000):
            data = self.prepare(document(count)).to_dict()
            self.assertEqual(data['counts']['source_units'], 6 + 2 * count)
            self.assertEqual(data['counts']['table_rows'], count)
            self.assertEqual(data['counts']['represented_findings'], count)
            self.assertEqual(sum(u['kind'] == 'table_header' for u in data['units']), 2)
            if count:
                self.assertEqual(data['units'][-1]['finding_id'], f'F{count - 1}')

    def test_wrong_expected_projection_is_rejected(self):
        with self.assertRaises(self.m.TypedPdfSourceError):
            self.prepare(expected='0' * 64)

    def test_foreign_case_cannot_reuse_another_expected_projection(self):
        own, foreign = document(), document(case='OTHER-SYNTHETIC-CASE')
        with self.assertRaises(self.m.TypedPdfSourceError):
            self.prepare(foreign, digest(own))
        self.assertNotEqual(self.prepare(own).expectation_sha256,
                            self.prepare(foreign).expectation_sha256)

    def test_stale_content_digest_cannot_accept_changed_literal_text(self):
        source = document()
        source['components'][2]['text'] = 'SYNTHETIC-REPLACEMENT'
        with self.assertRaises(self.m.TypedPdfSourceError):
            self.prepare(source)

    def test_omission_duplicate_and_row_order_drift_are_rejected(self):
        for change in ('omit', 'duplicate', 'reverse'):
            source = document()
            rows = source['components'][3]['rows']
            if change == 'omit':
                rows.pop()
            elif change == 'duplicate':
                rows.append(rows[0])
            else:
                rows.reverse()
            with self.assertRaises(self.m.TypedPdfSourceError):
                self.prepare(source)

    def test_source_budget_exhaustion_refuses_the_whole_expectation(self):
        source = document()
        source['components'][2]['text'] = 'X' * (64 * 1024 + 1)
        with self.assertRaises(self.m.TypedPdfSourceError):
            self.prepare(source)

    def test_unit_budget_accepts_boundary_then_refuses_without_truncation(self):
        with patch.object(self.m, 'MAX_SOURCE_UNITS', 10):
            self.assertEqual(len(self.prepare().to_dict()['units']), 10)
        with patch.object(self.m, 'MAX_SOURCE_UNITS', 9):
            with self.assertRaises(self.m.TypedPdfSourceError):
                self.prepare()

    def test_serialized_budget_accepts_exact_bytes_then_refuses(self):
        source = document()
        size = len(canonical(self.prepare(source).to_dict()))
        with patch.object(self.m, 'MAX_EXPECTATION_BYTES', size):
            self.assertEqual(len(canonical(self.prepare(source).to_dict())), size)
        with patch.object(self.m, 'MAX_EXPECTATION_BYTES', size - 1):
            with self.assertRaises(self.m.TypedPdfSourceError):
                self.prepare(source)

    def test_native_types_only_and_cycles_refuse_without_calling_user_hooks(self):
        class Foreign(dict):
            def items(self):
                raise AssertionError('untrusted hook called')

        for source in (Foreign(document()), object()):
            with self.assertRaises(self.m.TypedPdfSourceError):
                self.prepare(source, '0' * 64)
        cycle = {}
        cycle['cycle'] = cycle
        with self.assertRaises(self.m.TypedPdfSourceError):
            self.prepare(cycle, '0' * 64)

    def test_bad_digest_representations_are_not_coerced(self):
        for expected in (None, 4, True, 'A' * 64, ' ' + 'a' * 64, b'a' * 64):
            with self.assertRaises(self.m.TypedPdfSourceError):
                self.prepare(document(), expected)

    def test_direct_constructor_cannot_bypass_capture(self):
        source = document()
        with self.assertRaises(self.m.TypedPdfSourceError):
            self.m.TypedPdfSourceExpectation(source, '0' * 64)
        direct = self.m.TypedPdfSourceExpectation(source, digest(source))
        self.assertEqual(direct.to_dict(), self.prepare(source).to_dict())

    def test_no_source_or_serialized_mutable_alias_is_retained(self):
        source = document()
        proof = self.prepare(source)
        before = proof.to_dict()
        source['components'].clear()
        detached = proof.to_dict()
        detached['units'].clear()
        detached['counts']['source_units'] = 0
        self.assertEqual(proof.to_dict(), before)
        self.assertEqual(proof.expectation_sha256, digest(before))
        with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
            proof.expectation_sha256 = '0' * 64

    def test_summary_repr_and_errors_expose_no_literal_report_text(self):
        sentinel = 'SYNTHETIC-PRIVATE-LITERAL'
        source = document(paragraph=sentinel)
        proof = self.prepare(source)
        summary = proof.summary()
        self.assertNotIn(sentinel, json.dumps(summary))
        self.assertNotIn('units', summary)
        self.assertNotIn(sentinel, repr(proof))
        self.assertEqual(summary['expectation_sha256'], proof.expectation_sha256)
        with self.assertRaises(self.m.TypedPdfSourceError) as caught:
            self.prepare(source, '0' * 64)
        self.assertNotIn(sentinel, str(caught.exception))

    def test_preparation_performs_no_render_process_file_or_network_operation(self):
        source = document()
        expected = digest(source)
        with patch('subprocess.Popen', side_effect=AssertionError('unexpected process')), \
             patch('socket.socket', side_effect=AssertionError('unexpected network')), \
             patch('builtins.open', side_effect=AssertionError('unexpected file')), \
             patch('reporting.typed_html._emit_typed_html',
                   side_effect=AssertionError('unexpected HTML rendering')):
            self.assertEqual(self.prepare(source, expected).to_dict()['counts']['source_units'], 10)

    def test_schema_accepts_real_output_and_rejects_claim_or_locator_expansion(self):
        path = ROOT / 'schemas/report-typed-pdf-source.v1.schema.json'
        self.assertTrue(path.is_file(), 'closed typed PDF source schema is missing')
        schema = json.loads(path.read_text())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        source = self.prepare().to_dict()
        self.assertFalse(list(validator.iter_errors(source)))
        for location, key, value in [
            ('root', 'pdf_sha256', 'a' * 64),
            ('root', 'rendered_content_validated', True),
            ('root', 'status', 'PASS'),
            ('unit', 'physical_page', 1),
            ('unit', 'row_ordinal', 0),
            ('unit', 'text_sha256', 'bad'),
            ('unit', 'scalars', -1),
            ('unit', 'ordinal', 100000),
        ]:
            changed = json.loads(json.dumps(source))
            target = changed if location == 'root' else changed['units'][0]
            target[key] = value
            self.assertTrue(list(validator.iter_errors(changed)), (location, key))
        changed = json.loads(json.dumps(source))
        del changed['units'][-1]['finding_id']
        self.assertTrue(list(validator.iter_errors(changed)))


if __name__ == '__main__':
    unittest.main()
