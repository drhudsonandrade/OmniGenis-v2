"""Synthetic tests for a closed, request-bound logical content projection."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator
from reporting.bindings import ReportArtifactBinding, ReportSourceBinding, ReportSourceIdentity, bind_report_sources
from reporting.completeness import ReportCompletenessPlan, FindingProjection, SectionAvailability, validate_report_completeness
from reporting.requests import ReportRequestSnapshot, bind_report_request
from reporting.workflow import ConsentStatus, ReviewState

ROOT = Path(__file__).resolve().parents[1]


def context(count=2, case='SYNTHETIC-CASE'):
    """Bind synthetic snapshots and a declared row inventory, not real science."""
    raw, evidence = b'SYNTHETIC-RESULT-0.12345678901234567890', b'SYNTHETIC-EVIDENCE'
    identity = ReportSourceIdentity('SYNTHETIC-NS', case, 'SYNTHETIC-SUBJECT',
                                    'SYNTHETIC-SAMPLE', 'SYNTHETIC-ANALYSIS', '1', None)
    binding = ReportSourceBinding(identity, ReportArtifactBinding('INPUT', 'a' * 64),
        ReportArtifactBinding('RESULT', hashlib.sha256(raw).hexdigest()),
        ReportArtifactBinding('EVIDENCE', hashlib.sha256(evidence).hexdigest()), 'b' * 64)
    sources = bind_report_sources(expected_binding=binding, resolved_binding=binding,
                                  canonical_result_bytes=raw, evidence_snapshot_bytes=evidence)
    plan = ReportCompletenessPlan(binding.binding_sha256, tuple(f'F{i}' for i in range(count)),
        ('identity', 'findings', 'optional'), ('identity', 'findings'))
    snapshot = ReportRequestSnapshot('SYNTHETIC-REQUEST', 'SYNTHETIC-REQUESTER', binding,
        plan.plan_sha256, 'c' * 64, ReportArtifactBinding('LOCALE', 'd' * 64),
        ReportArtifactBinding('POLICY', 'e' * 64), ConsentStatus.VERIFIED,
        ReportArtifactBinding('CONSENT', 'f' * 64), ReviewState.APPROVED,
        ReportArtifactBinding('REVIEW', '0' * 64))
    request = bind_report_request(request=snapshot, resolved_request=snapshot, sources=sources, plan=plan)
    ledger = validate_report_completeness(sources=sources, plan=plan,
        projection_source_binding_sha256=binding.binding_sha256, projection_plan_sha256=plan.plan_sha256,
        represented=tuple(FindingProjection(f, 'findings', ('table',)) for f in plan.expected_finding_ids),
        section_states=(SectionAvailability('identity', 'PRESENT'), SectionAvailability('findings', 'PRESENT'),
                        SectionAvailability('optional', 'NOT_AVAILABLE', 'NOT_SUPPLIED')))
    return request, ledger


class TypedProjectionTests(unittest.TestCase):
    """Closed content preserves declared meaning without activating a renderer."""

    def setUp(self):
        """Fail explicitly until the real component boundary has been implemented."""
        self.assertIsNotNone(importlib.util.find_spec('reporting.components'), 'typed component module is missing')
        self.m = importlib.import_module('reporting.components')
        self.request, self.ledger = context()
        self.parts = self.components(self.request.plan.expected_finding_ids)

    def components(self, ids):
        """Create plain-text and table fixtures for two actual component use cases."""
        m = self.m
        return (m.TextComponent('title', 'identity', 'document_title', 'Technical report'),
                m.TextComponent('heading', 'findings', 'section_heading', 'Declared findings'),
                m.TextComponent('intro', 'findings', 'paragraph', 'Synthetic values only.'),
                m.FindingsTable('table', 'findings', 'All declared synthetic findings',
                    (m.TableColumn('variant', 'Variant'), m.TableColumn('value', 'Value')),
                    tuple(m.FindingRow(f, (f'NM_000001.1:c.{i + 1}A>G', '0.12345678901234567890'))
                          for i, f in enumerate(ids))))

    def build(self, **changes):
        """Supply an independently pinned content digest to the public factory."""
        parts = changes.pop('components', self.parts)
        values = dict(request=self.request, ledger=self.ledger,
                      projection_request_sha256=self.request.request.request_sha256,
                      expected_content_sha256=self.m.component_content_sha256(parts), components=parts)
        values.update(changes)
        return self.m.build_typed_report_projection(**values)

    def reject(self, **changes):
        """No malformed input may return a partial typed projection."""
        with self.assertRaises(self.m.ComponentError):
            self.build(**changes)

    def test_exact_projection_has_truthful_scope(self):
        """Structural projection is not scientific, rendering or release approval."""
        data = self.build().to_dict()
        self.assertEqual(data['profile_id'], 'typed-report-projection-v1')
        self.assertEqual(data['status'], 'PROJECTED')
        self.assertEqual(data['conformance_scope'], 'DECLARED_TYPED_PROJECTION_ONLY')
        self.assertEqual(data['release_authorization'], 'NOT_ESTABLISHED')
        self.assertFalse(data['source_semantics_validated'])
        self.assertFalse(data['rendered_content_validated'])
        self.assertEqual(data['request_sha256'], self.request.request.request_sha256)
        self.assertEqual(data['ledger_sha256'], self.ledger.ledger_sha256)

    def test_all_table_cells_and_precision_are_preserved(self):
        """Numeric-looking strings and versioned identifiers are never recoded."""
        table = self.build().to_dict()['components'][-1]
        self.assertEqual(table['rows'][0]['cells'], ['NM_000001.1:c.1A>G', '0.12345678901234567890'])
        self.assertEqual([r['finding_id'] for r in table['rows']], ['F0', 'F1'])

    def test_initial_registry_contains_only_admitted_types(self):
        """No staged figure or old semantic-section alias is activated silently."""
        self.assertEqual(self.m.COMPONENT_TYPES, frozenset({'document_title', 'section_heading', 'paragraph', 'findings_table'}))
        for kind in ('html', 'chart', 'figure', 'semantic-section', True):
            with self.subTest(kind=kind), self.assertRaises(self.m.ComponentError):
                self.m.TextComponent('x', 'findings', kind, 'value')

    def test_markup_is_inert_plain_text_not_an_html_field(self):
        """Untrusted markup-like content is retained literally, never evaluated."""
        text = '<script>alert(1)</script> ${value} & < 0.1'
        part = replace(self.parts[2], text=text)
        data = self.build(components=self.parts[:2] + (part, self.parts[3])).to_dict()
        self.assertEqual(data['components'][2]['text'], text)
        self.assertEqual(data['components'][2]['text_format'], 'plain')
        with self.assertRaises(TypeError):
            self.m.TextComponent('x', 'findings', 'paragraph', 'value', html='<b>x</b>')

    def test_legacy_adapter_rejects_the_unqualified_typed_profile(self):
        """New contracts cannot enter an unchanged semantic-section PDF path."""
        from reporting.adapters import build_html_css_and_pdf_adapter
        result = build_html_css_and_pdf_adapter(presentation_ir=self.build().to_dict())
        self.assertFalse(result.passed)
        self.assertIsNone(result.pdf_bytes)

    def test_long_scientific_display_identifiers_remain_intact(self):
        """A long display label is not shortened to the opaque join-key width."""
        text = 'NM_000001.1:c.' + 'A' * 4000 + '>G'
        row = replace(self.parts[-1].rows[0], cells=(text, '0'))
        table = replace(self.parts[-1], rows=(row, self.parts[-1].rows[1]))
        data = self.build(components=self.parts[:-1] + (table,)).to_dict()
        self.assertEqual(data['components'][-1]['rows'][0]['cells'][0], text)

    def test_caption_headers_and_nonempty_display_values_are_required(self):
        """Accessible table context cannot be an empty placeholder."""
        for op in (lambda: replace(self.parts[-1], caption=''),
                   lambda: self.m.TableColumn('x', ''),
                   lambda: replace(self.parts[0], text='   ')):
            with self.assertRaises(self.m.ComponentError):
                op()

    def test_invalid_scalars_and_unicode_controls_are_rejected(self):
        """Unsupported objects, non-finite numbers and invalid text never coerce."""
        for value in (None, 3, True, float('nan'), 'x\x00y', 'x\ud800y', 'x\u202ey'):
            with self.subTest(kind=type(value).__name__), self.assertRaises(self.m.ComponentError):
                replace(self.parts[2], text=value)

    def test_component_identifiers_remain_exact_and_bounded(self):
        """Names, path traversal and whitespace cannot become logical join keys."""
        for value in ('../escape', '', ' x', 'x' * 257, True):
            with self.assertRaises(self.m.ComponentError):
                replace(self.parts[0], component_id=value)

    def test_missing_table_row_is_rejected(self):
        """A successful ledger cannot hide a row omitted by presentation."""
        table = replace(self.parts[-1], rows=self.parts[-1].rows[:1])
        self.reject(components=self.parts[:-1] + (table,))

    def test_unknown_table_row_is_rejected(self):
        """A table cannot create an undeclared finding."""
        table = replace(self.parts[-1], rows=self.parts[-1].rows + (self.m.FindingRow('FOREIGN', ('x', 'y')),))
        self.reject(components=self.parts[:-1] + (table,))

    def test_duplicate_table_rows_are_rejected(self):
        """Repeated row identities do not inflate the finding count."""
        with self.assertRaises(self.m.ComponentError):
            replace(self.parts[-1], rows=self.parts[-1].rows * 2)

    def test_table_row_order_matches_the_declared_inventory(self):
        """Presentation cannot silently reorder a declared source priority."""
        table = replace(self.parts[-1], rows=self.parts[-1].rows[::-1])
        self.reject(components=self.parts[:-1] + (table,))

    def test_table_width_must_match_all_columns(self):
        """Extra and missing cells are failures, not silently dropped values."""
        for cells in (('x',), ('x', 'y', 'z')):
            with self.assertRaises(self.m.ComponentError):
                replace(self.parts[-1], rows=(self.m.FindingRow('F0', cells),))

    def test_duplicate_and_empty_column_sets_are_rejected(self):
        """Column identity and labels define a complete rectangular table."""
        for columns in ((), self.parts[-1].columns[:1] * 2):
            with self.assertRaises(self.m.ComponentError):
                replace(self.parts[-1], columns=columns)

    def test_ledger_locator_must_resolve_to_the_actual_table(self):
        """A renamed component cannot satisfy a stale finding locator."""
        table = replace(self.parts[-1], component_id='another-table')
        self.reject(components=self.parts[:-1] + (table,))

    def test_finding_table_must_remain_in_its_bound_section(self):
        """The same row IDs in a different section do not preserve projection."""
        table = replace(self.parts[-1], section_id='identity')
        self.reject(components=(self.parts[0], table) + self.parts[1:3])

    def test_absent_and_unknown_sections_cannot_receive_content(self):
        """Unavailable source sections stay explicit, not filled by inference."""
        for section in ('optional', 'foreign'):
            part = replace(self.parts[2], section_id=section)
            self.reject(components=self.parts[:2] + (part, self.parts[3]))

    def test_present_sections_need_actual_components(self):
        """Removing the only identity section content is not complete projection."""
        title = replace(self.parts[0], section_id='findings')
        self.reject(components=(title,) + self.parts[1:])

    def test_component_ids_are_globally_unique(self):
        """Duplicate IDs cannot make logical locations ambiguous."""
        part = replace(self.parts[2], component_id='heading')
        self.reject(components=self.parts[:2] + (part, self.parts[3]))

    def test_cross_case_context_is_rejected(self):
        """Equal text and findings never permit another sample's request."""
        foreign, unused = context(case='SYNTHETIC-OTHER-CASE')
        self.reject(request=foreign, projection_request_sha256=foreign.request.request_sha256)

    def test_stale_request_digest_is_rejected(self):
        """The whole request revision, not only source identity, is pinned."""
        self.reject(projection_request_sha256='f' * 64)

    def test_ledger_from_another_declared_plan_is_rejected(self):
        """Source bytes alone cannot reconcile changed finding expectations."""
        unused, ledger = context(count=1)
        self.reject(ledger=ledger)

    def test_changed_content_cannot_reuse_the_expected_digest(self):
        """Exact pinned content includes punctuation, whitespace and numeric text."""
        digest = self.m.component_content_sha256(self.parts)
        part = replace(self.parts[2], text='Changed value.')
        self.reject(components=self.parts[:2] + (part, self.parts[3]), expected_content_sha256=digest)

    def test_locale_support_is_not_inferred_from_text(self):
        """Only the existing request locale is admitted in the first profile."""
        for locale in ('pt-BR', 'en-us', None, True):
            with self.assertRaises(self.m.ComponentError):
                replace(self.parts[2], locale_id=locale)

    def test_protected_tokens_must_survive_without_normalization(self):
        """Exact token retention is checked separately from text formatting."""
        part = replace(self.parts[2], text='NM_1.2:c.1A>G is 0.001', protected_tokens=('NM_1.2:c.1A>G', '0.001'))
        self.build(components=self.parts[:2] + (part, self.parts[3]))
        with self.assertRaises(self.m.ComponentError):
            replace(part, text='NM_1.2:c.1A>G is 0.01')
        with self.assertRaises(self.m.ComponentError):
            replace(self.parts[-1].rows[0], protected_tokens=('MISSING',))

    def test_mutable_containers_and_duck_types_are_rejected(self):
        """No unsafe conversion creates an apparently immutable projection."""
        for op in (lambda: replace(self.parts[-1], rows=list(self.parts[-1].rows)),
                   lambda: self.m.FindingRow('F0', ['x', 'y']),
                   lambda: replace(self.parts[2], protected_tokens=['x']),
                   lambda: self.m.component_content_sha256(list(self.parts)),
                   lambda: self.build(request=SimpleNamespace(passed=True))):
            with self.assertRaises(self.m.ComponentError):
                op()

    def test_direct_constructor_has_the_same_guard(self):
        """A result constructor never accepts an injectable success flag."""
        args = dict(request=self.request, ledger=self.ledger, components=self.parts,
                    projection_request_sha256='f' * 64,
                    expected_content_sha256=self.m.component_content_sha256(self.parts))
        with self.assertRaises(self.m.ComponentError):
            self.m.TypedReportProjection(**args)
        with self.assertRaises(TypeError):
            self.m.TypedReportProjection(**args, status='PROJECTED')

    def test_zero_one_and_many_rows_are_not_truncated(self):
        """All admitted rows survive, independent of illustrative report lengths."""
        for count in (0, 1, 1000):
            with self.subTest(count=count):
                request, ledger = context(count)
                result = self.build(request=request, ledger=ledger,
                    projection_request_sha256=request.request.request_sha256,
                    components=self.components(request.plan.expected_finding_ids))
                self.assertEqual(len(result.to_dict()['components'][-1]['rows']), count)
                self.assertEqual(result.summary()['counts']['represented_findings'], count)

    def test_document_has_one_title_first(self):
        """The initial closed document profile has an unambiguous top-level title."""
        self.reject(components=self.parts[1:] + self.parts[:1])
        title = replace(self.parts[0], component_id='title2')
        self.reject(components=(self.parts[0], title) + self.parts[1:])

    def test_no_raw_sources_or_identity_in_diagnostic_summary(self):
        """Projection evidence retains hashes, not raw source or requester data."""
        result = self.build()
        summary = json.dumps(result.summary()) + repr(result)
        for value in ('SYNTHETIC-CASE', 'SYNTHETIC-REQUESTER', 'SYNTHETIC-EVIDENCE', '0.123456789'):
            self.assertNotIn(value, summary)
        self.assertFalse(hasattr(result, 'sources'))
        self.assertFalse(hasattr(result, 'request'))
        self.assertFalse(hasattr(result, 'ledger'))

    def test_snapshots_stay_frozen_and_exported_containers_are_detached(self):
        """Detached serialization cannot mutate the retained typed records."""
        result = self.build()
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            result.components = ()
        original = result.to_dict()
        export = result.to_dict(); export['components'][-1]['rows'][0]['cells'][0] = 'changed'
        self.assertEqual(result.to_dict(), original)
        self.assertEqual(result.projection_sha256, self.build().projection_sha256)

    def test_closed_schema_accepts_exact_output_and_rejects_extensions(self):
        """The schema is self-contained and cannot pretend to certify release."""
        schema = json.loads((ROOT / 'schemas/report-typed-projection.v1.schema.json').read_text())
        Draft202012Validator.check_schema(schema); validator = Draft202012Validator(schema)
        data = self.build().to_dict(); self.assertEqual(list(validator.iter_errors(data)), [])
        for key, value in (('extra', True), ('release_authorization', 'GRANTED'),
                           ('source_semantics_validated', True), ('profile_id', 'other')):
            mutated = json.loads(json.dumps(data)); mutated[key] = value
            self.assertTrue(list(validator.iter_errors(mutated)), key)
        mutated = json.loads(json.dumps(data)); mutated['components'][2]['html'] = '<b>bad</b>'
        self.assertTrue(list(validator.iter_errors(mutated)))

    def test_scalar_budget_rejects_without_truncation(self):
        """A scalar exceeding admission never becomes a shortened valid record."""
        text = 'x' * (self.m.MAX_TEXT_BYTES + 1)
        with self.assertRaisesRegex(self.m.ComponentError, 'component_budget_exceeded'):
            replace(self.parts[2], text=text)

    def test_aggregate_item_budget_precedes_serialization(self):
        """Repeated references cannot multiply serialization before admission."""
        with patch.object(self.m, 'MAX_COMPONENT_ITEMS', 2), patch.object(self.m.json, 'dumps', side_effect=AssertionError('serialized before admission')):
            with self.assertRaisesRegex(self.m.ComponentError, 'component_budget_exceeded'):
                self.m.component_content_sha256(self.parts)

    def test_aggregate_utf8_budget_counts_all_text_values(self):
        """Non-ASCII bytes and repeated cells count toward the full input budget."""
        with patch.object(self.m, 'MAX_COMPONENT_TEXT_BYTES', 12):
            with self.assertRaisesRegex(self.m.ComponentError, 'component_budget_exceeded'):
                self.m.component_content_sha256(self.parts)

    def test_digest_types_are_exact(self):
        """Malformed digest strings cannot be normalized into a source claim."""
        for digest in (None, True, 'A' * 64, 'f' * 63, 'f' * 64 + '\n'):
            self.reject(expected_content_sha256=digest)

    def test_source_bytes_and_existing_ledger_are_unchanged(self):
        """Both successful and rejected projections leave upstream objects intact."""
        before = (self.request.sources.canonical_result_bytes, self.ledger.to_dict())
        self.build(); self.reject(projection_request_sha256='f' * 64)
        self.assertEqual(before, (self.request.sources.canonical_result_bytes, self.ledger.to_dict()))

    def test_protected_token_admission_bounds_match_work(self):
        """A record's token search work has an explicit finite admission bound."""
        tokens = tuple(f'T{i}' for i in range(65))
        with self.assertRaisesRegex(self.m.ComponentError, 'component_budget_exceeded'):
            replace(self.parts[2], text=' '.join(tokens), protected_tokens=tokens)

    def two_table_ledger(self):
        """Supply two explicit locators for each finding without changing counts."""
        return replace(self.ledger, represented=tuple(
            replace(finding, component_ids=('table', 'second-table'))
            for finding in self.ledger.represented))

    def test_multiple_explicit_locators_do_not_inflate_finding_counts(self):
        """A declared second representation adds rows, not extra findings."""
        table = replace(self.parts[-1], component_id='second-table')
        result = self.build(ledger=self.two_table_ledger(), components=self.parts + (table,))
        self.assertEqual(result.summary()['counts']['represented_findings'], 2)
        self.assertEqual(result.summary()['counts']['table_rows'], 4)

    def test_component_locator_order_is_preserved_across_tables(self):
        """Correct rows in reversed tables do not preserve declared locators."""
        table = replace(self.parts[-1], component_id='second-table')
        self.reject(ledger=self.two_table_ledger(), components=self.parts[:-1] + (table, self.parts[-1]))


if __name__ == '__main__':
    unittest.main()
