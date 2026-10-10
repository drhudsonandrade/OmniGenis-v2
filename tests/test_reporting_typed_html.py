"""Synthetic tests for explicit typed HTML preparation and independent checking."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator
from reporting import adapters, components, localization
from test_reporting_typed_projection import context

ROOT = Path(__file__).resolve().parents[1]


def digest(value):
    """Hash already bounded fixture JSON with the established canonical encoding."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode('utf-8')).hexdigest()


def document(count=2, text='Synthetic values only.', case='SYNTHETIC-CASE'):
    """Build real upstream boundaries using only synthetic snapshots."""
    request, ledger = context(count, case)
    parts = (components.TextComponent('title', 'identity', 'document_title', 'Technical report'),
        components.TextComponent('heading', 'findings', 'section_heading', 'Declared findings'),
        components.TextComponent('intro', 'findings', 'paragraph', text),
        components.FindingsTable('table', 'findings', 'All declared synthetic findings',
            (components.TableColumn('variant', 'Variant'), components.TableColumn('value', 'Value')),
            tuple(components.FindingRow(f, (f'NM_000001.1:c.{i+1}A>G', '0.12345678901234567890'))
                  for i, f in enumerate(request.plan.expected_finding_ids))))
    return components.build_typed_report_projection(request=request, ledger=ledger,
        projection_request_sha256=request.request.request_sha256,
        expected_content_sha256=components.component_content_sha256(parts), components=parts).to_dict()


class TypedHtmlTests(unittest.TestCase):
    """HTML preparation never claims PDF, authorization or visual qualification."""

    def setUp(self):
        """Require the missing production boundary before each independent case."""
        self.assertIsNotNone(importlib.util.find_spec('reporting.typed_html'),
                             'typed HTML preparation module is missing')
        self.m = importlib.import_module('reporting.typed_html')
        self.doc = document()
        self.sha = digest(self.doc)

    def localized(self, data=None, sha=None, locale='en-US'):
        """Use the explicit locale boundary, not a raw adapter input shortcut."""
        return localization.localize_typed_projection(presentation_ir=self.doc if data is None else data,
            expected_projection_sha256=self.sha if sha is None else sha, locale_id=locale)

    def build(self, data=None):
        """Follow the native LocalizationResult handoff to the existing adapter module."""
        data = self.doc if data is None else data
        loc = self.localized(data=data, sha=digest(data))
        self.assertTrue(loc.passed, loc.errors)
        return adapters.build_typed_html_adapter(localized_ir=loc.to_dict()['localized_ir'],
            expected_ir_sha256=loc.localized_ir_sha256)

    def verify(self, html=None, data=None, expected_html=None):
        """Rehash altered HTML so negative tests exercise semantics, not only identity."""
        html = self.build().html if html is None else html
        data = self.doc if data is None else data
        return self.m.validate_typed_html(presentation_ir=data, expected_ir_sha256=digest(data),
            html=html, expected_html_sha256=expected_html or hashlib.sha256(html.encode()).hexdigest())

    def reject_html(self, html):
        """Require a fixed failure without a partial conformance result."""
        with self.assertRaises(self.m.TypedHtmlError):
            self.verify(html=html)

    def test_identity_locale_retains_all_metadata_and_text(self):
        """en-US identity selection does not rewrite already admitted content."""
        result = self.localized()
        self.assertTrue(result.passed)
        self.assertEqual(result.to_dict()['localized_ir'], self.doc)
        self.assertEqual(result.localized_ir_sha256, self.sha)

    def test_unsupported_locale_never_falls_back(self):
        """Locale input is exact and no unsupported language is claimed."""
        for locale in ('pt-BR', 'fr-FR', 'en', 'en-us', None, True, ['en-US']):
            with self.subTest(locale=locale):
                self.assertFalse(self.localized(locale=locale).passed)

    def test_localization_requires_independently_expected_digest(self):
        """No missing or stale identity becomes a matching snapshot."""
        for sha in ('0' * 64, '', 'A' * 64, 1):
            self.assertFalse(self.localized(sha=sha).passed)

    def test_no_catalog_substitution_for_prelocalized_components(self):
        """The old label catalog cannot replace typed text or expand language support."""
        with patch.object(localization, '_load_locale', side_effect=AssertionError('catalog access')):
            self.assertTrue(self.localized().passed)

    def test_html_uses_semantic_headings_and_table_not_json_pre(self):
        """All four current kinds have real HTML elements and accessible table labels."""
        result = self.build()
        self.assertTrue(result.passed, result.errors)
        for tag in ('<h1 ', '<h2 ', '<p ', '<table ', '<caption>', '<thead>', '<tbody>', '<th '):
            self.assertIn(tag, result.html)
        self.assertNotIn('<pre', result.html)
        self.assertIn('scope="col"', result.html)
        self.assertIn('NM_000001.1:c.1A&gt;G', result.html)
        self.assertIn('0.12345678901234567890', result.html)

    def test_result_is_html_only_and_never_final(self):
        """A successful preparation has no PDF artifact or delivery authority."""
        result = self.build()
        self.assertIsNone(result.pdf_bytes)
        self.assertIsNone(result.pdf_sha256)
        self.assertEqual(result.pdf_status, 'DISABLED')
        self.assertEqual(result.pdf_reason, 'typed_pdf_profile_not_qualified')
        self.assertEqual(result.conformance['conformance_scope'], 'TYPED_HTML_STRUCTURE_AND_TEXT_ONLY')
        self.assertEqual(result.conformance['release_authorization'], 'NOT_ESTABLISHED')
        self.assertFalse(result.conformance['pdf_validated'])
        self.assertFalse(result.conformance['visual_layout_validated'])

    def test_preparation_does_not_launch_native_renderer_or_fetch_resources(self):
        """The new entrypoint performs no PDF, file, URL or subprocess operation."""
        with (patch.object(adapters, '_render_pdf', side_effect=AssertionError('native renderer')),
              patch.object(adapters, '_pdf_stack_readiness', side_effect=AssertionError('stack probe'))):
            self.assertTrue(self.build().passed)

    def test_markup_and_url_like_data_remain_literal(self):
        """Stored text cannot become active tags, links or template evaluation."""
        data = document(text='<script>alert(1)</script> ${value} file:///private & <img src=x>')
        result = self.build(data)
        self.assertTrue(result.passed)
        self.assertNotIn('<script>', result.html)
        self.assertNotIn('<img ', result.html)
        self.assertIn('&lt;script&gt;', result.html)
        self.assertTrue(self.verify(html=result.html, data=data).passed)

    def test_entity_like_source_text_is_not_decoded_twice(self):
        """Literal ampersand entities remain the exact source characters."""
        data = document(text='&amp; &#x61; &lt; &unknown;')
        result = self.build(data)
        self.assertIn('&amp;amp;', result.html)
        self.assertTrue(self.verify(html=result.html, data=data).passed)

    def test_unicode_and_whitespace_are_not_normalized(self):
        """Scientific scalar spelling and whitespace remain exact text-node values."""
        data = document(text='alpha\r\nbeta\t  Gamma e\u0301 \u00e9 \u03bc')
        result = self.build(data)
        self.assertTrue(result.passed)
        self.assertIn('&#13;', result.html)
        self.assertNotIn('\r', result.html)
        self.assertTrue(self.verify(html=result.html, data=data).passed)

    def test_zero_one_and_many_rows_survive(self):
        """All admitted rows are emitted, not a fixed illustrative subset."""
        for n in (0, 1, 5000):
            with self.subTest(rows=n):
                result = self.build(document(n))
                self.assertTrue(result.passed, result.errors)
                self.assertEqual(result.conformance['counts']['table_rows'], n)
                self.assertEqual(result.html.count('<tr data-finding='), n)

    def test_missing_row_fails_even_with_matching_candidate_hash(self):
        """An altered valid-looking HTML file cannot hide one omitted finding."""
        html = self.build().html
        a = html.index('<tr data-finding="F0">'); b = html.index('</tr>', a) + 5
        self.reject_html(html[:a] + html[b:])

    def test_duplicate_row_fails(self):
        """Duplicate rendering cannot inflate the declared inventory."""
        html = self.build().html
        a = html.index('<tr data-finding="F0">'); b = html.index('</tr>', a) + 5
        self.reject_html(html[:b] + html[a:b] + html[b:])

    def test_row_reordering_fails(self):
        """Reordering all the correct values is still a different projection."""
        html = self.build().html
        a = html.index('<tr data-finding="F0">'); b = html.index('</tr>', a) + 5
        c = html.index('<tr data-finding="F1">'); d = html.index('</tr>', c) + 5
        self.reject_html(html[:a] + html[c:d] + html[a:b] + html[d:])

    def test_changed_value_or_identifier_fails(self):
        """Precision loss and row identity changes are independently detected."""
        html = self.build().html
        for old, new in [('0.12345678901234567890', '0.1235'), ('c.1A&gt;G', 'c.2A&gt;G'),
                         ('data-finding="F0"', 'data-finding="FOREIGN"')]:
            self.reject_html(html.replace(old, new, 1))

    def test_extra_or_empty_cell_fails(self):
        """A table must preserve every declared rectangular cell."""
        html = self.build().html
        self.reject_html(html.replace('</tr></tbody>', '<td>extra</td></tr></tbody>'))
        self.reject_html(html.replace('<td>0.12345678901234567890</td>', '<td></td>', 1))

    def test_caption_and_header_text_are_required(self):
        """Table labels are checked as content, not decoration."""
        html = self.build().html
        for old in ('All declared synthetic findings', '>Variant</th>'):
            self.reject_html(html.replace(old, '', 1))

    def test_column_scope_and_component_context_are_checked(self):
        """Accessibility attributes and opaque component bindings cannot change."""
        html = self.build().html
        for old, new in [('scope="col"', 'scope="row"'), ('data-section="findings"', 'data-section="identity"'),
                         ('data-column="variant"', 'data-column="other"')]:
            self.reject_html(html.replace(old, new, 1))

    def test_active_content_and_unregistered_links_are_rejected(self):
        """The entire grammar excludes resource, action and executable elements."""
        html = self.build().html
        for payload in ('<script>x</script>', '<img src="https://example.invalid/x">',
                        '<a href="javascript:x">x</a>', '<iframe></iframe>', '<style>p{display:none}</style>',
                        '<svg onload="x"></svg>', '<input value="x">'):
            self.reject_html(html.replace('</body>', payload + '</body>'))

    def test_unexpected_or_duplicate_attributes_are_rejected(self):
        """A matched title cannot carry event handlers or styling side effects."""
        html = self.build().html
        for payload in ('onclick="x" ', 'style="display:none" ', 'id="duplicate" '):
            self.reject_html(html.replace('<h1 ', '<h1 ' + payload, 1))

    def test_comments_declarations_and_processing_instructions_are_closed(self):
        """Invisible channels and external identifiers are not accepted markup."""
        html = self.build().html
        for payload in ('<!-- hidden -->', '<?target secret?>', '<!DOCTYPE html SYSTEM "file:///private">'):
            self.reject_html(payload + html)

    def test_incomplete_or_trailing_structure_fails(self):
        """An unclosed or extended document is not a complete checked artifact."""
        html = self.build().html
        for candidate in (html[:-7], html + 'hidden', html.replace('</table>', '', 1),
                          html.replace('<meta charset="utf-8">', '<meta charset="utf-8"/>')):
            self.reject_html(candidate)

    def test_wrong_html_language_fails(self):
        """Document-level language remains the exact requested supported profile."""
        self.reject_html(self.build().html.replace('lang="en-US"', 'lang="fr-FR"'))

    def test_expected_html_digest_is_mandatory(self):
        """An otherwise valid candidate cannot be rebound to stale evidence."""
        with self.assertRaises(self.m.TypedHtmlError):
            self.verify(expected_html='0' * 64)

    def test_foreign_case_projection_rejected_before_emission(self):
        """Shared table contents cannot substitute for the expected case digest."""
        with patch.object(self.m, '_emit_typed_html', side_effect=AssertionError('emitted foreign IR')):
            result = adapters.build_typed_html_adapter(localized_ir=document(case='FOREIGN'), expected_ir_sha256=self.sha)
        self.assertFalse(result.passed)
        self.assertIsNone(result.html)

    def test_closed_root_and_nested_fields_reject_rehashed_invalid_input(self):
        """A valid digest is not a substitute for the declared input grammar."""
        for path in ((), ('components', 0), ('components', 3, 'rows', 0)):
            data = json.loads(json.dumps(self.doc)); node = data
            for k in path: node = node[k]
            node['unexpected'] = 'x'
            self.assertFalse(self.localized(data=data, sha=digest(data)).passed)

    def test_invalid_counts_flags_and_component_type_fail(self):
        """Truth-like values and future components cannot pass current validation."""
        for key, val in (('status', 'FINAL'), ('report_id', 'foreign'), ('locale_id', 'pt-BR'),
                         ('source_semantics_validated', True), ('release_authorization', 'GRANTED')):
            data = dict(self.doc); data[key] = val
            self.assertFalse(self.localized(data=data, sha=digest(data)).passed)
        for val in (True, 99, -1):
            data = json.loads(json.dumps(self.doc)); data['counts']['table_rows'] = val
            self.assertFalse(self.localized(data=data, sha=digest(data)).passed)

    def test_missing_and_reordered_section_records_fail(self):
        """The HTML path does not silently discard typed section invariants."""
        data = json.loads(json.dumps(self.doc)); data['section_states'].pop(0)
        self.assertFalse(self.localized(data=data, sha=digest(data)).passed)
        data = json.loads(json.dumps(self.doc)); data['components'][0], data['components'][1] = data['components'][1], data['components'][0]
        self.assertFalse(self.localized(data=data, sha=digest(data)).passed)

    def test_hostile_native_input_is_rejected_before_serializer(self):
        """Cycles, subclasses and unknown objects are outside the sealed input contract."""
        cycle = {}; cycle['self'] = cycle
        class ForeignDict(dict):
            def items(self):
                raise AssertionError('foreign mapping enumerated')
        for value in (cycle, ForeignDict(self.doc), SimpleNamespace(passed=True), []):
            with patch.object(self.m, '_emit_typed_html', side_effect=AssertionError('serializer invoked')):
                result = adapters.build_typed_html_adapter(localized_ir=value, expected_ir_sha256=self.sha)
            self.assertFalse(result.passed)

    def test_html_budget_rejects_whole_output_and_precedes_parsing(self):
        """Finite output admission never returns a truncated successful candidate."""
        with patch.object(self.m, 'MAX_HTML_BYTES', 128):
            self.assertFalse(self.build().passed)
            with patch.object(self.m, '_check_html_events', side_effect=AssertionError('oversized HTML parsed')):
                with self.assertRaises(self.m.TypedHtmlError):
                    self.verify(html='x' * 129)

    def test_ir_budget_precedes_hashing(self):
        """Existing bounded capture remains ahead of hashing unadmitted content."""
        from reporting import pdf_candidate_qa
        with patch.object(pdf_candidate_qa, 'MAX_PDF_BYTES', 128):
            self.assertFalse(self.localized().passed)

    def test_independent_checker_detects_serializer_omission(self):
        """The adapter verifies actual HTML rather than certifying its own assumptions."""
        bad = self.build().html.replace('Synthetic values only.', '')
        with patch.object(self.m, '_emit_typed_html', return_value=bad):
            result = self.build()
        self.assertFalse(result.passed)
        self.assertIsNone(result.html)

    def test_forged_validation_result_does_not_admit_html(self):
        """A success-looking object is not the expected validated evidence type."""
        with patch.object(self.m, 'validate_typed_html', return_value=SimpleNamespace(passed=True)):
            result = self.build()
        self.assertFalse(result.passed)
        self.assertIsNone(result.html)

    def test_direct_validator_construction_runs_the_same_checks(self):
        """No public constructor accepts a success flag in place of verification."""
        html = self.build().html
        kwargs = dict(presentation_ir=self.doc, expected_ir_sha256=self.sha, html=html,
                      expected_html_sha256=hashlib.sha256(html.encode()).hexdigest())
        with self.assertRaises(TypeError):
            self.m.TypedHtmlValidation(**kwargs, passed=True)
        kwargs['html'] = html.replace('Technical report', 'changed')
        with self.assertRaises(self.m.TypedHtmlError):
            self.m.TypedHtmlValidation(**kwargs)

    def test_evidence_is_immutable_and_diagnostics_are_content_free(self):
        """Metadata exposes digests/counts, not case IDs, text or source objects."""
        result = self.verify()
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            result.html_sha256 = '0' * 64
        text = json.dumps(result.to_dict()) + repr(result)
        for marker in ('Technical report', 'SYNTHETIC-CASE', 'NM_000001', '0.123456789'):
            self.assertNotIn(marker, text)
        self.assertEqual(result.to_dict()['counts']['not_present_sections'], 1)

    def test_schema_matches_real_evidence_and_is_closed(self):
        """The evidence schema cannot silently advertise broader validation."""
        schema = json.loads((ROOT/'schemas/report-typed-html-evidence.v1.schema.json').read_text())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        data = self.verify().to_dict()
        self.assertEqual(list(validator.iter_errors(data)), [])
        for key, value in (('extra', 1), ('pdf_validated', True), ('release_authorization', 'GRANTED')):
            bad = dict(data); bad[key] = value
            self.assertTrue(list(validator.iter_errors(bad)))

    def test_legacy_pdf_entrypoint_still_rejects_new_profile(self):
        """Native PDF support cannot be inferred from an HTML preparation result."""
        with patch.object(adapters, '_render_pdf', side_effect=AssertionError('legacy renderer')):
            self.assertFalse(adapters.build_html_css_and_pdf_adapter(presentation_ir=self.doc).passed)

    def test_input_is_unchanged_after_success_and_rejection(self):
        """No transformation mutates the sealed source projection."""
        before = json.dumps(self.doc, sort_keys=True)
        self.build(); self.reject_html(self.build().html.replace('Technical report', 'changed'))
        self.assertEqual(before, json.dumps(self.doc, sort_keys=True))
        exposed = self.localized().to_dict()['localized_ir']; exposed['components'][0]['text'] = 'foreign'
        self.assertEqual(before, json.dumps(self.doc, sort_keys=True))

    def test_equivalent_entities_preserve_semantics_without_active_content(self):
        """An equivalent numeric entity is valid only when every event remains exact."""
        html = self.build().html.replace('Technical report', 'Technic&#97;l report')
        self.assertTrue(self.verify(html=html).passed)

    def test_malformed_declarations_do_not_expose_parser_diagnostics(self):
        """Malformed declaration text must not escape through a standard-library error."""
        html = '<![PRIVATE-PARSER-MARKER]>' + self.build().html
        with self.assertRaises(self.m.TypedHtmlError) as caught:
            self.verify(html=html)
        self.assertNotIn('PRIVATE-PARSER-MARKER', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
