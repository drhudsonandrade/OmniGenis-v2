"""Whole generated-document text parity and exact native rejection boundaries."""
from __future__ import annotations

import ast
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
from html import escape
from io import BytesIO
import importlib
import importlib.util
import json
import os
from pathlib import Path
from tempfile import TemporaryFile
import unittest
from unittest.mock import patch

from reporting.page_windows import plan_pdf_page_windows
from reporting.pdf_text_windows import PROFILE_ID as TEXT_PROFILE
from reporting.pdf_content import _expected_content, validate_pdf_text_content

ROOT = Path(__file__).resolve().parents[1]


def generated_case(pages, ir=None):
    """Render only synthetic current-format source sections with real physical pages."""
    from weasyprint import HTML
    from weasyprint.urls import URLFetcher
    from pypdf import PdfReader
    if type(pages) is not int or not 1 <= pages <= 65:
        raise ValueError('synthetic fixture outside finite test domain')
    if ir is None:
        ir = {'report_id': 'SYNTHETIC-TEXT-REPORT', 'locale_id': 'en-US',
              'components': [{'component_type': 'semantic-section',
                'component_id': f'section-{i}', 'title': f'Synthetic section {i}',
                'state': 'PRESENT', 'content': {'text': f'Synthetic value {i}', 'value': i}}
                for i in range(1, pages + 1)]}
    parts = ['<html lang="en-US"><head><title>OmniGenis</title>',
             '<meta name="author" content="Hudson Silva Andrade">',
             '<meta name="generator" content="OmniGenis">',
             '<style>pre{white-space:pre-wrap}section+section{break-before:page}</style>',
             '</head><body>', '<h1>' + escape(ir['report_id']) + '</h1>']
    for c in ir['components']:
        text = json.dumps(c['content'], sort_keys=True, separators=(',', ':'),
                          ensure_ascii=False, allow_nan=False)
        parts.extend(['<section><h2>' + escape(c['title']) + '</h2>',
                      '<p>' + escape(c['state']) + '</p><pre>' + escape(text) + '</pre></section>'])
    parts.append('</body></html>')
    pdf = HTML(string=''.join(parts), url_fetcher=URLFetcher(
        allowed_protocols=(), allow_redirects=False, fail_on_errors=True)).write_pdf(
        pdf_variant='pdf/ua-1', pdf_version='1.7', pdf_identifier=bytes.fromhex('a' * 64))
    assert len(PdfReader(BytesIO(pdf), strict=True).pages) == pages
    return ir, pdf


def changed_pdf(pdf, change):
    """Rewrite one synthetic candidate with an explicit test mutation."""
    from pypdf import PdfWriter
    writer = PdfWriter(clone_from=BytesIO(pdf)); writer.pdf_header = b'%PDF-1.7'
    change(writer)
    output = BytesIO(); writer.write(output)
    return output.getvalue()


class PdfDocumentContentTests(unittest.TestCase):
    """No missing page, altered source or unsuccessful worker produces equality evidence."""

    @classmethod
    def setUpClass(cls):
        """Use shared immutable native fixtures only after the feature exists."""
        cls.cases = None

    def setUp(self):
        """Observe an explicit missing-feature RED before generating native fixtures."""
        self.assertIsNotNone(importlib.util.find_spec('reporting.pdf_document_content'),
                             'whole-document source-text validator is missing')
        self.m = importlib.import_module('reporting.pdf_document_content')
        self.worker = importlib.import_module('reporting._pdf_document_content_worker')
        if self.__class__.cases is None:
            self.__class__.cases = {n: generated_case(n) for n in (1, 33, 64)}
        self.ir, self.pdf = self.cases[1]
        self.ir = json.loads(json.dumps(self.ir))
        self.plan = self.make_plan(self.ir, self.pdf, 1)

    def make_plan(self, ir, pdf, pages):
        """Bind the expected source digest independently from the candidate bytes."""
        return plan_pdf_page_windows(pdf_sha256=sha256(pdf).hexdigest(),
            ir_sha256=_expected_content(ir)[0], page_count=pages,
            admitted_page_budget=pages, pages_per_window=16,
            inspector_profile_id=TEXT_PROFILE)

    def inspect(self, **changes):
        """Invoke the production boundary with exact independently alterable pins."""
        args = dict(presentation_ir=self.ir, pdf_bytes=self.pdf, plan=self.plan,
                    expected_plan_sha256=self.plan.plan_sha256,
                    expected_ir_sha256=self.plan.ir_sha256, expected_language='en-US')
        return self.m.inspect_pdf_document_content(**{**args, **changes})

    def reject_candidate(self, pdf, pages=1, ir=None):
        """A newly recomputed PDF hash cannot excuse disagreement with unchanged source."""
        ir = self.ir if ir is None else ir
        plan = self.make_plan(ir, pdf, pages)
        with self.assertRaises(self.m.PdfDocumentContentError):
            self.inspect(presentation_ir=ir, pdf_bytes=pdf, plan=plan,
                         expected_plan_sha256=plan.plan_sha256,
                         expected_ir_sha256=plan.ir_sha256)

    def test_native_one_thirty_three_and_sixty_four_pages(self):
        """Every physical page contributes to the current normalized source-text digest."""
        for count, (ir, pdf) in self.cases.items():
            with self.subTest(pages=count):
                plan = self.make_plan(ir, pdf, count)
                result = self.inspect(presentation_ir=ir, pdf_bytes=pdf, plan=plan,
                    expected_plan_sha256=plan.plan_sha256, expected_ir_sha256=plan.ir_sha256)
                d = result.to_dict()
                self.assertEqual(d['page_count'], count)
                self.assertEqual(d['inspected_pages'], count)
                self.assertEqual(d['expected_text_sha256'], _expected_content(ir)[1])
                self.assertEqual(d['expected_text_sha256'], d['extracted_text_sha256'])
                self.assertTrue(d['normalized_text_equivalence_verified'])
                self.assertFalse(d['release_authorized'])

    def test_small_profile_matches_existing_content_validator(self):
        """No new source projection or normalization is introduced for the existing profile."""
        old = validate_pdf_text_content(presentation_ir=self.ir,
            expected_ir_sha256=self.plan.ir_sha256, pdf_bytes=self.pdf,
            expected_pdf_sha256=self.plan.pdf_sha256)
        self.assertTrue(old.passed, old.errors)
        result = self.inspect().to_dict()
        self.assertEqual(result['expected_text_sha256'], old.expected_text_sha256)
        self.assertEqual(result['extracted_text_sha256'], old.extracted_text_sha256)

    def test_omitted_last_page_rejected_even_with_rehashed_pdf(self):
        """A new document hash and honest reduced page count cannot hide omitted source text."""
        ir, pdf = self.cases[33]
        altered = changed_pdf(pdf, lambda w: w.remove_page(32))
        self.reject_candidate(altered, 32, ir)

    def test_duplicated_page_rejected_even_with_rehashed_pdf(self):
        """Adding an extra valid content page must disagree with the source stream."""
        self.reject_candidate(changed_pdf(self.pdf, lambda w: w.add_page(w.pages[0])), 2)

    def test_reordered_page_sequence_rejected(self):
        """All pages present in the wrong order are not equivalent to source order."""
        ir, pdf = self.cases[33]
        def rotate(writer):
            """Move the first synthetic page to the end without editing its text."""
            page = writer.pages[0]; writer.remove_page(0); writer.add_page(page)
        self.reject_candidate(changed_pdf(pdf, rotate), 33, ir)

    def test_changed_numbers_case_and_spaces_are_not_normalized_away(self):
        """Changed values retain their distinct meaning under the unchanged whitespace rule."""
        for text in ('Changed value', 'synthetic value 1', 'Synthetic  value 1'):
            ir = json.loads(json.dumps(self.ir)); ir['components'][0]['content']['text'] = text
            _, pdf = generated_case(1, ir)
            self.reject_candidate(pdf)

    def test_altered_source_with_new_ir_digest_still_requires_equal_pdf(self):
        """Expected source hashes are not inferred from PDF extraction."""
        changed = json.loads(json.dumps(self.ir)); changed['components'][0]['content']['value'] = 999
        plan = self.make_plan(changed, self.pdf, 1)
        with self.assertRaises(self.m.PdfDocumentContentError):
            self.inspect(presentation_ir=changed, plan=plan,
                expected_plan_sha256=plan.plan_sha256, expected_ir_sha256=plan.ir_sha256)

    def test_absent_or_blank_content_page_rejected(self):
        """Blank pages do not disappear from the complete-document comparison."""
        self.reject_candidate(changed_pdf(self.pdf, lambda w: w.add_blank_page(width=612, height=792)), 2)

    def test_encryption_malformed_and_wrong_pdf_version_rejected(self):
        """Unsupported native input produces no successful content evidence."""
        self.reject_candidate(changed_pdf(self.pdf, lambda w: w.encrypt('synthetic-only')))
        for pdf in (b'not-pdf', self.pdf.replace(b'%PDF-1.7', b'%PDF-1.6', 1)):
            with self.assertRaises(self.m.PdfDocumentContentError): self.inspect(pdf_bytes=pdf)


    def test_input_byte_limit_and_native_bytes_only(self):
        """Mutable inputs and excessive byte counts cannot enter the worker."""
        overflow = b'%PDF-1.7' + b'x' * 16777209
        plan = self.make_plan(self.ir, overflow, 1)
        with patch.object(self.m, '_run_worker') as worker:
            for value in (bytearray(self.pdf), memoryview(self.pdf)):
                with self.assertRaises(self.m.PdfDocumentContentError):
                    self.inspect(pdf_bytes=value)
            with self.assertRaises(self.m.PdfDocumentContentError):
                self.inspect(pdf_bytes=overflow, plan=plan, expected_plan_sha256=plan.plan_sha256)
            worker.assert_not_called()

    def test_sixty_five_page_plan_is_not_admitted(self):
        """The optional content class is 64 pages, not the generic 512-page ceiling."""
        plan = self.make_plan(self.ir, self.pdf, 65)
        with patch.object(self.m, '_run_worker', side_effect=AssertionError('must not launch')):
            with self.assertRaises(self.m.PdfDocumentContentError):
                self.inspect(plan=plan, expected_plan_sha256=plan.plan_sha256)

    def test_actual_physical_count_must_match_plan(self):
        """A falsely declared count cannot create whole-document evidence."""
        plan = self.make_plan(self.ir, self.pdf, 2)
        with self.assertRaises(self.m.PdfDocumentContentError):
            self.inspect(plan=plan, expected_plan_sha256=plan.plan_sha256)

    def test_foreign_pdf_ir_and_plan_pins_rejected(self):
        """Each independently supplied identity must match before native work."""
        for changes in ({'expected_ir_sha256': 'e' * 64}, {'expected_plan_sha256': 'e' * 64},
                        {'pdf_bytes': self.cases[33][1]}, {'expected_ir_sha256': True}):
            with self.assertRaises(self.m.PdfDocumentContentError): self.inspect(**changes)

    def test_unsupported_locale_and_source_shape_rejected(self):
        """No alternate locale, generic PASS object or empty report can be projected."""
        for changes in ({'expected_language': 'pt-BR'}, {'presentation_ir': {}},
                        {'presentation_ir': None}, {'presentation_ir': {'status': 'PASS'}}):
            with self.assertRaises(self.m.PdfDocumentContentError): self.inspect(**changes)

    def test_disable_switch_prevents_execution(self):
        """The new adapter can be independently disabled without a permissive fallback."""
        with patch.dict(os.environ, {'OMNIGENIS_PDF_DOCUMENT_CONTENT_DISABLED': '1'}):
            with patch.object(self.m, '_run_worker', side_effect=AssertionError('must not launch')):
                with self.assertRaises(self.m.PdfDocumentContentError): self.inspect()

    def test_source_mutation_during_execution_rejected(self):
        """In-flight mutation of the supplied source cannot retain an earlier source pin."""
        original = self.m._run_worker
        def altered(pdf, identity):
            """Return actual worker data after mutating only the caller's synthetic source."""
            data = original(pdf, identity)
            self.ir['components'][0]['content']['value'] = 77
            return data
        with patch.object(self.m, '_run_worker', side_effect=altered):
            with self.assertRaises(self.m.PdfDocumentContentError): self.inspect()

    def test_plan_mutation_during_execution_rejected(self):
        """Retained plans are checked again after native execution."""
        original = self.m._run_worker
        def altered(pdf, identity):
            """Return actual worker data after an illicit frozen-plan modification."""
            data = original(pdf, identity); object.__setattr__(self.plan, 'ir_sha256', 'e' * 64)
            return data
        with patch.object(self.m, '_run_worker', side_effect=altered):
            with self.assertRaises(self.m.PdfDocumentContentError): self.inspect()

    def test_no_pdf_parser_runs_in_the_adapter_process(self):
        """Only the isolated worker parses candidate PDF bytes."""
        with patch('pypdf.PdfReader', side_effect=AssertionError('host parser forbidden')):
            self.assertEqual(self.inspect().page_count, 1)

    def test_decoded_and_text_budgets_fail_closed(self):
        """A small test budget rejects actual native extraction without a partial digest."""
        identity = {k: getattr(self.plan, k) for k in self.worker.IDENTITY_FIELDS}
        for name in ('MAX_DECODED_BYTES', 'MAX_TEXT_CHARS'):
            with patch.object(self.worker, name, 1):
                with self.assertRaises(ValueError): self.worker._inspect(self.pdf, identity)

    def test_unavailable_parser_version_is_not_accepted(self):
        """Native parsing never silently switches its pinned implementation."""
        identity = {k: getattr(self.plan, k) for k in self.worker.IDENTITY_FIELDS}
        with patch.object(self.worker, 'version', return_value='unsupported'):
            with self.assertRaises(ValueError): self.worker._inspect(self.pdf, identity)

    def test_worker_protocol_is_closed_and_identity_bound(self):
        """Unknown keys, profiles, counts and digest substitutions cannot authorize equality."""
        identity = {k: getattr(self.plan, k) for k in self.worker.IDENTITY_FIELDS}
        raw = self.m._run_worker(self.pdf, identity)
        packet = json.loads(raw)
        variants = []
        for key, value in (('profile_id', 'unknown'), ('extra', 1)):
            altered = json.loads(raw); altered[key] = value; variants.append(altered)
        for key, value in (('text_chars', True), ('inspected_pages', 2), ('text_sha256', 'INVALID')):
            altered = json.loads(raw); altered['inspection'][key] = value; variants.append(altered)
        altered = json.loads(raw); altered['identity']['ir_sha256'] = 'e' * 64; variants.append(altered)
        for altered in variants:
            with self.assertRaises(self.m.PdfDocumentContentError):
                self.m._decode(json.dumps(altered).encode(), identity)
        self.assertEqual(self.m._decode(raw, identity)['inspected_pages'], 1)

    def test_duplicate_json_and_excessive_protocol_output_rejected(self):
        """Ambiguous JSON and oversized responses cannot become a receipt."""
        identity = {k: getattr(self.plan, k) for k in self.worker.IDENTITY_FIELDS}
        raw = self.m._run_worker(self.pdf, identity)
        for data in (b'', raw + b' ' * 4096, raw.replace(b'"profile_id":', b'"profile_id":"x","profile_id":', 1)):
            with self.assertRaises(self.m.PdfDocumentContentError): self.m._decode(data, identity)

    def test_real_worker_guards_precede_candidate_read(self):
        """Exercise main with anonymous descriptors and reject before reading on guard failure."""
        for guard in ('enforce_pdf_landlock', 'enforce_pdf_network_filter'):
            with ExitStack() as stack:
                src = stack.enter_context(TemporaryFile()); out = stack.enter_context(TemporaryFile())
                read = stack.enter_context(patch.object(self.worker, '_read_request', side_effect=AssertionError('read')))
                stack.enter_context(patch.object(self.worker, '_limits', return_value={}))
                stack.enter_context(patch.object(self.worker, '_lifetime'))
                landlock = stack.enter_context(patch.object(self.worker, 'enforce_pdf_landlock'))
                network = stack.enter_context(patch.object(self.worker, 'enforce_pdf_network_filter'))
                (landlock if guard == 'enforce_pdf_landlock' else network).side_effect = OSError('blocked')
                self.assertEqual(self.worker.main(['worker', str(src.fileno()), str(out.fileno()), str(os.getpid())]), 70)
                read.assert_not_called(); self.assertEqual(os.fstat(out.fileno()).st_size, 0)

    def test_receipt_is_sealed_frozen_detached_and_content_free(self):
        """The result carries hashes/counts rather than source text and cannot be repinned in place."""
        result = self.inspect(); before = result.to_bytes()
        self.assertEqual(result.inspection_sha256, sha256(before).hexdigest())
        self.assertNotIn(b'SYNTHETIC-TEXT-REPORT', before)
        with self.assertRaises(FrozenInstanceError): result.page_count = 2
        detached = result.to_dict(); detached['page_count'] = 999
        self.assertEqual(result.to_bytes(), before)
        object.__setattr__(result, 'text_chars', result.text_chars + 1)
        with self.assertRaises(self.m.PdfDocumentContentError): result.to_bytes()

    def test_forged_direct_receipt_does_not_accept_mismatched_text(self):
        """The constructor rejects a contradictory extracted/expected digest pair."""
        result = self.inspect()
        with self.assertRaises(self.m.PdfDocumentContentError):
            replace(result, extracted_text_sha256='e' * 64)

    def test_failures_never_disclose_private_source_or_parser_details(self):
        """Arbitrary worker exceptions remain fixed content-free boundary errors."""
        with patch.object(self.m, '_run_worker', side_effect=RuntimeError('SYNTHETIC-PRIVATE-TEXT')):
            with self.assertRaises(self.m.PdfDocumentContentError) as error: self.inspect()
        self.assertNotIn('SYNTHETIC-PRIVATE-TEXT', str(error.exception))

    def test_no_science_visual_accessibility_or_release_claim(self):
        """Text equality is not scientific interpretation, full coverage or release authorization."""
        d = self.inspect().to_dict()
        for key in ('scientific_equivalence_verified', 'visible_glyphs_verified',
                    'full_accessibility_qualified', 'finding_completeness_verified',
                    'worker_results_authenticated', 'aggregate_job_resources_qualified', 'release_authorized'):
            self.assertIs(d[key], False)
        self.assertEqual(d['release_authorization'], 'NOT_ESTABLISHED')

    def test_manifest_and_existing_default_limits_unchanged(self):
        """The optional profile neither edits the 32-page validator nor the 64-page coordinator."""
        from reporting._pdf_content_worker import MAX_PAGES
        from reporting.pdf_inspection_job import MAX_PAGES as JOB_PAGES
        manifest = json.loads((ROOT / 'reporting/pdf-document-content-engine.v1.json').read_text())
        self.assertEqual(MAX_PAGES, 32); self.assertEqual(JOB_PAGES, 64)
        self.assertEqual(manifest['resource_budget']['pages'], 64)
        self.assertEqual(manifest['parser_version'], '6.19.0')
        self.assertFalse(manifest['default_pipeline_activated'])
        self.assertFalse(manifest['release_authorized'])

    def test_new_functions_are_documented(self):
        """Added boundary, worker and test functions retain explicit scope documentation."""
        for path in ('reporting/pdf_document_content.py', 'reporting/_pdf_document_content_worker.py',
                     'tests/test_reporting_pdf_document_content.py'):
            tree = ast.parse((ROOT / path).read_text())
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.assertTrue(ast.get_docstring(node), f'{path}:{node.name}')


if __name__ == '__main__':
    unittest.main()
