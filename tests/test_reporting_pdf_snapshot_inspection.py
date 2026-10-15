"""Immutable canonical source admission with real existing PDF inspection paths."""
from __future__ import annotations

import ast
from hashlib import sha256
import importlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from reporting import pdf_structured_source_job as structured
from reporting.page_checkpoints import _json_bytes
from tests import test_reporting_pdf_structured_source_job as prior
from tests.test_reporting_pdf_source_inspection_job import generated_job_case

ROOT = Path(__file__).resolve().parents[1]


class PdfSnapshotInspectionTests(unittest.TestCase):
    """The immutable representation is an input boundary, not new release authority."""

    cases = None

    def setUp(self):
        """Require a real RED assertion before the new module is implemented."""
        self.assertIsNotNone(importlib.util.find_spec('reporting.pdf_snapshot_inspection'),
                             'immutable snapshot inspection is missing')
        self.m = importlib.import_module('reporting.pdf_snapshot_inspection')
        self.h = prior.PdfStructuredSourceJobTests()
        self.h.setUp()
        self.raw = _json_bytes(self.h.ir)
        self.args = {k: v for k, v in self.h.args.items() if k != 'presentation_ir'}
        self.args.update(presentation_ir_bytes=self.raw,
                         expected_source_profile_sha256=self.m.PROFILE_SHA256)

    def run_job(self, **changes):
        """Invoke the bytes entrypoint without supplying inspection results."""
        return self.m.execute_pdf_snapshot_inspection_job(**{**self.args, **changes})

    def source_args(self, raw):
        """Pin each adversarial representation independently, excluding hash mismatches."""
        return dict(presentation_ir_bytes=raw, expected_ir_sha256=sha256(raw).hexdigest())

    @classmethod
    def native_cases(cls):
        """Generate controlled synthetic PDFs only, never genomic or patient records."""
        if cls.cases is None:
            cls.cases = {n: generated_job_case(n) for n in (1, 33, 64)}
        return cls.cases

    def test_real_native_one_thirty_three_sixty_four_page_parity(self):
        """The bytes API preserves the existing complete eight-dimension result."""
        for pages, (ir, pdf) in self.native_cases().items():
            with self.subTest(pages=pages):
                raw = _json_bytes(ir)
                args = dict(pdf_bytes=pdf, expected_pdf_sha256=sha256(pdf).hexdigest(),
                    expected_ir_sha256=sha256(raw).hexdigest(), page_count=pages)
                result = self.run_job(presentation_ir_bytes=raw, **args)
                previous = structured.execute_pdf_structured_source_job(
                    **{**self.h.args, **args, 'presentation_ir': ir})
                self.assertEqual(result.to_bytes(), previous.to_bytes())
                self.assertEqual(result.to_dict()['structure_tree']['mapped_mcids'], 3 * pages + 1)
                self.assertEqual(len(result.to_dict()['inspection_dimensions']), 8)
                self.assertEqual(_json_bytes(ir), raw)

    def test_only_exact_immutable_bytes_are_admitted(self):
        """Mutable buffers, strings, subclasses and arbitrary objects cannot be snapshots."""
        class ForeignBytes(bytes):
            """A subclass is not the exact immutable transport type."""
        for value in (bytearray(self.raw), memoryview(self.raw), self.raw.decode(),
                      ForeignBytes(self.raw), {}, None):
            with self.h.mocked() as calls:
                with self.assertRaises(self.m.PdfSnapshotInspectionError):
                    self.run_job(presentation_ir_bytes=value)
                self.assertEqual(calls, [])

    def test_digest_mismatch_precedes_json_decode(self):
        """Unbound bytes are rejected before parsing or any native inspector."""
        with self.h.mocked() as calls, patch.object(self.m, '_decode_source') as decoder:
            with self.assertRaises(self.m.PdfSnapshotInspectionError):
                self.run_job(expected_ir_sha256='f' * 64)
            decoder.assert_not_called()
            self.assertEqual(calls, [])

    def test_noncanonical_encodings_are_rejected_not_repaired(self):
        """Whitespace, BOM, escaped alternatives and UTF-16 are not silently normalized."""
        variants = [self.raw + b'\n', b' ' + self.raw, b'\xef\xbb\xbf' + self.raw,
                    json.dumps(self.h.ir, indent=2).encode(), self.raw.decode().encode('utf-16'),
                    self.raw.replace(b'SYNTHETIC', b'\\u0053YNTHETIC')]
        for raw in variants:
            with self.h.mocked() as calls:
                with self.assertRaises(self.m.PdfSnapshotInspectionError):
                    self.run_job(**self.source_args(raw))
                self.assertEqual(calls, [])

    def test_duplicate_root_nested_and_escaped_keys_are_rejected(self):
        """Different spellings of the same decoded key never receive last-value wins."""
        variants = [self.raw[:-1] + b',"report_id":"SYNTHETIC-OTHER"}',
                    self.raw.replace(b'"value":17', b'"value":17,"value":18'),
                    self.raw.replace(b'"value":17', b'"value":17,"\\u0076alue":17')]
        for raw in variants:
            with self.h.mocked() as calls:
                with self.assertRaises(self.m.PdfSnapshotInspectionError):
                    self.run_job(**self.source_args(raw))
                self.assertEqual(calls, [])

    def test_rounded_or_underflow_numeric_tokens_are_rejected(self):
        """High-precision decimals and underflow cannot become rounded source values."""
        for token in (b'0.1234567890123456789012345', b'1e-9999', b'-0', b'1.000', b'1e0'):
            raw = self.raw.replace(b'"value":17', b'"value":' + token)
            with self.h.mocked() as calls:
                with self.assertRaises(self.m.PdfSnapshotInspectionError):
                    self.run_job(**self.source_args(raw))
                self.assertEqual(calls, [])

    def test_nonfinite_extensions_and_overflow_are_rejected(self):
        """NaN, infinities and overflowing decimal exponents never enter inspection."""
        for token in (b'NaN', b'Infinity', b'-Infinity', b'1e9999'):
            raw = self.raw.replace(b'"value":17', b'"value":' + token)
            with self.h.mocked() as calls:
                with self.assertRaises(self.m.PdfSnapshotInspectionError):
                    self.run_job(**self.source_args(raw))
                self.assertEqual(calls, [])

    def test_valid_native_scalar_types_and_values_are_preserved(self):
        """Null, Boolean, integer, float, signed float zero and Unicode stay exact."""
        ir = json.loads(self.raw)
        ir['components'][0]['content'] = {'null': None, 'false': False, 'zero': 0,
            'large': 2 ** 300, 'float': 0.25, 'negative_zero': -0.0, 'text': 'Synthetic caf\u00e9'}
        raw = _json_bytes(ir)
        original = structured.execute_pdf_structured_source_job
        def check(**values):
            """Check actual decoded values before executing both existing coordinators."""
            decoded = values['presentation_ir']
            self.assertEqual(_json_bytes(decoded), raw)
            for name, value in ir['components'][0]['content'].items():
                self.assertIs(type(decoded['components'][0]['content'][name]), type(value))
            return original(**values)
        with self.h.mocked(), patch.object(self.m, 'execute_pdf_structured_source_job', side_effect=check):
            result = self.run_job(**self.source_args(raw))
        self.assertEqual(result.ir_sha256, sha256(raw).hexdigest())

    def test_byte_budget_precedes_json_decode(self):
        """An oversized representation is blocked before any JSON allocation."""
        raw = b' ' * (8 * 1024 * 1024 + 1)
        with self.h.mocked() as calls, patch.object(self.m, '_decode_source') as decoder:
            with self.assertRaises(self.m.PdfSnapshotInspectionError):
                self.run_job(**self.source_args(raw))
            decoder.assert_not_called()
            self.assertEqual(calls, [])

    def test_depth_budget_precedes_json_decode(self):
        """Deep raw JSON is rejected before the standard decoder builds its graph."""
        raw = b'{"x":' + b'[' * 65 + b'0' + b']' * 65 + b'}'
        with self.h.mocked() as calls, patch.object(self.m, '_decode_source') as decoder:
            with self.assertRaises(self.m.PdfSnapshotInspectionError):
                self.run_job(**self.source_args(raw))
            decoder.assert_not_called()
            self.assertEqual(calls, [])

    def test_node_budget_precedes_json_decode(self):
        """Wide raw arrays cannot allocate more than the existing node admission count."""
        raw = b'{"x":[' + b','.join([b'0'] * 100000) + b']}'
        with self.h.mocked() as calls, patch.object(self.m, '_decode_source') as decoder:
            with self.assertRaises(self.m.PdfSnapshotInspectionError):
                self.run_job(**self.source_args(raw))
            decoder.assert_not_called()
            self.assertEqual(calls, [])

    def test_structure_inside_escaped_strings_is_not_counted(self):
        """Brackets, braces, escaped quotes and backslashes in data are not JSON nodes."""
        ir = json.loads(self.raw)
        ir['components'][0]['content']['value'] = '[{\\"' * 1000
        raw = _json_bytes(ir)
        with self.h.mocked(): result = self.run_job(**self.source_args(raw))
        self.assertEqual(result.ir_sha256, sha256(raw).hexdigest())

    def test_integer_bit_budget_is_preserved(self):
        """Boundary integers retain native exactness; larger integers are rejected whole."""
        for bits, accepted in ((4095, True), (4096, False)):
            ir = json.loads(self.raw); ir['components'][0]['content']['value'] = 1 << bits
            raw = _json_bytes(ir)
            with self.h.mocked() as calls:
                if accepted:
                    self.assertEqual(self.run_job(**self.source_args(raw)).ir_sha256, sha256(raw).hexdigest())
                else:
                    with self.assertRaises(self.m.PdfSnapshotInspectionError):
                        self.run_job(**self.source_args(raw))
                    self.assertEqual(calls, [])

    def test_malformed_unicode_json_and_root_types_are_rejected(self):
        """Invalid UTF-8, lone surrogates, malformed tokens and non-object roots fail closed."""
        for raw in (b'{}\xff', b'{"x":"\\ud800"}', b'{"x":truefalse}', b'{"x":1,}',
                    b'[]', b'null', b'"text"', b'{}{}', b'', b'{]'):
            with self.h.mocked() as calls:
                with self.assertRaises(self.m.PdfSnapshotInspectionError):
                    self.run_job(**self.source_args(raw))
                self.assertEqual(calls, [])

    def test_unsupported_semantic_source_prevents_inspection(self):
        """The bytes boundary does not widen the original semantic-section source profile."""
        for source in ({}, {'locale_id': 'pt-BR'}, {'report_id': 'x', 'locale_id': 'en-US', 'components': []}):
            with self.h.mocked() as calls:
                with self.assertRaises(self.m.PdfSnapshotInspectionError):
                    self.run_job(**self.source_args(_json_bytes(source)))
                self.assertEqual(calls, [])

    def test_external_mutable_dictionary_cannot_change_admitted_bytes(self):
        """Mutation of the dictionary used upstream to encode bytes cannot change this job."""
        def mutate(stage, values, receipt):
            """Change only the caller-side former dictionary, not the immutable transport."""
            self.h.ir['report_id'] = 'SYNTHETIC-CHANGED-ELSEWHERE'
            return receipt
        with self.h.mocked(mutate): result = self.run_job()
        self.assertEqual(result.ir_sha256, sha256(self.raw).hexdigest())

    def test_decoded_source_mutation_prevents_return(self):
        """The private decoded dictionary cannot be changed after a successful child result."""
        original = structured.execute_pdf_structured_source_job
        def mutate(**values):
            """Complete the child then change its retained synthetic source."""
            result = original(**values)
            values['presentation_ir']['report_id'] = 'SYNTHETIC-CHANGED-CHILD'
            return result
        with self.h.mocked(), patch.object(self.m, 'execute_pdf_structured_source_job', side_effect=mutate):
            with self.assertRaises(self.m.PdfSnapshotInspectionError): self.run_job()

    def test_foreign_typed_job_results_are_rejected(self):
        """A valid sealed result from another job or namespace cannot satisfy this call."""
        original = structured.execute_pdf_structured_source_job
        for field in ('namespace_id', 'job_id', 'request_sha256'):
            def foreign(**values):
                """Produce a real typed result using a different independent context."""
                values[field] = 'd' * 64 if field == 'request_sha256' else 'synthetic-foreign'
                return original(**values)
            with self.h.mocked(), patch.object(self.m, 'execute_pdf_structured_source_job', side_effect=foreign):
                with self.assertRaises(self.m.PdfSnapshotInspectionError): self.run_job()

    def test_generic_success_is_not_a_typed_result(self):
        """Caller-shaped success dictionaries never substitute for the real result type."""
        with patch.object(self.m, 'execute_pdf_structured_source_job', return_value={'status': 'PASS'}):
            with self.assertRaises(self.m.PdfSnapshotInspectionError): self.run_job()

    def test_child_failure_discloses_no_input_or_exception(self):
        """Only the fixed execution failure escapes the new boundary."""
        with patch.object(self.m, 'execute_pdf_structured_source_job', side_effect=RuntimeError('PRIVATE-SYNTHETIC')):
            with self.assertRaises(self.m.PdfSnapshotInspectionError) as caught: self.run_job()
        self.assertEqual(str(caught.exception), 'pdf_snapshot_inspection_execution_failed')

    def test_source_disable_prevents_decode_and_native_work(self):
        """A disabled input profile performs no decoder or inspection work."""
        with patch.dict(os.environ, {'OMNIGENIS_PDF_SNAPSHOT_INSPECTION_DISABLED': '1'}), self.h.mocked() as calls:
            with patch.object(self.m, '_decode_source') as decoder:
                with self.assertRaises(self.m.PdfSnapshotInspectionError): self.run_job()
                decoder.assert_not_called()
            self.assertEqual(calls, [])

    def test_source_disable_during_work_prevents_return(self):
        """Disabling after admission invalidates final acceptance without modifying child profiles."""
        def disable(stage, values, receipt):
            """Set the new admission switch while an underlying stage is running."""
            os.environ['OMNIGENIS_PDF_SNAPSHOT_INSPECTION_DISABLED'] = '1'
            return receipt
        with patch.dict(os.environ), self.h.mocked(disable):
            with self.assertRaises(self.m.PdfSnapshotInspectionError): self.run_job()

    def test_all_existing_disable_switches_remain_effective(self):
        """A new entrypoint cannot bypass any prerequisite's disabled state."""
        for flag in prior.DISABLES:
            with patch.dict(os.environ, {flag: '1'}), self.h.mocked() as calls:
                with self.assertRaises(self.m.PdfSnapshotInspectionError): self.run_job()
                self.assertEqual(calls, [])

    def test_profile_pins_and_runtime_drift_are_rejected(self):
        """Both independent profiles stay pinned and source limits cannot drift silently."""
        for changes in ({'expected_source_profile_sha256': 'f' * 64},
                        {'expected_resource_profile_sha256': 'f' * 64}):
            with self.h.mocked() as calls:
                with self.assertRaises(self.m.PdfSnapshotInspectionError): self.run_job(**changes)
                self.assertEqual(calls, [])
        with patch.object(self.m, 'MAX_SOURCE_BYTES', 16 * 1024 * 1024), self.h.mocked() as calls:
            with self.assertRaises(self.m.PdfSnapshotInspectionError): self.run_job()
            self.assertEqual(calls, [])

    def test_no_parent_pdf_parser_on_real_path(self):
        """Immutable source decoding does not move PDF parsing into the parent process."""
        ir, pdf = self.native_cases()[1]
        with patch('pypdf.PdfReader', side_effect=AssertionError('parent parser forbidden')):
            result = self.run_job(**self.source_args(_json_bytes(ir)), pdf_bytes=pdf,
                                 expected_pdf_sha256=sha256(pdf).hexdigest(), page_count=1)
        self.assertTrue(result.to_dict()['forward_reverse_linkage_verified'])

    def test_return_type_and_qualification_claims_remain_unchanged(self):
        """An input transport change adds no new result wrapper or scientific claims."""
        with self.h.mocked(): result = self.run_job()
        self.assertIs(type(result), structured.PdfStructuredSourceResult)
        data = result.to_dict()
        self.assertEqual(data['resource_profile_sha256'], structured.PROFILE_SHA256)
        for key in ('worker_results_authenticated', 'scientific_equivalence_verified',
                    'full_accessibility_qualified', 'aggregate_job_resources_qualified', 'release_authorized'):
            self.assertIs(data[key], False)
        profile = self.m.snapshot_source_profile(); profile['max_source_bytes'] = 1
        self.assertEqual(self.m.snapshot_source_profile()['max_source_bytes'], 8 * 1024 * 1024)
        self.assertEqual(set(inspect.signature(self.m.execute_pdf_snapshot_inspection_job).parameters), set(self.args))

    def test_manifest_reused_sources_limits_and_docstrings(self):
        """All prior sources, defaults and legal/dependency identities remain intact."""
        from reporting._pdf_safety_worker import MAX_PAGES
        manifest = json.loads((ROOT/'reporting/pdf-snapshot-inspection.v1.json').read_text())
        self.assertEqual(MAX_PAGES, 32)
        self.assertEqual(manifest['profile'], self.m.snapshot_source_profile())
        self.assertEqual(manifest['profile_sha256'], self.m.PROFILE_SHA256)
        self.assertFalse(manifest['default_pipeline_activated'])
        for name, digest in manifest['reused_source_sha256'].items():
            self.assertEqual(sha256((ROOT/name).read_bytes()).hexdigest(), digest)
        for name in ('reporting/pdf_snapshot_inspection.py', 'tests/test_reporting_pdf_snapshot_inspection.py'):
            for node in ast.walk(ast.parse((ROOT/name).read_text())):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.assertTrue(ast.get_docstring(node), name + ':' + node.name)


if __name__ == '__main__':
    unittest.main()
