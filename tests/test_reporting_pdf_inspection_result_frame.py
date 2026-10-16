"""Exact transport of the complete existing PDF inspection result."""
from hashlib import sha256
import ast
import importlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

from reporting import pdf_snapshot_inspection as snapshot
from reporting import pdf_structured_source_job as structured
from reporting.page_checkpoints import _json_bytes
from tests import test_reporting_pdf_snapshot_inspection as previous

ROOT = Path(__file__).resolve().parents[1]
DISABLE = 'OMNIGENIS_PDF_INSPECTION_RESULT_FRAME_DISABLED'


class ResultFrameTests(unittest.TestCase):
    """Transport acceptance is not authenticated execution or release."""

    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('reporting.pdf_inspection_result_frame'),
                             'result frame module is missing')
        self.m = importlib.import_module('reporting.pdf_inspection_result_frame')
        self.h = previous.PdfSnapshotInspectionTests()
        self.h.setUp()
        a = self.h.args
        self.args = a.copy()
        self.expected = dict(expected_pdf_sha256=a['expected_pdf_sha256'],
            expected_ir_sha256=a['expected_ir_sha256'],
            expected_page_count=a['page_count'],
            expected_language=a['expected_language'],
            expected_namespace_id=a['namespace_id'],
            expected_job_id=a['job_id'],
            expected_request_sha256=a['request_sha256'],
            expected_resource_profile_sha256=structured.PROFILE_SHA256)

    def options(self, **changes):
        return {**self.expected, 'expected_frame_profile_sha256':self.m.PROFILE_SHA256, **changes}

    def result(self, **changes):
        with self.h.h.mocked():
            return snapshot.execute_pdf_snapshot_inspection_job(**{**self.args, **changes})

    def encode(self, result=None, **changes):
        return self.m.encode_pdf_inspection_result_frame(
            self.result() if result is None else result, **self.options(**changes))

    def decode(self, packet, **changes):
        return self.m.decode_pdf_inspection_result_frame(packet, **self.options(**changes))

    def forge(self, obj=None, raw=None):
        body = _json_bytes(obj) if raw is None else raw
        return self.m.HEADER.pack(self.m.MAGIC, len(body), sha256(body).digest()) + body

    def reject(self, packet, **changes):
        with self.assertRaisesRegex(self.m.PdfInspectionResultFrameError,
                                    '^pdf_inspection_result_frame_invalid$'):
            self.decode(packet, **changes)

    def test_no_arbitrary_executor_receipts_paths_or_options(self):
        named = set(self.expected) | {'expected_frame_profile_sha256'}
        for function, parameter in (
            (self.m.encode_pdf_inspection_result_frame,'result'),
            (self.m.decode_pdf_inspection_result_frame,'packet_bytes')):
            signature = inspect.signature(function)
            self.assertEqual(set(signature.parameters),named|{parameter})
            self.assertFalse(any(x.kind in (x.VAR_KEYWORD,x.VAR_POSITIONAL)
                for x in signature.parameters.values()))

    def test_original_complete_bytes_roundtrip_and_original_unmodified(self):
        result=self.result(); original=result.to_bytes()
        packet=self.encode(result)
        self.assertEqual(self.decode(packet),original)
        self.assertEqual(result.to_bytes(),original)
        self.assertEqual(packet[:8],b'OGPDFRS1')
        self.assertEqual(len(packet),self.m.HEADER.size+len(original))

    def test_decoder_returns_untrusted_transport_bytes_not_release_object(self):
        raw=self.decode(self.encode())
        self.assertIs(type(raw),bytes)
        record=json.loads(raw)
        self.assertFalse(record['release_authorized'])
        self.assertFalse(record['aggregate_job_resources_qualified'])

    def test_real_1_33_64_page_result_bytes_are_identical(self):
        for pages,(ir,pdf) in self.h.native_cases().items():
            raw=_json_bytes(ir)
            args={**self.args,'presentation_ir_bytes':raw,
                  'expected_ir_sha256':sha256(raw).hexdigest(),'pdf_bytes':pdf,
                  'expected_pdf_sha256':sha256(pdf).hexdigest(),'page_count':pages}
            result=snapshot.execute_pdf_snapshot_inspection_job(**args)
            changes=dict(expected_pdf_sha256=args['expected_pdf_sha256'],
                         expected_ir_sha256=args['expected_ir_sha256'],
                         expected_page_count=pages)
            packet=self.m.encode_pdf_inspection_result_frame(result,**self.options(**changes))
            self.assertEqual(self.decode(packet,**changes),result.to_bytes())
            self.assertEqual(len(json.loads(self.decode(packet,**changes))['inspection_dimensions']),8)

    def test_dict_boolean_bytes_none_and_objects_cannot_assert_result(self):
        for value in (None,False,True,b'{}',{'status':'PASS'},object()):
            with self.assertRaises(self.m.PdfInspectionResultFrameError):
                self.m.encode_pdf_inspection_result_frame(value,**self.options())

    def test_mutated_original_nested_result_is_rejected(self):
        result=self.result()
        object.__setattr__(result.source_inspection,'namespace_id','foreign')
        with self.assertRaises(self.m.PdfInspectionResultFrameError):self.encode(result)

    def test_independent_identity_mismatch_at_both_sides(self):
        packet=self.encode()
        for name in self.expected:
            wrong=1 if name=='expected_page_count' else (
                'f'*64 if name.endswith('sha256') else 'foreign')
            with self.subTest(name=name):
                self.reject(packet,**{name:wrong})
                with self.assertRaises(self.m.PdfInspectionResultFrameError):
                    self.encode(**{name:wrong})

    def test_nonbytes_invalid_frames_and_overbudget_rejected(self):
        for value in (None,True,False,0,{},bytearray(b'no'),b'',
                      b'x'*(self.m.MAX_FRAME_BYTES+1)):
            self.reject(value)

    def test_wrong_magic_checksum_lengths_and_trailing_bytes(self):
        packet=self.encode()
        for value in (b'BROKEN!!'+packet[8:],packet[:12]+b'\x00'*32+packet[44:],
                      packet[:8]+struct.pack('>I',0)+packet[12:],
                      packet[:8]+struct.pack('>I',self.m.MAX_RESULT_BYTES+1)+packet[12:],
                      packet[:-1],packet[:43],packet+b'x',b'x'+packet):
            self.reject(value)

    def test_body_corruption_is_rejected(self):
        packet=bytearray(self.encode());packet[-2]^=1
        self.reject(bytes(packet))

    def test_rehashed_foreign_identity_is_rejected(self):
        original=json.loads(self.decode(self.encode()))
        for name in ('pdf_sha256','ir_sha256','page_count','language','namespace_id',
                     'job_id','request_sha256','resource_profile_sha256'):
            modified={**original,name:1 if name=='page_count' else (
                'f'*64 if name.endswith('sha256') else 'foreign')}
            self.reject(self.forge(modified))

    def test_rehashed_nested_child_tamper_is_rejected(self):
        original=json.loads(self.decode(self.encode()))
        for child in ('source_inspection','structure_tree'):
            modified=json.loads(_json_bytes(original))
            modified[child]['pdf_sha256']='f'*64
            self.reject(self.forge(modified))
            modified=json.loads(_json_bytes(original))
            modified[child]['page_count']=64
            self.reject(self.forge(modified))

    def test_changed_nested_hash_does_not_override_parent_binding(self):
        modified=json.loads(self.decode(self.encode()))
        modified['source_inspection']['namespace_id']='foreign'
        modified['source_inspection_sha256']=sha256(_json_bytes(modified['source_inspection'])).hexdigest()
        self.reject(self.forge(modified))

    def test_duplicate_nonfinite_noncanonical_and_nonobject_rejected(self):
        raw=self.decode(self.encode())
        for body in (raw[:-1]+b',"status":"FORGED"}',
                     raw[:-1]+b',"extra":NaN}',b' '+raw,b'[]',b'false',
                     b'{' + b'"nest":'*70+b'null'+b'}'*70):
            self.reject(self.forge(raw=body))

    def test_rehashed_false_authority_flags_cannot_be_promoted(self):
        original=json.loads(self.decode(self.encode()))
        for key in ('aggregate_job_resources_qualified','release_authorized',
                    'worker_results_authenticated','scientific_equivalence_verified'):
            self.reject(self.forge({**original,key:True}))

    def test_rehashed_nested_authority_flags_are_rejected(self):
        original=json.loads(self.decode(self.encode()))
        for child, digest in (('source_inspection','source_inspection_sha256'),
                              ('structure_tree','structure_inspection_sha256')):
            for name in ('aggregate_job_resources_qualified','release_authorized',
                         'worker_results_authenticated','scientific_equivalence_verified',
                         'full_accessibility_qualified'):
                altered=json.loads(_json_bytes(original))
                altered[child][name]=True
                altered[digest]=sha256(_json_bytes(altered[child])).hexdigest()
                with self.subTest(child=child,flag=name):
                    self.reject(self.forge(altered))

    def test_rehashed_global_structure_and_coverage_mismatch_rejected(self):
        original=json.loads(self.decode(self.encode()))
        for name, value in (('plan_sha256','f'*64),
                            ('mapped_mcids',original['structure_tree']['mapped_mcids']+1)):
            altered=json.loads(_json_bytes(original))
            altered['structure_tree'][name]=value
            altered['structure_inspection_sha256']=sha256(
                _json_bytes(altered['structure_tree'])).hexdigest()
            with self.subTest(name=name):self.reject(self.forge(altered))
        altered=json.loads(_json_bytes(original))
        altered['source_inspection']['inspection_dimensions']=['text']
        altered['source_inspection_sha256']=sha256(
            _json_bytes(altered['source_inspection'])).hexdigest()
        self.reject(self.forge(altered))

    def test_profile_and_dependency_drift_or_disabled_flag_rejected(self):
        result=self.result()
        packet=self.encode(result)
        for key in ('expected_frame_profile_sha256','expected_resource_profile_sha256'):
            self.reject(packet,**{key:'f'*64})
        for flag in (DISABLE,'OMNIGENIS_PDF_STRUCTURED_SOURCE_JOB_DISABLED'):
            with patch.dict(os.environ,{flag:'1'}):
                self.reject(packet)
                with self.assertRaises(self.m.PdfInspectionResultFrameError):self.encode(result)

    def test_manifest_exact_reused_sources_and_no_activation(self):
        manifest=json.loads((ROOT/'reporting/pdf-inspection-result-frame.v1.json').read_text())
        self.assertEqual(manifest['profile'],self.m.result_frame_profile())
        self.assertEqual(manifest['profile_sha256'],self.m.PROFILE_SHA256)
        for key in ('default_pipeline_activated','new_executor_activated',
                    'production_resources_qualified','dependencies_changed','release_authorized'):
            self.assertIs(manifest[key],False)
        for name,digest in manifest['reused_source_sha256'].items():
            self.assertEqual(sha256((ROOT/name).read_bytes()).hexdigest(),digest)

    def test_source_docstrings_and_no_process_network_or_exec(self):
        text=(ROOT/'reporting/pdf_inspection_result_frame.py').read_text()
        for node in ast.walk(ast.parse(text)):
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                self.assertIsNotNone(ast.get_docstring(node))
        for token in ('subprocess','Popen','os.system','systemctl','eval(','exec(','pickle',
                      'http://','https://'):
            self.assertNotIn(token,text)

    def test_profile_is_detached_and_original_resource_budget_unchanged(self):
        value=self.m.result_frame_profile();value['max_result_bytes']=1
        self.assertNotEqual(value,self.m.result_frame_profile())
        self.assertEqual(self.m.result_frame_profile()['max_result_bytes'],
                         structured.MAX_RESULT_BYTES)


if __name__=='__main__':
    unittest.main()
