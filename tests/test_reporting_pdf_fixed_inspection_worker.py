"""Optional fixed process ingress/egress for existing complete technical PDF inspection."""
from hashlib import sha256
import ast
import importlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from reporting import pdf_inspection_request as codec
from reporting import pdf_request_descriptor as descriptor
from reporting import pdf_sealed_inspection as sealed
from reporting import pdf_inspection_result_frame as framed
from reporting import pdf_structured_source_job as structured
from reporting.page_checkpoints import _json_bytes
from tests import test_reporting_pdf_sealed_inspection as prior

ROOT=Path(__file__).resolve().parents[1]
WORKER=ROOT/'reporting/_pdf_fixed_inspection_worker.py'
DISABLE='OMNIGENIS_PDF_FIXED_INSPECTION_WORKER_DISABLED'


class FixedInspectionWorkerTests(unittest.TestCase):
    """A real child produces bounded bytes but never authenticates itself."""

    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('reporting._pdf_fixed_inspection_worker'),
            'fixed request/result worker module missing')
        self.m=importlib.import_module('reporting._pdf_fixed_inspection_worker')
        self.h=prior.PdfSealedInspectionTests()
        self.h.setUp()

    def context(self, expected, args, **changes):
        payload=dict(
            expected_worker_profile_sha256=self.m.PROFILE_SHA256,
            expected_packet_sha256=expected['expected_packet_sha256'],
            expected_protocol_profile_sha256=codec.PROFILE_SHA256,
            expected_namespace_id=args['namespace_id'],
            expected_job_id=args['job_id'],
            expected_request_sha256=args['request_sha256'],
            expected_descriptor_profile_sha256=descriptor.PROFILE_SHA256,
            expected_execution_profile_sha256=sealed.PROFILE_SHA256,
            expected_pdf_sha256=args['expected_pdf_sha256'],
            expected_ir_sha256=args['expected_ir_sha256'],
            expected_page_count=args['page_count'],
            expected_language=args['expected_language'],
            expected_resource_profile_sha256=structured.PROFILE_SHA256,
            expected_frame_profile_sha256=framed.PROFILE_SHA256)
        return {**payload, **changes}

    def launch(self,fd,raw,parent=None,pipe=True):
        cmd=[sys.executable,'-I','-B',str(WORKER),str(fd),
             str(os.getpid() if parent is None else parent)]
        result=subprocess.run(cmd,input=raw,stdout=subprocess.PIPE if pipe else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,pass_fds=(fd,) if fd>=3 else (),
            cwd=ROOT,timeout=360)
        return result.returncode,result.stdout if result.stdout is not None else b''

    def assertRejected(self,fd,data,parent=None,pipe=True):
        code,result=self.launch(fd,data,parent,pipe)
        self.assertNotEqual(code,0)
        self.assertEqual(result,b'')

    def test_exact_signature_and_new_profile_are_bounded_and_disabled_in_default(self):
        profile=self.m.worker_profile()
        self.assertEqual(profile['max_context_bytes'],codec.MAX_METADATA_BYTES)
        self.assertEqual(profile['max_result_frame_bytes'],framed.MAX_FRAME_BYTES)
        for key in ('default_pipeline_activated','service_installed',
                    'aggregate_job_resources_qualified','release_authorized',
                    'origin_authenticated','descendant_cleanup_qualified'):
            self.assertIs(profile[key],False)

    def test_source_has_docstrings_and_no_arbitrary_process_or_network_launch(self):
        source=WORKER.read_text()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                self.assertIsNotNone(ast.get_docstring(node))
        for token in ('subprocess','Popen','os.system','eval(','exec(','http://','https://',
                      'os.chdir(','pickle','requests.'):
            self.assertNotIn(token,source)

    def test_manifest_pins_unchanged_original_sources_and_worker_profile(self):
        record=json.loads((ROOT/'reporting/pdf-fixed-inspection-worker.v1.json').read_text())
        self.assertEqual(record['profile_sha256'],self.m.PROFILE_SHA256)
        self.assertEqual(record['profile'],self.m.worker_profile())
        for key in ('default_pipeline_activated','service_installed',
                    'aggregate_job_resources_qualified','release_authorized',
                    'dependencies_changed'):
            self.assertIs(record[key],False)
        for name,digest in record['reused_source_sha256'].items():
            self.assertEqual(sha256((ROOT/name).read_bytes()).hexdigest(),digest)

    def test_canonical_context_and_fixed_keys_are_required(self):
        with self.h.request() as (fd,expected,args,_):
            record=self.context(expected,args)
            clean=_json_bytes(record)
            self.assertEqual(self.m._parse_context(clean),record)
            for variant in (b'',b'{}',b'[]',b' '+clean,
                clean[:-1]+b',"expected_job_id":"changed"}',
                clean[:-1]+b',"unknown_critical":"1"}',
                clean[:-1]+b',"extra":NaN}',
                b'x'*(codec.MAX_METADATA_BYTES+1)):
                with self.subTest(length=len(variant)):
                    self.assertRejected(fd,variant)

    def test_expected_profile_and_identity_drift_fail_before_native_work(self):
        with self.h.request() as (fd,expected,args,_):
            source=self.context(expected,args)
            for key in source:
                altered=dict(source)
                altered[key]= 1 if key=='expected_page_count' else (
                    'f'*64 if key.endswith('sha256') else 'synthetic-foreign')
                with self.subTest(key=key):
                    self.assertRejected(fd,_json_bytes(altered))

    def test_missing_invalid_descriptor_and_wrong_parent_are_rejected(self):
        with self.h.request() as (fd,expected,args,_):
            payload=_json_bytes(self.context(expected,args))
            self.assertRejected(-1,payload)
            self.assertRejected(fd,payload,parent=os.getpid()+1)

    def test_stdout_must_be_a_pipe_and_extra_arguments_are_rejected(self):
        with self.h.request() as (fd,expected,args,_):
            payload=_json_bytes(self.context(expected,args))
            self.assertRejected(fd,payload,pipe=False)
            response=subprocess.run([sys.executable,'-I','-B',str(WORKER),
                str(fd),str(os.getpid()),'extra'],input=payload,
                stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                pass_fds=(fd,),cwd=ROOT,timeout=30)
            self.assertNotEqual(response.returncode,0)
            self.assertEqual(response.stdout,b'')

    def test_worker_disable_prevents_any_result(self):
        with self.h.request() as (fd,expected,args,_):
            payload=_json_bytes(self.context(expected,args))
            with patch.dict(os.environ,{DISABLE:'1'}):
                self.assertRejected(fd,payload)

    def test_real_one_thirty_three_sixty_four_page_unchanged_result(self):
        for pages,(ir,pdf) in self.h.h.native_cases().items():
            raw=_json_bytes(ir)
            changes=dict(presentation_ir_bytes=raw,
                expected_ir_sha256=sha256(raw).hexdigest(),
                pdf_bytes=pdf,expected_pdf_sha256=sha256(pdf).hexdigest(),
                page_count=pages)
            with self.h.request(**changes) as (fd,expected,args,packet):
                context=self.context(expected,args)
                os.lseek(fd,7,os.SEEK_SET)
                code,output=self.launch(fd,_json_bytes(context))
                self.assertEqual(os.lseek(fd,0,os.SEEK_CUR),7)
                self.assertEqual(code,0,f'worker_failed_on_{pages}_pages')
                decoded=framed.decode_pdf_inspection_result_frame(output,
                    expected_pdf_sha256=args['expected_pdf_sha256'],
                    expected_ir_sha256=args['expected_ir_sha256'],
                    expected_page_count=pages,
                    expected_language=args['expected_language'],
                    expected_namespace_id=args['namespace_id'],
                    expected_job_id=args['job_id'],
                    expected_request_sha256=args['request_sha256'],
                    expected_resource_profile_sha256=structured.PROFILE_SHA256,
                    expected_frame_profile_sha256=framed.PROFILE_SHA256)
                record=json.loads(decoded)
                self.assertEqual(record['page_count'],pages)
                self.assertEqual(len(record['inspection_dimensions']),8)
                self.assertFalse(record['release_authorized'])
                self.assertFalse(record['aggregate_job_resources_qualified'])
                self.assertEqual(os.pread(fd,len(packet),0),packet)

    def test_valid_envelope_cannot_override_invalid_source_or_pdf(self):
        with self.h.request() as (fd,expected,args,_):
            data=_json_bytes(self.context(expected,args))
            self.assertRejected(fd,data)
        # The synthetic control fixture above contains an opaque placeholder PDF,
        # not the signed-off real candidate used in the positive native tests.

    def test_unsealed_and_named_request_descriptors_are_rejected(self):
        with self.h.request() as (_,expected,args,packet):
            raw=_json_bytes(self.context(expected,args))
            memfd=os.memfd_create('synthetic-unsealed',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
            try:
                os.fchmod(memfd,0o600)
                self.assertEqual(os.write(memfd,packet),len(packet))
                self.assertRejected(memfd,raw)
            finally:
                os.close(memfd)
            import tempfile
            with tempfile.TemporaryFile() as named:
                named.write(packet)
                named.flush()
                self.assertRejected(named.fileno(),raw)

    def test_context_pipe_cannot_be_replaced_with_ordinary_file(self):
        with self.h.request() as (fd,expected,args,_):
            import tempfile
            with tempfile.TemporaryFile() as incoming:
                incoming.write(_json_bytes(self.context(expected,args)))
                incoming.seek(0)
                process=subprocess.run([sys.executable,'-I','-B',str(WORKER),
                    str(fd),str(os.getpid())],stdin=incoming,stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,pass_fds=(fd,),cwd=ROOT,timeout=30)
                self.assertNotEqual(process.returncode,0)
                self.assertEqual(process.stdout,b'')

    def test_private_request_bytes_never_in_failure_output(self):
        with self.h.request() as (fd,expected,args,packet):
            payload=_json_bytes(self.context(expected,args,
                expected_request_sha256='f'*64))
            code,out=self.launch(fd,payload)
            self.assertNotEqual(code,0)
            self.assertEqual(out,b'')
            self.assertNotIn(packet[:32],out)


if __name__=='__main__':
    unittest.main()
