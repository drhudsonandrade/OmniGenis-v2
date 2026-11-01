"""Fixed sealed-request execution with exact existing input and result semantics."""
from contextlib import contextmanager
from hashlib import sha256
import ast
import importlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from reporting import pdf_inspection_request as codec
from reporting import pdf_request_descriptor as descriptor
from reporting import pdf_snapshot_inspection as snapshot
from reporting import pdf_structured_source_job as structured
from reporting.page_checkpoints import _json_bytes
from tests import test_reporting_pdf_snapshot_inspection as previous
from tests import test_reporting_pdf_structured_source_job as structured_tests

ROOT = Path(__file__).resolve().parents[1]
DISABLE = 'OMNIGENIS_PDF_SEALED_INSPECTION_DISABLED'


class PdfSealedInspectionTests(unittest.TestCase):
    """A transport seal never replaces the complete job or authorizes report release."""

    def setUp(self):
        """Observe an assertion RED for the absent entrypoint before fixture creation."""
        self.assertIsNotNone(importlib.util.find_spec('reporting.pdf_sealed_inspection'),
                             'sealed inspection entrypoint is missing')
        self.m = importlib.import_module('reporting.pdf_sealed_inspection')
        self.h = previous.PdfSnapshotInspectionTests(); self.h.setUp()
        self.args = self.h.args.copy()

    def fixture(self, **changes):
        """Prepare synthetic exact bytes and independent receiver expectations."""
        args = {**self.args, **changes}
        packet = codec.encode_pdf_snapshot_request(**args,
            expected_protocol_profile_sha256=codec.PROFILE_SHA256)
        expected = dict(expected_packet_sha256=sha256(packet).hexdigest(),
            expected_protocol_profile_sha256=codec.PROFILE_SHA256,
            expected_descriptor_profile_sha256=descriptor.PROFILE_SHA256,
            expected_namespace_id=args['namespace_id'], expected_job_id=args['job_id'],
            expected_request_sha256=args['request_sha256'])
        return packet, expected, args

    @contextmanager
    def request(self, **changes):
        """Own the real sealed descriptor only for the explicitly bounded test scope."""
        packet, expected, args = self.fixture(**changes)
        with descriptor.sealed_pdf_request(packet, **expected) as fd:
            yield fd, expected, args, packet

    def invoke(self, fd, expected, **changes):
        """Call only the fixed entrypoint; no user-selected executor or result input exists."""
        return self.m.execute_sealed_pdf_inspection_job(fd,
            **{**expected, 'expected_execution_profile_sha256':self.m.PROFILE_SHA256, **changes})

    def controlled_result(self, **changes):
        """Exercise real coordinators with synthetic native observations for branch tests."""
        with self.h.h.mocked():
            return snapshot.execute_pdf_snapshot_inspection_job(**{**self.args, **changes})

    def test_public_signature_has_no_overrides_receipts_or_executor(self):
        """The request and all identity expectations are explicit, with no arbitrary kwargs."""
        signature = inspect.signature(self.m.execute_sealed_pdf_inspection_job)
        self.assertEqual(set(signature.parameters), {'request_fd','expected_packet_sha256',
            'expected_protocol_profile_sha256','expected_namespace_id','expected_job_id',
            'expected_request_sha256','expected_descriptor_profile_sha256','expected_execution_profile_sha256'})
        self.assertFalse(any(p.kind in (p.VAR_POSITIONAL,p.VAR_KEYWORD) for p in signature.parameters.values()))

    def test_capture_and_snapshot_dispatch_once_with_exact_arguments(self):
        """Read once and call the unchanged complete job once, preserving all native stages."""
        read = descriptor.read_sealed_pdf_request
        with self.request() as (fd, expected, args, packet), self.h.h.mocked() as calls, \
             patch.object(self.m.descriptor,'read_sealed_pdf_request',wraps=read) as capture, \
             patch.object(self.m,'execute_pdf_snapshot_inspection_job',wraps=snapshot.execute_pdf_snapshot_inspection_job) as job:
            result = self.invoke(fd, expected)
            capture.assert_called_once_with(fd, **expected)
            job.assert_called_once_with(**args)
            self.assertEqual(len(calls),18)
            self.assertEqual(result.ir_sha256,sha256(args['presentation_ir_bytes']).hexdigest())
            self.assertEqual(os.pread(fd,len(packet),0),packet)

    def test_same_result_object_is_returned_without_a_new_wrapper(self):
        """The original sealed result and resource identity survive the integration."""
        result = self.controlled_result()
        with self.request() as (fd, expected, _, _), patch.object(self.m,'execute_pdf_snapshot_inspection_job',return_value=result):
            self.assertIs(self.invoke(fd, expected), result)
        self.assertIs(type(result),structured.PdfStructuredSourceResult)
        self.assertEqual(result.resource_profile_sha256,structured.PROFILE_SHA256)

    def test_invalid_descriptor_types_never_dispatch(self):
        """Booleans, standard streams, negative values and objects cannot become requests."""
        _, expected, _ = self.fixture()
        for value in (None,True,False,-1,0,1,2,2**31,'3',b'3',{}):
            with patch.object(self.m,'execute_pdf_snapshot_inspection_job') as job:
                with self.assertRaises(self.m.PdfSealedInspectionError): self.invoke(value,expected)
                job.assert_not_called()

    def test_closed_descriptor_never_dispatches(self):
        """A stale descriptor number fails without touching the original owned request."""
        with self.request() as (fd, expected, _, packet):
            closed = os.dup(fd); os.close(closed)
            with patch.object(self.m,'execute_pdf_snapshot_inspection_job') as job:
                with self.assertRaises(self.m.PdfSealedInspectionError): self.invoke(closed,expected)
                job.assert_not_called()
            self.assertEqual(os.pread(fd,len(packet),0),packet)

    def test_unsealed_descriptor_blocks_before_snapshot_job(self):
        """Correct bytes and hashes without actual kernel seals do not authorize inspection."""
        packet, expected, _ = self.fixture()
        fd = os.memfd_create('synthetic-unsealed-inspection',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
        try:
            os.fchmod(fd,0o600); self.assertEqual(os.write(fd,packet),len(packet))
            with patch.object(self.m,'execute_pdf_snapshot_inspection_job') as job:
                with self.assertRaises(self.m.PdfSealedInspectionError): self.invoke(fd,expected)
                job.assert_not_called()
        finally: os.close(fd)

    def test_wrong_integration_descriptor_or_codec_pin_precedes_capture(self):
        """No descriptor read occurs when any separately expected entry profile is wrong."""
        _, expected, _ = self.fixture()
        for name in ('expected_execution_profile_sha256','expected_descriptor_profile_sha256','expected_protocol_profile_sha256'):
            with patch.object(self.m.descriptor,'read_sealed_pdf_request') as capture:
                with self.assertRaises(self.m.PdfSealedInspectionError): self.invoke(3,expected,**{name:'f'*64})
                capture.assert_not_called()

    def test_wrong_packet_or_receiver_identity_blocks_dispatch(self):
        """A sealed object still requires independently supplied packet and job identities."""
        with self.request() as (fd, expected, _, _):
            for name in ('expected_packet_sha256','expected_namespace_id','expected_job_id','expected_request_sha256'):
                value = 'f'*64 if name.endswith('sha256') else 'synthetic-foreign'
                with patch.object(self.m,'execute_pdf_snapshot_inspection_job') as job:
                    with self.assertRaises(self.m.PdfSealedInspectionError): self.invoke(fd,expected,**{name:value})
                    job.assert_not_called()

    def test_unknown_or_missing_captured_arguments_block_dispatch(self):
        """The capture vocabulary cannot become a hidden executor or metadata override."""
        _, expected, _ = self.fixture()
        variants = [{**self.args,'executor':'synthetic-foreign'}, {k:v for k,v in self.args.items() if k!='pdf_bytes'}, None]
        for values in variants:
            with patch.object(self.m.descriptor,'read_sealed_pdf_request',return_value=values), \
                 patch.object(self.m,'execute_pdf_snapshot_inspection_job') as job:
                with self.assertRaises(self.m.PdfSealedInspectionError): self.invoke(3,expected)
                job.assert_not_called()

    def test_captured_context_and_child_profiles_are_rebound_before_dispatch(self):
        """Defensive binding does not trust a foreign dictionary returned by a broken boundary."""
        _, expected, _ = self.fixture()
        for name in ('namespace_id','job_id','request_sha256','expected_source_profile_sha256','expected_resource_profile_sha256'):
            values = {**self.args,name:'f'*64 if name.endswith('sha256') else 'synthetic-foreign'}
            with patch.object(self.m.descriptor,'read_sealed_pdf_request',return_value=values), \
                 patch.object(self.m,'execute_pdf_snapshot_inspection_job') as job:
                with self.assertRaises(self.m.PdfSealedInspectionError): self.invoke(3,expected)
                job.assert_not_called()

    def test_opaque_invalid_source_still_fails_before_native_work(self):
        """A transport-valid sealed packet does not turn malformed source into valid JSON."""
        for raw in (b'not-json',b'{}',b'{"x":1,"x":2}'):
            with self.request(presentation_ir_bytes=raw,expected_ir_sha256=sha256(raw).hexdigest()) as (fd, expected, _, _), self.h.h.mocked() as calls:
                with self.assertRaises(self.m.PdfSealedInspectionError): self.invoke(fd,expected)
                self.assertEqual(calls,[])

    def test_actual_malformed_pdf_fails_without_partial_result(self):
        """The real guarded PDF path rejects the control-flow fixture's opaque non-PDF body."""
        with self.request() as (fd, expected, _, _):
            with self.assertRaisesRegex(self.m.PdfSealedInspectionError,'^pdf_sealed_inspection_failed$'):
                self.invoke(fd,expected)

    def test_actual_source_text_mismatch_is_not_excused_by_sealing(self):
        """A real structurally valid one-page PDF cannot satisfy different source text."""
        ir, pdf = self.h.native_cases()[1]
        ir = json.loads(_json_bytes(ir)); ir['components'][0]['content']['value'] = 999
        raw = _json_bytes(ir)
        with self.request(presentation_ir_bytes=raw,expected_ir_sha256=sha256(raw).hexdigest(),pdf_bytes=pdf,
                expected_pdf_sha256=sha256(pdf).hexdigest(),page_count=1) as (fd, expected, _, _):
            with self.assertRaises(self.m.PdfSealedInspectionError): self.invoke(fd,expected)

    def test_job_failure_is_fixed_content_free_and_never_retried(self):
        """Native error details do not escape and failure is not changed into a partial result."""
        with self.request() as (fd, expected, _, _), \
             patch.object(self.m,'execute_pdf_snapshot_inspection_job',side_effect=RuntimeError('SYNTHETIC-PAYLOAD-DETAIL')) as job:
            with self.assertRaises(self.m.PdfSealedInspectionError) as caught: self.invoke(fd,expected)
            self.assertEqual(str(caught.exception),'pdf_sealed_inspection_failed')
            self.assertTrue(caught.exception.__suppress_context__)
            self.assertEqual(job.call_count,1)

    def test_nonresult_objects_cannot_assert_success(self):
        """Dictionaries, booleans, missing values and arbitrary objects cannot become typed results."""
        with self.request() as (fd, expected, _, _):
            for value in (None,True,{'status':'PASS'},b'{}',object()):
                with patch.object(self.m,'execute_pdf_snapshot_inspection_job',return_value=value):
                    with self.assertRaises(self.m.PdfSealedInspectionError): self.invoke(fd,expected)

    def test_valid_foreign_sealed_results_are_rejected(self):
        """Every source/PDF/page/job binding is compared, not just the returned object's type."""
        raw = self.args['presentation_ir_bytes'].replace(b'"value":17',b'"value":18')
        pdf = self.args['pdf_bytes']+b'changed'
        variants = [{'namespace_id':'synthetic-other'}, {'job_id':'synthetic-other'}, {'request_sha256':'f'*64},
            {'page_count':1}, {'presentation_ir_bytes':raw,'expected_ir_sha256':sha256(raw).hexdigest()},
            {'pdf_bytes':pdf,'expected_pdf_sha256':sha256(pdf).hexdigest()}]
        with self.request() as (fd, expected, _, _):
            for changes in variants:
                result = self.controlled_result(**changes)
                with patch.object(self.m,'execute_pdf_snapshot_inspection_job',return_value=result):
                    with self.assertRaises(self.m.PdfSealedInspectionError): self.invoke(fd,expected)

    def test_nested_result_tampering_is_revalidated(self):
        """Matching top-level IDs do not conceal a changed sealed child observation."""
        result = self.controlled_result()
        object.__setattr__(result.source_inspection,'namespace_id','synthetic-tampered')
        with self.request() as (fd, expected, _, _), patch.object(self.m,'execute_pdf_snapshot_inspection_job',return_value=result):
            with self.assertRaises(self.m.PdfSealedInspectionError): self.invoke(fd,expected)

    def test_disabling_entrypoint_prevents_capture(self):
        """The opt-out switch stops before descriptor access, even for valid-looking expectations."""
        _, expected, _ = self.fixture()
        with patch.dict(os.environ,{DISABLE:'1'}), patch.object(self.m.descriptor,'read_sealed_pdf_request') as capture:
            with self.assertRaises(self.m.PdfSealedInspectionError): self.invoke(3,expected)
            capture.assert_not_called()

    def test_transitive_disables_still_block_native_dispatch(self):
        """The integration cannot reactivate disabled transport, source or inspector prerequisites."""
        flags = structured_tests.DISABLES+('OMNIGENIS_PDF_SNAPSHOT_INSPECTION_DISABLED',
            'OMNIGENIS_PDF_INSPECTION_REQUEST_DISABLED','OMNIGENIS_PDF_REQUEST_DESCRIPTOR_DISABLED',DISABLE)
        with self.request() as (fd, expected, _, _):
            for flag in flags:
                with patch.dict(os.environ,{flag:'1'}), patch.object(self.m,'execute_pdf_snapshot_inspection_job') as job:
                    with self.assertRaises(self.m.PdfSealedInspectionError): self.invoke(fd,expected)
                    job.assert_not_called()

    def test_disable_during_capture_prevents_job(self):
        """Recheck the entrypoint between the immutable capture and native dispatch."""
        read = descriptor.read_sealed_pdf_request
        def capture(*args,**kwargs):
            """Change the synthetic switch only after real descriptor capture."""
            result = read(*args,**kwargs); os.environ[DISABLE]='1'; return result
        with self.request() as (fd, expected, _, _), patch.dict(os.environ,{}), \
             patch.object(self.m.descriptor,'read_sealed_pdf_request',side_effect=capture), \
             patch.object(self.m,'execute_pdf_snapshot_inspection_job') as job:
            with self.assertRaises(self.m.PdfSealedInspectionError): self.invoke(fd,expected)
            job.assert_not_called()

    def test_disable_during_job_withholds_complete_result(self):
        """Even a complete result is withheld when the optional entrypoint is disabled mid-call."""
        result = self.controlled_result()
        def execute(**kwargs):
            """Return a real typed control result after changing the synthetic switch."""
            os.environ[DISABLE]='1'; return result
        with self.request() as (fd, expected, _, _), patch.dict(os.environ,{}), \
             patch.object(self.m,'execute_pdf_snapshot_inspection_job',side_effect=execute):
            with self.assertRaises(self.m.PdfSealedInspectionError): self.invoke(fd,expected)

    def test_profile_drift_before_and_after_dispatch_is_rejected(self):
        """The integration's result budget and dependency identity cannot silently drift."""
        _, expected, _ = self.fixture()
        for name,value in (('MAX_RESULT_BYTES',1),('SOURCE_PROFILE_SHA256','f'*64)):
            with patch.object(self.m,name,value), patch.object(self.m.descriptor,'read_sealed_pdf_request') as capture:
                with self.assertRaises(self.m.PdfSealedInspectionError): self.invoke(3,expected)
                capture.assert_not_called()
        result = self.controlled_result()
        def execute(**kwargs):
            """Simulate runtime drift after a successful fixed job."""
            self.m.MAX_RESULT_BYTES=1; return result
        with self.request() as (fd, expected, _, _), patch.object(self.m,'MAX_RESULT_BYTES',self.m.MAX_RESULT_BYTES), \
             patch.object(self.m,'execute_pdf_snapshot_inspection_job',side_effect=execute):
            with self.assertRaises(self.m.PdfSealedInspectionError): self.invoke(fd,expected)

    def test_borrowed_descriptor_offset_flags_and_lifetime_are_preserved(self):
        """The entrypoint captures once and never closes, seeks or rewrites the borrowed handle."""
        with self.request() as (fd, expected, _, packet), self.h.h.mocked():
            os.lseek(fd,7,os.SEEK_SET); inheritable=os.get_inheritable(fd)
            self.invoke(fd,expected)
            self.assertEqual(os.lseek(fd,0,os.SEEK_CUR),7)
            self.assertEqual(os.get_inheritable(fd),inheritable)
            self.assertEqual(os.pread(fd,len(packet),0),packet)
        with self.assertRaises(OSError): os.fstat(fd)

    def test_process_interrupt_is_not_disguised_as_completion(self):
        """BaseException cancellation is propagated and the caller still owns descriptor cleanup."""
        with self.request() as (fd, expected, _, _), \
             patch.object(self.m,'execute_pdf_snapshot_inspection_job',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt): self.invoke(fd,expected)
            os.fstat(fd)
        with self.assertRaises(OSError): os.fstat(fd)

    def test_returned_result_retains_its_existing_seal(self):
        """Post-return tampering remains rejected by the original result API."""
        with self.request() as (fd, expected, _, _), self.h.h.mocked(): result=self.invoke(fd,expected)
        object.__setattr__(result,'page_count',1)
        with self.assertRaises(structured.PdfStructuredSourceJobError): result.to_bytes()

    def test_actual_one_thirty_three_sixty_four_page_result_parity(self):
        """Run every real native stage and compare complete result bytes with the original route."""
        for pages,(ir,pdf) in self.h.native_cases().items():
            raw=_json_bytes(ir)
            with self.request(presentation_ir_bytes=raw,expected_ir_sha256=sha256(raw).hexdigest(),pdf_bytes=pdf,
                    expected_pdf_sha256=sha256(pdf).hexdigest(),page_count=pages) as (fd,expected,args,packet):
                before=snapshot.execute_pdf_snapshot_inspection_job(**args)
                after=self.invoke(fd,expected)
                self.assertEqual(after.to_bytes(),before.to_bytes())
                self.assertIs(type(after),structured.PdfStructuredSourceResult)
                self.assertEqual(len(after.to_dict()['inspection_dimensions']),8)
                self.assertFalse(after.to_dict()['aggregate_job_resources_qualified'])
                self.assertFalse(after.to_dict()['release_authorized'])
                self.assertEqual(os.pread(fd,len(packet),0),packet)
                self.assertEqual(_json_bytes(ir),raw)

    def test_manifest_exact_reuse_and_unchanged_default_scope(self):
        """Updated source/profile pins retain the existing default, executor and release boundaries."""
        manifest=json.loads((ROOT/'reporting/pdf-sealed-inspection.v1.json').read_text())
        self.assertEqual(manifest['profile'],self.m.sealed_inspection_profile())
        self.assertEqual(manifest['profile_sha256'],self.m.PROFILE_SHA256)
        for key in ('default_pipeline_activated','new_executor_activated','release_authorized','dependencies_changed'):
            self.assertIs(manifest[key],False)
        self.assertIs(manifest['existing_profiles_changed'],True)
        for name,digest in manifest['reused_source_sha256'].items():
            self.assertEqual(sha256((ROOT/name).read_bytes()).hexdigest(),digest)
        for name in ('reporting/pdf_sealed_inspection.py','tests/test_reporting_pdf_sealed_inspection.py'):
            tree=ast.parse((ROOT/name).read_text())
            for node in ast.walk(tree):
                if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):self.assertTrue(ast.get_docstring(node),node.name)

    def test_profile_is_detached_and_result_identity_remains_original(self):
        """Mutating a returned manifest view never alters the active integration profile."""
        value=self.m.sealed_inspection_profile();value['max_result_bytes']=1
        self.assertEqual(self.m.sealed_inspection_profile()['max_result_bytes'],structured.MAX_RESULT_BYTES)
        self.assertEqual(self.m.sealed_inspection_profile()['resource_profile_sha256'],structured.PROFILE_SHA256)


if __name__ == '__main__':
    unittest.main()
