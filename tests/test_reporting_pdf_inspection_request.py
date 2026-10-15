"""Bounded lossless request transport, distinct from execution and authorization."""
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
from reporting.page_checkpoints import _json_bytes
from tests import test_reporting_pdf_snapshot_inspection as previous
from tests import test_reporting_pdf_structured_source_job as structured_tests

ROOT = Path(__file__).resolve().parents[1]
HEADER = struct.Struct('>8sIII')


class PdfInspectionRequestTests(unittest.TestCase):
    """The frame transports exact arguments, never grants a right to execute them."""

    def setUp(self):
        """Require observed missing implementation before testing the codec."""
        self.assertIsNotNone(importlib.util.find_spec('reporting.pdf_inspection_request'),
                             'bounded inspection request codec is missing')
        self.m = importlib.import_module('reporting.pdf_inspection_request')
        self.h = previous.PdfSnapshotInspectionTests()
        self.h.setUp()
        self.args = self.h.args.copy()

    def encode(self, **changes):
        """Call the explicit encoder with independent source and profile identities."""
        return self.m.encode_pdf_snapshot_request(**{**self.args, **changes},
            expected_protocol_profile_sha256=self.m.PROFILE_SHA256)

    def decode(self, packet, **changes):
        """Pin packet bytes and original context separately from decoded metadata."""
        expected = dict(expected_packet_sha256=sha256(packet).hexdigest(),
            expected_protocol_profile_sha256=self.m.PROFILE_SHA256,
            expected_namespace_id=self.args['namespace_id'], expected_job_id=self.args['job_id'],
            expected_request_sha256=self.args['request_sha256'])
        return self.m.decode_pdf_snapshot_request(packet, **{**expected, **changes})

    def reframe(self, packet, *, metadata=None, source=None, pdf=None, magic=b'OGPDFRQ1'):
        """Build independently hash-pinned adversarial frames, not only bad digests."""
        _, m, s, d = HEADER.unpack_from(packet)
        start = HEADER.size
        meta = packet[start:start+m] if metadata is None else metadata
        raw = packet[start+m:start+m+s] if source is None else source
        document = packet[start+m+s:] if pdf is None else pdf
        return HEADER.pack(magic,len(meta),len(raw),len(document))+meta+raw+document

    def metadata(self, packet):
        """Read the small flat metadata for independent negative fixtures."""
        size = HEADER.unpack_from(packet)[1]
        return json.loads(packet[HEADER.size:HEADER.size+size])

    def test_roundtrip_returns_only_original_call_arguments(self):
        """No executor, result wrapper or caller-controlled service property is introduced."""
        packet = self.encode()
        self.assertEqual(self.decode(packet), self.args)
        self.assertEqual(set(self.decode(packet)), set(inspect.signature(
            snapshot.execute_pdf_snapshot_inspection_job).parameters))
        self.assertEqual(sha256(packet).hexdigest(), sha256(self.encode()).hexdigest())

    def test_framing_is_fixed_big_endian_and_lossless(self):
        """Independent framing preserves raw UTF-8 source and PDF bytes without base64."""
        packet = self.encode()
        meta = _json_bytes({k:v for k,v in self.args.items() if k not in ('pdf_bytes','presentation_ir_bytes')})
        expected = HEADER.pack(b'OGPDFRQ1',len(meta),len(self.args['presentation_ir_bytes']),
            len(self.args['pdf_bytes']))+meta+self.args['presentation_ir_bytes']+self.args['pdf_bytes']
        self.assertEqual(packet,expected)

    def test_exact_bytes_required_without_coercion(self):
        """Mutable buffers, subclasses and strings never become trusted immutable frames."""
        class Foreign(bytes):
            """An immutable subclass is still outside the exact transport type."""
        for name in ('pdf_bytes','presentation_ir_bytes'):
            for value in (bytearray(self.args[name]),memoryview(self.args[name]),Foreign(self.args[name]),'x',None):
                with self.subTest(name=name,kind=type(value)):
                    with self.assertRaises(self.m.PdfInspectionRequestError):self.encode(**{name:value})
        packet=self.encode()
        for value in (bytearray(packet),memoryview(packet),Foreign(packet),'x',None):
            with self.assertRaises(self.m.PdfInspectionRequestError):
                self.m.decode_pdf_snapshot_request(value,expected_packet_sha256=sha256(packet).hexdigest(),
                    expected_protocol_profile_sha256=self.m.PROFILE_SHA256,
                    expected_namespace_id=self.args['namespace_id'],expected_job_id=self.args['job_id'],
                    expected_request_sha256=self.args['request_sha256'])

    def test_truncation_concatenation_and_trailing_bytes_rejected(self):
        """Exactly one complete packet is required, not a prefix of a larger stream."""
        packet=self.encode()
        for raw in [packet[:n] for n in range(HEADER.size)]+[packet[:-1],packet+b'\0',packet+packet]:
            with self.assertRaises(self.m.PdfInspectionRequestError):self.decode(raw)

    def test_forged_length_bounds_precede_json_decode(self):
        """Huge, zero or inconsistent field lengths cannot allocate a claimed body."""
        packet=self.encode();values=list(HEADER.unpack_from(packet))
        for index in (1,2,3):
            for value in (0,0xffffffff,values[index]+1):
                other=values.copy();other[index]=value
                raw=HEADER.pack(*other)+packet[HEADER.size:]
                with patch.object(self.m.json,'loads') as decoder:
                    with self.assertRaises(self.m.PdfInspectionRequestError):self.decode(raw)
                    decoder.assert_not_called()

    def test_packet_digest_precedes_header_metadata_decode(self):
        """Rehashed source metadata does not replace an independently expected packet hash."""
        packet=self.encode()
        for digest in ('f'*64,'A'*64,'1',' '+sha256(packet).hexdigest(),None):
            with patch.object(self.m.json,'loads') as decoder:
                with self.assertRaises(self.m.PdfInspectionRequestError):
                    self.decode(packet,expected_packet_sha256=digest)
                decoder.assert_not_called()

    def test_magic_and_version_are_not_accepted_as_aliases(self):
        """Unknown transport versions require a different reviewed profile."""
        packet=self.encode()
        for magic in (b'OGPDFRQ2',b'ogpdfrq1',b'XXXXXXXX'):
            with self.assertRaises(self.m.PdfInspectionRequestError):self.decode(self.reframe(packet,magic=magic))

    def test_source_and_pdf_hashes_remain_independent(self):
        """A valid outer hash cannot conceal changed source or PDF segments."""
        packet=self.encode()
        for change in ({'source':self.args['presentation_ir_bytes']+b' '},
                       {'pdf':self.args['pdf_bytes']+b' '}):
            with self.assertRaises(self.m.PdfInspectionRequestError):self.decode(self.reframe(packet,**change))
        for name in ('expected_pdf_sha256','expected_ir_sha256'):
            with self.assertRaises(self.m.PdfInspectionRequestError):self.encode(**{name:'e'*64})

    def test_foreign_job_namespace_and_request_rejected_when_repinned(self):
        """The receiver's independent context defeats cross-job packet replacement."""
        packet=self.encode()
        for field in ('namespace_id','job_id','request_sha256'):
            meta=self.metadata(packet);meta[field]='e'*64 if field.endswith('sha256') else 'synthetic-foreign'
            with self.assertRaises(self.m.PdfInspectionRequestError):
                self.decode(self.reframe(packet,metadata=_json_bytes(meta)))
        for field in ('expected_namespace_id','expected_job_id','expected_request_sha256'):
            value='e'*64 if field.endswith('sha256') else 'synthetic-foreign'
            with self.assertRaises(self.m.PdfInspectionRequestError):self.decode(packet,**{field:value})

    def test_unknown_missing_command_and_path_fields_rejected(self):
        """A fixed metadata vocabulary is not a generic remote-command protocol."""
        packet=self.encode()
        for key in ('command','path','executor','service','environment','authorization','status'):
            meta=self.metadata(packet);meta[key]='SYNTHETIC-UNTRUSTED'
            with self.assertRaises(self.m.PdfInspectionRequestError):
                self.decode(self.reframe(packet,metadata=_json_bytes(meta)))
        for key in self.metadata(packet):
            meta=self.metadata(packet);del meta[key]
            with self.assertRaises(self.m.PdfInspectionRequestError):
                self.decode(self.reframe(packet,metadata=_json_bytes(meta)))

    def test_duplicate_escaped_and_noncanonical_metadata_rejected(self):
        """Duplicate keys and alternate spellings are rejected, not repaired."""
        packet=self.encode();meta=_json_bytes(self.metadata(packet))
        altered=[meta+b'\n',b' '+meta,json.dumps(self.metadata(packet),indent=2).encode(),
            meta[:-1]+b',"page_count":1}',meta[:-1]+b',"page_\\u0063ount":1}',
            meta.replace(b'en-US',b'\\u0065n-US')]
        for raw in altered:
            with self.assertRaises(self.m.PdfInspectionRequestError):self.decode(self.reframe(packet,metadata=raw))

    def test_malformed_metadata_is_fixed_error(self):
        """Invalid Unicode, root types, syntax, deep values and nonfinite values fail closed."""
        packet=self.encode()
        for raw in (b'{}\xff',b'\xef\xbb\xbf{}',b'[]',b'null',b'{}{}',b'{"x":NaN}',
                    b'{"x":"\\ud800"}',b'['*2000+b']'*2000):
            with self.assertRaises(self.m.PdfInspectionRequestError) as caught:
                self.decode(self.reframe(packet,metadata=raw))
            self.assertEqual(str(caught.exception),'pdf_inspection_request_invalid')
            self.assertTrue(caught.exception.__suppress_context__)

    def test_metadata_types_ranges_and_identifiers_are_strict(self):
        """Booleans are not pages; identifiers and digest strings are not coerced."""
        for value in (True,1.0,'1',0,65,None):
            with self.assertRaises(self.m.PdfInspectionRequestError):self.encode(page_count=value)
        for field,values in {'expected_language':['pt-BR',None,1],
                'namespace_id':['','../foreign','x'*10000,None],
                'job_id':['','a b',{},True], 'request_sha256':['F'*64,0,False]}.items():
            for value in values:
                with self.assertRaises(self.m.PdfInspectionRequestError):self.encode(**{field:value})

    def test_segment_maxima_and_one_byte_overflow(self):
        """Each 8-MiB boundary is independent and never raised by framing overhead."""
        raw=b's'*(8*1024*1024);pdf=b'%PDF-1.7'+b'p'*(len(raw)-8)
        args=dict(presentation_ir_bytes=raw,expected_ir_sha256=sha256(raw).hexdigest(),
                  pdf_bytes=pdf,expected_pdf_sha256=sha256(pdf).hexdigest())
        packet=self.encode(**args)
        self.assertEqual(self.decode(packet),{**self.args,**args})
        for field,data in (('presentation_ir_bytes',raw),('pdf_bytes',pdf)):
            extra={**args,field:data+b'x'}
            extra['expected_ir_sha256' if field=='presentation_ir_bytes' else 'expected_pdf_sha256']=sha256(data+b'x').hexdigest()
            with self.assertRaises(self.m.PdfInspectionRequestError):self.encode(**extra)
        with self.assertRaises(self.m.PdfInspectionRequestError):self.decode(b'x'*(self.m.MAX_PACKET_BYTES+1))

    def test_metadata_budget_rejected_before_parse(self):
        """Metadata has its own 4-KiB cap, independent of document budgets."""
        packet=self.reframe(self.encode(),metadata=b' ' * 4097)
        with patch.object(self.m.json,'loads') as decoder:
            with self.assertRaises(self.m.PdfInspectionRequestError):self.decode(packet)
            decoder.assert_not_called()

    def test_profile_pin_and_drift_rejected(self):
        """Transport, source and execution profiles remain distinct and exact."""
        packet=self.encode()
        with self.assertRaises(self.m.PdfInspectionRequestError):self.decode(packet,expected_protocol_profile_sha256='f'*64)
        for field in ('expected_source_profile_sha256','expected_resource_profile_sha256'):
            with self.assertRaises(self.m.PdfInspectionRequestError):self.encode(**{field:'f'*64})
        for field in ('MAX_SOURCE_BYTES','MAX_PDF_BYTES','MAX_METADATA_BYTES'):
            with patch.object(self.m,field,1):
                with self.assertRaises(self.m.PdfInspectionRequestError):self.decode(packet)

    def test_disable_switches_apply_to_both_directions(self):
        """Neither direction offers permissive fallback after any prerequisite is disabled."""
        packet=self.encode()
        flags=structured_tests.DISABLES+('OMNIGENIS_PDF_SNAPSHOT_INSPECTION_DISABLED',
                                        'OMNIGENIS_PDF_INSPECTION_REQUEST_DISABLED')
        for flag in flags:
            with patch.dict(os.environ,{flag:'1'}):
                with self.assertRaises(self.m.PdfInspectionRequestError):self.encode()
                with self.assertRaises(self.m.PdfInspectionRequestError):self.decode(packet)

    def test_codec_does_not_execute_or_parse_documents(self):
        """Codec operations perform no filesystem, subprocess, PDF or source-graph work."""
        with patch('subprocess.run',side_effect=AssertionError('unexpected execution')), \
             patch('subprocess.Popen',side_effect=AssertionError('unexpected process')), \
             patch('builtins.open',side_effect=AssertionError('unexpected file')), \
             patch.object(snapshot,'_decode_source',side_effect=AssertionError('unexpected source parse')):
            self.assertEqual(self.decode(self.encode()),self.args)

    def test_opaque_invalid_source_still_rejected_by_existing_job(self):
        """Lossless transport does not qualify malformed source as a valid presentation."""
        for raw in (b'not-json',b'{}',b'{"x":1,"x":2}'):
            packet=self.encode(presentation_ir_bytes=raw,expected_ir_sha256=sha256(raw).hexdigest())
            args=self.decode(packet)
            with self.h.h.mocked() as calls:
                with self.assertRaises(snapshot.PdfSnapshotInspectionError):
                    snapshot.execute_pdf_snapshot_inspection_job(**args)
                self.assertEqual(calls,[])

    def test_decoded_objects_do_not_mutate_packet_or_other_calls(self):
        """Decoded dictionaries are detached; original packet and body bytes are unchanged."""
        packet=self.encode();digest=sha256(packet).hexdigest()
        first=self.decode(packet);first['namespace_id']='different'
        self.assertEqual(self.decode(packet),self.args)
        self.assertEqual(sha256(packet).hexdigest(),digest)

    def test_empty_segments_and_wrong_pdf_marker_rejected(self):
        """Minimal envelope requirements are enforced without claiming PDF validation."""
        for field in ('pdf_bytes','presentation_ir_bytes'):
            with self.assertRaises(self.m.PdfInspectionRequestError):self.encode(**{field:b''})
        pdf=b'%PDF-2.0 synthetic'
        with self.assertRaises(self.m.PdfInspectionRequestError):
            self.encode(pdf_bytes=pdf,expected_pdf_sha256=sha256(pdf).hexdigest())

    def test_native_one_thirty_three_sixty_four_page_parity(self):
        """Original and transported arguments produce identical complete native results."""
        for pages,(ir,pdf) in self.h.native_cases().items():
            raw=_json_bytes(ir);args={**self.args,'presentation_ir_bytes':raw,
                'expected_ir_sha256':sha256(raw).hexdigest(),'pdf_bytes':pdf,
                'expected_pdf_sha256':sha256(pdf).hexdigest(),'page_count':pages}
            packet=self.encode(**args);decoded=self.decode(packet)
            before=snapshot.execute_pdf_snapshot_inspection_job(**args)
            after=snapshot.execute_pdf_snapshot_inspection_job(**decoded)
            self.assertEqual(after.to_bytes(),before.to_bytes())
            self.assertEqual(decoded,args)
            self.assertEqual(len(after.to_dict()['inspection_dimensions']),8)
            self.assertFalse(after.to_dict()['aggregate_job_resources_qualified'])
            self.assertFalse(after.to_dict()['release_authorized'])
            self.assertEqual(_json_bytes(ir),raw)

    def test_manifest_and_all_reused_hashes(self):
        """The codec adds no executor, resource qualification or default activation."""
        manifest=json.loads((ROOT/'reporting/pdf-inspection-request.v1.json').read_text())
        self.assertEqual(manifest['profile'],self.m.inspection_request_profile())
        self.assertEqual(manifest['profile_sha256'],self.m.PROFILE_SHA256)
        for key in ('default_pipeline_activated','executor_activated','release_authorized'):
            self.assertIs(manifest[key],False)
        for name,digest in manifest['reused_source_sha256'].items():
            self.assertEqual(sha256((ROOT/name).read_bytes()).hexdigest(),digest)
        for name in ('reporting/pdf_inspection_request.py','tests/test_reporting_pdf_inspection_request.py'):
            for node in ast.walk(ast.parse((ROOT/name).read_text())):
                if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                    self.assertTrue(ast.get_docstring(node),node.name)
        profile=self.m.inspection_request_profile();profile['max_metadata_bytes']=1
        self.assertEqual(self.m.inspection_request_profile()['max_metadata_bytes'],4096)


if __name__ == '__main__':
    unittest.main()
