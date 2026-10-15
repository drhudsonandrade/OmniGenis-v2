"""Real sealed descriptor handoff, kept separate from execution and authorization."""
from contextlib import contextmanager
from hashlib import sha256
import ast
import errno
import fcntl
import importlib
import importlib.util
import json
import mmap
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from reporting import pdf_inspection_request as codec
from reporting import pdf_snapshot_inspection as snapshot
from reporting.page_checkpoints import _json_bytes
from tests import test_reporting_pdf_inspection_request as prior

ROOT = Path(__file__).resolve().parents[1]
SEALS = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL


class PdfRequestDescriptorTests(unittest.TestCase):
    """A kernel seal binds bytes, not an issuer, complete job or release authority."""

    def setUp(self):
        """Require an observed assertion RED before the new boundary exists."""
        self.assertIsNotNone(importlib.util.find_spec('reporting.pdf_request_descriptor'),
                             'sealed request descriptor boundary is missing')
        self.m = importlib.import_module('reporting.pdf_request_descriptor')
        self.h = prior.PdfInspectionRequestTests(); self.h.setUp()
        self.args = self.h.args.copy(); self.packet = self.h.encode()
        self.expected = dict(expected_packet_sha256=sha256(self.packet).hexdigest(),
            expected_protocol_profile_sha256=codec.PROFILE_SHA256,
            expected_namespace_id=self.args['namespace_id'], expected_job_id=self.args['job_id'],
            expected_request_sha256=self.args['request_sha256'],
            expected_descriptor_profile_sha256=self.m.PROFILE_SHA256)

    def opened(self, packet=None, **changes):
        """Pass independently resolved context, not values read out of a received frame."""
        raw = self.packet if packet is None else packet
        values = {**self.expected, 'expected_packet_sha256':sha256(raw).hexdigest(), **changes}
        return self.m.sealed_pdf_request(raw, **values)

    def read(self, fd, **changes):
        """Read a borrowed descriptor through the fixed receiver interface."""
        return self.m.read_sealed_pdf_request(fd, **{**self.expected, **changes})

    @contextmanager
    def raw_descriptor(self, raw=None, seals=SEALS, mode=0o600, size=None):
        """Create synthetic adversarial kernel objects independently of the producer."""
        fd = os.memfd_create('synthetic-request-test', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            data = self.packet if raw is None else raw
            os.fchmod(fd, mode)
            self.assertEqual(os.write(fd, data), len(data))
            if size is not None: os.ftruncate(fd, size)
            if seals: fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
            yield fd
        finally:
            os.close(fd)

    def assert_closed(self, fd):
        """Observe actual descriptor closure, rather than counting open handles globally."""
        with self.assertRaises(OSError) as caught: os.fstat(fd)
        self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_real_anonymous_private_sealed_roundtrip(self):
        """The handoff preserves every byte and returns only the existing job arguments."""
        with self.opened() as fd:
            info = os.fstat(fd)
            self.assertTrue(stat.S_ISREG(info.st_mode)); self.assertEqual(info.st_nlink, 0)
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            self.assertEqual(info.st_size, len(self.packet))
            self.assertEqual(fcntl.fcntl(fd, fcntl.F_GET_SEALS) & SEALS, SEALS)
            self.assertFalse(os.get_inheritable(fd))
            self.assertEqual(self.read(fd), self.args)
            self.assertEqual(os.pread(fd, len(self.packet), 0), self.packet)
        self.assert_closed(fd)

    def test_kernel_rejects_write_grow_shrink_and_new_shared_mapping(self):
        """Even another open handle cannot change a sealed inode's content or size."""
        with self.opened() as fd:
            duplicate = os.dup(fd)
            try:
                for handle in (fd, duplicate):
                    operations = (lambda:os.pwrite(handle,b'X',0),
                                  lambda:os.ftruncate(handle,len(self.packet)+1),
                                  lambda:os.ftruncate(handle,0),
                                  lambda:mmap.mmap(handle,len(self.packet),access=mmap.ACCESS_WRITE))
                    for action in operations:
                        with self.assertRaises(OSError) as caught: action()
                        self.assertEqual(caught.exception.errno, errno.EPERM)
                with self.assertRaises(OSError): fcntl.fcntl(fd, fcntl.F_ADD_SEALS, 0)
                self.assertEqual(self.read(fd), self.args)
            finally: os.close(duplicate)

    def test_context_closes_on_caller_exception_without_rewriting_it(self):
        """Exceptions in the caller's body are not converted into input-validation errors."""
        with self.assertRaisesRegex(RuntimeError, 'synthetic caller failure'):
            with self.opened() as fd: raise RuntimeError('synthetic caller failure')
        self.assert_closed(fd)

    def test_receiver_preserves_borrowed_descriptor_and_offset(self):
        """Positional reads leave the original file offset, flags and handle ownership intact."""
        with self.opened() as fd:
            os.lseek(fd, 7, os.SEEK_SET)
            flags = fcntl.fcntl(fd, fcntl.F_GETFD)
            self.assertEqual(self.read(fd), self.args)
            self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), 7)
            self.assertEqual(fcntl.fcntl(fd, fcntl.F_GETFD), flags)
            self.assertEqual(os.fstat(fd).st_size, len(self.packet))

    def test_receiver_closes_only_its_duplicate_on_success_and_failure(self):
        """The receiver's close-on-exec duplicate is released on both acceptance paths."""
        original = fcntl.fcntl; copies = []
        def tracked(fd, operation, argument=0):
            """Observe real duplication without substituting file contents or kernel guards."""
            result = original(fd, operation, argument)
            if operation == fcntl.F_DUPFD_CLOEXEC:
                self.assertFalse(os.get_inheritable(result)); copies.append(result)
            return result
        with self.opened() as fd:
            for digest in (self.expected['expected_packet_sha256'], 'f'*64):
                with patch.object(self.m.fcntl, 'fcntl', side_effect=tracked):
                    if digest == 'f'*64:
                        with self.assertRaises(self.m.PdfRequestDescriptorError):
                            self.read(fd, expected_packet_sha256=digest)
                    else: self.assertEqual(self.read(fd), self.args)
                self.assert_closed(copies[-1]); os.fstat(fd)

    def test_every_required_seal_is_mandatory_before_payload_read(self):
        """Read-only permissions and a partial seal mask are not immutable transport."""
        for missing in (fcntl.F_SEAL_WRITE, fcntl.F_SEAL_GROW, fcntl.F_SEAL_SHRINK, fcntl.F_SEAL_SEAL):
            with self.raw_descriptor(seals=SEALS & ~missing) as fd, patch.object(self.m.os,'pread') as reader:
                with self.assertRaises(self.m.PdfRequestDescriptorError): self.read(fd)
                reader.assert_not_called()

    def test_named_unlinked_unsealed_and_nonregular_inputs_are_rejected(self):
        """Paths, plain anonymous files, pipes, sockets and directories do not gain seals."""
        with tempfile.TemporaryFile() as plain, tempfile.NamedTemporaryFile() as named:
            for stream in (plain, named):
                stream.write(self.packet); stream.flush()
                with patch.object(self.m.os,'pread') as reader:
                    with self.assertRaises(self.m.PdfRequestDescriptorError): self.read(stream.fileno())
                    reader.assert_not_called()
        read_fd, write_fd = os.pipe()
        left, right = socket.socketpair()
        directory = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for fd in (read_fd, write_fd, left.fileno(), directory):
                with patch.object(self.m.os,'pread') as reader:
                    with self.assertRaises(self.m.PdfRequestDescriptorError): self.read(fd)
                    reader.assert_not_called()
        finally:
            os.close(read_fd); os.close(write_fd); left.close(); right.close(); os.close(directory)

    def test_descriptor_types_and_standard_streams_rejected_before_io(self):
        """A borrowed FD is an exact non-standard-stream integer, not a path or fileno object."""
        for value in (True,False,None,-1,0,1,2,2**31,'3',Path('synthetic'),object()):
            with patch.object(self.m.fcntl,'fcntl') as call:
                with self.assertRaises(self.m.PdfRequestDescriptorError): self.read(value)
                call.assert_not_called()

    def test_closed_descriptor_fails_with_content_free_error(self):
        """A stale handle never resolves to an accepted request merely because it is numeric."""
        with self.opened() as fd: pass
        with self.assertRaises(self.m.PdfRequestDescriptorError) as caught: self.read(fd)
        self.assertEqual(str(caught.exception),'pdf_request_descriptor_invalid')
        self.assertTrue(caught.exception.__suppress_context__)

    def test_sealed_file_size_checked_before_read(self):
        """A sparse oversized kernel file does not trigger allocation of its claimed length."""
        for size in (0,codec.HEADER.size,codec.MAX_PACKET_BYTES+1):
            with self.raw_descriptor(size=size) as fd, patch.object(self.m.os,'pread') as reader:
                with self.assertRaises(self.m.PdfRequestDescriptorError): self.read(fd)
                reader.assert_not_called()

    def test_permissions_are_checked_not_assumed_from_seals(self):
        """The fixed descriptor profile admits only its exact owner-private mode."""
        for mode in (0o400,0o644,0o666,0o700):
            with self.raw_descriptor(mode=mode) as fd, patch.object(self.m.os,'pread') as reader:
                with self.assertRaises(self.m.PdfRequestDescriptorError): self.read(fd)
                reader.assert_not_called()

    def test_invalid_packet_and_context_precede_allocation(self):
        """A wrong expected digest or foreign receiver context is not sealed as accepted input."""
        changes = ({'expected_packet_sha256':'f'*64}, {'expected_namespace_id':'synthetic-other'},
                   {'expected_job_id':'synthetic-other'}, {'expected_request_sha256':'f'*64},
                   {'expected_protocol_profile_sha256':'f'*64}, {'expected_descriptor_profile_sha256':'f'*64})
        for change in changes:
            with patch.object(self.m.os,'memfd_create') as allocate:
                with self.assertRaises(self.m.PdfRequestDescriptorError):
                    with self.opened(**change): pass
                allocate.assert_not_called()

    def test_exact_immutable_packet_bytes_required(self):
        """The creator never coerces a mutable or foreign byte-like transport."""
        class ForeignBytes(bytes):
            """A subclass is not the codec's exact immutable bytes input type."""
        for raw in (bytearray(self.packet),memoryview(self.packet),ForeignBytes(self.packet),'x',None):
            with patch.object(self.m.os,'memfd_create') as allocate:
                with self.assertRaises(self.m.PdfRequestDescriptorError):
                    with self.m.sealed_pdf_request(raw, **self.expected): pass
                allocate.assert_not_called()

    def test_receiver_rechecks_hash_and_foreign_context(self):
        """An actual sealed descriptor never replaces independent receiver identity checks."""
        with self.opened() as fd:
            for change in ({'expected_packet_sha256':'f'*64},{'expected_namespace_id':'synthetic-other'},
                           {'expected_job_id':'synthetic-other'},{'expected_request_sha256':'f'*64}):
                with self.assertRaises(self.m.PdfRequestDescriptorError): self.read(fd, **change)
            self.assertEqual(self.read(fd), self.args)

    def test_repinned_malformed_frame_is_still_rejected(self):
        """A seal and matching packet hash do not excuse truncation or trailing frame bytes."""
        for raw in (self.packet[:-1],self.packet+b'X',self.packet+self.packet):
            with self.raw_descriptor(raw=raw) as fd:
                with self.assertRaises(self.m.PdfRequestDescriptorError):
                    self.read(fd, expected_packet_sha256=sha256(raw).hexdigest())

    def test_short_writes_progress_without_losing_bytes(self):
        """The creator handles real partial writes rather than assuming a single full write."""
        original = os.write
        with patch.object(self.m.os,'write',side_effect=lambda fd,data:original(fd,data[:7])) as writer:
            with self.opened() as fd: self.assertEqual(self.read(fd),self.args)
        self.assertGreater(writer.call_count,1)

    def test_zero_progress_write_closes_created_descriptor(self):
        """A stalled writer cannot loop forever or leak an accepted descriptor."""
        original = os.memfd_create; created=[]
        def allocate(*args):
            """Record the actual owned FD for a direct closure check."""
            fd=original(*args);created.append(fd);return fd
        with patch.object(self.m.os,'memfd_create',side_effect=allocate), patch.object(self.m.os,'write',return_value=0):
            with self.assertRaises(self.m.PdfRequestDescriptorError):
                with self.opened(): pass
        self.assert_closed(created[0])

    def test_unavailable_memfd_has_no_named_or_privileged_fallback(self):
        """Unsupported anonymous sealing remains a fixed failure, not a weaker transport."""
        with patch.object(self.m.os,'memfd_create',side_effect=OSError('SYNTHETIC-INTERNAL')), \
             patch('builtins.open') as named, patch('subprocess.run') as commands:
            with self.assertRaises(self.m.PdfRequestDescriptorError) as caught:
                with self.opened(): pass
            self.assertEqual(str(caught.exception),'pdf_request_descriptor_invalid')
            named.assert_not_called();commands.assert_not_called()

    def test_seal_failure_closes_the_unpublished_object(self):
        """Failure to install kernel guards never yields an unsealed fallback handle."""
        original_allocate=os.memfd_create;original_call=fcntl.fcntl;created=[]
        def allocate(*args):
            """Observe the new handle without replacing its real kernel allocation."""
            fd=original_allocate(*args);created.append(fd);return fd
        def failure(fd,operation,argument=0):
            """Inject only the actual seal-installation syscall failure."""
            if operation==fcntl.F_ADD_SEALS: raise OSError('SYNTHETIC-SEAL-FAILURE')
            return original_call(fd,operation,argument)
        with patch.object(self.m.os,'memfd_create',side_effect=allocate), patch.object(self.m.fcntl,'fcntl',side_effect=failure):
            with self.assertRaises(self.m.PdfRequestDescriptorError):
                with self.opened(): pass
        self.assert_closed(created[0])

    def test_existing_writable_shared_mapping_prevents_acceptance(self):
        """The real kernel refuses WRITE sealing while an older writable mapping exists."""
        original=os.write;views=[]
        def mapped_write(fd,data):
            """Retain a writable mapping only for this small synthetic pre-seal fixture."""
            count=original(fd,data)
            if not views: views.append(mmap.mmap(fd,os.fstat(fd).st_size,access=mmap.ACCESS_WRITE))
            return count
        try:
            with patch.object(self.m.os,'write',side_effect=mapped_write):
                with self.assertRaises(self.m.PdfRequestDescriptorError):
                    with self.opened(): pass
            self.assertEqual(len(views),1)
        finally:
            for view in views:view.close()

    def test_short_positional_reads_preserve_exact_packet_and_offset(self):
        """A short read is accumulated within the original finite size and without seeking."""
        original=os.pread
        with self.opened() as fd:
            offset=os.lseek(fd,0,os.SEEK_CUR)
            with patch.object(self.m.os,'pread',side_effect=lambda fd,count,at:original(fd,min(count,11),at)):
                self.assertEqual(self.read(fd),self.args)
            self.assertEqual(os.lseek(fd,0,os.SEEK_CUR),offset)

    def test_early_eof_or_read_failure_never_returns_partial_arguments(self):
        """The receiver rejects an incomplete capture and retains the borrowed descriptor."""
        with self.opened() as fd:
            with patch.object(self.m.os,'pread',return_value=b''):
                with self.assertRaises(self.m.PdfRequestDescriptorError):self.read(fd)
            with patch.object(self.m.os,'pread',side_effect=OSError('SYNTHETIC-READ-FAILURE')):
                with self.assertRaises(self.m.PdfRequestDescriptorError):self.read(fd)
            self.assertEqual(self.read(fd),self.args)

    def test_disabled_profiles_prevent_allocation_and_receiving(self):
        """Every existing prerequisite and the new descriptor switch remain fail-closed."""
        flags=prior.structured_tests.DISABLES+('OMNIGENIS_PDF_SNAPSHOT_INSPECTION_DISABLED',
            'OMNIGENIS_PDF_INSPECTION_REQUEST_DISABLED','OMNIGENIS_PDF_REQUEST_DESCRIPTOR_DISABLED')
        with self.opened() as fd:
            for flag in flags:
                with patch.dict(os.environ,{flag:'1'}),patch.object(self.m.os,'memfd_create') as allocate:
                    with self.assertRaises(self.m.PdfRequestDescriptorError):
                        with self.opened():pass
                    with self.assertRaises(self.m.PdfRequestDescriptorError):self.read(fd)
                    allocate.assert_not_called()

    def test_disabling_during_capture_prevents_final_return(self):
        """A switch change during a real positional read invalidates final acceptance."""
        original=os.pread
        def disable(fd,count,offset):
            """Set the new switch while preserving the actual synthetic file read."""
            result=original(fd,count,offset);os.environ['OMNIGENIS_PDF_REQUEST_DESCRIPTOR_DISABLED']='1';return result
        with self.opened() as fd,patch.dict(os.environ),patch.object(self.m.os,'pread',side_effect=disable):
            with self.assertRaises(self.m.PdfRequestDescriptorError):self.read(fd)

    def test_profile_drift_and_unsupported_runtime_fail_closed(self):
        """Pinned transport and descriptor policies cannot silently change their limits."""
        with self.opened() as fd:
            for name,value in (('MAX_PACKET_BYTES',codec.MAX_PACKET_BYTES+1),('CHUNK_BYTES',1),('_SUPPORTED',False)):
                with patch.object(self.m,name,value):
                    with self.assertRaises(self.m.PdfRequestDescriptorError):self.read(fd)
                    with self.assertRaises(self.m.PdfRequestDescriptorError):
                        with self.opened():pass

    def test_no_named_storage_process_or_document_parser(self):
        """Only the declared anonymous descriptor operations occur in this adapter."""
        with patch('builtins.open',side_effect=AssertionError('named open')), \
             patch.object(os,'open',side_effect=AssertionError('path open')), \
             patch('subprocess.run',side_effect=AssertionError('process launch')), \
             patch('subprocess.Popen',side_effect=AssertionError('process launch')), \
             patch.object(snapshot,'_decode_source',side_effect=AssertionError('source parse')):
            with self.opened() as fd:self.assertEqual(self.read(fd),self.args)

    def test_opaque_invalid_source_requires_original_inspection_rejection(self):
        """Sealed transport does not promote a malformed presentation to valid input."""
        raw=b'not-json';packet=self.h.encode(presentation_ir_bytes=raw,expected_ir_sha256=sha256(raw).hexdigest())
        with self.opened(packet) as fd:
            args=self.read(fd,expected_packet_sha256=sha256(packet).hexdigest())
        with self.h.h.h.mocked() as calls:
            with self.assertRaises(snapshot.PdfSnapshotInspectionError):snapshot.execute_pdf_snapshot_inspection_job(**args)
            self.assertEqual(calls,[])

    def test_explicit_child_inheritance_retains_real_kernel_seals(self):
        """A controlled child can inspect a deliberately inherited FD but cannot mutate it."""
        code="""import errno,fcntl,hashlib,json,os,sys
fd=int(sys.argv[1]);n=os.fstat(fd).st_size;denied=0
for op in (lambda:os.pwrite(fd,b'X',0),lambda:os.ftruncate(fd,n+1),lambda:os.ftruncate(fd,0)):
 try:op()
 except OSError as e:
  if e.errno!=errno.EPERM:raise
  denied+=1
print(json.dumps({'denied':denied,'sha256':hashlib.sha256(os.pread(fd,n,0)).hexdigest(),'seals':fcntl.fcntl(fd,fcntl.F_GET_SEALS)}))
"""
        with self.opened() as fd:
            result=subprocess.run([sys.executable,'-I','-B','-c',code,str(fd)],pass_fds=(fd,),
                capture_output=True,text=True,timeout=5,check=True)
            record=json.loads(result.stdout)
            self.assertEqual(record['denied'],3);self.assertEqual(record['sha256'],sha256(self.packet).hexdigest())
            self.assertEqual(record['seals']&SEALS,SEALS);self.assertFalse(os.get_inheritable(fd))

    def test_detected_handle_replacement_is_not_closed(self):
        """A caller ownership violation must not close an unrelated replacement inode."""
        context=self.opened();fd=context.__enter__();os.close(fd)
        other=os.open(os.devnull,os.O_RDONLY|os.O_CLOEXEC)
        if other!=fd:os.dup2(other,fd,inheritable=False);os.close(other)
        try:
            with self.assertRaises(self.m.PdfRequestDescriptorError):context.__exit__(None,None,None)
            self.assertTrue(stat.S_ISCHR(os.fstat(fd).st_mode))
        finally:os.close(fd)

    def test_independent_owned_copy_outlives_context_without_revocation_claim(self):
        """Closing the producer is not revocation of descriptors deliberately copied by its caller."""
        with self.opened() as fd:copy=os.dup(fd)
        try:
            self.assert_closed(fd);self.assertEqual(self.read(copy),self.args)
            self.assertFalse(self.m.descriptor_profile()['duplicate_revocation_qualified'])
        finally:os.close(copy)

    def test_real_native_one_thirty_three_sixty_four_page_parity(self):
        """The same complete eight-dimensional result survives the actual sealed handoff."""
        for pages,(ir,pdf) in self.h.h.native_cases().items():
            raw=_json_bytes(ir);args={**self.args,'presentation_ir_bytes':raw,'expected_ir_sha256':sha256(raw).hexdigest(),
                'pdf_bytes':pdf,'expected_pdf_sha256':sha256(pdf).hexdigest(),'page_count':pages}
            packet=self.h.encode(**args)
            with self.opened(packet) as fd:decoded=self.read(fd,expected_packet_sha256=sha256(packet).hexdigest())
            self.assertEqual(decoded,args)
            before=snapshot.execute_pdf_snapshot_inspection_job(**args)
            after=snapshot.execute_pdf_snapshot_inspection_job(**decoded)
            self.assertEqual(after.to_bytes(),before.to_bytes())
            self.assertEqual(len(after.to_dict()['inspection_dimensions']),8)
            self.assertFalse(after.to_dict()['aggregate_job_resources_qualified'])
            self.assertFalse(after.to_dict()['release_authorized']);self.assertEqual(_json_bytes(ir),raw)

    def test_manifest_unchanged_dependencies_and_claims(self):
        """The descriptor profile is not execution, authentication or a replacement source codec."""
        manifest=json.loads((ROOT/'reporting/pdf-request-descriptor.v1.json').read_text())
        self.assertEqual(manifest['profile'],self.m.descriptor_profile());self.assertEqual(manifest['profile_sha256'],self.m.PROFILE_SHA256)
        for name,digest in manifest['reused_source_sha256'].items():self.assertEqual(sha256((ROOT/name).read_bytes()).hexdigest(),digest)
        self.assertEqual(self.m.MAX_PACKET_BYTES,codec.MAX_PACKET_BYTES);self.assertEqual(self.m.CHUNK_BYTES,65536)
        for flag in ('transport_authenticated','executor_activated','aggregate_job_resources_qualified','hard_job_deadline_enforced','release_authorized','duplicate_revocation_qualified'):
            self.assertIs(self.m.descriptor_profile()[flag],False)
        profile=self.m.descriptor_profile();profile['max_packet_bytes']=1
        self.assertEqual(self.m.descriptor_profile()['max_packet_bytes'],codec.MAX_PACKET_BYTES)
        for name in ('reporting/pdf_request_descriptor.py','tests/test_reporting_pdf_request_descriptor.py'):
            parsed=ast.parse((ROOT/name).read_text())
            for node in ast.walk(parsed):
                if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):self.assertTrue(ast.get_docstring(node),node.name)
            if name.startswith('reporting/'):self.assertFalse(any(isinstance(node,ast.Assert) for node in ast.walk(parsed)))


if __name__=='__main__':unittest.main()
