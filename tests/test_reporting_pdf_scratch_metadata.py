"""Real confined metadata reads and strict descriptor refusal regressions."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from reporting import _pdf_bounded_scratch as scratch

ROOT = Path(__file__).resolve().parents[1]


class ScratchMetadataTests(unittest.TestCase):
    """Preserve exact mount mappings without granting post-confinement proc access."""

    def child(self, code):
        """Run a bounded disposable process without changing the test runner policy."""
        result = subprocess.run([sys.executable, '-I', '-B', '-c',
            'import sys;sys.path.insert(0,' + repr(str(ROOT)) + ');' + code],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=12,
            env={'PATH': os.defpath, 'LANG': 'C.UTF-8'})
        self.assertEqual(result.returncode, 0, result.stderr.decode()[-4000:])
        return json.loads(result.stdout)

    def test_real_mount_identity_remains_readable_after_landlock(self):
        """Reproduce the former fdinfo denial while requiring a live descriptor result."""
        value = self.child(r"""
import os, json
from pathlib import Path
from reporting import _pdf_bounded_scratch as s, _pdf_process_sandbox as box
fd=os.open('/run',os.O_PATH|os.O_DIRECTORY|os.O_CLOEXEC)
try:
 expected=s._fd_mount_id(fd)
 box.enforce_pdf_landlock(Path(s.__file__).with_name('_pdf_raster_window_worker.py'))
 box.enforce_pdf_network_filter()
 actual=s._fd_mount_id(fd)
 assert actual==expected
 try:os.open('/proc/self/mountinfo',os.O_RDONLY)
 except PermissionError:denied=True
 else:denied=False
 assert denied
 print(json.dumps({'same_mount':True,'proc_denied':denied}))
finally:os.close(fd)
""")
        self.assertEqual(value, {'same_mount': True, 'proc_denied': True})

    def test_original_mount_parser_works_after_inherited_landlock_and_exec(self):
        """Use a real read-only proc descriptor across exec, not synthetic mount records."""
        value = self.child(r"""
import os,json,subprocess,sys
from pathlib import Path
from reporting import _pdf_bounded_scratch as s, _pdf_process_sandbox as box
fd=os.open('/run',os.O_PATH|os.O_DIRECTORY|os.O_CLOEXEC)
try:
 expected=s._fd_mount_id(fd);dev=os.fstat(fd).st_dev
 before=s._mount_record(Path('/run'),dev,expected)
 with s.mountinfo_scope() as metadata:
  box.enforce_pdf_landlock(Path(s.__file__).with_name('_pdf_raster_window_worker.py'))
  box.enforce_pdf_network_filter()
  program='''import sys,os,json
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from reporting import _pdf_bounded_scratch as s
fd,metadata,expected=map(int,sys.argv[2:])
with s.mountinfo_scope(metadata):
 assert s._fd_mount_id(fd)==expected
 kind,flags=s._mount_record(Path('/run'),os.fstat(fd).st_dev,expected)
 assert kind=='tmpfs'
 try:os.open('/proc/self/mountinfo',os.O_RDONLY)
 except PermissionError:denied=True
 else:denied=False
 assert denied
 try:s._mount_record(Path('/run'),os.fstat(fd).st_dev,expected+1)
 except s.PdfBoundedScratchError:foreign=True
 else:foreign=False
 assert foreign
 print(json.dumps({'mapping_valid':True,'foreign_mount_rejected':foreign,'proc_denied':denied}))
os.close(metadata);os.close(fd)
'''
  r=subprocess.run([sys.executable,'-I','-B','-c',program,str(Path(s.__file__).parents[1]),str(fd),str(metadata),str(expected)],pass_fds=(fd,metadata),stdin=subprocess.DEVNULL,capture_output=True,timeout=8,env={'PATH':os.defpath,'LANG':'C.UTF-8'})
  assert r.returncode==0,r.stderr
  print(r.stdout.decode(),end='')
finally:os.close(fd)
""")
        self.assertEqual(value, {'mapping_valid': True, 'foreign_mount_rejected': True, 'proc_denied': True})

    def test_live_statx_matches_original_proc_identity(self):
        """Check the actual mount ID against independently opened kernel fdinfo."""
        fd=os.open('/run',os.O_PATH|os.O_DIRECTORY|os.O_CLOEXEC)
        try:
            lines=Path(f'/proc/self/fdinfo/{fd}').read_text().splitlines()
            expected=int(next(x.split(':',1)[1] for x in lines if x.startswith('mnt_id:')))
            with patch.object(scratch,'_read_kernel_text',side_effect=AssertionError('proc path forbidden')):
                self.assertEqual(scratch._fd_mount_id(fd),expected)
        finally:os.close(fd)

    def test_invalid_descriptor_types_and_closed_descriptor_are_refused(self):
        """Reject ambiguous integers, stdlib coercions, invalid FDs and overflow."""
        fd=os.open('/run',os.O_PATH|os.O_DIRECTORY);os.close(fd)
        for value in (True,False,None,'3',-1,2**40,fd):
            with self.subTest(value=value),self.assertRaises(scratch.PdfBoundedScratchError):
                scratch._fd_mount_id(value)

    def test_owned_metadata_scope_closes_its_descriptor(self):
        """Close the descriptor acquired by the scope without leaving process state."""
        with scratch.mountinfo_scope() as fd:
            self.assertEqual(scratch.active_mountinfo_fd(),fd)
            self.assertFalse(os.get_inheritable(fd))
        with self.assertRaises(OSError):os.fstat(fd)
        with self.assertRaises(scratch.PdfBoundedScratchError):scratch.active_mountinfo_fd()

    def test_borrowed_metadata_scope_preserves_borrowed_descriptor(self):
        """Never close a caller-owned descriptor when leaving a temporary scope."""
        fd=os.open('/proc/self/mountinfo',os.O_RDONLY|os.O_CLOEXEC)
        try:
            with scratch.mountinfo_scope(fd):
                self.assertEqual(scratch.active_mountinfo_fd(),fd)
            os.fstat(fd)
        finally:os.close(fd)

    def test_nested_scope_is_refused_and_outer_remains_valid(self):
        """Prevent a nested metadata scope from substituting another observation."""
        with scratch.mountinfo_scope() as fd:
            with self.assertRaises(scratch.PdfBoundedScratchError):
                with scratch.mountinfo_scope():pass
            self.assertEqual(scratch.active_mountinfo_fd(),fd)

    def test_regular_file_pipe_and_memfd_cannot_forge_mountinfo(self):
        """Only a real read-only procfs file can supply mount mapping bytes."""
        with tempfile.TemporaryFile() as ordinary:
            pipe=os.pipe();mem=os.memfd_create('metadata-negative',os.MFD_CLOEXEC)
            try:
                for fd in (ordinary.fileno(),*pipe,mem):
                    with self.subTest(fd=fd),self.assertRaises(scratch.PdfBoundedScratchError):
                        with scratch.mountinfo_scope(fd):pass
            finally:
                os.close(pipe[0]);os.close(pipe[1]);os.close(mem)

    def test_scope_rejects_low_fds_and_path_only_proc_descriptors(self):
        """Do not accept stdio or an unreadable O_PATH handle as metadata."""
        fd=os.open('/proc/self/mountinfo',os.O_PATH|os.O_CLOEXEC)
        try:
            for value in (0,1,2,-1,True,fd):
                with self.subTest(value=value),self.assertRaises(scratch.PdfBoundedScratchError):
                    with scratch.mountinfo_scope(value):pass
        finally:os.close(fd)

    def test_metadata_pread_does_not_advance_shared_offset(self):
        """Repeated metadata queries do not consume another process's shared cursor."""
        with scratch.mountinfo_scope() as fd:
            os.lseek(fd,7,os.SEEK_SET)
            first=scratch._read_kernel_text(Path('/proc/self/mountinfo'),262144)
            second=scratch._read_kernel_text(Path('/proc/self/mountinfo'),262144)
            self.assertEqual(first,second)
            self.assertEqual(os.lseek(fd,0,os.SEEK_CUR),7)
            with self.assertRaises(scratch.PdfBoundedScratchError):
                scratch._read_kernel_text(Path('/proc/self/mountinfo'),8)

    def test_closed_borrowed_metadata_never_falls_back_to_proc_path(self):
        """A lost retained handle remains an error, not an ambient-path fallback."""
        fd=os.open('/proc/self/mountinfo',os.O_RDONLY|os.O_CLOEXEC)
        with scratch.mountinfo_scope(fd):
            os.close(fd)
            with self.assertRaises(scratch.PdfBoundedScratchError):
                scratch._read_kernel_text(Path('/proc/self/mountinfo'),262144)

    def test_wrong_proc_record_cannot_satisfy_exact_mount_mapping(self):
        """Kernel proc provenance alone never qualifies an unrelated metadata format."""
        fd=os.open('/proc/self/status',os.O_RDONLY|os.O_CLOEXEC)
        directory=os.open('/run',os.O_PATH|os.O_DIRECTORY)
        try:
            with scratch.mountinfo_scope(fd),self.assertRaises(scratch.PdfBoundedScratchError):
                scratch._mount_record(Path('/run'),os.fstat(directory).st_dev,scratch._fd_mount_id(directory))
        finally:os.close(fd);os.close(directory)


class RasterMetadataBridgeTests(unittest.TestCase):
    """Pass only live kernel metadata, closing it before the native raster exec."""

    def test_bounded_page_passes_only_current_metadata_handle(self):
        """Add no report handles to the direct raster child descriptor allowlist."""
        from reporting import _pdf_raster_window_worker as worker
        from reporting._pdf_raster_launch_budget import RasterLaunchBudget
        from types import SimpleNamespace
        budget = RasterLaunchBudget((1,))
        budget.consume_probe()
        self.addCleanup(budget.close)
        with patch.dict(os.environ, {"OMNIGENIS_PDF_BOUNDED_SCRATCH_V1": "1"}), \
             scratch.mountinfo_scope() as fd, \
             patch.object(worker.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
            worker._raster_page('/usr/bin/pdftoppm', Path('/tmp/candidate.pdf'), Path('/tmp/page-1'), 1,
                                launch_budget=budget)
            self.assertEqual(run.call_args.kwargs.get('pass_fds'), (fd,))
            self.assertEqual(run.call_args.args[0][-1], str(fd))
            self.assertTrue(run.call_args.kwargs['close_fds'])

    def test_bounded_page_without_metadata_fails_before_launch(self):
        """Never attempt an ambient proc fallback from an already confined parent."""
        from reporting import _pdf_raster_window_worker as worker
        from reporting._pdf_raster_launch_budget import RasterLaunchBudget
        budget = RasterLaunchBudget((1,))
        budget.consume_probe()
        self.addCleanup(budget.close)
        with patch.dict(os.environ, {"OMNIGENIS_PDF_BOUNDED_SCRATCH_V1": "1"}), \
             patch.object(worker.subprocess, 'run') as run:
            with self.assertRaises(scratch.PdfBoundedScratchError):
                worker._raster_page('/usr/bin/pdftoppm', Path('/tmp/candidate.pdf'), Path('/tmp/page-1'), 1,
                                    launch_budget=budget)
            run.assert_not_called()

    def test_bounded_executor_refuses_missing_metadata_before_lifetime(self):
        """Require the narrow extra argument only for the bounded scratch route."""
        from reporting import _pdf_raster_executor as worker
        args=['worker',str(os.getpid()),'/usr/bin/pdftoppm','/tmp/candidate.pdf','/tmp/page-1','1']
        with patch.dict(os.environ, {"OMNIGENIS_PDF_BOUNDED_SCRATCH_V1": "1"}), \
             patch.object(worker,'_arm_lifetime') as lifetime:
            self.assertEqual(worker.main(args),64)
            lifetime.assert_not_called()

    def test_closed_metadata_returns_silent_failure_without_cleanup_exception(self):
        """A missing inherited capability cannot escape the fixed failure contract."""
        from reporting import _pdf_raster_executor as worker
        fd=os.open('/proc/self/mountinfo',os.O_RDONLY|os.O_CLOEXEC)
        os.close(fd)
        args=['worker',str(os.getpid()),'/usr/bin/pdftoppm','/tmp/candidate.pdf','/tmp/page-1','1',str(fd)]
        with patch.dict(os.environ, {"OMNIGENIS_PDF_BOUNDED_SCRATCH_V1": "1"}), \
             patch.object(worker,'_arm_lifetime'),patch.object(worker,'_limits'), \
             patch.object(worker,'_bind_scratch') as bind:
            self.assertEqual(worker.main(args),70)
            bind.assert_not_called()

    def test_borrowed_metadata_is_closed_before_native_binary_open(self):
        """Keep the proc capability out of both the native version check and raster exec."""
        from reporting import _pdf_raster_executor as worker
        fd=os.open('/proc/self/mountinfo',os.O_RDONLY|os.O_CLOEXEC)
        directory=os.open('/tmp',os.O_PATH|os.O_DIRECTORY|os.O_CLOEXEC)
        args=['worker',str(os.getpid()),'/usr/bin/pdftoppm','/tmp/candidate.pdf','/tmp/page-1','1',str(fd)]
        observed=[]
        def before_binary(tool):
            """Stop before native execution after proving the capability was dropped."""
            with self.assertRaises(OSError):os.fstat(fd)
            observed.append(True)
            raise ValueError('stop after descriptor closure')
        try:
            with patch.dict(os.environ, {"OMNIGENIS_PDF_BOUNDED_SCRATCH_V1": "1"}), \
                 patch.object(worker,'_arm_lifetime'), patch.object(worker,'_limits'), \
                 patch.object(worker,'_bind_scratch', return_value=(Path('/tmp'),directory)), \
                 patch.object(worker,'enforce_pdf_landlock'),patch.object(worker,'enforce_pdf_network_filter'), \
                 patch.object(worker,'_open_executable',side_effect=before_binary):
                self.assertEqual(worker.main(args),70)
                self.assertEqual(observed,[True])
        finally:
            for item in (fd,directory):
                try:os.close(item)
                except OSError:pass


if __name__=='__main__':
    unittest.main(verbosity=2)
