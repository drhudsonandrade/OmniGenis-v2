"""A private candidate and its manifest commit together without release authority."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from hashlib import sha256
import importlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import select
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from reporting import pdf_generated_source_job as generated
from reporting import _pdf_job_durable_receipt as receipts
from tests import test_reporting_pdf_generated_source_job as fixtures

MODE = 'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE'
DISABLE = 'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED'


class CandidateStoreTests(unittest.TestCase):
    """Use genuine generated results; mocks inject failures, never accepted output."""

    results = {}

    def setUp(self):
        """Fail at the missing operation before launching any rendering fixture."""
        self.assertIsNotNone(importlib.util.find_spec('reporting.pdf_candidate_store'),
                             'private candidate storage API missing')
        self.m = importlib.import_module('reporting.pdf_candidate_store')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.run_id = 'a' * 32
        self.env = patch.dict(os.environ, {MODE: 'qualification-only'})
        self.env.start()
        self.addCleanup(self.env.stop)
        os.environ.pop(DISABLE, None)
        self.helper = fixtures.GeneratedSourceJobTests()
        self.helper.setUp()

    def candidate(self, count=2):
        """Cache only an actual generated-and-inspected sealed result."""
        if count not in type(self).results:
            arguments = self.helper.arguments(fixtures.source(count))
            type(self).results[count] = generated.execute_pdf_generated_source_job(**arguments)
        return type(self).results[count]

    def arguments(self, count=2, **changes):
        """Provide expectations independently at both storage and recovery boundaries."""
        result = self.candidate(count)
        return {'directory': self.root, 'run_id': self.run_id,
                'expected_result_sha256': result.result_sha256,
                'expected_pdf_sha256': result.pdf_sha256,
                'namespace_id': result.namespace_id, 'job_id': result.job_id,
                'request_sha256': result.request_sha256,
                'expected_ir_sha256': result.ir_sha256,
                'expected_resource_profile_sha256': result.resource_profile_sha256, **changes}

    def persist(self, count=2, **changes):
        """Pass the real sealed result rather than a receipt or user QA Boolean."""
        return self.m.persist_qualification_pdf_candidate(candidate=self.candidate(count),
                                                          **self.arguments(count, **changes))

    def recover(self, count=2, **changes):
        """Read without calling any generator or native inspector."""
        return self.m.read_qualification_pdf_candidate(**self.arguments(count, **changes))

    def directory(self):
        """Locate only this fixture's explicitly owned run."""
        return self.root / self.run_id

    def snapshot(self):
        """Compare bytes, identity and write times, not access-time side effects."""
        found = {}
        for path in self.root.rglob('*'):
            s = path.lstat()
            found[str(path.relative_to(self.root))] = (
                s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_mtime_ns, s.st_ctime_ns,
                path.read_bytes() if stat.S_ISREG(s.st_mode) else None)
        return found

    def test_actual_short_candidate_roundtrip_is_exact_and_private(self):
        """Store the actual PDF, full result metadata and existing exact receipt."""
        result = self.candidate()
        manifest = self.persist()
        pdf, recovered = self.recover()
        self.assertEqual(pdf, result.pdf_bytes)
        self.assertEqual(manifest, recovered)
        self.assertEqual(manifest['result'], result.to_dict())
        self.assertEqual(manifest['result_sha256'], result.result_sha256)
        self.assertEqual(manifest['pdf_sha256'], result.pdf_sha256)
        self.assertEqual(manifest['pdf_bytes'], len(pdf))
        self.assertEqual(manifest['state'], 'STORED_PRIVATE_CANDIDATE')
        self.assertIs(manifest['release_authorized'], False)
        self.assertIs(manifest['supported_execution'], False)
        self.assertIs(manifest['default_pipeline_activated'], False)
        self.assertEqual(set(p.name for p in self.directory().iterdir()),
                         {'candidate.pdf', 'manifest.json', self.run_id + '.json'})
        for p in self.directory().iterdir():
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
            self.assertEqual(p.stat().st_nlink, 1)
        self.assertEqual(stat.S_IMODE(self.directory().stat().st_mode), 0o700)
        self.assertEqual(receipts.read_job_receipt(self.directory(), self.run_id,
                         'SUCCEEDED', result.result_sha256)['release_authorized'], False)

    def test_actual_long_candidate_recovers_all_original_bytes(self):
        """A real generated document beyond 32 pages is stored without truncation."""
        result = self.candidate(1200)
        self.assertGreater(result.page_count, 32)
        self.persist(1200)
        pdf, manifest = self.recover(1200)
        self.assertEqual(pdf, result.pdf_bytes)
        self.assertEqual(manifest['result'], result.to_dict())
        self.assertEqual(manifest['page_count'], result.page_count)
        self.assertFalse(manifest['result']['aggregate_job_resources_qualified'])

    def test_default_disabled_refuses_before_storage(self):
        """No write takes place without explicit qualification opt-in."""
        args = self.arguments()
        os.environ.pop(MODE)
        with self.assertRaises(self.m.PdfCandidateStoreError):
            self.m.persist_qualification_pdf_candidate(candidate=self.candidate(), **args)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_explicit_disable_and_unknown_mode_refuse(self):
        """Unsupported configuration is not treated as a weaker valid mode."""
        for mode, disable in [('production', None), ('qualification-only', '1'),
                              ('qualification-only', 'true')]:
            with self.subTest(mode=mode, disable=disable), patch.dict(os.environ):
                os.environ[MODE] = mode
                if disable is None:
                    os.environ.pop(DISABLE, None)
                else:
                    os.environ[DISABLE] = disable
                with self.assertRaises(self.m.PdfCandidateStoreError): self.persist()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_wrong_expectations_cannot_create_storage(self):
        """Reject foreign result, PDF, IR, request, context and resource profile."""
        for key, value in [('expected_result_sha256', '0'*64), ('expected_pdf_sha256', '1'*64),
                           ('expected_ir_sha256', '2'*64), ('request_sha256', '3'*64),
                           ('namespace_id', 'foreign-namespace'), ('job_id', 'foreign-job'),
                           ('expected_resource_profile_sha256', '4'*64)]:
            with self.subTest(key=key), self.assertRaises(self.m.PdfCandidateStoreError):
                self.persist(**{key: value})
            self.assertEqual(list(self.root.iterdir()), [])

    def test_invalid_candidate_type_refuses_without_writes(self):
        """A caller's success-shaped dictionary is never accepted as a candidate."""
        for candidate in (None, {}, self.candidate().to_dict(), True):
            with self.assertRaises(self.m.PdfCandidateStoreError):
                self.m.persist_qualification_pdf_candidate(candidate=candidate, **self.arguments())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_invalid_run_ids_and_directory_types_refuse(self):
        """No path traversal, implicit string conversion or caller filenames."""
        for change in ({'run_id': '../escape'}, {'run_id': True}, {'run_id': 'A'*32},
                       {'directory': str(self.root)}, {'directory': Path('relative')},
                       {'directory': self.root/'..'/self.root.name}):
            with self.subTest(change=change), self.assertRaises(self.m.PdfCandidateStoreError):
                self.persist(**change)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_nonprivate_root_refuses(self):
        """A directory readable by other accounts is not an accepted store."""
        self.root.chmod(0o755)
        with self.assertRaises(self.m.PdfCandidateStoreError): self.persist()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_symlink_root_and_ancestor_refuse(self):
        """Walk existing owner-bound ancestors without following symbolic links."""
        real = self.root/'real'; real.mkdir(mode=0o700)
        leaf = real/'leaf'; leaf.mkdir(mode=0o700)
        alias = self.root/'alias'; alias.symlink_to(real, target_is_directory=True)
        for directory in (alias, alias/'leaf'):
            with self.assertRaises(self.m.PdfCandidateStoreError): self.persist(directory=directory)
        self.assertEqual(list(leaf.iterdir()), [])

    def test_unknown_existing_attempt_is_preserved_and_refused(self):
        """A partial attempt never becomes a retry or overwrite opportunity."""
        self.directory().mkdir(mode=0o700)
        sentinel = self.directory()/'unknown'; sentinel.write_bytes(b'preserve')
        before = self.snapshot()
        with self.assertRaises(self.m.PdfCandidateStoreError): self.persist()
        self.assertEqual(self.snapshot(), before)

    def test_existing_run_symlink_refused(self):
        """An existing linked run cannot redirect any data writes."""
        real = self.root/'other'; real.mkdir(mode=0o700)
        self.directory().symlink_to(real, target_is_directory=True)
        with self.assertRaises(self.m.PdfCandidateStoreError): self.persist()
        self.assertEqual(list(real.iterdir()), [])

    def test_completed_identical_store_is_idempotent_and_read_only(self):
        """An exact committed attempt is returned without rewriting or regenerating."""
        first = self.persist(); before = self.snapshot()
        with patch.object(self.m, '_write_data', side_effect=AssertionError('write')):
            second = self.persist()
        self.assertEqual(first, second)
        self.assertEqual(self.snapshot(), before)

    def test_foreign_existing_candidate_is_not_overwritten(self):
        """The same run ID cannot be rebound to different independent expectations."""
        self.persist(); before = self.snapshot()
        with self.assertRaises(self.m.PdfCandidateStoreError):
            self.persist(namespace_id='foreign')
        self.assertEqual(self.snapshot(), before)

    def test_missing_commit_is_not_readable_and_cannot_be_repaired(self):
        """Data files alone never establish completion."""
        self.persist(); (self.directory()/(self.run_id+'.json')).unlink()
        before = self.snapshot()
        with self.assertRaises(self.m.PdfCandidateStoreError): self.recover()
        with self.assertRaises(self.m.PdfCandidateStoreError): self.persist()
        self.assertEqual(self.snapshot(), before)

    def test_missing_pdf_is_not_recovered(self):
        """A valid receipt cannot substitute for absent PDF bytes."""
        self.persist(); (self.directory()/'candidate.pdf').unlink()
        with self.assertRaises(self.m.PdfCandidateStoreError): self.recover()

    def test_missing_manifest_is_not_recovered(self):
        """PDF and receipt without the complete QA/context manifest are refused."""
        self.persist(); (self.directory()/'manifest.json').unlink()
        with self.assertRaises(self.m.PdfCandidateStoreError): self.recover()

    def test_tampered_pdf_refused(self):
        """A same-size byte mutation cannot retain the original PDF identity."""
        self.persist(); p = self.directory()/'candidate.pdf'; data=p.read_bytes()
        p.write_bytes(data[:-1]+bytes([data[-1]^1]))
        with self.assertRaises(self.m.PdfCandidateStoreError): self.recover()

    def test_tampered_result_metadata_refused(self):
        """A resealed-looking manifest cannot change the independently expected result."""
        self.persist(); p=self.directory()/'manifest.json'; value=json.loads(p.read_bytes())
        value['result']['namespace_id']='foreign'
        p.write_bytes(self.m._canonical(value))
        with self.assertRaises(self.m.PdfCandidateStoreError): self.recover()

    def test_manifest_unknown_fields_and_release_promotion_refused(self):
        """Stored metadata cannot silently broaden qualification or release scope."""
        self.persist(); p=self.directory()/'manifest.json'; original=p.read_bytes()
        for key,value in [('unexpected',True),('release_authorized',True),
                          ('supported_execution',True),('page_count',True)]:
            document=json.loads(original);document[key]=value;p.write_bytes(self.m._canonical(document))
            with self.subTest(key=key),self.assertRaises(self.m.PdfCandidateStoreError):self.recover()
        p.write_bytes(original)

    def test_noncanonical_and_duplicate_manifest_keys_refused(self):
        """Canonical exact encoding excludes duplicate-key and whitespace ambiguity."""
        self.persist();p=self.directory()/'manifest.json';original=p.read_bytes()
        for raw in (b' '+original, b'{"state":"FAKE",'+original[1:], b'{"x":NaN}'):
            p.write_bytes(raw)
            with self.assertRaises(self.m.PdfCandidateStoreError):self.recover()
        p.write_bytes(original)

    def test_oversized_or_empty_files_refused(self):
        """Read limits are finite before loading bytes into memory."""
        self.persist()
        for name,limit in [('candidate.pdf',self.m.MAX_PDF_BYTES),('manifest.json',self.m.MAX_MANIFEST_BYTES)]:
            p=self.directory()/name;original=p.read_bytes()
            for size in (0,limit+1):
                with p.open('wb') as f:f.truncate(size)
                with self.assertRaises(self.m.PdfCandidateStoreError):self.recover()
            p.write_bytes(original)

    def test_symlink_data_file_refused(self):
        """Readback never follows a link even when the target bytes are correct."""
        self.persist();p=self.directory()/'candidate.pdf';other=self.root/'other.pdf';p.rename(other);p.symlink_to(other)
        with self.assertRaises(self.m.PdfCandidateStoreError):self.recover()

    def test_hardlinked_data_file_refused(self):
        """An alias makes an otherwise matching private file ineligible."""
        self.persist();os.link(self.directory()/'candidate.pdf',self.root/'alias.pdf')
        with self.assertRaises(self.m.PdfCandidateStoreError):self.recover()

    def test_fifo_and_directory_data_paths_refused(self):
        """Special files are rejected before blocking reads."""
        self.persist();p=self.directory()/'candidate.pdf';p.unlink();os.mkfifo(p,0o600)
        with self.assertRaises(self.m.PdfCandidateStoreError):self.recover()
        p.unlink();p.mkdir(mode=0o700)
        with self.assertRaises(self.m.PdfCandidateStoreError):self.recover()

    def test_nonprivate_data_and_run_permissions_refused(self):
        """Changing either file or run permissions invalidates recovery."""
        self.persist();p=self.directory()/'candidate.pdf';p.chmod(0o644)
        with self.assertRaises(self.m.PdfCandidateStoreError):self.recover()
        p.chmod(0o600);self.directory().chmod(0o755)
        with self.assertRaises(self.m.PdfCandidateStoreError):self.recover()

    def test_extra_files_and_foreign_commit_refused(self):
        """Closed directory contents exclude unaccounted staged or foreign records."""
        self.persist();p=self.directory()/'extra';p.write_bytes(b'x')
        with self.assertRaises(self.m.PdfCandidateStoreError):self.recover()
        p.unlink();commit=self.directory()/(self.run_id+'.json')
        commit.write_bytes(receipts._receipt_bytes(self.run_id,'SUCCEEDED','0'*64))
        with self.assertRaises(self.m.PdfCandidateStoreError):self.recover()

    def test_commit_is_last_and_requires_both_synced_data_files(self):
        """The existing receipt writer is invoked only after complete exact data."""
        real=receipts.write_job_receipt;checked=[]
        def inspect(directory,run_id,state,digest):
            """Verify complete synced data before invoking the real commit-marker writer."""
            self.assertEqual(set(p.name for p in directory.iterdir()),{'candidate.pdf','manifest.json'})
            self.assertEqual((directory/'candidate.pdf').read_bytes(),self.candidate().pdf_bytes)
            with self.assertRaises(self.m.PdfCandidateStoreError):self.recover()
            checked.append(True)
            return real(directory,run_id,state,digest)
        with patch.object(receipts,'write_job_receipt',side_effect=inspect):self.persist()
        self.assertEqual(checked,[True])

    def test_data_sync_failure_never_commits(self):
        """A failed file sync leaves inspectable but unreadable partial evidence."""
        real=os.fsync
        def fail_file(fd):
            """Fail regular-file synchronization while preserving real directory syncs."""
            if stat.S_ISREG(os.fstat(fd).st_mode):raise OSError('synthetic sync failure')
            return real(fd)
        with patch.object(os,'fsync',side_effect=fail_file),self.assertRaises(self.m.PdfCandidateStoreError):self.persist()
        self.assertFalse((self.directory()/(self.run_id+'.json')).exists())
        with self.assertRaises(self.m.PdfCandidateStoreError):self.recover()

    def test_partial_data_write_and_zero_progress_refuse(self):
        """Short writes are assembled; zero progress is never mistaken for completion."""
        real=os.write;calls=[]
        def short(fd,data):
            """Force short progress through the real filesystem write operation."""
            calls.append(len(data));return real(fd,data[:7])
        with patch.object(os,'write',side_effect=short):self.persist()
        self.assertGreater(len(calls),2)
        self.assertEqual(self.recover()[0],self.candidate().pdf_bytes)
        with patch.object(os,'write',return_value=0),self.assertRaises(self.m.PdfCandidateStoreError):
            self.persist(run_id='b'*32)
        self.assertFalse((self.root/('b'*32)/(('b'*32)+'.json')).exists())

    def test_commit_failure_preserves_unaccepted_data(self):
        """Failure of the existing receipt writer is not hidden by valid PDF bytes."""
        with patch.object(receipts,'write_job_receipt',side_effect=OSError('commit')):
            with self.assertRaises(self.m.PdfCandidateStoreError):self.persist()
        self.assertTrue((self.directory()/'candidate.pdf').exists())
        with self.assertRaises(self.m.PdfCandidateStoreError):self.recover()

    def test_postcommit_interrupt_preserves_recoverable_bundle(self):
        """An interrupted return does not erase a genuinely committed candidate."""
        real=receipts.write_job_receipt
        def interrupt(*args,**kwargs):
            """Commit the real receipt before interrupting the public return path."""
            real(*args,**kwargs);raise KeyboardInterrupt()
        with patch.object(receipts,'write_job_receipt',side_effect=interrupt),self.assertRaises(KeyboardInterrupt):self.persist()
        self.assertEqual(self.recover()[0],self.candidate().pdf_bytes)

    def test_disable_after_commit_refuses_return_without_deletion(self):
        """A late policy change refuses exposure but preserves committed evidence."""
        real=receipts.write_job_receipt
        def disable(*args,**kwargs):
            """Disable qualification immediately after the real receipt is committed."""
            value=real(*args,**kwargs);os.environ[DISABLE]='1';return value
        with patch.object(receipts,'write_job_receipt',side_effect=disable),self.assertRaises(self.m.PdfCandidateStoreError):self.persist()
        os.environ.pop(DISABLE)
        self.assertEqual(self.recover()[0],self.candidate().pdf_bytes)

    def test_changed_candidate_during_commit_refuses_return(self):
        """Recheck the in-memory sealed result after I/O; do not silently accept drift."""
        result=self.candidate();old=result.namespace_id;real=receipts.write_job_receipt
        def mutate(*args,**kwargs):
            """Alter the sealed candidate only after the real commit completes."""
            value=real(*args,**kwargs);object.__setattr__(result,'namespace_id','changed');return value
        try:
            with patch.object(receipts,'write_job_receipt',side_effect=mutate),self.assertRaises(self.m.PdfCandidateStoreError):self.persist()
        finally:object.__setattr__(result,'namespace_id',old)

    def test_changed_file_during_read_refuses(self):
        """A descriptor read and final named-file identity must describe the same bytes."""
        self.persist();p=self.directory()/'candidate.pdf';target=p.stat().st_ino;real=os.read;changed=[]
        def mutate(fd,n):
            """Change the exact open PDF after its first read to test stability checks."""
            value=real(fd,n)
            if not changed and os.fstat(fd).st_ino==target:
                changed.append(True);p.write_bytes(p.read_bytes()+b'x')
            return value
        with patch.object(os,'read',side_effect=mutate),self.assertRaises(self.m.PdfCandidateStoreError):self.recover()
        self.assertTrue(changed)

    def test_replaced_run_directory_refuses(self):
        """A captured descriptor cannot authorize returning through a replaced path."""
        self.persist();real=self.m._read_data;changed=[]
        def replace(*args,**kwargs):
            """Move the owned run after a real read to exercise named-path binding."""
            value=real(*args,**kwargs)
            if not changed:
                changed.append(True);self.directory().rename(self.root/'displaced');self.directory().mkdir(mode=0o700)
            return value
        with patch.object(self.m,'_read_data',side_effect=replace),self.assertRaises(self.m.PdfCandidateStoreError):self.recover()

    def test_returned_manifest_is_detached(self):
        """Caller edits cannot change persisted metadata or subsequent reads."""
        original=self.persist();returned=self.recover()[1];returned['result']['namespace_id']='changed'
        self.assertEqual(self.recover()[1],original)

    def test_recovery_does_not_write_or_launch_generation(self):
        """Exact recovery is read-only and does not need a live result instance."""
        self.persist();args=self.arguments();before=self.snapshot()
        with patch.object(generated,'execute_pdf_generated_source_job',side_effect=AssertionError('generation')),\
             patch.object(receipts,'write_job_receipt',side_effect=AssertionError('receipt')),\
             patch.object(self.m,'_write_data',side_effect=AssertionError('write')):
            pdf,_=self.m.read_qualification_pdf_candidate(**args)
        self.assertEqual(pdf,self.candidate().pdf_bytes);self.assertEqual(self.snapshot(),before)

    def test_fresh_process_recovery_needs_only_exact_expectations(self):
        """A new interpreter returns original bytes without reconstructing generation."""
        self.persist();args=self.arguments();args['directory']=str(args['directory'])
        script='''import json,sys\nfrom pathlib import Path\nsys.path.insert(0,sys.argv[1])\nfrom reporting.pdf_candidate_store import read_qualification_pdf_candidate\nfrom reporting import pdf_generated_source_job as g\ndef forbidden(**kwargs):raise AssertionError('regeneration')\ng.execute_pdf_generated_source_job=forbidden\na=json.loads(sys.stdin.read());a['directory']=Path(a['directory'])\npdf,m=read_qualification_pdf_candidate(**a)\nfrom hashlib import sha256\nprint(json.dumps({'pdf_sha256':sha256(pdf).hexdigest(),'release_authorized':m['release_authorized']}))\n'''
        done=subprocess.run([sys.executable,'-I','-B','-c',script,str(Path(__file__).resolve().parents[1])],
                            input=json.dumps(args),text=True,capture_output=True,timeout=20)
        self.assertEqual(done.returncode,0,done.stderr)
        self.assertEqual(json.loads(done.stdout),{'pdf_sha256':self.candidate().pdf_sha256,'release_authorized':False})

    def test_concurrent_same_attempt_never_overwrites(self):
        """One exclusive run wins; a loser may read the exact completed bundle only."""
        candidate=self.candidate();args=self.arguments()
        def call():
            """Attempt exact persistence while preserving an explicit admission refusal."""
            try:return self.m.persist_qualification_pdf_candidate(candidate=candidate,**args)
            except self.m.PdfCandidateStoreError:return None
        with ThreadPoolExecutor(max_workers=2) as pool:values=list(pool.map(lambda _:call(),range(2)))
        self.assertTrue(any(v is not None for v in values))
        self.assertEqual(self.recover()[0],candidate.pdf_bytes)
        self.assertEqual(set(p.name for p in self.directory().iterdir()),{'candidate.pdf','manifest.json',self.run_id+'.json'})

    def test_same_bytes_file_replacement_between_reads_is_refused(self):
        """Matching content does not excuse a changed named file inside one read."""
        self.persist(); real=self.m._read_data; changed=[]
        def replace(fd,name,limit):
            """Replace the named PDF with identical bytes after the actual first read."""
            value=real(fd,name,limit)
            if name=='candidate.pdf' and not changed:
                changed.append(True)
                p=self.directory()/name;raw=p.read_bytes();p.rename(self.root/'original.pdf')
                p.write_bytes(raw);p.chmod(0o600)
            return value
        with patch.object(self.m,'_read_data',side_effect=replace),self.assertRaises(self.m.PdfCandidateStoreError):
            self.recover()
        self.assertTrue(changed)

    def test_same_bytes_commit_replacement_between_reads_is_refused(self):
        """The transaction marker identity must remain stable across the bundle read."""
        self.persist();real=self.m._read_data;changed=[]
        def replace(*args,**kwargs):
            """Replace the commit marker with identical bytes during bundle recovery."""
            value=real(*args,**kwargs)
            if not changed:
                changed.append(True);p=self.directory()/(self.run_id+'.json');raw=p.read_bytes()
                p.rename(self.root/'original.json');p.write_bytes(raw);p.chmod(0o600)
            return value
        with patch.object(self.m,'_read_data',side_effect=replace),self.assertRaises(self.m.PdfCandidateStoreError):
            self.recover()

    def test_disable_during_recovery_refuses_without_writes(self):
        """A policy change during readback cannot leak an otherwise matching bundle."""
        self.persist();before=self.snapshot();real=self.m._read_data
        def disable(*args,**kwargs):
            """Change policy after an actual data read, without rewriting stored files."""
            value=real(*args,**kwargs);os.environ[DISABLE]='1';return value
        with patch.object(self.m,'_read_data',side_effect=disable),self.assertRaises(self.m.PdfCandidateStoreError):
            self.recover()
        self.assertEqual(self.snapshot(),before)

    def test_readback_wrong_context_and_digest_are_refused(self):
        """Read-only recovery retains each independently expected job binding."""
        self.persist();before=self.snapshot()
        for key,value in [('namespace_id','foreign'),('job_id','foreign'),
                          ('request_sha256','0'*64),('expected_result_sha256','1'*64),
                          ('expected_pdf_sha256','2'*64),('expected_ir_sha256','3'*64)]:
            with self.subTest(key=key),self.assertRaises(self.m.PdfCandidateStoreError):
                self.recover(**{key:value})
        self.assertEqual(self.snapshot(),before)

    def test_valid_commit_does_not_allow_manifest_size_or_count_change(self):
        """The manifest's PDF size and page count are derived, never trusted flags."""
        self.persist();p=self.directory()/'manifest.json';original=p.read_bytes()
        for key,value in [('pdf_bytes',1),('page_count',64),('run_id','b'*32),('state','FINAL')]:
            row=json.loads(original);row[key]=value;p.write_bytes(self.m._canonical(row))
            with self.subTest(key=key),self.assertRaises(self.m.PdfCandidateStoreError):self.recover()
        p.write_bytes(original)

    def test_recovery_does_not_expose_private_paths_or_data_in_errors(self):
        """A refusal carries only its public code, without underlying exceptions."""
        with self.assertRaises(self.m.PdfCandidateStoreError) as caught:self.recover()
        self.assertEqual(str(caught.exception),'pdf_candidate_store_recovery_refused')
        self.assertIsNone(caught.exception.__cause__)
        self.assertNotIn(str(self.root),str(caught.exception))

    def test_data_directory_sync_failure_has_no_commit(self):
        """Durable data alone does not excuse failure to sync directory entries."""
        real=os.fsync
        def fail(fd):
            """Reject the run-directory sync once both candidate data files exist."""
            if stat.S_ISDIR(os.fstat(fd).st_mode) and set(os.listdir(fd))=={'candidate.pdf','manifest.json'}:
                raise OSError('directory sync')
            return real(fd)
        with patch.object(os,'fsync',side_effect=fail),self.assertRaises(self.m.PdfCandidateStoreError):self.persist()
        self.assertFalse((self.directory()/(self.run_id+'.json')).exists())
        with self.assertRaises(self.m.PdfCandidateStoreError):self.recover()

    def test_committed_corruption_is_never_repaired_on_retry(self):
        """Idempotency permits exact existing bytes, never rewriting damaged data."""
        self.persist();p=self.directory()/'candidate.pdf';p.write_bytes(b'corrupted')
        before=self.snapshot()
        with self.assertRaises(self.m.PdfCandidateStoreError):self.persist()
        self.assertEqual(self.snapshot(),before)

    def interrupt_owned_writer(self, committed):
        """Stop one unreaped fixture child at an observed receipt boundary."""
        candidate=self.candidate();args=self.arguments();r,w=os.pipe();pid=None;held=None;reaped=False
        try:
            pid=os.fork()
            if pid==0:
                try:
                    os.close(r);real=receipts.write_job_receipt
                    def stop(*values,**keywords):
                        """Expose the selected receipt boundary and wait for the owning parent."""
                        if committed:real(*values,**keywords)
                        os.write(w,b'C');os.close(w)
                        while True:signal.pause()
                    with patch.object(receipts,'write_job_receipt',side_effect=stop):
                        self.m.persist_qualification_pdf_candidate(candidate=candidate,**args)
                finally:os._exit(3)
            os.close(w);w=-1;held=os.pidfd_open(pid)
            self.assertTrue(select.select([r],[],[],15)[0],'writer did not reach boundary')
            self.assertEqual(os.read(r,1),b'C')
            self.assertIsNone(os.waitid(os.P_PID,pid,os.WEXITED|os.WNOHANG|os.WNOWAIT))
            signal.pidfd_send_signal(held,signal.SIGKILL,None,0)
            retired,status=os.waitpid(pid,0);reaped=True
            self.assertEqual(retired,pid);self.assertEqual(os.waitstatus_to_exitcode(status),-9)
        finally:
            if pid and pid>0 and not reaped:
                if held is not None:
                    try:signal.pidfd_send_signal(held,signal.SIGKILL,None,0)
                    except ProcessLookupError:pass
                os.waitpid(pid,0)
            for fd in (r,w,held):
                if fd is not None and fd>=0:os.close(fd)

    def test_writer_process_death_after_commit_recovers_original_pdf(self):
        """A real killed writer leaves the committed PDF and manifest recoverable."""
        self.interrupt_owned_writer(True)
        pdf,manifest=self.recover()
        self.assertEqual(pdf,self.candidate().pdf_bytes)
        self.assertEqual(manifest['result'],self.candidate().to_dict())

    def test_writer_process_death_before_commit_remains_unverified(self):
        """A real killed precommit writer leaves data but no accepted completion."""
        self.interrupt_owned_writer(False);before=self.snapshot()
        self.assertTrue((self.directory()/'candidate.pdf').exists())
        self.assertFalse((self.directory()/(self.run_id+'.json')).exists())
        with self.assertRaises(self.m.PdfCandidateStoreError):self.recover()
        with self.assertRaises(self.m.PdfCandidateStoreError):self.persist()
        self.assertEqual(self.snapshot(),before)

    def test_descriptor_balance_for_store_read_and_failure(self):
        """All file and directory handles close on success and refusal."""
        self.candidate();before=len(os.listdir('/proc/self/fd'))
        self.persist();self.recover()
        with self.assertRaises(self.m.PdfCandidateStoreError):self.recover(expected_pdf_sha256='0'*64)
        self.assertEqual(len(os.listdir('/proc/self/fd')),before)


if __name__ == '__main__':
    unittest.main()
