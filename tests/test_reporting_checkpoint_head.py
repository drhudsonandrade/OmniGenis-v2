"""Synthetic filesystem and process tests for exact checkpoint head advancement."""
from __future__ import annotations

import ast
from dataclasses import asdict, replace
import errno
import fcntl
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from reporting.checkpoint_files import CheckpointDirectoryIdentity, store_page_checkpoint
from reporting.page_checkpoints import PageWindowCheckpoint
from reporting.page_windows import WindowObservation, plan_pdf_page_windows

ROOT = Path(__file__).resolve().parents[1]
HEAD_NAME = 'checkpoint-head-v1'


def make_checkpoint(count=0, marker='synthetic', page_count=33):
    """Build a declared synthetic prefix without claiming PDF execution."""
    plan = plan_pdf_page_windows(pdf_sha256='a' * 64, ir_sha256='b' * 64,
        page_count=page_count, admitted_page_budget=page_count, pages_per_window=16,
        inspector_profile_id='synthetic-inspection-v1')
    observations = tuple(WindowObservation(index=w.index, first_page=w.first_page,
        last_page=w.last_page, pdf_sha256=plan.pdf_sha256, plan_sha256=plan.plan_sha256,
        inspector_profile_id=plan.inspector_profile_id,
        observation_sha256=hashlib.sha256(f'{marker}:{w.index}'.encode()).hexdigest())
        for w in plan.windows[:count])
    return PageWindowCheckpoint(plan=plan, namespace_id='synthetic-namespace',
        job_id='synthetic-job', request_sha256='c' * 64,
        resource_profile_sha256='d' * 64, observations=observations)


class CheckpointHeadTests(unittest.TestCase):
    def setUp(self):
        """Require the implementation and allocate only a disposable private root."""
        self.assertIsNotNone(importlib.util.find_spec('reporting.checkpoint_head'),
                             'checkpoint head coordination is missing')
        self.m = importlib.import_module('reporting.checkpoint_head')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        st = os.fstat(self.fd)
        self.identity = CheckpointDirectoryIdentity(device_id=st.st_dev,
            inode_id=st.st_ino, owner_uid=st.st_uid, namespace_id='synthetic-namespace',
            job_id='synthetic-job', request_sha256='c' * 64,
            resource_profile_sha256='d' * 64)
        self.zero = make_checkpoint()
        self.one = make_checkpoint(1)
        self.two = make_checkpoint(2)

    def advance(self, checkpoint=None, previous=None, **changes):
        """Invoke only the opt-in coordinator with independently supplied expectations."""
        checkpoint = self.zero if checkpoint is None else checkpoint
        args = dict(directory_fd=self.fd, expected_directory=self.identity,
                    checkpoint=checkpoint, expected_checkpoint_sha256=checkpoint.checkpoint_sha256,
                    expected_previous_checkpoint_sha256=previous)
        args.update(changes)
        return self.m.advance_checkpoint_head(**args)

    def load(self, checkpoint=None, **changes):
        """Read only an independently expected current checkpoint, never discover latest."""
        checkpoint = self.zero if checkpoint is None else checkpoint
        args = dict(directory_fd=self.fd, expected_directory=self.identity,
                    expected_plan=checkpoint.plan,
                    expected_checkpoint_sha256=checkpoint.checkpoint_sha256)
        args.update(changes)
        return self.m.load_current_checkpoint(**args)

    def head(self):
        """Inspect the fixture's exact fixed-size current digest record."""
        return (self.root / HEAD_NAME).read_bytes()

    def initialize(self):
        """Publish an empty prefix as the only admitted first checkpoint."""
        self.assertEqual(self.advance(), self.zero.checkpoint_sha256)

    def corrupt_head(self, raw):
        """Mutate synthetic head bytes without granting production mutation authority."""
        p = self.root / HEAD_NAME
        p.chmod(0o600)
        p.write_bytes(raw)
        p.chmod(0o400)

    def child(self, code, *args):
        """Run bounded subprocess probes with only this test's directory descriptor."""
        return subprocess.run([sys.executable, '-B', '-c', code, str(self.fd),
            json.dumps(asdict(self.identity)), *args], pass_fds=(self.fd,), cwd=ROOT,
            capture_output=True, text=True, timeout=15)

    def test_initialize_and_exact_current_roundtrip(self):
        """Initialization persists one immutable object and a private current reference."""
        self.initialize()
        self.assertEqual(self.head(), self.zero.checkpoint_sha256.encode())
        self.assertEqual(self.load().to_bytes(), self.zero.to_bytes())
        st = (self.root / HEAD_NAME).stat()
        self.assertEqual((stat.S_IMODE(st.st_mode), st.st_nlink, st.st_size), (0o400, 1, 64))

    def test_progress_retains_every_prior_checkpoint(self):
        """An ordered prefix grows without rewriting any previous content-addressed object."""
        self.initialize()
        original = (self.root / self.zero.checkpoint_sha256).read_bytes()
        self.advance(self.one, self.zero.checkpoint_sha256)
        self.advance(self.two, self.one.checkpoint_sha256)
        self.assertEqual(self.load(self.two).to_bytes(), self.two.to_bytes())
        self.assertEqual((self.root / self.zero.checkpoint_sha256).read_bytes(), original)
        self.assertEqual((self.root / self.one.checkpoint_sha256).read_bytes(), self.one.to_bytes())

    def test_initial_nonempty_prefix_rejected_without_io(self):
        """Existing external progress cannot silently become a newly initialized job."""
        with self.assertRaises(self.m.CheckpointHeadError):
            self.advance(self.one)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_exact_retry_and_already_current_acknowledgment(self):
        """Lost acknowledgment can be retried only toward the same exact current target."""
        self.initialize()
        self.advance(self.one, self.zero.checkpoint_sha256)
        for previous in (self.zero.checkpoint_sha256, self.one.checkpoint_sha256):
            self.assertEqual(self.advance(self.one, previous), self.one.checkpoint_sha256)
        self.assertEqual(self.advance(self.one, self.one.checkpoint_sha256), self.one.checkpoint_sha256)

    def test_stale_writer_cannot_publish_a_different_successor(self):
        """A losing writer cannot replace a current checkpoint using an old predecessor."""
        self.initialize()
        self.advance(self.one, self.zero.checkpoint_sha256)
        before = set(self.root.iterdir())
        with self.assertRaises(self.m.CheckpointHeadError):
            self.advance(make_checkpoint(1, 'other'), self.zero.checkpoint_sha256)
        self.assertEqual(self.head(), self.one.checkpoint_sha256.encode())
        self.assertEqual(set(self.root.iterdir()), before)

    def test_backward_progress_is_rejected(self):
        """The coordinator never selects an earlier prefix as the new current state."""
        self.initialize()
        self.advance(self.two, self.zero.checkpoint_sha256)
        with self.assertRaises(self.m.CheckpointHeadError):
            self.advance(self.one, self.two.checkpoint_sha256)
        self.assertEqual(self.head(), self.two.checkpoint_sha256.encode())

    def test_changed_retained_observation_rejected(self):
        """More records cannot conceal replacement of a previously retained observation."""
        self.initialize()
        self.advance(self.one, self.zero.checkpoint_sha256)
        with self.assertRaises(self.m.CheckpointHeadError):
            self.advance(make_checkpoint(2, 'different'), self.one.checkpoint_sha256)

    def test_current_read_refuses_stale_digest(self):
        """Current selection never falls back to an older valid immutable object."""
        self.initialize()
        self.advance(self.one, self.zero.checkpoint_sha256)
        with self.assertRaises(self.m.CheckpointHeadError):
            self.load(self.zero)

    def test_missing_current_does_not_scan_or_guess(self):
        """An unselected object is not a current head just because it is valid."""
        store_page_checkpoint(directory_fd=self.fd, expected_directory=self.identity,
                              checkpoint=self.zero, expected_checkpoint_sha256=self.zero.checkpoint_sha256)
        with patch.object(os, 'listdir', side_effect=AssertionError('scan')):
            with self.assertRaises(self.m.CheckpointHeadError):
                self.load()

    def test_missing_expected_predecessor_is_not_initialization(self):
        """A missing current record cannot satisfy a supplied prior digest."""
        with self.assertRaises(self.m.CheckpointHeadError):
            self.advance(self.one, self.zero.checkpoint_sha256)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_invalid_digest_types_fail_before_io(self):
        """Paths, uppercase hashes, booleans and malformed digest hints are rejected."""
        for value in ('../other', 'A' * 64, True, '', 3, 'a' * 63):
            with self.subTest(value=value), self.assertRaises(self.m.CheckpointHeadError):
                self.advance(expected_previous_checkpoint_sha256=value)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_wrong_source_digest_has_no_side_effects(self):
        """A real checkpoint cannot be published under a different desired digest."""
        with self.assertRaises(self.m.CheckpointHeadError):
            self.advance(expected_checkpoint_sha256='e' * 64)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_cross_context_is_rejected(self):
        """Namespace, job, request and resource expectations must all bind the stored job."""
        self.initialize()
        for change in ({'namespace_id':'other'}, {'job_id':'other'},
                       {'request_sha256':'e' * 64}, {'resource_profile_sha256':'f' * 64}):
            with self.subTest(change=change), self.assertRaises(self.m.CheckpointHeadError):
                self.load(expected_directory=replace(self.identity, **change))

    def test_changed_plan_rejected(self):
        """A different PDF or plan cannot take over an existing checkpoint chain."""
        self.initialize()
        for changed in (replace(self.zero.plan, pdf_sha256='f' * 64),
                        replace(self.zero.plan, ir_sha256='e' * 64)):
            with self.assertRaises(self.m.CheckpointHeadError):
                self.load(expected_plan=changed)

    def test_unsafe_directory_and_native_types_rejected(self):
        """Wrong roots, shared permissions and arbitrary descriptor objects fail closed."""
        for changes in ({'directory_fd':True}, {'expected_directory':{}},
                        {'expected_directory':replace(self.identity, inode_id=self.identity.inode_id + 1)}):
            with self.assertRaises(self.m.CheckpointHeadError):
                self.advance(**changes)
        self.root.chmod(0o755)
        with self.assertRaises(self.m.CheckpointHeadError):
            self.advance()
        self.root.chmod(0o700)

    def test_symlink_head_is_rejected_not_replaced(self):
        """The fixed head name cannot redirect reads or be silently overwritten."""
        target = self.root / 'unrelated'
        target.write_bytes(b'unchanged')
        (self.root / HEAD_NAME).symlink_to(target)
        with self.assertRaises(self.m.CheckpointHeadError):
            self.advance()
        self.assertEqual(target.read_bytes(), b'unchanged')
        self.assertTrue((self.root / HEAD_NAME).is_symlink())

    def test_head_modes_links_size_and_bytes_are_strict(self):
        """Shared, malformed, oversized and externally aliased pointers are invalid."""
        self.initialize()
        for raw in (b'', b'x' * 64, b'a' * 65, b'a' * (1024 * 1024 + 1), b'A' * 64):
            self.corrupt_head(raw)
            with self.assertRaises(self.m.CheckpointHeadError):
                self.load()
        self.corrupt_head(self.zero.checkpoint_sha256.encode())
        (self.root / HEAD_NAME).chmod(0o600)
        with self.assertRaises(self.m.CheckpointHeadError):
            self.load()
        (self.root / HEAD_NAME).chmod(0o400)
        os.link(self.root / HEAD_NAME, self.root / 'extra-link')
        with self.assertRaises(self.m.CheckpointHeadError):
            self.load()

    def test_fifo_head_never_blocks(self):
        """A special-file pointer fails before any blocking read."""
        os.mkfifo(self.root / HEAD_NAME, 0o400)
        with self.assertRaises(self.m.CheckpointHeadError):
            self.advance()

    def test_in_process_conflict_does_not_share_callers_lock_description(self):
        """Independent open descriptions contend even with the same borrowed descriptor."""
        fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            with self.assertRaisesRegex(self.m.CheckpointHeadError, 'busy'):
                self.advance()
            second = os.open('.', os.O_RDONLY | os.O_DIRECTORY, dir_fd=self.fd)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(second, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(second)
        finally:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
        self.initialize()

    def test_independent_process_observes_lock_contention(self):
        """A second interpreter cannot enter a directory already exclusively locked."""
        fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            result = self.child("""import sys,json
from reporting.checkpoint_files import CheckpointDirectoryIdentity
from reporting.checkpoint_head import advance_checkpoint_head,CheckpointHeadError
from tests.test_reporting_checkpoint_head import make_checkpoint
c=make_checkpoint()
try: advance_checkpoint_head(directory_fd=int(sys.argv[1]),expected_directory=CheckpointDirectoryIdentity(**json.loads(sys.argv[2])),checkpoint=c,expected_checkpoint_sha256=c.checkpoint_sha256,expected_previous_checkpoint_sha256=None)
except CheckpointHeadError as e: sys.exit(17 if 'busy' in str(e) else 18)
sys.exit(19)
""")
            self.assertEqual(result.returncode, 17, result.stderr)
        finally:
            fcntl.flock(self.fd, fcntl.LOCK_UN)

    def test_process_death_before_replace_preserves_old_head_and_retries(self):
        """An interrupted staged pointer is not current and exact retry reconciles it."""
        self.crash_at_replace(after=False)

    def test_process_death_after_replace_allows_exact_recovery(self):
        """After atomic replacement, process death cannot retain the cooperative lock."""
        self.crash_at_replace(after=True)

    def crash_at_replace(self, *, after):
        """Kill only a disposable child at the precise replacement boundary."""
        self.initialize()
        result = self.child("""import sys,json,os
from unittest.mock import patch
from reporting.checkpoint_files import CheckpointDirectoryIdentity
from reporting.checkpoint_head import advance_checkpoint_head
from tests.test_reporting_checkpoint_head import make_checkpoint
real=os.replace
def die(*a,**k):
 if sys.argv[3]=='after': real(*a,**k)
 os._exit(42)
c=make_checkpoint(1)
with patch('os.replace',side_effect=die):
 advance_checkpoint_head(directory_fd=int(sys.argv[1]),expected_directory=CheckpointDirectoryIdentity(**json.loads(sys.argv[2])),checkpoint=c,expected_checkpoint_sha256=c.checkpoint_sha256,expected_previous_checkpoint_sha256=make_checkpoint().checkpoint_sha256)
""", 'after' if after else 'before')
        self.assertEqual(result.returncode, 42, result.stderr)
        expected = self.one if after else self.zero
        self.assertEqual(self.load(expected).to_bytes(), expected.to_bytes())
        self.assertEqual(self.advance(self.one, self.zero.checkpoint_sha256), self.one.checkpoint_sha256)
        self.assertEqual(self.load(self.one).to_bytes(), self.one.to_bytes())

    def test_two_processes_cannot_publish_conflicting_successors(self):
        """Only one competing successor is current; the other is busy or stale."""
        self.initialize()
        code = """import sys,json
from reporting.checkpoint_files import CheckpointDirectoryIdentity
from reporting.checkpoint_head import advance_checkpoint_head,CheckpointHeadError
from tests.test_reporting_checkpoint_head import make_checkpoint
c=make_checkpoint(1,sys.argv[3])
try: advance_checkpoint_head(directory_fd=int(sys.argv[1]),expected_directory=CheckpointDirectoryIdentity(**json.loads(sys.argv[2])),checkpoint=c,expected_checkpoint_sha256=c.checkpoint_sha256,expected_previous_checkpoint_sha256=make_checkpoint().checkpoint_sha256)
except CheckpointHeadError: sys.exit(17)
"""
        children = [subprocess.Popen([sys.executable,'-B','-c',code,str(self.fd),
            json.dumps(asdict(self.identity)),marker], pass_fds=(self.fd,),cwd=ROOT,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for marker in ('one','two')]
        try:
            outputs = [p.communicate(timeout=15) for p in children]
            self.assertEqual(sorted(p.returncode for p in children), [0,17], outputs)
            winner = next(marker for marker,p in zip(('one','two'),children,strict=True) if p.returncode == 0)
            self.assertEqual(self.load(make_checkpoint(1,winner)).to_bytes(), make_checkpoint(1,winner).to_bytes())
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)

    def test_replace_failure_preserves_current_and_exact_retry(self):
        """A failed rename never turns staged metadata into acknowledged current state."""
        self.initialize()
        with patch.object(os,'replace',side_effect=OSError('private-detail')):
            with self.assertRaises(self.m.CheckpointHeadError) as error:
                self.advance(self.one,self.zero.checkpoint_sha256)
        self.assertNotIn('private-detail',str(error.exception))
        self.assertEqual(self.head(),self.zero.checkpoint_sha256.encode())
        self.advance(self.one,self.zero.checkpoint_sha256)

    def test_directory_sync_failure_is_unacknowledged_and_retryable(self):
        """A post-replace durability error is explicit even when the desired head exists."""
        self.initialize()
        real = os.fsync
        def fail_after_replace(fd):
            """Fail the synthetic final directory sync, not the immutable object sync."""
            if stat.S_ISDIR(os.fstat(fd).st_mode) and self.head() == self.one.checkpoint_sha256.encode():
                raise OSError('private-sync-detail')
            return real(fd)
        with patch.object(os,'fsync',side_effect=fail_after_replace):
            with self.assertRaises(self.m.CheckpointHeadError):
                self.advance(self.one,self.zero.checkpoint_sha256)
        self.assertEqual(self.advance(self.one,self.zero.checkpoint_sha256),self.one.checkpoint_sha256)

    def test_final_readback_detects_pointer_change(self):
        """An observed change at the last sync cannot receive a successful acknowledgment."""
        self.initialize()
        real = os.fsync
        def change(fd):
            """Tamper only with this fixture's head after the desired replacement."""
            result = real(fd)
            if stat.S_ISDIR(os.fstat(fd).st_mode) and self.head() == self.one.checkpoint_sha256.encode():
                self.corrupt_head(self.zero.checkpoint_sha256.encode())
            return result
        with patch.object(os,'fsync',side_effect=change):
            with self.assertRaises(self.m.CheckpointHeadError):
                self.advance(self.one,self.zero.checkpoint_sha256)

    def test_missing_or_corrupt_current_object_is_not_replaced(self):
        """A pointer cannot authorize progress when its referenced checkpoint is invalid."""
        self.initialize()
        p=self.root/self.zero.checkpoint_sha256
        p.chmod(0o600);p.write_bytes(b'not-a-checkpoint');p.chmod(0o400)
        with self.assertRaises(self.m.CheckpointHeadError):
            self.advance(self.one,self.zero.checkpoint_sha256)
        self.assertFalse((self.root/self.one.checkpoint_sha256).exists())

    def test_borrowed_descriptor_and_unrelated_files_survive(self):
        """The wrapper neither closes the caller's handle nor removes unrelated data."""
        other=self.root/'unrelated';other.write_bytes(b'keep')
        self.initialize();self.advance(self.one,self.zero.checkpoint_sha256)
        self.assertEqual(other.read_bytes(),b'keep')
        self.assertTrue(stat.S_ISDIR(os.fstat(self.fd).st_mode))

    def test_repeated_calls_and_failures_do_not_leak_descriptors(self):
        """Every newly owned directory description closes after success and rejection."""
        self.initialize()
        before=len(os.listdir('/proc/self/fd'))
        for _ in range(20):
            self.load()
            with self.assertRaises(self.m.CheckpointHeadError):
                self.load(expected_checkpoint_sha256='e'*64)
        self.assertEqual(len(os.listdir('/proc/self/fd')),before)

    def test_no_scans_or_network_or_worker_activation(self):
        """A head operation composes local exact storage without discovery or execution."""
        with patch.object(os,'listdir',side_effect=AssertionError('scan')):
            self.initialize()
            result=self.load()
        self.assertIs(result.to_dict()['native_resume_performed'],False)
        self.assertEqual(result.to_dict()['release_authorization'],'NOT_ESTABLISHED')

    def test_unsupported_profile_has_no_io_fallback(self):
        """Unavailable locking support rejects before creating any checkpoint or pointer."""
        with patch.object(self.m,'_SUPPORTED',False):
            with self.assertRaises(self.m.CheckpointHeadError):
                self.advance()
        self.assertEqual(list(self.root.iterdir()),[])

    def test_unexpected_lock_error_is_fixed_and_closes_owned_fd(self):
        """Non-contention lock failure remains failure without leaking system details."""
        before=len(os.listdir('/proc/self/fd'))
        with patch.object(fcntl,'flock',side_effect=OSError(errno.EIO,'private-lock-detail')):
            with self.assertRaises(self.m.CheckpointHeadError) as error:
                self.advance()
        self.assertNotIn('private-lock-detail',str(error.exception))
        self.assertEqual(len(os.listdir('/proc/self/fd')),before)

    def test_large_declared_prefix_remains_complete_but_unqualified(self):
        """The same coordinator handles all 300 declared pages without executing a PDF."""
        zero=make_checkpoint(0,page_count=300);done=make_checkpoint(19,page_count=300)
        self.advance(zero)
        self.advance(done,zero.checkpoint_sha256)
        loaded=self.load(done)
        self.assertEqual(loaded.as_complete_ledger().to_dict()['page_count'],300)
        self.assertIs(loaded.to_dict()['whole_pdf_safety_qualified'],False)

    def test_every_changed_function_has_a_docstring(self):
        """Keep the two added modules documented without changing existing source files."""
        for relative in ('reporting/checkpoint_head.py','tests/test_reporting_checkpoint_head.py'):
            tree=ast.parse((ROOT/relative).read_text())
            missing=[n.name for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and not ast.get_docstring(n)]
            self.assertEqual(missing,[],relative)


if __name__ == '__main__':
    unittest.main()
