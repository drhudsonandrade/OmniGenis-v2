"""Synthetic POSIX checkpoint persistence, failure and identity regressions."""
from __future__ import annotations

import ast
from dataclasses import asdict, replace
import hashlib
import importlib
import importlib.util
import json
import os
import socket
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from reporting.page_checkpoints import PageCheckpointError, PageWindowCheckpoint
from reporting.page_windows import plan_pdf_page_windows, WindowObservation


class CheckpointFileTests(unittest.TestCase):
    def setUp(self):
        """Create one synthetic private job directory and an existing partial codec."""
        self.assertIsNotNone(importlib.util.find_spec('reporting.checkpoint_files'),
                             'checkpoint file persistence is missing')
        self.m = importlib.import_module('reporting.checkpoint_files')
        self.temp = tempfile.TemporaryDirectory(prefix='checkpoint-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        self.plan_args = dict(pdf_sha256='a' * 64, ir_sha256='b' * 64, page_count=33,
                              admitted_page_budget=300, pages_per_window=16,
                              inspector_profile_id='synthetic-inspection-v1')
        self.plan = plan_pdf_page_windows(**self.plan_args)
        observations = tuple(WindowObservation(
            index=w.index, first_page=w.first_page, last_page=w.last_page,
            pdf_sha256=self.plan.pdf_sha256, plan_sha256=self.plan.plan_sha256,
            inspector_profile_id=self.plan.inspector_profile_id,
            observation_sha256=hashlib.sha256(f'window:{w.index}'.encode()).hexdigest(),
        ) for w in self.plan.windows)
        self.observations = observations
        self.cp = PageWindowCheckpoint(self.plan, 'synthetic-namespace', 'synthetic-job',
                                       'c' * 64, 'd' * 64, observations[:1])
        st = os.fstat(self.fd)
        self.directory = self.m.CheckpointDirectoryIdentity(
            st.st_dev, st.st_ino, st.st_uid, self.cp.namespace_id, self.cp.job_id,
            self.cp.request_sha256, self.cp.resource_profile_sha256)
        self.digest = self.cp.checkpoint_sha256

    def store(self, **changes):
        """Call the scoped writer with independently expected synthetic arguments."""
        values = dict(directory_fd=self.fd, expected_directory=self.directory,
                      checkpoint=self.cp, expected_checkpoint_sha256=self.digest)
        values.update(changes)
        return self.m.store_page_checkpoint(**values)

    def load(self, **changes):
        """Call the strict reader with the exact existing plan and pinned digest."""
        values = dict(directory_fd=self.fd, expected_directory=self.directory,
                      expected_plan=self.plan, expected_checkpoint_sha256=self.digest)
        values.update(changes)
        return self.m.load_page_checkpoint(**values)

    def seed(self, raw, mode=0o400, name=None):
        """Install a deliberately controlled or hostile test-owned fixture."""
        path = self.root / (self.digest if name is None else name)
        path.write_bytes(raw)
        path.chmod(mode)
        return path

    def child(self, action):
        """Run a disposable process against only the test-owned borrowed descriptor."""
        code = '''import json,os,sys
from unittest.mock import patch
from reporting.checkpoint_files import CheckpointDirectoryIdentity,store_page_checkpoint,load_page_checkpoint
from reporting.page_windows import plan_pdf_page_windows
from reporting.page_checkpoints import resume_page_checkpoint
d=json.load(sys.stdin);root=CheckpointDirectoryIdentity(**d['directory']);plan=plan_pdf_page_windows(**d['plan'])
args=dict(directory_fd=d['fd'],expected_directory=root,expected_checkpoint_sha256=d['digest'])
if d['action']=='read':
 c=load_page_checkpoint(**args,expected_plan=plan);print(c.checkpoint_sha256)
else:
 c=resume_page_checkpoint(checkpoint_bytes=d['checkpoint'].encode(),expected_checkpoint_sha256=d['digest'],expected_plan=plan,namespace_id=root.namespace_id,job_id=root.job_id,expected_request_sha256=root.request_sha256,expected_resource_profile_sha256=root.resource_profile_sha256)
 original_link=os.link
 def stop_at_link(*a,**k):
  if d['action']=='crash-after':
   original_link(*a,**k);os._exit(42)
  os._exit(41)
 with patch('reporting.checkpoint_files.os.link',side_effect=stop_at_link):
  store_page_checkpoint(**args,checkpoint=c)
'''
        data = dict(action=action, fd=self.fd, directory=asdict(self.directory),
                    plan=self.plan_args, digest=self.digest, checkpoint=self.cp.to_bytes().decode())
        return subprocess.run([sys.executable, '-c', code], input=json.dumps(data),
                              text=True, capture_output=True, pass_fds=(self.fd,), timeout=10)

    def test_roundtrip_preserves_exact_canonical_bytes(self):
        """A real file roundtrip returns the original strict checkpoint and bytes."""
        self.assertEqual(self.store(), self.digest)
        self.assertEqual(self.load().to_bytes(), self.cp.to_bytes())
        self.assertEqual((self.root / self.digest).read_bytes(), self.cp.to_bytes())

    def test_final_file_is_single_link_and_owner_read_only(self):
        """Only the content-addressed private final object survives normal publication."""
        self.store()
        self.assertEqual(os.listdir(self.root), [self.digest])
        st = (self.root / self.digest).stat()
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o400)
        self.assertEqual(st.st_nlink, 1)
        self.assertEqual(st.st_uid, os.geteuid())

    def test_fresh_process_can_reopen_persisted_checkpoint(self):
        """Persisted bytes survive the original codec instance and process boundary."""
        self.store()
        result = self.child('read')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), self.digest)

    def test_idempotent_retry_does_not_replace_existing_inode(self):
        """An identical object is verified rather than rewritten or replaced."""
        self.store()
        inode = (self.root / self.digest).stat().st_ino
        with patch.object(self.m.os, 'write', side_effect=AssertionError('unexpected rewrite')):
            self.assertEqual(self.store(), self.digest)
        self.assertEqual((self.root / self.digest).stat().st_ino, inode)

    def test_progress_gets_new_digest_without_replacing_history(self):
        """Appending a prefix creates another object without overwriting prior progress."""
        self.store()
        newer = self.cp.append_observations(self.observations[1:2])
        self.store(checkpoint=newer, expected_checkpoint_sha256=newer.checkpoint_sha256)
        self.assertEqual(len(os.listdir(self.root)), 2)
        self.assertEqual(self.load().to_bytes(), self.cp.to_bytes())
        self.assertEqual(self.load(expected_checkpoint_sha256=newer.checkpoint_sha256).to_bytes(), newer.to_bytes())

    def test_existing_conflicting_bytes_are_not_repaired_or_overwritten(self):
        """A corrupt digest entry causes rejection and remains untouched for recovery."""
        target = self.seed(b'invalid-checkpoint')
        before = target.stat()
        with self.assertRaises(self.m.CheckpointFileError):
            self.store()
        self.assertEqual(target.read_bytes(), b'invalid-checkpoint')
        self.assertEqual(target.stat().st_ino, before.st_ino)

    def test_missing_expected_digest_never_falls_back_to_other_file(self):
        """The reader does not scan for a latest or similarly named checkpoint."""
        self.store()
        with self.assertRaises(self.m.CheckpointFileError):
            self.load(expected_checkpoint_sha256='e' * 64)

    def test_wrong_expected_digest_is_rejected_before_creation(self):
        """A caller cannot publish a checkpoint under a foreign expected digest."""
        with self.assertRaises(self.m.CheckpointFileError):
            self.store(expected_checkpoint_sha256='e' * 64)
        self.assertEqual(os.listdir(self.root), [])

    def test_malformed_digest_inputs_fail_before_io(self):
        """Paths, uppercase digests and truth-like values never become filenames."""
        for value in ('../checkpoint', '/absolute', 'A' * 64, '', True, None):
            with self.subTest(value=value), patch.object(self.m.os, 'dup', side_effect=AssertionError('I/O')):
                with self.assertRaises(self.m.CheckpointFileError):
                    self.store(expected_checkpoint_sha256=value)

    def test_invalid_directory_descriptor_types_are_rejected(self):
        """Borrowed descriptors are bounded native integers, not coerced values."""
        for value in (True, -1, '3', 2 ** 32, None):
            with self.subTest(value=value), self.assertRaises(self.m.CheckpointFileError):
                self.store(directory_fd=value)

    def test_closed_directory_descriptor_is_content_free(self):
        """A closed borrowed handle yields a fixed domain failure without OS detail."""
        fd = os.dup(self.fd)
        os.close(fd)
        with self.assertRaises(self.m.CheckpointFileError):
            self.store(directory_fd=fd)

    def test_wrong_directory_inode_is_rejected_without_writing(self):
        """A valid directory handle cannot substitute for the independently pinned root."""
        other = replace(self.directory, inode_id=self.directory.inode_id + 1)
        with self.assertRaises(self.m.CheckpointFileError):
            self.store(expected_directory=other)
        self.assertEqual(os.listdir(self.root), [])

    def test_directory_binding_requires_exact_type_and_integer_identity(self):
        """Dictionaries and bool-like filesystem identities cannot impersonate a pin."""
        with self.assertRaises(self.m.CheckpointFileError):
            self.store(expected_directory=asdict(self.directory))
        for key in ('device_id', 'inode_id', 'owner_uid'):
            with self.subTest(key=key), self.assertRaises(self.m.CheckpointFileError):
                replace(self.directory, **{key: True})

    def test_directory_must_be_owner_private(self):
        """Group access, world access and special directory bits are not admitted."""
        for mode in (0o750, 0o770, 0o777, 0o1700):
            self.root.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(self.m.CheckpointFileError):
                self.store()
        self.root.chmod(0o700)

    def test_foreign_job_context_is_rejected_before_write(self):
        """Exact namespace, job, request and resource bindings are required for writes."""
        for key, value in (('namespace_id', 'other-namespace'), ('job_id', 'other-job'),
                           ('request_sha256', 'e' * 64), ('resource_profile_sha256', 'f' * 64)):
            other = replace(self.directory, **{key: value})
            with self.subTest(key=key), self.assertRaises(self.m.CheckpointFileError):
                self.store(expected_directory=other)
        self.assertEqual(os.listdir(self.root), [])

    def test_foreign_job_or_plan_cannot_read_matching_bytes(self):
        """Equal on-disk bytes do not remove independent job and plan expectations."""
        self.store()
        with self.assertRaises(self.m.CheckpointFileError):
            self.load(expected_directory=replace(self.directory, job_id='other-job'))
        altered = plan_pdf_page_windows(**{**self.plan_args, 'pdf_sha256': 'f' * 64})
        with self.assertRaises(self.m.CheckpointFileError):
            self.load(expected_plan=altered)

    def test_checkpoint_and_plan_types_are_strict(self):
        """No duck-typed source object or plan can reach filesystem processing."""
        with self.assertRaises(self.m.CheckpointFileError):
            self.store(checkpoint=self.cp.to_dict())
        with self.assertRaises(self.m.CheckpointFileError):
            self.load(expected_plan={})

    def test_symlink_entry_is_never_followed(self):
        """A digest-shaped symlink cannot redirect checkpoint reads or writes."""
        target = self.seed(self.cp.to_bytes(), name='unrelated')
        (self.root / self.digest).symlink_to(target)
        for call in (self.store, self.load):
            with self.assertRaises(self.m.CheckpointFileError):
                call()
        self.assertEqual(target.read_bytes(), self.cp.to_bytes())

    def test_hardlink_entry_is_rejected(self):
        """Externally aliased final entries are not accepted as sealed checkpoint files."""
        target = self.seed(self.cp.to_bytes(), name='aliased')
        os.link(target, self.root / self.digest)
        with self.assertRaises(self.m.CheckpointFileError):
            self.load()

    def test_fifo_entry_fails_without_blocking(self):
        """Nonblocking no-follow opens reject FIFO metadata before any read."""
        os.mkfifo(self.root / self.digest, 0o600)
        with patch.object(self.m.os, 'read', side_effect=AssertionError('FIFO read')):
            with self.assertRaises(self.m.CheckpointFileError):
                self.load()

    def test_directory_entry_is_rejected(self):
        """A directory named after the expected digest is not a checkpoint file."""
        (self.root / self.digest).mkdir()
        with self.assertRaises(self.m.CheckpointFileError):
            self.store()

    def test_writable_or_shared_final_file_is_rejected(self):
        """An existing final entry needs the exact owner-read-only file mode."""
        target = self.seed(self.cp.to_bytes())
        for mode in (0o600, 0o440, 0o444, 0o500, 0o1400):
            target.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(self.m.CheckpointFileError):
                self.load()

    def test_oversized_file_is_rejected_before_read(self):
        """Existing codec byte admission is enforced from file size before allocation."""
        self.seed(b'x' * (self.m.MAX_CHECKPOINT_BYTES + 1))
        with patch.object(self.m.os, 'read', side_effect=AssertionError('oversized read')):
            with self.assertRaises(self.m.CheckpointFileError):
                self.load()

    def test_empty_or_corrupt_file_is_not_a_checkpoint(self):
        """Neither an empty object nor altered bytes can produce a resumed prefix."""
        target = self.seed(b'')
        with self.assertRaises(self.m.CheckpointFileError):
            self.load()
        target.chmod(0o600)
        target.write_bytes(b'corrupt')
        target.chmod(0o400)
        with self.assertRaises(self.m.CheckpointFileError):
            self.load()

    def test_short_writes_are_completed_with_bounded_chunks(self):
        """Successful partial OS writes do not silently truncate persisted metadata."""
        original = os.write
        def short(fd, data):
            """Write a small positive prefix to simulate a short system write."""
            self.assertLessEqual(len(data), 64 * 1024)
            return original(fd, data[:max(1, min(37, len(data)))])
        with patch.object(self.m.os, 'write', side_effect=short):
            self.store()
        self.assertEqual(self.load().to_bytes(), self.cp.to_bytes())

    def test_zero_write_never_publishes_partial_bytes(self):
        """An OS write making no progress fails and removes only owned scratch."""
        with patch.object(self.m.os, 'write', return_value=0):
            with self.assertRaises(self.m.CheckpointFileError):
                self.store()
        self.assertEqual(os.listdir(self.root), [])

    def test_write_exception_does_not_publish_or_leak_detail(self):
        """A failed write returns a fixed diagnostic with no private exception payload."""
        with patch.object(self.m.os, 'write', side_effect=OSError('SYNTHETIC-IO-DETAIL')):
            with self.assertRaises(self.m.CheckpointFileError) as caught:
                self.store()
        self.assertNotIn('SYNTHETIC-IO-DETAIL', str(caught.exception))
        self.assertEqual(os.listdir(self.root), [])

    def test_file_sync_failure_withholds_publication(self):
        """The final name is absent when syncing staged file contents fails."""
        with patch.object(self.m.os, 'fsync', side_effect=OSError('sync')):
            with self.assertRaises(self.m.CheckpointFileError):
                self.store()
        self.assertEqual(os.listdir(self.root), [])

    def test_directory_sync_failure_is_unacknowledged_then_retryable(self):
        """A complete but unacknowledged object is rechecked on retry without overwrite."""
        original = os.fsync
        def fail_directory(fd):
            """Reject only directory synchronization while allowing file sync."""
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError('directory sync')
            return original(fd)
        with patch.object(self.m.os, 'fsync', side_effect=fail_directory):
            with self.assertRaises(self.m.CheckpointFileError):
                self.store()
        target = self.root / self.digest
        self.assertEqual(target.read_bytes(), self.cp.to_bytes())
        inode = target.stat().st_ino
        self.assertEqual(self.store(), self.digest)
        self.assertEqual(target.stat().st_ino, inode)

    def test_atomic_publication_does_not_overwrite_a_racing_entry(self):
        """A concurrent conflicting final name cannot be replaced by publication."""
        original = os.link
        def racing(src, dst, **kwargs):
            """Install a conflicting test-owned entry immediately before no-clobber link."""
            self.seed(b'concurrent-conflict')
            return original(src, dst, **kwargs)
        with patch.object(self.m.os, 'link', side_effect=racing):
            with self.assertRaises(self.m.CheckpointFileError):
                self.store()
        self.assertEqual((self.root / self.digest).read_bytes(), b'concurrent-conflict')
        self.assertEqual(os.listdir(self.root), [self.digest])

    def test_link_failure_cleans_only_own_scratch(self):
        """Publication failure preserves unrelated files and removes staged scratch."""
        self.seed(b'keep', name='unrelated')
        with patch.object(self.m.os, 'link', side_effect=OSError('publication')):
            with self.assertRaises(self.m.CheckpointFileError):
                self.store()
        self.assertEqual(os.listdir(self.root), ['unrelated'])

    def test_killed_writer_cannot_publish_a_partial_final_file(self):
        """Process death before linking leaves no directory entry or valid final object."""
        result = self.child('crash')
        self.assertEqual(result.returncode, 41, result.stderr)
        self.assertFalse((self.root / self.digest).exists())
        with self.assertRaises(self.m.CheckpointFileError):
            self.load()
        self.assertEqual(os.listdir(self.root), [])

    def test_killed_writer_after_link_is_loadable_and_retryable(self):
        """Death after publication leaves a single-link object requiring no scratch cleanup."""
        result = self.child('crash-after')
        self.assertEqual(result.returncode, 42, result.stderr)
        target = self.root / self.digest
        self.assertEqual(target.stat().st_nlink, 1)
        self.assertEqual(os.listdir(self.root), [self.digest])
        self.assertEqual(self.load().to_bytes(), self.cp.to_bytes())
        inode = target.stat().st_ino
        self.assertEqual(self.store(), self.digest)
        self.assertEqual(target.stat().st_ino, inode)

    def test_unsupported_anonymous_filesystem_has_no_named_fallback(self):
        """Missing filesystem support rejects the operation rather than creating named scratch."""
        original = os.open
        def unsupported(path, flags, *args, **kwargs):
            """Reject the anonymous-open operation in this synthetic filesystem probe."""
            if flags & os.O_TMPFILE == os.O_TMPFILE:
                raise OSError('synthetic O_TMPFILE unsupported')
            return original(path, flags, *args, **kwargs)
        with patch.object(self.m.os, 'open', side_effect=unsupported):
            with self.assertRaises(self.m.CheckpointFileError):
                self.store()
        self.assertEqual(os.listdir(self.root), [])

    def test_publication_uses_only_its_owned_anonymous_descriptor(self):
        """The only followed link is the kernel self-FD path for this zero-link staging inode."""
        original = os.link
        observed = []
        def inspect_link(src, dst, **kwargs):
            """Inspect the actual publication descriptor before the no-clobber link call."""
            self.assertRegex(src, r'^/proc/self/fd/[0-9]+$')
            fd = int(src.rsplit('/', 1)[1])
            value = os.fstat(fd)
            self.assertEqual(value.st_nlink, 0)
            self.assertEqual(stat.S_IMODE(value.st_mode), 0o400)
            self.assertEqual(os.pread(fd, len(self.cp.to_bytes()) + 1, 0), self.cp.to_bytes())
            self.assertIs(kwargs.get('follow_symlinks'), True)
            self.assertEqual(dst, self.digest)
            self.assertNotIn('src_dir_fd', kwargs)
            observed.append(value.st_ino)
            return original(src, dst, **kwargs)
        with patch.object(self.m.os, 'link', side_effect=inspect_link):
            self.store()
        self.assertEqual(observed, [(self.root / self.digest).stat().st_ino])

    def test_anonymous_publication_never_needs_unlink_cleanup(self):
        """A normal new write never depends on removing a named temporary entry."""
        with patch.object(self.m.os, 'unlink', side_effect=AssertionError('named cleanup')):
            self.assertEqual(self.store(), self.digest)
        self.assertEqual(os.listdir(self.root), [self.digest])

    def test_short_staging_pread_is_completed_without_moving_offset(self):
        """Positive short positional reads reconstruct the entire staged byte sequence."""
        original = os.pread
        counts = []
        def short(fd, size, offset):
            """Limit each real positional read while checking the established chunk cap."""
            self.assertLessEqual(size, 64 * 1024)
            counts.append(size)
            return original(fd, min(size, 23), offset)
        with patch.object(self.m.os, 'pread', side_effect=short):
            self.store()
        self.assertGreater(len(counts), 1)
        self.assertEqual(self.load().to_bytes(), self.cp.to_bytes())

    def test_corrupt_staging_pread_never_publishes(self):
        """Failed anonymous-descriptor readback cannot create the final digest entry."""
        with patch.object(self.m.os, 'pread', side_effect=[b'corrupt', b'']):
            with self.assertRaises(self.m.CheckpointFileError):
                self.store()
        self.assertEqual(os.listdir(self.root), [])

    def test_entry_replacement_during_read_is_rejected(self):
        """A new inode with even equal bytes cannot replace the opened entry unnoticed."""
        self.store()
        original = os.read
        changed = False
        def replace_entry(fd, count):
            """Replace the digest directory entry after its first read."""
            nonlocal changed
            raw = original(fd, count)
            if not changed:
                changed = True
                (self.root / self.digest).rename(self.root / 'previous')
                self.seed(self.cp.to_bytes())
            return raw
        with patch.object(self.m.os, 'read', side_effect=replace_entry):
            with self.assertRaises(self.m.CheckpointFileError):
                self.load()

    def test_directory_permission_change_is_rejected(self):
        """Changing the pinned directory policy during writing cannot yield success."""
        original = os.write
        def change_mode(fd, data):
            """Alter the test-owned directory mode while a staged write occurs."""
            n = original(fd, data)
            self.root.chmod(0o770)
            return n
        with patch.object(self.m.os, 'write', side_effect=change_mode):
            with self.assertRaises(self.m.CheckpointFileError):
                self.store()
        self.root.chmod(0o700)

    def test_caller_descriptor_is_never_closed(self):
        """Success and rejection both preserve the borrowed directory descriptor."""
        before = os.fstat(self.fd)
        self.store()
        self.load()
        with self.assertRaises(self.m.CheckpointFileError):
            self.load(expected_checkpoint_sha256='f' * 64)
        self.assertEqual(os.fstat(self.fd).st_ino, before.st_ino)

    def test_repeated_failure_does_not_leak_descriptors(self):
        """Owned file and root handles are closed after repeated failed writes."""
        before = len(os.listdir('/proc/self/fd'))
        for _ in range(8):
            with patch.object(self.m.os, 'write', side_effect=OSError('write')):
                with self.assertRaises(self.m.CheckpointFileError):
                    self.store()
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_unsupported_profile_fails_before_io(self):
        """Unavailable POSIX features cannot fall back to weaker path handling."""
        with patch.object(self.m, '_SUPPORTED', False), patch.object(self.m.os, 'dup', side_effect=AssertionError('I/O')):
            with self.assertRaises(self.m.CheckpointFileError):
                self.store()

    def test_no_directory_scan_network_or_process_is_used(self):
        """Production persistence only uses the borrowed root and digest basename."""
        with patch.object(self.m.os, 'listdir', side_effect=AssertionError('scan')), patch.object(self.m.os, 'scandir', side_effect=AssertionError('scan')), patch.object(socket, 'create_connection', side_effect=AssertionError('network')), patch.object(subprocess, 'Popen', side_effect=AssertionError('process')):
            self.store()
            self.assertEqual(self.load().checkpoint_sha256, self.digest)

    def test_partial_storage_does_not_claim_native_or_release_completion(self):
        """Persisting an incomplete prefix changes no scientific or execution guarantees."""
        self.store()
        restored = self.load()
        with self.assertRaises(PageCheckpointError):
            restored.as_complete_ledger()
        record = restored.to_dict()
        self.assertFalse(record['native_resume_performed'])
        self.assertFalse(record['checkpoint_storage_authenticated'])
        self.assertEqual(record['release_authorization'], 'NOT_ESTABLISHED')

    def test_final_readback_detects_change_during_directory_sync(self):
        """A changed final entry at the last sync barrier cannot receive acknowledgment."""
        original = os.fsync
        def alter_at_barrier(fd):
            """Alter only the synthetic final object when its parent is synchronized."""
            result = original(fd)
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                target = self.root / self.digest
                target.chmod(0o600)
                target.write_bytes(b'changed-at-sync')
                target.chmod(0o400)
            return result
        with patch.object(self.m.os, 'fsync', side_effect=alter_at_barrier):
            with self.assertRaises(self.m.CheckpointFileError):
                self.store()

    def test_maximum_window_checkpoint_roundtrip_is_chunk_bounded(self):
        """Existing maximum metadata plans persist completely with bounded read/write calls."""
        plan = plan_pdf_page_windows(**{**self.plan_args, 'page_count': 32768,
                                        'admitted_page_budget': 32768, 'pages_per_window': 32})
        obs = tuple(WindowObservation(w.index, w.first_page, w.last_page, plan.pdf_sha256,
                                      plan.plan_sha256, plan.inspector_profile_id, 'e' * 64)
                    for w in plan.windows)
        cp = replace(self.cp, plan=plan, observations=obs)
        self.assertGreater(len(cp.to_bytes()), 64 * 1024)
        old_write, old_read = os.write, os.read
        sizes = []
        def bounded_write(fd, raw):
            """Record real bounded system writes for the large synthetic checkpoint."""
            sizes.append(len(raw))
            return old_write(fd, raw)
        def bounded_read(fd, size):
            """Assert that each real read stays within one fixed metadata chunk."""
            self.assertLessEqual(size, 64 * 1024)
            return old_read(fd, size)
        with patch.object(self.m.os, 'write', side_effect=bounded_write), patch.object(self.m.os, 'read', side_effect=bounded_read):
            self.store(checkpoint=cp, expected_checkpoint_sha256=cp.checkpoint_sha256)
            loaded = self.load(expected_plan=plan, expected_checkpoint_sha256=cp.checkpoint_sha256)
        self.assertEqual(loaded.to_bytes(), cp.to_bytes())
        self.assertGreater(len(sizes), 1)
        self.assertLessEqual(max(sizes), 64 * 1024)

    def test_all_changed_functions_have_docstrings(self):
        """The storage API and all test functions document their exact boundaries."""
        root = Path(__file__).resolve().parents[1]
        for name in ('reporting/checkpoint_files.py', 'tests/test_reporting_checkpoint_files.py'):
            tree = ast.parse((root / name).read_text())
            missing = [node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not ast.get_docstring(node)]
            self.assertEqual(missing, [], name)


if __name__ == '__main__':
    unittest.main()
