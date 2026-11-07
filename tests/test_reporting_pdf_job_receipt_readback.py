"""Exact private outcome readback without execution or release authority."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from reporting import _pdf_job_durable_receipt as receipt


class ReceiptReadbackTests(unittest.TestCase):
    """Recover only expected, canonical, owner-bound local outcome metadata."""

    def setUp(self):
        """Require the new operation before any fixture filesystem writes."""
        self.assertTrue(callable(getattr(receipt, "read_job_receipt", None)),
                        "exact receipt readback API is missing")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.run_id = "a" * 32
        self.digest = "b" * 64

    def write(self, directory=None):
        """Use the real existing fsynced writer, never a success-shaped mock."""
        return receipt.write_job_receipt(directory or self.root, self.run_id,
                                         "SUCCEEDED", self.digest)

    def read(self, directory=None):
        """Read with independently supplied expected identity and result digest."""
        return receipt.read_job_receipt(directory or self.root, self.run_id,
                                        "SUCCEEDED", self.digest)

    def test_real_success_and_failure_roundtrip(self):
        """Both existing terminal states are read without rewriting their wire."""
        path = self.write()
        self.assertEqual(self.read(), json.loads(path.read_bytes()))
        failed = receipt.write_job_receipt(self.root, "c" * 32, "FAILED", None)
        self.assertEqual(receipt.read_job_receipt(self.root, "c" * 32, "FAILED", None),
                         json.loads(failed.read_bytes()))

    def test_terminal_output_error_does_not_erase_recoverable_receipt(self):
        """A real persisted result remains verifiable after optional console EIO."""
        path = self.write()
        before = path.read_bytes()
        class BrokenOutput:
            def write(self, _text):
                raise OSError("synthetic terminal output failure")
        with self.assertRaises(OSError):
            print("completion", file=BrokenOutput())
        self.assertEqual(self.read()["result_sha256"], self.digest)
        self.assertEqual(path.read_bytes(), before)

    def test_absent_receipt_is_not_success(self):
        """Absence raises rather than returning an inferred successful outcome."""
        with self.assertRaises(FileNotFoundError):
            self.read()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_foreign_run_state_and_digest_are_refused(self):
        """Well-formed metadata from another expectation cannot be accepted."""
        self.write()
        with self.assertRaises(FileNotFoundError):
            receipt.read_job_receipt(self.root, "c" * 32, "SUCCEEDED", self.digest)
        for state, digest in (("FAILED", None), ("SUCCEEDED", "c" * 64)):
            with self.subTest(state=state), self.assertRaises(ValueError):
                receipt.read_job_receipt(self.root, self.run_id, state, digest)

    def test_invalid_expectations_fail_before_directory_open(self):
        """Invalid types, nonterminal states and wrong digests never access a directory."""
        cases = [(None, "FAILED", None), ("../x", "FAILED", None),
                 ("A" * 32, "FAILED", None), (True, "FAILED", None),
                 (self.run_id, "PENDING", None), (self.run_id, True, None),
                 (self.run_id, "SUCCEEDED", None), (self.run_id, "SUCCEEDED", "B" * 64),
                 (self.run_id, "SUCCEEDED", True), (self.run_id, "FAILED", self.digest)]
        with patch.object(receipt, "_open_private_directory", side_effect=AssertionError("opened")):
            for run_id, state, digest in cases:
                with self.subTest(run_id=run_id, state=state), self.assertRaises(ValueError):
                    receipt.read_job_receipt(self.root, run_id, state, digest)

    def test_directory_type_relative_and_parent_paths_refused(self):
        """Only the existing absolute Path-based directory contract is accepted."""
        for directory in (str(self.root), None, Path("relative"), self.root / ".." / self.root.name):
            with self.subTest(directory=directory), self.assertRaises(ValueError):
                receipt.read_job_receipt(directory, self.run_id, "SUCCEEDED", self.digest)

    def test_directory_requires_owner_only_mode(self):
        """A readable but nonprivate receipt directory is not an accepted boundary."""
        self.write()
        self.root.chmod(0o755)
        with self.assertRaises(ValueError):
            self.read()

    def test_group_writable_ancestor_refused(self):
        """A private leaf does not compensate for a writable nonsticky ancestor."""
        parent = self.root / "parent"
        parent.mkdir(mode=0o700)
        leaf = parent / "leaf"
        leaf.mkdir(mode=0o700)
        self.write(leaf)
        parent.chmod(0o770)
        with self.assertRaises(ValueError):
            self.read(leaf)

    def test_symlink_directory_and_ancestor_refused(self):
        """Neither the receipt directory nor an ancestor can be a symbolic link."""
        real = self.root / "real"
        real.mkdir(mode=0o700)
        leaf = real / "leaf"
        leaf.mkdir(mode=0o700)
        self.write(leaf)
        link = self.root / "alias"
        link.symlink_to(real, target_is_directory=True)
        for directory in (link / "leaf", self.root / "direct"):
            if directory.name == "direct":
                directory.symlink_to(leaf, target_is_directory=True)
            with self.subTest(directory=directory), self.assertRaises(OSError):
                self.read(directory)

    def test_symlink_receipt_refused_without_touching_target(self):
        """A canonical-looking target reached through a link remains untrusted."""
        path = self.write()
        raw = path.read_bytes()
        target = path.with_name("saved")
        path.rename(target)
        path.symlink_to(target)
        with self.assertRaises((ValueError, OSError)):
            self.read()
        self.assertEqual(target.read_bytes(), raw)
        self.assertTrue(path.is_symlink())

    def test_hardlinked_receipt_refused(self):
        """An aliased file cannot be treated as a single-use local receipt."""
        path = self.write()
        os.link(path, self.root / "alias")
        with self.assertRaises(ValueError):
            self.read()

    def test_directory_and_fifo_destinations_refused_before_open(self):
        """Special files are rejected without a potentially blocking content open."""
        path = self.root / (self.run_id + ".json")
        real_open = os.open
        def guarded(name, *args, **kwargs):
            if name == path.name:
                raise AssertionError("special file opened")
            return real_open(name, *args, **kwargs)
        for kind in ("directory", "fifo"):
            if kind == "directory":
                path.mkdir()
            else:
                os.mkfifo(path, 0o600)
            try:
                with patch.object(receipt.os, "open", side_effect=guarded), self.assertRaises(ValueError):
                    self.read()
            finally:
                path.rmdir() if kind == "directory" else path.unlink()

    def test_file_permissions_are_exact(self):
        """Only a caller-owned 0600 regular file is admitted."""
        path = self.write()
        for mode in (0o400, 0o644, 0o660, 0o700, 0o1600):
            path.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.read()
        path.chmod(0o600)
        self.assertEqual(self.read()["state"], "SUCCEEDED")

    def test_foreign_file_owner_refused(self):
        """Observed foreign ownership is not accepted even for canonical bytes."""
        path = self.write()
        real_stat = os.stat
        def foreign(name, *args, **kwargs):
            info = real_stat(name, *args, **kwargs)
            if name != path.name:
                return info
            fields = {key: getattr(info, key) for key in
                      ("st_mode", "st_dev", "st_ino", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")}
            return SimpleNamespace(**fields, st_uid=os.geteuid() + 1)
        with patch.object(receipt.os, "stat", side_effect=foreign), self.assertRaises(ValueError):
            self.read()

    def test_noncanonical_duplicate_unknown_and_nonfinite_bytes_refused(self):
        """Only the existing exact closed canonical wire is recoverable."""
        path = self.write()
        original = path.read_bytes()
        value = json.loads(original)
        cases = [original.rstrip(b"\n"), original + b"\n", b" " + original,
                 original.replace(b'"state":"SUCCEEDED"', b'"state":"FAILED","state":"SUCCEEDED"'),
                 json.dumps({**value, "unknown": True}, sort_keys=True, separators=(",", ":")).encode() + b"\n",
                 original.replace(b'"release_authorized":false', b'"release_authorized":true'),
                 original.replace(b'"release_authorized":false', b'"release_authorized":NaN'),
                 original.replace(b'"schema":"pdf-job-durable-receipt/v1"', b'"schema":"unknown"')]
        for raw in cases:
            path.write_bytes(raw)
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.read()

    def test_empty_oversized_and_truncated_bytes_refused(self):
        """Bounded recovery never admits an empty, oversized or partial record."""
        path = self.write()
        original = path.read_bytes()
        for raw in (b"", original[:20], original + b"x" * 600):
            path.write_bytes(raw)
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                self.read()
        self.assertEqual(receipt.MAX_RECEIPT_BYTES, 512)

    def test_returned_metadata_is_detached(self):
        """A caller editing the returned object cannot alter persisted metadata."""
        path = self.write()
        before = path.read_bytes()
        result = self.read()
        result["state"] = "FAILED"
        result["release_authorized"] = True
        self.assertEqual(self.read(), json.loads(before))
        self.assertEqual(path.read_bytes(), before)

    def test_short_reads_are_assembled_with_a_finite_budget(self):
        """A regular file may be read in smaller chunks without losing validation."""
        self.write()
        real_read = os.read
        requests = []
        def short(fd, count):
            requests.append(count)
            return real_read(fd, min(count, 7))
        with patch.object(receipt.os, "read", side_effect=short):
            self.assertEqual(self.read()["result_sha256"], self.digest)
        self.assertGreater(len(requests), 1)
        self.assertTrue(all(0 < count <= 513 for count in requests))

    def assert_descriptors_closed(self, failure=None):
        """Observe descriptor closure directly after success or a read failure."""
        self.write()
        real_open = os.open
        opened = []
        def capture(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            opened.append(fd)
            return fd
        with patch.object(receipt.os, "open", side_effect=capture):
            if failure is None:
                self.read()
            else:
                with patch.object(receipt.os, "read", side_effect=failure):
                    with self.assertRaises(type(failure)) as caught:
                        self.read()
                self.assertIs(caught.exception, failure)
        self.assertTrue(opened)
        for fd in set(opened):
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_success_closes_all_descriptors(self):
        """A successful recovery leaves no live directory or file descriptor."""
        self.assert_descriptors_closed()

    def test_read_error_closes_all_descriptors(self):
        """Read failures propagate after closing every owned descriptor."""
        self.assert_descriptors_closed(OSError("synthetic read failure"))

    def test_read_interrupt_closes_all_descriptors(self):
        """Interrupt identity survives cleanup without leaking descriptors."""
        self.assert_descriptors_closed(KeyboardInterrupt("synthetic interruption"))

    def change_during_read(self, change, directory=None):
        """Inject real filesystem mutation after the first content read."""
        real_read = os.read
        changed = []
        def altered(fd, count):
            raw = real_read(fd, count)
            if not changed:
                changed.append(True)
                change()
            return raw
        with patch.object(receipt.os, "read", side_effect=altered), self.assertRaises((ValueError, OSError)):
            self.read(directory)
        self.assertTrue(changed)

    def test_same_inode_content_mutation_refused(self):
        """Appending after a read invalidates its file-identity observation."""
        path = self.write()
        def append():
            with path.open("ab") as stream:
                stream.write(b"x")
        self.change_during_read(append)

    def test_named_file_replacement_refused(self):
        """Identical canonical bytes on a replacement inode cannot hide a race."""
        path = self.write()
        raw = path.read_bytes()
        def replace():
            path.rename(self.root / "prior")
            path.write_bytes(raw)
            path.chmod(0o600)
        self.change_during_read(replace)

    def test_named_file_symlink_replacement_refused(self):
        """Replacing the name by a link is rejected even when it targets original bytes."""
        path = self.write()
        def replace():
            saved = self.root / "prior"
            path.rename(saved)
            path.symlink_to(saved)
        self.change_during_read(replace)

    def test_receipt_directory_replacement_refused(self):
        """A descriptor into a renamed directory is not the caller's current directory."""
        live = self.root / "live"
        live.mkdir(mode=0o700)
        path = self.write(live)
        raw = path.read_bytes()
        def replace():
            live.rename(self.root / "old")
            live.mkdir(mode=0o700)
            replacement = live / path.name
            replacement.write_bytes(raw)
            replacement.chmod(0o600)
        self.change_during_read(replace, live)

    def test_metadata_permission_change_during_read_refused(self):
        """Changed permission metadata invalidates the same inode's observation."""
        path = self.write()
        self.change_during_read(lambda: path.chmod(0o400))

    def test_readback_performs_no_write_sync_link_or_removal(self):
        """Recovery reads existing metadata; it does not repair, promote or sync it."""
        path = self.write()
        before = path.read_bytes()
        with patch.object(receipt.os, "write", side_effect=AssertionError("write")), \
             patch.object(receipt.os, "fsync", side_effect=AssertionError("sync")), \
             patch.object(receipt.os, "link", side_effect=AssertionError("link")), \
             patch.object(receipt.os, "unlink", side_effect=AssertionError("unlink")):
            result = self.read()
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(set(result), {"schema", "run_id", "state", "result_sha256", "release_authorized"})
        self.assertIs(result["release_authorized"], False)
        with self.assertRaises(FileExistsError):
            self.write()


if __name__ == "__main__":
    unittest.main()
