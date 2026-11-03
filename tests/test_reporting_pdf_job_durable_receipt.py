"""Fail-closed, single-use durable receipt contract for isolated PDF qualification."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from reporting._pdf_job_durable_receipt import write_job_receipt

class DurableJobReceiptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        os.chmod(self.root, 0o700)
        self.run_id = "a" * 32
        self.sha = "b" * 64

    def write(self, **kwargs):
        return write_job_receipt(self.root, self.run_id, "SUCCEEDED", self.sha, **kwargs)

    def test_success_is_canonical_durable_and_not_overwritten(self):
        path = self.write()
        self.assertEqual(path.parent, self.root)
        self.assertEqual(path.name, self.run_id + ".json")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(path.read_bytes()), {"schema": "pdf-job-durable-receipt/v1", "run_id": self.run_id, "state": "SUCCEEDED", "result_sha256": self.sha, "release_authorized": False})
        self.assertEqual(path.read_bytes(), json.dumps(json.loads(path.read_bytes()), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() + b"\n")
        with self.assertRaises(FileExistsError):self.write()
        self.assertEqual(json.loads(path.read_bytes())["state"], "SUCCEEDED")

    def test_failed_refuses_result_hash_and_is_durable(self):
        path = write_job_receipt(self.root, self.run_id, "FAILED", None)
        self.assertIsNone(json.loads(path.read_bytes())["result_sha256"])
        with self.assertRaises(ValueError):write_job_receipt(self.root, "c" * 32, "FAILED", self.sha)

    def test_no_success_without_exact_result_hash(self):
        for value in (None, "", "x" * 64, "B" * 64, True, 0):
            with self.subTest(value=value),self.assertRaises(ValueError):write_job_receipt(self.root, self.run_id, "SUCCEEDED", value)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_invalid_identity_and_states_do_not_write(self):
        for value in ("../escape", "a" * 31, "A" * 32, "z" * 32, "a" * 33, "a" * 32 + "/x", None, True):
            with self.subTest(value=value),self.assertRaises(ValueError):write_job_receipt(self.root, value, "FAILED", None)
        for state in ("PENDING", "SKIPPED", "SUCCESS", "NOT_VERIFIED", "", None, True):
            with self.subTest(state=state),self.assertRaises(ValueError):write_job_receipt(self.root, self.run_id, state, None)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_rejects_world_readable_and_symlink_directory(self):
        os.chmod(self.root, 0o755)
        with self.assertRaises(ValueError):self.write()
        os.chmod(self.root, 0o700)
        link=self.root.parent/(self.root.name+"-link")
        link.symlink_to(self.root, target_is_directory=True)
        self.addCleanup(link.unlink)
        with self.assertRaises(OSError):write_job_receipt(link,self.run_id,"SUCCEEDED",self.sha)

    def test_rejects_preexisting_symlink_destination(self):
        target=self.root/"target"
        target.write_text("unchanged")
        (self.root/(self.run_id+".json")).symlink_to(target)
        with self.assertRaises(FileExistsError):self.write()
        self.assertEqual(target.read_text(),"unchanged")

    def test_receipt_not_visible_before_file_sync(self):
        real = os.fsync
        checked = []
        def inspect(fd):
            if not checked:
                checked.append(True)
                self.assertFalse((self.root / (self.run_id + ".json")).exists())
            return real(fd)
        with patch("reporting._pdf_job_durable_receipt.os.fsync", side_effect=inspect):
            self.write()
        self.assertTrue(checked)

    def test_no_receipt_on_file_sync_failure(self):
        original=os.fsync
        def fail(fd):
            raise OSError("simulated sync error")
        with patch("reporting._pdf_job_durable_receipt.os.fsync", side_effect=fail):
            with self.assertRaises(OSError):self.write()
        self.assertFalse((self.root/(self.run_id+".json")).exists())

    def test_no_receipt_on_directory_sync_failure_is_not_success(self):
        real=os.fsync
        count=[0]
        def fail_after_file(fd):
            count[0]+=1
            if count[0]>=2:raise OSError("simulated directory sync error")
            return real(fd)
        with patch("reporting._pdf_job_durable_receipt.os.fsync", side_effect=fail_after_file):
            with self.assertRaises(OSError):self.write()
        self.assertFalse((self.root/(self.run_id+".json")).exists())

if __name__=="__main__":unittest.main()
