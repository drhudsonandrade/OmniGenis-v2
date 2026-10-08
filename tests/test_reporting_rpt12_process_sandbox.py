"""RPT-12 proof of process-local filesystem/TCP restrictions (not full sandbox)."""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
PROFILE_NAME = "omnigenis-generated-pdf-landlock-v1"


class LandlockContainmentTests(unittest.TestCase):
    def test_declared_process_only_profile_and_fail_closed_preflight(self):
        from reporting import _pdf_process_sandbox as sandbox

        self.assertEqual(sandbox.PROFILE_ID, PROFILE_NAME)
        with mock.patch.object(sandbox, "landlock_abi_version", return_value=0):
            with self.assertRaisesRegex(RuntimeError, "pdf_sandbox_unavailable"):
                sandbox.enforce_pdf_landlock(ROOT / "reporting/_pdf_render_worker.py")

    def test_target_linux_restricts_unapproved_file_and_tcp(self):
        """Apply the irreversible policy only in a disposable child process."""
        with tempfile.TemporaryDirectory(prefix="omnigenis-landlock-test-") as directory:
            forbidden = Path(directory) / "synthetic-not-approved.txt"
            forbidden.write_text("SYNTHETIC_SENTINEL_DO_NOT_READ", encoding="utf-8")
            script = """
import json,errno,os,socket,sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from reporting._pdf_process_sandbox import enforce_pdf_landlock
enforce_pdf_landlock(Path(sys.argv[1]) / "reporting/_pdf_render_worker.py")
approved=(Path(sys.argv[1]) / "reporting/_pdf_render_worker.py")
ok=approved.is_file()
try:
    write_fd=os.open(approved,os.O_WRONLY|os.O_CLOEXEC)
    os.close(write_fd)
    blocked_write=False
except OSError as exc:
    blocked_write=exc.errno in {errno.EACCES,errno.EPERM}
try:
    Path(sys.argv[2]).read_text()
    blocked_file=False
except OSError as exc:
    blocked_file=exc.errno in {errno.EACCES,errno.EPERM}
sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
try:
    sock.connect(("127.0.0.1",9))
    blocked_tcp=False
except OSError as exc:
    blocked_tcp=exc.errno in {errno.EACCES,errno.EPERM}
finally:
    sock.close()
print(json.dumps({"approved_source_access":ok,"blocked_file":blocked_file,
                  "blocked_tcp":blocked_tcp,"blocked_source_write":blocked_write,
                  "abi":"4+"}))
"""
            complete = subprocess.run(
                [sys.executable, "-I", "-c", script, str(ROOT), str(forbidden)],
                cwd=ROOT, capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(complete.returncode, 0, complete.stderr[-400:])
            evidence = json.loads(complete.stdout)
            self.assertEqual(
                evidence,
                {"approved_source_access": True, "blocked_file": True,
                 "blocked_tcp": True, "blocked_source_write": True, "abi": "4+"},
            )
            # The inherited parent remains unrestricted by its child's policy.
            self.assertEqual(
                forbidden.read_text(encoding="utf-8"),
                "SYNTHETIC_SENTINEL_DO_NOT_READ",
            )

    def test_both_fixed_workers_activate_before_native_evaluation(self):
        """Guard the exact worker wiring without executing a policy in this host."""
        expected = (
            ("_pdf_render_worker.py", "_render"),
            ("_pdf_validation_worker.py", "_evaluate"),
        )
        for filename, native_function in expected:
            with self.subTest(worker=filename):
                tree = ast.parse(
                    (ROOT / "reporting" / filename).read_text(encoding="utf-8")
                )
                func = next(
                    n for n in tree.body
                    if isinstance(n, ast.FunctionDef) and n.name == "main"
                )
                sandbox_calls = [
                    node.lineno for node in ast.walk(func)
                    if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "enforce_pdf_landlock"
                ]
                native_calls = [
                    node.lineno for node in ast.walk(func)
                    if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == native_function
                ]
                self.assertEqual(len(sandbox_calls), 1)
                self.assertEqual(len(native_calls), 1)
                self.assertLess(sandbox_calls[0], native_calls[0])

    def test_manifest_identifies_partial_isolation_without_overclaim(self):
        data = json.loads(
            (ROOT / "reporting/pdf-engine.v1.json").read_text(encoding="utf-8")
        )
        isolation = data["process_local_sandbox"]
        self.assertEqual(isolation["profile_id"], PROFILE_NAME)
        self.assertEqual(isolation["landlock_abi_minimum"], 4)
        self.assertEqual(isolation["filesystem"], "deny unapproved new path access")
        self.assertEqual(isolation["network"], "deny TCP bind/connect only")
        self.assertEqual(isolation["unsupported_os_behavior"], "fail_closed")
        self.assertFalse(data["execution_envelope"]["os_sandbox_claimed"])
        self.assertFalse(data["postvalidation_envelope"]["os_sandbox_claimed"])
        self.assertFalse(isolation["aggregate_resource_closure_claimed"])
        self.assertFalse(isolation["complete_network_isolation_claimed"])


if __name__ == "__main__":
    unittest.main()
