"""RPT-12 Linux seccomp-BPF network guard, distinct from full OS sandboxing."""
from __future__ import annotations

import ast
import ctypes
import errno
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PROFILE = "omnigenis-generated-pdf-seccomp-network-v1"
EXPECTED_SYSCALLS = {
    "socket": 41, "connect": 42, "accept": 43, "sendto": 44,
    "recvfrom": 45, "sendmsg": 46, "recvmsg": 47, "shutdown": 48,
    "bind": 49, "listen": 50, "getsockname": 51, "getpeername": 52,
    "socketpair": 53, "setsockopt": 54, "getsockopt": 55,
    "accept4": 288, "recvmmsg": 299, "sendmmsg": 307,
    "io_uring_setup": 425, "io_uring_enter": 426,
    "io_uring_register": 427,
}


class NetworkSyscallGuardTests(unittest.TestCase):
    def test_profile_is_pinned_to_x86_64_linux_and_denies_missing_capability(self):
        from reporting import _pdf_process_sandbox as sandbox

        self.assertEqual(sandbox.NETWORK_PROFILE_ID, EXPECTED_PROFILE)
        self.assertEqual(dict(sandbox._DENIED_NETWORK_SYSCALLS), EXPECTED_SYSCALLS)
        with patch.object(sandbox.sys, "platform", "darwin"):
            with self.assertRaisesRegex(RuntimeError, "pdf_network_filter_unavailable"):
                sandbox.enforce_pdf_network_filter()
        with patch.object(sandbox.platform, "machine", return_value="aarch64"):
            with self.assertRaisesRegex(RuntimeError, "pdf_network_filter_unavailable"):
                sandbox.enforce_pdf_network_filter()

    def test_disposable_worker_denies_tcp_udp_unix_sockets_without_affecting_host(self):
        script = """
import errno,json,os,socket,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from reporting._pdf_process_sandbox import enforce_pdf_network_filter
enforce_pdf_network_filter()
out={}
for name,af,kind in (
    ("tcp",socket.AF_INET,socket.SOCK_STREAM),
    ("udp",socket.AF_INET,socket.SOCK_DGRAM),
    ("unix",socket.AF_UNIX,socket.SOCK_STREAM),
):
    try:
        s=socket.socket(af,kind)
    except OSError as exc:
        out[name]=exc.errno==errno.EPERM
    else:
        s.close()
        out[name]=False
try:
    left,right=socket.socketpair()
except OSError as exc:
    out["socketpair"]=exc.errno==errno.EPERM
else:
    left.close()
    right.close()
    out["socketpair"]=False
try:
    out["file_read"]=Path(sys.argv[2]).read_bytes()==b"OMNIGENIS_SYNTHETIC_READ_PROBE"
except OSError:
    out["file_read"]=False
print(json.dumps(out,sort_keys=True))
"""
        parent_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        parent_socket.close()
        with tempfile.TemporaryDirectory(prefix="omnigenis-read-probe-") as directory:
            fixture=Path(directory)/"read-probe.bin"
            fixture.write_bytes(b"OMNIGENIS_SYNTHETIC_READ_PROBE")
            child=subprocess.run(
                [sys.executable,"-I","-c",script,str(ROOT),str(fixture)],
                capture_output=True,text=True,cwd=ROOT,timeout=10,
            )
        self.assertEqual(child.returncode,0,child.stderr[-500:])
        self.assertEqual(json.loads(child.stdout),{
            "tcp":True,"udp":True,"unix":True,"socketpair":True,"file_read":True,
        })
        missing=ROOT / "nonexistent-synthetic-network-read-check.bin"
        self.assertFalse(missing.exists())
        negative=subprocess.run(
            [sys.executable,"-I","-c",script,str(ROOT),str(missing)],
            capture_output=True,text=True,cwd=ROOT,timeout=10,
        )
        self.assertEqual(negative.returncode,0,negative.stderr[-300:])
        self.assertFalse(json.loads(negative.stdout)["file_read"])
        another_parent_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        another_parent_socket.close()

    def test_pdf_workers_enforce_network_guard_before_reading_native_input(self):
        for filename in ("_pdf_render_worker.py","_pdf_validation_worker.py"):
            with self.subTest(worker=filename):
                tree=ast.parse((ROOT/"reporting"/filename).read_text())
                main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=="main")
                calls={
                    name:sorted(
                        x.lineno for x in ast.walk(main)
                        if isinstance(x,ast.Call) and isinstance(x.func,ast.Name)
                        and x.func.id==name
                    )
                    for name in ("enforce_pdf_landlock","enforce_pdf_network_filter","_read_request")
                }
                self.assertEqual(len(calls["enforce_pdf_landlock"]),1)
                self.assertEqual(len(calls["enforce_pdf_network_filter"]),1)
                self.assertEqual(len(calls["_read_request"]),1)
                self.assertLess(calls["enforce_pdf_landlock"][0],calls["enforce_pdf_network_filter"][0])
                self.assertLess(calls["enforce_pdf_network_filter"][0],calls["_read_request"][0])

    def test_manifest_stays_partial_and_declares_kernel_network_profile(self):
        data=json.loads((ROOT/"reporting/pdf-engine.v1.json").read_text())
        local=data["process_local_sandbox"]
        network=local["network_syscall_guard"]
        self.assertEqual(network["profile_id"],EXPECTED_PROFILE)
        self.assertEqual(network["kernel_api"],"seccomp-BPF / prctl")
        self.assertEqual(network["architecture"],"Linux x86_64")
        self.assertEqual(network["denied_syscall_count"],len(EXPECTED_SYSCALLS))
        self.assertTrue(network["fail_closed"])
        self.assertTrue(network["no_external_runtime_dependency"])
        self.assertFalse(network["inherited_network_descriptors_claimed_blocked"])
        self.assertFalse(network["complete_network_isolation_claimed"])
        self.assertFalse(network["aggregate_resource_closure_claimed"])
        self.assertFalse(data["execution_envelope"]["os_sandbox_claimed"])
        self.assertFalse(data["postvalidation_envelope"]["os_sandbox_claimed"])

    def _capture_network_program(self):
        """Copy the exact emitted BPF instructions while mocking kernel install."""
        from reporting import _pdf_process_sandbox as sandbox

        calls=[]
        instructions=[]
        libc=Mock(spec=["prctl"])

        def record(option, value, payload, unused_a, unused_b):
            name=option.value
            calls.append(name)
            self.assertEqual(unused_a.value,0)
            self.assertEqual(unused_b.value,0)
            if name==38:  # PR_SET_NO_NEW_PRIVS
                self.assertEqual(value.value,1)
                self.assertEqual(payload.value,0)
                return 0
            self.assertEqual(name,22)  # PR_SET_SECCOMP
            self.assertEqual(value.value,2) # SECCOMP_MODE_FILTER
            program=ctypes.cast(
                payload,ctypes.POINTER(sandbox._SockFprog),
            ).contents
            self.assertGreater(program.len,0)
            self.assertLessEqual(program.len,4096)
            instructions.extend(
                (int(program.filter[i].code),int(program.filter[i].jt),
                 int(program.filter[i].jf),int(program.filter[i].k))
                for i in range(program.len)
            )
            return 0

        libc.prctl.side_effect=record
        with (
            patch.object(sandbox.ctypes,"CDLL",return_value=libc),
            patch.object(sandbox.sys,"platform","linux"),
            patch.object(sandbox.platform,"machine",return_value="x86_64"),
        ):
            sandbox.enforce_pdf_network_filter()
        self.assertEqual(calls,[38,22])
        return tuple(instructions)

    @staticmethod
    def _evaluate_network_program(program, *, architecture, syscall):
        """Evaluate the four BPF opcodes permitted by this fixed test profile."""
        acc=0
        position=0
        fields={0:syscall & 0xFFFFFFFF,4:architecture & 0xFFFFFFFF}
        for _ in range(len(program)+1):
            if not 0<=position<len(program):
                raise AssertionError("BPF jumps outside the program")
            opcode,jt,jf,value=program[position]
            if opcode==0x20:
                if value not in fields:raise AssertionError("unexpected data offset")
                acc=fields[value]
                position+=1
            elif opcode==0x15:
                position+=1+(jt if acc==value else jf)
            elif opcode==0x45:
                position+=1+(jt if acc & value else jf)
            elif opcode==0x06:
                return value
            else:raise AssertionError("unexpected BPF opcode")
        raise AssertionError("BPF did not return a decision")

    def test_emitted_bpf_denies_each_declared_network_syscall(self):
        """Every syscall number, not just the source mapping, must deny."""
        code=self._capture_network_program()
        for name,number in EXPECTED_SYSCALLS.items():
            with self.subTest(syscall=name):
                self.assertEqual(
                    self._evaluate_network_program(
                        code,architecture=0xC000003E,syscall=number
                    ),0x00050000|errno.EPERM,
                )

    def test_emitted_bpf_allows_narrow_nonnetwork_control_calls(self):
        """Only network and alternate-ABI calls are denied by this filter."""
        code=self._capture_network_program()
        for number in (0,1,3,9,12,60,231):
            with self.subTest(syscall=number):
                self.assertEqual(
                    self._evaluate_network_program(
                        code,architecture=0xC000003E,syscall=number
                    ),0x7FFF0000,
                )

    def test_emitted_bpf_rejects_foreign_architectures(self):
        """The arch gate must precede all other decisions."""
        code=self._capture_network_program()
        for arch in (0,0x40000003,0xC00000B7):
            for number in (0,41):
                with self.subTest(arch=arch,syscall=number):
                    self.assertEqual(
                        self._evaluate_network_program(
                            code,architecture=arch,syscall=number
                        ),0x80000000,
                    )

    def test_emitted_bpf_rejects_x32_bit(self):
        """No x32 ABI network/filter bypass on the x86_64 path."""
        code=self._capture_network_program()
        for number in (0,41,427):
            with self.subTest(syscall=number):
                self.assertEqual(
                    self._evaluate_network_program(
                        code,architecture=0xC000003E,syscall=number|0x40000000
                    ),0x80000000,
                )

    def test_kernel_installation_call_order_and_bpf_length(self):
        """No-new-privileges must precede installation of a bounded program."""
        program=self._capture_network_program()
        self.assertEqual(len(program),7+2*len(EXPECTED_SYSCALLS))
        self.assertEqual(program[0],(0x20,0,0,4))
        self.assertEqual(program[-1],(0x06,0,0,0x7FFF0000))

    def test_no_new_privileges_failure_aborts_installation(self):
        """Failure of the first kernel precondition must fail closed."""
        from reporting import _pdf_process_sandbox as sandbox
        libc=Mock(spec=["prctl"])
        libc.prctl.return_value=-1
        with (
            patch.object(sandbox.ctypes,"CDLL",return_value=libc),
            patch.object(sandbox.sys,"platform","linux"),
            patch.object(sandbox.platform,"machine",return_value="x86_64"),
        ):
            with self.assertRaisesRegex(RuntimeError,"^pdf_network_filter_unavailable$"):
                sandbox.enforce_pdf_network_filter()
        self.assertEqual(libc.prctl.call_count,1)
        self.assertEqual(libc.prctl.call_args.args[0].value,38)

    def test_filter_load_failure_aborts_without_reporting_success(self):
        """Explicit rejection of the seccomp filter must be closed."""
        from reporting import _pdf_process_sandbox as sandbox
        libc=Mock(spec=["prctl"])
        libc.prctl.side_effect=[0,-1]
        with (
            patch.object(sandbox.ctypes,"CDLL",return_value=libc),
            patch.object(sandbox.sys,"platform","linux"),
            patch.object(sandbox.platform,"machine",return_value="x86_64"),
        ):
            with self.assertRaisesRegex(RuntimeError,"^pdf_network_filter_unavailable$"):
                sandbox.enforce_pdf_network_filter()
        self.assertEqual(
            [call.args[0].value for call in libc.prctl.call_args_list],[38,22]
        )

    def test_libc_failure_does_not_expose_private_os_details(self):
        """Fixed outward exception on an untrusted library load failure."""
        from reporting import _pdf_process_sandbox as sandbox
        sentinel="SYNTHETIC_PRIVATE_OS_DETAIL"
        with (
            patch.object(sandbox.ctypes,"CDLL",side_effect=OSError(sentinel)),
            patch.object(sandbox.sys,"platform","linux"),
            patch.object(sandbox.platform,"machine",return_value="x86_64"),
        ):
            with self.assertRaises(RuntimeError) as error:
                sandbox.enforce_pdf_network_filter()
        self.assertEqual(str(error.exception),"pdf_network_filter_unavailable")
        self.assertNotIn(sentinel,str(error.exception))



if __name__=="__main__":
    unittest.main()
