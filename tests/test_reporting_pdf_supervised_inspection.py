"""Fixed-child transport tests; synthetic process faults are not service qualification."""
from contextlib import ExitStack, contextmanager
from hashlib import sha256
import ast
import ctypes
import importlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from reporting.page_checkpoints import _json_bytes
from reporting import pdf_inspection_result_frame as frame
from tests import test_reporting_pdf_fixed_inspection_worker as previous
from tests.test_reporting_pdf_source_inspection_job import generated_job_case

ROOT = Path(__file__).resolve().parents[1]
REAL_POPEN = subprocess.Popen


class SupervisedInspectionTests(unittest.TestCase):
    """No partial bytes or unconfirmed termination can become an accepted result."""

    def setUp(self):
        """Require the new boundary before constructing existing controlled fixtures."""
        self.assertIsNotNone(importlib.util.find_spec('reporting.pdf_supervised_inspection'),
                             'fixed-worker supervision is missing')
        self.m = importlib.import_module('reporting.pdf_supervised_inspection')
        self.fixture = previous.FixedInspectionWorkerTests()
        self.fixture.setUp()
        self.h = self.fixture.h

    def invoke(self, fd, context, **changes):
        """Use the fixed public API, never a caller-specified command or budget."""
        return self.m.execute_supervised_pdf_inspection(fd, **{
            'expected_context': context,
            'expected_supervisor_profile_sha256': self.m.PROFILE_SHA256, **changes})

    def synthetic_frame(self, context):
        """Encode controlled result metadata without claiming native execution."""
        original = self.h.controlled_result()
        return frame.encode_pdf_inspection_result_frame(original,
            **{key: context[key] for key in self.m.RESULT_KEYS}), original.to_bytes()

    @contextmanager
    def child(self, script, *, short_deadline=False):
        """Replace only process construction with a bounded synthetic Python child."""
        launches = []
        def launch(command, **kwargs):
            """Retain production pipe, session, environment and descriptor settings."""
            process = REAL_POPEN([sys.executable, '-I', '-B', '-c', script], **kwargs)
            launches.append((command, kwargs, process))
            return process
        clock_class = self.m._Clock
        def short_clock():
            """Inject a short internal clock only; the production profile is unchanged."""
            value = clock_class()
            value.deadline = value.started + 250_000_000
            return value
        try:
            with patch.object(self.m.subprocess, 'Popen', side_effect=launch):
                if short_deadline:
                    with patch.object(self.m, '_Clock', side_effect=short_clock):
                        yield launches
                else:
                    yield launches
        finally:
            # Assertions run before this emergency fixture cleanup.
            for _, _, process in launches:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=3)
                for stream in (process.stdin, process.stdout):
                    if stream is not None:
                        stream.close()

    def fail_with_child(self, script, *, short=False):
        """Run a fault against a real sealed request and require a fixed safe error."""
        with self.h.request() as (fd, expected, args, _):
            raw = _json_bytes(self.fixture.context(expected, args))
            before = time.monotonic()
            with self.child(script, short_deadline=short) as launches:
                with self.assertRaises(self.m.PdfSupervisedInspectionError) as caught:
                    self.invoke(fd, raw)
                self.assertEqual(len(launches), 1)
                process = launches[0][2]
                self.assertIsNotNone(process.returncode, 'direct child was not reaped')
                with self.assertRaises(ChildProcessError):
                    os.waitpid(process.pid, os.WNOHANG)
            self.assertLess(time.monotonic() - before, 5)
            self.assertTrue(str(caught.exception).startswith('pdf_supervised_inspection_'))
            self.assertNotIn('SYNTHETIC_SECRET', str(caught.exception))
            return str(caught.exception)

    def test_public_signature_has_no_executor_budget_or_environment_override(self):
        """The independent context and profile pin are the only public controls."""
        signature = inspect.signature(self.m.execute_supervised_pdf_inspection)
        self.assertEqual(set(signature.parameters), {'request_fd', 'expected_context',
                                                   'expected_supervisor_profile_sha256'})
        self.assertFalse(any(p.kind in (p.VAR_KEYWORD, p.VAR_POSITIONAL)
                             for p in signature.parameters.values()))

    def test_profile_preserves_original_limits_and_unqualified_scope(self):
        """Fixed transport supervision does not promote release or aggregate isolation."""
        profile = self.m.supervisor_profile()
        self.assertEqual(profile['worker_profile_sha256'], self.fixture.m.PROFILE_SHA256)
        self.assertEqual(profile['max_context_bytes'], self.fixture.m.MAX_CONTEXT_BYTES)
        self.assertEqual(profile['max_frame_bytes'], frame.MAX_FRAME_BYTES)
        self.assertEqual(profile['acceptance_deadline_ns'], 300_000_000_000)
        for name in ('aggregate_job_resources_qualified', 'arbitrary_descendant_cleanup_qualified',
                     'host_authenticated', 'release_authorized', 'default_pipeline_activated',
                     'service_installed', 'hard_job_deadline_qualified'):
            self.assertIs(profile[name], False)
        profile['max_frame_bytes'] = 1
        self.assertEqual(self.m.supervisor_profile()['max_frame_bytes'], frame.MAX_FRAME_BYTES)

    def test_manifest_source_pins_and_docstrings(self):
        """A separate manifest binds the new component without altering prior profiles."""
        record = json.loads((ROOT / 'reporting/pdf-supervised-inspection.v1.json').read_text())
        self.assertEqual(record['profile_sha256'], self.m.PROFILE_SHA256)
        self.assertEqual(record['profile'], self.m.supervisor_profile())
        for name, value in record['source_sha256'].items():
            self.assertEqual(sha256((ROOT / name).read_bytes()).hexdigest(), value)
        for node in ast.walk(ast.parse((ROOT / 'reporting/pdf_supervised_inspection.py').read_text())):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.assertIsNotNone(ast.get_docstring(node), node.name)

    def test_context_types_and_noncanonical_bytes_fail_before_launch(self):
        """Malformed and mutable contexts never trigger a process."""
        with self.h.request() as (fd, expected, args, _):
            raw = _json_bytes(self.fixture.context(expected, args))
            for value in (None, {}, raw.decode(), bytearray(raw), memoryview(raw), b'',
                          b' ' + raw, raw + b'\n', b'x' * 4097,
                          raw[:-1] + b',"extra":1}'):
                with self.subTest(kind=type(value).__name__), \
                     patch.object(self.m.subprocess, 'Popen') as launch, \
                     self.assertRaises(self.m.PdfSupervisedInspectionError):
                    self.invoke(fd, value)
                launch.assert_not_called()

    def test_profile_drift_and_disable_fail_before_launch(self):
        """No new pin or runtime mutation can silently widen the fixed profile."""
        with self.h.request() as (fd, expected, args, _):
            raw = _json_bytes(self.fixture.context(expected, args))
            with patch.object(self.m.subprocess, 'Popen') as launch:
                with self.assertRaises(self.m.PdfSupervisedInspectionError):
                    self.invoke(fd, raw, expected_supervisor_profile_sha256='f' * 64)
                with patch.dict(os.environ, {'OMNIGENIS_PDF_SUPERVISOR_DISABLED': '1'}), \
                     self.assertRaises(self.m.PdfSupervisedInspectionError):
                    self.invoke(fd, raw)
                with patch.object(self.m, 'MAX_FRAME_BYTES', 1), \
                     self.assertRaises(self.m.PdfSupervisedInspectionError):
                    self.invoke(fd, raw)
                launch.assert_not_called()

    def test_root_and_unsupported_platform_fail_before_launch(self):
        """The wrapper never starts a privileged child or changes execution platform."""
        with patch.object(self.m.subprocess, 'Popen') as launch:
            with patch.object(self.m.os, 'geteuid', return_value=0), \
                 self.assertRaises(self.m.PdfSupervisedInspectionError):
                self.invoke(3, b'{}')
            with patch.object(self.m.sys, 'platform', 'unsupported'), \
                 self.assertRaises(self.m.PdfSupervisedInspectionError):
                self.invoke(3, b'{}')
            launch.assert_not_called()

    def test_invalid_descriptors_fail_before_launch(self):
        """Standard streams, booleans and invalid handles are never child inputs."""
        _, expected, args = self.h.fixture()
        raw = _json_bytes(self.fixture.context(expected, args))
        for value in (None, True, -1, 0, 1, 2, 2**31, '3'):
            with self.subTest(value=value), patch.object(self.m.subprocess, 'Popen') as launch, \
                 self.assertRaises(self.m.PdfSupervisedInspectionError):
                self.invoke(value, raw)
            launch.assert_not_called()

    def test_unsealed_request_fails_before_launch(self):
        """A valid packet hash does not replace kernel content seals."""
        packet, expected, args = self.h.fixture()
        fd = os.memfd_create('synthetic-unsealed', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, packet)
            with patch.object(self.m.subprocess, 'Popen') as launch, \
                 self.assertRaises(self.m.PdfSupervisedInspectionError):
                self.invoke(fd, _json_bytes(self.fixture.context(expected, args)))
            launch.assert_not_called()
        finally:
            os.close(fd)

    def test_request_and_expected_result_mismatch_fail_before_launch(self):
        """The expected frame context must agree with the sealed request before work."""
        with self.h.request() as (fd, expected, args, _):
            context = self.fixture.context(expected, args)
            for name, value in (('expected_pdf_sha256', 'f' * 64),
                                ('expected_ir_sha256', 'f' * 64), ('expected_page_count', 1),
                                ('expected_job_id', 'synthetic-foreign')):
                with self.subTest(name=name), patch.object(self.m.subprocess, 'Popen') as launch, \
                     self.assertRaises(self.m.PdfSupervisedInspectionError):
                    self.invoke(fd, _json_bytes({**context, name: value}))
                launch.assert_not_called()

    def test_complete_frame_zero_exit_preserves_borrowed_request(self):
        """Exact original bytes return only after a real child closes and exits."""
        with self.h.request() as (fd, expected, args, packet):
            context = self.fixture.context(expected, args)
            encoded, decoded = self.synthetic_frame(context)
            script = 'import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(' + repr(encoded) + ')'
            os.lseek(fd, 7, os.SEEK_SET)
            with self.child(script) as launches:
                self.assertEqual(self.invoke(fd, _json_bytes(context)), decoded)
            self.assertEqual(len(launches), 1)
            command, options, _ = launches[0]
            self.assertEqual(command[:3], [sys.executable, '-I', '-B'])
            self.assertTrue(command[3].endswith('/reporting/_pdf_fixed_inspection_worker.py'))
            self.assertEqual(command[-1], str(os.getpid()))
            self.assertTrue(options['close_fds'])
            self.assertTrue(options['start_new_session'])
            self.assertNotIn('shell', options)
            self.assertEqual(len(options['pass_fds']), 1)
            self.assertNotEqual(options['pass_fds'][0], fd)
            self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), 7)
            self.assertEqual(os.pread(fd, len(packet), 0), packet)
            self.assertFalse(os.get_inheritable(fd))

    def test_fragmented_result_is_collected_without_changing_bytes(self):
        """Multiple pipe writes form exactly one original complete frame."""
        with self.h.request() as (fd, expected, args, _):
            context = self.fixture.context(expected, args)
            encoded, decoded = self.synthetic_frame(context)
            script = ('import os,sys,time;sys.stdin.buffer.read();data=' + repr(encoded)
                      + '\nfor i in range(0,len(data),127):\n os.write(1,data[i:i+127]);time.sleep(0.0001)')
            with self.child(script):
                self.assertEqual(self.invoke(fd, _json_bytes(context)), decoded)

    def test_nonzero_exit_with_valid_frame_never_succeeds(self):
        """Even valid framed metadata cannot mask a failed child exit."""
        with self.h.request() as (fd, expected, args, _):
            context = self.fixture.context(expected, args)
            encoded, _ = self.synthetic_frame(context)
            script = ('import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(' + repr(encoded)
                      + ');sys.stdout.buffer.flush();sys.exit(70)')
            with self.child(script), self.assertRaises(self.m.PdfSupervisedInspectionError):
                self.invoke(fd, _json_bytes(context))

    def test_empty_or_partial_frame_zero_exit_is_refused(self):
        """EOF and zero exit are necessary but cannot complete a malformed frame."""
        for payload in (b'', b'OGPDFRS1', b'not-a-result'):
            with self.subTest(payload=payload):
                self.fail_with_child('import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(' + repr(payload) + ')')

    def test_deadline_kills_and_reaps_direct_child(self):
        """An unresponsive child cannot hold the caller past the injected short deadline."""
        reason = self.fail_with_child('import time;time.sleep(10)', short=True)
        self.assertEqual(reason, 'pdf_supervised_inspection_deadline')

    def test_eof_without_process_exit_is_not_completion(self):
        """Closing stdout before sleeping must not bypass the termination deadline."""
        self.assertEqual(self.fail_with_child(
            'import os,sys,time;sys.stdin.buffer.read();os.close(1);time.sleep(10)', short=True),
            'pdf_supervised_inspection_deadline')

    def test_output_overflow_is_bounded_and_refused(self):
        """Only cap plus one detection byte can be retained from an oversized stream."""
        reason = self.fail_with_child('import os,sys;sys.stdin.buffer.read();os.write(1,b"x"*400000)')
        self.assertEqual(reason, 'pdf_supervised_inspection_output_budget')

    def test_worker_failure_does_not_expose_stderr(self):
        """Arbitrary worker stderr never becomes an exception message."""
        self.fail_with_child('import sys;sys.stderr.write("SYNTHETIC_SECRET");sys.exit(70)')

    def test_unrelated_python_environment_is_not_forwarded(self):
        """Fixed isolated execution does not inherit arbitrary import or loader settings."""
        with patch.dict(os.environ, {'PYTHONPATH': '/synthetic', 'LD_PRELOAD': '/synthetic',
                                    'OMNIGENIS_PDF_RASTER_WINDOWS_DISABLED': '1'}):
            env = self.m._environment()
        self.assertNotIn('PYTHONPATH', env)
        self.assertNotIn('LD_PRELOAD', env)
        self.assertEqual(env['OMNIGENIS_PDF_RASTER_WINDOWS_DISABLED'], '1')

    def test_bad_native_selector_does_not_become_unconfined_execution(self):
        """Invalid native selectors fail closed instead of being silently omitted."""
        for name in ('OMNIGENIS_PDF_FIXED_KERNEL_ADMISSION_V1', 'OMNIGENIS_PDF_BOUNDED_SCRATCH_V1'):
            with patch.dict(os.environ, {name: '0'}), self.assertRaises(Exception):
                self.m._environment()

    def test_profile_disable_during_execution_prevents_return(self):
        """A valid completed frame cannot survive a final disable check."""
        with self.h.request() as (fd, expected, args, _):
            context = self.fixture.context(expected, args)
            encoded, _ = self.synthetic_frame(context)
            def changed(*unused):
                """Inject only post-dispatch policy drift in the parent process."""
                os.environ['OMNIGENIS_PDF_SUPERVISOR_DISABLED'] = '1'
                return encoded
            with patch.dict(os.environ, {}, clear=False), patch.object(self.m, '_exchange', side_effect=changed), \
                 self.assertRaises(self.m.PdfSupervisedInspectionError):
                self.invoke(fd, _json_bytes(context))

    def test_clock_rejects_backward_and_noninteger_observations(self):
        """A malformed time source is not a usable remaining budget."""
        for ticks in ((10, 9), (True,), (-1,), (10, 10.5)):
            with self.subTest(ticks=ticks), patch.object(self.m, 'monotonic_ns', side_effect=ticks), \
                 self.assertRaises(Exception):
                self.m._Clock().remaining()

    def test_exited_parent_with_open_descendant_pipe_hits_deadline(self):
        """Observe exact descendant exit, with a surviving no-group-signal control."""
        for signal_group in (False, True):
            with self.subTest(signal_group=signal_group):
                code = ("import json,sys;sys.path.insert(0," + repr(str(ROOT)) + ");"
                        "from tests.test_reporting_pdf_supervised_inspection import descendant_cleanup_probe;"
                        "print(json.dumps(descendant_cleanup_probe(" + repr(signal_group) + ")))")
                completed = subprocess.run([sys.executable, '-I', '-B', '-c', code],
                    cwd=ROOT, capture_output=True, text=True, timeout=20, check=True)
                result = json.loads(completed.stdout)
                self.assertEqual(result['reason'], 'pdf_supervised_inspection_deadline')
                self.assertEqual(result['direct_exit'], 0)
                self.assertTrue(result['direct_reaped'])
                self.assertEqual(result['descendant_exited'], signal_group)
                self.assertEqual(result['descendant_signal'], signal.SIGKILL if signal_group else None)

    def test_zero_context_write_cannot_succeed(self):
        """An anomalous no-progress write must close and reap the owned child."""
        with self.h.request() as (fd, expected, args, _), \
             self.child('import sys;sys.stdin.buffer.read()'), \
             patch.object(self.m.os, 'write', return_value=0), \
             self.assertRaises(self.m.PdfSupervisedInspectionError) as caught:
            self.invoke(fd, _json_bytes(self.fixture.context(expected, args)))
        self.assertEqual(str(caught.exception), 'pdf_supervised_inspection_context_incomplete')

    def test_already_reaped_identity_is_never_signalled(self):
        """Lost child ownership must not signal a potentially reused numeric PID."""
        import io
        from types import SimpleNamespace
        process = SimpleNamespace(pid=42, returncode=0, stdin=io.BytesIO(), stdout=io.BytesIO())
        with patch.object(self.m.os, 'killpg') as group, patch.object(self.m.os, 'kill') as direct, \
             self.assertRaises(self.m._Refusal):
            self.m._finish_child(process)
        group.assert_not_called()
        direct.assert_not_called()
        self.assertTrue(process.stdin.closed and process.stdout.closed)

    def test_cleanup_wait_failure_prevents_success(self):
        """Unknown direct-child termination remains a failure, not an assumed reap."""
        import io
        from types import SimpleNamespace
        def unresolved(**unused):
            """Simulate a bounded wait failure without creating a real unreaped process."""
            raise subprocess.TimeoutExpired('synthetic', 2)
        process = SimpleNamespace(pid=42, returncode=None, stdin=io.BytesIO(),
                                  stdout=io.BytesIO(), wait=unresolved)
        with patch.object(self.m, '_unreaped_exit', return_value=None), \
             patch.object(self.m.os, 'killpg'), patch.object(self.m.os, 'kill'), \
             self.assertRaises(self.m._Refusal) as caught:
            self.m._finish_child(process)
        self.assertEqual(str(caught.exception), 'cleanup_unresolved')
        self.assertTrue(process.stdin.closed and process.stdout.closed)

    def test_spawn_failure_is_content_free_and_preserves_descriptor(self):
        """Failed creation never leaks the underlying OS message or closes input."""
        with self.h.request() as (fd, expected, args, packet), \
             patch.object(self.m.subprocess, 'Popen', side_effect=OSError('SYNTHETIC_SECRET')), \
             self.assertRaises(self.m.PdfSupervisedInspectionError) as caught:
            self.invoke(fd, _json_bytes(self.fixture.context(expected, args)))
        self.assertNotIn('SYNTHETIC_SECRET', str(caught.exception))

    def test_repeated_failures_do_not_leak_owned_descriptors(self):
        """Admission and transport failures preserve the caller's descriptor count."""
        with self.h.request() as (fd, expected, args, packet):
            raw = _json_bytes(self.fixture.context(expected, args))
            count = len(os.listdir('/proc/self/fd'))
            for _ in range(6):
                with self.child('import sys;sys.stdin.buffer.read();sys.exit(70)'), \
                     self.assertRaises(self.m.PdfSupervisedInspectionError):
                    self.invoke(fd, raw)
                self.assertEqual(len(os.listdir('/proc/self/fd')), count)
                self.assertEqual(os.pread(fd, len(packet), 0), packet)

    def test_deadline_during_final_validation_withholds_valid_result(self):
        """Completing transport does not extend the deadline for decoding or return."""
        with self.h.request() as (fd, expected, args, _):
            context = self.fixture.context(expected, args)
            encoded, _ = self.synthetic_frame(context)
            def expire(unused_fd, unused_context, unused_env, clock):
                """Force expiry only after producing a valid controlled frame."""
                clock.deadline = clock.started
                return encoded
            with patch.object(self.m, '_exchange', side_effect=expire), \
                 self.assertRaises(self.m.PdfSupervisedInspectionError) as caught:
                self.invoke(fd, _json_bytes(context))
        self.assertEqual(str(caught.exception), 'pdf_supervised_inspection_deadline')

    def test_real_one_page_uses_original_worker_and_result(self):
        """Run the existing guarded native inspectors as an unprivileged direct child."""
        ir, pdf = generated_job_case(1)
        raw = _json_bytes(ir)
        with self.h.request(presentation_ir_bytes=raw, expected_ir_sha256=sha256(raw).hexdigest(),
                            pdf_bytes=pdf, expected_pdf_sha256=sha256(pdf).hexdigest(),
                            page_count=1) as (fd, expected, args, packet):
            context = self.fixture.context(expected, args)
            result = self.invoke(fd, _json_bytes(context))
            data = json.loads(result)
            self.assertEqual(data['page_count'], 1)
            self.assertEqual(len(data['inspection_dimensions']), 8)
            self.assertFalse(data['aggregate_job_resources_qualified'])
            self.assertFalse(data['release_authorized'])
            self.assertEqual(os.pread(fd, len(packet), 0), packet)



def descendant_cleanup_probe(signal_group: bool) -> dict:
    """Pin and reap one original-group descendant in a disposable subreaper process."""
    if ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) != 0:
        raise RuntimeError('test subreaper unavailable')
    case = SupervisedInspectionTests()
    case.setUp()
    processes, clocks = [], []
    child_pid = child_fd = None
    reaped = False
    original_clock = case.m._Clock
    with tempfile.TemporaryDirectory(prefix='omnigenis-supervisor-cleanup-') as directory:
        marker = Path(directory) / 'descendant.pid'
        release = Path(directory) / 'release'
        script = (
            'import os,sys,time\nfrom pathlib import Path\nchild=os.fork()\n'
            'if child == 0:\n time.sleep(10);os._exit(0)\n'
            'marker=Path(' + repr(str(marker)) + ')\n'
            'temporary=marker.with_suffix(".tmp")\n'
            'temporary.write_text(str(child),encoding="ascii");temporary.replace(marker)\n'
            'deadline=time.monotonic()+5\n'
            'while not Path(' + repr(str(release)) + ').exists():\n'
            ' if time.monotonic()>=deadline:os._exit(71)\n time.sleep(0.005)\n'
            'sys.stdin.buffer.read();os._exit(0)\n')

        def clock():
            """Retain only the synthetic transport clock; production budgets are untouched."""
            value = original_clock()
            clocks.append(value)
            return value

        def launch(command, **kwargs):
            """Pin the live descendant before releasing its still-owned direct parent."""
            nonlocal child_pid, child_fd
            process = REAL_POPEN([sys.executable, '-I', '-B', '-c', script], **kwargs)
            processes.append(process)
            limit = time.monotonic() + 5
            while not marker.exists():
                if time.monotonic() >= limit:
                    raise RuntimeError('test descendant readiness missing')
                time.sleep(0.005)
            child_pid = int(marker.read_text(encoding='ascii'))
            child_fd = os.pidfd_open(child_pid)
            case.assertFalse(select.select([child_fd], [], [], 0)[0])
            case.assertEqual(os.getpgid(child_pid), process.pid)
            status = Path(f'/proc/{child_pid}/status').read_text()
            case.assertIn('PPid:\t' + str(process.pid) + '\n', status)
            release.touch(exist_ok=False)
            # Start the artificial short transport window after fixture readiness.
            clocks[0].deadline = time.monotonic_ns() + 1_000_000_000
            return process

        try:
            with ExitStack() as stack:
                stack.enter_context(patch.object(case.m, '_Clock', side_effect=clock))
                stack.enter_context(patch.object(case.m.subprocess, 'Popen', side_effect=launch))
                if not signal_group:
                    stack.enter_context(patch.object(case.m.os, 'killpg', return_value=None))
                with case.h.request() as (fd, expected, args, _):
                    with case.assertRaises(case.m.PdfSupervisedInspectionError) as caught:
                        case.invoke(fd, _json_bytes(case.fixture.context(expected, args)))
            case.assertEqual(len(processes), 1)
            process = processes[0]
            case.assertEqual(process.returncode, 0)
            with case.assertRaises(ChildProcessError):
                os.waitpid(process.pid, os.WNOHANG)
            exited = bool(select.select([child_fd], [], [], 1)[0])
            exit_signal = None
            if exited:
                observed = os.waitid(os.P_PIDFD, child_fd, os.WEXITED | os.WNOHANG)
                case.assertIsNotNone(observed)
                reaped = True
                case.assertEqual(observed.si_pid, child_pid)
                case.assertEqual(observed.si_code, os.CLD_KILLED)
                exit_signal = observed.si_status
            return {'reason': str(caught.exception), 'direct_exit': process.returncode,
                    'direct_reaped': True, 'descendant_exited': exited,
                    'descendant_signal': exit_signal}
        finally:
            # Never signal a recycled numeric descendant PID or count fixture cleanup as proof.
            if child_fd is not None:
                try:
                    signal.pidfd_send_signal(child_fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=3)
                for stream in (process.stdin, process.stdout):
                    if stream is not None:
                        stream.close()
            if child_fd is not None:
                try:
                    if not reaped:
                        if not select.select([child_fd], [], [], 3)[0]:
                            raise RuntimeError('test descendant cleanup unresolved')
                        os.waitid(os.P_PIDFD, child_fd, os.WEXITED | os.WNOHANG)
                finally:
                    os.close(child_fd)


if __name__ == '__main__':
    unittest.main(verbosity=2)
