"""Optional bounded transport supervisor for the existing fixed PDF worker.

Only a sealed request descriptor and independently expected canonical context
are accepted. The worker command, resource profile, environment and output cap
are fixed. Successful transport requires complete context delivery, stdout EOF,
zero exit, direct-child reap and validation of the original complete frame.

This component does not install a service, grant privileges, activate the default
pipeline, authenticate the caller or qualify aggregate CPU/RSS, all descendants
or report release. The deadline is enforced by a live parent around nonblocking
pipe operations; OS process creation and uninterruptible syscalls are not hard
real-time bounded. Parent death and descendants escaping the original process
group still require separately qualified outer lifecycle supervision. Use a
trusted immutable deployment and do not concurrently mutate process-global
policy, close/reassign borrowed descriptors, or externally reap this child.
"""
from __future__ import annotations

import fcntl
from hashlib import sha256
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
from time import monotonic_ns

from reporting import _pdf_fixed_inspection_worker as worker
from reporting import pdf_inspection_result_frame as frame
from reporting import pdf_request_descriptor as descriptor
from reporting import pdf_structured_source_job as structured
from reporting import pdf_native_source_job as native
from reporting.page_checkpoints import _json_bytes

PROFILE_ID = 'fixed-pdf-supervised-transport-v1'
MAX_CONTEXT_BYTES = worker.MAX_CONTEXT_BYTES
MAX_FRAME_BYTES = frame.MAX_FRAME_BYTES
ACCEPTANCE_NS = structured.ACCEPTANCE_NS
CLEANUP_SECONDS = 2
WORKER_PROFILE_SHA256 = worker.PROFILE_SHA256
FRAME_PROFILE_SHA256 = frame.PROFILE_SHA256
NATIVE_PROFILE_ID = 'fixed-pdf-supervised-transport-v2'
NATIVE_MAX_FRAME_BYTES = frame.NATIVE_MAX_FRAME_BYTES
NATIVE_WORKER_PROFILE_SHA256 = worker.NATIVE_PROFILE_SHA256
NATIVE_FRAME_PROFILE_SHA256 = frame.NATIVE_PROFILE_SHA256
_DISABLE = 'OMNIGENIS_PDF_SUPERVISOR_DISABLED'
_ROOT = Path(__file__).resolve().parents[1]
_WORKER = _ROOT / 'reporting/_pdf_fixed_inspection_worker.py'
_SELECTORS = ('OMNIGENIS_PDF_FIXED_KERNEL_ADMISSION_V1', 'OMNIGENIS_PDF_BOUNDED_SCRATCH_V1')
RESULT_KEYS = ('expected_pdf_sha256', 'expected_ir_sha256', 'expected_page_count',
               'expected_language', 'expected_namespace_id', 'expected_job_id',
               'expected_request_sha256', 'expected_resource_profile_sha256',
               'expected_frame_profile_sha256')
_DESCRIPTOR_KEYS = ('expected_packet_sha256', 'expected_protocol_profile_sha256',
                    'expected_namespace_id', 'expected_job_id', 'expected_request_sha256',
                    'expected_descriptor_profile_sha256')


class PdfSupervisedInspectionError(ValueError):
    """Fixed content-free refusal; no partial output or unknown cleanup is accepted."""


class _Refusal(Exception):
    """Carry an internally selected reason token, never worker-controlled text."""


def supervisor_profile() -> dict:
    """Detach the fixed transport contract without promoting unrelated qualification."""
    return {'schema_version': '1.0.0', 'profile_id': PROFILE_ID,
            'worker_profile_sha256': WORKER_PROFILE_SHA256,
            'frame_profile_sha256': FRAME_PROFILE_SHA256,
            'max_context_bytes': MAX_CONTEXT_BYTES, 'max_frame_bytes': MAX_FRAME_BYTES,
            'acceptance_deadline_ns': ACCEPTANCE_NS, 'cleanup_seconds': CLEANUP_SECONDS,
            'platform': 'linux', 'unprivileged_caller_required': True,
            'stdout_storage': 'BOUNDED_PIPE_FRAME_PLUS_ONE_OVERFLOW_BYTE',
            'completion': 'CONTEXT_SENT_EOF_ZERO_EXIT_REAP_VALID_FRAME',
            'cleanup_scope': 'OWNED_DIRECT_CHILD_AND_ORIGINAL_PROCESS_GROUP_ONLY',
            'retries': 0, 'caller_command_override': False,
            'aggregate_job_resources_qualified': False,
            'arbitrary_descendant_cleanup_qualified': False,
            'host_authenticated': False, 'release_authorized': False,
            'default_pipeline_activated': False, 'service_installed': False,
            'hard_job_deadline_qualified': False}


PROFILE_SHA256 = sha256(_json_bytes(supervisor_profile())).hexdigest()


def native_supervisor_profile() -> dict:
    """Select the complete native wire family while preserving lifecycle and nonclaims."""
    return {**supervisor_profile(), 'schema_version':'2.0.0', 'profile_id':NATIVE_PROFILE_ID,
            'worker_profile_sha256':NATIVE_WORKER_PROFILE_SHA256,
            'frame_profile_sha256':NATIVE_FRAME_PROFILE_SHA256,
            'max_frame_bytes':NATIVE_MAX_FRAME_BYTES}


NATIVE_PROFILE_SHA256 = sha256(_json_bytes(native_supervisor_profile())).hexdigest()


def _profile(expected: str) -> bool:
    """Refuse unsupported, disabled, privileged or changed execution contracts."""
    selected_native = type(expected) is str and expected == NATIVE_PROFILE_SHA256
    profile_pin = NATIVE_PROFILE_SHA256 if selected_native else PROFILE_SHA256
    profile = native_supervisor_profile if selected_native else supervisor_profile
    worker_pin = NATIVE_WORKER_PROFILE_SHA256 if selected_native else WORKER_PROFILE_SHA256
    frame_pin = NATIVE_FRAME_PROFILE_SHA256 if selected_native else FRAME_PROFILE_SHA256
    if (type(expected) is not str or expected != profile_pin
            or sys.platform != 'linux' or os.getuid() == 0 or os.geteuid() == 0
            or any(not hasattr(os, name) for name in ('waitid', 'WNOWAIT', 'WEXITED', 'WNOHANG', 'P_PID'))
            or os.environ.get(_DISABLE) == '1'
            or sha256(_json_bytes(profile())).hexdigest() != profile_pin
            or worker_pin != (worker.NATIVE_PROFILE_SHA256 if selected_native else worker.PROFILE_SHA256)
            or frame_pin != (frame.NATIVE_PROFILE_SHA256 if selected_native else frame.PROFILE_SHA256)
            or MAX_CONTEXT_BYTES != worker.MAX_CONTEXT_BYTES
            or (NATIVE_MAX_FRAME_BYTES if selected_native else MAX_FRAME_BYTES)
                != (frame.NATIVE_MAX_FRAME_BYTES if selected_native else frame.MAX_FRAME_BYTES)
            or ACCEPTANCE_NS != (native.ACCEPTANCE_NS if selected_native else structured.ACCEPTANCE_NS)):
        raise _Refusal('profile_invalid')
    worker._profile(worker_pin)
    frame._profile(frame_pin)
    return selected_native


class _Clock:
    """One monotonic budget for admission, child transport and final acceptance."""

    def __init__(self) -> None:
        """Reject malformed start values before computing a fixed deadline."""
        self.started = monotonic_ns()
        if type(self.started) is not int or self.started < 0:
            raise _Refusal('clock_invalid')
        self.previous = self.started
        self.deadline = self.started + ACCEPTANCE_NS

    def remaining(self) -> float:
        """Reject regressions and expiry; return only positive remaining seconds."""
        current = monotonic_ns()
        if type(current) is not int or current < self.previous:
            raise _Refusal('clock_invalid')
        self.previous = current
        if current >= self.deadline:
            raise _Refusal('deadline')
        return (self.deadline - current) / 1_000_000_000


def _environment() -> dict[str, str]:
    """Forward disabling switches and exact native selectors, not caller import paths."""
    result = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
              'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1'}
    for key, value in os.environ.copy().items():
        if key.startswith('OMNIGENIS_') and key.endswith('_DISABLED'):
            if len(key) > 128 or len(value) > 128 or len(result) >= 128:
                raise _Refusal('environment_invalid')
            result[key] = value
    for key in _SELECTORS:
        value = os.environ.get(key)
        if value is not None:
            if value != '1':
                raise _Refusal('environment_invalid')
            result[key] = value
    if result.get('OMNIGENIS_PDF_BOUNDED_SCRATCH_V1') == '1':
        result['TMPDIR'] = str(worker.bounded_scratch_parent())
    return result


def _unreaped_exit(process: subprocess.Popen) -> int | None:
    """Observe the owned child's exit without releasing its PID before cleanup."""
    if process.returncode is not None:
        raise _Refusal('child_ownership_lost')
    observed = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    if observed is None:
        return None
    if observed.si_pid != process.pid:
        raise _Refusal('child_ownership_lost')
    if observed.si_code == os.CLD_EXITED:
        return observed.si_status
    if observed.si_code in (os.CLD_KILLED, os.CLD_DUMPED):
        return -observed.si_status
    raise _Refusal('child_state_invalid')


def _finish_child(process: subprocess.Popen) -> int:
    """Signal only an unreaped owned child/group, then wait with a finite cleanup bound."""
    try:
        _unreaped_exit(process)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.kill(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return process.wait(timeout=CLEANUP_SECONDS)
    except Exception:
        raise _Refusal('cleanup_unresolved') from None
    finally:
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                stream.close()


def _exchange(request_fd: int, context: bytes, environment: dict[str, str], clock: _Clock,
              *, selected_native: bool = False) -> bytes:
    """Exchange bounded pipes with only the fixed child and preserve its unreaped identity."""
    clock.remaining()
    maximum = NATIVE_MAX_FRAME_BYTES if selected_native else MAX_FRAME_BYTES
    # Prepare fallible transport state before creating the owned child.
    output = bytearray()
    sent = 0
    eof = False
    exit_code = None
    process = subprocess.Popen(
        [sys.executable, '-I', '-B', str(_WORKER), str(request_fd), str(os.getpid())],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        pass_fds=(request_fd,), close_fds=True, start_new_session=True,
        cwd=_ROOT, env=environment, bufsize=0)
    try:
        with selectors.DefaultSelector() as ready:
            os.set_blocking(process.stdin.fileno(), False)
            os.set_blocking(process.stdout.fileno(), False)
            ready.register(process.stdin, selectors.EVENT_WRITE, 'input')
            ready.register(process.stdout, selectors.EVENT_READ, 'output')
            while True:
                remaining = clock.remaining()
                exit_code = _unreaped_exit(process)
                if exit_code is not None and (exit_code != 0 or sent != len(context)):
                    raise _Refusal('worker_failed')
                if exit_code == 0 and sent == len(context) and eof:
                    break
                for event, _ in ready.select(min(remaining, 0.05)):
                    clock.remaining()
                    if event.data == 'input':
                        try:
                            count = os.write(event.fd, memoryview(context)[sent:])
                        except BlockingIOError:
                            continue
                        if type(count) is not int or not 0 < count <= len(context) - sent:
                            raise _Refusal('context_incomplete')
                        sent += count
                        if sent == len(context):
                            ready.unregister(process.stdin)
                            process.stdin.close()
                    else:
                        try:
                            chunk = os.read(event.fd, min(65536, maximum + 1 - len(output)))
                        except BlockingIOError:
                            continue
                        if not chunk:
                            ready.unregister(process.stdout)
                            process.stdout.close()
                            eof = True
                        else:
                            output.extend(chunk)
                            if len(output) > maximum:
                                raise _Refusal('output_budget')
            clock.remaining()
    finally:
        reaped = _finish_child(process)
    if exit_code != 0 or reaped != 0 or sent != len(context) or not eof:
        raise _Refusal('worker_failed')
    return bytes(output)


def execute_supervised_pdf_inspection(
    request_fd: object, *, expected_context: object,
    expected_supervisor_profile_sha256: str,
) -> bytes:
    """Run one fixed worker and return only its fully validated original result bytes.

    Expectations must be independently resolved from authenticated job state.
    Request seals and matching hashes do not authenticate that state. The owned
    descriptor duplicate survives dispatch while the borrowed offset/ownership
    remain unchanged. No arbitrary command, environment, deadline, retry, result
    receipt, publication or service operation is accepted through this boundary.
    """
    owned = None
    identity = None
    try:
        selected_native = _profile(expected_supervisor_profile_sha256)
        clock = _Clock()
        context = worker._parse_context(expected_context)
        if (context['expected_worker_profile_sha256'] !=
                (NATIVE_WORKER_PROFILE_SHA256 if selected_native else WORKER_PROFILE_SHA256)
                or context['expected_frame_profile_sha256'] !=
                (NATIVE_FRAME_PROFILE_SHA256 if selected_native else FRAME_PROFILE_SHA256)):
            raise _Refusal('profile_invalid')
        environment = _environment()
        if type(request_fd) is not int or not 3 <= request_fd <= 2**31 - 1:
            raise _Refusal('input_invalid')
        before = descriptor._identity(descriptor._descriptor(request_fd))
        owned = fcntl.fcntl(request_fd, fcntl.F_DUPFD_CLOEXEC, 3)
        info = os.fstat(owned)
        identity = (info.st_dev, info.st_ino)
        if descriptor._identity(descriptor._descriptor(owned)) != before or os.get_inheritable(owned):
            raise _Refusal('input_changed')
        arguments = descriptor.read_sealed_pdf_request(owned,
            **{key: context[key] for key in _DESCRIPTOR_KEYS})
        for expected, actual in (('expected_pdf_sha256', 'expected_pdf_sha256'),
                                 ('expected_ir_sha256', 'expected_ir_sha256'),
                                 ('expected_page_count', 'page_count'),
                                 ('expected_language', 'expected_language'),
                                 ('expected_resource_profile_sha256', 'expected_resource_profile_sha256')):
            if context[expected] != arguments[actual]:
                raise _Refusal('input_invalid')
        del arguments
        clock.remaining()
        if selected_native:
            output = _exchange(owned, expected_context, environment, clock, selected_native=True)
        else:
            output = _exchange(owned, expected_context, environment, clock)
        result = frame.decode_pdf_inspection_result_frame(output,
            **{key: context[key] for key in RESULT_KEYS})
        _profile(expected_supervisor_profile_sha256)
        if _environment() != environment:
            raise _Refusal('policy_changed')
        if (descriptor._identity(descriptor._descriptor(owned)) != before
                or descriptor._identity(descriptor._descriptor(request_fd)) != before):
            raise _Refusal('input_changed')
        clock.remaining()
        return result
    except _Refusal as error:
        raise PdfSupervisedInspectionError('pdf_supervised_inspection_' + str(error)) from None
    except Exception:
        raise PdfSupervisedInspectionError('pdf_supervised_inspection_failed') from None
    finally:
        if owned is not None:
            try:
                descriptor._close_owned(owned, identity)
            except Exception:
                raise PdfSupervisedInspectionError('pdf_supervised_inspection_cleanup_unresolved') from None
