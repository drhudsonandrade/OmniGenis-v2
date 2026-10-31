"""Real direct-worker lifetime regressions; signal mutations stay in children."""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest

from reporting import _pdf_fixed_inspection_worker as worker
from reporting.page_checkpoints import _json_bytes
from tests import test_reporting_pdf_fixed_inspection_worker as prior


ROOT = Path(__file__).resolve().parents[1]


def lifetime_child(request_fd: int, report_fd: int, mode: str, inherited: str) -> int:
    """Exercise the real entrypoint with shortened real syscalls in a disposable child."""
    real_timer = signal.setitimer
    real_gettimer = signal.getitimer
    real_signal = signal.signal
    real_mask = signal.pthread_sigmask

    def report(event, **values):
        """Write bounded test observations to a separate anonymous file, never stdout."""
        os.write(report_fd, _json_bytes({'event': event, **values}) + b'\n')

    if inherited in ('ignored', 'both'):
        real_signal(signal.SIGALRM, signal.SIG_IGN)
    if inherited in ('blocked', 'both'):
        real_mask(signal.SIG_BLOCK, {signal.SIGALRM})
    if mode == 'existing_timer':
        real_timer(signal.ITIMER_REAL, 5)
    if mode.startswith('bound_'):
        worker.WORKER_WALL_SECONDS = {'bound_bool': True, 'bound_float': 300.0,
                                      'bound_larger': 301, 'bound_zero': 0}[mode]
    if mode == 'profile_pin':
        worker.WORKER_LIFETIME_PROFILE_SHA256 = '0' * 64
    if mode == 'profile_body':
        worker.worker_lifetime_profile = lambda: {'unexpected': True}
    if mode == 'structured_bound':
        worker.structured.ACCEPTANCE_NS = 301_000_000_000
    if mode == 'native_bound':
        worker.native.ACCEPTANCE_NS = 301_000_000_000

    def disposition(number, action):
        """Keep actual disposition changes and inject only the requested syscall failure."""
        report('disposition', number=int(number), default=action == signal.SIG_DFL)
        if mode == 'fail_disposition':
            raise OSError('test disposition failure')
        return real_signal(number, action)

    def mask(how, values):
        """Keep actual signal-mask changes and expose their ordering."""
        report('mask', how=int(how), signals=sorted(int(item) for item in values))
        if mode == 'fail_mask':
            raise OSError('test mask failure')
        return real_mask(how, values)

    def gettimer(which):
        """Observe the real preexisting timer unless this syscall is the fault target."""
        if mode == 'fail_observation':
            raise OSError('test observation failure')
        return real_gettimer(which)

    def arm(which, seconds, interval=0.0):
        """Record the exact production interval and shorten only this disposable timer."""
        report('arm', which=int(which), seconds=seconds, interval=interval)
        if mode == 'fail_arm':
            raise OSError('test timer failure')
        if mode == 'negative_control':
            return real_gettimer(which)
        shortened = 5.0 if mode == 'complete' else 0.4
        return real_timer(which, shortened if seconds else 0, interval)

    signal.signal = disposition
    signal.pthread_sigmask = mask
    signal.getitimer = gettimer
    signal.setitimer = arm
    original_admission = worker._open_kernel_admission
    original_read = worker._read_pipe
    original_write = worker._write_frame

    def read():
        """Expose readiness immediately before the production blocking context read."""
        report('context')
        return original_read()

    def admission(fd):
        """Observe ordering and supply cleanup only for isolated lifecycle-stage cases."""
        report('admission')
        if mode in ('output', 'cleanup', 'complete'):
            return SimpleNamespace(recheck=lambda: report('recheck'), close=close)
        return original_admission(fd)

    def close():
        """Keep a real pending alarm visible during owned-admission cleanup."""
        report('cleanup', remaining=real_gettimer(signal.ITIMER_REAL)[0])
        if mode == 'cleanup':
            signal.pause()
        return True

    def inspect(*args, **kwargs):
        """Replace unrelated native inspection while retaining the real lifecycle path."""
        report('work', remaining=real_gettimer(signal.ITIMER_REAL)[0])
        return SimpleNamespace(to_bytes=lambda: b'original')

    def encode(*args, **kwargs):
        """Produce finite test bytes without replacing production pipe handling."""
        report('encode', remaining=real_gettimer(signal.ITIMER_REAL)[0])
        return b'x' * 65536 if mode == 'output' else b'frame'

    def write(data, selected_native=False):
        """Expose readiness immediately before the production blocking frame write."""
        report('write', remaining=real_gettimer(signal.ITIMER_REAL)[0])
        return original_write(data, selected_native)

    worker._open_kernel_admission = admission
    worker._read_pipe = read
    worker._write_frame = write
    if mode in ('output', 'cleanup', 'complete'):
        worker.sealed.execute_sealed_pdf_inspection_job = inspect
        worker.frame.encode_pdf_inspection_result_frame = encode
        worker.frame.decode_pdf_inspection_result_frame = lambda *args, **kwargs: b'original'
    sys.argv = ['worker', str(request_fd), str(os.getppid())]
    status = worker._entrypoint()
    parent_signal = ctypes.c_int()
    library = ctypes.CDLL(None)
    if library.prctl(2, ctypes.byref(parent_signal), 0, 0, 0) != 0:
        raise RuntimeError('test parent-death observation failed')
    report('return', status=status, remaining=real_gettimer(signal.ITIMER_REAL)[0],
           parent_signal=parent_signal.value)
    return status



def parent_death_worker(request_fd: int, report_fd: int,
                        expected_parent: int, guarded: bool) -> int:
    """Enter the real worker; observe its registered lifetime before the real read."""
    original_read = worker._read_pipe

    def read():
        """Remove only PDEATHSIG for the control, leaving the 300-second timer intact."""
        library = ctypes.CDLL(None, use_errno=True)
        if not guarded and library.prctl(1, 0, 0, 0, 0) != 0:
            raise RuntimeError('test parent-death removal failed')
        parent_signal = ctypes.c_int()
        if library.prctl(2, ctypes.byref(parent_signal), 0, 0, 0) != 0:
            raise RuntimeError('test parent-death observation failed')
        remaining, interval = signal.getitimer(signal.ITIMER_REAL)
        report = {'pid': os.getpid(), 'parent': os.getppid(),
                  'parent_signal': parent_signal.value, 'remaining': remaining,
                  'interval': interval, 'observed_at': time.monotonic()}
        os.write(report_fd, _json_bytes(report))
        return original_read()

    worker._read_pipe = read
    sys.argv = ['worker', str(request_fd), str(expected_parent)]
    return worker._entrypoint()


def parent_death_parent(request_fd: int, context_read: int, output_write: int,
                        ready_write: int, error_fd: int, guarded: bool) -> None:
    """Own setup cleanup until the observer pins the child and kills this parent."""
    args = (request_fd, ready_write, os.getpid(), guarded)
    code = ('import sys;sys.path.insert(0,' + repr(str(ROOT)) + ');'
            'from tests.test_reporting_pdf_fixed_worker_lifetime import parent_death_worker;'
            'raise SystemExit(parent_death_worker(*' + repr(args) + '))')
    child = subprocess.Popen([sys.executable, '-I', '-B', '-c', code],
        stdin=context_read, stdout=output_write, stderr=error_fd,
        pass_fds=(request_fd, ready_write), close_fds=True)
    try:
        print(child.pid, flush=True)
        sys.stdin.buffer.read(1)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=3)


def parent_death_probe(request_fd: int, guarded: bool) -> dict:
    """Observe an adopted worker before rescue, inside a disposable subreaper."""
    if ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) != 0:
        raise RuntimeError('test subreaper unavailable')
    context_read, context_write = os.pipe()
    output_read, output_write = os.pipe()
    ready_read, ready_write = os.pipe()
    parent = None
    worker_fd = None
    worker_pid = None
    reaped = False
    descriptors = [context_read, context_write, output_read, output_write,
                   ready_read, ready_write]
    with tempfile.TemporaryFile() as errors:
        args = (request_fd, context_read, output_write, ready_write,
                errors.fileno(), guarded)
        parent_code = ('import sys;sys.path.insert(0,' + repr(str(ROOT)) + ');'
                       'from tests.test_reporting_pdf_fixed_worker_lifetime '
                       'import parent_death_parent;parent_death_parent(*' + repr(args) + ')')
        try:
            parent = subprocess.Popen([sys.executable, '-I', '-B', '-c', parent_code],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors,
                pass_fds=(request_fd, context_read, output_write, ready_write,
                          errors.fileno()), cwd=ROOT,
                env={'PATH': os.defpath, 'LANG': 'C.UTF-8'})
            # Only this observer retains a writer; killing the parent cannot supply EOF.
            for fd in (context_read, output_write, ready_write):
                os.close(fd)
                descriptors.remove(fd)
            if not select.select([parent.stdout], [], [], 30)[0]:
                raise RuntimeError('test worker identity missing')
            worker_pid = int(parent.stdout.readline(128))
            worker_fd = os.pidfd_open(worker_pid)
            if not select.select([ready_read], [], [], 30)[0]:
                raise RuntimeError('test worker readiness missing')
            ready = json.loads(os.read(ready_read, 4096))
            if (ready['pid'] != worker_pid or ready['parent'] != parent.pid
                    or parent.poll() is not None
                    or select.select([worker_fd], [], [], 0)[0]):
                raise RuntimeError('test ready worker or immediate parent is not live')
            if (not 0 < ready['remaining'] <= 300 or ready['interval'] != 0
                    or ready['remaining'] - (time.monotonic() - ready['observed_at']) <= 10):
                raise RuntimeError('test independent timer margin missing')
            # Do not signal the group: only this abrupt direct-parent death is the event.
            parent.kill()
            parent.wait(timeout=3)
            if parent.returncode != -signal.SIGKILL:
                raise RuntimeError('test immediate parent was not killed')
            exited = bool(select.select([worker_fd], [], [], 2)[0])
            elapsed = time.monotonic() - ready['observed_at']
            if elapsed >= ready['remaining']:
                raise RuntimeError('test observation crossed the independent timer')
            status = None
            if exited:
                status = os.waitid(os.P_PIDFD, worker_fd, os.WEXITED | os.WNOHANG)
                if status is None or status.si_pid != worker_pid:
                    raise RuntimeError('test adopted worker was not reaped')
                reaped = True
            # The result is fixed before the finally block can kill a surviving control.
            result = {'ready': ready, 'parent_killed': True, 'exited': exited,
                      'exit_code': status.si_code if status else None,
                      'exit_signal': status.si_status if status else None,
                      'observation_seconds': elapsed}
        finally:
            if parent is not None:
                if worker_fd is None:
                    # Before pinned identity, let the still-owning parent clean up its child.
                    parent.stdin.close()
                    parent.wait(timeout=3)
                else:
                    if parent.poll() is None:
                        parent.kill()
                    parent.wait(timeout=3)
                if not parent.stdin.closed:
                    parent.stdin.close()
                parent.stdout.close()
            if worker_fd is not None:
                try:
                    if not reaped:
                        try:
                            signal.pidfd_send_signal(worker_fd, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        if not select.select([worker_fd], [], [], 3)[0]:
                            raise RuntimeError('test worker rescue timed out')
                        status = os.waitid(os.P_PIDFD, worker_fd, os.WEXITED | os.WNOHANG)
                        if status is None or status.si_pid != worker_pid:
                            raise RuntimeError('test worker rescue did not reap its child')
                finally:
                    os.close(worker_fd)
            for fd in descriptors:
                os.close(fd)
        errors.seek(0)
        diagnostic = errors.read(16384)
        if diagnostic:
            raise RuntimeError(diagnostic.decode('utf-8', 'replace'))
        return result


def registration_race_worker(request_fd: int, observations_fd: int,
                             ready_write: int, release_read: int,
                             expected_parent: int, recheck_parent: bool) -> int:
    """Delay the real libc return until this disposable worker loses its parent."""
    real_cdll = ctypes.CDLL
    real_getppid = os.getppid
    parent_checks = []
    original_admission = worker._open_kernel_admission
    original_read = worker._read_pipe
    original_work = worker.sealed.execute_sealed_pdf_inspection_job
    original_write = worker._write_frame

    def report(event, **values):
        """Record lifecycle observations separately from the worker's output."""
        os.write(observations_fd, _json_bytes({'event': event, **values}) + b'\n')

    def parent_signal():
        """Read the real parent-death signal through a fresh libc function object."""
        # A fresh function object avoids production's c_ulong argument declaration.
        library = real_cdll(None, use_errno=True)
        value = ctypes.c_int()
        if library.prctl(2, ctypes.byref(value), 0, 0, 0) != 0:
            raise RuntimeError('test parent-death observation failed')
        return value.value

    def getppid():
        """Observe real parents and falsify only the control's second return."""
        actual = real_getppid()
        sequence = len(parent_checks) + 1
        returned = expected_parent if sequence == 2 and not recheck_parent else actual
        parent_checks.append(actual)
        if sequence == 2:
            os.getppid = real_getppid
        report('parent_check', sequence=sequence, actual=actual, returned=returned)
        return returned

    def library(name, *args, **kwargs):
        """Return real libc after the observer releases the parent-loss handshake."""
        value = real_cdll(name, *args, **kwargs)
        ctypes.CDLL = real_cdll
        if (name is not None or args or kwargs != {'use_errno': True}
                or parent_checks != [expected_parent]):
            raise RuntimeError('test registration boundary was not reached')
        ready = {'pid': os.getpid(), 'parent': real_getppid(),
                 'first_parent': parent_checks[0], 'parent_signal': parent_signal()}
        report('ready', **ready)
        os.write(ready_write, _json_bytes(ready))
        os.close(ready_write)
        if (not select.select([release_read], [], [], 30)[0]
                or os.read(release_read, 1) != b'R'):
            raise RuntimeError('test registration release missing')
        os.close(release_read)
        report('released', parent=real_getppid(), parent_signal=parent_signal())
        return value

    def admission(*args, **kwargs):
        """Record admission and delegate to the unchanged production function."""
        report('admission')
        return original_admission(*args, **kwargs)

    def read():
        """Record context access and delegate to the real pipe reader."""
        report('context')
        return original_read()

    def inspect(*args, **kwargs):
        """Record sealed work and delegate to the unchanged production function."""
        report('work')
        return original_work(*args, **kwargs)

    def write(*args, **kwargs):
        """Record frame output and delegate to the real frame writer."""
        report('write')
        return original_write(*args, **kwargs)

    os.getppid = getppid
    ctypes.CDLL = library
    worker._open_kernel_admission = admission
    worker._read_pipe = read
    worker.sealed.execute_sealed_pdf_inspection_job = inspect
    worker._write_frame = write
    sys.argv = ['worker', str(request_fd), str(expected_parent)]
    status = worker._entrypoint()
    ctypes.CDLL = real_cdll
    os.getppid = real_getppid
    remaining, interval = signal.getitimer(signal.ITIMER_REAL)
    report('return', status=status, parent=real_getppid(),
           parent_signal=parent_signal(), remaining=remaining, interval=interval)
    return status


def registration_race_parent(request_fd: int, context_read: int, output_write: int,
                             observations_fd: int, ready_write: int,
                             release_read: int, error_fd: int,
                             recheck_parent: bool) -> None:
    """Retain child ownership until the observer pins it and kills this parent."""
    args = (request_fd, observations_fd, ready_write, release_read,
            os.getpid(), recheck_parent)
    code = ('import sys;sys.path.insert(0,' + repr(str(ROOT)) + ');'
            'from tests.test_reporting_pdf_fixed_worker_lifetime import registration_race_worker;'
            'raise SystemExit(registration_race_worker(*' + repr(args) + '))')
    child = subprocess.Popen([sys.executable, '-I', '-B', '-c', code],
        stdin=context_read, stdout=output_write, stderr=error_fd,
        pass_fds=(request_fd, observations_fd, ready_write, release_read), close_fds=True)
    try:
        print(child.pid, flush=True)
        sys.stdin.buffer.read(1)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=3)


def registration_race_probe(request_fd: int, recheck_parent: bool) -> dict:
    """Order real parent death before registration and observe before any rescue."""
    if ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) != 0:
        raise RuntimeError('test subreaper unavailable')
    context_read, context_write = os.pipe()
    os.close(context_write)  # The control must naturally reject an empty real FIFO.
    output_read, output_write = os.pipe()
    ready_read, ready_write = os.pipe()
    release_read, release_write = os.pipe()
    descriptors = [context_read, output_read, output_write, ready_read, ready_write,
                   release_read, release_write]
    parent = None
    worker_fd = None
    worker_pid = None
    reaped = False
    with tempfile.TemporaryFile() as errors, tempfile.TemporaryFile() as observations:
        args = (request_fd, context_read, output_write, observations.fileno(),
                ready_write, release_read, errors.fileno(), recheck_parent)
        code = ('import sys;sys.path.insert(0,' + repr(str(ROOT)) + ');'
                'from tests.test_reporting_pdf_fixed_worker_lifetime '
                'import registration_race_parent;registration_race_parent(*' + repr(args) + ')')
        try:
            parent = subprocess.Popen([sys.executable, '-I', '-B', '-c', code],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors,
                pass_fds=(request_fd, context_read, output_write, observations.fileno(),
                          ready_write, release_read, errors.fileno()), cwd=ROOT,
                env={'PATH': os.defpath, 'LANG': 'C.UTF-8'})
            # The release writer belongs only to this observer, never the parent/worker.
            for fd in (context_read, output_write, ready_write, release_read):
                os.close(fd)
                descriptors.remove(fd)
            if not select.select([parent.stdout], [], [], 30)[0]:
                raise RuntimeError('test registration worker identity missing')
            worker_pid = int(parent.stdout.readline(128))
            worker_fd = os.pidfd_open(worker_pid)
            if not select.select([ready_read], [], [], 30)[0]:
                raise RuntimeError('test registration boundary readiness missing')
            ready = json.loads(os.read(ready_read, 4096))
            if (ready['pid'] != worker_pid or ready['parent'] != parent.pid
                    or ready['first_parent'] != parent.pid or ready['parent_signal'] != 0
                    or parent.poll() is not None
                    or select.select([worker_fd], [], [], 0)[0]):
                raise RuntimeError('test initial live parent/worker registration boundary invalid')
            parent.kill()
            parent.wait(timeout=3)
            if parent.returncode != -signal.SIGKILL:
                raise RuntimeError('test immediate parent was not killed')
            if select.select([worker_fd], [], [], 0)[0]:
                raise RuntimeError('test worker exited before registration release')
            os.write(release_write, b'R')
            os.close(release_write)
            descriptors.remove(release_write)
            exited = bool(select.select([worker_fd], [], [], 30)[0])
            status = None
            if exited:
                status = os.waitid(os.P_PIDFD, worker_fd, os.WEXITED | os.WNOHANG)
                if status is None or status.si_pid != worker_pid:
                    raise RuntimeError('test adopted registration worker was not reaped')
                reaped = True
            events = [json.loads(line) for line in
                      os.pread(observations.fileno(), 16384, 0).splitlines()]
            # Freeze all behavioral observations before cleanup can signal the worker.
            result = {'ready': ready, 'observer_pid': os.getpid(), 'parent_killed': True,
                      'worker_alive_before_release': True, 'exited': exited,
                      'exit_code': status.si_code if status else None,
                      'exit_status': status.si_status if status else None, 'events': events,
                      'output_hex': os.read(output_read, 65537).hex() if exited else None}
        finally:
            try:
                if parent is not None:
                    try:
                        if worker_fd is None:
                            parent.stdin.close()
                        elif parent.poll() is None:
                            parent.kill()
                        parent.wait(timeout=3)
                    finally:
                        if not parent.stdin.closed:
                            parent.stdin.close()
                        parent.stdout.close()
            finally:
                try:
                    if worker_fd is not None:
                        try:
                            if not reaped:
                                try:
                                    signal.pidfd_send_signal(worker_fd, signal.SIGKILL)
                                except ProcessLookupError:
                                    pass
                                if not select.select([worker_fd], [], [], 3)[0]:
                                    raise RuntimeError('test registration worker rescue timed out')
                                status = os.waitid(os.P_PIDFD, worker_fd, os.WEXITED | os.WNOHANG)
                                if status is None or status.si_pid != worker_pid:
                                    raise RuntimeError('test registration worker rescue did not reap')
                        finally:
                            os.close(worker_fd)
                finally:
                    for fd in descriptors:
                        os.close(fd)
        diagnostic = os.pread(errors.fileno(), 16384, 0)
        if diagnostic:
            raise RuntimeError(diagnostic.decode('utf-8', 'replace'))
        return result


class FixedWorkerLifetimeTests(unittest.TestCase):
    """Observe direct-worker lifecycle before fixture rescue, with real pipes."""

    def setUp(self):
        """Reuse the existing independently bound sealed request fixture."""
        self.fixture = prior.FixedInspectionWorkerTests()
        self.fixture.setUp()


    @unittest.skipUnless(
        sys.platform == 'linux' and hasattr(os, 'pidfd_open')
        and hasattr(os, 'P_PIDFD') and hasattr(os, 'waitid')
        and hasattr(signal, 'pidfd_send_signal')
        and hasattr(ctypes.CDLL(None), 'prctl'),
        'Linux pidfd and subreaper facilities required')
    def parent_death(self, guarded=True):
        """Keep the probe group owned until success or bounded fallback cleanup."""
        with self.fixture.h.request() as (fd, _, _, _), \
                tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            code = ('import json,sys;sys.path.insert(0,' + repr(str(ROOT)) + ');'
                    'from tests.test_reporting_pdf_fixed_worker_lifetime import parent_death_probe;'
                    'print(json.dumps(parent_death_probe(' + repr(fd) + ','
                    + repr(guarded) + ')))')
            process = subprocess.Popen([sys.executable, '-I', '-B', '-c', code],
                stdin=subprocess.DEVNULL, stdout=output, stderr=errors, pass_fds=(fd,),
                cwd=ROOT, start_new_session=True,
                env={'PATH': os.defpath, 'LANG': 'C.UTF-8'})
            probe_fd = None
            try:
                probe_fd = os.pidfd_open(process.pid)
                finished = bool(select.select([probe_fd], [], [], 80)[0])
                status = (os.waitid(os.P_PIDFD, probe_fd,
                                   os.WEXITED | os.WNOWAIT | os.WNOHANG)
                          if finished else None)
                if (status is None or status.si_code != os.CLD_EXITED
                        or status.si_status != 0):
                    # The unreaped group leader keeps this fallback bound to the fixture.
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)
                diagnostic = os.pread(errors.fileno(), 16384, 0).decode('utf-8', 'replace')
                self.assertTrue(finished, 'parent-death probe timed out: ' + diagnostic)
                self.assertEqual(process.returncode, 0, diagnostic)
                return json.loads(os.pread(output.fileno(), 16384, 0))
            finally:
                if process.returncode is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=3)
                if probe_fd is not None:
                    os.close(probe_fd)

    def test_registered_worker_terminates_after_immediate_parent_death(self):
        """The real ready worker dies by SIGKILL before rescue or its independent timer."""
        result = self.parent_death()
        self.assertTrue(result['parent_killed'])
        self.assertTrue(result['exited'], 'worker survived until fixture rescue')
        self.assertEqual(result['ready']['parent_signal'], signal.SIGKILL)
        self.assertEqual(result['exit_code'], os.CLD_KILLED)
        self.assertEqual(result['exit_signal'], signal.SIGKILL)

    def test_disabling_only_parent_death_signal_keeps_worker_alive(self):
        """A retained external writer and real timer cannot hide a missing parent guard."""
        result = self.parent_death(guarded=False)
        self.assertTrue(result['parent_killed'])
        self.assertEqual(result['ready']['parent_signal'], 0)
        self.assertFalse(result['exited'], 'control exited before fixture rescue')
        self.assertIsNone(result['exit_code'])
        self.assertIsNone(result['exit_signal'])


    @unittest.skipUnless(
        sys.platform == 'linux' and hasattr(os, 'pidfd_open')
        and hasattr(os, 'P_PIDFD') and hasattr(os, 'waitid')
        and hasattr(signal, 'pidfd_send_signal')
        and hasattr(ctypes.CDLL(None), 'prctl'),
        'Linux pidfd and subreaper facilities required')
    def registration_race(self, recheck_parent=True):
        """Keep a separate observer group owned through bounded failure cleanup."""
        with self.fixture.h.request() as (fd, _, _, _), \
                tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            code = ('import json,sys;sys.path.insert(0,' + repr(str(ROOT)) + ');'
                    'from tests.test_reporting_pdf_fixed_worker_lifetime import registration_race_probe;'
                    'print(json.dumps(registration_race_probe(' + repr(fd) + ','
                    + repr(recheck_parent) + ')))')
            process = subprocess.Popen([sys.executable, '-I', '-B', '-c', code],
                stdin=subprocess.DEVNULL, stdout=output, stderr=errors, pass_fds=(fd,),
                cwd=ROOT, start_new_session=True,
                env={'PATH': os.defpath, 'LANG': 'C.UTF-8'})
            probe_fd = None
            try:
                probe_fd = os.pidfd_open(process.pid)
                finished = bool(select.select([probe_fd], [], [], 120)[0])
                status = (os.waitid(os.P_PIDFD, probe_fd,
                                   os.WEXITED | os.WNOWAIT | os.WNOHANG)
                          if finished else None)
                if (status is None or status.si_code != os.CLD_EXITED
                        or status.si_status != 0):
                    # An unreaped leader keeps the fallback bound to this fixture group.
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)
                diagnostic = os.pread(errors.fileno(), 16384, 0).decode('utf-8', 'replace')
                self.assertTrue(finished, 'registration-race probe timed out: ' + diagnostic)
                self.assertEqual(process.returncode, 0, diagnostic)
                return json.loads(os.pread(output.fileno(), 16384, 0))
            finally:
                if process.returncode is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=3)
                if probe_fd is not None:
                    os.close(probe_fd)

    def assert_registration_observation(self, result):
        """Reject early fixture failures, timer deaths and rescue-derived outcomes."""
        self.assertTrue(result['parent_killed'])
        self.assertTrue(result['worker_alive_before_release'])
        self.assertTrue(result['exited'], 'worker survived until fixture rescue')
        self.assertEqual(result['exit_code'], os.CLD_EXITED)
        self.assertEqual(result['exit_status'], 70)
        self.assertEqual(result['output_hex'], '')
        events = result['events']
        checks = [item for item in events if item['event'] == 'parent_check']
        self.assertEqual([item['sequence'] for item in checks], [1, 2])
        original_parent = result['ready']['parent']
        self.assertEqual(checks[0]['actual'], original_parent)
        self.assertEqual(checks[0]['returned'], original_parent)
        self.assertEqual(checks[1]['actual'], result['observer_pid'])
        self.assertNotEqual(original_parent, result['observer_pid'])
        self.assertEqual(result['ready']['first_parent'], original_parent)
        self.assertEqual(result['ready']['parent_signal'], 0)
        released = [item for item in events if item['event'] == 'released']
        self.assertEqual(released, [{'event': 'released', 'parent': result['observer_pid'],
                                     'parent_signal': 0}])
        terminal = [item for item in events if item['event'] == 'return']
        self.assertEqual(len(terminal), 1)
        self.assertEqual(terminal[0]['status'], 70)
        self.assertEqual(terminal[0]['parent'], result['observer_pid'])
        self.assertEqual(terminal[0]['parent_signal'], signal.SIGKILL)
        self.assertEqual(terminal[0]['interval'], 0)
        self.assertEqual(events[-1], terminal[0])
        self.assertNotIn('work', [item['event'] for item in events])
        self.assertNotIn('write', [item['event'] for item in events])
        return checks, terminal[0]

    def test_parent_change_during_registration_refuses_before_admission(self):
        """Real parent loss during registration cannot reach admission or context."""
        result = self.registration_race()
        names = [item['event'] for item in result['events']]
        self.assertNotIn('admission', names)
        self.assertNotIn('context', names)
        checks, terminal = self.assert_registration_observation(result)
        self.assertEqual(checks[1]['returned'], result['observer_pid'])
        self.assertEqual(terminal['remaining'], 0)

    def test_disabling_post_registration_parent_check_reaches_admission(self):
        """Only falsifying the second parent observation admits the empty context."""
        result = self.registration_race(recheck_parent=False)
        checks, terminal = self.assert_registration_observation(result)
        names = [item['event'] for item in result['events']]
        self.assertIn('admission', names)
        self.assertIn('context', names)
        self.assertLess(names.index('admission'), names.index('context'))
        self.assertEqual(checks[1]['returned'], result['ready']['parent'])
        self.assertGreater(terminal['remaining'], 0)
        self.assertLessEqual(terminal['remaining'], 300)


    def probe(self, mode='read', inherited='default'):
        """Run the real worker entrypoint, keeping context or output blocked as selected."""
        with self.fixture.h.request() as (fd, expected, args, _), \
                tempfile.TemporaryFile() as observations:
            code = ('import sys;sys.path.insert(0,' + repr(str(ROOT)) + ');'
                    'from tests.test_reporting_pdf_fixed_worker_lifetime import lifetime_child;'
                    'raise SystemExit(lifetime_child(' + repr(fd) + ','
                    + repr(observations.fileno()) + ',' + repr(mode) + ','
                    + repr(inherited) + '))')
            process = subprocess.Popen([sys.executable, '-I', '-B', '-c', code],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                pass_fds=(fd, observations.fileno()), cwd=ROOT, pipesize=4096,
                env={'PATH': os.defpath, 'LANG': 'C.UTF-8'})
            try:
                if mode in ('output', 'cleanup', 'complete'):
                    context = _json_bytes(self.fixture.context(expected, args))
                    process.stdin.write(context)
                    process.stdin.close()
                try:
                    process.wait(timeout=3)
                    observed_exit = True
                except subprocess.TimeoutExpired:
                    observed_exit = False
                # Capture this before rescue: a fixture SIGKILL is never timer evidence.
                returncode = process.returncode
                events = [json.loads(line) for line in
                          os.pread(observations.fileno(), 16384, 0).splitlines()]
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=3)
                if not process.stdin.closed:
                    process.stdin.close()
                output = process.stdout.read(65537)
                errors = process.stderr.read(16384)
                process.stdout.close()
                process.stderr.close()
            self.assertEqual(errors, b'', errors.decode('utf-8', 'replace'))
            return {'exited': observed_exit, 'returncode': returncode,
                    'events': events, 'output': output}

    def assert_timer_exit(self, result, stage):
        """Require a real SIGALRM exit and the fixed production syscall arguments."""
        self.assertIn(stage, [item['event'] for item in result['events']])
        self.assertTrue(result['exited'], 'worker remained blocked until fixture rescue')
        self.assertEqual(result['returncode'], -signal.SIGALRM)
        attempts = [item for item in result['events'] if item['event'] == 'arm']
        self.assertEqual(attempts, [{'event': 'arm', 'which': int(signal.ITIMER_REAL),
                                    'seconds': 300, 'interval': 0.0}])

    def test_blocked_context_terminates_with_parent_alive(self):
        """Removing timer setup leaves this real read blocked until fixture rescue."""
        result = self.probe()
        self.assert_timer_exit(result, 'context')
        self.assertEqual(result['output'], b'')

    def test_ignored_and_blocked_alarm_are_repaired(self):
        """Inherited SIG_IGN or a blocked SIGALRM cannot neutralize the independent timer."""
        for inherited in ('ignored', 'blocked', 'both'):
            with self.subTest(inherited=inherited):
                result = self.probe(inherited=inherited)
                self.assert_timer_exit(result, 'context')
                self.assertEqual(result['output'], b'')

    def test_real_blocking_output_terminates_without_parent_drain(self):
        """A partial prefix does not turn a timer-terminated blocked write into success."""
        result = self.probe(mode='output')
        self.assert_timer_exit(result, 'write')
        self.assertGreater(len(result['output']), 0)
        self.assertLess(len(result['output']), 65536)
        self.assertNotIn('return', [item['event'] for item in result['events']])

    def test_cleanup_remains_inside_the_same_timer(self):
        """A complete frame does not authorize success when owned cleanup stalls."""
        result = self.probe(mode='cleanup')
        self.assert_timer_exit(result, 'cleanup')
        self.assertEqual(result['output'], b'frame')

    def test_disabling_only_the_timer_keeps_the_negative_control_alive(self):
        """The live parent and fixture do not themselves terminate a stalled worker."""
        result = self.probe(mode='negative_control')
        self.assertIn('context', [item['event'] for item in result['events']])
        self.assertFalse(result['exited'])
        self.assertIsNone(result['returncode'])
        self.assertEqual(result['output'], b'')

    def test_timer_setup_faults_refuse_before_admission_and_context(self):
        """Each failed timer observation or installation syscall forbids later work."""
        for mode in ('fail_observation', 'fail_disposition', 'fail_mask', 'fail_arm'):
            with self.subTest(mode=mode):
                result = self.probe(mode=mode)
                self.assertTrue(result['exited'], 'setup fault was ignored')
                self.assertEqual(result['returncode'], 70)
                self.assertEqual(result['output'], b'')
                names = [item['event'] for item in result['events']]
                self.assertNotIn('admission', names)
                self.assertNotIn('context', names)

    def test_existing_timer_is_refused_without_replacement(self):
        """An already armed shorter timer cannot be overwritten by the 300-second bound."""
        result = self.probe(mode='existing_timer')
        self.assertTrue(result['exited'], 'preexisting timer was ignored')
        self.assertEqual(result['returncode'], 70)
        self.assertEqual(result['output'], b'')
        self.assertEqual([item['event'] for item in result['events']], ['return'])
        self.assertGreater(result['events'][0]['remaining'], 0)
        self.assertLessEqual(result['events'][0]['remaining'], 5)

    def test_lifetime_policy_drift_refuses_before_admission(self):
        """Changing the bound, policy pin/body or either family allowance fails closed."""
        for mode in ('bound_bool', 'bound_float', 'bound_larger', 'bound_zero',
                     'profile_pin', 'profile_body', 'structured_bound', 'native_bound'):
            with self.subTest(mode=mode):
                result = self.probe(mode=mode)
                self.assertTrue(result['exited'], 'changed lifetime policy was ignored')
                self.assertEqual(result['returncode'], 70)
                self.assertEqual(result['output'], b'')
                self.assertEqual([item['event'] for item in result['events']], ['return'])

    def test_success_keeps_one_timer_through_work_write_cleanup_and_return(self):
        """Resetting or cancelling the timer in any later phase breaks the observed lifetime."""
        result = self.probe(mode='complete')
        self.assertTrue(result['exited'])
        self.assertEqual(result['returncode'], 0)
        self.assertEqual(result['output'], b'frame')
        events = result['events']
        arms = [item for item in events if item['event'] == 'arm']
        self.assertEqual(arms, [{'event': 'arm', 'which': int(signal.ITIMER_REAL),
                               'seconds': 300, 'interval': 0.0}])
        names = [item['event'] for item in events]
        self.assertLess(names.index('arm'), names.index('admission'))
        remaining = [item['remaining'] for item in events if 'remaining' in item]
        self.assertEqual(len(remaining), 5)
        self.assertTrue(all(value > 0 for value in remaining))
        self.assertEqual(remaining, sorted(remaining, reverse=True))
        self.assertEqual(events[-1]['parent_signal'], int(signal.SIGKILL))

    def test_manifest_pins_separate_lifetime_without_changing_wire_profiles(self):
        """Bind the checked lifecycle policy separately from unchanged legacy/native wire bytes."""
        from hashlib import sha256

        profile = getattr(worker, 'worker_lifetime_profile', None)
        self.assertTrue(callable(profile), 'independent worker lifetime policy is missing')
        record = json.loads((ROOT / 'reporting/pdf-fixed-inspection-worker.v1.json').read_text())
        self.assertEqual(record['lifetime_policy']['profile'], profile())
        self.assertEqual(record['lifetime_policy']['profile_sha256'],
                         sha256(_json_bytes(profile())).hexdigest())
        self.assertEqual(worker.WORKER_LIFETIME_PROFILE_SHA256,
                         record['lifetime_policy']['profile_sha256'])
        self.assertEqual(worker.PROFILE_SHA256,
                         '48701b4b85dc7f56d5ac1b5032bb71069c9d44189de3da265b59e94d3b3fead3')
        self.assertEqual(worker.NATIVE_PROFILE_SHA256,
                         '835e4c927283609888a2a1741ed26d93db2a324521239e8f51470fe1f8d87d6f')
        self.assertFalse(worker.worker_profile()['hard_job_deadline_enforced'])
        self.assertFalse(worker.worker_profile()['aggregate_job_resources_qualified'])


if __name__ == '__main__':
    unittest.main()
