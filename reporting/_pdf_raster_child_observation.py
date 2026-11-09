"""Optional actual raster child observations; no process-tree or release authority.

Only the fixed probe and selected page launchers are recorded. Waitable child
identity is retained until exact reap. Timestamps describe parent observations,
not kernel event times. No tracer, timer process, extra privilege or report data
is introduced; unknown native descendants remain outside this local boundary.
"""
from __future__ import annotations

from hashlib import sha256
import json
import math
import os
from pathlib import Path
import signal
from subprocess import Popen as _Process, TimeoutExpired
import sys
import threading
import time

from reporting._pdf_process_lifecycle import _observe, _wait_for_exit
from reporting._pdf_text_window_worker import _validate_identity
from reporting._pdf_visual_worker import TOOL_SHA256

SCHEMA = 'raster-window-child-observation/v1'
MODE = 'observe-children-v1'
MAX_RECORD_BYTES = 3072
MAX_COUNTER = (1 << 63) - 1
_ROW_KEYS = {'sequence', 'kind', 'page', 'pid', 'parent_pid', 'observed_spawn_ns',
             'observed_exit_ns', 'exit_code', 'launcher', 'launcher_sha256'}
_FALSE_KEYS = ('authenticated_worker_execution', 'aggregate_job_resources_qualified',
               'arbitrary_descendants_observed', 'release_authorized')
_TIMING = 'Parent observations after spawn and reap; not kernel event timestamps.'


def _canonical(value: object) -> bytes:
    """Encode bounded content-free metadata with no nonfinite JSON numbers."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _integer(value: object, lower: int = 0, upper: int = MAX_COUNTER) -> int:
    """Admit exact bounded integers, never booleans or implicit coercions."""
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError('raster child integer')
    return value


def wait_owned_raster_child(process: _Process, *, wall_seconds: float) -> int:
    """Wait and reap one exclusively owned child; preserve timeout/interrupt failure.

    No process-group signal is used because these children share their worker's
    group. WNOWAIT reserves child identity before the exact waitpid reap. A lost
    waitable identity is a refusal without a later numeric-PID signal. Startup
    syscalls, unrelated reapers and arbitrary descendants are not covered.
    """
    if (type(wall_seconds) not in (int, float) or not 0 <= wall_seconds <= 8
            or not math.isfinite(wall_seconds)):
        raise ValueError('raster child wait budget')
    if not isinstance(process, _Process):
        raise ValueError('actual raster child required')
    _observe(process)
    failure = None
    try:
        if _wait_for_exit(process, time.monotonic() + wall_seconds) is None:
            raise TimeoutExpired(process.args, wall_seconds)
    except ChildProcessError:
        raise
    except BaseException as exc:
        failure = exc
    try:
        if failure is not None and _observe(process) is None:
            os.kill(process.pid, signal.SIGKILL)
        if _wait_for_exit(process, time.monotonic() + 2) is None:
            raise TimeoutExpired(process.args, 2)
        pid, status = os.waitpid(process.pid, os.WNOHANG)
        if pid != process.pid:
            raise ChildProcessError('raster child reap unresolved')
        process.returncode = os.waitstatus_to_exitcode(status)
    except BaseException as cleanup:
        if failure is not None:
            raise failure from cleanup
        raise
    if failure is not None:
        raise failure
    return process.returncode


def cleanup_created_child(process: _Process) -> None:
    """Retire a child just created by the caller when observation registration fails."""
    if not isinstance(process, _Process) or process.returncode is not None:
        return
    try:
        wait_owned_raster_child(process, wall_seconds=0)
    except TimeoutExpired:
        if process.returncode is None:
            raise


def _launcher(sequence: int) -> str:
    """Select only the existing version query or guarded page executable source."""
    return '_pdf_raster_probe.py' if sequence == 0 else '_pdf_raster_executor.py'


def _source_hash(name: str) -> str:
    """Hash a fixed sibling source; this is source identity, not authenticated exec."""
    return sha256(Path(__file__).resolve().with_name(name).read_bytes()).hexdigest()


def validate_observation(value: object, identity: dict, inspection: dict,
                         worker_pid: int) -> dict:
    """Require exact source/plan/result binding and the complete fixed child schedule."""
    _validate_identity(identity)
    pages = list(range(identity['first_page'], identity['last_page'] + 1))
    if not 1 <= len(pages) <= 4:
        raise ValueError('raster observed page count')
    _integer(worker_pid, 2, 2147483647)
    keys = {'schema', 'state', 'worker_pid', 'identity', 'inspection_sha256',
            'tool_sha256', 'observed_spawns', 'observed_exits', 'declared_retries',
            'timing_scope', 'processes', 'observation_sha256', *_FALSE_KEYS}
    if type(value) is not dict or set(value) != keys or len(_canonical(value)) > MAX_RECORD_BYTES:
        raise ValueError('raster observation shape or budget')
    if (value['schema'] != SCHEMA or value['state'] != 'COMPLETE_SELECTED_RASTER_CHILDREN_OBSERVED'
            or _integer(value['worker_pid'], 2, 2147483647) != worker_pid
            or _canonical(value['identity']) != _canonical(identity)
            or value['inspection_sha256'] != sha256(_canonical(inspection)).hexdigest()
            or value['tool_sha256'] != TOOL_SHA256 or value['timing_scope'] != _TIMING
            or any(value[key] is not False for key in _FALSE_KEYS)):
        raise ValueError('raster observation identity or scope')
    count = 1 + len(pages)
    if (_integer(value['observed_spawns']) != count or _integer(value['observed_exits']) != count
            or _integer(value['declared_retries']) != 0
            or type(value['processes']) is not list or len(value['processes']) != count):
        raise ValueError('raster observation counts')
    pids = set()
    previous = 0
    for index, row in enumerate(value['processes']):
        if type(row) is not dict or set(row) != _ROW_KEYS:
            raise ValueError('raster child row shape')
        page = None if index == 0 else pages[index - 1]
        wrong_page = (row['page'] is not None) if page is None else (type(row['page']) is not int or row['page'] != page)
        if wrong_page:
            raise ValueError('raster child page')
        name = _launcher(index)
        begin = _integer(row['observed_spawn_ns'])
        end = _integer(row['observed_exit_ns'])
        pid = _integer(row['pid'], 2, 2147483647)
        if (_integer(row['sequence']) != index or row['kind'] != ('version_probe' if index == 0 else 'raster_page')
                or _integer(row['parent_pid'], 2, 2147483647) != worker_pid
                or _integer(row['exit_code']) != 0 or begin < previous or end < begin
                or pid == worker_pid or pid in pids or row['launcher'] != name
                or row['launcher_sha256'] != _source_hash(name)):
            raise ValueError('raster child observation mismatch')
        pids.add(pid); previous = end
    expected = sha256(_canonical({k:v for k,v in value.items() if k != 'observation_sha256'})).hexdigest()
    if value['observation_sha256'] != expected:
        raise ValueError('raster observation digest')
    return json.loads(_canonical(value))


class RasterChildObservation:
    """Record one creator-owned actual probe/page sequence; any violation poisons it."""

    __slots__ = ('_pages', '_pid', '_thread', '_rows', '_pending', '_broken', '_closed', '_previous')

    def __init__(self, pages: tuple[int, ...]) -> None:
        """Bind one to four immutable consecutive physical pages before any child exists."""
        if (type(pages) is not tuple or not 1 <= len(pages) <= 4
                or any(type(p) is not int or not 1 <= p <= 512 for p in pages)
                or any(b != a + 1 for a,b in zip(pages, pages[1:]))):
            raise ValueError('raster observed page schedule')
        self._pages = pages
        self._pid = os.getpid(); self._thread = threading.current_thread()
        self._rows = []; self._pending = None
        self._broken = self._closed = False
        self._previous = _integer(time.monotonic_ns())

    def _active(self) -> None:
        """Refuse changed ownership, closure or any earlier invalid operation."""
        if (os.getpid() != self._pid or threading.current_thread() is not self._thread
                or self._broken or self._closed):
            self._broken = True
            raise ValueError('raster observation owner or state')

    def _clock(self) -> int:
        """Require monotonically ordered parent observations within finite integer units."""
        current = _integer(time.monotonic_ns())
        if current < self._previous:
            raise ValueError('raster observation clock')
        self._previous = current
        return current

    def require_idle(self, completed: int) -> None:
        """A next attempt cannot start before all previously charged children were reaped."""
        self._active()
        if (self._pending is not None or len(self._rows) != completed
                or any(row['exit_code'] != 0 for row in self._rows)):
            self._broken = True
            raise ValueError('raster observation incomplete sequence')

    def record_spawn(self, process: _Process, command: list[str]) -> None:
        """Bind only an actual unreaped child running the exact next fixed launcher."""
        self._active()
        try:
            index = len(self._rows)
            if (self._pending is not None or index > len(self._pages)
                    or not isinstance(process, _Process) or process.returncode is not None
                    or type(command) is not list or any(type(x) is not str for x in command)
                    or process.args != command):
                raise ValueError('raster observed spawn')
            name = _launcher(index)
            prefix = [sys.executable, '-I', str(Path(__file__).resolve().with_name(name)), str(self._pid)]
            if index == 0:
                if command != prefix:
                    raise ValueError('raster probe launch identity')
            else:
                page = self._pages[index - 1]
                if (len(command) not in (8, 9) or command[:4] != prefix
                        or command[4] != '/usr/bin/pdftoppm' or command[7] != str(page)):
                    raise ValueError('raster page launch identity')
                source = Path(command[5]); destination = Path(command[6])
                if (not source.is_absolute() or '..' in source.parts or source.name != 'candidate.pdf'
                        or destination != source.parent / ('page-' + str(page))):
                    raise ValueError('raster page source identity')
                if len(command) == 9 and (not command[8].isascii() or not command[8].isdecimal()
                        or len(command[8]) > 10 or str(int(command[8])) != command[8]
                        or not 3 <= int(command[8]) <= 2147483647):
                    raise ValueError('raster metadata descriptor identity')
            _observe(process)
            pid = _integer(process.pid, 2, 2147483647)
            if pid == self._pid or any(row['pid'] == pid for row in self._rows):
                raise ValueError('raster child duplicate identity')
            row = dict(sequence=index, kind='version_probe' if index == 0 else 'raster_page',
                page=None if index == 0 else self._pages[index - 1], pid=pid, parent_pid=self._pid,
                observed_spawn_ns=self._clock(), observed_exit_ns=None, exit_code=None,
                launcher=name, launcher_sha256=_source_hash(name))
            self._rows.append(row); self._pending = (process, row)
        except BaseException:
            self._broken = True
            raise

    def require_pending(self, process: _Process) -> None:
        """Reject unregistered or foreign use before granting any cleanup authority."""
        self._active()
        if self._pending is None or self._pending[0] is not process:
            self._broken = True
            raise ValueError('unregistered raster child')

    def wait(self, process: _Process, *, wall_seconds: float) -> int:
        """Observe exact reap only for this ledger's currently pending real child."""
        self.require_pending(process)
        try:
            code = wait_owned_raster_child(process, wall_seconds=wall_seconds)
            if code != 0:
                raise ValueError('raster child failed')
            row = self._pending[1]
            row['observed_exit_ns'] = self._clock(); row['exit_code'] = code
            self._pending = None
            return code
        except BaseException:
            self._broken = True
            raise

    def finish(self, *, identity: dict | None = None, inspection: dict | None = None) -> dict:
        """Detach complete source/result-bound metadata once; partial work never exports."""
        self._active()
        try:
            self.require_idle(1 + len(self._pages))
            if (type(identity) is not dict or type(inspection) is not dict
                    or tuple(range(identity['first_page'], identity['last_page'] + 1)) != self._pages):
                raise ValueError('raster observation completion identity')
            value = dict(schema=SCHEMA, state='COMPLETE_SELECTED_RASTER_CHILDREN_OBSERVED',
                worker_pid=self._pid, identity=identity, inspection_sha256=sha256(_canonical(inspection)).hexdigest(),
                tool_sha256=TOOL_SHA256, observed_spawns=len(self._rows), observed_exits=len(self._rows),
                declared_retries=0, timing_scope=_TIMING, processes=self._rows,
                **{key:False for key in _FALSE_KEYS})
            value['observation_sha256'] = sha256(_canonical(value)).hexdigest()
            result = validate_observation(value, identity, inspection, self._pid)
            self._closed = True
            return result
        except BaseException:
            self._broken = True
            raise

    def close(self) -> None:
        """Close idempotently without resetting capacity or asserting successful completion."""
        if os.getpid() != self._pid or threading.current_thread() is not self._thread:
            self._broken = True
            raise ValueError('raster observation owner')
        self._closed = True
