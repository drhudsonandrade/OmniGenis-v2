"""Optional bounded observer timing and CPU measurements, not native qualification.

Local clocks measure the calling observer process and its reaped children. Job
counters are caller-reported snapshots: their source, cgroup and acquisition time
are not authenticated here. No process is launched, signaled or limited; no file,
service, default pipeline or report-release behavior is changed by this module.
"""
from __future__ import annotations

from hashlib import sha256
import json
import math
import os
import resource
import threading
import time

MAX_COUNTER = (1 << 63) - 1
MAX_SAMPLES = 10000
SCHEMA = 'pdf-observer-measurements/v1'


def _integer(value: object, *, minimum: int = 0, maximum: int = MAX_COUNTER) -> int:
    """Require a bounded exact integer rather than boolean or implicit coercion."""
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError('bounded observer measurement integer required')
    return value


def _seconds_to_ns(value: object) -> int:
    """Convert finite nonnegative resource CPU seconds without claiming resolution."""
    if (type(value) not in (int, float)
            or not 0 <= value <= MAX_COUNTER / 1_000_000_000
            or not math.isfinite(value)):
        raise ValueError('finite bounded resource CPU seconds required')
    return _integer(round(value * 1_000_000_000))


def _read_counters() -> tuple[int, int, int, int, int]:
    """Bracket process and reaped-child CPU observations with monotonic timestamps.

    CPU includes every thread in this process and all children reaped by it,
    including unrelated concurrent work. Resource-counter resolution is platform
    dependent even though the report uses integer nanoseconds.
    """
    before = time.monotonic_ns()
    own = time.process_time_ns()
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    user = _seconds_to_ns(children.ru_utime)
    system = _seconds_to_ns(children.ru_stime)
    after = time.monotonic_ns()
    return before, after, own, user, system


def _validate_counters(current: object, previous: tuple | None = None) -> tuple:
    """Reject malformed, internally reversed or individually regressing clocks."""
    if type(current) is not tuple or len(current) != 5:
        raise ValueError('complete observer clock snapshot required')
    for value in current:
        _integer(value)
    if current[1] < current[0]:
        raise ValueError('observer clock capture regressed')
    if previous is not None and (
        current[0] < previous[1]
        or any(now < old for now, old in zip(current[2:], previous[2:]))
    ):
        raise ValueError('observer clock or CPU counter regressed')
    return current


class ObserverMeasurements:
    """Measure one creator-owned interval; any invalid operation poisons the scope.

    Limits supplied to this class describe the evidence record and the comparison
    target, not an activated resource profile. Sampling is synchronous; callers
    must arrange actual kernel reads and lifecycle enforcement separately.
    """

    __slots__ = ('_pid', '_thread', '_initial', '_previous', '_samples', '_max_samples',
                 '_target', '_budget', '_broken', '_closed', '_busy', '_capture_span')

    def __init__(self, *, cpu_budget_usec: int, target_interval_ns: int = 100000000,
                 max_samples: int = MAX_SAMPLES) -> None:
        """Validate metadata before observing any clock or capturing process state."""
        self._budget = _integer(cpu_budget_usec, minimum=1)
        self._target = _integer(target_interval_ns, minimum=1)
        self._max_samples = _integer(max_samples, minimum=1, maximum=MAX_SAMPLES)
        self._pid = os.getpid()
        self._thread = threading.current_thread()
        self._broken = self._closed = self._busy = False
        self._samples = []
        self._initial = self._previous = _validate_counters(_read_counters())
        self._capture_span = self._initial[1] - self._initial[0]

    def _begin(self) -> None:
        """Refuse foreign ownership, reuse or reentry before any measurement read."""
        if (os.getpid() != self._pid or threading.current_thread() is not self._thread
                or self._broken or self._closed or self._busy):
            self._broken = True
            raise ValueError('observer measurement owner or state mismatch')
        self._busy = True

    def _capture(self) -> tuple:
        """Read and validate actual counters; reentrant failure remains irreversible."""
        current = _validate_counters(_read_counters(), self._previous)
        if self._broken:
            raise ValueError('observer measurement interrupted by invalid operation')
        return current

    def record_sample(self, *, job_cpu_usec: int, tasks_current: int) -> None:
        """Retain one caller-reported snapshot with its local receipt-time bracket.

        Task count is a gauge and may fall. The reported CPU counter must not
        regress. The timestamp is when this recorder receives the values, not
        proof of when a kernel counter was read. No old sample is overwritten.
        """
        self._begin()
        try:
            cpu = _integer(job_cpu_usec)
            tasks = _integer(tasks_current)
            if len(self._samples) >= self._max_samples:
                raise ValueError('observer sample capacity exhausted')
            if self._samples and cpu < self._samples[-1]['job_cpu_usec']:
                raise ValueError('reported job CPU counter regressed')
            current = self._capture()
            self._samples.append({'received_start_ns': current[0],
                                  'received_end_ns': current[1],
                                  'job_cpu_usec': cpu, 'tasks_current': tasks})
            self._capture_span = max(self._capture_span, current[1] - current[0])
            self._previous = current
        except BaseException:
            self._broken = True
            raise
        finally:
            self._busy = False

    def finish(self) -> dict:
        """Seal detached measurements once, including the gap after the last sample.

        A digest binds these descriptive values, not authenticated host execution.
        No result is returned when a final clock read or any previous operation
        failed. There is no PASS, resource-enforcement or release authorization.
        """
        self._begin()
        try:
            if not self._samples:
                raise ValueError('observer measurement requires at least one sample')
            final = self._capture()
            times = [self._initial[1]] + [row['received_end_ns'] for row in self._samples] + [final[1]]
            maximum_gap = max(later - earlier for earlier, later in zip(times, times[1:]))
            user = final[3] - self._initial[3]
            system = final[4] - self._initial[4]
            first_cpu = self._samples[0]['job_cpu_usec']
            last_cpu = self._samples[-1]['job_cpu_usec']
            value = {
                'schema': SCHEMA, 'state': 'OBSERVED_INTERVAL_ONLY',
                'started_monotonic_ns': self._initial[1], 'finished_monotonic_ns': final[1],
                'wall_elapsed_ns': final[1] - self._initial[1],
                'observer_process_cpu_ns': final[2] - self._initial[2],
                'reaped_children_user_cpu_ns': user, 'reaped_children_system_cpu_ns': system,
                'reaped_children_cpu_ns': user + system,
                'sample_count': len(self._samples), 'sample_capacity': self._max_samples,
                'declared_target_interval_ns': self._target,
                'maximum_received_sample_gap_ns': maximum_gap,
                'maximum_clock_capture_span_ns': max(self._capture_span, final[1] - final[0]),
                'observed_gap_above_target_ns': max(0, maximum_gap - self._target),
                'declared_cpu_budget_usec': self._budget,
                'job_cpu_first_reported_usec': first_cpu, 'job_cpu_last_reported_usec': last_cpu,
                'job_cpu_reported_delta_usec': last_cpu - first_cpu,
                'observed_cpu_above_budget_usec': max(0, last_cpu - self._budget),
                'samples': self._samples,
                'sampling_boundary': 'Locally received snapshots; kernel acquisition time is not authenticated.',
                'cpu_accounting_boundary': 'Observer process includes all threads; child CPU includes all reaped children during the interval.',
                'counter_resolution': 'Platform dependent; integer units do not establish nanosecond precision.',
                'job_counters_authenticated': False, 'exclusive_observer_process': False,
                'exclusive_reaped_children': False, 'continuous_enforcement': False,
                'hard_realtime_bound': False, 'native_profile_qualified': False,
                'release_authorized': False,
            }
            encoded = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')
            result = json.loads(encoded)
            result['measurements_sha256'] = sha256(encoded).hexdigest()
            if self._broken:
                raise ValueError('observer measurement interrupted before completion')
            self._closed = True
            return result
        except BaseException:
            self._broken = True
            raise
        finally:
            self._busy = False
