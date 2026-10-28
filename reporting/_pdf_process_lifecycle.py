"""Retain an exclusively owned inspection child's identity through group cleanup.

The caller must remain alive and exclusively own a Popen child launched with
start_new_session=True. Concurrent reaping or mutation of that object is not
supported. Linux waitid with WNOWAIT is required: a non-reaped direct child
reserves its PID while the original process group is signaled. This covers the
direct child and original group, not escaped descendants, parent death,
aggregate resources or hard real-time syscall completion.
"""
from __future__ import annotations

import math
import os
import signal
import subprocess
import time


def _observe(process: subprocess.Popen):
    """Prove waitable ownership without reaping or using Popen.poll()."""
    if process.returncode is not None:
        raise ChildProcessError("inspection child ownership lost")
    observed = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    if observed is not None and (
        observed.si_pid != process.pid
        or observed.si_code not in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED)
    ):
        raise ChildProcessError("inspection child identity or exit state unknown")
    return observed


def _wait_for_exit(process: subprocess.Popen, deadline: float):
    """Return an unreaped exit observation, or None when the finite budget ends."""
    while True:
        observed = _observe(process)
        if observed is not None:
            return observed
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        time.sleep(min(0.01, remaining))


def wait_owned_process_group(process: subprocess.Popen, *, wall_seconds: float) -> int:
    """Wait, clean the original group while identity is owned, then reap once.

    A timeout remains a timeout even when cleanup succeeds. Unknown ownership or
    any unresolved cleanup operation refuses success. The two-second cleanup
    budget is shared by independent group/direct-child cleanup and final reap.
    """
    if not math.isfinite(wall_seconds) or wall_seconds < 0:
        raise ValueError("finite inspection wall budget required")
    failure = None
    try:
        if _wait_for_exit(process, time.monotonic() + wall_seconds) is None:
            raise subprocess.TimeoutExpired(process.args, wall_seconds)
    except ChildProcessError:
        # Definitive identity loss is terminal; a later PID lookup cannot undo it.
        raise
    except BaseException as error:
        failure = error

    cleanup_deadline = time.monotonic() + 2
    cleanup_failure = None
    try:
        _observe(process)
    except (OSError, AttributeError) as error:
        # Without a current ownership proof, neither numeric signal is safe.
        cleanup_failure = error
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as error:
            cleanup_failure = error

        # Group failure must not prevent independent cleanup of an owned child.
        try:
            if _observe(process) is None:
                try:
                    os.kill(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        except ChildProcessError:
            # Do not reap through a numeric PID after ownership was declared lost.
            if failure is not None:
                raise failure
            raise
        except OSError as error:
            cleanup_failure = cleanup_failure or error

        try:
            if _wait_for_exit(process, cleanup_deadline) is None:
                raise subprocess.TimeoutExpired(process.args, 2)
            # Popen.wait() hides ECHILD by reporting zero. Explicitly reap so a
            # lost child cannot be mistaken for a successful inspection.
            pid, status = os.waitpid(process.pid, os.WNOHANG)
            if pid != process.pid:
                raise ChildProcessError("inspection child reap unresolved")
            process.returncode = os.waitstatus_to_exitcode(status)
        except (OSError, subprocess.TimeoutExpired) as error:
            cleanup_failure = cleanup_failure or error

    if failure is not None:
        raise failure
    if cleanup_failure is not None:
        raise cleanup_failure
    return process.returncode
