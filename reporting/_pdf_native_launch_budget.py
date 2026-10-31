"""Owner-bound cumulative attempts for one synchronous native inspection job.

This private ledger binds declared request headers, not adversarial concurrent
writers or authenticated successful execution. Reservations are ceilings, not
observed processes. Direct waits share the post-admission acceptance deadline;
parent work and syscalls are not preempted. CPU, RSS, arbitrary descendants and
release remain unqualified.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import os
from pathlib import Path
import stat
import sys
import threading
from time import monotonic_ns

from reporting._pdf_process_lifecycle import wait_owned_process_group

from reporting.page_windows import PageWindowPlan, plan_pdf_page_windows

POLICY_ID = "native-pdf-cumulative-launch-attempt-budget-v1"
MAX_PAGES = 64
MAX_PDF_BYTES = 8 * 1024 * 1024
ACCEPTANCE_NS = 300 * 1000 * 1000 * 1000
TEXT_WIDTH = 16
RASTER_WIDTH = 4
TEXT_PROFILE = "generated-pdf-text-window-v1"
RASTER_PROFILE = "generated-pdf-raster-window-v1"
FIXED_ROLES = (
    "structure_role_edges", "single_revision", "xref_entries", "xref_resolution",
    "trailer_catalog", "page_surface", "resource_leaves", "font_descriptor",
    "cid_widths", "tounicode_header", "tounicode_zlib", "tounicode_cmap_frame",
    "tounicode_utf16be_targets", "tounicode_bfchar_sources", "tounicode_width_coverage",
    "structure_tree", "document_content", "object_graph", "document_metadata",
    "page_tags", "mcid_coverage",
)
_LOCK = threading.Lock()
_ACTIVE = None


def launch_budget_policy() -> dict:
    """Detach the separately versioned contract without changing resource profiles."""
    return {
        "policy_id": POLICY_ID, "max_pages": MAX_PAGES,
        "max_pdf_bytes": MAX_PDF_BYTES, "text_window_pages": TEXT_WIDTH,
        "raster_window_pages": RASTER_WIDTH, "fixed_roles": list(FIXED_ROLES),
        "launchers": {"object_graph": "reporting/pdf_object_graph.py",
                      "text_windows": "reporting/pdf_text_windows.py",
                      "raster_windows": "reporting/pdf_raster_windows.py"},
        "direct_attempts": "21+ceil(P/16)+ceil(P/4)",
        "reserved_raster_child_attempts": "ceil(P/4)+P",
        "composed_attempt_ceiling": "21+ceil(P/16)+2*ceil(P/4)+P",
        "at_64_pages": {"direct_attempts": 41, "reserved_raster_child_attempts": 80,
                        "composed_attempt_ceiling": 121,
                        "with_optional_fixed_supervisor": 122},
        "cumulative_wall_wait": {
            "budget_ns": ACCEPTANCE_NS,
            "start": "native_coordinator_post_admission",
            "direct_wait_limit": "min(stage_wall_seconds,remaining_job_seconds)",
            "cleanup_seconds": 2, "cleanup_within_execution_budget": False,
            "hard_job_deadline_enforced": False,
        },
        "aggregate_job_resources_qualified": False,
        "default_pipeline_activated": False, "release_authorized": False,
        "retries": 0, "refunds": False, "persistent_checkpoints": False,
    }


def _before_lock() -> None:
    """Reject inherited foreign-PID state before touching a possibly inherited lock.

    Poisoning this child's copied state does not poison the parent's memory.
    """
    active = _ACTIVE
    if active is not None and os.getpid() != active._pid:
        active._invalid = True
        raise ValueError("native launch foreign process")


def require_no_active_scope() -> None:
    """Refuse and poison nested API entry before any input admission can fail."""
    _before_lock()
    with _LOCK:
        if _ACTIVE is not None:
            _ACTIVE._invalid = True
            raise ValueError("native launch scope already active")


@dataclass(frozen=True, slots=True)
class _Attempt:
    """Immutable launcher, resolved fixed worker, declared header and child reserve."""

    kind: str
    worker: str
    header: bytes
    reserved_children: int


def _schedule(plan: PageWindowPlan) -> tuple[_Attempt, ...]:
    """Derive the sole fixed schedule from a validated admitted text plan."""
    if type(plan) is not PageWindowPlan:
        raise ValueError("native launch text plan required")
    plan.__post_init__()
    if (not 1 <= plan.page_count <= MAX_PAGES or plan.admitted_page_budget != plan.page_count
            or plan.pages_per_window != TEXT_WIDTH or plan.inspector_profile_id != TEXT_PROFILE):
        raise ValueError("native launch text plan mismatch")
    raster = plan_pdf_page_windows(
        pdf_sha256=plan.pdf_sha256, ir_sha256=plan.ir_sha256,
        page_count=plan.page_count, admitted_page_budget=plan.page_count,
        pages_per_window=RASTER_WIDTH, inspector_profile_id=RASTER_PROFILE)
    root = Path(__file__).resolve().parent
    common = f"1 {plan.pdf_sha256} {plan.ir_sha256} {plan.plan_sha256} {plan.page_count}\n"
    attempts = [_Attempt("object_graph", str(root / f"_pdf_{role}_worker.py"),
                         common.encode("ascii"), 0) for role in FIXED_ROLES]
    for kind, role, selected in (("text_windows", "text_window", plan),
                                 ("raster_windows", "raster_window", raster)):
        for window in selected.windows:
            header = (f"1 {selected.pdf_sha256} {selected.ir_sha256} {selected.plan_sha256} "
                      f"{selected.page_count} {window.index} {window.first_page} {window.last_page}\n")
            reserve = 1 + window.last_page - window.first_page + 1 if kind == "raster_windows" else 0
            attempts.append(_Attempt(kind, str(root / f"_pdf_{role}_worker.py"),
                                     header.encode("ascii"), reserve))
    return tuple(attempts)


def _descriptor_identity(info: os.stat_result) -> tuple:
    """Capture observable identity and mutation metadata around a bounded header read."""
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class NativeLaunchScope:
    """Own one immutable attempt sequence through final coordinator acceptance."""

    __slots__ = ("_pid", "_thread", "_attempts", "_pdf_size", "_next", "_invalid", "_closed",
                 "_started", "_previous")

    def __init__(self, plan: PageWindowPlan, pdf_size: int, *, started_ns: int | None = None) -> None:
        """Derive internal attempts; callers never provide roles or reusable allowances."""
        if type(pdf_size) is not int or not 1 <= pdf_size <= MAX_PDF_BYTES:
            raise ValueError("native launch source size")
        self._pid = os.getpid()
        self._thread = threading.current_thread()
        self._attempts = _schedule(plan)
        self._pdf_size = pdf_size
        self._next = 0
        self._invalid = False
        self._closed = False
        self._started = monotonic_ns() if started_ns is None else started_ns
        if type(self._started) is not int or self._started < 0:
            raise ValueError("native launch clock invalid")
        self._previous = self._started

    def _owner(self) -> None:
        """Require both exact creator PID and thread object, poisoning any misuse."""
        if os.getpid() != self._pid or threading.current_thread() is not self._thread:
            self._invalid = True
            raise ValueError("native launch owner")

    def _active(self) -> None:
        """Require identical live global ownership; never revive a closed or poisoned scope."""
        self._owner()
        if _ACTIVE is not self or self._closed or self._invalid:
            self._invalid = True
            raise ValueError("native launch inactive")

    def _remaining_seconds(self) -> float:
        """Observe the original deadline while the short-held owner lock is held."""
        try:
            current = monotonic_ns()
            if (type(current) is not int or current < self._previous
                    or current - self._started >= ACCEPTANCE_NS):
                raise ValueError("native launch acceptance deadline")
            self._previous = current
            return (ACCEPTANCE_NS - (current - self._started)) / 1_000_000_000
        except BaseException:
            self._invalid = True
            raise

    def __enter__(self) -> NativeLaunchScope:
        """Activate once after source admission and refuse any existing active scope."""
        global _ACTIVE
        _before_lock()
        with _LOCK:
            self._owner()
            if _ACTIVE is not None:
                _ACTIVE._invalid = True
                self._invalid = True
                raise ValueError("native launch nested activation")
            if self._closed or self._invalid or self._next:
                self._invalid = True
                raise ValueError("native launch reused scope")
            self._remaining_seconds()
            _ACTIVE = self
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        """Clear only the owner's identical slot on Exception or BaseException unwinding."""
        self.close()

    def close(self) -> None:
        """Close idempotently without letting stale or foreign scopes clear another owner."""
        global _ACTIVE
        if os.getpid() != self._pid:
            self._invalid = True
            raise ValueError("native launch foreign process")
        _before_lock()
        with _LOCK:
            self._owner()
            self._closed = True
            if _ACTIVE is self:
                _ACTIVE = None

    def _require_complete(self) -> None:
        """Check live ownership and exact completion while the shared lock is held."""
        self._active()
        self._remaining_seconds()
        if self._next != len(self._attempts):
            self._invalid = True
            raise ValueError("native launch schedule incomplete")

    def require_complete(self) -> None:
        """Reject poisoned state or any missing direct attempt before result acceptance."""
        _before_lock()
        with _LOCK:
            self._require_complete()

    def complete_and_close(self) -> None:
        """Atomically accept the complete unpoisoned job and deactivate its identical slot."""
        global _ACTIVE
        _before_lock()
        with _LOCK:
            self._require_complete()
            self._closed = True
            _ACTIVE = None

    def _consume(self, kind: str, command: object, fds: object, scratch: object) -> None:
        """Validate and spend the next exact request while the short-held lock is owned."""
        self._active()
        try:
            self._remaining_seconds()
            if self._next >= len(self._attempts):
                raise ValueError("native launch exhausted")
            attempt = self._attempts[self._next]
            count = 3 if attempt.kind == "raster_windows" else 2
            if (kind != attempt.kind or type(fds) is not tuple or len(fds) != count
                    or any(type(fd) is not int or fd < 0 for fd in fds)
                    or len(set(fds)) != count or type(command) is not list
                    or any(type(argument) is not str for argument in command)
                    or command != [sys.executable, "-I", attempt.worker,
                                   *(str(fd) for fd in fds), str(self._pid)]):
                raise ValueError("native launch command mismatch")
            before = tuple(os.fstat(fd) for fd in fds[:2])
            if (any(not stat.S_ISREG(info.st_mode) or info.st_nlink != 0
                    or info.st_uid != os.geteuid() for info in before)
                    or (before[0].st_dev, before[0].st_ino) == (before[1].st_dev, before[1].st_ino)
                    or before[0].st_size != len(attempt.header) + self._pdf_size
                    or before[1].st_size != 0):
                raise ValueError("native launch anonymous descriptors")
            if kind == "raster_windows":
                held = os.fstat(fds[2])
                if type(scratch) is not str:
                    raise ValueError("native launch scratch path")
                named = os.stat(scratch, follow_symlinks=False)
                if (not stat.S_ISDIR(held.st_mode) or held.st_uid != os.geteuid()
                        or stat.S_IMODE(held.st_mode) != 0o700 or held.st_nlink < 1
                        or (held.st_dev, held.st_ino, held.st_mode, held.st_uid)
                        != (named.st_dev, named.st_ino, named.st_mode, named.st_uid)):
                    raise ValueError("native launch scratch identity")
            header = os.pread(fds[0], len(attempt.header), 0)
            after = tuple(os.fstat(fd) for fd in fds[:2])
            if (header != attempt.header or tuple(map(_descriptor_identity, before))
                    != tuple(map(_descriptor_identity, after))):
                raise ValueError("native launch declared header mismatch")
            self._remaining_seconds()
            self._next += 1
        except BaseException:
            self._invalid = True
            raise


@contextmanager
def admit_launch(kind: str, command: object, fds: object, scratch: object = None):
    """Consume immediately before Popen; a failed spawn poisons without refund.

    With no active job this is deliberately inert for existing standalone adapters.
    The lock never covers Popen, process waits or PDF parsing.
    """
    _before_lock()
    with _LOCK:
        scope = _ACTIVE
        if scope is not None:
            scope._consume(kind, command, fds, scratch)
    try:
        yield
    except BaseException:
        if scope is not None:
            _before_lock()
            with _LOCK:
                scope._invalid = True
        raise


def wait_native_process_group(process, *, wall_seconds: float) -> int:
    """Cap a direct wait by the active job while preserving owned-child cleanup.

    The existing independent two-second cleanup budget is unchanged. A deadline
    fault after spawn must still clean/reap; parent work and syscalls are not
    preempted. Standalone adapters retain their original stage deadline.
    """
    scope = None
    try:
        _before_lock()
        with _LOCK:
            scope = _ACTIVE
            if scope is not None:
                scope._active()
                wall_seconds = min(wall_seconds, scope._remaining_seconds())
    except BaseException as failure:
        if scope is not None:
            with _LOCK:
                scope._invalid = True
        try:
            wait_owned_process_group(process, wall_seconds=0)
        except BaseException as cleanup:
            raise failure from cleanup
        raise
    try:
        result = wait_owned_process_group(process, wall_seconds=wall_seconds)
        if scope is not None:
            _before_lock()
            with _LOCK:
                scope._active()
                scope._remaining_seconds()
        return result
    except BaseException:
        if scope is not None:
            _before_lock()
            with _LOCK:
                scope._invalid = True
        raise
