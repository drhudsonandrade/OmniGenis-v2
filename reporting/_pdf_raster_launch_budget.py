"""Consumable launch attempts for one synchronous optional raster window.

This allowance belongs to its creator process and thread. It counts one version
probe and the exact selected page attempts, not successful native execution,
arbitrary descendants or aggregate job resources. It is not an authorization
boundary against code running inside the worker.
"""
from __future__ import annotations

import os
import threading

from reporting._pdf_raster_child_observation import RasterChildObservation, cleanup_created_child


class RasterLaunchBudget:
    """Admit one probe followed by an immutable consecutive schedule without refunds."""

    __slots__ = ("_pages", "_pid", "_thread", "_probe_consumed", "_next_page", "_invalid", "_closed", "_observer")

    def __init__(self, pages: tuple[int, ...] = (), *, observe_processes: bool = False) -> None:
        """Bind at most four physical pages; an empty tuple is the standalone probe path."""
        if (type(pages) is not tuple or len(pages) > 4
                or any(type(page) is not int or not 1 <= page <= 512 for page in pages)
                or any(right != left + 1 for left, right in zip(pages, pages[1:]))):
            raise ValueError("raster launch page schedule")
        if type(observe_processes) is not bool:
            raise ValueError("raster observation flag")
        self._observer = RasterChildObservation(pages) if observe_processes else None
        self._pages = pages
        self._pid = os.getpid()
        self._thread = threading.current_thread()
        self._probe_consumed = False
        self._next_page = 0
        self._invalid = False
        self._closed = False

    def _require_owner(self) -> None:
        """Poison any use outside the creator PID and the exact creator thread object."""
        if os.getpid() != self._pid or threading.current_thread() is not self._thread:
            self._invalid = True
            raise ValueError("raster launch budget owner")

    def _require_active(self) -> None:
        """Reject closed or previously violated state without restoring any capacity."""
        self._require_owner()
        if self._closed or self._invalid:
            self._invalid = True
            raise ValueError("raster launch budget inactive")

    def consume_probe(self) -> None:
        """Spend the sole version-probe attempt immediately before child creation."""
        self._require_active()
        if self._probe_consumed:
            self._invalid = True
            raise ValueError("raster launch probe exhausted")
        if self._observer is not None:
            self._observer.require_idle(0)
        self._probe_consumed = True

    def consume_page(self, page: int) -> None:
        """Spend only the next exact selected page after the probe attempt was consumed."""
        self._require_active()
        if (type(page) is not int or not self._probe_consumed
                or self._next_page >= len(self._pages) or page != self._pages[self._next_page]):
            self._invalid = True
            raise ValueError("raster launch page order")
        if self._observer is not None:
            self._observer.require_idle(1 + self._next_page)
        self._next_page += 1

    def require_complete(self) -> None:
        """Require every admitted attempt without interpreting it as native success."""
        self._require_active()
        if not self._probe_consumed or self._next_page != len(self._pages):
            self._invalid = True
            raise ValueError("raster launch schedule incomplete")
        if self._observer is not None:
            self._observer.require_idle(1 + len(self._pages))

    def close(self) -> None:
        """Idempotently close owned state on either success or failure, never resetting it."""
        self._require_owner()
        self._closed = True
        if self._observer is not None:
            self._observer.close()


    @property
    def observing(self) -> bool:
        """Indicate explicit optional tracking without changing default attempt accounting."""
        return self._observer is not None

    def record_spawn(self, process, command: list[str]) -> None:
        """Record an actual just-created child and clean it on registration failure."""
        if self._observer is None:
            return
        self._require_active()
        try:
            self._observer.record_spawn(process, command)
        except BaseException as failure:
            self._invalid = True
            try:
                cleanup_created_child(process)
            except BaseException as cleanup:
                raise failure from cleanup
            raise

    def wait_observed(self, process, *, wall_seconds: float) -> int:
        """Preserve owned-child cleanup when the optional state rejects an in-flight wait."""
        self._require_active()
        if self._observer is None:
            raise ValueError("raster observation not selected")
        self._observer.require_pending(process)
        try:
            return self._observer.wait(process, wall_seconds=wall_seconds)
        except BaseException as failure:
            self._invalid = True
            try:
                cleanup_created_child(process)
            except BaseException as cleanup:
                raise failure from cleanup
            raise

    def process_ledger(self, identity: dict, inspection: dict) -> dict:
        """Require actual complete observations separately from consumed attempt ceilings."""
        self.require_complete()
        if self._observer is None:
            raise ValueError("raster observation not selected")
        return self._observer.finish(identity=identity, inspection=inspection)


def _require_launch_budget(value: object) -> RasterLaunchBudget:
    """Reject missing, duck-typed or subclass allowances at the concrete launch boundary."""
    if type(value) is not RasterLaunchBudget:
        raise ValueError("raster launch budget required")
    return value
