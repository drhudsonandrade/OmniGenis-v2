"""Inert exact-range accounting for a future qualified long-PDF inspection profile.

This boundary only plans finite declared page windows and checks structural
agreement of externally supplied observation identifiers. Neither a caller's
page count nor a matching observation hash authenticates a worker or proves
that a PDF page was inspected. It never reads PDFs, runs a renderer, changes
legacy 32-page safety policy, enables annotations, or authorizes release.
An unadmitted job fails whole; findings and pages are never truncated.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json

from reporting.bindings import ReportBindingError, _digest, _identity

SCHEMA_VERSION = "1.0.0"
PROFILE_ID = "inert-pdf-page-window-ledger-v1"
MAX_DECLARED_PAGES = 32768
MAX_WINDOWS = 1024
MAX_PAGES_PER_WINDOW = 32


class PageWindowError(ValueError):
    """Content-free failure of finite page planning or evidence binding."""


def _sha(value: object) -> None:
    """Reject noncanonical SHA-256 values without normalizing caller input."""
    try:
        _digest(value)
    except ReportBindingError:
        raise PageWindowError("page_window_digest_invalid") from None


def _profile(value: object) -> None:
    """Require a bounded opaque inspector identifier without authenticating it."""
    try:
        _identity(value)
    except ReportBindingError:
        raise PageWindowError("page_window_profile_invalid") from None


def _count(value: object, lower: int, upper: int) -> None:
    """Require a native integer within the declared finite admission interval."""
    if type(value) is not int or not lower <= value <= upper:
        raise PageWindowError("page_window_resource_budget_invalid")


def _canonical_sha256(value: object) -> str:
    """Hash sorted compact UTF-8 metadata using the established JSON encoding."""
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class WindowSpan:
    """One-based, inclusive final-document page range and zero-based ordinal."""

    index: int
    first_page: int
    last_page: int

    def __post_init__(self) -> None:
        """Validate the ordinal, positive page bounds and maximum window width."""
        _count(self.index, 0, MAX_WINDOWS - 1)
        _count(self.first_page, 1, MAX_DECLARED_PAGES)
        _count(self.last_page, 1, MAX_DECLARED_PAGES)
        if not self.first_page <= self.last_page < self.first_page + MAX_PAGES_PER_WINDOW:
            raise PageWindowError("page_window_range_invalid")

    def to_dict(self) -> dict[str, int]:
        """Revalidate and return detached metadata for this inclusive page range."""
        self.__post_init__()
        return {
            "index": self.index,
            "first_page": self.first_page,
            "last_page": self.last_page,
        }


def _expected_spans(page_count: int, pages_per_window: int) -> tuple[WindowSpan, ...]:
    """Partition an admitted page count into ordered inclusive windows."""
    return tuple(
        WindowSpan(index=index, first_page=start + 1,
                   last_page=min(page_count, start + pages_per_window))
        for index, start in enumerate(range(0, page_count, pages_per_window))
    )


@dataclass(frozen=True, slots=True, repr=False)
class PageWindowPlan:
    """Finite admitted *declared* workload; not an authorized PDF inspection."""

    pdf_sha256: str
    ir_sha256: str
    page_count: int
    admitted_page_budget: int
    pages_per_window: int
    inspector_profile_id: str
    windows: tuple[WindowSpan, ...]
    _plan_sha256: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Enforce admission, exact contiguous spans and the retained plan digest."""
        _sha(self.pdf_sha256)
        _sha(self.ir_sha256)
        _profile(self.inspector_profile_id)
        _count(self.page_count, 1, MAX_DECLARED_PAGES)
        _count(self.admitted_page_budget, 1, MAX_DECLARED_PAGES)
        _count(self.pages_per_window, 1, MAX_PAGES_PER_WINDOW)
        if self.page_count > self.admitted_page_budget:
            raise PageWindowError("page_window_job_not_admitted")
        if type(self.windows) is not tuple:
            raise PageWindowError("page_window_span_tuple_required")
        if len(self.windows) > MAX_WINDOWS:
            raise PageWindowError("page_window_count_over_budget")
        if any(type(window) is not WindowSpan for window in self.windows):
            raise PageWindowError("page_window_span_type_invalid")
        expected = _expected_spans(self.page_count, self.pages_per_window)
        if self.windows != expected or len(expected) > MAX_WINDOWS:
            raise PageWindowError("page_window_coverage_plan_invalid")
        for window in self.windows:
            window.__post_init__()
        computed = _canonical_sha256(self._identity_record())
        if hasattr(self, "_plan_sha256") and self._plan_sha256 != computed:
            raise PageWindowError("page_window_plan_mutated")
        object.__setattr__(self, "_plan_sha256", computed)

    def _identity_record(self) -> dict[str, object]:
        """Build the canonical metadata record that determines the plan identity."""
        return {
            "pdf_sha256": self.pdf_sha256,
            "ir_sha256": self.ir_sha256,
            "page_count": self.page_count,
            "admitted_page_budget": self.admitted_page_budget,
            "pages_per_window": self.pages_per_window,
            "inspector_profile_id": self.inspector_profile_id,
            "windows": [window.to_dict() for window in self.windows],
        }

    @property
    def plan_sha256(self) -> str:
        """Return the retained digest of this declared planning snapshot."""
        return self._plan_sha256

    @property
    def window_count(self) -> int:
        """Return the number of retained spans, not a measured PDF page count."""
        return len(self.windows)

    def to_dict(self) -> dict[str, object]:
        """Revalidate the plan and serialize its explicitly unqualified metadata."""
        self.__post_init__()
        return {
            "schema_version": SCHEMA_VERSION,
            "profile_id": PROFILE_ID,
            "status": "STAGED_UNQUALIFIED",
            "conformance_scope": "DECLARED_PAGE_WINDOWS_ONLY",
            **self._identity_record(),
            "window_count": self.window_count,
            "window_plan_sha256": self.plan_sha256,
            "worker_results_authenticated": False,
            "whole_pdf_safety_qualified": False,
            "release_authorization": "NOT_ESTABLISHED",
        }


@dataclass(frozen=True, slots=True, repr=False)
class WindowObservation:
    """Externally asserted window output identity, not proof of worker execution."""

    index: int
    first_page: int
    last_page: int
    pdf_sha256: str
    plan_sha256: str
    inspector_profile_id: str
    observation_sha256: str

    def __post_init__(self) -> None:
        """Validate range and digest syntax without claiming a worker executed."""
        WindowSpan(self.index, self.first_page, self.last_page)
        _sha(self.pdf_sha256)
        _sha(self.plan_sha256)
        _sha(self.observation_sha256)
        _profile(self.inspector_profile_id)

    def to_dict(self) -> dict[str, object]:
        """Revalidate and detach the externally asserted observation metadata."""
        self.__post_init__()
        return {
            "index": self.index,
            "first_page": self.first_page,
            "last_page": self.last_page,
            "pdf_sha256": self.pdf_sha256,
            "plan_sha256": self.plan_sha256,
            "inspector_profile_id": self.inspector_profile_id,
            "observation_sha256": self.observation_sha256,
        }


@dataclass(frozen=True, slots=True, repr=False)
class BoundPageWindowLedger:
    """All declared ranges bound exactly, with native verification still absent."""

    plan: PageWindowPlan
    observations: tuple[WindowObservation, ...]

    def __post_init__(self) -> None:
        """Reject any missing, foreign, reordered or mismatched window observation."""
        if type(self.plan) is not PageWindowPlan:
            raise PageWindowError("page_window_plan_required")
        self.plan.__post_init__()
        if (type(self.observations) is not tuple
                or len(self.observations) != self.plan.window_count):
            raise PageWindowError("page_window_observation_count_invalid")
        for expected, observation in zip(self.plan.windows, self.observations):
            if type(observation) is not WindowObservation:
                raise PageWindowError("page_window_observation_type_invalid")
            observation.__post_init__()
            if (
                observation.index != expected.index
                or observation.first_page != expected.first_page
                or observation.last_page != expected.last_page
                or observation.pdf_sha256 != self.plan.pdf_sha256
                or observation.plan_sha256 != self.plan.plan_sha256
                or observation.inspector_profile_id != self.plan.inspector_profile_id
            ):
                raise PageWindowError("page_window_observation_binding_mismatch")

    def to_dict(self) -> dict[str, object]:
        """Serialize complete declared range agreement without granting qualification."""
        self.__post_init__()
        observation_records = [item.to_dict() for item in self.observations]
        return {
            "schema_version": SCHEMA_VERSION,
            "profile_id": PROFILE_ID,
            "status": "STAGED_UNQUALIFIED",
            "conformance_scope": "EXACT_PAGE_RANGE_AND_DIGEST_BINDING_ONLY",
            "coverage_scope": "DECLARED_RANGES_COMPLETE_ONLY",
            "pdf_sha256": self.plan.pdf_sha256,
            "ir_sha256": self.plan.ir_sha256,
            "page_count": self.plan.page_count,
            "admitted_page_budget": self.plan.admitted_page_budget,
            "pages_per_window": self.plan.pages_per_window,
            "inspector_profile_id": self.plan.inspector_profile_id,
            "window_count": self.plan.window_count,
            "window_plan_sha256": self.plan.plan_sha256,
            "observations_sha256": _canonical_sha256(observation_records),
            "observations": observation_records,
            "worker_results_authenticated": False,
            "whole_pdf_safety_qualified": False,
            "raster_pages_validated": False,
            "renderer_activated": False,
            "release_authorized": False,
            "release_authorization": "NOT_ESTABLISHED",
        }


def plan_pdf_page_windows(
    *, pdf_sha256: object, ir_sha256: object, page_count: object,
    admitted_page_budget: object, pages_per_window: object,
    inspector_profile_id: object,
) -> PageWindowPlan:
    """Plan a bounded workload; never inspect an actual PDF or truncate pages."""
    _sha(pdf_sha256)
    _sha(ir_sha256)
    _profile(inspector_profile_id)
    _count(page_count, 1, MAX_DECLARED_PAGES)
    _count(admitted_page_budget, 1, MAX_DECLARED_PAGES)
    _count(pages_per_window, 1, MAX_PAGES_PER_WINDOW)
    if page_count > admitted_page_budget:
        raise PageWindowError("page_window_job_not_admitted")
    if (page_count + pages_per_window - 1) // pages_per_window > MAX_WINDOWS:
        raise PageWindowError("page_window_count_over_budget")
    return PageWindowPlan(
        pdf_sha256=pdf_sha256,
        ir_sha256=ir_sha256,
        page_count=page_count,
        admitted_page_budget=admitted_page_budget,
        pages_per_window=pages_per_window,
        inspector_profile_id=inspector_profile_id,
        windows=_expected_spans(page_count, pages_per_window),
    )


def bind_pdf_page_window_evidence(
    *, plan: PageWindowPlan, observations: tuple[WindowObservation, ...],
) -> BoundPageWindowLedger:
    """Require exact windows, order, PDF, plan and inspection-profile claims."""
    return BoundPageWindowLedger(plan=plan, observations=observations)
