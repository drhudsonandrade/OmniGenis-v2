"""Opt-in exact-plan raster-window inspection with bounded native execution.

Receipts contain unsigned hashes and counts, never raster pixels or report text.
They can populate a separate raster checkpoint plan but cannot replace text,
object-safety, metadata, accessibility or release checks. The caller must supply
sealed expectations and supervise aggregate resources across the complete job.
The default renderer and existing whole-document validators remain unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

from reporting._pdf_process_lifecycle import wait_owned_process_group

from reporting._pdf_bounded_scratch import (
    _open_verified_bounded_child, _require_same_bounded_mount,
    bounded_scratch_parent, bounded_scratch_requested, raster_child_environment,
)
from reporting._pdf_raster_window_worker import (
    CPU_SECONDS, FILE_BYTES, IDENTITY_FIELDS, MAX_DOCUMENT_PAGES, MAX_PDF_BYTES,
    MAX_PIXELS_PER_PAGE, MAX_TOTAL_PIXELS, MAX_WINDOW_PAGES, MEMORY_BYTES,
    MIN_EDGE_MARGIN_PX, OPEN_FILES, PARSER_VERSION, PILLOW_VERSION, PROFILE_ID,
    PROTOCOL_VERSION, RESULT_BYTES, TOOL_SHA256, TOOL_VERSION, WALL_SECONDS,
    _is_digest, _validate_identity,
)
from reporting.page_windows import PageWindowPlan, WindowObservation
from reporting.pdf_text_windows import _canonical, _unique_pairs

_LIMITS = {"memory_bytes": MEMORY_BYTES, "cpu_seconds": CPU_SECONDS,
           "file_bytes": FILE_BYTES, "open_files": OPEN_FILES}


class PdfRasterWindowError(ValueError):
    """Fixed content-free failure; no partial successful raster observation is returned."""


@dataclass(frozen=True, slots=True, repr=False)
class PdfRasterWindowInspection:
    """Immutable unsigned geometry evidence for exactly one physical page interval."""

    pdf_sha256: str
    ir_sha256: str
    plan_sha256: str
    page_count: int
    window_index: int
    first_page: int
    last_page: int
    raster_sha256: str
    total_pixels: int
    min_edge_margin_px: int

    def __post_init__(self) -> None:
        """Reject invalid digests, counts, incomplete ranges and contradictory geometry."""
        try:
            _validate_identity(self._identity())
            if not _is_digest(self.raster_sha256):
                raise ValueError("raster digest")
            margin = self.min_edge_margin_px
            if type(margin) is not int or not MIN_EDGE_MARGIN_PX <= margin <= 1000:
                raise ValueError("raster margin")
            if (type(self.total_pixels) is not int
                    or not self.inspected_pages * (2 * margin + 1) ** 2 <= self.total_pixels
                    <= min(MAX_TOTAL_PIXELS, self.inspected_pages * MAX_PIXELS_PER_PAGE)):
                raise ValueError("raster pixel relation")
        except Exception:
            raise PdfRasterWindowError("pdf_raster_window_receipt_invalid") from None

    def _identity(self) -> dict:
        """Detach the closed request identity used by both worker and supervisor."""
        return {key: getattr(self, key) for key in IDENTITY_FIELDS}

    @property
    def inspected_pages(self) -> int:
        """Return the exact inclusive range size represented by this receipt."""
        return self.last_page - self.first_page + 1

    def to_dict(self) -> dict:
        """Expose only digest/count geometry evidence and unestablished global guarantees."""
        self.__post_init__()
        return {"schema_version": "1.0.0", "profile_id": PROFILE_ID,
                "status": "WINDOW_RASTER_INSPECTED", **self._identity(),
                "raster_sha256": self.raster_sha256, "total_pixels": self.total_pixels,
                "min_edge_margin_px": self.min_edge_margin_px,
                "inspected_pages": self.inspected_pages, "parser_version": PARSER_VERSION,
                "pillow_version": PILLOW_VERSION, "raster_tool_version": TOOL_VERSION,
                "raster_tool_sha256": TOOL_SHA256,
                "raster_digest_profile": "physical-page-rgb-geometry-framed-v1",
                "worker_results_authenticated": False, "whole_pdf_safety_qualified": False,
                "semantic_visual_equivalence_verified": False,
                "aggregate_job_resources_qualified": False, "release_authorized": False,
                "release_authorization": "NOT_ESTABLISHED"}

    @property
    def observation_sha256(self) -> str:
        """Hash the complete detached metadata; this digest is not authentication."""
        return hashlib.sha256(_canonical(self.to_dict())).hexdigest()

    def to_observation(self) -> WindowObservation:
        """Project into an existing raster-plan ledger without publishing any job state."""
        self.__post_init__()
        return WindowObservation(index=self.window_index, first_page=self.first_page,
            last_page=self.last_page, pdf_sha256=self.pdf_sha256, plan_sha256=self.plan_sha256,
            inspector_profile_id=PROFILE_ID, observation_sha256=self.observation_sha256)


def _decode(data: bytes, expected: dict) -> PdfRasterWindowInspection:
    """Require exact protocol shape, identities, process limits and complete range evidence."""
    try:
        if type(data) is not bytes or not 0 < len(data) <= RESULT_BYTES:
            raise ValueError("raster response size")
        _validate_identity(expected)
        record = json.loads(data.decode("ascii"), object_pairs_hook=_unique_pairs)
        if type(record) is not dict or set(record) != {
            "protocol_version", "profile_id", "identity", "limits", "inspection",
        }:
            raise ValueError("raster response shape")
        if (type(record["protocol_version"]) is not int
                or record["protocol_version"] != PROTOCOL_VERSION or record["profile_id"] != PROFILE_ID):
            raise ValueError("raster response version")
        _validate_identity(record["identity"])
        if record["identity"] != expected:
            raise ValueError("raster response identity")
        limits = record["limits"]
        if (type(limits) is not dict or set(limits) != set(_LIMITS)
                or any(type(v) is not int or v != _LIMITS[k] for k, v in limits.items())):
            raise ValueError("raster response limits")
        found = record["inspection"]
        if type(found) is not dict or set(found) != {
            "status", "raster_sha256", "total_pixels", "min_edge_margin_px", "inspected_pages",
        }:
            raise ValueError("raster inspection shape")
        if (found["status"] != "WINDOW_RASTER_INSPECTED" or type(found["inspected_pages"]) is not int
                or found["inspected_pages"] != expected["last_page"] - expected["first_page"] + 1):
            raise ValueError("raster inspection coverage")
        return PdfRasterWindowInspection(**expected, **{key: found[key] for key in
            ("raster_sha256", "total_pixels", "min_edge_margin_px")})
    except Exception:
        raise PdfRasterWindowError("pdf_raster_window_protocol_invalid") from None


def _start(command: list[str], fds: tuple[int, int, int], scratch: str) -> subprocess.Popen:
    """Launch the isolated worker with only declared protocol and private scratch descriptors."""
    return subprocess.Popen(command, cwd=Path(__file__).resolve().parents[1],
        env=raster_child_environment(scratch), shell=False,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        close_fds=True, pass_fds=fds, start_new_session=True)


def _wait(process: subprocess.Popen) -> int:
    """Keep child identity reserved until original-group cleanup and final reap."""
    return wait_owned_process_group(process, wall_seconds=WALL_SECONDS)


def _run_worker(pdf: bytes, identity: dict) -> bytes:
    """Own the exact scratch inode and anonymous request/result files for one invocation."""
    opted_in = bounded_scratch_requested()
    parent = bounded_scratch_parent()
    with tempfile.TemporaryDirectory(
        prefix="omnigenis-pdf-visual-supervisor-", dir=parent
    ) as scratch:
        scratch_fd = (
            _open_verified_bounded_child(scratch)
            if opted_in
            else os.open(
                scratch,
                os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
        )
        try:
            protocol_options = {"dir": parent} if opted_in else {}
            with tempfile.TemporaryFile(**protocol_options) as source, \
                    tempfile.TemporaryFile(**protocol_options) as result:
                fds = source.fileno(), result.fileno(), scratch_fd
                infos = [os.fstat(fd) for fd in fds[:2]]
                _require_same_bounded_mount(scratch_fd, *fds[:2])
                if any(not stat.S_ISREG(i.st_mode) or i.st_nlink != 0 for i in infos):
                    raise ValueError("anonymous raster protocol required")
                if (infos[0].st_dev, infos[0].st_ino) == (infos[1].st_dev, infos[1].st_ino):
                    raise ValueError("distinct raster protocol required")
                header = " ".join([str(PROTOCOL_VERSION), *(str(identity[k]) for k in IDENTITY_FIELDS)])
                source.write(header.encode("ascii") + b"\n"); source.write(pdf); source.flush()
                process = _start([sys.executable, "-I",
                    str(Path(__file__).resolve().with_name("_pdf_raster_window_worker.py")),
                    *(str(fd) for fd in fds), str(os.getpid())], fds, scratch)
                if _wait(process) != 0 or not 0 < os.fstat(result.fileno()).st_size <= RESULT_BYTES:
                    raise ValueError("raster worker failed")
                result.seek(0)
                return result.read(RESULT_BYTES + 1)
        finally:
            os.close(scratch_fd)


def inspect_pdf_raster_window(
    *, pdf_bytes: object, plan: PageWindowPlan, window_index: int,
    expected_plan_sha256: str,
) -> PdfRasterWindowInspection:
    """Inspect one native raster interval without modifying default whole-file qualification.

    The optional 512-page class accepts at most four selected pages per call.
    It checks blank pages, simple geometry and edge-contact risk, not visual
    semantics, font/color correctness, accessibility, full coverage or release.
    """
    if (sys.platform != "linux"
            or os.environ.get("OMNIGENIS_PDF_RASTER_WINDOWS_DISABLED") == "1"):
        raise PdfRasterWindowError("pdf_raster_window_execution_unavailable")
    if (type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b"%PDF-1.7")
            or len(pdf_bytes) > MAX_PDF_BYTES):
        raise PdfRasterWindowError("pdf_raster_window_input_invalid")
    try:
        if type(plan) is not PageWindowPlan or not _is_digest(expected_plan_sha256):
            raise ValueError("typed raster plan required")
        plan.__post_init__()
        if (plan.plan_sha256 != expected_plan_sha256 or plan.inspector_profile_id != PROFILE_ID
                or plan.page_count > MAX_DOCUMENT_PAGES or plan.pages_per_window > MAX_WINDOW_PAGES
                or type(window_index) is not int or not 0 <= window_index < plan.window_count
                or hashlib.sha256(pdf_bytes).hexdigest() != plan.pdf_sha256):
            raise ValueError("raster plan mismatch")
        window = plan.windows[window_index]
        identity = {"pdf_sha256": plan.pdf_sha256, "ir_sha256": plan.ir_sha256,
            "plan_sha256": plan.plan_sha256, "page_count": plan.page_count,
            "window_index": window.index, "first_page": window.first_page, "last_page": window.last_page}
        _validate_identity(identity)
    except Exception:
        raise PdfRasterWindowError("pdf_raster_window_plan_invalid") from None
    try:
        receipt = _decode(_run_worker(pdf_bytes, identity), identity)
        plan.__post_init__()
        if plan.plan_sha256 != expected_plan_sha256:
            raise ValueError("raster plan changed")
        return receipt
    except Exception:
        raise PdfRasterWindowError("pdf_raster_window_execution_failed") from None
