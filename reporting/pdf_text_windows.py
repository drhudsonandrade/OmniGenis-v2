"""Opt-in exact-plan adapter for bounded generated-PDF text-window inspection.

The adapter observes one local guarded worker and returns unsigned digest/count
metadata. It does not authenticate the job or generating source, validate the
whole PDF, establish scientific text equivalence, schedule further windows,
persist a checkpoint or authorize release. Existing whole-file validators and
default renderer paths are unchanged. The caller must supply sealed expectations
and supervise aggregate job resources and any later checkpoint publication.
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

from reporting._pdf_native_launch_budget import admit_launch, wait_native_process_group

from reporting._pdf_text_window_worker import (
    CPU_SECONDS, EXTRACTOR_VERSION, IDENTITY_FIELDS, MAX_DECODED_BYTES,
    MAX_DOCUMENT_PAGES, MAX_PDF_BYTES, MAX_TEXT_BYTES, MAX_WINDOW_PAGES,
    MEMORY_BYTES, OPEN_FILES, PROFILE_ID, PROTOCOL_VERSION, RESULT_BYTES,
    WALL_SECONDS, _is_digest, _validate_identity,
)
from reporting.page_windows import PageWindowPlan, WindowObservation

_LIMITS = {"memory_bytes": MEMORY_BYTES, "cpu_seconds": CPU_SECONDS,
           "file_bytes": RESULT_BYTES, "open_files": OPEN_FILES}


class PdfTextWindowError(ValueError):
    """Content-free rejection; an error never provides a successful observation."""


def _canonical(value: object) -> bytes:
    """Encode validated metadata with the established deterministic JSON convention."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _unique_pairs(pairs: list) -> dict:
    """Reject duplicate protocol names instead of silently replacing earlier values."""
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate response field")
        out[key] = value
    return out


@dataclass(frozen=True, slots=True, repr=False)
class PdfTextWindowInspection:
    """Unsigned exact-window metadata, not a transferable execution attestation."""

    pdf_sha256: str
    ir_sha256: str
    plan_sha256: str
    page_count: int
    window_index: int
    first_page: int
    last_page: int
    text_sha256: str
    text_bytes: int
    text_chars: int
    decoded_bytes: int

    def __post_init__(self) -> None:
        """Revalidate all identities and finite nonempty selected-text count relations."""
        try:
            _validate_identity(self._identity())
            if not _is_digest(self.text_sha256):
                raise ValueError("text digest")
            for value, maximum in ((self.text_bytes, MAX_TEXT_BYTES),
                                   (self.text_chars, MAX_TEXT_BYTES),
                                   (self.decoded_bytes, MAX_DECODED_BYTES)):
                if type(value) is not int or not 1 <= value <= maximum:
                    raise ValueError("text count")
            if not self.inspected_pages <= self.text_chars <= self.text_bytes <= 4 * self.text_chars:
                raise ValueError("text count relation")
        except Exception:
            raise PdfTextWindowError("pdf_text_window_receipt_invalid") from None

    def _identity(self) -> dict:
        """Detach the complete request identity without accepting additional fields."""
        return {key: getattr(self, key) for key in IDENTITY_FIELDS}

    @property
    def inspected_pages(self) -> int:
        """Return the size of the exact inclusive interval represented by this receipt."""
        return self.last_page - self.first_page + 1

    def to_dict(self) -> dict:
        """Serialize digest/count evidence and explicitly unestablished global guarantees."""
        self.__post_init__()
        return {"schema_version": "1.0.0", "profile_id": PROFILE_ID,
                "status": "WINDOW_TEXT_INSPECTED", **self._identity(),
                "text_sha256": self.text_sha256, "text_bytes": self.text_bytes,
                "text_chars": self.text_chars, "decoded_bytes": self.decoded_bytes,
                "inspected_pages": self.inspected_pages, "parser_version": EXTRACTOR_VERSION,
                "text_digest_profile": "physical-page-and-utf8-length-framed-v1",
                "worker_results_authenticated": False,
                "whole_pdf_safety_qualified": False, "scientific_equivalence_verified": False,
                "aggregate_job_resources_qualified": False, "release_authorized": False,
                "release_authorization": "NOT_ESTABLISHED"}

    @property
    def observation_sha256(self) -> str:
        """Hash the full validated receipt; the hash alone does not authenticate it."""
        return hashlib.sha256(_canonical(self.to_dict())).hexdigest()

    def to_observation(self) -> WindowObservation:
        """Project into the existing inert ledger without storing or advancing a job."""
        self.__post_init__()
        return WindowObservation(index=self.window_index, first_page=self.first_page,
                                 last_page=self.last_page, pdf_sha256=self.pdf_sha256,
                                 plan_sha256=self.plan_sha256, inspector_profile_id=PROFILE_ID,
                                 observation_sha256=self.observation_sha256)


def _decode(data: bytes, expected: dict) -> PdfTextWindowInspection:
    """Accept only the exact current wire protocol with complete selected-page evidence."""
    try:
        if type(data) is not bytes or not 0 < len(data) <= RESULT_BYTES:
            raise ValueError("response size")
        _validate_identity(expected)
        record = json.loads(data.decode("ascii"), object_pairs_hook=_unique_pairs)
        if type(record) is not dict or set(record) != {
            "protocol_version", "profile_id", "identity", "limits", "inspection",
        }:
            raise ValueError("response shape")
        if (type(record["protocol_version"]) is not int
                or record["protocol_version"] != PROTOCOL_VERSION
                or record["profile_id"] != PROFILE_ID):
            raise ValueError("response version")
        _validate_identity(record["identity"])
        if record["identity"] != expected:
            raise ValueError("response identity")
        limits = record["limits"]
        if (type(limits) is not dict or set(limits) != set(_LIMITS)
                or any(type(v) is not int or v != _LIMITS[k] for k, v in limits.items())):
            raise ValueError("response limits")
        found = record["inspection"]
        if type(found) is not dict or set(found) != {
            "status", "text_sha256", "text_bytes", "text_chars", "decoded_bytes", "inspected_pages",
        }:
            raise ValueError("inspection shape")
        if (found["status"] != "WINDOW_TEXT_INSPECTED"
                or type(found["inspected_pages"]) is not int
                or found["inspected_pages"] != expected["last_page"] - expected["first_page"] + 1):
            raise ValueError("inspection coverage")
        return PdfTextWindowInspection(**expected, **{
            key: found[key] for key in ("text_sha256", "text_bytes", "text_chars", "decoded_bytes")})
    except Exception:
        raise PdfTextWindowError("pdf_text_window_protocol_invalid") from None


def _start(command: list[str], fds: tuple[int, int]) -> subprocess.Popen:
    """Launch an isolated child with only the two declared protocol descriptors."""
    with admit_launch("text_windows", command, fds):
        return subprocess.Popen(
            command, cwd=Path(__file__).resolve().parents[1],
            env={"PATH": os.defpath, "LANG": "C.UTF-8"}, shell=False,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True, pass_fds=fds, start_new_session=True,
        )


def _wait(process: subprocess.Popen) -> int:
    """Keep child identity reserved until original-group cleanup and final reap."""
    return wait_native_process_group(process, wall_seconds=WALL_SECONDS)


def _run_worker(pdf: bytes, identity: dict) -> bytes:
    """Use bounded anonymous request/result files, never pipes or arbitrary commands."""
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as result:
        fds = source.fileno(), result.fileno()
        infos = [os.fstat(fd) for fd in fds]
        if any(not stat.S_ISREG(i.st_mode) or i.st_nlink != 0 for i in infos):
            raise ValueError("anonymous protocol required")
        if (infos[0].st_dev, infos[0].st_ino) == (infos[1].st_dev, infos[1].st_ino):
            raise ValueError("distinct protocol objects required")
        header = " ".join([str(PROTOCOL_VERSION), *(str(identity[k]) for k in IDENTITY_FIELDS)])
        source.write(header.encode("ascii") + b"\n")
        source.write(pdf)
        source.flush()
        process = _start([sys.executable, "-I",
                          str(Path(__file__).resolve().with_name("_pdf_text_window_worker.py")),
                          str(fds[0]), str(fds[1]), str(os.getpid())], fds)
        if _wait(process) != 0 or not 0 < os.fstat(result.fileno()).st_size <= RESULT_BYTES:
            raise ValueError("window process failed")
        result.seek(0)
        return result.read(RESULT_BYTES + 1)


def inspect_pdf_text_window(
    *, pdf_bytes: object, plan: PageWindowPlan, window_index: int,
    expected_plan_sha256: str,
) -> PdfTextWindowInspection:
    """Observe one bounded native interval with independently pinned sealed inputs.

    The 512-page internal class does not replace the default 32-page whole-file
    policy. Text extraction cannot establish original report completeness,
    arbitrary PDF safety, visual correctness, source authenticity or release.
    """
    if (sys.platform != "linux"
            or os.environ.get("OMNIGENIS_PDF_TEXT_WINDOWS_DISABLED") == "1"):
        raise PdfTextWindowError("pdf_text_window_execution_unavailable")
    if (type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b"%PDF-1.7")
            or len(pdf_bytes) > MAX_PDF_BYTES):
        raise PdfTextWindowError("pdf_text_window_input_invalid")
    try:
        if type(plan) is not PageWindowPlan or not _is_digest(expected_plan_sha256):
            raise ValueError("typed sealed plan required")
        plan.__post_init__()
        if (plan.plan_sha256 != expected_plan_sha256 or plan.inspector_profile_id != PROFILE_ID
                or plan.page_count > MAX_DOCUMENT_PAGES or plan.pages_per_window > MAX_WINDOW_PAGES
                or type(window_index) is not int or not 0 <= window_index < plan.window_count
                or hashlib.sha256(pdf_bytes).hexdigest() != plan.pdf_sha256):
            raise ValueError("plan admission mismatch")
        window = plan.windows[window_index]
        identity = {"pdf_sha256": plan.pdf_sha256, "ir_sha256": plan.ir_sha256,
                    "plan_sha256": plan.plan_sha256, "page_count": plan.page_count,
                    "window_index": window.index, "first_page": window.first_page,
                    "last_page": window.last_page}
        _validate_identity(identity)
    except Exception:
        raise PdfTextWindowError("pdf_text_window_plan_invalid") from None
    try:
        receipt = _decode(_run_worker(pdf_bytes, identity), identity)
        plan.__post_init__()
        if plan.plan_sha256 != expected_plan_sha256:
            raise ValueError("plan changed during execution")
        return receipt
    except Exception:
        raise PdfTextWindowError("pdf_text_window_execution_failed") from None
