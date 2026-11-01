"""Opt-in bounded inspection of the effective graph of a complete generated PDF.

This adapter reuses the passive object deny policy without changing the default
32-page route. It binds a local worker result to independently sealed PDF, IR and
plan identities. The unsigned metadata is not portable proof of execution,
authentication, every historical object, opaque stream safety, full PDF or report
qualification, accessibility, aggregate job resources or release authorization.
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

from reporting._pdf_document_byte_budget import require_pdf_document_budget
from reporting._pdf_native_launch_budget import admit_launch, wait_native_process_group

from reporting._pdf_object_graph_worker import (
    CPU_SECONDS, IDENTITY_FIELDS, MAX_DOCUMENT_PAGES, MAX_PDF_BYTES, MAX_VISITS,
    MEMORY_BYTES, OPEN_FILES, PARSER_VERSION, POLICY_ID, PROFILE_ID,
    PROTOCOL_VERSION, RESULT_BYTES, STATUS, WALL_SECONDS, _is_digest, _validate_identity,
)
from reporting.page_windows import PageWindowPlan

_LIMITS = {"memory_bytes": MEMORY_BYTES, "cpu_seconds": CPU_SECONDS,
           "file_bytes": RESULT_BYTES, "open_files": OPEN_FILES}


class PdfObjectGraphError(ValueError):
    """Fixed rejection; no failure provides a successful graph inspection receipt."""


def _canonical(value: object) -> bytes:
    """Encode detached metadata with the existing canonical JSON convention."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _unique_pairs(pairs: list) -> dict:
    """Reject duplicate wire-protocol names rather than selecting the last value."""
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate protocol field")
        out[key] = value
    return out


@dataclass(frozen=True, slots=True, repr=False)
class PdfObjectGraphInspection:
    """Unsigned effective-object count bound to one exact declared document plan."""

    pdf_sha256: str
    ir_sha256: str
    plan_sha256: str
    page_count: int
    object_count: int

    def __post_init__(self) -> None:
        """Require canonical identities and finite counts; construction is not authentication."""
        try:
            _validate_identity(self._identity())
            if type(self.object_count) is not int or not self.page_count <= self.object_count <= MAX_VISITS:
                raise ValueError("invalid graph count")
        except Exception:
            raise PdfObjectGraphError("pdf_object_graph_receipt_invalid") from None

    def _identity(self) -> dict:
        """Detach the request identity without adding execution or source authority."""
        return {key: getattr(self, key) for key in IDENTITY_FIELDS}

    def to_dict(self) -> dict:
        """Expose only bounded graph metadata and explicit unqualified safety dimensions."""
        self.__post_init__()
        return {"schema_version": "1.0.0", "profile_id": PROFILE_ID, "policy_id": POLICY_ID,
                "status": STATUS, **self._identity(), "object_count": self.object_count,
                "parser_version": PARSER_VERSION,
                "inspection_scope": "EFFECTIVE_TRAILER_REACHABLE_OBJECTS_ONLY",
                "all_file_revisions_inspected": False, "opaque_stream_payloads_inspected": False,
                "worker_results_authenticated": False, "whole_pdf_safety_qualified": False,
                "text_equivalence_verified": False, "accessibility_qualified": False,
                "aggregate_job_resources_qualified": False, "release_authorized": False,
                "release_authorization": "NOT_ESTABLISHED"}

    @property
    def inspection_sha256(self) -> str:
        """Hash this exact unsigned record without claiming an authenticated attestation."""
        return hashlib.sha256(_canonical(self.to_dict())).hexdigest()


def _decode(data: bytes, expected: dict) -> PdfObjectGraphInspection:
    """Require every field of the exact successful protocol before constructing a receipt."""
    try:
        if type(data) is not bytes or not 0 < len(data) <= RESULT_BYTES:
            raise ValueError("protocol byte budget")
        _validate_identity(expected)
        record = json.loads(data.decode("ascii"), object_pairs_hook=_unique_pairs)
        if type(record) is not dict or set(record) != {
            "protocol_version", "profile_id", "policy_id", "parser_version", "identity", "limits", "inspection",
        }:
            raise ValueError("protocol shape")
        if (type(record["protocol_version"]) is not int or record["protocol_version"] != PROTOCOL_VERSION
                or record["profile_id"] != PROFILE_ID or record["policy_id"] != POLICY_ID
                or record["parser_version"] != PARSER_VERSION):
            raise ValueError("protocol profile")
        _validate_identity(record["identity"])
        if record["identity"] != expected:
            raise ValueError("protocol identity")
        limits = record["limits"]
        if (type(limits) is not dict or set(limits) != set(_LIMITS)
                or any(type(v) is not int or v != _LIMITS[k] for k, v in limits.items())):
            raise ValueError("protocol limits")
        inspection = record["inspection"]
        if (type(inspection) is not dict or set(inspection) != {"status", "object_count"}
                or inspection["status"] != STATUS):
            raise ValueError("protocol inspection")
        return PdfObjectGraphInspection(**expected, object_count=inspection["object_count"])
    except Exception:
        raise PdfObjectGraphError("pdf_object_graph_protocol_invalid") from None


def _start(command: list[str], fds: tuple[int, int]) -> subprocess.Popen:
    """Start the isolated fixed worker inheriting only its anonymous request and result."""
    with admit_launch("object_graph", command, fds):
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
    """Exchange bounded protocol data with the fixed worker using distinct anonymous files."""
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as result:
        fds = source.fileno(), result.fileno()
        infos = [os.fstat(fd) for fd in fds]
        if any(not stat.S_ISREG(i.st_mode) or i.st_nlink != 0 for i in infos):
            raise ValueError("anonymous protocol required")
        if (infos[0].st_dev, infos[0].st_ino) == (infos[1].st_dev, infos[1].st_ino):
            raise ValueError("distinct protocol files required")
        header = " ".join([str(PROTOCOL_VERSION), *(str(identity[k]) for k in IDENTITY_FIELDS)])
        source.write(header.encode("ascii") + b"\n")
        source.write(pdf)
        source.flush()
        process = _start([sys.executable, "-I",
                          str(Path(__file__).resolve().with_name("_pdf_object_graph_worker.py")),
                          str(fds[0]), str(fds[1]), str(os.getpid())], fds)
        if _wait(process) != 0 or not 0 < os.fstat(result.fileno()).st_size <= RESULT_BYTES:
            raise ValueError("object graph worker failed")
        result.seek(0)
        return result.read(RESULT_BYTES + 1)


def inspect_pdf_object_graph(
    *, pdf_bytes: object, plan: PageWindowPlan, expected_plan_sha256: str,
) -> PdfObjectGraphInspection:
    """Inspect a complete effective graph under the optional bounded generated-PDF class.

    The window plan contributes document identity only; its inspector is not
    changed. This result is separate from all window observations and cannot
    substitute for text coverage, global semantic QA, rendering or release.
    """
    if (sys.platform != "linux"
            or os.environ.get("OMNIGENIS_PDF_OBJECT_GRAPH_DISABLED") == "1"):
        raise PdfObjectGraphError("pdf_object_graph_execution_unavailable")
    if (type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b"%PDF-1.7")
            or len(pdf_bytes) > MAX_PDF_BYTES):
        raise PdfObjectGraphError("pdf_object_graph_input_invalid")
    try:
        if type(plan) is not PageWindowPlan or not _is_digest(expected_plan_sha256):
            raise ValueError("sealed plan required")
        plan.__post_init__()
        require_pdf_document_budget(len(pdf_bytes), plan.page_count)
        if (plan.plan_sha256 != expected_plan_sha256 or plan.page_count > MAX_DOCUMENT_PAGES
                or hashlib.sha256(pdf_bytes).hexdigest() != plan.pdf_sha256):
            raise ValueError("plan admission mismatch")
        identity = {"pdf_sha256": plan.pdf_sha256, "ir_sha256": plan.ir_sha256,
                    "plan_sha256": plan.plan_sha256, "page_count": plan.page_count}
        _validate_identity(identity)
    except Exception:
        raise PdfObjectGraphError("pdf_object_graph_plan_invalid") from None
    try:
        receipt = _decode(_run_worker(pdf_bytes, identity), identity)
        plan.__post_init__()
        if plan.plan_sha256 != expected_plan_sha256:
            raise ValueError("plan changed during inspection")
        return receipt
    except Exception:
        raise PdfObjectGraphError("pdf_object_graph_execution_failed") from None
