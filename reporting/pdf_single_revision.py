"""Optional strict single-xref-revision admission for generated PDF candidates.

This unsigned, bounded receipt does not audit every PDF object or revision,
prove accessible semantics, activate delivery, or authorize any release.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

from reporting.page_windows import PageWindowPlan
from reporting.pdf_text_windows import PROFILE_ID as TEXT_PROFILE
from reporting import pdf_structure_role_edges as prior
from reporting.pdf_object_graph import _canonical, _start, _unique_pairs, _wait
from reporting._pdf_object_graph_worker import (
    CPU_SECONDS, IDENTITY_FIELDS, MAX_PDF_BYTES, MEMORY_BYTES, OPEN_FILES,
    PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES, _is_digest,
)
from reporting._pdf_single_revision_worker import (
    LANGUAGE, MAX_DOCUMENT_PAGES, POLICY_ID, PROFILE_ID, STATUS,
    _identity, _identity_from_plan,
)

_DISABLE = "OMNIGENIS_PDF_SINGLE_REVISION_DISABLED"
_FIXED_PARENT_PROFILE = "c1a94f20313eb3bbfc0744ae14b4d7029f6f753e151e1b6f28fbbb73f711bff9"
_FIXED_ENVELOPE = (64, 16 * 1024 * 1024)
_LIMITS = {
    "memory_bytes": MEMORY_BYTES, "cpu_seconds": CPU_SECONDS,
    "file_bytes": RESULT_BYTES, "open_files": OPEN_FILES,
}


class PdfSingleRevisionError(ValueError):
    """Fixed content-free refusal: the generated single-xref subset was not proved."""


def single_revision_profile() -> dict:
    """Return the one generated single-xref-stream admission contract."""
    return {
        "schema_version": "1.0.0",
        "profile_id": PROFILE_ID, "policy_id": POLICY_ID,
        "parser_version": PARSER_VERSION,
        "previous_role_edges_profile_sha256": prior.PROFILE_SHA256,
        "language": LANGUAGE,
        "max_pages": MAX_DOCUMENT_PAGES,
        "max_pdf_bytes": MAX_PDF_BYTES,
        "supported_xref_kind": "STREAM",
        "marker_policy": "EXACTLY_ONE_RAW_STARTXREF_AND_EOF",
        "exact_terminal_syntax_required": True,
        "xref_offset_bound_to_physical_object": True,
        "xref_prev_chain_allowed": False,
        "conformance_scope": "GENERATED_SINGLE_XREF_STREAM_ADMISSION_ONLY",
        "all_file_revisions_inspected": False,
        "opaque_payloads_audited": False,
        "single_xref_revision_admitted": True,
        "pdf_ua_qualified": False,
        "reading_order_verified": False,
        "worker_results_authenticated": False,
        "aggregate_job_resources_qualified": False,
        "default_pipeline_activated": False,
        "release_authorized": False,
    }


PROFILE_SHA256 = sha256(_canonical(single_revision_profile())).hexdigest()
_FIXED_PROFILE_SHA256 = "564a7e609902c3ad8abbe9e7b17b0e5f612931521d6af7017d94bee53873c9f9"


def _profile() -> None:
    """Refuse unknown host, profile, parser or dependency changes and disables."""
    prior._profile()
    if (sys.platform != "linux" or os.environ.get(_DISABLE) == "1"
            or (MAX_DOCUMENT_PAGES, MAX_PDF_BYTES) != _FIXED_ENVELOPE
            or LANGUAGE != "en-US" or PARSER_VERSION != "6.19.0"
            or prior.PROFILE_SHA256 != _FIXED_PARENT_PROFILE
            or PROFILE_SHA256 != _FIXED_PROFILE_SHA256
            or sha256(_canonical(single_revision_profile())).hexdigest()
               != PROFILE_SHA256):
        raise ValueError("generated single-xref profile disabled or changed")


@dataclass(frozen=True, slots=True, repr=False)
class PdfSingleRevision:
    """Checksum-bound metadata-only statement, not a worker signature."""

    pdf_sha256: str
    ir_sha256: str
    plan_sha256: str
    page_count: int
    xref_offset: int
    xref_object_number: int
    xref_marker_pairs: int
    role_edge_inspection_sha256: str
    _sealed_sha256: str = field(init=False, repr=False, compare=False)

    def _record(self) -> dict:
        _profile()
        _identity({key: getattr(self, key) for key in IDENTITY_FIELDS})
        if (type(self.xref_offset) is not int
                or type(self.xref_object_number) is not int
                or type(self.xref_marker_pairs) is not int
                or not 9 < self.xref_offset < MAX_PDF_BYTES
                or not 1 <= self.xref_object_number <= 20000
                or self.xref_marker_pairs != 1
                or not _is_digest(self.role_edge_inspection_sha256)):
            raise ValueError("single-xref receipt out of bound")
        return {
            "schema_version": "1.0.0",
            "profile_id": PROFILE_ID, "policy_id": POLICY_ID,
            "status": STATUS, "parser_version": PARSER_VERSION,
            "language": LANGUAGE, "profile_sha256": PROFILE_SHA256,
            "previous_role_edges_profile_sha256": prior.PROFILE_SHA256,
            "pdf_sha256": self.pdf_sha256, "ir_sha256": self.ir_sha256,
            "plan_sha256": self.plan_sha256, "page_count": self.page_count,
            "xref_offset": self.xref_offset,
            "xref_object_number": self.xref_object_number,
            "xref_marker_pairs": self.xref_marker_pairs,
            "role_edge_inspection_sha256": self.role_edge_inspection_sha256,
            "single_xref_revision_admitted": True,
            "all_file_revisions_inspected": False,
            "opaque_payloads_audited": False,
            "pdf_ua_qualified": False, "reading_order_verified": False,
            "worker_results_authenticated": False,
            "aggregate_job_resources_qualified": False,
            "default_pipeline_activated": False, "release_authorized": False,
            "release_authorization": "NOT_ESTABLISHED",
        }

    def __post_init__(self) -> None:
        try:
            raw = _canonical(self._record())
            if len(raw) > RESULT_BYTES:
                raise ValueError("single-xref receipt exceeds result budget")
            digest = sha256(raw).hexdigest()
            if hasattr(self, "_sealed_sha256") and self._sealed_sha256 != digest:
                raise ValueError("single-xref receipt mutated")
            object.__setattr__(self, "_sealed_sha256", digest)
        except Exception:
            raise PdfSingleRevisionError("pdf_single_revision_receipt_invalid") from None

    def to_bytes(self) -> bytes:
        try:
            raw = _canonical(self._record())
            if len(raw) > RESULT_BYTES or sha256(raw).hexdigest() != self._sealed_sha256:
                raise ValueError("single-xref receipt was modified")
            return raw
        except Exception:
            raise PdfSingleRevisionError("pdf_single_revision_receipt_invalid") from None

    def to_dict(self) -> dict:
        return json.loads(self.to_bytes())

    @property
    def inspection_sha256(self) -> str:
        """Metadata checksum only; native worker output is not authenticated."""
        return sha256(self.to_bytes()).hexdigest()


def _decode(data: bytes, identity: dict, role_digest: str) -> PdfSingleRevision:
    """Validate exact native worker schema, resources and source identity."""
    try:
        _identity(identity)
        if not _is_digest(role_digest) or type(data) is not bytes:
            raise ValueError("single-xref wire or prior receipt missing")
        if not 0 < len(data) <= RESULT_BYTES:
            raise ValueError("single-xref wire size invalid")
        record = json.loads(data.decode("ascii"), object_pairs_hook=_unique_pairs)
        if (type(record) is not dict or set(record) != {
                "protocol_version", "profile_id", "policy_id", "parser_version",
                "identity", "limits", "inspection"}
                or type(record["protocol_version"]) is not int
                or record["protocol_version"] != PROTOCOL_VERSION
                or record["profile_id"] != PROFILE_ID or record["policy_id"] != POLICY_ID
                or record["parser_version"] != PARSER_VERSION):
            raise ValueError("single-xref wire profile changed")
        _identity(record["identity"])
        if record["identity"] != identity:
            raise ValueError("single-xref identity changed")
        limits = record["limits"]
        if (type(limits) is not dict or set(limits) != set(_LIMITS)
                or any(type(value) is not int or value != _LIMITS[key]
                       for key, value in limits.items())):
            raise ValueError("single-xref child limits changed")
        inspection = record["inspection"]
        if (type(inspection) is not dict or set(inspection) != {
                "status", "xref_offset", "xref_object_number", "xref_marker_pairs"}
                or inspection["status"] != STATUS):
            raise ValueError("single-xref inspection envelope invalid")
        return PdfSingleRevision(
            **identity, xref_offset=inspection["xref_offset"],
            xref_object_number=inspection["xref_object_number"],
            xref_marker_pairs=inspection["xref_marker_pairs"],
            role_edge_inspection_sha256=role_digest,
        )
    except Exception:
        raise PdfSingleRevisionError("pdf_single_revision_protocol_invalid") from None


def _run_worker(pdf: bytes, identity: dict) -> bytes:
    """Dispatch one fixed isolated child through anonymous, owned descriptors."""
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as result:
        fds = (source.fileno(), result.fileno())
        infos = [os.fstat(fd) for fd in fds]
        if (any(not stat.S_ISREG(info.st_mode) or info.st_nlink != 0
                or info.st_uid != os.geteuid() for info in infos)
                or (infos[0].st_dev, infos[0].st_ino)
                   == (infos[1].st_dev, infos[1].st_ino)):
            raise ValueError("single-xref native descriptor invalid")
        header = " ".join([str(PROTOCOL_VERSION), *(str(identity[key])
                          for key in IDENTITY_FIELDS)])
        source.write(header.encode("ascii") + b"\n")
        source.write(pdf)
        source.flush()
        process = _start([
            sys.executable, "-I",
            str(Path(__file__).resolve().with_name("_pdf_single_revision_worker.py")),
            str(fds[0]), str(fds[1]), str(os.getpid()),
        ], fds)
        if _wait(process) != 0 or not 0 < os.fstat(result.fileno()).st_size <= RESULT_BYTES:
            raise ValueError("single-xref native child did not complete")
        result.seek(0)
        return result.read(RESULT_BYTES + 1)


def inspect_pdf_single_revision(
    *, pdf_bytes: object, plan: PageWindowPlan,
    expected_plan_sha256: str, expected_language: str,
) -> PdfSingleRevision:
    """Admit only the prior-validated exact generated PDF with a single xref."""
    try:
        _profile()
        if (type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b"%PDF-1.7")
                or not 0 < len(pdf_bytes) <= MAX_PDF_BYTES
                or type(plan) is not PageWindowPlan
                or not _is_digest(expected_plan_sha256)
                or type(expected_language) is not str or expected_language != LANGUAGE):
            raise ValueError("single-xref input or locale unsupported")
        plan.__post_init__()
        if (plan.plan_sha256 != expected_plan_sha256
                or plan.inspector_profile_id != TEXT_PROFILE
                or plan.page_count > MAX_DOCUMENT_PAGES
                or plan.pdf_sha256 != sha256(pdf_bytes).hexdigest()):
            raise ValueError("single-xref request identity does not bind PDF")
        identity = _identity_from_plan(plan)
    except Exception:
        raise PdfSingleRevisionError("pdf_single_revision_input_invalid") from None
    try:
        previous = prior.inspect_pdf_structure_role_edges(
            pdf_bytes=pdf_bytes, plan=plan,
            expected_plan_sha256=expected_plan_sha256,
            expected_language=expected_language,
        )
        prior_digest = previous.inspection_sha256
        result = _decode(_run_worker(pdf_bytes, identity), identity, prior_digest)
        plan.__post_init__()
        _profile()
        if (plan.plan_sha256 != expected_plan_sha256
                or _identity_from_plan(plan) != identity
                or previous.inspection_sha256 != prior_digest):
            raise ValueError("single-xref parent plan or prerequisite changed")
        return result
    except Exception:
        raise PdfSingleRevisionError("pdf_single_revision_execution_failed") from None
