"""Opt-in exact page/ParentTree reference checks with no semantic release authority.

The worker inspects a restricted tagged-PDF structural correspondence profile.
Its signed-off catalog prerequisites and exact physical counts cannot establish
PDF/UA conformance, every MCID, reading order, semantics or complete text.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

from reporting._pdf_page_tags_worker import (
    CPU_SECONDS, IDENTITY_FIELDS, LANGUAGE, MAX_DOCUMENT_PAGES, MAX_PDF_BYTES,
    MEMORY_BYTES, OPEN_FILES, PARSER_VERSION, POLICY_ID, PROFILE_ID,
    PROTOCOL_VERSION, RESULT_BYTES, STATUS, _is_digest, _validate_identity,
)
from reporting.page_windows import PageWindowPlan
from reporting.pdf_object_graph import _canonical, _start, _unique_pairs, _wait

_LIMITS = {"memory_bytes": MEMORY_BYTES, "cpu_seconds": CPU_SECONDS,
           "file_bytes": RESULT_BYTES, "open_files": OPEN_FILES}


class PdfPageTagError(ValueError):
    """Opaque failure: no rejected candidate receives a successful receipt."""


@dataclass(frozen=True, slots=True, repr=False)
class PdfPageTagInspection:
    """Immutable local document identity with bounded physical reference counts."""

    pdf_sha256: str
    ir_sha256: str
    plan_sha256: str
    page_count: int
    tagged_pages: int
    parent_tree_entries: int

    def __post_init__(self) -> None:
        """Reject forged or non-native counts, including boolean-as-integer claims."""
        try:
            _validate_identity(self._identity())
            if (type(self.tagged_pages) is not int
                    or type(self.parent_tree_entries) is not int
                    or self.tagged_pages != self.page_count
                    or self.parent_tree_entries != self.page_count):
                raise ValueError("page tag coverage count invalid")
        except Exception:
            raise PdfPageTagError("pdf_page_tags_receipt_invalid") from None

    def _identity(self) -> dict:
        """Project only the previously established exact worker document identity."""
        return {key: getattr(self, key) for key in IDENTITY_FIELDS}

    def to_dict(self) -> dict:
        """Expose fixed conservative scope and explicitly unestablished dimensions."""
        self.__post_init__()
        return {"schema_version": "1.0.0", "profile_id": PROFILE_ID,
                "policy_id": POLICY_ID, "status": STATUS, **self._identity(),
                "language": LANGUAGE, "tagged_pages": self.tagged_pages,
                "parent_tree_entries": self.parent_tree_entries,
                "catalog_prerequisites_met": True,
                "parser_version": PARSER_VERSION,
                "inspection_scope": "PAGE_STRUCTPARENTS_PARENTTREE_REFERENCE_COHERENCE_ONLY",
                "all_marked_content_covered": False,
                "semantic_tag_tree_verified": False,
                "reading_order_verified": False,
                "full_accessibility_qualified": False,
                "all_metadata_channels_inspected": False,
                "aggregate_job_resources_qualified": False,
                "worker_results_authenticated": False,
                "release_authorized": False,
                "release_authorization": "NOT_ESTABLISHED"}

    @property
    def inspection_sha256(self) -> str:
        """Hash the detached unsigned receipt without asserting portable provenance."""
        return hashlib.sha256(_canonical(self.to_dict())).hexdigest()


def _decode(data: bytes, expected: dict) -> PdfPageTagInspection:
    """Require exact profile, identity, finite limits, native types and full-page counts."""
    try:
        if type(data) is not bytes or not 0 < len(data) <= RESULT_BYTES:
            raise ValueError("page tag response size")
        _validate_identity(expected)
        message = json.loads(data.decode("ascii"), object_pairs_hook=_unique_pairs)
        if (type(message) is not dict or set(message) != {
                "protocol_version", "profile_id", "policy_id", "parser_version",
                "identity", "limits", "inspection"}):
            raise ValueError("page tag response shape")
        if (type(message["protocol_version"]) is not int
                or message["protocol_version"] != PROTOCOL_VERSION
                or message["profile_id"] != PROFILE_ID
                or message["policy_id"] != POLICY_ID
                or message["parser_version"] != PARSER_VERSION):
            raise ValueError("page tag response profile")
        _validate_identity(message["identity"])
        if message["identity"] != expected:
            raise ValueError("page tag response foreign identity")
        limits = message["limits"]
        if (type(limits) is not dict or set(limits) != set(_LIMITS)
                or any(type(v) is not int or v != _LIMITS[key]
                       for key, v in limits.items())):
            raise ValueError("page tag response limits")
        found = message["inspection"]
        if (type(found) is not dict
                or set(found) != {"status", "language", "tagged_pages", "parent_tree_entries"}
                or found["status"] != STATUS or found["language"] != LANGUAGE
                or type(found["tagged_pages"]) is not int
                or type(found["parent_tree_entries"]) is not int
                or found["tagged_pages"] != expected["page_count"]
                or found["parent_tree_entries"] != expected["page_count"]):
            raise ValueError("page tag response inspection")
        return PdfPageTagInspection(**expected, tagged_pages=found["tagged_pages"],
                                    parent_tree_entries=found["parent_tree_entries"])
    except Exception:
        raise PdfPageTagError("pdf_page_tags_protocol_invalid") from None


def _run_worker(pdf: bytes, identity: dict) -> bytes:
    """Run one fixed disposable child with two distinct owned anonymous protocol files."""
    with tempfile.TemporaryFile() as request, tempfile.TemporaryFile() as result:
        fds = request.fileno(), result.fileno()
        infos = [os.fstat(fd) for fd in fds]
        if any(not stat.S_ISREG(v.st_mode) or v.st_nlink != 0
               or v.st_uid != os.geteuid() for v in infos):
            raise ValueError("page tag anonymous protocol required")
        if (infos[0].st_dev, infos[0].st_ino) == (infos[1].st_dev, infos[1].st_ino):
            raise ValueError("page tag distinct descriptors required")
        header = " ".join([str(PROTOCOL_VERSION), *(str(identity[k]) for k in IDENTITY_FIELDS)])
        request.write(header.encode("ascii") + b"\n")
        request.write(pdf)
        request.flush()
        process = _start([sys.executable, "-I",
                          str(Path(__file__).resolve().with_name("_pdf_page_tags_worker.py")),
                          str(fds[0]), str(fds[1]), str(os.getpid())], fds)
        if _wait(process) != 0 or not 0 < os.fstat(result.fileno()).st_size <= RESULT_BYTES:
            raise ValueError("page tag guarded worker did not complete")
        result.seek(0)
        return result.read(RESULT_BYTES + 1)


def inspect_pdf_page_tag_parents(
    *, pdf_bytes: object, plan: PageWindowPlan,
    expected_plan_sha256: str, expected_language: str,
) -> PdfPageTagInspection:
    """Inspect exact final PDF physical-page/parent-tree slots, not all tag semantics.

    Only the existing en-US generated PDF 1.7 profile is supported, and no
    default validator, report bundle, scientific or release path is activated.
    """
    if (sys.platform != "linux"
            or os.environ.get("OMNIGENIS_PDF_PAGE_TAGS_DISABLED") == "1"):
        raise PdfPageTagError("pdf_page_tags_execution_unavailable")
    if (type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b"%PDF-1.7")
            or len(pdf_bytes) > MAX_PDF_BYTES):
        raise PdfPageTagError("pdf_page_tags_input_invalid")
    if type(expected_language) is not str or expected_language != LANGUAGE:
        raise PdfPageTagError("pdf_page_tags_language_unavailable")
    try:
        if type(plan) is not PageWindowPlan or not _is_digest(expected_plan_sha256):
            raise ValueError("page tag plan expected")
        plan.__post_init__()
        if (plan.plan_sha256 != expected_plan_sha256
                or plan.page_count > MAX_DOCUMENT_PAGES
                or hashlib.sha256(pdf_bytes).hexdigest() != plan.pdf_sha256):
            raise ValueError("page tag plan identity mismatch")
        identity = {"pdf_sha256": plan.pdf_sha256, "ir_sha256": plan.ir_sha256,
                    "plan_sha256": plan.plan_sha256, "page_count": plan.page_count}
        _validate_identity(identity)
    except Exception:
        raise PdfPageTagError("pdf_page_tags_plan_invalid") from None
    try:
        inspection = _decode(_run_worker(pdf_bytes, identity), identity)
        plan.__post_init__()
        if plan.plan_sha256 != expected_plan_sha256:
            raise ValueError("page tag plan changed during native execution")
        return inspection
    except Exception:
        raise PdfPageTagError("pdf_page_tags_execution_failed") from None
