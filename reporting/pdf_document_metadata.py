"""Opt-in exact-document metadata inspection without new release authority.

The unchanged controlled metadata and catalog accessibility-prerequisite policies
run in a disposable guarded process. Receipts expose fixed policy identities and
counts, never raw metadata or XML. They are unsigned local observations, not job
authentication, full PDF sanitization, tag semantics or whole-report qualification.
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

from reporting._pdf_document_metadata_worker import (
    CPU_SECONDS, IDENTITY_FIELDS, LANGUAGE, MAX_DOCUMENT_PAGES, MAX_PDF_BYTES,
    MEMORY_BYTES, METADATA_PROFILE_ID, OPEN_FILES, PARSER_VERSION, PROFILE_ID,
    PROTOCOL_VERSION, RESULT_BYTES, STATUS, _is_digest, _validate_identity,
)
from reporting.page_windows import PageWindowPlan
from reporting.pdf_object_graph import _canonical, _start, _unique_pairs, _wait

_LIMITS = {"memory_bytes": MEMORY_BYTES, "cpu_seconds": CPU_SECONDS,
           "file_bytes": RESULT_BYTES, "open_files": OPEN_FILES}
_INSPECTION = {"status": STATUS, "metadata_profile_id": METADATA_PROFILE_ID,
               "language": LANGUAGE, "marked": True, "struct_tree_root": True}


class PdfDocumentMetadataError(ValueError):
    """Content-free failure; no rejected candidate receives a successful receipt."""


@dataclass(frozen=True, slots=True, repr=False)
class PdfDocumentMetadataInspection:
    """Unsigned document identity with controlled metadata and catalog prerequisites only."""

    pdf_sha256: str
    ir_sha256: str
    plan_sha256: str
    page_count: int

    def __post_init__(self) -> None:
        """Require exact digests and native bounded counts even for direct construction."""
        try:
            _validate_identity(self._identity())
        except Exception:
            raise PdfDocumentMetadataError("pdf_document_metadata_receipt_invalid") from None

    def _identity(self) -> dict:
        """Detach only the closed document identity shared with the worker."""
        return {key: getattr(self, key) for key in IDENTITY_FIELDS}

    def to_dict(self) -> dict:
        """Expose constants and counts while withholding all unestablished global guarantees."""
        self.__post_init__()
        return {"schema_version": "1.0.0", "profile_id": PROFILE_ID,
                **self._identity(), **_INSPECTION, "parser_version": PARSER_VERSION,
                "inspection_scope": "CONTROLLED_INFO_DOCUMENT_XMP_AND_CATALOG_PREREQUISITES_ONLY",
                "worker_results_authenticated": False, "all_metadata_channels_inspected": False,
                "semantic_tag_tree_verified": False, "full_accessibility_qualified": False,
                "whole_pdf_safety_qualified": False, "text_equivalence_verified": False,
                "aggregate_job_resources_qualified": False, "release_authorized": False,
                "release_authorization": "NOT_ESTABLISHED"}

    @property
    def inspection_sha256(self) -> str:
        """Hash the revalidated unsigned receipt without authenticating its execution origin."""
        return hashlib.sha256(_canonical(self.to_dict())).hexdigest()


def _decode(data: bytes, expected: dict) -> PdfDocumentMetadataInspection:
    """Require exact protocol, native types, limits and complete prerequisite decisions."""
    try:
        if type(data) is not bytes or not 0 < len(data) <= RESULT_BYTES:
            raise ValueError("metadata response byte budget")
        _validate_identity(expected)
        record = json.loads(data.decode("ascii"), object_pairs_hook=_unique_pairs)
        if type(record) is not dict or set(record) != {
            "protocol_version", "profile_id", "parser_version", "identity", "limits", "inspection",
        }:
            raise ValueError("metadata response shape")
        if (type(record["protocol_version"]) is not int or record["protocol_version"] != PROTOCOL_VERSION
                or record["profile_id"] != PROFILE_ID or record["parser_version"] != PARSER_VERSION):
            raise ValueError("metadata response profile")
        _validate_identity(record["identity"])
        if record["identity"] != expected:
            raise ValueError("metadata response identity")
        limits = record["limits"]
        if (type(limits) is not dict or set(limits) != set(_LIMITS)
                or any(type(v) is not int or v != _LIMITS[k] for k, v in limits.items())):
            raise ValueError("metadata response limits")
        found = record["inspection"]
        if (type(found) is not dict or set(found) != set(_INSPECTION)
                or found != _INSPECTION or found["marked"] is not True
                or found["struct_tree_root"] is not True):
            raise ValueError("metadata response prerequisites")
        return PdfDocumentMetadataInspection(**expected)
    except Exception:
        raise PdfDocumentMetadataError("pdf_document_metadata_protocol_invalid") from None


def _run_worker(pdf: bytes, identity: dict) -> bytes:
    """Use the reviewed launch and wait boundary with two distinct anonymous protocol files."""
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as result:
        fds = source.fileno(), result.fileno()
        infos = [os.fstat(fd) for fd in fds]
        if any(not stat.S_ISREG(i.st_mode) or i.st_nlink != 0 or i.st_uid != os.geteuid() for i in infos):
            raise ValueError("metadata anonymous protocol required")
        if (infos[0].st_dev, infos[0].st_ino) == (infos[1].st_dev, infos[1].st_ino):
            raise ValueError("metadata distinct protocol required")
        header = " ".join([str(PROTOCOL_VERSION), *(str(identity[k]) for k in IDENTITY_FIELDS)])
        source.write(header.encode("ascii") + b"\n"); source.write(pdf); source.flush()
        process = _start([sys.executable, "-I",
            str(Path(__file__).resolve().with_name("_pdf_document_metadata_worker.py")),
            str(fds[0]), str(fds[1]), str(os.getpid())], fds)
        if _wait(process) != 0 or not 0 < os.fstat(result.fileno()).st_size <= RESULT_BYTES:
            raise ValueError("metadata worker failed")
        result.seek(0)
        return result.read(RESULT_BYTES + 1)


def inspect_pdf_document_metadata(
    *, pdf_bytes: object, plan: PageWindowPlan, expected_plan_sha256: str,
    expected_language: str,
) -> PdfDocumentMetadataInspection:
    """Inspect the current controlled en-US document profile without expanding default routes.

    The plan binds the physical count and PDF/IR identities, not job authority.
    Catalog prerequisites do not prove all-page tag coverage or full PDF/UA.
    Missing metadata, wrong identity or unavailable execution returns no receipt.
    """
    if (sys.platform != "linux"
            or os.environ.get("OMNIGENIS_PDF_DOCUMENT_METADATA_DISABLED") == "1"):
        raise PdfDocumentMetadataError("pdf_document_metadata_execution_unavailable")
    if (type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b"%PDF-1.7")
            or len(pdf_bytes) > MAX_PDF_BYTES):
        raise PdfDocumentMetadataError("pdf_document_metadata_input_invalid")
    if type(expected_language) is not str or expected_language != LANGUAGE:
        raise PdfDocumentMetadataError("pdf_document_metadata_language_unavailable")
    try:
        if type(plan) is not PageWindowPlan or not _is_digest(expected_plan_sha256):
            raise ValueError("metadata sealed plan required")
        plan.__post_init__()
        if (plan.plan_sha256 != expected_plan_sha256 or plan.page_count > MAX_DOCUMENT_PAGES
                or hashlib.sha256(pdf_bytes).hexdigest() != plan.pdf_sha256):
            raise ValueError("metadata plan mismatch")
        identity = {"pdf_sha256": plan.pdf_sha256, "ir_sha256": plan.ir_sha256,
                    "plan_sha256": plan.plan_sha256, "page_count": plan.page_count}
        _validate_identity(identity)
    except Exception:
        raise PdfDocumentMetadataError("pdf_document_metadata_plan_invalid") from None
    try:
        receipt = _decode(_run_worker(pdf_bytes, identity), identity)
        plan.__post_init__()
        if plan.plan_sha256 != expected_plan_sha256:
            raise ValueError("metadata plan changed during inspection")
        return receipt
    except Exception:
        raise PdfDocumentMetadataError("pdf_document_metadata_execution_failed") from None
