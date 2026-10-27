"""Opt-in generated XRef native parser-resolution parity with exact receipts.

This is a conservative structural admission, not a complete opaque-payload,
historical-revision, PDF/UA, scientific or final-release authorization.
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
from reporting import pdf_xref_entries as prior
from reporting.pdf_object_graph import _canonical, _start, _unique_pairs, _wait
from reporting._pdf_object_graph_worker import (
    CPU_SECONDS, IDENTITY_FIELDS, MAX_PDF_BYTES, MEMORY_BYTES, OPEN_FILES,
    PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES, _is_digest,
)
from reporting._pdf_xref_resolution_worker import (
    LANGUAGE, MAX_DOCUMENT_PAGES, POLICY_ID, PROFILE_ID, STATUS,
    _identity, _identity_from_plan,
)

_DISABLE = "OMNIGENIS_PDF_XREF_RESOLUTION_DISABLED"
_FIXED_PARENT_PROFILE_SHA256 = "22cefc2ba113c99cb1f4ecae039cf3c090e9603f02f0b140880f1dce44be1fa0"
_FIXED_ENVELOPE = (64, 8 * 1024 * 1024)
_LIMITS = {
    "memory_bytes": MEMORY_BYTES, "cpu_seconds": CPU_SECONDS,
    "file_bytes": RESULT_BYTES, "open_files": OPEN_FILES,
}


class PdfXrefResolutionError(ValueError):
    """Content-free refusal when native generated indexed objects disagree."""


def xref_resolution_profile() -> dict:
    """Declare the narrow generated-PDF parser resolution subset."""
    return {
        "schema_version": "1.0.0",
        "profile_id": PROFILE_ID,
        "policy_id": POLICY_ID,
        "parser_version": PARSER_VERSION,
        "previous_xref_entries_profile_sha256": prior.PROFILE_SHA256,
        "language": LANGUAGE,
        "max_pages": MAX_DOCUMENT_PAGES,
        "max_pdf_bytes": MAX_PDF_BYTES,
        "parser_mapping_policy": "EXACT_GENERATION_ZERO_DIRECT_AND_COMPRESSED_XREF",
        "direct_resolution_policy": "EVERY_INDEXED_DIRECT_OBJECT_RESOLVES_NON_NULL",
        "compressed_resolution_policy": "EVERY_INDEXED_COMPRESSED_OBJECT_RESOLVES_DICTIONARY",
        "parser_repair_policy": "NO_NEW_OR_CHANGED_XREF_MAPS_DURING_RESOLUTION",
        "conformance_scope": "GENERATED_PDF_1_7_XREF_PARSER_RESOLUTION_PARITY_ONLY",
        "all_indexed_objects_resolved": True,
        "parser_xref_mapping_consistent": True,
        "all_file_revisions_inspected": False,
        "opaque_payloads_audited": False,
        "pdf_ua_qualified": False,
        "reading_order_verified": False,
        "worker_results_authenticated": False,
        "aggregate_job_resources_qualified": False,
        "default_pipeline_activated": False,
        "release_authorized": False,
    }


PROFILE_SHA256 = sha256(_canonical(xref_resolution_profile())).hexdigest()
_FIXED_PROFILE_SHA256 = "211feff2c3c875bd868206b8c5db15db386fa74ae59276c53f8b48cc9455f8e5"


def _profile() -> None:
    """Reject disabled, unpinned or changed generated/parser prerequisites."""
    prior._profile()
    if (sys.platform != "linux" or os.environ.get(_DISABLE) == "1"
            or (MAX_DOCUMENT_PAGES, MAX_PDF_BYTES) != _FIXED_ENVELOPE
            or LANGUAGE != "en-US" or PARSER_VERSION != "6.19.0"
            or prior.PROFILE_SHA256 != _FIXED_PARENT_PROFILE_SHA256
            or PROFILE_SHA256 != _FIXED_PROFILE_SHA256
            or sha256(_canonical(xref_resolution_profile())).hexdigest()
               != PROFILE_SHA256):
        raise ValueError("XRef parser resolution profile disabled or changed")


@dataclass(frozen=True, slots=True, repr=False)
class PdfXrefResolution:
    """Immutable unsigned metadata receipt with predecessor checksum binding."""

    pdf_sha256: str
    ir_sha256: str
    plan_sha256: str
    page_count: int
    parser_direct_entries: int
    parser_compressed_entries: int
    direct_objects_resolved: int
    compressed_objects_resolved: int
    parser_xref_mapping_consistent: bool
    all_indexed_objects_resolved: bool
    prior_xref_entries_sha256: str
    _sealed_sha256: str = field(init=False, repr=False, compare=False)

    def _record(self) -> dict:
        _profile()
        _identity({key: getattr(self, key) for key in IDENTITY_FIELDS})
        counts = (
            self.parser_direct_entries, self.parser_compressed_entries,
            self.direct_objects_resolved, self.compressed_objects_resolved,
        )
        if (any(type(value) is not int for value in counts)
                or not 2 <= self.parser_direct_entries < prior.MAX_ENTRIES
                or not 1 <= self.parser_compressed_entries < prior.MAX_ENTRIES
                or sum(counts[:2]) + 1 > prior.MAX_ENTRIES
                or self.direct_objects_resolved != self.parser_direct_entries
                or self.compressed_objects_resolved != self.parser_compressed_entries
                or self.parser_xref_mapping_consistent is not True
                or self.all_indexed_objects_resolved is not True
                or not _is_digest(self.prior_xref_entries_sha256)):
            raise ValueError("XRef parser resolution counts or bindings invalid")
        return {
            "schema_version": "1.0.0",
            "profile_id": PROFILE_ID, "policy_id": POLICY_ID,
            "status": STATUS, "parser_version": PARSER_VERSION,
            "language": LANGUAGE, "profile_sha256": PROFILE_SHA256,
            "previous_xref_entries_profile_sha256": prior.PROFILE_SHA256,
            "pdf_sha256": self.pdf_sha256, "ir_sha256": self.ir_sha256,
            "plan_sha256": self.plan_sha256, "page_count": self.page_count,
            "parser_direct_entries": self.parser_direct_entries,
            "parser_compressed_entries": self.parser_compressed_entries,
            "direct_objects_resolved": self.direct_objects_resolved,
            "compressed_objects_resolved": self.compressed_objects_resolved,
            "parser_xref_mapping_consistent": self.parser_xref_mapping_consistent,
            "all_indexed_objects_resolved": self.all_indexed_objects_resolved,
            "prior_xref_entries_sha256": self.prior_xref_entries_sha256,
            "all_file_revisions_inspected": False,
            "opaque_payloads_audited": False,
            "pdf_ua_qualified": False,
            "reading_order_verified": False,
            "worker_results_authenticated": False,
            "aggregate_job_resources_qualified": False,
            "default_pipeline_activated": False,
            "release_authorized": False,
            "release_authorization": "NOT_ESTABLISHED",
        }

    def __post_init__(self) -> None:
        try:
            raw = _canonical(self._record())
            if len(raw) > RESULT_BYTES:
                raise ValueError("XRef resolution metadata exceeds fixed budget")
            digest = sha256(raw).hexdigest()
            if hasattr(self, "_sealed_sha256") and self._sealed_sha256 != digest:
                raise ValueError("XRef resolution receipt mutated")
            object.__setattr__(self, "_sealed_sha256", digest)
        except Exception:
            raise PdfXrefResolutionError("pdf_xref_resolution_receipt_invalid") from None

    def to_bytes(self) -> bytes:
        try:
            raw = _canonical(self._record())
            if len(raw) > RESULT_BYTES or sha256(raw).hexdigest() != self._sealed_sha256:
                raise ValueError("XRef resolution receipt changed")
            return raw
        except Exception:
            raise PdfXrefResolutionError("pdf_xref_resolution_receipt_invalid") from None

    def to_dict(self) -> dict:
        return json.loads(self.to_bytes())

    @property
    def inspection_sha256(self) -> str:
        """Checksum only; not a cryptographic worker signature."""
        return sha256(self.to_bytes()).hexdigest()


def _decode(data: bytes, identity: dict, previous_receipt: prior.PdfXrefEntries) -> PdfXrefResolution:
    """Verify the exact child protocol plus independent prior entry counts."""
    try:
        _identity(identity)
        if (type(previous_receipt) is not prior.PdfXrefEntries
                or type(data) is not bytes or not 0 < len(data) <= RESULT_BYTES):
            raise ValueError("XRef parser child wire or precursor invalid")
        previous_digest = previous_receipt.inspection_sha256
        record = json.loads(data.decode("ascii"), object_pairs_hook=_unique_pairs)
        if (type(record) is not dict or set(record) != {
                "protocol_version", "profile_id", "policy_id", "parser_version",
                "identity", "limits", "inspection",
            } or type(record["protocol_version"]) is not int
                or record["protocol_version"] != PROTOCOL_VERSION
                or record["profile_id"] != PROFILE_ID
                or record["policy_id"] != POLICY_ID
                or record["parser_version"] != PARSER_VERSION):
            raise ValueError("XRef parser child protocol changed")
        _identity(record["identity"])
        if record["identity"] != identity:
            raise ValueError("XRef parser child identity differs")
        limits = record["limits"]
        if (type(limits) is not dict or set(limits) != set(_LIMITS)
                or any(type(v) is not int or v != _LIMITS[key]
                       for key, v in limits.items())):
            raise ValueError("XRef parser child resource envelope changed")
        inspection = record["inspection"]
        keys = {
            "status", "parser_direct_entries", "parser_compressed_entries",
            "direct_objects_resolved", "compressed_objects_resolved",
            "parser_xref_mapping_consistent", "all_indexed_objects_resolved",
        }
        if (type(inspection) is not dict or set(inspection) != keys
                or inspection["status"] != STATUS
                or inspection["parser_direct_entries"] != previous_receipt.direct_entry_count
                or inspection["parser_compressed_entries"] != previous_receipt.compressed_entry_count):
            raise ValueError("XRef parser child counts do not match precursor")
        return PdfXrefResolution(
            **identity,
            **{key: inspection[key] for key in keys - {"status"}},
            prior_xref_entries_sha256=previous_digest,
        )
    except Exception:
        raise PdfXrefResolutionError("pdf_xref_resolution_protocol_invalid") from None


def _run_worker(pdf: bytes, identity: dict) -> bytes:
    """Invoke fixed confined native worker through owned unlinked descriptors."""
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as result:
        fds = (source.fileno(), result.fileno())
        infos = [os.fstat(fd) for fd in fds]
        if (any(not stat.S_ISREG(info.st_mode) or info.st_nlink != 0
                or info.st_uid != os.geteuid() for info in infos)
                or (infos[0].st_dev, infos[0].st_ino)
                   == (infos[1].st_dev, infos[1].st_ino)):
            raise ValueError("XRef parser native descriptor invalid")
        header = " ".join([str(PROTOCOL_VERSION), *(str(identity[key])
                          for key in IDENTITY_FIELDS)])
        source.write(header.encode("ascii") + b"\n")
        source.write(pdf)
        source.flush()
        process = _start([
            sys.executable, "-I",
            str(Path(__file__).resolve().with_name("_pdf_xref_resolution_worker.py")),
            str(fds[0]), str(fds[1]), str(os.getpid()),
        ], fds)
        if _wait(process) != 0 or not 0 < os.fstat(result.fileno()).st_size <= RESULT_BYTES:
            raise ValueError("XRef parser child did not complete")
        result.seek(0)
        return result.read(RESULT_BYTES + 1)


def inspect_pdf_xref_resolution(
    *, pdf_bytes: object, plan: PageWindowPlan,
    expected_plan_sha256: str, expected_language: str,
) -> PdfXrefResolution:
    """Require physical XRef admission before parser map/object resolution."""
    try:
        _profile()
        if (type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b"%PDF-1.7")
                or not 0 < len(pdf_bytes) <= MAX_PDF_BYTES
                or type(plan) is not PageWindowPlan
                or not _is_digest(expected_plan_sha256)
                or type(expected_language) is not str or expected_language != LANGUAGE):
            raise ValueError("XRef resolution request outside generated subset")
        plan.__post_init__()
        if (plan.plan_sha256 != expected_plan_sha256
                or plan.inspector_profile_id != TEXT_PROFILE
                or plan.page_count > MAX_DOCUMENT_PAGES
                or plan.pdf_sha256 != sha256(pdf_bytes).hexdigest()):
            raise ValueError("XRef resolution request mismatches source identity")
        identity = _identity_from_plan(plan)
    except Exception:
        raise PdfXrefResolutionError("pdf_xref_resolution_input_invalid") from None
    try:
        predecessor = prior.inspect_pdf_xref_entries(
            pdf_bytes=pdf_bytes, plan=plan,
            expected_plan_sha256=expected_plan_sha256,
            expected_language=expected_language,
        )
        previous_digest = predecessor.inspection_sha256
        result = _decode(_run_worker(pdf_bytes, identity), identity, predecessor)
        plan.__post_init__()
        _profile()
        if (plan.plan_sha256 != expected_plan_sha256
                or _identity_from_plan(plan) != identity
                or predecessor.inspection_sha256 != previous_digest):
            raise ValueError("XRef resolution prerequisite or plan mutated")
        return result
    except Exception:
        raise PdfXrefResolutionError("pdf_xref_resolution_execution_failed") from None
