"""Opt-in generated PDF XRef entry-map admission with exact source bindings.

Metadata-only checksum receipts are not signed worker output, PDF/UA claims,
scientific validation, default activation, aggregate supervision or release.
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
from reporting import pdf_single_revision as previous
from reporting.pdf_object_graph import _canonical, _start, _unique_pairs, _wait
from reporting._pdf_object_graph_worker import (
    CPU_SECONDS, IDENTITY_FIELDS, MAX_PDF_BYTES, MEMORY_BYTES, OPEN_FILES,
    PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES, _is_digest,
)
from reporting._pdf_xref_entries_worker import (
    LANGUAGE, MAX_DOCUMENT_PAGES, MAX_ENTRIES, MAX_ENTRY_WIDTH,
    POLICY_ID, PROFILE_ID, STATUS, _identity, _identity_from_plan,
)


_DISABLE = "OMNIGENIS_PDF_XREF_ENTRIES_DISABLED"
_FIXED_PARENT_PROFILE_SHA256 = "d66b42e0ddfa874dc504933348cf415bc30877de7bb9d4f7de9f9c1d2c7f48c3"
_FIXED_ENVELOPE = (64, 8 * 1024 * 1024)
_LIMITS = {
    "memory_bytes": MEMORY_BYTES, "cpu_seconds": CPU_SECONDS,
    "file_bytes": RESULT_BYTES, "open_files": OPEN_FILES,
}


class PdfXrefEntriesError(ValueError):
    """Fixed refusal when the generated XRef entry map cannot be proven."""


def xref_entries_profile() -> dict:
    """Return one conservative generated PDF physical XRef entry contract."""
    return {
        "schema_version": "1.0.0",
        "profile_id": PROFILE_ID,
        "policy_id": POLICY_ID,
        "parser_version": PARSER_VERSION,
        "previous_single_revision_profile_sha256": previous.PROFILE_SHA256,
        "language": LANGUAGE,
        "max_pages": MAX_DOCUMENT_PAGES,
        "max_pdf_bytes": MAX_PDF_BYTES,
        "supported_xref_kind": "STREAM",
        "xref_index_policy": "EXACT_INDEX_ZERO_TO_SIZE",
        "xref_entry_bytes_policy": "EXACT_DECODED_RECORD_LENGTH",
        "xref_direct_policy": "EVERY_DIRECT_ENTRY_PHYSICAL_OBJECT_HEADER",
        "xref_compressed_policy": "EVERY_COMPRESSED_ENTRY_MATCHES_OBJSTM_OWNER_AND_INDEX",
        "max_xref_entries": MAX_ENTRIES,
        "max_xref_entry_width": MAX_ENTRY_WIDTH,
        "conformance_scope": "GENERATED_PDF_1_7_XREF_ENTRY_MAP_CONSISTENCY_ONLY",
        "xref_entry_map_consistency_admitted": True,
        "all_file_revisions_inspected": False,
        "opaque_payloads_audited": False,
        "pdf_ua_qualified": False,
        "reading_order_verified": False,
        "worker_results_authenticated": False,
        "aggregate_job_resources_qualified": False,
        "default_pipeline_activated": False,
        "release_authorized": False,
    }


PROFILE_SHA256 = sha256(_canonical(xref_entries_profile())).hexdigest()
_FIXED_PROFILE_SHA256 = "22cefc2ba113c99cb1f4ecae039cf3c090e9603f02f0b140880f1dce44be1fa0"


def _profile() -> None:
    """Refuse unpinned generated/parser/prerequisite host changes and disables."""
    previous._profile()
    if (sys.platform != "linux" or os.environ.get(_DISABLE) == "1"
            or (MAX_DOCUMENT_PAGES, MAX_PDF_BYTES) != _FIXED_ENVELOPE
            or PARSER_VERSION != "6.19.0" or LANGUAGE != "en-US"
            or previous.PROFILE_SHA256 != _FIXED_PARENT_PROFILE_SHA256
            or PROFILE_SHA256 != _FIXED_PROFILE_SHA256
            or sha256(_canonical(xref_entries_profile())).hexdigest() !=
               PROFILE_SHA256):
        raise ValueError("generated XRef entry profile disabled or changed")


@dataclass(frozen=True, slots=True, repr=False)
class PdfXrefEntries:
    """Immutable content-free metadata, not a cryptographically signed verifier."""

    pdf_sha256: str
    ir_sha256: str
    plan_sha256: str
    page_count: int
    xref_entry_count: int
    free_entry_count: int
    direct_entry_count: int
    compressed_entry_count: int
    object_stream_count: int
    decoded_entry_bytes: int
    direct_headers_verified: int
    object_stream_indices_verified: int
    xref_entry_map_consistent: bool
    prior_single_revision_sha256: str
    _sealed_sha256: str = field(init=False, repr=False, compare=False)

    def _record(self) -> dict:
        _profile()
        _identity({key: getattr(self, key) for key in IDENTITY_FIELDS})
        values = tuple(getattr(self, key) for key in (
            "xref_entry_count", "free_entry_count", "direct_entry_count",
            "compressed_entry_count", "object_stream_count",
            "decoded_entry_bytes", "direct_headers_verified",
            "object_stream_indices_verified",
        ))
        if (any(type(value) is not int for value in values)
                or not 2 < self.xref_entry_count <= MAX_ENTRIES
                or self.free_entry_count != 1
                or not 2 <= self.direct_entry_count < self.xref_entry_count
                or not 1 <= self.compressed_entry_count < self.xref_entry_count
                or not 1 <= self.object_stream_count <= self.direct_entry_count
                or (self.free_entry_count + self.direct_entry_count
                    + self.compressed_entry_count) != self.xref_entry_count
                or not (3 * self.xref_entry_count <= self.decoded_entry_bytes
                        <= MAX_ENTRY_WIDTH * self.xref_entry_count)
                or self.decoded_entry_bytes % self.xref_entry_count != 0
                or self.direct_headers_verified != self.direct_entry_count
                or self.object_stream_indices_verified != self.compressed_entry_count
                or self.xref_entry_map_consistent is not True
                or not _is_digest(self.prior_single_revision_sha256)):
            raise ValueError("XRef metadata counts or predecessor digest invalid")
        return {
            "schema_version": "1.0.0",
            "profile_id": PROFILE_ID,
            "policy_id": POLICY_ID,
            "status": STATUS,
            "parser_version": PARSER_VERSION,
            "language": LANGUAGE,
            "profile_sha256": PROFILE_SHA256,
            "previous_single_revision_profile_sha256": previous.PROFILE_SHA256,
            "pdf_sha256": self.pdf_sha256,
            "ir_sha256": self.ir_sha256,
            "plan_sha256": self.plan_sha256,
            "page_count": self.page_count,
            "xref_entry_count": self.xref_entry_count,
            "free_entry_count": self.free_entry_count,
            "direct_entry_count": self.direct_entry_count,
            "compressed_entry_count": self.compressed_entry_count,
            "object_stream_count": self.object_stream_count,
            "decoded_entry_bytes": self.decoded_entry_bytes,
            "direct_headers_verified": self.direct_headers_verified,
            "object_stream_indices_verified": self.object_stream_indices_verified,
            "xref_entry_map_consistent": self.xref_entry_map_consistent,
            "prior_single_revision_sha256": self.prior_single_revision_sha256,
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
                raise ValueError("XRef receipt exceeds fixed size")
            digest = sha256(raw).hexdigest()
            if hasattr(self, "_sealed_sha256") and self._sealed_sha256 != digest:
                raise ValueError("XRef receipt already mutated")
            object.__setattr__(self, "_sealed_sha256", digest)
        except Exception:
            raise PdfXrefEntriesError("pdf_xref_entries_receipt_invalid") from None

    def to_bytes(self) -> bytes:
        try:
            raw = _canonical(self._record())
            if len(raw) > RESULT_BYTES or sha256(raw).hexdigest() != self._sealed_sha256:
                raise ValueError("XRef receipt mutation")
            return raw
        except Exception:
            raise PdfXrefEntriesError("pdf_xref_entries_receipt_invalid") from None

    def to_dict(self) -> dict:
        return json.loads(self.to_bytes())

    @property
    def inspection_sha256(self) -> str:
        """Receipt checksum is only metadata binding, never worker authentication."""
        return sha256(self.to_bytes()).hexdigest()


def _decode(data: bytes, identity: dict, prior_digest: str) -> PdfXrefEntries:
    """Parse the complete exact native child wire protocol and count constraints."""
    try:
        _identity(identity)
        if (not _is_digest(prior_digest) or type(data) is not bytes
                or not 0 < len(data) <= RESULT_BYTES):
            raise ValueError("XRef native response missing or unbounded")
        record = json.loads(data.decode("ascii"), object_pairs_hook=_unique_pairs)
        if (type(record) is not dict or set(record) != {
                "protocol_version", "profile_id", "policy_id", "parser_version",
                "identity", "limits", "inspection"}
                or type(record["protocol_version"]) is not int
                or record["protocol_version"] != PROTOCOL_VERSION
                or record["profile_id"] != PROFILE_ID
                or record["policy_id"] != POLICY_ID
                or record["parser_version"] != PARSER_VERSION):
            raise ValueError("XRef child profile/wire structure changed")
        _identity(record["identity"])
        if record["identity"] != identity:
            raise ValueError("XRef child switched source identity")
        limits = record["limits"]
        if (type(limits) is not dict or set(limits) != set(_LIMITS)
                or any(type(v) is not int or v != _LIMITS[key]
                       for key, v in limits.items())):
            raise ValueError("XRef child execution envelope changed")
        inspection = record["inspection"]
        keys = {
            "status", "xref_entry_count", "free_entry_count",
            "direct_entry_count", "compressed_entry_count",
            "object_stream_count", "decoded_entry_bytes",
            "direct_headers_verified", "object_stream_indices_verified",
            "xref_entry_map_consistent",
        }
        if (type(inspection) is not dict or set(inspection) != keys
                or inspection["status"] != STATUS):
            raise ValueError("XRef child inspection fields missing")
        values = {key: inspection[key] for key in keys - {"status"}}
        return PdfXrefEntries(
            **identity, **values, prior_single_revision_sha256=prior_digest,
        )
    except Exception:
        raise PdfXrefEntriesError("pdf_xref_entries_protocol_invalid") from None


def _run_worker(pdf: bytes, identity: dict) -> bytes:
    """Invoke only the fixed native child via unlinked owned regular descriptors."""
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as result:
        fds = (source.fileno(), result.fileno())
        infos = [os.fstat(fd) for fd in fds]
        if (any(not stat.S_ISREG(info.st_mode) or info.st_nlink != 0
                or info.st_uid != os.geteuid() for info in infos)
                or (infos[0].st_dev, infos[0].st_ino)
                   == (infos[1].st_dev, infos[1].st_ino)):
            raise ValueError("XRef native descriptor identity invalid")
        header = " ".join([str(PROTOCOL_VERSION), *(str(identity[key])
                          for key in IDENTITY_FIELDS)])
        source.write(header.encode("ascii") + b"\n")
        source.write(pdf)
        source.flush()
        process = _start([
            sys.executable, "-I",
            str(Path(__file__).resolve().with_name("_pdf_xref_entries_worker.py")),
            str(fds[0]), str(fds[1]), str(os.getpid()),
        ], fds)
        if _wait(process) != 0 or not 0 < os.fstat(result.fileno()).st_size <= RESULT_BYTES:
            raise ValueError("XRef native child incomplete")
        result.seek(0)
        return result.read(RESULT_BYTES + 1)


def inspect_pdf_xref_entries(
    *, pdf_bytes: object, plan: PageWindowPlan,
    expected_plan_sha256: str, expected_language: str,
) -> PdfXrefEntries:
    """Admit a generated XRef entry map only after all prior native receipts pass."""
    try:
        _profile()
        if (type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b"%PDF-1.7")
                or not 0 < len(pdf_bytes) <= MAX_PDF_BYTES
                or type(plan) is not PageWindowPlan
                or not _is_digest(expected_plan_sha256)
                or type(expected_language) is not str or expected_language != LANGUAGE):
            raise ValueError("XRef request outside generated profile")
        plan.__post_init__()
        if (plan.plan_sha256 != expected_plan_sha256
                or plan.inspector_profile_id != TEXT_PROFILE
                or plan.page_count > MAX_DOCUMENT_PAGES
                or plan.pdf_sha256 != sha256(pdf_bytes).hexdigest()):
            raise ValueError("XRef request mismatches PDF/plan identity")
        identity = _identity_from_plan(plan)
    except Exception:
        raise PdfXrefEntriesError("pdf_xref_entries_input_invalid") from None
    try:
        prior = previous.inspect_pdf_single_revision(
            pdf_bytes=pdf_bytes, plan=plan,
            expected_plan_sha256=expected_plan_sha256,
            expected_language=expected_language,
        )
        prior_digest = prior.inspection_sha256
        receipt = _decode(_run_worker(pdf_bytes, identity), identity, prior_digest)
        plan.__post_init__()
        _profile()
        if (plan.plan_sha256 != expected_plan_sha256
                or _identity_from_plan(plan) != identity
                or prior.inspection_sha256 != prior_digest):
            raise ValueError("XRef plan or predecessor mutated during execution")
        return receipt
    except Exception:
        raise PdfXrefEntriesError("pdf_xref_entries_execution_failed") from None
