"""Opt-in native ToUnicode raw Flate-header admission for generated PDFs.

A checksum-only receipt of indexed raw zlib CMF/FLG headers, not decoded
Unicode mappings, glyph correctness, accessibility, or release readiness.
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

from reporting._pdf_document_byte_budget import LEGACY_MAX_PDF_BYTES
from reporting.page_windows import PageWindowPlan
from reporting.pdf_text_windows import PROFILE_ID as TEXT_PROFILE
from reporting import pdf_cid_widths as previous
from reporting.pdf_object_graph import _canonical, _start, _unique_pairs, _wait
from reporting._pdf_object_graph_worker import (
    CPU_SECONDS, IDENTITY_FIELDS, MAX_PDF_BYTES, MEMORY_BYTES, OPEN_FILES,
    PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES, _is_digest,
)
from reporting._pdf_tounicode_header_worker import (
    LANGUAGE, MAX_DOCUMENT_PAGES, MAX_RAW_CMAP_BYTES, POLICY_ID, PROFILE_ID,
    STATUS, _identity, _identity_from_plan,
)

_DISABLE = "OMNIGENIS_PDF_TOUNICODE_HEADER_DISABLED"
_FIXED_PARENT_PROFILE_SHA256 = "4aba561c7218d21f40136a14e225d192ed48c6949370956986889280987479a3"
_FIXED_ENVELOPE = (64, 16 * 1024 * 1024)
_LIMITS = {
    "memory_bytes": MEMORY_BYTES, "cpu_seconds": CPU_SECONDS,
    "file_bytes": RESULT_BYTES, "open_files": OPEN_FILES,
}


class PdfToUnicodeHeaderError(ValueError):
    """Content-free rejection of unsupported native ToUnicode headers."""


def tounicode_header_profile() -> dict:
    """Closed default-off child of the exact sealed CID /W profile."""
    return {
        "schema_version": "1.0.0",
        "profile_id": PROFILE_ID,
        "policy_id": POLICY_ID,
        "parser_version": PARSER_VERSION,
        "previous_cid_widths_profile_sha256": previous.PROFILE_SHA256,
        "language": LANGUAGE,
        "max_pages": MAX_DOCUMENT_PAGES,
        "max_pdf_bytes": MAX_PDF_BYTES,
        "max_raw_cmap_bytes": MAX_RAW_CMAP_BYTES,
        "raw_tounicode_header_policy": "NATIVE_FLATE_ZLIB_HEADER_ONLY",
        "tounicode_raw_flate_headers_checked": True,
        "tounicode_stream_count_matches_cid_widths": True,
        "all_file_revisions_inspected": False,
        "decoded_contents_audited": False,
        "font_programs_audited": False,
        "glyph_widths_audited": False,
        "tounicode_decoded": False,
        "unicode_mappings_audited": False,
        "reading_order_verified": False,
        "pdf_ua_qualified": False,
        "worker_results_authenticated": False,
        "aggregate_job_resources_qualified": False,
        "default_pipeline_activated": False,
        "release_authorized": False,
    }


PROFILE_SHA256 = sha256(_canonical(tounicode_header_profile())).hexdigest()
_FIXED_PROFILE_SHA256 = "9fdd911b498ef76aa9e82962f066dff2eebbc43c44035b09c635644c4fdde68c"


def _profile() -> None:
    """Fail closed for source, parent, profile, platform, or parser drift."""
    previous._profile()
    if (sys.platform != "linux" or os.environ.get(_DISABLE) == "1"
            or (MAX_DOCUMENT_PAGES, MAX_PDF_BYTES) != _FIXED_ENVELOPE
            or MAX_RAW_CMAP_BYTES != LEGACY_MAX_PDF_BYTES
            or LANGUAGE != "en-US" or PARSER_VERSION != "6.19.0"
            or previous.PROFILE_SHA256 != _FIXED_PARENT_PROFILE_SHA256
            or PROFILE_SHA256 != _FIXED_PROFILE_SHA256
            or sha256(_canonical(tounicode_header_profile())).hexdigest()
               != PROFILE_SHA256):
        raise ValueError("generated ToUnicode header profile disabled or changed")


@dataclass(frozen=True, slots=True, repr=False)
class PdfToUnicodeHeader:
    """Immutable local receipt; checksum is not a worker signature."""

    pdf_sha256: str
    ir_sha256: str
    plan_sha256: str
    page_count: int
    tounicode_stream_count: int
    tounicode_checked_header_count: int
    tounicode_headers_native: bool
    prior_cid_widths_sha256: str
    _sealed_sha256: str = field(init=False, repr=False, compare=False)

    def _record(self) -> dict:
        _profile()
        _identity({key: getattr(self, key) for key in IDENTITY_FIELDS})
        if (type(self.tounicode_stream_count) is not int
                or not 1 <= self.tounicode_stream_count <= 32 * self.page_count
                or type(self.tounicode_checked_header_count) is not int
                or self.tounicode_checked_header_count
                   != self.tounicode_stream_count
                or self.tounicode_headers_native is not True
                or not _is_digest(self.prior_cid_widths_sha256)):
            raise ValueError("generated ToUnicode header receipt inconsistent")
        return {
            "schema_version": "1.0.0", "profile_id": PROFILE_ID,
            "policy_id": POLICY_ID, "status": STATUS,
            "parser_version": PARSER_VERSION, "language": LANGUAGE,
            "profile_sha256": PROFILE_SHA256,
            "previous_cid_widths_profile_sha256": previous.PROFILE_SHA256,
            "pdf_sha256": self.pdf_sha256, "ir_sha256": self.ir_sha256,
            "plan_sha256": self.plan_sha256, "page_count": self.page_count,
            "tounicode_stream_count": self.tounicode_stream_count,
            "tounicode_checked_header_count": self.tounicode_checked_header_count,
            "tounicode_headers_native": self.tounicode_headers_native,
            "prior_cid_widths_sha256": self.prior_cid_widths_sha256,
            "all_file_revisions_inspected": False,
            "decoded_contents_audited": False,
            "font_programs_audited": False,
            "glyph_widths_audited": False,
            "tounicode_decoded": False,
            "unicode_mappings_audited": False,
            "reading_order_verified": False,
            "pdf_ua_qualified": False,
            "worker_results_authenticated": False,
            "aggregate_job_resources_qualified": False,
            "default_pipeline_activated": False,
            "release_authorized": False,
            "release_authorization": "NOT_ESTABLISHED",
        }

    def __post_init__(self) -> None:
        try:
            encoded = _canonical(self._record())
            if len(encoded) > RESULT_BYTES:
                raise ValueError("generated ToUnicode header receipt oversized")
            digest = sha256(encoded).hexdigest()
            if (hasattr(self, "_sealed_sha256")
                    and self._sealed_sha256 != digest):
                raise ValueError("generated ToUnicode header receipt mutated")
            object.__setattr__(self, "_sealed_sha256", digest)
        except Exception:
            raise PdfToUnicodeHeaderError("pdf_tounicode_header_receipt_invalid") from None

    def to_bytes(self) -> bytes:
        try:
            encoded = _canonical(self._record())
            if (len(encoded) > RESULT_BYTES
                    or sha256(encoded).hexdigest() != self._sealed_sha256):
                raise ValueError("generated ToUnicode header receipt changed")
            return encoded
        except Exception:
            raise PdfToUnicodeHeaderError("pdf_tounicode_header_receipt_invalid") from None

    def to_dict(self) -> dict:
        return json.loads(self.to_bytes())

    @property
    def inspection_sha256(self) -> str:
        """Content checksum, not independent worker authentication."""
        return sha256(self.to_bytes()).hexdigest()


def _decode(data: bytes, identity: dict, ancestor: previous.PdfCidWidths) -> PdfToUnicodeHeader:
    """Validate exact child protocol, counters and document-bound CID proof."""
    try:
        _identity(identity)
        if (type(ancestor) is not previous.PdfCidWidths
                or type(data) is not bytes or not 0 < len(data) <= RESULT_BYTES
                or {key: getattr(ancestor, key) for key in IDENTITY_FIELDS}
                   != identity):
            raise ValueError("ToUnicode header child result or ancestor invalid")
        ancestor_digest = ancestor.inspection_sha256
        record = json.loads(data.decode("ascii"), object_pairs_hook=_unique_pairs)
        if (type(record) is not dict or set(record) != {
                "protocol_version", "profile_id", "policy_id", "parser_version",
                "identity", "limits", "inspection",
            } or type(record["protocol_version"]) is not int
                or record["protocol_version"] != PROTOCOL_VERSION
                or record["profile_id"] != PROFILE_ID
                or record["policy_id"] != POLICY_ID
                or record["parser_version"] != PARSER_VERSION):
            raise ValueError("ToUnicode header child protocol differs")
        _identity(record["identity"])
        if record["identity"] != identity:
            raise ValueError("ToUnicode header child source differs")
        limits = record["limits"]
        if (type(limits) is not dict or set(limits) != set(_LIMITS)
                or any(type(v) is not int or v != _LIMITS[key]
                       for key, v in limits.items())):
            raise ValueError("ToUnicode header resource envelope differs")
        inspection = record["inspection"]
        keys = {
            "status", "tounicode_stream_count",
            "tounicode_checked_header_count", "tounicode_headers_native",
        }
        if (type(inspection) is not dict or set(inspection) != keys
                or inspection["status"] != STATUS
                or type(inspection["tounicode_stream_count"]) is not int
                or inspection["tounicode_stream_count"]
                   != ancestor.cid_width_font_count
                or type(inspection["tounicode_checked_header_count"]) is not int
                or inspection["tounicode_checked_header_count"]
                   != inspection["tounicode_stream_count"]
                or inspection["tounicode_headers_native"] is not True):
            raise ValueError("ToUnicode header child count, type or keys differ")
        return PdfToUnicodeHeader(
            **identity,
            tounicode_stream_count=inspection["tounicode_stream_count"],
            tounicode_checked_header_count=inspection["tounicode_checked_header_count"],
            tounicode_headers_native=inspection["tounicode_headers_native"],
            prior_cid_widths_sha256=ancestor_digest,
        )
    except Exception:
        raise PdfToUnicodeHeaderError("pdf_tounicode_header_protocol_invalid") from None


def _run_worker(pdf: bytes, identity: dict) -> bytes:
    """Send sealed generated PDF via two owned, unlinked anonymous FDs."""
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as result:
        fds = (source.fileno(), result.fileno())
        infos = [os.fstat(fd) for fd in fds]
        if (any(not stat.S_ISREG(v.st_mode) or v.st_nlink != 0
                or v.st_uid != os.geteuid() for v in infos)
                or (infos[0].st_dev, infos[0].st_ino)
                   == (infos[1].st_dev, infos[1].st_ino)):
            raise ValueError("generated ToUnicode worker descriptors invalid")
        header = " ".join([str(PROTOCOL_VERSION), *(str(identity[key])
                          for key in IDENTITY_FIELDS)])
        source.write(header.encode("ascii") + b"\n")
        source.write(pdf)
        source.flush()
        process = _start([
            sys.executable, "-I",
            str(Path(__file__).resolve().with_name("_pdf_tounicode_header_worker.py")),
            str(fds[0]), str(fds[1]), str(os.getpid()),
        ], fds)
        if (_wait(process) != 0
                or not 0 < os.fstat(result.fileno()).st_size <= RESULT_BYTES):
            raise ValueError("generated ToUnicode worker rejected")
        result.seek(0)
        return result.read(RESULT_BYTES + 1)


def inspect_pdf_tounicode_header(
    *, pdf_bytes: object, plan: PageWindowPlan,
    expected_plan_sha256: str, expected_language: str,
) -> PdfToUnicodeHeader:
    """Admit only raw headers bound to a still-valid sealed CID width proof."""
    try:
        _profile()
        if (type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b"%PDF-1.7")
                or not 0 < len(pdf_bytes) <= MAX_PDF_BYTES
                or type(plan) is not PageWindowPlan
                or not _is_digest(expected_plan_sha256)
                or type(expected_language) is not str
                or expected_language != LANGUAGE):
            raise ValueError("unsupported generated ToUnicode header request")
        plan.__post_init__()
        if (plan.plan_sha256 != expected_plan_sha256
                or plan.inspector_profile_id != TEXT_PROFILE
                or plan.page_count > MAX_DOCUMENT_PAGES
                or plan.pdf_sha256 != sha256(pdf_bytes).hexdigest()):
            raise ValueError("generated ToUnicode header plan differs")
        identity = _identity_from_plan(plan)
    except Exception:
        raise PdfToUnicodeHeaderError("pdf_tounicode_header_input_invalid") from None
    try:
        ancestor = previous.inspect_pdf_cid_widths(
            pdf_bytes=pdf_bytes, plan=plan,
            expected_plan_sha256=expected_plan_sha256,
            expected_language=expected_language,
        )
        ancestor_digest = ancestor.inspection_sha256
        receipt = _decode(_run_worker(pdf_bytes, identity), identity, ancestor)
        plan.__post_init__()
        _profile()
        if (plan.plan_sha256 != expected_plan_sha256
                or _identity_from_plan(plan) != identity
                or ancestor.inspection_sha256 != ancestor_digest):
            raise ValueError("ToUnicode prerequisite or input mutated")
        return receipt
    except Exception:
        raise PdfToUnicodeHeaderError("pdf_tounicode_header_execution_failed") from None
