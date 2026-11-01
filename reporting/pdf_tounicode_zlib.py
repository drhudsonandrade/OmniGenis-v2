"""Opt-in bounded native ToUnicode zlib completion for generated PDFs.

The confined child verifies deflate completion and Adler-32 inside finite
decoded-byte budgets. The receipt contains no decoded CMap text and asserts
neither CMap syntax nor Unicode semantics, accessibility or release readiness.
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
from reporting import pdf_tounicode_header as previous
from reporting.pdf_object_graph import _canonical, _start, _unique_pairs, _wait
from reporting._pdf_object_graph_worker import (
    CPU_SECONDS, IDENTITY_FIELDS, MAX_PDF_BYTES, MEMORY_BYTES, OPEN_FILES,
    PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES, _is_digest,
)
from reporting._pdf_tounicode_zlib_worker import (
    LANGUAGE, MAX_DOCUMENT_PAGES, MAX_DECODED_CMAP_BYTES,
    MAX_TOTAL_DECODED_BYTES, POLICY_ID, PROFILE_ID, STATUS,
    _identity, _identity_from_plan,
)

_DISABLE = "OMNIGENIS_PDF_TOUNICODE_ZLIB_DISABLED"
_FIXED_PARENT_PROFILE_SHA256 = "9fdd911b498ef76aa9e82962f066dff2eebbc43c44035b09c635644c4fdde68c"
_FIXED_ENVELOPE = (64, 16 * 1024 * 1024, 256 * 1024, 512 * 1024)
_LIMITS = {
    "memory_bytes": MEMORY_BYTES, "cpu_seconds": CPU_SECONDS,
    "file_bytes": RESULT_BYTES, "open_files": OPEN_FILES,
}


class PdfToUnicodeZlibError(ValueError):
    """Content-free rejection of incomplete generated ToUnicode streams."""


def tounicode_zlib_profile() -> dict:
    """Default-off closed child of the exact sealed native header profile."""
    return {
        "schema_version": "1.0.0",
        "profile_id": PROFILE_ID,
        "policy_id": POLICY_ID,
        "parser_version": PARSER_VERSION,
        "previous_tounicode_header_profile_sha256": previous.PROFILE_SHA256,
        "language": LANGUAGE,
        "max_pages": MAX_DOCUMENT_PAGES,
        "max_pdf_bytes": MAX_PDF_BYTES,
        "max_decoded_cmap_bytes": MAX_DECODED_CMAP_BYTES,
        "max_total_decoded_cmap_bytes": MAX_TOTAL_DECODED_BYTES,
        "native_tounicode_zlib_policy": "NATIVE_FLATE_ZLIB_COMPLETE_ONLY",
        "tounicode_zlib_completion_verified": True,
        "tounicode_zlib_adler32_verified": True,
        "all_file_revisions_inspected": False,
        "decoded_contents_audited": False,
        "cmap_syntax_audited": False,
        "unicode_mappings_audited": False,
        "font_programs_audited": False,
        "glyph_widths_audited": False,
        "reading_order_verified": False,
        "pdf_ua_qualified": False,
        "worker_results_authenticated": False,
        "aggregate_job_resources_qualified": False,
        "default_pipeline_activated": False,
        "release_authorized": False,
    }


PROFILE_SHA256 = sha256(_canonical(tounicode_zlib_profile())).hexdigest()
_FIXED_PROFILE_SHA256 = "97c958f48138ac34d327a0b5210fa59e49ee91e075ca9d12d0a039133ff2b878"


def _profile() -> None:
    """Fail closed on source, ancestor, profile, platform or parser drift."""
    previous._profile()
    if (sys.platform != "linux" or os.environ.get(_DISABLE) == "1"
            or (MAX_DOCUMENT_PAGES, MAX_PDF_BYTES, MAX_DECODED_CMAP_BYTES,
                MAX_TOTAL_DECODED_BYTES) != _FIXED_ENVELOPE
            or LANGUAGE != "en-US" or PARSER_VERSION != "6.19.0"
            or previous.PROFILE_SHA256 != _FIXED_PARENT_PROFILE_SHA256
            or PROFILE_SHA256 != _FIXED_PROFILE_SHA256
            or sha256(_canonical(tounicode_zlib_profile())).hexdigest()
               != PROFILE_SHA256):
        raise ValueError("generated ToUnicode zlib profile disabled or changed")


@dataclass(frozen=True, slots=True, repr=False)
class PdfToUnicodeZlib:
    """Immutable local checksum receipt, not an independently signed claim."""

    pdf_sha256: str
    ir_sha256: str
    plan_sha256: str
    page_count: int
    tounicode_stream_count: int
    tounicode_completed_stream_count: int
    tounicode_zlib_complete: bool
    tounicode_zlib_adler32_verified: bool
    prior_tounicode_header_sha256: str
    _sealed_sha256: str = field(init=False, repr=False, compare=False)

    def _record(self) -> dict:
        """Serialize source identity, verified counts and explicit nonclaims."""
        _profile()
        _identity({key: getattr(self, key) for key in IDENTITY_FIELDS})
        if (type(self.tounicode_stream_count) is not int
                or not 1 <= self.tounicode_stream_count <= 32 * self.page_count
                or type(self.tounicode_completed_stream_count) is not int
                or self.tounicode_completed_stream_count
                   != self.tounicode_stream_count
                or self.tounicode_zlib_complete is not True
                or self.tounicode_zlib_adler32_verified is not True
                or not _is_digest(self.prior_tounicode_header_sha256)):
            raise ValueError("generated ToUnicode zlib receipt inconsistent")
        return {
            "schema_version": "1.0.0", "profile_id": PROFILE_ID,
            "policy_id": POLICY_ID, "status": STATUS,
            "parser_version": PARSER_VERSION, "language": LANGUAGE,
            "profile_sha256": PROFILE_SHA256,
            "previous_tounicode_header_profile_sha256": previous.PROFILE_SHA256,
            "pdf_sha256": self.pdf_sha256, "ir_sha256": self.ir_sha256,
            "plan_sha256": self.plan_sha256, "page_count": self.page_count,
            "tounicode_stream_count": self.tounicode_stream_count,
            "tounicode_completed_stream_count": self.tounicode_completed_stream_count,
            "tounicode_zlib_complete": self.tounicode_zlib_complete,
            "tounicode_zlib_adler32_verified": self.tounicode_zlib_adler32_verified,
            "prior_tounicode_header_sha256": self.prior_tounicode_header_sha256,
            "all_file_revisions_inspected": False,
            "decoded_contents_audited": False,
            "cmap_syntax_audited": False,
            "unicode_mappings_audited": False,
            "font_programs_audited": False,
            "glyph_widths_audited": False,
            "reading_order_verified": False,
            "pdf_ua_qualified": False,
            "worker_results_authenticated": False,
            "aggregate_job_resources_qualified": False,
            "default_pipeline_activated": False,
            "release_authorized": False,
            "release_authorization": "NOT_ESTABLISHED",
        }

    def __post_init__(self) -> None:
        """Seal the canonical receipt and reject inconsistent fields."""
        try:
            encoded = _canonical(self._record())
            if len(encoded) > RESULT_BYTES:
                raise ValueError("generated ToUnicode zlib receipt oversized")
            digest = sha256(encoded).hexdigest()
            if (hasattr(self, "_sealed_sha256")
                    and self._sealed_sha256 != digest):
                raise ValueError("generated ToUnicode zlib receipt mutated")
            object.__setattr__(self, "_sealed_sha256", digest)
        except Exception:
            raise PdfToUnicodeZlibError("pdf_tounicode_zlib_receipt_invalid") from None

    def to_bytes(self) -> bytes:
        """Return canonical receipt bytes only if the seal still matches."""
        try:
            encoded = _canonical(self._record())
            if (len(encoded) > RESULT_BYTES
                    or sha256(encoded).hexdigest() != self._sealed_sha256):
                raise ValueError("generated ToUnicode zlib receipt changed")
            return encoded
        except Exception:
            raise PdfToUnicodeZlibError("pdf_tounicode_zlib_receipt_invalid") from None

    def to_dict(self) -> dict:
        """Return a new dictionary from the validated serialized receipt."""
        return json.loads(self.to_bytes())

    @property
    def inspection_sha256(self) -> str:
        """Content checksum only; no independent worker authentication."""
        return sha256(self.to_bytes()).hexdigest()


def _decode(data: bytes, identity: dict, ancestor: previous.PdfToUnicodeHeader) -> PdfToUnicodeZlib:
    """Bind exact isolated-child protocol to the sealed header receipt."""
    try:
        _identity(identity)
        if (type(ancestor) is not previous.PdfToUnicodeHeader
                or type(data) is not bytes or not 0 < len(data) <= RESULT_BYTES
                or {key: getattr(ancestor, key) for key in IDENTITY_FIELDS}
                   != identity):
            raise ValueError("ToUnicode zlib child or ancestor invalid")
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
            raise ValueError("ToUnicode zlib child protocol differs")
        _identity(record["identity"])
        if record["identity"] != identity:
            raise ValueError("ToUnicode zlib child source differs")
        limits = record["limits"]
        if (type(limits) is not dict or set(limits) != set(_LIMITS)
                or any(type(v) is not int or v != _LIMITS[key]
                       for key, v in limits.items())):
            raise ValueError("ToUnicode zlib resource envelope differs")
        inspection = record["inspection"]
        keys = {
            "status", "tounicode_stream_count",
            "tounicode_completed_stream_count", "tounicode_zlib_complete",
            "tounicode_zlib_adler32_verified",
        }
        if (type(inspection) is not dict or set(inspection) != keys
                or inspection["status"] != STATUS
                or type(inspection["tounicode_stream_count"]) is not int
                or inspection["tounicode_stream_count"]
                   != ancestor.tounicode_stream_count
                or type(inspection["tounicode_completed_stream_count"]) is not int
                or inspection["tounicode_completed_stream_count"]
                   != inspection["tounicode_stream_count"]
                or inspection["tounicode_zlib_complete"] is not True
                or inspection["tounicode_zlib_adler32_verified"] is not True):
            raise ValueError("ToUnicode zlib count, type or keys differ")
        return PdfToUnicodeZlib(
            **identity,
            tounicode_stream_count=inspection["tounicode_stream_count"],
            tounicode_completed_stream_count=inspection["tounicode_completed_stream_count"],
            tounicode_zlib_complete=inspection["tounicode_zlib_complete"],
            tounicode_zlib_adler32_verified=inspection["tounicode_zlib_adler32_verified"],
            prior_tounicode_header_sha256=ancestor_digest,
        )
    except Exception:
        raise PdfToUnicodeZlibError("pdf_tounicode_zlib_protocol_invalid") from None


def _run_worker(pdf: bytes, identity: dict) -> bytes:
    """Pass sealed PDF via two owned and unlinked anonymous file descriptors."""
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as result:
        fds = (source.fileno(), result.fileno())
        infos = [os.fstat(fd) for fd in fds]
        if (any(not stat.S_ISREG(v.st_mode) or v.st_nlink != 0
                or v.st_uid != os.geteuid() for v in infos)
                or (infos[0].st_dev, infos[0].st_ino)
                   == (infos[1].st_dev, infos[1].st_ino)):
            raise ValueError("generated ToUnicode zlib descriptors invalid")
        header = " ".join([str(PROTOCOL_VERSION), *(str(identity[key])
                          for key in IDENTITY_FIELDS)])
        source.write(header.encode("ascii") + b"\n")
        source.write(pdf)
        source.flush()
        process = _start([
            sys.executable, "-I",
            str(Path(__file__).resolve().with_name("_pdf_tounicode_zlib_worker.py")),
            str(fds[0]), str(fds[1]), str(os.getpid()),
        ], fds)
        if (_wait(process) != 0
                or not 0 < os.fstat(result.fileno()).st_size <= RESULT_BYTES):
            raise ValueError("generated ToUnicode zlib child rejected")
        result.seek(0)
        return result.read(RESULT_BYTES + 1)


def inspect_pdf_tounicode_zlib(
    *, pdf_bytes: object, plan: PageWindowPlan,
    expected_plan_sha256: str, expected_language: str,
) -> PdfToUnicodeZlib:
    """Admit bounded zlib integrity only after exact sealed header admission."""
    try:
        _profile()
        if (type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b"%PDF-1.7")
                or not 0 < len(pdf_bytes) <= MAX_PDF_BYTES
                or type(plan) is not PageWindowPlan
                or not _is_digest(expected_plan_sha256)
                or type(expected_language) is not str
                or expected_language != LANGUAGE):
            raise ValueError("unsupported generated ToUnicode zlib request")
        plan.__post_init__()
        if (plan.plan_sha256 != expected_plan_sha256
                or plan.inspector_profile_id != TEXT_PROFILE
                or plan.page_count > MAX_DOCUMENT_PAGES
                or plan.pdf_sha256 != sha256(pdf_bytes).hexdigest()):
            raise ValueError("generated ToUnicode zlib plan differs")
        identity = _identity_from_plan(plan)
    except Exception:
        raise PdfToUnicodeZlibError("pdf_tounicode_zlib_input_invalid") from None
    try:
        ancestor = previous.inspect_pdf_tounicode_header(
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
            raise ValueError("ToUnicode zlib predecessor or input mutated")
        return receipt
    except Exception:
        raise PdfToUnicodeZlibError("pdf_tounicode_zlib_execution_failed") from None
