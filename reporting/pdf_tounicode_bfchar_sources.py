"""Opt-in content-free native ToUnicode bfchar source uniqueness receipt.

Confirms only that 16-bit bfchar source operands do not repeat within each
renderer-generated font CMap. No general mapping semantics or accessibility
claims. The checksum is not a signed or authenticated worker attestation.
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
from reporting import pdf_tounicode_utf16be_targets as previous
from reporting.pdf_object_graph import _canonical, _start, _unique_pairs, _wait
from reporting._pdf_object_graph_worker import (
    CPU_SECONDS, IDENTITY_FIELDS, MAX_PDF_BYTES, MEMORY_BYTES, OPEN_FILES,
    PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES, _is_digest,
)
from reporting._pdf_tounicode_bfchar_sources_worker import (
    LANGUAGE, MAX_DOCUMENT_PAGES, MAX_DECODED_CMAP_BYTES,
    MAX_TOTAL_DECODED_BYTES, MAX_BFCHAR_BLOCKS, MAX_BFCHAR_RECORDS,
    MAX_BFCHAR_PER_BLOCK, MAX_UTF16BE_UNITS, POLICY_ID, PROFILE_ID, STATUS,
    _identity, _identity_from_plan,
)

_DISABLE = "OMNIGENIS_PDF_TOUNICODE_BFCHAR_SOURCES_DISABLED"
_FIXED_PARENT_PROFILE_SHA256 = "becaba64879ed60662de3c4c952c1262720fee0bd09f89241da0a3938511c6f2"
_FIXED_ENVELOPE = (
    64, 16 * 1024 * 1024, 256 * 1024, 512 * 1024,
    256, 16384, 100, 262144,
)
_LIMITS = {
    "memory_bytes": MEMORY_BYTES, "cpu_seconds": CPU_SECONDS,
    "file_bytes": RESULT_BYTES, "open_files": OPEN_FILES,
}


class PdfToUnicodeBfcharSourcesError(ValueError):
    """Content-free failure of the narrow source uniqueness descendant."""


def tounicode_bfchar_sources_profile() -> dict:
    """Versioned default-off generated CMap source collision policy."""
    return {
        "schema_version": "1.0.0",
        "profile_id": PROFILE_ID,
        "policy_id": POLICY_ID,
        "parser_version": PARSER_VERSION,
        "previous_tounicode_utf16be_targets_profile_sha256": previous.PROFILE_SHA256,
        "language": LANGUAGE,
        "max_pages": MAX_DOCUMENT_PAGES,
        "max_pdf_bytes": MAX_PDF_BYTES,
        "max_decoded_cmap_bytes": MAX_DECODED_CMAP_BYTES,
        "max_total_decoded_cmap_bytes": MAX_TOTAL_DECODED_BYTES,
        "max_bfchar_blocks": MAX_BFCHAR_BLOCKS,
        "max_bfchar_records": MAX_BFCHAR_RECORDS,
        "max_bfchar_per_block": MAX_BFCHAR_PER_BLOCK,
        "max_utf16be_code_units": MAX_UTF16BE_UNITS,
        "native_bfchar_source_policy": "UNIQUE_PER_GENERATED_CMAP_ONLY",
        "bfchar_source_16bit_codespace_inherited": True,
        "bfchar_sources_per_stream_unique_verified": True,
        "all_file_revisions_inspected": False,
        "all_native_cmap_dialects_supported": False,
        "general_postscript_executed": False,
        "cmap_syntax_audited": False,
        "unicode_mappings_audited": False,
        "glyph_meanings_verified": False,
        "font_programs_audited": False,
        "glyph_widths_audited": False,
        "reading_order_verified": False,
        "pdf_ua_qualified": False,
        "worker_results_authenticated": False,
        "aggregate_job_resources_qualified": False,
        "default_pipeline_activated": False,
        "release_authorized": False,
    }


PROFILE_SHA256 = sha256(_canonical(tounicode_bfchar_sources_profile())).hexdigest()
_FIXED_PROFILE_SHA256 = "7b0ec9977c118352bbe1d5db7bfdee0de15d18babc4fbf640a0171cdc9a82cf5"


def _profile() -> None:
    """Require pinned ancestor, parser, Linux and resource envelopes."""
    previous._profile()
    if (sys.platform != "linux" or os.environ.get(_DISABLE) == "1"
            or (MAX_DOCUMENT_PAGES, MAX_PDF_BYTES, MAX_DECODED_CMAP_BYTES,
                MAX_TOTAL_DECODED_BYTES, MAX_BFCHAR_BLOCKS,
                MAX_BFCHAR_RECORDS, MAX_BFCHAR_PER_BLOCK,
                MAX_UTF16BE_UNITS) != _FIXED_ENVELOPE
            or LANGUAGE != "en-US" or PARSER_VERSION != "6.19.0"
            or previous.PROFILE_SHA256 != _FIXED_PARENT_PROFILE_SHA256
            or PROFILE_SHA256 != _FIXED_PROFILE_SHA256
            or sha256(_canonical(tounicode_bfchar_sources_profile())).hexdigest()
               != PROFILE_SHA256):
        raise ValueError("native ToUnicode bfchar source profile disabled/changed")


@dataclass(frozen=True, slots=True, repr=False)
class PdfToUnicodeBfcharSources:
    """Sealed source counts and plan digests, never the source operands."""

    pdf_sha256: str
    ir_sha256: str
    plan_sha256: str
    page_count: int
    tounicode_stream_count: int
    cmap_framed_stream_count: int
    bfchar_source_count: int
    bfchar_unique_source_count: int
    cmap_bfchar_source_uniqueness_valid: bool
    prior_tounicode_utf16be_targets_sha256: str
    _sealed_sha256: str = field(init=False, repr=False, compare=False)

    def _record(self) -> dict:
        """Validate the exact count envelope and preserve inherited nonclaims."""
        _profile()
        _identity({key: getattr(self, key) for key in IDENTITY_FIELDS})
        if (type(self.tounicode_stream_count) is not int
                or not 1 <= self.tounicode_stream_count <= 32 * self.page_count
                or type(self.cmap_framed_stream_count) is not int
                or self.cmap_framed_stream_count != self.tounicode_stream_count
                or type(self.bfchar_source_count) is not int
                or not 1 <= self.bfchar_source_count <= MAX_BFCHAR_RECORDS
                or type(self.bfchar_unique_source_count) is not int
                or self.bfchar_unique_source_count != self.bfchar_source_count
                or self.cmap_bfchar_source_uniqueness_valid is not True
                or not _is_digest(self.prior_tounicode_utf16be_targets_sha256)):
            raise ValueError("native bfchar source receipt fields differ")
        return {
            "schema_version": "1.0.0", "profile_id": PROFILE_ID,
            "policy_id": POLICY_ID, "status": STATUS,
            "parser_version": PARSER_VERSION, "language": LANGUAGE,
            "profile_sha256": PROFILE_SHA256,
            "previous_tounicode_utf16be_targets_profile_sha256":
                previous.PROFILE_SHA256,
            "pdf_sha256": self.pdf_sha256, "ir_sha256": self.ir_sha256,
            "plan_sha256": self.plan_sha256, "page_count": self.page_count,
            "tounicode_stream_count": self.tounicode_stream_count,
            "cmap_framed_stream_count": self.cmap_framed_stream_count,
            "bfchar_source_count": self.bfchar_source_count,
            "bfchar_unique_source_count": self.bfchar_unique_source_count,
            "cmap_bfchar_source_uniqueness_valid":
                self.cmap_bfchar_source_uniqueness_valid,
            "prior_tounicode_utf16be_targets_sha256":
                self.prior_tounicode_utf16be_targets_sha256,
            "all_file_revisions_inspected": False,
            "all_native_cmap_dialects_supported": False,
            "general_postscript_executed": False,
            "cmap_syntax_audited": False,
            "unicode_mappings_audited": False,
            "glyph_meanings_verified": False,
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
        """Seal immutable canonical bytes with an unsigned digest."""
        try:
            encoded = _canonical(self._record())
            if len(encoded) > RESULT_BYTES:
                raise ValueError("native bfchar source receipt too large")
            digest = sha256(encoded).hexdigest()
            if hasattr(self, "_sealed_sha256") and self._sealed_sha256 != digest:
                raise ValueError("native bfchar source receipt changed")
            object.__setattr__(self, "_sealed_sha256", digest)
        except Exception:
            raise PdfToUnicodeBfcharSourcesError("pdf_tounicode_bfchar_sources_receipt_invalid") from None

    def to_bytes(self) -> bytes:
        """Expose only sealed counts/digests and inherited negative claims."""
        try:
            encoded = _canonical(self._record())
            if len(encoded) > RESULT_BYTES or sha256(encoded).hexdigest() != self._sealed_sha256:
                raise ValueError("native bfchar source receipt mutated")
            return encoded
        except Exception:
            raise PdfToUnicodeBfcharSourcesError("pdf_tounicode_bfchar_sources_receipt_invalid") from None

    def to_dict(self) -> dict:
        """Return a copy of content-free canonical receipt JSON."""
        return json.loads(self.to_bytes())

    @property
    def inspection_sha256(self) -> str:
        """Digest of content-free receipt; does not authenticate worker."""
        return sha256(self.to_bytes()).hexdigest()


def _decode(
    data: bytes, identity: dict, ancestor: previous.PdfToUnicodeUtf16beTargets,
) -> PdfToUnicodeBfcharSources:
    """Decode only exact worker fields bound to the prior sealed receipt."""
    try:
        _identity(identity)
        if (type(ancestor) is not previous.PdfToUnicodeUtf16beTargets
                or type(data) is not bytes or not 0 < len(data) <= RESULT_BYTES
                or {key: getattr(ancestor, key) for key in IDENTITY_FIELDS} != identity):
            raise ValueError("native bfchar source parent identity differs")
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
            raise ValueError("native bfchar source child protocol differs")
        _identity(record["identity"])
        if record["identity"] != identity:
            raise ValueError("native bfchar source binding differs")
        limits = record["limits"]
        if (type(limits) is not dict or set(limits) != set(_LIMITS)
                or any(type(v) is not int or v != _LIMITS[key]
                       for key, v in limits.items())):
            raise ValueError("native bfchar source child limits differ")
        info = record["inspection"]
        keys = {
            "status", "tounicode_stream_count", "cmap_framed_stream_count",
            "bfchar_source_count", "bfchar_unique_source_count",
            "cmap_bfchar_source_uniqueness_valid",
        }
        if (type(info) is not dict or set(info) != keys
                or info["status"] != STATUS
                or type(info["tounicode_stream_count"]) is not int
                or info["tounicode_stream_count"] != ancestor.tounicode_stream_count
                or type(info["cmap_framed_stream_count"]) is not int
                or info["cmap_framed_stream_count"] != ancestor.cmap_framed_stream_count
                or type(info["bfchar_source_count"]) is not int
                or info["bfchar_source_count"] != ancestor.utf16be_target_count
                or type(info["bfchar_unique_source_count"]) is not int
                or info["bfchar_unique_source_count"] != info["bfchar_source_count"]
                or info["cmap_bfchar_source_uniqueness_valid"] is not True):
            raise ValueError("native bfchar source child count/type/keys differ")
        return PdfToUnicodeBfcharSources(
            **identity,
            tounicode_stream_count=info["tounicode_stream_count"],
            cmap_framed_stream_count=info["cmap_framed_stream_count"],
            bfchar_source_count=info["bfchar_source_count"],
            bfchar_unique_source_count=info["bfchar_unique_source_count"],
            cmap_bfchar_source_uniqueness_valid=
                info["cmap_bfchar_source_uniqueness_valid"],
            prior_tounicode_utf16be_targets_sha256=ancestor_digest,
        )
    except Exception:
        raise PdfToUnicodeBfcharSourcesError("pdf_tounicode_bfchar_sources_protocol_invalid") from None


def _run_worker(pdf: bytes, identity: dict) -> bytes:
    """Send exact source/result over owned separate anonymous regular FDs."""
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as result:
        fds = (source.fileno(), result.fileno())
        infos = [os.fstat(fd) for fd in fds]
        if (any(not stat.S_ISREG(v.st_mode) or v.st_nlink != 0
                or v.st_uid != os.geteuid() for v in infos)
                or (infos[0].st_dev, infos[0].st_ino)
                   == (infos[1].st_dev, infos[1].st_ino)):
            raise ValueError("native bfchar source anonymous descriptors invalid")
        header = " ".join([str(PROTOCOL_VERSION), *(str(identity[key])
                          for key in IDENTITY_FIELDS)])
        source.write(header.encode("ascii") + b"\n")
        source.write(pdf)
        source.flush()
        process = _start([
            sys.executable, "-I",
            str(Path(__file__).resolve().with_name("_pdf_tounicode_bfchar_sources_worker.py")),
            str(fds[0]), str(fds[1]), str(os.getpid()),
        ], fds)
        if (_wait(process) != 0
                or not 0 < os.fstat(result.fileno()).st_size <= RESULT_BYTES):
            raise ValueError("native bfchar source child rejected")
        result.seek(0)
        return result.read(RESULT_BYTES + 1)

def inspect_pdf_tounicode_bfchar_sources(
    *, pdf_bytes: object, plan: PageWindowPlan,
    expected_plan_sha256: str, expected_language: str,
) -> PdfToUnicodeBfcharSources:
    """Opt-in native source uniqueness proof, preserving all ancestors."""
    try:
        _profile()
        if (type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b"%PDF-1.7")
                or not 0 < len(pdf_bytes) <= MAX_PDF_BYTES
                or type(plan) is not PageWindowPlan
                or not _is_digest(expected_plan_sha256)
                or type(expected_language) is not str
                or expected_language != LANGUAGE):
            raise ValueError("unsupported native bfchar source input")
        plan.__post_init__()
        if (plan.plan_sha256 != expected_plan_sha256
                or plan.inspector_profile_id != TEXT_PROFILE
                or plan.page_count > MAX_DOCUMENT_PAGES
                or plan.pdf_sha256 != sha256(pdf_bytes).hexdigest()):
            raise ValueError("native bfchar source plan identity differs")
        identity = _identity_from_plan(plan)
    except Exception:
        raise PdfToUnicodeBfcharSourcesError("pdf_tounicode_bfchar_sources_input_invalid") from None
    try:
        ancestor = previous.inspect_pdf_tounicode_utf16be_targets(
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
            raise ValueError("native bfchar source ancestor or plan mutated")
        return receipt
    except Exception:
        raise PdfToUnicodeBfcharSourcesError("pdf_tounicode_bfchar_sources_execution_failed") from None
