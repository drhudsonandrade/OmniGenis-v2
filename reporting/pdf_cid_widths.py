"""Opt-in native generated PDF CID width-array structural admission.

This checksum-only technical receipt is not a glyph-correctness, ToUnicode,
PDF/UA, scientific, clinical or release-authorization decision.
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
from reporting import pdf_font_descriptor as previous
from reporting.pdf_object_graph import _canonical, _start, _unique_pairs, _wait
from reporting._pdf_object_graph_worker import (
    CPU_SECONDS, IDENTITY_FIELDS, MAX_PDF_BYTES, MEMORY_BYTES, OPEN_FILES,
    PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES, _is_digest,
)
from reporting._pdf_cid_widths_worker import (
    LANGUAGE, MAX_CID, MAX_CID_WIDTH_VALUES_PER_FONT, MAX_DOCUMENT_PAGES,
    MAX_NATIVE_WIDTH, MAX_WIDTH_ARRAY_ENTRIES, POLICY_ID, PROFILE_ID,
    STATUS, _identity, _identity_from_plan,
)

_DISABLE = "OMNIGENIS_PDF_CID_WIDTHS_DISABLED"
_FIXED_PARENT_PROFILE_SHA256 = "d5a6bd2642b56e47f09437e442c0d66e4defc35e575199e84822a43a5e0e88db"
_FIXED_ENVELOPE = (64, 8 * 1024 * 1024)
_LIMITS = {
    "memory_bytes": MEMORY_BYTES, "cpu_seconds": CPU_SECONDS,
    "file_bytes": RESULT_BYTES, "open_files": OPEN_FILES,
}


class PdfCidWidthsError(ValueError):
    """Content-free rejection of unsupported generated native width arrays."""


def cid_widths_profile() -> dict:
    """A default-off, closed child of exact FontDescriptor qualification."""
    return {
        "schema_version": "1.0.0",
        "profile_id": PROFILE_ID,
        "policy_id": POLICY_ID,
        "parser_version": PARSER_VERSION,
        "previous_font_descriptor_profile_sha256": previous.PROFILE_SHA256,
        "language": LANGUAGE,
        "max_pages": MAX_DOCUMENT_PAGES,
        "max_pdf_bytes": MAX_PDF_BYTES,
        "cid_width_policy": "NATIVE_SORTED_NONOVERLAPPING_CID_ARRAY_PAIRS_ONLY",
        "max_cid": MAX_CID,
        "max_width_array_entries": MAX_WIDTH_ARRAY_ENTRIES,
        "max_native_width": MAX_NATIVE_WIDTH,
        "max_width_values_per_font": MAX_CID_WIDTH_VALUES_PER_FONT,
        "cid_width_font_count_matches_descriptor": True,
        "cid_ranges_strictly_ascending": True,
        "cid_widths_natively_bounded": True,
        "all_file_revisions_inspected": False,
        "decoded_contents_audited": False,
        "font_programs_audited": False,
        "glyph_widths_audited": False,
        "tounicode_decoded": False,
        "reading_order_verified": False,
        "pdf_ua_qualified": False,
        "worker_results_authenticated": False,
        "aggregate_job_resources_qualified": False,
        "default_pipeline_activated": False,
        "release_authorized": False,
    }


PROFILE_SHA256 = sha256(_canonical(cid_widths_profile())).hexdigest()
_FIXED_PROFILE_SHA256 = "7b436ffbf10bf7d41eab3363cced89e84989a323f3d9412b19ee3d6b9b6734ad"


def _profile() -> None:
    """Fail closed on source, ancestor, profile, platform or parser drift."""
    previous._profile()
    if (sys.platform != "linux" or os.environ.get(_DISABLE) == "1"
            or (MAX_DOCUMENT_PAGES, MAX_PDF_BYTES) != _FIXED_ENVELOPE
            or LANGUAGE != "en-US" or PARSER_VERSION != "6.19.0"
            or (MAX_CID, MAX_WIDTH_ARRAY_ENTRIES, MAX_NATIVE_WIDTH)
               != (65535, 4096, 16384)
            or previous.PROFILE_SHA256 != _FIXED_PARENT_PROFILE_SHA256
            or PROFILE_SHA256 != _FIXED_PROFILE_SHA256
            or sha256(_canonical(cid_widths_profile())).hexdigest()
               != PROFILE_SHA256):
        raise ValueError("generated CID width profile disabled or changed")


@dataclass(frozen=True, slots=True, repr=False)
class PdfCidWidths:
    """Immutable local receipt; its checksum is not a digital signature."""

    pdf_sha256: str
    ir_sha256: str
    plan_sha256: str
    page_count: int
    cid_width_font_count: int
    cid_width_pair_count: int
    cid_width_value_count: int
    cid_ranges_strictly_ascending: bool
    cid_widths_natively_bounded: bool
    prior_font_descriptor_sha256: str
    _sealed_sha256: str = field(init=False, repr=False, compare=False)

    def _record(self) -> dict:
        _profile()
        _identity({key: getattr(self, key) for key in IDENTITY_FIELDS})
        if (type(self.cid_width_font_count) is not int
                or not 1 <= self.cid_width_font_count <= 32 * self.page_count
                or type(self.cid_width_pair_count) is not int
                or not 1 <= self.cid_width_pair_count <= 2048 * self.cid_width_font_count
                or type(self.cid_width_value_count) is not int
                or not 1 <= self.cid_width_value_count
                   <= MAX_CID_WIDTH_VALUES_PER_FONT * self.cid_width_font_count
                or self.cid_ranges_strictly_ascending is not True
                or self.cid_widths_natively_bounded is not True
                or not _is_digest(self.prior_font_descriptor_sha256)):
            raise ValueError("generated CID width receipt inconsistent")
        return {
            "schema_version": "1.0.0", "profile_id": PROFILE_ID,
            "policy_id": POLICY_ID, "status": STATUS,
            "parser_version": PARSER_VERSION, "language": LANGUAGE,
            "profile_sha256": PROFILE_SHA256,
            "previous_font_descriptor_profile_sha256": previous.PROFILE_SHA256,
            "pdf_sha256": self.pdf_sha256, "ir_sha256": self.ir_sha256,
            "plan_sha256": self.plan_sha256, "page_count": self.page_count,
            "cid_width_font_count": self.cid_width_font_count,
            "cid_width_pair_count": self.cid_width_pair_count,
            "cid_width_value_count": self.cid_width_value_count,
            "cid_ranges_strictly_ascending": self.cid_ranges_strictly_ascending,
            "cid_widths_natively_bounded": self.cid_widths_natively_bounded,
            "prior_font_descriptor_sha256": self.prior_font_descriptor_sha256,
            "all_file_revisions_inspected": False,
            "decoded_contents_audited": False,
            "font_programs_audited": False,
            "glyph_widths_audited": False,
            "tounicode_decoded": False,
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
                raise ValueError("generated CID width receipt oversized")
            digest = sha256(encoded).hexdigest()
            if hasattr(self, "_sealed_sha256") and self._sealed_sha256 != digest:
                raise ValueError("generated CID width receipt mutated")
            object.__setattr__(self, "_sealed_sha256", digest)
        except Exception:
            raise PdfCidWidthsError("pdf_cid_widths_receipt_invalid") from None

    def to_bytes(self) -> bytes:
        try:
            encoded = _canonical(self._record())
            if len(encoded) > RESULT_BYTES or sha256(encoded).hexdigest() != self._sealed_sha256:
                raise ValueError("generated CID width receipt changed")
            return encoded
        except Exception:
            raise PdfCidWidthsError("pdf_cid_widths_receipt_invalid") from None

    def to_dict(self) -> dict:
        return json.loads(self.to_bytes())

    @property
    def inspection_sha256(self) -> str:
        """Content checksum; never a worker-authentication claim."""
        return sha256(self.to_bytes()).hexdigest()


def _decode(data: bytes, identity: dict, ancestor: previous.PdfFontDescriptor) -> PdfCidWidths:
    """Validate exact child protocol and exact document-bound ancestor proof."""
    try:
        _identity(identity)
        if (type(ancestor) is not previous.PdfFontDescriptor
                or type(data) is not bytes or not 0 < len(data) <= RESULT_BYTES
                or {key: getattr(ancestor, key) for key in IDENTITY_FIELDS}
                   != identity):
            raise ValueError("CID width child result or ancestor invalid")
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
            raise ValueError("CID width child protocol differs")
        _identity(record["identity"])
        if record["identity"] != identity:
            raise ValueError("CID width child source differs")
        limits = record["limits"]
        if (type(limits) is not dict or set(limits) != set(_LIMITS)
                or any(type(v) is not int or v != _LIMITS[key]
                       for key, v in limits.items())):
            raise ValueError("CID width resource envelope differs")
        inspection = record["inspection"]
        keys = {
            "status", "cid_width_font_count", "cid_width_pair_count",
            "cid_width_value_count", "cid_ranges_strictly_ascending",
            "cid_widths_natively_bounded",
        }
        if (type(inspection) is not dict or set(inspection) != keys
                or inspection["status"] != STATUS
                or inspection["cid_width_font_count"]
                   != ancestor.font_descriptor_envelope_count):
            raise ValueError("CID width child counts or keys differ")
        return PdfCidWidths(
            **identity,
            **{key: inspection[key] for key in keys - {"status"}},
            prior_font_descriptor_sha256=ancestor_digest,
        )
    except Exception:
        raise PdfCidWidthsError("pdf_cid_widths_protocol_invalid") from None


def _run_worker(pdf: bytes, identity: dict) -> bytes:
    """Transfer bounded generated bytes via owned anonymous FDs only."""
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as result:
        fds = (source.fileno(), result.fileno())
        infos = [os.fstat(fd) for fd in fds]
        if (any(not stat.S_ISREG(v.st_mode) or v.st_nlink != 0
                or v.st_uid != os.geteuid() for v in infos)
                or (infos[0].st_dev, infos[0].st_ino)
                   == (infos[1].st_dev, infos[1].st_ino)):
            raise ValueError("generated CID width worker descriptors invalid")
        header = " ".join([str(PROTOCOL_VERSION), *(str(identity[key])
                          for key in IDENTITY_FIELDS)])
        source.write(header.encode("ascii") + b"\n")
        source.write(pdf)
        source.flush()
        process = _start([
            sys.executable, "-I",
            str(Path(__file__).resolve().with_name("_pdf_cid_widths_worker.py")),
            str(fds[0]), str(fds[1]), str(os.getpid()),
        ], fds)
        if _wait(process) != 0 or not 0 < os.fstat(result.fileno()).st_size <= RESULT_BYTES:
            raise ValueError("generated CID width worker rejected")
        result.seek(0)
        return result.read(RESULT_BYTES + 1)


def inspect_pdf_cid_widths(
    *, pdf_bytes: object, plan: PageWindowPlan,
    expected_plan_sha256: str, expected_language: str,
) -> PdfCidWidths:
    """Bind exactly to the sealed plan and prior native FontDescriptor."""
    try:
        _profile()
        if (type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b"%PDF-1.7")
                or not 0 < len(pdf_bytes) <= MAX_PDF_BYTES
                or type(plan) is not PageWindowPlan
                or not _is_digest(expected_plan_sha256)
                or type(expected_language) is not str
                or expected_language != LANGUAGE):
            raise ValueError("unsupported generated CID width request")
        plan.__post_init__()
        if (plan.plan_sha256 != expected_plan_sha256
                or plan.inspector_profile_id != TEXT_PROFILE
                or plan.page_count > MAX_DOCUMENT_PAGES
                or plan.pdf_sha256 != sha256(pdf_bytes).hexdigest()):
            raise ValueError("generated CID width plan differs")
        identity = _identity_from_plan(plan)
    except Exception:
        raise PdfCidWidthsError("pdf_cid_widths_input_invalid") from None
    try:
        ancestor = previous.inspect_pdf_font_descriptor(
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
            raise ValueError("CID width prerequisite or input mutated")
        return receipt
    except Exception:
        raise PdfCidWidthsError("pdf_cid_widths_execution_failed") from None
