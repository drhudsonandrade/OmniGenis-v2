"""Opt-in strict generated PDF Type0/Lab native resource leaf admission.

This local checksum-bound receipt is NOT font-program verification, decoded
ToUnicode correctness, PDF/UA conformance, certification or release approval.
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
from reporting import pdf_page_surface as prior
from reporting.pdf_object_graph import _canonical, _start, _unique_pairs, _wait
from reporting._pdf_object_graph_worker import (
    CPU_SECONDS, IDENTITY_FIELDS, MAX_PDF_BYTES, MEMORY_BYTES, OPEN_FILES,
    PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES, _is_digest,
)
from reporting._pdf_resource_leaves_worker import (
    LANGUAGE, MAX_DOCUMENT_PAGES, POLICY_ID, PROFILE_ID, STATUS,
    _identity, _identity_from_plan,
)

_DISABLE = "OMNIGENIS_PDF_RESOURCE_LEAVES_DISABLED"
_FIXED_PARENT_PROFILE_SHA256 = "6de06faa02128f4a1d5650bc352492f71879e665f35fc5d4b7ba341b325651a1"
_FIXED_ENVELOPE = (64, 8 * 1024 * 1024)
_LIMITS = {
    "memory_bytes": MEMORY_BYTES, "cpu_seconds": CPU_SECONDS,
    "file_bytes": RESULT_BYTES, "open_files": OPEN_FILES,
}


class PdfResourceLeavesError(ValueError):
    """Content-free rejection of unsupported native generated resource leaves."""


def resource_leaves_profile() -> dict:
    """Pin only the generated Type0/Lab inner-resource surface."""
    return {
        "schema_version": "1.0.0",
        "profile_id": PROFILE_ID,
        "policy_id": POLICY_ID,
        "parser_version": PARSER_VERSION,
        "previous_page_surface_profile_sha256": prior.PROFILE_SHA256,
        "language": LANGUAGE,
        "max_pages": MAX_DOCUMENT_PAGES,
        "max_pdf_bytes": MAX_PDF_BYTES,
        "resource_dictionary_policy": "DISTINCT_INDEXED_GENERATED_RESOURCES",
        "font_binding_policy": "BOUNDED_INDEXED_GENERATION_ZERO_TYPE0_CIDFONT_TYPE2",
        "tounicode_stream_policy": "DISTINCT_INDEXED_FLATE_RAW_BYTES_ONLY",
        "font_descriptor_policy": "INDEXED_DICTIONARY_REFERENCE_ONLY",
        "lab_color_policy": "TWO_GENERATED_DIRECT_LAB_PRESETS_NATIVE_SCALARS",
        "font_reference_roles_disjoint": True,
        "type0_cid_links_match": True,
        "lab_color_presets_match": True,
        "tounicode_raw_streams_indexed": True,
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


PROFILE_SHA256 = sha256(_canonical(resource_leaves_profile())).hexdigest()
_FIXED_PROFILE_SHA256 = "cecea0ee9e3b0c9603d72ee06fa612b0929357fc8a6a0026513d9eaa5e8f5597"


def _profile() -> None:
    """Fail closed if ancestor authority, environment or profile drifts."""
    prior._profile()
    if (sys.platform != "linux" or os.environ.get(_DISABLE) == "1"
            or (MAX_DOCUMENT_PAGES, MAX_PDF_BYTES) != _FIXED_ENVELOPE
            or LANGUAGE != "en-US" or PARSER_VERSION != "6.19.0"
            or prior.PROFILE_SHA256 != _FIXED_PARENT_PROFILE_SHA256
            or PROFILE_SHA256 != _FIXED_PROFILE_SHA256
            or sha256(_canonical(resource_leaves_profile())).hexdigest()
               != PROFILE_SHA256):
        raise ValueError("generated resource leaves profile disabled or changed")


@dataclass(frozen=True, slots=True, repr=False)
class PdfResourceLeaves:
    """Immutable unsigned locally checksummed receipt, not an attestation."""

    pdf_sha256: str
    ir_sha256: str
    plan_sha256: str
    page_count: int
    resource_dictionary_count: int
    font_binding_count: int
    cid_descendant_reference_count: int
    tounicode_stream_reference_count: int
    lab_color_space_count: int
    font_reference_roles_disjoint: bool
    type0_cid_links_match: bool
    lab_color_presets_match: bool
    tounicode_raw_streams_indexed: bool
    prior_page_surface_sha256: str
    _sealed_sha256: str = field(init=False, repr=False, compare=False)

    def _record(self) -> dict:
        _profile()
        _identity({key: getattr(self, key) for key in IDENTITY_FIELDS})
        if (type(self.resource_dictionary_count) is not int
                or not 1 <= self.resource_dictionary_count <= self.page_count
                or type(self.font_binding_count) is not int
                or not 1 <= self.font_binding_count <= 32 * self.resource_dictionary_count
                or type(self.cid_descendant_reference_count) is not int
                or self.cid_descendant_reference_count != self.font_binding_count
                or type(self.tounicode_stream_reference_count) is not int
                or self.tounicode_stream_reference_count != self.font_binding_count
                or type(self.lab_color_space_count) is not int
                or self.lab_color_space_count != 2 * self.resource_dictionary_count
                or self.font_reference_roles_disjoint is not True
                or self.type0_cid_links_match is not True
                or self.lab_color_presets_match is not True
                or self.tounicode_raw_streams_indexed is not True
                or not _is_digest(self.prior_page_surface_sha256)):
            raise ValueError("generated resource leaves receipt is inconsistent")
        return {
            "schema_version": "1.0.0", "profile_id": PROFILE_ID,
            "policy_id": POLICY_ID, "status": STATUS,
            "parser_version": PARSER_VERSION, "language": LANGUAGE,
            "profile_sha256": PROFILE_SHA256,
            "previous_page_surface_profile_sha256": prior.PROFILE_SHA256,
            "pdf_sha256": self.pdf_sha256, "ir_sha256": self.ir_sha256,
            "plan_sha256": self.plan_sha256, "page_count": self.page_count,
            "resource_dictionary_count": self.resource_dictionary_count,
            "font_binding_count": self.font_binding_count,
            "cid_descendant_reference_count": self.cid_descendant_reference_count,
            "tounicode_stream_reference_count": self.tounicode_stream_reference_count,
            "lab_color_space_count": self.lab_color_space_count,
            "font_reference_roles_disjoint": self.font_reference_roles_disjoint,
            "type0_cid_links_match": self.type0_cid_links_match,
            "lab_color_presets_match": self.lab_color_presets_match,
            "tounicode_raw_streams_indexed": self.tounicode_raw_streams_indexed,
            "prior_page_surface_sha256": self.prior_page_surface_sha256,
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
                raise ValueError("generated resource leaves receipt oversized")
            digest = sha256(encoded).hexdigest()
            if hasattr(self, "_sealed_sha256") and self._sealed_sha256 != digest:
                raise ValueError("generated resource leaves receipt mutated")
            object.__setattr__(self, "_sealed_sha256", digest)
        except Exception:
            raise PdfResourceLeavesError("pdf_resource_leaves_receipt_invalid") from None

    def to_bytes(self) -> bytes:
        try:
            encoded = _canonical(self._record())
            if len(encoded) > RESULT_BYTES or sha256(encoded).hexdigest() != self._sealed_sha256:
                raise ValueError("generated resource leaves receipt changed")
            return encoded
        except Exception:
            raise PdfResourceLeavesError("pdf_resource_leaves_receipt_invalid") from None

    def to_dict(self) -> dict:
        return json.loads(self.to_bytes())

    @property
    def inspection_sha256(self) -> str:
        """Local deterministic checksum only, never a worker signature."""
        return sha256(self.to_bytes()).hexdigest()


def _decode(
    data: bytes, identity: dict, previous_receipt: prior.PdfPageSurface,
) -> PdfResourceLeaves:
    """Verify exact child wire, native resource counts and ancestor checksum."""
    try:
        _identity(identity)
        if (type(previous_receipt) is not prior.PdfPageSurface
                or type(data) is not bytes or not 0 < len(data) <= RESULT_BYTES):
            raise ValueError("resource leaves child result/prerequisite type")
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
            raise ValueError("resource leaves worker protocol changed")
        _identity(record["identity"])
        if record["identity"] != identity:
            raise ValueError("resource leaves worker source identity differs")
        limits = record["limits"]
        if (type(limits) is not dict or set(limits) != set(_LIMITS)
                or any(type(v) is not int or v != _LIMITS[key]
                       for key, v in limits.items())):
            raise ValueError("resource leaves worker resource limits differ")
        inspection = record["inspection"]
        keys = {
            "status", "resource_dictionary_count", "font_binding_count",
            "cid_descendant_reference_count", "tounicode_stream_reference_count",
            "lab_color_space_count", "font_reference_roles_disjoint",
            "type0_cid_links_match", "lab_color_presets_match",
            "tounicode_raw_streams_indexed",
        }
        if (type(inspection) is not dict or set(inspection) != keys
                or inspection["status"] != STATUS):
            raise ValueError("resource leaves worker success record malformed")
        return PdfResourceLeaves(
            **identity,
            **{key: inspection[key] for key in keys - {"status"}},
            prior_page_surface_sha256=previous_digest,
        )
    except Exception:
        raise PdfResourceLeavesError("pdf_resource_leaves_protocol_invalid") from None


def _run_worker(pdf: bytes, identity: dict) -> bytes:
    """Only owned unlinked input/output FDs reach a bounded isolated child."""
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as result:
        fds = (source.fileno(), result.fileno())
        infos = [os.fstat(fd) for fd in fds]
        if (any(not stat.S_ISREG(v.st_mode) or v.st_nlink != 0
                or v.st_uid != os.geteuid() for v in infos)
                or (infos[0].st_dev, infos[0].st_ino)
                   == (infos[1].st_dev, infos[1].st_ino)):
            raise ValueError("generated resource leaves worker FDs invalid")
        header = " ".join([str(PROTOCOL_VERSION), *(str(identity[key])
                          for key in IDENTITY_FIELDS)])
        source.write(header.encode("ascii") + b"\n")
        source.write(pdf)
        source.flush()
        process = _start([
            sys.executable, "-I",
            str(Path(__file__).resolve().with_name("_pdf_resource_leaves_worker.py")),
            str(fds[0]), str(fds[1]), str(os.getpid()),
        ], fds)
        if _wait(process) != 0 or not 0 < os.fstat(result.fileno()).st_size <= RESULT_BYTES:
            raise ValueError("resource leaves worker rejected")
        result.seek(0)
        return result.read(RESULT_BYTES + 1)


def inspect_pdf_resource_leaves(
    *, pdf_bytes: object, plan: PageWindowPlan,
    expected_plan_sha256: str, expected_language: str,
) -> PdfResourceLeaves:
    """Bind the same immutable plan and prior page-surface admission first."""
    try:
        _profile()
        if (type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b"%PDF-1.7")
                or not 0 < len(pdf_bytes) <= MAX_PDF_BYTES
                or type(plan) is not PageWindowPlan
                or not _is_digest(expected_plan_sha256)
                or type(expected_language) is not str
                or expected_language != LANGUAGE):
            raise ValueError("unsupported generated resource leaves request")
        plan.__post_init__()
        if (plan.plan_sha256 != expected_plan_sha256
                or plan.inspector_profile_id != TEXT_PROFILE
                or plan.page_count > MAX_DOCUMENT_PAGES
                or plan.pdf_sha256 != sha256(pdf_bytes).hexdigest()):
            raise ValueError("generated resource leaves request differs")
        identity = _identity_from_plan(plan)
    except Exception:
        raise PdfResourceLeavesError("pdf_resource_leaves_input_invalid") from None
    try:
        precursor = prior.inspect_pdf_page_surface(
            pdf_bytes=pdf_bytes, plan=plan,
            expected_plan_sha256=expected_plan_sha256,
            expected_language=expected_language,
        )
        precursor_digest = precursor.inspection_sha256
        proof = _decode(_run_worker(pdf_bytes, identity), identity, precursor)
        plan.__post_init__()
        _profile()
        if (plan.plan_sha256 != expected_plan_sha256
                or _identity_from_plan(plan) != identity
                or precursor.inspection_sha256 != precursor_digest):
            raise ValueError("resource leaves prerequisite or input mutated")
        return proof
    except Exception:
        raise PdfResourceLeavesError("pdf_resource_leaves_execution_failed") from None
