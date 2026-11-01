"""Opt-in strict native generated PDF page surface/resource admission.

The resulting checksum-bound receipt is local metadata, not cryptographic
attestation, full content validation, reading-order or PDF/UA qualification.
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

from reporting._pdf_document_byte_budget import LEGACY_MAX_PDF_BYTES as MAX_RAW_STREAM_BYTES
from reporting.page_windows import PageWindowPlan
from reporting.pdf_text_windows import PROFILE_ID as TEXT_PROFILE
from reporting import pdf_trailer_catalog as prior
from reporting.pdf_object_graph import _canonical, _start, _unique_pairs, _wait
from reporting._pdf_object_graph_worker import (
    CPU_SECONDS, IDENTITY_FIELDS, MAX_PDF_BYTES, MEMORY_BYTES, OPEN_FILES,
    PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES, _is_digest,
)
from reporting._pdf_page_surface_worker import (
    LANGUAGE, MAX_DOCUMENT_PAGES, POLICY_ID, PROFILE_ID, STATUS,
    _identity, _identity_from_plan,
)

_DISABLE = "OMNIGENIS_PDF_PAGE_SURFACE_DISABLED"
_FIXED_PARENT_PROFILE_SHA256 = "3d3502d1f2ff01f63a4d05195e219b5ae63e21e2c75667df4f2492b3395058ae"
_FIXED_ENVELOPE = (64, 16 * 1024 * 1024)
_LIMITS = {
    "memory_bytes": MEMORY_BYTES, "cpu_seconds": CPU_SECONDS,
    "file_bytes": RESULT_BYTES, "open_files": OPEN_FILES,
}


class PdfPageSurfaceError(ValueError):
    """Content-free rejection of unsupported generated physical page state."""


def page_surface_profile() -> dict:
    """Declare the generated native page subset without wider conformance claims."""
    return {
        "schema_version": "1.0.0",
        "profile_id": PROFILE_ID,
        "policy_id": POLICY_ID,
        "parser_version": PARSER_VERSION,
        "previous_trailer_catalog_profile_sha256": prior.PROFILE_SHA256,
        "language": LANGUAGE,
        "max_pages": MAX_DOCUMENT_PAGES,
        "max_pdf_bytes": MAX_PDF_BYTES,
        "max_raw_stream_bytes": MAX_RAW_STREAM_BYTES,
        "native_page_dictionary_policy": "EXACT_GENERATED_KEYS_INDEXED_GENERATION_ZERO",
        "page_box_policy": "FINITE_EQUAL_MEDIA_TRIM_BLEED_BOUNDED",
        "content_stream_policy": "DISTINCT_INDEXED_FLATE_RAW_BYTES_ONLY",
        "resource_reference_policy": "INDEXED_KNOWN_OUTER_CATEGORIES",
        "native_tab_slot_policy": "TABS_S_CONTIGUOUS_STRUCTPARENTS",
        "boxes_match": True,
        "content_references_indexed": True,
        "resource_references_indexed": True,
        "structure_slots_contiguous": True,
        "all_file_revisions_inspected": False,
        "decoded_contents_audited": False,
        "inner_resources_audited": False,
        "reading_order_verified": False,
        "pdf_ua_qualified": False,
        "worker_results_authenticated": False,
        "aggregate_job_resources_qualified": False,
        "default_pipeline_activated": False,
        "release_authorized": False,
    }


PROFILE_SHA256 = sha256(_canonical(page_surface_profile())).hexdigest()
_FIXED_PROFILE_SHA256 = "0f50a0dbda655217f0dcb8a4e7590f4347fe54c6a58632a8efeaffa700fd5b5e"


def _profile() -> None:
    """Require unchanged parent authority, locale, parser and bounded profile."""
    prior._profile()
    if (sys.platform != "linux" or os.environ.get(_DISABLE) == "1"
            or (MAX_DOCUMENT_PAGES, MAX_PDF_BYTES) != _FIXED_ENVELOPE
            or LANGUAGE != "en-US" or PARSER_VERSION != "6.19.0"
            or prior.PROFILE_SHA256 != _FIXED_PARENT_PROFILE_SHA256
            or PROFILE_SHA256 != _FIXED_PROFILE_SHA256
            or sha256(_canonical(page_surface_profile())).hexdigest()
               != PROFILE_SHA256):
        raise ValueError("generated page surface profile disabled or changed")


@dataclass(frozen=True, slots=True, repr=False)
class PdfPageSurface:
    """Immutable checksum-bound local receipt; no worker signature is claimed."""

    pdf_sha256: str
    ir_sha256: str
    plan_sha256: str
    page_count: int
    page_dictionary_count: int
    content_stream_count: int
    resource_reference_count: int
    distinct_resource_objects: int
    boxes_match: bool
    content_references_indexed: bool
    resource_references_indexed: bool
    structure_slots_contiguous: bool
    prior_trailer_catalog_sha256: str
    _sealed_sha256: str = field(init=False, repr=False, compare=False)

    def _record(self) -> dict:
        _profile()
        _identity({key: getattr(self, key) for key in IDENTITY_FIELDS})
        if (any(type(v) is not int or v != self.page_count
                for v in (
                    self.page_dictionary_count, self.content_stream_count,
                    self.resource_reference_count,
                ))
                or type(self.distinct_resource_objects) is not int
                or not 1 <= self.distinct_resource_objects <= self.page_count
                or self.boxes_match is not True
                or self.content_references_indexed is not True
                or self.resource_references_indexed is not True
                or self.structure_slots_contiguous is not True
                or not _is_digest(self.prior_trailer_catalog_sha256)):
            raise ValueError("generated page surface receipt is not self-consistent")
        return {
            "schema_version": "1.0.0", "profile_id": PROFILE_ID,
            "policy_id": POLICY_ID, "status": STATUS,
            "parser_version": PARSER_VERSION, "language": LANGUAGE,
            "profile_sha256": PROFILE_SHA256,
            "previous_trailer_catalog_profile_sha256": prior.PROFILE_SHA256,
            "pdf_sha256": self.pdf_sha256, "ir_sha256": self.ir_sha256,
            "plan_sha256": self.plan_sha256, "page_count": self.page_count,
            "page_dictionary_count": self.page_dictionary_count,
            "content_stream_count": self.content_stream_count,
            "resource_reference_count": self.resource_reference_count,
            "distinct_resource_objects": self.distinct_resource_objects,
            "boxes_match": self.boxes_match,
            "content_references_indexed": self.content_references_indexed,
            "resource_references_indexed": self.resource_references_indexed,
            "structure_slots_contiguous": self.structure_slots_contiguous,
            "prior_trailer_catalog_sha256": self.prior_trailer_catalog_sha256,
            "all_file_revisions_inspected": False,
            "decoded_contents_audited": False,
            "inner_resources_audited": False,
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
                raise ValueError("generated page surface receipt oversized")
            digest = sha256(encoded).hexdigest()
            if hasattr(self, "_sealed_sha256") and self._sealed_sha256 != digest:
                raise ValueError("generated page surface receipt changed")
            object.__setattr__(self, "_sealed_sha256", digest)
        except Exception:
            raise PdfPageSurfaceError("pdf_page_surface_receipt_invalid") from None

    def to_bytes(self) -> bytes:
        try:
            encoded = _canonical(self._record())
            if len(encoded) > RESULT_BYTES or sha256(encoded).hexdigest() != self._sealed_sha256:
                raise ValueError("generated page surface receipt modified")
            return encoded
        except Exception:
            raise PdfPageSurfaceError("pdf_page_surface_receipt_invalid") from None

    def to_dict(self) -> dict:
        return json.loads(self.to_bytes())

    @property
    def inspection_sha256(self) -> str:
        """A deterministic checksum only, not a cryptographic signature."""
        return sha256(self.to_bytes()).hexdigest()


def _decode(
    data: bytes, identity: dict, previous_receipt: prior.PdfTrailerCatalog,
) -> PdfPageSurface:
    """Require exact child protocol, successful inspection and prior checksum."""
    try:
        _identity(identity)
        if (type(previous_receipt) is not prior.PdfTrailerCatalog
                or type(data) is not bytes or not 0 < len(data) <= RESULT_BYTES):
            raise ValueError("page surface result/prerequisite type")
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
            raise ValueError("page surface child protocol changed")
        _identity(record["identity"])
        if record["identity"] != identity:
            raise ValueError("page surface child source identity differs")
        limits = record["limits"]
        if (type(limits) is not dict or set(limits) != set(_LIMITS)
                or any(type(v) is not int or v != _LIMITS[key]
                       for key, v in limits.items())):
            raise ValueError("page surface worker limits differ")
        inspection = record["inspection"]
        keys = {
            "status", "page_dictionary_count", "content_stream_count",
            "resource_reference_count", "distinct_resource_objects",
            "boxes_match", "content_references_indexed",
            "resource_references_indexed", "structure_slots_contiguous",
        }
        if (type(inspection) is not dict or set(inspection) != keys
                or inspection["status"] != STATUS):
            raise ValueError("page surface child success record invalid")
        return PdfPageSurface(
            **identity,
            **{key: inspection[key] for key in keys - {"status"}},
            prior_trailer_catalog_sha256=previous_digest,
        )
    except Exception:
        raise PdfPageSurfaceError("pdf_page_surface_protocol_invalid") from None


def _run_worker(pdf: bytes, identity: dict) -> bytes:
    """Use owned, unlinked source and result FDs in the fixed isolated child."""
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as result:
        fds = (source.fileno(), result.fileno())
        infos = [os.fstat(fd) for fd in fds]
        if (any(not stat.S_ISREG(v.st_mode) or v.st_nlink != 0
                or v.st_uid != os.geteuid() for v in infos)
                or (infos[0].st_dev, infos[0].st_ino)
                   == (infos[1].st_dev, infos[1].st_ino)):
            raise ValueError("generated page surface worker FDs invalid")
        header = " ".join([str(PROTOCOL_VERSION), *(str(identity[key])
                          for key in IDENTITY_FIELDS)])
        source.write(header.encode("ascii") + b"\n")
        source.write(pdf)
        source.flush()
        process = _start([
            sys.executable, "-I",
            str(Path(__file__).resolve().with_name("_pdf_page_surface_worker.py")),
            str(fds[0]), str(fds[1]), str(os.getpid()),
        ], fds)
        if _wait(process) != 0 or not 0 < os.fstat(result.fileno()).st_size <= RESULT_BYTES:
            raise ValueError("page surface worker execution rejected")
        result.seek(0)
        return result.read(RESULT_BYTES + 1)


def inspect_pdf_page_surface(
    *, pdf_bytes: object, plan: PageWindowPlan,
    expected_plan_sha256: str, expected_language: str,
) -> PdfPageSurface:
    """Bind exact current PDF, plan, prior receipt and physical page proof."""
    try:
        _profile()
        if (type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b"%PDF-1.7")
                or not 0 < len(pdf_bytes) <= MAX_PDF_BYTES
                or type(plan) is not PageWindowPlan
                or not _is_digest(expected_plan_sha256)
                or type(expected_language) is not str or expected_language != LANGUAGE):
            raise ValueError("unsupported page surface request")
        plan.__post_init__()
        if (plan.plan_sha256 != expected_plan_sha256
                or plan.inspector_profile_id != TEXT_PROFILE
                or plan.page_count > MAX_DOCUMENT_PAGES
                or plan.pdf_sha256 != sha256(pdf_bytes).hexdigest()):
            raise ValueError("page surface request identity differs")
        identity = _identity_from_plan(plan)
    except Exception:
        raise PdfPageSurfaceError("pdf_page_surface_input_invalid") from None
    try:
        precursor = prior.inspect_pdf_trailer_catalog(
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
            raise ValueError("page surface prerequisite/input mutated")
        return proof
    except Exception:
        raise PdfPageSurfaceError("pdf_page_surface_execution_failed") from None
