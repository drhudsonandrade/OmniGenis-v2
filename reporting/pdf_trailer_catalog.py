"""Opt-in native generated PDF trailer/catalog identity and flat page-link admission.

A narrow exact-document structural receipt, not general PDF conformance,
PDF/UA, cryptographic worker authentication or final release approval.
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
from reporting import pdf_xref_resolution as prior
from reporting.pdf_object_graph import _canonical, _start, _unique_pairs, _wait
from reporting._pdf_object_graph_worker import (
    CPU_SECONDS, IDENTITY_FIELDS, MAX_PDF_BYTES, MEMORY_BYTES, OPEN_FILES,
    PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES, _is_digest,
)
from reporting._pdf_trailer_catalog_worker import (
    LANGUAGE, MAX_DOCUMENT_PAGES, POLICY_ID, PROFILE_ID, STATUS,
    _identity, _identity_from_plan,
)

_DISABLE = "OMNIGENIS_PDF_TRAILER_CATALOG_DISABLED"
_FIXED_PARENT_PROFILE_SHA256 = "211feff2c3c875bd868206b8c5db15db386fa74ae59276c53f8b48cc9455f8e5"
_FIXED_ENVELOPE = (64, 8 * 1024 * 1024)
_LIMITS = {
    "memory_bytes": MEMORY_BYTES, "cpu_seconds": CPU_SECONDS,
    "file_bytes": RESULT_BYTES, "open_files": OPEN_FILES,
}


class PdfTrailerCatalogError(ValueError):
    """Content-free rejection of unsupported generated trailer/catalog state."""


def trailer_catalog_profile() -> dict:
    """Declare the strictly pinned generated document's native subset."""
    return {
        "schema_version": "1.0.0",
        "profile_id": PROFILE_ID,
        "policy_id": POLICY_ID,
        "parser_version": PARSER_VERSION,
        "previous_xref_resolution_profile_sha256": prior.PROFILE_SHA256,
        "language": LANGUAGE,
        "max_pages": MAX_DOCUMENT_PAGES,
        "max_pdf_bytes": MAX_PDF_BYTES,
        "trailer_keys_policy": "EXACT_ROOT_INFO_ID_SIZE",
        "catalog_reference_policy": "INDEXED_GENERATION_ZERO_ROOT_INFO_PAGES",
        "catalog_page_tree_policy": "FLAT_KIDS_MATCH_PHYSICAL_PAGE_ORDER_AND_PARENT",
        "parser_repair_policy": "NO_XREF_MAP_CHANGES_DURING_CATALOG_RESOLUTION",
        "conformance_scope": "GENERATED_PDF_1_7_XREF_TRAILER_AND_CATALOG_PARITY_ONLY",
        "xref_trailer_values_match": True,
        "flat_page_tree_consistent": True,
        "all_file_revisions_inspected": False,
        "opaque_payloads_audited": False,
        "reading_order_verified": False,
        "pdf_ua_qualified": False,
        "worker_results_authenticated": False,
        "aggregate_job_resources_qualified": False,
        "default_pipeline_activated": False,
        "release_authorized": False,
    }


PROFILE_SHA256 = sha256(_canonical(trailer_catalog_profile())).hexdigest()
_FIXED_PROFILE_SHA256 = "0bf16bc9a672b2fddfcf8ada89cd599260255b6c2252957cdc969d3135a5c49c"


def _profile() -> None:
    """Require unchanged enabled dependencies, versions, locale and finite budgets."""
    prior._profile()
    if (sys.platform != "linux" or os.environ.get(_DISABLE) == "1"
            or (MAX_DOCUMENT_PAGES, MAX_PDF_BYTES) != _FIXED_ENVELOPE
            or LANGUAGE != "en-US" or PARSER_VERSION != "6.19.0"
            or prior.PROFILE_SHA256 != _FIXED_PARENT_PROFILE_SHA256
            or PROFILE_SHA256 != _FIXED_PROFILE_SHA256
            or sha256(_canonical(trailer_catalog_profile())).hexdigest()
               != PROFILE_SHA256):
        raise ValueError("generated trailer/catalog profile disabled or changed")


@dataclass(frozen=True, slots=True, repr=False)
class PdfTrailerCatalog:
    """Immutable local checksum-bound metadata, with no worker attestation."""

    pdf_sha256: str
    ir_sha256: str
    plan_sha256: str
    page_count: int
    root_object_number: int
    info_object_number: int
    pages_root_object_number: int
    catalog_page_count: int
    indexed_page_refs: int
    xref_trailer_values_match: bool
    flat_page_tree_consistent: bool
    prior_xref_resolution_sha256: str
    _sealed_sha256: str = field(init=False, repr=False, compare=False)

    def _record(self) -> dict:
        _profile()
        _identity({key: getattr(self, key) for key in IDENTITY_FIELDS})
        ids = (self.root_object_number, self.info_object_number,
               self.pages_root_object_number)
        if (any(type(value) is not int or not 1 <= value < 20000 for value in ids)
                or len(set(ids)) != len(ids)
                or type(self.catalog_page_count) is not int
                or type(self.indexed_page_refs) is not int
                or self.catalog_page_count != self.page_count
                or self.indexed_page_refs != self.page_count
                or self.xref_trailer_values_match is not True
                or self.flat_page_tree_consistent is not True
                or not _is_digest(self.prior_xref_resolution_sha256)):
            raise ValueError("generated trailer/catalog proof or binding invalid")
        return {
            "schema_version": "1.0.0",
            "profile_id": PROFILE_ID, "policy_id": POLICY_ID,
            "status": STATUS, "parser_version": PARSER_VERSION,
            "language": LANGUAGE, "profile_sha256": PROFILE_SHA256,
            "previous_xref_resolution_profile_sha256": prior.PROFILE_SHA256,
            "pdf_sha256": self.pdf_sha256, "ir_sha256": self.ir_sha256,
            "plan_sha256": self.plan_sha256, "page_count": self.page_count,
            "root_object_number": self.root_object_number,
            "info_object_number": self.info_object_number,
            "pages_root_object_number": self.pages_root_object_number,
            "catalog_page_count": self.catalog_page_count,
            "indexed_page_refs": self.indexed_page_refs,
            "xref_trailer_values_match": self.xref_trailer_values_match,
            "flat_page_tree_consistent": self.flat_page_tree_consistent,
            "prior_xref_resolution_sha256": self.prior_xref_resolution_sha256,
            "all_file_revisions_inspected": False,
            "opaque_payloads_audited": False,
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
                raise ValueError("trailer catalog receipt exceeds wire budget")
            digest = sha256(encoded).hexdigest()
            if hasattr(self, "_sealed_sha256") and self._sealed_sha256 != digest:
                raise ValueError("trailer catalog receipt changed")
            object.__setattr__(self, "_sealed_sha256", digest)
        except Exception:
            raise PdfTrailerCatalogError("pdf_trailer_catalog_receipt_invalid") from None

    def to_bytes(self) -> bytes:
        try:
            encoded = _canonical(self._record())
            if len(encoded) > RESULT_BYTES or sha256(encoded).hexdigest() != self._sealed_sha256:
                raise ValueError("trailer catalog receipt changed")
            return encoded
        except Exception:
            raise PdfTrailerCatalogError("pdf_trailer_catalog_receipt_invalid") from None

    def to_dict(self) -> dict:
        return json.loads(self.to_bytes())

    @property
    def inspection_sha256(self) -> str:
        """Only a deterministic checksum; never a signature."""
        return sha256(self.to_bytes()).hexdigest()


def _decode(
    data: bytes, identity: dict,
    previous_receipt: prior.PdfXrefResolution,
) -> PdfTrailerCatalog:
    """Require exact child status, limits, source identity and predecessor pin."""
    try:
        _identity(identity)
        if (type(previous_receipt) is not prior.PdfXrefResolution
                or type(data) is not bytes or not 0 < len(data) <= RESULT_BYTES):
            raise ValueError("trailer catalog child or precursor type invalid")
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
            raise ValueError("trailer catalog worker protocol disagrees")
        _identity(record["identity"])
        if record["identity"] != identity:
            raise ValueError("trailer catalog identity differs")
        limits = record["limits"]
        if (type(limits) is not dict or set(limits) != set(_LIMITS)
                or any(type(value) is not int or value != _LIMITS[key]
                       for key, value in limits.items())):
            raise ValueError("trailer catalog worker limits differ")
        inspection = record["inspection"]
        keys = {
            "status", "root_object_number", "info_object_number",
            "pages_root_object_number", "catalog_page_count", "indexed_page_refs",
            "xref_trailer_values_match", "flat_page_tree_consistent",
        }
        if (type(inspection) is not dict or set(inspection) != keys
                or inspection["status"] != STATUS
                or inspection["catalog_page_count"] != identity["page_count"]
                or inspection["indexed_page_refs"] != identity["page_count"]):
            raise ValueError("trailer catalog child counts/status incompatible")
        return PdfTrailerCatalog(
            **identity,
            **{key: inspection[key] for key in keys - {"status"}},
            prior_xref_resolution_sha256=previous_digest,
        )
    except Exception:
        raise PdfTrailerCatalogError("pdf_trailer_catalog_protocol_invalid") from None


def _run_worker(pdf: bytes, identity: dict) -> bytes:
    """Use fixed confined child and two owned, private, unlinked file descriptors."""
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as result:
        fds = (source.fileno(), result.fileno())
        infos = [os.fstat(fd) for fd in fds]
        if (any(not stat.S_ISREG(v.st_mode) or v.st_nlink != 0
                or v.st_uid != os.geteuid() for v in infos)
                or (infos[0].st_dev, infos[0].st_ino)
                   == (infos[1].st_dev, infos[1].st_ino)):
            raise ValueError("trailer catalog worker descriptor invalid")
        header = " ".join([str(PROTOCOL_VERSION), *(str(identity[key])
                          for key in IDENTITY_FIELDS)])
        source.write(header.encode("ascii") + b"\n")
        source.write(pdf)
        source.flush()
        process = _start([
            sys.executable, "-I",
            str(Path(__file__).resolve().with_name("_pdf_trailer_catalog_worker.py")),
            str(fds[0]), str(fds[1]), str(os.getpid()),
        ], fds)
        if _wait(process) != 0 or not 0 < os.fstat(result.fileno()).st_size <= RESULT_BYTES:
            raise ValueError("trailer catalog worker did not complete")
        result.seek(0)
        return result.read(RESULT_BYTES + 1)


def inspect_pdf_trailer_catalog(
    *, pdf_bytes: object, plan: PageWindowPlan,
    expected_plan_sha256: str, expected_language: str,
) -> PdfTrailerCatalog:
    """Bind exact current generated bytes and prior XRef receipt to a new native proof."""
    try:
        _profile()
        if (type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b"%PDF-1.7")
                or not 0 < len(pdf_bytes) <= MAX_PDF_BYTES
                or type(plan) is not PageWindowPlan
                or not _is_digest(expected_plan_sha256)
                or type(expected_language) is not str or expected_language != LANGUAGE):
            raise ValueError("generated trailer catalog request unsupported")
        plan.__post_init__()
        if (plan.plan_sha256 != expected_plan_sha256
                or plan.inspector_profile_id != TEXT_PROFILE
                or plan.page_count > MAX_DOCUMENT_PAGES
                or plan.pdf_sha256 != sha256(pdf_bytes).hexdigest()):
            raise ValueError("trailer catalog request identity mismatched")
        identity = _identity_from_plan(plan)
    except Exception:
        raise PdfTrailerCatalogError("pdf_trailer_catalog_input_invalid") from None
    try:
        predecessor = prior.inspect_pdf_xref_resolution(
            pdf_bytes=pdf_bytes, plan=plan,
            expected_plan_sha256=expected_plan_sha256,
            expected_language=expected_language,
        )
        predecessor_digest = predecessor.inspection_sha256
        proof = _decode(_run_worker(pdf_bytes, identity), identity, predecessor)
        plan.__post_init__()
        _profile()
        if (plan.plan_sha256 != expected_plan_sha256
                or _identity_from_plan(plan) != identity
                or predecessor.inspection_sha256 != predecessor_digest):
            raise ValueError("trailer catalog prerequisite or input mutated in flight")
        return proof
    except Exception:
        raise PdfTrailerCatalogError("pdf_trailer_catalog_execution_failed") from None
