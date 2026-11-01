"""Optional guarded MCID-to-ParentTree linkage, with no PDF/UA or release claim.

An exact final PDF, immutable plan and worker profile are required. Unsigned
receipts do not certify visible-content coverage, semantic tags, reading order,
source equivalence, aggregate resources or an authenticated execution identity.
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

from reporting._pdf_document_byte_budget import require_pdf_document_budget
from reporting._pdf_mcid_coverage_worker import (
    CPU_SECONDS, IDENTITY_FIELDS, LANGUAGE, MAX_DECODED_BYTES,
    MAX_DOCUMENT_PAGES, MAX_PDF_BYTES, MAX_VISITS,
    MEMORY_BYTES, OPEN_FILES, PARSER_VERSION, POLICY_ID, PROFILE_ID,
    PROTOCOL_VERSION, RESULT_BYTES, STATUS, _validate_identity,
)
from reporting._pdf_object_graph_worker import _is_digest
from reporting.page_windows import PageWindowPlan
from reporting.pdf_object_graph import _canonical, _start, _unique_pairs, _wait

_LIMITS={"memory_bytes":MEMORY_BYTES,"cpu_seconds":CPU_SECONDS,
         "file_bytes":RESULT_BYTES,"open_files":OPEN_FILES}


class PdfMcidCoverageError(ValueError):
    """Unqualified or failed inspection; errors never contain PDF content."""


@dataclass(frozen=True,slots=True,repr=False)
class PdfMcidCoverageInspection:
    """Unsigned exact-document count receipt for a supported marked-content profile."""

    pdf_sha256:str
    ir_sha256:str
    plan_sha256:str
    page_count:int
    matched_mcids:int
    decoded_bytes:int
    inspected_pages:int

    def _identity(self):
        return {name:getattr(self,name) for name in IDENTITY_FIELDS}

    def __post_init__(self):
        try:
            _validate_identity(self._identity())
            if (type(self.matched_mcids) is not int
                    or type(self.decoded_bytes) is not int
                    or type(self.inspected_pages) is not int
                    or not self.page_count<=self.matched_mcids<=MAX_VISITS
                    or not 0<self.decoded_bytes<=MAX_DECODED_BYTES
                    or self.inspected_pages!=self.page_count):
                raise ValueError("invalid matched MCID receipt count")
        except Exception:
            raise PdfMcidCoverageError("pdf_mcid_coverage_receipt_invalid") from None

    def to_dict(self):
        """Emit only bounded structural observations with explicit nonclaims."""
        self.__post_init__()
        return {"schema_version":"1.0.0","profile_id":PROFILE_ID,
                "policy_id":POLICY_ID,"status":STATUS,**self._identity(),
                "parser_version":PARSER_VERSION,"language":LANGUAGE,
                "matched_mcids":self.matched_mcids,
                "inspected_pages":self.inspected_pages,
                "decoded_bytes":self.decoded_bytes,
                "inspection_scope":"PARSED_PAGE_MCID_PARENTTREE_REFERENCE_LINKAGE_ONLY",
                "prior_page_parenttree_gate_applied":True,
                "all_streams_or_revisions_inspected":False,
                "whole_visual_content_covered":False,
                "full_struct_tree_verified":False,
                "reading_order_verified":False,
                "semantic_tags_qualified":False,
                "pdf_ua_qualified":False,
                "text_equivalence_verified":False,
                "aggregate_job_resources_qualified":False,
                "worker_results_authenticated":False,
                "release_authorized":False,
                "release_authorization":"NOT_ESTABLISHED"}

    @property
    def inspection_sha256(self):
        return hashlib.sha256(_canonical(self.to_dict())).hexdigest()


def _decode(data:bytes, expected:dict) -> PdfMcidCoverageInspection:
    """Reject malformed, duplicate, ambiguous or foreign worker protocol fields."""
    try:
        if type(data) is not bytes or not 0<len(data)<=RESULT_BYTES:
            raise ValueError("MCID protocol bounds")
        _validate_identity(expected)
        packet=json.loads(data.decode("ascii"),object_pairs_hook=_unique_pairs)
        if (type(packet) is not dict or set(packet)!={
                "protocol_version","profile_id","policy_id","parser_version",
                "identity","limits","inspection"}):
            raise ValueError("MCID protocol shape")
        if (type(packet["protocol_version"]) is not int
                or packet["protocol_version"]!=PROTOCOL_VERSION
                or packet["profile_id"]!=PROFILE_ID
                or packet["policy_id"]!=POLICY_ID
                or packet["parser_version"]!=PARSER_VERSION):
            raise ValueError("MCID worker pin mismatch")
        _validate_identity(packet["identity"])
        if packet["identity"]!=expected:
            raise ValueError("MCID worker identity mismatch")
        limits=packet["limits"]
        if (type(limits) is not dict or set(limits)!=set(_LIMITS)
                or any(type(v) is not int or v!=_LIMITS[name]
                       for name,v in limits.items())):
            raise ValueError("MCID worker limits mismatch")
        found=packet["inspection"]
        if (type(found) is not dict or set(found)!={
                "status","matched_mcids","decoded_bytes","inspected_pages"}
                or found["status"]!=STATUS):
            raise ValueError("MCID result shape")
        return PdfMcidCoverageInspection(**expected,
            matched_mcids=found["matched_mcids"],
            decoded_bytes=found["decoded_bytes"],
            inspected_pages=found["inspected_pages"])
    except Exception:
        raise PdfMcidCoverageError("pdf_mcid_coverage_protocol_invalid") from None


def _run_worker(pdf:bytes,identity:dict) -> bytes:
    """Pass only distinct anonymous owned protocol files to a confined native worker."""
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as result:
        fds=(source.fileno(),result.fileno())
        infos=[os.fstat(fd) for fd in fds]
        if any(not stat.S_ISREG(v.st_mode) or v.st_nlink!=0
               or v.st_uid!=os.geteuid() for v in infos):
            raise ValueError("MCID worker requires anonymous owned regular files")
        if (infos[0].st_dev,infos[0].st_ino)==(infos[1].st_dev,infos[1].st_ino):
            raise ValueError("MCID worker requires distinct descriptors")
        header=" ".join([str(PROTOCOL_VERSION),*(str(identity[k]) for k in IDENTITY_FIELDS)])
        source.write(header.encode("ascii")+b"\n")
        source.write(pdf)
        source.flush()
        process=_start([sys.executable,"-I",
                        str(Path(__file__).resolve().with_name("_pdf_mcid_coverage_worker.py")),
                        str(fds[0]),str(fds[1]),str(os.getpid())],fds)
        if _wait(process)!=0 or not 0<os.fstat(result.fileno()).st_size<=RESULT_BYTES:
            raise ValueError("MCID worker failed")
        result.seek(0)
        return result.read(RESULT_BYTES+1)


def inspect_pdf_mcid_coverage(
    *,pdf_bytes:object,plan:PageWindowPlan,
    expected_plan_sha256:str,expected_language:str,
) -> PdfMcidCoverageInspection:
    """Inspect only a strict supported generated-PDF MCID mapping; never release."""
    if (sys.platform!="linux" or
            os.environ.get("OMNIGENIS_PDF_MCID_COVERAGE_DISABLED")=="1"):
        raise PdfMcidCoverageError("pdf_mcid_coverage_execution_unavailable")
    if (type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b"%PDF-1.7")
            or len(pdf_bytes)>MAX_PDF_BYTES):
        raise PdfMcidCoverageError("pdf_mcid_coverage_input_invalid")
    if type(expected_language) is not str or expected_language!=LANGUAGE:
        raise PdfMcidCoverageError("pdf_mcid_coverage_language_unavailable")
    try:
        if type(plan) is not PageWindowPlan or not _is_digest(expected_plan_sha256):
            raise ValueError("MCID plan type or digest")
        plan.__post_init__()
        require_pdf_document_budget(len(pdf_bytes), plan.page_count)
        if (plan.plan_sha256!=expected_plan_sha256
                or plan.page_count>MAX_DOCUMENT_PAGES
                or plan.pdf_sha256!=hashlib.sha256(pdf_bytes).hexdigest()):
            raise ValueError("MCID exact plan identity")
        identity={"pdf_sha256":plan.pdf_sha256,
                  "ir_sha256":plan.ir_sha256,
                  "plan_sha256":plan.plan_sha256,
                  "page_count":plan.page_count}
        _validate_identity(identity)
    except Exception:
        raise PdfMcidCoverageError("pdf_mcid_coverage_plan_invalid") from None
    try:
        inspected=_decode(_run_worker(pdf_bytes,identity),identity)
        plan.__post_init__()
        if plan.plan_sha256!=expected_plan_sha256:
            raise ValueError("MCID plan mutated after execution")
        return inspected
    except Exception:
        raise PdfMcidCoverageError("pdf_mcid_coverage_execution_failed") from None
