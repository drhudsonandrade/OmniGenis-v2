"""Bounded post-render raster visual QA for newly generated PDF candidates."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile

from reporting._pdf_visual_worker import (
    ERRORS as WORKER_ERRORS,MAX_PAGES,MAX_PDF_BYTES,MAX_TOTAL_PIXELS,
    MIN_EDGE_MARGIN_PX,WALL_SECONDS,
)

_SHA256=re.compile(r"[0-9a-f]{64}\Z")
_WORKER=Path(__file__).with_name("_pdf_visual_worker.py")
_ERRORS=WORKER_ERRORS|frozenset({
    "expected_pdf_digest_invalid","pdf_digest_mismatch","pdf_visual_worker_timeout",
    "pdf_visual_worker_failed","pdf_visual_worker_invalid_response",
})


def _is_digest(value: object) -> bool:
    """Accept only canonical lowercase SHA-256 strings."""
    return isinstance(value,str) and _SHA256.fullmatch(value) is not None


@dataclass(frozen=True,slots=True)
class PdfVisualValidation:
    """Immutable content-free evidence for one bounded raster QA decision."""

    pdf_sha256: str|None
    page_count: int|None
    raster_sha256: str|None
    min_edge_margin_px: int|None
    total_pixels: int|None
    errors: tuple[str,...]

    def __post_init__(self) -> None:
        """Prevent incomplete or contradictory visual success records."""
        if not isinstance(self.errors,tuple) or any(
            not isinstance(error,str) or error not in _ERRORS for error in self.errors
        ):
            raise ValueError("invalid visual errors")
        if self.pdf_sha256 is not None and not _is_digest(self.pdf_sha256):
            raise ValueError("invalid candidate identity")
        if not self.errors and (
            not _is_digest(self.pdf_sha256)
            or type(self.page_count) is not int or not 1<=self.page_count<=MAX_PAGES
            or not _is_digest(self.raster_sha256)
            or type(self.min_edge_margin_px) is not int
            or self.min_edge_margin_px<MIN_EDGE_MARGIN_PX
            or type(self.total_pixels) is not int
            or not 1<=self.total_pixels<=MAX_TOTAL_PIXELS
        ):
            raise ValueError("incomplete visual evidence")
        if self.errors and any(
            value is not None for value in
            (self.page_count,self.raster_sha256,self.min_edge_margin_px,self.total_pixels)
        ):
            raise ValueError("partial visual inspection cannot claim completed evidence")

    @property
    def passed(self) -> bool:
        """Return whether the bounded raster geometry gate passed."""
        return not self.errors

    def to_dict(self) -> dict[str,object]:
        """Return detached evidence without pixels, paths or report text."""
        return {
            "status":"PASS" if self.passed else "BLOCKED",
            "conformance_scope":"PDF_RASTER_GEOMETRY_ONLY",
            "release_authorization":"NOT_ESTABLISHED",
            "pdf_sha256":self.pdf_sha256,
            "page_count":self.page_count,
            "raster_sha256":self.raster_sha256,
            "min_edge_margin_px":self.min_edge_margin_px,
            "total_pixels":self.total_pixels,
            "errors":list(self.errors),
            "limitations":[
                "Raster QA detects blank pages, geometry mismatch and edge-contact clipping risk only.",
                "It does not establish semantic visual equivalence, color accuracy, font correctness, accessibility completeness, or human review.",
                "Only newly generated OmniGenis report candidates are supported.",
                "FINAL release authorization requires separate downstream gates.",
            ],
        }


def _run_worker(pdf_bytes: bytes) -> subprocess.CompletedProcess:
    """Own the worker process group and temporary files through every exit."""
    with tempfile.TemporaryDirectory(prefix="omnigenis-pdf-visual-supervisor-") as scratch:
        with subprocess.Popen(
            [sys.executable,"-I",str(_WORKER)],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
            env={**os.environ,"TMPDIR":scratch},start_new_session=True,
        ) as process:
            try:
                output,_=process.communicate(input=pdf_bytes,timeout=WALL_SECONDS)
            finally:
                try:
                    os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=2)
            return subprocess.CompletedProcess(process.args,process.returncode,output)


def validate_pdf_visual_geometry(
    *,pdf_bytes: object,expected_pdf_sha256: object
) -> PdfVisualValidation:
    """Bind exact candidate bytes before invoking bounded raster geometry inspection."""
    pdf_digest=None

    def fail(error: str) -> PdfVisualValidation:
        """Return candidate-bound failure evidence without partial raster claims."""
        return PdfVisualValidation(pdf_digest,None,None,None,None,(error,))

    if not isinstance(pdf_bytes,bytes) or not pdf_bytes.startswith(b"%PDF-"):
        return fail("pdf_visual_structure_invalid")
    if len(pdf_bytes)>MAX_PDF_BYTES:
        return fail("pdf_visual_budget_exceeded")
    pdf_digest=hashlib.sha256(pdf_bytes).hexdigest()
    if not _is_digest(expected_pdf_sha256):
        return fail("expected_pdf_digest_invalid")
    if pdf_digest!=expected_pdf_sha256:
        return fail("pdf_digest_mismatch")
    if sys.platform!="linux":
        return fail("pdf_visual_worker_unavailable")
    try:
        child=_run_worker(pdf_bytes)
    except subprocess.TimeoutExpired:
        return fail("pdf_visual_worker_timeout")
    except OSError:
        return fail("pdf_visual_worker_failed")
    if child.returncode!=0:
        return fail("pdf_visual_worker_failed")
    try:
        if not isinstance(child.stdout,bytes) or len(child.stdout)>8192:
            raise ValueError("worker protocol budget")
        record=json.loads(child.stdout)
        required={
            "status","pdf_sha256","page_count","raster_sha256",
            "min_edge_margin_px","total_pixels","errors",
        }
        if not isinstance(record,dict) or set(record)!=required:
            raise ValueError("invalid worker fields")
        errors=record["errors"]
        if not isinstance(errors,list) or any(
            not isinstance(error,str) or error not in WORKER_ERRORS for error in errors
        ):
            raise ValueError("invalid worker errors")
        if record["status"]=="BLOCKED" and errors:
            if record["pdf_sha256"] not in (None,pdf_digest) or any(
                record[key] is not None for key in (
                    "page_count","raster_sha256","min_edge_margin_px","total_pixels"
                )
            ):
                raise ValueError("invalid blocked state")
            return PdfVisualValidation(pdf_digest,None,None,None,None,tuple(errors))
        if record["status"]!="PASS" or errors or record["pdf_sha256"]!=pdf_digest:
            raise ValueError("invalid worker state")
        page_count=record["page_count"]
        raster_sha256=record["raster_sha256"]
        margin=record["min_edge_margin_px"]
        pixels=record["total_pixels"]
        if (
            type(page_count) is not int or not 1<=page_count<=MAX_PAGES
            or not _is_digest(raster_sha256)
            or type(margin) is not int or margin<MIN_EDGE_MARGIN_PX
            or type(pixels) is not int or not 1<=pixels<=MAX_TOTAL_PIXELS
        ):
            raise ValueError("invalid worker evidence")
        return PdfVisualValidation(
            pdf_digest,page_count,raster_sha256,margin,pixels,()
        )
    except (ValueError,TypeError,UnicodeError):
        return fail("pdf_visual_worker_invalid_response")
