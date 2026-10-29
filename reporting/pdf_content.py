"""Bind a candidate PDF's extracted text to an exact localized Presentation IR.

This verifies text content only, not its visual appearance, scientific meaning,
accessibility semantics, privacy metadata, or authorization for final release.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time

from reporting._pdf_content_worker import (
    ERRORS as WORKER_ERRORS, MAX_PAGES, MAX_PDF_BYTES, MAX_TEXT_CHARS,
    WALL_SECONDS, normalize_stream,
)
from reporting.localization import is_supported_report_locale

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_WORKER = Path(__file__).with_name("_pdf_content_worker.py")
_MAX_RESPONSE_BYTES = 4096
_CLEANUP_SECONDS = 2


def _is_digest(value: object) -> bool:
    """Accept only canonical lowercase SHA-256 identities."""
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class PdfContentValidation:
    """Immutable content evidence with no retained input or extracted report text."""

    ir_sha256: str | None
    pdf_sha256: str | None
    expected_text_sha256: str | None
    extracted_text_sha256: str | None
    page_count: int | None
    errors: tuple[str, ...]

    def __post_init__(self) -> None:
        """Reject success-looking records with missing or contradictory evidence."""
        if not isinstance(self.errors, tuple) or any(not isinstance(e, str) or not e for e in self.errors):
            raise ValueError("invalid content errors")
        if not self.errors and (
            not all(_is_digest(v) for v in (self.ir_sha256, self.pdf_sha256,
                                           self.expected_text_sha256, self.extracted_text_sha256))
            or self.expected_text_sha256 != self.extracted_text_sha256
            or type(self.page_count) is not int or not 1 <= self.page_count <= MAX_PAGES
        ):
            raise ValueError("incomplete content verification evidence")

    @property
    def passed(self) -> bool:
        """Return whether the bounded text-content comparison passed."""
        return not self.errors

    def to_dict(self) -> dict[str, object]:
        """Return detached, content-free evidence without promoting a release."""
        return {
            "status": "PASS" if self.passed else "BLOCKED",
            "conformance_scope": "PDF_TEXT_CONTENT_ONLY",
            "release_authorization": "NOT_ESTABLISHED",
            "ir_sha256": self.ir_sha256, "pdf_sha256": self.pdf_sha256,
            "expected_text_sha256": self.expected_text_sha256,
            "extracted_text_sha256": self.extracted_text_sha256,
            "page_count": self.page_count, "errors": list(self.errors),
            "limitations": [
                "Only newly generated PDFs from the current localized semantic-section adapter are supported.",
                "CR, LF and form-feed are ignored; other whitespace, case, punctuation and values are preserved.",
                "Text extraction does not establish visible glyphs, layout, tag semantics or reading-order quality.",
                "Image-only or blank pages fail closed; no OCR is performed.",
                "Metadata privacy, full accessibility and final-release authorization require separate gates.",
            ],
        }


def _expected_content(presentation_ir: object) -> tuple[str, str]:
    """Derive the full expected stream independently of the HTML/PDF renderer."""
    if not isinstance(presentation_ir, dict):
        raise ValueError("invalid input")
    canonical = json.dumps(presentation_ir, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False).encode("utf-8")
    if len(canonical) > MAX_PDF_BYTES:
        raise ValueError("input budget exceeded")
    ir = json.loads(canonical)
    if ir != presentation_ir:
        raise ValueError("source is not lossless JSON")
    if not isinstance(ir.get("report_id"), str) or not ir["report_id"]:
        raise ValueError("invalid report identity")
    if not is_supported_report_locale(ir.get("locale_id")):
        raise ValueError("invalid locale")
    components = ir.get("components")
    if not isinstance(components, list) or not components:
        raise ValueError("invalid components")
    parts = [ir["report_id"]]
    seen = set()
    for component in components:
        if not isinstance(component, dict):
            raise ValueError("invalid component")
        identity = component.get("component_id")
        if (not isinstance(identity, str) or not identity or identity in seen
                or component.get("component_type") != "semantic-section"
                or any(not isinstance(component.get(k), str) or not component[k]
                       for k in ("title", "state"))
                or not isinstance(component.get("content"), dict)):
            raise ValueError("invalid component")
        seen.add(identity)
        parts.extend([component["title"], component["state"],
                      json.dumps(component["content"], sort_keys=True,
                                 separators=(",", ":"), ensure_ascii=False, allow_nan=False)])
    text = normalize_stream("\n".join(parts))
    if len(text) > MAX_TEXT_CHARS:
        raise ValueError("text budget exceeded")
    return hashlib.sha256(canonical).hexdigest(), hashlib.sha256(text.encode("utf-8")).hexdigest()


class _ContentWorkerResponseOverflow(ValueError):
    """Refuse output as soon as the existing response allowance is exceeded."""


def _exchange_content_pipes(
    process: subprocess.Popen, pdf_bytes: bytes, deadline: float,
) -> bytes:
    """Transfer input and collect at most the response limit plus one overflow byte."""
    output = bytearray()
    pending = memoryview(pdf_bytes)
    position = 0
    with selectors.DefaultSelector() as selector:
        for stream, event in (
            (process.stdin, selectors.EVENT_WRITE),
            (process.stdout, selectors.EVENT_READ),
        ):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, event)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(process.args, WALL_SECONDS)
            for key, _ in selector.select(remaining):
                if key.fileobj is process.stdin:
                    try:
                        written = os.write(key.fd, pending[position:position + 65536])
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        # A worker setup failure can return BLOCKED before reading input.
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    if written <= 0:
                        raise OSError("content worker input transfer stalled")
                    position += written
                    if position == len(pending):
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                else:
                    try:
                        chunk = os.read(key.fd, _MAX_RESPONSE_BYTES + 1 - len(output))
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                    else:
                        output.extend(chunk)
                        if len(output) > _MAX_RESPONSE_BYTES:
                            raise _ContentWorkerResponseOverflow("worker protocol budget")
    return bytes(output)


def _wait_content_worker(process: subprocess.Popen, deadline: float) -> int:
    """Reap only the exclusively owned child within the original work deadline."""
    while True:
        # Popen.wait() treats ECHILD as success. An unknown child cannot attest a PDF.
        pid, status = os.waitpid(process.pid, os.WNOHANG)
        if pid == process.pid:
            process.returncode = os.waitstatus_to_exitcode(status)
            return process.returncode
        if pid != 0:
            raise ChildProcessError("content worker identity unavailable")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(process.args, WALL_SECONDS)
        time.sleep(min(0.01, remaining))


def _run_worker(pdf_bytes: bytes) -> subprocess.CompletedProcess:
    """Bound pipe exchange and direct-child cleanup without changing the launch session.

    This function exclusively owns the child and its pipes. Cleanup is limited to
    that child, with a two-second reap allowance after the nonblocking signal; it
    does not claim process-group or arbitrary-descendant containment.
    """
    operation_failed = False
    process = subprocess.Popen(
        [sys.executable, "-I", str(_WORKER), str(os.getpid())],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        bufsize=0,
    )
    try:
        try:
            deadline = time.monotonic() + WALL_SECONDS
            output = _exchange_content_pipes(process, pdf_bytes, deadline)
            if time.monotonic() > deadline:
                raise subprocess.TimeoutExpired(process.args, WALL_SECONDS)
            returncode = _wait_content_worker(process, deadline)
            return subprocess.CompletedProcess(process.args, returncode, output)
        except ChildProcessError:
            # Confirmed ownership loss is terminal; never recover authority from a PID.
            raise
        except BaseException:
            # Popen.kill() checks its child state before signaling, including after reap.
            # A signal failure must not skip the independent, finite reap attempt.
            try:
                process.kill()
            except OSError:
                pass
            try:
                process.wait(timeout=_CLEANUP_SECONDS)
            except (OSError, subprocess.TimeoutExpired):
                pass
            raise
    except BaseException:
        operation_failed = True
        raise
    finally:
        close_error = None
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                try:
                    stream.close()
                except (OSError, ValueError) as error:
                    close_error = close_error or error
        if close_error is not None and not operation_failed:
            raise close_error


def validate_pdf_text_content(
    *, presentation_ir: object, expected_ir_sha256: object,
    pdf_bytes: object, expected_pdf_sha256: object,
) -> PdfContentValidation:
    """Compare independently derived report text and a bounded candidate text digest."""
    ir_digest = pdf_digest = expected_text = actual_text = None
    pages = None

    def fail(error: str) -> PdfContentValidation:
        """Retain available identities but never raw input when failing closed."""
        return PdfContentValidation(ir_digest, pdf_digest, expected_text,
                                    actual_text, pages, (error,))

    try:
        ir_digest, expected_text = _expected_content(presentation_ir)
    except (TypeError, ValueError, RecursionError, UnicodeError):
        return fail("presentation_ir_invalid")
    if not _is_digest(expected_ir_sha256):
        return fail("expected_ir_digest_invalid")
    if ir_digest != expected_ir_sha256:
        return fail("presentation_ir_digest_mismatch")
    if not isinstance(pdf_bytes, bytes) or not pdf_bytes.startswith(b"%PDF-"):
        return fail("pdf_content_structure_invalid")
    if len(pdf_bytes) > MAX_PDF_BYTES:
        return fail("pdf_content_budget_exceeded")
    pdf_digest = hashlib.sha256(pdf_bytes).hexdigest()
    if not _is_digest(expected_pdf_sha256):
        return fail("expected_pdf_digest_invalid")
    if pdf_digest != expected_pdf_sha256:
        return fail("pdf_digest_mismatch")
    try:
        process = _run_worker(pdf_bytes)
    except subprocess.TimeoutExpired:
        return fail("pdf_content_worker_timeout")
    except _ContentWorkerResponseOverflow:
        return fail("pdf_content_worker_invalid_response")
    except (OSError, AttributeError, ValueError):
        return fail("pdf_content_worker_unavailable")
    if process.returncode != 0:
        return fail("pdf_content_worker_failed")
    try:
        if not isinstance(process.stdout, bytes) or len(process.stdout) > _MAX_RESPONSE_BYTES:
            raise ValueError("worker protocol limit")
        record = json.loads(process.stdout)
        if not isinstance(record, dict) or set(record) != {"status", "pdf_sha256", "text_sha256", "page_count", "errors"}:
            raise ValueError("invalid worker fields")
        errors = record["errors"]
        if not isinstance(errors, list) or any(not isinstance(e, str) or e not in WORKER_ERRORS for e in errors):
            raise ValueError("invalid worker errors")
        if record["status"] == "BLOCKED" and errors:
            return fail(errors[0])
        if record["status"] != "PASS" or errors or record["pdf_sha256"] != pdf_digest:
            raise ValueError("invalid worker state")
        if not _is_digest(record["text_sha256"]) or type(record["page_count"]) is not int or not 1 <= record["page_count"] <= MAX_PAGES:
            raise ValueError("invalid worker evidence")
        actual_text, pages = record["text_sha256"], record["page_count"]
    except (ValueError, TypeError, UnicodeError):
        return fail("pdf_content_worker_invalid_response")
    if actual_text != expected_text:
        return fail("pdf_text_content_mismatch")
    return PdfContentValidation(ir_digest, pdf_digest, expected_text, actual_text, pages, ())
