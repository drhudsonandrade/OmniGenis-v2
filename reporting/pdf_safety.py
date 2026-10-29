"""Exact-byte evidence for a bounded passive-report PDF object policy.

This is not malware scanning, operating-system isolation, full PDF conformance,
or authorization to publish a report. It does not modify candidate bytes.
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

from reporting._pdf_safety_worker import (
    ERRORS as WORKER_ERRORS, MAX_PAGES, MAX_PDF_BYTES, MAX_VISITS, POLICY_ID, WALL_SECONDS,
)

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_WORKER = Path(__file__).with_name("_pdf_safety_worker.py")
_MAX_RESPONSE_BYTES = 4096
_CLEANUP_SECONDS = 2
_ERRORS = WORKER_ERRORS | frozenset({
    "expected_pdf_digest_invalid", "pdf_digest_mismatch", "pdf_safety_worker_timeout",
    "pdf_safety_worker_failed", "pdf_safety_worker_invalid_response",
})


def _is_digest(value: object) -> bool:
    """Accept canonical lowercase SHA-256 only."""
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _count(value: object, maximum: int) -> bool:
    """Reject booleans and out-of-budget counts in worker or public evidence."""
    return type(value) is int and 1 <= value <= maximum


@dataclass(frozen=True, slots=True)
class PdfSafetyValidation:
    """Immutable, content-free evidence for one exact candidate and fixed policy."""

    pdf_sha256: str | None
    page_count: int | None
    object_count: int | None
    errors: tuple[str, ...]

    def __post_init__(self) -> None:
        """Prevent incomplete success claims and mutable or unrecognized error records."""
        if not isinstance(self.errors, tuple) or any(not isinstance(e, str) or e not in _ERRORS for e in self.errors):
            raise ValueError("invalid PDF safety errors")
        if self.pdf_sha256 is not None and not _is_digest(self.pdf_sha256):
            raise ValueError("invalid candidate identity")
        if not self.errors and (not _is_digest(self.pdf_sha256)
                                or not _count(self.page_count, MAX_PAGES)
                                or not _count(self.object_count, MAX_VISITS)):
            raise ValueError("incomplete PDF safety evidence")
        if self.errors and (self.page_count is not None or self.object_count is not None):
            raise ValueError("partial inspection cannot claim completed counts")

    @property
    def passed(self) -> bool:
        """Return whether the bounded object-policy inspection completed cleanly."""
        return not self.errors

    def to_dict(self) -> dict[str, object]:
        """Return detached evidence without filenames, report text or release promotion."""
        return {
            "status": "PASS" if self.passed else "BLOCKED", "policy_id": POLICY_ID,
            "conformance_scope": "REACHABLE_PDF_OBJECT_POLICY_ONLY",
            "release_authorization": "NOT_ESTABLISHED", "pdf_sha256": self.pdf_sha256,
            "page_count": self.page_count, "object_count": self.object_count,
            "errors": list(self.errors),
            "limitations": [
                "Only newly generated passive report candidates are supported, not arbitrary uploaded PDFs.",
                "All A dictionary entries are excluded, including structural attributes not used by the current report profile.",
                "Only the effective reachable object graph is inspected; orphan historical objects and opaque stream payload semantics are excluded.",
                "Process resource limits are not an operating-system sandbox or a malware-safety guarantee.",
                "Text integrity, visual QA, metadata privacy, full accessibility and FINAL authorization require separate gates.",
            ],
        }


class _SafetyWorkerResponseOverflow(ValueError):
    """Refuse output as soon as the existing response allowance is exceeded."""


def _exchange_safety_pipes(
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
                        raise OSError("safety worker input transfer stalled")
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
                            raise _SafetyWorkerResponseOverflow("worker protocol budget")
    return bytes(output)


def _wait_safety_worker(process: subprocess.Popen, deadline: float) -> int:
    """Reap only the exclusively owned child within the original work deadline."""
    while True:
        # Popen.wait() treats ECHILD as success. An unknown child cannot attest a PDF.
        pid, status = os.waitpid(process.pid, os.WNOHANG)
        if pid == process.pid:
            process.returncode = os.waitstatus_to_exitcode(status)
            return process.returncode
        if pid != 0:
            raise ChildProcessError("safety worker identity unavailable")
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
    process = subprocess.Popen(
        [sys.executable, "-I", str(_WORKER), str(os.getpid())],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        bufsize=0,
    )
    try:
        try:
            deadline = time.monotonic() + WALL_SECONDS
            output = _exchange_safety_pipes(process, pdf_bytes, deadline)
            if time.monotonic() > deadline:
                raise subprocess.TimeoutExpired(process.args, WALL_SECONDS)
            returncode = _wait_safety_worker(process, deadline)
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
    finally:
        primary_error = sys.exception()
        close_error = None
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                try:
                    stream.close()
                except (OSError, ValueError) as error:
                    close_error = close_error or error
        if close_error is not None and primary_error is None:
            raise close_error


def validate_pdf_object_safety(*, pdf_bytes: object, expected_pdf_sha256: object) -> PdfSafetyValidation:
    """Bind bytes before resource-limited inspection and validate the complete child protocol."""
    pdf_digest = None

    def fail(error: str) -> PdfSafetyValidation:
        """Return only bounded failure evidence for the current candidate."""
        return PdfSafetyValidation(pdf_digest, None, None, (error,))

    if not isinstance(pdf_bytes, bytes) or not pdf_bytes.startswith(b"%PDF-"):
        return fail("pdf_safety_structure_invalid")
    if len(pdf_bytes) > MAX_PDF_BYTES:
        return fail("pdf_safety_budget_exceeded")
    pdf_digest = hashlib.sha256(pdf_bytes).hexdigest()
    if not _is_digest(expected_pdf_sha256):
        return fail("expected_pdf_digest_invalid")
    if pdf_digest != expected_pdf_sha256:
        return fail("pdf_digest_mismatch")
    try:
        child = _run_worker(pdf_bytes)
    except subprocess.TimeoutExpired:
        return fail("pdf_safety_worker_timeout")
    except _SafetyWorkerResponseOverflow:
        return fail("pdf_safety_worker_invalid_response")
    except (OSError, AttributeError, ValueError):
        return fail("pdf_safety_worker_unavailable")
    if child.returncode != 0:
        return fail("pdf_safety_worker_failed")
    try:
        if not isinstance(child.stdout, bytes) or len(child.stdout) > _MAX_RESPONSE_BYTES:
            raise ValueError("worker protocol budget")
        record = json.loads(child.stdout)
        if not isinstance(record, dict) or set(record) != {"status", "pdf_sha256", "page_count", "object_count", "errors"}:
            raise ValueError("invalid worker fields")
        errors = record["errors"]
        if not isinstance(errors, list) or any(not isinstance(e, str) or e not in WORKER_ERRORS for e in errors):
            raise ValueError("invalid worker errors")
        if record["status"] == "BLOCKED" and errors:
            if record["pdf_sha256"] not in (None, pdf_digest) or record["page_count"] is not None or record["object_count"] is not None:
                raise ValueError("invalid blocked state")
            return PdfSafetyValidation(pdf_digest, None, None, tuple(errors))
        if record["status"] != "PASS" or errors or record["pdf_sha256"] != pdf_digest:
            raise ValueError("invalid worker state")
        if not _count(record["page_count"], MAX_PAGES) or not _count(record["object_count"], MAX_VISITS):
            raise ValueError("invalid worker counts")
        return PdfSafetyValidation(pdf_digest, record["page_count"], record["object_count"], ())
    except (ValueError, TypeError, UnicodeError):
        return fail("pdf_safety_worker_invalid_response")
