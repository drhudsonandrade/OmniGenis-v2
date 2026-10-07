"""Bounded host adapters for the existing generated en-US PDF validators.

Only the native creation and fixed candidate-QA routes use this boundary.
Standalone low-level validators are unchanged. A process limit is not a sandbox.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
from types import MappingProxyType

from reporting._pdf_safety_worker import MAX_PAGES
from reporting._pdf_validation_worker import (
    CPU_SECONDS, ERRORS, MEMORY_BYTES, OPEN_FILES, OPERATIONS, PDF_BYTES,
    PROFILE_ID, PROTOCOL_VERSION, RESULT_BYTES, WALL_SECONDS,
)
from reporting.pdf_accessibility import PdfAccessibilityValidation
from reporting.pdf_qa import (
    GENERATED_PDF_AUTHOR, GENERATED_PDF_METADATA_PROFILE, GENERATED_PDF_PRODUCT,
    PdfCandidateValidation,
)

_LIMITS = {"memory_bytes": MEMORY_BYTES, "cpu_seconds": CPU_SECONDS,
           "file_bytes": RESULT_BYTES, "open_files": OPEN_FILES}
_METADATA = {"/Author": GENERATED_PDF_AUTHOR, "/Title": GENERATED_PDF_PRODUCT,
             "/Creator": GENERATED_PDF_PRODUCT, "/Producer": "WeasyPrint 70.0"}


def _unique_pairs(pairs: list) -> dict:
    """Reject repeated JSON object names at every nesting level."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate validation field")
        result[key] = value
    return result


def _decode(data: bytes, operation: str, digest: str) -> dict:
    """Check the entire protocol before reconstructing any success-looking result."""
    try:
        if type(data) is not bytes or not 1 <= len(data) <= RESULT_BYTES:
            raise ValueError("invalid response budget")
        record = json.loads(data.decode("ascii"), object_pairs_hook=_unique_pairs)
        if type(record) is not dict or set(record) != {
            "protocol_version", "profile_id", "operation", "pdf_sha256", "limits", "decision",
        }:
            raise ValueError("invalid response shape")
        if type(record["protocol_version"]) is not int or record["protocol_version"] != PROTOCOL_VERSION:
            raise ValueError("invalid response version")
        if (record["profile_id"] != PROFILE_ID or record["operation"] != operation
                or record["pdf_sha256"] != digest):
            raise ValueError("foreign response identity")
        limits = record["limits"]
        if (type(limits) is not dict or set(limits) != set(_LIMITS)
                or any(type(v) is not int or v != _LIMITS[k] for k, v in limits.items())):
            raise ValueError("invalid limit attestation")
        decision = record["decision"]
        fields = {"errors"}
        if operation == "metadata":
            fields.add("page_count")
        elif operation == "accessibility":
            fields.update(("marked", "struct_tree_root"))
        if type(decision) is not dict or set(decision) != fields:
            raise ValueError("invalid decision shape")
        errors = decision["errors"]
        if (type(errors) is not list or len(errors) > len(ERRORS[operation])
                or any(type(e) is not str or e not in ERRORS[operation] for e in errors)
                or len(set(errors)) != len(errors)):
            raise ValueError("invalid decision errors")
        if operation == "structure" and len(errors) > 1:
            raise ValueError("invalid structure decision")
        if operation == "metadata":
            pages = decision["page_count"]
            if errors:
                if pages is not None:
                    raise ValueError("evidence on blocked metadata")
            elif type(pages) is not int or not 1 <= pages <= MAX_PAGES:
                raise ValueError("invalid page count")
        if operation == "accessibility":
            if any(type(decision[k]) is not bool for k in ("marked", "struct_tree_root")):
                raise ValueError("invalid accessibility evidence")
            if not errors and not (decision["marked"] and decision["struct_tree_root"]):
                raise ValueError("contradictory accessibility decision")
        return decision
    except Exception:
        raise RuntimeError("pdf_validation_failed") from None


def _start(command: list[str], fds: tuple[int, int]) -> subprocess.Popen:
    """Start a worker with only the declared anonymous descriptors inherited."""
    env = os.environ.copy()
    env["PYTHONNOUSERSITE"] = "1"
    return subprocess.Popen(
        command, cwd=Path(__file__).resolve().parents[1], env=env,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True, close_fds=True, pass_fds=fds,
    )


def _wait(process: subprocess.Popen) -> int:
    """Reap the worker and terminate its inherited group on every exit path."""
    try:
        return process.wait(timeout=WALL_SECONDS)
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if process.returncode is None:
            process.wait(timeout=2)


def _run(operation: str, pdf: object, expected_digest: object) -> dict:
    """Perform identity preflight before the bounded parser process is started."""
    if os.environ.get("OMNIGENIS_PDF_VALIDATION_DISABLED") == "1":
        raise RuntimeError("pdf_validation_disabled")
    if sys.platform != "linux":
        raise RuntimeError("pdf_validation_unavailable")
    if type(operation) is not str or operation not in OPERATIONS:
        raise RuntimeError("pdf_validation_failed")
    if type(pdf) is not bytes or not pdf.startswith(b"%PDF-") or len(pdf) > PDF_BYTES:
        raise RuntimeError("pdf_validation_input_invalid")
    if (type(expected_digest) is not str or len(expected_digest) != 64
            or any(c not in "0123456789abcdef" for c in expected_digest)
            or hashlib.sha256(pdf).hexdigest() != expected_digest):
        raise RuntimeError("pdf_validation_digest_mismatch")
    try:
        with tempfile.TemporaryFile() as request, tempfile.TemporaryFile() as result:
            fds = (request.fileno(), result.fileno())
            for fd in fds:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 0:
                    raise ValueError("anonymous storage required")
            request.write(f"1 {operation} {expected_digest}\n".encode("ascii"))
            request.write(pdf)
            request.flush()
            process = _start([
                sys.executable, "-m", "reporting._pdf_validation_worker",
                str(fds[0]), str(fds[1]), str(os.getpid()),
            ], fds)
            if _wait(process) != 0 or not 1 <= os.fstat(result.fileno()).st_size <= RESULT_BYTES:
                raise ValueError("validation process failed")
            result.seek(0)
            response = result.read(RESULT_BYTES + 1)
        return _decode(response, operation, expected_digest)
    except Exception:
        raise RuntimeError("pdf_validation_failed") from None


def validate_native_structure(pdf: bytes, *, expected_language: str) -> None:
    """Preserve native structural rejection reasons with no host-side parsing."""
    if type(pdf) is not bytes or not pdf.startswith(b"%PDF-1.7"):
        raise RuntimeError("pdf_engine_invalid_output")
    if len(pdf) > PDF_BYTES:
        raise RuntimeError("pdf_validation_input_invalid")
    if type(expected_language) is not str or expected_language != "en-US":
        raise RuntimeError("pdf_validation_profile_invalid")
    decision = _run("structure", pdf, hashlib.sha256(pdf).hexdigest())
    if decision["errors"]:
        raise RuntimeError(decision["errors"][0])


def validate_generated_metadata(
    *, pdf_bytes: object, expected_pdf_sha256: object, expected_author: object,
    expected_language: object, metadata_profile: object = None,
) -> PdfCandidateValidation:
    """Return the existing result class for the fixed generated metadata profile."""
    if (type(expected_author) is not str or expected_author != GENERATED_PDF_AUTHOR
            or type(expected_language) is not str or expected_language != "en-US"
            or type(metadata_profile) is not str or metadata_profile != GENERATED_PDF_METADATA_PROFILE):
        raise RuntimeError("pdf_validation_profile_invalid")
    decision = _run("metadata", pdf_bytes, expected_pdf_sha256)
    errors = tuple(decision["errors"])
    return PdfCandidateValidation(
        expected_pdf_sha256, decision["page_count"],
        MappingProxyType({} if errors else dict(_METADATA)),
        "BLOCKED" if errors else "PASS", errors, GENERATED_PDF_METADATA_PROFILE,
    )


def validate_generated_accessibility(
    *, pdf_bytes: object, expected_language: object,
) -> PdfAccessibilityValidation:
    """Project only safe accessibility scalars from the digest-bound worker."""
    if (type(expected_language) is not str or expected_language != "en-US"
            or type(pdf_bytes) is not bytes or len(pdf_bytes) > PDF_BYTES):
        raise RuntimeError("pdf_validation_profile_invalid")
    decision = _run("accessibility", pdf_bytes, hashlib.sha256(pdf_bytes).hexdigest())
    errors = tuple(decision["errors"])
    return PdfAccessibilityValidation(
        None if errors else "en-US", decision["marked"], decision["struct_tree_root"],
        "PDF_UA_1_STRUCTURAL_PREREQUISITES_ONLY", errors,
    )
