"""Bound the existing generated-PDF validators; not an OS sandbox."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import stat
import sys

from reporting._pdf_render_worker import _arm_worker_lifetime, _write_bytes

PROFILE_ID = "generated-pdf-validation-envelope-v1"
PROTOCOL_VERSION = 1
PDF_BYTES = 8 * 1024 * 1024
MEMORY_BYTES = 256 * 1024 * 1024
CPU_SECONDS = 5
WALL_SECONDS = 10
OPEN_FILES = 128
RESULT_BYTES = 64 * 1024
OPERATIONS = frozenset({"structure", "metadata", "accessibility"})
ERRORS = {
    "structure": frozenset({"pdf_engine_invalid_output", "pdf_metadata_invalid",
                            "pdf_validator_unavailable", "pdf_validator_version_mismatch"}),
    "metadata": frozenset({"pdf_structure_invalid", "encrypted_pdf_forbidden",
                           "pdf_validator_unavailable", "pdf_metadata_budget_exceeded",
                           "pdf_xmp_invalid", "pdf_metadata_profile_mismatch",
                           "pdf_author_mismatch", "pdf_language_mismatch",
                           "pdf_metadata_sensitive"}),
    "accessibility": frozenset({"pdf_accessibility_structure_invalid",
                                "encrypted_pdf_forbidden", "pdf_not_marked",
                                "pdf_struct_tree_missing", "pdf_accessibility_language_mismatch"}),
}


def _limits() -> dict[str, int]:
    """Enforce per-process budgets before loading any PDF parser."""
    import resource

    for key, value in ((resource.RLIMIT_AS, MEMORY_BYTES),
                       (resource.RLIMIT_CPU, CPU_SECONDS),
                       (resource.RLIMIT_FSIZE, RESULT_BYTES),
                       (resource.RLIMIT_NOFILE, OPEN_FILES),
                       (resource.RLIMIT_CORE, 0)):
        resource.setrlimit(key, (value, value))
    return {"memory_bytes": resource.getrlimit(resource.RLIMIT_AS)[0],
            "cpu_seconds": resource.getrlimit(resource.RLIMIT_CPU)[0],
            "file_bytes": resource.getrlimit(resource.RLIMIT_FSIZE)[0],
            "open_files": resource.getrlimit(resource.RLIMIT_NOFILE)[0]}


def _lifetime(parent: int) -> None:
    """Reuse the reviewed Linux parent-death guard, then narrow its timer."""
    _arm_worker_lifetime(parent)
    signal.setitimer(signal.ITIMER_REAL, WALL_SECONDS)


def _read_request(fd: int) -> tuple[str, str, bytes]:
    """Read one bounded anonymous-file request and verify its actual identity."""
    size = os.fstat(fd).st_size
    if size < 70 or size > PDF_BYTES + 128:
        raise ValueError("invalid validation request size")
    with os.fdopen(os.dup(fd), "rb") as source:
        source.seek(0)
        data = source.read(PDF_BYTES + 129)
    header, sep, pdf = data.partition(b"\n")
    if len(data) != size or not sep or len(header) > 127:
        raise ValueError("invalid validation request")
    fields = header.decode("ascii").split(" ")
    if len(fields) != 3 or fields[0] != "1" or fields[1] not in OPERATIONS:
        raise ValueError("unsupported validation operation")
    operation, digest = fields[1:]
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("invalid validation digest")
    if not pdf.startswith(b"%PDF-") or len(pdf) > PDF_BYTES:
        raise ValueError("invalid validation PDF")
    if hashlib.sha256(pdf).hexdigest() != digest:
        raise ValueError("validation digest mismatch")
    return operation, digest, pdf


def _metadata(pdf: bytes, digest: str):
    """Use the unmodified controlled-metadata rules on one generated candidate."""
    from reporting.pdf_qa import (
        GENERATED_PDF_AUTHOR, GENERATED_PDF_METADATA_PROFILE, validate_pdf_candidate,
    )
    return validate_pdf_candidate(
        pdf_bytes=pdf, expected_pdf_sha256=digest,
        expected_author=GENERATED_PDF_AUTHOR, expected_language="en-US",
        metadata_profile=GENERATED_PDF_METADATA_PROFILE,
    )


def _structure(pdf: bytes, digest: str) -> dict:
    """Preserve the native adapter's existing structure and metadata decisions."""
    if not pdf.startswith(b"%PDF-1.7"):
        return {"errors": ["pdf_engine_invalid_output"]}
    try:
        from importlib.metadata import version
        from pypdf import PdfReader
    except (ImportError, OSError):
        return {"errors": ["pdf_validator_unavailable"]}
    if version("pypdf") != "6.19.0":
        return {"errors": ["pdf_validator_version_mismatch"]}
    result = _metadata(pdf, digest)
    if not result.passed:
        invalid = {"pdf_structure_invalid", "encrypted_pdf_forbidden"}
        error = "pdf_engine_invalid_output" if invalid.intersection(result.errors) else "pdf_metadata_invalid"
        return {"errors": [error]}
    try:
        from io import BytesIO
        reader = PdfReader(BytesIO(pdf), strict=True)
        if len(reader.pages) < 1:
            raise ValueError("empty PDF")
        root = reader.trailer.get("/Root")
        if root is None:
            raise ValueError("missing PDF root")
        root.get_object()
        for page in reader.pages:
            _ = page.mediabox
    except Exception:
        return {"errors": ["pdf_engine_invalid_output"]}
    return {"errors": []}


def _evaluate(operation: str, pdf: bytes, digest: str) -> dict:
    """Return only fixed error codes and necessary non-content scalar evidence."""
    if operation == "structure":
        return _structure(pdf, digest)
    if operation == "metadata":
        result = _metadata(pdf, digest)
        return {"errors": list(result.errors),
                "page_count": result.page_count if result.passed else None}
    from importlib.metadata import version
    if version("pypdf") != "6.19.0":
        raise ValueError("validator version mismatch")
    from reporting.pdf_accessibility import validate_pdf_accessibility_structure
    result = validate_pdf_accessibility_structure(pdf_bytes=pdf, expected_language="en-US")
    return {"errors": list(result.errors), "marked": result.marked,
            "struct_tree_root": result.struct_tree_root}


def main(argv: list[str] | None = None) -> int:
    """Run one declared validator with anonymous descriptors and fixed budgets."""
    argv = sys.argv if argv is None else argv
    if len(argv) != 4:
        return 64
    try:
        request_fd, result_fd, parent_pid = map(int, argv[1:])
        if min(request_fd, result_fd) < 3 or request_fd == result_fd:
            return 64
        infos = [os.fstat(fd) for fd in (request_fd, result_fd)]
        if any(not stat.S_ISREG(i.st_mode) or i.st_nlink != 0 for i in infos):
            return 64
        if (infos[0].st_dev, infos[0].st_ino) == (infos[1].st_dev, infos[1].st_ino) or infos[1].st_size:
            return 64
        limits = _limits()
        _lifetime(parent_pid)
        operation, digest, pdf = _read_request(request_fd)
        decision = _evaluate(operation, pdf, digest)
        errors = decision["errors"]
        if any(type(e) is not str or e not in ERRORS[operation] for e in errors):
            return 70
        record = {"protocol_version": PROTOCOL_VERSION, "profile_id": PROFILE_ID,
                  "operation": operation, "pdf_sha256": digest,
                  "limits": limits, "decision": decision}
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("ascii")
        if len(encoded) > RESULT_BYTES:
            return 70
        _write_bytes(result_fd, encoded)
    except Exception:
        return 70
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
