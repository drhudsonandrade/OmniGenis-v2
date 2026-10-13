"""Bounded text extraction for one planned interval of a generated PDF.

Only the declared interval is inspected. The strict parser may read whole-file
structures to resolve pages; this is not a whole-document safety, accessibility,
semantic-equivalence or release decision. The process-local guards and finite
budgets do not establish aggregate resource closure for an entire multi-window job.
"""
from __future__ import annotations

import hashlib
from importlib.metadata import version
from io import BytesIO
import json
import os
from pathlib import Path
import signal
import stat
import sys

if __name__ == "__main__":
    # Isolated startup trusts only the resolved deployment source, not caller paths.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reporting._pdf_process_sandbox import enforce_pdf_landlock, enforce_pdf_network_filter
from reporting._pdf_render_worker import _arm_worker_lifetime, _write_bytes

PROFILE_ID = "generated-pdf-text-window-v1"
PROTOCOL_VERSION = 1
EXTRACTOR_VERSION = "6.19.0"
MAX_PDF_BYTES = 8 * 1024 * 1024
MAX_DOCUMENT_PAGES = 512
MAX_WINDOW_PAGES = 16
MAX_DECODED_BYTES = 8 * 1024 * 1024
MAX_TEXT_BYTES = 1024 * 1024
MEMORY_BYTES = 256 * 1024 * 1024
CPU_SECONDS = 5
WALL_SECONDS = 10
OPEN_FILES = 128
RESULT_BYTES = 4096
HEADER_BYTES = 512
IDENTITY_FIELDS = ("pdf_sha256", "ir_sha256", "plan_sha256", "page_count",
                   "window_index", "first_page", "last_page")


def _is_digest(value: object) -> bool:
    """Require the exact lowercase SHA-256 representation without coercion."""
    return (type(value) is str and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _validate_identity(identity: object) -> None:
    """Check the finite closed interval identity independently of parser input."""
    if type(identity) is not dict or set(identity) != set(IDENTITY_FIELDS):
        raise ValueError("window identity shape")
    if any(not _is_digest(identity[k]) for k in IDENTITY_FIELDS[:3]):
        raise ValueError("window identity digest")
    for key in IDENTITY_FIELDS[3:]:
        value = identity[key]
        lower = 0 if key == "window_index" else 1
        upper = MAX_DOCUMENT_PAGES - 1 if key == "window_index" else MAX_DOCUMENT_PAGES
        if type(value) is not int or not lower <= value <= upper:
            raise ValueError("window identity count")
    if not (identity["first_page"] <= identity["last_page"] <= identity["page_count"]
            and identity["last_page"] - identity["first_page"] + 1 <= MAX_WINDOW_PAGES):
        raise ValueError("window identity range")


def _limits() -> dict[str, int]:
    """Enforce fixed process limits before parser loading or candidate inspection."""
    import resource
    pairs = ((resource.RLIMIT_AS, MEMORY_BYTES), (resource.RLIMIT_CPU, CPU_SECONDS),
             (resource.RLIMIT_FSIZE, RESULT_BYTES), (resource.RLIMIT_NOFILE, OPEN_FILES),
             (resource.RLIMIT_CORE, 0))
    for key, limit in pairs:
        resource.setrlimit(key, (limit, limit))
    return {"memory_bytes": resource.getrlimit(resource.RLIMIT_AS)[0],
            "cpu_seconds": resource.getrlimit(resource.RLIMIT_CPU)[0],
            "file_bytes": resource.getrlimit(resource.RLIMIT_FSIZE)[0],
            "open_files": resource.getrlimit(resource.RLIMIT_NOFILE)[0]}


def _lifetime(parent: int) -> None:
    """Bind to the launching parent and arm the existing independent kernel timer."""
    _arm_worker_lifetime(parent)
    signal.setitimer(signal.ITIMER_REAL, WALL_SECONDS)


def _read_request(fd: int) -> tuple[dict, bytes]:
    """Read a finite anonymous request and bind its exact header and PDF bytes."""
    before = os.fstat(fd)
    if not 0 < before.st_size <= MAX_PDF_BYTES + HEADER_BYTES:
        raise ValueError("window request budget")
    with os.fdopen(os.dup(fd), "rb") as source:
        source.seek(0)
        header = source.readline(HEADER_BYTES + 1)
        pdf = source.read(MAX_PDF_BYTES + 1)
    after = os.fstat(fd)
    attributes = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, key) != getattr(after, key) for key in attributes):
        raise ValueError("window request changed")
    if (not header.endswith(b"\n") or len(header) > HEADER_BYTES
            or len(header) + len(pdf) != before.st_size
            or not pdf.startswith(b"%PDF-1.7") or len(pdf) > MAX_PDF_BYTES):
        raise ValueError("window request shape")
    fields = header[:-1].decode("ascii").split(" ")
    if len(fields) != 8 or fields[0] != str(PROTOCOL_VERSION):
        raise ValueError("window protocol version")
    identity = dict(zip(IDENTITY_FIELDS, fields[1:], strict=True))
    for key in IDENTITY_FIELDS[3:]:
        raw = identity[key]
        if not raw.isascii() or not raw.isdecimal() or len(raw) > 3:
            raise ValueError("window request integer")
        identity[key] = int(raw)
        if str(identity[key]) != raw:
            raise ValueError("window request noncanonical integer")
    _validate_identity(identity)
    if hashlib.sha256(pdf).hexdigest() != identity["pdf_sha256"]:
        raise ValueError("window PDF digest mismatch")
    return identity, pdf


def _extract(pdf: bytes, identity: dict) -> dict:
    """Extract every selected page and retain only ordered text/count digests."""
    _validate_identity(identity)
    if version("pypdf") != EXTRACTOR_VERSION:
        raise ValueError("window parser version")
    from pypdf import PdfReader
    reader = PdfReader(BytesIO(pdf), strict=True)
    if reader.is_encrypted or len(reader.pages) != identity["page_count"]:
        raise ValueError("window physical document mismatch")
    decoded_bytes = text_bytes = text_chars = inspected_pages = 0
    aggregate = hashlib.sha256()
    for number in range(identity["first_page"], identity["last_page"] + 1):
        page = reader.pages[number - 1]
        content = page.get_contents()
        if content is None:
            raise ValueError("window selected text missing")
        decoded_bytes += len(content.get_data())
        if decoded_bytes > MAX_DECODED_BYTES:
            raise ValueError("window decoded content budget")
        text = page.extract_text()
        if type(text) is not str or not text.strip():
            raise ValueError("window selected text empty")
        if len(text) > MAX_TEXT_BYTES - text_chars:
            raise ValueError("window character budget")
        encoded = text.encode("utf-8", "strict")
        text_chars += len(text)
        text_bytes += len(encoded)
        if text_bytes > MAX_TEXT_BYTES:
            raise ValueError("window UTF-8 budget")
        aggregate.update(f"{number}:{len(encoded)}:".encode("ascii"))
        aggregate.update(encoded)
        inspected_pages += 1
    return {"status": "WINDOW_TEXT_INSPECTED", "text_sha256": aggregate.hexdigest(),
            "inspected_pages": inspected_pages, "decoded_bytes": decoded_bytes,
            "text_bytes": text_bytes, "text_chars": text_chars}


def main(argv: list[str] | None = None) -> int:
    """Run one guarded finite request; any failure leaves no success-looking reply."""
    argv = sys.argv if argv is None else argv
    if sys.platform != "linux" or len(argv) != 4:
        return 64
    try:
        request_fd, result_fd, parent = map(int, argv[1:])
        if min(request_fd, result_fd) < 3 or request_fd == result_fd:
            return 64
        infos = [os.fstat(fd) for fd in (request_fd, result_fd)]
        if any(not stat.S_ISREG(i.st_mode) or i.st_nlink != 0 or i.st_uid != os.geteuid()
               for i in infos):
            return 64
        if (infos[0].st_dev, infos[0].st_ino) == (infos[1].st_dev, infos[1].st_ino) or infos[1].st_size:
            return 64
        limits = _limits()
        _lifetime(parent)
        enforce_pdf_landlock(Path(__file__))
        enforce_pdf_network_filter()
        identity, pdf = _read_request(request_fd)
        inspection = _extract(pdf, identity)
        response = {"protocol_version": PROTOCOL_VERSION, "profile_id": PROFILE_ID,
                    "identity": identity, "limits": limits, "inspection": inspection}
        encoded = json.dumps(response, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("ascii")
        if not 0 < len(encoded) <= RESULT_BYTES:
            return 70
        _write_bytes(result_fd, encoded)
    except Exception:  # Parser and OS messages never enter the result or public logs.
        return 70
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
