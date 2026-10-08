"""Private, resource-limited text-digest worker for newly generated PDF candidates."""

from __future__ import annotations

import hashlib
from importlib.metadata import version
from io import BytesIO
import json
from pathlib import Path
import sys

MAX_PDF_BYTES = 8 * 1024 * 1024
MAX_PAGES = 32
MAX_DECODED_BYTES = 8 * 1024 * 1024
MAX_TEXT_CHARS = 1024 * 1024
MEMORY_BYTES = 256 * 1024 * 1024
CPU_SECONDS = 5
WALL_SECONDS = 10
EXTRACTOR_VERSION = "6.19.0"
ERRORS = frozenset({
    "encrypted_pdf_forbidden", "pdf_content_structure_invalid",
    "pdf_content_text_missing", "pdf_content_budget_exceeded",
    "pdf_content_extractor_version_mismatch", "pdf_content_extractor_unavailable",
    "pdf_content_worker_unavailable",
})


def normalize_stream(text: str) -> str:
    """Ignore physical line/page breaks only; preserve every other code point."""
    return text.replace("\r", "").replace("\n", "").replace("\f", "")


def blocked(error: str, pdf_digest: str | None = None) -> dict:
    """Return a bounded error record without parser messages or report content."""
    return {"status": "BLOCKED", "pdf_sha256": pdf_digest, "text_sha256": None,
            "page_count": None, "errors": [error]}


def extract_document(pdf: bytes) -> dict:
    """Inspect a candidate inside the limited child, retaining only a text digest."""
    if len(pdf) > MAX_PDF_BYTES:
        return blocked("pdf_content_budget_exceeded")
    pdf_digest = hashlib.sha256(pdf).hexdigest()
    if not pdf.startswith(b"%PDF-"):
        return blocked("pdf_content_structure_invalid", pdf_digest)
    try:
        if version("pypdf") != EXTRACTOR_VERSION:
            return blocked("pdf_content_extractor_version_mismatch", pdf_digest)
        from pypdf import PdfReader
    except (ImportError, OSError):
        return blocked("pdf_content_extractor_unavailable", pdf_digest)
    try:
        reader = PdfReader(BytesIO(pdf), strict=True)
        if reader.is_encrypted:
            return blocked("encrypted_pdf_forbidden", pdf_digest)
        page_count = len(reader.pages)
        if page_count < 1:
            return blocked("pdf_content_structure_invalid", pdf_digest)
        if page_count > MAX_PAGES:
            return blocked("pdf_content_budget_exceeded", pdf_digest)
        decoded_bytes = text_chars = 0
        text_hash = hashlib.sha256()
        for page in reader.pages:
            content = page.get_contents()
            if content is None:
                return blocked("pdf_content_text_missing", pdf_digest)
            decoded_bytes += len(content.get_data())
            if decoded_bytes > MAX_DECODED_BYTES:
                return blocked("pdf_content_budget_exceeded", pdf_digest)
            text = page.extract_text()
            if not isinstance(text, str) or not text.strip():
                return blocked("pdf_content_text_missing", pdf_digest)
            text_chars += len(text)
            if text_chars > MAX_TEXT_CHARS:
                return blocked("pdf_content_budget_exceeded", pdf_digest)
            text_hash.update(normalize_stream(text).encode("utf-8"))
        return {"status": "PASS", "pdf_sha256": pdf_digest,
                "text_sha256": text_hash.hexdigest(), "page_count": page_count,
                "errors": []}
    except MemoryError:
        return blocked("pdf_content_budget_exceeded", pdf_digest)
    except Exception:  # noqa: BLE001 - parser failures cannot yield content attestation
        return blocked("pdf_content_structure_invalid", pdf_digest)


def main() -> None:
    """Apply fixed resource and kernel guards before reading candidate bytes."""
    try:
        if sys.platform != "linux":
            raise OSError("unsupported platform")
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (MEMORY_BYTES, MEMORY_BYTES))
        resource.setrlimit(resource.RLIMIT_CPU, (CPU_SECONDS, CPU_SECONDS))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if __name__ == "__main__":
            # Isolated Python omits the script directory. Restore only the
            # resolved, trusted sibling directory, never CWD or PYTHONPATH.
            sys.path.insert(0, str(Path(__file__).resolve(strict=True).parent))
            from _pdf_process_sandbox import (
                enforce_pdf_landlock, enforce_pdf_network_filter,
            )
        else:
            from reporting._pdf_process_sandbox import (
                enforce_pdf_landlock, enforce_pdf_network_filter,
            )
        enforce_pdf_landlock(Path(__file__))
        enforce_pdf_network_filter()
    except (ImportError, OSError, ValueError, RuntimeError):
        response = blocked("pdf_content_worker_unavailable")
    else:
        try:
            response = extract_document(sys.stdin.buffer.read(MAX_PDF_BYTES + 1))
        except Exception:  # noqa: BLE001 - never print sensitive input or parser exceptions
            response = blocked("pdf_content_structure_invalid")
    sys.stdout.write(json.dumps(response, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
