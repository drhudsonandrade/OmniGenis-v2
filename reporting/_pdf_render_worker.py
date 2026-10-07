"""Bounded subprocess worker for deterministic generated-PDF rendering."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import resource
import sys


PROTOCOL_VERSION = 1
HTML_BYTES = 64 * 1024 * 1024
PDF_BYTES = 8 * 1024 * 1024
MEMORY_BYTES = 1024 * 1024 * 1024
CPU_SECONDS = 20
OPEN_FILES = 128
RESULT_BYTES = 64 * 1024
SOURCE_DATE_EPOCH = "0"

_ALLOWED_ERRORS = frozenset(
    {
        "pdf_engine_unavailable",
        "pdf_engine_version_mismatch",
        "pdf_render_failed",
        "pdf_engine_invalid_output",
        "pdf_candidate_budget_exceeded",
        "pdf_render_protocol_invalid",
    }
)


def _apply_resource_limits() -> dict[str, int]:
    """Apply fixed worker limits before importing the rendering stack."""
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_BYTES, MEMORY_BYTES))
    resource.setrlimit(resource.RLIMIT_CPU, (CPU_SECONDS, CPU_SECONDS))
    resource.setrlimit(resource.RLIMIT_FSIZE, (PDF_BYTES, PDF_BYTES))
    resource.setrlimit(resource.RLIMIT_NOFILE, (OPEN_FILES, OPEN_FILES))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    return {
        "memory_bytes": resource.getrlimit(resource.RLIMIT_AS)[0],
        "cpu_seconds": resource.getrlimit(resource.RLIMIT_CPU)[0],
        "file_bytes": resource.getrlimit(resource.RLIMIT_FSIZE)[0],
        "open_files": resource.getrlimit(resource.RLIMIT_NOFILE)[0],
    }


def _write_result(path: Path, record: dict[str, object]) -> None:
    encoded = json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    if len(encoded) > RESULT_BYTES:
        raise ValueError("result exceeds fixed protocol budget")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(encoded)
    finally:
        os.close(descriptor)


def _failure(path: Path, error: str, limits: dict[str, int]) -> int:
    if error not in _ALLOWED_ERRORS:
        error = "pdf_render_failed"
    _write_result(
        path,
        {
            "protocol_version": PROTOCOL_VERSION,
            "status": "FAIL",
            "error": error,
            "limits": limits,
        },
    )
    return 0


def _read_request(path: Path) -> tuple[str, str]:
    size = path.stat().st_size
    if size < 67 or size > HTML_BYTES + 67:
        raise ValueError("request size outside protocol")
    data = path.read_bytes()
    header, separator, html_bytes = data.partition(b"\n")
    if not separator:
        raise ValueError("request header missing")
    fields = header.split(b" ")
    if len(fields) != 2 or fields[0] != str(PROTOCOL_VERSION).encode("ascii"):
        raise ValueError("protocol version mismatch")
    try:
        digest = fields[1].decode("ascii")
        int(digest, 16)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("invalid digest") from exc
    if len(digest) != 64 or len(html_bytes) > HTML_BYTES:
        raise ValueError("invalid request")
    try:
        html = html_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("invalid UTF-8") from exc
    if hashlib.sha256(html_bytes).hexdigest() != digest:
        raise ValueError("digest mismatch")
    return html, digest


def _render(html: str, digest: str) -> tuple[bytes | None, str | None]:
    try:
        from importlib.metadata import version

        from weasyprint import HTML
        from weasyprint.urls import URLFetcher
    except (ImportError, OSError):
        return None, "pdf_engine_unavailable"

    try:
        if version("weasyprint") != "70.0":
            return None, "pdf_engine_version_mismatch"
    except Exception:
        return None, "pdf_engine_unavailable"

    try:
        fetcher = URLFetcher(
            allowed_protocols=(),
            allow_redirects=False,
            fail_on_errors=True,
        )
        pdf = HTML(string=html, url_fetcher=fetcher).write_pdf(
            pdf_identifier=bytes.fromhex(digest),
            pdf_variant="pdf/ua-1",
            pdf_version="1.7",
        )
    except Exception:
        return None, "pdf_render_failed"

    if type(pdf) is not bytes or not pdf.startswith(b"%PDF-1.7"):
        return None, "pdf_engine_invalid_output"
    if len(pdf) > PDF_BYTES:
        return None, "pdf_candidate_budget_exceeded"
    return pdf, None


def main(argv: list[str] | None = None) -> int:
    """Run one fixed render request and emit only bounded result metadata."""
    argv = sys.argv if argv is None else argv
    if len(argv) != 4:
        return 64

    os.umask(0o077)
    request_path = Path(argv[1])
    pdf_path = Path(argv[2])
    result_path = Path(argv[3])

    try:
        limits = _apply_resource_limits()
    except Exception:
        return 70

    try:
        html, digest = _read_request(request_path)
    except Exception:
        return _failure(result_path, "pdf_render_protocol_invalid", limits)

    os.environ["SOURCE_DATE_EPOCH"] = SOURCE_DATE_EPOCH
    pdf, error = _render(html, digest)
    if error is not None:
        return _failure(result_path, error, limits)

    try:
        descriptor = os.open(
            pdf_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as output:
                output.write(pdf)
        finally:
            os.close(descriptor)
        _write_result(
            result_path,
            {
                "protocol_version": PROTOCOL_VERSION,
                "status": "PASS",
                "pdf_bytes": len(pdf),
                "pdf_sha256": hashlib.sha256(pdf).hexdigest(),
                "limits": limits,
            },
        )
    except Exception:
        try:
            if pdf_path.exists():
                pdf_path.unlink()
        except OSError:
            pass
        return _failure(result_path, "pdf_render_failed", limits)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
