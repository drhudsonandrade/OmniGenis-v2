"""Linux-only bounded subprocess for deterministic generated-PDF rendering."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys

PROTOCOL_VERSION = 1
# Escaping a bounded 8 MiB IR can expand strings by up to six times.
HTML_BYTES = 64 * 1024 * 1024
PDF_BYTES = 8 * 1024 * 1024
MEMORY_BYTES = 1024 * 1024 * 1024
CPU_SECONDS = 20
WALL_SECONDS = 30
OPEN_FILES = 128
RESULT_BYTES = 64 * 1024
SOURCE_DATE_EPOCH = "0"
NATIVE_MODE = "native-source-v1"
NATIVE_PROTOCOL_VERSION = 2
NATIVE_PROFILE_ID = "generated-native-source-render-v1"
NATIVE_PDF_BYTES = 16 * 1024 * 1024
NATIVE_MAX_PAGES = 64

_ALLOWED_ERRORS = frozenset({
    "pdf_engine_unavailable", "pdf_engine_version_mismatch",
    "pdf_render_failed", "pdf_engine_invalid_output",
    "pdf_candidate_budget_exceeded", "pdf_render_protocol_invalid",
})
_NATIVE_ERRORS = _ALLOWED_ERRORS | {
    "pdf_candidate_page_budget_exceeded", "pdf_page_discovery_failed",
}


def native_render_profile() -> dict:
    """Describe one closed optional class without changing the legacy defaults."""
    return {
        "schema_version": "1.0.0", "profile_id": NATIVE_PROFILE_ID,
        "protocol_version": NATIVE_PROTOCOL_VERSION, "mode": NATIVE_MODE,
        "html_bytes": HTML_BYTES, "pdf_bytes": NATIVE_PDF_BYTES,
        "max_pages": NATIVE_MAX_PAGES, "result_bytes": RESULT_BYTES,
        "memory_bytes": MEMORY_BYTES, "cpu_seconds": CPU_SECONDS,
        "wall_seconds": WALL_SECONDS, "open_files": OPEN_FILES,
        "renderer": "weasyprint:70.0", "page_parser": "pypdf:6.19.0",
        "page_discovery": "STRICT_COMPLETE_GENERATED_BYTES_IN_RENDER_CHILD",
        "default_pipeline_activated": False, "release_authorized": False,
        "aggregate_job_resources_qualified": False,
    }


def native_render_profile_sha256() -> str:
    """Hash only the canonical fixed optional profile metadata."""
    return hashlib.sha256(json.dumps(native_render_profile(), sort_keys=True,
        separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()


def _arm_worker_lifetime(expected_parent: int) -> None:
    """Bind this worker to its Linux launching thread and an independent timer.

    SIGKILL on parent death is kernel-enforced, including during native calls.
    Recheck parent identity after prctl to cover a death during registration.
    This does not bind arbitrary forked descendants or establish an OS sandbox.
    """
    if sys.platform != "linux" or type(expected_parent) is not int or expected_parent <= 1:
        raise RuntimeError("unsupported worker lifecycle")
    if os.getppid() != expected_parent:
        raise RuntimeError("worker parent changed")
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGALRM})
    signal.setitimer(signal.ITIMER_REAL, WALL_SECONDS)
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.restype = ctypes.c_int
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                     ctypes.c_ulong, ctypes.c_ulong]
    if prctl(1, signal.SIGKILL, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG
        raise OSError(ctypes.get_errno(), "worker lifetime setup failed")
    if os.getppid() != expected_parent:
        raise RuntimeError("worker parent changed")


def _apply_resource_limits(*, max_pdf_bytes: int = PDF_BYTES) -> dict[str, int]:
    """Apply fixed limits before loading native renderer libraries."""
    import resource

    if type(max_pdf_bytes) is not int or max_pdf_bytes not in (PDF_BYTES, NATIVE_PDF_BYTES):
        raise ValueError("unsupported render file class")
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_BYTES, MEMORY_BYTES))
    resource.setrlimit(resource.RLIMIT_CPU, (CPU_SECONDS, CPU_SECONDS))
    resource.setrlimit(resource.RLIMIT_FSIZE, (max_pdf_bytes, max_pdf_bytes))
    resource.setrlimit(resource.RLIMIT_NOFILE, (OPEN_FILES, OPEN_FILES))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    return {
        "memory_bytes": resource.getrlimit(resource.RLIMIT_AS)[0],
        "cpu_seconds": resource.getrlimit(resource.RLIMIT_CPU)[0],
        "file_bytes": resource.getrlimit(resource.RLIMIT_FSIZE)[0],
        "open_files": resource.getrlimit(resource.RLIMIT_NOFILE)[0],
    }


def _write_bytes(fd: int, data: bytes) -> None:
    """Write one response into an inherited anonymous regular file."""
    os.lseek(fd, 0, os.SEEK_SET)
    os.ftruncate(fd, 0)
    remaining = memoryview(data)
    while remaining:
        written = os.write(fd, remaining)
        if written <= 0:
            raise OSError("short protocol write")
        remaining = remaining[written:]


def _write_result(fd: int, record: dict[str, object]) -> None:
    """Emit only bounded, ASCII protocol metadata."""
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
    if len(encoded) > RESULT_BYTES:
        raise ValueError("result exceeds protocol budget")
    _write_bytes(fd, encoded)


def _failure(fd: int, error: str, limits: dict[str, int], *, native_mode: bool = False) -> int:
    """Return an allowlisted failure without copying arbitrary exception text."""
    if error not in (_NATIVE_ERRORS if native_mode else _ALLOWED_ERRORS):
        error = "pdf_render_failed"
    record = {"protocol_version": PROTOCOL_VERSION, "status": "FAIL",
              "error": error, "limits": limits}
    if native_mode:
        record.update(protocol_version=NATIVE_PROTOCOL_VERSION, profile_id=NATIVE_PROFILE_ID,
                      profile_sha256=native_render_profile_sha256())
    _write_result(fd, record)
    return 0


def _read_request(fd: int, *, protocol_version: int = PROTOCOL_VERSION) -> tuple[str, str]:
    """Read a bounded header and exact UTF-8 payload from an inherited file."""
    if type(protocol_version) is not int or protocol_version not in (1, 2):
        raise ValueError("unsupported render request protocol")
    size = os.fstat(fd).st_size
    if size < 67 or size > HTML_BYTES + 67:
        raise ValueError("request size outside protocol")
    with os.fdopen(os.dup(fd), "rb") as source:
        source.seek(0)
        data = source.read(HTML_BYTES + 68)
    if len(data) != size:
        raise ValueError("request changed")
    header, separator, html_bytes = data.partition(b"\n")
    if not separator or not header.startswith(f"{protocol_version} ".encode("ascii")) or len(header) != 66:
        raise ValueError("invalid request header")
    digest = header[2:].decode("ascii")
    if any(char not in "0123456789abcdef" for char in digest):
        raise ValueError("invalid digest")
    if len(html_bytes) > HTML_BYTES or hashlib.sha256(html_bytes).hexdigest() != digest:
        raise ValueError("request identity mismatch")
    return html_bytes.decode("utf-8"), digest


def _render(html: str, digest: str, *, max_pdf_bytes: int = PDF_BYTES) -> tuple[bytes | None, str | None]:
    """Invoke only the pinned, offline renderer inside the limited worker."""
    if type(max_pdf_bytes) is not int or max_pdf_bytes not in (PDF_BYTES, NATIVE_PDF_BYTES):
        return None, "pdf_render_failed"
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
        fetcher = URLFetcher(allowed_protocols=(), allow_redirects=False,
                             fail_on_errors=True)
        pdf = HTML(string=html, url_fetcher=fetcher).write_pdf(
            pdf_identifier=bytes.fromhex(digest), pdf_variant="pdf/ua-1",
            pdf_version="1.7")
    except Exception:
        return None, "pdf_render_failed"
    if type(pdf) is not bytes or not pdf.startswith(b"%PDF-1.7"):
        return None, "pdf_engine_invalid_output"
    if len(pdf) > max_pdf_bytes:
        return None, "pdf_candidate_budget_exceeded"
    return pdf, None


def _discover_page_count(pdf: bytes) -> tuple[int | None, str | None]:
    """Inspect the complete immutable generated bytes without rewriting the PDF."""
    try:
        from importlib.metadata import version
        from io import BytesIO
        from pypdf import PdfReader

        if version("pypdf") != "6.19.0":
            return None, "pdf_page_discovery_failed"
        if type(pdf) is not bytes or not 1 <= len(pdf) <= NATIVE_PDF_BYTES:
            return None, "pdf_page_discovery_failed"
        reader = PdfReader(BytesIO(pdf), strict=True)
        if reader.is_encrypted:
            return None, "pdf_page_discovery_failed"
        page_count = len(reader.pages)
    except Exception:
        return None, "pdf_page_discovery_failed"
    if not 1 <= page_count <= NATIVE_MAX_PAGES:
        return None, "pdf_candidate_page_budget_exceeded"
    return page_count, None


def main(argv: list[str] | None = None) -> int:
    """Render one request through three anonymous descriptors and a parent PID."""
    argv = sys.argv if argv is None else argv
    native_mode = len(argv) == 6 and argv[5] == NATIVE_MODE
    if len(argv) != 5 and not native_mode:
        return 64
    try:
        request_fd, pdf_fd, result_fd, parent_pid = map(int, argv[1:5])
        fds = (request_fd, pdf_fd, result_fd)
        if len(set(fds)) != 3 or any(fd < 3 for fd in fds):
            return 64
        for fd in fds:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 0:
                return 64
        if os.fstat(pdf_fd).st_size or os.fstat(result_fd).st_size:
            return 64
        limits = (_apply_resource_limits(max_pdf_bytes=NATIVE_PDF_BYTES)
                  if native_mode else _apply_resource_limits())
        _arm_worker_lifetime(parent_pid)
        if __name__ == "__main__":
            # -I excludes the worker script directory from sys.path; restore
            # only the fixed, resolved and trusted sibling module directory.
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            from _pdf_process_sandbox import (
                enforce_pdf_landlock, enforce_pdf_network_filter,
            )
        else:
            from reporting._pdf_process_sandbox import (
                enforce_pdf_landlock, enforce_pdf_network_filter,
            )
        enforce_pdf_landlock(Path(__file__))
        enforce_pdf_network_filter()
    except Exception:
        return 70
    try:
        html, digest = (_read_request(request_fd, protocol_version=NATIVE_PROTOCOL_VERSION)
                        if native_mode else _read_request(request_fd))
    except Exception:
        return _failure(result_fd, "pdf_render_protocol_invalid", limits, native_mode=native_mode)
    os.environ["SOURCE_DATE_EPOCH"] = SOURCE_DATE_EPOCH
    pdf, error = (_render(html, digest, max_pdf_bytes=NATIVE_PDF_BYTES)
                  if native_mode else _render(html, digest))
    page_count = None
    if error is None and native_mode:
        page_count, error = _discover_page_count(pdf)
    if error is not None:
        return _failure(result_fd, error, limits, native_mode=native_mode)
    try:
        _write_bytes(pdf_fd, pdf)
        record = {
            "protocol_version": PROTOCOL_VERSION, "status": "PASS",
            "pdf_bytes": len(pdf), "pdf_sha256": hashlib.sha256(pdf).hexdigest(),
            "limits": limits,
        }
        if native_mode:
            record.update(protocol_version=NATIVE_PROTOCOL_VERSION, profile_id=NATIVE_PROFILE_ID,
                          profile_sha256=native_render_profile_sha256(), html_sha256=digest,
                          page_count=page_count)
        _write_result(result_fd, record)
    except Exception:
        try:
            os.ftruncate(pdf_fd, 0)
        except OSError:
            pass
        return 70
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
