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

_ALLOWED_ERRORS = frozenset({
    "pdf_engine_unavailable", "pdf_engine_version_mismatch",
    "pdf_render_failed", "pdf_engine_invalid_output",
    "pdf_candidate_budget_exceeded", "pdf_render_protocol_invalid",
})


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


def _apply_resource_limits() -> dict[str, int]:
    """Apply fixed limits before loading native renderer libraries."""
    import resource

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


def _failure(fd: int, error: str, limits: dict[str, int]) -> int:
    """Return an allowlisted failure without copying arbitrary exception text."""
    if error not in _ALLOWED_ERRORS:
        error = "pdf_render_failed"
    _write_result(fd, {"protocol_version": PROTOCOL_VERSION, "status": "FAIL",
                       "error": error, "limits": limits})
    return 0


def _read_request(fd: int) -> tuple[str, str]:
    """Read a bounded header and exact UTF-8 payload from an inherited file."""
    size = os.fstat(fd).st_size
    if size < 67 or size > HTML_BYTES + 67:
        raise ValueError("request size outside protocol")
    with os.fdopen(os.dup(fd), "rb") as source:
        source.seek(0)
        data = source.read(HTML_BYTES + 68)
    if len(data) != size:
        raise ValueError("request changed")
    header, separator, html_bytes = data.partition(b"\n")
    if not separator or not header.startswith(b"1 ") or len(header) != 66:
        raise ValueError("invalid request header")
    digest = header[2:].decode("ascii")
    if any(char not in "0123456789abcdef" for char in digest):
        raise ValueError("invalid digest")
    if len(html_bytes) > HTML_BYTES or hashlib.sha256(html_bytes).hexdigest() != digest:
        raise ValueError("request identity mismatch")
    return html_bytes.decode("utf-8"), digest


def _render(html: str, digest: str) -> tuple[bytes | None, str | None]:
    """Invoke only the pinned, offline renderer inside the limited worker."""
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
    if len(pdf) > PDF_BYTES:
        return None, "pdf_candidate_budget_exceeded"
    return pdf, None


def main(argv: list[str] | None = None) -> int:
    """Render one request through three anonymous descriptors and a parent PID."""
    argv = sys.argv if argv is None else argv
    if len(argv) != 5:
        return 64
    try:
        request_fd, pdf_fd, result_fd, parent_pid = map(int, argv[1:])
        fds = (request_fd, pdf_fd, result_fd)
        if len(set(fds)) != 3 or any(fd < 3 for fd in fds):
            return 64
        for fd in fds:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 0:
                return 64
        if os.fstat(pdf_fd).st_size or os.fstat(result_fd).st_size:
            return 64
        limits = _apply_resource_limits()
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
        html, digest = _read_request(request_fd)
    except Exception:
        return _failure(result_fd, "pdf_render_protocol_invalid", limits)
    os.environ["SOURCE_DATE_EPOCH"] = SOURCE_DATE_EPOCH
    pdf, error = _render(html, digest)
    if error is not None:
        return _failure(result_fd, error, limits)
    try:
        _write_bytes(pdf_fd, pdf)
        _write_result(result_fd, {
            "protocol_version": PROTOCOL_VERSION, "status": "PASS",
            "pdf_bytes": len(pdf), "pdf_sha256": hashlib.sha256(pdf).hexdigest(),
            "limits": limits,
        })
    except Exception:
        try:
            os.ftruncate(pdf_fd, 0)
        except OSError:
            pass
        return 70
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
