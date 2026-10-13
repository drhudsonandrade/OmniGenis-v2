"""Bound the optional raster version query without accepting PDF or command input.

The disposable launcher becomes only the pinned pdftoppm -v process. Direct-parent
registration, an independent timer and finite output limits survive admitted exec.
This is tool identity checking, not report validation. Startup before registration,
arbitrary descendants and aggregate-job resources remain outside the guarantee.
The legacy whole-file raster route is unchanged.
"""
from __future__ import annotations

import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reporting._pdf_process_sandbox import enforce_pdf_landlock, enforce_pdf_network_filter
from reporting._pdf_render_worker import _arm_worker_lifetime
from reporting._pdf_raster_executor import TOOL_PATH, _file_identity, _open_executable
from reporting._pdf_visual_worker import MEMORY_BYTES, TOOL_SHA256, TOOL_VERSION

WALL_SECONDS = 3
OUTPUT_BYTES = 4096
OPEN_FILES = 128


def _parse_parent(argv: object) -> int:
    """Require one canonical expected parent PID and forbid extra operation arguments."""
    if type(argv) is not list or len(argv) != 2 or any(type(v) is not str for v in argv):
        raise ValueError("version probe arguments")
    raw = argv[1]
    if not raw.isascii() or not raw.isdecimal() or len(raw) > 10:
        raise ValueError("version probe parent")
    value = int(raw)
    if not 2 <= value <= 2147483647 or str(value) != raw:
        raise ValueError("version probe parent")
    return value


def _arm_lifetime(parent: int) -> None:
    """Register direct-parent termination and a three-second independent kernel timer."""
    _arm_worker_lifetime(parent)
    signal.setitimer(signal.ITIMER_REAL, WALL_SECONDS)


def _limits() -> None:
    """Narrow existing raster limits for one version query and its shared output file."""
    import resource
    for key, bound in ((resource.RLIMIT_AS, MEMORY_BYTES), (resource.RLIMIT_CPU, WALL_SECONDS),
                       (resource.RLIMIT_FSIZE, OUTPUT_BYTES), (resource.RLIMIT_NOFILE, OPEN_FILES),
                       (resource.RLIMIT_CORE, 0)):
        resource.setrlimit(key, (bound, bound))


def _validate_output(stdout_fd: int = 1, stderr_fd: int = 2) -> None:
    """Require both native output streams to reference the same empty anonymous file."""
    if any(type(fd) is not int or fd < 0 for fd in (stdout_fd, stderr_fd)):
        raise ValueError("version probe descriptors")
    infos = [os.fstat(fd) for fd in (stdout_fd, stderr_fd)]
    if any(not stat.S_ISREG(i.st_mode) or i.st_nlink != 0 or i.st_uid != os.geteuid()
           or i.st_size != 0 for i in infos):
        raise ValueError("version probe output")
    if (infos[0].st_dev, infos[0].st_ino) != (infos[1].st_dev, infos[1].st_ino):
        raise ValueError("version probe output identity")


def _exec_version(fd: int) -> None:
    """Exec only the admitted descriptor with the fixed version argument and environment."""
    os.execve(fd, [TOOL_PATH, "-v"], {"PATH": os.defpath, "LANG": "C.UTF-8"})


def _start(output) -> subprocess.Popen:
    """Pass no report descriptors, shell, arbitrary executable or inherited environment."""
    return subprocess.Popen(
        [sys.executable, "-I", str(Path(__file__).resolve()), str(os.getpid())],
        cwd=Path(__file__).resolve().parents[1], env={"PATH": os.defpath, "LANG": "C.UTF-8"},
        stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
        close_fds=True, shell=False,
    )


def _wait(process: subprocess.Popen) -> int:
    """Bound the caller wait and reap only its still-owned direct child on failure."""
    try:
        return process.wait(timeout=WALL_SECONDS)
    finally:
        if process.returncode is None:
            process.kill()
            process.wait(timeout=2)


def _read_output(output) -> bytes:
    """Read only bounded anonymous output and reject observable changes during the read."""
    before = os.fstat(output.fileno())
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 0
            or before.st_uid != os.geteuid() or not 0 < before.st_size <= OUTPUT_BYTES):
        raise ValueError("version probe output size")
    output.seek(0)
    data = output.read(OUTPUT_BYTES + 1)
    after = os.fstat(output.fileno())
    if len(data) != before.st_size or _file_identity(before) != _file_identity(after):
        raise ValueError("version probe output changed")
    return data


def _run_probe() -> bytes:
    """Capture both native streams in one bounded anonymous file, never an output pipe."""
    with tempfile.TemporaryFile() as output:
        _validate_output(output.fileno(), output.fileno())
        process = _start(output)
        if _wait(process) != 0:
            raise ValueError("version probe failed")
        return _read_output(output)


def _decode_version(data: bytes) -> tuple[str, str, str]:
    """Accept only the exact activated version after a successful pinned native invocation."""
    if type(data) is not bytes or not 0 < len(data) <= OUTPUT_BYTES:
        raise ValueError("version probe response size")
    lines = data.decode("utf-8", "strict").splitlines()
    if not lines or lines[0] != "pdftoppm version " + TOOL_VERSION:
        raise ValueError("version probe response identity")
    return TOOL_VERSION, TOOL_SHA256, TOOL_PATH


def _tool_identity() -> tuple[str, str, str]:
    """Return the verified native identity or a fixed failure with no legacy fallback."""
    if sys.platform != "linux" or os.environ.get("OMNIGENIS_PDF_RASTER_WINDOWS_DISABLED") == "1":
        raise OSError("pdf_raster_version_probe_unavailable")
    try:
        return _decode_version(_run_probe())
    except Exception:
        raise OSError("pdf_raster_version_probe_failed") from None


def main(argv: list[str] | None = None) -> int:
    """Set independent guards before binary reads and exec the version-only operation."""
    if sys.platform != "linux":
        return 64
    try:
        parent = _parse_parent(sys.argv if argv is None else argv)
    except (TypeError, ValueError):
        return 64
    try:
        _arm_lifetime(parent)
        _limits()
        _validate_output()
        enforce_pdf_landlock(Path(__file__))
        enforce_pdf_network_filter()
        fd = _open_executable(TOOL_PATH)
        try:
            if os.getppid() != parent or os.getuid() != os.geteuid() or os.getgid() != os.getegid():
                raise ValueError("version probe parent or credentials changed")
            _exec_version(fd)
        finally:
            os.close(fd)
    except Exception:
        return 70
    return 70  # A successful exec never returns; setup cannot manufacture success.


if __name__ == "__main__":
    raise SystemExit(main())
