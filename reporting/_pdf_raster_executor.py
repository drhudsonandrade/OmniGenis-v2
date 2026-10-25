"""Execute only the pinned raster binary with direct-parent and elapsed-time guards.

This disposable launcher becomes the native process without changing PID. Its
parent-death registration and interval timer survive the admitted non-set-ID,
capability-free exec. Startup before registration, arbitrary descendants, scratch
cleanup after supervisor death and aggregate reporting resources remain outside
this narrow guarantee. No host settings or default PDF route are changed.
"""
from __future__ import annotations

from contextlib import nullcontext
import errno
import hashlib
import os
from pathlib import Path
import signal
import stat
import sys

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reporting import _pdf_bounded_scratch as mount_metadata
from reporting._pdf_process_sandbox import enforce_pdf_landlock, enforce_pdf_network_filter
from reporting._pdf_render_worker import _arm_worker_lifetime
from reporting._pdf_text_window_worker import MAX_DOCUMENT_PAGES
from reporting._pdf_visual_worker import (
    CPU_SECONDS, DPI, MEMORY_BYTES, PAGE_WALL_SECONDS, TOOL_SHA256, _open_trusted_scratch,
)

TOOL_PATH = "/usr/bin/pdftoppm"
MAX_EXECUTABLE_BYTES = 1024 * 1024
FILE_BYTES = 64 * 1024 * 1024
OPEN_FILES = 128


def _parse(argv: object) -> tuple[int, str, Path, Path, int]:
    """Accept one fixed command and canonical parent/page integers with absolute paths."""
    if type(argv) is not list or len(argv) != 6 or any(type(v) is not str for v in argv):
        raise ValueError("raster executor arguments")
    _, parent, tool, source, prefix, page = argv
    values = []
    for raw, lower, upper in ((parent, 2, 2147483647), (page, 1, MAX_DOCUMENT_PAGES)):
        if not raw.isascii() or not raw.isdecimal() or len(raw) > 10:
            raise ValueError("raster executor integer")
        value = int(raw)
        if str(value) != raw or not lower <= value <= upper:
            raise ValueError("raster executor integer")
        values.append(value)
    if tool != TOOL_PATH:
        raise ValueError("raster executor identity")
    for raw in (source, prefix):
        if not raw or len(raw) > 4096 or "\x00" in raw or not Path(raw).is_absolute() or ".." in Path(raw).parts:
            raise ValueError("raster executor path")
    return values[0], tool, Path(source), Path(prefix), values[1]


def _arm_lifetime(parent: int) -> None:
    """Register direct-parent SIGKILL and a fixed kernel timer before executable reads."""
    _arm_worker_lifetime(parent)
    signal.setitimer(signal.ITIMER_REAL, PAGE_WALL_SECONDS)


def _limits() -> None:
    """Reapply the existing raster process limits without expanding inherited hard limits."""
    import resource
    for key, bound in ((resource.RLIMIT_AS, MEMORY_BYTES), (resource.RLIMIT_CPU, CPU_SECONDS),
                       (resource.RLIMIT_FSIZE, FILE_BYTES), (resource.RLIMIT_NOFILE, OPEN_FILES),
                       (resource.RLIMIT_CORE, 0)):
        resource.setrlimit(key, (bound, bound))


def _bind_scratch(source: Path, prefix: Path, page: int) -> tuple[Path, int]:
    """Bind only the current private raster directory and fixed per-page filenames."""
    scratch, fd = _open_trusted_scratch()
    try:
        directory = source.parent
        if (source.name != "candidate.pdf" or prefix != directory / f"page-{page}"
                or directory.parent != scratch or not directory.name.startswith("raster-window-")):
            raise ValueError("raster executor scratch paths")
        info = os.stat(directory, follow_symlinks=False)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError("raster executor scratch directory")
        return scratch, fd
    except BaseException:
        os.close(fd)
        raise


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    """Retain observable executable identity and privilege metadata without access time."""
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _open_executable(tool: str) -> int:
    """Hash a bounded, capability-free system binary and return that exact owned descriptor."""
    if tool != TOOL_PATH or os.execve not in os.supports_fd:
        raise ValueError("raster descriptor execution unavailable")
    fd = os.open(tool, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink < 1
                or not before.st_mode & stat.S_IXUSR or before.st_mode & 0o6022
                or not 0 < before.st_size <= MAX_EXECUTABLE_BYTES):
            raise ValueError("raster executable metadata")
        try:
            os.getxattr(fd, "security.capability")
        except OSError as exc:
            if exc.errno != errno.ENODATA:
                raise
        else:
            raise ValueError("raster executable capabilities")
        digest = hashlib.sha256()
        size = 0
        while True:
            block = os.read(fd, min(65536, MAX_EXECUTABLE_BYTES + 1 - size))
            if not block:
                break
            size += len(block)
            if size > MAX_EXECUTABLE_BYTES:
                raise ValueError("raster executable budget")
            digest.update(block)
        after = os.fstat(fd)
        linked = os.stat(tool, follow_symlinks=False)
        if (size != before.st_size or digest.hexdigest() != TOOL_SHA256
                or _file_identity(before) != _file_identity(after)
                or _file_identity(after) != _file_identity(linked)):
            raise ValueError("raster executable changed")
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd)
        raise


def main(argv: list[str] | None = None) -> int:
    """Replace this guarded process with the fixed native rasterizer or fail silently."""
    if sys.platform != "linux":
        return 64
    metadata_fd = None
    try:
        args = sys.argv if argv is None else argv
        if mount_metadata.bounded_scratch_requested():
            if (type(args) is not list or len(args) != 7
                    or type(args[-1]) is not str or not args[-1].isascii()
                    or not args[-1].isdecimal() or len(args[-1]) > 10):
                raise ValueError("raster metadata argument")
            metadata_fd = int(args[-1])
            if not 3 <= metadata_fd <= 2**31 - 1 or str(metadata_fd) != args[-1]:
                raise ValueError("raster metadata descriptor")
            args = args[:-1]
        parent, tool, source, prefix, page = _parse(args)
    except (TypeError, ValueError, mount_metadata.PdfBoundedScratchError):
        return 64
    try:
        _arm_lifetime(parent)
        _limits()
        metadata = (mount_metadata.mountinfo_scope(metadata_fd)
                    if metadata_fd is not None else nullcontext())
        with metadata:
            scratch, scratch_fd = _bind_scratch(source, prefix, page)
            try:
                enforce_pdf_landlock(Path(__file__), writable_scratch_fd=scratch_fd)
                enforce_pdf_network_filter()
            finally:
                os.close(scratch_fd)
        if metadata_fd is not None:
            os.close(metadata_fd)
            metadata_fd = None
        executable_fd = _open_executable(tool)
        try:
            if os.getppid() != parent or os.getuid() != os.geteuid() or os.getgid() != os.getegid():
                raise ValueError("raster executor parent or credentials changed")
            os.execve(executable_fd,
                [tool, "-f", str(page), "-l", str(page), "-singlefile", "-r", str(DPI),
                 "-png", str(source), str(prefix)],
                {"PATH": os.defpath, "LANG": "C.UTF-8", "TMPDIR": str(scratch)})
        finally:
            os.close(executable_fd)
    except Exception:
        return 70
    finally:
        if metadata_fd is not None:
            try:
                os.close(metadata_fd)
            except OSError:
                return 70
    return 70  # A successful exec never returns; no fallback or synthetic success.


if __name__ == "__main__":
    raise SystemExit(main())
