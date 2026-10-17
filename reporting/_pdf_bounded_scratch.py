"""Opt-in, fixed-identity bounded PDF scratch root for isolated ED-04 workers.

The existing /tmp parent remains the default. The optional profile is not
resource or release qualification; only the owning systemd cgroup can prove
aggregate limits. Reject missing, foreign, unbounded or weak scratch mounts.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile

_SWITCH = "OMNIGENIS_PDF_BOUNDED_SCRATCH_V1"
_PARENT = Path("/run/omnigenis-ed04-scratch")
_LEGACY = Path("/tmp")
_MAX_BYTES = 128 * 1024 * 1024
_MAX_INODES = 4096
_REQUIRED_FLAGS = frozenset({"nosuid", "nodev", "noexec"})


class PdfBoundedScratchError(RuntimeError):
    """An unavailable optional resource boundary never triggers fallback."""


def bounded_scratch_requested() -> bool:
    """Permit only the absent legacy switch or its one exact opt-in value."""
    value = os.environ.get(_SWITCH)
    if value is None:
        return False
    if value != "1":
        raise PdfBoundedScratchError("pdf_bounded_scratch_profile_invalid")
    return True


def _mount_record(path: Path) -> tuple[str, frozenset[str]]:
    """Read a single exact mount-namespace entry for the fixed scratch path."""
    lines = Path("/proc/self/mountinfo").read_text(encoding="ascii").splitlines()
    found = []
    for line in lines:
        head, separator, tail = line.partition(" - ")
        fields = head.split()
        if separator and len(fields) > 5 and fields[4] == str(path):
            detail = tail.split()
            if not detail:
                raise PdfBoundedScratchError("pdf_bounded_scratch_mount_invalid")
            found.append((detail[0], frozenset(fields[5].split(","))))
    if len(found) != 1:
        raise PdfBoundedScratchError("pdf_bounded_scratch_mount_missing")
    return found[0]


def bounded_scratch_parent() -> Path:
    """Return a trusted fixed parent, verifying the actual private mount if opted in."""
    if not bounded_scratch_requested():
        return _LEGACY
    try:
        info = os.stat(_PARENT, follow_symlinks=False)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o1777):
            raise PdfBoundedScratchError("pdf_bounded_scratch_owner_or_mode")
        fd = os.open(_PARENT, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            held = os.fstat(fd)
            if (held.st_dev, held.st_ino, held.st_uid, held.st_mode) != (
                info.st_dev, info.st_ino, info.st_uid, info.st_mode
            ):
                raise PdfBoundedScratchError("pdf_bounded_scratch_path_changed")
        finally:
            os.close(fd)
        filesystem, flags = _mount_record(_PARENT)
        if filesystem != "tmpfs" or not _REQUIRED_FLAGS <= flags:
            raise PdfBoundedScratchError("pdf_bounded_scratch_mount_weak")
        usage = os.statvfs(_PARENT)
        if (not 0 < usage.f_blocks * usage.f_frsize <= _MAX_BYTES
                or not 0 < usage.f_files <= _MAX_INODES):
            raise PdfBoundedScratchError("pdf_bounded_scratch_unbounded")
        return _PARENT
    except PdfBoundedScratchError:
        raise
    except (OSError, UnicodeError, ValueError):
        raise PdfBoundedScratchError("pdf_bounded_scratch_unavailable") from None


def activate_bounded_process_temporaries() -> bool:
    """Bind Python's default temporary-file creation only in an opt-in child.

    This must be called inside a dedicated child before its first filesystem
    temporary allocation. Never mutate the default-process global tempdir.
    """
    if not bounded_scratch_requested():
        return False
    parent = bounded_scratch_parent()
    if os.environ.get("TMPDIR") != str(parent):
        raise PdfBoundedScratchError("pdf_bounded_scratch_tmpdir_mismatch")
    tempfile.tempdir = str(parent)
    if tempfile.gettempdir() != str(parent):
        raise PdfBoundedScratchError("pdf_bounded_scratch_tempdir_changed")
    return True


def raster_child_environment(scratch: str) -> dict[str, str]:
    """Preserve the old closed environment and forward only the fixed opt-in marker."""
    child = {"PATH": os.defpath, "LANG": "C.UTF-8", "TMPDIR": scratch}
    if bounded_scratch_requested():
        parent = bounded_scratch_parent()
        directory = Path(scratch)
        try:
            info = os.stat(directory, follow_symlinks=False)
            if (not directory.is_absolute() or directory.parent != parent
                    or not directory.name.startswith("omnigenis-pdf-visual-supervisor-")
                    or not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise PdfBoundedScratchError("pdf_bounded_scratch_child_invalid")
        except PdfBoundedScratchError:
            raise
        except (OSError, ValueError):
            raise PdfBoundedScratchError("pdf_bounded_scratch_child_missing") from None
        child[_SWITCH] = "1"
    return child
