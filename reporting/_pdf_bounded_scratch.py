"""Opt-in, fixed-identity bounded scratch root for isolated PDF workers.

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
_PARENT = Path("/run/omnigenis-pdf-bounded-scratch")
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


def _fd_mount_id(fd: int) -> int:
    """Return the one canonical Linux mount ID bound to an open descriptor."""
    if type(fd) is not int or fd < 0:
        raise PdfBoundedScratchError("pdf_bounded_scratch_mount_invalid")
    lines = Path(f"/proc/self/fdinfo/{fd}").read_text(encoding="ascii").splitlines()
    found = []
    for line in lines:
        key, separator, value = line.partition(":")
        if key == "mnt_id":
            candidate = value.strip()
            if (not separator or not candidate.isascii()
                    or not candidate.isdecimal() or len(candidate) > 20):
                raise PdfBoundedScratchError("pdf_bounded_scratch_mount_invalid")
            found.append(int(candidate))
    if len(found) != 1 or found[0] <= 0:
        raise PdfBoundedScratchError("pdf_bounded_scratch_mount_invalid")
    return found[0]


def _mount_record(
    path: Path, device: int, mount_id: int
) -> tuple[str, frozenset[str]]:
    """Bind one exact mountinfo record to an already-open directory descriptor."""
    if type(device) is not int or device < 0 or type(mount_id) is not int or mount_id <= 0:
        raise PdfBoundedScratchError("pdf_bounded_scratch_mount_invalid")
    device_id = f"{os.major(device)}:{os.minor(device)}"
    lines = Path("/proc/self/mountinfo").read_text(
        encoding="ascii", errors="surrogateescape"
    ).splitlines()
    found = []
    for line in lines:
        head, separator, tail = line.partition(" - ")
        fields = head.split()
        if len(fields) > 4 and fields[4] == str(path):
            detail = tail.split()
            if (not separator or len(fields) < 6 or len(detail) < 3
                    or fields[0] != str(mount_id) or fields[2] != device_id
                    or fields[3] != "/" or detail[1] != "tmpfs"):
                raise PdfBoundedScratchError("pdf_bounded_scratch_mount_invalid")
            found.append((detail[0], frozenset(fields[5].split(","))))
    if len(found) != 1:
        raise PdfBoundedScratchError("pdf_bounded_scratch_mount_missing")
    return found[0]


def _open_verified_bounded_parent() -> tuple[int, os.stat_result, int]:
    """Open and retain the admitted parent while all mount checks are performed."""
    fd = None
    try:
        info = os.stat(_PARENT, follow_symlinks=False)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o1777):
            raise PdfBoundedScratchError("pdf_bounded_scratch_owner_or_mode")
        fd = os.open(_PARENT, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        held = os.fstat(fd)
        identity = (held.st_dev, held.st_ino, held.st_uid, held.st_mode)
        if identity != (info.st_dev, info.st_ino, info.st_uid, info.st_mode):
            raise PdfBoundedScratchError("pdf_bounded_scratch_path_changed")
        mount_id = _fd_mount_id(fd)
        filesystem, flags = _mount_record(_PARENT, held.st_dev, mount_id)
        if filesystem != "tmpfs" or not _REQUIRED_FLAGS <= flags:
            raise PdfBoundedScratchError("pdf_bounded_scratch_mount_weak")
        usage = os.fstatvfs(fd)
        if (not 0 < usage.f_blocks * usage.f_frsize <= _MAX_BYTES
                or not 0 < usage.f_files <= _MAX_INODES):
            raise PdfBoundedScratchError("pdf_bounded_scratch_unbounded")
        current = os.stat(_PARENT, follow_symlinks=False)
        if identity != (current.st_dev, current.st_ino, current.st_uid, current.st_mode):
            raise PdfBoundedScratchError("pdf_bounded_scratch_path_changed")
        return fd, held, mount_id
    except PdfBoundedScratchError:
        if fd is not None:
            os.close(fd)
        raise
    except (OSError, UnicodeError, ValueError, TypeError, OverflowError):
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        raise PdfBoundedScratchError("pdf_bounded_scratch_unavailable") from None


def bounded_scratch_parent() -> Path:
    """Return a trusted fixed parent, verifying the actual private mount if opted in."""
    if not bounded_scratch_requested():
        return _LEGACY
    fd, _, _ = _open_verified_bounded_parent()
    os.close(fd)
    return _PARENT


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


def _open_verified_bounded_child(scratch: str) -> int:
    """Open one private child and prove that it remains on the admitted mount."""
    parent_fd, parent_info, parent_mount_id = _open_verified_bounded_parent()
    child_fd = None
    try:
        directory = Path(scratch)
        if (not directory.is_absolute() or directory.parent != _PARENT
                or not directory.name.startswith("omnigenis-pdf-visual-supervisor-")):
            raise PdfBoundedScratchError("pdf_bounded_scratch_child_invalid")
        child_fd = os.open(
            directory, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        held = os.fstat(child_fd)
        linked = os.stat(directory, follow_symlinks=False)
        identity = (held.st_dev, held.st_ino, held.st_uid, held.st_mode)
        if (not stat.S_ISDIR(held.st_mode) or held.st_uid != os.geteuid()
                or stat.S_IMODE(held.st_mode) != 0o700 or held.st_nlink < 1
                or identity != (
                    linked.st_dev, linked.st_ino, linked.st_uid, linked.st_mode
                )
                or held.st_dev != parent_info.st_dev
                or _fd_mount_id(child_fd) != parent_mount_id):
            raise PdfBoundedScratchError("pdf_bounded_scratch_child_invalid")
        current_parent = os.stat(_PARENT, follow_symlinks=False)
        if (parent_info.st_dev, parent_info.st_ino) != (
            current_parent.st_dev, current_parent.st_ino
        ):
            raise PdfBoundedScratchError("pdf_bounded_scratch_path_changed")
        result = child_fd
        child_fd = None
        return result
    except PdfBoundedScratchError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError):
        raise PdfBoundedScratchError("pdf_bounded_scratch_child_missing") from None
    finally:
        if child_fd is not None:
            os.close(child_fd)
        os.close(parent_fd)


def _require_same_bounded_mount(reference_fd: int, *fds: int) -> None:
    """Reject protocol descriptors that escaped the admitted child mount."""
    if not bounded_scratch_requested():
        return
    try:
        reference = os.fstat(reference_fd)
        mount_id = _fd_mount_id(reference_fd)
        for fd in fds:
            candidate = os.fstat(fd)
            if candidate.st_dev != reference.st_dev or _fd_mount_id(fd) != mount_id:
                raise PdfBoundedScratchError("pdf_bounded_scratch_child_invalid")
    except PdfBoundedScratchError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError):
        raise PdfBoundedScratchError("pdf_bounded_scratch_child_missing") from None


def raster_child_environment(scratch: str) -> dict[str, str]:
    """Preserve the old closed environment and forward only the fixed opt-in marker."""
    child = {"PATH": os.defpath, "LANG": "C.UTF-8", "TMPDIR": scratch}
    if bounded_scratch_requested():
        fd = _open_verified_bounded_child(scratch)
        os.close(fd)
        child[_SWITCH] = "1"
    return child
