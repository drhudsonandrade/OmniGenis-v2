"""Opt-in, fixed-identity bounded scratch root for isolated PDF workers.

The existing /tmp parent remains the default. The optional profile is not
resource or release qualification; only the owning systemd cgroup can prove
aggregate limits. Reject missing, foreign, unbounded or weak scratch mounts.
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
import fcntl
import os
import struct
import sys
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


_MOUNTINFO_PATH = Path("/proc/self/mountinfo")
_HELD_MOUNTINFO: tuple[int, tuple[int, ...]] | None = None


class _DescriptorStatfs(ctypes.Structure):
    """Fixed Linux x86-64 LP64 statfs layout for procfs provenance checks."""

    _fields_ = [
        ("f_type", ctypes.c_long), ("f_bsize", ctypes.c_long),
        ("f_blocks", ctypes.c_ulong), ("f_bfree", ctypes.c_ulong),
        ("f_bavail", ctypes.c_ulong), ("f_files", ctypes.c_ulong),
        ("f_ffree", ctypes.c_ulong), ("f_fsid", ctypes.c_int * 2),
        ("f_namelen", ctypes.c_long), ("f_frsize", ctypes.c_long),
        ("f_flags", ctypes.c_long), ("f_spare", ctypes.c_long * 4),
    ]


def _require_descriptor_abi() -> None:
    """Refuse unsupported layouts instead of guessing kernel structure offsets."""
    if (sys.platform != "linux" or os.uname().machine != "x86_64"
            or ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(ctypes.c_long) != 8
            or ctypes.sizeof(_DescriptorStatfs) != 120):
        raise PdfBoundedScratchError("pdf_bounded_scratch_metadata_abi")


def _metadata_identity(fd: int) -> tuple[int, ...]:
    """Require a readable regular procfs file, never caller-supplied file bytes."""
    try:
        _require_descriptor_abi()
        if type(fd) is not int or not 3 <= fd <= 2**31 - 1:
            raise ValueError("invalid metadata descriptor")
        value = os.fstat(fd)
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        if (not stat.S_ISREG(value.st_mode) or flags & os.O_PATH
                or flags & os.O_ACCMODE != os.O_RDONLY):
            raise ValueError("metadata file type or access")
        call = ctypes.CDLL(None, use_errno=True).fstatfs
        call.argtypes = [ctypes.c_int, ctypes.POINTER(_DescriptorStatfs)]
        call.restype = ctypes.c_int
        observed = _DescriptorStatfs()
        if call(fd, ctypes.byref(observed)) != 0 or observed.f_type != 0x9FA0:
            raise ValueError("metadata is not real procfs")
        return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
                value.st_gid, value.st_nlink)
    except (OSError, ValueError, TypeError, AttributeError, OverflowError,
            ctypes.ArgumentError):
        raise PdfBoundedScratchError("pdf_bounded_scratch_metadata_invalid") from None


@contextmanager
def mountinfo_scope(borrowed_fd: int | None = None):
    """Retain one real read-only mountinfo handle in a dedicated worker process.

    Capture occurs before Landlock. A descendant may borrow the explicitly
    passed handle; it does not receive authority to reopen proc paths. The
    original parser still binds path, mount ID, device, root, source and flags.
    This process-local scope is intentionally not a concurrent parent API.
    """
    global _HELD_MOUNTINFO
    if _HELD_MOUNTINFO is not None:
        raise PdfBoundedScratchError("pdf_bounded_scratch_metadata_scope_active")
    owned = borrowed_fd is None
    fd = None
    identity = None
    try:
        fd = (os.open(_MOUNTINFO_PATH, os.O_RDONLY | os.O_NOFOLLOW
                      | os.O_CLOEXEC | os.O_NONBLOCK) if owned else borrowed_fd)
        identity = _metadata_identity(fd)
        _HELD_MOUNTINFO = (fd, identity)
        yield fd
    finally:
        _HELD_MOUNTINFO = None
        if owned and fd is not None:
            # Never close a substituted descriptor belonging to another caller.
            if identity is not None and _metadata_identity(fd) != identity:
                raise PdfBoundedScratchError("pdf_bounded_scratch_metadata_changed")
            os.close(fd)


def active_mountinfo_fd() -> int:
    """Expose only the current verified handle for one explicit child launch."""
    if (_HELD_MOUNTINFO is None
            or _metadata_identity(_HELD_MOUNTINFO[0]) != _HELD_MOUNTINFO[1]):
        raise PdfBoundedScratchError("pdf_bounded_scratch_metadata_missing")
    return _HELD_MOUNTINFO[0]


def _read_retained_mountinfo(limit: int, errors: str) -> str:
    """Read current kernel metadata without consuming a shared descriptor offset."""
    fd = active_mountinfo_fd()
    if type(limit) is not int or not 0 < limit <= 262144:
        raise PdfBoundedScratchError("pdf_bounded_scratch_metadata_budget")
    data = bytearray()
    try:
        while True:
            block = os.pread(fd, min(8192, limit + 1 - len(data)), len(data))
            if not block:
                if active_mountinfo_fd() != fd:
                    raise PdfBoundedScratchError("pdf_bounded_scratch_metadata_changed")
                return data.decode("ascii", errors=errors)
            data.extend(block)
            if len(data) > limit:
                raise PdfBoundedScratchError("pdf_bounded_scratch_metadata_budget")
    except OSError:
        raise PdfBoundedScratchError("pdf_bounded_scratch_metadata_unavailable") from None


def bounded_scratch_requested() -> bool:
    """Permit only the absent legacy switch or its one exact opt-in value."""
    value = os.environ.get(_SWITCH)
    if value is None:
        return False
    if value != "1":
        raise PdfBoundedScratchError("pdf_bounded_scratch_profile_invalid")
    return True


def _read_kernel_text(path: Path, limit: int, *, errors: str = "strict") -> str:
    """Read bounded proc metadata, using the scoped handle only for mountinfo."""
    if path == _MOUNTINFO_PATH and _HELD_MOUNTINFO is not None:
        return _read_retained_mountinfo(limit, errors)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        data = bytearray()
        while True:
            block = os.read(fd, min(8192, limit + 1 - len(data)))
            if not block:
                return data.decode("ascii", errors=errors)
            data.extend(block)
            if len(data) > limit:
                raise PdfBoundedScratchError("pdf_bounded_scratch_metadata_budget")
    finally:
        os.close(fd)


def _descriptor_statx(fd: int) -> bytes:
    """Capture the fixed-width kernel response for an already validated FD number."""
    _require_descriptor_abi()
    call = ctypes.CDLL(None, use_errno=True).statx
    call.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                     ctypes.c_uint, ctypes.c_void_p]
    call.restype = ctypes.c_int
    output = (ctypes.c_uint64 * 32)()
    # AT_EMPTY_PATH; STATX_TYPE | STATX_INO | STATX_MNT_ID.
    if call(fd, b"", 0x1000, 0x1101, ctypes.byref(output)) != 0:
        raise OSError(ctypes.get_errno(), "descriptor metadata unavailable")
    return bytes(output)


def _fd_mount_id(fd: int) -> int:
    """Observe an open descriptor's mount identity without reopening proc paths."""
    try:
        _require_descriptor_abi()
        if type(fd) is not int or not 0 <= fd <= 2**31 - 1:
            raise ValueError("invalid descriptor")
        required = 0x1101
        raw = _descriptor_statx(fd)
        held = os.fstat(fd)
        if (struct.unpack_from("=I", raw, 0)[0] & required != required
                or struct.unpack_from("=Q", raw, 0x20)[0] != held.st_ino
                or os.makedev(*struct.unpack_from("=II", raw, 0x88)) != held.st_dev
                or stat.S_IFMT(struct.unpack_from("=H", raw, 0x1c)[0])
                != stat.S_IFMT(held.st_mode)):
            raise ValueError("descriptor identity mismatch")
        mount_id = struct.unpack_from("=Q", raw, 0x90)[0]
        if not 0 < mount_id <= 2**63 - 1:
            raise ValueError("invalid mount identity")
        return mount_id
    except (OSError, ValueError, TypeError, AttributeError, OverflowError,
            ctypes.ArgumentError):
        raise PdfBoundedScratchError("pdf_bounded_scratch_mount_invalid") from None


def _mount_record(
    path: Path, device: int, mount_id: int
) -> tuple[str, frozenset[str]]:
    """Bind one exact mountinfo record to an already-open directory descriptor."""
    if type(device) is not int or device < 0 or type(mount_id) is not int or mount_id <= 0:
        raise PdfBoundedScratchError("pdf_bounded_scratch_mount_invalid")
    device_id = f"{os.major(device)}:{os.minor(device)}"
    lines = _read_kernel_text(
        Path("/proc/self/mountinfo"), 262144, errors="surrogateescape"
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
        result = (fd, held, mount_id)
        fd = None
        return result
    except PdfBoundedScratchError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError, OverflowError):
        raise PdfBoundedScratchError("pdf_bounded_scratch_unavailable") from None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


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
