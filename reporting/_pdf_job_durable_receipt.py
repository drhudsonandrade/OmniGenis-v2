"""Optional private local outcome receipt; not a product execution adapter.

A receipt is a single-use, owner-bound local record. It is not a claim that
external cgroup enforcement, observer continuity or artifact release passed.
Never infer a successful job from terminal output or an absent receipt.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
from secrets import token_hex

SCHEMA = "pdf-job-durable-receipt/v1"


def _open_private_directory(directory: Path) -> int:
    """Walk absolute path components with dirfds; never follow ancestor links.

    Root-owned sticky ancestors (such as /tmp) are permitted, but every other
    ancestor must be owned by root or the caller and not group/world writable.
    The final directory is separately checked for exact owner-only mode.
    """
    if not directory.is_absolute() or any(x in (".", "..") for x in directory.parts):
        raise ValueError("receipt absolute directory required")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    try:
        for part in directory.parts[1:]:
            next_fd = os.open(part, flags, dir_fd=fd)
            try:
                info = os.fstat(next_fd)
                if info.st_uid not in (0, os.geteuid()):
                    raise ValueError("receipt untrusted ancestor owner")
                writable = info.st_mode & 0o022
                trusted_sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
                if writable and not trusted_sticky:
                    raise ValueError("receipt writable ancestor")
            except BaseException:
                os.close(next_fd)
                raise
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def write_job_receipt(directory: Path, run_id: str, state: str,
                      result_sha256: str | None) -> Path:
    """Create one canonical, fsynced receipt; never overwrite or follow links.

    Caller must supply a private, already-created directory it owns. A failed
    write or sync raises; no caller may interpret that exception as completion.
    """
    if (type(run_id) is not str or len(run_id) != 32
            or any(char not in "0123456789abcdef" for char in run_id)):
        raise ValueError("receipt run identity")
    if type(state) is not str or state not in ("SUCCEEDED", "FAILED"):
        raise ValueError("receipt terminal state")
    if state == "SUCCEEDED":
        if (type(result_sha256) is not str or len(result_sha256) != 64
                or any(char not in "0123456789abcdef" for char in result_sha256)):
            raise ValueError("receipt result digest")
    elif result_sha256 is not None:
        raise ValueError("failed receipt cannot promote result")
    if not isinstance(directory, Path):
        raise ValueError("receipt directory type")
    name = run_id + ".json"
    data = (json.dumps({"schema": SCHEMA, "run_id": run_id,
                        "state": state, "result_sha256": result_sha256,
                        "release_authorized": False}, sort_keys=True,
                       separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
    dirfd = _open_private_directory(directory)
    temporary = "." + run_id + "." + token_hex(16) + ".tmp"
    staged = False
    published = False
    try:
        info = os.fstat(dirfd)
        if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
                or info.st_uid != os.geteuid()):
            raise ValueError("receipt directory ownership or permissions")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dirfd)
        staged = True
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(data)
                stream.flush()
            os.fsync(fd)
        finally:
            os.close(fd)
        # Hard link is exclusive: a preexisting receipt, including a symlink,
        # fails without replacement. The complete bytes were fsynced first.
        os.link(temporary, name, src_dir_fd=dirfd, dst_dir_fd=dirfd,
                follow_symlinks=False)
        published = True
        os.fsync(dirfd)
        os.unlink(temporary, dir_fd=dirfd)
        staged = False
        os.fsync(dirfd)
        return directory / name
    except BaseException:
        if published:
            try:
                os.unlink(name, dir_fd=dirfd)
            except OSError:
                pass
        if staged:
            try:
                os.unlink(temporary, dir_fd=dirfd)
            except OSError:
                pass
        try:
            os.fsync(dirfd)
        except OSError:
            pass
        raise
    finally:
        os.close(dirfd)
