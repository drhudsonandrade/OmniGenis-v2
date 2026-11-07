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
MAX_RECEIPT_BYTES = 512


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


def _receipt_bytes(run_id: str, state: str, result_sha256: str | None) -> bytes:
    """Validate the unchanged terminal expectations and encode the canonical wire."""
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
    data = (json.dumps({"schema": SCHEMA, "run_id": run_id,
                        "state": state, "result_sha256": result_sha256,
                        "release_authorized": False}, sort_keys=True,
                       separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
    return data


def write_job_receipt(directory: Path, run_id: str, state: str,
                      result_sha256: str | None) -> Path:
    """Create one canonical, fsynced receipt; never overwrite or follow links.

    Caller must supply a private, already-created directory it owns. A failed
    write or sync raises; no caller may interpret that exception as completion.
    """
    data = _receipt_bytes(run_id, state, result_sha256)
    if not isinstance(directory, Path):
        raise ValueError("receipt directory type")
    name = run_id + ".json"
    temporary = "." + run_id + "." + token_hex(16) + ".tmp"
    dirfd = _open_private_directory(directory)
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



def _private_directory_identity(fd: int) -> tuple[int, int]:
    """Require the original caller-owned private directory, not just a pathname."""
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_uid != os.geteuid()):
        raise ValueError("receipt directory ownership or permissions")
    return info.st_dev, info.st_ino


def _receipt_file_identity(info: os.stat_result) -> tuple[int, ...]:
    """Admit only a bounded regular private file without hard-link aliases."""
    if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != os.geteuid() or info.st_nlink != 1
            or not 0 < info.st_size <= MAX_RECEIPT_BYTES):
        raise ValueError("receipt file ownership, type or bounds")
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_job_receipt(directory: Path, run_id: str, state: str,
                     result_sha256: str | None) -> dict:
    """Read only the exact expected canonical outcome from a private local file.

    Expectations must come from separately trusted job evidence. This verifies
    observed bytes and local file identity, not actual execution, historical
    fsync, resource qualification or release authorization. Missing, changed,
    linked or partial receipts raise; no retry, repair or promotion is performed.
    File and directory identities are rechecked before returning detached data.
    """
    expected = _receipt_bytes(run_id, state, result_sha256)
    if not isinstance(directory, Path):
        raise ValueError("receipt directory type")
    name = run_id + ".json"
    dirfd = _open_private_directory(directory)
    try:
        directory_identity = _private_directory_identity(dirfd)
        identity = _receipt_file_identity(os.stat(name, dir_fd=dirfd, follow_symlinks=False))
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=dirfd)
        try:
            if _receipt_file_identity(os.fstat(fd)) != identity:
                raise ValueError("receipt changed before read")
            data = bytearray()
            while len(data) <= MAX_RECEIPT_BYTES:
                chunk = os.read(fd, MAX_RECEIPT_BYTES + 1 - len(data))
                if not chunk:
                    break
                data.extend(chunk)
            if data != expected:
                raise ValueError("receipt does not match exact expected outcome")
            if (_receipt_file_identity(os.fstat(fd)) != identity
                    or _receipt_file_identity(os.stat(name, dir_fd=dirfd,
                                                     follow_symlinks=False)) != identity):
                raise ValueError("receipt changed during read")
            current_dirfd = _open_private_directory(directory)
            try:
                if (_private_directory_identity(current_dirfd) != directory_identity
                        or _private_directory_identity(dirfd) != directory_identity):
                    raise ValueError("receipt directory changed during read")
            finally:
                os.close(current_dirfd)
            return json.loads(data)
        finally:
            os.close(fd)
    finally:
        os.close(dirfd)


def qualification_receipt_boundary() -> dict:
    """Declare only the local qualification receipt boundary; never activate jobs.

    Default and explicit rollback disable the qualification surface. This
    operation does not execute a job, persist a receipt, authorize release or
    qualify an external supervisor. Unknown configuration fails closed.
    """
    mode = os.environ.get('OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE')
    disabled = os.environ.get('OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED')
    if mode not in (None, 'qualification-only') or disabled not in (None, '1'):
        raise ValueError('qualification receipt boundary configuration invalid')
    return {
        'mode': 'QUALIFICATION_ONLY' if mode == 'qualification-only' and disabled is None else 'DISABLED',
        'receipt_schema': SCHEMA,
        'supported_execution': False,
        'native_resources_qualified': False,
        'release_authorized': False,
    }
