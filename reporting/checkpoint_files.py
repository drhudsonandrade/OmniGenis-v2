"""Opt-in, no-clobber local persistence for exact job-bound page checkpoints.

The caller supplies an already authorized private directory descriptor and an
independently pinned directory/job identity. Only digest basenames are resolved.
A new object is written to private scratch, file-synced, linked without replacing
an existing name, read back, and directory-synced before acknowledgment.

Supported scope is local Linux/POSIX descriptor-relative storage. The caller must
control the directory, serialize job operations, authenticate expected digests and
manage retention. Read-only mode is not filesystem immutability or protection
against a malicious same-UID writer. This adapter has no latest pointer, rollback
protection, tenant authentication, native PDF execution or release authority.
On error, a complete but unacknowledged final entry may remain; exact retry checks
it without replacement. Process death can leave private scratch for job-owned
recovery. No directory scan or automatic deletion of unrelated files is performed.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import secrets
import stat
import sys

from reporting.bindings import ReportBindingError, _digest
from reporting.page_checkpoints import (
    MAX_CHECKPOINT_BYTES, PageCheckpointError, PageWindowCheckpoint,
    _validate_context, _validate_plan, resume_page_checkpoint,
)
from reporting.page_windows import PageWindowPlan

_READ_CHUNK_BYTES = 64 * 1024
_SUPPORTED = (
    sys.platform == 'linux' and os.name == 'posix'
    and all(hasattr(os, name) for name in ('O_NOFOLLOW', 'O_NONBLOCK', 'O_CLOEXEC', 'geteuid', 'fsync'))
    and all(fn in os.supports_dir_fd for fn in (os.open, os.stat, os.link, os.unlink))
    and all(fn in os.supports_follow_symlinks for fn in (os.stat, os.link))
)


class CheckpointFileError(ValueError):
    """Fixed diagnostic; failed storage never implies an accepted checkpoint."""


def _reject(code: str) -> None:
    """Raise one content-free storage rejection code."""
    raise CheckpointFileError(code)


@dataclass(frozen=True, slots=True, repr=False)
class CheckpointDirectoryIdentity:
    """Host-private directory and job pin supplied by the authorized storage owner."""

    device_id: int
    inode_id: int
    owner_uid: int
    namespace_id: str
    job_id: str
    request_sha256: str
    resource_profile_sha256: str

    def __post_init__(self) -> None:
        """Validate exact bounded filesystem identities and the existing job grammar."""
        for value, low, high in ((self.device_id, 0, 2**64 - 1),
                                 (self.inode_id, 1, 2**64 - 1),
                                 (self.owner_uid, 0, 2**32 - 1)):
            if type(value) is not int or not low <= value <= high:
                _reject('checkpoint_directory_identity_invalid')
        try:
            _validate_context(self.namespace_id, self.job_id, self.request_sha256,
                              self.resource_profile_sha256)
        except PageCheckpointError:
            raise CheckpointFileError('checkpoint_directory_context_invalid') from None


def _arguments(fd: object, expected: object, digest: object) -> None:
    """Check the supported profile and native input types before filesystem I/O."""
    if not _SUPPORTED:
        _reject('checkpoint_file_profile_unsupported')
    if type(fd) is not int or not 0 <= fd <= 2**31 - 1:
        _reject('checkpoint_directory_descriptor_invalid')
    if type(expected) is not CheckpointDirectoryIdentity:
        _reject('checkpoint_directory_identity_required')
    expected.__post_init__()
    try:
        _digest(digest)
    except ReportBindingError:
        raise CheckpointFileError('checkpoint_file_expected_digest_invalid') from None


def _directory(fd: int, expected: CheckpointDirectoryIdentity) -> None:
    """Require the pinned owner-private directory without changing its permissions."""
    value = os.fstat(fd)
    if (not stat.S_ISDIR(value.st_mode) or value.st_nlink < 1
            or (value.st_dev, value.st_ino, value.st_uid)
            != (expected.device_id, expected.inode_id, expected.owner_uid)
            or value.st_uid != os.geteuid() or stat.S_IMODE(value.st_mode) != 0o700):
        _reject('checkpoint_directory_binding_or_permissions_invalid')


def _file_identity(value: os.stat_result) -> tuple[int, ...]:
    """Capture observable file changes while excluding read-induced access time."""
    return (value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _read_file(root: int, name: str, expected: CheckpointDirectoryIdentity,
               *, sync: bool = False) -> bytes:
    """Read one private regular single-link file within the unchanged codec budget."""
    _directory(root, expected)
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                 dir_fd=root)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != expected.owner_uid or before.st_dev != expected.device_id
                or stat.S_IMODE(before.st_mode) != 0o400
                or not 0 < before.st_size <= MAX_CHECKPOINT_BYTES):
            _reject('checkpoint_file_type_permissions_or_size_invalid')
        chunks: list[bytes] = []
        remaining = before.st_size + 1
        while remaining:
            raw = os.read(fd, min(_READ_CHUNK_BYTES, remaining))
            if not raw:
                break
            chunks.append(raw)
            remaining -= len(raw)
        payload = b''.join(chunks)
        if len(payload) != before.st_size:
            _reject('checkpoint_file_read_length_mismatch')
        if sync:
            os.fsync(fd)
        after = os.fstat(fd)
        try:
            entry = os.stat(name, dir_fd=root, follow_symlinks=False)
        except FileNotFoundError:
            raise CheckpointFileError('checkpoint_file_changed_during_read') from None
        if _file_identity(before) != _file_identity(after) or _file_identity(after) != _file_identity(entry):
            _reject('checkpoint_file_changed_during_read')
        return payload
    finally:
        os.close(fd)


def _restore(raw: bytes, digest: str, plan: PageWindowPlan,
             expected: CheckpointDirectoryIdentity) -> PageWindowCheckpoint:
    """Delegate byte, canonical encoding, plan and job checks to the existing codec."""
    try:
        return resume_page_checkpoint(
            checkpoint_bytes=raw, expected_checkpoint_sha256=digest,
            expected_plan=plan, namespace_id=expected.namespace_id, job_id=expected.job_id,
            expected_request_sha256=expected.request_sha256,
            expected_resource_profile_sha256=expected.resource_profile_sha256)
    except PageCheckpointError:
        raise CheckpointFileError('checkpoint_file_content_or_context_invalid') from None


def _publish(root: int, name: str, raw: bytes,
             expected: CheckpointDirectoryIdentity) -> None:
    """Stage bounded bytes and link without clobber; clean only this invocation's name."""
    temporary = '.checkpoint-' + secrets.token_hex(16)
    fd: int | None = None
    owned: tuple[int, int] | None = None
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                     | os.O_CLOEXEC, 0o600, dir_fd=root)
        initial = os.fstat(fd)
        owned = (initial.st_dev, initial.st_ino)
        if (not stat.S_ISREG(initial.st_mode) or initial.st_nlink != 1
                or initial.st_dev != expected.device_id or initial.st_uid != expected.owner_uid
                or initial.st_size != 0):
            _reject('checkpoint_staging_file_invalid')
        offset = 0
        while offset < len(raw):
            piece = raw[offset:offset + _READ_CHUNK_BYTES]
            written = os.write(fd, piece)
            if type(written) is not int or not 0 < written <= len(piece):
                _reject('checkpoint_file_write_incomplete')
            offset += written
        os.fchmod(fd, 0o400)
        os.fsync(fd)
        _directory(root, expected)
        if _read_file(root, temporary, expected) != raw:
            _reject('checkpoint_staging_readback_mismatch')
        if _file_identity(os.fstat(fd)) != _file_identity(os.stat(temporary, dir_fd=root, follow_symlinks=False)):
            _reject('checkpoint_staging_entry_changed')
        try:
            os.link(temporary, name, src_dir_fd=root, dst_dir_fd=root, follow_symlinks=False)
        except FileExistsError:
            # The caller verifies the existing object after owned scratch cleanup.
            pass
    finally:
        try:
            if fd is not None:
                os.close(fd)
        finally:
            if owned is not None:
                entry = os.stat(temporary, dir_fd=root, follow_symlinks=False)
                if (entry.st_dev, entry.st_ino) != owned:
                    _reject('checkpoint_staging_cleanup_identity_changed')
                os.unlink(temporary, dir_fd=root)


def store_page_checkpoint(
    *, directory_fd: int, expected_directory: CheckpointDirectoryIdentity,
    checkpoint: PageWindowCheckpoint, expected_checkpoint_sha256: str,
) -> str:
    """Persist exact canonical bytes without replacing any existing digest entry.

    A returned digest means this call completed file and directory fsync plus
    byte/context readback. It is not authentication, power-loss certification or
    a current-version pointer. On any error publication may be unacknowledged;
    retry only with the same independently authorized expectations.
    """
    _arguments(directory_fd, expected_directory, expected_checkpoint_sha256)
    if type(checkpoint) is not PageWindowCheckpoint:
        _reject('checkpoint_file_typed_checkpoint_required')
    try:
        raw = checkpoint.to_bytes()
    except (PageCheckpointError, AttributeError, TypeError):
        raise CheckpointFileError('checkpoint_file_source_invalid') from None
    if hashlib.sha256(raw).hexdigest() != expected_checkpoint_sha256:
        _reject('checkpoint_file_source_digest_mismatch')
    _restore(raw, expected_checkpoint_sha256, checkpoint.plan, expected_directory)
    try:
        root = os.dup(directory_fd)
        try:
            _directory(root, expected_directory)
            try:
                stored = _read_file(root, expected_checkpoint_sha256, expected_directory, sync=True)
            except FileNotFoundError:
                _publish(root, expected_checkpoint_sha256, raw, expected_directory)
                stored = _read_file(root, expected_checkpoint_sha256, expected_directory, sync=True)
            if stored != raw:
                _reject('checkpoint_file_existing_content_mismatch')
            _restore(stored, expected_checkpoint_sha256, checkpoint.plan, expected_directory)
            _directory(root, expected_directory)
            os.fsync(root)
            if _read_file(root, expected_checkpoint_sha256, expected_directory) != raw:
                _reject('checkpoint_file_changed_after_sync')
            _directory(root, expected_directory)
            return expected_checkpoint_sha256
        finally:
            os.close(root)
    except OSError:
        raise CheckpointFileError('checkpoint_file_io_failed') from None


def load_page_checkpoint(
    *, directory_fd: int, expected_directory: CheckpointDirectoryIdentity,
    expected_plan: PageWindowPlan, expected_checkpoint_sha256: str,
) -> PageWindowCheckpoint:
    """Read one exact checkpoint from a borrowed directory; never search for latest."""
    _arguments(directory_fd, expected_directory, expected_checkpoint_sha256)
    try:
        _validate_plan(expected_plan)
    except PageCheckpointError:
        raise CheckpointFileError('checkpoint_file_plan_invalid') from None
    try:
        root = os.dup(directory_fd)
        try:
            raw = _read_file(root, expected_checkpoint_sha256, expected_directory)
            result = _restore(raw, expected_checkpoint_sha256, expected_plan, expected_directory)
            _directory(root, expected_directory)
            return result
        finally:
            os.close(root)
    except OSError:
        raise CheckpointFileError('checkpoint_file_io_failed') from None
