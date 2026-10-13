"""Cooperative exact-head advancement over immutable local checkpoint objects.

One fixed job-private reference contains the current checkpoint's 64-byte ASCII
SHA-256. Writers must supply the independently expected predecessor and desired
checkpoint. A fresh directory open description takes a nonblocking exclusive
flock, validates append-only progress, persists the immutable object, and replaces
only the current reference atomically. Historical checkpoint objects never change.

This opt-in local Linux protocol requires all head writers to cooperate and the
caller to authenticate directory/job identities and expected digests. It does not
protect against malicious same-UID mutation, filesystem rollback, distributed
writers or arbitrary power loss. Existing raw checkpoint storage does not acquire
this lock or select a current reference. Never fork while an operation is active.

A failure may leave an unselected object, a deterministic private head stage, or
an already-replaced but unacknowledged head. Exact retry validates these states;
there is no directory scan, automatic rollback, unrelated cleanup or fallback.
Retention/quota, syscall deadlines, authorization, native work and release remain
caller responsibilities. A recorded prefix still does not prove a worker ran.
"""
from __future__ import annotations

from contextlib import contextmanager
import errno
import hashlib
import os
from typing import Iterator

try:
    import fcntl
except ImportError:
    fcntl = None

from reporting import checkpoint_files as files
from reporting.bindings import ReportBindingError, _digest
from reporting.page_checkpoints import PageCheckpointError, PageWindowCheckpoint
from reporting.page_windows import PageWindowPlan

_HEAD_NAME = 'checkpoint-head-v1'
_HEAD_BYTES = 64
_SUPPORTED = (files._SUPPORTED and fcntl is not None
              and hasattr(os, 'O_DIRECTORY') and hasattr(os, 'replace')
              and os.rename in os.supports_dir_fd)


class CheckpointHeadError(ValueError):
    """Content-free admission, contention, stale-state or storage failure."""


def _digest_argument(value: object) -> None:
    """Require the existing exact digest grammar, never a filename or alias."""
    try:
        _digest(value)
    except ReportBindingError:
        raise CheckpointHeadError('checkpoint_head_digest_invalid') from None


def _arguments(directory_fd: object, expected_directory: object,
               expected_digest: object) -> None:
    """Validate the platform and existing exact storage inputs before I/O."""
    if not _SUPPORTED:
        raise CheckpointHeadError('checkpoint_head_profile_unsupported')
    files._arguments(directory_fd, expected_directory, expected_digest)


@contextmanager
def _locked_root(directory_fd: int,
                 expected: files.CheckpointDirectoryIdentity) -> Iterator[int]:
    """Own a separate open description so caller duplicates never bypass locking."""
    files._directory(directory_fd, expected)
    root = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                   dir_fd=directory_fd)
    try:
        files._directory(root, expected)
        try:
            fcntl.flock(root, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EACCES):
                raise CheckpointHeadError('checkpoint_head_busy') from None
            raise
        files._directory(root, expected)
        yield root
    finally:
        # Closing only this independently opened description releases its lock.
        os.close(root)


def _head(root: int, expected: files.CheckpointDirectoryIdentity,
          name: str = _HEAD_NAME, *, sync: bool = False) -> str | None:
    """Read exactly one internal fixed-size reference without discovery or fallback."""
    try:
        before = os.stat(name, dir_fd=root, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if before.st_size != _HEAD_BYTES:
        raise CheckpointHeadError('checkpoint_head_size_invalid')
    raw = files._read_file(root, name, expected, sync=sync)
    if len(raw) != _HEAD_BYTES:
        raise CheckpointHeadError('checkpoint_head_size_invalid')
    try:
        digest = raw.decode('ascii')
    except UnicodeError:
        raise CheckpointHeadError('checkpoint_head_encoding_invalid') from None
    _digest_argument(digest)
    return digest


def _snapshot(checkpoint: object, digest: str,
              expected: files.CheckpointDirectoryIdentity) -> PageWindowCheckpoint:
    """Capture and validate exact canonical bytes before any current-state mutation."""
    if type(checkpoint) is not PageWindowCheckpoint:
        raise CheckpointHeadError('checkpoint_head_typed_source_required')
    try:
        raw = checkpoint.to_bytes()
    except (PageCheckpointError, AttributeError, TypeError):
        raise CheckpointHeadError('checkpoint_head_source_invalid') from None
    if hashlib.sha256(raw).hexdigest() != digest:
        raise CheckpointHeadError('checkpoint_head_source_digest_mismatch')
    return files._restore(raw, digest, checkpoint.plan, expected)


def _progress(root: int, expected: files.CheckpointDirectoryIdentity,
              checkpoint: PageWindowCheckpoint, previous: str | None,
              desired: str) -> None:
    """Require empty initialization or a strictly extended, unchanged prior prefix."""
    if previous is None:
        if checkpoint.observations:
            raise CheckpointHeadError('checkpoint_head_initial_prefix_not_empty')
        return
    prior = files.load_page_checkpoint(directory_fd=root, expected_directory=expected,
        expected_plan=checkpoint.plan, expected_checkpoint_sha256=previous)
    if previous == desired:
        if prior.to_bytes() != checkpoint.to_bytes():
            raise CheckpointHeadError('checkpoint_head_retry_mismatch')
        return
    count = len(prior.observations)
    if (len(checkpoint.observations) <= count
            or checkpoint.observations[:count] != prior.observations):
        raise CheckpointHeadError('checkpoint_head_nonmonotonic_prefix')


def advance_checkpoint_head(
    *, directory_fd: int, expected_directory: files.CheckpointDirectoryIdentity,
    checkpoint: PageWindowCheckpoint, expected_checkpoint_sha256: str,
    expected_previous_checkpoint_sha256: str | None,
) -> str:
    """Compare and advance one job-private head while preserving immutable history.

    Initialization requires an empty prefix and an absent expected predecessor.
    An exact already-current target may be retried with itself or a valid prior
    prefix. Any different current target rejects a stale writer before new data
    is persisted. A returned digest follows file/directory sync and readback, not
    native execution, tenant authentication or universal durability certification.
    """
    try:
        _arguments(directory_fd, expected_directory, expected_checkpoint_sha256)
        previous, desired = expected_previous_checkpoint_sha256, expected_checkpoint_sha256
        if previous is not None:
            _digest_argument(previous)
        captured = _snapshot(checkpoint, desired, expected_directory)
        if previous is None and captured.observations:
            raise CheckpointHeadError('checkpoint_head_initial_prefix_not_empty')
        with _locked_root(directory_fd, expected_directory) as root:
            current = _head(root, expected_directory)
            if current not in (previous, desired):
                raise CheckpointHeadError('checkpoint_head_stale_predecessor')
            if current is None and previous is not None:
                raise CheckpointHeadError('checkpoint_head_missing_predecessor')
            _progress(root, expected_directory, captured, previous, desired)
            files.store_page_checkpoint(directory_fd=root, expected_directory=expected_directory,
                checkpoint=captured, expected_checkpoint_sha256=desired)
            if current != desired:
                stage = '.checkpoint-head-' + desired
                staged = _head(root, expected_directory, stage, sync=True)
                if staged is None:
                    files._publish(root, stage, desired.encode('ascii'), expected_directory)
                    staged = _head(root, expected_directory, stage, sync=True)
                if staged != desired:
                    raise CheckpointHeadError('checkpoint_head_stage_mismatch')
                if _head(root, expected_directory) != current:
                    raise CheckpointHeadError('checkpoint_head_changed_before_replace')
                files._directory(root, expected_directory)
                os.replace(stage, _HEAD_NAME, src_dir_fd=root, dst_dir_fd=root)
            else:
                if _head(root, expected_directory, sync=True) != desired:
                    raise CheckpointHeadError('checkpoint_head_retry_changed')
            os.fsync(root)
            if _head(root, expected_directory) != desired:
                raise CheckpointHeadError('checkpoint_head_changed_after_sync')
            verified = files.load_page_checkpoint(directory_fd=root,
                expected_directory=expected_directory, expected_plan=captured.plan,
                expected_checkpoint_sha256=desired)
            if verified.to_bytes() != captured.to_bytes():
                raise CheckpointHeadError('checkpoint_head_final_content_mismatch')
            files._directory(root, expected_directory)
            if _head(root, expected_directory) != desired:
                raise CheckpointHeadError('checkpoint_head_changed_before_acknowledgment')
            return desired
    except (OSError, files.CheckpointFileError, PageCheckpointError):
        raise CheckpointHeadError('checkpoint_head_storage_or_context_failed') from None


def load_current_checkpoint(
    *, directory_fd: int, expected_directory: files.CheckpointDirectoryIdentity,
    expected_plan: PageWindowPlan, expected_checkpoint_sha256: str,
) -> PageWindowCheckpoint:
    """Return only the independently expected current state under the same lock.

    This read does not discover latest, select by timestamp or accept a previous
    content-addressed object when the current reference differs or is absent.
    """
    try:
        _arguments(directory_fd, expected_directory, expected_checkpoint_sha256)
        with _locked_root(directory_fd, expected_directory) as root:
            if _head(root, expected_directory) != expected_checkpoint_sha256:
                raise CheckpointHeadError('checkpoint_head_current_digest_mismatch')
            result = files.load_page_checkpoint(directory_fd=root,
                expected_directory=expected_directory, expected_plan=expected_plan,
                expected_checkpoint_sha256=expected_checkpoint_sha256)
            files._directory(root, expected_directory)
            if _head(root, expected_directory) != expected_checkpoint_sha256:
                raise CheckpointHeadError('checkpoint_head_changed_during_load')
            return result
    except (OSError, files.CheckpointFileError, PageCheckpointError):
        raise CheckpointHeadError('checkpoint_head_storage_or_context_failed') from None
