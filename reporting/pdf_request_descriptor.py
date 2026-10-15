"""Optional Linux sealed-descriptor handoff for the existing bounded PDF request.

The codec still owns packet, body-hash and receiver-context validation. Sealing
qualifies content and size immutability only; it is not origin authentication,
encryption, replay prevention, execution authorization or job-wide supervision.
No path, service, process, socket, source parser or PDF parser is opened here.

The caller owns the context and must not close or reassign its borrowed FD.
Receiver reads use an owned close-on-exec duplicate and preserve caller offsets.
Detected producer-FD replacement is rejected without closing the replacement.
This is not protection against hostile concurrent descriptor-table manipulation
inside the same trusted process. Copies deliberately made by a caller outlive
the context until closed by their owner; no duplicate revocation is claimed.
Plaintext, Unix permissions, swap and interprocess access still require the
separately qualified outer execution/storage boundary. No fallback is allowed.
"""
from __future__ import annotations

from contextlib import contextmanager
from hashlib import sha256
from typing import Iterator
import fcntl
import os
import stat
import sys

from reporting import pdf_inspection_request as codec
from reporting.bindings import _digest
from reporting.page_checkpoints import _json_bytes, _validate_context

PROFILE_ID = 'sealed-pdf-inspection-request-descriptor-v1'
CODEC_PROFILE_SHA256 = codec.PROFILE_SHA256
MAX_PACKET_BYTES = codec.MAX_PACKET_BYTES
CHUNK_BYTES = 64 * 1024
_SEAL_NAMES = ('F_SEAL_WRITE', 'F_SEAL_GROW', 'F_SEAL_SHRINK', 'F_SEAL_SEAL')
REQUIRED_SEALS = sum(getattr(fcntl, name, 0) for name in _SEAL_NAMES)
_DISABLE = 'OMNIGENIS_PDF_REQUEST_DESCRIPTOR_DISABLED'
_SUPPORTED = (sys.platform == 'linux'
    and all(hasattr(os, name) for name in ('memfd_create','MFD_CLOEXEC','MFD_ALLOW_SEALING','pread','write','fchmod','get_inheritable'))
    and all(hasattr(fcntl, name) for name in (*_SEAL_NAMES,'F_ADD_SEALS','F_GET_SEALS','F_DUPFD_CLOEXEC')))


class PdfRequestDescriptorError(ValueError):
    """One fixed content-free failure, never a partially accepted descriptor or request."""


def descriptor_profile() -> dict:
    """Return the detached, finite descriptor policy without expanding execution claims."""
    return {'schema_version':'1.0.0', 'profile_id':PROFILE_ID, 'platform':'linux',
            'codec_profile_sha256':CODEC_PROFILE_SHA256, 'max_packet_bytes':MAX_PACKET_BYTES,
            'io_chunk_bytes':CHUNK_BYTES, 'file_type':'ANONYMOUS_REGULAR', 'file_mode':0o600,
            'required_seals':list(_SEAL_NAMES), 'required_seal_mask':REQUIRED_SEALS,
            'producer_noninheritable':True, 'receiver_owned_cloexec_duplicate':True,
            'receiver_preserves_borrowed_offset':True, 'named_file_fallback':False,
            'source_and_pdf_semantics_validated':False, 'transport_authenticated':False,
            'duplicate_revocation_qualified':False, 'executor_activated':False,
            'aggregate_job_resources_qualified':False, 'hard_job_deadline_enforced':False,
            'release_authorized':False}


PROFILE_SHA256 = sha256(_json_bytes(descriptor_profile())).hexdigest()


def _profile(descriptor_pin: str, codec_pin: str) -> None:
    """Require both exact profiles and retain every existing prerequisite switch."""
    _digest(descriptor_pin)
    if (not _SUPPORTED or sys.platform != 'linux' or os.environ.get(_DISABLE) == '1'
            or descriptor_pin != PROFILE_SHA256
            or sha256(_json_bytes(descriptor_profile())).hexdigest() != PROFILE_SHA256
            or codec_pin != CODEC_PROFILE_SHA256 or codec.PROFILE_SHA256 != CODEC_PROFILE_SHA256
            or MAX_PACKET_BYTES != codec.MAX_PACKET_BYTES
            or REQUIRED_SEALS != sum(getattr(fcntl, name, 0) for name in _SEAL_NAMES)):
        raise ValueError('descriptor profile unavailable')
    codec._profile(codec_pin)


def _expectations(packet_pin: str, codec_pin: str, namespace: str, job: str,
                  request_pin: str, descriptor_pin: str) -> dict:
    """Validate bounded independent identity metadata before allocating or duplicating FDs."""
    _profile(descriptor_pin, codec_pin)
    _digest(packet_pin)
    _validate_context(namespace, job, request_pin, codec.RESOURCE_PROFILE_SHA256)
    return {'expected_packet_sha256':packet_pin, 'expected_protocol_profile_sha256':codec_pin,
            'expected_namespace_id':namespace, 'expected_job_id':job,
            'expected_request_sha256':request_pin}


def _identity(info: os.stat_result) -> tuple[int, ...]:
    """Exclude read-induced access times while detecting inode and metadata replacement."""
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _descriptor(fd: int) -> os.stat_result:
    """Reject nonregular, named, nonprivate, oversized or insufficiently sealed inputs."""
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 0
            or stat.S_IMODE(info.st_mode) != 0o600
            or not codec.HEADER.size < info.st_size <= MAX_PACKET_BYTES
            or fcntl.fcntl(fd, fcntl.F_GET_SEALS) & REQUIRED_SEALS != REQUIRED_SEALS):
        raise ValueError('descriptor type, mode, size or seals')
    return info


def _capture(fd: int, size: int) -> bytes:
    """Read exactly the previously admitted finite length without changing file offsets."""
    pieces = []; offset = 0
    while offset < size:
        count = min(CHUNK_BYTES, size - offset)
        piece = os.pread(fd, count, offset)
        if type(piece) is not bytes or not 0 < len(piece) <= count:
            raise ValueError('descriptor read incomplete')
        pieces.append(piece); offset += len(piece)
    return b''.join(pieces)


def _close_owned(fd: int, identity: tuple[int, int] | None) -> None:
    """Close only the owned inode; detected caller-side replacement is never closed."""
    try:
        info = os.fstat(fd)
        if identity is not None and (info.st_dev, info.st_ino) != identity:
            raise ValueError('descriptor ownership lost')
        os.close(fd)
    except Exception:
        raise PdfRequestDescriptorError('pdf_request_descriptor_invalid') from None


@contextmanager
def sealed_pdf_request(
    packet_bytes: object, *, expected_packet_sha256: str,
    expected_protocol_profile_sha256: str, expected_namespace_id: str,
    expected_job_id: str, expected_request_sha256: str,
    expected_descriptor_profile_sha256: str,
) -> Iterator[int]:
    """Yield one borrowed non-inheritable FD only after exact codec and kernel-seal checks.

    The context owns this FD, not descriptors independently copied by its caller.
    Cleanup also runs on caller exceptions. A service invocation is deliberately
    absent: qualified admission, descriptor delivery and supervision belong outside.
    """
    fd = None; owned = None
    try:
        try:
            expected = _expectations(expected_packet_sha256, expected_protocol_profile_sha256,
                expected_namespace_id, expected_job_id, expected_request_sha256,
                expected_descriptor_profile_sha256)
            codec.decode_pdf_snapshot_request(packet_bytes, **expected)
            fd = os.memfd_create('omnigenis-inspection-request', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            info = os.fstat(fd); owned = (info.st_dev, info.st_ino)
            if fd < 3 or info.st_size != 0 or info.st_nlink != 0 or not stat.S_ISREG(info.st_mode):
                raise ValueError('new descriptor invalid')
            os.fchmod(fd, 0o600)
            view = memoryview(packet_bytes); offset = 0
            while offset < len(view):
                piece = view[offset:offset + CHUNK_BYTES]
                count = os.write(fd, piece)
                if type(count) is not int or not 0 < count <= len(piece):
                    raise ValueError('descriptor write incomplete')
                offset += count
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, REQUIRED_SEALS)
            before = _descriptor(fd)
            if (before.st_size != len(packet_bytes) or os.get_inheritable(fd)
                    or _capture(fd, before.st_size) != packet_bytes
                    or _identity(before) != _identity(_descriptor(fd))):
                raise ValueError('sealed descriptor readback mismatch')
            _profile(expected_descriptor_profile_sha256, expected_protocol_profile_sha256)
        except Exception:
            raise PdfRequestDescriptorError('pdf_request_descriptor_invalid') from None
        yield fd
    finally:
        if fd is not None: _close_owned(fd, owned)


def read_sealed_pdf_request(
    request_fd: object, *, expected_packet_sha256: str,
    expected_protocol_profile_sha256: str, expected_namespace_id: str,
    expected_job_id: str, expected_request_sha256: str,
    expected_descriptor_profile_sha256: str,
) -> dict:
    """Capture a borrowed sealed object and return only fully revalidated codec arguments.

    The owned duplicate is closed on success and failure without seeking or
    closing the caller's descriptor. Opaque body bytes still need the original
    snapshot entrypoint's complete source/PDF admission and guarded inspection.
    """
    fd = None; owned = None
    try:
        try:
            expected = _expectations(expected_packet_sha256, expected_protocol_profile_sha256,
                expected_namespace_id, expected_job_id, expected_request_sha256,
                expected_descriptor_profile_sha256)
            if type(request_fd) is not int or not 3 <= request_fd <= 2**31 - 1:
                raise ValueError('borrowed descriptor invalid')
            fd = fcntl.fcntl(request_fd, fcntl.F_DUPFD_CLOEXEC, 3)
            info = os.fstat(fd); owned = (info.st_dev, info.st_ino)
            if os.get_inheritable(fd): raise ValueError('duplicate inheritable')
            before = _descriptor(fd)
            raw = _capture(fd, before.st_size)
            if _identity(before) != _identity(_descriptor(fd)):
                raise ValueError('descriptor changed during capture')
            result = codec.decode_pdf_snapshot_request(raw, **expected)
            _profile(expected_descriptor_profile_sha256, expected_protocol_profile_sha256)
            if _identity(before) != _identity(_descriptor(fd)):
                raise ValueError('descriptor changed before acceptance')
            return result
        except Exception:
            raise PdfRequestDescriptorError('pdf_request_descriptor_invalid') from None
    finally:
        if fd is not None: _close_owned(fd, owned)
