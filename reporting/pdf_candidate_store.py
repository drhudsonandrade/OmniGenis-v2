"""Explicit private candidate storage, not final publication or delivery.

Data files are fsynced before the existing receipt becomes the commit marker.
Only these APIs define bundle visibility: raw intermediate paths are not valid
artifacts. Incomplete attempts remain unverified and are never repaired or
regenerated. Exact completed attempts may be read idempotently without writes.

This boundary assumes caller-owned private local storage. Identity rechecks
reject observed changes; they do not authenticate execution or prevent a
malicious same-owner process from changing files after the last check. No
power-loss, native-resource, consent or release qualification is implied.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import stat

from reporting import _pdf_job_durable_receipt as receipts
from reporting import pdf_generated_source_job as generated
from reporting import pdf_qualification_job as qualification

SCHEMA = 'pdf-private-candidate-store/v1'
MAX_PDF_BYTES = generated.MAX_PDF_BYTES
MAX_MANIFEST_BYTES = generated.MAX_RESULT_BYTES + 4096
_DATA_NAMES = frozenset({'candidate.pdf', 'manifest.json'})


class PdfCandidateStoreError(ValueError):
    """A content-free refusal; never expose partial bytes or storage details."""


def _canonical(value: object) -> bytes:
    """Use the unchanged generated-result encoding without nonfinite values."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def _admit(directory: Path, run_id: str, expectations: dict) -> None:
    """Validate policy and independent expectations before any storage operation."""
    qualification._require_policy()
    receipts._receipt_bytes(run_id, 'SUCCEEDED', expectations['result_sha256'])
    if not isinstance(directory, Path):
        raise ValueError('candidate store directory type')
    for field in ('pdf_sha256', 'ir_sha256', 'request_sha256', 'resource_profile_sha256'):
        generated._pin(expectations[field])
    generated._profile(expectations['resource_profile_sha256'])
    generated._validate_context(expectations['namespace_id'], expectations['job_id'],
                                expectations['request_sha256'],
                                expectations['resource_profile_sha256'])


def _expectations(result_sha256: str, pdf_sha256: str, namespace_id: str,
                  job_id: str, request_sha256: str, ir_sha256: str,
                  resource_profile_sha256: str) -> dict:
    """Keep context explicit; a file's own digest is not an independent expectation."""
    return {'result_sha256': result_sha256, 'pdf_sha256': pdf_sha256,
            'namespace_id': namespace_id, 'job_id': job_id,
            'request_sha256': request_sha256, 'ir_sha256': ir_sha256,
            'resource_profile_sha256': resource_profile_sha256}


def _manifest(result: dict, pdf: bytes, run_id: str, expected: dict) -> dict:
    """Bind exact generated metadata, bytes and context without promoting scope."""
    if (type(result) is not dict or type(pdf) is not bytes
            or not 0 < len(pdf) <= MAX_PDF_BYTES
            or sha256(pdf).hexdigest() != expected['pdf_sha256']
            or sha256(_canonical(result)).hexdigest() != expected['result_sha256']):
        raise ValueError('candidate result or PDF identity')
    for field in ('pdf_sha256', 'namespace_id', 'job_id', 'request_sha256',
                  'ir_sha256', 'resource_profile_sha256'):
        if type(result.get(field)) is not str or result[field] != expected[field]:
            raise ValueError('candidate context differs')
    if (result.get('status') != 'GENERATED_CANDIDATE_AND_NATIVE_SOURCE_BOUND'
            or result.get('language') != generated.LANGUAGE
            or type(result.get('page_count')) is not int
            or not 0 < result['page_count'] <= generated.MAX_PAGES
            or result.get('release_authorized') is not False
            or result.get('default_pipeline_activated') is not False
            or result.get('release_authorization') != 'NOT_ESTABLISHED'):
        raise ValueError('candidate state or scope')
    manifest = {'schema': SCHEMA, 'state': 'STORED_PRIVATE_CANDIDATE',
                'run_id': run_id, 'result_sha256': expected['result_sha256'],
                'pdf_sha256': expected['pdf_sha256'], 'pdf_bytes': len(pdf),
                'page_count': result['page_count'], 'result': result,
                'release_authorized': False, 'supported_execution': False,
                'default_pipeline_activated': False}
    if len(_canonical(manifest)) > MAX_MANIFEST_BYTES:
        raise ValueError('candidate manifest budget')
    return manifest


def _file_identity(info: os.stat_result, limit: int) -> tuple[int, ...]:
    """Require finite regular private files with no hard-link aliases."""
    if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != os.geteuid() or info.st_nlink != 1
            or not 0 < info.st_size <= limit):
        raise ValueError('candidate file identity or bounds')
    return tuple(getattr(info, name) for name in (
        'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def _read_data(directory_fd: int, name: str, limit: int) -> bytes:
    """Read bounded anchored bytes, checking descriptor and named identity twice."""
    identity = _file_identity(os.stat(name, dir_fd=directory_fd,
                                     follow_symlinks=False), limit)
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                 dir_fd=directory_fd)
    try:
        if _file_identity(os.fstat(fd), limit) != identity:
            raise ValueError('candidate replaced before read')
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if (len(data) != identity[6]
                or _file_identity(os.fstat(fd), limit) != identity
                or _file_identity(os.stat(name, dir_fd=directory_fd,
                                         follow_symlinks=False), limit) != identity):
            raise ValueError('candidate changed during read')
        return bytes(data)
    finally:
        os.close(fd)


def _write_data(directory_fd: int, name: str, data: bytes, limit: int) -> None:
    """Create-only complete writes with sync; preserve partial files on failure."""
    if name not in _DATA_NAMES or type(data) is not bytes or not 0 < len(data) <= limit:
        raise ValueError('candidate data contract')
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                 | os.O_CLOEXEC, 0o600, dir_fd=directory_fd)
    try:
        os.fchmod(fd, 0o600)
        position = 0
        while position < len(data):
            written = os.write(fd, memoryview(data)[position:position + 65536])
            if type(written) is not int or not 0 < written <= min(65536, len(data)-position):
                raise OSError('candidate write made no progress')
            position += written
        os.fsync(fd)
        identity = _file_identity(os.fstat(fd), limit)
        if (identity[6] != len(data)
                or _file_identity(os.stat(name, dir_fd=directory_fd,
                                         follow_symlinks=False), limit) != identity):
            raise ValueError('candidate changed during write')
    finally:
        os.close(fd)


def _decode(raw: bytes) -> dict:
    """Reject duplicate fields and noncanonical encodings rather than normalizing."""
    def pairs(items):
        """Reject duplicate manifest keys without normalizing conflicting values."""
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('duplicate candidate manifest key')
            value[key] = item
        return value
    def nonfinite(_value):
        """Refuse nonfinite JSON scalars before accepting stored metadata."""
        raise ValueError('nonfinite candidate manifest value')
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)
    if type(value) is not dict or _canonical(value) != raw:
        raise ValueError('candidate manifest is not canonical')
    return value


def _bundle_identities(directory_fd: int, run_id: str) -> dict:
    """Pin all named objects across one complete read, including the commit marker."""
    limits = {'candidate.pdf': MAX_PDF_BYTES, 'manifest.json': MAX_MANIFEST_BYTES,
              run_id + '.json': receipts.MAX_RECEIPT_BYTES}
    return {name: _file_identity(os.stat(name, dir_fd=directory_fd,
                                        follow_symlinks=False), limit)
            for name, limit in limits.items()}


def _recover(directory: Path, run_id: str, expected: dict) -> tuple[bytes, dict]:
    """Require the exact commit marker and closed bundle before returning bytes."""
    with qualification._run_directory(directory, run_id, create=False) as (run, check):
        fd = receipts._open_private_directory(run)
        try:
            identity = receipts._private_directory_identity(fd)
            names = _DATA_NAMES | {run_id + '.json'}
            if set(os.listdir(fd)) != names:
                raise ValueError('candidate bundle is incomplete')
            identities = _bundle_identities(fd, run_id)
            outcome = receipts.read_job_receipt(run, run_id, 'SUCCEEDED', expected['result_sha256'])
            manifest_raw = _read_data(fd, 'manifest.json', MAX_MANIFEST_BYTES)
            pdf = _read_data(fd, 'candidate.pdf', MAX_PDF_BYTES)
            document = _decode(manifest_raw)
            manifest = _manifest(document.get('result'), pdf, run_id, expected)
            if _canonical(manifest) != manifest_raw:
                raise ValueError('candidate manifest binding differs')
            # Bind earlier reads across the complete transaction, not only each file.
            if (_read_data(fd, 'manifest.json', MAX_MANIFEST_BYTES) != manifest_raw
                    or _read_data(fd, 'candidate.pdf', MAX_PDF_BYTES) != pdf
                    or receipts.read_job_receipt(run, run_id, 'SUCCEEDED',
                                                expected['result_sha256']) != outcome
                    or set(os.listdir(fd)) != names
                    or _bundle_identities(fd, run_id) != identities
                    or receipts._private_directory_identity(fd) != identity):
                raise ValueError('candidate bundle changed')
            qualification._require_policy()
            generated._profile(expected['resource_profile_sha256'])
            check()
            return pdf, manifest
        finally:
            os.close(fd)


def persist_qualification_pdf_candidate(
    *, candidate: generated.PdfGeneratedSourceResult, directory: Path, run_id: str,
    expected_result_sha256: str, expected_pdf_sha256: str, namespace_id: str,
    job_id: str, request_sha256: str, expected_ir_sha256: str,
    expected_resource_profile_sha256: str,
) -> dict:
    """Persist one exact private candidate, with the existing receipt committed last.

    Only a currently valid generated result is accepted. Existing exact complete
    attempts are returned read-only; any incomplete or foreign attempt refuses.
    Errors preserve evidence and never initiate generation, repair or release.
    A postcommit exception may leave a valid bundle for explicit exact recovery.
    """
    try:
        expected = _expectations(expected_result_sha256, expected_pdf_sha256,
            namespace_id, job_id, request_sha256, expected_ir_sha256,
            expected_resource_profile_sha256)
        _admit(directory, run_id, expected)
        if type(candidate) is not generated.PdfGeneratedSourceResult:
            raise ValueError('candidate result type')
        result_raw = candidate.to_bytes()
        pdf = candidate.pdf_bytes
        manifest_raw = _canonical(_manifest(json.loads(result_raw), pdf, run_id, expected))
        claimed = False
        try:
            with qualification._run_directory(directory, run_id, create=True) as (run, check):
                claimed = True
                fd = receipts._open_private_directory(run)
                try:
                    identity = receipts._private_directory_identity(fd)
                    if os.listdir(fd):
                        raise ValueError('new candidate run is not empty')
                    check()
                    _write_data(fd, 'candidate.pdf', pdf, MAX_PDF_BYTES)
                    _write_data(fd, 'manifest.json', manifest_raw, MAX_MANIFEST_BYTES)
                    os.fsync(fd)
                    if (set(os.listdir(fd)) != _DATA_NAMES
                            or _read_data(fd, 'candidate.pdf', MAX_PDF_BYTES) != pdf
                            or _read_data(fd, 'manifest.json', MAX_MANIFEST_BYTES) != manifest_raw
                            or receipts._private_directory_identity(fd) != identity):
                        raise ValueError('candidate changed before commit')
                    qualification._require_policy()
                    if candidate.to_bytes() != result_raw:
                        raise ValueError('candidate source changed before commit')
                    check()
                    receipts.write_job_receipt(run, run_id, 'SUCCEEDED', expected_result_sha256)
                    check()
                    if candidate.to_bytes() != result_raw:
                        raise ValueError('candidate source changed during commit')
                finally:
                    os.close(fd)
        except FileExistsError:
            if claimed:
                raise
        stored_pdf, manifest = _recover(directory, run_id, expected)
        if stored_pdf != pdf or _canonical(manifest) != manifest_raw:
            raise ValueError('candidate readback differs')
        return manifest
    except Exception:
        raise PdfCandidateStoreError('pdf_candidate_store_persistence_refused') from None


def read_qualification_pdf_candidate(
    *, directory: Path, run_id: str, expected_result_sha256: str,
    expected_pdf_sha256: str, namespace_id: str, job_id: str, request_sha256: str,
    expected_ir_sha256: str, expected_resource_profile_sha256: str,
) -> tuple[bytes, dict]:
    """Recover exact expected candidate bytes and detached metadata without writes.

    Expectations must come from separately trusted job evidence. Matching hashes
    prove these bytes, not execution authenticity, historical sync or final
    authorization. This performs no rendering, repair, network access or delivery.
    Missing, changed, partial, disabled or unsupported records are refused.
    """
    try:
        expected = _expectations(expected_result_sha256, expected_pdf_sha256,
            namespace_id, job_id, request_sha256, expected_ir_sha256,
            expected_resource_profile_sha256)
        _admit(directory, run_id, expected)
        return _recover(directory, run_id, expected)
    except Exception:
        raise PdfCandidateStoreError('pdf_candidate_store_recovery_refused') from None
