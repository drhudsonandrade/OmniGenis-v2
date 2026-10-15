"""Fixed, optional, lossless transport for existing immutable PDF inspection inputs.

This codec performs no execution, storage, authentication or PDF/source parsing.
Decoded values still require the original snapshot job's full admission checks.
The independent packet digest and job context must be resolved by an authenticated
caller; a hash is not an authorization grant. Packets contain plaintext source
and PDF contents and belong only on an authorized private transport, never logs.

The format has a fixed 20-byte big-endian header, flat canonical JSON metadata,
then unchanged source and PDF bytes. There is no pickle, base64, compression,
arbitrary command, file path, service option, result wrapper or implicit launch.
All existing source, resource, result and default-rendering profiles stay intact.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
import struct

from reporting import pdf_snapshot_inspection as snapshot
from reporting import pdf_structured_source_job as structured
from reporting.bindings import _digest
from reporting.page_checkpoints import _json_bytes, _reject_constant, _unique_object, _validate_context

PROFILE_ID = 'immutable-pdf-inspection-request-v1'
MAGIC = b'OGPDFRQ1'
HEADER = struct.Struct('>8sIII')
MAX_METADATA_BYTES = 4096
MAX_SOURCE_BYTES = snapshot.MAX_SOURCE_BYTES
MAX_PDF_BYTES = structured.MAX_PDF_BYTES
MAX_PACKET_BYTES = HEADER.size + MAX_METADATA_BYTES + MAX_SOURCE_BYTES + MAX_PDF_BYTES
SOURCE_PROFILE_SHA256 = snapshot.PROFILE_SHA256
RESOURCE_PROFILE_SHA256 = structured.PROFILE_SHA256
_DISABLE = 'OMNIGENIS_PDF_INSPECTION_REQUEST_DISABLED'
_KEYS = frozenset(('expected_ir_sha256','expected_pdf_sha256','page_count','expected_language',
                   'namespace_id','job_id','request_sha256','expected_source_profile_sha256',
                   'expected_resource_profile_sha256'))


class PdfInspectionRequestError(ValueError):
    """One fixed content-free rejection with no partial decoded request."""


def inspection_request_profile() -> dict:
    """Expose the transport contract without promoting it to an execution profile."""
    return {'schema_version':'1.0.0','profile_id':PROFILE_ID,'magic':MAGIC.decode('ascii'),
            'header_format':HEADER.format,'header_bytes':HEADER.size,
            'segment_order':['metadata','presentation_ir','pdf'],
            'metadata_keys':sorted(_KEYS),'metadata_encoding':'EXISTING_CANONICAL_COMPACT_UTF8_JSON',
            'max_metadata_bytes':MAX_METADATA_BYTES,'max_source_bytes':MAX_SOURCE_BYTES,
            'max_pdf_bytes':MAX_PDF_BYTES,'max_packet_bytes':MAX_PACKET_BYTES,
            'max_pages':structured.MAX_PAGES,'language':structured.LANGUAGE,
            'source_profile_sha256':SOURCE_PROFILE_SHA256,
            'resource_profile_sha256':RESOURCE_PROFILE_SHA256,
            'source_and_pdf_semantics_validated':False,'transport_authenticated':False,
            'executor_activated':False,'aggregate_job_resources_qualified':False,
            'hard_job_deadline_enforced':False,'release_authorized':False}


PROFILE_SHA256 = sha256(_json_bytes(inspection_request_profile())).hexdigest()


def _profile(expected: object) -> None:
    """Reject transport drift, foreign pins and all disabled prerequisites."""
    _digest(expected)
    if (os.environ.get(_DISABLE) == '1' or expected != PROFILE_SHA256
            or sha256(_json_bytes(inspection_request_profile())).hexdigest() != PROFILE_SHA256
            or snapshot.PROFILE_SHA256 != SOURCE_PROFILE_SHA256
            or structured.PROFILE_SHA256 != RESOURCE_PROFILE_SHA256
            or (MAX_SOURCE_BYTES,MAX_PDF_BYTES) != (snapshot.MAX_SOURCE_BYTES,structured.MAX_PDF_BYTES)):
        raise ValueError('transport profile unavailable')
    snapshot._profile(SOURCE_PROFILE_SHA256,RESOURCE_PROFILE_SHA256)


def _metadata(record: object) -> None:
    """Validate only the fixed flat metadata vocabulary, types, bounds and pins."""
    if type(record) is not dict or set(record) != _KEYS:
        raise ValueError('metadata fields')
    for name in ('expected_ir_sha256','expected_pdf_sha256','request_sha256',
                 'expected_source_profile_sha256','expected_resource_profile_sha256'):
        _digest(record[name])
    if (type(record['page_count']) is not int or not 1 <= record['page_count'] <= structured.MAX_PAGES
            or type(record['expected_language']) is not str
            or record['expected_language'] != structured.LANGUAGE
            or record['expected_source_profile_sha256'] != SOURCE_PROFILE_SHA256
            or record['expected_resource_profile_sha256'] != RESOURCE_PROFILE_SHA256):
        raise ValueError('metadata types or profile')
    _validate_context(record['namespace_id'],record['job_id'],record['request_sha256'],
                      record['expected_resource_profile_sha256'])


def _body_identity(source: memoryview, pdf: memoryview, record: dict) -> None:
    """Check exact segment identities without allocating another complete document."""
    if (not 0 < len(source) <= MAX_SOURCE_BYTES or not 8 <= len(pdf) <= MAX_PDF_BYTES
            or bytes(pdf[:8]) != b'%PDF-1.7'
            or sha256(source).hexdigest() != record['expected_ir_sha256']
            or sha256(pdf).hexdigest() != record['expected_pdf_sha256']):
        raise ValueError('body identity or budget')


def encode_pdf_snapshot_request(
    *, presentation_ir_bytes: object, expected_ir_sha256: str,
    pdf_bytes: object, expected_pdf_sha256: str, page_count: int,
    expected_language: str, namespace_id: str, job_id: str, request_sha256: str,
    expected_source_profile_sha256: str, expected_resource_profile_sha256: str,
    expected_protocol_profile_sha256: str,
) -> bytes:
    """Frame existing call arguments without interpreting or executing the documents.

    Source/PDF bytes remain opaque and unchanged. The original snapshot API must
    still validate their canonical source semantics and the actual PDF. Finite
    packet bounds are not aggregate memory/CPU, lifecycle or release qualification.
    """
    try:
        _profile(expected_protocol_profile_sha256)
        if type(presentation_ir_bytes) is not bytes or type(pdf_bytes) is not bytes:
            raise ValueError('immutable bytes required')
        record = dict(expected_ir_sha256=expected_ir_sha256,expected_pdf_sha256=expected_pdf_sha256,
            page_count=page_count,expected_language=expected_language,namespace_id=namespace_id,
            job_id=job_id,request_sha256=request_sha256,
            expected_source_profile_sha256=expected_source_profile_sha256,
            expected_resource_profile_sha256=expected_resource_profile_sha256)
        _metadata(record)
        _body_identity(memoryview(presentation_ir_bytes),memoryview(pdf_bytes),record)
        meta = _json_bytes(record)
        if not 0 < len(meta) <= MAX_METADATA_BYTES:
            raise ValueError('metadata budget')
        header = HEADER.pack(MAGIC,len(meta),len(presentation_ir_bytes),len(pdf_bytes))
        packet = b''.join((header,meta,presentation_ir_bytes,pdf_bytes))
        _profile(expected_protocol_profile_sha256)
        return packet
    except Exception:
        raise PdfInspectionRequestError('pdf_inspection_request_invalid') from None


def decode_pdf_snapshot_request(
    packet_bytes: object, *, expected_packet_sha256: str,
    expected_protocol_profile_sha256: str, expected_namespace_id: str,
    expected_job_id: str, expected_request_sha256: str,
) -> dict:
    """Decode exactly one frame into the original snapshot call's keyword arguments.

    Verify whole-packet identity before metadata parsing. Check declared lengths
    before slicing and body hashes before copying the decoded bytes. Independent
    receiver context is never replaced by the sender's metadata. No stream read,
    filesystem access, authentication, PDF parsing or process launch takes place.
    """
    try:
        _profile(expected_protocol_profile_sha256)
        if type(packet_bytes) is not bytes or not HEADER.size < len(packet_bytes) <= MAX_PACKET_BYTES:
            raise ValueError('packet type or budget')
        _digest(expected_packet_sha256)
        _validate_context(expected_namespace_id,expected_job_id,expected_request_sha256,RESOURCE_PROFILE_SHA256)
        if sha256(packet_bytes).hexdigest() != expected_packet_sha256:
            raise ValueError('packet digest mismatch')
        magic,meta_size,source_size,pdf_size = HEADER.unpack_from(packet_bytes)
        if (magic != MAGIC or not 0 < meta_size <= MAX_METADATA_BYTES
                or not 0 < source_size <= MAX_SOURCE_BYTES or not 8 <= pdf_size <= MAX_PDF_BYTES
                or HEADER.size+meta_size+source_size+pdf_size != len(packet_bytes)):
            raise ValueError('frame lengths or magic')
        start = HEADER.size
        meta = packet_bytes[start:start+meta_size]
        snapshot._scan_json_budget(meta)
        record = json.loads(meta.decode('utf-8'),object_pairs_hook=_unique_object,parse_constant=_reject_constant)
        _metadata(record)
        if _json_bytes(record) != meta:
            raise ValueError('metadata not canonical')
        if (record['namespace_id'] != expected_namespace_id or record['job_id'] != expected_job_id
                or record['request_sha256'] != expected_request_sha256):
            raise ValueError('receiver context mismatch')
        view = memoryview(packet_bytes)
        source = view[start+meta_size:start+meta_size+source_size]
        pdf = view[start+meta_size+source_size:]
        _body_identity(source,pdf,record)
        result = {**record,'presentation_ir_bytes':bytes(source),'pdf_bytes':bytes(pdf)}
        _profile(expected_protocol_profile_sha256)
        return result
    except Exception:
        raise PdfInspectionRequestError('pdf_inspection_request_invalid') from None
