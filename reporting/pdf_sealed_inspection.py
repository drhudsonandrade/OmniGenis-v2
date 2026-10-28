"""Optional fixed inspection of one independently bound sealed PDF request.

Capture once through the existing descriptor reader, then invoke the pinned
immutable-source inspection exactly once. Independent profile expectations
select either the original structured family or the complete native family.
The returned object is the original complete sealed result, not a new receipt,
authentication claim or release grant.
All source, PDF, page, locale and job bindings are checked before returning it.

The caller supplies authorized independent expectations and owns the borrowed
handle. Capture preserves its offset and closes only the reader's duplicate.
After capture this function uses immutable bytes and never retains or rereads
the descriptor. It does not revoke other handles or protect hostile concurrent
manipulation of the caller's descriptor table. Plaintext and swap remain outer
boundary responsibilities. No service, new worker, retry or default route is
introduced; job-wide resource and hard-deadline qualification remain absent.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os

from reporting import pdf_inspection_request as codec
from reporting import pdf_request_descriptor as descriptor
from reporting import pdf_snapshot_inspection as snapshot
from reporting import pdf_native_source_job as native
from reporting import pdf_structured_source_job as structured
from reporting.bindings import _digest
from reporting.page_checkpoints import _json_bytes
from reporting.pdf_snapshot_inspection import execute_pdf_snapshot_inspection_job
from reporting.pdf_native_source_job import PdfNativeSourceResult
from reporting.pdf_structured_source_job import PdfStructuredSourceResult

PROFILE_ID = 'sealed-request-pdf-inspection-v1'
NATIVE_PROFILE_ID = 'sealed-request-pdf-inspection-v2'
DESCRIPTOR_PROFILE_SHA256 = descriptor.PROFILE_SHA256
PROTOCOL_PROFILE_SHA256 = codec.PROFILE_SHA256
SOURCE_PROFILE_SHA256 = snapshot.PROFILE_SHA256
RESOURCE_PROFILE_SHA256 = structured.PROFILE_SHA256
MAX_RESULT_BYTES = structured.MAX_RESULT_BYTES
NATIVE_DESCRIPTOR_PROFILE_SHA256 = descriptor.NATIVE_PROFILE_SHA256
NATIVE_PROTOCOL_PROFILE_SHA256 = codec.NATIVE_PROFILE_SHA256
NATIVE_SOURCE_PROFILE_SHA256 = snapshot.NATIVE_PROFILE_SHA256
NATIVE_RESOURCE_PROFILE_SHA256 = native.PROFILE_SHA256
NATIVE_MAX_RESULT_BYTES = native.MAX_RESULT_BYTES
_DISABLE = 'OMNIGENIS_PDF_SEALED_INSPECTION_DISABLED'
_ARGUMENT_KEYS = frozenset(('presentation_ir_bytes','expected_ir_sha256','pdf_bytes',
    'expected_pdf_sha256','page_count','expected_language','namespace_id','job_id',
    'request_sha256','expected_source_profile_sha256','expected_resource_profile_sha256'))


class PdfSealedInspectionError(ValueError):
    """One content-free rejection with no partially accepted inspection result."""


def sealed_inspection_profile() -> dict:
    """Expose this opt-in integration pin without replacing any child resource contract."""
    return {'schema_version':'1.0.0','profile_id':PROFILE_ID,
            'descriptor_profile_sha256':DESCRIPTOR_PROFILE_SHA256,
            'protocol_profile_sha256':PROTOCOL_PROFILE_SHA256,
            'source_profile_sha256':SOURCE_PROFILE_SHA256,
            'resource_profile_sha256':RESOURCE_PROFILE_SHA256,
            'capture':'ONCE_TO_IMMUTABLE_BYTES_THROUGH_EXISTING_SEALED_DESCRIPTOR_READER',
            'snapshot_job_calls':1,'max_native_inspector_invocations':structured.MAX_INVOCATIONS,
            'max_packet_bytes':codec.MAX_PACKET_BYTES,'max_source_bytes':snapshot.MAX_SOURCE_BYTES,
            'max_pdf_bytes':structured.MAX_PDF_BYTES,'max_pages':structured.MAX_PAGES,
            'max_result_bytes':MAX_RESULT_BYTES,'language':structured.LANGUAGE,
            'returned_result_type':'PdfStructuredSourceResult','result_wrapper_added':False,
            'new_executor_activated':False,'default_pipeline_activated':False,
            'transport_authenticated':False,'duplicate_revocation_qualified':False,
            'aggregate_job_resources_qualified':False,'hard_job_deadline_enforced':False,
            'release_authorized':False}


PROFILE_SHA256 = sha256(_json_bytes(sealed_inspection_profile())).hexdigest()


def native_sealed_inspection_profile() -> dict:
    """Expose one native snapshot call with unchanged descriptor semantics and child scope."""
    profile = sealed_inspection_profile()
    del profile['max_native_inspector_invocations']
    profile.update(schema_version='2.0.0', profile_id=NATIVE_PROFILE_ID,
                   descriptor_profile_sha256=NATIVE_DESCRIPTOR_PROFILE_SHA256,
                   protocol_profile_sha256=NATIVE_PROTOCOL_PROFILE_SHA256,
                   source_profile_sha256=NATIVE_SOURCE_PROFILE_SHA256,
                   resource_profile_sha256=NATIVE_RESOURCE_PROFILE_SHA256,
                   native_source_job_calls=1, max_outer_stages=native.MAX_OUTER_STAGES,
                   max_pdf_bytes=native.MAX_PDF_BYTES, max_pages=native.MAX_PAGES,
                   max_result_bytes=NATIVE_MAX_RESULT_BYTES, language=native.LANGUAGE,
                   returned_result_type='PdfNativeSourceResult')
    return profile


NATIVE_PROFILE_SHA256 = sha256(_json_bytes(native_sealed_inspection_profile())).hexdigest()


def _profile(execution_pin: str, descriptor_pin: str, protocol_pin: str) -> bool:
    """Reject drift or disabling before capture, before dispatch and before acceptance."""
    _digest(execution_pin)
    if os.environ.get(_DISABLE) == '1':
        raise ValueError('sealed inspection profile unavailable')
    if execution_pin == PROFILE_SHA256:
        if (sha256(_json_bytes(sealed_inspection_profile())).hexdigest() != PROFILE_SHA256
                or descriptor_pin != DESCRIPTOR_PROFILE_SHA256
                or protocol_pin != PROTOCOL_PROFILE_SHA256
                or descriptor.PROFILE_SHA256 != DESCRIPTOR_PROFILE_SHA256
                or codec.PROFILE_SHA256 != PROTOCOL_PROFILE_SHA256
                or snapshot.PROFILE_SHA256 != SOURCE_PROFILE_SHA256
                or structured.PROFILE_SHA256 != RESOURCE_PROFILE_SHA256
                or MAX_RESULT_BYTES != structured.MAX_RESULT_BYTES):
            raise ValueError('sealed inspection profile unavailable')
        descriptor._profile(descriptor_pin, protocol_pin)
        snapshot._profile(SOURCE_PROFILE_SHA256, RESOURCE_PROFILE_SHA256)
        return False
    if execution_pin == NATIVE_PROFILE_SHA256:
        if (sha256(_json_bytes(native_sealed_inspection_profile())).hexdigest() != NATIVE_PROFILE_SHA256
                or descriptor_pin != NATIVE_DESCRIPTOR_PROFILE_SHA256
                or protocol_pin != NATIVE_PROTOCOL_PROFILE_SHA256
                or descriptor.NATIVE_PROFILE_SHA256 != NATIVE_DESCRIPTOR_PROFILE_SHA256
                or codec.NATIVE_PROFILE_SHA256 != NATIVE_PROTOCOL_PROFILE_SHA256
                or snapshot.NATIVE_PROFILE_SHA256 != NATIVE_SOURCE_PROFILE_SHA256
                or native.PROFILE_SHA256 != NATIVE_RESOURCE_PROFILE_SHA256
                or NATIVE_MAX_RESULT_BYTES != native.MAX_RESULT_BYTES):
            raise ValueError('sealed inspection profile unavailable')
        descriptor._profile(descriptor_pin, protocol_pin)
        snapshot._profile(NATIVE_SOURCE_PROFILE_SHA256, NATIVE_RESOURCE_PROFILE_SHA256)
        return True
    raise ValueError('sealed inspection profile unavailable')


def _result_bindings(arguments: object, namespace: str, job: str, request: str,
                     selected_native: bool = False) -> dict:
    """Bind only the fixed captured vocabulary to independent receiver and child profiles."""
    source_pin = NATIVE_SOURCE_PROFILE_SHA256 if selected_native else SOURCE_PROFILE_SHA256
    resource_pin = NATIVE_RESOURCE_PROFILE_SHA256 if selected_native else RESOURCE_PROFILE_SHA256
    if (type(arguments) is not dict or set(arguments) != _ARGUMENT_KEYS
            or arguments['namespace_id'] != namespace or arguments['job_id'] != job
            or arguments['request_sha256'] != request
            or arguments['expected_source_profile_sha256'] != source_pin
            or arguments['expected_resource_profile_sha256'] != resource_pin):
        raise ValueError('captured request context or vocabulary')
    return {'pdf_sha256':arguments['expected_pdf_sha256'],
            'ir_sha256':arguments['expected_ir_sha256'],'page_count':arguments['page_count'],
            'language':arguments['expected_language'],'namespace_id':namespace,
            'job_id':job,'request_sha256':request,'resource_profile_sha256':resource_pin}


def execute_sealed_pdf_inspection_job(
    request_fd: object, *, expected_packet_sha256: str,
    expected_protocol_profile_sha256: str, expected_namespace_id: str,
    expected_job_id: str, expected_request_sha256: str,
    expected_descriptor_profile_sha256: str, expected_execution_profile_sha256: str,
) -> PdfStructuredSourceResult | PdfNativeSourceResult:
    """Capture one sealed request and run exactly one independently pinned snapshot job.

    Transport validity does not replace source/PDF admission. No source override,
    callback, precomputed receipt, retry or publication is accepted. The snapshot
    job retains its original guarded native workers and source/result checks.
    Its elapsed-acceptance clock is not a hard deadline covering this outer call.
    Required authentication and aggregate supervision must be established outside.
    """
    try:
        selected_native = _profile(expected_execution_profile_sha256,
                                   expected_descriptor_profile_sha256,
                                   expected_protocol_profile_sha256)
        arguments = descriptor.read_sealed_pdf_request(request_fd,
            expected_packet_sha256=expected_packet_sha256,
            expected_protocol_profile_sha256=expected_protocol_profile_sha256,
            expected_namespace_id=expected_namespace_id, expected_job_id=expected_job_id,
            expected_request_sha256=expected_request_sha256,
            expected_descriptor_profile_sha256=expected_descriptor_profile_sha256)
        bindings = _result_bindings(arguments, expected_namespace_id, expected_job_id,
                                    expected_request_sha256, selected_native)
        _profile(expected_execution_profile_sha256, expected_descriptor_profile_sha256,
                 expected_protocol_profile_sha256)
        result = execute_pdf_snapshot_inspection_job(**arguments)
        _profile(expected_execution_profile_sha256, expected_descriptor_profile_sha256,
                 expected_protocol_profile_sha256)
        result_type = PdfNativeSourceResult if selected_native else PdfStructuredSourceResult
        if type(result) is not result_type:
            raise ValueError('sealed inspection result type')
        raw = result.to_bytes()
        maximum = NATIVE_MAX_RESULT_BYTES if selected_native else MAX_RESULT_BYTES
        if type(raw) is not bytes or not 0 < len(raw) <= maximum:
            raise ValueError('sealed inspection result budget')
        record = json.loads(raw)
        if any(record[key] != value for key, value in bindings.items()):
            raise ValueError('sealed inspection result belongs to another request')
        _profile(expected_execution_profile_sha256, expected_descriptor_profile_sha256,
                 expected_protocol_profile_sha256)
        return result
    except Exception:
        raise PdfSealedInspectionError('pdf_sealed_inspection_failed') from None
