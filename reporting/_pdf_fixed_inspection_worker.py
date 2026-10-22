"""Optional Linux child entrypoint for existing sealed-request/full-result transport.

This is a fixed ingress/egress process boundary, not an authenticated or
qualified supervisor. Independent expectations must originate from a trusted
controller. Stdin is a single bounded canonical context through a private pipe;
the source/PDF request is an existing kernel-sealed borrowed descriptor. Stdout
contains only the complete existing bounded result frame after acceptance.

The kernel parent-death signal covers only this worker, not every descendant.
Aggregate CPU/memory/wall/scratch/process enforcement, process-tree cleanup,
private caller authorization and release remain outside this module. No service
is installed, no renderer/default route is enabled and no fallback is allowed.
"""
from __future__ import annotations

import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import stat
import sys

# Python -I runs the fixed script without trusting cwd or caller PYTHONPATH.
if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reporting import pdf_inspection_request as codec
from reporting import pdf_request_descriptor as descriptor
from reporting import pdf_sealed_inspection as sealed
from reporting import pdf_inspection_result_frame as frame
from reporting._pdf_bounded_scratch import (
    activate_bounded_process_temporaries,
    bounded_scratch_parent,
    bounded_scratch_requested,
)
from reporting import pdf_structured_source_job as structured
from reporting.page_checkpoints import _json_bytes, _reject_constant, _unique_object
from reporting.bindings import _digest

PROFILE_ID='fixed-sealed-request-result-worker-v1'
MAX_CONTEXT_BYTES=codec.MAX_METADATA_BYTES
MAX_RESULT_FRAME_BYTES=frame.MAX_FRAME_BYTES
_DISABLE='OMNIGENIS_PDF_FIXED_INSPECTION_WORKER_DISABLED'
_KEYS=frozenset((
    'expected_worker_profile_sha256','expected_packet_sha256',
    'expected_protocol_profile_sha256','expected_namespace_id','expected_job_id',
    'expected_request_sha256','expected_descriptor_profile_sha256',
    'expected_execution_profile_sha256','expected_pdf_sha256',
    'expected_ir_sha256','expected_page_count','expected_language',
    'expected_resource_profile_sha256','expected_frame_profile_sha256',
))


def worker_profile() -> dict:
    """Expose exact fixed source/transport pins without claiming host supervision."""
    return {'schema_version':'1.0.0','profile_id':PROFILE_ID,
            'context_encoding':'EXACT_CANONICAL_NATIVE_JSON_OVER_PRIVATE_STDIN_PIPE',
            'context_keys':sorted(_KEYS),'max_context_bytes':MAX_CONTEXT_BYTES,
            'max_result_frame_bytes':MAX_RESULT_FRAME_BYTES,
            'request_profile_sha256':codec.PROFILE_SHA256,
            'descriptor_profile_sha256':descriptor.PROFILE_SHA256,
            'inspection_profile_sha256':sealed.PROFILE_SHA256,
            'result_frame_profile_sha256':frame.PROFILE_SHA256,
            'resource_profile_sha256':structured.PROFILE_SHA256,
            'independent_expectations_required':True,
            'anonymous_sealed_request_required':True,
            'stdin_pipe_required':True,'stdout_pipe_required':True,
            'parent_death_signal_for_this_worker':True,
            'descendant_cleanup_qualified':False,'origin_authenticated':False,
            'aggregate_job_resources_qualified':False,'hard_job_deadline_enforced':False,
            'release_authorized':False,'service_installed':False,
            'default_pipeline_activated':False}


PROFILE_SHA256=sha256(_json_bytes(worker_profile())).hexdigest()


def _profile(expected: object) -> None:
    """Reject an unpinned or disabled worker before accessing request content."""
    _digest(expected)
    if (sys.platform!='linux' or os.environ.get(_DISABLE)=='1'
            or expected!=PROFILE_SHA256
            or sha256(_json_bytes(worker_profile())).hexdigest()!=PROFILE_SHA256
            or MAX_CONTEXT_BYTES!=codec.MAX_METADATA_BYTES
            or MAX_RESULT_FRAME_BYTES!=frame.MAX_FRAME_BYTES):
        raise ValueError('fixed inspection worker profile invalid')
    sealed._profile(sealed.PROFILE_SHA256,descriptor.PROFILE_SHA256,codec.PROFILE_SHA256)
    frame._profile(frame.PROFILE_SHA256)


def _parse_context(raw: object) -> dict:
    """Read only independently expected bounded canonical metadata; no PDF bytes."""
    if (type(raw) is not bytes or not 0<len(raw)<=MAX_CONTEXT_BYTES):
        raise ValueError('fixed worker context budget')
    codec.snapshot._scan_json_budget(raw)
    data=json.loads(raw.decode('utf-8'),object_pairs_hook=_unique_object,
                    parse_constant=_reject_constant)
    if type(data) is not dict or set(data)!=_KEYS or _json_bytes(data)!=raw:
        raise ValueError('fixed worker context not canonical')
    _profile(data['expected_worker_profile_sha256'])
    for key,value in data.items():
        if key.endswith('sha256'):
            _digest(value)
    if (type(data['expected_page_count']) is not int
            or not 1<=data['expected_page_count']<=structured.MAX_PAGES
            or data['expected_language']!=structured.LANGUAGE
            or data['expected_protocol_profile_sha256']!=codec.PROFILE_SHA256
            or data['expected_descriptor_profile_sha256']!=descriptor.PROFILE_SHA256
            or data['expected_execution_profile_sha256']!=sealed.PROFILE_SHA256
            or data['expected_resource_profile_sha256']!=structured.PROFILE_SHA256
            or data['expected_frame_profile_sha256']!=frame.PROFILE_SHA256):
        raise ValueError('fixed worker context profile mismatch')
    return data


def _parent_lifetime(expected_parent: int) -> None:
    """Require actual Linux parent identity and SIGKILL on this worker's parent death."""
    if (type(expected_parent) is not int or expected_parent<=1
            or os.getppid()!=expected_parent):
        raise ValueError('worker launched from unexpected parent')
    libc=ctypes.CDLL(None,use_errno=True)
    prctl=libc.prctl
    prctl.restype=ctypes.c_int
    prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,
                    ctypes.c_ulong,ctypes.c_ulong]
    if prctl(1,signal.SIGKILL,0,0,0)!=0:
        raise OSError(ctypes.get_errno(),'worker parent-death guard failed')
    if os.getppid()!=expected_parent:
        raise ValueError('worker parent changed while arming lifetime')


def _read_pipe() -> bytes:
    """Bound context allocation and require one terminated private stdin pipe."""
    data=bytearray()
    while True:
        block=os.read(0,min(8192,MAX_CONTEXT_BYTES+1-len(data)))
        if not block:
            return bytes(data)
        data.extend(block)
        if len(data)>MAX_CONTEXT_BYTES:
            raise ValueError('worker context exceeds fixed limit')


def _write_frame(data: bytes) -> None:
    """Write only the complete framed result; a partial pipe is never acceptance."""
    if type(data) is not bytes or not 0<len(data)<=MAX_RESULT_FRAME_BYTES:
        raise ValueError('worker output budget')
    pending=memoryview(data)
    while pending:
        count=os.write(1,pending)
        if type(count) is not int or count<=0:
            raise ValueError('worker output incomplete')
        pending=pending[count:]


def _entrypoint() -> int:
    """Bind the fixed opt-in parent before entering the dedicated worker."""
    try:
        if bounded_scratch_requested():
            os.environ["TMPDIR"]=str(bounded_scratch_parent())
    except BaseException:
        return 70
    return main()


def main(argv: list[str] | None=None) -> int:
    """Run exactly one fixed sealed inspection with no partial successful stdout."""
    args=sys.argv if argv is None else argv
    if len(args)!=3:
        return 64
    try:
        if (sys.platform!='linux' or os.environ.get(_DISABLE)=='1'
                or not args[1].isascii() or not args[1].isdecimal()
                or not args[2].isascii() or not args[2].isdecimal()):
            return 70
        request_fd=int(args[1]);parent_pid=int(args[2])
        if (request_fd<3 or request_fd>2**31-1 or parent_pid<=1
                or not stat.S_ISFIFO(os.fstat(0).st_mode)
                or not stat.S_ISFIFO(os.fstat(1).st_mode)):
            return 70
        _parent_lifetime(parent_pid)
        expected=_parse_context(_read_pipe())
        activate_bounded_process_temporaries()
        original=sealed.execute_sealed_pdf_inspection_job(
            request_fd, expected_packet_sha256=expected['expected_packet_sha256'],
            expected_protocol_profile_sha256=expected['expected_protocol_profile_sha256'],
            expected_namespace_id=expected['expected_namespace_id'],
            expected_job_id=expected['expected_job_id'],
            expected_request_sha256=expected['expected_request_sha256'],
            expected_descriptor_profile_sha256=expected['expected_descriptor_profile_sha256'],
            expected_execution_profile_sha256=expected['expected_execution_profile_sha256'])
        result_context={
            'expected_pdf_sha256':expected['expected_pdf_sha256'],
            'expected_ir_sha256':expected['expected_ir_sha256'],
            'expected_page_count':expected['expected_page_count'],
            'expected_language':expected['expected_language'],
            'expected_namespace_id':expected['expected_namespace_id'],
            'expected_job_id':expected['expected_job_id'],
            'expected_request_sha256':expected['expected_request_sha256'],
            'expected_resource_profile_sha256':expected['expected_resource_profile_sha256'],
            'expected_frame_profile_sha256':expected['expected_frame_profile_sha256'],
        }
        result=frame.encode_pdf_inspection_result_frame(original,**result_context)
        if frame.decode_pdf_inspection_result_frame(result,**result_context)!=original.to_bytes():
            raise ValueError('worker result frame identity mismatch')
        _profile(expected['expected_worker_profile_sha256'])
        _write_frame(result)
        return 0
    except BaseException:
        return 70


if __name__=='__main__':
    raise SystemExit(_entrypoint())
