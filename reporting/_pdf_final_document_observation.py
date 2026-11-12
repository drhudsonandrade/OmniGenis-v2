"""Bound actual declared workers to one complete stored private document.

Capture-time ownership checks precede the existing owned cleanup and reap.
Composition checks unsigned parent records afterward; it cannot authenticate
historical execution or observe arbitrary native descendants. No launch,
budget, callback, host policy, persisted format or release gate is introduced.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import re
from subprocess import Popen
from time import monotonic_ns

from reporting.page_checkpoints import _json_bytes
from reporting._pdf_process_lifecycle import _observe, wait_owned_process_group

SCHEMA = 'stored-final-document-process-observation/v1'
PROFILE_ID = 'source-bound-final-document-process-observation-v1'
MAX_OBSERVATION_BYTES = 160 * 1024
MAX_PROCESS_BYTES = 2048
_WORKERS = {'render':'_pdf_render_worker.py', 'locations':'_pdf_final_locations_worker.py'}
_BASE = {'kind','worker','worker_source_sha256','parent_pid','pid',
         'spawn_monotonic_ns','exit_monotonic_ns','exit_code'}
_FALSE = ('whole_graph_observed','arbitrary_descendants_observed','authenticated_worker_execution',
          'aggregate_job_resources_qualified','native_profile_qualified','external_observer_measured',
          'default_pipeline_activated','release_authorized','supported_execution',
          'hard_job_deadline_enforced','storage_deadline_enforced','durable_observation_storage')


def _require(condition: bool) -> None:
    """Refuse incomplete evidence without returning any candidate observation."""
    if not condition:raise ValueError('final document process observation unverified')


def _integer(value, minimum=0, maximum=(1 << 63)-1):
    """Booleans and noninteger counters never stand for process or clock facts."""
    _require(type(value) is int and minimum <= value <= maximum)
    return value


def _hash(value) -> str:
    """Digest complete canonical metadata without implying authenticity."""
    return sha256(_json_bytes(value)).hexdigest()


def _bounded(value, limit):
    """Return detached finite metadata, retaining no mutable caller containers."""
    raw = _json_bytes(value); _require(0 < len(raw) <= limit)
    return json.loads(raw)


def _seal(value, limit):
    """Include the final digest field in the enforced serialized-byte ceiling."""
    result = dict(value); result['observation_sha256'] = _hash(result)
    return _bounded(result, limit)


def observe_spawn(process, command, kind):
    """Observe the actual waitable direct child while its numeric identity is held."""
    _require(kind in _WORKERS and isinstance(process, Popen)
             and type(process.pid) is int and process.pid > 1
             and type(command) is list and process.args == command
             and process.returncode is None and len(command) > 3)
    worker = Path(__file__).with_name(_WORKERS[kind]).resolve()
    _require(Path(command[3]).resolve() == worker)
    _observe(process)
    _require(os.getpgid(process.pid) == process.pid)
    stamp = _integer(monotonic_ns())
    return {'kind':kind, 'worker':worker.name,
        'worker_source_sha256':sha256(worker.read_bytes()).hexdigest(),
        'parent_pid':os.getpid(), 'pid':process.pid, 'spawn_monotonic_ns':stamp}


def capture_spawn(process, command, kind):
    """An observation refusal still cleans the exclusively owned original group."""
    try:
        return observe_spawn(process, command, kind)
    except BaseException as failure:
        if isinstance(process, Popen):
            try:wait_owned_process_group(process, wall_seconds=0)
            except BaseException as cleanup:raise failure from cleanup
        raise


def observe_exit(process, record, code):
    """Record only the same actual child after successful owned cleanup and reap."""
    _require(isinstance(process, Popen) and type(record) is dict
             and record.get('pid') == process.pid and type(code) is int
             and code == process.returncode == 0)
    stamp = _integer(monotonic_ns())
    _require(stamp >= _integer(record.get('spawn_monotonic_ns')))
    return {**record, 'exit_monotonic_ns':stamp, 'exit_code':code}


def _base(record, kind):
    """Validate capture metadata consistently; ownership was checked before reap."""
    _require(type(record) is dict and _BASE <= set(record) and kind in _WORKERS)
    worker = Path(__file__).with_name(_WORKERS[kind])
    _require(record['kind'] == kind and record['worker'] == worker.name
             and record['worker_source_sha256'] == sha256(worker.read_bytes()).hexdigest()
             and _integer(record['parent_pid'], 2, 2147483647) == os.getpid()
             and _integer(record['pid'], 2, 2147483647) != record['parent_pid']
             and _integer(record['exit_code']) == 0
             and _integer(record['spawn_monotonic_ns']) <= _integer(record['exit_monotonic_ns']))
    return {k:record[k] for k in _BASE}


def render_record(record, rendered):
    """Bind the closed raster-child observation to protocol three and sealed bytes."""
    from reporting import pdf_raster_render as raster
    _require(type(rendered) is raster.RasterPdfCandidate)
    render = rendered.to_dict()
    expected = {'request_header_sha256':sha256(
        f"3 {render['html_sha256']} {render['resources_sha256']}\n".encode('ascii')).hexdigest(),
        **{k:render[k] for k in ('html_sha256','resources_sha256','pdf_sha256','page_count')},
        'render_sha256':_hash(render), 'profile_sha256':raster.profile_sha256()}
    return _seal({**_base(record,'render'), **expected}, MAX_PROCESS_BYTES)


def locations_record(record, identity, receipt):
    """Bind one exact location worker, protocol header and accepted page partition."""
    from reporting import _pdf_final_locations_worker as locations
    locations._identity(identity)
    _require(type(receipt) is dict and receipt.get('identity') == identity)
    header = ' '.join([str(locations.PROTOCOL_VERSION),
                      *(str(identity[k]) for k in locations.IDENTITY_FIELDS)]) + '\n'
    return _seal({**_base(record,'locations'), 'request_header_sha256':sha256(header.encode('ascii')).hexdigest(),
                  'identity':identity, 'receipt_sha256':_hash(receipt)}, MAX_PROCESS_BYTES)


def _check_row(record, kind, expected):
    """Rehashing a foreign, omitted or extra field cannot produce a valid row."""
    _require(type(record) is dict and set(record) == _BASE | set(expected) | {'observation_sha256'})
    record = _bounded(record, MAX_PROCESS_BYTES)
    rebuilt = _seal({**_base(record,kind), **expected}, MAX_PROCESS_BYTES)
    _require(_json_bytes(record) == _json_bytes(rebuilt))
    return rebuilt


def compose_stored_observation(*, rendered, inspected, binding, layout_processes,
        native_observation, pdf, manifest, started_ns, verified_ns):
    """Compose only after exact receipt-last storage/readback, preserving all nonclaims.

    The caller supplies its internal sealed results, never a public observation
    input. These consistency checks do not reconstruct historical ownership.
    Reused PIDs, ambiguous ordering or missing selected children cause refusal.
    An already committed candidate remains recoverable under the existing
    independent-expectation contract if this optional final composition fails.
    """
    from reporting import pdf_final_document_candidate as final
    from reporting import pdf_raster_render as raster
    from reporting._pdf_raster_job_observation import validate_native
    _require(type(rendered) is raster.RasterPdfCandidate and type(binding) is dict
             and type(pdf) is bytes and pdf == rendered.pdf_bytes and type(manifest) is dict)
    started_ns = _integer(started_ns); verified_ns = _integer(verified_ns)
    _require(started_ns <= verified_ns)
    render = rendered.to_dict(); native = validate_native(inspected, native_observation)
    native_raw = inspected.to_bytes()
    _require(binding.get('render_result_sha256') == _hash(render)
             and binding.get('native_inspection_sha256') == sha256(native_raw).hexdigest())
    layout = binding.get('layout')
    _require(type(layout) is dict and type(layout.get('passes')) is list
             and 2 <= len(layout['passes']) <= final.MAX_LAYOUT_PASSES
             and type(layout_processes) is list and len(layout_processes) == len(layout['passes']))
    _require(_json_bytes(layout) == _json_bytes(final._layout_record(layout['passes'],layout.get('final_page_map'))))
    _require(_json_bytes(binding) == _json_bytes(final._binding(binding['source_projection'],
             binding['composition'],render,native_raw,layout)))
    result = {'render_result':render,'native_inspection':inspected.to_dict(),'binding':binding}
    run_id = manifest.get('run_id')
    _require(type(run_id) is str and re.fullmatch('[0-9a-f]{32}',run_id) is not None)
    expected_manifest = {'schema':final.STORAGE_SCHEMA,'state':'STORED_PRIVATE_CANDIDATE',
        'run_id':run_id,'storage_profile_sha256':final.STORAGE_PROFILE_SHA256,
        'result_sha256':_hash(result),'pdf_sha256':sha256(pdf).hexdigest(),'pdf_bytes':len(pdf),
        'page_count':render['page_count'],'result':result,'release_authorized':False,
        'supported_execution':False,'default_pipeline_activated':False}
    _require(_json_bytes(manifest) == _json_bytes(expected_manifest))
    parent = os.getpid(); seen = {parent}; previous = started_ns; rows = []
    for number,(row, original) in enumerate(zip(layout_processes,layout['passes'],strict=True),1):
        _require(type(row) is dict and set(row) == {'pass_number','render','locations'}
                 and _integer(row['pass_number'],1,4) == number
                 and _integer(original['pass_number'],1,4) == number)
        r = original['render_result']; identity = original['location_receipt']['identity']
        render_expected = {'request_header_sha256':sha256(
            f"3 {r['html_sha256']} {r['resources_sha256']}\n".encode('ascii')).hexdigest(),
            **{k:r[k] for k in ('html_sha256','resources_sha256','pdf_sha256','page_count')},
            'render_sha256':_hash(r),'profile_sha256':raster.profile_sha256()}
        render_row = _check_row(row['render'],'render',render_expected)
        location_expected = locations_record(row['locations'],identity,original['location_receipt'])
        _require(_json_bytes(row['locations']) == _json_bytes(location_expected))
        _require(set(row['locations']) == set(location_expected))
        location_row = location_expected
        for process in (render_row,location_row):
            _require(process['pid'] not in seen and previous <= process['spawn_monotonic_ns'])
            seen.add(process['pid']);previous = process['exit_monotonic_ns']
        rows.append({'pass_number':number,'render':render_row,'locations':location_row})
    _require(rows[-1]['render']['pdf_sha256'] == render['pdf_sha256'])
    direct = native['direct_observation']['direct_process_ledger']['processes']
    for process in direct:
        _require(process['parent_pid'] == parent and process['pid'] not in seen
                 and previous <= process['spawn_monotonic_ns'])
        seen.add(process['pid']);previous = process['exit_monotonic_ns']
    for window in native['raster_child_ledger']['windows']:
        for process in window['observation']['processes']:
            _require(process['pid'] not in seen);seen.add(process['pid'])
    _require(previous <= verified_ns)
    direct_count = 2*len(rows) + native['observed_direct_spawns']
    nested_count = native['observed_nested_spawns'];total = direct_count + nested_count
    _require(len(seen) == total+1)
    return _seal({'schema':SCHEMA,'profile_id':PROFILE_ID,
        'state':'COMPLETE_DECLARED_FINAL_DOCUMENT_WORKERS_OBSERVED','parent_pid':parent,
        'run_id':run_id,'pdf_sha256':manifest['pdf_sha256'],'pdf_bytes':len(pdf),
        'page_count':manifest['page_count'],'result_sha256':manifest['result_sha256'],
        'manifest_sha256':_hash(manifest),'layout_sha256':_hash(layout),
        'request_sha256':inspected.request_sha256,'namespace_id':inspected.namespace_id,'job_id':inspected.job_id,
        'resource_profile_sha256':final.PROFILE_SHA256,'storage_profile_sha256':final.STORAGE_PROFILE_SHA256,
        'operation_started_ns':started_ns,'storage_verified_ns':verified_ns,
        'timing_scope':'Parent observations after spawn/reap and exact stored readback; not kernel event timestamps.',
        'layout_processes':rows,'native_observation':native,
        'observed_layout_spawns':2*len(rows),'observed_layout_exits':2*len(rows),
        'observed_direct_spawns':direct_count,'observed_direct_exits':direct_count,
        'observed_nested_spawns':nested_count,'observed_nested_exits':nested_count,
        'observed_total_spawns':total,'observed_total_exits':total,'declared_retries':0,
        **{k:False for k in _FALSE}}, MAX_OBSERVATION_BYTES)
