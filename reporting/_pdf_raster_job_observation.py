"""Bounded composition of actual fixed raster children and unchanged job results.

The controlled worker supplies parent-observed creation/reap metadata. These
unsigned records reconcile the declared probe/page schedule only, not arbitrary
native descendants, authenticated execution, external observer cost or release.
Existing direct-only records keep their original schema and meaning.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

from reporting.page_checkpoints import _json_bytes
from reporting.page_windows import plan_pdf_page_windows
from reporting._pdf_raster_child_observation import validate_observation, _integer

MAX_LEDGER_BYTES = 64 * 1024
MAX_ENVELOPE_BYTES = 128 * 1024
LEDGER_SCHEMA = 'native-raster-child-ledger/v1'
NATIVE_SCHEMA = 'native-job-raster-observation/v1'
GENERATED_SCHEMA = 'generated-job-raster-observation/v1'
_IDENTITY = ('pdf_sha256', 'ir_sha256', 'plan_sha256', 'page_count',
             'namespace_id', 'job_id', 'request_sha256', 'resource_profile_sha256')
_FALSE = ('whole_graph_observed', 'authenticated_worker_execution',
          'aggregate_job_resources_qualified', 'native_profile_qualified',
          'external_observer_measured', 'default_pipeline_activated', 'release_authorized')
_DIRECT_KEYS = {'schema', 'state', 'observed_spawns', 'observed_exits',
                'reserved_nested_attempts_not_observed', 'declared_retries', 'processes',
                'descendants_qualified', 'aggregate_job_resources_qualified',
                'release_authorized', 'ledger_sha256'}
_ROW_KEYS = {'sequence', 'kind', 'worker', 'worker_source_sha256', 'request_header_sha256',
             'pdf_sha256', 'ir_sha256', 'plan_sha256', 'page_count', 'window', 'parent_pid',
             'pid', 'spawn_monotonic_ns', 'exit_monotonic_ns', 'exit_code'}
_FOUND_KEYS = {'status', 'raster_sha256', 'total_pixels', 'min_edge_margin_px', 'inspected_pages'}


def _require(condition, message):
    """An incomplete or ambiguous record is always a refusal, never a partial pass."""
    if not condition:
        raise ValueError(message)


def _bounded(value, limit):
    """Detach finite canonical metadata without accepting bytes from unrelated work."""
    try:
        encoded = _json_bytes(value)
    except Exception:
        raise ValueError('raster job observation encoding') from None
    _require(0 < len(encoded) <= limit, 'raster job observation byte budget')
    return json.loads(encoded)


def _digest(record, field):
    """Require the exact descriptive digest while retaining nonauthentication limits."""
    _require(type(record) is dict and type(record.get(field)) is str, 'raster job digest shape')
    expected = sha256(_json_bytes({k:v for k,v in record.items() if k != field})).hexdigest()
    _require(record[field] == expected, 'raster job digest differs')


def _seal(value, field, limit):
    """Attach one deterministic digest and detach the complete bounded object."""
    value[field] = sha256(_json_bytes(value)).hexdigest()
    return _bounded(value, limit)


def _checked_direct(direct):
    """Revalidate the original fixed direct schedule without changing its v1 wire."""
    from reporting._pdf_native_launch_budget import _schedule, TEXT_PROFILE
    _require(type(direct) is dict and set(direct) == _DIRECT_KEYS, 'direct raster parent ledger shape')
    direct = _bounded(direct, 64 * 1024)
    _digest(direct, 'ledger_sha256')
    rows = direct['processes']
    _require(direct['schema'] == 'native-direct-process-observation/v1'
             and direct['state'] == 'COMPLETE_DIRECT_CHILDREN_OBSERVED'
             and type(rows) is list and 23 <= len(rows) <= 41,
             'complete direct raster parent ledger required')
    _require(all(direct[k] is False for k in ('descendants_qualified',
             'aggregate_job_resources_qualified', 'release_authorized')), 'direct ledger scope changed')
    _require(_integer(direct['declared_retries']) == 0
             and _integer(direct['observed_spawns']) == len(rows)
             and _integer(direct['observed_exits']) == len(rows), 'direct ledger counts differ')
    first = rows[0]
    _require(type(first) is dict and set(first) == _ROW_KEYS, 'direct ledger first row shape')
    count = _integer(first['page_count'], 1, 64)
    plan = plan_pdf_page_windows(pdf_sha256=first['pdf_sha256'], ir_sha256=first['ir_sha256'],
        page_count=count, admitted_page_budget=count, pages_per_window=16,
        inspector_profile_id=TEXT_PROFILE)
    attempts = _schedule(plan)
    _require(len(attempts) == len(rows), 'direct raster schedule length')
    owner = _integer(first['parent_pid'], 2, 2147483647)
    pids = {owner}; previous = 0
    for index, (row, attempt) in enumerate(zip(rows, attempts, strict=True)):
        _require(type(row) is dict and set(row) == _ROW_KEYS, 'direct ledger row shape')
        fields = attempt.header.decode('ascii').strip().split(' ')
        window = [int(v) for v in fields[5:]] if len(fields) == 8 else None
        expected = {'sequence': index, 'kind': attempt.kind, 'worker': Path(attempt.worker).name,
            'worker_source_sha256': sha256(Path(attempt.worker).read_bytes()).hexdigest(),
            'request_header_sha256': sha256(attempt.header).hexdigest(), 'pdf_sha256':fields[1],
            'ir_sha256':fields[2], 'plan_sha256':fields[3], 'page_count':int(fields[4]),
            'window':window, 'parent_pid':owner, 'exit_code':0}
        _require(_json_bytes({k:row[k] for k in expected}) == _json_bytes(expected),
                 'direct raster parent schedule or source mismatch')
        pid = _integer(row['pid'], 2, 2147483647)
        begin = _integer(row['spawn_monotonic_ns']); end = _integer(row['exit_monotonic_ns'])
        _require(pid not in pids and previous <= begin <= end, 'direct raster parent identity or clock')
        pids.add(pid); previous = end
    reserved = sum(attempt.reserved_children for attempt in attempts)
    _require(_integer(direct['reserved_nested_attempts_not_observed']) == reserved,
             'direct nested reservation mismatch')
    return direct, pids, count, reserved


def validate_window(row, entry):
    """Bind one complete child ledger to its exact reaped direct raster worker."""
    from reporting.pdf_raster_windows import PdfRasterWindowInspection
    _require(type(row) is dict and set(row) == _ROW_KEYS and row['kind'] == 'raster_windows',
             'direct raster worker required')
    _require(type(entry) is dict and set(entry) == {'sequence','inspection','observation'},
             'nested raster association shape')
    _require(_integer(entry['sequence']) == row['sequence'], 'nested raster sequence differs')
    span = row['window']
    _require(type(span) is list and len(span) == 3, 'direct raster interval required')
    identity = {k:row[k] for k in ('pdf_sha256','ir_sha256','plan_sha256','page_count')}
    identity.update(zip(('window_index','first_page','last_page'),span,strict=True))
    found = entry['inspection']
    _require(type(found) is dict and set(found) == _FOUND_KEYS
             and found['status'] == 'WINDOW_RASTER_INSPECTED'
             and _integer(found['inspected_pages'],1,4) == span[2]-span[1]+1,
             'nested raster inspection shape')
    receipt = PdfRasterWindowInspection(**identity, **{k:found[k] for k in
        ('raster_sha256','total_pixels','min_edge_margin_px')})
    observed = validate_observation(entry['observation'],identity,found,row['pid'])
    for child in observed['processes']:
        _require(row['spawn_monotonic_ns'] <= child['observed_spawn_ns']
                 <= child['observed_exit_ns'] <= row['exit_monotonic_ns'],
                 'nested raster observation outside parent lifetime')
    return _bounded({'sequence':entry['sequence'], 'inspection':found, 'observation':observed,
                     'raster_receipt_sha256':receipt.observation_sha256}, 4096)


def build_raster_ledger(direct, entries):
    """Reconcile each reserved raster child with one actual complete window record."""
    direct, pids, pages, reserved = _checked_direct(direct)
    parents = [row for row in direct['processes'] if row['kind'] == 'raster_windows']
    _require(type(entries) is list and len(entries) == len(parents), 'missing or extra raster windows')
    windows = []
    for row, entry in zip(parents,entries,strict=True):
        accepted = validate_window(row,entry)
        for child in accepted['observation']['processes']:
            _require(child['pid'] not in pids, 'nested raster PID collision')
            pids.add(child['pid'])
        windows.append(accepted)
    observed = sum(item['observation']['observed_spawns'] for item in windows)
    _require(observed == reserved == pages + len(parents), 'nested raster count or reservation differs')
    return _seal({'schema':LEDGER_SCHEMA,'state':'DECLARED_RASTER_CHILDREN_RECONCILED',
        'direct_ledger_sha256':direct['ledger_sha256'],'observed_spawns':observed,
        'observed_exits':observed,'covered_pages':pages,'covered_raster_windows':len(windows),
        'reserved_nested_attempts':reserved,'unmatched_reserved_nested_attempts':0,
        'declared_retries':0,'windows':windows,'timer_helper_processes_added':0,
        'arbitrary_descendants_observed':False,'aggregate_job_resources_qualified':False,
        'release_authorized':False},'ledger_sha256',MAX_LEDGER_BYTES)


def validate_raster_ledger(value, direct):
    """Rebuild every association, refusing rehashed changes and unknown fields."""
    _require(type(value) is dict and type(value.get('windows')) is list
             and 1 <= len(value['windows']) <= 16,'raster ledger shape')
    value = _bounded(value,MAX_LEDGER_BYTES)
    entries = []
    for window in value['windows']:
        _require(type(window) is dict and set(window) ==
                 {'sequence','inspection','observation','raster_receipt_sha256'}, 'raster window fields')
        entries.append({k:window[k] for k in ('sequence','inspection','observation')})
    rebuilt = build_raster_ledger(direct,entries)
    _require(_json_bytes(value) == _json_bytes(rebuilt),'raster ledger changed')
    return rebuilt


def _native_binding(result, direct, ledger):
    """Bind actual nested geometry to the sealed whole-job raster receipts."""
    from reporting import pdf_native_source_job as native
    _require(type(result) is native.PdfNativeSourceResult, 'native raster result type')
    result_bytes = result.to_bytes()
    fields = {'schema','state','inspection_sha256','direct_process_ledger','generation_observed',
              'nested_processes_observed','external_observer_measured','authenticated_worker_execution',
              'aggregate_job_resources_qualified','native_profile_qualified','default_pipeline_activated',
              'release_authorized','observation_sha256',*_IDENTITY}
    _require(type(direct) is dict and set(direct) == fields,'native direct observation shape')
    direct = _bounded(direct,native.MAX_OBSERVATION_BYTES); _digest(direct,'observation_sha256')
    _require(direct['schema'] == native.OBSERVATION_SCHEMA
             and direct['state'] == 'COMPLETE_DIRECT_INSPECTION_JOB_OBSERVED'
             and direct['inspection_sha256'] == sha256(result_bytes).hexdigest()
             and _json_bytes({k:direct[k] for k in _IDENTITY}) ==
                 _json_bytes({k:getattr(result,k) for k in _IDENTITY}), 'native direct observation context')
    _require(all(direct[k] is False for k in ('generation_observed','nested_processes_observed',
             'external_observer_measured','authenticated_worker_execution','aggregate_job_resources_qualified',
             'native_profile_qualified','default_pipeline_activated','release_authorized')), 'native direct scope changed')
    bound = validate_raster_ledger(ledger,direct['direct_process_ledger'])
    rows = direct['direct_process_ledger']['processes']
    _require(all(row['pdf_sha256'] == result.pdf_sha256 and row['ir_sha256'] == result.ir_sha256
                 and row['page_count'] == result.page_count for row in rows)
             and rows[0]['plan_sha256'] == result.plan_sha256, 'native parent rows differ from result')
    inventory = result.structured_inspection.source_inspection.inspection_set.to_dict()
    spans = inventory['page_bundle']['raster_stream']['receipts']
    _require(len(spans) == len(bound['windows']), 'sealed raster result coverage differs')
    for index,(span,window) in enumerate(zip(spans,bound['windows'],strict=True)):
        identity = window['observation']['identity']
        _require(span['index'] == index and span['first_page'] == identity['first_page']
                 and span['last_page'] == identity['last_page']
                 and span['observation_sha256'] == window['raster_receipt_sha256'],
                 'nested raster receipt not in accepted result')
    return direct, bound


def _compose(result, direct, ledger, generated):
    """Construct a new envelope without altering original result or direct v1 records."""
    if generated:
        from reporting import pdf_generated_source_job as job
        _require(type(result) is job.PdfGeneratedSourceResult, 'generated raster result type')
        _require(type(direct) is dict, 'generated direct observation type')
        rebuilt = job._generated_process_observation(result,direct.get('render_process'),direct.get('native_observation'))
        _require(_json_bytes(rebuilt) == _json_bytes(direct), 'generated direct observation changed')
        native_direct,bound = _native_binding(result.native_inspection,direct['native_observation'],ledger)
        direct_count = direct['observed_direct_spawns']
        render_pid = direct['render_process']['pid']
        all_pids = [row['pid'] for row in native_direct['direct_process_ledger']['processes']]
        all_pids += [row['pid'] for window in bound['windows'] for row in window['observation']['processes']]
        _require(render_pid not in all_pids,'renderer identity collides with inspection children')
        context = {k:getattr(result,k) for k in (*_IDENTITY,'html_sha256')}
        digest = {'generated_result_sha256':sha256(result.to_bytes()).hexdigest()}
    else:
        direct,bound = _native_binding(result,direct,ledger)
        direct_count = direct['direct_process_ledger']['observed_spawns']
        context = {k:getattr(result,k) for k in _IDENTITY}
        digest = {'inspection_sha256':sha256(result.to_bytes()).hexdigest()}
    total = direct_count + bound['observed_spawns']
    return _seal({'schema':GENERATED_SCHEMA if generated else NATIVE_SCHEMA,
        'state':'DECLARED_RASTER_CHILDREN_LINKED',**context,**digest,
        'direct_observation':direct,'raster_child_ledger':bound,
        'observed_direct_spawns':direct_count,'observed_direct_exits':direct_count,
        'observed_nested_spawns':bound['observed_spawns'],'observed_nested_exits':bound['observed_exits'],
        'observed_total_spawns':total,'observed_total_exits':total,'declared_retries':0,
        **{k:False for k in _FALSE}},'observation_sha256',MAX_ENVELOPE_BYTES)


def compose_native(result, direct, ledger):
    """Return a detached native-job envelope for exact direct and raster evidence."""
    return _compose(result,direct,ledger,False)


def compose_generated(result, direct, ledger):
    """Return a detached generated-job envelope with the same accepted source/PDF."""
    return _compose(result,direct,ledger,True)


def _validate(result, value, generated):
    """Closed equality includes nested evidence, context and every unqualified claim."""
    _require(type(value) is dict,'raster job envelope shape')
    value = _bounded(value,MAX_ENVELOPE_BYTES)
    rebuilt = _compose(result,value.get('direct_observation'),value.get('raster_child_ledger'),generated)
    _require(_json_bytes(value) == _json_bytes(rebuilt),'raster job envelope differs')
    return rebuilt


def validate_native(result, value):
    """Validate native composition without launching workers or writing outcomes."""
    return _validate(result,value,False)


def validate_generated(result, value):
    """Validate generated composition without granting persistence or release authority."""
    return _validate(result,value,True)
