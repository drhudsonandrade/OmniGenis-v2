"""Exact-plan nested raster child observations without changing default receipts."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tests.test_reporting_pdf_text_windows import fixture_pdf


def canonical(value):
    """Use a closed deterministic encoding for explicitly synthetic mutations."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


class RasterProcessObservationTests(unittest.TestCase):
    """Check real children and refusal of rehashed but semantically false metadata."""

    def setUp(self):
        """Require the optional API before creating a native fixture."""
        self.m = importlib.import_module('reporting.pdf_raster_windows')
        self.assertTrue(callable(getattr(self.m, 'inspect_observed_pdf_raster_window', None)),
                        'observed raster window API missing')
        self.w = importlib.import_module('reporting._pdf_raster_window_worker')
        self.h = importlib.import_module('reporting._pdf_raster_child_observation')
        from reporting.page_windows import plan_pdf_page_windows
        self.pdf = fixture_pdf(5)
        self.plan = plan_pdf_page_windows(pdf_sha256=hashlib.sha256(self.pdf).hexdigest(),
            ir_sha256='b'*64, page_count=5, admitted_page_budget=5,
            pages_per_window=4, inspector_profile_id=self.m.PROFILE_ID)

    def arguments(self, **changes):
        """Return only the existing four public source/plan expectations."""
        return dict(pdf_bytes=self.pdf, plan=self.plan, window_index=0,
                    expected_plan_sha256=self.plan.plan_sha256, **changes)

    def observed(self, index=0):
        """Run the actual guarded window and all its selected child processes."""
        a = self.arguments(); a['window_index'] = index
        return self.m.inspect_observed_pdf_raster_window(**a)

    @classmethod
    def cached_wire(cls):
        """Generate one genuine finite reply; every mutation gets a detached copy."""
        if not hasattr(cls, '_wire'):
            from reporting import pdf_raster_windows as m
            from reporting.page_windows import plan_pdf_page_windows
            pdf = fixture_pdf(4)
            plan = plan_pdf_page_windows(pdf_sha256=hashlib.sha256(pdf).hexdigest(), ir_sha256='b'*64,
                page_count=4, admitted_page_budget=4, pages_per_window=4, inspector_profile_id=m.PROFILE_ID)
            identity = dict(pdf_sha256=plan.pdf_sha256, ir_sha256=plan.ir_sha256,
                plan_sha256=plan.plan_sha256, page_count=4, window_index=0, first_page=1, last_page=4)
            raw, pid = m._run_worker(pdf, identity, observe_processes=True)
            cls._wire = (json.loads(raw), pid, identity)
        return deepcopy(cls._wire)

    def decode(self, record, pid, identity, rehash=True):
        """Rehash deliberate changes so semantic checks, not only digest checks, are tested."""
        if rehash and isinstance(record, dict) and 'process_observation' in record:
            value = record['process_observation']
            value['observation_sha256'] = hashlib.sha256(canonical({k:v for k,v in value.items()
                if k != 'observation_sha256'})).hexdigest()
        return self.m._decode_observed(canonical(record), identity, pid)

    def test_real_first_and_tail_windows_observe_every_child(self):
        """A full window observes five children and its one-page tail observes two."""
        for index, pages in ((0, [1,2,3,4]), (1, [5])):
            result, value = self.observed(index)
            self.assertEqual(value['observed_spawns'], 1 + len(pages))
            self.assertEqual(value['observed_exits'], 1 + len(pages))
            self.assertEqual([r['page'] for r in value['processes']], [None] + pages)
            self.assertEqual([r['kind'] for r in value['processes']], ['version_probe'] + ['raster_page']*len(pages))
            self.assertEqual(value['identity'], result._identity())
            self.assertTrue(all(r['exit_code']==0 and r['parent_pid']==value['worker_pid'] for r in value['processes']))
            self.assertTrue(all(r['observed_exit_ns'] >= r['observed_spawn_ns'] for r in value['processes']))
            self.assertEqual(len({r['pid'] for r in value['processes']}), 1+len(pages))
            self.assertFalse(Path('/proc',str(value['worker_pid'])).exists())
            self.assertTrue(all(not Path('/proc',str(r['pid'])).exists() for r in value['processes']))

    def test_native_all_35_pages_account_for_44_nested_launches(self):
        """All nine windows record actual 9 probes plus 35 page processes, not reserves."""
        from reporting.page_windows import plan_pdf_page_windows
        pdf=fixture_pdf(35);plan=plan_pdf_page_windows(pdf_sha256=hashlib.sha256(pdf).hexdigest(),
            ir_sha256='b'*64,page_count=35,admitted_page_budget=35,pages_per_window=4,
            inspector_profile_id=self.m.PROFILE_ID)
        rows=[];covered=[]
        for index in range(plan.window_count):
            result, value = self.m.inspect_observed_pdf_raster_window(pdf_bytes=pdf,plan=plan,
                window_index=index,expected_plan_sha256=plan.plan_sha256)
            rows.extend(value['processes']);covered.extend(range(result.first_page,result.last_page+1))
        self.assertEqual(len(rows),44)
        self.assertEqual(sum(r['kind']=='version_probe' for r in rows),9)
        self.assertEqual([r['page'] for r in rows if r['kind']=='raster_page'],list(range(1,36)))
        self.assertEqual(covered,list(range(1,36)))
        self.assertEqual(len({r['pid'] for r in rows}),44)

    def test_legacy_receipt_and_signature_remain_identical(self):
        """Observation is an additional result, not a new raster geometry outcome."""
        legacy=self.m.inspect_pdf_raster_window(**self.arguments())
        observed, value=self.observed()
        self.assertEqual(legacy.to_dict(),observed.to_dict())
        self.assertEqual(legacy.observation_sha256,observed.observation_sha256)
        self.assertEqual(list(inspect.signature(self.m.inspect_pdf_raster_window).parameters),
                         list(inspect.signature(self.m.inspect_observed_pdf_raster_window).parameters))
        self.assertEqual(value['declared_retries'],0)

    def test_default_worker_reply_has_no_process_observation(self):
        """Existing calls retain the original five-key wire without environment opt-in."""
        _,_,identity=self.cached_wire()
        pdf=fixture_pdf(4)
        raw=self.m._run_worker(pdf,identity)
        self.assertEqual(set(json.loads(raw)),{'protocol_version','profile_id','identity','limits','inspection'})

    def test_observation_hash_and_nonclaims_are_exact(self):
        """The detached hash binds all metadata without claiming full job or authenticated exec."""
        _,value=self.observed(1)
        self.assertEqual(value['observation_sha256'],hashlib.sha256(canonical({k:v for k,v in value.items()
            if k!='observation_sha256'})).hexdigest())
        for key in ('authenticated_worker_execution','aggregate_job_resources_qualified',
                    'arbitrary_descendants_observed','release_authorized'):
            self.assertIs(value[key],False)
        self.assertNotIn('pdf_bytes',value);self.assertNotIn('command',canonical(value).decode())

    def test_default_disabled_and_platform_refuse_before_launch(self):
        """Both entry points retain the existing fail-closed disable and platform guards."""
        with patch.object(self.m,'_run_worker',side_effect=AssertionError('launched')):
            with patch.dict(os.environ,{'OMNIGENIS_PDF_RASTER_WINDOWS_DISABLED':'1'}):
                with self.assertRaises(self.m.PdfRasterWindowError):self.observed()
            with patch.object(self.m.sys,'platform','unsupported'):
                with self.assertRaises(self.m.PdfRasterWindowError):self.observed()

    def test_invalid_inputs_refuse_before_launch(self):
        """The optional route cannot admit mutable data or a foreign plan digest."""
        with patch.object(self.m,'_run_worker',side_effect=AssertionError('launched')):
            for key,value in [('pdf_bytes',bytearray(self.pdf)),('plan',None),('window_index',True),
                              ('expected_plan_sha256','f'*64)]:
                arguments=self.arguments();arguments[key]=value
                with self.assertRaises(self.m.PdfRasterWindowError):
                    self.m.inspect_observed_pdf_raster_window(**arguments)

    def test_observed_wire_keeps_existing_4096_byte_limit(self):
        """Full observations fit the original worker output budget without a relaxed cap."""
        record,pid,identity=self.cached_wire()
        self.assertLessEqual(len(canonical(record)),4096)
        self.assertEqual(self.m.RESULT_BYTES,4096)
        with self.assertRaises(self.m.PdfRasterWindowError):
            self.m._decode_observed(b'x'*4097,identity,pid)

    def test_rehashed_missing_extra_and_reordered_rows_refuse(self):
        """Reservations, omissions and permutations cannot replace the exact child schedule."""
        for change in ('missing','extra','reordered'):
            record,pid,identity=self.cached_wire();rows=record['process_observation']['processes']
            if change=='missing':rows.pop()
            elif change=='extra':rows.append(deepcopy(rows[-1]))
            else:rows[1],rows[2]=rows[2],rows[1]
            with self.subTest(change=change),self.assertRaises(self.m.PdfRasterWindowError):self.decode(record,pid,identity)

    def test_rehashed_foreign_parent_pid_and_identity_refuse(self):
        """The creating worker PID and exact PDF/plan/page context bind the returned rows."""
        for kind in ('worker','parent','identity'):
            record,pid,identity=self.cached_wire();o=record['process_observation']
            if kind=='worker':o['worker_pid']+=1
            elif kind=='parent':o['processes'][0]['parent_pid']+=1
            else:o['identity']['pdf_sha256']='c'*64
            with self.subTest(kind=kind),self.assertRaises(self.m.PdfRasterWindowError):self.decode(record,pid,identity)

    def test_rehashed_exit_or_clock_errors_refuse(self):
        """Boolean/nonzero status and reversed/overflowed clock observations are not success."""
        for key,value in [('exit_code',True),('exit_code',1),('observed_exit_ns',0),
                          ('observed_spawn_ns',-1),('observed_spawn_ns',2**63)]:
            record,pid,identity=self.cached_wire();record['process_observation']['processes'][0][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(self.m.PdfRasterWindowError):self.decode(record,pid,identity)

    def test_rehashed_count_source_and_scope_changes_refuse(self):
        """Correct hashes cannot promote forged counts, worker sources or global claims."""
        for key,value in [('observed_spawns',True),('observed_exits',99),('declared_retries',1),
                          ('release_authorized',True),('arbitrary_descendants_observed',True)]:
            record,pid,identity=self.cached_wire();record['process_observation'][key]=value
            with self.subTest(key=key),self.assertRaises(self.m.PdfRasterWindowError):self.decode(record,pid,identity)
        record,pid,identity=self.cached_wire()
        record['process_observation']['processes'][0]['launcher_sha256']='0'*64
        with self.assertRaises(self.m.PdfRasterWindowError):self.decode(record,pid,identity)

    def test_rehashed_duplicate_pid_or_wrong_page_refuse(self):
        """No repeated process or unselected page may count as an observed launch."""
        for kind in ('pid','page'):
            record,pid,identity=self.cached_wire();rows=record['process_observation']['processes']
            rows[1][kind]=rows[0]['pid'] if kind=='pid' else 99
            with self.subTest(kind=kind),self.assertRaises(self.m.PdfRasterWindowError):self.decode(record,pid,identity)

    def test_rehashed_changed_inspection_refuses(self):
        """Nested metadata cannot be combined with another otherwise valid raster result."""
        record,pid,identity=self.cached_wire();record['inspection']['raster_sha256']='e'*64
        with self.assertRaises(self.m.PdfRasterWindowError):self.decode(record,pid,identity)

    def test_unknown_keys_and_wrong_types_refuse(self):
        """Every new observation object and row has a closed type/field contract."""
        for location in ('root','row'):
            record,pid,identity=self.cached_wire();o=record['process_observation']
            (o if location=='root' else o['processes'][0])['unexpected']=True
            with self.subTest(location=location),self.assertRaises(self.m.PdfRasterWindowError):self.decode(record,pid,identity)
        record,pid,identity=self.cached_wire();record['process_observation']['worker_pid']=True
        with self.assertRaises(self.m.PdfRasterWindowError):self.decode(record,pid,identity)

    def test_duplicate_noncanonical_and_nonfinite_wire_refuse(self):
        """No duplicate JSON fields, whitespace variant or nonfinite data is accepted."""
        record,pid,identity=self.cached_wire();raw=canonical(record)
        for invalid in (raw+b' ',raw[:-1]+b',"protocol_version":1}',b'NaN',b'\xff',b''):
            with self.subTest(raw=invalid[:30]),self.assertRaises(self.m.PdfRasterWindowError):
                self.m._decode_observed(invalid,identity,pid)

    def test_returned_observation_is_detached(self):
        """Editing caller-owned observation data does not alter the cached wire or receipt."""
        record,pid,identity=self.cached_wire();before=deepcopy(record)
        receipt,value=self.decode(record,pid,identity);value['processes'].clear()
        self.assertEqual(record,before)
        self.assertEqual(len(self.decode(record,pid,identity)[1]['processes']),5)
        self.assertEqual(receipt.inspected_pages,4)

    def test_real_failure_leaves_no_success_or_scratch(self):
        """Blank selected content fails and the parent releases its private scratch/fds."""
        from reporting.page_windows import plan_pdf_page_windows
        before=len(os.listdir('/proc/self/fd'));paths=[];real=self.m._start
        def capture(command,fds,scratch):
            """Retain only the created private scratch path while spawning the actual worker."""
            paths.append(scratch);return real(command,fds,scratch)
        pdf=fixture_pdf(1,blank=1);plan=plan_pdf_page_windows(pdf_sha256=hashlib.sha256(pdf).hexdigest(),
            ir_sha256='b'*64,page_count=1,admitted_page_budget=1,pages_per_window=4,
            inspector_profile_id=self.m.PROFILE_ID)
        with patch.object(self.m,'_start',side_effect=capture):
            with self.assertRaises(self.m.PdfRasterWindowError):
                self.m.inspect_observed_pdf_raster_window(pdf_bytes=pdf,plan=plan,window_index=0,
                    expected_plan_sha256=plan.plan_sha256)
        self.assertEqual(len(paths),1);self.assertTrue(all(not Path(p).exists() for p in paths))
        self.assertEqual(len(os.listdir('/proc/self/fd')),before)

    def test_invalid_worker_mode_refuses_before_any_request(self):
        """Only the exact optional mode token can change the closed wire protocol."""
        with patch.object(self.w,'_read_request',side_effect=AssertionError('read')):
            for mode in ('observed','1','',self.h.MODE+'extra'):
                self.assertEqual(self.w.main(['worker','3','4','5','123',mode]),64)

    def test_result_mutation_after_worker_refuses(self):
        """A plan cannot change while the optional result is in flight."""
        real=self.m._run_worker
        def change(*args,**kwargs):
            """Return the real admitted reply, then mutate the caller's plan before recheck."""
            result=real(*args,**kwargs)
            object.__setattr__(self.plan,'page_count',9)
            return result
        with patch.object(self.m,'_run_worker',side_effect=change):
            with self.assertRaises(self.m.PdfRasterWindowError):self.observed()


    def test_existing_native_scope_is_not_silently_widened(self):
        """Standalone child evidence cannot bypass a currently active fixed job schedule."""
        from reporting._pdf_native_launch_budget import NativeLaunchScope
        from reporting.page_windows import plan_pdf_page_windows
        text=plan_pdf_page_windows(pdf_sha256=self.plan.pdf_sha256,ir_sha256='b'*64,page_count=5,
            admitted_page_budget=5,pages_per_window=16,inspector_profile_id='generated-pdf-text-window-v1')
        with NativeLaunchScope(text,len(self.pdf)) as scope:
            with patch.object(self.m,'_start',side_effect=AssertionError('launched')):
                with self.assertRaises(self.m.PdfRasterWindowError):self.observed()
            self.assertTrue(scope._invalid)

    def test_observed_transport_inherits_only_existing_three_descriptors(self):
        """Observation uses the existing bounded result file, not a new open channel."""
        calls=[];original=self.m._start
        def capture(command,fds,scratch):
            """Inspect launch metadata without substituting native process execution."""
            calls.append((command,fds));return original(command,fds,scratch)
        with patch.object(self.m,'_start',side_effect=capture):self.observed(1)
        self.assertEqual(len(calls),1)
        self.assertEqual(len(calls[0][1]),3)
        self.assertEqual(calls[0][0][-1],self.h.MODE)

    def test_largest_integer_widths_stay_inside_original_wire_budget(self):
        """Permitted finite metadata widths never require a larger result file."""
        record,pid,identity=self.cached_wire();o=record['process_observation'];pid=2147483647
        o['worker_pid']=pid
        for i,row in enumerate(o['processes']):
            row.update(pid=2147483600+i,parent_pid=pid,
                observed_spawn_ns=(1<<63)-100+3*i,observed_exit_ns=(1<<63)-99+3*i)
        receipt,result=self.decode(record,pid,identity)
        self.assertEqual(receipt.inspected_pages,4)
        self.assertLessEqual(len(canonical(result)),self.h.MAX_RECORD_BYTES)
        self.assertLessEqual(len(canonical(record)),self.m.RESULT_BYTES)

    def test_old_decoder_refuses_observed_wire(self):
        """An opt-in reply cannot silently cross the unchanged default protocol shape."""
        record,pid,identity=self.cached_wire()
        with self.assertRaises(self.m.PdfRasterWindowError):self.m._decode(canonical(record),identity)


if __name__ == '__main__':
    unittest.main()
