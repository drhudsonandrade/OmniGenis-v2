"""Actual raster child records propagate through one generated qualification job."""
from __future__ import annotations
from copy import deepcopy
from hashlib import sha256
import importlib
import inspect
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from reporting import pdf_generated_source_job as generated
from reporting import pdf_native_source_job as native
from reporting import pdf_qualification_job as qualified
from reporting import _pdf_native_launch_budget as budget
from tests import test_reporting_pdf_generated_source_job as fixtures

MODE = 'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE'
DISABLE = 'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED'


def canonical(value):
    """Encode independently for mutation tests without accepting resealed lies."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode()


def reseal(value, field='observation_sha256'):
    """Update only a descriptive digest after deliberately invalid metadata changes."""
    value[field] = sha256(canonical({k:v for k,v in value.items() if k != field})).hexdigest()


class JobRasterObservationTests(unittest.TestCase):
    """Bind actual per-window children to the same completed generated result."""

    completed = {}

    def setUp(self):
        """Refuse a missing API before generating any expensive fixture."""
        self.assertTrue(callable(getattr(generated, 'execute_raster_observed_pdf_generated_source_job', None)),
                        'integrated generated raster observation API missing')
        self.assertTrue(callable(getattr(native, 'execute_raster_observed_pdf_native_source_job', None)),
                        'integrated native raster observation API missing')
        self.m = importlib.import_module('reporting._pdf_raster_job_observation')
        self.helper = fixtures.GeneratedSourceJobTests(); self.helper.setUp()
        budget.require_no_active_scope()

    def arguments(self, count=2, **changes):
        """Use existing admitted synthetic source and independent expectations."""
        return self.helper.arguments(fixtures.source(count), **changes)

    def positive(self, count=2):
        """Cache only an actual public invocation; return a detached observation copy."""
        if count not in type(self).completed:
            args = self.arguments(count)
            before = canonical(args['presentation_ir'])
            result, observation = generated.execute_raster_observed_pdf_generated_source_job(**args)
            self.assertEqual(canonical(args['presentation_ir']), before)
            type(self).completed[count] = result, canonical(observation)
        result, raw = type(self).completed[count]
        return result, json.loads(raw)

    def reject(self, mutate):
        """Rehash deliberately altered records, requiring semantic rejection."""
        result, record = self.positive()
        mutate(record)
        reseal(record['raster_child_ledger'], 'ledger_sha256')
        reseal(record)
        with self.assertRaises(ValueError): self.m.validate_generated(result, record)

    def test_real_short_and_35_page_jobs_account_for_nested_children(self):
        """One real generation binds each probe and page child to its direct worker."""
        for count in (2, 1680):
            result, record = self.positive(count)
            pages = result.page_count; windows = (pages+3)//4
            direct_count = 22 + (pages+15)//16 + windows
            ledger = record['raster_child_ledger']
            self.assertEqual(record['observed_direct_spawns'], direct_count)
            self.assertEqual(record['observed_nested_spawns'], pages+windows)
            self.assertEqual(record['observed_total_spawns'], direct_count+pages+windows)
            self.assertEqual(record['observed_total_exits'], record['observed_total_spawns'])
            self.assertEqual(ledger['unmatched_reserved_nested_attempts'], 0)
            self.assertEqual(ledger['covered_pages'], pages)
            self.assertEqual(ledger['covered_raster_windows'], windows)
            rows = [row for entry in ledger['windows'] for row in entry['observation']['processes']]
            self.assertEqual(sum(row['kind']=='version_probe' for row in rows), windows)
            self.assertEqual([row['page'] for row in rows if row['kind']=='raster_page'], list(range(1,pages+1)))
            self.assertEqual(len({row['pid'] for row in rows}),len(rows))
            if count == 1680:
                self.assertEqual(pages,35); self.assertEqual(len(rows),44)
                self.assertEqual(record['observed_total_spawns'],78)
            self.assertEqual(self.m.validate_generated(result,record), record)

    def test_native_entry_reuses_same_pdf_and_result(self):
        """The new native entry inspects the identical PDF and canonical source result."""
        result, record = self.positive()
        args=self.arguments()
        found, observed=native.execute_raster_observed_pdf_native_source_job(
            **{**args, 'pdf_bytes':result.pdf_bytes, 'expected_pdf_sha256':result.pdf_sha256,
               'page_count':result.page_count, 'expected_resource_profile_sha256':native.PROFILE_SHA256})
        self.assertEqual(found.to_bytes(), result.native_inspection.to_bytes())
        self.assertEqual(self.m.validate_native(found,observed),observed)
        self.assertEqual(observed['observed_total_spawns'],25)

    def test_new_signatures_match_direct_only_entrypoints(self):
        """No callback, caller budget, process, plan or receipt can be injected."""
        for old,new in ((generated.execute_observed_pdf_generated_source_job,
                         generated.execute_raster_observed_pdf_generated_source_job),
                        (native.execute_observed_pdf_native_source_job,
                         native.execute_raster_observed_pdf_native_source_job)):
            self.assertEqual(list(inspect.signature(old).parameters), list(inspect.signature(new).parameters))

    def test_legacy_direct_observation_retains_its_schema_and_nonclaims(self):
        """The established direct-only API neither returns nor silently collects nested data."""
        with patch.object(budget, 'record_raster_child_observation', side_effect=AssertionError('nested collection')):
            result, record=generated.execute_observed_pdf_generated_source_job(**self.arguments())
        self.assertEqual(record['schema'],generated.OBSERVATION_SCHEMA)
        self.assertNotIn('raster_child_ledger',record)
        self.assertIs(record['nested_processes_observed'],False)
        self.assertEqual(result.page_count,1)

    def test_original_direct_record_is_preserved_inside_new_envelope(self):
        """The v1 record stays internally truthful; the separate ledger reconciles reserves."""
        result, record=self.positive();direct=record['direct_observation']
        rebuilt=generated._generated_process_observation(result,direct['render_process'],direct['native_observation'])
        self.assertEqual(direct,rebuilt)
        self.assertIs(direct['nested_processes_observed'],False)
        self.assertEqual(direct['native_observation']['direct_process_ledger']['reserved_nested_attempts_not_observed'],2)
        self.assertEqual(record['raster_child_ledger']['observed_spawns'],2)

    def test_nested_geometry_receipts_match_the_sealed_result(self):
        """The observed execution is linked to the actual accepted raster receipt, not just PDF hashes."""
        result,record=self.positive()
        original=result.native_inspection.structured_inspection.source_inspection.inspection_set.to_dict()
        spans=original['page_bundle']['raster_stream']['receipts']
        self.assertEqual([e['raster_receipt_sha256'] for e in record['raster_child_ledger']['windows']],
                         [e['observation_sha256'] for e in spans])

    def test_all_unqualified_guarantees_remain_false(self):
        """Fixed recorded children never become authentication, whole-tree or release proof."""
        _,record=self.positive()
        for key in ('whole_graph_observed','authenticated_worker_execution','aggregate_job_resources_qualified',
                    'native_profile_qualified','external_observer_measured','default_pipeline_activated','release_authorized'):
            self.assertIs(record[key],False)
        self.assertIs(record['raster_child_ledger']['arbitrary_descendants_observed'],False)
        self.assertEqual(record['raster_child_ledger']['timer_helper_processes_added'],0)

    def test_canonical_byte_caps_and_detached_exports(self):
        """Bounded new envelopes do not alter the existing per-window wire limit."""
        result,record=self.positive(1680)
        self.assertLessEqual(len(canonical(record)),self.m.MAX_ENVELOPE_BYTES)
        self.assertLessEqual(len(canonical(record['raster_child_ledger'])),self.m.MAX_LEDGER_BYTES)
        self.assertEqual(self.m.MAX_ENVELOPE_BYTES,128*1024)
        self.assertEqual(self.m.MAX_LEDGER_BYTES,64*1024)
        detached=self.m.validate_generated(result,record)
        detached['raster_child_ledger']['windows'].clear()
        self.assertEqual(len(record['raster_child_ledger']['windows']),9)
        from reporting import pdf_raster_windows as raster
        self.assertEqual(raster.RESULT_BYTES,4096)

    def test_missing_extra_or_reordered_windows_refuse(self):
        """Every admitted raster interval has exactly one matching record in order."""
        result,original=self.positive(1680)
        for op in ('missing','extra','reorder'):
            record=deepcopy(original);rows=record['raster_child_ledger']['windows']
            if op=='missing':rows.pop()
            elif op=='extra':rows.append(deepcopy(rows[-1]))
            else:rows[0],rows[1]=rows[1],rows[0]
            reseal(record['raster_child_ledger'],'ledger_sha256');reseal(record)
            with self.subTest(op=op),self.assertRaises(ValueError):self.m.validate_generated(result,record)

    def test_rehashed_counts_and_boolean_counts_refuse(self):
        """Neither rehashing nor Python boolean/int equality can forge coverage."""
        for key in ('observed_spawns','observed_exits','covered_pages','covered_raster_windows','unmatched_reserved_nested_attempts'):
            for value in (True,-1,999):
                with self.subTest(key=key,value=value):self.reject(lambda r:r['raster_child_ledger'].__setitem__(key,value))

    def test_unknown_ledger_envelope_and_window_fields_refuse(self):
        """Closed schemas do not admit unreviewed claims or content-bearing fields."""
        for where in ('envelope','ledger','window'):
            def mutate(r):
                """Select a closed metadata boundary for an unknown-field injection."""
                target=r if where=='envelope' else (r['raster_child_ledger'] if where=='ledger' else r['raster_child_ledger']['windows'][0])
                target['unexpected']='not allowed'
            with self.subTest(where=where):self.reject(mutate)

    def test_wrong_direct_worker_or_sequence_refuses(self):
        """A child record cannot migrate to a different enclosing direct process."""
        for field in ('sequence','worker_pid'):
            def mutate(r):
                """Change either direct-row association or nested creator identity."""
                e=r['raster_child_ledger']['windows'][0]
                if field=='sequence':e['sequence']+=1
                else:e['observation']['worker_pid']+=1;reseal(e['observation'])
            with self.subTest(field=field):self.reject(mutate)

    def test_wrong_nested_parent_or_pid_collision_refuses(self):
        """Nested PIDs must be distinct and belong to their exact recorded worker."""
        for field in ('parent_pid','pid'):
            def mutate(r):
                """Forge one child identity and rehash its descriptive wire."""
                e=r['raster_child_ledger']['windows'][0];o=e['observation']
                previous=o['processes'][0][field]
                o['processes'][0][field]=o['worker_pid']+1 if field=='parent_pid' else o['worker_pid']
                self.assertNotEqual(o['processes'][0][field],previous)
                reseal(o)
            with self.subTest(field=field):self.reject(mutate)

    def test_nested_clock_must_fit_direct_lifetime(self):
        """A child cannot appear before the enclosing worker or after its reap."""
        for field,value in (('observed_spawn_ns',0),('observed_exit_ns',(1<<63)-1)):
            def mutate(r):
                """Move one parent-observed event outside the enclosing lifetime."""
                o=r['raster_child_ledger']['windows'][0]['observation'];o['processes'][0][field]=value;reseal(o)
            with self.subTest(field=field):self.reject(mutate)

    def test_changed_source_plan_and_page_bindings_refuse(self):
        """Rehashed nested metadata cannot describe a different source or interval."""
        for field,value in (('pdf_sha256','d'*64),('ir_sha256','e'*64),('plan_sha256','f'*64),('first_page',2)):
            def mutate(r):
                """Change one request identity field inside the nested record."""
                o=r['raster_child_ledger']['windows'][0]['observation'];o['identity'][field]=value;reseal(o)
            with self.subTest(field=field):self.reject(mutate)

    def test_changed_inspection_cannot_keep_same_final_result(self):
        """A fully resealed per-window geometry alteration disagrees with the sealed result."""
        result,record=self.positive();e=record['raster_child_ledger']['windows'][0]
        e['inspection']['raster_sha256']='d'*64
        e['observation']['inspection_sha256']=sha256(canonical(e['inspection'])).hexdigest();reseal(e['observation'])
        direct=record['direct_observation']['native_observation']['direct_process_ledger']
        entries=[{'sequence':x['sequence'],'inspection':x['inspection'],'observation':x['observation']}
                 for x in record['raster_child_ledger']['windows']]
        record['raster_child_ledger']=self.m.build_raster_ledger(direct,entries);reseal(record)
        with self.assertRaises(ValueError):self.m.validate_generated(result,record)

    def test_changed_tool_and_launcher_hashes_refuse(self):
        """Execution source identities remain pinned independently of descriptive hashes."""
        for field in ('tool_sha256','launcher_sha256'):
            def mutate(r):
                """Change a tool or fixed-launcher source fingerprint."""
                o=r['raster_child_ledger']['windows'][0]['observation']
                if field=='tool_sha256':o[field]='f'*64
                else:o['processes'][0][field]='f'*64
                reseal(o)
            with self.subTest(field=field):self.reject(mutate)

    def test_outer_job_and_result_identity_cannot_change(self):
        """The envelope describes this result and namespace/job, not another attempt."""
        for field in ('generated_result_sha256','job_id','resource_profile_sha256'):
            with self.subTest(field=field):self.reject(lambda r:r.__setitem__(field,'f'*64))

    def test_nonclaims_cannot_be_promoted_by_rehash(self):
        """Success here never certifies an unrelated execution or release guarantee."""
        for key in ('whole_graph_observed','release_authorized','native_profile_qualified'):
            with self.subTest(key=key):self.reject(lambda r:r.__setitem__(key,True))

    def test_nested_record_failure_refuses_complete_generated_job(self):
        """A real completed raster child with missing association cannot yield a job result."""
        with patch.object(budget,'record_raster_child_observation',side_effect=ValueError('synthetic association failure')):
            with self.assertRaises(generated.PdfGeneratedSourceJobError):
                generated.execute_raster_observed_pdf_generated_source_job(**self.arguments())
        budget.require_no_active_scope()

    def test_missing_worker_observation_refuses_without_partial_result(self):
        """A valid geometry reply alone is insufficient under the explicit nested mode."""
        from reporting import pdf_raster_windows as raster
        original=raster._run_worker
        def omit(*args,**kwargs):
            """Capture actual work, removing only its newly required observation field."""
            raw,pid=original(*args,**kwargs);record=json.loads(raw);record.pop('process_observation')
            return canonical(record),pid
        with patch.object(raster,'_run_worker',side_effect=omit):
            with self.assertRaises(generated.PdfGeneratedSourceJobError):
                generated.execute_raster_observed_pdf_generated_source_job(**self.arguments())
        budget.require_no_active_scope()

    def test_disable_during_composition_refuses(self):
        """Optional metadata assembly cannot bypass the generator's last policy check."""
        original=self.m.compose_generated
        def disable(*args,**kwargs):
            """Disable only after the real bounded composition has completed."""
            value=original(*args,**kwargs);os.environ['OMNIGENIS_PDF_GENERATED_SOURCE_JOB_DISABLED']='1';return value
        with patch.dict(os.environ,{}),patch.object(self.m,'compose_generated',side_effect=disable):
            with self.assertRaises(generated.PdfGeneratedSourceJobError):
                generated.execute_raster_observed_pdf_generated_source_job(**self.arguments())

    def test_invalid_input_does_not_launch(self):
        """Input refusal still precedes rendering and scope activation."""
        with patch.object(generated,'_render_pdf_candidate',side_effect=AssertionError('launched')):
            with self.assertRaises(generated.PdfGeneratedSourceJobError):
                generated.execute_raster_observed_pdf_generated_source_job(**self.arguments(expected_ir_sha256='f'*64))

    def test_scope_poisoning_from_foreign_access_refuses(self):
        """The explicit operation does not permit an already-active unrelated scope."""
        result,_=self.positive()
        from reporting.page_windows import plan_pdf_page_windows
        plan=plan_pdf_page_windows(pdf_sha256=result.pdf_sha256,ir_sha256=result.ir_sha256,
            page_count=1,admitted_page_budget=1,pages_per_window=16,inspector_profile_id=budget.TEXT_PROFILE)
        with budget.NativeLaunchScope(plan,len(result.pdf_bytes)):
            with self.assertRaises(generated.PdfGeneratedSourceJobError):
                generated.execute_raster_observed_pdf_generated_source_job(**self.arguments())


    def test_real_64_page_native_boundary_has_121_observed_children(self):
        """The unchanged maximum native page class fits the new bounded ledger."""
        from tests.test_reporting_pdf_source_inspection_job import generated_job_case
        from reporting.pdf_content import _expected_content
        ir,pdf=generated_job_case(64)
        args=self.arguments()
        result,record=native.execute_raster_observed_pdf_native_source_job(
            **{**args,'presentation_ir':ir,'expected_ir_sha256':_expected_content(ir)[0],
               'pdf_bytes':pdf,'expected_pdf_sha256':sha256(pdf).hexdigest(),'page_count':64,
               'expected_resource_profile_sha256':native.PROFILE_SHA256})
        self.assertEqual(record['observed_direct_spawns'],41)
        self.assertEqual(record['observed_nested_spawns'],80)
        self.assertEqual(record['observed_total_spawns'],121)
        self.assertEqual(record['raster_child_ledger']['covered_raster_windows'],16)
        self.assertLessEqual(len(canonical(record)),self.m.MAX_ENVELOPE_BYTES)
        self.assertEqual(self.m.validate_native(result,record),record)

    def test_swallowed_association_cannot_complete(self):
        """Even a silently omitted last-window registration prevents scope completion."""
        with patch.object(budget,'record_raster_child_observation',return_value=None):
            with self.assertRaises(generated.PdfGeneratedSourceJobError):
                generated.execute_raster_observed_pdf_generated_source_job(**self.arguments())
        budget.require_no_active_scope()

    def test_duplicate_association_poisoning_prevents_acceptance(self):
        """A second record for the same actual direct worker cannot be counted twice."""
        original=budget.record_raster_child_observation
        def duplicate(*args,**kwargs):
            """Replay only the record call, never the native worker itself."""
            original(*args,**kwargs);original(*args,**kwargs)
        with patch.object(budget,'record_raster_child_observation',side_effect=duplicate):
            with self.assertRaises(generated.PdfGeneratedSourceJobError):
                generated.execute_raster_observed_pdf_generated_source_job(**self.arguments())
        budget.require_no_active_scope()


class ReceiptedRasterObservationTests(unittest.TestCase):
    """Existing qualification policy and durable outcome apply to the same observed attempt."""

    def setUp(self):
        """Assert new behavior before creating private fixture storage."""
        self.assertTrue(callable(getattr(qualified,'execute_raster_observed_receipted_pdf_generated_source_job',None)),
                        'integrated receipted raster observation API missing')
        self.helper=fixtures.GeneratedSourceJobTests();self.helper.setUp()
        self.env=patch.dict(os.environ,{MODE:'qualification-only'});self.env.start();self.addCleanup(self.env.stop)
        os.environ.pop(DISABLE,None)
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.run_id='a'*32

    def args(self, **changes):
        """Bind the same fixed source and local attempt independently."""
        return {**self.helper.arguments(fixtures.source(2)), 'receipt_directory':self.root,
                'run_id':self.run_id, **changes}

    def pair(self):
        """Use genuine generated records for isolated persistence fault tests."""
        helper=JobRasterObservationTests();helper.setUp();return helper.positive()

    def invoke(self, **changes):
        """Call only the explicit new qualification entrypoint."""
        return qualified.execute_raster_observed_receipted_pdf_generated_source_job(**self.args(**changes))

    def stored(self):
        """Locate the existing computation receipt without implying PDF persistence."""
        return self.root/self.run_id/(self.run_id+'.json')

    def test_actual_attempt_binds_nested_ledger_and_durable_outcome(self):
        """A real invocation returns one result/observation/outcome with no rerender."""
        result,record,outcome=self.invoke()
        self.assertEqual(record['generated_result_sha256'],result.result_sha256)
        self.assertEqual(outcome['result_sha256'],result.result_sha256)
        self.assertEqual(record['observed_total_spawns'],26)
        self.assertEqual(outcome,json.loads(self.stored().read_bytes()))
        self.assertIs(outcome['release_authorized'],False)
        self.assertEqual(list((self.root/self.run_id).iterdir()),[self.stored()])

    def test_signature_and_default_disabled_policy_preserved(self):
        """The new call adds no caller-controlled executor or additional permission."""
        self.assertEqual(list(inspect.signature(qualified.execute_observed_receipted_pdf_generated_source_job).parameters),
                         list(inspect.signature(qualified.execute_raster_observed_receipted_pdf_generated_source_job).parameters))
        with patch.dict(os.environ,{}):
            os.environ.pop(MODE,None)
            with patch.object(generated,'execute_raster_observed_pdf_generated_source_job',side_effect=AssertionError('launched')):
                with self.assertRaises(qualified.PdfQualificationJobError):self.invoke()
        self.assertEqual(list(self.root.iterdir()),[])

    def test_duplicate_attempt_refuses_before_generation(self):
        """A stored run cannot be retried automatically by choosing this entrypoint."""
        with patch.object(generated,'execute_raster_observed_pdf_generated_source_job',return_value=self.pair()):self.invoke()
        with patch.object(generated,'execute_raster_observed_pdf_generated_source_job',side_effect=AssertionError('rerun')):
            with self.assertRaises(qualified.PdfQualificationJobError):self.invoke()

    def test_invalid_nested_record_persists_failed_not_success(self):
        """Missing nested metadata fails before committing a successful computation."""
        result,record=self.pair();record['raster_child_ledger']['windows'].clear()
        with patch.object(generated,'execute_raster_observed_pdf_generated_source_job',return_value=(result,record)):
            with self.assertRaises(qualified.PdfQualificationJobError):self.invoke()
        self.assertEqual(json.loads(self.stored().read_bytes())['state'],'FAILED')

    def test_mutation_during_persist_refuses_return_without_overwrite(self):
        """A postcommit refusal may retain SUCCEEDED but cannot return altered evidence."""
        pair=self.pair();original=qualified._persist
        def alter(*args,**kwargs):
            """Preserve actual receipt I/O, then corrupt only the retained observation."""
            result=original(*args,**kwargs);pair[1]['raster_child_ledger']['windows'].clear();return result
        with patch.object(generated,'execute_raster_observed_pdf_generated_source_job',return_value=pair), \
             patch.object(qualified,'_persist',side_effect=alter):
            with self.assertRaises(qualified.PdfQualificationJobError):self.invoke()
        self.assertEqual(json.loads(self.stored().read_bytes())['state'],'SUCCEEDED')

    def test_recovery_never_reruns_or_reconstructs_observation(self):
        """Existing recovery reads only the expected computation receipt."""
        pair=self.pair()
        with patch.object(generated,'execute_raster_observed_pdf_generated_source_job',return_value=pair):
            result,record,outcome=self.invoke()
        with patch.object(generated,'execute_raster_observed_pdf_generated_source_job',side_effect=AssertionError('rerun')):
            recovered=qualified.read_qualification_job_outcome(receipt_directory=self.root,run_id=self.run_id,
                                                              state='SUCCEEDED',result_sha256=result.result_sha256)
        self.assertEqual(recovered,outcome);self.assertNotIn('raster_child_ledger',recovered)

    def test_generation_interrupt_keeps_exception_and_failed_record(self):
        """An interrupted observed job cannot become a successful durable outcome."""
        failure=KeyboardInterrupt('synthetic interrupt')
        with patch.object(generated,'execute_raster_observed_pdf_generated_source_job',side_effect=failure):
            with self.assertRaises(KeyboardInterrupt) as caught:self.invoke()
        self.assertIs(caught.exception,failure)
        self.assertEqual(json.loads(self.stored().read_bytes())['state'],'FAILED')


    def test_disable_after_persistence_refuses_return(self):
        """Committed computation metadata does not override a final policy disable."""
        original=qualified._persist
        def disable(*args,**kwargs):
            """Keep the real durable write, then disable before the final recheck."""
            value=original(*args,**kwargs);os.environ[DISABLE]='1';return value
        with patch.object(generated,'execute_raster_observed_pdf_generated_source_job',return_value=self.pair()), \
             patch.object(qualified,'_persist',side_effect=disable):
            with self.assertRaises(qualified.PdfQualificationJobError):self.invoke()
        self.assertEqual(json.loads(self.stored().read_bytes())['state'],'SUCCEEDED')


if __name__ == '__main__': unittest.main()
