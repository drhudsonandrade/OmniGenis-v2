"""Actual declared children bind to the same completed private document operation."""
from copy import deepcopy
from hashlib import sha256
from importlib import import_module, util
import builtins
import json
import os
from pathlib import Path
from subprocess import TimeoutExpired
import tempfile
import unittest
from unittest.mock import patch

from reporting import adapters
from reporting import pdf_final_document_candidate as final
from reporting import pdf_raster_render as raster
from tests.test_reporting_pdf_bound_candidate import bound_request, canonical
from tests.test_reporting_pdf_bound_raster_candidate import bundle, long_raster_inputs

MODE = 'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE'
_ACTUAL = None
_FAILURE = None


class Inputs:
    def setUp(self):
        self.assertIsNotNone(util.find_spec('reporting._pdf_final_document_observation'),
                             'complete final-document observations are not implemented')
        self.o = import_module('reporting._pdf_final_document_observation')
        self.assertTrue(callable(getattr(final, 'execute_observed_stored_final_document_candidate', None)),
                        'observed stored operation is missing')
        env = patch.dict(os.environ, {MODE: 'qualification-only'})
        env.start(); self.addCleanup(env.stop)
        for key in ('OMNIGENIS_PDF_FINAL_DOCUMENT_DISABLED', 'OMNIGENIS_PDF_BOUND_RASTER_DISABLED',
                    'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED', 'OMNIGENIS_PDF_PRELOADED_RASTER_DISABLED',
                    'OMNIGENIS_PDF_RENDERER_DISABLED'):
            os.environ.pop(key, None)
        self.bound = bound_request(); self.assets = bundle()

    def arguments(self):
        return dict(bound_request=self.bound, resources=self.assets,
            expected_request_sha256=self.bound.request.request_sha256,
            expected_resources_sha256=self.assets.bundle_sha256,
            expected_resource_profile_sha256=final.PROFILE_SHA256)

    def render_arguments(self):
        _, html, binding = final.prepare_final_document_candidate(**self.arguments())
        return dict(html=html, expected_html_sha256=binding['composition']['html_sha256'],
                    resources=self.assets, expected_resources_sha256=self.assets.bundle_sha256)

    def actual(self):
        global _ACTUAL, _FAILURE
        if _FAILURE is not None:self.fail('prior actual observed fixture failed: ' + _FAILURE)
        if _ACTUAL is None:
            arguments, document = long_raster_inputs(final); captured = []
            compose = self.o.compose_stored_observation
            def capture(**values):
                result = compose(**values); captured.append(values); return result
            try:
                with tempfile.TemporaryDirectory() as directory, \
                        patch.object(self.o, 'compose_stored_observation', side_effect=capture):
                    pdf, manifest, observed = final.execute_observed_stored_final_document_candidate(
                        **arguments, expected_storage_profile_sha256=final.STORAGE_PROFILE_SHA256,
                        directory=Path(directory), run_id='c' * 32)
                    self.assertEqual(sorted(p.name for p in (Path(directory)/('c'*32)).iterdir()),
                                     ['candidate.pdf', 'c'*32+'.json', 'manifest.json'])
                self.assertEqual(len(captured), 1)
                _ACTUAL = dict(pdf=pdf, manifest=manifest, observed=observed,
                               arguments=arguments, document=document, captured=captured[0])
            except Exception as error:
                _FAILURE = type(error).__name__ + ': ' + str(error); raise
        return _ACTUAL

    def composition(self):
        return {k:deepcopy(v) if type(v) in (dict,list) else v
                for k,v in self.actual()['captured'].items()}

    def refused(self, values):
        for row in values['layout_processes']:
            for kind in ('render', 'locations'):
                record = row[kind]
                record['observation_sha256'] = sha256(canonical(
                    {k:v for k,v in record.items() if k!='observation_sha256'})).hexdigest()
        with self.assertRaises(ValueError):self.o.compose_stored_observation(**values)

    def refuse_observation_import(self, name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'reporting' and '_pdf_final_document_observation' in fromlist:
            raise ImportError('injected optional observation import refusal')
        return self.original_import(name, globals, locals, fromlist, level)

    def cached_execution(self):
        data = self.actual()['captured']
        return (data['rendered'], data['inspected'], deepcopy(data['binding']),
                {'layout_processes':deepcopy(data['layout_processes']),
                 'native_observation':deepcopy(data['native_observation'])})


class RasterProcessTests(Inputs, unittest.TestCase):
    def test_observation_import_refusal_launches_no_raster_child(self):
        arguments = self.render_arguments(); children = []; start = adapters._start_pdf_render_worker
        self.original_import = builtins.__import__
        def capture(*args, **kwargs):
            child = start(*args, **kwargs); children.append(child); return child
        try:
            with patch.object(adapters, '_start_pdf_render_worker', side_effect=capture), \
                    patch('builtins.__import__', side_effect=self.refuse_observation_import):
                with self.assertRaises(raster.RasterRenderError):
                    raster.render_observed_preloaded_raster_pdf(**arguments)
        finally:
            for child in children:
                try:self.o.wait_owned_process_group(child, wall_seconds=0)
                except TimeoutExpired:pass
                self.assertIsNotNone(child.returncode)
                with self.assertRaises(ChildProcessError):os.waitpid(child.pid, os.WNOHANG)
        self.assertEqual(children, [])

    def test_actual_raster_child_binds_protocol_resources_and_unchanged_pdf(self):
        arguments = self.render_arguments(); children = []; start = adapters._start_pdf_render_worker
        def capture(*args, **kwargs):
            child = start(*args, **kwargs); children.append(child); return child
        with patch.object(adapters, '_start_pdf_render_worker', side_effect=capture):
            rendered, record = raster.render_observed_preloaded_raster_pdf(**arguments)
        original = raster.render_preloaded_raster_pdf(**arguments)
        self.assertEqual(rendered.pdf_bytes, original.pdf_bytes)
        self.assertEqual(record['pid'], children[0].pid); self.assertEqual(record['parent_pid'], os.getpid())
        self.assertEqual(record['exit_code'], 0); self.assertEqual(children[0].returncode, 0)
        self.assertEqual(record['worker'], '_pdf_render_worker.py')
        self.assertEqual(record['html_sha256'], arguments['expected_html_sha256'])
        self.assertEqual(record['resources_sha256'], self.assets.bundle_sha256)
        header = f"3 {arguments['expected_html_sha256']} {self.assets.bundle_sha256}\n".encode()
        self.assertEqual(record['request_header_sha256'], sha256(header).hexdigest())
        self.assertEqual(record['render_sha256'], sha256(canonical(rendered.to_dict())).hexdigest())
        self.assertLessEqual(record['spawn_monotonic_ns'], record['exit_monotonic_ns'])
        with self.assertRaises(ChildProcessError):os.waitpid(children[0].pid, os.WNOHANG)

    def test_raster_observation_failure_reaps_the_actual_owned_child(self):
        children = []; start = adapters._start_pdf_render_worker
        def capture(*args, **kwargs):
            child = start(*args, **kwargs); children.append(child); return child
        with patch.object(adapters, '_start_pdf_render_worker', side_effect=capture), \
                patch.object(self.o, 'observe_spawn', side_effect=ValueError('injected observation refusal')):
            with self.assertRaises(raster.RasterRenderError):
                raster.render_observed_preloaded_raster_pdf(**self.render_arguments())
        self.assertEqual(len(children), 1); self.assertIsNotNone(children[0].returncode)
        with self.assertRaises(ChildProcessError):os.waitpid(children[0].pid, os.WNOHANG)

    def test_default_render_does_not_enable_optional_observations(self):
        with patch.object(self.o, 'observe_spawn', side_effect=AssertionError('default path observed')):
            rendered = raster.render_preloaded_raster_pdf(**self.render_arguments())
        self.assertIs(type(rendered), raster.RasterPdfCandidate)

    def test_disabled_observed_raster_starts_no_child(self):
        arguments = self.render_arguments()
        with patch.dict(os.environ, {'OMNIGENIS_PDF_PRELOADED_RASTER_DISABLED':'1'}), \
                patch.object(adapters, '_start_pdf_render_worker', side_effect=AssertionError('disabled launch')):
            with self.assertRaises(raster.RasterRenderError):raster.render_observed_preloaded_raster_pdf(**arguments)


class FinalProcessBindingTests(Inputs, unittest.TestCase):
    def test_real_long_roundtrip_accounts_for_all_declared_children(self):
        data = self.actual(); observed = data['observed']; manifest = data['manifest']
        self.assertEqual((len(data['pdf']), manifest['page_count']), (9632150, 56))
        self.assertEqual(manifest['result']['binding']['finding_count'], 96)
        self.assertEqual(len(observed['layout_processes']), 3)
        self.assertEqual((observed['observed_direct_spawns'], observed['observed_direct_exits']), (45,45))
        self.assertEqual((observed['observed_nested_spawns'], observed['observed_nested_exits']), (70,70))
        self.assertEqual((observed['observed_total_spawns'], observed['observed_total_exits']), (115,115))
        self.assertEqual(observed['declared_retries'], 0)
        self.assertEqual(observed['pdf_sha256'], sha256(data['pdf']).hexdigest())
        self.assertEqual(observed['manifest_sha256'], sha256(canonical(manifest)).hexdigest())
        self.assertEqual(observed['result_sha256'], manifest['result_sha256'])
        self.assertEqual(observed['run_id'], 'c'*32)
        self.assertEqual(observed['native_observation']['observed_total_spawns'], 109)
        self.assertLessEqual(len(canonical(observed)), 160*1024)
        self.assertEqual(observed['observation_sha256'], sha256(canonical(
            {k:v for k,v in observed.items() if k!='observation_sha256'})).hexdigest())

    def test_intermediate_passes_bind_their_own_pdf_and_location_receipt(self):
        data = self.actual(); rows = data['observed']['layout_processes']
        passes = data['manifest']['result']['binding']['layout']['passes']
        self.assertNotEqual(passes[0]['render_result']['pdf_sha256'], passes[-1]['render_result']['pdf_sha256'])
        for number, (row, original) in enumerate(zip(rows, passes, strict=True), 1):
            self.assertEqual(row['pass_number'], number)
            self.assertEqual(row['render']['pdf_sha256'], original['render_result']['pdf_sha256'])
            self.assertEqual(row['locations']['identity'], original['location_receipt']['identity'])
            self.assertEqual(row['locations']['receipt_sha256'], sha256(canonical(original['location_receipt'])).hexdigest())
        self.assertEqual(rows[-1]['render']['pdf_sha256'], data['observed']['pdf_sha256'])

    def test_observations_keep_resource_authentication_and_release_unqualified(self):
        value = self.actual()['observed']
        for key in ('whole_graph_observed','arbitrary_descendants_observed','authenticated_worker_execution',
                    'aggregate_job_resources_qualified','native_profile_qualified','external_observer_measured',
                    'default_pipeline_activated','release_authorized','supported_execution',
                    'hard_job_deadline_enforced','storage_deadline_enforced','durable_observation_storage'):
            self.assertIs(value[key], False, key)

    def test_returned_observation_is_detached_from_future_composition(self):
        values = self.composition(); first = self.o.compose_stored_observation(**values)
        first['layout_processes'].clear(); first['native_observation']['release_authorized'] = True
        again = self.o.compose_stored_observation(**values)
        self.assertEqual(again, self.actual()['observed'])

    def test_missing_duplicate_and_extra_layout_rows_are_refused(self):
        for action in ('missing','duplicate','extra'):
            values = self.composition(); rows = values['layout_processes']
            if action=='missing':rows.pop()
            elif action=='duplicate':rows[1]=deepcopy(rows[0])
            else:rows.append(deepcopy(rows[-1]))
            with self.subTest(action=action):self.refused(values)

    def test_reordered_or_noninteger_passes_are_refused(self):
        for action in ('reorder','boolean'):
            values = self.composition()
            if action=='reorder':values['layout_processes'].reverse()
            else:values['layout_processes'][0]['pass_number']=True
            with self.subTest(action=action):self.refused(values)

    def test_foreign_render_identity_source_and_header_are_refused(self):
        for key in ('pdf_sha256','html_sha256','resources_sha256','worker_source_sha256',
                    'request_header_sha256','profile_sha256','render_sha256'):
            values=self.composition();values['layout_processes'][0]['render'][key]='0'*64
            with self.subTest(key=key):self.refused(values)

    def test_location_identity_receipt_and_worker_substitution_are_refused(self):
        for key in ('receipt_sha256','worker_source_sha256','request_header_sha256'):
            values=self.composition();values['layout_processes'][0]['locations'][key]='0'*64
            with self.subTest(key=key):self.refused(values)
        values=self.composition();values['layout_processes'][0]['locations']['identity']['pass_number']=2
        self.refused(values)

    def test_cross_stage_pid_collision_and_foreign_parent_are_refused(self):
        for action in ('layout_collision','native_collision','foreign_parent','boolean_pid'):
            values=self.composition();row=values['layout_processes'][0]['render']
            if action=='layout_collision':row['pid']=values['layout_processes'][1]['locations']['pid']
            elif action=='native_collision':row['pid']=values['native_observation']['direct_observation']['direct_process_ledger']['processes'][0]['pid']
            elif action=='foreign_parent':row['parent_pid']+=1
            else:row['pid']=True
            with self.subTest(action=action):self.refused(values)

    def test_clock_reversal_and_stage_overlap_are_refused(self):
        for action in ('reverse','overlap','outside_operation','bad_end'):
            values=self.composition();row=values['layout_processes'][0]
            if action=='reverse':row['render']['exit_monotonic_ns']=row['render']['spawn_monotonic_ns']-1
            elif action=='overlap':row['locations']['spawn_monotonic_ns']=row['render']['spawn_monotonic_ns']
            elif action=='outside_operation':values['started_ns']=row['render']['spawn_monotonic_ns']+1
            else:values['verified_ns']=True
            with self.subTest(action=action):self.refused(values)

    def test_incomplete_and_rehashed_native_observation_are_refused(self):
        for action in ('missing','count','claim','parent'):
            values=self.composition();n=values['native_observation']
            if action=='missing':n['raster_child_ledger']['windows'].pop()
            elif action=='count':n['observed_total_spawns']+=1
            elif action=='claim':n['aggregate_job_resources_qualified']=True
            else:n['direct_observation']['direct_process_ledger']['processes'][0]['parent_pid']+=1
            n['observation_sha256']=sha256(canonical({k:v for k,v in n.items() if k!='observation_sha256'})).hexdigest()
            with self.subTest(action=action):self.refused(values)

    def test_manifest_result_pdf_and_profile_mismatches_are_refused(self):
        for action in ('pdf','result','profile','manifest_result','run_id'):
            values=self.composition()
            if action=='pdf':values['pdf']=values['pdf']+b'changed'
            elif action=='result':values['manifest']['result_sha256']='0'*64
            elif action=='profile':values['manifest']['storage_profile_sha256']='0'*64
            elif action=='manifest_result':values['manifest']['result']['binding']['finding_count']-=1
            else:values['manifest']['run_id']='invalid'
            with self.subTest(action=action):self.refused(values)

    def test_unknown_fields_and_oversized_observation_rows_are_refused(self):
        for extra in ('unknown', 'x'*(160*1024)):
            values=self.composition();values['layout_processes'][0]['render']['extra']=extra
            self.refused(values)

    def test_manifest_pins_current_sources_and_preserves_original_profiles(self):
        path=Path(self.o.__file__).with_name('pdf-final-document-observation.v1.json')
        document=json.loads(path.read_text());root=path.parent.parent
        self.assertEqual(document['max_observation_bytes'],160*1024)
        for name,expected in document['source_sha256'].items():
            self.assertEqual(sha256((root/name).read_bytes()).hexdigest(),expected,name)
        self.assertEqual(final.PROFILE_SHA256,'93b440c41d025cc39645ddc66764577fad414fbb3b471662afb89d2763f39ab7')
        self.assertEqual(final.STORAGE_PROFILE_SHA256,'bc9c3fb920cc2ab6ce8f784ff54f1cf544b999fda082f4edac99979d1d315368')
        for key in ('release_authorized','supported_execution','aggregate_job_resources_qualified','scientific_activation'):
            self.assertIs(document[key],False)


class FinalObservedFailureTests(Inputs, unittest.TestCase):
    def test_native_observation_import_refusal_claims_no_run_or_work(self):
        """A missing optional native dependency refuses before consuming a run."""
        original_import = builtins.__import__; refusals = []
        def refuse(name, globals=None, locals=None, fromlist=(), level=0):
            if name == 'reporting._pdf_raster_job_observation':
                refusals.append(name)
                raise ImportError('injected native observation dependency refusal')
            return original_import(name, globals, locals, fromlist, level)
        with tempfile.TemporaryDirectory() as directory, \
                patch('builtins.__import__', side_effect=refuse), \
                patch.object(final, '_execute_final_document_candidate',
                             side_effect=AssertionError('execution reached before dependency preflight')) as work:
            with self.assertRaises(final.PdfFinalDocumentError):
                final.execute_observed_stored_final_document_candidate(**self.arguments(),
                    directory=Path(directory), run_id='e'*32,
                    expected_storage_profile_sha256=final.STORAGE_PROFILE_SHA256)
            self.assertEqual({'entries':sorted(p.name for p in Path(directory).iterdir()),
                              'work_calls':work.call_count, 'import_refusals':refusals},
                             {'entries':[], 'work_calls':0,
                              'import_refusals':['reporting._pdf_raster_job_observation']})

    def test_observation_import_refusal_launches_no_location_child(self):
        pdf = b'%PDF-1.7\n'; children = []; start = final.graph._start
        identity = dict(pdf_sha256=sha256(pdf).hexdigest(), ir_sha256='b'*64,
                        plan_sha256='c'*64, page_count=1)
        self.original_import = builtins.__import__
        def capture(*args, **kwargs):
            child = start(*args, **kwargs); children.append(child); return child
        try:
            with patch.object(final.graph, '_start', side_effect=capture), \
                    patch('builtins.__import__', side_effect=self.refuse_observation_import):
                with self.assertRaises(ImportError):
                    final._run_locations(pdf, identity, observe_processes=True)
        finally:
            for child in children:
                try:self.o.wait_owned_process_group(child, wall_seconds=0)
                except TimeoutExpired:pass
                self.assertIsNotNone(child.returncode)
                with self.assertRaises(ChildProcessError):os.waitpid(child.pid, os.WNOHANG)
        self.assertEqual(children, [])

    def test_disable_refuses_before_creating_a_run_or_launching(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'OMNIGENIS_PDF_FINAL_DOCUMENT_DISABLED':'1'}):
            with self.assertRaises(final.PdfFinalDocumentError):
                final.execute_observed_stored_final_document_candidate(**self.arguments(),directory=Path(directory),
                    run_id='e'*32,expected_storage_profile_sha256=final.STORAGE_PROFILE_SHA256)
            self.assertEqual(list(Path(directory).iterdir()),[])

    def test_consumed_attempt_refuses_without_new_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory)/('e'*32)).mkdir(mode=0o700)
            with patch.object(final,'_execute_final_document_candidate',side_effect=AssertionError('attempt repeated')):
                with self.assertRaises(final.PdfFinalDocumentError):
                    final.execute_observed_stored_final_document_candidate(**self.arguments(),directory=Path(directory),
                        run_id='e'*32,expected_storage_profile_sha256=final.STORAGE_PROFILE_SHA256)
            self.assertEqual(list((Path(directory)/('e'*32)).iterdir()),[])

    def test_location_observation_failure_cleans_owned_child_and_withholds_store(self):
        children=[];start=final.graph._start;observe=self.o.observe_spawn
        def capture(*args,**kwargs):
            child=start(*args,**kwargs);children.append(child);return child
        def refuse(process,command,kind):
            if kind=='locations':raise ValueError('injected location observation refusal')
            return observe(process,command,kind)
        with tempfile.TemporaryDirectory() as directory,patch.object(final.graph,'_start',side_effect=capture), \
                patch.object(self.o,'observe_spawn',side_effect=refuse):
            with self.assertRaises(final.PdfFinalDocumentError):
                final.execute_observed_stored_final_document_candidate(**self.arguments(),directory=Path(directory),
                    run_id='e'*32,expected_storage_profile_sha256=final.STORAGE_PROFILE_SHA256)
            self.assertEqual(list((Path(directory)/('e'*32)).iterdir()),[])
        self.assertEqual(len(children),1);self.assertIsNotNone(children[0].returncode)
        with self.assertRaises(ChildProcessError):os.waitpid(children[0].pid,os.WNOHANG)

    def test_receipt_failure_preserves_uncommitted_data_without_observed_success(self):
        data=self.actual()
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(final,'_execute_final_document_candidate',return_value=self.cached_execution()), \
                patch.object(final.previous,'_write_stored_receipt',side_effect=OSError('receipt failure')):
            with self.assertRaises(final.PdfFinalDocumentError):
                final.execute_observed_stored_final_document_candidate(**data['arguments'],directory=Path(directory),
                    run_id='e'*32,expected_storage_profile_sha256=final.STORAGE_PROFILE_SHA256)
            self.assertEqual(sorted(p.name for p in (Path(directory)/('e'*32)).iterdir()),['candidate.pdf','manifest.json'])

    def test_postcommit_observation_failure_preserves_explicit_recovery(self):
        data=self.actual()
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(final,'_execute_final_document_candidate',return_value=self.cached_execution()), \
                patch.object(self.o,'compose_stored_observation',side_effect=ValueError('sidecar refusal')):
            with self.assertRaises(final.PdfFinalDocumentError):
                final.execute_observed_stored_final_document_candidate(**data['arguments'],directory=Path(directory),
                    run_id='e'*32,expected_storage_profile_sha256=final.STORAGE_PROFILE_SHA256)
            pdf,manifest=final.read_stored_final_document_candidate(**data['arguments'],directory=Path(directory),
                run_id='e'*32,expected_storage_profile_sha256=final.STORAGE_PROFILE_SHA256,
                expected_result_sha256=data['manifest']['result_sha256'],expected_pdf_sha256=sha256(data['pdf']).hexdigest())
            self.assertEqual(pdf,data['pdf']);self.assertEqual(manifest['run_id'],'e'*32)
            self.assertNotIn('process_observation',manifest)


if __name__=='__main__':unittest.main()
