"""Final printed page references are bound to the exact source and physical PDF."""
from copy import deepcopy
from hashlib import sha256
from importlib import import_module, util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from reporting import pdf_bound_raster_candidate as previous
from reporting import pdf_native_source_job as native
from reporting import pdf_raster_render as raster
from reporting import _pdf_job_durable_receipt as receipts
from tests.test_reporting_pdf_bound_candidate import bound_request, source, IDS, canonical
from tests.test_reporting_pdf_bound_raster_candidate import bundle, long_raster_inputs

MODE = 'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE'
DISABLE = 'OMNIGENIS_PDF_FINAL_DOCUMENT_DISABLED'
_GENUINE = None
_GENUINE_FAILURE = None


def measured(stream, lengths):
    """Independently frame known source slices for protocol and boundary fault cases."""
    partition = sha256(); position = 0
    for number, size in enumerate(lengths, 1):
        partition.update(f'{number}:{size}:'.encode())
        partition.update(stream[position:position + size]); position += size
    return {'status': 'FINAL_DOCUMENT_PAGE_PARTITION_INSPECTED',
        'inspected_pages': len(lengths), 'decoded_bytes': len(stream),
        'text_chars': len(stream.decode()), 'text_bytes': len(stream),
        'text_sha256': sha256(stream).hexdigest(), 'page_byte_lengths': lengths,
        'page_partition_sha256': partition.hexdigest()}


def protocol(identity, inspection):
    """Use literal wire values independently of the new worker's encoder."""
    return {'protocol_version': 1, 'profile_id': 'final-document-page-locations-v1',
        'policy_id': 'semantic-section-physical-page-partition-v1',
        'parser_version': '7.1.0', 'identity': identity,
        'limits': {'memory_bytes': 268435456, 'cpu_seconds': 5,
                   'file_bytes': 4096, 'open_files': 128},
        'inspection': inspection}


class Inputs:
    """Real request/resource preparation; no caller-supplied compiler or renderer."""
    def setUp(self):
        self.assertIsNotNone(util.find_spec('reporting.pdf_final_document_candidate'),
                             'final-document composition is not implemented')
        self.m = import_module('reporting.pdf_final_document_candidate')
        self.bound = bound_request(); self.assets = bundle()
        env = patch.dict(os.environ, {MODE: 'qualification-only'})
        env.start(); self.addCleanup(env.stop)
        for key in (DISABLE, 'OMNIGENIS_PDF_BOUND_RASTER_DISABLED',
                    'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED',
                    'OMNIGENIS_PDF_PRELOADED_RASTER_DISABLED', 'OMNIGENIS_PDF_RENDERER_DISABLED'):
            os.environ.pop(key, None)

    def arguments(self, **changes):
        values = dict(bound_request=self.bound, resources=self.assets,
            expected_request_sha256=self.bound.request.request_sha256,
            expected_resources_sha256=self.assets.bundle_sha256,
            expected_resource_profile_sha256=self.m.PROFILE_SHA256)
        values.update(changes); return values

    def prepare(self):
        return self.m.prepare_final_document_candidate(**self.arguments())

    def small(self, count):
        document, _ = source()
        document['canonical_payload']['items'] = document['canonical_payload']['items'][:count]
        document['canonical_payload']['interpretation_item_count'] = count
        document['raw_artifact_refs'] = document['raw_artifact_refs'][:count]
        self.bound = bound_request(document, finding_ids=IDS[:count])
        return document

    def genuine(self):
        """One real complete long roundtrip; preserve a failure and never retry it."""
        global _GENUINE, _GENUINE_FAILURE
        if _GENUINE_FAILURE is not None:
            self.fail('genuine final-document fixture failed: ' + _GENUINE_FAILURE)
        if _GENUINE is None:
            arguments, document = long_raster_inputs(self.m)
            captured = []
            execute = self.m.execute_final_document_candidate
            def capture(**values):
                pair = execute(**values); captured.append(pair); return pair
            try:
                with tempfile.TemporaryDirectory() as directory, \
                        patch.object(self.m, 'execute_final_document_candidate', side_effect=capture):
                    pdf, manifest = self.m.execute_stored_final_document_candidate(**arguments,
                        expected_storage_profile_sha256=self.m.STORAGE_PROFILE_SHA256,
                        directory=Path(directory), run_id='a' * 32)
                self.assertEqual(len(captured), 1)
                _GENUINE = dict(pdf=pdf, manifest=manifest, arguments=arguments,
                                document=document, pair=captured[0])
            except Exception as error:
                _GENUINE_FAILURE = type(error).__name__ + ': ' + str(error)
                raise
        return _GENUINE


class FinalProjectionTests(Inputs, unittest.TestCase):
    def test_printed_index_preserves_all_original_components(self):
        original, _, source_binding = previous.prepare_bound_raster_candidate(
            **self.arguments(expected_resource_profile_sha256=previous.PROFILE_SHA256))
        ir, html, binding = self.prepare()
        self.assertEqual(ir['components'][1:], original['components'])
        self.assertEqual(ir['components'][0]['component_id'], 'technical-document-index')
        index = ir['components'][0]['content']
        self.assertEqual([r['finding_id'] for r in index['findings']], list(IDS))
        self.assertTrue(all(r['first_page'] is None and r['last_page'] is None
                            for r in index['findings']))
        self.assertIsNone(index['page_count'])
        self.assertIn('Document index and internal references', html)
        self.assertEqual(binding['source_projection'], source_binding)
        self.assertFalse(binding['release_authorized'])

    def test_zero_and_one_finding_sources_stay_complete(self):
        for count in (0, 1):
            with self.subTest(count=count):
                document = self.small(count); ir, _, _ = self.prepare()
                self.assertEqual(len(ir['components'][0]['content']['findings']), count)
                self.assertEqual(ir['components'][2]['content']['canonical_interpretation.items'],
                                 document['canonical_payload']['items'])
                if not count: self.assertEqual(ir['components'][2]['state'], 'EXPLICIT_NONE')

    def test_returned_values_cannot_mutate_later_projection(self):
        ir, html, binding = self.prepare(); expected = canonical(ir)
        ir['components'][0]['content']['findings'].clear(); binding['release_authorized'] = True
        again = self.prepare()
        self.assertEqual(canonical(again[0]), expected); self.assertEqual(again[1], html)
        self.assertFalse(again[2]['release_authorized'])

    def test_wrong_input_expectations_refuse_before_render(self):
        for key in ('expected_request_sha256', 'expected_resources_sha256',
                    'expected_resource_profile_sha256'):
            with self.subTest(key=key), patch.object(raster, 'render_preloaded_raster_pdf') as render:
                with self.assertRaises(self.m.PdfFinalDocumentError):
                    self.m.execute_final_document_candidate(**self.arguments(**{key: '0' * 64}))
                render.assert_not_called()

    def test_default_and_inherited_disable_flags_refuse_before_render(self):
        for key in (DISABLE, 'OMNIGENIS_PDF_BOUND_RASTER_DISABLED',
                    'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED'):
            with self.subTest(key=key), patch.dict(os.environ, {key: '1'}), \
                    patch.object(raster, 'render_preloaded_raster_pdf') as render:
                with self.assertRaises(self.m.PdfFinalDocumentError): self.prepare()
                render.assert_not_called()
        with patch.dict(os.environ, {MODE: ''}), self.assertRaises(self.m.PdfFinalDocumentError):
            self.prepare()

    def test_above_finding_class_refuses_without_truncating_source(self):
        document, _ = source(); template = document['canonical_payload']['items'][0]
        items = []
        for i in range(129):
            item = deepcopy(template)
            item['canonical_variant_id'] = 'omnigenis:small-variant:v1:sha256:' + sha256(str(i).encode()).hexdigest()
            items.append(item)
        document['canonical_payload']['items'] = items
        document['canonical_payload']['interpretation_item_count'] = 129
        document['raw_artifact_refs'] = [item['evidence_sha256'] for item in items]
        self.bound = bound_request(document, finding_ids=tuple(i['canonical_variant_id'] for i in items))
        before = self.bound.sources.canonical_result_bytes
        with self.assertRaises(self.m.PdfFinalDocumentError): self.prepare()
        self.assertEqual(before, self.bound.sources.canonical_result_bytes)

    def test_manifest_profile_pins_current_source_and_preserves_nonclaims(self):
        path = Path(self.m.__file__).with_name('pdf-final-document-candidate.v1.json')
        document = json.loads(path.read_text())
        self.assertEqual(document['profile'], self.m.final_document_profile())
        self.assertEqual(document['profile_sha256'], sha256(canonical(document['profile'])).hexdigest())
        self.assertEqual(document['storage_profile'], self.m.final_document_storage_profile())
        root = path.parent.parent
        for name, expected in document['source_sha256'].items():
            self.assertEqual(sha256((root / name).read_bytes()).hexdigest(), expected, name)
        for key in ('release_authorized', 'supported_execution', 'scientific_activation',
                    'aggregate_job_resources_qualified', 'default_pipeline_activated'):
            self.assertIs(document[key], False)


class FinalLocationTests(Inputs, unittest.TestCase):
    def tiny_ir(self):
        return {'report_id': 'R', 'locale_id': 'en-US', 'components': [{
            'component_id': 'verified-source-interpretations', 'component_type': 'semantic-section',
            'title': 'T', 'state': 'PRESENT', 'content': {'canonical_interpretation.items': [
                {'canonical_variant_id': 'one', 'note': 'same'},
                {'canonical_variant_id': 'two', 'note': 'same'}]}}]}

    def test_structured_offsets_do_not_match_repeated_index_text(self):
        ir = self.tiny_ir()
        expected = (b'RTPRESENT{"canonical_interpretation.items":['
                    b'{"canonical_variant_id":"one","note":"same"},'
                    b'{"canonical_variant_id":"two","note":"same"}]}')
        stream, spans = self.m._stream_and_spans(ir)
        self.assertEqual(stream, expected)
        self.assertEqual([(v['start'], v['end']) for v in spans['findings']], [(44, 88), (89, 133)])
        self.assertEqual([(v['start'], v['end']) for v in spans['sections']], [(1, 135)])

    def test_utf8_escapes_and_multpage_finding_use_byte_intervals(self):
        ir = self.tiny_ir(); ir['components'][0]['content']['canonical_interpretation.items'][0]['note'] = 'é"\\same'
        stream, spans = self.m._stream_and_spans(ir)
        first = spans['findings'][0]
        self.assertEqual(stream[first['start']:first['end']],
                         b'{"canonical_variant_id":"one","note":"\xc3\xa9\\"\\\\same"}')
        cut = first['start'] + 10
        result = self.m._resolve_locations(ir, measured(stream, [cut, len(stream) - cut]), 2)
        self.assertEqual([(r['first_page'], r['last_page']) for r in result['findings']], [(1, 2), (2, 2)])

    def test_all_physical_pages_and_final_sections_are_accounted(self):
        ir, _, _ = self.prepare(); stream, spans = self.m._stream_and_spans(ir)
        cut = spans['sections'][1]['start']
        location = self.m._resolve_locations(ir, measured(stream, [cut, len(stream) - cut]), 2)
        self.assertEqual(location['page_count'], 2)
        self.assertEqual([s['component_id'] for s in location['sections']],
                         [c['component_id'] for c in ir['components']])
        self.assertEqual(len(location['findings']), 2)
        self.assertEqual(location['sections'][0]['last_page'], 1)
        self.assertEqual(location['sections'][1]['first_page'], 2)

    def test_bad_partition_lengths_digests_and_count_are_refused(self):
        ir = self.tiny_ir(); stream, _ = self.m._stream_and_spans(ir)
        valid = measured(stream, [42, len(stream) - 42])
        changes = [dict(page_byte_lengths=[42]), dict(page_byte_lengths=[True, len(stream) - 1]),
            dict(page_byte_lengths=[0, len(stream)]), dict(page_byte_lengths=[43, len(stream) - 42]),
            dict(page_partition_sha256='0' * 64), dict(text_sha256='0' * 64),
            dict(inspected_pages=1), dict(text_bytes=len(stream) + 1)]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.m._resolve_locations(ir, {**valid, **change}, 2)

    def test_reordered_page_partitions_fail_even_with_matching_whole_text_digest(self):
        ir = self.tiny_ir(); stream, _ = self.m._stream_and_spans(ir)
        valid = measured(stream, [42, len(stream) - 42])
        valid['page_byte_lengths'].reverse()
        with self.assertRaises(ValueError): self.m._resolve_locations(ir, valid, 2)

    def test_protocol_rejects_foreign_identity_limits_duplicates_and_promotions(self):
        identity = dict(pdf_sha256='a' * 64, ir_sha256='b' * 64, plan_sha256='c' * 64, page_count=1)
        valid = protocol(identity, measured(b'abc', [3]))
        self.assertEqual(self.m._decode_locations(canonical(valid), identity), valid)
        records = []
        for key, value in [('profile_id', 'foreign'), ('parser_version', 'unknown'), ('protocol_version', True)]:
            records.append({**valid, key: value})
        changed = deepcopy(valid); changed['limits']['cpu_seconds'] = 6; records.append(changed)
        changed = deepcopy(valid); changed['identity']['pdf_sha256'] = 'd' * 64; records.append(changed)
        changed = deepcopy(valid); changed['inspection']['release_authorized'] = True; records.append(changed)
        for value in records:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.m._decode_locations(canonical(value), identity)
        for raw in (b'{}', b' ' * 4097, canonical(valid).replace(b'"protocol_version":1', b'"protocol_version":1,"protocol_version":1')):
            with self.assertRaises(ValueError): self.m._decode_locations(raw, identity)

    def test_maximum_page_partition_receipt_fits_original_wire_envelope(self):
        identity = dict(pdf_sha256='a' * 64, ir_sha256='b' * 64, plan_sha256='c' * 64, page_count=64)
        inspection = measured(b'x' * 65536, [1024] * 64)
        raw = canonical(protocol(identity, inspection))
        self.assertLessEqual(len(raw), 4096)
        self.assertEqual(self.m._decode_locations(raw, identity)['inspection']['inspected_pages'], 64)

    def test_missing_duplicate_or_foreign_target_cannot_be_printed_as_resolved(self):
        base, _, _ = previous._prepare(**self.arguments(expected_resource_profile_sha256=previous.PROFILE_SHA256))
        ir, _, _ = self.prepare(); stream, _ = self.m._stream_and_spans(ir)
        valid = self.m._resolve_locations(ir, measured(stream, [len(stream)]), 1)
        for kind in ('missing', 'duplicate', 'foreign', 'boolean', 'unresolved'):
            broken = deepcopy(valid)
            if kind == 'missing': broken['findings'].pop()
            elif kind == 'duplicate': broken['findings'][1] = deepcopy(broken['findings'][0])
            elif kind == 'foreign': broken['sections'][1]['component_id'] = 'foreign'
            elif kind == 'boolean': broken['findings'][0]['first_page'] = True
            else: broken['findings'][0]['first_page'] = None
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.m._compose(base, self.assets, broken)

    def test_worker_invalid_descriptor_shape_refuses_without_parsing(self):
        worker = import_module('reporting._pdf_final_locations_worker')
        for argv in ([], ['worker', '1', '2', '3'], ['worker', '3', '3', '4'],
                     ['worker', '03', '4', '5'], ['worker', '3', '4', '1']):
            with self.subTest(argv=argv), patch.object(worker, '_inspect') as inspect:
                self.assertEqual(worker.main(argv), 64)
                inspect.assert_not_called()

    def test_worker_guard_failure_produces_no_location_receipt(self):
        worker = import_module('reporting._pdf_final_locations_worker')
        with tempfile.TemporaryFile() as request, tempfile.TemporaryFile() as result, \
                patch.object(worker, '_limits', return_value={}), \
                patch.object(worker, '_lifetime'), \
                patch.object(worker, 'enforce_pdf_landlock', side_effect=OSError('guard')), \
                patch.object(worker, '_read_request') as read, patch.object(worker, '_inspect') as inspect:
            self.assertEqual(worker.main(['worker', str(request.fileno()), str(result.fileno()), str(os.getpid())]), 70)
            read.assert_not_called(); inspect.assert_not_called()
            self.assertEqual(os.fstat(result.fileno()).st_size, 0)


class FinalConvergenceFailureTests(Inputs, unittest.TestCase):
    def test_oscillating_target_map_with_constant_page_count_stops_after_four_passes(self):
        actual_compose = self.m._compose; current = {}; count = 0
        def compose(*args):
            values = actual_compose(*args); current['ir'] = values[0]; return values
        def render(**values):
            return raster.RasterPdfCandidate(b'%PDF-1.7\n' + sha256(values['html'].encode()).digest(),
                values['expected_html_sha256'], values['expected_resources_sha256'], 2, 1)
        def inspect(pdf, identity):
            nonlocal count
            count += 1; stream, _ = self.m._stream_and_spans(current['ir'])
            cut = 1 if count % 2 else len(stream) // 2
            return canonical(protocol(identity, measured(stream, [cut, len(stream) - cut])))
        with patch.object(self.m, '_compose', side_effect=compose), \
                patch.object(raster, 'render_preloaded_raster_pdf', side_effect=render) as renders, \
                patch.object(self.m, '_run_locations', side_effect=inspect) as locations, \
                patch.object(native, 'execute_pdf_native_source_job') as full:
            with self.assertRaises(self.m.PdfFinalDocumentError):
                self.m.execute_final_document_candidate(**self.arguments())
        self.assertEqual((renders.call_count, locations.call_count), (4, 4))
        full.assert_not_called()

    def test_renderer_failure_is_once_content_free_and_does_not_launch_inspection(self):
        with patch.object(raster, 'render_preloaded_raster_pdf', side_effect=ValueError('PRIVATE-SOURCE')) as render, \
                patch.object(self.m, '_run_locations') as locations:
            with self.assertRaises(self.m.PdfFinalDocumentError) as error:
                self.m.execute_final_document_candidate(**self.arguments())
        self.assertNotIn('PRIVATE-SOURCE', str(error.exception)); self.assertEqual(render.call_count, 1)
        locations.assert_not_called()

    def test_source_change_after_render_stops_before_location_worker(self):
        def render(**values):
            candidate = raster.RasterPdfCandidate(b'%PDF-1.7\nfixture', values['expected_html_sha256'],
                values['expected_resources_sha256'], 2, 1)
            object.__setattr__(self.bound.sources, 'canonical_result_bytes', b'{}'); return candidate
        with patch.object(raster, 'render_preloaded_raster_pdf', side_effect=render), \
                patch.object(self.m, '_run_locations') as locations:
            with self.assertRaises(self.m.PdfFinalDocumentError):
                self.m.execute_final_document_candidate(**self.arguments())
        locations.assert_not_called()

    def test_forged_renderer_html_identity_is_refused(self):
        candidate = raster.RasterPdfCandidate(b'%PDF-1.7\nfixture', '0' * 64, self.assets.bundle_sha256, 2, 1)
        with patch.object(raster, 'render_preloaded_raster_pdf', return_value=candidate), \
                patch.object(self.m, '_run_locations') as locations:
            with self.assertRaises(self.m.PdfFinalDocumentError):
                self.m.execute_final_document_candidate(**self.arguments())
        locations.assert_not_called()

    def test_elapsed_acceptance_limit_refuses_before_any_render(self):
        with patch.object(self.m.time, 'monotonic_ns', side_effect=[1, 600000000002]), \
                patch.object(raster, 'render_preloaded_raster_pdf') as render:
            with self.assertRaises(self.m.PdfFinalDocumentError):
                self.m.execute_final_document_candidate(**self.arguments())
        render.assert_not_called()

    def test_location_failure_does_not_retry_or_start_final_native_inspection(self):
        def render(**values):
            return raster.RasterPdfCandidate(b'%PDF-1.7\nfixture', values['expected_html_sha256'],
                values['expected_resources_sha256'], 2, 1)
        with patch.object(raster, 'render_preloaded_raster_pdf', side_effect=render) as renders, \
                patch.object(self.m, '_run_locations', side_effect=OSError('worker')) as locations, \
                patch.object(native, 'execute_pdf_native_source_job') as full:
            with self.assertRaises(self.m.PdfFinalDocumentError):
                self.m.execute_final_document_candidate(**self.arguments())
        self.assertEqual((renders.call_count, locations.call_count), (1, 1)); full.assert_not_called()


class FinalNativeTests(Inputs, unittest.TestCase):
    def test_real_long_stored_pdf_has_complete_resolved_printed_index(self):
        value = self.genuine(); pdf = value['pdf']; manifest = value['manifest']
        result = manifest['result']; binding = result['binding']; layout = binding['layout']
        self.assertGreater(len(pdf), 8 * 1024 * 1024); self.assertLessEqual(len(pdf), 16 * 1024 * 1024)
        self.assertGreater(manifest['page_count'], 32); self.assertLessEqual(manifest['page_count'], 64)
        self.assertEqual(sha256(pdf).hexdigest(), manifest['pdf_sha256'])
        self.assertEqual(sha256(canonical(result)).hexdigest(), manifest['result_sha256'])
        self.assertEqual(binding['finding_count'], 96)
        self.assertEqual(len(layout['final_page_map']['findings']), 96)
        self.assertEqual(len(layout['final_page_map']['sections']), 9)
        self.assertTrue(layout['converged']); self.assertGreaterEqual(layout['pass_count'], 2)
        self.assertLessEqual(layout['pass_count'], 4)
        self.assertEqual(layout['render_invocations'], layout['pass_count'])
        self.assertEqual(layout['location_invocations'], layout['pass_count'])
        self.assertEqual(layout['native_inspection_invocations'], 1)
        self.assertEqual(result['native_inspection']['pdf_sha256'], manifest['pdf_sha256'])
        self.assertEqual(result['native_inspection']['ir_sha256'], binding['composition']['ir_sha256'])
        self.assertTrue(result['native_inspection']['normalized_text_equivalence_verified'])
        self.assertFalse(manifest['release_authorized'])
        original = previous._prepare(**{**value['arguments'], 'expected_resource_profile_sha256': previous.PROFILE_SHA256})[0]
        ir, html, composition = self.m._compose(original, value['arguments']['resources'], layout['final_page_map'])
        index = ir['components'][0]['content']
        self.assertEqual(composition, binding['composition'])
        self.assertEqual(index['page_count'], manifest['page_count'])
        self.assertEqual([v['finding_id'] for v in index['findings']],
                         [v['canonical_variant_id'] for v in value['document']['canonical_payload']['items']])
        self.assertTrue(all(type(v['first_page']) is int and 1 <= v['first_page'] <= v['last_page'] <= manifest['page_count']
                            for v in index['findings']))
        self.assertIn('Document index and internal references', html)
        self.assertNotIn('<a ', html)

    def test_zero_and_one_real_documents_have_exact_finding_locations(self):
        for count in (0, 1):
            with self.subTest(count=count):
                self.small(count)
                rendered, inspected, binding = self.m.execute_final_document_candidate(**self.arguments())
                self.assertEqual(len(binding['layout']['final_page_map']['findings']), count)
                self.assertEqual(inspected.to_dict()['pdf_sha256'], rendered.pdf_sha256)
                self.assertEqual(binding['layout']['final_page_map']['page_count'], rendered.page_count)

    def test_final_receipt_cannot_claim_an_extra_or_unobserved_layout_pass(self):
        value = self.genuine(); arguments = value['arguments']; result = value['manifest']['result']
        prepared = self.m._prepared_bytes(**arguments)
        for change in ('extra', 'pass_count', 'native_count', 'wrong_map', 'wrong_source', 'wrong_final_pdf'):
            broken = deepcopy(result); layout = broken['binding']['layout']
            if change == 'extra': layout['passes'].append(deepcopy(layout['passes'][-1]))
            elif change == 'pass_count': layout['pass_count'] += 1
            elif change == 'native_count': layout['native_inspection_invocations'] = 0
            elif change == 'wrong_map': layout['final_page_map']['findings'][0]['first_page'] = 1
            elif change == 'wrong_source': broken['binding']['source_projection']['request_sha256'] = '0' * 64
            else: layout['passes'][-1]['render_result']['pdf_sha256'] = '0' * 64
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.m._stored_manifest(broken, value['pdf'], 'a' * 32, prepared,
                    arguments['resources'], sha256(canonical(broken)).hexdigest(), sha256(value['pdf']).hexdigest())


class FinalStorageTests(Inputs, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.run_id = 'b' * 32

    def use_genuine(self):
        value = self.genuine(); arguments = deepcopy(value['arguments'])
        self.bound = arguments['bound_request']; self.assets = arguments['resources']
        return value

    def execute(self):
        return self.m.execute_stored_final_document_candidate(**self.arguments(),
            directory=self.root, run_id=self.run_id,
            expected_storage_profile_sha256=self.m.STORAGE_PROFILE_SHA256)

    def stage(self):
        value = self.use_genuine(); run = self.root / self.run_id; run.mkdir(mode=0o700)
        manifest = deepcopy(value['manifest']); manifest['run_id'] = self.run_id
        for name, data in [('candidate.pdf', value['pdf']), ('manifest.json', canonical(manifest)),
            (self.run_id + '.json', receipts._receipt_bytes(self.run_id, 'SUCCEEDED', manifest['result_sha256']))]:
            path = run / name; path.write_bytes(data); path.chmod(0o600)
        return value, run, manifest

    def recover(self, value, **changes):
        kwargs = dict(expected_result_sha256=value['manifest']['result_sha256'],
                      expected_pdf_sha256=value['manifest']['pdf_sha256'])
        kwargs.update(changes)
        return self.m.read_stored_final_document_candidate(**self.arguments(),
            directory=self.root, run_id=self.run_id,
            expected_storage_profile_sha256=self.m.STORAGE_PROFILE_SHA256, **kwargs)

    def snapshot(self, run):
        return {p.name: (p.read_bytes(), p.stat().st_ino, p.stat().st_mode,
                        p.stat().st_mtime_ns) for p in run.iterdir()}

    def test_read_only_recovery_returns_exact_bundle_without_native_or_writes(self):
        value, run, manifest = self.stage(); before = self.snapshot(run)
        with patch.object(raster, 'render_preloaded_raster_pdf') as render, \
                patch.object(native, 'execute_pdf_native_source_job') as inspect, \
                patch.object(self.m, '_run_locations') as locate, \
                patch.object(previous, '_write_stored_data') as write, \
                patch.object(previous, '_write_stored_receipt') as commit:
            pdf, actual = self.recover(value)
        self.assertEqual(pdf, value['pdf']); self.assertEqual(actual, manifest)
        self.assertEqual(before, self.snapshot(run))
        for operation in (render, inspect, locate, write, commit): operation.assert_not_called()

    def test_consumed_attempt_never_renders_again(self):
        (self.root / self.run_id).mkdir(mode=0o700)
        with patch.object(self.m, 'execute_final_document_candidate') as execute:
            with self.assertRaises(self.m.PdfFinalDocumentError): self.execute()
        execute.assert_not_called()

    def test_generation_failure_preserves_claim_without_successful_receipt(self):
        with patch.object(self.m, 'execute_final_document_candidate', side_effect=ValueError('PRIVATE')) as execute:
            with self.assertRaises(self.m.PdfFinalDocumentError) as error: self.execute()
        self.assertEqual(execute.call_count, 1); self.assertNotIn('PRIVATE', str(error.exception))
        self.assertTrue((self.root / self.run_id).is_dir())
        self.assertEqual(list((self.root / self.run_id).iterdir()), [])

    def test_wrong_recovery_expectations_and_corruption_are_read_only_refusals(self):
        value, run, _ = self.stage(); before = self.snapshot(run)
        for key in ('expected_result_sha256', 'expected_pdf_sha256'):
            with self.subTest(key=key), self.assertRaises(self.m.PdfFinalDocumentError):
                self.recover(value, **{key: '0' * 64})
        self.assertEqual(before, self.snapshot(run))
        path = run / 'candidate.pdf'; path.write_bytes(path.read_bytes() + b'corrupt')
        corrupt = self.snapshot(run)
        with self.assertRaises(self.m.PdfFinalDocumentError): self.recover(value)
        self.assertEqual(corrupt, self.snapshot(run))

    def test_missing_extra_linked_and_noncanonical_members_refuse(self):
        value, run, _ = self.stage()
        extra = run / 'extra'; extra.write_bytes(b'x')
        with self.assertRaises(self.m.PdfFinalDocumentError): self.recover(value)
        extra.unlink()
        original = (run / 'manifest.json').read_bytes()
        (run / 'manifest.json').write_bytes(b' ' + original)
        with self.assertRaises(self.m.PdfFinalDocumentError): self.recover(value)
        (run / 'manifest.json').write_bytes(original)
        os.link(run / 'candidate.pdf', self.root / 'linked')
        with self.assertRaises(self.m.PdfFinalDocumentError): self.recover(value)
        (self.root / 'linked').unlink(); (run / (self.run_id + '.json')).unlink()
        with self.assertRaises(self.m.PdfFinalDocumentError): self.recover(value)

    def test_writer_handoff_same_bytes_replacement_prevents_receipt_commit(self):
        value = self.use_genuine(); real = previous._write_stored_data; replaced = False
        def write(fd, name, data, limit):
            nonlocal replaced
            identity = real(fd, name, data, limit)
            if not replaced:
                replaced = True
                os.unlink(name, dir_fd=fd)
                new = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=fd)
                try:
                    position = 0
                    while position < len(data): position += os.write(new, data[position:])
                finally: os.close(new)
            return identity
        with patch.object(self.m, 'execute_final_document_candidate', return_value=value['pair']), \
                patch.object(previous, '_write_stored_data', side_effect=write):
            with self.assertRaises(self.m.PdfFinalDocumentError): self.execute()
        self.assertTrue(replaced)
        self.assertFalse((self.root / self.run_id / (self.run_id + '.json')).exists())

    def test_receipt_failure_preserves_data_without_success(self):
        value = self.use_genuine()
        with patch.object(self.m, 'execute_final_document_candidate', return_value=value['pair']), \
                patch.object(previous, '_write_stored_receipt', side_effect=OSError('sync')):
            with self.assertRaises(self.m.PdfFinalDocumentError): self.execute()
        self.assertEqual(set(p.name for p in (self.root / self.run_id).iterdir()),
                         {'candidate.pdf', 'manifest.json'})

    def test_equal_bytes_replacement_during_recovery_source_check_refuses(self):
        value, run, _ = self.stage(); real = self.m._storage_unchanged; replaced = False
        def check(*args):
            nonlocal replaced
            real(*args)
            if not replaced:
                replaced = True; path = run / 'manifest.json'; data = path.read_bytes()
                path.unlink(); path.write_bytes(data); path.chmod(0o600)
        with patch.object(self.m, '_storage_unchanged', side_effect=check), \
                self.assertRaises(self.m.PdfFinalDocumentError):
            self.recover(value)
        self.assertTrue(replaced)


if __name__ == '__main__':
    unittest.main()
