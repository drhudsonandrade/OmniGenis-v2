"""Truthful opt-in methodology records only observed technical reporting work."""
from copy import deepcopy
from hashlib import sha256
import inspect
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from reporting import pdf_bound_candidate as consumer
from reporting import pdf_generated_source_job as generated
from tests.test_reporting_pdf_bound_candidate import bound_request, canonical, source

MODE = 'technical-assembly-v1'
LEGACY = 'source-only-v1'


class TechnicalMethodologyTests(unittest.TestCase):
    """Exercise source projection, refusal and real persisted-candidate recovery."""

    def setUp(self):
        """Allocate one private attempt only after the explicit API exists."""
        self.assertIn('methodology_profile', inspect.signature(
            consumer.execute_bound_qualification_pdf_candidate).parameters,
            'explicit technical methodology profile missing')
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.bound = bound_request()
        self.environment = patch.dict(os.environ, {
            'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE': 'qualification-only'})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        os.environ.pop('OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED', None)

    def prepare(self, bound=None, mode=MODE):
        """Use the same admission and projection invoked by both public routes."""
        return consumer._prepare(self.bound if bound is None else bound,
            generated.PROFILE_SHA256, mode)

    def method(self, arguments):
        """Read the method in the real identity/provenance section."""
        return arguments['presentation_ir']['components'][0]['content'][
            'canonical_interpretation.provenance']['methodology']

    def test_record_binds_exact_request_sources_and_observed_steps(self):
        """The immutable record describes verified reporting work, not new analysis."""
        arguments, binding = self.prepare()
        method = self.method(arguments)
        record = method['execution_record']
        self.assertEqual(record['schema'], 'technical-report-assembly-execution-v1')
        self.assertEqual(record['request_sha256'], self.bound.request.request_sha256)
        self.assertEqual(record['source_binding_sha256'], self.bound.sources.expected_binding.binding_sha256)
        self.assertEqual(record['canonical_result_sha256'], self.bound.request.source_binding.canonical_result.sha256)
        self.assertEqual(record['evidence_snapshot_sha256'], self.bound.request.source_binding.evidence_snapshot.sha256)
        self.assertEqual(record['reference_bundle_sha256'], self.bound.request.source_binding.reference_bundle_sha256)
        self.assertEqual(record['completed_reporting_steps'], [
            'REQUEST_SNAPSHOT_BINDING', 'CANONICAL_SOURCE_BYTE_INTEGRITY',
            'DECLARED_FINDING_INVENTORY_ACCOUNTING'])
        self.assertEqual(record['declared_finding_count'], 2)
        self.assertEqual(method['execution_record_sha256'], sha256(canonical(record)).hexdigest())
        self.assertEqual(binding['methodology_record_sha256'], method['execution_record_sha256'])
        self.assertEqual(binding['methodology_profile'], MODE)
        self.assertEqual(binding['schema'], 'bound-qualification-pdf-candidate-v2')
        self.assertIs(binding['release_authorized'], False)

    def test_missing_upstream_details_stay_unavailable_not_zero_or_negative(self):
        """VCF provenance cannot manufacture assay, quality or performed classes."""
        method = self.method(self.prepare()[0])
        record = method['execution_record']
        for field in ('upstream_execution_record', 'laboratory', 'assay', 'quality',
                      'callable_scope', 'requested_scientific_capabilities',
                      'performed_scientific_capabilities'):
            self.assertEqual(record[field], {'availability': 'NOT_AVAILABLE'})
        self.assertEqual(record['scientific_operations_executed_by_report_job'], [])
        self.assertEqual(record['declared_upstream_input_format'], 'VCF')
        self.assertIn('does not execute sequencing or variant analysis', method['brief'])
        self.assertIn('does not establish a negative result', method['brief'])
        self.assertNotIn('sequencing performed', method['brief'])

    def test_legacy_projection_and_binding_are_unchanged_by_default(self):
        """The new mode never alters the previous source-only result or reader."""
        default = consumer._prepare(self.bound, generated.PROFILE_SHA256)
        explicit = self.prepare(mode=LEGACY)
        self.assertEqual(canonical(default), canonical(explicit))
        arguments, binding = default
        self.assertEqual(binding['schema'], 'bound-qualification-pdf-candidate-v1')
        self.assertNotIn('methodology_profile', binding)
        self.assertNotIn('methodology', arguments['presentation_ir']['components'][0][
            'content']['canonical_interpretation.provenance'])
        enriched, _ = self.prepare()
        restored = deepcopy(enriched)
        for component in restored['presentation_ir']['components']:
            provenance = component['content'].get('canonical_interpretation.provenance')
            if provenance is not None:
                provenance.pop('methodology')
        self.assertEqual(restored['presentation_ir'], arguments['presentation_ir'])

    def test_unknown_or_coerced_profile_refuses_without_any_attempt(self):
        """A mode is a strict closed identifier, never an inferred truthy option."""
        for mode in ('', 'latest', 'clinical', 'Technical-Assembly-v1', True, None, 1):
            with self.subTest(mode=mode), patch.object(
                generated, 'execute_raster_observed_pdf_generated_source_job') as worker:
                with self.assertRaises(consumer.PdfBoundCandidateError) as caught:
                    consumer.execute_bound_qualification_pdf_candidate(self.bound,
                        directory=self.directory, run_id='b' * 32,
                        expected_resource_profile_sha256=generated.PROFILE_SHA256,
                        methodology_profile=mode)
                self.assertEqual(str(caught.exception), 'pdf_bound_candidate_input_invalid')
                worker.assert_not_called()
                self.assertEqual(list(self.directory.iterdir()), [])

    def test_source_bytes_and_reported_items_are_preserved(self):
        """Methodology is derived reporting metadata, not a source rewrite."""
        before = self.bound.sources.canonical_result_bytes
        arguments, _ = self.prepare()
        document, _ = source()
        self.assertEqual(self.bound.sources.canonical_result_bytes, before)
        self.assertEqual(arguments['presentation_ir']['components'][1]['content'][
            'canonical_interpretation.items'], document['canonical_payload']['items'])
        self.assertEqual(arguments['presentation_ir']['components'][3]['content'][
            'canonical_interpretation.limitations'], document['limitations'])

    def test_zero_findings_do_not_become_unperformed_negative_science(self):
        """An empty admitted inventory does not provide a callable-scope result."""
        document, _ = source()
        document['canonical_payload']['items'] = []
        document['canonical_payload']['interpretation_item_count'] = 0
        document['raw_artifact_refs'] = []
        record = self.method(self.prepare(bound_request(document, finding_ids=()))[0])['execution_record']
        self.assertEqual(record['declared_finding_count'], 0)
        self.assertEqual(record['callable_scope'], {'availability': 'NOT_AVAILABLE'})
        self.assertEqual(record['scientific_operations_executed_by_report_job'], [])

    def test_cutoff_is_a_preserved_source_declaration(self):
        """Report generation neither refreshes nor upgrades evidence timing."""
        record = self.method(self.prepare()[0])['execution_record']
        document, _ = source()
        self.assertEqual(record['declared_evidence_cutoff'], document['canonical_payload']['as_of_date'])
        self.assertIs(record['upstream_scientific_execution_verified'], False)

    def test_detached_record_tampering_does_not_change_next_projection(self):
        """Mutation of an exported dictionary cannot modify sealed inputs or later output."""
        original, original_binding = self.prepare()
        captured = canonical(original)
        changed, _ = self.prepare()
        self.method(changed)['execution_record']['laboratory'] = {'availability': 'PRESENT'}
        actual, binding = self.prepare()
        self.assertEqual(canonical(actual), captured)
        self.assertEqual(binding, original_binding)

    def test_disabled_qualification_never_admits_methodology(self):
        """Content enrichment cannot bypass the existing disable switch."""
        with patch.dict(os.environ, {'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED': '1'}), patch.object(
                generated, 'execute_raster_observed_pdf_generated_source_job') as worker:
            with self.assertRaises(consumer.PdfBoundCandidateError):
                consumer.execute_bound_qualification_pdf_candidate(self.bound,
                    directory=self.directory, run_id='b' * 32,
                    expected_resource_profile_sha256=generated.PROFILE_SHA256,
                    methodology_profile=MODE)
            worker.assert_not_called()
            self.assertEqual(list(self.directory.iterdir()), [])

    def test_real_method_candidate_persists_and_recovers_only_in_matching_mode(self):
        """The actual new-method PDF passes native checks and exact private readback."""
        result, observation, binding, manifest = consumer.execute_bound_qualification_pdf_candidate(
            self.bound, directory=self.directory, run_id='b' * 32,
            expected_resource_profile_sha256=generated.PROFILE_SHA256,
            methodology_profile=MODE)
        self.assertGreater(result.page_count, 0)
        self.assertTrue(result.pdf_bytes.startswith(b'%PDF-1.7'))
        self.assertEqual(binding['ir_sha256'], result.ir_sha256)
        self.assertEqual(manifest['result'], result.to_dict())
        self.assertEqual(binding['methodology_record_sha256'],
                         self.method(self.prepare()[0])['execution_record_sha256'])
        arguments = dict(directory=self.directory, run_id='b' * 32,
            expected_result_sha256=result.result_sha256,
            expected_pdf_sha256=result.pdf_sha256,
            expected_resource_profile_sha256=generated.PROFILE_SHA256)
        before = {str(p): p.read_bytes() for p in self.directory.rglob('*') if p.is_file()}
        with patch.object(generated, 'execute_raster_observed_pdf_generated_source_job') as worker:
            pdf, recovered, recovered_binding = consumer.read_bound_qualification_pdf_candidate(
                self.bound, methodology_profile=MODE, **arguments)
            with self.assertRaises(consumer.PdfBoundCandidateError):
                consumer.read_bound_qualification_pdf_candidate(self.bound, **arguments)
            worker.assert_not_called()
        self.assertEqual(pdf, result.pdf_bytes)
        self.assertEqual(recovered, manifest)
        self.assertEqual(recovered_binding, binding)
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.directory.rglob('*') if p.is_file()})
