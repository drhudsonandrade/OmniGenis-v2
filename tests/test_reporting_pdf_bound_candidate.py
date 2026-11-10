"""Source-bound qualification joins preserve inventory and single-use attempts."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import importlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from omnigenis.capabilities.canonical_interpretation import build_canonical_interpretation_object
from reporting import pdf_generated_source_job as generated
from reporting import pdf_candidate_store as storage
from reporting import localization
from reporting.bindings import (ReportArtifactBinding, ReportSourceBinding,
    ReportSourceIdentity, bind_report_sources)
from reporting.completeness import ReportCompletenessPlan, UpstreamFindingExclusion
from reporting.contracts import REPORT_ID, validate_rpt01_contracts
from reporting.requests import ReportRequestSnapshot, bind_report_request
from reporting.workflow import ConsentStatus, ReviewState
from tests import test_canonical_interpretation_capability as fixtures

ROOT = Path(__file__).resolve().parents[1] / 'reporting'
MODE = 'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE'
DISABLE = 'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED'
IDS = ('omnigenis:small-variant:v1:sha256:' + 'a' * 64,
       'omnigenis:small-variant:v1:sha256:' + 'b' * 64)
SECTIONS = ('identity-and-provenance', 'verified-source-interpretations',
            'unresolved-evidence-conflicts', 'limitations-and-not-assessed',
            'sources-and-versioning')
CONTRACT_FILES = {'catalog': 'catalog.v1.json',
    'section_contracts': 'sections/e1a-small-variant-report.v1.json',
    'intended_use': 'intended-use/e1a-small-variant-report.v1.json',
    'report_capability_manifest': 'capabilities/e1a-small-variant-report.v1.json'}


def canonical(value):
    """Encode fixture expectations independently of the consumer implementation."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


def source():
    """Use the existing producer with synthetic model and evidence fixtures only."""
    first = fixtures.model(IDS[0])
    model = replace(first, variants=(first.variants[0],
        replace(first.variants[0], canonical_variant_id=IDS[1])))
    first_snapshot = fixtures.evidence_snapshot(model, variant_id=IDS[0])
    conflict = fixtures.evidence_snapshot(model, variant_id=IDS[1], conflict=True,
        classification='Conflicting classifications of pathogenicity',
        review_status='criteria provided, conflicting classifications')
    snapshot = replace(first_snapshot, items=first_snapshot.items + conflict.items)
    result = build_canonical_interpretation_object(canonical_model=model,
        evidence_snapshot=snapshot, as_of_date='2026-09-24')
    if not result.passed:
        raise AssertionError(result.errors)
    return result.to_dict(), canonical(snapshot.to_dict())


def bound_request(document=None, *, raw=None, finding_ids=IDS, exclusions=(),
                  section_ids=SECTIONS, required_ids=SECTIONS, **request_changes):
    """Resolve a real request against actual report pins and synthetic sources."""
    original, evidence = source()
    raw = canonical(original if document is None else document) if raw is None else raw
    identity = ReportSourceIdentity('SYNTHETIC-NAMESPACE', 'SYNTHETIC-CASE',
        'SYNTHETIC-SUBJECT', 'SYNTHETIC-SAMPLE', 'SYNTHETIC-ANALYSIS', '1', None)
    binding = ReportSourceBinding(identity, ReportArtifactBinding('SYNTHETIC-INPUT', '3' * 64),
        ReportArtifactBinding('SYNTHETIC-CANONICAL', sha256(raw).hexdigest()),
        ReportArtifactBinding('SYNTHETIC-EVIDENCE', sha256(evidence).hexdigest()), '4' * 64)
    sources = bind_report_sources(expected_binding=binding, resolved_binding=binding,
        canonical_result_bytes=raw, evidence_snapshot_bytes=evidence)
    plan = ReportCompletenessPlan(binding.binding_sha256, finding_ids,
        section_ids, required_ids, exclusions)
    contracts = validate_rpt01_contracts(report_id=REPORT_ID,
        **{key: json.loads((ROOT / path).read_bytes()) for key, path in CONTRACT_FILES.items()})
    if not contracts.passed:
        raise AssertionError(contracts.errors)
    values = dict(request_id='SYNTHETIC-REQUEST', requester_id='SYNTHETIC-REQUESTER',
        source_binding=binding, completeness_plan_sha256=plan.plan_sha256,
        report_contract_bundle_sha256=contracts.bundle_sha256,
        locale_pack=ReportArtifactBinding('SYNTHETIC-LOCALE', sha256(
            (ROOT / 'locales/en-US.v1.json').read_bytes()).hexdigest()),
        policy_record=ReportArtifactBinding('SYNTHETIC-POLICY', 'e' * 64),
        consent_status=ConsentStatus.VERIFIED,
        consent_record=ReportArtifactBinding('SYNTHETIC-CONSENT', 'f' * 64),
        review_state=ReviewState.APPROVED,
        review_record=ReportArtifactBinding('SYNTHETIC-REVIEW', '0' * 64))
    values.update(request_changes)
    return bind_report_request(request=ReportRequestSnapshot(**values),
        resolved_request=ReportRequestSnapshot(**values), sources=sources, plan=plan)


class BoundCandidateTests(unittest.TestCase):
    """Exercise real joins; cache one actual native result only for fault injection."""

    actual_pair = None
    actual_failure = None

    def setUp(self):
        """Check the missing API first, then allocate private synthetic storage."""
        self.assertIsNotNone(importlib.util.find_spec('reporting.pdf_bound_candidate'),
                             'source-bound candidate consumer missing')
        self.m = importlib.import_module('reporting.pdf_bound_candidate')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.run_id = 'a' * 32
        self.bound = bound_request()
        self.env = patch.dict(os.environ, {MODE: 'qualification-only'})
        self.env.start()
        self.addCleanup(self.env.stop)
        os.environ.pop(DISABLE, None)

    def execute(self, bound=None, **changes):
        """Call the public API without supplying source projections or context IDs."""
        return self.m.execute_bound_qualification_pdf_candidate(
            self.bound if bound is None else bound, directory=self.root,
            run_id=self.run_id, expected_resource_profile_sha256=generated.PROFILE_SHA256,
            **changes)

    def refused_before_work(self, bound=None):
        """An admission refusal must leave storage empty and never invoke a worker."""
        with patch.object(generated, 'execute_raster_observed_pdf_generated_source_job') as worker:
            with self.assertRaises(self.m.PdfBoundCandidateError) as caught:
                self.execute(bound)
        worker.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertEqual(str(caught.exception), 'pdf_bound_candidate_input_invalid')

    def capture_ir(self, bound=None):
        """Inspect actual upstream assembly while deliberately refusing native work."""
        with patch.object(generated, 'execute_raster_observed_pdf_generated_source_job',
                          side_effect=ValueError('synthetic worker refusal')) as worker:
            with self.assertRaises(self.m.PdfBoundCandidateError):
                self.execute(bound)
        self.assertEqual(worker.call_count, 1)
        self.captured_arguments = worker.call_args.kwargs
        return worker.call_args.kwargs['presentation_ir']

    def actual(self):
        """Render and inspect once through the actual new consumer for this class."""
        if type(self).actual_pair is None:
            with tempfile.TemporaryDirectory() as directory:
                result, observation, binding, manifest = self.new_actual(Path(directory))
                self.assertEqual(manifest['result'], result.to_dict())
                self.assertEqual(binding['request_sha256'], self.bound.request.request_sha256)
                type(self).actual_pair = result, observation
        return type(self).actual_pair

    def new_actual(self, directory):
        """Remember a failed native fixture so dependent tests fail without retrying it."""
        if type(self).actual_failure is not None:
            self.fail('actual native fixture already failed: ' + type(self).actual_failure)
        try:
            return self.m.execute_bound_qualification_pdf_candidate(self.bound,
                directory=directory, run_id=self.run_id,
                expected_resource_profile_sha256=generated.PROFILE_SHA256)
        except Exception as failure:
            type(self).actual_failure = type(failure).__name__ + ': ' + str(failure)
            raise

    def test_actual_candidate_persists_and_recovers_without_reexecution(self):
        """A genuine inspected PDF survives the joined private storage boundary."""
        result, observation, binding, manifest = self.new_actual(self.root)
        type(self).actual_pair = result, observation
        self.assertGreater(result.page_count, 0)
        self.assertTrue(result.pdf_bytes.startswith(b'%PDF-1.7'))
        self.assertEqual(binding['finding_count'], 2)
        self.assertEqual(binding['family_id'], 'e1a-small-variant')
        self.assertEqual(binding['request_sha256'], self.bound.request.request_sha256)
        self.assertEqual(binding['source_binding_sha256'], self.bound.sources.expected_binding.binding_sha256)
        self.assertEqual(binding['completeness_plan_sha256'], self.bound.plan.plan_sha256)
        self.assertEqual(binding['ir_sha256'], result.ir_sha256)
        for flag in ('upstream_authorization_validated', 'evidence_membership_validated',
                     'supported_execution', 'release_authorized', 'default_pipeline_activated'):
            self.assertIs(binding[flag], False)
        self.assertIs(binding['declared_source_inventory_accounted'], True)
        self.assertIs(manifest['release_authorized'], False)
        args = dict(directory=self.root, run_id=self.run_id,
            expected_result_sha256=result.result_sha256, expected_pdf_sha256=result.pdf_sha256,
            expected_resource_profile_sha256=generated.PROFILE_SHA256)
        before = {p: (p.stat().st_ino, p.stat().st_mtime_ns, p.read_bytes())
                  for p in self.root.rglob('*') if p.is_file()}
        with patch.object(generated, 'execute_raster_observed_pdf_generated_source_job') as worker:
            pdf, recovered, recovered_binding = self.m.read_bound_qualification_pdf_candidate(
                self.bound, **args)
            with self.assertRaises(self.m.PdfBoundCandidateError):
                self.execute()
        worker.assert_not_called()
        self.assertEqual(pdf, result.pdf_bytes)
        self.assertEqual(recovered, manifest)
        self.assertEqual(recovered_binding, binding)
        self.assertEqual(before, {p: (p.stat().st_ino, p.stat().st_mtime_ns, p.read_bytes())
                         for p in self.root.rglob('*') if p.is_file()})

    def test_actual_projection_preserves_every_declared_item_and_limitation(self):
        """The real compiler/family/locale chain retains exact ordered source values."""
        ir = self.capture_ir()
        components = ir['components']
        self.assertEqual(tuple(c['component_id'] for c in components), SECTIONS)
        document, _ = source()
        self.assertEqual(components[1]['content']['canonical_interpretation.items'],
                         document['canonical_payload']['items'])
        self.assertEqual(components[3]['content']['canonical_interpretation.limitations'],
                         document['limitations'])
        self.assertEqual(components[0]['content']['canonical_interpretation.identity'],
                         self.bound.request.source_binding.identity.to_dict())
        conflicts = components[2]['content']['canonical_interpretation.conflicts']
        self.assertEqual(conflicts['availability'], 'NOT_ASSESSED')
        self.assertNotEqual(components[2]['state'], 'EXPLICIT_NO_CONFLICTS')
        self.assertIs(components[1]['content']['canonical_interpretation.items'][1]['source_conflict'], True)

    def test_empty_declared_inventory_remains_explicit(self):
        """The existing source contract permits zero findings without fabricating one."""
        document, _ = source()
        document['canonical_payload']['items'] = []
        document['canonical_payload']['interpretation_item_count'] = 0
        document['raw_artifact_refs'] = []
        ir = self.capture_ir(bound_request(document, finding_ids=()))
        self.assertEqual(ir['components'][1]['content']['canonical_interpretation.items'], [])
        self.assertEqual(ir['components'][1]['state'], 'EXPLICIT_NONE')

    def test_inconsistent_resolved_request_refuses_before_work(self):
        """A mutated resolved case cannot bypass revalidation of frozen records."""
        foreign = replace(self.bound.resolved_request.source_binding.identity, case_id='FOREIGN')
        object.__setattr__(self.bound.resolved_request, 'source_binding',
            replace(self.bound.resolved_request.source_binding, identity=foreign))
        self.refused_before_work()

    def test_changed_source_bytes_refuse_before_work(self):
        """The stored source digest is rechecked even on an already bound object."""
        object.__setattr__(self.bound.sources, 'canonical_result_bytes', b'{}')
        self.refused_before_work()

    def test_unverified_workflow_refuses_before_work(self):
        """Changing a retained consent assertion cannot keep a usable bound request."""
        object.__setattr__(self.bound.request, 'consent_status', ConsentStatus.WITHDRAWN)
        self.refused_before_work()

    def test_wrong_canonical_input_digest_refuses_before_work(self):
        """A different VCF digest cannot be attached to this declared canonical source."""
        document, _ = source()
        document['canonical_payload']['canonical_model_source_vcf_sha256'] = '1' * 64
        self.refused_before_work(bound_request(document))

    def test_wrong_contract_and_locale_pins_refuse_before_work(self):
        """Agreement between request snapshots cannot substitute for actual files."""
        for change in ({'report_contract_bundle_sha256': '1' * 64},
                       {'locale_pack': ReportArtifactBinding('SYNTHETIC-LOCALE', '1' * 64)}):
            with self.subTest(change=change):
                self.refused_before_work(bound_request(**change))

    def test_inventory_loss_addition_and_reordering_refuse_before_work(self):
        """Expected IDs must equal the actual full ordered inventory exactly."""
        for ids in (IDS[:1], IDS + ('SYNTHETIC-EXTRA',), tuple(reversed(IDS))):
            with self.subTest(ids=ids):
                self.refused_before_work(bound_request(finding_ids=ids))

    def test_duplicate_source_item_refuses_before_work(self):
        """No duplicate source occurrence is silently collapsed to a unique ledger."""
        document, _ = source()
        document['canonical_payload']['items'][1] = deepcopy(document['canonical_payload']['items'][0])
        self.refused_before_work(bound_request(document))

    def test_declared_count_and_identifier_shapes_refuse_before_work(self):
        """Item identities and cardinality retain their exact declared types."""
        for value in (True, 1, 3):
            document, _ = source()
            document['canonical_payload']['interpretation_item_count'] = value
            self.refused_before_work(bound_request(document))
        document, _ = source()
        document['canonical_payload']['items'][0]['canonical_variant_id'] = 'UNKNOWN'
        self.refused_before_work(bound_request(document))

    def test_unsupported_exclusions_refuse_before_work(self):
        """The whole-inventory consumer does not invent an exclusion-policy executor."""
        exclusion = UpstreamFindingExclusion(IDS[0],
            ReportArtifactBinding('SYNTHETIC-EXCLUSION-POLICY', 'a' * 64), 'SYNTHETIC-REASON')
        self.refused_before_work(bound_request(exclusions=(exclusion,)))

    def test_section_inventory_and_required_set_refuse_before_work(self):
        """Neither the plan nor the projection may silently remove a required section."""
        self.refused_before_work(bound_request(section_ids=SECTIONS[:-1], required_ids=SECTIONS[:-1]))
        self.refused_before_work(bound_request(required_ids=SECTIONS[:-1]))

    def test_ambiguous_or_precision_losing_json_refuses_before_work(self):
        """Canonical integer-only source admission refuses coercion and duplicate keys."""
        document, _ = source()
        valid = canonical(document)
        invalid = [valid + b'\n', b'{"x":1,"x":2}', b'{"x":NaN}',
                   b'{"x":0.12345678901234567890}', b'\xef\xbb\xbf' + valid,
                   b'[' * 100 + b'0' + b']' * 100]
        for raw in invalid:
            with self.subTest(raw=raw[:30]):
                self.refused_before_work(bound_request(raw=raw))

    def test_failed_or_unknown_source_envelope_refuses_before_work(self):
        """The consumer preserves a known producer declaration without promoting failures."""
        for key, value in (('canonical_status', 'FAIL'), ('availability', 'BLOCKED'),
                           ('capability_version', '2.0.0'), ('capability_id', 'UNKNOWN')):
            document, _ = source()
            document[key] = value
            self.refused_before_work(bound_request(document))

    def test_wrong_item_types_and_unknown_fields_refuse_before_work(self):
        """The admitted source shape never silently coerces or discards item fields."""
        for key, value in (('source_conflict', 'false'), ('source_vcv_version', True),
                           ('condition_names', 'condition'), ('extra', 'UNKNOWN')):
            document, _ = source()
            document['canonical_payload']['items'][0][key] = value
            self.refused_before_work(bound_request(document))

    def test_context_identifiers_are_derived_without_normalization(self):
        """The shared context grammar preserves supported colon and long identifiers."""
        identifier = 'SYNTHETIC:' + 'X' * 190
        bound = bound_request(request_id=identifier)
        self.capture_ir(bound)
        self.assertEqual(self.captured_arguments['job_id'], identifier)
        self.assertEqual(self.captured_arguments['namespace_id'], 'SYNTHETIC-NAMESPACE')
        self.assertEqual(self.captured_arguments['request_sha256'], bound.request.request_sha256)

    def test_disabled_policy_refuses_before_work(self):
        """The optional consumer remains disabled without the existing opt-in."""
        os.environ.pop(MODE)
        self.refused_before_work()
        os.environ[MODE] = 'qualification-only'
        os.environ[DISABLE] = '1'
        self.refused_before_work()

    def test_locale_reload_cannot_change_captured_titles(self):
        """A transient independently loaded locale cannot escape the request pin."""
        locale = json.loads((ROOT / 'locales/en-US.v1.json').read_bytes())
        locale['labels'][SECTIONS[1]] = 'UNBOUND TITLE'
        with patch.object(localization, '_load_locale', return_value=locale):
            self.refused_before_work()

    def test_projection_preserves_exact_numeric_types(self):
        """Boolean/float equality cannot conceal a changed canonical integer value."""
        original = self.m.localize_presentation_ir

        def changed(**arguments):
            """Alter an actual localized result and recompute its internally valid digest."""
            localized = original(**arguments)
            ir = localized.to_dict()['localized_ir']
            ir['components'][1]['content']['canonical_interpretation.items'][0]['source_submission_count'] = True
            return replace(localized, localized_ir=ir, localized_ir_sha256=sha256(canonical(ir)).hexdigest())

        with patch.object(self.m, 'localize_presentation_ir', side_effect=changed):
            self.refused_before_work()

    def test_partial_attempt_is_not_rendered_again(self):
        """A consumed outer directory is enough to block automatic retry."""
        (self.root / self.run_id).mkdir(mode=0o700)
        with patch.object(generated, 'execute_raster_observed_pdf_generated_source_job') as worker:
            with self.assertRaises(self.m.PdfBoundCandidateError):
                self.execute()
        worker.assert_not_called()
        self.assertEqual(list((self.root / self.run_id).iterdir()), [])

    def test_failed_native_fixture_is_not_reexecuted(self):
        """Dependent fault tests report a failed fixture without another native attempt."""
        old_pair = type(self).actual_pair
        old_failure = getattr(type(self), 'actual_failure', None)
        self.addCleanup(setattr, type(self), 'actual_pair', old_pair)
        self.addCleanup(setattr, type(self), 'actual_failure', old_failure)
        type(self).actual_pair = None
        type(self).actual_failure = None
        with patch.object(self.m, 'execute_bound_qualification_pdf_candidate',
                          side_effect=ValueError('synthetic fixture failure')) as execute:
            for _ in range(2):
                with self.assertRaises((ValueError, AssertionError)):
                    self.actual()
        self.assertEqual(execute.call_count, 1)

    def test_source_mutation_during_generation_withholds_success(self):
        """Post-generation request/source checks run before candidate persistence."""
        pair = self.actual()

        def changed(**_arguments):
            """Inject source drift after an actual bound result has been obtained."""
            object.__setattr__(self.bound.sources, 'canonical_result_bytes', b'{}')
            return pair

        with patch.object(generated, 'execute_raster_observed_pdf_generated_source_job',
                          side_effect=changed), patch.object(storage, 'persist_qualification_pdf_candidate') as persist:
            with self.assertRaises(self.m.PdfBoundCandidateError):
                self.execute()
        persist.assert_not_called()

    def test_persistence_failure_preserves_consumed_attempt(self):
        """No candidate escapes a failed persistence operation or retries implicitly."""
        with patch.object(generated, 'execute_raster_observed_pdf_generated_source_job',
                          return_value=self.actual()) as worker:
            with patch.object(storage, 'persist_qualification_pdf_candidate',
                              side_effect=OSError('synthetic storage failure')):
                with self.assertRaises(self.m.PdfBoundCandidateError):
                    self.execute()
            with self.assertRaises(self.m.PdfBoundCandidateError):
                self.execute()
        self.assertEqual(worker.call_count, 1)
        self.assertFalse(any(p.name == 'candidate.pdf' for p in self.root.rglob('*')))

    def test_postcommit_failure_can_only_be_recovered_explicitly(self):
        """An existing committed candidate can be read without reentering generation."""
        pair = self.actual()
        original = storage.persist_qualification_pdf_candidate

        def after_commit(**arguments):
            """Inject one failure after the real storage commit and readback."""
            original(**arguments)
            raise OSError('synthetic postcommit failure')

        with patch.object(generated, 'execute_raster_observed_pdf_generated_source_job',
                          return_value=pair) as worker:
            with patch.object(storage, 'persist_qualification_pdf_candidate', side_effect=after_commit):
                with self.assertRaises(self.m.PdfBoundCandidateError):
                    self.execute()
            result = pair[0]
            pdf, manifest, binding = self.m.read_bound_qualification_pdf_candidate(self.bound,
                directory=self.root, run_id=self.run_id,
                expected_resource_profile_sha256=generated.PROFILE_SHA256,
                expected_result_sha256=result.result_sha256, expected_pdf_sha256=result.pdf_sha256)
            with self.assertRaises(self.m.PdfBoundCandidateError):
                self.execute()
        self.assertEqual(worker.call_count, 1)
        self.assertEqual(pdf, result.pdf_bytes)
        self.assertEqual(manifest['result_sha256'], result.result_sha256)
        self.assertIs(binding['release_authorized'], False)

    def test_wrong_recovery_expectations_never_return_bytes(self):
        """A stored candidate is not authoritative for its own independent expectations."""
        with patch.object(generated, 'execute_raster_observed_pdf_generated_source_job',
                          return_value=self.actual()):
            result, _, _, _ = self.execute()
        with patch.object(generated, 'execute_raster_observed_pdf_generated_source_job') as worker:
            with self.assertRaises(self.m.PdfBoundCandidateError):
                self.m.read_bound_qualification_pdf_candidate(self.bound,
                    directory=self.root, run_id=self.run_id,
                    expected_resource_profile_sha256=generated.PROFILE_SHA256,
                    expected_result_sha256='0' * 64, expected_pdf_sha256=result.pdf_sha256)
        worker.assert_not_called()
