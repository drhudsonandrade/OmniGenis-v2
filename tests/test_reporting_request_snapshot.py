"""Synthetic tests for immutable request metadata and source/plan binding."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator
from reporting.bindings import (
    BoundReportSources, ReportArtifactBinding, ReportSourceBinding,
    ReportSourceIdentity, bind_report_sources,
)
from reporting.completeness import (
    ReportCompletenessPlan, FindingProjection, SectionAvailability,
    validate_report_completeness,
)
from reporting.workflow import ConsentStatus, ReviewState

ROOT = Path(__file__).resolve().parents[1]


def synthetic_sources():
    """Return explicit synthetic artifacts, never patient or approval evidence."""
    result = b'{"synthetic":true,"value":0.12345678901234567890}'
    evidence = b'SYNTHETIC_EVIDENCE_SNAPSHOT'
    identity = ReportSourceIdentity('SYNTHETIC-NAMESPACE', 'SYNTHETIC-CASE',
        'SYNTHETIC-SUBJECT', 'SYNTHETIC-SAMPLE', 'SYNTHETIC-ANALYSIS', '1', None)
    binding = ReportSourceBinding(identity, ReportArtifactBinding('SYNTHETIC-INPUT', 'a' * 64),
        ReportArtifactBinding('SYNTHETIC-RESULT', hashlib.sha256(result).hexdigest()),
        ReportArtifactBinding('SYNTHETIC-EVIDENCE', hashlib.sha256(evidence).hexdigest()), 'b' * 64)
    return bind_report_sources(expected_binding=binding, resolved_binding=binding,
        canonical_result_bytes=result, evidence_snapshot_bytes=evidence)


class ReportRequestSnapshotTests(unittest.TestCase):
    """A bound snapshot is not authenticated authorization or final delivery."""

    def setUp(self):
        """Require the actual missing boundary before constructing each fixture."""
        name = 'reporting.requests'
        self.assertIsNotNone(importlib.util.find_spec(name), 'report request module is missing')
        self.m = importlib.import_module(name)
        self.sources = synthetic_sources()
        self.plan = ReportCompletenessPlan(self.sources.expected_binding.binding_sha256,
            ('SYNTHETIC-F1',), ('identity', 'findings'), ('identity', 'findings'))
        self.request = self.make_snapshot()

    def make_snapshot(self, **changes):
        """Supply independently resolved synthetic control/profile references."""
        data = dict(request_id='SYNTHETIC-REQUEST', requester_id='SYNTHETIC-REQUESTER',
            source_binding=self.sources.expected_binding, completeness_plan_sha256=self.plan.plan_sha256,
            report_contract_bundle_sha256='c' * 64,
            locale_pack=ReportArtifactBinding('SYNTHETIC-LOCALE', 'd' * 64),
            policy_record=ReportArtifactBinding('SYNTHETIC-POLICY', 'e' * 64),
            consent_status=ConsentStatus.VERIFIED,
            consent_record=ReportArtifactBinding('SYNTHETIC-CONSENT', 'f' * 64),
            review_state=ReviewState.APPROVED,
            review_record=ReportArtifactBinding('SYNTHETIC-REVIEW', '0' * 64),
            locale_id='en-US', intended_use_id='e1a-technical-validation')
        data.update(changes)
        return self.m.ReportRequestSnapshot(**data)

    def build(self, **changes):
        """Use the public factory without manufacturing a runtime approval."""
        data = dict(request=self.request, resolved_request=self.make_snapshot(),
                    sources=self.sources, plan=self.plan)
        data.update(changes)
        return self.m.bind_report_request(**data)

    def rejected(self, **changes):
        """Require a content-free typed failure rather than a partial result."""
        with self.assertRaises(self.m.ReportRequestError):
            self.build(**changes)

    def schema_validator(self):
        """Validate the self-contained snapshot schema without any external resolver."""
        schema = json.loads((ROOT / 'schemas/report-request-snapshot.v1.schema.json').read_text())
        Draft202012Validator.check_schema(schema)
        return Draft202012Validator(schema)

    def test_equal_independently_built_snapshots_bind(self):
        """Equality is by all metadata values, not Python object identity."""
        bound = self.build()
        self.assertIs(bound.request, self.request)
        self.assertIsNot(bound.request, bound.resolved_request)
        self.assertEqual(bound.to_dict()['request_sha256'], self.request.request_sha256)
        self.assertEqual(bound.to_dict()['release_authorization'], 'NOT_ESTABLISHED')

    def test_source_identity_dimensions_never_cross_bind(self):
        """Namespace, case, subject, sample, specimen and analysis are exact joins."""
        for key in ('namespace_id', 'case_id', 'subject_id', 'sample_id', 'specimen_id',
                    'analysis_id', 'analysis_revision'):
            with self.subTest(key=key):
                identity = replace(self.request.source_binding.identity, **{key: 'FOREIGN'})
                source = replace(self.request.source_binding, identity=identity)
                self.rejected(resolved_request=self.make_snapshot(source_binding=source))

    def test_request_id_mismatch_is_rejected(self):
        """A different request is not interchangeable with an identical analysis."""
        self.rejected(resolved_request=self.make_snapshot(request_id='OTHER-REQUEST'))

    def test_requester_id_mismatch_is_rejected(self):
        """A matching case does not authorize substituting the requester."""
        self.rejected(resolved_request=self.make_snapshot(requester_id='OTHER-REQUESTER'))

    def test_control_and_locale_revisions_are_exact(self):
        """Every consent, review, policy and language-pack reference participates."""
        for key in ('consent_record', 'review_record', 'policy_record', 'locale_pack'):
            old = getattr(self.request, key)
            for new in (replace(old, artifact_id=old.artifact_id + '-2'), replace(old, sha256='1' * 64)):
                with self.subTest(key=key):
                    self.rejected(resolved_request=self.make_snapshot(**{key: new}))

    def test_contract_and_plan_revisions_are_exact(self):
        """Current source bytes cannot make a stale contract or plan current."""
        for key in ('report_contract_bundle_sha256', 'completeness_plan_sha256'):
            with self.subTest(key=key):
                self.rejected(resolved_request=self.make_snapshot(**{key: '2' * 64}))

    def test_equal_foreign_requests_do_not_bind_local_sources(self):
        """Expected/resolved agreement does not replace the sealed source check."""
        source = replace(self.request.source_binding,
                         reference_bundle_sha256='3' * 64)
        request = self.make_snapshot(source_binding=source)
        self.rejected(request=request, resolved_request=request)

    def test_equal_requests_do_not_bypass_actual_plan_hash(self):
        """A matching request pair must still match the actual plan content."""
        request = self.make_snapshot(completeness_plan_sha256='4' * 64)
        self.rejected(request=request, resolved_request=request)

    def test_plan_must_belong_to_same_source_binding(self):
        """An independently valid plan from another source fails the join."""
        plan = replace(self.plan, source_binding_sha256='5' * 64)
        request = self.make_snapshot(completeness_plan_sha256=plan.plan_sha256)
        self.rejected(request=request, resolved_request=request, plan=plan)

    def test_unverified_or_withdrawn_consent_blocks_binding(self):
        """Snapshot creation may retain unready state, never admit its request."""
        for status in (ConsentStatus.NOT_VERIFIED, ConsentStatus.WITHDRAWN):
            request = self.make_snapshot(consent_status=status, consent_record=None)
            self.rejected(request=request, resolved_request=request)

    def test_incomplete_or_rejected_review_blocks_binding(self):
        """All nonapproved existing review states prevent a usable bound request."""
        for state in (ReviewState.PENDING, ReviewState.IN_REVIEW, ReviewState.REJECTED):
            request = self.make_snapshot(review_state=state, review_record=None)
            self.rejected(request=request, resolved_request=request)

    def test_verified_consent_requires_explicit_record(self):
        """A status flag alone cannot stand in for a consent revision."""
        with self.assertRaises(self.m.ReportRequestError):
            self.make_snapshot(consent_record=None)

    def test_unverified_consent_cannot_carry_verified_record(self):
        """Keep the original RPT-09 consent-record presence rules unchanged."""
        for status in (ConsentStatus.NOT_VERIFIED, ConsentStatus.WITHDRAWN):
            with self.assertRaises(self.m.ReportRequestError):
                self.make_snapshot(consent_status=status)

    def test_approved_review_requires_explicit_record(self):
        """An approved review snapshot requires its exact upstream evidence reference."""
        with self.assertRaises(self.m.ReportRequestError):
            self.make_snapshot(review_record=None)

    def test_existing_enum_types_are_required_without_coercion(self):
        """Strings and truth-like values cannot be silently normalized to approval."""
        for key, values in (('consent_status', ('VERIFIED', True, None)),
                            ('review_state', ('APPROVED', True, None))):
            for value in values:
                with self.subTest(key=key), self.assertRaises(self.m.ReportRequestError):
                    self.make_snapshot(**{key: value})

    def test_identifiers_are_never_trimmed_or_inferred(self):
        """Opaque request identities must already satisfy the existing grammar."""
        for key in ('request_id', 'requester_id'):
            for value in (None, True, 1, '', ' leading', '../path', 'x' * 257):
                with self.subTest(key=key), self.assertRaises(self.m.ReportRequestError):
                    self.make_snapshot(**{key: value})

    def test_digest_fields_are_exact_not_normalized(self):
        """Uppercase, short and whitespace digests are rejected before binding."""
        for key in ('completeness_plan_sha256', 'report_contract_bundle_sha256'):
            for value in (None, 7, 'A' * 64, 'f' * 63, 'f' * 64 + '\n'):
                with self.assertRaises(self.m.ReportRequestError):
                    self.make_snapshot(**{key: value})

    def test_unqualified_locale_never_falls_back(self):
        """This initial request boundary does not claim additional language support."""
        for locale in ('pt-BR', 'es-ES', 'it-IT', 'fr-FR', 'en-us', '', None):
            with self.assertRaises(self.m.ReportRequestError):
                self.make_snapshot(locale_id=locale)

    def test_unsupported_intended_use_is_rejected(self):
        """Administrative binding cannot expand the technical report's intended use."""
        for value in ('CLINICAL', '', None, True):
            with self.assertRaises(self.m.ReportRequestError):
                self.make_snapshot(intended_use_id=value)

    def test_nested_metadata_must_have_existing_exact_types(self):
        """Dictionaries or success-like objects do not constitute sealed references."""
        for key in ('source_binding', 'locale_pack', 'policy_record', 'consent_record', 'review_record'):
            for value in ({}, SimpleNamespace(passed=True)):
                with self.assertRaises(self.m.ReportRequestError):
                    self.make_snapshot(**{key: value})

    def test_artifact_roles_cannot_reuse_an_ambiguous_id(self):
        """Control and source roles stay distinct even if all digests look valid."""
        for key in ('locale_pack', 'policy_record', 'consent_record', 'review_record'):
            for artifact in (self.request.source_binding.canonical_result, self.request.source_binding.input_artifact):
                with self.assertRaises(self.m.ReportRequestError):
                    self.make_snapshot(**{key: artifact})
        with self.assertRaises(self.m.ReportRequestError):
            self.make_snapshot(review_record=self.request.consent_record)

    def test_direct_bound_constructor_enforces_same_invariants(self):
        """Direct construction cannot bypass the public factory or inject approval."""
        with self.assertRaises(self.m.ReportRequestError):
            self.m.BoundReportRequest(self.request, self.make_snapshot(request_id='FOREIGN'),
                                      self.sources, self.plan)
        with self.assertRaises(TypeError):
            self.m.BoundReportRequest(self.request, self.request, self.sources,
                                      self.plan, release_authorization='GRANTED')

    def test_bound_factory_rejects_duck_typed_inputs(self):
        """Every admitted domain boundary requires its actual existing class."""
        for key in ('request', 'resolved_request', 'sources', 'plan'):
            self.rejected(**{key: SimpleNamespace(passed=True)})

    def test_existing_source_budget_is_rechecked(self):
        """Previously built sources cannot evade the current admission budget."""
        with patch('reporting.bindings.MAX_SNAPSHOT_BYTES', 1):
            self.rejected()

    def test_existing_plan_budget_is_rechecked(self):
        """A bound request does not turn an oversized plan into approved work."""
        with patch('reporting.completeness.MAX_LEDGER_REFERENCES', 1):
            self.rejected()

    def test_source_integrity_is_rechecked_before_binding(self):
        """Directly corrupted retained bytes cannot rely on an old success flag."""
        sources = synthetic_sources()
        object.__setattr__(sources, 'evidence_snapshot_bytes', b'ALTERED')
        self.rejected(sources=sources)

    def test_nested_source_metadata_is_revalidated(self):
        """A tampered exact-type source object cannot rely on its class name."""
        request = self.make_snapshot()
        object.__setattr__(request.source_binding.identity, 'case_id', ' invalid')
        with self.assertRaises(self.m.ReportRequestError):
            self.make_snapshot(source_binding=request.source_binding)

    def test_snapshot_serialization_is_detached_and_hash_is_canonical(self):
        """Detached metadata uses the same sorted compact UTF-8 encoding as reporting."""
        original = self.request.to_dict()
        mutated = self.request.to_dict()
        mutated['source_binding']['identity']['case_id'] = 'CHANGED'
        mutated['consent_record']['sha256'] = '6' * 64
        self.assertEqual(self.request.to_dict(), original)
        payload = json.dumps(original, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=False, allow_nan=False).encode('utf-8')
        self.assertEqual(self.request.request_sha256, hashlib.sha256(payload).hexdigest())

    def test_changed_semantic_dimension_changes_snapshot_identity(self):
        """A deterministic digest is not an implemented idempotency service."""
        changes = [dict(request_id='OTHER'), dict(requester_id='OTHER'),
                   dict(report_contract_bundle_sha256='7' * 64),
                   dict(completeness_plan_sha256='8' * 64)]
        for key in ('locale_pack', 'policy_record', 'consent_record', 'review_record'):
            changes.append({key: replace(getattr(self.request, key), sha256='9' * 64)})
        for change in changes:
            self.assertNotEqual(self.make_snapshot(**change).request_sha256,
                                self.request.request_sha256)

    def test_original_bytes_and_plan_are_not_mutated(self):
        """No scientific decoding, number formatting or fresh analysis occurs."""
        before = self.sources.canonical_result_bytes, self.sources.evidence_snapshot_bytes
        bound = self.build()
        self.assertIs(bound.sources, self.sources)
        self.assertIs(bound.plan, self.plan)
        self.assertEqual(before, (bound.sources.canonical_result_bytes, bound.sources.evidence_snapshot_bytes))
        self.assertIn(b'0.12345678901234567890', bound.sources.canonical_result_bytes)

    def test_snapshot_and_bound_fields_reject_assignment(self):
        """Normal caller assignment cannot change captured request or control metadata."""
        for obj, key, value in ((self.request, 'requester_id', 'CHANGED'),
                                (self.build(), 'plan', None)):
            with self.assertRaises((FrozenInstanceError, AttributeError)):
                setattr(obj, key, value)

    def test_schema_accepts_actual_snapshot_with_local_source_definition(self):
        """The additive schema reuses the existing source schema by exact identity."""
        self.assertEqual(list(self.schema_validator().iter_errors(self.request.to_dict())), [])
        original = json.loads((ROOT / 'reporting/intended-use/e1a-small-variant-report.v1.json').read_text())
        self.assertEqual(self.request.intended_use_id, original['intended_use_id'])

    def test_embedded_source_contract_preserves_exact_existing_structure(self):
        """A self-contained schema cannot silently drift from the source contract."""
        original = json.loads((ROOT / 'schemas/report-source-binding.v1.schema.json').read_text())
        schema = json.loads((ROOT / 'schemas/report-request-snapshot.v1.schema.json').read_text())
        for key, value in original['$defs'].items():
            self.assertEqual(schema['$defs'][key], value)
        expected = {k: v for k, v in original.items()
                    if k not in ('$schema', '$id', '$defs', 'title', 'description')}
        self.assertEqual(schema['$defs']['source_binding'], expected)
        self.assertNotIn('urn:', json.dumps(schema['properties']))

    def test_schema_rejects_unknown_fields_states_and_missing_records(self):
        """Schema closure cannot admit invented approval or a foreign report profile."""
        validator = self.schema_validator()
        for key, value in (('unknown', True), ('schema_version', '2.0.0'), ('locale_id', 'pt-BR'),
                           ('consent_status', 'APPROVED'), ('review_state', 'VERIFIED'),
                           ('consent_record', None), ('review_record', None)):
            data = self.request.to_dict();data[key] = value
            self.assertTrue(list(validator.iter_errors(data)), key)

    def test_schema_can_retain_unready_snapshot_without_admission(self):
        """Structural snapshot validity and binding eligibility remain distinct."""
        request = self.make_snapshot(consent_status=ConsentStatus.WITHDRAWN, consent_record=None,
                                     review_state=ReviewState.REJECTED, review_record=None)
        self.assertEqual(list(self.schema_validator().iter_errors(request.to_dict())), [])
        self.rejected(request=request, resolved_request=request)

    def test_request_can_feed_existing_projection_ledger(self):
        """The new boundary composes with existing accounting without rendering a PDF."""
        bound = self.build()
        ledger = validate_report_completeness(sources=bound.sources, plan=bound.plan,
            projection_source_binding_sha256=bound.plan.source_binding_sha256,
            projection_plan_sha256=bound.plan.plan_sha256,
            represented=(FindingProjection('SYNTHETIC-F1', 'findings', ('table',)),),
            section_states=(SectionAvailability('identity', 'PRESENT'),
                            SectionAvailability('findings', 'PRESENT')))
        self.assertEqual(ledger.summary()['counts']['represented_findings'], 1)
        self.assertFalse(ledger.summary()['rendered_content_validated'])

    def test_diagnostics_never_expose_payloads_or_grant_authority(self):
        """Summaries contain only counts/digests and truthful boundary qualifications."""
        record = self.build().to_dict()
        text = json.dumps(record) + repr(self.request) + repr(self.build())
        for value in ('SYNTHETIC-CASE', 'SYNTHETIC-REQUESTER', 'SYNTHETIC_EVIDENCE', '0.123456789'):
            self.assertNotIn(value, text)
        self.assertEqual(record['conformance_scope'], 'REPORT_REQUEST_SNAPSHOT_BINDING_ONLY')
        self.assertEqual(record['release_authorization'], 'NOT_ESTABLISHED')
        self.assertFalse(record['upstream_authorization_validated'])


if __name__ == '__main__':
    unittest.main()
