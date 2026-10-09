"""Synthetic conformance for the opt-in report source integrity boundary."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas/report-source-binding.v1.schema.json"
REPORT_ID = "e1a-small-variant-report"


def digest(data: bytes) -> str:
    """Identify exact synthetic bytes without changing their encoding."""
    return hashlib.sha256(data).hexdigest()


class ReportSourceBindingTests(unittest.TestCase):
    """Verify identity and bytes without granting upstream or release authority."""

    def setUp(self):
        """Require the new boundary before constructing isolated test inputs."""
        name = "reporting.bindings"
        self.assertIsNotNone(importlib.util.find_spec(name), "report source binding module is missing")
        self.sut = importlib.import_module(name)
        self.result_bytes = b'{"items":[{"gene":"SYNTHETIC-GENE","value":0.12345678901234567890}]}'
        self.evidence_bytes = b'{"revision":"SYNTHETIC-EVIDENCE-1","source":"SYNTHETIC"}'
        self.identity = self.sut.ReportSourceIdentity(
            namespace_id="SYNTHETIC-NAMESPACE-A", case_id="SYNTHETIC-CASE-A",
            subject_id="SYNTHETIC-SUBJECT-A", sample_id="SYNTHETIC-SAMPLE-A",
            specimen_id="SYNTHETIC-SPECIMEN-A", analysis_id="SYNTHETIC-ANALYSIS-A",
            analysis_revision="1",
        )
        self.binding = self.metadata()

    def metadata(self, result_bytes=None, evidence_bytes=None):
        """Create source references independently from the boundary under test."""
        reference = self.sut.ReportArtifactBinding
        return self.sut.ReportSourceBinding(
            identity=self.identity,
            input_artifact=reference("SYNTHETIC-INPUT-A", digest(b"SYNTHETIC-INPUT")),
            canonical_result=reference("SYNTHETIC-RESULT-A", digest(self.result_bytes if result_bytes is None else result_bytes)),
            evidence_snapshot=reference("SYNTHETIC-EVIDENCE-A", digest(self.evidence_bytes if evidence_bytes is None else evidence_bytes)),
            reference_bundle_sha256=digest(b"SYNTHETIC-REFERENCE"),
            report_id=REPORT_ID,
        )

    def bind(self, **overrides):
        """Exercise the public binding API with independently resolved metadata."""
        values = dict(expected_binding=self.binding, resolved_binding=replace(self.binding),
                      canonical_result_bytes=self.result_bytes, evidence_snapshot_bytes=self.evidence_bytes)
        values.update(overrides)
        return self.sut.bind_report_sources(**values)

    def test_exact_identity_and_raw_bytes_are_bound(self):
        """A matched pair retains both complete original immutable snapshots."""
        bound = self.bind()
        self.assertIs(bound.canonical_result_bytes, self.result_bytes)
        self.assertIs(bound.evidence_snapshot_bytes, self.evidence_bytes)
        self.assertEqual(bound.to_dict()["status"], "BOUND")
        self.assertEqual(bound.to_dict()["binding_sha256"], self.binding.binding_sha256)

    def test_each_cross_case_sample_or_analysis_field_fails_closed(self):
        """Identical genes or payloads never compensate for a foreign identity."""
        for field in ("namespace_id", "case_id", "subject_id", "sample_id", "specimen_id", "analysis_id", "analysis_revision"):
            with self.subTest(field=field):
                other = replace(self.binding, identity=replace(self.identity, **{field: "SYNTHETIC-FOREIGN"}))
                with self.assertRaisesRegex(self.sut.ReportBindingError, "report_source_binding_mismatch"):
                    self.bind(resolved_binding=other)

    def test_stale_or_foreign_artifact_references_fail_closed(self):
        """Every artifact identifier and digest participates in request binding."""
        for role in ("input_artifact", "canonical_result", "evidence_snapshot"):
            for field, value in (("artifact_id", "SYNTHETIC-FOREIGN"), ("sha256", digest(b"OTHER-REVISION"))):
                with self.subTest(role=role, field=field):
                    other = replace(self.binding, **{role: replace(getattr(self.binding, role), **{field: value})})
                    with self.assertRaisesRegex(self.sut.ReportBindingError, "report_source_binding_mismatch"):
                        self.bind(resolved_binding=other)

    def test_reference_bundle_identity_mismatch_is_rejected(self):
        """Reference names are not used as a substitute for exact content identity."""
        other = replace(self.binding, reference_bundle_sha256=digest(b"OTHER-REFERENCE"))
        with self.assertRaisesRegex(self.sut.ReportBindingError, "report_source_binding_mismatch"):
            self.bind(resolved_binding=other)

    def test_modified_canonical_result_bytes_are_rejected(self):
        """A claimed source digest cannot authorize altered result content."""
        with self.assertRaisesRegex(self.sut.ReportBindingError, "canonical_result_digest_mismatch"):
            self.bind(canonical_result_bytes=self.result_bytes + b" ")

    def test_modified_evidence_bytes_are_rejected(self):
        """Evidence bytes are checked independently from the result snapshot."""
        with self.assertRaisesRegex(self.sut.ReportBindingError, "evidence_snapshot_digest_mismatch"):
            self.bind(evidence_snapshot_bytes=self.evidence_bytes + b" ")

    def test_mutable_buffers_and_live_objects_are_rejected(self):
        """Only exact bytes are accepted; no copy of a mutable object is a seal."""
        for value in (bytearray(self.result_bytes), memoryview(self.result_bytes), {}, [], object(), self.result_bytes.decode()):
            for role in ("canonical_result_bytes", "evidence_snapshot_bytes"):
                with self.subTest(role=role, type=type(value).__name__):
                    with self.assertRaisesRegex(self.sut.ReportBindingError, "immutable_snapshot_bytes_required"):
                        self.bind(**{role: value})

    def test_empty_snapshot_bytes_are_rejected(self):
        """Missing artifacts are not treated as an empty valid analysis."""
        for role in ("canonical_result_bytes", "evidence_snapshot_bytes"):
            with self.subTest(role=role), self.assertRaisesRegex(self.sut.ReportBindingError, "immutable_snapshot_bytes_required"):
                self.bind(**{role: b""})

    def test_direct_result_constructor_enforces_identity_and_hashes(self):
        """Calling the result class directly cannot bypass the public factory."""
        with self.assertRaisesRegex(self.sut.ReportBindingError, "report_source_binding_mismatch"):
            self.sut.BoundReportSources(self.binding, replace(self.binding, identity=replace(self.identity, case_id="OTHER")), self.result_bytes, self.evidence_bytes)
        with self.assertRaisesRegex(self.sut.ReportBindingError, "canonical_result_digest_mismatch"):
            self.sut.BoundReportSources(self.binding, self.binding, b"ALTERED", self.evidence_bytes)

    def test_fake_binding_objects_are_rejected(self):
        """Truth-like flags and duck-typed payloads do not establish provenance."""
        for value in ({"passed": True}, object(), None):
            for role in ("expected_binding", "resolved_binding"):
                with self.subTest(role=role), self.assertRaisesRegex(self.sut.ReportBindingError, "report_source_binding_required"):
                    self.bind(**{role: value})

    def test_direct_binding_constructor_rejects_wrong_metadata_types(self):
        """Nested mutable dictionaries cannot masquerade as frozen references."""
        for field, value in (("identity", {}), ("input_artifact", {}), ("canonical_result", {}), ("evidence_snapshot", {})):
            with self.subTest(field=field), self.assertRaises(self.sut.ReportBindingError):
                replace(self.binding, **{field: value})

    def test_identity_fields_are_not_coerced_trimmed_or_inferred(self):
        """Invalid identifiers are rejected rather than normalized into a match."""
        for value in (None, True, 1, "", " A", "A ", "A\n", "../A", "A/B", "A" * 257):
            with self.subTest(value=repr(value)), self.assertRaises(self.sut.ReportBindingError):
                replace(self.identity, case_id=value)

    def test_explicit_unknown_specimen_is_preserved(self):
        """An absent specimen remains explicit and must match on both sides."""
        known = replace(self.binding, identity=replace(self.identity, specimen_id=None))
        bound = self.bind(expected_binding=known, resolved_binding=known)
        self.assertIsNone(bound.expected_binding.identity.specimen_id)
        with self.assertRaises(self.sut.ReportBindingError):
            self.bind(resolved_binding=known)

    def test_artifact_digests_are_exact_lowercase_sha256(self):
        """Malformed or normalized digest hints cannot become artifact identity."""
        for value in (None, 0, "g" * 64, "A" * 64, "a" * 63, "a" * 64 + "\n"):
            with self.subTest(value=repr(value)), self.assertRaises(self.sut.ReportBindingError):
                self.sut.ReportArtifactBinding("SYNTHETIC", value)
        with self.assertRaises(self.sut.ReportBindingError):
            replace(self.binding, reference_bundle_sha256="INVALID")

    def test_duplicate_artifact_ids_across_roles_are_rejected(self):
        """Distinct source roles cannot silently reuse one ambiguous artifact ID."""
        with self.assertRaisesRegex(self.sut.ReportBindingError, "duplicate_artifact_identity"):
            replace(self.binding, evidence_snapshot=replace(self.binding.evidence_snapshot, artifact_id=self.binding.canonical_result.artifact_id))

    def test_existing_report_identity_is_preserved_and_other_families_blocked(self):
        """The boundary does not activate an additional report family."""
        self.assertEqual(self.binding.to_dict()["report_id"], REPORT_ID)
        with self.assertRaisesRegex(self.sut.ReportBindingError, "report_id_not_supported"):
            replace(self.binding, report_id="future-family")
        with self.assertRaises(TypeError):
            replace(self.binding, release_ready=True)

    def test_retained_metadata_and_result_fields_reject_assignment(self):
        """Normal caller assignment cannot mutate a verified snapshot."""
        bound = self.bind()
        for obj, field, value in ((self.identity, "case_id", "OTHER"), (self.binding.canonical_result, "sha256", digest(b"X")), (self.binding, "report_id", "OTHER"), (bound, "canonical_result_bytes", b"OTHER")):
            with self.subTest(field=field), self.assertRaises(FrozenInstanceError):
                setattr(obj, field, value)

    def test_serialized_metadata_is_detached(self):
        """Mutating a returned dictionary cannot alter the binding or its digest."""
        original = self.binding.binding_sha256
        payload = self.binding.to_dict()
        payload["identity"]["case_id"] = "OTHER"
        payload["canonical_result"]["sha256"] = digest(b"OTHER")
        self.assertEqual(self.binding.binding_sha256, original)
        self.assertEqual(self.binding.identity.case_id, "SYNTHETIC-CASE-A")

    def test_binding_hash_uses_existing_compact_sorted_utf8_encoding(self):
        """Metadata identity follows the established reporting hash encoding."""
        encoded = json.dumps(self.binding.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertEqual(self.binding.binding_sha256, digest(encoded))
        self.assertEqual(self.binding.binding_sha256, replace(self.binding).binding_sha256)

    def test_scientific_numbers_and_original_encoding_remain_exact(self):
        """Opaque snapshots retain all original numeric lexemes and whitespace."""
        value = b'{ "number": 0.123456789012345678901234567890, "zero": -0.0 }\n'
        binding = self.metadata(result_bytes=value)
        bound = self.bind(expected_binding=binding, resolved_binding=binding, canonical_result_bytes=value)
        self.assertEqual(bound.canonical_result_bytes, value)
        self.assertIn(b"0.123456789012345678901234567890", bound.canonical_result_bytes)

    def test_zero_one_and_many_findings_are_never_truncated(self):
        """Byte integrity is independent of a renderer's page or row count."""
        for count in (0, 1, 5000):
            with self.subTest(count=count):
                payload = json.dumps({"items": [{"id": f"SYNTHETIC-{i}"} for i in range(count)]}).encode()
                binding = self.metadata(result_bytes=payload)
                result = self.bind(expected_binding=binding, resolved_binding=binding, canonical_result_bytes=payload)
                self.assertEqual(result.canonical_result_bytes, payload)
                self.assertEqual(len(json.loads(result.canonical_result_bytes)["items"]), count)

    def test_snapshot_size_boundary_is_finite_and_not_a_truncation(self):
        """A qualified byte budget admits its boundary and rejects excess whole."""
        self.assertEqual(self.sut.MAX_SNAPSHOT_BYTES, 8 * 1024 * 1024)
        payload = b'"' + b"x" * (self.sut.MAX_SNAPSHOT_BYTES - 2) + b'"'
        binding = self.metadata(result_bytes=payload)
        bound = self.bind(expected_binding=binding, resolved_binding=binding, canonical_result_bytes=payload)
        self.assertEqual(len(bound.canonical_result_bytes), self.sut.MAX_SNAPSHOT_BYTES)
        for role in ("canonical_result_bytes", "evidence_snapshot_bytes"):
            with self.subTest(role=role), patch.object(self.sut.hashlib, "sha256", side_effect=AssertionError("budget check must precede hashing")):
                with self.assertRaisesRegex(self.sut.ReportBindingError, "report_source_budget_exceeded"):
                    self.bind(**{role: payload + b" "})

    def test_diagnostics_do_not_echo_source_data_or_claim_release(self):
        """Summaries and exceptions carry no source contents or false authority."""
        bound = self.bind()
        summary = bound.to_dict()
        self.assertEqual(summary["release_authorization"], "NOT_ESTABLISHED")
        self.assertEqual(summary["conformance_scope"], "REPORT_SOURCE_INTEGRITY_ONLY")
        for text in (repr(bound), json.dumps(summary), repr(self.binding)):
            self.assertNotIn("SYNTHETIC-GENE", text)
            self.assertNotIn("0.123456789", text)
        with self.assertRaises(self.sut.ReportBindingError) as raised:
            self.bind(canonical_result_bytes=b"SYNTHETIC-PRIVATE-CONTENT")
        self.assertNotIn("SYNTHETIC-PRIVATE-CONTENT", str(raised.exception))

    def test_closed_versioned_schema_matches_runtime_metadata(self):
        """The new schema is additive and describes actual serialized metadata."""
        self.assertTrue(SCHEMA.is_file(), "closed source-binding schema is missing")
        schema = json.loads(SCHEMA.read_text())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        validator.validate(self.binding.to_dict())
        payload = self.binding.to_dict()
        payload["identity"]["specimen_id"] = None
        validator.validate(payload)
        self.assertEqual(schema["$id"], "urn:omnigenis:schema:report-source-binding:1.0.0")

    def test_schema_rejects_unknown_fields_versions_and_invalid_ids(self):
        """Closed metadata cannot silently admit later profiles or foreign fields."""
        validator = Draft202012Validator(json.loads(SCHEMA.read_text()))
        for path, value in (("extra", True), ("schema_version", "2.0.0"), ("report_id", "OTHER"), ("case_id", "A\n"), ("sha256", "A" * 64)):
            payload = self.binding.to_dict()
            if path == "case_id": payload["identity"][path] = value
            elif path == "sha256": payload["canonical_result"][path] = value
            else: payload[path] = value
            with self.subTest(path=path):
                self.assertFalse(validator.is_valid(payload))


if __name__ == "__main__":
    unittest.main()
