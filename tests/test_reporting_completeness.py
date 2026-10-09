"""Synthetic contract tests for source-bound logical projection accounting."""
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

ROOT = Path(__file__).resolve().parents[1]


def synthetic_sources(case_id="SYNTHETIC-CASE-A", evidence=b"SYNTHETIC_EVIDENCE"):
    """Construct already sealed synthetic bytes, not clinical source evidence."""
    result = b'{"synthetic":true,"value":0.12345678901234567890,"findings":[]}'
    identity = ReportSourceIdentity("SYNTHETIC-NAMESPACE", case_id, "SYNTHETIC-SUBJECT",
                                    "SYNTHETIC-SAMPLE", "SYNTHETIC-ANALYSIS", "1", None)
    binding = ReportSourceBinding(identity, ReportArtifactBinding("SYNTHETIC-INPUT", "a" * 64),
        ReportArtifactBinding("SYNTHETIC-RESULT", hashlib.sha256(result).hexdigest()),
        ReportArtifactBinding("SYNTHETIC-EVIDENCE", hashlib.sha256(evidence).hexdigest()), "b" * 64)
    return bind_report_sources(expected_binding=binding, resolved_binding=binding,
                               canonical_result_bytes=result, evidence_snapshot_bytes=evidence)


class ReportCompletenessTests(unittest.TestCase):
    """Match a declared inventory without claiming source or rendering validation."""

    def setUp(self):
        """Require the real module before constructing each independent fixture."""
        name = "reporting.completeness"
        self.assertIsNotNone(importlib.util.find_spec(name), "report completeness module is missing")
        self.m = importlib.import_module(name)
        self.sources = synthetic_sources()
        self.plan = self.make_plan()
        self.projections = tuple(self.m.FindingProjection(f, "findings", ("shared-table",))
                                 for f in self.plan.expected_finding_ids)
        self.states = (self.m.SectionAvailability("identity", "PRESENT"),
                       self.m.SectionAvailability("findings", "PRESENT"),
                       self.m.SectionAvailability("optional", "NOT_AVAILABLE", "NOT_SUPPLIED"))

    def make_plan(self, **overrides):
        """Supply explicit synthetic upstream inventory and section requirements."""
        data = dict(source_binding_sha256=self.sources.expected_binding.binding_sha256,
                    expected_finding_ids=("SYNTHETIC-F1", "SYNTHETIC-F2"),
                    expected_section_ids=("identity", "findings", "optional"),
                    required_section_ids=("identity", "findings"), upstream_exclusions=())
        data.update(overrides)
        return self.m.ReportCompletenessPlan(**data)

    def build(self, **overrides):
        """Call the same public boundary used by an explicit assembly integration."""
        data = dict(sources=self.sources, plan=self.plan,
                    projection_source_binding_sha256=self.plan.source_binding_sha256,
                    projection_plan_sha256=self.plan.plan_sha256,
                    represented=self.projections, section_states=self.states)
        data.update(overrides)
        return self.m.validate_report_completeness(**data)

    def assert_rejected(self, code, **overrides):
        """Require a fixed failure code, never a partial success result."""
        with self.assertRaisesRegex(self.m.ReportCompletenessError, "^" + code + "$"):
            self.build(**overrides)

    def test_exact_inventory_is_accounted_with_explicit_scope(self):
        """Counts come from the same unique declared records, not headline hints."""
        result = self.build()
        record = result.to_dict()
        self.assertEqual(record["status"], "ACCOUNTED")
        self.assertEqual(record["conformance_scope"], "DECLARED_PROJECTION_ACCOUNTING_ONLY")
        self.assertEqual(record["release_authorization"], "NOT_ESTABLISHED")
        self.assertFalse(record["source_inventory_validated"])
        self.assertFalse(record["rendered_content_validated"])
        self.assertEqual(record["counts"], dict(expected_findings=2, represented_findings=2,
            upstream_excluded_findings=0, expected_sections=3, required_sections=2,
            present_required_sections=2))

    def test_empty_valid_inventory_is_not_a_negative_scientific_claim(self):
        """An empty declared inventory is structurally valid but proves no assay ran."""
        plan = self.make_plan(expected_finding_ids=())
        result = self.build(plan=plan, projection_plan_sha256=plan.plan_sha256, represented=())
        self.assertEqual(result.summary()["counts"]["represented_findings"], 0)
        self.assertFalse(result.to_dict()["source_inventory_validated"])

    def test_many_findings_are_preserved_without_top_n_truncation(self):
        """Thousands of logical findings survive regardless of exemplar page counts."""
        ids = tuple(f"SYNTHETIC-F{i}" for i in range(5000))
        plan = self.make_plan(expected_finding_ids=ids)
        projections = tuple(self.m.FindingProjection(f, "findings", ("shared-table",)) for f in ids)
        result = self.build(plan=plan, projection_plan_sha256=plan.plan_sha256, represented=projections)
        self.assertEqual(tuple(p["finding_id"] for p in result.to_dict()["represented"]), ids)
        self.assertEqual(result.summary()["counts"]["represented_findings"], 5000)

    def test_upstream_exclusion_is_explicit_and_counted_once(self):
        """An exclusion retains its exact policy reference and reason, not a vote."""
        exclusion = self.m.UpstreamFindingExclusion("SYNTHETIC-F2",
            ReportArtifactBinding("SYNTHETIC-POLICY", "c" * 64), "UPSTREAM_SCOPE")
        plan = self.make_plan(upstream_exclusions=(exclusion,))
        result = self.build(plan=plan, projection_plan_sha256=plan.plan_sha256,
                            represented=self.projections[:1])
        self.assertEqual(result.summary()["counts"]["upstream_excluded_findings"], 1)
        self.assertEqual(result.to_dict()["plan"]["upstream_exclusions"][0], exclusion.to_dict())

    def test_missing_finding_blocks_accounting(self):
        """Omission is a failure even with otherwise matching source hashes."""
        self.assert_rejected("finding_projection_incomplete", represented=self.projections[:1])

    def test_duplicate_projection_cannot_inflate_counts(self):
        """A duplicated finding cannot satisfy a different missing finding."""
        self.assert_rejected("duplicate_finding_projection", represented=(self.projections[0],) * 2)

    def test_unknown_finding_cannot_enter_the_ledger(self):
        """Presentation data cannot invent a finding outside the declared inventory."""
        item = self.m.FindingProjection("SYNTHETIC-FOREIGN", "findings", ("row",))
        self.assert_rejected("unknown_finding_projection", represented=self.projections + (item,))

    def test_excluded_finding_cannot_also_be_represented(self):
        """Dispositions are disjoint rather than double counted."""
        exclusion = self.m.UpstreamFindingExclusion("SYNTHETIC-F2",
            ReportArtifactBinding("SYNTHETIC-POLICY", "c" * 64), "UPSTREAM_SCOPE")
        plan = self.make_plan(upstream_exclusions=(exclusion,))
        self.assert_rejected("excluded_finding_projected", plan=plan,
                             projection_plan_sha256=plan.plan_sha256)

    def test_duplicate_expected_finding_is_rejected(self):
        """A bad upstream declaration does not receive plausible summary counts."""
        with self.assertRaises(self.m.ReportCompletenessError):
            self.make_plan(expected_finding_ids=("SYNTHETIC-F1",) * 2)

    def test_unknown_duplicate_or_unreferenced_exclusions_are_rejected(self):
        """An exclusion requires a known ID and a typed nonempty policy reference."""
        m = self.m
        exclusion = m.UpstreamFindingExclusion("SYNTHETIC-F1",
            ReportArtifactBinding("SYNTHETIC-POLICY", "c" * 64), "UPSTREAM_SCOPE")
        for entries in ((exclusion, exclusion), (replace(exclusion, finding_id="FOREIGN"),)):
            with self.subTest(entries=len(entries)), self.assertRaises(m.ReportCompletenessError):
                self.make_plan(upstream_exclusions=entries)
        for policy, reason in ((None, "UPSTREAM_SCOPE"), ({"sha256": "c" * 64}, "UPSTREAM_SCOPE"),
                               (exclusion.policy_record, "")):
            with self.assertRaises(m.ReportCompletenessError):
                m.UpstreamFindingExclusion("SYNTHETIC-F1", policy, reason)

    def test_foreign_case_source_is_rejected_even_with_identical_payload(self):
        """Shared genes/content do not compensate for different source identities."""
        self.assert_rejected("completeness_source_binding_mismatch",
                             sources=synthetic_sources("SYNTHETIC-CASE-B"))

    def test_changed_evidence_snapshot_invalidates_the_plan(self):
        """Source and plan are pinned; a new evidence digest needs a new plan."""
        self.assert_rejected("completeness_source_binding_mismatch",
                             sources=synthetic_sources(evidence=b"SYNTHETIC_REVISION_2"))

    def test_projection_header_must_match_the_exact_source(self):
        """A projection from another source cannot be relabeled with the local plan."""
        self.assert_rejected("completeness_source_binding_mismatch",
                             projection_source_binding_sha256="f" * 64)

    def test_projection_header_must_match_the_exact_plan(self):
        """A stale plan cannot pass by presenting otherwise plausible records."""
        self.assert_rejected("completeness_plan_mismatch", projection_plan_sha256="f" * 64)

    def test_missing_required_or_optional_section_state_is_rejected(self):
        """Every declared section has an explicit state, including optional absence."""
        for states in (self.states[1:], self.states[:-1]):
            with self.subTest(count=len(states)):
                self.assert_rejected("section_projection_incomplete", section_states=states)

    def test_duplicate_and_unknown_sections_are_rejected(self):
        """Duplicate states and foreign sections never repair a missing section."""
        self.assert_rejected("duplicate_section_projection", section_states=self.states + self.states[:1])
        self.assert_rejected("unknown_section_projection", section_states=self.states +
                             (self.m.SectionAvailability("foreign", "PRESENT"),))

    def test_required_section_absence_cannot_claim_accounting_success(self):
        """The initial profile does not invent critical-section waiver authority."""
        for status in ("NOT_MEASURED", "NOT_AVAILABLE", "NOT_APPLICABLE", "BLOCKED", "UNKNOWN"):
            with self.subTest(status=status):
                state = self.m.SectionAvailability("findings", status, "UPSTREAM_ABSENCE")
                with self.assertRaises(self.m.ReportCompletenessError):
                    self.build(section_states=(self.states[0], state, self.states[2]))

    def test_optional_absence_keeps_its_original_state_and_reason(self):
        """Unavailable is not silently collapsed into zero or a negative result."""
        for status in ("NOT_MEASURED", "NOT_AVAILABLE", "NOT_APPLICABLE"):
            with self.subTest(status=status):
                state = self.m.SectionAvailability("optional", status, "UPSTREAM_ABSENCE")
                result = self.build(section_states=self.states[:2] + (state,))
                self.assertEqual(result.to_dict()["section_states"][-1], state.to_dict())

    def test_blocked_or_unknown_optional_state_fails_closed(self):
        """Unresolved availability is not completed accounting in this profile."""
        for status in ("BLOCKED", "UNKNOWN"):
            state = self.m.SectionAvailability("optional", status, "UPSTREAM_ABSENCE")
            with self.assertRaises(self.m.ReportCompletenessError):
                self.build(section_states=self.states[:2] + (state,))

    def test_unknown_availability_and_contradictory_reasons_are_rejected(self):
        """Closed literal availability states do not accept truth-like substitutes."""
        for status, reason in (("MAYBE", None), (True, None), ("NOT_AVAILABLE", None),
                               ("PRESENT", "ABSENT"), ("NOT_MEASURED", "")):
            with self.subTest(status=status), self.assertRaises(self.m.ReportCompletenessError):
                self.m.SectionAvailability("optional", status, reason)

    def test_finding_cannot_point_to_unknown_or_absent_section(self):
        """A locator needs a present declared section, not a convenient label."""
        for section in ("foreign", "optional"):
            item = replace(self.projections[0], section_id=section)
            with self.assertRaises(self.m.ReportCompletenessError):
                self.build(represented=(item, self.projections[1]))

    def test_plan_finding_and_section_order_is_preserved(self):
        """This profile cannot silently reorder a source's declared priority."""
        self.assert_rejected("finding_projection_order_mismatch", represented=self.projections[::-1])
        self.assert_rejected("section_projection_order_mismatch", section_states=self.states[::-1])

    def test_shared_table_component_does_not_duplicate_findings(self):
        """Two distinct findings may point into a common logical table component."""
        record = self.build().to_dict()
        self.assertEqual(record["represented"][0]["component_ids"], ["shared-table"])
        self.assertEqual(record["counts"]["represented_findings"], 2)

    def test_empty_duplicate_or_mutable_component_references_are_rejected(self):
        """A finding needs at least one unique immutable logical locator."""
        for ids in ((), ("row", "row"), ["row"], ("",)):
            with self.assertRaises(self.m.ReportCompletenessError):
                self.m.FindingProjection("SYNTHETIC-F1", "findings", ids)

    def test_identity_fields_are_not_coerced_or_normalized(self):
        """Names, paths, whitespace and malformed IDs do not become join keys."""
        for value in (None, 1, True, " leading", "line\nbreak", "../path", "x" * 257):
            with self.assertRaises(self.m.ReportCompletenessError):
                self.m.FindingProjection(value, "findings", ("row",))
        for digest in (None, 1, "A" * 64, "f" * 63, "f" * 64 + "\n"):
            with self.assertRaises(self.m.ReportCompletenessError):
                self.make_plan(source_binding_sha256=digest)

    def test_plan_requires_unique_known_section_requirements(self):
        """Critical-section requirements must reference the actual declared set."""
        for fields in (dict(expected_section_ids=()), dict(expected_section_ids=("x", "x")),
                       dict(required_section_ids=("foreign",)), dict(required_section_ids=("identity",) * 2)):
            with self.assertRaises(self.m.ReportCompletenessError):
                self.make_plan(**fields)

    def test_mutable_iterables_and_duck_typed_objects_are_rejected(self):
        """No mutable snapshot copy or truth-like result flags establish a ledger."""
        for fields in (dict(expected_finding_ids=list(self.plan.expected_finding_ids)),
                       dict(upstream_exclusions=[])):
            with self.assertRaises(self.m.ReportCompletenessError):
                self.make_plan(**fields)
        for fields in (dict(represented=list(self.projections)), dict(section_states=list(self.states)),
                       dict(sources=SimpleNamespace(passed=True)), dict(plan=SimpleNamespace(passed=True))):
            with self.assertRaises(self.m.ReportCompletenessError):
                self.build(**fields)
        class HostileTuple(tuple):
            def __iter__(self):
                raise AssertionError("must not iterate untrusted tuple subclass")
        with self.assertRaises(self.m.ReportCompletenessError):
            self.make_plan(expected_finding_ids=HostileTuple(("f",)))

    def test_direct_constructor_cannot_override_or_bypass_completeness(self):
        """The result constructor enforces the same rules as the public factory."""
        args = dict(sources=self.sources, plan=self.plan,
                    projection_source_binding_sha256=self.plan.source_binding_sha256,
                    projection_plan_sha256=self.plan.plan_sha256,
                    represented=self.projections[:1], section_states=self.states)
        with self.assertRaises(self.m.ReportCompletenessError):
            self.m.ReportProjectionLedger(**args)
        args["represented"] = self.projections
        with self.assertRaises(TypeError):
            self.m.ReportProjectionLedger(**args, status="ACCOUNTED")

    def test_retained_records_and_sources_remain_immutable(self):
        """Ordinary assignment cannot alter sealed inputs or a completed ledger."""
        original = (self.sources.canonical_result_bytes, self.sources.evidence_snapshot_bytes)
        result = self.build()
        for obj, field, value in ((result, "represented", ()), (self.plan, "expected_finding_ids", ()),
                                  (self.projections[0], "finding_id", "changed")):
            with self.assertRaises((FrozenInstanceError, AttributeError)):
                setattr(obj, field, value)
        self.assertIs(result.sources, self.sources)
        self.assertEqual(original, (result.sources.canonical_result_bytes, result.sources.evidence_snapshot_bytes))
        self.assertIn(b"0.12345678901234567890", result.sources.canonical_result_bytes)

    def test_detached_metadata_and_canonical_digest_are_deterministic(self):
        """Metadata hashing follows existing sorted compact UTF-8 encoding."""
        result = self.build()
        original = result.to_dict()
        exposed = result.to_dict()
        exposed["represented"][0]["component_ids"].append("changed")
        exposed["plan"]["expected_finding_ids"].append("changed")
        self.assertEqual(result.to_dict(), original)
        encoded = json.dumps(original, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertEqual(result.ledger_sha256, hashlib.sha256(encoded).hexdigest())
        self.assertEqual(result.ledger_sha256, self.build().ledger_sha256)

    def test_summaries_and_errors_do_not_echo_source_values(self):
        """Public-safe summaries contain counts/hashes but no source text or IDs."""
        result = self.build()
        text = json.dumps(result.summary()) + repr(result) + repr(self.plan) + repr(self.projections[0])
        for marker in ("SYNTHETIC-CASE", "SYNTHETIC-F1", "SYNTHETIC_EVIDENCE", "0.123456789"):
            self.assertNotIn(marker, text)
        self.assert_rejected("finding_projection_incomplete", represented=())
        self.assertEqual(result.summary()["release_authorization"], "NOT_ESTABLISHED")

    def test_closed_ledger_schema_matches_the_runtime_record(self):
        """Schema describes serialized evidence, not a grant of scientific authority."""
        schema = json.loads((ROOT / "schemas/report-projection-ledger.v1.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        record = self.build().to_dict()
        self.assertEqual(list(validator.iter_errors(record)), [])
        for key, value in (("extra", True), ("schema_version", "2.0.0"),
                           ("report_id", "another-family"), ("release_authorization", "GRANTED"),
                           ("source_inventory_validated", True)):
            mutated = json.loads(json.dumps(record));mutated[key] = value
            self.assertTrue(list(validator.iter_errors(mutated)), key)
        mutated = json.loads(json.dumps(record))
        mutated["represented"][0]["unexpected"] = True
        self.assertTrue(list(validator.iter_errors(mutated)))

    def test_reference_admission_is_finite_and_rejects_whole_inputs(self):
        """The resource guard rejects excess metadata; it never keeps a prefix."""
        references = len(self.plan.expected_finding_ids) + len(self.plan.expected_section_ids) + len(self.plan.required_section_ids)
        with patch.object(self.m, "MAX_LEDGER_REFERENCES", references):
            self.assertEqual(self.make_plan().expected_finding_ids, self.plan.expected_finding_ids)
            with self.assertRaisesRegex(self.m.ReportCompletenessError, "accounting_budget_exceeded"):
                self.make_plan(expected_finding_ids=self.plan.expected_finding_ids + ("SYNTHETIC-F3",))
        too_many = ("x",) * (self.m.MAX_LEDGER_REFERENCES + 1)
        with self.assertRaisesRegex(self.m.ReportCompletenessError, "accounting_budget_exceeded"):
            self.make_plan(expected_finding_ids=too_many)

    def test_aggregate_projection_budget_precedes_nested_revalidation(self):
        """Repeated large component tuples cannot multiply work before admission."""
        with patch.object(self.m, "MAX_LEDGER_REFERENCES", 7):
            with patch.object(self.m.FindingProjection, "__post_init__",
                              side_effect=AssertionError("nested validation before admission")):
                self.assert_rejected("accounting_budget_exceeded")

    def test_aggregate_exclusion_budget_precedes_nested_revalidation(self):
        """All exclusion references count before repeated policy validation."""
        exclusion = self.m.UpstreamFindingExclusion("SYNTHETIC-F2",
            ReportArtifactBinding("SYNTHETIC-POLICY", "c" * 64), "UPSTREAM_SCOPE")
        with patch.object(self.m, "MAX_LEDGER_REFERENCES", 7):
            with patch.object(self.m.UpstreamFindingExclusion, "__post_init__",
                              side_effect=AssertionError("nested validation before admission")):
                with self.assertRaisesRegex(self.m.ReportCompletenessError, "accounting_budget_exceeded"):
                    self.make_plan(upstream_exclusions=(exclusion,))

    def test_identifier_byte_budget_rejects_large_valid_metadata(self):
        """Long identifiers cannot evade a finite budget by staying below item count."""
        ids = tuple(f"F{i:08d}" + "x" * 247 for i in range(32769))
        with self.assertRaisesRegex(self.m.ReportCompletenessError, "accounting_budget_exceeded"):
            self.make_plan(expected_finding_ids=ids)


if __name__ == "__main__":
    unittest.main()
