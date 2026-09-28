from __future__ import annotations

import copy
import importlib
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "report-family.v1.schema.json"
CATALOG = ROOT / "reporting" / "families.v1.json"
CAPABILITY = ROOT / "reporting" / "capabilities" / "e1a-small-variant-report.v1.json"
VALID_FIXTURE = ROOT / "tests" / "fixtures" / "reporting" / "rpt10" / "report-family.valid.json"
INVALID_FIXTURE = ROOT / "tests" / "fixtures" / "reporting" / "rpt10" / "report-family.invalid.json"
REPORT_ID = "e1a-small-variant-report"
FAMILY_ID = "e1a-small-variant"


def load_json(path: Path) -> object:
    """Load one deterministic JSON fixture."""
    return json.loads(path.read_text(encoding="utf-8"))


class Rpt10ReportFamilyTests(unittest.TestCase):
    def setUp(self) -> None:
        """Build the existing canonical E1A ReportViewModel for family binding."""
        compiler = importlib.import_module("reporting.compiler")
        viewmodel = importlib.import_module("reporting.viewmodel")
        catalog = load_json(ROOT / "reporting" / "catalog.v1.json")
        sections = load_json(
            ROOT / "reporting" / "sections" / "e1a-small-variant-report.v1.json"
        )
        intended_use = load_json(
            ROOT / "reporting" / "intended-use" / "e1a-small-variant-report.v1.json"
        )
        capability = load_json(CAPABILITY)
        interpretation = {
            "identity": {"sample_id": "SYNTHETIC-001"},
            "items": [],
            "conflicts": [],
            "limitations": ["Synthetic fixture only"],
            "provenance": [{"source_id": "synthetic"}],
        }
        compiled = compiler.compile_report_pack(
            report_id=REPORT_ID,
            catalog=catalog,
            section_contracts=sections,
            intended_use=intended_use,
            report_capability_manifest=capability,
            canonical_interpretation=interpretation,
        )
        self.rpt03 = viewmodel.build_report_view_model_and_release_bundle(
            compiled_report_pack=compiled,
            artifact_ids=["canonical-interpretation:synthetic-001"],
        )
        self.assertTrue(self.rpt03.passed, self.rpt03.errors)
        self.family_catalog = load_json(CATALOG)
        self.capability = capability

    def build(self, **overrides):
        """Invoke the RPT-10 binder with canonical defaults."""
        module = importlib.import_module("reporting.families")
        values = {
            "family_catalog": self.family_catalog,
            "report_capability_manifest": self.capability,
            "rpt03_result": self.rpt03,
        }
        values.update(overrides)
        return module.build_report_family_view_model(**values)

    def test_family_schema_is_valid_draft_2020_12_with_positive_and_negative_fixtures(self):
        """Family descriptors are closed Draft 2020-12 contracts."""
        schema = load_json(SCHEMA)
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(load_json(VALID_FIXTURE))
        with self.assertRaises(ValidationError):
            Draft202012Validator(schema).validate(load_json(INVALID_FIXTURE))

    def test_current_catalog_exposes_only_the_existing_e1a_family(self):
        """RPT-10 does not activate deferred report families."""
        catalog = self.family_catalog
        self.assertEqual(catalog["schema_version"], "1.0.0")
        self.assertEqual(catalog["catalog_id"], "e1a-report-family-catalog-v1")
        self.assertEqual(len(catalog["families"]), 1)
        family = catalog["families"][0]
        self.assertEqual(family["family_id"], FAMILY_ID)
        self.assertEqual(family["report_ids"], [REPORT_ID])
        self.assertEqual(
            family["required_capability_ids"],
            ["canonical-interpretation-object"],
        )
        self.assertEqual(
            family["evaluated_analysis_class_ids"],
            ["germline-snv-small-indel"],
        )

    def test_binds_family_metadata_over_the_canonical_view_model(self):
        """The family layer wraps, rather than reinterprets, the canonical view model."""
        result = self.build()
        self.assertTrue(result.passed, result.errors)
        payload = result.to_dict()
        self.assertEqual(payload["family_id"], FAMILY_ID)
        self.assertEqual(payload["report_id"], REPORT_ID)
        self.assertEqual(
            payload["family_view_model"]["report_view_model"],
            self.rpt03.to_dict()["view_model"],
        )
        self.assertEqual(
            payload["family_view_model"]["report_view_model_sha256"],
            self.rpt03.to_dict()["release_bundle"]["report_view_model_sha256"],
        )

    def test_family_binding_is_deterministic_and_snapshot_isolated(self):
        """Equivalent inputs produce identical immutable family snapshots."""
        first = self.build()
        second = self.build()
        self.assertEqual(first.to_dict(), second.to_dict())
        exposed = first.to_dict()
        exposed["family_view_model"]["report_view_model"]["sections"][0]["title"] = "MUTATED"
        self.assertNotEqual(
            exposed["family_view_model"]["report_view_model"]["sections"][0]["title"],
            first.to_dict()["family_view_model"]["report_view_model"]["sections"][0]["title"],
        )
        with self.assertRaises(TypeError):
            first.family_view_model["family_id"] = "mutated"

    def test_unknown_report_family_fails_closed(self):
        """A canonical report without a family entry cannot be silently categorized."""
        bad = copy.deepcopy(self.family_catalog)
        bad["families"][0]["report_ids"] = ["other-report"]
        result = self.build(family_catalog=bad)
        self.assertFalse(result.passed)
        self.assertIn("report_family_not_found", result.errors)

    def test_additional_family_is_rejected_until_explicit_activation(self):
        """The E1A RPT-10 catalog cannot silently activate a second family."""
        bad = copy.deepcopy(self.family_catalog)
        duplicate = copy.deepcopy(bad["families"][0])
        duplicate["family_id"] = "future-family"
        duplicate["report_ids"] = ["future-report"]
        bad["families"].append(duplicate)
        result = self.build(family_catalog=bad)
        self.assertFalse(result.passed)
        self.assertIn("family_catalog_invalid", result.errors)

    def test_invalid_family_identifier_fails_closed_at_runtime(self):
        """Runtime validation enforces the same family-id shape as the JSON Schema."""
        bad = copy.deepcopy(self.family_catalog)
        bad["families"][0]["family_id"] = "Bad Family"
        result = self.build(family_catalog=bad)
        self.assertFalse(result.passed)
        self.assertIn("family_catalog_invalid", result.errors)

    def test_family_capability_requirements_must_match_report_contract(self):
        """Family requirements cannot silently widen or narrow report capabilities."""
        bad = copy.deepcopy(self.family_catalog)
        bad["families"][0]["required_capability_ids"] = ["other-capability"]
        result = self.build(family_catalog=bad)
        self.assertFalse(result.passed)
        self.assertIn("family_capability_mismatch", result.errors)

    def test_family_analysis_classes_must_match_report_contract(self):
        """Family metadata cannot claim an analysis class the report did not evaluate."""
        bad = copy.deepcopy(self.family_catalog)
        bad["families"][0]["evaluated_analysis_class_ids"] = ["other-analysis"]
        result = self.build(family_catalog=bad)
        self.assertFalse(result.passed)
        self.assertIn("family_analysis_class_mismatch", result.errors)

    def test_stale_upstream_view_model_digest_fails_closed(self):
        """A passed-looking RPT-03 object with stale digest is rejected."""
        payload = self.rpt03.to_dict()
        fake = type(
            "FakeRpt03",
            (),
            {
                "passed": True,
                "view_model": copy.deepcopy(payload["view_model"]),
                "release_bundle": copy.deepcopy(payload["release_bundle"]),
            },
        )()
        fake.view_model["sections"][0]["title"] = "MUTATED AFTER HASH"
        result = self.build(rpt03_result=fake)
        self.assertFalse(result.passed)
        self.assertIn("canonical_report_view_model_required", result.errors)

    def test_mismatched_release_bundle_identity_fails_closed(self):
        """A passed-looking RPT-03 object with wrong bundle identity is rejected."""
        payload = self.rpt03.to_dict()
        fake = type(
            "FakeRpt03",
            (),
            {
                "passed": True,
                "view_model": copy.deepcopy(payload["view_model"]),
                "release_bundle": copy.deepcopy(payload["release_bundle"]),
            },
        )()
        fake.release_bundle["release_bundle_id"] = "other-report:deadbeefdeadbeef"
        result = self.build(rpt03_result=fake)
        self.assertFalse(result.passed)
        self.assertIn("canonical_report_view_model_required", result.errors)

    def test_invalid_upstream_view_model_fails_closed(self):
        """RPT-10 accepts only a successful canonical RPT-03 result."""
        bad = type("BadRpt03", (), {"passed": False})()
        result = self.build(rpt03_result=bad)
        self.assertFalse(result.passed)
        self.assertIn("canonical_report_view_model_required", result.errors)

    def test_rpt10_does_not_add_interoperability_or_future_family_semantics(self):
        """RPT-10 remains below RPT-11 and future family activation."""
        serialized = json.dumps(self.build().to_dict(), sort_keys=True).lower()
        for forbidden in (
            "fhir",
            "phenopacket",
            "vrs",
            "pharmacogen",
            "ancestry",
            "somatic",
        ):
            self.assertNotIn(forbidden, serialized)


if __name__ == "__main__":
    unittest.main()
