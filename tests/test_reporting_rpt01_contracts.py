from __future__ import annotations

import importlib
import importlib.util
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
CATALOG_SCHEMA = ROOT / "schemas" / "report-catalog-entry.v1.schema.json"
CAPABILITY_SCHEMA = ROOT / "schemas" / "report-capability-manifest.v1.schema.json"
SECTION_SCHEMA = ROOT / "schemas" / "report-section-contract.v1.schema.json"
INTENDED_USE_SCHEMA = ROOT / "schemas" / "report-intended-use.v1.schema.json"
CATALOG = ROOT / "reporting" / "catalog.v1.json"
SECTIONS = (
    ROOT
    / "reporting"
    / "sections"
    / "e1a-small-variant-report.v1.json"
)
INTENDED_USE = (
    ROOT
    / "reporting"
    / "intended-use"
    / "e1a-small-variant-report.v1.json"
)
REPORT_CAPABILITY = (
    ROOT
    / "reporting"
    / "capabilities"
    / "e1a-small-variant-report.v1.json"
)
VALID_SECTION = (
    ROOT
    / "tests"
    / "fixtures"
    / "reporting"
    / "rpt01"
    / "section-contract.valid.json"
)
INVALID_SECTION = (
    ROOT
    / "tests"
    / "fixtures"
    / "reporting"
    / "rpt01"
    / "section-contract.invalid.json"
)
VALID_INTENDED_USE = (
    ROOT
    / "tests"
    / "fixtures"
    / "reporting"
    / "rpt01"
    / "intended-use.valid.json"
)
INVALID_INTENDED_USE = (
    ROOT
    / "tests"
    / "fixtures"
    / "reporting"
    / "rpt01"
    / "intended-use.invalid.json"
)

REPORT_ID = "e1a-small-variant-report"
SECTION_IDS = (
    "identity-and-provenance",
    "verified-source-interpretations",
    "unresolved-evidence-conflicts",
    "limitations-and-not-assessed",
    "sources-and-versioning",
)


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def load_sut(testcase: unittest.TestCase):
    name = "reporting.contracts"
    if importlib.util.find_spec(name) is None:
        testcase.fail("reporting.contracts module is missing")
    module = importlib.import_module(name)
    for attr in ("validate_rpt01_contracts", "Rpt01ContractBundleResult"):
        if not hasattr(module, attr):
            testcase.fail(f"{attr} is missing")
    return module


class Rpt01ReportingContractsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = load_json(CATALOG)
        self.sections = load_json(SECTIONS)
        self.intended_use = load_json(INTENDED_USE)
        self.capability = load_json(REPORT_CAPABILITY)

    def validate(self, **overrides):
        sut = load_sut(self)
        values = {
            "report_id": REPORT_ID,
            "catalog": self.catalog,
            "section_contracts": self.sections,
            "intended_use": self.intended_use,
            "report_capability_manifest": self.capability,
        }
        values.update(overrides)
        return sut.validate_rpt01_contracts(**values)

    def test_new_schemas_are_valid_draft_2020_12(self) -> None:
        for path in (SECTION_SCHEMA, INTENDED_USE_SCHEMA):
            with self.subTest(path=path.name):
                schema = load_json(path)
                Draft202012Validator.check_schema(schema)

    def test_positive_and_negative_schema_fixtures(self) -> None:
        section_schema = load_json(SECTION_SCHEMA)
        intended_schema = load_json(INTENDED_USE_SCHEMA)
        Draft202012Validator(section_schema).validate(load_json(VALID_SECTION))
        Draft202012Validator(intended_schema).validate(
            load_json(VALID_INTENDED_USE)
        )
        with self.assertRaises(Exception):
            Draft202012Validator(section_schema).validate(
                load_json(INVALID_SECTION)
            )
        with self.assertRaises(Exception):
            Draft202012Validator(intended_schema).validate(
                load_json(INVALID_INTENDED_USE)
            )
    def test_single_e1a_catalog_entry_and_capability_manifest_validate(self) -> None:
        catalog_schema = load_json(CATALOG_SCHEMA)
        capability_schema = load_json(CAPABILITY_SCHEMA)
        reports = self.catalog["reports"]
        self.assertEqual(len(reports), 1)
        Draft202012Validator(catalog_schema).validate(reports[0])
        Draft202012Validator(capability_schema).validate(self.capability)
        self.assertEqual(reports[0]["report_id"], REPORT_ID)
        self.assertEqual(
            self.capability["required_capability_ids"],
            ["canonical-interpretation-object"],
        )
        self.assertEqual(
            self.capability["evaluated_analysis_class_ids"],
            ["germline-snv-small-indel"],
        )

    def test_bundle_cross_binding_and_order_are_exact(self) -> None:
        result = self.validate()
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(result.report_id, REPORT_ID)
        self.assertEqual(
            tuple(section.section_id for section in result.sections),
            SECTION_IDS,
        )
        self.assertEqual(
            tuple(section.order for section in result.sections),
            (1, 2, 3, 4, 5),
        )
        self.assertEqual(
            tuple(section.title for section in result.sections),
            tuple(self.catalog["reports"][0]["sections"]),
        )
        self.assertEqual(
            result.intended_use.clinical_use_status,
            "NOT_CLINICALLY_PROMOTED",
        )
        self.assertEqual(
            result.required_capability_ids,
            ("canonical-interpretation-object",),
        )

    def test_unknown_report_id_fails_closed(self) -> None:
        result = self.validate(report_id="unknown-report")
        self.assertFalse(result.passed)
        self.assertIn("report_id_not_in_catalog", result.errors)

    def test_report_id_mismatch_across_resources_fails_closed(self) -> None:
        bad = json.loads(json.dumps(self.intended_use))
        bad["report_id"] = "other-report"
        result = self.validate(intended_use=bad)
        self.assertFalse(result.passed)
        self.assertIn("report_contract_binding_mismatch", result.errors)

        bad = json.loads(json.dumps(self.capability))
        bad["report_id"] = "other-report"
        result = self.validate(report_capability_manifest=bad)
        self.assertFalse(result.passed)
        self.assertIn("report_contract_binding_mismatch", result.errors)

    def test_duplicate_or_whitespace_section_identity_fails_closed(self) -> None:
        bad = json.loads(json.dumps(self.sections))
        bad["sections"][1]["section_id"] = bad["sections"][0]["section_id"]
        result = self.validate(section_contracts=bad)
        self.assertFalse(result.passed)
        self.assertIn("section_contract_invalid", result.errors)

        bad = json.loads(json.dumps(self.sections))
        bad["sections"][0]["title"] = "   "
        result = self.validate(section_contracts=bad)
        self.assertFalse(result.passed)
        self.assertIn("section_contract_invalid", result.errors)
    def test_section_semantic_inputs_are_closed_to_canonical_interpretation(self) -> None:
        result = self.validate()
        self.assertTrue(result.passed, result.errors)
        for section in result.sections:
            for semantic_input in section.required_semantic_inputs:
                self.assertTrue(
                    semantic_input.startswith("canonical_interpretation.")
                )

        bad = json.loads(json.dumps(self.sections))
        bad["sections"][0]["required_semantic_inputs"].append(
            "evidence_snapshot.raw_xml"
        )
        result = self.validate(section_contracts=bad)
        self.assertFalse(result.passed)
        self.assertIn("section_semantic_input_not_allowed", result.errors)

    def test_intended_use_is_explicitly_non_clinically_promoted(self) -> None:
        result = self.validate()
        self.assertTrue(result.passed, result.errors)
        intended = result.intended_use
        self.assertEqual(
            intended.intended_use_category,
            "TECHNICAL_E1A_VALIDATION",
        )
        self.assertEqual(
            intended.clinical_use_status,
            "NOT_CLINICALLY_PROMOTED",
        )
        self.assertIn("diagnosis", " ".join(intended.prohibited_claims).lower())
        self.assertIn("treatment", " ".join(intended.prohibited_claims).lower())
        self.assertEqual(intended.confirmation_status, "NOT_DEFINED_IN_RPT01")

    def test_rpt01_contains_no_compiler_renderer_locale_or_release_behavior(self) -> None:
        result = self.validate()
        payload = result.to_dict()
        serialized = json.dumps(payload, sort_keys=True).lower()
        for forbidden in (
            "renderer_id",
            "presentation_ir",
            "report_view_model",
            "release_bundle",
            "locale_id",
            "pdf",
            "html",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_malformed_runtime_contract_fields_fail_closed(self) -> None:
        cases = []

        bad_catalog = json.loads(json.dumps(self.catalog))
        bad_catalog["reports"][0]["accent"] = 123456
        cases.append(({"catalog": bad_catalog}, "catalog_invalid"))

        bad_sections = json.loads(json.dumps(self.sections))
        bad_sections["sections"][0]["empty_state_policy"] = []
        cases.append(
            ({"section_contracts": bad_sections}, "section_contract_invalid")
        )

        bad_intended = json.loads(json.dumps(self.intended_use))
        bad_intended["intended_use_id"] = "Bad ID"
        cases.append(
            ({"intended_use": bad_intended}, "intended_use_invalid")
        )

        for overrides, expected_error in cases:
            with self.subTest(expected_error=expected_error):
                try:
                    result = self.validate(**overrides)
                except (TypeError, ValueError) as exc:
                    self.fail(
                        f"Malformed runtime contract escaped as {type(exc).__name__}"
                    )
                self.assertFalse(result.passed)
                self.assertIn(expected_error, result.errors)

    def test_bundle_is_deterministic(self) -> None:
        first = self.validate()
        second = self.validate()
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(first.bundle_sha256, second.bundle_sha256)


if __name__ == "__main__":
    unittest.main()
