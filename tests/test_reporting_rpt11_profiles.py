from __future__ import annotations
import json
from pathlib import Path
import unittest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

ROOT=Path(__file__).resolve().parents[1]
SCHEMA=ROOT/"schemas"/"interoperability-profile.v1.schema.json"
REGISTRY=ROOT/"interoperability"/"profiles.v1.json"
VALID=ROOT/"tests"/"fixtures"/"interoperability"/"rpt11"/"profile.valid.json"
INVALID=ROOT/"tests"/"fixtures"/"interoperability"/"rpt11"/"profile.invalid.json"

def load(path):
    """Load deterministic JSON."""
    return json.loads(path.read_text(encoding="utf-8"))

class Rpt11ProfileContractTests(unittest.TestCase):
    def test_schema_and_fixtures(self):
        """Profile contracts use a closed Draft 2020-12 schema."""
        schema=load(SCHEMA)
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(load(VALID))
        with self.assertRaises(ValidationError):
            Draft202012Validator(schema).validate(load(INVALID))

    def test_every_registry_entry_conforms_to_profile_schema(self):
        """Every declared registry profile must satisfy the public profile contract."""
        validator = Draft202012Validator(load(SCHEMA))
        for profile in load(REGISTRY)["profiles"]:
            validator.validate(profile)

    def test_registry_pins_exactly_three_non_ballot_profiles(self):
        """RPT-11 profile expansion is bounded to the accepted budget."""
        data=load(REGISTRY)
        self.assertEqual(data["schema_version"],"1.0.0")
        self.assertEqual(len(data["profiles"]),3)
        by_id={p["profile_id"]:p for p in data["profiles"]}
        self.assertEqual(set(by_id),{"fhir-genomics-reporting-r4","ga4gh-phenopackets-v2","ga4gh-vrs-v2"})
        self.assertEqual(by_id["fhir-genomics-reporting-r4"]["standard_version"],"3.0.0")
        self.assertEqual(by_id["fhir-genomics-reporting-r4"]["base_version"],"FHIR 4.0.1")
        self.assertEqual(by_id["ga4gh-phenopackets-v2"]["standard_version"],"2.0")
        self.assertEqual(by_id["ga4gh-vrs-v2"]["standard_version"],"2.0")
        for profile in by_id.values():
            self.assertNotIn("ballot", profile["standard_version"].lower())

    def test_profiles_expose_only_reviewed_bounded_adapters(self):
        """Enabled profiles remain bounded, offline, and explicitly non-clinical."""
        for profile in load(REGISTRY)["profiles"]:
            self.assertEqual(profile["activation_state"],"BOUNDED_ADAPTER_ENABLED")
            self.assertTrue(profile["adapter_enabled"])
            self.assertEqual(profile["network_access"],"FORBIDDEN_DURING_PROJECTION")
            self.assertEqual(profile["conformance_scope"],"BOUNDED_PROFILE_ONLY")
            self.assertEqual(profile["clinical_authorization"],"NOT_ESTABLISHED")

    def test_identity_and_scientific_boundaries_are_explicit(self):
        """Profiles prohibit inferred person identity and new scientific claims."""
        by_id={p["profile_id"]:p for p in load(REGISTRY)["profiles"]}
        self.assertEqual(by_id["fhir-genomics-reporting-r4"]["subject_identity_policy"],"OPTIONAL_EXPLICIT_ONLY")
        self.assertEqual(by_id["ga4gh-phenopackets-v2"]["subject_identity_policy"],"REQUIRED_EXPLICIT_FOR_SUBJECT_PROJECTION")
        self.assertEqual(by_id["ga4gh-vrs-v2"]["subject_identity_policy"],"NOT_APPLICABLE")
        for profile in by_id.values():
            self.assertEqual(profile["scientific_semantics"],"PROJECT_EXISTING_CANONICAL_E1A_ONLY")
            self.assertEqual(profile["unsupported_behavior"],"FAIL_CLOSED")

    def test_rights_and_sources_are_explicit(self):
        """Every external standard records source and license identity."""
        by_id={p["profile_id"]:p for p in load(REGISTRY)["profiles"]}
        self.assertEqual(by_id["fhir-genomics-reporting-r4"]["license"],"CC-BY-4.0")
        self.assertEqual(by_id["ga4gh-phenopackets-v2"]["license"],"BSD-3-Clause")
        self.assertEqual(by_id["ga4gh-vrs-v2"]["license"],"Apache-2.0")
        for profile in by_id.values():
            self.assertTrue(profile["source_url"].startswith("https://"))

if __name__=="__main__":
    unittest.main()
