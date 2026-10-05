from __future__ import annotations
import importlib
import json
from pathlib import Path
import unittest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

ROOT=Path(__file__).resolve().parents[1]
REGISTRY=ROOT/"interoperability"/"profiles.v1.json"
EXPECTED={
 "ga4gh-vrs-v2":("interoperability.vrs","tests.test_reporting_rpt11_vrs_adapter"),
 "ga4gh-phenopackets-v2":("interoperability.phenopackets","tests.test_reporting_rpt11_phenopackets_adapter"),
 "fhir-genomics-reporting-r4":("interoperability.fhir","tests.test_reporting_rpt11_fhir_adapter"),
}

class Rpt11ActivationTests(unittest.TestCase):
    def profiles(self):
        return {p["profile_id"]:p for p in json.loads(REGISTRY.read_text())["profiles"]}

    def test_exactly_reviewed_profiles_are_enabled(self):
        profiles=self.profiles()
        self.assertEqual(set(profiles),set(EXPECTED))
        for profile in profiles.values():
            self.assertEqual(profile["activation_state"],"BOUNDED_ADAPTER_ENABLED")
            self.assertTrue(profile["adapter_enabled"])
            self.assertEqual(profile["unsupported_behavior"],"FAIL_CLOSED")

    def test_enabled_profiles_bind_importable_adapter_and_conformance_test(self):
        for profile_id,(adapter,test_module) in EXPECTED.items():
            profile=self.profiles()[profile_id]
            self.assertEqual(profile["adapter_module"],adapter)
            self.assertEqual(profile["conformance_test_module"],test_module)
            importlib.import_module(adapter)
            importlib.import_module(test_module)

    def test_activation_is_explicitly_bounded_and_disableable(self):
        for profile in self.profiles().values():
            self.assertEqual(profile["conformance_scope"],"BOUNDED_PROFILE_ONLY")
            self.assertGreaterEqual(len(profile["limitations"]),2)
            self.assertEqual(profile["disable_path"],"set adapter_enabled=false and activation_state=DISABLED")
            self.assertEqual(profile["clinical_authorization"],"NOT_ESTABLISHED")

    def test_v1_pending_profile_remains_schema_compatible(self):
        """Legacy declared/pending v1 profiles remain valid without activation-only fields."""
        schema=json.loads((ROOT/"schemas"/"interoperability-profile.v1.schema.json").read_text())
        profile=dict(self.profiles()["fhir-genomics-reporting-r4"])
        for field in ("adapter_module","conformance_test_module","conformance_scope","limitations","disable_path","clinical_authorization"):
            profile.pop(field)
        profile["activation_state"]="PROFILE_DECLARED_ADAPTER_PENDING"
        profile["adapter_enabled"]=False
        Draft202012Validator(schema).validate(profile)

    def test_schema_rejects_contradictory_activation_pairs(self):
        """Activation state and enabled flag cannot contradict each other."""
        schema=json.loads((ROOT/"schemas"/"interoperability-profile.v1.schema.json").read_text())
        validator=Draft202012Validator(schema)
        profile=dict(self.profiles()["ga4gh-vrs-v2"])
        for state,enabled in (
            ("PROFILE_DECLARED_ADAPTER_PENDING",True),
            ("BOUNDED_ADAPTER_ENABLED",False),
            ("DISABLED",True),
        ):
            candidate=dict(profile)
            candidate["activation_state"]=state
            candidate["adapter_enabled"]=enabled
            with self.assertRaises(ValidationError):
                validator.validate(candidate)

    def test_versions_remain_pinned(self):
        profiles=self.profiles()
        self.assertEqual(profiles["ga4gh-vrs-v2"]["standard_version"],"2.0")
        self.assertEqual(profiles["ga4gh-phenopackets-v2"]["standard_version"],"2.0")
        self.assertEqual(profiles["fhir-genomics-reporting-r4"]["standard_version"],"3.0.0")
        self.assertEqual(profiles["fhir-genomics-reporting-r4"]["base_version"],"FHIR 4.0.1")

if __name__=="__main__":
    unittest.main()
