from __future__ import annotations

import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from omnigenis.capabilities.artifact_gate import (
    CAPABILITY_ID,
    CAPABILITY_VERSION,
    RULE_MANIFEST,
    RULE_SHA256,
    RULE_SIZE,
    verify_artifact_bytes,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "artifact_gate"
ARTIFACT_SCHEMA = ROOT / "schemas" / "artifact-manifest.v1.schema.json"
CAPABILITY_SCHEMA = ROOT / "schemas" / "capability-pack-manifest.v1.schema.json"
CAPABILITY_MANIFEST = ROOT / "capabilities" / "artifact-integrity-gate.manifest.json"


def load_manifest(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def rule_statuses(result: object) -> dict[str, str]:
    return {rule.rule_id: rule.status for rule in result.rules}


class ArtifactIntegrityGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = (FIXTURES / "artifact.bin").read_bytes()
        self.valid_manifest = load_manifest("valid-manifest.json")

    def test_valid_artifact_passes_all_individual_rules(self) -> None:
        result = verify_artifact_bytes(self.valid_manifest, self.data)
        self.assertTrue(result.passed)
        self.assertEqual(
            rule_statuses(result),
            {
                RULE_MANIFEST: "PASS",
                RULE_SHA256: "PASS",
                RULE_SIZE: "PASS",
            },
        )
        self.assertEqual(result.artifact_id, "artifact-synthetic-001")
        self.assertEqual(result.actual_size_bytes, len(self.data))
    def test_wrong_digest_fails_only_content_identity(self) -> None:
        result = verify_artifact_bytes(
            load_manifest("wrong-digest-manifest.json"),
            self.data,
        )
        self.assertFalse(result.passed)
        self.assertEqual(
            rule_statuses(result),
            {
                RULE_MANIFEST: "PASS",
                RULE_SHA256: "FAIL",
                RULE_SIZE: "PASS",
            },
        )

    def test_wrong_size_fails_only_size_identity(self) -> None:
        result = verify_artifact_bytes(
            load_manifest("wrong-size-manifest.json"),
            self.data,
        )
        self.assertEqual(
            rule_statuses(result),
            {
                RULE_MANIFEST: "PASS",
                RULE_SHA256: "PASS",
                RULE_SIZE: "FAIL",
            },
        )

    def test_invalid_version_and_duplicate_parents_fail_manifest_rule(self) -> None:
        for name in (
            "invalid-version-manifest.json",
            "duplicate-parents-manifest.json",
        ):
            with self.subTest(name=name):
                result = verify_artifact_bytes(load_manifest(name), self.data)
                statuses = rule_statuses(result)
                self.assertEqual(statuses[RULE_MANIFEST], "FAIL")
                self.assertEqual(statuses[RULE_SHA256], "PASS")
                self.assertEqual(statuses[RULE_SIZE], "PASS")

    def test_non_mapping_manifest_fails_closed_without_exception(self) -> None:
        result = verify_artifact_bytes(["not", "a", "mapping"], self.data)  # type: ignore[arg-type]
        self.assertEqual(
            rule_statuses(result),
            {
                RULE_MANIFEST: "FAIL",
                RULE_SHA256: "FAIL",
                RULE_SIZE: "FAIL",
            },
        )
        self.assertIsNone(result.artifact_id)
    def test_manifest_type_edges_match_closed_json_contract(self) -> None:
        bool_size = dict(self.valid_manifest)
        bool_size["size_bytes"] = True

        fractional_size = dict(self.valid_manifest)
        fractional_size["size_bytes"] = 25.5

        negative_size = dict(self.valid_manifest)
        negative_size["size_bytes"] = -1.0

        extra_property = dict(self.valid_manifest)
        extra_property["path"] = "must-not-be-trusted"

        non_string_key = dict(self.valid_manifest)
        non_string_key[7] = "invalid-json-object-key"  # type: ignore[index]

        for manifest in (
            bool_size,
            fractional_size,
            negative_size,
            extra_property,
            non_string_key,
        ):
            with self.subTest(manifest=manifest):
                result = verify_artifact_bytes(manifest, self.data)
                self.assertEqual(rule_statuses(result)[RULE_MANIFEST], "FAIL")

        self.assertEqual(rule_statuses(verify_artifact_bytes(bool_size, self.data))[RULE_SIZE], "FAIL")

        integer_valued_float = dict(self.valid_manifest)
        integer_valued_float["size_bytes"] = 25.0
        result = verify_artifact_bytes(integer_valued_float, self.data)
        self.assertEqual(rule_statuses(result)[RULE_MANIFEST], "PASS")
        self.assertEqual(rule_statuses(result)[RULE_SIZE], "PASS")

    def test_manifest_contract_tracks_artifact_json_schema(self) -> None:
        schema = json.loads(ARTIFACT_SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)

        cases = [
            self.valid_manifest,
            load_manifest("invalid-version-manifest.json"),
            load_manifest("duplicate-parents-manifest.json"),
        ]
        extra = dict(self.valid_manifest)
        extra["path"] = "unexpected"
        cases.append(extra)
        bool_size = dict(self.valid_manifest)
        bool_size["size_bytes"] = True
        cases.append(bool_size)
        integer_valued_float = dict(self.valid_manifest)
        integer_valued_float["size_bytes"] = 25.0
        cases.append(integer_valued_float)
        fractional_size = dict(self.valid_manifest)
        fractional_size["size_bytes"] = 25.5
        cases.append(fractional_size)

        for manifest in cases:
            with self.subTest(manifest=manifest):
                schema_valid = not list(validator.iter_errors(manifest))
                gate_valid = rule_statuses(
                    verify_artifact_bytes(manifest, self.data)
                )[RULE_MANIFEST] == "PASS"
                self.assertEqual(gate_valid, schema_valid)

    def test_rule_result_order_is_stable(self) -> None:
        result = verify_artifact_bytes(self.valid_manifest, self.data)
        self.assertEqual(
            [rule.rule_id for rule in result.rules],
            [RULE_MANIFEST, RULE_SHA256, RULE_SIZE],
        )
    def test_tool_neutral_result_contract_is_complete(self) -> None:
        payload = verify_artifact_bytes(self.valid_manifest, self.data).to_dict()
        expected = {
            "capability_id",
            "capability_version",
            "canonical_status",
            "canonical_payload",
            "availability",
            "limitations",
            "executor_id",
            "executor_version",
            "adapter_version",
            "model_id",
            "resource_release",
            "reference_bundle",
            "execution_profile",
            "raw_artifact_refs",
            "provenance_refs",
        }
        self.assertEqual(set(payload), expected)
        self.assertEqual(payload["capability_id"], CAPABILITY_ID)
        self.assertEqual(payload["capability_version"], CAPABILITY_VERSION)
        self.assertEqual(payload["canonical_status"], "PASS")
        rules = payload["canonical_payload"]["rules"]
        self.assertEqual(len(rules), 3)

    def test_capability_manifest_conforms_and_is_disabled_by_default(self) -> None:
        schema = json.loads(CAPABILITY_SCHEMA.read_text(encoding="utf-8"))
        manifest = json.loads(CAPABILITY_MANIFEST.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(manifest)
        self.assertEqual(manifest["capability_id"], CAPABILITY_ID)
        self.assertIn("Not wired", manifest["disable_path"])

    def test_gate_has_no_reference_or_promotion_claim(self) -> None:
        payload = verify_artifact_bytes(self.valid_manifest, self.data).to_dict()
        self.assertIsNone(payload["reference_bundle"])
        self.assertEqual(payload["raw_artifact_refs"], [])
        limitations = " ".join(payload["limitations"]).lower()
        self.assertIn("no artifact promotion", limitations)
        self.assertIn("no reference identity", limitations)


if __name__ == "__main__":
    unittest.main()
