from __future__ import annotations

import json
import re
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
FIXTURES = ROOT / "tests" / "fixtures" / "foundation"

CASES = (
    ("input-profile.v1.schema.json", "input-profile.valid.json", "input-profile.invalid.json"),
    ("execution-profile.v1.schema.json", "execution-profile.valid.json", "execution-profile.invalid.json"),
    ("artifact-manifest.v1.schema.json", "artifact-manifest.valid.json", "artifact-manifest.invalid.json"),
    ("capability-pack-manifest.v1.schema.json", "capability-pack-manifest.valid.json", "capability-pack-manifest.invalid.json"),
    ("evidence-snapshot-metadata.v1.schema.json", "evidence-snapshot-metadata.valid.json", "evidence-snapshot-metadata.invalid.json"),
    ("release-bundle-metadata.v1.schema.json", "release-bundle-metadata.valid.json", "release-bundle-metadata.invalid.json"),
)


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise AssertionError(f"{path} must contain a JSON object")
    return value


def _matches_type(expected: str, value: Any) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    return False


def validate_subset(schema: dict[str, Any], value: Any, path: str = "$") -> list[str]:
    errors: list[str] = []
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: const mismatch")
    expected = schema.get("type")
    if expected and not _matches_type(expected, value):
        return errors + [f"{path}: expected {expected}"]

    if expected == "object":
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                errors.append(f"{path}.{key}: required")
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in properties:
                    errors.append(f"{path}.{key}: additional property")
        for key, child_schema in properties.items():
            if key in value:
                errors.extend(validate_subset(child_schema, value[key], f"{path}.{key}"))
    elif expected == "string":
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{path}: shorter than minLength")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            errors.append(f"{path}: pattern mismatch")
    elif expected == "integer":
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: below minimum")
    elif expected == "array":
        if schema.get("uniqueItems"):
            encoded = [json.dumps(item, sort_keys=True) for item in value]
            if len(encoded) != len(set(encoded)):
                errors.append(f"{path}: duplicate items")
        item_schema = schema.get("items")
        if item_schema:
            for index, item in enumerate(value):
                errors.extend(validate_subset(item_schema, item, f"{path}[{index}]"))
    return errors


class FoundationSchemaTests(unittest.TestCase):
    def test_schema_documents_are_versioned_and_closed(self) -> None:
        for schema_name, _, _ in CASES:
            with self.subTest(schema=schema_name):
                schema = load_json(SCHEMAS / schema_name)
                self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
                self.assertTrue(schema["$id"].startswith("urn:omnigenis:schema:"))
                self.assertEqual(schema["type"], "object")
                self.assertIs(schema["additionalProperties"], False)
                self.assertEqual(schema["properties"]["schema_version"]["const"], "1.0.0")

    def test_positive_fixtures_conform(self) -> None:
        for schema_name, valid_name, _ in CASES:
            with self.subTest(schema=schema_name):
                schema = load_json(SCHEMAS / schema_name)
                fixture = load_json(FIXTURES / valid_name)
                self.assertEqual(validate_subset(schema, fixture), [])

    def test_negative_fixtures_are_rejected(self) -> None:
        for schema_name, _, invalid_name in CASES:
            with self.subTest(schema=schema_name):
                schema = load_json(SCHEMAS / schema_name)
                fixture = load_json(FIXTURES / invalid_name)
                self.assertTrue(validate_subset(schema, fixture))

    def test_artifact_parent_ids_must_be_unique(self) -> None:
        schema = load_json(SCHEMAS / "artifact-manifest.v1.schema.json")
        fixture = load_json(FIXTURES / "artifact-manifest.duplicate-parents.invalid.json")
        errors = validate_subset(schema, fixture)
        self.assertIn("$.parent_artifact_ids: duplicate items", errors)

    def test_capability_pack_manifest_requires_activation_contract(self) -> None:
        schema = load_json(SCHEMAS / "capability-pack-manifest.v1.schema.json")
        required = set(schema["required"])
        expected = {
            "real_use_case", "owner_priority", "upstream_status", "license",
            "supported_profile", "resource_budget", "input_fixture", "output_contract",
            "known_issues", "security", "disable_path",
        }
        self.assertTrue(expected.issubset(required))

    def test_evidence_snapshot_metadata_requires_traceability_identity(self) -> None:
        schema = load_json(SCHEMAS / "evidence-snapshot-metadata.v1.schema.json")
        required = set(schema["required"])
        expected = {
            "snapshot_id", "source_registry_id", "source_version", "version_kind",
            "checked_at", "locator", "retrieval_method", "result_sha256", "mutable",
        }
        self.assertTrue(expected.issubset(required))

    def test_release_bundle_metadata_requires_bundle_identity(self) -> None:
        schema = load_json(SCHEMAS / "release-bundle-metadata.v1.schema.json")
        required = set(schema["required"])
        expected = {
            "release_bundle_id", "bundle_sha256", "release_status", "artifact_ids",
        }
        self.assertTrue(expected.issubset(required))

    def test_release_bundle_artifact_ids_must_be_unique(self) -> None:
        schema = load_json(SCHEMAS / "release-bundle-metadata.v1.schema.json")
        fixture = load_json(
            FIXTURES / "release-bundle-metadata.duplicate-artifacts.invalid.json"
        )
        errors = validate_subset(schema, fixture)
        self.assertIn("$.artifact_ids: duplicate items", errors)

    def test_foundation_contracts_do_not_embed_scientific_semantics(self) -> None:
        forbidden = ("grch", "variant", "genomic", "pharmacogen", "pgx", "prs", "hla")
        for schema_name, _, _ in CASES:
            with self.subTest(schema=schema_name):
                text = (SCHEMAS / schema_name).read_text(encoding="utf-8").lower()
                for token in forbidden:
                    self.assertNotIn(token, text)


if __name__ == "__main__":
    unittest.main()
