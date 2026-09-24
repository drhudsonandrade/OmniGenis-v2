from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
APPROVED = ROOT / "tests" / "fixtures" / "gene_identity" / "hgnc-approved-mini.tsv"
WITHDRAWN = ROOT / "tests" / "fixtures" / "gene_identity" / "hgnc-withdrawn-mini.tsv"
CAPABILITY_MANIFEST = ROOT / "capabilities" / "hgnc-gene-identity.manifest.json"
CAPABILITY_SCHEMA = ROOT / "schemas" / "capability-pack-manifest.v1.schema.json"
PUBLIC_BOM = ROOT / "resources" / "scientific-resource-bom" / "hgnc-gene-identity-2026-09-18-v1.json"
PUBLIC_REGISTRY = ROOT / "resources" / "source-registry.v1.json"

PROFILE_ID = "hgnc-gene-identity-2026-09-18-v1"
SOURCE_ID = "hgnc-gene-nomenclature"
REGISTRY_ID = "source-registry-minimal-e1a-v1"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_sha256(value: object) -> str:
    return sha256_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    )
def load_sut(testcase: unittest.TestCase):
    name = "omnigenis.capabilities.gene_identity"
    if importlib.util.find_spec(name) is None:
        testcase.fail("gene_identity capability module is missing")
    module = importlib.import_module(name)
    for attr in ("resolve_gene_identity", "GeneIdentityResult"):
        if not hasattr(module, attr):
            testcase.fail(f"{attr} is missing")
    return module


def synthetic_contract(approved: bytes, withdrawn: bytes):
    descriptor = {
        "profile_id": PROFILE_ID,
        "source_id": SOURCE_ID,
        "upstream_last_modified": "2026-09-18",
        "approved_sha256": sha256_bytes(approved),
        "approved_size_bytes": len(approved),
        "withdrawn_sha256": sha256_bytes(withdrawn),
        "withdrawn_size_bytes": len(withdrawn),
    }
    bundle_sha = canonical_sha256(descriptor)
    registry = {
        "registry_id": REGISTRY_ID,
        "schema_version": "1.0.0",
        "sources": [
            {
                "source_id": SOURCE_ID,
                "provider": "HUGO Gene Nomenclature Committee (HGNC)",
                "version_release": "HGNC snapshot 2026-09-18",
                "retrieval_date": "2026-09-24",
                "source_url": "https://storage.googleapis.com/public-download-files/hgnc/",
                "terms_url": "https://www.genenames.org/about/license/",
                "license": "Creative Commons Zero (CC0)",
                "rights_status": "PUBLIC_DOMAIN_CC0",
                "local_reference_use": "ALLOWED",
                "redistribution": "ALLOWED_CC0",
                "lifecycle": "PINNED_BY_DIGEST",
                "limitations": "Mutable upstream current files; trusted identity is digest-pinned.",
                "known_issues": "Symbols can change; withdrawn and merged/split reports exist.",
                "replacement_path": "Create a new versioned HGNC resource BOM.",
                "attribution": "RECOMMENDED_NOT_REQUIRED",
            }
        ],
    }
    bom = {
        "schema_version": "1.0.0",
        "bom_id": "scientific-resource-bom-hgnc-gene-identity-2026-09-18-v1",
        "profile_id": PROFILE_ID,
        "source_registry_id": REGISTRY_ID,
        "source_id": SOURCE_ID,
        "bundle_descriptor": descriptor,
        "bundle_sha256": bundle_sha,
        "resources": [
            {
                "resource_id": "hgnc-approved-complete-set-2026-09-18",
                "role": "approved_gene_records",
                "source_id": SOURCE_ID,
                "source_url": "https://storage.googleapis.com/public-download-files/hgnc/tsv/tsv/hgnc_complete_set.txt",
                "version_release": "HGNC snapshot 2026-09-18",
                "sha256": descriptor["approved_sha256"],
                "size_bytes": descriptor["approved_size_bytes"],
                "license": "Creative Commons Zero (CC0)",
                "use_rights": "PUBLIC_DOMAIN_CC0",
                "storage_mode": "EXTERNAL_PRIVATE_CACHE_NOT_REPOSITORY",
                "lifecycle": "PINNED",
                "known_issues": "Approved symbols remain mutable display/search metadata.",
                "replacement_path": "Create a new versioned HGNC resource BOM.",
            },
            {
                "resource_id": "hgnc-withdrawn-set-2026-09-18",
                "role": "withdrawn_gene_records",
                "source_id": SOURCE_ID,
                "source_url": "https://storage.googleapis.com/public-download-files/hgnc/tsv/tsv/withdrawn.txt",
                "version_release": "HGNC snapshot 2026-09-18",
                "sha256": descriptor["withdrawn_sha256"],
                "size_bytes": descriptor["withdrawn_size_bytes"],
                "license": "Creative Commons Zero (CC0)",
                "use_rights": "PUBLIC_DOMAIN_CC0",
                "storage_mode": "EXTERNAL_PRIVATE_CACHE_NOT_REPOSITORY",
                "lifecycle": "PINNED",
                "known_issues": "Withdrawn records are lifecycle evidence, not current canonical genes.",
                "replacement_path": "Create a new versioned HGNC resource BOM.",
            },
        ],
        "validation": {
            "approved_row_count": 3,
            "withdrawn_row_count": 3,
            "approved_ids_unique": True,
            "approved_symbols_unique": True,
            "withdrawn_ids_unique": True,
            "withdrawn_symbols_unique": True,
        },
    }
    return registry, bom, bundle_sha
class GeneIdentityCapabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.approved = APPROVED.read_bytes()
        self.withdrawn = WITHDRAWN.read_bytes()
        self.registry, self.bom, self.bundle_sha = synthetic_contract(
            self.approved,
            self.withdrawn,
        )

    def run_synthetic(self, query: str, *, approved: bytes | None = None,
                      withdrawn: bytes | None = None, registry=None, bom=None):
        sut = load_sut(self)
        approved_bytes = self.approved if approved is None else approved
        withdrawn_bytes = self.withdrawn if withdrawn is None else withdrawn
        registry_value = self.registry if registry is None else registry
        bom_value = self.bom if bom is None else bom
        with (
            patch.object(sut, "HGNC_APPROVED_SHA256", sha256_bytes(self.approved)),
            patch.object(sut, "HGNC_APPROVED_SIZE_BYTES", len(self.approved)),
            patch.object(sut, "HGNC_APPROVED_ROW_COUNT", 3),
            patch.object(sut, "HGNC_WITHDRAWN_SHA256", sha256_bytes(self.withdrawn)),
            patch.object(sut, "HGNC_WITHDRAWN_SIZE_BYTES", len(self.withdrawn)),
            patch.object(sut, "HGNC_WITHDRAWN_ROW_COUNT", 3),
            patch.object(sut, "HGNC_BUNDLE_SHA256", self.bundle_sha),
        ):
            return sut.resolve_gene_identity(
                query,
                approved_tsv=approved_bytes,
                withdrawn_tsv=withdrawn_bytes,
                source_registry=registry_value,
                resource_bom=bom_value,
            )

    def test_hgnc_id_and_approved_symbol_resolve_to_same_stable_identity(self) -> None:
        by_id = self.run_synthetic("HGNC:1001")
        by_symbol = self.run_synthetic("GENEA")
        self.assertTrue(by_id.passed, by_id.errors)
        self.assertTrue(by_symbol.passed, by_symbol.errors)
        self.assertEqual(by_id.gene.canonical_gene_id, "HGNC:1001")
        self.assertEqual(by_symbol.gene.canonical_gene_id, "HGNC:1001")
        self.assertEqual(by_id.gene.approved_symbol, "GENEA")
        self.assertEqual(by_id.gene.approved_name, "Gene alpha")
        self.assertEqual(by_id.gene.resolution_basis, "HGNC_ID")
        self.assertEqual(by_symbol.gene.resolution_basis, "APPROVED_SYMBOL")

    def test_unique_previous_and_alias_symbols_resolve_with_explicit_basis(self) -> None:
        previous = self.run_synthetic("OLDA")
        alias = self.run_synthetic("ALPHA")
        self.assertTrue(previous.passed, previous.errors)
        self.assertTrue(alias.passed, alias.errors)
        self.assertEqual(previous.gene.canonical_gene_id, "HGNC:1001")
        self.assertEqual(previous.gene.resolution_basis, "PREVIOUS_SYMBOL")
        self.assertEqual(alias.gene.canonical_gene_id, "HGNC:1001")
        self.assertEqual(alias.gene.resolution_basis, "ALIAS_SYMBOL")

    def test_current_approved_symbol_precedes_alias_collision(self) -> None:
        result = self.run_synthetic("GENEA")
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(result.gene.canonical_gene_id, "HGNC:1001")
        self.assertEqual(result.gene.resolution_basis, "APPROVED_SYMBOL")

    def test_ambiguous_alias_fails_closed(self) -> None:
        result = self.run_synthetic("SHARED")
        self.assertFalse(result.passed)
        self.assertIn("gene_symbol_ambiguous", result.errors)
        self.assertIsNone(result.gene)

    def test_unknown_query_fails_closed(self) -> None:
        result = self.run_synthetic("DOES_NOT_EXIST")
        self.assertFalse(result.passed)
        self.assertIn("gene_identity_not_found", result.errors)
    def test_withdrawn_and_merged_records_preserve_lifecycle_without_canonicalization(self) -> None:
        for query, status, replacement_count in (
            ("HGNC:9001", "Entry Withdrawn", 0),
            ("OLDY", "Merged/Split", 1),
            ("OLDZ", "Merged/Split", 2),
        ):
            with self.subTest(query=query):
                result = self.run_synthetic(query)
                self.assertFalse(result.passed)
                self.assertEqual(result.to_dict()["canonical_status"], "WITHDRAWN_OR_REPLACED")
                self.assertIsNone(result.gene)
                self.assertEqual(result.lifecycle.status, status)
                self.assertEqual(len(result.lifecycle.replacement_candidates), replacement_count)
                if query == "OLDZ":
                    self.assertTrue(result.lifecycle.upstream_duplicate_replacement_candidates)
                self.assertIn("withdrawn_gene_identifier", result.errors)

    def test_resource_digest_mismatch_fails_before_resolution(self) -> None:
        corrupted = bytes([self.approved[0] ^ 1]) + self.approved[1:]
        result = self.run_synthetic("GENEA", approved=corrupted)
        self.assertFalse(result.passed)
        self.assertIn("hgnc_approved_digest_mismatch", result.errors)

    def test_forged_bom_and_source_registry_fail_closed(self) -> None:
        forged_bom = json.loads(json.dumps(self.bom))
        forged_bom["bundle_sha256"] = "0" * 64
        result = self.run_synthetic("GENEA", bom=forged_bom)
        self.assertFalse(result.passed)
        self.assertIn("hgnc_resource_contract_not_verified", result.errors)

        forged_registry = json.loads(json.dumps(self.registry))
        forged_registry["sources"][0]["license"] = "unknown"
        result = self.run_synthetic("GENEA", registry=forged_registry)
        self.assertFalse(result.passed)
        self.assertIn("hgnc_resource_contract_not_verified", result.errors)

    def test_resource_role_guards_reject_two_resource_boms(self) -> None:
        sut = load_sut(self)
        for mutation in ("duplicate_role", "non_string_role"):
            with self.subTest(mutation=mutation):
                forged = json.loads(json.dumps(self.bom))
                if mutation == "duplicate_role":
                    forged["resources"][1]["role"] = (
                        forged["resources"][0]["role"]
                    )
                else:
                    forged["resources"][1]["role"] = 123
                self.assertEqual(sut._resources_by_role(forged), {})

    def test_three_resource_entries_fail_closed(self) -> None:
        forged = json.loads(json.dumps(self.bom))
        forged["resources"].append(
            json.loads(json.dumps(forged["resources"][0]))
        )
        result = self.run_synthetic("GENEA", bom=forged)
        self.assertFalse(result.passed)
        self.assertIn(
            "hgnc_resource_contract_not_verified",
            result.errors,
        )

    def test_nonserializable_bundle_descriptor_fails_closed(self) -> None:
        sut = load_sut(self)
        forged = json.loads(json.dumps(self.bom))
        forged["bundle_descriptor"]["unexpected"] = b"not-json"
        with (
            patch.object(sut, "HGNC_APPROVED_SHA256", sha256_bytes(self.approved)),
            patch.object(sut, "HGNC_APPROVED_SIZE_BYTES", len(self.approved)),
            patch.object(sut, "HGNC_APPROVED_ROW_COUNT", 3),
            patch.object(sut, "HGNC_WITHDRAWN_SHA256", sha256_bytes(self.withdrawn)),
            patch.object(sut, "HGNC_WITHDRAWN_SIZE_BYTES", len(self.withdrawn)),
            patch.object(sut, "HGNC_WITHDRAWN_ROW_COUNT", 3),
            patch.object(sut, "HGNC_BUNDLE_SHA256", self.bundle_sha),
        ):
            try:
                result = sut.resolve_gene_identity(
                    "GENEA",
                    approved_tsv=self.approved,
                    withdrawn_tsv=self.withdrawn,
                    source_registry=self.registry,
                    resource_bom=forged,
                )
            except (TypeError, ValueError) as exc:
                self.fail(
                    f"Malformed descriptor escaped as {type(exc).__name__}"
                )
        self.assertFalse(result.passed)
        self.assertIn(
            "hgnc_resource_contract_not_verified",
            result.errors,
        )

    def test_malformed_inputs_fail_closed_without_exception(self) -> None:
        sut = load_sut(self)
        with (
            patch.object(sut, "HGNC_APPROVED_SHA256", sha256_bytes(self.approved)),
            patch.object(sut, "HGNC_APPROVED_SIZE_BYTES", len(self.approved)),
            patch.object(sut, "HGNC_APPROVED_ROW_COUNT", 3),
            patch.object(sut, "HGNC_WITHDRAWN_SHA256", sha256_bytes(self.withdrawn)),
            patch.object(sut, "HGNC_WITHDRAWN_SIZE_BYTES", len(self.withdrawn)),
            patch.object(sut, "HGNC_WITHDRAWN_ROW_COUNT", 3),
            patch.object(sut, "HGNC_BUNDLE_SHA256", self.bundle_sha),
        ):
            for query in (None, "", 123, [], {}):
                with self.subTest(query=query):
                    try:
                        result = sut.resolve_gene_identity(
                            query,
                            approved_tsv=self.approved,
                            withdrawn_tsv=self.withdrawn,
                            source_registry=self.registry,
                            resource_bom=self.bom,
                        )
                    except (AttributeError, TypeError, ValueError) as exc:
                        self.fail(f"Malformed input escaped as {type(exc).__name__}")
                    self.assertFalse(result.passed)
                    self.assertIn("gene_query_invalid", result.errors)

    def test_tool_neutral_result_and_public_resource_contract(self) -> None:
        sut = load_sut(self)
        result = self.run_synthetic("GENEA")
        payload = result.to_dict()
        self.assertEqual(payload["capability_id"], "hgnc-gene-identity")
        self.assertEqual(payload["canonical_status"], "VERIFIED")
        self.assertEqual(payload["executor_id"], "omnigenis.python-stdlib")
        self.assertEqual(payload["canonical_payload"]["gene"]["canonical_gene_id"], "HGNC:1001")
        self.assertNotEqual(
            payload["canonical_payload"]["gene"]["canonical_gene_id"],
            payload["canonical_payload"]["gene"]["approved_symbol"],
        )

        schema = json.loads(CAPABILITY_SCHEMA.read_text())
        manifest = json.loads(CAPABILITY_MANIFEST.read_text())
        Draft202012Validator(schema).validate(manifest)
        self.assertEqual(manifest["capability_id"], "hgnc-gene-identity")
        self.assertIn("HGNC ID", manifest["output_contract"])
        registry = json.loads(PUBLIC_REGISTRY.read_text())
        source = next(s for s in registry["sources"] if s["source_id"] == SOURCE_ID)
        self.assertEqual(source["license"], "Creative Commons Zero (CC0)")
        self.assertEqual(source["lifecycle"], "PINNED_BY_DIGEST")
        public_bom = json.loads(PUBLIC_BOM.read_text())
        self.assertEqual(public_bom["profile_id"], PROFILE_ID)
        self.assertEqual(
            public_bom["bundle_sha256"],
            "e437feb98c084d34f4988f61d3d0556e59b9aa81e5d082830bfe83e969cdab94",
        )
        resources = {r["role"]: r for r in public_bom["resources"]}
        self.assertEqual(
            resources["approved_gene_records"]["sha256"],
            "69bb5722d5a42bb355580deb2c9f197ce3d7f7d13807173b9674a7db65e52191",
        )
        self.assertEqual(
            resources["withdrawn_gene_records"]["sha256"],
            "9328a7361ed5149bf7901cae52c6c30b832b8ec55af22146ea296081278a3140",
        )


if __name__ == "__main__":
    unittest.main()
