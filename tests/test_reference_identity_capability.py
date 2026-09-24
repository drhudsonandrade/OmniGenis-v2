import copy
import hashlib
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from omnigenis.capabilities.reference_identity import (
    RULE_ASSEMBLY,
    RULE_BUNDLE,
    RULE_CONTIGS,
    RULE_FASTA,
    RULE_PROFILE,
    RULE_REPORT,
    RULE_RIGHTS,
    RULE_SOURCE,
    verify_reference_identity,
)

ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = (
    ROOT
    / "resources"
    / "reference-profiles"
    / "grch38-p14-ncbi-refseq-autosomal-v1.json"
)
BOM_PATH = (
    ROOT
    / "resources"
    / "scientific-resource-bom"
    / "grch38-p14-ncbi-refseq-autosomal-v1.json"
)
REGISTRY_PATH = ROOT / "resources" / "source-registry.v1.json"
OBSERVATION_PATH = (
    ROOT
    / "tests"
    / "fixtures"
    / "reference_identity"
    / "ncbi-grch38-p14.observation.json"
)
NEGATIVE_CASES_PATH = (
    ROOT / "tests" / "fixtures" / "reference_identity" / "negative-cases.json"
)
CAPABILITY_MANIFEST = ROOT / "capabilities" / "reference-identity.manifest.json"
CAPABILITY_SCHEMA = ROOT / "schemas" / "capability-pack-manifest.v1.schema.json"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class ReferenceIdentityCapabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = load_json(PROFILE_PATH)
        self.bom = load_json(BOM_PATH)
        self.registry = load_json(REGISTRY_PATH)
        self.observation = load_json(OBSERVATION_PATH)

    def verify(
        self,
        *,
        profile: dict | None = None,
        bom: dict | None = None,
        registry: dict | None = None,
        observation: dict | None = None,
    ):
        return verify_reference_identity(
            profile if profile is not None else self.profile,
            registry if registry is not None else self.registry,
            bom if bom is not None else self.bom,
            observation if observation is not None else self.observation,
        )

    def test_verified_reference_identity_passes_all_rules(self) -> None:
        result = self.verify()
        self.assertTrue(result.passed)
        self.assertEqual(len(result.rules), 8)
        self.assertEqual(
            {rule.rule_id for rule in result.rules},
            {
                RULE_PROFILE,
                RULE_ASSEMBLY,
                RULE_FASTA,
                RULE_REPORT,
                RULE_BUNDLE,
                RULE_SOURCE,
                RULE_RIGHTS,
                RULE_CONTIGS,
            },
        )
        payload = result.to_dict()
        self.assertEqual(payload["canonical_status"], "PASS")
        self.assertEqual(
            payload["canonical_payload"]["verification_status"],
            "VERIFIED",
        )
        self.assertEqual(
            payload["canonical_payload"]["assembly_accession"],
            "GCF_000001405.40",
        )
        self.assertEqual(
            payload["canonical_payload"]["fasta_content_sha256"],
            "df6e4918316e05a9cc1fd29c352841d3678b607d7a436819cd43371b52c814c0",
        )
        self.assertEqual(
            payload["canonical_payload"]["fasta_content_size_bytes"],
            3339739109,
        )
        self.assertEqual(
            len(payload["canonical_payload"]["autosomal_refseq_accessions"]),
            22,
        )
        self.assertEqual(
            payload["canonical_payload"]["autosomal_refseq_accessions"][0],
            "NC_000001.11",
        )
        self.assertEqual(
            payload["canonical_payload"]["autosomal_refseq_accessions"][-1],
            "NC_000022.11",
        )
        self.assertEqual(
            payload["reference_bundle"],
            "1c34b839e1ae36102d003a217f76f1dd57cd1d10b0310cbd9e1d8078c8e88672",
        )

    def test_bundle_and_contig_hashes_are_deterministic(self) -> None:
        self.assertEqual(
            canonical_sha256(self.bom["bundle_descriptor"]),
            self.bom["bundle_sha256"],
        )
        contigs = self.profile["contig_alias_profile"]["contigs"]
        self.assertEqual(
            canonical_sha256(contigs),
            self.profile["contig_alias_profile"]["sha256"],
        )
        self.assertEqual(
            [item["assigned_molecule"] for item in contigs],
            [str(number) for number in range(1, 23)],
        )

    def test_human_alias_alone_is_not_reference_identity(self) -> None:
        result = self.verify(profile={"human_aliases": ["GRCh38"]})
        self.assertFalse(result.passed)
        self.assertEqual(result.rules[0].rule_id, RULE_PROFILE)
        self.assertEqual(result.rules[0].status, "FAIL")
    def test_wrong_fasta_transport_digest_fails(self) -> None:
        observation = copy.deepcopy(self.observation)
        observation["fasta_transport_sha256"] = "0" * 64
        result = self.verify(observation=observation)
        self.assertFalse(result.passed)
        self.assertEqual(
            next(rule for rule in result.rules if rule.rule_id == RULE_FASTA).status,
            "FAIL",
        )

    def test_wrong_fasta_content_digest_fails(self) -> None:
        observation = copy.deepcopy(self.observation)
        observation["fasta_content_sha256"] = "1" * 64
        result = self.verify(observation=observation)
        self.assertFalse(result.passed)
        self.assertEqual(
            next(rule for rule in result.rules if rule.rule_id == RULE_FASTA).status,
            "FAIL",
        )

    def test_wrong_assembly_report_digest_fails(self) -> None:
        observation = copy.deepcopy(self.observation)
        observation["assembly_report_sha256"] = "2" * 64
        result = self.verify(observation=observation)
        self.assertFalse(result.passed)
        self.assertEqual(
            next(rule for rule in result.rules if rule.rule_id == RULE_REPORT).status,
            "FAIL",
        )

    def test_missing_paired_evidence_never_passes_via_none_equality(self) -> None:
        cases = (
            (RULE_FASTA, "bom", ("resources", 0, "size_bytes"), "observation", ("fasta_transport_size_bytes",)),
            (RULE_FASTA, "bom", ("resources", 0, "content_size_bytes"), "observation", ("fasta_content_size_bytes",)),
            (RULE_FASTA, "bom", ("resources", 0, "upstream_md5"), "observation", ("fasta_upstream_md5",)),
            (RULE_REPORT, "bom", ("resources", 1, "size_bytes"), "observation", ("assembly_report_size_bytes",)),
            (RULE_REPORT, "bom", ("validation", "assembly_report_refseq_count"), "observation", ("assembly_report_refseq_count",)),
            (RULE_REPORT, "bom", ("validation", "fasta_sequence_count"), "observation", ("fasta_sequence_count",)),
        )
        for expected_rule, left_name, left_path, right_name, right_path in cases:
            with self.subTest(left_path=left_path, right_path=right_path):
                payloads = {
                    "bom": copy.deepcopy(self.bom),
                    "observation": copy.deepcopy(self.observation),
                }
                for name, path in ((left_name, left_path), (right_name, right_path)):
                    cursor = payloads[name]
                    for part in path[:-1]:
                        cursor = cursor[part]
                    del cursor[path[-1]]
                result = self.verify(
                    bom=payloads["bom"],
                    observation=payloads["observation"],
                )
                self.assertFalse(result.passed)
                self.assertEqual(
                    next(
                        rule for rule in result.rules
                        if rule.rule_id == expected_rule
                    ).status,
                    "FAIL",
                )

    def test_wrong_evidence_types_fail_closed(self) -> None:
        bom = copy.deepcopy(self.bom)
        observation = copy.deepcopy(self.observation)
        bom["resources"][0]["upstream_md5"] = []
        observation["fasta_upstream_md5"] = []
        bom["validation"]["fasta_sequence_count"] = True
        observation["fasta_sequence_count"] = True
        result = self.verify(bom=bom, observation=observation)
        self.assertFalse(result.passed)
        self.assertEqual(
            next(rule for rule in result.rules if rule.rule_id == RULE_FASTA).status,
            "FAIL",
        )
        self.assertEqual(
            next(rule for rule in result.rules if rule.rule_id == RULE_REPORT).status,
            "FAIL",
        )
    def test_wrong_assembly_accession_fails(self) -> None:
        observation = copy.deepcopy(self.observation)
        observation["assembly_refseq_accession"] = "GCF_000001405.39"
        result = self.verify(observation=observation)
        self.assertFalse(result.passed)
        self.assertEqual(
            next(rule for rule in result.rules if rule.rule_id == RULE_ASSEMBLY).status,
            "FAIL",
        )

    def test_unclosed_rights_state_fails(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["sources"][0]["rights_status"] = "REVIEW_REQUIRED"
        result = self.verify(registry=registry)
        self.assertFalse(result.passed)
        self.assertEqual(
            next(rule for rule in result.rules if rule.rule_id == RULE_RIGHTS).status,
            "FAIL",
        )

    def test_source_registry_mismatch_fails(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["sources"][0]["refseq_assembly_accession"] = "GCF_000001405.39"
        result = self.verify(registry=registry)
        self.assertFalse(result.passed)
        self.assertEqual(
            next(rule for rule in result.rules if rule.rule_id == RULE_SOURCE).status,
            "FAIL",
        )
    def test_changed_contig_length_fails(self) -> None:
        observation = copy.deepcopy(self.observation)
        observation["autosomal_contigs"][0]["sequence_length"] += 1
        result = self.verify(observation=observation)
        self.assertFalse(result.passed)
        self.assertEqual(
            next(rule for rule in result.rules if rule.rule_id == RULE_CONTIGS).status,
            "FAIL",
        )

    def test_declared_bundle_digest_mismatch_fails(self) -> None:
        bom = copy.deepcopy(self.bom)
        bom["bundle_sha256"] = "3" * 64
        result = self.verify(bom=bom)
        self.assertFalse(result.passed)
        self.assertEqual(
            next(rule for rule in result.rules if rule.rule_id == RULE_BUNDLE).status,
            "FAIL",
        )

    def test_bundle_descriptor_must_bind_verified_resources(self) -> None:
        bom = copy.deepcopy(self.bom)
        bom["bundle_descriptor"]["fasta_content_sha256"] = "4" * 64
        bom["bundle_sha256"] = canonical_sha256(bom["bundle_descriptor"])
        profile = copy.deepcopy(self.profile)
        profile["resource_bom_ref"]["bundle_sha256"] = bom["bundle_sha256"]
        result = self.verify(profile=profile, bom=bom)
        self.assertFalse(result.passed)
        self.assertEqual(
            next(rule for rule in result.rules if rule.rule_id == RULE_BUNDLE).status,
            "FAIL",
        )

    def test_bundle_resources_must_bind_declared_source(self) -> None:
        bom = copy.deepcopy(self.bom)
        bom["resources"][0]["source_id"] = "different-source"
        result = self.verify(bom=bom)
        self.assertFalse(result.passed)
        self.assertEqual(
            next(rule for rule in result.rules if rule.rule_id == RULE_BUNDLE).status,
            "FAIL",
        )

    def test_unhashable_resource_role_fails_closed(self) -> None:
        bom = copy.deepcopy(self.bom)
        bom["resources"][0]["role"] = []
        result = self.verify(bom=bom)
        self.assertFalse(result.passed)
        self.assertEqual(
            next(rule for rule in result.rules if rule.rule_id == RULE_BUNDLE).status,
            "FAIL",
        )

    def test_unhashable_contig_accession_fails_closed(self) -> None:
        profile = copy.deepcopy(self.profile)
        profile["contig_alias_profile"]["contigs"][0]["refseq_accession"] = []
        result = self.verify(profile=profile)
        self.assertFalse(result.passed)
        self.assertEqual(
            next(rule for rule in result.rules if rule.rule_id == RULE_CONTIGS).status,
            "FAIL",
        )

    def test_boolean_contig_length_fails_closed(self) -> None:
        profile = copy.deepcopy(self.profile)
        profile["contig_alias_profile"]["contigs"][0]["sequence_length"] = True
        result = self.verify(profile=profile)
        self.assertFalse(result.passed)
        self.assertEqual(
            next(rule for rule in result.rules if rule.rule_id == RULE_CONTIGS).status,
            "FAIL",
        )

    def test_negative_fixture_cases_fail_expected_rule(self) -> None:
        cases = load_json(NEGATIVE_CASES_PATH)["cases"]
        for case in cases:
            with self.subTest(case_id=case["case_id"]):
                payloads = {
                    "profile": copy.deepcopy(self.profile),
                    "bom": copy.deepcopy(self.bom),
                    "registry": copy.deepcopy(self.registry),
                    "observation": copy.deepcopy(self.observation),
                }
                cursor = payloads[case["target"]]
                for part in case["path"][:-1]:
                    cursor = cursor[part]
                cursor[case["path"][-1]] = case["value"]
                result = self.verify(
                    profile=payloads["profile"],
                    bom=payloads["bom"],
                    registry=payloads["registry"],
                    observation=payloads["observation"],
                )
                self.assertFalse(result.passed)
                rule = next(
                    item for item in result.rules
                    if item.rule_id == case["expected_rule"]
                )
                self.assertEqual(rule.status, "FAIL")

    def test_partial_manual_result_cannot_claim_verified(self) -> None:
        from omnigenis.capabilities.reference_identity import (
            ReferenceIdentityResult,
            ReferenceRuleResult,
        )

        partial = ReferenceIdentityResult(
            profile_id="grch38-p14-ncbi-refseq-autosomal-v1",
            assembly_accession="GCF_000001405.40",
            bundle_sha256="1c34b839e1ae36102d003a217f76f1dd57cd1d10b0310cbd9e1d8078c8e88672",
            fasta_content_sha256="df6e4918316e05a9cc1fd29c352841d3678b607d7a436819cd43371b52c814c0",
            fasta_content_size_bytes=3339739109,
            autosomal_refseq_accessions=(),
            rules=(
                ReferenceRuleResult(
                    RULE_PROFILE,
                    "PASS",
                    "incomplete_manual_result",
                ),
            ),
        )
        self.assertFalse(partial.passed)
        self.assertEqual(
            partial.to_dict()["canonical_payload"]["verification_status"],
            "NOT_VERIFIED",
        )

    def test_capability_manifest_conforms_and_is_disabled_by_default(self) -> None:
        schema = load_json(CAPABILITY_SCHEMA)
        manifest = load_json(CAPABILITY_MANIFEST)
        Draft202012Validator(schema).validate(manifest)
        self.assertEqual(manifest["capability_id"], "reference-identity")
        self.assertIn("Do not select", manifest["disable_path"])


if __name__ == "__main__":
    unittest.main()
