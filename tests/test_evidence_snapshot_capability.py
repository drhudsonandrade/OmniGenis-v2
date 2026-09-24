from __future__ import annotations

from dataclasses import replace
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from omnigenis.capabilities.canonical_genomic_model import (
    CanonicalGenomicModelResult,
    CanonicalGenomicModelRuleResult,
    CanonicalGenomicVariant,
    RULE_CANONICAL_VARIANTS,
    RULE_MODEL,
    RULE_NORMALIZATION,
    RULE_NORMALIZED_QC,
    RULE_REFERENCE,
    RULE_SAMPLE,
    RULE_SOURCE_ARTIFACT,
    RULE_SOURCE_QC,
)

ROOT = Path(__file__).resolve().parents[1]
SIMPLE_XML = ROOT / "tests" / "fixtures" / "evidence_snapshot" / "simple-vcv.xml"
CONFLICT_XML = ROOT / "tests" / "fixtures" / "evidence_snapshot" / "conflict-vcv.xml"
CAPABILITY_MANIFEST = ROOT / "capabilities" / "minimum-evidence-snapshot.manifest.json"
CAPABILITY_SCHEMA = ROOT / "schemas" / "capability-pack-manifest.v1.schema.json"
METADATA_SCHEMA = ROOT / "schemas" / "evidence-snapshot-metadata.v1.schema.json"
SOURCE_REGISTRY = ROOT / "resources" / "source-registry.v1.json"

MODEL_RULE_IDS = (
    RULE_SOURCE_ARTIFACT,
    RULE_SOURCE_QC,
    RULE_REFERENCE,
    RULE_NORMALIZATION,
    RULE_CANONICAL_VARIANTS,
    RULE_SAMPLE,
    RULE_NORMALIZED_QC,
    RULE_MODEL,
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_id(seed: str) -> str:
    return "omnigenis:small-variant:v1:sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def model_for_variant(
    *,
    contig: str,
    position: int,
    ref: str,
    alt: str,
    seed: str,
) -> CanonicalGenomicModelResult:
    variant = CanonicalGenomicVariant(
        canonical_variant_id=canonical_id(seed),
        contig_accession=contig,
        position_1_based=position,
        ref=ref,
        alt=alt,
        genotype="0/1",
        zygosity="HETEROZYGOUS",
        phase_semantics="UNPHASED",
        depth=30,
        genotype_quality=60,
        allele_balance=0.5,
        filter_status="PASS",
        normalized_record_ordinal=1,
        normalized_record_sha256="1" * 64,
        source_record_sha256s=("2" * 64,),
        normalization_transformation="UNCHANGED",
    )
    return CanonicalGenomicModelResult(
        sample_id="SAMPLE_A",
        source_artifact_id="source-vcf",
        source_vcf_sha256="3" * 64,
        source_vcf_size_bytes=1234,
        reference_profile_id="grch38-p14-ncbi-refseq-autosomal-v1",
        reference_assembly_accession="GCF_000001405.40",
        reference_bundle_sha256="1c34b839e1ae36102d003a217f76f1dd57cd1d10b0310cbd9e1d8078c8e88672",
        normalization_output_sha256="4" * 64,
        variants=(variant,),
        rules=tuple(
            CanonicalGenomicModelRuleResult(rule_id, "PASS", "fixture")
            for rule_id in MODEL_RULE_IDS
        ),
        errors=(),
    )


def empty_model() -> CanonicalGenomicModelResult:
    model = model_for_variant(
        contig="NC_000001.11",
        position=10471,
        ref="C",
        alt="G",
        seed="empty-template",
    )
    return replace(model, variants=())


def metadata(xml_bytes: bytes, source_version: str, checked_at: str = "2026-09-24T18:00:00Z"):
    digest = sha256_bytes(xml_bytes)
    return {
        "schema_version": "1.0.0",
        "snapshot_id": f"clinvar-vcv:{source_version}:sha256:{digest[:16]}",
        "source_registry_id": "source-registry-minimal-e1a-v1",
        "source_version": source_version,
        "version_kind": "accession.version",
        "checked_at": checked_at,
        "locator": (
            "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/efetch.fcgi"
            f"?db=clinvar&rettype=vcv&id={source_version}"
        ),
        "retrieval_method": "NCBI_EUTILS_HTTPS_EFETCH_VCV",
        "result_sha256": digest,
        "mutable": True,
    }
def source_registry():
    return {
        "registry_id": "source-registry-minimal-e1a-v1",
        "schema_version": "1.0.0",
        "sources": [
            {
                "source_id": "ncbi-clinvar-vcv",
                "provider": "NCBI ClinVar",
                "version_release": "Per-record VCV accession.version snapshots",
                "retrieval_date": "2026-09-24",
                "source_url": "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/efetch.fcgi",
                "terms_url": "https://www.ncbi.nlm.nih.gov/clinvar/docs/maintenance_use/",
                "license": "ClinVar data are freely available for any use; attribution to ClinVar requested.",
                "rights_status": "UNRESTRICTED_USE_WITH_ATTRIBUTION_REQUESTED",
                "local_reference_use": "ALLOWED",
                "redistribution": "ALLOWED_WITH_ATTRIBUTION_REQUESTED",
                "lifecycle": "MUTABLE_PER_RECORD_SNAPSHOT",
                "limitations": "NIH does not independently verify submitted information; not intended for direct diagnostic use without genetics professional review.",
                "known_issues": "ClinVar is continuously updated and classifications may conflict; every EvidenceSnapshot must pin accession.version, retrieval time, and content digest.",
                "replacement_path": "Retrieve the required VCV accession.version, record retrieval time and SHA-256, and create a new EvidenceSnapshot rather than mutating an existing one.",
                "attribution": "CLINVAR_ATTRIBUTION_REQUESTED",
            }
        ],
    }


def item(model: CanonicalGenomicModelResult, xml_bytes: bytes, source_version: str):
    return {
        "canonical_variant_id": model.variants[0].canonical_variant_id,
        "metadata": metadata(xml_bytes, source_version),
        "xml_bytes": xml_bytes,
    }


def load_sut(testcase: unittest.TestCase):
    name = "omnigenis.capabilities.evidence_snapshot"
    if importlib.util.find_spec(name) is None:
        testcase.fail("evidence_snapshot capability module is missing")
    module = importlib.import_module(name)
    for attr in ("build_minimum_evidence_snapshot", "MinimumEvidenceSnapshotResult"):
        if not hasattr(module, attr):
            testcase.fail(f"{attr} is missing")
    return module


class MinimumEvidenceSnapshotCapabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.simple_xml = SIMPLE_XML.read_bytes()
        self.conflict_xml = CONFLICT_XML.read_bytes()
        self.simple_model = model_for_variant(
            contig="NC_000001.11",
            position=10471,
            ref="C",
            alt="G",
            seed="simple",
        )
        self.conflict_model = model_for_variant(
            contig="NC_000016.10",
            position=88738562,
            ref="G",
            alt="C",
            seed="conflict",
        )
        self.registry = source_registry()

    def build(self, model, evidence_items, registry=None):
        sut = load_sut(self)
        return sut.build_minimum_evidence_snapshot(
            canonical_model=model,
            evidence_items=evidence_items,
            source_registry=self.registry if registry is None else registry,
        )

    def test_simple_vcv_snapshot_preserves_aggregate_and_submission_evidence(self) -> None:
        result = self.build(
            self.simple_model,
            [item(self.simple_model, self.simple_xml, "VCV000001001.3")],
        )
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(len(result.items), 1)
        evidence = result.items[0]
        self.assertEqual(evidence.canonical_variant_id, self.simple_model.variants[0].canonical_variant_id)
        self.assertEqual(evidence.vcv_accession, "VCV000001001")
        self.assertEqual(evidence.vcv_version, 3)
        self.assertEqual(evidence.variation_id, 1001)
        self.assertEqual(evidence.aggregate_classification, "Likely pathogenic")
        self.assertEqual(evidence.aggregate_review_status, "criteria provided, single submitter")
        self.assertEqual(evidence.condition_names, ("Synthetic condition A",))
        self.assertFalse(evidence.conflict)
        self.assertEqual(len(evidence.submissions), 1)
        submission = evidence.submissions[0]
        self.assertEqual(submission.accession, "SCV000001001")
        self.assertEqual(submission.version, 2)
        self.assertEqual(submission.submitter_name, "Synthetic Laboratory")
        self.assertEqual(submission.classification, "Likely pathogenic")
        self.assertEqual(submission.review_status, "criteria provided, single submitter")
        self.assertEqual(submission.condition_names, ("Synthetic condition A",))
    def test_no_conflicts_review_status_is_not_marked_as_conflict(self) -> None:
        xml_bytes = self.simple_xml.replace(
            b"criteria provided, single submitter",
            b"criteria provided, multiple submitters, no conflicts",
            1,
        )
        result = self.build(
            self.simple_model,
            [item(self.simple_model, xml_bytes, "VCV000001001.3")],
        )
        self.assertTrue(result.passed, result.errors)
        self.assertFalse(result.items[0].conflict)

    def test_conflicting_vcv_preserves_all_scv_classifications_without_winner(self) -> None:
        result = self.build(
            self.conflict_model,
            [item(self.conflict_model, self.conflict_xml, "VCV000002002.4")],
        )
        self.assertTrue(result.passed, result.errors)
        evidence = result.items[0]
        self.assertTrue(evidence.conflict)
        self.assertEqual(
            evidence.aggregate_classification,
            "Conflicting classifications of pathogenicity",
        )
        self.assertEqual(
            {submission.classification for submission in evidence.submissions},
            {"Likely benign", "Uncertain significance"},
        )
        item_payload = result.to_dict()["canonical_payload"]["items"][0]
        forbidden_decision_keys = {"winner", "consensus", "vote", "selected_classification"}
        self.assertTrue(forbidden_decision_keys.isdisjoint(item_payload))
        for submission_payload in item_payload["submissions"]:
            self.assertTrue(
                forbidden_decision_keys.isdisjoint(submission_payload)
            )

    def test_metadata_digest_version_locator_and_retrieval_contract_fail_closed(self) -> None:
        base = item(self.simple_model, self.simple_xml, "VCV000001001.3")
        mutations = []
        bad = json.loads(json.dumps(base["metadata"]))
        bad["result_sha256"] = "0" * 64
        mutations.append((bad, "evidence_metadata_digest_mismatch"))
        bad = json.loads(json.dumps(base["metadata"]))
        bad["source_version"] = "VCV000001001.2"
        bad["locator"] = (
            "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/efetch.fcgi"
            "?db=clinvar&rettype=vcv&id=VCV000001001.2"
        )
        mutations.append((bad, "clinvar_version_binding_mismatch"))
        bad = json.loads(json.dumps(base["metadata"]))
        bad["locator"] = "https://example.invalid/clinvar"
        mutations.append((bad, "evidence_metadata_locator_invalid"))
        bad = json.loads(json.dumps(base["metadata"]))
        bad["retrieval_method"] = "OTHER"
        mutations.append((bad, "evidence_metadata_retrieval_invalid"))
        for metadata_value, expected_error in mutations:
            with self.subTest(expected_error=expected_error):
                forged = dict(base)
                forged["metadata"] = metadata_value
                result = self.build(self.simple_model, [forged])
                self.assertFalse(result.passed)
                self.assertIn(expected_error, result.errors)

    def test_variant_coordinate_and_allele_binding_fail_closed(self) -> None:
        cases = (
            replace(
                self.simple_model,
                variants=(replace(self.simple_model.variants[0], position_1_based=10472),),
            ),
            replace(
                self.simple_model,
                variants=(replace(self.simple_model.variants[0], alt="T"),),
            ),
        )
        for forged_model in cases:
            with self.subTest(variant=forged_model.variants[0]):
                evidence_item = {
                    "canonical_variant_id": forged_model.variants[0].canonical_variant_id,
                    "metadata": metadata(self.simple_xml, "VCV000001001.3"),
                    "xml_bytes": self.simple_xml,
                }
                result = self.build(forged_model, [evidence_item])
                self.assertFalse(result.passed)
                self.assertIn("clinvar_variant_binding_mismatch", result.errors)

    def test_missing_duplicate_and_unknown_variant_items_fail_closed(self) -> None:
        good = item(self.simple_model, self.simple_xml, "VCV000001001.3")
        result = self.build(self.simple_model, [])
        self.assertFalse(result.passed)
        self.assertIn("evidence_cardinality_mismatch", result.errors)

        result = self.build(self.simple_model, [good, dict(good)])
        self.assertFalse(result.passed)
        self.assertIn("duplicate_evidence_variant_id", result.errors)

        unknown = dict(good)
        unknown["canonical_variant_id"] = canonical_id("other")
        result = self.build(self.simple_model, [unknown])
        self.assertFalse(result.passed)
        self.assertIn("evidence_variant_not_in_model", result.errors)

    def test_empty_canonical_model_yields_empty_snapshot(self) -> None:
        result = self.build(empty_model(), [])
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(result.items, ())
        self.assertEqual(result.to_dict()["canonical_payload"]["evidence_item_count"], 0)
    def test_malformed_unsafe_and_wrong_root_xml_fail_closed(self) -> None:
        utf16_unsafe = (
            '<?xml version="1.0" encoding="UTF-16"?>'
            '<!DOCTYPE x [<!ENTITY a "x">]>'
            '<ClinVarResult-Set>&a;</ClinVarResult-Set>'
        ).encode("utf-16")
        cases = (
            (b"<not-xml", "clinvar_xml_invalid"),
            (
                b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "x">]><ClinVarResult-Set>&a;</ClinVarResult-Set>',
                "clinvar_xml_unsafe",
            ),
            (utf16_unsafe, "clinvar_xml_unsafe"),
            (b'<?xml version="1.0"?><Other/>', "clinvar_root_invalid"),
        )
        for xml_bytes, expected_error in cases:
            with self.subTest(expected_error=expected_error):
                evidence_item = {
                    "canonical_variant_id": self.simple_model.variants[0].canonical_variant_id,
                    "metadata": metadata(xml_bytes, "VCV000001001.3"),
                    "xml_bytes": xml_bytes,
                }
                result = self.build(self.simple_model, [evidence_item])
                self.assertFalse(result.passed)
                self.assertIn(expected_error, result.errors)

    def test_submission_condition_reference_without_name_is_preserved(self) -> None:
        xml_bytes = self.simple_xml.replace(
            b'<Name><ElementValue Type="Preferred">Synthetic condition A</ElementValue></Name>',
            b'<XRef DB="MedGen" ID="C123456" Type="CUI"/>',
        )
        result = self.build(
            self.simple_model,
            [item(self.simple_model, xml_bytes, "VCV000001001.3")],
        )
        self.assertTrue(result.passed, result.errors)
        evidence = result.items[0]
        self.assertEqual(evidence.condition_names, ())
        self.assertEqual(
            evidence.condition_references,
            ("MedGen:C123456",),
        )
        submission = evidence.submissions[0]
        self.assertEqual(submission.condition_names, ())
        self.assertEqual(
            submission.condition_references,
            ("MedGen:C123456",),
        )

    def test_malformed_model_and_source_registry_fail_closed(self) -> None:
        forged_model = replace(self.simple_model, rules=(None,))
        try:
            result = self.build(
                forged_model,
                [item(self.simple_model, self.simple_xml, "VCV000001001.3")],
            )
        except (AttributeError, TypeError, ValueError) as exc:
            self.fail(f"Malformed model escaped as {type(exc).__name__}")
        self.assertFalse(result.passed)
        self.assertIn("canonical_model_not_verified", result.errors)

        forged_registry = source_registry()
        forged_registry["sources"][0]["license"] = "unknown"
        result = self.build(
            self.simple_model,
            [item(self.simple_model, self.simple_xml, "VCV000001001.3")],
            registry=forged_registry,
        )
        self.assertFalse(result.passed)
        self.assertIn("clinvar_source_contract_not_verified", result.errors)

    def test_non_ascii_integer_attributes_fail_closed_without_exception(self) -> None:
        cases = (
            (
                self.simple_xml.replace(b'Version="3"', 'Version="²"'.encode("utf-8"), 1),
                "clinvar_archive_invalid",
            ),
            (
                self.simple_xml.replace(b'VariationID="1001"', 'VariationID="²"'.encode("utf-8"), 1),
                "clinvar_archive_invalid",
            ),
            (
                self.simple_xml.replace(b'Version="2"', 'Version="²"'.encode("utf-8"), 1),
                "clinvar_submission_invalid",
            ),
            (
                self.simple_xml.replace(
                    b'NumberOfSubmissions="1"',
                    'NumberOfSubmissions="²"'.encode("utf-8"),
                    1,
                ),
                "clinvar_submission_count_mismatch",
            ),
        )
        for xml_bytes, expected_error in cases:
            with self.subTest(expected_error=expected_error):
                try:
                    result = self.build(
                        self.simple_model,
                        [item(self.simple_model, xml_bytes, "VCV000001001.3")],
                    )
                except (TypeError, ValueError) as exc:
                    self.fail(
                        f"Unicode numeric attribute escaped as {type(exc).__name__}"
                    )
                self.assertFalse(result.passed)
                self.assertIn(expected_error, result.errors)

    def test_clinvar_no_conflicts_aggregate_is_authoritative_over_differing_scvs(self) -> None:
        xml_bytes = self.conflict_xml
        xml_bytes = xml_bytes.replace(
            b"criteria provided, conflicting classifications",
            b"criteria provided, multiple submitters, no conflicts",
            1,
        )
        xml_bytes = xml_bytes.replace(
            b"Conflicting classifications of pathogenicity",
            b"Pathogenic/Likely pathogenic",
            1,
        )
        xml_bytes = xml_bytes.replace(b"Likely benign", b"Pathogenic", 1)
        xml_bytes = xml_bytes.replace(
            b"Uncertain significance",
            b"Likely pathogenic",
            1,
        )
        result = self.build(
            self.conflict_model,
            [item(self.conflict_model, xml_bytes, "VCV000002002.4")],
        )
        self.assertTrue(result.passed, result.errors)
        self.assertFalse(result.items[0].conflict)
        self.assertEqual(
            {submission.classification for submission in result.items[0].submissions},
            {"Pathogenic", "Likely pathogenic"},
        )

    def test_metadata_schema_manifest_and_public_source_registry_contract(self) -> None:
        metadata_value = metadata(self.simple_xml, "VCV000001001.3")
        Draft202012Validator(json.loads(METADATA_SCHEMA.read_text())).validate(metadata_value)

        manifest = json.loads(CAPABILITY_MANIFEST.read_text())
        Draft202012Validator(json.loads(CAPABILITY_SCHEMA.read_text())).validate(manifest)
        self.assertEqual(manifest["capability_id"], "minimum-evidence-snapshot")
        self.assertIn("conflict", manifest["known_issues"].lower())

        registry = json.loads(SOURCE_REGISTRY.read_text())
        source = next(
            source
            for source in registry["sources"]
            if source["source_id"] == "ncbi-clinvar-vcv"
        )
        self.assertEqual(
            source["rights_status"],
            "UNRESTRICTED_USE_WITH_ATTRIBUTION_REQUESTED",
        )
        self.assertEqual(source["lifecycle"], "MUTABLE_PER_RECORD_SNAPSHOT")

    def test_tool_neutral_output_contains_no_clinical_reclassification(self) -> None:
        result = self.build(
            self.conflict_model,
            [item(self.conflict_model, self.conflict_xml, "VCV000002002.4")],
        )
        payload = result.to_dict()
        self.assertEqual(payload["capability_id"], "minimum-evidence-snapshot")
        self.assertEqual(payload["canonical_status"], "SNAPSHOT_VERIFIED")
        self.assertEqual(payload["canonical_payload"]["artifact_kind"], "EVIDENCE_SNAPSHOT")
        self.assertEqual(payload["executor_id"], "omnigenis.python-stdlib")
        serialized = json.dumps(payload, sort_keys=True).lower()
        self.assertNotIn("acmg_classification", serialized)
        self.assertNotIn("project_priority", serialized)
        self.assertNotIn("clinical_interpretation", serialized)


if __name__ == "__main__":
    unittest.main()
