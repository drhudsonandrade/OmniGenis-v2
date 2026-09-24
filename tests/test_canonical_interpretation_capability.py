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
from omnigenis.capabilities.evidence_snapshot import (
    ClinVarEvidenceItem,
    ClinVarSubmissionEvidence,
    EvidenceSnapshotMetadataRecord,
    EvidenceSnapshotRuleResult,
    MinimumEvidenceSnapshotResult,
    RULE_CANONICAL_MODEL,
    RULE_CARDINALITY,
    RULE_METADATA,
    RULE_PRESERVATION,
    RULE_SOURCE_CONTRACT,
    RULE_VARIANT_BINDING,
    RULE_XML,
)

ROOT = Path(__file__).resolve().parents[1]
CAPABILITY_MANIFEST = (
    ROOT / "capabilities" / "canonical-interpretation-object.manifest.json"
)
CAPABILITY_SCHEMA = ROOT / "schemas" / "capability-pack-manifest.v1.schema.json"

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
EVIDENCE_RULE_IDS = (
    RULE_CANONICAL_MODEL,
    RULE_SOURCE_CONTRACT,
    RULE_CARDINALITY,
    RULE_METADATA,
    RULE_XML,
    RULE_VARIANT_BINDING,
    RULE_PRESERVATION,
)


def canonical_id(seed: str) -> str:
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return f"omnigenis:small-variant:v1:sha256:{digest}"


def model(
    variant_id: str | None = None,
) -> CanonicalGenomicModelResult:
    variant = CanonicalGenomicVariant(
        canonical_variant_id=variant_id or canonical_id("interpretation"),
        contig_accession="NC_000001.11",
        position_1_based=10471,
        ref="C",
        alt="G",
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
        reference_bundle_sha256="4" * 64,
        normalization_output_sha256="5" * 64,
        variants=(variant,),
        rules=tuple(
            CanonicalGenomicModelRuleResult(rule_id, "PASS", "fixture")
            for rule_id in MODEL_RULE_IDS
        ),
        errors=(),
    )
def evidence_snapshot(
    canonical_model: CanonicalGenomicModelResult,
    *,
    classification: str = "Likely pathogenic",
    review_status: str = (
        "criteria provided, multiple submitters, no conflicts"
    ),
    conflict: bool = False,
    checked_at: str = "2026-09-24T18:00:00Z",
    variant_id: str | None = None,
) -> MinimumEvidenceSnapshotResult:
    target_id = variant_id or canonical_model.variants[0].canonical_variant_id
    metadata = EvidenceSnapshotMetadataRecord(
        schema_version="1.0.0",
        snapshot_id="clinvar-vcv:VCV000001001.3:sha256:1234567890abcdef",
        source_registry_id="source-registry-minimal-e1a-v1",
        source_version="VCV000001001.3",
        version_kind="accession.version",
        checked_at=checked_at,
        locator=(
            "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/efetch.fcgi"
            "?db=clinvar&rettype=vcv&id=VCV000001001.3"
        ),
        retrieval_method="NCBI_EUTILS_HTTPS_EFETCH_VCV",
        result_sha256="6" * 64,
        mutable=True,
    )
    submission = ClinVarSubmissionEvidence(
        accession="SCV000001001",
        version=2,
        submitter_name="Synthetic Laboratory",
        date_updated="2026-09-20",
        date_created="2026-09-20",
        date_last_evaluated="2026-09-15",
        review_status="criteria provided, single submitter",
        classification=classification,
        condition_names=("Synthetic condition A",),
        condition_references=("MedGen:C123456",),
    )
    evidence = ClinVarEvidenceItem(
        canonical_variant_id=target_id,
        metadata=metadata,
        vcv_accession="VCV000001001",
        vcv_version=3,
        variation_id=1001,
        date_last_updated="2026-09-20",
        canonical_spdi="NC_000001.11:10470:C:G",
        clinvar_grch38_assembly_accession="GCF_000001405.38",
        aggregate_classification=classification,
        aggregate_review_status=review_status,
        condition_names=("Synthetic condition A",),
        condition_references=("MedGen:C123456",),
        conflict=conflict,
        submissions=(submission,),
    )
    return MinimumEvidenceSnapshotResult(
        canonical_model_source_vcf_sha256=canonical_model.source_vcf_sha256,
        canonical_model_normalization_output_sha256=(
            canonical_model.normalization_output_sha256
        ),
        source_registry_id="source-registry-minimal-e1a-v1",
        items=(evidence,),
        rules=tuple(
            EvidenceSnapshotRuleResult(rule_id, "PASS", "fixture")
            for rule_id in EVIDENCE_RULE_IDS
        ),
        errors=(),
    )


def empty_model() -> CanonicalGenomicModelResult:
    return replace(model(), variants=())


def empty_snapshot(
    canonical_model: CanonicalGenomicModelResult,
) -> MinimumEvidenceSnapshotResult:
    return replace(
        evidence_snapshot(model()),
        items=(),
        canonical_model_source_vcf_sha256=canonical_model.source_vcf_sha256,
        canonical_model_normalization_output_sha256=(
            canonical_model.normalization_output_sha256
        ),
    )
def load_sut(testcase: unittest.TestCase):
    name = "omnigenis.capabilities.canonical_interpretation"
    if importlib.util.find_spec(name) is None:
        testcase.fail("canonical_interpretation capability module is missing")
    module = importlib.import_module(name)
    for attr in (
        "build_canonical_interpretation_object",
        "CanonicalInterpretationObjectResult",
    ):
        if not hasattr(module, attr):
            testcase.fail(f"{attr} is missing")
    return module


class CanonicalInterpretationObjectCapabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = model()
        self.snapshot = evidence_snapshot(self.model)

    def build(self, **overrides):
        sut = load_sut(self)
        values = {
            "canonical_model": self.model,
            "evidence_snapshot": self.snapshot,
            "as_of_date": "2026-09-24",
        }
        values.update(overrides)
        return sut.build_canonical_interpretation_object(**values)
    def test_simple_source_classification_is_verified_without_local_reclassification(self) -> None:
        result = self.build()
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(len(result.items), 1)
        item = result.items[0]
        self.assertEqual(
            item.canonical_variant_id,
            self.model.variants[0].canonical_variant_id,
        )
        self.assertEqual(item.operational_status, "VERIFIED")
        self.assertEqual(
            item.interpretation_status,
            "SOURCE_CLASSIFICATION_VERIFIED",
        )
        self.assertEqual(item.source_classification, "Likely pathogenic")
        self.assertEqual(
            item.source_review_status,
            "criteria provided, multiple submitters, no conflicts",
        )
        self.assertFalse(item.source_conflict)
        self.assertEqual(item.local_classification_status, "NOT_PERFORMED")
        self.assertIsNone(item.local_classification)
        self.assertEqual(item.acmg_amp_status, "NOT_PERFORMED")
        self.assertEqual(item.clingen_vcep_status, "NOT_PERFORMED")
        self.assertEqual(item.gene_disease_validity_status, "NOT_AVAILABLE")
        self.assertEqual(item.actionability_status, "NOT_ASSESSED")
        self.assertEqual(item.personal_relevance_status, "NOT_ASSESSED")
        self.assertEqual(item.diagnosis_status, "NOT_ASSESSED")
        self.assertEqual(item.treatment_status, "NOT_ASSESSED")
    def test_conflict_remains_unresolved_without_winner(self) -> None:
        snapshot = evidence_snapshot(
            self.model,
            classification="Conflicting classifications of pathogenicity",
            review_status="criteria provided, conflicting classifications",
            conflict=True,
        )
        result = self.build(evidence_snapshot=snapshot)
        self.assertTrue(result.passed, result.errors)
        item = result.items[0]
        self.assertEqual(
            item.interpretation_status,
            "EVIDENCE_CONFLICT_UNRESOLVED",
        )
        self.assertTrue(item.source_conflict)
        self.assertIsNone(item.local_classification)
        payload = item.to_dict()
        self.assertNotIn("winner", payload)
        self.assertNotIn("consensus", payload)
        self.assertNotIn("selected_classification", payload)

    def test_freshness_boundaries_are_deterministic(self) -> None:
        cases = (
            ("2026-09-24T18:00:00Z", "UPDATED_LT_6_MONTHS"),
            ("2026-03-24T18:00:00Z", "UPDATED_6_TO_12_MONTHS"),
            ("2025-09-24T18:00:00Z", "UPDATED_6_TO_12_MONTHS"),
            ("2025-09-23T18:00:00Z", "POTENTIALLY_OUTDATED_GT_12_MONTHS"),
        )
        for checked_at, expected in cases:
            with self.subTest(checked_at=checked_at):
                snapshot = evidence_snapshot(
                    self.model,
                    checked_at=checked_at,
                )
                result = self.build(evidence_snapshot=snapshot)
                self.assertTrue(result.passed, result.errors)
                self.assertEqual(
                    result.items[0].evidence_freshness_status,
                    expected,
                )

    def test_future_evidence_and_invalid_as_of_date_fail_closed(self) -> None:
        future = evidence_snapshot(
            self.model,
            checked_at="2026-09-25T00:00:00Z",
        )
        result = self.build(evidence_snapshot=future)
        self.assertFalse(result.passed)
        self.assertIn("evidence_checked_at_in_future", result.errors)

        result = self.build(as_of_date="24/09/2026")
        self.assertFalse(result.passed)
        self.assertIn("as_of_date_invalid", result.errors)

    def test_unknown_source_classification_is_preserved_verbatim(self) -> None:
        snapshot = evidence_snapshot(
            self.model,
            classification="Emerging source label",
        )
        result = self.build(evidence_snapshot=snapshot)
        self.assertTrue(result.passed, result.errors)
        item = result.items[0]
        self.assertEqual(item.source_classification, "Emerging source label")
        self.assertEqual(
            item.interpretation_status,
            "SOURCE_CLASSIFICATION_VERIFIED",
        )
        self.assertIsNone(item.local_classification)

    def test_model_snapshot_provenance_mismatch_fails_closed(self) -> None:
        forged = replace(
            self.snapshot,
            canonical_model_source_vcf_sha256="0" * 64,
        )
        result = self.build(evidence_snapshot=forged)
        self.assertFalse(result.passed)
        self.assertIn("model_snapshot_provenance_mismatch", result.errors)

        forged = replace(
            self.snapshot,
            canonical_model_normalization_output_sha256="0" * 64,
        )
        result = self.build(evidence_snapshot=forged)
        self.assertFalse(result.passed)
        self.assertIn("model_snapshot_provenance_mismatch", result.errors)
    def test_variant_identity_and_cardinality_mismatch_fail_closed(self) -> None:
        forged = evidence_snapshot(
            self.model,
            variant_id=canonical_id("other"),
        )
        result = self.build(evidence_snapshot=forged)
        self.assertFalse(result.passed)
        self.assertIn("interpretation_variant_binding_mismatch", result.errors)

        forged = replace(self.snapshot, items=())
        result = self.build(evidence_snapshot=forged)
        self.assertFalse(result.passed)
        self.assertIn("interpretation_cardinality_mismatch", result.errors)

    def test_empty_valid_inputs_produce_empty_interpretation_object(self) -> None:
        model_value = empty_model()
        snapshot = empty_snapshot(model_value)
        result = self.build(
            canonical_model=model_value,
            evidence_snapshot=snapshot,
        )
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(result.items, ())
        self.assertEqual(
            result.to_dict()["canonical_payload"]["interpretation_item_count"],
            0,
        )
    def test_snapshot_source_registry_binding_fails_closed(self) -> None:
        forged = replace(
            self.snapshot,
            source_registry_id="unexpected-registry",
        )
        result = self.build(evidence_snapshot=forged)
        self.assertFalse(result.passed)
        self.assertIn("evidence_snapshot_not_verified", result.errors)

        forged_item = replace(
            self.snapshot.items[0],
            metadata=replace(
                self.snapshot.items[0].metadata,
                source_registry_id="unexpected-registry",
            ),
        )
        forged = replace(self.snapshot, items=(forged_item,))
        result = self.build(evidence_snapshot=forged)
        self.assertFalse(result.passed)
        self.assertIn("evidence_snapshot_not_verified", result.errors)

    def test_noncanonical_variant_identity_fails_closed(self) -> None:
        bad_model = replace(
            self.model,
            variants=(
                replace(
                    self.model.variants[0],
                    canonical_variant_id="not-canonical",
                ),
            ),
        )
        bad_snapshot = replace(
            self.snapshot,
            items=(
                replace(
                    self.snapshot.items[0],
                    canonical_variant_id="not-canonical",
                ),
            ),
        )
        result = self.build(
            canonical_model=bad_model,
            evidence_snapshot=bad_snapshot,
        )
        self.assertFalse(result.passed)
        self.assertIn("canonical_model_not_verified", result.errors)

    def test_non_string_identity_fields_fail_closed_without_exception(self) -> None:
        bad_model = replace(
            self.model,
            variants=(
                replace(
                    self.model.variants[0],
                    canonical_variant_id=None,
                ),
            ),
        )
        bad_item_id = replace(
            self.snapshot,
            items=(
                replace(
                    self.snapshot.items[0],
                    canonical_variant_id=None,
                ),
            ),
        )
        bad_vcv = replace(
            self.snapshot,
            items=(
                replace(
                    self.snapshot.items[0],
                    vcv_accession=None,
                ),
            ),
        )
        bad_sha = replace(
            self.snapshot,
            items=(
                replace(
                    self.snapshot.items[0],
                    metadata=replace(
                        self.snapshot.items[0].metadata,
                        result_sha256=None,
                    ),
                ),
            ),
        )
        cases = (
            ({"canonical_model": bad_model}, "canonical_model_not_verified"),
            ({"evidence_snapshot": bad_item_id}, "evidence_snapshot_not_verified"),
            ({"evidence_snapshot": bad_vcv}, "interpretation_source_invalid"),
            ({"evidence_snapshot": bad_sha}, "interpretation_source_invalid"),
        )
        for overrides, expected_error in cases:
            with self.subTest(expected_error=expected_error):
                try:
                    result = self.build(**overrides)
                except (TypeError, ValueError, AttributeError) as exc:
                    self.fail(
                        f"Non-string identity field escaped as {type(exc).__name__}"
                    )
                self.assertFalse(result.passed)
                self.assertIn(expected_error, result.errors)

    def test_malformed_upstream_objects_fail_closed_without_exception(self) -> None:
        cases = (
            (
                {"canonical_model": replace(self.model, rules=(None,))},
                "canonical_model_not_verified",
            ),
            (
                {
                    "evidence_snapshot": replace(
                        self.snapshot,
                        rules=(None,),
                    )
                },
                "evidence_snapshot_not_verified",
            ),
            (
                {
                    "evidence_snapshot": replace(
                        self.snapshot,
                        items=(None,),
                    )
                },
                "evidence_snapshot_not_verified",
            ),
        )
        for overrides, expected_error in cases:
            with self.subTest(expected_error=expected_error):
                try:
                    result = self.build(**overrides)
                except (AttributeError, TypeError, ValueError) as exc:
                    self.fail(
                        f"Malformed upstream object escaped as {type(exc).__name__}"
                    )
                self.assertFalse(result.passed)
                self.assertIn(expected_error, result.errors)

    def test_tool_neutral_contract_exposes_negative_scope_honestly(self) -> None:
        result = self.build()
        payload = result.to_dict()
        self.assertEqual(
            payload["capability_id"],
            "canonical-interpretation-object",
        )
        self.assertEqual(
            payload["canonical_status"],
            "INTERPRETATION_OBJECT_VERIFIED",
        )
        self.assertEqual(
            payload["canonical_payload"]["artifact_kind"],
            "CANONICAL_INTERPRETATION",
        )
        item = payload["canonical_payload"]["items"][0]
        self.assertEqual(item["local_classification_status"], "NOT_PERFORMED")
        self.assertEqual(item["acmg_amp_status"], "NOT_PERFORMED")
        self.assertEqual(item["clingen_vcep_status"], "NOT_PERFORMED")
        self.assertEqual(
            item["gene_disease_validity_status"],
            "NOT_AVAILABLE",
        )
        self.assertNotIn(
            "diagnosis",
            item.get("source_classification", "").lower(),
        )
        manifest = json.loads(CAPABILITY_MANIFEST.read_text())
        schema = json.loads(CAPABILITY_SCHEMA.read_text())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(manifest)
        self.assertEqual(
            manifest["capability_id"],
            "canonical-interpretation-object",
        )
        self.assertIn("acmg", manifest["known_issues"].lower())
        self.assertIn("not wired", manifest["disable_path"].lower())


if __name__ == "__main__":
    unittest.main()
