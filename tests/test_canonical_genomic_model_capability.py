from __future__ import annotations

from dataclasses import replace
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from omnigenis.capabilities.artifact_gate import verify_artifact_bytes
from omnigenis.capabilities.canonical_variant_identity import canonicalize_normalized_variants
from omnigenis.capabilities.reference_identity import verify_reference_identity
from omnigenis.capabilities.vcf_qc import observe_vcf_qc
from omnigenis.capabilities.variant_normalization import (
    NormalizationRuleResult,
    OutputVariantRecord,
    RULE_CARDINALITY,
    RULE_EXECUTOR,
    RULE_INDEXABILITY,
    RULE_INPUT,
    RULE_ORDERING,
    RULE_PHASE,
    RULE_REFERENCE,
    RULE_REF_CONCORDANCE,
    RULE_RETENTION,
    RULE_STRICT_REPARSE,
    VariantNormalizationResult,
    VariantTransformationLedgerEntry,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "canonical_genomic_model" / "source-normalized.vcf"
REFERENCE_PROFILE = ROOT / "resources" / "reference-profiles" / "grch38-p14-ncbi-refseq-autosomal-v1.json"
REFERENCE_BOM = ROOT / "resources" / "scientific-resource-bom" / "grch38-p14-ncbi-refseq-autosomal-v1.json"
SOURCE_REGISTRY = ROOT / "resources" / "source-registry.v1.json"
REFERENCE_OBSERVATION = ROOT / "tests" / "fixtures" / "reference_identity" / "ncbi-grch38-p14.observation.json"
CAPABILITY_MANIFEST = ROOT / "capabilities" / "canonical-genomic-model.manifest.json"
CAPABILITY_SCHEMA = ROOT / "schemas" / "capability-pack-manifest.v1.schema.json"

NORMALIZATION_RULE_IDS = (
    RULE_INPUT,
    RULE_EXECUTOR,
    RULE_REFERENCE,
    RULE_STRICT_REPARSE,
    RULE_CARDINALITY,
    RULE_PHASE,
    RULE_ORDERING,
    RULE_INDEXABILITY,
    RULE_REF_CONCORDANCE,
    RULE_RETENTION,
)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def reference_identity():
    return verify_reference_identity(
        load_json(REFERENCE_PROFILE),
        load_json(SOURCE_REGISTRY),
        load_json(REFERENCE_BOM),
        load_json(REFERENCE_OBSERVATION),
    )
def parse_records(data: bytes) -> list[tuple[str, int, str, str, str | None, str]]:
    records: list[tuple[str, int, str, str, str | None, str]] = []
    for line in data.decode("utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        fmt = fields[8].split(":")
        sample = fields[9].split(":")
        values = dict(zip(fmt, sample, strict=False))
        records.append(
            (fields[0], int(fields[1]), fields[3], fields[4], values.get("GT"), line)
        )
    return records


def normalization_result(
    source: bytes,
    normalized: bytes | None = None,
    *,
    phase_status: str = "PASS",
    transformations: tuple[str, ...] | None = None,
) -> VariantNormalizationResult:
    normalized_bytes = source if normalized is None else normalized
    records = parse_records(normalized_bytes)
    transformations = transformations or tuple("UNCHANGED" for _ in records)
    if len(transformations) != len(records):
        raise AssertionError("test fixture transformation count mismatch")
    ledger = []
    for ordinal, ((chrom, pos, ref, alt, genotype, _line), transformation) in enumerate(
        zip(records, transformations, strict=True),
        start=1,
    ):
        ledger.append(
            VariantTransformationLedgerEntry(
                source_record_ordinal=ordinal,
                source_record_sha256=sha256_bytes(f"source:{ordinal}".encode("ascii")),
                chrom=chrom,
                pos=pos,
                record_id=f"source-{ordinal}",
                ref=ref,
                alt=alt,
                genotype=genotype,
                transformation=transformation,
                output_records=(
                    OutputVariantRecord(
                        output_record_ordinal=ordinal,
                        chrom=chrom,
                        pos=pos,
                        ref=ref,
                        alt=alt,
                        genotype=genotype,
                        used_alt_index=None,
                    ),
                ),
            )
        )
    rules = []
    for rule_id in NORMALIZATION_RULE_IDS:
        status = phase_status if rule_id == RULE_PHASE else "PASS"
        rules.append(NormalizationRuleResult(rule_id, status, "fixture"))
    return VariantNormalizationResult(
        normalized_vcf=normalized_bytes,
        input_sha256=sha256_bytes(source),
        output_sha256=sha256_bytes(normalized_bytes),
        input_record_count=len(parse_records(source)),
        output_record_count=len(records),
        reference_content_sha256="df6e4918316e05a9cc1fd29c352841d3678b607d7a436819cd43371b52c814c0",
        executor_sha256="a1f364208a061f2347134bdbbb37d77fa5dba79938822370b1e046f19684f04b",
        executor_version="1.24",
        rules=tuple(rules),
        transformation_ledger=tuple(ledger),
        errors=(),
    )


def artifact_manifest(data: bytes) -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "artifact_id": "source-vcf",
        "artifact_kind": "RAW_INPUT",
        "media_type": "text/vcf",
        "sha256": sha256_bytes(data),
        "size_bytes": len(data),
        "producer_execution_profile_id": "canonical-genomic-model-test-v1",
        "parent_artifact_ids": [],
    }
def load_sut(testcase: unittest.TestCase):
    name = "omnigenis.capabilities.canonical_genomic_model"
    if importlib.util.find_spec(name) is None:
        testcase.fail("canonical_genomic_model capability module is missing")
    module = importlib.import_module(name)
    for attr in ("build_canonical_genomic_model", "CanonicalGenomicModelResult"):
        if not hasattr(module, attr):
            testcase.fail(f"{attr} is missing")
    return module


class CanonicalGenomicModelCapabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = FIXTURE.read_bytes()
        self.identity = reference_identity()
        self.assertTrue(self.identity.passed)
        self.manifest = artifact_manifest(self.source)
        self.artifact_gate = verify_artifact_bytes(self.manifest, self.source)
        self.qc = observe_vcf_qc(self.source)
        self.normalization = normalization_result(self.source)
        self.canonical = canonicalize_normalized_variants(
            self.normalization,
            self.identity,
        )
        self.assertTrue(self.artifact_gate.passed)
        self.assertEqual(self.qc.errors, ())
        self.assertTrue(self.canonical.passed)

    def build(self, **overrides):
        sut = load_sut(self)
        values = {
            "source_vcf": self.source,
            "source_artifact_manifest": self.manifest,
            "source_artifact_gate": self.artifact_gate,
            "source_qc": self.qc,
            "reference_identity": self.identity,
            "normalization": self.normalization,
            "canonical_variants": self.canonical,
        }
        values.update(overrides)
        return sut.build_canonical_genomic_model(**values)

    def test_builds_minimum_canonical_model_with_technical_observations(self) -> None:
        result = self.build()
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(result.sample_id, "SAMPLE_A")
        self.assertEqual(result.source_artifact_id, "source-vcf")
        self.assertEqual(result.source_vcf_sha256, sha256_bytes(self.source))
        self.assertEqual(result.reference_bundle_sha256, self.identity.bundle_sha256)
        self.assertEqual(len(result.variants), 2)

        snv, indel = result.variants
        self.assertEqual(snv.canonical_variant_id, self.canonical.variants[0].canonical_variant_id)
        self.assertEqual(snv.genotype, "0/1")
        self.assertEqual(snv.zygosity, "HETEROZYGOUS")
        self.assertEqual(snv.phase_semantics, "UNPHASED")
        self.assertEqual(snv.depth, 30)
        self.assertEqual(snv.genotype_quality, 60)
        self.assertAlmostEqual(snv.allele_balance, 0.5)
        self.assertEqual(snv.filter_status, "PASS")

        self.assertEqual(indel.genotype, "1|1")
        self.assertEqual(indel.zygosity, "HOMOZYGOUS_ALTERNATE")
        self.assertEqual(indel.phase_semantics, "PHASED")
        self.assertEqual(indel.depth, 20)
        self.assertEqual(indel.genotype_quality, 50)
        self.assertIsNone(indel.allele_balance)
        self.assertEqual(indel.filter_status, "q10")
    def test_model_is_deterministic_and_preserves_provenance(self) -> None:
        first = self.build()
        second = self.build()
        self.assertEqual(first.to_dict(), second.to_dict())
        for model_variant, canonical_variant in zip(
            first.variants,
            self.canonical.variants,
            strict=True,
        ):
            self.assertEqual(
                model_variant.normalized_record_sha256,
                canonical_variant.normalized_record_sha256,
            )
            self.assertEqual(
                model_variant.source_record_sha256s,
                canonical_variant.source_record_sha256s,
            )
            self.assertEqual(
                model_variant.normalization_transformation,
                "UNCHANGED",
            )

    def test_source_artifact_and_qc_are_reverified_against_exact_bytes(self) -> None:
        forged_gate = replace(self.artifact_gate, actual_sha256="0" * 64)
        result = self.build(source_artifact_gate=forged_gate)
        self.assertFalse(result.passed)
        self.assertIn("source_artifact_attestation_mismatch", result.errors)

        forged_qc = replace(self.qc, sample_id="OTHER_SAMPLE")
        result = self.build(source_qc=forged_qc)
        self.assertFalse(result.passed)
        self.assertIn("source_qc_attestation_mismatch", result.errors)

    def test_cross_capability_bindings_fail_closed(self) -> None:
        forged_normalization = replace(
            self.normalization,
            input_sha256="0" * 64,
        )
        result = self.build(normalization=forged_normalization)
        self.assertFalse(result.passed)
        self.assertIn("normalization_input_binding_mismatch", result.errors)

        forged_canonical = replace(
            self.canonical,
            normalization_output_sha256="0" * 64,
        )
        result = self.build(canonical_variants=forged_canonical)
        self.assertFalse(result.passed)
        self.assertIn("canonical_variant_attestation_mismatch", result.errors)

    def test_normalized_sample_identity_must_match_source_sample(self) -> None:
        changed = self.source.replace(b"\tSAMPLE_A\n", b"\tSAMPLE_B\n")
        forged_norm = normalization_result(self.source, changed)
        forged_canon = canonicalize_normalized_variants(forged_norm, self.identity)
        self.assertTrue(forged_canon.passed)
        result = self.build(
            normalization=forged_norm,
            canonical_variants=forged_canon,
        )
        self.assertFalse(result.passed)
        self.assertIn("sample_identity_mismatch", result.errors)
    def test_empty_valid_callset_produces_empty_model(self) -> None:
        header = b"\n".join(
            line
            for line in self.source.splitlines()
            if line.startswith(b"#")
        ) + b"\n"
        manifest = artifact_manifest(header)
        gate = verify_artifact_bytes(manifest, header)
        qc = observe_vcf_qc(header)
        norm = normalization_result(header)
        canonical = canonicalize_normalized_variants(norm, self.identity)
        self.assertTrue(canonical.passed, canonical.errors)
        result = self.build(
            source_vcf=header,
            source_artifact_manifest=manifest,
            source_artifact_gate=gate,
            source_qc=qc,
            normalization=norm,
            canonical_variants=canonical,
        )
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(result.variants, ())
        self.assertEqual(result.to_dict()["canonical_payload"]["variant_count"], 0)

    def test_qc_errors_block_model_construction(self) -> None:
        invalid = self.source.replace(b"0/1:30:60:15,15", b"0/1:-1:60:15,15")
        manifest = artifact_manifest(invalid)
        gate = verify_artifact_bytes(manifest, invalid)
        qc = observe_vcf_qc(invalid)
        self.assertTrue(qc.errors)
        norm = normalization_result(invalid)
        canonical = canonicalize_normalized_variants(norm, self.identity)
        result = self.build(
            source_vcf=invalid,
            source_artifact_manifest=manifest,
            source_artifact_gate=gate,
            source_qc=qc,
            normalization=norm,
            canonical_variants=canonical,
        )
        self.assertFalse(result.passed)
        self.assertIn("source_qc_not_acceptable", result.errors)

    def test_malformed_upstream_rule_sets_fail_closed(self) -> None:
        cases = (
            (
                {"reference_identity": replace(self.identity, rules=(None,))},
                "reference_identity_not_verified",
            ),
            (
                {"normalization": replace(self.normalization, rules=(None,))},
                "normalization_not_verified",
            ),
        )
        for overrides, expected_error in cases:
            with self.subTest(expected_error=expected_error):
                try:
                    result = self.build(**overrides)
                except (AttributeError, TypeError, ValueError) as exc:
                    self.fail(
                        "Malformed upstream attestation escaped as "
                        f"{type(exc).__name__}"
                    )
                self.assertFalse(result.passed)
                self.assertIn(expected_error, result.errors)

    def test_unknown_normalization_transformation_fails_closed(self) -> None:
        forged_entry = replace(
            self.normalization.transformation_ledger[0],
            transformation="INVENTED",
        )
        forged_norm = replace(
            self.normalization,
            transformation_ledger=(
                forged_entry,
                *self.normalization.transformation_ledger[1:],
            ),
        )
        forged_canonical = canonicalize_normalized_variants(
            forged_norm,
            self.identity,
        )
        self.assertTrue(forged_canonical.passed, forged_canonical.errors)
        result = self.build(
            normalization=forged_norm,
            canonical_variants=forged_canonical,
        )
        self.assertFalse(result.passed)
        self.assertIn("normalization_transformation_invalid", result.errors)

    def test_tool_neutral_contract_excludes_downstream_annotation_and_evidence(self) -> None:
        result = self.build()
        payload = result.to_dict()
        self.assertEqual(payload["capability_id"], "canonical-genomic-model")
        self.assertEqual(payload["canonical_status"], "CANONICALIZED")
        self.assertEqual(
            payload["canonical_payload"]["artifact_kind"],
            "CANONICAL_GENOMIC_MODEL",
        )
        serialized = json.dumps(payload, sort_keys=True).lower()
        self.assertNotIn("hgvs", serialized)
        self.assertNotIn("gene_hgnc", serialized)
        self.assertNotIn("evidence_snapshot", serialized)
        self.assertNotIn("interpretation", serialized)

        manifest = load_json(CAPABILITY_MANIFEST)
        schema = load_json(CAPABILITY_SCHEMA)
        Draft202012Validator(schema).validate(manifest)
        self.assertEqual(manifest["capability_id"], "canonical-genomic-model")
        self.assertIn("gene mapping", manifest["known_issues"].lower())
        self.assertIn("not wired", manifest["disable_path"].lower())

    def test_split_transformation_preserves_phase_invalidation(self) -> None:
        rules = tuple(
            NormalizationRuleResult(
                rule.rule_id,
                "EXPLICITLY_INVALIDATED" if rule.rule_id == RULE_PHASE else rule.status,
                "fixture",
            )
            for rule in self.normalization.rules
        )
        ledger = (
            replace(
                self.normalization.transformation_ledger[0],
                transformation="SPLIT",
            ),
            self.normalization.transformation_ledger[1],
        )
        norm = replace(
            self.normalization,
            rules=rules,
            transformation_ledger=ledger,
        )
        canonical = canonicalize_normalized_variants(norm, self.identity)
        self.assertTrue(canonical.passed, canonical.errors)
        result = self.build(
            normalization=norm,
            canonical_variants=canonical,
        )
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(
            result.variants[0].phase_semantics,
            "EXPLICITLY_INVALIDATED",
        )
        self.assertEqual(
            result.variants[1].phase_semantics,
            "PHASED",
        )

    def test_normalized_qc_errors_block_model_construction(self) -> None:
        invalid_normalized = self.source.replace(
            b"0/1:30:60:15,15",
            b"0/1:-1:60:15,15",
        )
        norm = normalization_result(self.source, invalid_normalized)
        canonical = canonicalize_normalized_variants(norm, self.identity)
        self.assertTrue(canonical.passed, canonical.errors)
        result = self.build(
            normalization=norm,
            canonical_variants=canonical,
        )
        self.assertFalse(result.passed)
        self.assertIn("normalized_qc_not_acceptable", result.errors)

    def test_canonical_variant_order_is_bound_to_recomputed_attestation(self) -> None:
        forged = replace(
            self.canonical,
            variants=tuple(reversed(self.canonical.variants)),
        )
        result = self.build(canonical_variants=forged)
        self.assertFalse(result.passed)
        self.assertIn("canonical_variant_attestation_mismatch", result.errors)


if __name__ == "__main__":
    unittest.main()
