from __future__ import annotations

from dataclasses import replace
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from omnigenis.capabilities.reference_identity import verify_reference_identity
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
FIXTURE = ROOT / "tests" / "fixtures" / "canonical_variant_identity" / "normalized-synthetic.vcf"
REFERENCE_PROFILE = ROOT / "resources" / "reference-profiles" / "grch38-p14-ncbi-refseq-autosomal-v1.json"
REFERENCE_BOM = ROOT / "resources" / "scientific-resource-bom" / "grch38-p14-ncbi-refseq-autosomal-v1.json"
SOURCE_REGISTRY = ROOT / "resources" / "source-registry.v1.json"
REFERENCE_OBSERVATION = ROOT / "tests" / "fixtures" / "reference_identity" / "ncbi-grch38-p14.observation.json"
CAPABILITY_MANIFEST = ROOT / "capabilities" / "canonical-small-variant-identity.manifest.json"
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
        records.append((fields[0], int(fields[1]), fields[3], fields[4], values.get("GT"), line))
    return records


def normalization_result(
    data: bytes,
    *,
    rule_ids: tuple[str, ...] = NORMALIZATION_RULE_IDS,
    errors: tuple[str, ...] = (),
    output_sha256: str | None = None,
) -> VariantNormalizationResult:
    records = parse_records(data)
    ledger = []
    for ordinal, (chrom, pos, ref, alt, genotype, line) in enumerate(records, start=1):
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
                transformation="UNCHANGED",
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
    return VariantNormalizationResult(
        normalized_vcf=data,
        input_sha256=sha256_bytes(b"synthetic-source-vcf"),
        output_sha256=output_sha256 if output_sha256 is not None else sha256_bytes(data),
        input_record_count=len(records),
        output_record_count=len(records),
        reference_content_sha256="df6e4918316e05a9cc1fd29c352841d3678b607d7a436819cd43371b52c814c0",
        executor_sha256="a1f364208a061f2347134bdbbb37d77fa5dba79938822370b1e046f19684f04b",
        executor_version="1.24",
        rules=tuple(NormalizationRuleResult(rule_id, "PASS", "synthetic_contract_fixture") for rule_id in rule_ids),
        transformation_ledger=tuple(ledger),
        errors=errors,
    )


def load_sut(testcase: unittest.TestCase):
    name = "omnigenis.capabilities.canonical_variant_identity"
    if importlib.util.find_spec(name) is None:
        testcase.fail("canonical_variant_identity capability module is missing")
    module = importlib.import_module(name)
    for attr in ("canonicalize_normalized_variants", "CanonicalVariantIdentityResult"):
        if not hasattr(module, attr):
            testcase.fail(f"{attr} is missing")
    return module


class CanonicalVariantIdentityCapabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = FIXTURE.read_bytes()
        self.identity = reference_identity()
        self.assertTrue(self.identity.passed)

    def test_canonicalizes_normalized_records_deterministically(self) -> None:
        sut = load_sut(self)
        result = sut.canonicalize_normalized_variants(normalization_result(self.data), self.identity)
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(len(result.variants), 2)
        first = result.variants[0]
        payload = {
            "alt": "G",
            "assembly_accession": "GCF_000001405.40",
            "contig_accession": "NC_000001.11",
            "identity_version": "1.0.0",
            "position_1_based": 10471,
            "ref": "C",
            "reference_bundle_sha256": "1c34b839e1ae36102d003a217f76f1dd57cd1d10b0310cbd9e1d8078c8e88672",
        }
        digest = sha256_bytes(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        )
        self.assertEqual(
            first.canonical_variant_id,
            f"omnigenis:small-variant:v1:sha256:{digest}",
        )
        self.assertEqual(result.to_dict()["canonical_payload"]["artifact_kind"], "CANONICAL_VARIANTS")

    def test_identity_ignores_non_identity_vcf_metadata_and_genotype(self) -> None:
        sut = load_sut(self)
        baseline = sut.canonicalize_normalized_variants(normalization_result(self.data), self.identity)
        changed = self.data.replace(
            b"synthetic-snv\tC\tG\t60\tPASS\t.\tGT\t0/1",
            b"different-id\tC\tG\t999\t.\tSYNTHETIC=1\tGT\t1/1",
        )
        changed_result = sut.canonicalize_normalized_variants(normalization_result(changed), self.identity)
        self.assertTrue(baseline.passed and changed_result.passed)
        self.assertEqual(
            baseline.variants[0].canonical_variant_id,
            changed_result.variants[0].canonical_variant_id,
        )

    def test_identity_changes_for_each_core_variant_identity_field(self) -> None:
        sut = load_sut(self)
        baseline = sut.canonicalize_normalized_variants(
            normalization_result(self.data),
            self.identity,
        )
        self.assertTrue(baseline.passed, baseline.errors)
        cases = {
            "position": (
                b"\t10471\tsynthetic-snv\tC\tG\t",
                b"\t10472\tsynthetic-snv\tC\tG\t",
            ),
            "alt": (
                b"\t10471\tsynthetic-snv\tC\tG\t",
                b"\t10471\tsynthetic-snv\tC\tT\t",
            ),
            "ref": (
                b"\t10471\tsynthetic-snv\tC\tG\t",
                b"\t10471\tsynthetic-snv\tA\tG\t",
            ),
            "contig": (
                b"NC_000001.11\t10471\tsynthetic-snv",
                b"NC_000002.12\t10471\tsynthetic-snv",
            ),
        }
        for field, (old, new) in cases.items():
            with self.subTest(field=field):
                changed = self.data.replace(old, new, 1)
                changed_result = sut.canonicalize_normalized_variants(
                    normalization_result(changed),
                    self.identity,
                )
                self.assertTrue(changed_result.passed, changed_result.errors)
                self.assertNotEqual(
                    baseline.variants[0].canonical_variant_id,
                    changed_result.variants[0].canonical_variant_id,
                )

    def test_rejects_failed_or_incomplete_normalization_attestation(self) -> None:
        sut = load_sut(self)
        failed = normalization_result(self.data, errors=("forced_failure",))
        result = sut.canonicalize_normalized_variants(failed, self.identity)
        self.assertFalse(result.passed)
        self.assertIn("normalization_not_verified", result.errors)

        incomplete = normalization_result(self.data, rule_ids=NORMALIZATION_RULE_IDS[:-1])
        result = sut.canonicalize_normalized_variants(incomplete, self.identity)
        self.assertFalse(result.passed)
        self.assertIn("normalization_rule_set_incomplete", result.errors)

    def test_rejects_normalization_output_digest_mismatch(self) -> None:
        sut = load_sut(self)
        forged = normalization_result(self.data, output_sha256="0" * 64)
        result = sut.canonicalize_normalized_variants(forged, self.identity)
        self.assertFalse(result.passed)
        self.assertIn("normalization_output_digest_mismatch", result.errors)

    def test_rejects_reference_identity_mismatch(self) -> None:
        sut = load_sut(self)
        forged = replace(self.identity, bundle_sha256="0" * 64)
        result = sut.canonicalize_normalized_variants(normalization_result(self.data), forged)
        self.assertFalse(result.passed)
        self.assertIn("reference_identity_not_verified", result.errors)

    def test_rejects_multiallelic_symbolic_and_out_of_scope_records(self) -> None:
        sut = load_sut(self)
        cases = (
            self.data.replace(b"\tC\tG\t60", b"\tC\tG,T\t60", 1),
            self.data.replace(b"\tC\tG\t60", b"\tC\t<DEL>\t60", 1),
            self.data.replace(b"NC_000001.11", b"NC_000023.11"),
        )
        for value in cases:
            with self.subTest(value=value.splitlines()[-2]):
                result = sut.canonicalize_normalized_variants(normalization_result(value), self.identity)
                self.assertFalse(result.passed)
                self.assertTrue(
                    any(error.startswith("unsupported_normalized_record_") for error in result.errors),
                    result.errors,
                )

    def test_empty_valid_normalized_vcf_yields_empty_canonical_artifact(self) -> None:
        sut = load_sut(self)
        lines = [
            line
            for line in self.data.decode("utf-8").splitlines()
            if line.startswith("#")
        ]
        empty = ("\n".join(lines) + "\n").encode("utf-8")
        result = sut.canonicalize_normalized_variants(
            normalization_result(empty),
            self.identity,
        )
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(result.variants, ())
        payload = result.to_dict()
        self.assertEqual(payload["canonical_status"], "CANONICALIZED")
        self.assertEqual(payload["canonical_payload"]["variant_count"], 0)

    def test_ambiguous_source_provenance_fails_closed(self) -> None:
        sut = load_sut(self)
        norm = normalization_result(self.data)
        alternate_source = replace(
            norm.transformation_ledger[0],
            source_record_sha256="f" * 64,
        )
        forged = replace(
            norm,
            transformation_ledger=(
                *norm.transformation_ledger,
                alternate_source,
            ),
        )
        result = sut.canonicalize_normalized_variants(forged, self.identity)
        self.assertFalse(result.passed)
        self.assertIn("normalization_provenance_ambiguous", result.errors)

    def test_duplicate_canonical_identity_fails_closed(self) -> None:
        sut = load_sut(self)
        lines = self.data.decode("utf-8").splitlines()
        first = next(line for line in lines if line.startswith("NC_000001.11\t10471\t"))
        text = self.data.decode("utf-8")
        duplicate = text.replace(first + "\n", first + "\n" + first + "\n", 1).encode("utf-8")
        result = sut.canonicalize_normalized_variants(normalization_result(duplicate), self.identity)
        self.assertFalse(result.passed)
        self.assertIn("duplicate_canonical_variant_identity", result.errors)

    def test_preserves_normalization_and_source_provenance_without_identity_pollution(self) -> None:
        sut = load_sut(self)
        norm = normalization_result(self.data)
        result = sut.canonicalize_normalized_variants(norm, self.identity)
        self.assertTrue(result.passed)
        first = result.variants[0]
        self.assertEqual(first.normalization_output_sha256, norm.output_sha256)
        self.assertEqual(first.source_record_sha256s, (norm.transformation_ledger[0].source_record_sha256,))
        serialized = json.dumps(result.to_dict(), sort_keys=True)
        self.assertNotIn("HGVS", serialized)
        self.assertNotIn("rsid", serialized.lower())
        self.assertNotIn("gene_symbol", serialized)

    def test_malformed_cross_capability_attestations_fail_closed(self) -> None:
        sut = load_sut(self)
        norm = normalization_result(self.data)
        cases = (
            (
                replace(norm, rules=(None,)),
                self.identity,
                "normalization_rule_set_invalid",
            ),
            (
                replace(norm, rules=("PASS",)),
                self.identity,
                "normalization_rule_set_invalid",
            ),
            (
                norm,
                replace(self.identity, rules=(None,)),
                "reference_identity_not_verified",
            ),
            (
                replace(norm, transformation_ledger=(None,)),
                self.identity,
                "normalization_provenance_invalid",
            ),
        )
        for normalization, identity, expected_error in cases:
            with self.subTest(expected_error=expected_error):
                try:
                    result = sut.canonicalize_normalized_variants(
                        normalization,
                        identity,
                    )
                except (AttributeError, TypeError, ValueError) as exc:
                    self.fail(
                        "Malformed cross-capability input escaped as "
                        f"{type(exc).__name__}"
                    )
                self.assertFalse(result.passed)
                self.assertIn(expected_error, result.errors)

    def test_tool_neutral_result_and_manifest_contract(self) -> None:
        sut = load_sut(self)
        result = sut.canonicalize_normalized_variants(normalization_result(self.data), self.identity)
        payload = result.to_dict()
        self.assertEqual(payload["capability_id"], "canonical-small-variant-identity")
        self.assertEqual(payload["canonical_status"], "CANONICALIZED")
        self.assertEqual(payload["executor_id"], "omnigenis.python-stdlib")
        self.assertIsNone(payload["adapter_version"])
        schema = load_json(CAPABILITY_SCHEMA)
        manifest = load_json(CAPABILITY_MANIFEST)
        Draft202012Validator(schema).validate(manifest)
        self.assertEqual(manifest["capability_id"], "canonical-small-variant-identity")
        self.assertIn("HGVS", manifest["known_issues"])
        self.assertIn("not wired", manifest["disable_path"])


if __name__ == "__main__":
    unittest.main()
