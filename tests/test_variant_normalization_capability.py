import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator

from omnigenis.capabilities.reference_identity import (
    RULE_ASSEMBLY as REF_RULE_ASSEMBLY,
    RULE_BUNDLE as REF_RULE_BUNDLE,
    RULE_CONTIGS as REF_RULE_CONTIGS,
    RULE_FASTA as REF_RULE_FASTA,
    RULE_PROFILE as REF_RULE_PROFILE,
    RULE_REPORT as REF_RULE_REPORT,
    RULE_RIGHTS as REF_RULE_RIGHTS,
    RULE_SOURCE as REF_RULE_SOURCE,
    ReferenceIdentityResult,
    ReferenceRuleResult,
)
from omnigenis.capabilities.variant_normalization import (
    REFERENCE_ASSEMBLY,
    REFERENCE_BUNDLE_SHA256,
    REFERENCE_FASTA_CONTENT_SHA256 as PRODUCTION_REFERENCE_FASTA_CONTENT_SHA256,
    REFERENCE_FASTA_CONTENT_SIZE_BYTES as PRODUCTION_REFERENCE_FASTA_CONTENT_SIZE_BYTES,
    REFERENCE_PROFILE_ID,
    RULE_CARDINALITY,
    RULE_EXECUTOR,
    RULE_INDEXABILITY,
    RULE_PHASE,
    RULE_REFERENCE,
    RULE_REF_CONCORDANCE,
    RULE_RETENTION,
    RULE_STRICT_REPARSE,
    VariantNormalizationResult,
    normalize_small_variants,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "variant_normalization"
INPUT = FIXTURES / "input.vcf"
REFERENCE = FIXTURES / "synthetic-reference.fa"
EXPECTED = FIXTURES / "expected-normalized.vcf"
CAPABILITY_MANIFEST = (
    ROOT / "capabilities" / "reference-bound-small-variant-normalization.manifest.json"
)
CAPABILITY_SCHEMA = ROOT / "schemas" / "capability-pack-manifest.v1.schema.json"
EXECUTOR_PROFILE = (
    ROOT
    / "resources"
    / "executor-profiles"
    / "bcftools-1.24-reference-normalization-v1.json"
)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def synthetic_reference_identity(reference: Path = REFERENCE) -> ReferenceIdentityResult:
    """Build an adapter-only fixture identity; this is not scientific verification."""
    return ReferenceIdentityResult(
        profile_id=REFERENCE_PROFILE_ID,
        assembly_accession=REFERENCE_ASSEMBLY,
        bundle_sha256=REFERENCE_BUNDLE_SHA256,
        fasta_content_sha256=sha256_file(reference),
        fasta_content_size_bytes=reference.stat().st_size,
        autosomal_refseq_accessions=("chr1",) + tuple(f"synthetic{i}" for i in range(2, 23)),
        rules=tuple(
            ReferenceRuleResult(
                rule_id,
                "PASS",
                "adapter_test_only_not_scientific_reference_verification",
            )
            for rule_id in (
                REF_RULE_PROFILE,
                REF_RULE_ASSEMBLY,
                REF_RULE_FASTA,
                REF_RULE_REPORT,
                REF_RULE_BUNDLE,
                REF_RULE_SOURCE,
                REF_RULE_RIGHTS,
                REF_RULE_CONTIGS,
            )
        ),
    )


class VariantNormalizationCapabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = INPUT.read_bytes()
        self.identity = synthetic_reference_identity()
        self.bcftools = os.environ.get("OMNIGENIS_BCFTOOLS")
        self.bcftools_sha256 = os.environ.get("OMNIGENIS_BCFTOOLS_SHA256")
        self.synthetic_reference_sha256 = sha256_file(REFERENCE)
        self.synthetic_reference_size = REFERENCE.stat().st_size
        sha_patch = patch("omnigenis.capabilities.variant_normalization.REFERENCE_FASTA_CONTENT_SHA256", self.synthetic_reference_sha256)
        size_patch = patch("omnigenis.capabilities.variant_normalization.REFERENCE_FASTA_CONTENT_SIZE_BYTES", self.synthetic_reference_size)
        sha_patch.start()
        size_patch.start()
        self.addCleanup(size_patch.stop)
        self.addCleanup(sha_patch.stop)

    def require_bcftools(self) -> tuple[str, str]:
        if not self.bcftools or not self.bcftools_sha256:
            self.skipTest("pinned BCFtools integration environment is not configured")
        return self.bcftools, self.bcftools_sha256

    def run_actual(
        self,
        data: bytes | None = None,
        *,
        reference: Path = REFERENCE,
        identity: ReferenceIdentityResult | None = None,
    ) -> VariantNormalizationResult:
        executable, digest = self.require_bcftools()
        return normalize_small_variants(
            self.data if data is None else data,
            reference_fasta=reference,
            reference_identity=self.identity if identity is None else identity,
            bcftools_executable=executable,
            expected_executor_sha256=digest,
            timeout_seconds=30,
        )

    def test_actual_bcftools_normalization_matches_pinned_fixture(self) -> None:
        result = self.run_actual()
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(result.normalized_vcf, EXPECTED.read_bytes())
        self.assertEqual(result.input_record_count, 3)
        self.assertEqual(result.output_record_count, 4)
        self.assertEqual(
            result.to_dict()["canonical_status"],
            "PASS_WITH_EXPLICIT_INVALIDATION",
        )
        rule_states = {rule.rule_id: rule.status for rule in result.rules}
        self.assertEqual(rule_states[RULE_PHASE], "EXPLICITLY_INVALIDATED")
        for rule_id in (
            RULE_CARDINALITY,
            RULE_INDEXABILITY,
            RULE_REF_CONCORDANCE,
            RULE_RETENTION,
            RULE_STRICT_REPARSE,
        ):
            self.assertEqual(rule_states[rule_id], "PASS")
        self.assertEqual(
            [entry.transformation for entry in result.transformation_ledger],
            ["REALIGNED", "SPLIT", "UNCHANGED"],
        )
        split = result.transformation_ledger[1]
        self.assertEqual(split.genotype, "1|2")
        self.assertEqual(
            [record.genotype for record in split.output_records],
            ["1|.", ".|1"],
        )
        self.assertEqual(
            [record.used_alt_index for record in split.output_records],
            [1, 2],
        )
        self.assertNotIn(str(REFERENCE.resolve()).encode("utf-8"), result.normalized_vcf)
        self.assertNotIn(b"##bcftools_", result.normalized_vcf)

    def test_synthetic_identity_cannot_satisfy_production_reference_binding(self) -> None:
        executable, digest = self.require_bcftools()
        with (
            patch(
                "omnigenis.capabilities.variant_normalization.REFERENCE_FASTA_CONTENT_SHA256",
                PRODUCTION_REFERENCE_FASTA_CONTENT_SHA256,
            ),
            patch(
                "omnigenis.capabilities.variant_normalization.REFERENCE_FASTA_CONTENT_SIZE_BYTES",
                PRODUCTION_REFERENCE_FASTA_CONTENT_SIZE_BYTES,
            ),
        ):
            result = normalize_small_variants(
                self.data,
                reference_fasta=REFERENCE,
                reference_identity=self.identity,
                bcftools_executable=executable,
                expected_executor_sha256=digest,
                timeout_seconds=30,
            )
        self.assertFalse(result.passed)
        states = {rule.rule_id: rule.status for rule in result.rules}
        self.assertEqual(states[RULE_REFERENCE], "FAIL")
        self.assertIn("reference_identity_not_verified", result.errors)

    def test_reference_digest_mismatch_fails_before_normalization(self) -> None:
        self.require_bcftools()
        with tempfile.TemporaryDirectory() as temp_name:
            changed = Path(temp_name) / "reference.fa"
            payload = bytearray(REFERENCE.read_bytes())
            payload[-2] = ord("A") if payload[-2] != ord("A") else ord("C")
            changed.write_bytes(payload)
            result = self.run_actual(reference=changed)
        self.assertFalse(result.passed)
        states = {rule.rule_id: rule.status for rule in result.rules}
        self.assertEqual(states[RULE_REFERENCE], "FAIL")
        self.assertIn("reference_content_digest_mismatch", result.errors)

    def test_ref_mismatch_fails_closed(self) -> None:
        bad = self.data.replace(
            b"chr1\t25\tsnv\tC\tT",
            b"chr1\t25\tsnv\tA\tT",
        )
        result = self.run_actual(bad)
        self.assertFalse(result.passed)
        states = {rule.rule_id: rule.status for rule in result.rules}
        self.assertEqual(states[RULE_REF_CONCORDANCE], "FAIL")
        self.assertTrue(any(error.startswith("executor_norm_exit_") for error in result.errors))

    def test_duplicate_provenance_key_is_rejected_before_executor(self) -> None:
        text = self.data.decode("utf-8")
        first_record = next(line for line in text.splitlines() if line.startswith("chr1\t8\t"))
        duplicate = text.replace(
            first_record + "\n",
            first_record + "\n" + first_record + "\n",
            1,
        ).encode("utf-8")
        result = normalize_small_variants(
            duplicate,
            reference_fasta=REFERENCE,
            reference_identity=self.identity,
            bcftools_executable="/does/not/matter",
            expected_executor_sha256="0" * 64,
        )
        self.assertFalse(result.passed)
        self.assertTrue(any(error.startswith("duplicate_provenance_key") for error in result.errors))

    def test_mnv_is_out_of_e1a_normalization_scope(self) -> None:
        mnv = self.data.replace(
            b"chr1\t25\tsnv\tC\tT",
            b"chr1\t25\tsnv\tCC\tTT",
        )
        result = normalize_small_variants(
            mnv,
            reference_fasta=REFERENCE,
            reference_identity=self.identity,
            bcftools_executable="/does/not/matter",
            expected_executor_sha256="0" * 64,
        )
        self.assertFalse(result.passed)
        self.assertIn("mnv_out_of_scope_record_3", result.errors)

    def test_non_autosomal_contig_is_out_of_scope(self) -> None:
        outside = self.data.replace(b"chr1", b"chrX")
        result = normalize_small_variants(
            outside,
            reference_fasta=REFERENCE,
            reference_identity=self.identity,
            bcftools_executable="/does/not/matter",
            expected_executor_sha256="0" * 64,
        )
        self.assertFalse(result.passed)
        self.assertIn("unsupported_contig_record_1", result.errors)

    def test_symbolic_alt_is_out_of_scope(self) -> None:
        symbolic = self.data.replace(
            b"chr1\t25\tsnv\tC\tT",
            b"chr1\t25\tsnv\tC\t<DEL>",
        )
        result = normalize_small_variants(
            symbolic,
            reference_fasta=REFERENCE,
            reference_identity=self.identity,
            bcftools_executable="/does/not/matter",
            expected_executor_sha256="0" * 64,
        )
        self.assertFalse(result.passed)
        self.assertIn("unsupported_alt_record_3", result.errors)

    def test_reserved_provenance_tag_collision_is_rejected(self) -> None:
        collision = self.data.replace(
            b"##FORMAT=<ID=GT",
            b"##INFO=<ID=OMNIGENIS_ORIGINAL,Number=1,Type=String,Description=\"collision\">\n##FORMAT=<ID=GT",
        )
        result = normalize_small_variants(
            collision,
            reference_fasta=REFERENCE,
            reference_identity=self.identity,
            bcftools_executable="/does/not/matter",
            expected_executor_sha256="0" * 64,
        )
        self.assertFalse(result.passed)
        self.assertIn("reserved_original_record_tag_declared", result.errors)

    def test_incomplete_reference_rule_set_is_rejected(self) -> None:
        incomplete = ReferenceIdentityResult(
            profile_id=REFERENCE_PROFILE_ID,
            assembly_accession=REFERENCE_ASSEMBLY,
            bundle_sha256=REFERENCE_BUNDLE_SHA256,
            fasta_content_sha256=sha256_file(REFERENCE),
            fasta_content_size_bytes=REFERENCE.stat().st_size,
            autosomal_refseq_accessions=("chr1",) + tuple(f"synthetic{i}" for i in range(2, 23)),
            rules=(),
        )
        result = self.run_actual(identity=incomplete)
        self.assertFalse(result.passed)
        states = {rule.rule_id: rule.status for rule in result.rules}
        self.assertEqual(states[RULE_REFERENCE], "FAIL")
        self.assertIn("reference_identity_not_verified", result.errors)

    def test_missing_reference_content_size_fails_closed(self) -> None:
        incomplete = ReferenceIdentityResult(
            profile_id=REFERENCE_PROFILE_ID,
            assembly_accession=REFERENCE_ASSEMBLY,
            bundle_sha256=REFERENCE_BUNDLE_SHA256,
            fasta_content_sha256=self.synthetic_reference_sha256,
            fasta_content_size_bytes=None,
            autosomal_refseq_accessions=("chr1",) + tuple(
                f"synthetic{i}" for i in range(2, 23)
            ),
            rules=self.identity.rules,
        )
        executable, digest = self.require_bcftools()
        result = normalize_small_variants(
            self.data,
            reference_fasta=REFERENCE,
            reference_identity=incomplete,
            bcftools_executable=executable,
            expected_executor_sha256=digest,
            timeout_seconds=30,
        )
        self.assertFalse(result.passed)
        self.assertIn("reference_identity_not_verified", result.errors)

    def test_executor_digest_mismatch_fails_closed(self) -> None:
        result = normalize_small_variants(
            self.data,
            reference_fasta=REFERENCE,
            reference_identity=self.identity,
            bcftools_executable=Path(os.sys.executable),
            expected_executor_sha256="0" * 64,
        )
        self.assertFalse(result.passed)
        states = {rule.rule_id: rule.status for rule in result.rules}
        self.assertEqual(states[RULE_EXECUTOR], "FAIL")
        self.assertIn("executor_digest_mismatch", result.errors)

    def test_executor_timeout_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            fake = Path(temp_name) / "bcftools"
            fake.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = \"--version\" ]; then\n"
                "  printf 'bcftools 1.24\\nUsing htslib 1.24\\n'\n"
                "  exit 0\n"
                "fi\n"
                "sleep 2\n",
                encoding="utf-8",
            )
            fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
            digest = sha256_file(fake)
            result = normalize_small_variants(
                self.data,
                reference_fasta=REFERENCE,
                reference_identity=self.identity,
                bcftools_executable=fake,
                expected_executor_sha256=digest,
                timeout_seconds=1,
            )
        self.assertFalse(result.passed)
        self.assertIn("executor_norm_timeout", result.errors)

    def test_executor_nonzero_exit_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            fake = Path(temp_name) / "bcftools"
            fake.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = \"--version\" ]; then\n"
                "  printf 'bcftools 1.24\\nUsing htslib 1.24\\n'\n"
                "  exit 0\n"
                "fi\n"
                "exit 7\n",
                encoding="utf-8",
            )
            fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
            digest = sha256_file(fake)
            result = normalize_small_variants(
                self.data,
                reference_fasta=REFERENCE,
                reference_identity=self.identity,
                bcftools_executable=fake,
                expected_executor_sha256=digest,
                timeout_seconds=2,
            )
        self.assertFalse(result.passed)
        self.assertIn("executor_norm_exit_7", result.errors)

    def test_ambiguous_sequence_allele_is_out_of_scope(self) -> None:
        ambiguous = self.data.replace(
            b"chr1\t25\tsnv\tC\tT",
            b"chr1\t25\tsnv\tC\tN",
        )
        result = normalize_small_variants(
            ambiguous,
            reference_fasta=REFERENCE,
            reference_identity=self.identity,
            bcftools_executable="/does/not/matter",
            expected_executor_sha256="0" * 64,
        )
        self.assertFalse(result.passed)
        self.assertIn("unsupported_alt_record_3", result.errors)

    def test_nonvariant_ref_alt_is_rejected(self) -> None:
        nonvariant = self.data.replace(
            b"chr1\t25\tsnv\tC\tT",
            b"chr1\t25\tsnv\tC\tC",
        )
        result = normalize_small_variants(
            nonvariant,
            reference_fasta=REFERENCE,
            reference_identity=self.identity,
            bcftools_executable="/does/not/matter",
            expected_executor_sha256="0" * 64,
        )
        self.assertFalse(result.passed)
        self.assertIn("nonvariant_allele_record_3", result.errors)

    def test_invalid_timeout_fails_closed(self) -> None:
        result = normalize_small_variants(
            self.data,
            reference_fasta=REFERENCE,
            reference_identity=self.identity,
            bcftools_executable="/does/not/matter",
            expected_executor_sha256="0" * 64,
            timeout_seconds=0,
        )
        self.assertFalse(result.passed)
        self.assertIn("invalid_timeout", result.errors)

    def test_executor_os_error_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            fake = Path(temp_name) / "bcftools"
            fake.write_text("#!/missing/interpreter\n", encoding="utf-8")
            fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
            result = normalize_small_variants(
                self.data,
                reference_fasta=REFERENCE,
                reference_identity=self.identity,
                bcftools_executable=fake,
                expected_executor_sha256=sha256_file(fake),
                timeout_seconds=2,
            )
        self.assertFalse(result.passed)
        self.assertIn("version:os_error", result.errors)

    def test_success_without_output_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            fake = Path(temp_name) / "bcftools"
            fake.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = \"--version\" ]; then\n"
                "  printf 'bcftools 1.24\\nUsing htslib 1.24\\n'\n"
                "fi\n"
                "exit 0\n",
                encoding="utf-8",
            )
            fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
            result = normalize_small_variants(
                self.data,
                reference_fasta=REFERENCE,
                reference_identity=self.identity,
                bcftools_executable=fake,
                expected_executor_sha256=sha256_file(fake),
                timeout_seconds=2,
            )
        self.assertFalse(result.passed)
        self.assertIn("executor_sort_output_missing", result.errors)

    def test_capability_manifest_and_executor_profile_are_closed(self) -> None:
        schema = json.loads(CAPABILITY_SCHEMA.read_text(encoding="utf-8"))
        manifest = json.loads(CAPABILITY_MANIFEST.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(manifest)
        self.assertEqual(
            manifest["capability_id"],
            "reference-bound-small-variant-normalization",
        )
        profile = json.loads(EXECUTOR_PROFILE.read_text(encoding="utf-8"))
        self.assertEqual(profile["executor_version"], "1.24")
        self.assertEqual(profile["bundled_htslib_version"], "1.24")
        self.assertEqual(
            profile["release"]["asset_sha256"],
            "8caddc22610ee2851666047c859bb91da0c1e32d0c2ec553db6f153ad130e46f",
        )
        self.assertEqual(profile["license_profile"]["gsl"], "DISABLED")
        self.assertEqual(profile["license_profile"]["perl_filters"], "DISABLED")
        self.assertEqual(
            profile["reference_binding"]["profile_id"],
            "grch38-p14-ncbi-refseq-autosomal-v1",
        )
        self.assertEqual(
            profile["reference_binding"]["bundle_sha256"],
            "1c34b839e1ae36102d003a217f76f1dd57cd1d10b0310cbd9e1d8078c8e88672",
        )
        self.assertEqual(
            profile["reference_binding"]["fasta_content_sha256"],
            PRODUCTION_REFERENCE_FASTA_CONTENT_SHA256,
        )
        self.assertEqual(
            profile["reference_binding"]["fasta_content_size_bytes"],
            PRODUCTION_REFERENCE_FASTA_CONTENT_SIZE_BYTES,
        )


if __name__ == "__main__":
    unittest.main()
