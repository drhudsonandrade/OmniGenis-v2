from __future__ import annotations

import json
from pathlib import Path
import unittest

from omnigenis.capabilities.vcf_qc import (
    CALLABILITY_STATUS,
    CAPABILITY_ID,
    CAPABILITY_VERSION,
    observe_vcf_qc,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
MANIFEST = ROOT / "capabilities" / "vcf-qc-observations.manifest.json"


def fixture(group: str, name: str) -> bytes:
    return (FIXTURES / group / name).read_bytes()


class VcfQcCapabilityTests(unittest.TestCase):
    def test_qc_rich_vcf_reports_observations_without_thresholds(self) -> None:
        result = observe_vcf_qc(fixture("vcf_qc", "valid-qc-rich.vcf"))
        self.assertTrue(result.input_valid)
        self.assertEqual(result.errors, ())
        self.assertEqual(result.sample_id, "SYNTHETIC")
        self.assertEqual(result.record_count, 3)
        self.assertEqual(result.declared_references, ("urn:example:synthetic-reference",))
        self.assertEqual(result.filter_pass_records, 1)
        self.assertEqual(result.filter_filtered_records, 1)
        self.assertEqual(result.filter_not_applied_records, 1)
        self.assertEqual(result.called_genotype_records, 2)
        self.assertEqual(result.missing_genotype_records, 1)
        self.assertEqual(result.genotype_not_present_records, 0)
        self.assertEqual(result.depth.to_dict(), {"observed_records": 2, "minimum": 20, "maximum": 30})
        self.assertEqual(
            result.genotype_quality.to_dict(),
            {"observed_records": 2, "minimum": 10, "maximum": 60},
        )
        self.assertEqual(result.allele_depth_observed_records, 2)
        self.assertEqual(result.allele_balance.observed_records, 2)
        self.assertAlmostEqual(result.allele_balance.minimum, 0.1)
        self.assertAlmostEqual(result.allele_balance.maximum, 0.5)
        payload = result.to_dict()
        self.assertEqual(payload["canonical_status"], "OBSERVED")
        self.assertEqual(payload["canonical_payload"]["callability_status"], CALLABILITY_STATUS)
        self.assertNotIn("quality_pass", payload["canonical_payload"])
        self.assertNotIn("quality_fail", payload["canonical_payload"])

    def test_missing_qc_fields_are_reported_as_absent_not_failed(self) -> None:
        result = observe_vcf_qc(fixture("vcf_intake", "valid-single-sample.vcf"))
        self.assertTrue(result.input_valid)
        self.assertEqual(result.errors, ())
        self.assertEqual(result.depth.observed_records, 0)
        self.assertEqual(result.genotype_quality.observed_records, 0)
        self.assertEqual(result.allele_depth_observed_records, 0)
        self.assertEqual(result.allele_balance.observed_records, 0)
        self.assertIn("reference_not_declared", result.warnings)
        self.assertEqual(result.to_dict()["canonical_status"], "OBSERVED")

    def test_multiple_reference_declarations_are_not_silently_collapsed(self) -> None:
        data = (
            b"##fileformat=VCFv4.5\n"
            b"##reference=urn:example:reference-a\n"
            b"##reference=urn:example:reference-b\n"
            b"#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tSYNTHETIC\n"
            b"1\t100\t.\tA\tC\t.\tPASS\t.\tGT\t0/1\n"
        )
        result = observe_vcf_qc(data)
        self.assertEqual(
            result.declared_references,
            ("urn:example:reference-a", "urn:example:reference-b"),
        )
        self.assertIn("multiple_reference_declarations", result.warnings)

    def test_absent_gt_is_distinct_from_missing_gt(self) -> None:
        data = (
            b"##fileformat=VCFv4.5\n"
            b"##FORMAT=<ID=DP,Number=1,Type=Integer,Description=\"Read Depth\">\n"
            b"#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tSYNTHETIC\n"
            b"1\t100\t.\tA\tC\t.\tPASS\t.\tDP\t10\n"
        )
        result = observe_vcf_qc(data)
        self.assertEqual(result.called_genotype_records, 0)
        self.assertEqual(result.missing_genotype_records, 0)
        self.assertEqual(result.genotype_not_present_records, 1)
        self.assertEqual(
            result.to_dict()["canonical_payload"]["genotype_counts"],
            {"called": 0, "missing": 0, "not_present": 1},
        )

    def test_invalid_intake_is_propagated_fail_closed(self) -> None:
        result = observe_vcf_qc(fixture("vcf_intake", "multiple-samples.vcf"))
        self.assertFalse(result.input_valid)
        self.assertEqual(result.to_dict()["canonical_status"], "INVALID_INPUT")
        self.assertTrue(any(error.startswith("input:") for error in result.errors))
    def test_invalid_reserved_numeric_fields_are_reported_independently(self) -> None:
        cases = (
            ("invalid-dp.vcf", ":dp_not_integer"),
            ("invalid-gq.vcf", ":gq_negative"),
            ("invalid-ad.vcf", ":ad_not_integer"),
        )
        for name, suffix in cases:
            with self.subTest(name=name):
                result = observe_vcf_qc(fixture("vcf_qc", name))
                self.assertTrue(result.input_valid)
                self.assertEqual(result.to_dict()["canonical_status"], "INVALID_QC_FIELDS")
                self.assertTrue(any(error.endswith(suffix) for error in result.errors))

    def test_reserved_integer_lexical_form_and_range_are_enforced(self) -> None:
        cases = (
            ("١٢", ":dp_not_integer"),
            (" 12 ", ":dp_not_integer"),
            ("2147483648", ":dp_out_of_range"),
        )
        for value, suffix in cases:
            with self.subTest(value=value):
                data = (
                    b"##fileformat=VCFv4.5\n"
                    b"#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tSYNTHETIC\n"
                    + f"1\t100\t.\tA\tC\t.\tPASS\t.\tGT:DP\t0/1:{value}\n".encode("utf-8")
                )
                result = observe_vcf_qc(data)
                self.assertTrue(any(error.endswith(suffix) for error in result.errors))

        maximum = (
            b"##fileformat=VCFv4.5\n"
            b"#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tSYNTHETIC\n"
            b"1\t100\t.\tA\tC\t.\tPASS\t.\tGT:DP\t0/1:2147483647\n"
        )
        result = observe_vcf_qc(maximum)
        self.assertEqual(result.errors, ())
        self.assertEqual(result.depth.maximum, 2147483647)

    def test_oversized_reserved_integers_fail_closed_before_conversion(self) -> None:
        huge = "9" * 5000
        cases = (
            ("GT:DP", f"0/1:{huge}", ":dp_out_of_range"),
            ("GT:GQ", f"0/1:{huge}", ":gq_out_of_range"),
            ("GT:AD", f"0/1:{huge},0", ":ad_out_of_range"),
        )
        for format_value, sample_value, suffix in cases:
            with self.subTest(format_value=format_value):
                data = (
                    b"##fileformat=VCFv4.5\n"
                    b"#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tSYNTHETIC\n"
                    + (
                        f"1\t100\t.\tA\tC\t.\tPASS\t.\t{format_value}\t{sample_value}\n"
                    ).encode("ascii")
                )
                result = observe_vcf_qc(data)
                self.assertTrue(any(error.endswith(suffix) for error in result.errors))
                self.assertEqual(result.to_dict()["canonical_status"], "INVALID_QC_FIELDS")

    def test_zero_values_do_not_create_an_invented_quality_failure(self) -> None:
        data = (
            b"##fileformat=VCFv4.5\n"
            b"##FORMAT=<ID=GT,Number=1,Type=String,Description=\"Genotype\">\n"
            b"##FORMAT=<ID=DP,Number=1,Type=Integer,Description=\"Read Depth\">\n"
            b"##FORMAT=<ID=GQ,Number=1,Type=Integer,Description=\"Genotype Quality\">\n"
            b"##FORMAT=<ID=AD,Number=R,Type=Integer,Description=\"Read depth for each allele\">\n"
            b"#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tSYNTHETIC\n"
            b"1\t100\t.\tA\tC\t.\tPASS\t.\tGT:DP:GQ:AD\t0/1:0:0:0,0\n"
        )
        result = observe_vcf_qc(data)
        self.assertEqual(result.errors, ())
        self.assertEqual(result.depth.minimum, 0)
        self.assertEqual(result.genotype_quality.minimum, 0)
        self.assertEqual(result.allele_balance.observed_records, 0)
        self.assertEqual(result.to_dict()["canonical_status"], "OBSERVED")
    def test_format_shape_checks_are_structural_only(self) -> None:
        duplicate = (
            b"##fileformat=VCFv4.5\n"
            b"#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tSYNTHETIC\n"
            b"1\t100\t.\tA\tC\t.\tPASS\t.\tGT:DP:DP\t0/1:10:11\n"
        )
        result = observe_vcf_qc(duplicate)
        self.assertTrue(any(error.endswith(":duplicate_format_key") for error in result.errors))

        gt_not_first = (
            b"##fileformat=VCFv4.5\n"
            b"#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tSYNTHETIC\n"
            b"1\t100\t.\tA\tC\t.\tPASS\t.\tDP:GT\t10:0/1\n"
        )
        result = observe_vcf_qc(gt_not_first)
        self.assertTrue(any(error.endswith(":gt_not_first") for error in result.errors))

        extra_value = (
            b"##fileformat=VCFv4.5\n"
            b"#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tSYNTHETIC\n"
            b"1\t100\t.\tA\tC\t.\tPASS\t.\tGT\t0/1:extra\n"
        )
        result = observe_vcf_qc(extra_value)
        self.assertTrue(
            any(error.endswith(":sample_value_count_exceeds_format") for error in result.errors)
        )

    def test_invalid_genotypes_are_not_counted_as_called(self) -> None:
        cases = ("0//1", "0/2", "A/1", "0/1|1", "./x")
        for gt in cases:
            with self.subTest(gt=gt):
                data = (
                    b"##fileformat=VCFv4.5\n"
                    b"#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tSYNTHETIC\n"
                    + f"1\t100\t.\tA\tC\t.\tPASS\t.\tGT\t{gt}\n".encode("utf-8")
                )
                result = observe_vcf_qc(data)
                self.assertTrue(any(error.endswith(":invalid_gt") for error in result.errors))
                self.assertEqual(result.called_genotype_records, 0)

    def test_ad_cardinality_matches_ref_plus_alt(self) -> None:
        invalid = (
            b"##fileformat=VCFv4.5\n"
            b"#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tSYNTHETIC\n"
            b"1\t100\t.\tA\tC,G\t.\tPASS\t.\tGT:AD\t1/2:10,5\n"
        )
        result = observe_vcf_qc(invalid)
        self.assertTrue(any(error.endswith(":ad_cardinality") for error in result.errors))
        self.assertEqual(result.allele_depth_observed_records, 0)

        valid = (
            b"##fileformat=VCFv4.5\n"
            b"#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tSYNTHETIC\n"
            b"1\t100\t.\tA\tC,G\t.\tPASS\t.\tGT:AD\t1/2:10,5,3\n"
        )
        result = observe_vcf_qc(valid)
        self.assertEqual(result.errors, ())
        self.assertEqual(result.allele_depth_observed_records, 1)
        self.assertEqual(result.allele_balance.observed_records, 0)

    def test_explicit_empty_format_values_are_rejected(self) -> None:
        cases = (
            ("GT:DP", "0/1:", ":dp_empty"),
            ("GT:GQ", "0/1:", ":gq_empty"),
            ("GT:AD", "0/1:", ":ad_empty"),
            ("GT:AD", "0/1:10,", ":ad_empty"),
            ("GT:DP", ":10", ":gt_empty"),
        )
        for format_value, sample_value, suffix in cases:
            with self.subTest(format_value=format_value, sample_value=sample_value):
                data = (
                    b"##fileformat=VCFv4.5\n"
                    b"#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tSYNTHETIC\n"
                    + (
                        f"1\t100\t.\tA\tC\t.\tPASS\t.\t{format_value}\t{sample_value}\n"
                    ).encode("utf-8")
                )
                result = observe_vcf_qc(data)
                self.assertTrue(any(error.endswith(suffix) for error in result.errors))

    def test_tool_neutral_result_contract_is_complete(self) -> None:
        payload = observe_vcf_qc(fixture("vcf_qc", "valid-qc-rich.vcf")).to_dict()
        expected = {
            "capability_id", "capability_version", "canonical_status",
            "canonical_payload", "availability", "limitations", "executor_id",
            "executor_version", "adapter_version", "model_id", "resource_release",
            "reference_bundle", "execution_profile", "raw_artifact_refs",
            "provenance_refs",
        }
        self.assertEqual(set(payload), expected)
        self.assertEqual(payload["capability_id"], CAPABILITY_ID)
        self.assertEqual(payload["capability_version"], CAPABILITY_VERSION)
    def test_capability_manifest_is_complete_and_disabled_by_default(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        required = {
            "schema_version", "capability_id", "capability_version", "real_use_case",
            "owner_priority", "upstream_status", "license", "supported_profile",
            "resource_budget", "input_fixture", "output_contract", "known_issues",
            "security", "disable_path",
        }
        self.assertTrue(required.issubset(manifest))
        self.assertEqual(manifest["capability_id"], CAPABILITY_ID)
        self.assertIn("Not wired", manifest["disable_path"])
        self.assertIn("cannot establish", manifest["known_issues"])


if __name__ == "__main__":
    unittest.main()
