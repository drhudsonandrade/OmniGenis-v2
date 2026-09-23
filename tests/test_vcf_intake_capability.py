from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest

from omnigenis.capabilities.vcf_intake import (
    CAPABILITY_ID,
    CAPABILITY_VERSION,
    VCF_STANDARD,
    validate_vcf_bytes,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "vcf_intake"
MANIFEST = ROOT / "capabilities" / "vcf-intake-envelope.manifest.json"


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


class VcfIntakeCapabilityTests(unittest.TestCase):
    def test_valid_single_sample_vcf45(self) -> None:
        data = fixture("valid-single-sample.vcf")
        result = validate_vcf_bytes(data)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.sample_id, "SYNTHETIC")
        self.assertEqual(result.record_count, 2)
        self.assertEqual(result.size_bytes, len(data))
        self.assertEqual(result.content_sha256, hashlib.sha256(data).hexdigest())
        payload = result.to_dict()
        self.assertEqual(payload["capability_id"], CAPABILITY_ID)
        self.assertEqual(payload["capability_version"], CAPABILITY_VERSION)
        self.assertEqual(payload["canonical_status"], "VALID")
        self.assertEqual(payload["canonical_payload"]["vcf_standard"], VCF_STANDARD)
        required_result_fields = {
            "capability_id", "capability_version", "canonical_status",
            "canonical_payload", "availability", "limitations", "executor_id",
            "executor_version", "adapter_version", "model_id", "resource_release",
            "reference_bundle", "execution_profile", "raw_artifact_refs",
            "provenance_refs",
        }
        self.assertEqual(set(payload), required_result_fields)

    def test_header_only_single_sample_vcf_is_structurally_valid(self) -> None:
        data = (
            b"##fileformat=VCFv4.5\n"
            b"#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tSYNTHETIC\n"
        )
        result = validate_vcf_bytes(data)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.record_count, 0)

    def test_crlf_line_endings_are_supported(self) -> None:
        data = fixture("valid-single-sample.vcf").replace(b"\n", b"\r\n")
        self.assertTrue(validate_vcf_bytes(data).is_valid)

    def test_older_vcf_version_is_outside_supported_profile(self) -> None:
        result = validate_vcf_bytes(fixture("wrong-version.vcf"))
        self.assertFalse(result.is_valid)
        self.assertIn("unsupported_or_missing_fileformat", result.errors)

    def test_multiple_samples_are_rejected(self) -> None:
        result = validate_vcf_bytes(fixture("multiple-samples.vcf"))
        self.assertFalse(result.is_valid)
        self.assertIn("exactly_one_sample_required", result.errors)

    def test_invalid_position_is_rejected(self) -> None:
        result = validate_vcf_bytes(fixture("invalid-position.vcf"))
        self.assertFalse(result.is_valid)
        self.assertTrue(any(error.endswith(":invalid_pos") for error in result.errors))

    def test_zero_length_fields_are_rejected(self) -> None:
        data = (
            b"##fileformat=VCFv4.5\n"
            b"#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tSYNTHETIC\n"
            b"1\t100\t.\tA\t\t.\tPASS\t.\tGT\t0/1\n"
        )
        result = validate_vcf_bytes(data)
        self.assertFalse(result.is_valid)
        self.assertTrue(any(error.endswith(":zero_length_field") for error in result.errors))

    def test_bom_invalid_utf8_and_controls_fail_closed(self) -> None:
        good = fixture("valid-single-sample.vcf")
        with self.subTest(case="bom"):
            self.assertIn("utf8_bom_not_allowed", validate_vcf_bytes(b"\xef\xbb\xbf" + good).errors)
        with self.subTest(case="invalid_utf8"):
            self.assertIn("invalid_utf8", validate_vcf_bytes(good + b"\xff").errors)
        with self.subTest(case="control"):
            result = validate_vcf_bytes(good.replace(b"PASS", b"PA\x01SS", 1))
            self.assertIn("disallowed_control_character", result.errors)

    def test_lone_carriage_return_is_rejected(self) -> None:
        data = fixture("valid-single-sample.vcf").replace(b"\n", b"\r")
        result = validate_vcf_bytes(data)
        self.assertFalse(result.is_valid)
        self.assertIn("invalid_line_separator", result.errors)

    def test_unicode_line_separators_are_rejected(self) -> None:
        good = fixture("valid-single-sample.vcf").decode("utf-8")
        for separator in ("\u0085", "\u2028", "\u2029"):
            with self.subTest(separator=hex(ord(separator))):
                data = good.replace("\n", separator, 1).encode("utf-8")
                result = validate_vcf_bytes(data)
                self.assertFalse(result.is_valid)
                self.assertIn("invalid_line_separator", result.errors)

    def test_final_data_record_requires_line_separator(self) -> None:
        data = fixture("valid-single-sample.vcf").rstrip(b"\n")
        result = validate_vcf_bytes(data)
        self.assertFalse(result.is_valid)
        self.assertIn("unterminated_final_data_line", result.errors)

    def test_positions_are_nondecreasing_within_chrom(self) -> None:
        data = (
            b"##fileformat=VCFv4.5\n"
            b"#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tSYNTHETIC\n"
            b"1\t200\t.\tA\tC\t.\tPASS\t.\tGT\t0/1\n"
            b"1\t100\t.\tA\tG\t.\tPASS\t.\tGT\t0/1\n"
        )
        result = validate_vcf_bytes(data)
        self.assertFalse(result.is_valid)
        self.assertTrue(any(error.endswith(":decreasing_pos") for error in result.errors))

    def test_chrom_blocks_must_be_contiguous(self) -> None:
        data = (
            b"##fileformat=VCFv4.5\n"
            b"#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tSYNTHETIC\n"
            b"1\t100\t.\tA\tC\t.\tPASS\t.\tGT\t0/1\n"
            b"2\t100\t.\tA\tC\t.\tPASS\t.\tGT\t0/1\n"
            b"1\t200\t.\tA\tG\t.\tPASS\t.\tGT\t0/1\n"
        )
        result = validate_vcf_bytes(data)
        self.assertFalse(result.is_valid)
        self.assertTrue(any(error.endswith(":non_contiguous_chrom") for error in result.errors))

    def test_telomere_zero_position_is_structurally_allowed(self) -> None:
        data = (
            b"##fileformat=VCFv4.5\n"
            b"#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tSYNTHETIC\n"
            b"1\t0\t.\tA\tC\t.\tPASS\t.\tGT\t0/1\n"
        )
        self.assertTrue(validate_vcf_bytes(data).is_valid)

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
        self.assertEqual(manifest["capability_version"], CAPABILITY_VERSION)
        self.assertIn("Not wired", manifest["disable_path"])

    def test_input_is_pure_bytes_and_does_not_require_external_services(self) -> None:
        result = validate_vcf_bytes(fixture("valid-single-sample.vcf"))
        self.assertTrue(result.is_valid)
        payload = result.to_dict()
        self.assertEqual(payload["availability"], "AVAILABLE")
        self.assertEqual(payload["raw_artifact_refs"], [])
        self.assertEqual(payload["canonical_payload"]["errors"], [])


if __name__ == "__main__":
    unittest.main()
