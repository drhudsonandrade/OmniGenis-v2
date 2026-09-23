"""Technical QC observations for validated single-sample VCF input."""

from __future__ import annotations

from dataclasses import dataclass

from .vcf_intake import validate_vcf_bytes

CAPABILITY_ID = "vcf-qc-observations"
CAPABILITY_VERSION = "1.0.0"
CALLABILITY_STATUS = "NOT_AVAILABLE_FROM_VARIANT_ONLY_VCF"
LIMITATIONS = (
    "Whole-genome or exome callability cannot be inferred from absent positions in a variant-only VCF.",
    "Coverage outside observed variant records is not inferred.",
    "No quality threshold classification is applied.",
    "No reference concordance, normalization, variant classification, or clinical interpretation is performed.",
)


@dataclass(frozen=True)
class NumericObservation:
    """Count and range for one optional integer QC field."""

    observed_records: int
    minimum: int | None
    maximum: int | None

    def to_dict(self) -> dict[str, int | None]:
        return {
            "observed_records": self.observed_records,
            "minimum": self.minimum,
            "maximum": self.maximum,
        }
@dataclass(frozen=True)
class FloatObservation:
    """Count and range for one derived floating-point observation."""

    observed_records: int
    minimum: float | None
    maximum: float | None

    def to_dict(self) -> dict[str, float | int | None]:
        return {
            "observed_records": self.observed_records,
            "minimum": self.minimum,
            "maximum": self.maximum,
        }


@dataclass(frozen=True)
class VcfQcObservationResult:
    """Deterministic output for the VCF QC observation capability."""

    input_valid: bool
    sample_id: str | None
    record_count: int
    declared_references: tuple[str, ...]
    filter_pass_records: int
    filter_filtered_records: int
    filter_not_applied_records: int
    called_genotype_records: int
    missing_genotype_records: int
    genotype_not_present_records: int
    depth: NumericObservation
    genotype_quality: NumericObservation
    allele_depth_observed_records: int
    allele_balance: FloatObservation
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    def to_dict(self) -> dict[str, object]:
        """Return the tool-neutral capability result contract."""
        if not self.input_valid:
            canonical_status = "INVALID_INPUT"
        elif self.errors:
            canonical_status = "INVALID_QC_FIELDS"
        else:
            canonical_status = "OBSERVED"
        return {
            "capability_id": CAPABILITY_ID,
            "capability_version": CAPABILITY_VERSION,
            "canonical_status": canonical_status,
            "canonical_payload": {
                "sample_id": self.sample_id,
                "record_count": self.record_count,
                "declared_references": list(self.declared_references),
                "filter_counts": {
                    "pass": self.filter_pass_records,
                    "filtered": self.filter_filtered_records,
                    "not_applied": self.filter_not_applied_records,
                },
                "genotype_counts": {
                    "called": self.called_genotype_records,
                    "missing": self.missing_genotype_records,
                    "not_present": self.genotype_not_present_records,
                },
                "depth": self.depth.to_dict(),
                "genotype_quality": self.genotype_quality.to_dict(),
                "allele_depth_observed_records": self.allele_depth_observed_records,
                "allele_balance": self.allele_balance.to_dict(),
                "callability_status": CALLABILITY_STATUS,
                "errors": list(self.errors),
                "warnings": list(self.warnings),
            },
            "availability": "AVAILABLE",
            "limitations": list(LIMITATIONS),
            "executor_id": "omnigenis.python-stdlib",
            "executor_version": CAPABILITY_VERSION,
            "adapter_version": None,
            "model_id": None,
            "resource_release": None,
            "reference_bundle": None,
            "execution_profile": "vcf-qc-observations-v1",
            "raw_artifact_refs": [],
            "provenance_refs": ["GA4GH-HTS-VCFv4.5"],
        }
def _numeric_summary(values: list[int]) -> NumericObservation:
    if not values:
        return NumericObservation(0, None, None)
    return NumericObservation(len(values), min(values), max(values))


def _float_summary(values: list[float]) -> FloatObservation:
    if not values:
        return FloatObservation(0, None, None)
    return FloatObservation(len(values), min(values), max(values))


def _parse_nonnegative_int(value: str, field: str, line_number: int, errors: list[str]) -> int | None:
    if value == ".":
        return None
    if value == "":
        errors.append(f"line_{line_number}:{field.lower()}_empty")
        return None
    try:
        parsed = int(value)
    except ValueError:
        errors.append(f"line_{line_number}:{field.lower()}_not_integer")
        return None
    if parsed < 0:
        errors.append(f"line_{line_number}:{field.lower()}_negative")
        return None
    return parsed


def _parse_ad(value: str, line_number: int, errors: list[str]) -> list[int] | None:
    if value in {"", "."}:
        return None
    parsed: list[int] = []
    for token in value.split(","):
        item = _parse_nonnegative_int(token, "AD", line_number, errors)
        if item is None:
            return None
        parsed.append(item)
    return parsed
def _is_missing_genotype(value: str | None) -> bool:
    if value is None or value in {"", "."}:
        return True
    alleles = value.replace("|", "/").split("/")
    return any(allele == "." for allele in alleles)


def _biallelic_heterozygous_balance(gt: str | None, alt: str, ad: list[int] | None) -> float | None:
    if gt is None or ad is None or "," in alt or len(ad) != 2:
        return None
    alleles = gt.replace("|", "/").split("/")
    if len(alleles) != 2 or set(alleles) != {"0", "1"}:
        return None
    total = ad[0] + ad[1]
    if total <= 0:
        return None
    return ad[1] / total


def observe_vcf_qc(data: bytes) -> VcfQcObservationResult:
    """Record technical observations from a validated VCF without quality thresholds."""
    intake = validate_vcf_bytes(data)
    base_warnings = ["callability_not_available_from_variant_only_vcf"]
    if not intake.is_valid:
        return VcfQcObservationResult(
            input_valid=False,
            sample_id=intake.sample_id,
            record_count=intake.record_count,
            declared_references=(),
            filter_pass_records=0,
            filter_filtered_records=0,
            filter_not_applied_records=0,
            called_genotype_records=0,
            missing_genotype_records=0,
            genotype_not_present_records=0,
            depth=_numeric_summary([]),
            genotype_quality=_numeric_summary([]),
            allele_depth_observed_records=0,
            allele_balance=_float_summary([]),
            errors=tuple(f"input:{error}" for error in intake.errors),
            warnings=tuple(base_warnings),
        )
    text = data.decode("utf-8").replace("\r\n", "\n")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()

    declared_references: list[str] = []
    header_index = -1
    for index, line in enumerate(lines):
        if line.startswith("##reference="):
            declared_references.append(line.removeprefix("##reference="))
        if line.startswith("#CHROM\t"):
            header_index = index
            break

    errors: list[str] = []
    warnings = list(base_warnings)
    unique_references = tuple(dict.fromkeys(declared_references))
    if not unique_references:
        warnings.append("reference_not_declared")
    elif len(unique_references) > 1:
        warnings.append("multiple_reference_declarations")

    pass_records = 0
    filtered_records = 0
    not_applied_records = 0
    called_genotypes = 0
    missing_genotypes = 0
    genotype_not_present = 0
    dp_values: list[int] = []
    gq_values: list[int] = []
    ad_observed = 0
    allele_balances: list[float] = []

    for line_number, line in enumerate(lines[header_index + 1 :], start=header_index + 2):
        fields = line.split("\t")
        filter_value = fields[6]
        if filter_value == "PASS":
            pass_records += 1
        elif filter_value == ".":
            not_applied_records += 1
        else:
            filtered_records += 1

        format_keys = fields[8].split(":")
        if len(format_keys) != len(set(format_keys)):
            errors.append(f"line_{line_number}:duplicate_format_key")
        if "GT" in format_keys and format_keys[0] != "GT":
            errors.append(f"line_{line_number}:gt_not_first")
        sample_values = fields[9].split(":")
        if len(sample_values) > len(format_keys):
            errors.append(f"line_{line_number}:sample_value_count_exceeds_format")
        format_values = dict(zip(format_keys, sample_values, strict=False))

        gt = format_values.get("GT")
        if "GT" not in format_keys:
            genotype_not_present += 1
        else:
            if gt == "":
                errors.append(f"line_{line_number}:gt_empty")
            if _is_missing_genotype(gt):
                missing_genotypes += 1
            else:
                called_genotypes += 1

        dp = _parse_nonnegative_int(format_values.get("DP", "."), "DP", line_number, errors)
        if dp is not None:
            dp_values.append(dp)
        gq = _parse_nonnegative_int(format_values.get("GQ", "."), "GQ", line_number, errors)
        if gq is not None:
            gq_values.append(gq)
        ad = _parse_ad(format_values.get("AD", "."), line_number, errors)
        if ad is not None:
            ad_observed += 1
        balance = _biallelic_heterozygous_balance(gt, fields[4], ad)
        if balance is not None:
            allele_balances.append(balance)
    return VcfQcObservationResult(
        input_valid=True,
        sample_id=intake.sample_id,
        record_count=intake.record_count,
        declared_references=unique_references,
        filter_pass_records=pass_records,
        filter_filtered_records=filtered_records,
        filter_not_applied_records=not_applied_records,
        called_genotype_records=called_genotypes,
        missing_genotype_records=missing_genotypes,
        genotype_not_present_records=genotype_not_present,
        depth=_numeric_summary(dp_values),
        genotype_quality=_numeric_summary(gq_values),
        allele_depth_observed_records=ad_observed,
        allele_balance=_float_summary(allele_balances),
        errors=tuple(errors),
        warnings=tuple(warnings),
    )
