"""Minimum canonical genomic model for the E1A small-variant path."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib

from .artifact_gate import ArtifactGateResult, verify_artifact_bytes
from .canonical_variant_identity import (
    CanonicalVariantIdentityResult,
    canonicalize_normalized_variants,
)
from .reference_identity import ReferenceIdentityResult, ReferenceRuleResult
from .variant_normalization import (
    RULE_PHASE,
    NormalizationRuleResult,
    VariantNormalizationResult,
    VariantTransformationLedgerEntry,
)
from .vcf_intake import validate_vcf_bytes
from .vcf_qc import VcfQcObservationResult, observe_vcf_qc

CAPABILITY_ID = "canonical-genomic-model"
CAPABILITY_VERSION = "1.0.0"
ARTIFACT_KIND = "CANONICAL_GENOMIC_MODEL"

RULE_SOURCE_ARTIFACT = "SOURCE_ARTIFACT_BINDING"
RULE_SOURCE_QC = "SOURCE_QC_BINDING"
RULE_REFERENCE = "REFERENCE_BINDING"
RULE_NORMALIZATION = "NORMALIZATION_BINDING"
RULE_CANONICAL_VARIANTS = "CANONICAL_VARIANT_BINDING"
RULE_SAMPLE = "SAMPLE_IDENTITY"
RULE_NORMALIZED_QC = "NORMALIZED_QC"
RULE_MODEL = "MODEL_ASSEMBLY"

_RULE_ORDER = (
    RULE_SOURCE_ARTIFACT,
    RULE_SOURCE_QC,
    RULE_REFERENCE,
    RULE_NORMALIZATION,
    RULE_CANONICAL_VARIANTS,
    RULE_SAMPLE,
    RULE_NORMALIZED_QC,
    RULE_MODEL,
)
_ALLOWED_TRANSFORMATIONS = frozenset(
    {"UNCHANGED", "REALIGNED", "SPLIT", "SPLIT_AND_REALIGNED"}
)
@dataclass(frozen=True)
class CanonicalGenomicModelRuleResult:
    """One independently traceable canonical-model rule result."""

    rule_id: str
    status: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "status": self.status,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class CanonicalGenomicVariant:
    """One canonical variant plus technical observations and lineage."""

    canonical_variant_id: str
    contig_accession: str
    position_1_based: int
    ref: str
    alt: str
    genotype: str | None
    zygosity: str | None
    phase_semantics: str
    depth: int | None
    genotype_quality: int | None
    allele_balance: float | None
    filter_status: str
    normalized_record_ordinal: int
    normalized_record_sha256: str
    source_record_sha256s: tuple[str, ...]
    normalization_transformation: str

    def to_dict(self) -> dict[str, object]:
        return {
            "canonical_variant_id": self.canonical_variant_id,
            "contig_accession": self.contig_accession,
            "position_1_based": self.position_1_based,
            "ref": self.ref,
            "alt": self.alt,
            "genotype": self.genotype,
            "zygosity": self.zygosity,
            "phase_semantics": self.phase_semantics,
            "depth": self.depth,
            "genotype_quality": self.genotype_quality,
            "allele_balance": self.allele_balance,
            "filter_status": self.filter_status,
            "normalized_record_ordinal": self.normalized_record_ordinal,
            "normalized_record_sha256": self.normalized_record_sha256,
            "source_record_sha256s": list(self.source_record_sha256s),
            "normalization_transformation": self.normalization_transformation,
        }
@dataclass(frozen=True)
class CanonicalGenomicModelResult:
    """Tool-neutral result for the minimum E1A canonical genomic model."""

    sample_id: str | None
    source_artifact_id: str | None
    source_vcf_sha256: str | None
    source_vcf_size_bytes: int | None
    reference_profile_id: str | None
    reference_assembly_accession: str | None
    reference_bundle_sha256: str | None
    normalization_output_sha256: str | None
    variants: tuple[CanonicalGenomicVariant, ...]
    rules: tuple[CanonicalGenomicModelRuleResult, ...]
    errors: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return (
            not self.errors
            and len(self.rules) == len(_RULE_ORDER)
            and all(rule.status == "PASS" for rule in self.rules)
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "capability_id": CAPABILITY_ID,
            "capability_version": CAPABILITY_VERSION,
            "canonical_status": "CANONICALIZED" if self.passed else "FAIL",
            "canonical_payload": {
                "artifact_kind": ARTIFACT_KIND,
                "sample_id": self.sample_id,
                "source_artifact_id": self.source_artifact_id,
                "source_vcf_sha256": self.source_vcf_sha256,
                "source_vcf_size_bytes": self.source_vcf_size_bytes,
                "reference_profile_id": self.reference_profile_id,
                "reference_assembly_accession": self.reference_assembly_accession,
                "reference_bundle_sha256": self.reference_bundle_sha256,
                "normalization_output_sha256": self.normalization_output_sha256,
                "variant_count": len(self.variants),
                "variants": [variant.to_dict() for variant in self.variants],
                "rules": [rule.to_dict() for rule in self.rules],
                "errors": list(self.errors),
            },
            "availability": "AVAILABLE" if self.passed else "BLOCKED",
            "limitations": [
                "Initial E1A profile only: one single-sample primary-autosome SNV/small-indel callset.",
                "Only technical observations available in the verified VCF are carried forward.",
                "Gene mapping, nomenclature projection, transcript consequence, external evidence, and downstream scientific classification are not performed.",
            ],
            "executor_id": "omnigenis.python-stdlib",
            "executor_version": CAPABILITY_VERSION,
            "adapter_version": None,
            "model_id": None,
            "resource_release": self.reference_assembly_accession,
            "reference_bundle": self.reference_bundle_sha256,
            "execution_profile": "canonical-genomic-model-e1a-v1",
            "raw_artifact_refs": [
                value
                for value in (
                    self.source_vcf_sha256,
                    self.normalization_output_sha256,
                )
                if value is not None
            ],
            "provenance_refs": [
                "artifact-integrity-gate",
                "vcf-qc-observations",
                "reference-identity",
                "reference-bound-small-variant-normalization",
                "canonical-small-variant-identity",
            ],
        }
@dataclass(frozen=True)
class _NormalizedRecord:
    ordinal: int
    chrom: str
    pos: int
    ref: str
    alt: str
    genotype: str | None
    depth: int | None
    genotype_quality: int | None
    allele_depths: tuple[int, ...] | None
    filter_status: str


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _rule(
    rule_id: str,
    passed: bool,
    detail: str,
) -> CanonicalGenomicModelRuleResult:
    return CanonicalGenomicModelRuleResult(
        rule_id=rule_id,
        status="PASS" if passed else "FAIL",
        detail=detail,
    )


def _rules(
    states: dict[str, tuple[bool, str]],
) -> tuple[CanonicalGenomicModelRuleResult, ...]:
    return tuple(
        _rule(
            rule_id,
            states.get(rule_id, (False, "not_run"))[0],
            states.get(rule_id, (False, "not_run"))[1],
        )
        for rule_id in _RULE_ORDER
    )


def _result(
    *,
    states: dict[str, tuple[bool, str]],
    errors: list[str],
    sample_id: str | None = None,
    source_artifact_id: str | None = None,
    source_vcf_sha256: str | None = None,
    source_vcf_size_bytes: int | None = None,
    reference_identity: ReferenceIdentityResult | None = None,
    normalization_output_sha256: str | None = None,
    variants: tuple[CanonicalGenomicVariant, ...] = (),
) -> CanonicalGenomicModelResult:
    return CanonicalGenomicModelResult(
        sample_id=sample_id,
        source_artifact_id=source_artifact_id,
        source_vcf_sha256=source_vcf_sha256,
        source_vcf_size_bytes=source_vcf_size_bytes,
        reference_profile_id=(
            reference_identity.profile_id
            if isinstance(reference_identity, ReferenceIdentityResult)
            else None
        ),
        reference_assembly_accession=(
            reference_identity.assembly_accession
            if isinstance(reference_identity, ReferenceIdentityResult)
            else None
        ),
        reference_bundle_sha256=(
            reference_identity.bundle_sha256
            if isinstance(reference_identity, ReferenceIdentityResult)
            else None
        ),
        normalization_output_sha256=normalization_output_sha256,
        variants=variants,
        rules=_rules(states),
        errors=tuple(errors),
    )
def _parse_optional_int(value: str | None) -> int | None:
    if value is None or value == ".":
        return None
    return int(value)


def _parse_allele_depths(value: str | None) -> tuple[int, ...] | None:
    if value is None or value == ".":
        return None
    return tuple(int(item) for item in value.split(","))


def _parse_normalized_records(data: bytes) -> tuple[_NormalizedRecord, ...]:
    text = data.decode("utf-8").replace("\r\n", "\n")
    records: list[_NormalizedRecord] = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        format_keys = fields[8].split(":")
        sample_values = fields[9].split(":")
        values = dict(zip(format_keys, sample_values, strict=False))
        records.append(
            _NormalizedRecord(
                ordinal=len(records) + 1,
                chrom=fields[0],
                pos=int(fields[1]),
                ref=fields[3],
                alt=fields[4],
                genotype=values.get("GT"),
                depth=_parse_optional_int(values.get("DP")),
                genotype_quality=_parse_optional_int(values.get("GQ")),
                allele_depths=_parse_allele_depths(values.get("AD")),
                filter_status=fields[6],
            )
        )
    return tuple(records)


def _zygosity(genotype: str | None) -> str | None:
    if not genotype:
        return None
    normalized = genotype.replace("|", "/")
    alleles = normalized.split("/")
    if len(alleles) != 2 or any(allele in {"", "."} for allele in alleles):
        return None
    if alleles[0] != alleles[1]:
        return "HETEROZYGOUS"
    if alleles[0] == "0":
        return "HOMOZYGOUS_REFERENCE"
    return "HOMOZYGOUS_ALTERNATE"


def _phase_semantics(
    genotype: str | None,
    transformation: str,
    phase_rule_status: str,
) -> str:
    if (
        phase_rule_status == "EXPLICITLY_INVALIDATED"
        and transformation in {"SPLIT", "SPLIT_AND_REALIGNED"}
    ):
        return "EXPLICITLY_INVALIDATED"
    if genotype and "|" in genotype:
        return "PHASED"
    if genotype and "/" in genotype:
        return "UNPHASED"
    return "NOT_AVAILABLE"


def _allele_balance(record: _NormalizedRecord) -> float | None:
    if record.genotype is None or record.allele_depths is None:
        return None
    if "," in record.alt or len(record.allele_depths) != 2:
        return None
    alleles = record.genotype.replace("|", "/").split("/")
    if len(alleles) != 2 or set(alleles) != {"0", "1"}:
        return None
    total = record.allele_depths[0] + record.allele_depths[1]
    if total <= 0:
        return None
    return record.allele_depths[1] / total


def _transformations_by_output_ordinal(
    normalization: VariantNormalizationResult,
) -> dict[int, str] | None:
    transformations: dict[int, str] = {}
    if type(normalization.transformation_ledger) is not tuple:
        return None
    for entry in normalization.transformation_ledger:
        if not isinstance(entry, VariantTransformationLedgerEntry):
            return None
        for output in entry.output_records:
            ordinal = output.output_record_ordinal
            if type(ordinal) is not int or ordinal <= 0 or ordinal in transformations:
                return None
            transformations[ordinal] = entry.transformation
    return transformations
def build_canonical_genomic_model(
    *,
    source_vcf: object,
    source_artifact_manifest: object,
    source_artifact_gate: object,
    source_qc: object,
    reference_identity: object,
    normalization: object,
    canonical_variants: object,
) -> CanonicalGenomicModelResult:
    """Assemble the minimum E1A canonical model from exact upstream attestations."""

    states: dict[str, tuple[bool, str]] = {}
    errors: list[str] = []

    if not isinstance(source_vcf, bytes):
        states[RULE_SOURCE_ARTIFACT] = (False, "source_vcf_invalid")
        errors.append("source_vcf_invalid")
        return _result(states=states, errors=errors)

    manifest = (
        source_artifact_manifest
        if isinstance(source_artifact_manifest, Mapping)
        else {}
    )
    recomputed_artifact = verify_artifact_bytes(manifest, source_vcf)
    if not recomputed_artifact.passed:
        states[RULE_SOURCE_ARTIFACT] = (
            False,
            "source_artifact_not_verified",
        )
        errors.append("source_artifact_not_verified")
        return _result(
            states=states,
            errors=errors,
            source_artifact_id=recomputed_artifact.artifact_id,
            source_vcf_sha256=recomputed_artifact.actual_sha256,
            source_vcf_size_bytes=recomputed_artifact.actual_size_bytes,
        )
    if (
        not isinstance(source_artifact_gate, ArtifactGateResult)
        or source_artifact_gate != recomputed_artifact
    ):
        states[RULE_SOURCE_ARTIFACT] = (
            False,
            "source_artifact_attestation_mismatch",
        )
        errors.append("source_artifact_attestation_mismatch")
        return _result(
            states=states,
            errors=errors,
            source_artifact_id=recomputed_artifact.artifact_id,
            source_vcf_sha256=recomputed_artifact.actual_sha256,
            source_vcf_size_bytes=recomputed_artifact.actual_size_bytes,
        )
    states[RULE_SOURCE_ARTIFACT] = (
        True,
        "source_artifact_reverified",
    )

    recomputed_qc = observe_vcf_qc(source_vcf)
    if not recomputed_qc.input_valid or recomputed_qc.errors:
        states[RULE_SOURCE_QC] = (False, "source_qc_not_acceptable")
        errors.append("source_qc_not_acceptable")
        return _result(
            states=states,
            errors=errors,
            source_artifact_id=recomputed_artifact.artifact_id,
            source_vcf_sha256=recomputed_artifact.actual_sha256,
            source_vcf_size_bytes=recomputed_artifact.actual_size_bytes,
            sample_id=recomputed_qc.sample_id,
        )
    if (
        not isinstance(source_qc, VcfQcObservationResult)
        or source_qc != recomputed_qc
    ):
        states[RULE_SOURCE_QC] = (
            False,
            "source_qc_attestation_mismatch",
        )
        errors.append("source_qc_attestation_mismatch")
        return _result(
            states=states,
            errors=errors,
            source_artifact_id=recomputed_artifact.artifact_id,
            source_vcf_sha256=recomputed_artifact.actual_sha256,
            source_vcf_size_bytes=recomputed_artifact.actual_size_bytes,
            sample_id=recomputed_qc.sample_id,
        )
    states[RULE_SOURCE_QC] = (True, "source_qc_reverified")
    if (
        not isinstance(reference_identity, ReferenceIdentityResult)
        or type(reference_identity.rules) is not tuple
        or not all(
            isinstance(rule, ReferenceRuleResult)
            for rule in reference_identity.rules
        )
        or not reference_identity.passed
    ):
        states[RULE_REFERENCE] = (False, "reference_identity_not_verified")
        errors.append("reference_identity_not_verified")
        return _result(
            states=states,
            errors=errors,
            source_artifact_id=recomputed_artifact.artifact_id,
            source_vcf_sha256=recomputed_artifact.actual_sha256,
            source_vcf_size_bytes=recomputed_artifact.actual_size_bytes,
            sample_id=recomputed_qc.sample_id,
        )
    states[RULE_REFERENCE] = (True, "reference_identity_verified")

    if (
        not isinstance(normalization, VariantNormalizationResult)
        or type(normalization.rules) is not tuple
        or not all(
            isinstance(rule, NormalizationRuleResult)
            for rule in normalization.rules
        )
        or not normalization.passed
    ):
        states[RULE_NORMALIZATION] = (False, "normalization_not_verified")
        errors.append("normalization_not_verified")
        return _result(
            states=states,
            errors=errors,
            source_artifact_id=recomputed_artifact.artifact_id,
            source_vcf_sha256=recomputed_artifact.actual_sha256,
            source_vcf_size_bytes=recomputed_artifact.actual_size_bytes,
            sample_id=recomputed_qc.sample_id,
            reference_identity=reference_identity,
        )
    source_sha256 = _sha256_bytes(source_vcf)
    if normalization.input_sha256 != source_sha256:
        states[RULE_NORMALIZATION] = (
            False,
            "normalization_input_binding_mismatch",
        )
        errors.append("normalization_input_binding_mismatch")
        return _result(
            states=states,
            errors=errors,
            source_artifact_id=recomputed_artifact.artifact_id,
            source_vcf_sha256=source_sha256,
            source_vcf_size_bytes=len(source_vcf),
            sample_id=recomputed_qc.sample_id,
            reference_identity=reference_identity,
            normalization_output_sha256=normalization.output_sha256,
        )
    states[RULE_NORMALIZATION] = (True, "normalization_input_bound")

    recomputed_canonical = canonicalize_normalized_variants(
        normalization,
        reference_identity,
    )
    if (
        not recomputed_canonical.passed
        or not isinstance(canonical_variants, CanonicalVariantIdentityResult)
        or canonical_variants != recomputed_canonical
    ):
        states[RULE_CANONICAL_VARIANTS] = (
            False,
            "canonical_variant_attestation_mismatch",
        )
        errors.append("canonical_variant_attestation_mismatch")
        return _result(
            states=states,
            errors=errors,
            source_artifact_id=recomputed_artifact.artifact_id,
            source_vcf_sha256=source_sha256,
            source_vcf_size_bytes=len(source_vcf),
            sample_id=recomputed_qc.sample_id,
            reference_identity=reference_identity,
            normalization_output_sha256=normalization.output_sha256,
        )
    states[RULE_CANONICAL_VARIANTS] = (
        True,
        "canonical_variant_attestation_recomputed",
    )
    normalized_intake = validate_vcf_bytes(normalization.normalized_vcf)
    source_sample = recomputed_qc.sample_id
    if (
        not normalized_intake.is_valid
        or source_sample is None
        or normalized_intake.sample_id != source_sample
    ):
        states[RULE_SAMPLE] = (False, "sample_identity_mismatch")
        errors.append("sample_identity_mismatch")
        return _result(
            states=states,
            errors=errors,
            source_artifact_id=recomputed_artifact.artifact_id,
            source_vcf_sha256=source_sha256,
            source_vcf_size_bytes=len(source_vcf),
            sample_id=source_sample,
            reference_identity=reference_identity,
            normalization_output_sha256=normalization.output_sha256,
        )
    states[RULE_SAMPLE] = (True, "source_and_normalized_sample_match")

    normalized_qc = observe_vcf_qc(normalization.normalized_vcf)
    if not normalized_qc.input_valid or normalized_qc.errors:
        states[RULE_NORMALIZED_QC] = (
            False,
            "normalized_qc_not_acceptable",
        )
        errors.append("normalized_qc_not_acceptable")
        return _result(
            states=states,
            errors=errors,
            source_artifact_id=recomputed_artifact.artifact_id,
            source_vcf_sha256=source_sha256,
            source_vcf_size_bytes=len(source_vcf),
            sample_id=source_sample,
            reference_identity=reference_identity,
            normalization_output_sha256=normalization.output_sha256,
        )
    states[RULE_NORMALIZED_QC] = (
        True,
        "normalized_qc_observed_without_errors",
    )

    try:
        records = _parse_normalized_records(normalization.normalized_vcf)
    except (UnicodeDecodeError, ValueError, IndexError):
        states[RULE_MODEL] = (False, "normalized_record_parse_failed")
        errors.append("normalized_record_parse_failed")
        return _result(
            states=states,
            errors=errors,
            source_artifact_id=recomputed_artifact.artifact_id,
            source_vcf_sha256=source_sha256,
            source_vcf_size_bytes=len(source_vcf),
            sample_id=source_sample,
            reference_identity=reference_identity,
            normalization_output_sha256=normalization.output_sha256,
        )
    if (
        len(records) != normalization.output_record_count
        or len(records) != len(recomputed_canonical.variants)
    ):
        states[RULE_MODEL] = (False, "canonical_model_cardinality_mismatch")
        errors.append("canonical_model_cardinality_mismatch")
        return _result(
            states=states,
            errors=errors,
            source_artifact_id=recomputed_artifact.artifact_id,
            source_vcf_sha256=source_sha256,
            source_vcf_size_bytes=len(source_vcf),
            sample_id=source_sample,
            reference_identity=reference_identity,
            normalization_output_sha256=normalization.output_sha256,
        )

    if any(
        entry.transformation not in _ALLOWED_TRANSFORMATIONS
        for entry in normalization.transformation_ledger
    ):
        states[RULE_MODEL] = (
            False,
            "normalization_transformation_invalid",
        )
        errors.append("normalization_transformation_invalid")
        return _result(
            states=states,
            errors=errors,
            source_artifact_id=recomputed_artifact.artifact_id,
            source_vcf_sha256=source_sha256,
            source_vcf_size_bytes=len(source_vcf),
            sample_id=source_sample,
            reference_identity=reference_identity,
            normalization_output_sha256=normalization.output_sha256,
        )

    transformations = _transformations_by_output_ordinal(normalization)
    if transformations is None or set(transformations) != {
        record.ordinal for record in records
    }:
        states[RULE_MODEL] = (False, "normalization_provenance_mismatch")
        errors.append("normalization_provenance_mismatch")
        return _result(
            states=states,
            errors=errors,
            source_artifact_id=recomputed_artifact.artifact_id,
            source_vcf_sha256=source_sha256,
            source_vcf_size_bytes=len(source_vcf),
            sample_id=source_sample,
            reference_identity=reference_identity,
            normalization_output_sha256=normalization.output_sha256,
        )
    phase_rule = next(
        (
            rule
            for rule in normalization.rules
            if isinstance(rule, NormalizationRuleResult)
            and rule.rule_id == RULE_PHASE
        ),
        None,
    )
    if phase_rule is None:
        states[RULE_MODEL] = (False, "phase_attestation_missing")
        errors.append("phase_attestation_missing")
        return _result(
            states=states,
            errors=errors,
            source_artifact_id=recomputed_artifact.artifact_id,
            source_vcf_sha256=source_sha256,
            source_vcf_size_bytes=len(source_vcf),
            sample_id=source_sample,
            reference_identity=reference_identity,
            normalization_output_sha256=normalization.output_sha256,
        )

    model_variants: list[CanonicalGenomicVariant] = []
    for record, canonical in zip(
        records,
        recomputed_canonical.variants,
        strict=True,
    ):
        if (
            canonical.normalized_record_ordinal != record.ordinal
            or canonical.contig_accession != record.chrom
            or canonical.position_1_based != record.pos
            or canonical.ref != record.ref
            or canonical.alt != record.alt
            or canonical.genotype != record.genotype
        ):
            states[RULE_MODEL] = (
                False,
                "canonical_model_record_binding_mismatch",
            )
            errors.append("canonical_model_record_binding_mismatch")
            return _result(
                states=states,
                errors=errors,
                source_artifact_id=recomputed_artifact.artifact_id,
                source_vcf_sha256=source_sha256,
                source_vcf_size_bytes=len(source_vcf),
                sample_id=source_sample,
                reference_identity=reference_identity,
                normalization_output_sha256=normalization.output_sha256,
            )
        transformation = transformations[record.ordinal]
        model_variants.append(
            CanonicalGenomicVariant(
                canonical_variant_id=canonical.canonical_variant_id,
                contig_accession=record.chrom,
                position_1_based=record.pos,
                ref=record.ref,
                alt=record.alt,
                genotype=record.genotype,
                zygosity=_zygosity(record.genotype),
                phase_semantics=_phase_semantics(
                    record.genotype,
                    transformation,
                    phase_rule.status,
                ),
                depth=record.depth,
                genotype_quality=record.genotype_quality,
                allele_balance=_allele_balance(record),
                filter_status=record.filter_status,
                normalized_record_ordinal=record.ordinal,
                normalized_record_sha256=canonical.normalized_record_sha256,
                source_record_sha256s=canonical.source_record_sha256s,
                normalization_transformation=transformation,
            )
        )

    states[RULE_MODEL] = (
        True,
        "canonical_genomic_model_assembled",
    )
    return _result(
        states=states,
        errors=errors,
        source_artifact_id=recomputed_artifact.artifact_id,
        source_vcf_sha256=source_sha256,
        source_vcf_size_bytes=len(source_vcf),
        sample_id=source_sample,
        reference_identity=reference_identity,
        normalization_output_sha256=normalization.output_sha256,
        variants=tuple(model_variants),
    )
