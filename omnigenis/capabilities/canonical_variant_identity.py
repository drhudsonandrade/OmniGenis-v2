"""Deterministic project-owned identity for normalized E1A small variants."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

from .reference_identity import ReferenceIdentityResult, ReferenceRuleResult
from .variant_normalization import (
    REFERENCE_ASSEMBLY,
    REFERENCE_AUTOSOMAL_REFSEQ_ACCESSIONS,
    REFERENCE_BUNDLE_SHA256,
    REFERENCE_FASTA_CONTENT_SHA256,
    REFERENCE_FASTA_CONTENT_SIZE_BYTES,
    REFERENCE_PROFILE_ID,
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
    NormalizationRuleResult,
    OutputVariantRecord,
    VariantNormalizationResult,
    VariantTransformationLedgerEntry,
)
from .vcf_intake import validate_vcf_bytes
CAPABILITY_ID = "canonical-small-variant-identity"
CAPABILITY_VERSION = "1.0.0"
IDENTITY_VERSION = "1.0.0"
IDENTIFIER_PREFIX = "omnigenis:small-variant:v1:sha256:"

RULE_NORMALIZATION = "NORMALIZATION_ATTESTATION"
RULE_REFERENCE_BINDING = "REFERENCE_BINDING"
RULE_DOMAIN = "CANONICAL_VARIANT_DOMAIN"
RULE_UNIQUENESS = "CANONICAL_IDENTITY_UNIQUENESS"
RULE_PROVENANCE = "PROVENANCE_RETENTION"

_RULE_ORDER = (
    RULE_NORMALIZATION,
    RULE_REFERENCE_BINDING,
    RULE_DOMAIN,
    RULE_UNIQUENESS,
    RULE_PROVENANCE,
)
_NORMALIZATION_RULE_IDS = frozenset(
    {
        RULE_INPUT, RULE_EXECUTOR, RULE_REFERENCE, RULE_STRICT_REPARSE,
        RULE_CARDINALITY, RULE_PHASE, RULE_ORDERING, RULE_INDEXABILITY,
        RULE_REF_CONCORDANCE, RULE_RETENTION,
    }
)
_ALLOWED_NORMALIZATION_STATES = frozenset({"PASS", "EXPLICITLY_INVALIDATED"})
_SEQUENCE_ALLELE = re.compile(r"^[ACGT]+$")
_HEX = frozenset("0123456789abcdef")
@dataclass(frozen=True)
class CanonicalIdentityRuleResult:
    """One independently traceable canonical-identity rule result."""

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
class CanonicalVariantIdentity:
    """Stable reference-bound variant identity plus non-identity provenance."""

    canonical_variant_id: str
    identity_version: str
    reference_bundle_sha256: str
    assembly_accession: str
    contig_accession: str
    position_1_based: int
    ref: str
    alt: str
    genotype: str | None
    normalized_record_ordinal: int
    normalized_record_sha256: str
    normalization_output_sha256: str
    source_record_sha256s: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "canonical_variant_id": self.canonical_variant_id,
            "identity_version": self.identity_version,
            "reference_bundle_sha256": self.reference_bundle_sha256,
            "assembly_accession": self.assembly_accession,
            "contig_accession": self.contig_accession,
            "position_1_based": self.position_1_based,
            "ref": self.ref,
            "alt": self.alt,
            "genotype": self.genotype,
            "normalized_record_ordinal": self.normalized_record_ordinal,
            "normalized_record_sha256": self.normalized_record_sha256,
            "normalization_output_sha256": self.normalization_output_sha256,
            "source_record_sha256s": list(self.source_record_sha256s),
        }


@dataclass(frozen=True)
class CanonicalVariantIdentityResult:
    """Tool-neutral CANONICAL_VARIANTS result for the initial E1A profile."""

    variants: tuple[CanonicalVariantIdentity, ...]
    normalization_input_sha256: str | None
    normalization_output_sha256: str | None
    reference_bundle_sha256: str | None
    rules: tuple[CanonicalIdentityRuleResult, ...]
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
                "artifact_kind": "CANONICAL_VARIANTS",
                "identity_version": IDENTITY_VERSION,
                "normalization_input_sha256": self.normalization_input_sha256,
                "normalization_output_sha256": self.normalization_output_sha256,
                "reference_bundle_sha256": self.reference_bundle_sha256,
                "variant_count": len(self.variants),
                "variants": [variant.to_dict() for variant in self.variants],
                "rules": [rule.to_dict() for rule in self.rules],
                "errors": list(self.errors),
            },
            "availability": "AVAILABLE" if self.passed else "BLOCKED",
            "limitations": [
                "Initial E1A profile only: primary-autosome sequence-resolved SNV and indel records.",
                "Identity is reference-bound and excludes display labels and downstream annotations.",
                "No external nomenclature projection, gene annotation, evidence federation, or interpretation is performed.",
            ],
            "executor_id": "omnigenis.python-stdlib",
            "executor_version": CAPABILITY_VERSION,
            "adapter_version": None,
            "model_id": None,
            "resource_release": REFERENCE_ASSEMBLY,
            "reference_bundle": self.reference_bundle_sha256,
            "execution_profile": "canonical-small-variant-identity-v1",
            "raw_artifact_refs": [
                value
                for value in (
                    self.normalization_input_sha256,
                    self.normalization_output_sha256,
                )
                if value is not None
            ],
            "provenance_refs": [
                REFERENCE_PROFILE_ID,
                "reference-bound-small-variant-normalization",
            ],
        }


@dataclass(frozen=True)
class _NormalizedRecord:
    ordinal: int
    line: str
    chrom: str
    pos: int
    ref: str
    alt: str
    genotype: str | None


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HEX for character in value)
    )


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return _sha256_bytes(payload)


def _rule(rule_id: str, passed: bool, detail: str) -> CanonicalIdentityRuleResult:
    return CanonicalIdentityRuleResult(
        rule_id=rule_id,
        status="PASS" if passed else "FAIL",
        detail=detail,
    )


def _rules(
    states: dict[str, tuple[bool, str]],
) -> tuple[CanonicalIdentityRuleResult, ...]:
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
    normalization: VariantNormalizationResult | None,
    reference_bundle_sha256: str | None,
    states: dict[str, tuple[bool, str]],
    errors: list[str],
    variants: tuple[CanonicalVariantIdentity, ...] = (),
) -> CanonicalVariantIdentityResult:
    return CanonicalVariantIdentityResult(
        variants=variants,
        normalization_input_sha256=(
            normalization.input_sha256
            if isinstance(normalization, VariantNormalizationResult)
            and _is_sha256(normalization.input_sha256)
            else None
        ),
        normalization_output_sha256=(
            normalization.output_sha256
            if isinstance(normalization, VariantNormalizationResult)
            and _is_sha256(normalization.output_sha256)
            else None
        ),
        reference_bundle_sha256=reference_bundle_sha256,
        rules=_rules(states),
        errors=tuple(errors),
    )


def _reference_identity_verified(reference: object) -> bool:
    if not isinstance(reference, ReferenceIdentityResult):
        return False
    if (
        type(reference.rules) is not tuple
        or not all(
            isinstance(rule, ReferenceRuleResult)
            for rule in reference.rules
        )
    ):
        return False
    return (
        reference.passed
        and reference.profile_id == REFERENCE_PROFILE_ID
        and reference.assembly_accession == REFERENCE_ASSEMBLY
        and reference.bundle_sha256 == REFERENCE_BUNDLE_SHA256
        and reference.fasta_content_sha256 == REFERENCE_FASTA_CONTENT_SHA256
        and type(reference.fasta_content_size_bytes) is int
        and reference.fasta_content_size_bytes == REFERENCE_FASTA_CONTENT_SIZE_BYTES
        and type(reference.autosomal_refseq_accessions) is tuple
        and reference.autosomal_refseq_accessions
        == REFERENCE_AUTOSOMAL_REFSEQ_ACCESSIONS
    )


def _normalization_attestation_error(normalization: object) -> str | None:
    if not isinstance(normalization, VariantNormalizationResult):
        return "normalization_not_verified"
    if (
        type(normalization.rules) is not tuple
        or not all(
            isinstance(rule, NormalizationRuleResult)
            for rule in normalization.rules
        )
    ):
        return "normalization_rule_set_invalid"
    rule_ids = tuple(rule.rule_id for rule in normalization.rules)
    if (
        len(rule_ids) != len(_NORMALIZATION_RULE_IDS)
        or frozenset(rule_ids) != _NORMALIZATION_RULE_IDS
    ):
        return "normalization_rule_set_incomplete"
    if (
        not normalization.passed
        or any(
            rule.status not in _ALLOWED_NORMALIZATION_STATES
            for rule in normalization.rules
        )
    ):
        return "normalization_not_verified"
    if (
        not isinstance(normalization.normalized_vcf, bytes)
        or not _is_sha256(normalization.output_sha256)
        or normalization.output_sha256
        != _sha256_bytes(normalization.normalized_vcf)
    ):
        return "normalization_output_digest_mismatch"
    if normalization.reference_content_sha256 != REFERENCE_FASTA_CONTENT_SHA256:
        return "normalization_reference_binding_mismatch"
    return None


def _extract_genotype(format_field: str, sample_field: str) -> str | None:
    keys = format_field.split(":")
    if "GT" not in keys:
        return None
    values = sample_field.split(":")
    index = keys.index("GT")
    return values[index] if index < len(values) else None


def _parse_normalized_records(data: bytes) -> tuple[_NormalizedRecord, ...]:
    text = data.decode("utf-8").replace("\r\n", "\n")
    records: list[_NormalizedRecord] = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 10:
            continue
        records.append(
            _NormalizedRecord(
                ordinal=len(records) + 1,
                line=line,
                chrom=fields[0],
                pos=int(fields[1]),
                ref=fields[3],
                alt=fields[4],
                genotype=_extract_genotype(fields[8], fields[9]),
            )
        )
    return tuple(records)


def _record_supported(record: _NormalizedRecord) -> bool:
    if record.chrom not in REFERENCE_AUTOSOMAL_REFSEQ_ACCESSIONS:
        return False
    if record.pos <= 0:
        return False
    if "," in record.alt:
        return False
    if not _SEQUENCE_ALLELE.fullmatch(record.ref):
        return False
    if not _SEQUENCE_ALLELE.fullmatch(record.alt):
        return False
    if record.ref == record.alt:
        return False
    if len(record.ref) == len(record.alt) and len(record.ref) > 1:
        return False
    return True


def _source_hashes_by_output_ordinal(
    normalization: VariantNormalizationResult,
    records: tuple[_NormalizedRecord, ...],
) -> tuple[dict[int, tuple[str, ...]], str | None]:
    normalized_by_ordinal = {record.ordinal: record for record in records}
    source_hashes: dict[int, list[str]] = {}
    if type(normalization.transformation_ledger) is not tuple:
        return {}, "normalization_provenance_invalid"

    for entry in normalization.transformation_ledger:
        if (
            not isinstance(entry, VariantTransformationLedgerEntry)
            or not _is_sha256(entry.source_record_sha256)
            or type(entry.output_records) is not tuple
            or not all(
                isinstance(output, OutputVariantRecord)
                for output in entry.output_records
            )
        ):
            return {}, "normalization_provenance_invalid"
        for output in entry.output_records:
            if (
                type(output.output_record_ordinal) is not int
                or output.output_record_ordinal <= 0
            ):
                return {}, "normalization_provenance_invalid"
            record = normalized_by_ordinal.get(output.output_record_ordinal)
            if record is None:
                return {}, "normalization_provenance_mismatch"
            if (
                output.chrom != record.chrom
                or output.pos != record.pos
                or output.ref != record.ref
                or output.alt != record.alt
                or output.genotype != record.genotype
            ):
                return {}, "normalization_provenance_mismatch"
            source_hashes.setdefault(record.ordinal, []).append(
                entry.source_record_sha256
            )

    if set(source_hashes) != set(normalized_by_ordinal):
        return {}, "normalization_provenance_incomplete"

    canonical: dict[int, tuple[str, ...]] = {}
    for ordinal, hashes in source_hashes.items():
        if len(hashes) != len(set(hashes)):
            return {}, "normalization_provenance_duplicate"
        if len(hashes) != 1:
            return {}, "normalization_provenance_ambiguous"
        canonical[ordinal] = tuple(hashes)
    return canonical, None


def canonicalize_normalized_variants(
    normalization: VariantNormalizationResult,
    reference_identity: ReferenceIdentityResult,
) -> CanonicalVariantIdentityResult:
    """Create deterministic reference-bound identities from verified normalized VCF output."""

    states: dict[str, tuple[bool, str]] = {}
    errors: list[str] = []

    normalization_error = _normalization_attestation_error(normalization)
    if normalization_error is not None:
        states[RULE_NORMALIZATION] = (False, normalization_error)
        errors.append(normalization_error)
        return _result(
            normalization=normalization
            if isinstance(normalization, VariantNormalizationResult)
            else None,
            reference_bundle_sha256=None,
            states=states,
            errors=errors,
        )
    states[RULE_NORMALIZATION] = (True, "normalization_attestation_verified")
    if not _reference_identity_verified(reference_identity):
        states[RULE_REFERENCE_BINDING] = (
            False,
            "reference_identity_not_verified",
        )
        errors.append("reference_identity_not_verified")
        return _result(
            normalization=normalization,
            reference_bundle_sha256=None,
            states=states,
            errors=errors,
        )
    states[RULE_REFERENCE_BINDING] = (True, "reference_binding_verified")

    intake = validate_vcf_bytes(normalization.normalized_vcf)
    if not intake.is_valid:
        states[RULE_DOMAIN] = (False, "normalized_vcf_invalid")
        errors.append("normalized_vcf_invalid")
        return _result(
            normalization=normalization,
            reference_bundle_sha256=REFERENCE_BUNDLE_SHA256,
            states=states,
            errors=errors,
        )

    records = _parse_normalized_records(normalization.normalized_vcf)
    if (
        len(records) != normalization.output_record_count
        or intake.record_count != normalization.output_record_count
    ):
        states[RULE_DOMAIN] = (False, "normalized_record_count_mismatch")
        errors.append("normalized_record_count_mismatch")
        return _result(
            normalization=normalization,
            reference_bundle_sha256=REFERENCE_BUNDLE_SHA256,
            states=states,
            errors=errors,
        )

    unsupported = [
        record.ordinal for record in records if not _record_supported(record)
    ]
    if unsupported:
        states[RULE_DOMAIN] = (False, "unsupported_normalized_record")
        errors.extend(
            f"unsupported_normalized_record_{ordinal}"
            for ordinal in unsupported
        )
        return _result(
            normalization=normalization,
            reference_bundle_sha256=REFERENCE_BUNDLE_SHA256,
            states=states,
            errors=errors,
        )
    states[RULE_DOMAIN] = (True, "normalized_variant_domain_verified")

    source_hashes, provenance_error = _source_hashes_by_output_ordinal(
        normalization,
        records,
    )
    if provenance_error is not None:
        states[RULE_PROVENANCE] = (False, provenance_error)
        errors.append(provenance_error)
        return _result(
            normalization=normalization,
            reference_bundle_sha256=REFERENCE_BUNDLE_SHA256,
            states=states,
            errors=errors,
        )

    variants: list[CanonicalVariantIdentity] = []
    seen: set[str] = set()
    for record in records:
        identity_payload = {
            "alt": record.alt,
            "assembly_accession": REFERENCE_ASSEMBLY,
            "contig_accession": record.chrom,
            "identity_version": IDENTITY_VERSION,
            "position_1_based": record.pos,
            "ref": record.ref,
            "reference_bundle_sha256": REFERENCE_BUNDLE_SHA256,
        }
        canonical_id = IDENTIFIER_PREFIX + _canonical_json_sha256(
            identity_payload
        )
        if canonical_id in seen:
            states[RULE_UNIQUENESS] = (
                False,
                "duplicate_canonical_variant_identity",
            )
            errors.append("duplicate_canonical_variant_identity")
            return _result(
                normalization=normalization,
                reference_bundle_sha256=REFERENCE_BUNDLE_SHA256,
                states=states,
                errors=errors,
            )
        seen.add(canonical_id)
        variants.append(
            CanonicalVariantIdentity(
                canonical_variant_id=canonical_id,
                identity_version=IDENTITY_VERSION,
                reference_bundle_sha256=REFERENCE_BUNDLE_SHA256,
                assembly_accession=REFERENCE_ASSEMBLY,
                contig_accession=record.chrom,
                position_1_based=record.pos,
                ref=record.ref,
                alt=record.alt,
                genotype=record.genotype,
                normalized_record_ordinal=record.ordinal,
                normalized_record_sha256=_sha256_bytes(
                    record.line.encode("utf-8")
                ),
                normalization_output_sha256=normalization.output_sha256,
                source_record_sha256s=source_hashes[record.ordinal],
            )
        )

    states[RULE_UNIQUENESS] = (
        True,
        "canonical_variant_identities_unique",
    )
    states[RULE_PROVENANCE] = (
        True,
        "normalization_and_source_provenance_retained",
    )
    return _result(
        normalization=normalization,
        reference_bundle_sha256=REFERENCE_BUNDLE_SHA256,
        states=states,
        errors=errors,
        variants=tuple(variants),
    )
