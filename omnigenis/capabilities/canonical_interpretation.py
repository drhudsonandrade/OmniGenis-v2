"""Minimum source-attributed CanonicalInterpretationObject for E1A."""

from __future__ import annotations

import calendar
from dataclasses import dataclass
from datetime import date, datetime
import re

from .canonical_genomic_model import (
    CanonicalGenomicModelResult,
    CanonicalGenomicModelRuleResult,
    CanonicalGenomicVariant,
)
from .evidence_snapshot import (
    ClinVarEvidenceItem,
    ClinVarSubmissionEvidence,
    EvidenceSnapshotMetadataRecord,
    EvidenceSnapshotRuleResult,
    MinimumEvidenceSnapshotResult,
)

CAPABILITY_ID = "canonical-interpretation-object"
CAPABILITY_VERSION = "1.0.0"
ARTIFACT_KIND = "CANONICAL_INTERPRETATION"
SOURCE_REGISTRY_ID = "source-registry-minimal-e1a-v1"
RULE_CANONICAL_MODEL = "CANONICAL_MODEL_BINDING"
RULE_EVIDENCE_SNAPSHOT = "EVIDENCE_SNAPSHOT_BINDING"
RULE_CARDINALITY = "INTERPRETATION_CARDINALITY"
RULE_FRESHNESS = "EVIDENCE_FRESHNESS"
RULE_INTERPRETATION = "INTERPRETATION_PROJECTION"

_RULE_ORDER = (
    RULE_CANONICAL_MODEL,
    RULE_EVIDENCE_SNAPSHOT,
    RULE_CARDINALITY,
    RULE_FRESHNESS,
    RULE_INTERPRETATION,
)

_DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_VCV = re.compile(r"^VCV[0-9]{9}$")
_CANONICAL_VARIANT_ID = re.compile(
    r"^omnigenis:small-variant:v1:sha256:[0-9a-f]{64}$"
)

SOURCE_CLASSIFICATION_VERIFIED = "SOURCE_CLASSIFICATION_VERIFIED"
EVIDENCE_CONFLICT_UNRESOLVED = "EVIDENCE_CONFLICT_UNRESOLVED"

UPDATED_LT_6_MONTHS = "UPDATED_LT_6_MONTHS"
UPDATED_6_TO_12_MONTHS = "UPDATED_6_TO_12_MONTHS"
POTENTIALLY_OUTDATED_GT_12_MONTHS = (
    "POTENTIALLY_OUTDATED_GT_12_MONTHS"
)
@dataclass(frozen=True)
class CanonicalInterpretationRuleResult:
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
class CanonicalInterpretationItem:
    canonical_variant_id: str
    operational_status: str
    interpretation_status: str
    source_name: str
    source_classification: str
    source_review_status: str
    source_conflict: bool
    source_variation_id: int
    source_vcv_accession: str
    source_vcv_version: int
    evidence_snapshot_id: str
    evidence_sha256: str
    evidence_checked_at: str
    evidence_freshness_status: str
    source_submission_count: int
    condition_names: tuple[str, ...]
    condition_references: tuple[str, ...]
    local_classification_status: str
    local_classification: str | None
    acmg_amp_status: str
    clingen_vcep_status: str
    gene_disease_validity_status: str
    actionability_status: str
    personal_relevance_status: str
    diagnosis_status: str
    treatment_status: str

    def to_dict(self) -> dict[str, object]:
        return {
            "canonical_variant_id": self.canonical_variant_id,
            "operational_status": self.operational_status,
            "interpretation_status": self.interpretation_status,
            "source_name": self.source_name,
            "source_classification": self.source_classification,
            "source_review_status": self.source_review_status,
            "source_conflict": self.source_conflict,
            "source_variation_id": self.source_variation_id,
            "source_vcv_accession": self.source_vcv_accession,
            "source_vcv_version": self.source_vcv_version,
            "evidence_snapshot_id": self.evidence_snapshot_id,
            "evidence_sha256": self.evidence_sha256,
            "evidence_checked_at": self.evidence_checked_at,
            "evidence_freshness_status": self.evidence_freshness_status,
            "source_submission_count": self.source_submission_count,
            "condition_names": list(self.condition_names),
            "condition_references": list(self.condition_references),
            "local_classification_status": self.local_classification_status,
            "local_classification": self.local_classification,
            "acmg_amp_status": self.acmg_amp_status,
            "clingen_vcep_status": self.clingen_vcep_status,
            "gene_disease_validity_status": (
                self.gene_disease_validity_status
            ),
            "actionability_status": self.actionability_status,
            "personal_relevance_status": self.personal_relevance_status,
            "diagnosis_status": self.diagnosis_status,
            "treatment_status": self.treatment_status,
        }
@dataclass(frozen=True)
class CanonicalInterpretationObjectResult:
    canonical_model_source_vcf_sha256: str | None
    canonical_model_normalization_output_sha256: str | None
    evidence_source_registry_id: str | None
    as_of_date: str | None
    items: tuple[CanonicalInterpretationItem, ...]
    rules: tuple[CanonicalInterpretationRuleResult, ...]
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
            "canonical_status": (
                "INTERPRETATION_OBJECT_VERIFIED"
                if self.passed
                else "FAIL"
            ),
            "canonical_payload": {
                "artifact_kind": ARTIFACT_KIND,
                "canonical_model_source_vcf_sha256": (
                    self.canonical_model_source_vcf_sha256
                ),
                "canonical_model_normalization_output_sha256": (
                    self.canonical_model_normalization_output_sha256
                ),
                "evidence_source_registry_id": self.evidence_source_registry_id,
                "as_of_date": self.as_of_date,
                "interpretation_item_count": len(self.items),
                "items": [item.to_dict() for item in self.items],
                "rules": [rule.to_dict() for rule in self.rules],
                "errors": list(self.errors),
            },
            "availability": "AVAILABLE" if self.passed else "BLOCKED",
            "limitations": [
                "This object verifies and types source-attributed evidence; it does not create a local pathogenicity classification.",
                "ACMG/AMP and ClinGen/VCEP criteria application are not performed.",
                "Gene-disease validity, mode of inheritance, actionability, phenotype/personal relevance, diagnosis, treatment, and confirmation policy are not assessed.",
                "A ClinVar conflict remains explicitly unresolved.",
            ],
            "executor_id": "omnigenis.python-stdlib",
            "executor_version": CAPABILITY_VERSION,
            "adapter_version": None,
            "model_id": None,
            "resource_release": None,
            "reference_bundle": None,
            "execution_profile": "canonical-interpretation-object-e1a-v1",
            "raw_artifact_refs": [
                item.evidence_sha256
                for item in self.items
            ],
            "provenance_refs": [
                "canonical-genomic-model",
                "minimum-evidence-snapshot",
            ],
        }


def _rule(
    rule_id: str,
    passed: bool,
    detail: str,
) -> CanonicalInterpretationRuleResult:
    return CanonicalInterpretationRuleResult(
        rule_id=rule_id,
        status="PASS" if passed else "FAIL",
        detail=detail,
    )
def _rules(
    states: dict[str, tuple[bool, str]],
) -> tuple[CanonicalInterpretationRuleResult, ...]:
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
    canonical_model: CanonicalGenomicModelResult | None,
    evidence_snapshot: MinimumEvidenceSnapshotResult | None,
    as_of_date: str | None,
    states: dict[str, tuple[bool, str]],
    errors: list[str],
    items: tuple[CanonicalInterpretationItem, ...] = (),
) -> CanonicalInterpretationObjectResult:
    return CanonicalInterpretationObjectResult(
        canonical_model_source_vcf_sha256=(
            canonical_model.source_vcf_sha256
            if isinstance(canonical_model, CanonicalGenomicModelResult)
            else None
        ),
        canonical_model_normalization_output_sha256=(
            canonical_model.normalization_output_sha256
            if isinstance(canonical_model, CanonicalGenomicModelResult)
            else None
        ),
        evidence_source_registry_id=(
            evidence_snapshot.source_registry_id
            if isinstance(evidence_snapshot, MinimumEvidenceSnapshotResult)
            else None
        ),
        as_of_date=as_of_date,
        items=items,
        rules=_rules(states),
        errors=tuple(errors),
    )


def _fullmatch(
    pattern: re.Pattern[str],
    value: object,
) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _canonical_model_verified(value: object) -> bool:
    if not isinstance(value, CanonicalGenomicModelResult):
        return False
    if (
        type(value.rules) is not tuple
        or not all(
            isinstance(rule, CanonicalGenomicModelRuleResult)
            for rule in value.rules
        )
        or type(value.variants) is not tuple
        or not all(
            isinstance(variant, CanonicalGenomicVariant)
            for variant in value.variants
        )
    ):
        return False
    if not all(
        _fullmatch(
            _CANONICAL_VARIANT_ID,
            variant.canonical_variant_id,
        )
        for variant in value.variants
    ):
        return False
    return value.passed


def _evidence_snapshot_verified(value: object) -> bool:
    if not isinstance(value, MinimumEvidenceSnapshotResult):
        return False
    if (
        value.source_registry_id != SOURCE_REGISTRY_ID
        or type(value.rules) is not tuple
        or not all(
            isinstance(rule, EvidenceSnapshotRuleResult)
            for rule in value.rules
        )
        or type(value.items) is not tuple
        or not all(
            isinstance(item, ClinVarEvidenceItem)
            for item in value.items
        )
    ):
        return False
    for item in value.items:
        if (
            not _fullmatch(
                _CANONICAL_VARIANT_ID,
                item.canonical_variant_id,
            )
            or not isinstance(item.metadata, EvidenceSnapshotMetadataRecord)
            or item.metadata.source_registry_id != SOURCE_REGISTRY_ID
            or type(item.submissions) is not tuple
            or not all(
                isinstance(submission, ClinVarSubmissionEvidence)
                for submission in item.submissions
            )
        ):
            return False
    return value.passed
def _parse_as_of_date(value: object) -> date | None:
    if not isinstance(value, str) or _DATE.fullmatch(value) is None:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def _parse_checked_at(value: object) -> date | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(
            value,
            "%Y-%m-%dT%H:%M:%SZ",
        ).date()
    except ValueError:
        return None


def _subtract_months(value: date, months: int) -> date:
    month_index = value.year * 12 + value.month - 1 - months
    year, month_zero = divmod(month_index, 12)
    month = month_zero + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return date(year, month, day)
def _freshness_status(
    checked_at: date,
    as_of: date,
) -> str:
    cutoff_6 = _subtract_months(as_of, 6)
    cutoff_12 = _subtract_months(as_of, 12)
    if checked_at > cutoff_6:
        return UPDATED_LT_6_MONTHS
    if checked_at >= cutoff_12:
        return UPDATED_6_TO_12_MONTHS
    return POTENTIALLY_OUTDATED_GT_12_MONTHS


def _evidence_item_valid(item: ClinVarEvidenceItem) -> bool:
    return all(
        (
            type(item.aggregate_classification) is str
            and bool(item.aggregate_classification),
            type(item.aggregate_review_status) is str
            and bool(item.aggregate_review_status),
            type(item.conflict) is bool,
            _fullmatch(_VCV, item.vcv_accession),
            type(item.vcv_version) is int and item.vcv_version > 0,
            type(item.variation_id) is int and item.variation_id > 0,
            type(item.metadata.snapshot_id) is str
            and bool(item.metadata.snapshot_id),
            _fullmatch(_SHA256, item.metadata.result_sha256),
            type(item.metadata.checked_at) is str
            and bool(item.metadata.checked_at),
            item.metadata.source_version
            == f"{item.vcv_accession}.{item.vcv_version}",
            type(item.condition_names) is tuple
            and all(type(value) is str for value in item.condition_names),
            type(item.condition_references) is tuple
            and all(type(value) is str for value in item.condition_references),
            type(item.submissions) is tuple,
        )
    )


def build_canonical_interpretation_object(
    *,
    canonical_model: object,
    evidence_snapshot: object,
    as_of_date: object,
) -> CanonicalInterpretationObjectResult:
    """Build a conservative, source-attributed E1A interpretation object."""

    states: dict[str, tuple[bool, str]] = {}
    errors: list[str] = []

    if not _canonical_model_verified(canonical_model):
        states[RULE_CANONICAL_MODEL] = (
            False,
            "canonical_model_not_verified",
        )
        errors.append("canonical_model_not_verified")
        return _result(
            canonical_model=(
                canonical_model
                if isinstance(canonical_model, CanonicalGenomicModelResult)
                else None
            ),
            evidence_snapshot=None,
            as_of_date=None,
            states=states,
            errors=errors,
        )
    states[RULE_CANONICAL_MODEL] = (
        True,
        "canonical_model_verified",
    )

    if not _evidence_snapshot_verified(evidence_snapshot):
        states[RULE_EVIDENCE_SNAPSHOT] = (
            False,
            "evidence_snapshot_not_verified",
        )
        errors.append("evidence_snapshot_not_verified")
        return _result(
            canonical_model=canonical_model,
            evidence_snapshot=(
                evidence_snapshot
                if isinstance(
                    evidence_snapshot,
                    MinimumEvidenceSnapshotResult,
                )
                else None
            ),
            as_of_date=None,
            states=states,
            errors=errors,
        )
    states[RULE_EVIDENCE_SNAPSHOT] = (
        True,
        "evidence_snapshot_verified",
    )
    if (
        evidence_snapshot.canonical_model_source_vcf_sha256
        != canonical_model.source_vcf_sha256
        or evidence_snapshot.canonical_model_normalization_output_sha256
        != canonical_model.normalization_output_sha256
    ):
        states[RULE_EVIDENCE_SNAPSHOT] = (
            False,
            "model_snapshot_provenance_mismatch",
        )
        errors.append("model_snapshot_provenance_mismatch")
        return _result(
            canonical_model=canonical_model,
            evidence_snapshot=evidence_snapshot,
            as_of_date=None,
            states=states,
            errors=errors,
        )

    as_of = _parse_as_of_date(as_of_date)
    if as_of is None:
        states[RULE_FRESHNESS] = (
            False,
            "as_of_date_invalid",
        )
        errors.append("as_of_date_invalid")
        return _result(
            canonical_model=canonical_model,
            evidence_snapshot=evidence_snapshot,
            as_of_date=None,
            states=states,
            errors=errors,
        )
    model_ids = [
        variant.canonical_variant_id
        for variant in canonical_model.variants
    ]
    snapshot_ids = [
        item.canonical_variant_id
        for item in evidence_snapshot.items
    ]
    if len(snapshot_ids) != len(model_ids):
        states[RULE_CARDINALITY] = (
            False,
            "interpretation_cardinality_mismatch",
        )
        errors.append("interpretation_cardinality_mismatch")
        return _result(
            canonical_model=canonical_model,
            evidence_snapshot=evidence_snapshot,
            as_of_date=as_of_date,
            states=states,
            errors=errors,
        )
    if len(snapshot_ids) != len(set(snapshot_ids)):
        states[RULE_CARDINALITY] = (
            False,
            "interpretation_variant_binding_mismatch",
        )
        errors.append("interpretation_variant_binding_mismatch")
        return _result(
            canonical_model=canonical_model,
            evidence_snapshot=evidence_snapshot,
            as_of_date=as_of_date,
            states=states,
            errors=errors,
        )
    if set(snapshot_ids) != set(model_ids):
        states[RULE_CARDINALITY] = (
            False,
            "interpretation_variant_binding_mismatch",
        )
        errors.append("interpretation_variant_binding_mismatch")
        return _result(
            canonical_model=canonical_model,
            evidence_snapshot=evidence_snapshot,
            as_of_date=as_of_date,
            states=states,
            errors=errors,
        )
    states[RULE_CARDINALITY] = (
        True,
        "model_and_evidence_variant_sets_match",
    )

    evidence_by_id = {
        item.canonical_variant_id: item
        for item in evidence_snapshot.items
    }
    built: list[CanonicalInterpretationItem] = []
    for variant in canonical_model.variants:
        evidence = evidence_by_id[variant.canonical_variant_id]
        if not _evidence_item_valid(evidence):
            states[RULE_INTERPRETATION] = (
                False,
                "interpretation_source_invalid",
            )
            errors.append("interpretation_source_invalid")
            return _result(
                canonical_model=canonical_model,
                evidence_snapshot=evidence_snapshot,
                as_of_date=as_of_date,
                states=states,
                errors=errors,
            )
        checked_at = _parse_checked_at(evidence.metadata.checked_at)
        if checked_at is None:
            states[RULE_FRESHNESS] = (
                False,
                "evidence_checked_at_invalid",
            )
            errors.append("evidence_checked_at_invalid")
            return _result(
                canonical_model=canonical_model,
                evidence_snapshot=evidence_snapshot,
                as_of_date=as_of_date,
                states=states,
                errors=errors,
            )
        if checked_at > as_of:
            states[RULE_FRESHNESS] = (
                False,
                "evidence_checked_at_in_future",
            )
            errors.append("evidence_checked_at_in_future")
            return _result(
                canonical_model=canonical_model,
                evidence_snapshot=evidence_snapshot,
                as_of_date=as_of_date,
                states=states,
                errors=errors,
            )

        freshness = _freshness_status(checked_at, as_of)
        status = (
            EVIDENCE_CONFLICT_UNRESOLVED
            if evidence.conflict
            else SOURCE_CLASSIFICATION_VERIFIED
        )
        built.append(
            CanonicalInterpretationItem(
                canonical_variant_id=variant.canonical_variant_id,
                operational_status="VERIFIED",
                interpretation_status=status,
                source_name="NCBI ClinVar",
                source_classification=evidence.aggregate_classification,
                source_review_status=evidence.aggregate_review_status,
                source_conflict=evidence.conflict,
                source_variation_id=evidence.variation_id,
                source_vcv_accession=evidence.vcv_accession,
                source_vcv_version=evidence.vcv_version,
                evidence_snapshot_id=evidence.metadata.snapshot_id,
                evidence_sha256=evidence.metadata.result_sha256,
                evidence_checked_at=evidence.metadata.checked_at,
                evidence_freshness_status=freshness,
                source_submission_count=len(evidence.submissions),
                condition_names=evidence.condition_names,
                condition_references=evidence.condition_references,
                local_classification_status="NOT_PERFORMED",
                local_classification=None,
                acmg_amp_status="NOT_PERFORMED",
                clingen_vcep_status="NOT_PERFORMED",
                gene_disease_validity_status="NOT_AVAILABLE",
                actionability_status="NOT_ASSESSED",
                personal_relevance_status="NOT_ASSESSED",
                diagnosis_status="NOT_ASSESSED",
                treatment_status="NOT_ASSESSED",
            )
        )

    states[RULE_FRESHNESS] = (
        True,
        "all_evidence_dates_classified_relative_to_as_of_date",
    )
    states[RULE_INTERPRETATION] = (
        True,
        "source_attributed_interpretation_projection_built",
    )
    return _result(
        canonical_model=canonical_model,
        evidence_snapshot=evidence_snapshot,
        as_of_date=as_of_date,
        states=states,
        errors=errors,
        items=tuple(built),
    )
