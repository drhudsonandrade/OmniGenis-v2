"""Minimum byte-bound ClinVar EvidenceSnapshot for the E1A path."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
import hashlib
import re
import xml.etree.ElementTree as ET

from .canonical_genomic_model import (
    CanonicalGenomicModelResult,
    CanonicalGenomicModelRuleResult,
    CanonicalGenomicVariant,
)

CAPABILITY_ID = "minimum-evidence-snapshot"
CAPABILITY_VERSION = "1.0.0"
ARTIFACT_KIND = "EVIDENCE_SNAPSHOT"
SOURCE_REGISTRY_ID = "source-registry-minimal-e1a-v1"
SOURCE_ID = "ncbi-clinvar-vcv"
RETRIEVAL_METHOD = "NCBI_EUTILS_HTTPS_EFETCH_VCV"
LOCATOR_BASE = (
    "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/efetch.fcgi"
    "?db=clinvar&rettype=vcv&id="
)
MAX_XML_BYTES = 5 * 1024 * 1024

RULE_CANONICAL_MODEL = "CANONICAL_MODEL_BINDING"
RULE_SOURCE_CONTRACT = "CLINVAR_SOURCE_CONTRACT"
RULE_CARDINALITY = "EVIDENCE_CARDINALITY"
RULE_METADATA = "EVIDENCE_METADATA"
RULE_XML = "CLINVAR_XML"
RULE_VARIANT_BINDING = "CLINVAR_VARIANT_BINDING"
RULE_PRESERVATION = "EVIDENCE_PRESERVATION"

_RULE_ORDER = (
    RULE_CANONICAL_MODEL,
    RULE_SOURCE_CONTRACT,
    RULE_CARDINALITY,
    RULE_METADATA,
    RULE_XML,
    RULE_VARIANT_BINDING,
    RULE_PRESERVATION,
)
_VCV = re.compile(r"^VCV[0-9]{9}$")
_VCV_VERSION = re.compile(r"^(VCV[0-9]{9})\.([1-9][0-9]*)$")
_SCV = re.compile(r"^SCV[0-9]{9}$")
_HEX = frozenset("0123456789abcdef")
_METADATA_KEYS = frozenset(
    {
        "schema_version",
        "snapshot_id",
        "source_registry_id",
        "source_version",
        "version_kind",
        "checked_at",
        "locator",
        "retrieval_method",
        "result_sha256",
        "mutable",
    }
)
@dataclass(frozen=True)
class EvidenceSnapshotRuleResult:
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
class EvidenceSnapshotMetadataRecord:
    schema_version: str
    snapshot_id: str
    source_registry_id: str
    source_version: str
    version_kind: str
    checked_at: str
    locator: str
    retrieval_method: str
    result_sha256: str
    mutable: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "snapshot_id": self.snapshot_id,
            "source_registry_id": self.source_registry_id,
            "source_version": self.source_version,
            "version_kind": self.version_kind,
            "checked_at": self.checked_at,
            "locator": self.locator,
            "retrieval_method": self.retrieval_method,
            "result_sha256": self.result_sha256,
            "mutable": self.mutable,
        }


@dataclass(frozen=True)
class ClinVarSubmissionEvidence:
    accession: str
    version: int
    submitter_name: str
    date_updated: str
    date_created: str
    date_last_evaluated: str | None
    review_status: str
    classification: str
    condition_names: tuple[str, ...]
    condition_references: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "accession": self.accession,
            "version": self.version,
            "submitter_name": self.submitter_name,
            "date_updated": self.date_updated,
            "date_created": self.date_created,
            "date_last_evaluated": self.date_last_evaluated,
            "review_status": self.review_status,
            "classification": self.classification,
            "condition_names": list(self.condition_names),
            "condition_references": list(self.condition_references),
        }
@dataclass(frozen=True)
class ClinVarEvidenceItem:
    canonical_variant_id: str
    metadata: EvidenceSnapshotMetadataRecord
    vcv_accession: str
    vcv_version: int
    variation_id: int
    date_last_updated: str
    canonical_spdi: str
    clinvar_grch38_assembly_accession: str
    aggregate_classification: str
    aggregate_review_status: str
    condition_names: tuple[str, ...]
    condition_references: tuple[str, ...]
    conflict: bool
    submissions: tuple[ClinVarSubmissionEvidence, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "canonical_variant_id": self.canonical_variant_id,
            "metadata": self.metadata.to_dict(),
            "vcv_accession": self.vcv_accession,
            "vcv_version": self.vcv_version,
            "variation_id": self.variation_id,
            "date_last_updated": self.date_last_updated,
            "canonical_spdi": self.canonical_spdi,
            "clinvar_grch38_assembly_accession": (
                self.clinvar_grch38_assembly_accession
            ),
            "aggregate_classification": self.aggregate_classification,
            "aggregate_review_status": self.aggregate_review_status,
            "condition_names": list(self.condition_names),
            "condition_references": list(self.condition_references),
            "conflict": self.conflict,
            "submissions": [
                submission.to_dict()
                for submission in self.submissions
            ],
        }


@dataclass(frozen=True)
class MinimumEvidenceSnapshotResult:
    canonical_model_source_vcf_sha256: str | None
    canonical_model_normalization_output_sha256: str | None
    source_registry_id: str | None
    items: tuple[ClinVarEvidenceItem, ...]
    rules: tuple[EvidenceSnapshotRuleResult, ...]
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
                "SNAPSHOT_VERIFIED" if self.passed else "FAIL"
            ),
            "canonical_payload": {
                "artifact_kind": ARTIFACT_KIND,
                "canonical_model_source_vcf_sha256": (
                    self.canonical_model_source_vcf_sha256
                ),
                "canonical_model_normalization_output_sha256": (
                    self.canonical_model_normalization_output_sha256
                ),
                "source_registry_id": self.source_registry_id,
                "evidence_item_count": len(self.items),
                "items": [item.to_dict() for item in self.items],
                "rules": [rule.to_dict() for rule in self.rules],
                "errors": list(self.errors),
            },
            "availability": "AVAILABLE" if self.passed else "BLOCKED",
            "limitations": [
                "Minimum E1A snapshot currently preserves ClinVar VCV aggregate and SCV evidence only.",
                "Conflicts are preserved and are never reduced by voting or local consensus.",
                "No ACMG/AMP classification, ClinGen/VCEP application, gene-disease validity, actionability, phenotype matching, or clinical interpretation is performed.",
                "Network retrieval is outside this pure capability; exact retrieval bytes and metadata must be supplied.",
            ],
            "executor_id": "omnigenis.python-stdlib",
            "executor_version": CAPABILITY_VERSION,
            "adapter_version": None,
            "model_id": None,
            "resource_release": None,
            "reference_bundle": None,
            "execution_profile": "minimum-evidence-snapshot-e1a-v1",
            "raw_artifact_refs": [
                item.metadata.result_sha256
                for item in self.items
            ],
            "provenance_refs": [
                SOURCE_ID,
                "canonical-genomic-model",
            ],
        }
def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HEX for character in value)
    )


def _local_name(element: ET.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def _children(element: ET.Element, name: str) -> list[ET.Element]:
    return [
        child
        for child in element
        if _local_name(child) == name
    ]


def _descendants(element: ET.Element, name: str) -> list[ET.Element]:
    return [
        child
        for child in element.iter()
        if _local_name(child) == name
    ]


def _first_text(element: ET.Element, name: str) -> str | None:
    for child in element.iter():
        if _local_name(child) == name:
            value = (child.text or "").strip()
            if value:
                return value
    return None


def _condition_context(
    element: ET.Element,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    names: list[str] = []
    references: list[str] = []
    seen_names: set[str] = set()
    seen_references: set[str] = set()
    traitsets = _descendants(element, "TraitSet")
    for traitset in traitsets:
        for child in traitset.iter():
            if (
                _local_name(child) == "ElementValue"
                and child.attrib.get("Type") == "Preferred"
            ):
                value = (child.text or "").strip()
                if value and value not in seen_names:
                    seen_names.add(value)
                    names.append(value)
            if _local_name(child) == "XRef":
                db = child.attrib.get("DB", "").strip()
                identifier = child.attrib.get("ID", "").strip()
                if db and identifier:
                    value = f"{db}:{identifier}"
                    if value not in seen_references:
                        seen_references.add(value)
                        references.append(value)
    return tuple(names), tuple(references)


def _rule(
    rule_id: str,
    passed: bool,
    detail: str,
) -> EvidenceSnapshotRuleResult:
    return EvidenceSnapshotRuleResult(
        rule_id=rule_id,
        status="PASS" if passed else "FAIL",
        detail=detail,
    )


def _rules(
    states: dict[str, tuple[bool, str]],
) -> tuple[EvidenceSnapshotRuleResult, ...]:
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
    source_registry_id: str | None,
    states: dict[str, tuple[bool, str]],
    errors: list[str],
    items: tuple[ClinVarEvidenceItem, ...] = (),
) -> MinimumEvidenceSnapshotResult:
    return MinimumEvidenceSnapshotResult(
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
        source_registry_id=source_registry_id,
        items=items,
        rules=_rules(states),
        errors=tuple(errors),
    )
def _source_contract_verified(source_registry: object) -> tuple[bool, str | None]:
    if not isinstance(source_registry, Mapping):
        return False, None
    if (
        source_registry.get("registry_id") != SOURCE_REGISTRY_ID
        or source_registry.get("schema_version") != "1.0.0"
    ):
        return False, None
    sources = source_registry.get("sources")
    if not isinstance(sources, list):
        return False, None
    matches = [
        source
        for source in sources
        if isinstance(source, Mapping)
        and source.get("source_id") == SOURCE_ID
    ]
    if len(matches) != 1:
        return False, None
    source = matches[0]
    expected = {
        "source_id": SOURCE_ID,
        "provider": "NCBI ClinVar",
        "version_release": "Per-record VCV accession.version snapshots",
        "retrieval_date": "2026-09-24",
        "source_url": "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/efetch.fcgi",
        "terms_url": "https://www.ncbi.nlm.nih.gov/clinvar/docs/maintenance_use/",
        "license": "ClinVar data are freely available for any use; attribution to ClinVar requested.",
        "rights_status": "UNRESTRICTED_USE_WITH_ATTRIBUTION_REQUESTED",
        "local_reference_use": "ALLOWED",
        "redistribution": "ALLOWED_WITH_ATTRIBUTION_REQUESTED",
        "lifecycle": "MUTABLE_PER_RECORD_SNAPSHOT",
        "limitations": "NIH does not independently verify submitted information; not intended for direct diagnostic use without genetics professional review.",
        "known_issues": "ClinVar is continuously updated and classifications may conflict; every EvidenceSnapshot must pin accession.version, retrieval time, and content digest.",
        "replacement_path": "Retrieve the required VCV accession.version, record retrieval time and SHA-256, and create a new EvidenceSnapshot rather than mutating an existing one.",
        "attribution": "CLINVAR_ATTRIBUTION_REQUESTED",
    }
    return dict(source) == expected, SOURCE_REGISTRY_ID


def _canonical_model_verified(model: object) -> bool:
    if not isinstance(model, CanonicalGenomicModelResult):
        return False
    if (
        type(model.rules) is not tuple
        or not all(
            isinstance(rule, CanonicalGenomicModelRuleResult)
            for rule in model.rules
        )
        or type(model.variants) is not tuple
        or not all(
            isinstance(variant, CanonicalGenomicVariant)
            for variant in model.variants
        )
        or not model.passed
    ):
        return False
    ids = [variant.canonical_variant_id for variant in model.variants]
    return (
        len(ids) == len(set(ids))
        and all(
            re.fullmatch(
                r"omnigenis:small-variant:v1:sha256:[0-9a-f]{64}",
                value,
            )
            for value in ids
        )
    )


def _validate_checked_at(value: object) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def _validate_metadata(
    value: object,
    xml_bytes: bytes,
) -> tuple[EvidenceSnapshotMetadataRecord | None, str | None]:
    if not isinstance(value, Mapping) or frozenset(value) != _METADATA_KEYS:
        return None, "evidence_metadata_invalid"
    if (
        value.get("schema_version") != "1.0.0"
        or not isinstance(value.get("snapshot_id"), str)
        or not value.get("snapshot_id")
        or len(value.get("snapshot_id", "")) > 512
        or value.get("source_registry_id") != SOURCE_REGISTRY_ID
        or value.get("version_kind") != "accession.version"
        or not _validate_checked_at(value.get("checked_at"))
        or value.get("mutable") is not True
    ):
        return None, "evidence_metadata_invalid"

    source_version = value.get("source_version")
    if not isinstance(source_version, str) or _VCV_VERSION.fullmatch(source_version) is None:
        return None, "evidence_metadata_invalid"

    expected_locator = LOCATOR_BASE + source_version
    if value.get("locator") != expected_locator:
        return None, "evidence_metadata_locator_invalid"
    if value.get("retrieval_method") != RETRIEVAL_METHOD:
        return None, "evidence_metadata_retrieval_invalid"

    digest = value.get("result_sha256")
    if not _is_sha256(digest):
        return None, "evidence_metadata_invalid"
    if digest != _sha256_bytes(xml_bytes):
        return None, "evidence_metadata_digest_mismatch"

    return (
        EvidenceSnapshotMetadataRecord(
            schema_version="1.0.0",
            snapshot_id=str(value["snapshot_id"]),
            source_registry_id=SOURCE_REGISTRY_ID,
            source_version=source_version,
            version_kind="accession.version",
            checked_at=str(value["checked_at"]),
            locator=expected_locator,
            retrieval_method=RETRIEVAL_METHOD,
            result_sha256=digest,
            mutable=True,
        ),
        None,
    )
def _vcf_to_spdi(
    contig: str,
    position_1_based: int,
    ref: str,
    alt: str,
) -> str:
    position_0_based = position_1_based - 1
    deleted = ref
    inserted = alt
    while deleted and inserted and deleted[-1] == inserted[-1]:
        deleted = deleted[:-1]
        inserted = inserted[:-1]
    while deleted and inserted and deleted[0] == inserted[0]:
        deleted = deleted[1:]
        inserted = inserted[1:]
        position_0_based += 1
    return f"{contig}:{position_0_based}:{deleted}:{inserted}"


def _exactly_one(
    elements: list[ET.Element],
) -> ET.Element | None:
    return elements[0] if len(elements) == 1 else None


def _parse_submission(
    assertion: ET.Element,
) -> tuple[ClinVarSubmissionEvidence | None, str | None]:
    accessions = _descendants(assertion, "ClinVarAccession")
    accession = _exactly_one(accessions)
    if accession is None:
        return None, "clinvar_submission_invalid"
    scv = accession.attrib.get("Accession", "")
    version_raw = accession.attrib.get("Version", "")
    if _SCV.fullmatch(scv) is None or not version_raw.isdigit() or int(version_raw) <= 0:
        return None, "clinvar_submission_invalid"
    submitter = accession.attrib.get("SubmitterName", "").strip()
    date_updated = accession.attrib.get("DateUpdated", "").strip()
    date_created = accession.attrib.get("DateCreated", "").strip()
    if not submitter or not date_updated or not date_created:
        return None, "clinvar_submission_invalid"

    classifications = _descendants(assertion, "Classification")
    classification_node = _exactly_one(classifications)
    if classification_node is None:
        return None, "clinvar_submission_invalid"
    review_status = _first_text(classification_node, "ReviewStatus")
    classification = _first_text(classification_node, "GermlineClassification")
    if not review_status or not classification:
        return None, "clinvar_submission_invalid"
    condition_names, condition_references = _condition_context(assertion)
    if not condition_names and not condition_references:
        return None, "clinvar_submission_invalid"
    evaluated = classification_node.attrib.get("DateLastEvaluated")
    return (
        ClinVarSubmissionEvidence(
            accession=scv,
            version=int(version_raw),
            submitter_name=submitter,
            date_updated=date_updated,
            date_created=date_created,
            date_last_evaluated=(
                evaluated.strip()
                if isinstance(evaluated, str) and evaluated.strip()
                else None
            ),
            review_status=review_status,
            classification=classification,
            condition_names=condition_names,
            condition_references=condition_references,
        ),
        None,
    )


def _parse_clinvar_xml(
    xml_bytes: bytes,
    metadata: EvidenceSnapshotMetadataRecord,
    variant: CanonicalGenomicVariant,
) -> tuple[ClinVarEvidenceItem | None, str | None]:
    if not isinstance(xml_bytes, bytes) or not xml_bytes or len(xml_bytes) > MAX_XML_BYTES:
        return None, "clinvar_xml_invalid"
    upper = xml_bytes.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        return None, "clinvar_xml_unsafe"
    try:
        root = ET.fromstring(xml_bytes)
    except (ET.ParseError, ValueError):
        return None, "clinvar_xml_invalid"
    if _local_name(root) != "ClinVarResult-Set":
        return None, "clinvar_root_invalid"

    archives = _descendants(root, "VariationArchive")
    archive = _exactly_one(archives)
    if archive is None:
        return None, "clinvar_archive_invalid"

    accession = archive.attrib.get("Accession", "")
    version_raw = archive.attrib.get("Version", "")
    variation_id_raw = archive.attrib.get("VariationID", "")
    if (
        _VCV.fullmatch(accession) is None
        or not version_raw.isdigit()
        or int(version_raw) <= 0
        or not variation_id_raw.isdigit()
        or int(variation_id_raw) <= 0
        or archive.attrib.get("RecordType") != "classified"
    ):
        return None, "clinvar_archive_invalid"
    if metadata.source_version != f"{accession}.{version_raw}":
        return None, "clinvar_version_binding_mismatch"
    date_last_updated = archive.attrib.get("DateLastUpdated", "").strip()
    if not date_last_updated:
        return None, "clinvar_archive_invalid"

    status = _first_text(archive, "RecordStatus")
    species = _first_text(archive, "Species")
    if status != "current" or species != "Homo sapiens":
        return None, "clinvar_archive_invalid"

    classified = _exactly_one(_children(archive, "ClassifiedRecord"))
    if classified is None:
        return None, "clinvar_archive_invalid"
    allele = _exactly_one(_children(classified, "SimpleAllele"))
    if allele is None:
        return None, "clinvar_archive_invalid"

    spdi_nodes = _descendants(allele, "CanonicalSPDI")
    spdi_node = _exactly_one(spdi_nodes)
    if spdi_node is None:
        return None, "clinvar_variant_binding_mismatch"
    canonical_spdi = (spdi_node.text or "").strip()
    if canonical_spdi != _vcf_to_spdi(
        variant.contig_accession,
        variant.position_1_based,
        variant.ref,
        variant.alt,
    ):
        return None, "clinvar_variant_binding_mismatch"

    display_locations = [
        location
        for location in _descendants(allele, "SequenceLocation")
        if location.attrib.get("Assembly") == "GRCh38"
        and location.attrib.get("forDisplay") == "true"
    ]
    location = _exactly_one(display_locations)
    if location is None:
        return None, "clinvar_variant_binding_mismatch"
    try:
        position = int(location.attrib.get("positionVCF", ""))
    except ValueError:
        return None, "clinvar_variant_binding_mismatch"
    if (
        location.attrib.get("Accession") != variant.contig_accession
        or position != variant.position_1_based
        or location.attrib.get("referenceAlleleVCF") != variant.ref
        or location.attrib.get("alternateAlleleVCF") != variant.alt
    ):
        return None, "clinvar_variant_binding_mismatch"
    clinvar_assembly = location.attrib.get("AssemblyAccessionVersion", "").strip()
    if not clinvar_assembly:
        return None, "clinvar_variant_binding_mismatch"
    classifications_container = _children(classified, "Classifications")
    aggregate_candidates: list[ET.Element] = []
    if len(classifications_container) == 1:
        aggregate_candidates = _children(
            classifications_container[0],
            "GermlineClassification",
        )
    if not aggregate_candidates:
        aggregate_candidates = _children(
            classified,
            "GermlineClassification",
        )
    aggregate = _exactly_one(aggregate_candidates)
    if aggregate is None:
        return None, "clinvar_aggregate_invalid"
    aggregate_review = _first_text(aggregate, "ReviewStatus")
    aggregate_classification = _first_text(aggregate, "Description")
    if not aggregate_review or not aggregate_classification:
        return None, "clinvar_aggregate_invalid"

    condition_names, condition_references = _condition_context(aggregate)
    if not condition_names and not condition_references:
        direct_traitsets = _children(classified, "TraitSet")
        fallback_names: list[str] = []
        fallback_references: list[str] = []
        for traitset in direct_traitsets:
            names, references = _condition_context(traitset)
            fallback_names.extend(names)
            fallback_references.extend(references)
        condition_names = tuple(dict.fromkeys(fallback_names))
        condition_references = tuple(dict.fromkeys(fallback_references))
    if not condition_names and not condition_references:
        return None, "clinvar_aggregate_invalid"

    assertions = _descendants(classified, "ClinicalAssertion")
    if not assertions:
        return None, "clinvar_submission_invalid"
    submissions: list[ClinVarSubmissionEvidence] = []
    submission_ids: set[tuple[str, int]] = set()
    for assertion in assertions:
        submission, error = _parse_submission(assertion)
        if error is not None or submission is None:
            return None, error or "clinvar_submission_invalid"
        key = (submission.accession, submission.version)
        if key in submission_ids:
            return None, "clinvar_submission_duplicate"
        submission_ids.add(key)
        submissions.append(submission)

    declared_submissions = archive.attrib.get("NumberOfSubmissions", "")
    if (
        not declared_submissions.isdigit()
        or int(declared_submissions) != len(submissions)
    ):
        return None, "clinvar_submission_count_mismatch"

    submission_classes = {
        submission.classification
        for submission in submissions
    }
    review_lower = aggregate_review.lower()
    classification_lower = aggregate_classification.lower()
    conflict = (
        "conflicting" in review_lower
        or "conflicting" in classification_lower
        or len(submission_classes) > 1
    )
    return (
        ClinVarEvidenceItem(
            canonical_variant_id=variant.canonical_variant_id,
            metadata=metadata,
            vcv_accession=accession,
            vcv_version=int(version_raw),
            variation_id=int(variation_id_raw),
            date_last_updated=date_last_updated,
            canonical_spdi=canonical_spdi,
            clinvar_grch38_assembly_accession=clinvar_assembly,
            aggregate_classification=aggregate_classification,
            aggregate_review_status=aggregate_review,
            condition_names=condition_names,
            condition_references=condition_references,
            conflict=conflict,
            submissions=tuple(submissions),
        ),
        None,
    )
def build_minimum_evidence_snapshot(
    *,
    canonical_model: object,
    evidence_items: object,
    source_registry: object,
) -> MinimumEvidenceSnapshotResult:
    """Build a byte-bound minimum ClinVar EvidenceSnapshot for one E1A model."""

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
            source_registry_id=None,
            states=states,
            errors=errors,
        )
    states[RULE_CANONICAL_MODEL] = (
        True,
        "canonical_model_verified",
    )

    source_ok, source_registry_id = _source_contract_verified(
        source_registry
    )
    if not source_ok:
        states[RULE_SOURCE_CONTRACT] = (
            False,
            "clinvar_source_contract_not_verified",
        )
        errors.append("clinvar_source_contract_not_verified")
        return _result(
            canonical_model=canonical_model,
            source_registry_id=source_registry_id,
            states=states,
            errors=errors,
        )
    states[RULE_SOURCE_CONTRACT] = (
        True,
        "clinvar_source_contract_verified",
    )

    if not isinstance(evidence_items, (list, tuple)):
        states[RULE_CARDINALITY] = (
            False,
            "evidence_items_invalid",
        )
        errors.append("evidence_items_invalid")
        return _result(
            canonical_model=canonical_model,
            source_registry_id=source_registry_id,
            states=states,
            errors=errors,
        )

    model_by_id = {
        variant.canonical_variant_id: variant
        for variant in canonical_model.variants
    }
    provided: dict[str, Mapping[str, object]] = {}
    for raw in evidence_items:
        if not isinstance(raw, Mapping):
            states[RULE_CARDINALITY] = (
                False,
                "evidence_items_invalid",
            )
            errors.append("evidence_items_invalid")
            return _result(
                canonical_model=canonical_model,
                source_registry_id=source_registry_id,
                states=states,
                errors=errors,
            )
        if frozenset(raw) != frozenset(
            {"canonical_variant_id", "metadata", "xml_bytes"}
        ):
            states[RULE_CARDINALITY] = (
                False,
                "evidence_items_invalid",
            )
            errors.append("evidence_items_invalid")
            return _result(
                canonical_model=canonical_model,
                source_registry_id=source_registry_id,
                states=states,
                errors=errors,
            )
        variant_id = raw.get("canonical_variant_id")
        if not isinstance(variant_id, str):
            states[RULE_CARDINALITY] = (
                False,
                "evidence_items_invalid",
            )
            errors.append("evidence_items_invalid")
            return _result(
                canonical_model=canonical_model,
                source_registry_id=source_registry_id,
                states=states,
                errors=errors,
            )
        if variant_id in provided:
            states[RULE_CARDINALITY] = (
                False,
                "duplicate_evidence_variant_id",
            )
            errors.append("duplicate_evidence_variant_id")
            return _result(
                canonical_model=canonical_model,
                source_registry_id=source_registry_id,
                states=states,
                errors=errors,
            )
        if variant_id not in model_by_id:
            states[RULE_CARDINALITY] = (
                False,
                "evidence_variant_not_in_model",
            )
            errors.append("evidence_variant_not_in_model")
            return _result(
                canonical_model=canonical_model,
                source_registry_id=source_registry_id,
                states=states,
                errors=errors,
            )
        provided[variant_id] = raw

    if len(provided) != len(model_by_id):
        states[RULE_CARDINALITY] = (
            False,
            "evidence_cardinality_mismatch",
        )
        errors.append("evidence_cardinality_mismatch")
        return _result(
            canonical_model=canonical_model,
            source_registry_id=source_registry_id,
            states=states,
            errors=errors,
        )
    states[RULE_CARDINALITY] = (
        True,
        "one_evidence_item_per_canonical_variant",
    )

    built: list[ClinVarEvidenceItem] = []
    snapshot_ids: set[str] = set()
    vcv_versions: set[str] = set()
    for variant in canonical_model.variants:
        raw = provided[variant.canonical_variant_id]
        xml_bytes = raw.get("xml_bytes")
        if not isinstance(xml_bytes, bytes):
            states[RULE_METADATA] = (
                False,
                "evidence_metadata_invalid",
            )
            errors.append("evidence_metadata_invalid")
            return _result(
                canonical_model=canonical_model,
                source_registry_id=source_registry_id,
                states=states,
                errors=errors,
            )
        metadata, metadata_error = _validate_metadata(
            raw.get("metadata"),
            xml_bytes,
        )
        if metadata_error is not None or metadata is None:
            states[RULE_METADATA] = (
                False,
                metadata_error or "evidence_metadata_invalid",
            )
            errors.append(
                metadata_error or "evidence_metadata_invalid"
            )
            return _result(
                canonical_model=canonical_model,
                source_registry_id=source_registry_id,
                states=states,
                errors=errors,
            )
        if metadata.snapshot_id in snapshot_ids:
            states[RULE_METADATA] = (
                False,
                "duplicate_snapshot_id",
            )
            errors.append("duplicate_snapshot_id")
            return _result(
                canonical_model=canonical_model,
                source_registry_id=source_registry_id,
                states=states,
                errors=errors,
            )
        snapshot_ids.add(metadata.snapshot_id)

        evidence, xml_error = _parse_clinvar_xml(
            xml_bytes,
            metadata,
            variant,
        )
        if xml_error is not None or evidence is None:
            rule_id = (
                RULE_VARIANT_BINDING
                if xml_error == "clinvar_variant_binding_mismatch"
                else RULE_XML
            )
            states[rule_id] = (
                False,
                xml_error or "clinvar_xml_invalid",
            )
            errors.append(xml_error or "clinvar_xml_invalid")
            return _result(
                canonical_model=canonical_model,
                source_registry_id=source_registry_id,
                states=states,
                errors=errors,
            )

        version_key = f"{evidence.vcv_accession}.{evidence.vcv_version}"
        if version_key in vcv_versions:
            states[RULE_PRESERVATION] = (
                False,
                "duplicate_vcv_version",
            )
            errors.append("duplicate_vcv_version")
            return _result(
                canonical_model=canonical_model,
                source_registry_id=source_registry_id,
                states=states,
                errors=errors,
            )
        vcv_versions.add(version_key)
        built.append(evidence)

    states[RULE_METADATA] = (
        True,
        "all_snapshot_metadata_byte_bound",
    )
    states[RULE_XML] = (
        True,
        "all_clinvar_vcv_xml_verified",
    )
    states[RULE_VARIANT_BINDING] = (
        True,
        "all_clinvar_records_bound_to_canonical_variants",
    )
    states[RULE_PRESERVATION] = (
        True,
        "aggregate_and_submission_evidence_preserved",
    )
    return _result(
        canonical_model=canonical_model,
        source_registry_id=source_registry_id,
        states=states,
        errors=errors,
        items=tuple(built),
    )
