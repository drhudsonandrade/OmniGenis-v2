"""Deterministic reference identity verification for the initial E1A profile."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json

CAPABILITY_ID = "reference-identity"
CAPABILITY_VERSION = "1.0.0"
PROFILE_ID = "grch38-p14-ncbi-refseq-autosomal-v1"
ASSEMBLY_ACCESSION = "GCF_000001405.40"

RULE_PROFILE = "REFERENCE_PROFILE_CONTRACT"
RULE_ASSEMBLY = "REFERENCE_ASSEMBLY_IDENTITY"
RULE_FASTA = "REFERENCE_FASTA_IDENTITY"
RULE_REPORT = "REFERENCE_ASSEMBLY_REPORT_IDENTITY"
RULE_BUNDLE = "REFERENCE_BUNDLE_IDENTITY"
RULE_SOURCE = "REFERENCE_SOURCE_REGISTRY"
RULE_RIGHTS = "REFERENCE_USE_RIGHTS"
RULE_CONTIGS = "REFERENCE_CONTIG_COMPATIBILITY"

_HEX = frozenset("0123456789abcdef")
_EXPECTED_AUTOSOMES = tuple(str(number) for number in range(1, 23))


@dataclass(frozen=True)
class ReferenceRuleResult:
    """One independently traceable reference-identity rule result."""

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
class ReferenceIdentityResult:
    """Tool-neutral result for the pinned-reference identity gate."""

    profile_id: str | None
    assembly_accession: str | None
    bundle_sha256: str | None
    rules: tuple[ReferenceRuleResult, ...]

    @property
    def passed(self) -> bool:
        return all(rule.status == "PASS" for rule in self.rules)

    def to_dict(self) -> dict[str, object]:
        verification_status = "VERIFIED" if self.passed else "NOT_VERIFIED"
        return {
            "capability_id": CAPABILITY_ID,
            "capability_version": CAPABILITY_VERSION,
            "canonical_status": "PASS" if self.passed else "FAIL",
            "canonical_payload": {
                "verification_status": verification_status,
                "profile_id": self.profile_id,
                "assembly_accession": self.assembly_accession,
                "bundle_sha256": self.bundle_sha256,
                "rules": [rule.to_dict() for rule in self.rules],
            },
            "availability": "AVAILABLE" if self.passed else "BLOCKED",
            "limitations": [
                "Reference identity only; no variant normalization or calling.",
                "Initial E1A profile is limited to primary autosomes 1-22.",
                "Human-readable reference names are aliases, not identity.",
            ],
            "executor_id": "omnigenis.python-stdlib",
            "executor_version": CAPABILITY_VERSION,
            "adapter_version": None,
            "model_id": None,
            "resource_release": self.assembly_accession,
            "reference_bundle": self.bundle_sha256,
            "execution_profile": "reference-identity-grch38-p14-autosomal-v1",
            "raw_artifact_refs": [],
            "provenance_refs": [
                "source-registry-minimal-e1a-v1",
                "scientific-resource-bom-grch38-p14-ncbi-refseq-autosomal-v1",
            ],
        }


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _is_nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HEX for character in value)
    )


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _rule(rule_id: str, passed: bool, detail: str) -> ReferenceRuleResult:
    return ReferenceRuleResult(rule_id, "PASS" if passed else "FAIL", detail)


def _resource_by_role(
    bom: Mapping[str, object],
    role: str,
) -> Mapping[str, object]:
    resources = bom.get("resources")
    if not isinstance(resources, list):
        return {}
    for resource in resources:
        candidate = _mapping(resource)
        if candidate.get("role") == role:
            return candidate
    return {}


def _source_by_id(
    registry: Mapping[str, object],
    source_id: object,
) -> Mapping[str, object]:
    sources = registry.get("sources")
    if not isinstance(sources, list):
        return {}
    for source in sources:
        candidate = _mapping(source)
        if candidate.get("source_id") == source_id:
            return candidate
    return {}


def _resource_metadata_closed(resource: Mapping[str, object]) -> bool:
    required_strings = (
        "resource_id",
        "role",
        "source_id",
        "source_url",
        "version_release",
        "license",
        "use_rights",
        "storage_mode",
        "lifecycle",
        "known_issues",
        "replacement_path",
    )
    return all(_is_nonempty_string(resource.get(field)) for field in required_strings)


def _profile_contract(profile: Mapping[str, object]) -> bool:
    assembly = _mapping(profile.get("assembly"))
    contig_profile = _mapping(profile.get("contig_alias_profile"))
    source_ref = _mapping(profile.get("source_registry_ref"))
    bom_ref = _mapping(profile.get("resource_bom_ref"))
    supported = _mapping(profile.get("supported_domain"))
    return all(
        (
            profile.get("schema_version") == "1.0.0",
            profile.get("profile_id") == PROFILE_ID,
            profile.get("profile_version") == "1.0.0",
            assembly.get("refseq_accession") == ASSEMBLY_ACCESSION,
            _is_nonempty_string(assembly.get("name")),
            _is_nonempty_string(source_ref.get("registry_id")),
            _is_nonempty_string(source_ref.get("source_id")),
            _is_nonempty_string(bom_ref.get("bom_id")),
            _is_sha256(bom_ref.get("bundle_sha256")),
            _is_nonempty_string(contig_profile.get("profile_id")),
            _is_sha256(contig_profile.get("sha256")),
            isinstance(contig_profile.get("contigs"), list),
            supported.get("reference_scope") == "primary autosomes 1-22 only",
            _is_nonempty_string(profile.get("disable_path")),
        )
    )


def verify_reference_identity(
    profile: Mapping[str, object],
    source_registry: Mapping[str, object],
    resource_bom: Mapping[str, object],
    observation: Mapping[str, object],
) -> ReferenceIdentityResult:
    """Verify a pinned GRCh38.p14 resource identity without reading reference bytes."""
    profile = _mapping(profile)
    source_registry = _mapping(source_registry)
    resource_bom = _mapping(resource_bom)
    observation = _mapping(observation)

    assembly = _mapping(profile.get("assembly"))
    source_ref = _mapping(profile.get("source_registry_ref"))
    bom_ref = _mapping(profile.get("resource_bom_ref"))
    contig_profile = _mapping(profile.get("contig_alias_profile"))
    validation = _mapping(resource_bom.get("validation"))

    contract_ok = _profile_contract(profile)
    profile_rule = _rule(
        RULE_PROFILE,
        contract_ok,
        "profile_contract_valid" if contract_ok else "profile_contract_invalid",
    )

    assembly_ok = all(
        (
            assembly.get("name") == "GRCh38.p14",
            assembly.get("refseq_accession") == ASSEMBLY_ACCESSION,
            assembly.get("genbank_accession") == "GCA_000001405.29",
            observation.get("assembly_refseq_accession") == ASSEMBLY_ACCESSION,
        )
    )
    assembly_rule = _rule(
        RULE_ASSEMBLY,
        assembly_ok,
        "assembly_identity_match" if assembly_ok else "assembly_identity_mismatch",
    )

    fasta = _resource_by_role(resource_bom, "reference_fasta_transport")
    fasta_ok = all(
        (
            _is_sha256(fasta.get("sha256")),
            fasta.get("sha256") == observation.get("fasta_transport_sha256"),
            fasta.get("size_bytes") == observation.get("fasta_transport_size_bytes"),
            _is_sha256(fasta.get("content_sha256")),
            fasta.get("content_sha256") == observation.get("fasta_content_sha256"),
            fasta.get("content_size_bytes") == observation.get("fasta_content_size_bytes"),
            fasta.get("upstream_md5") == observation.get("fasta_upstream_md5"),
            observation.get("upstream_md5_match") is True,
            validation.get("upstream_md5_match") is True,
        )
    )
    fasta_rule = _rule(
        RULE_FASTA,
        fasta_ok,
        "fasta_transport_and_content_identity_match"
        if fasta_ok
        else "fasta_identity_mismatch",
    )

    report = _resource_by_role(resource_bom, "assembly_report")
    report_ok = all(
        (
            _is_sha256(report.get("sha256")),
            report.get("sha256") == observation.get("assembly_report_sha256"),
            report.get("size_bytes") == observation.get("assembly_report_size_bytes"),
            validation.get("assembly_report_refseq_count")
            == observation.get("assembly_report_refseq_count"),
            validation.get("fasta_sequence_count")
            == observation.get("fasta_sequence_count"),
            observation.get("assembly_report_refseq_count")
            == observation.get("fasta_sequence_count"),
        )
    )
    report_rule = _rule(
        RULE_REPORT,
        report_ok,
        "assembly_report_identity_match" if report_ok else "assembly_report_mismatch",
    )

    descriptor = resource_bom.get("bundle_descriptor")
    computed_bundle_sha = _canonical_sha256(descriptor)
    declared_bundle_sha = resource_bom.get("bundle_sha256")
    resources = resource_bom.get("resources")
    resource_metadata_ok = (
        isinstance(resources, list)
        and len(resources) == 2
        and all(_resource_metadata_closed(_mapping(item)) for item in resources)
    )
    bundle_ok = all(
        (
            resource_bom.get("schema_version") == "1.0.0",
            resource_bom.get("profile_id") == PROFILE_ID,
            _is_sha256(declared_bundle_sha),
            declared_bundle_sha == computed_bundle_sha,
            bom_ref.get("bundle_sha256") == declared_bundle_sha,
            bom_ref.get("bom_id") == resource_bom.get("bom_id"),
            resource_metadata_ok,
        )
    )
    bundle_rule = _rule(
        RULE_BUNDLE,
        bundle_ok,
        "bundle_identity_match" if bundle_ok else "bundle_identity_mismatch",
    )

    source_id = source_ref.get("source_id")
    source = _source_by_id(source_registry, source_id)
    source_ok = all(
        (
            source_registry.get("schema_version") == "1.0.0",
            source_registry.get("registry_id") == source_ref.get("registry_id"),
            source_registry.get("registry_id")
            == resource_bom.get("source_registry_id"),
            source_id == resource_bom.get("source_id"),
            source.get("refseq_assembly_accession") == ASSEMBLY_ACCESSION,
            source.get("assembly_name") == "GRCh38.p14",
            isinstance(source.get("source_url"), str)
            and source.get("source_url", "").startswith("https://ftp.ncbi.nlm.nih.gov/"),
        )
    )
    source_rule = _rule(
        RULE_SOURCE,
        source_ok,
        "source_registry_binding_match" if source_ok else "source_registry_mismatch",
    )

    rights_ok = all(
        (
            source.get("rights_status") == "DOCUMENTED_WITH_OBLIGATIONS",
            source.get("local_reference_use") == "ALLOWED_WITH_NCBI_CAVEAT",
            source.get("redistribution")
            == "NCBI_NO_RESTRICTION_WITH_THIRD_PARTY_RIGHTS_CAVEAT",
            source.get("lifecycle") == "PINNED",
            _is_nonempty_string(source.get("license")),
            _is_nonempty_string(source.get("limitations")),
            _is_nonempty_string(source.get("known_issues")),
            _is_nonempty_string(source.get("replacement_path")),
            isinstance(source.get("terms_url"), str)
            and source.get("terms_url", "").startswith("https://"),
        )
    )
    rights_rule = _rule(
        RULE_RIGHTS,
        rights_ok,
        "rights_state_documented_with_caveat"
        if rights_ok
        else "rights_state_not_closed",
    )

    configured_contigs = contig_profile.get("contigs")
    observed_contigs = observation.get("autosomal_contigs")
    configured_hash = (
        _canonical_sha256(configured_contigs)
        if isinstance(configured_contigs, list)
        else None
    )
    observed_hash = (
        _canonical_sha256(observed_contigs)
        if isinstance(observed_contigs, list)
        else None
    )
    molecules = (
        tuple(str(_mapping(item).get("assigned_molecule")) for item in configured_contigs)
        if isinstance(configured_contigs, list)
        else ()
    )
    refseq_accessions = (
        tuple(_mapping(item).get("refseq_accession") for item in configured_contigs)
        if isinstance(configured_contigs, list)
        else ()
    )
    contigs_ok = all(
        (
            isinstance(configured_contigs, list),
            isinstance(observed_contigs, list),
            configured_contigs == observed_contigs,
            len(configured_contigs) == 22 if isinstance(configured_contigs, list) else False,
            molecules == _EXPECTED_AUTOSOMES,
            len(refseq_accessions) == len(set(refseq_accessions)),
            all(
                _mapping(item).get("sequence_role") == "assembled-molecule"
                and isinstance(_mapping(item).get("sequence_length"), int)
                and _mapping(item).get("sequence_length", 0) > 0
                and _is_nonempty_string(_mapping(item).get("ucsc_style_name"))
                for item in configured_contigs
            )
            if isinstance(configured_contigs, list)
            else False,
            configured_hash == contig_profile.get("sha256"),
            observed_hash == contig_profile.get("sha256"),
            validation.get("autosomal_contig_count") == 22,
            validation.get("autosomal_contig_profile_sha256")
            == contig_profile.get("sha256"),
        )
    )
    contig_rule = _rule(
        RULE_CONTIGS,
        contigs_ok,
        "primary_autosome_contig_profile_match"
        if contigs_ok
        else "contig_profile_mismatch",
    )

    bundle_value = declared_bundle_sha if _is_sha256(declared_bundle_sha) else None
    assembly_value = assembly.get("refseq_accession")
    return ReferenceIdentityResult(
        profile_id=profile.get("profile_id")
        if _is_nonempty_string(profile.get("profile_id"))
        else None,
        assembly_accession=assembly_value
        if _is_nonempty_string(assembly_value)
        else None,
        bundle_sha256=bundle_value,
        rules=(
            profile_rule,
            assembly_rule,
            fasta_rule,
            report_rule,
            bundle_rule,
            source_rule,
            rights_rule,
            contig_rule,
        ),
    )
