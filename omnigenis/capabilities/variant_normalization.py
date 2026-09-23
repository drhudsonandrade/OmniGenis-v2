"""Reference-bound small-variant normalization through a pinned BCFtools adapter."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Iterable

from .reference_identity import (
    RULE_ASSEMBLY,
    RULE_BUNDLE,
    RULE_CONTIGS,
    RULE_FASTA,
    RULE_PROFILE,
    RULE_REPORT,
    RULE_RIGHTS,
    RULE_SOURCE,
    ReferenceIdentityResult,
)
from .vcf_intake import validate_vcf_bytes

CAPABILITY_ID = "reference-bound-small-variant-normalization"
CAPABILITY_VERSION = "1.0.0"
EXECUTOR_ID = "bcftools"
EXECUTOR_VERSION = "1.24"
HTSLIB_VERSION = "1.24"
REFERENCE_PROFILE_ID = "grch38-p14-ncbi-refseq-autosomal-v1"
REFERENCE_ASSEMBLY = "GCF_000001405.40"
REFERENCE_BUNDLE_SHA256 = (
    "1c34b839e1ae36102d003a217f76f1dd57cd1d10b0310cbd9e1d8078c8e88672"
)
ORIGINAL_RECORD_TAG = "OMNIGENIS_ORIGINAL"
SORT_MEMORY = "256M"

RULE_INPUT = "NORMALIZATION_INPUT"
RULE_EXECUTOR = "EXECUTOR_IDENTITY"
RULE_REFERENCE = "REFERENCE_BINDING"
RULE_STRICT_REPARSE = "STRICT_REPARSE"
RULE_CARDINALITY = "CARDINALITY"
RULE_PHASE = "PHASE_SEMANTICS"
RULE_ORDERING = "ORDERING"
RULE_INDEXABILITY = "INDEXABILITY"
RULE_REF_CONCORDANCE = "REF_CONCORDANCE"
RULE_RETENTION = "RETENTION_ACCOUNTING"

_RULE_ORDER = (
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
_ALLOWED_PASS_STATES = frozenset({"PASS", "EXPLICITLY_INVALIDATED"})
_REFERENCE_RULE_IDS = frozenset(
    {
        RULE_PROFILE,
        RULE_ASSEMBLY,
        RULE_FASTA,
        RULE_REPORT,
        RULE_BUNDLE,
        RULE_SOURCE,
        RULE_RIGHTS,
        RULE_CONTIGS,
    }
)
_HEX = frozenset("0123456789abcdef")
_SEQUENCE_ALLELE = re.compile(r"^[ACGT]+$")


@dataclass(frozen=True)
class NormalizationRuleResult:
    """One independently traceable normalization rule result."""

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
class OutputVariantRecord:
    """One normalized output record associated with a source record."""

    output_record_ordinal: int
    chrom: str
    pos: int
    ref: str
    alt: str
    genotype: str | None
    used_alt_index: int | None

    def to_dict(self) -> dict[str, object]:
        return {
            "output_record_ordinal": self.output_record_ordinal,
            "chrom": self.chrom,
            "pos": self.pos,
            "ref": self.ref,
            "alt": self.alt,
            "genotype": self.genotype,
            "used_alt_index": self.used_alt_index,
        }


@dataclass(frozen=True)
class VariantTransformationLedgerEntry:
    """Provenance link from one source VCF record to normalized descendants."""

    source_record_ordinal: int
    source_record_sha256: str
    chrom: str
    pos: int
    record_id: str
    ref: str
    alt: str
    genotype: str | None
    transformation: str
    output_records: tuple[OutputVariantRecord, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "source_record_ordinal": self.source_record_ordinal,
            "source_record_sha256": self.source_record_sha256,
            "source_variant": {
                "chrom": self.chrom,
                "pos": self.pos,
                "id": self.record_id,
                "ref": self.ref,
                "alt": self.alt,
                "genotype": self.genotype,
            },
            "transformation": self.transformation,
            "output_records": [record.to_dict() for record in self.output_records],
        }


@dataclass(frozen=True)
class VariantNormalizationResult:
    """Tool-neutral result for reference-bound VCF normalization."""

    normalized_vcf: bytes | None
    input_sha256: str
    output_sha256: str | None
    input_record_count: int
    output_record_count: int
    reference_content_sha256: str | None
    executor_sha256: str | None
    executor_version: str | None
    rules: tuple[NormalizationRuleResult, ...]
    transformation_ledger: tuple[VariantTransformationLedgerEntry, ...]
    errors: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return (
            not self.errors
            and all(rule.status in _ALLOWED_PASS_STATES for rule in self.rules)
            and self.normalized_vcf is not None
        )

    def to_dict(self) -> dict[str, object]:
        phase_invalidated = any(
            rule.rule_id == RULE_PHASE and rule.status == "EXPLICITLY_INVALIDATED"
            for rule in self.rules
        )
        if not self.passed:
            canonical_status = "FAIL"
        elif phase_invalidated:
            canonical_status = "PASS_WITH_EXPLICIT_INVALIDATION"
        else:
            canonical_status = "PASS"
        return {
            "capability_id": CAPABILITY_ID,
            "capability_version": CAPABILITY_VERSION,
            "canonical_status": canonical_status,
            "canonical_payload": {
                "input_sha256": self.input_sha256,
                "output_sha256": self.output_sha256,
                "input_record_count": self.input_record_count,
                "output_record_count": self.output_record_count,
                "reference_content_sha256": self.reference_content_sha256,
                "executor_sha256": self.executor_sha256,
                "executor_version": self.executor_version,
                "rules": [rule.to_dict() for rule in self.rules],
                "transformation_ledger": [
                    entry.to_dict() for entry in self.transformation_ledger
                ],
                "errors": list(self.errors),
            },
            "availability": "AVAILABLE" if self.passed else "BLOCKED",
            "limitations": [
                "Only the E1A single-sample sequence-resolved SNV/indel profile is supported.",
                "Symbolic alleles, breakends, MNV-only records, gVCF and later capability domains are rejected.",
                "A numeric small-indel size threshold is not invented by this adapter; upstream E1A profile governance owns that scientific boundary.",
                "Multiallelic decomposition explicitly invalidates native multiallelic genotype/phase semantics and retains the source genotype in the transformation ledger.",
                "Input contig names must be directly resolvable by the verified reference FASTA; alias rewriting is not performed by this capability.",
            ],
            "executor_id": EXECUTOR_ID,
            "executor_version": self.executor_version,
            "adapter_version": CAPABILITY_VERSION,
            "model_id": None,
            "resource_release": REFERENCE_ASSEMBLY,
            "reference_bundle": REFERENCE_BUNDLE_SHA256,
            "execution_profile": "bcftools-1.24-grch38-p14-e1a-normalization-v1",
            "raw_artifact_refs": [self.input_sha256],
            "provenance_refs": [
                REFERENCE_PROFILE_ID,
                "bcftools-1.24-release",
            ],
        }


@dataclass(frozen=True)
class _ParsedRecord:
    ordinal: int
    line: str
    chrom: str
    pos: int
    record_id: str
    ref: str
    alt: str
    info: str
    fmt: str
    sample: str
    genotype: str | None

    @property
    def key(self) -> str:
        return f"{self.chrom}|{self.pos}|{self.ref}|{self.alt}"

    @property
    def alt_count(self) -> int:
        return len(self.alt.split(","))


class _ExecutorFailure(RuntimeError):
    def __init__(self, stage: str, reason: str) -> None:
        self.stage = stage
        self.reason = reason
        super().__init__(f"{stage}:{reason}")


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HEX for character in value)
    )


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _extract_genotype(fmt: str, sample: str) -> str | None:
    keys = fmt.split(":")
    if "GT" not in keys:
        return None
    values = sample.split(":")
    index = keys.index("GT")
    return values[index] if index < len(values) else None


def _parse_records(data: bytes) -> tuple[_ParsedRecord, ...]:
    text = data.decode("utf-8").replace("\r\n", "\n")
    records: list[_ParsedRecord] = []
    ordinal = 0
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 10:
            continue
        ordinal += 1
        records.append(
            _ParsedRecord(
                ordinal=ordinal,
                line=line,
                chrom=fields[0],
                pos=int(fields[1]),
                record_id=fields[2],
                ref=fields[3],
                alt=fields[4],
                info=fields[7],
                fmt=fields[8],
                sample=fields[9],
                genotype=_extract_genotype(fields[8], fields[9]),
            )
        )
    return tuple(records)


def _supported_domain_errors(data: bytes, records: Iterable[_ParsedRecord]) -> list[str]:
    text = data.decode("utf-8").replace("\r\n", "\n")
    errors: list[str] = []
    if any(
        line.startswith(f"##INFO=<ID={ORIGINAL_RECORD_TAG},")
        for line in text.splitlines()
    ):
        errors.append("reserved_original_record_tag_declared")
    seen: set[str] = set()
    for record in records:
        if record.key in seen:
            errors.append(f"duplicate_provenance_key_record_{record.ordinal}")
        seen.add(record.key)
        if record.info == ORIGINAL_RECORD_TAG or any(
            item.split("=", 1)[0] == ORIGINAL_RECORD_TAG
            for item in record.info.split(";")
            if item
        ):
            errors.append(f"reserved_original_record_tag_used_{record.ordinal}")
        if not _SEQUENCE_ALLELE.fullmatch(record.ref):
            errors.append(f"unsupported_ref_record_{record.ordinal}")
        for alt in record.alt.split(","):
            if not _SEQUENCE_ALLELE.fullmatch(alt):
                errors.append(f"unsupported_alt_record_{record.ordinal}")
                continue
            if alt == record.ref:
                errors.append(f"nonvariant_allele_record_{record.ordinal}")
            if len(record.ref) == len(alt) and len(record.ref) > 1:
                errors.append(f"mnv_out_of_scope_record_{record.ordinal}")
    return errors


def _rules(
    states: dict[str, tuple[str, str]],
) -> tuple[NormalizationRuleResult, ...]:
    return tuple(
        NormalizationRuleResult(
            rule_id,
            states.get(rule_id, ("NOT_RUN", "not_run"))[0],
            states.get(rule_id, ("NOT_RUN", "not_run"))[1],
        )
        for rule_id in _RULE_ORDER
    )


def _result(
    *,
    data: bytes,
    input_record_count: int,
    states: dict[str, tuple[str, str]],
    errors: list[str],
    normalized_vcf: bytes | None = None,
    output_record_count: int = 0,
    reference_sha256: str | None = None,
    executor_sha256: str | None = None,
    executor_version: str | None = None,
    ledger: tuple[VariantTransformationLedgerEntry, ...] = (),
) -> VariantNormalizationResult:
    return VariantNormalizationResult(
        normalized_vcf=normalized_vcf,
        input_sha256=_sha256_bytes(data),
        output_sha256=_sha256_bytes(normalized_vcf)
        if normalized_vcf is not None
        else None,
        input_record_count=input_record_count,
        output_record_count=output_record_count,
        reference_content_sha256=reference_sha256,
        executor_sha256=executor_sha256,
        executor_version=executor_version,
        rules=_rules(states),
        transformation_ledger=ledger,
        errors=tuple(errors),
    )


def _run(
    args: list[str],
    *,
    cwd: Path,
    timeout_seconds: int,
    stage: str,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            args,
            cwd=cwd,
            check=False,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
            env={
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
                "TZ": "UTC",
            },
        )
    except subprocess.TimeoutExpired as exc:
        raise _ExecutorFailure(stage, "timeout") from exc
    except OSError as exc:
        raise _ExecutorFailure(stage, "os_error") from exc
    if completed.returncode != 0:
        raise _ExecutorFailure(stage, f"exit_{completed.returncode}")
    return completed


def _parse_original_key(info: str) -> tuple[str | None, int | None]:
    prefix = ORIGINAL_RECORD_TAG + "="
    for item in info.split(";"):
        if not item.startswith(prefix):
            continue
        value = item[len(prefix) :]
        parts = value.split("|")
        if len(parts) not in {4, 5}:
            return None, None
        try:
            pos = int(parts[1])
        except ValueError:
            return None, None
        used_alt_index: int | None = None
        if len(parts) == 5:
            try:
                used_alt_index = int(parts[4])
            except ValueError:
                return None, None
            if used_alt_index < 1:
                return None, None
        return f"{parts[0]}|{pos}|{parts[2]}|{parts[3]}", used_alt_index
    return None, None


def _build_ledger(
    source_records: tuple[_ParsedRecord, ...],
    output_records: tuple[_ParsedRecord, ...],
) -> tuple[VariantTransformationLedgerEntry, ...]:
    source_by_key = {record.key: record for record in source_records}
    children: dict[int, list[OutputVariantRecord]] = {
        record.ordinal: [] for record in source_records
    }
    changed: dict[int, bool] = {record.ordinal: False for record in source_records}
    for output in output_records:
        original_key, used_alt_index = _parse_original_key(output.info)
        source_key = original_key or output.key
        source = source_by_key.get(source_key)
        if source is None:
            raise ValueError("unmapped_output_record")
        changed[source.ordinal] = changed[source.ordinal] or original_key is not None
        children[source.ordinal].append(
            OutputVariantRecord(
                output_record_ordinal=output.ordinal,
                chrom=output.chrom,
                pos=output.pos,
                ref=output.ref,
                alt=output.alt,
                genotype=output.genotype,
                used_alt_index=used_alt_index,
            )
        )

    ledger: list[VariantTransformationLedgerEntry] = []
    for source in source_records:
        outputs = tuple(children[source.ordinal])
        if len(outputs) != source.alt_count:
            raise ValueError("source_output_cardinality_mismatch")
        if source.alt_count > 1:
            transformation = (
                "SPLIT_AND_REALIGNED"
                if any(
                    child.chrom != source.chrom
                    or child.pos != source.pos
                    or child.ref != source.ref
                    for child in outputs
                )
                else "SPLIT"
            )
        elif changed[source.ordinal]:
            transformation = "REALIGNED"
        else:
            transformation = "UNCHANGED"
        ledger.append(
            VariantTransformationLedgerEntry(
                source_record_ordinal=source.ordinal,
                source_record_sha256=_sha256_bytes(source.line.encode("utf-8")),
                chrom=source.chrom,
                pos=source.pos,
                record_id=source.record_id,
                ref=source.ref,
                alt=source.alt,
                genotype=source.genotype,
                transformation=transformation,
                output_records=outputs,
            )
        )
    return tuple(ledger)


def normalize_small_variants(
    data: bytes,
    *,
    reference_fasta: str | os.PathLike[str],
    reference_identity: ReferenceIdentityResult,
    bcftools_executable: str | os.PathLike[str],
    expected_executor_sha256: str,
    timeout_seconds: int = 600,
) -> VariantNormalizationResult:
    """Normalize an E1A VCF with exact executor/reference identity checks."""

    states: dict[str, tuple[str, str]] = {}
    errors: list[str] = []
    intake = validate_vcf_bytes(data)
    source_records = _parse_records(data) if intake.is_valid else ()
    if not intake.is_valid:
        states[RULE_INPUT] = ("FAIL", "vcf_intake_invalid")
        errors.append("input_vcf_invalid")
        return _result(
            data=data,
            input_record_count=intake.record_count,
            states=states,
            errors=errors,
        )

    domain_errors = _supported_domain_errors(data, source_records)
    if domain_errors:
        states[RULE_INPUT] = ("FAIL", "unsupported_or_ambiguous_variant_domain")
        errors.extend(domain_errors)
        return _result(
            data=data,
            input_record_count=len(source_records),
            states=states,
            errors=errors,
        )
    states[RULE_INPUT] = ("PASS", "validated_single_sample_sequence_variant_vcf")

    if type(timeout_seconds) is not int or timeout_seconds <= 0:
        states[RULE_EXECUTOR] = ("FAIL", "invalid_timeout")
        errors.append("invalid_timeout")
        return _result(
            data=data,
            input_record_count=len(source_records),
            states=states,
            errors=errors,
        )
    try:
        executable = Path(bcftools_executable).resolve(strict=True)
    except (OSError, TypeError):
        states[RULE_EXECUTOR] = ("FAIL", "executor_path_invalid")
        errors.append("executor_path_invalid")
        return _result(
            data=data,
            input_record_count=len(source_records),
            states=states,
            errors=errors,
        )
    executor_sha256: str | None = None
    executor_version: str | None = None
    if not _is_sha256(expected_executor_sha256):
        states[RULE_EXECUTOR] = ("FAIL", "invalid_expected_executor_digest")
        errors.append("invalid_expected_executor_digest")
        return _result(
            data=data,
            input_record_count=len(source_records),
            states=states,
            errors=errors,
        )
    if not executable.is_file() or not os.access(executable, os.X_OK):
        states[RULE_EXECUTOR] = ("FAIL", "executor_not_executable")
        errors.append("executor_not_executable")
        return _result(
            data=data,
            input_record_count=len(source_records),
            states=states,
            errors=errors,
        )
    try:
        executor_sha256 = _sha256_file(executable)
    except OSError:
        states[RULE_EXECUTOR] = ("FAIL", "executor_identity_read_failed")
        errors.append("executor_identity_read_failed")
        return _result(
            data=data,
            input_record_count=len(source_records),
            states=states,
            errors=errors,
        )
    if executor_sha256 != expected_executor_sha256:
        states[RULE_EXECUTOR] = ("FAIL", "executor_digest_mismatch")
        errors.append("executor_digest_mismatch")
        return _result(
            data=data,
            input_record_count=len(source_records),
            states=states,
            errors=errors,
            executor_sha256=executor_sha256,
        )
    try:
        version = _run(
            [str(executable), "--version"],
            cwd=executable.parent,
            timeout_seconds=min(timeout_seconds, 30),
            stage="version",
        )
    except _ExecutorFailure as exc:
        states[RULE_EXECUTOR] = ("FAIL", "executor_version_probe_failed")
        errors.append(str(exc))
        return _result(
            data=data,
            input_record_count=len(source_records),
            states=states,
            errors=errors,
            executor_sha256=executor_sha256,
        )
    version_lines = version.stdout.splitlines()
    if (
        len(version_lines) < 2
        or version_lines[0] != f"bcftools {EXECUTOR_VERSION}"
        or version_lines[1] != f"Using htslib {HTSLIB_VERSION}"
    ):
        states[RULE_EXECUTOR] = ("FAIL", "executor_version_mismatch")
        errors.append("executor_version_mismatch")
        return _result(
            data=data,
            input_record_count=len(source_records),
            states=states,
            errors=errors,
            executor_sha256=executor_sha256,
        )
    executor_version = EXECUTOR_VERSION
    states[RULE_EXECUTOR] = ("PASS", "bcftools_and_htslib_identity_verified")

    try:
        reference = Path(reference_fasta).resolve(strict=True)
    except (OSError, TypeError):
        states[RULE_REFERENCE] = ("FAIL", "reference_path_invalid")
        errors.append("reference_path_invalid")
        return _result(
            data=data,
            input_record_count=len(source_records),
            states=states,
            errors=errors,
            executor_sha256=executor_sha256,
            executor_version=executor_version,
        )
    reference_sha256: str | None = None
    reference_identity_valid = False
    if isinstance(reference_identity, ReferenceIdentityResult):
        observed_reference_rules = {rule.rule_id for rule in reference_identity.rules}
        reference_identity_valid = all(
            (
                reference_identity.passed,
                observed_reference_rules == _REFERENCE_RULE_IDS,
                len(reference_identity.rules) == len(_REFERENCE_RULE_IDS),
                reference_identity.profile_id == REFERENCE_PROFILE_ID,
                reference_identity.assembly_accession == REFERENCE_ASSEMBLY,
                reference_identity.bundle_sha256 == REFERENCE_BUNDLE_SHA256,
                _is_sha256(reference_identity.fasta_content_sha256),
                type(reference_identity.fasta_content_size_bytes) is int,
                reference_identity.fasta_content_size_bytes > 0,
            )
        )
    if not reference_identity_valid:
        states[RULE_REFERENCE] = ("FAIL", "reference_identity_not_verified")
        errors.append("reference_identity_not_verified")
        return _result(
            data=data,
            input_record_count=len(source_records),
            states=states,
            errors=errors,
            executor_sha256=executor_sha256,
            executor_version=executor_version,
        )
    if not reference.is_file():
        states[RULE_REFERENCE] = ("FAIL", "reference_fasta_missing")
        errors.append("reference_fasta_missing")
        return _result(
            data=data,
            input_record_count=len(source_records),
            states=states,
            errors=errors,
            executor_sha256=executor_sha256,
            executor_version=executor_version,
        )
    expected_reference_size = reference_identity.fasta_content_size_bytes
    reference_stat_before = reference.stat()
    if reference_stat_before.st_size != expected_reference_size:
        states[RULE_REFERENCE] = ("FAIL", "reference_size_mismatch")
        errors.append("reference_size_mismatch")
        return _result(
            data=data,
            input_record_count=len(source_records),
            states=states,
            errors=errors,
            executor_sha256=executor_sha256,
            executor_version=executor_version,
        )
    try:
        reference_sha256 = _sha256_file(reference)
    except OSError:
        states[RULE_REFERENCE] = ("FAIL", "reference_content_read_failed")
        errors.append("reference_content_read_failed")
        return _result(
            data=data,
            input_record_count=len(source_records),
            states=states,
            errors=errors,
            executor_sha256=executor_sha256,
            executor_version=executor_version,
        )
    if reference_sha256 != reference_identity.fasta_content_sha256:
        states[RULE_REFERENCE] = ("FAIL", "reference_content_digest_mismatch")
        errors.append("reference_content_digest_mismatch")
        return _result(
            data=data,
            input_record_count=len(source_records),
            states=states,
            errors=errors,
            reference_sha256=reference_sha256,
            executor_sha256=executor_sha256,
            executor_version=executor_version,
        )
    states[RULE_REFERENCE] = ("PASS", "verified_reference_bytes_bound_to_execution")

    try:
        with tempfile.TemporaryDirectory(prefix="omnigenis-normalize-") as temp_name:
            workspace = Path(temp_name)
            input_path = workspace / "input.vcf"
            reference_link = workspace / "reference.fa"
            normalized_path = workspace / "normalized.vcf"
            sorted_path = workspace / "sorted.vcf"
            compressed_path = workspace / "indexable.vcf.gz"
            roundtrip_path = workspace / "roundtrip.vcf"
            input_path.write_bytes(data)
            os.symlink(reference, reference_link)

            _run(
                [
                    str(executable),
                    "norm",
                    "--no-version",
                    "-c",
                    "e",
                    "-f",
                    "reference.fa",
                    "-m",
                    "-any",
                    "--multi-overlaps",
                    ".",
                    "--old-rec-tag",
                    ORIGINAL_RECORD_TAG,
                    "-Ov",
                    "-o",
                    "normalized.vcf",
                    "input.vcf",
                ],
                cwd=workspace,
                timeout_seconds=timeout_seconds,
                stage="norm",
            )
            states[RULE_REF_CONCORDANCE] = (
                "PASS",
                "bcftools_norm_check_ref_error_mode_passed",
            )

            _run(
                [
                    str(executable),
                    "sort",
                    "-m",
                    SORT_MEMORY,
                    "-T",
                    "sorttmp",
                    "-Ov",
                    "-o",
                    "sorted.vcf",
                    "normalized.vcf",
                ],
                cwd=workspace,
                timeout_seconds=timeout_seconds,
                stage="sort",
            )
            if not sorted_path.is_file():
                raise _ExecutorFailure("sort", "output_missing")
            normalized_vcf = sorted_path.read_bytes()
            source_bcftools_headers = tuple(
                line for line in data.splitlines() if line.startswith(b"##bcftools_")
            )
            output_bcftools_headers = tuple(
                line
                for line in normalized_vcf.splitlines()
                if line.startswith(b"##bcftools_")
            )
            if output_bcftools_headers != source_bcftools_headers:
                raise _ExecutorFailure("metadata", "unexpected_bcftools_header_change")

            post_intake = validate_vcf_bytes(normalized_vcf)
            if not post_intake.is_valid:
                states[RULE_STRICT_REPARSE] = ("FAIL", "normalized_vcf_reparse_failed")
                errors.append("normalized_vcf_reparse_failed")
                return _result(
                    data=data,
                    input_record_count=len(source_records),
                    states=states,
                    errors=errors,
                    reference_sha256=reference_sha256,
                    executor_sha256=executor_sha256,
                    executor_version=executor_version,
                )
            states[RULE_STRICT_REPARSE] = ("PASS", "normalized_vcf_strict_reparse_passed")
            states[RULE_ORDERING] = ("PASS", "sorted_output_reparse_ordering_passed")

            output_records = _parse_records(normalized_vcf)
            expected_output_count = sum(record.alt_count for record in source_records)
            if len(output_records) != expected_output_count:
                states[RULE_CARDINALITY] = ("FAIL", "split_output_cardinality_mismatch")
                errors.append("split_output_cardinality_mismatch")
                return _result(
                    data=data,
                    input_record_count=len(source_records),
                    states=states,
                    errors=errors,
                    normalized_vcf=normalized_vcf,
                    output_record_count=len(output_records),
                    reference_sha256=reference_sha256,
                    executor_sha256=executor_sha256,
                    executor_version=executor_version,
                )
            states[RULE_CARDINALITY] = ("PASS", "all_multiallelic_records_split_once_per_alt")

            try:
                ledger = _build_ledger(source_records, output_records)
            except ValueError:
                states[RULE_RETENTION] = ("FAIL", "transformation_ledger_unresolved")
                errors.append("transformation_ledger_unresolved")
                return _result(
                    data=data,
                    input_record_count=len(source_records),
                    states=states,
                    errors=errors,
                    normalized_vcf=normalized_vcf,
                    output_record_count=len(output_records),
                    reference_sha256=reference_sha256,
                    executor_sha256=executor_sha256,
                    executor_version=executor_version,
                )
            states[RULE_RETENTION] = (
                "PASS",
                "every_source_and_output_record_accounted_for",
            )

            if any(record.alt_count > 1 for record in source_records):
                states[RULE_PHASE] = (
                    "EXPLICITLY_INVALIDATED",
                    "native_multiallelic_genotype_phase_semantics_retained_only_in_ledger",
                )
            else:
                states[RULE_PHASE] = ("PASS", "no_multiallelic_decomposition")

            _run(
                [
                    str(executable),
                    "view",
                    "--no-version",
                    "-Oz",
                    "-o",
                    "indexable.vcf.gz",
                    "sorted.vcf",
                ],
                cwd=workspace,
                timeout_seconds=timeout_seconds,
                stage="compress",
            )
            _run(
                [str(executable), "index", "-f", "indexable.vcf.gz"],
                cwd=workspace,
                timeout_seconds=timeout_seconds,
                stage="index",
            )
            _run(
                [
                    str(executable),
                    "view",
                    "--no-version",
                    "-Ov",
                    "-o",
                    "roundtrip.vcf",
                    "indexable.vcf.gz",
                ],
                cwd=workspace,
                timeout_seconds=timeout_seconds,
                stage="index_reparse",
            )
            csi = Path(str(compressed_path) + ".csi")
            if (
                not csi.is_file()
                or csi.stat().st_size <= 0
                or not roundtrip_path.is_file()
                or roundtrip_path.read_bytes() != normalized_vcf
            ):
                states[RULE_INDEXABILITY] = ("FAIL", "index_roundtrip_mismatch")
                errors.append("index_roundtrip_mismatch")
                return _result(
                    data=data,
                    input_record_count=len(source_records),
                    states=states,
                    errors=errors,
                    normalized_vcf=normalized_vcf,
                    output_record_count=len(output_records),
                    reference_sha256=reference_sha256,
                    executor_sha256=executor_sha256,
                    executor_version=executor_version,
                    ledger=ledger,
                )
            states[RULE_INDEXABILITY] = ("PASS", "csi_index_roundtrip_exact")
    except _ExecutorFailure as exc:
        if exc.stage == "norm":
            states[RULE_REF_CONCORDANCE] = ("FAIL", "normalization_executor_rejected_input")
        errors.append(f"executor_{exc.stage}_{exc.reason}")
        return _result(
            data=data,
            input_record_count=len(source_records),
            states=states,
            errors=errors,
            reference_sha256=reference_sha256,
            executor_sha256=executor_sha256,
            executor_version=executor_version,
        )
    except OSError:
        errors.append("workspace_io_error")
        return _result(
            data=data,
            input_record_count=len(source_records),
            states=states,
            errors=errors,
            reference_sha256=reference_sha256,
            executor_sha256=executor_sha256,
            executor_version=executor_version,
        )

    try:
        reference_stat_after = reference.stat()
        reference_sha256_after = _sha256_file(reference)
    except OSError:
        states[RULE_REFERENCE] = ("FAIL", "reference_missing_after_execution")
        errors.append("reference_missing_after_execution")
        return _result(
            data=data,
            input_record_count=len(source_records),
            states=states,
            errors=errors,
            reference_sha256=reference_sha256,
            executor_sha256=executor_sha256,
            executor_version=executor_version,
        )
    if (
        reference_stat_after.st_dev != reference_stat_before.st_dev
        or reference_stat_after.st_ino != reference_stat_before.st_ino
        or reference_stat_after.st_size != reference_stat_before.st_size
        or reference_stat_after.st_mtime_ns != reference_stat_before.st_mtime_ns
        or reference_sha256_after != reference_identity.fasta_content_sha256
    ):
        states[RULE_REFERENCE] = ("FAIL", "reference_changed_during_execution")
        errors.append("reference_changed_during_execution")
        return _result(
            data=data,
            input_record_count=len(source_records),
            states=states,
            errors=errors,
            reference_sha256=reference_sha256,
            executor_sha256=executor_sha256,
            executor_version=executor_version,
        )

    try:
        executor_sha256_after = _sha256_file(executable)
    except OSError:
        executor_sha256_after = None
    if executor_sha256_after != expected_executor_sha256:
        states[RULE_EXECUTOR] = ("FAIL", "executor_changed_during_execution")
        errors.append("executor_changed_during_execution")
        return _result(
            data=data,
            input_record_count=len(source_records),
            states=states,
            errors=errors,
            reference_sha256=reference_sha256,
            executor_sha256=executor_sha256,
            executor_version=executor_version,
        )

    return _result(
        data=data,
        input_record_count=len(source_records),
        states=states,
        errors=errors,
        normalized_vcf=normalized_vcf,
        output_record_count=len(output_records),
        reference_sha256=reference_sha256,
        executor_sha256=executor_sha256,
        executor_version=executor_version,
        ledger=ledger,
    )
