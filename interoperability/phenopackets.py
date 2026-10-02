"""Minimal GA4GH Phenopackets 2.0 projection for explicit E1A subject context."""

from __future__ import annotations
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from types import MappingProxyType

PROFILE_ID="ga4gh-phenopackets-v2"
PROFILE_VERSION="2.0"
_ALLOWED_FORMATS=frozenset({"vcf","bcf","gvcf"})


def _freeze(value: object) -> object:
    """Recursively freeze retained JSON-compatible values."""
    if isinstance(value,Mapping):
        return MappingProxyType({key:_freeze(item) for key,item in value.items()})
    if isinstance(value,list):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: object) -> object:
    """Return a detached JSON-compatible value."""
    if isinstance(value,Mapping):
        return {key:_thaw(item) for key,item in value.items()}
    if isinstance(value,tuple):
        return [_thaw(item) for item in value]
    return deepcopy(value)


def _nonblank(value: object) -> str | None:
    """Normalize one required non-empty string."""
    if not isinstance(value,str) or not value.strip():
        return None
    return value.strip()


def _digest(value: object) -> str:
    """Return deterministic OmniGenis payload SHA-256."""
    raw=json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class PhenopacketProjectionResult:
    """Immutable result of one bounded Phenopackets projection."""

    payload: Mapping[str,object] | None
    payload_sha256: str | None
    errors: tuple[str,...]

    @property
    def passed(self) -> bool:
        """Return whether all projection gates passed."""
        return not self.errors

    def to_dict(self) -> dict[str,object]:
        """Return a detached JSON-compatible representation."""
        return {
            "profile_id":PROFILE_ID,
            "profile_version":PROFILE_VERSION,
            "status":"PASS" if self.passed else "BLOCKED",
            "payload":_thaw(self.payload),
            "payload_sha256":self.payload_sha256,
            "errors":list(self.errors),
            "limitations":[
                "Minimal Phenopackets 2.0 projection only.",
                "Subject identity is explicit and is never inferred from canonical sample identity.",
                "Phenotypic features, diseases, interpretations, demographics, and medical actions are not synthesized.",
                "No network access or genomic-file retrieval is performed.",
            ],
        }


def _failure(error: str) -> PhenopacketProjectionResult:
    """Return one fail-closed projection result."""
    return PhenopacketProjectionResult(None,None,(error,))


def project_phenopacket(
    *,
    phenopacket_id: object,
    subject_id: object,
    genomic_file_uri: object,
    genomic_file_format: object,
    genome_assembly: object,
    canonical_sample_id: object | None = None,
    created: object = None,
) -> PhenopacketProjectionResult:
    """Project explicit subject and genomic-file context into Phenopackets 2.0."""
    packet_id=_nonblank(phenopacket_id)
    if packet_id is None:
        return _failure("phenopacket_id_required")
    subject=_nonblank(subject_id)
    if subject is None:
        return _failure("explicit_subject_required")
    uri=_nonblank(genomic_file_uri)
    if uri is None:
        return _failure("genomic_file_reference_required")
    file_format=_nonblank(genomic_file_format)
    if file_format is None or file_format.lower() not in _ALLOWED_FORMATS:
        return _failure("unsupported_genomic_file_format")
    assembly=_nonblank(genome_assembly)
    if assembly is None:
        return _failure("genome_assembly_required")
    created_at=_nonblank(created)
    if created_at is None:
        return _failure("metadata_created_required")

    sample=None
    if canonical_sample_id is not None:
        sample=_nonblank(canonical_sample_id)
        if sample is None:
            return _failure("canonical_sample_id_invalid")

    file_attributes={
        "genomeAssembly":assembly,
        "fileFormat":file_format.lower(),
    }
    if sample is not None:
        file_attributes["canonicalSampleId"]=sample

    payload={
        "id":packet_id,
        "subject":{"id":subject},
        "files":[{
            "uri":uri,
            **({"individualToFileIdentifiers":{subject:sample}} if sample is not None else {}),
            "fileAttributes":file_attributes,
        }],
        "metaData":{
            "created":created_at,
            "createdBy":"OmniGenis",
            "phenopacketSchemaVersion":"2.0",
            "resources":[],
        },
    }
    return PhenopacketProjectionResult(_freeze(payload),_digest(payload),())
