"""Bounded GA4GH VRS 2.0 Allele projection for the E1A small-variant path."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from types import MappingProxyType
from collections.abc import Mapping

PROFILE_ID = "ga4gh-vrs-v2"
PROFILE_VERSION = "2.0"
_ALLOWED_BASES = frozenset("ACGTN")


def _freeze(value: object) -> object:
    """Recursively freeze retained JSON-compatible values."""
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: object) -> object:
    """Return a detached JSON-compatible value."""
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return deepcopy(value)


def _digest(value: object) -> str:
    """Return a deterministic OmniGenis payload SHA-256, not a VRS identifier."""
    raw=json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def _literal_allele(value: object) -> str | None:
    """Normalize a literal nucleotide allele accepted by the E1A profile."""
    if not isinstance(value,str):
        return None
    allele=value.strip().upper()
    if not allele or any(base not in _ALLOWED_BASES for base in allele):
        return None
    return allele


@dataclass(frozen=True)
class VrsProjectionResult:
    """Immutable result of one bounded VRS Allele projection."""

    payload: Mapping[str,object] | None
    payload_sha256: str | None
    vrs_computed_identifier: None
    errors: tuple[str,...]

    @property
    def passed(self) -> bool:
        """Return whether the projection passed all adapter gates."""
        return not self.errors

    @property
    def profile_id(self) -> str:
        """Return the pinned interoperability profile identity."""
        return PROFILE_ID

    def to_dict(self) -> dict[str,object]:
        """Return a detached JSON-compatible representation."""
        return {
            "profile_id":PROFILE_ID,
            "profile_version":PROFILE_VERSION,
            "status":"PASS" if self.passed else "BLOCKED",
            "payload":_thaw(self.payload),
            "payload_sha256":self.payload_sha256,
            "vrs_computed_identifier":None,
            "errors":list(self.errors),
            "limitations":[
                "E1A literal SNV/small-indel Allele projection only.",
                "refgetAccession must be supplied by an explicit verified binding.",
                "No VRS computed identifier is claimed by this adapter unit.",
                "No network access or reference lookup is performed."
            ],
        }


def _failure(error: str) -> VrsProjectionResult:
    """Return one fail-closed adapter result."""
    return VrsProjectionResult(None,None,None,(error,))


def project_vrs_allele(
    *,
    contig_accession: object,
    position_1_based: object,
    ref: object,
    alt: object,
    refget_accession: object,
    bound_contig_accession: object,
) -> VrsProjectionResult:
    """Project one canonical E1A variant into a bounded VRS 2.0 Allele."""
    if not isinstance(contig_accession,str) or not contig_accession.strip():
        return _failure("unsupported_canonical_variant")
    if not isinstance(position_1_based,int) or isinstance(position_1_based,bool) or position_1_based < 1:
        return _failure("unsupported_canonical_variant")
    ref_allele=_literal_allele(ref)
    alt_allele=_literal_allele(alt)
    if ref_allele is None or alt_allele is None:
        return _failure("unsupported_canonical_variant")

    if not isinstance(refget_accession,str) or not refget_accession.strip():
        return _failure("refget_binding_required")
    if (
        not isinstance(bound_contig_accession,str)
        or bound_contig_accession.strip() != contig_accession.strip()
    ):
        return _failure("refget_binding_mismatch")

    start=position_1_based-1
    payload={
        "type":"Allele",
        "location":{
            "type":"SequenceLocation",
            "sequenceReference":{
                "type":"SequenceReference",
                "refgetAccession":refget_accession.strip(),
            },
            "start":start,
            "end":start+len(ref_allele),
        },
        "state":{
            "type":"LiteralSequenceExpression",
            "sequence":alt_allele,
        },
    }
    digest=_digest(payload)
    return VrsProjectionResult(_freeze(payload),digest,None,())
