"""Bounded HL7 Genomics Reporting 3.0.0 GenomicReport projection."""

from __future__ import annotations
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import re
from types import MappingProxyType

PROFILE_ID="fhir-genomics-reporting-r4"
PROFILE_VERSION="3.0.0"
FHIR_VERSION="4.0.1"
PROFILE_URL="http://hl7.org/fhir/uv/genomics-reporting/StructureDefinition/genomic-report"
_FHIR_ID=re.compile(r"^[A-Za-z0-9\-.]{1,64}$")
_PATIENT_REFERENCE=re.compile(r"^Patient/[A-Za-z0-9\-.]{1,64}$")


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


def _digest(value: object) -> str:
    """Return a deterministic OmniGenis payload SHA-256."""
    raw=json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class FhirGenomicReportResult:
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
            "fhir_version":FHIR_VERSION,
            "status":"PASS" if self.passed else "BLOCKED",
            "payload":_thaw(self.payload),
            "payload_sha256":self.payload_sha256,
            "errors":list(self.errors),
            "limitations":[
                "Report-level GenomicReport projection only.",
                "Subject is optional and explicit-only; no identity inference occurs.",
                "No Observation results, clinical conclusion, recommendation, or presented form is synthesized.",
                "No network or terminology lookup is performed.",
            ],
        }


def _failure(error: str) -> FhirGenomicReportResult:
    """Return one fail-closed projection result."""
    return FhirGenomicReportResult(None,None,(error,))


def project_genomic_report(*,report_id: object,subject_reference: object | None) -> FhirGenomicReportResult:
    """Project a bounded FHIR R4 GenomicReport resource."""
    if not isinstance(report_id,str) or _FHIR_ID.fullmatch(report_id) is None:
        return _failure("report_id_invalid")

    subject=None
    if subject_reference is not None:
        if not isinstance(subject_reference,str) or _PATIENT_REFERENCE.fullmatch(subject_reference) is None:
            return _failure("subject_reference_invalid")
        subject={"reference":subject_reference}

    payload={
        "resourceType":"DiagnosticReport",
        "id":report_id,
        "meta":{"profile":[PROFILE_URL]},
        "status":"final",
        "category":[{
            "coding":[{
                "system":"http://terminology.hl7.org/CodeSystem/v2-0074",
                "code":"GE",
            }]
        }],
        "code":{
            "coding":[{
                "system":"http://loinc.org",
                "code":"51969-4",
            }]
        },
    }
    if subject is not None:
        payload["subject"]=subject
    return FhirGenomicReportResult(_freeze(payload),_digest(payload),())
