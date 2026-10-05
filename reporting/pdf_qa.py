"""RPT-12 fail-closed post-render PDF candidate validation."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from io import BytesIO
import re
from types import MappingProxyType
from collections.abc import Mapping

ROADMAP_ID="RPT-12"
_SHA256=re.compile(r"^[0-9a-f]{64}$")
_SENSITIVE=(
    re.compile(r"(?:^|[\s=:])(?:token|password|secret|credential|api[_-]?key)\s*=",re.I),
    re.compile(r"(?:/srv/|/home/|[A-Za-z]:\\Users\\)",re.I),
)


@dataclass(frozen=True)
class PdfCandidateValidation:
    """Immutable decision for one newly rendered PDF candidate."""

    pdf_sha256: str | None
    page_count: int | None
    metadata: Mapping[str,str]
    accessibility_prerequisites: str
    errors: tuple[str,...]

    @property
    def passed(self) -> bool:
        """Return whether the candidate can proceed to later RPT-12 gates."""
        return not self.errors

    def to_dict(self) -> dict[str,object]:
        """Return a detached JSON-compatible validation record."""
        return {
            "roadmap_id":ROADMAP_ID,
            "status":"PASS" if self.passed else "BLOCKED",
            "pdf_sha256":self.pdf_sha256,
            "page_count":self.page_count,
            "metadata":dict(self.metadata),
            "accessibility_prerequisites":self.accessibility_prerequisites,
            "errors":list(self.errors),
            "limitations":[
                "This gate validates post-render integrity, structure, metadata hygiene, and accessibility prerequisites only.",
                "Visual QA, tagged-PDF semantics, reading order, and full accessibility conformance are not established by this unit.",
                "PDF remains a derived artifact and is never scientific source of truth.",
            ],
        }


def _result(*,digest=None,page_count=None,metadata=None,accessibility="BLOCKED",errors=()):
    """Build one immutable validation result."""
    return PdfCandidateValidation(
        digest,page_count,MappingProxyType(dict(metadata or {})),accessibility,tuple(errors)
    )


def validate_pdf_candidate(
    *,
    pdf_bytes: object,
    expected_pdf_sha256: object,
    expected_author: object,
    expected_language: object,
) -> PdfCandidateValidation:
    """Validate one newly rendered candidate without promoting it to FINAL."""
    errors=[]
    if not isinstance(pdf_bytes,bytes) or not pdf_bytes.startswith(b"%PDF-"):
        return _result(errors=("pdf_structure_invalid",))
    digest=hashlib.sha256(pdf_bytes).hexdigest()
    if not isinstance(expected_pdf_sha256,str) or _SHA256.fullmatch(expected_pdf_sha256) is None:
        errors.append("expected_pdf_digest_invalid")
    elif digest != expected_pdf_sha256:
        errors.append("pdf_digest_mismatch")

    try:
        from pypdf import PdfReader
        reader=PdfReader(BytesIO(pdf_bytes),strict=True)
        if reader.is_encrypted:
            errors.append("encrypted_pdf_forbidden")
            return _result(digest=digest,metadata={},errors=errors)
        page_count=len(reader.pages)
        if page_count < 1:
            errors.append("pdf_structure_invalid")
        raw_metadata=reader.metadata or {}
        metadata={str(k):str(v) for k,v in raw_metadata.items() if v is not None}
    except Exception:
        return _result(digest=digest,errors=tuple(errors)+("pdf_structure_invalid",))

    author=metadata.get("/Author")
    language=metadata.get("/Lang")
    if not isinstance(expected_author,str) or not expected_author.strip() or author != expected_author.strip():
        errors.append("pdf_author_mismatch")
    if not isinstance(expected_language,str) or not expected_language.strip() or language != expected_language.strip():
        errors.append("pdf_language_mismatch")
    if any(pattern.search(value) for value in metadata.values() for pattern in _SENSITIVE):
        errors.append("pdf_metadata_sensitive")

    accessibility="PASS" if author == str(expected_author).strip() and language == str(expected_language).strip() else "BLOCKED"
    return _result(
        digest=digest,page_count=page_count,metadata=metadata,
        accessibility=accessibility,errors=errors,
    )
