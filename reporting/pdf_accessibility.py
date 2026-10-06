"""RPT-12 structural accessibility validation for newly rendered PDFs."""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO

from reporting.localization import is_supported_report_locale


@dataclass(frozen=True)
class PdfAccessibilityValidation:
    """Immutable result for bounded PDF accessibility prerequisites."""

    language: str | None
    marked: bool
    struct_tree_root: bool
    conformance_claim: str
    errors: tuple[str,...]

    @property
    def passed(self) -> bool:
        """Return whether structural accessibility prerequisites passed."""
        return not self.errors

    def to_dict(self) -> dict[str,object]:
        """Return a detached JSON-compatible validation record."""
        return {
            "status":"PASS" if self.passed else "BLOCKED",
            "language":self.language,
            "marked":self.marked,
            "struct_tree_root":self.struct_tree_root,
            "conformance_claim":self.conformance_claim,
            "errors":list(self.errors),
            "limitations":[
                "This gate checks PDF/UA-1 structural prerequisites only.",
                "Only explicitly activated reporting locales are accepted.",
                "Reading order, alternate-text quality, semantic tag correctness, visual QA, and full PDF/UA conformance are not established.",
            ],
        }


def _failure(error: str) -> PdfAccessibilityValidation:
    """Return one fail-closed accessibility result."""
    return PdfAccessibilityValidation(
        None,False,False,"PDF_UA_1_STRUCTURAL_PREREQUISITES_ONLY",(error,)
    )


def validate_pdf_accessibility_structure(
    *,pdf_bytes: object,expected_language: object
) -> PdfAccessibilityValidation:
    """Validate bounded catalog-level tagged-PDF prerequisites."""
    if not isinstance(pdf_bytes,bytes) or not pdf_bytes.startswith(b"%PDF-"):
        return _failure("pdf_accessibility_structure_invalid")
    try:
        from pypdf import PdfReader
        from pypdf.generic import BooleanObject, DictionaryObject, NameObject
        reader=PdfReader(BytesIO(pdf_bytes),strict=True)
        if reader.is_encrypted:
            return _failure("encrypted_pdf_forbidden")
        root=reader.root_object
        language=root["/Lang"] if "/Lang" in root else None
        mark_info=root.get("/MarkInfo")
        if mark_info is not None:
            mark_info=mark_info.get_object()
        marked_value=(
            mark_info["/Marked"]
            if isinstance(mark_info,DictionaryObject) and "/Marked" in mark_info
            else None
        )
        marked=isinstance(marked_value,BooleanObject) and marked_value.value is True
        struct=root.get("/StructTreeRoot")
        if struct is not None:
            struct=struct.get_object()
        struct_type=(
            struct["/Type"]
            if isinstance(struct,DictionaryObject) and "/Type" in struct
            else None
        )
        struct_present=isinstance(struct_type,NameObject) and struct_type=="/StructTreeRoot"
    except Exception:  # noqa: BLE001 - malformed PDF parser errors must fail closed
        return _failure("pdf_accessibility_structure_invalid")

    errors=[]
    if not marked:
        errors.append("pdf_not_marked")
    if not struct_present:
        errors.append("pdf_struct_tree_missing")
    if (
        not is_supported_report_locale(expected_language)
        or language != expected_language
    ):
        errors.append("pdf_accessibility_language_mismatch")
    return PdfAccessibilityValidation(
        str(language) if language is not None else None,
        marked,
        struct_present,
        "PDF_UA_1_STRUCTURAL_PREREQUISITES_ONLY",
        tuple(errors),
    )
