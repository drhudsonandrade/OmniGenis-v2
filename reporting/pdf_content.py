"""Bind a candidate PDF's extracted text to an exact localized Presentation IR.

This verifies text content only, not its visual appearance, scientific meaning,
accessibility semantics, privacy metadata, or authorization for final release.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

from reporting._pdf_content_worker import (
    ERRORS as WORKER_ERRORS, MAX_PAGES, MAX_PDF_BYTES, MAX_TEXT_CHARS,
    WALL_SECONDS, normalize_stream,
)
from reporting.localization import is_supported_report_locale

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_WORKER = Path(__file__).with_name("_pdf_content_worker.py")


def _is_digest(value: object) -> bool:
    """Accept only canonical lowercase SHA-256 identities."""
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class PdfContentValidation:
    """Immutable content evidence with no retained input or extracted report text."""

    ir_sha256: str | None
    pdf_sha256: str | None
    expected_text_sha256: str | None
    extracted_text_sha256: str | None
    page_count: int | None
    errors: tuple[str, ...]

    def __post_init__(self) -> None:
        """Reject success-looking records with missing or contradictory evidence."""
        if not isinstance(self.errors, tuple) or any(not isinstance(e, str) or not e for e in self.errors):
            raise ValueError("invalid content errors")
        if not self.errors and (
            not all(_is_digest(v) for v in (self.ir_sha256, self.pdf_sha256,
                                           self.expected_text_sha256, self.extracted_text_sha256))
            or self.expected_text_sha256 != self.extracted_text_sha256
            or type(self.page_count) is not int or not 1 <= self.page_count <= MAX_PAGES
        ):
            raise ValueError("incomplete content verification evidence")

    @property
    def passed(self) -> bool:
        """Return whether the bounded text-content comparison passed."""
        return not self.errors

    def to_dict(self) -> dict[str, object]:
        """Return detached, content-free evidence without promoting a release."""
        return {
            "status": "PASS" if self.passed else "BLOCKED",
            "conformance_scope": "PDF_TEXT_CONTENT_ONLY",
            "release_authorization": "NOT_ESTABLISHED",
            "ir_sha256": self.ir_sha256, "pdf_sha256": self.pdf_sha256,
            "expected_text_sha256": self.expected_text_sha256,
            "extracted_text_sha256": self.extracted_text_sha256,
            "page_count": self.page_count, "errors": list(self.errors),
            "limitations": [
                "Only newly generated PDFs from the current localized semantic-section adapter are supported.",
                "CR, LF and form-feed are ignored; other whitespace, case, punctuation and values are preserved.",
                "Text extraction does not establish visible glyphs, layout, tag semantics or reading-order quality.",
                "Image-only or blank pages fail closed; no OCR is performed.",
                "Metadata privacy, full accessibility and final-release authorization require separate gates.",
            ],
        }


def _expected_content(presentation_ir: object) -> tuple[str, str]:
    """Derive the full expected stream independently of the HTML/PDF renderer."""
    if not isinstance(presentation_ir, dict):
        raise ValueError("invalid input")
    canonical = json.dumps(presentation_ir, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False).encode("utf-8")
    if len(canonical) > MAX_PDF_BYTES:
        raise ValueError("input budget exceeded")
    ir = json.loads(canonical)
    if ir != presentation_ir:
        raise ValueError("source is not lossless JSON")
    if not isinstance(ir.get("report_id"), str) or not ir["report_id"]:
        raise ValueError("invalid report identity")
    if not is_supported_report_locale(ir.get("locale_id")):
        raise ValueError("invalid locale")
    components = ir.get("components")
    if not isinstance(components, list) or not components:
        raise ValueError("invalid components")
    parts = [ir["report_id"]]
    seen = set()
    for component in components:
        if not isinstance(component, dict):
            raise ValueError("invalid component")
        identity = component.get("component_id")
        if (not isinstance(identity, str) or not identity or identity in seen
                or component.get("component_type") != "semantic-section"
                or any(not isinstance(component.get(k), str) or not component[k]
                       for k in ("title", "state"))
                or not isinstance(component.get("content"), dict)):
            raise ValueError("invalid component")
        seen.add(identity)
        parts.extend([component["title"], component["state"],
                      json.dumps(component["content"], sort_keys=True,
                                 separators=(",", ":"), ensure_ascii=False, allow_nan=False)])
    text = normalize_stream("\n".join(parts))
    if len(text) > MAX_TEXT_CHARS:
        raise ValueError("text budget exceeded")
    return hashlib.sha256(canonical).hexdigest(), hashlib.sha256(text.encode("utf-8")).hexdigest()


def validate_pdf_text_content(
    *, presentation_ir: object, expected_ir_sha256: object,
    pdf_bytes: object, expected_pdf_sha256: object,
) -> PdfContentValidation:
    """Compare independently derived report text and a bounded candidate text digest."""
    ir_digest = pdf_digest = expected_text = actual_text = None
    pages = None

    def fail(error: str) -> PdfContentValidation:
        """Retain available identities but never raw input when failing closed."""
        return PdfContentValidation(ir_digest, pdf_digest, expected_text,
                                    actual_text, pages, (error,))

    try:
        ir_digest, expected_text = _expected_content(presentation_ir)
    except (TypeError, ValueError, RecursionError, UnicodeError):
        return fail("presentation_ir_invalid")
    if not _is_digest(expected_ir_sha256):
        return fail("expected_ir_digest_invalid")
    if ir_digest != expected_ir_sha256:
        return fail("presentation_ir_digest_mismatch")
    if not isinstance(pdf_bytes, bytes) or not pdf_bytes.startswith(b"%PDF-"):
        return fail("pdf_content_structure_invalid")
    if len(pdf_bytes) > MAX_PDF_BYTES:
        return fail("pdf_content_budget_exceeded")
    pdf_digest = hashlib.sha256(pdf_bytes).hexdigest()
    if not _is_digest(expected_pdf_sha256):
        return fail("expected_pdf_digest_invalid")
    if pdf_digest != expected_pdf_sha256:
        return fail("pdf_digest_mismatch")
    try:
        process = subprocess.run(
            [sys.executable, "-I", str(_WORKER)], input=pdf_bytes,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=WALL_SECONDS, check=False,
        )
    except subprocess.TimeoutExpired:
        return fail("pdf_content_worker_timeout")
    except OSError:
        return fail("pdf_content_worker_unavailable")
    if process.returncode != 0:
        return fail("pdf_content_worker_failed")
    try:
        if not isinstance(process.stdout, bytes) or len(process.stdout) > 4096:
            raise ValueError("worker protocol limit")
        record = json.loads(process.stdout)
        if not isinstance(record, dict) or set(record) != {"status", "pdf_sha256", "text_sha256", "page_count", "errors"}:
            raise ValueError("invalid worker fields")
        errors = record["errors"]
        if not isinstance(errors, list) or any(not isinstance(e, str) or e not in WORKER_ERRORS for e in errors):
            raise ValueError("invalid worker errors")
        if record["status"] == "BLOCKED" and errors:
            return fail(errors[0])
        if record["status"] != "PASS" or errors or record["pdf_sha256"] != pdf_digest:
            raise ValueError("invalid worker state")
        if not _is_digest(record["text_sha256"]) or type(record["page_count"]) is not int or not 1 <= record["page_count"] <= MAX_PAGES:
            raise ValueError("invalid worker evidence")
        actual_text, pages = record["text_sha256"], record["page_count"]
    except (ValueError, TypeError, UnicodeError):
        return fail("pdf_content_worker_invalid_response")
    if actual_text != expected_text:
        return fail("pdf_text_content_mismatch")
    return PdfContentValidation(ir_digest, pdf_digest, expected_text, actual_text, pages, ())
