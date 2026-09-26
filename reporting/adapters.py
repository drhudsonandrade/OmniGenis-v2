"""RPT-08 deterministic HTML/CSS adapter and conformance harness."""

from __future__ import annotations

from dataclasses import dataclass
from html import escape
import hashlib
from io import BytesIO
import json
import os
import threading
from collections.abc import Mapping

ROADMAP_ID = "RPT-08"
_PDF_RENDER_ENV_LOCK = threading.Lock()
_PDF_SOURCE_DATE_EPOCH = "0"


@dataclass(frozen=True)
class AdapterResult:
    html: str | None
    html_sha256: str | None
    pdf_bytes: bytes | None
    pdf_sha256: str | None
    pdf_engine_id: str | None
    pdf_status: str
    pdf_reason: str | None
    conformance: dict[str, object] | None
    errors: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, object]:
        return {
            "roadmap_id": ROADMAP_ID,
            "status": "PASS" if self.passed else "FAIL",
            "html": self.html,
            "html_sha256": self.html_sha256,
            "pdf_sha256": self.pdf_sha256,
            "pdf_engine_id": self.pdf_engine_id,
            "pdf_status": self.pdf_status,
            "pdf_reason": self.pdf_reason,
            "conformance": self.conformance,
            "errors": list(self.errors),
        }


def _failure(error: str) -> AdapterResult:
    return AdapterResult(None, None, None, None, None, "DISABLED", None, None, (error,))


def _validate_ir(presentation_ir: object) -> bool:
    if not isinstance(presentation_ir, Mapping):
        return False
    report_id = presentation_ir.get("report_id")
    components = presentation_ir.get("components")
    if not isinstance(report_id, str) or not report_id:
        return False
    if not isinstance(components, list) or not components:
        return False
    seen: set[str] = set()
    for component in components:
        if not isinstance(component, Mapping):
            return False
        component_id = component.get("component_id")
        if (
            component.get("component_type") != "semantic-section"
            or not isinstance(component_id, str)
            or not component_id
            or component_id in seen
            or not isinstance(component.get("title"), str)
            or not component.get("title")
            or not isinstance(component.get("state"), str)
            or not component.get("state")
            or not isinstance(component.get("content"), Mapping)
        ):
            return False
        seen.add(component_id)
    return True


def _pdf_stack_readiness() -> tuple[bool, str | None]:
    try:
        from importlib.metadata import version

        from weasyprint import HTML  # noqa: F401
        from weasyprint.urls import URLFetcher
    except (ImportError, OSError):
        return False, "pdf_engine_unavailable"
    if version("weasyprint") != "70.0":
        return False, "pdf_engine_version_mismatch"

    try:
        from pypdf import PdfReader  # noqa: F401
    except (ImportError, OSError):
        return False, "pdf_validator_unavailable"
    if version("pypdf") != "6.19.0":
        return False, "pdf_validator_version_mismatch"

    try:
        URLFetcher(
            allowed_protocols=(),
            allow_redirects=False,
            fail_on_errors=True,
        )
    except Exception:
        return False, "pdf_engine_unavailable"
    return True, None


def _validate_pdf_structure(pdf: bytes) -> None:
    if not isinstance(pdf, bytes) or not pdf.startswith(b"%PDF-1.7"):
        raise RuntimeError("pdf_engine_invalid_output")

    try:
        from importlib.metadata import version

        from pypdf import PdfReader
    except (ImportError, OSError) as exc:
        raise RuntimeError("pdf_validator_unavailable") from exc
    if version("pypdf") != "6.19.0":
        raise RuntimeError("pdf_validator_version_mismatch")

    try:
        reader = PdfReader(BytesIO(pdf), strict=True)
        if len(reader.pages) < 1:
            raise RuntimeError("pdf_engine_invalid_output")
        root = reader.trailer.get("/Root")
        if root is None:
            raise RuntimeError("pdf_engine_invalid_output")
        root.get_object()
        for page in reader.pages:
            _ = page.mediabox
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError("pdf_engine_invalid_output") from exc


def _render_pdf(html: str, html_sha256: str) -> bytes:
    with _PDF_RENDER_ENV_LOCK:
        previous_source_date_epoch = os.environ.get("SOURCE_DATE_EPOCH")
        os.environ["SOURCE_DATE_EPOCH"] = _PDF_SOURCE_DATE_EPOCH
        try:
            try:
                from weasyprint import HTML, __version__ as weasyprint_version
                from weasyprint.urls import URLFetcher
            except (ImportError, OSError) as exc:
                raise RuntimeError("pdf_engine_unavailable") from exc
            if weasyprint_version != "70.0":
                raise RuntimeError("pdf_engine_version_mismatch")

            fetcher = URLFetcher(
                allowed_protocols=(),
                allow_redirects=False,
                fail_on_errors=True,
            )
            try:
                pdf = HTML(string=html, url_fetcher=fetcher).write_pdf(
                    pdf_identifier=bytes.fromhex(html_sha256),
                    pdf_version="1.7",
                )
            except Exception as exc:
                raise RuntimeError("pdf_render_failed") from exc
            if not isinstance(pdf, bytes) or not pdf.startswith(b"%PDF-1.7"):
                raise RuntimeError("pdf_engine_invalid_output")
            return pdf
        finally:
            if previous_source_date_epoch is None:
                os.environ.pop("SOURCE_DATE_EPOCH", None)
            else:
                os.environ["SOURCE_DATE_EPOCH"] = previous_source_date_epoch


def build_html_css_and_pdf_adapter(*, presentation_ir: object) -> AdapterResult:
    if not _validate_ir(presentation_ir):
        return _failure("presentation_ir_invalid")

    parts = [
        "<!doctype html><html><head><meta charset=\"utf-8\">",
        "<style>body{font-family:sans-serif}section{margin-block:1rem}pre{white-space:pre-wrap}</style>",
        "</head><body>",
        f"<h1>{escape(presentation_ir['report_id'])}</h1>",
    ]
    component_ids: list[str] = []
    try:
        for component in presentation_ir["components"]:
            component_ids.append(component["component_id"])
            payload = json.dumps(
                component["content"],
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
            parts.extend(
                [
                    f'<section data-component="{escape(component["component_id"], quote=True)}">',
                    f"<h2>{escape(component['title'])}</h2>",
                    f"<p>{escape(component['state'])}</p>",
                    f"<pre>{escape(payload)}</pre>",
                    "</section>",
                ]
            )
        parts.append("</body></html>")
        html = "".join(parts)
        digest = hashlib.sha256(html.encode("utf-8")).hexdigest()
    except (TypeError, ValueError, UnicodeEncodeError):
        return _failure("presentation_ir_invalid")

    try:
        pdf_bytes = _render_pdf(html, digest)
        _validate_pdf_structure(pdf_bytes)
    except RuntimeError as exc:
        reason = str(exc)
        return AdapterResult(
            html, digest, None, None, "weasyprint:70.0", "DISABLED", reason, None, (reason,)
        )
    except (TypeError, ValueError, UnicodeError):
        return _failure("pdf_render_failed")

    pdf_sha256 = hashlib.sha256(pdf_bytes).hexdigest()
    conformance = {
        "status": "PASS",
        "component_count": len(component_ids),
        "component_ids": component_ids,
        "html_sha256": digest,
        "pdf_sha256": pdf_sha256,
        "pdf_adapter_status": "READY",
        "pdf_engine_id": "weasyprint:70.0",
        "pdf_validator_id": "pypdf:6.19.0",
    }
    return AdapterResult(
        html,
        digest,
        pdf_bytes,
        pdf_sha256,
        "weasyprint:70.0",
        "READY",
        None,
        conformance,
        (),
    )
