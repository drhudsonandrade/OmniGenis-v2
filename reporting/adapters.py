"""RPT-08 deterministic HTML/CSS adapter and conformance harness."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from html import escape
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import threading
from collections.abc import Mapping

from reporting.localization import is_supported_report_locale
from reporting._pdf_render_worker import (
    HTML_BYTES as PDF_RENDER_MAX_HTML_BYTES,
    MEMORY_BYTES as PDF_RENDER_MEMORY_BYTES,
    CPU_SECONDS as PDF_RENDER_CPU_SECONDS,
    OPEN_FILES as PDF_RENDER_OPEN_FILES,
    PDF_BYTES as PDF_RENDER_MAX_PDF_BYTES,
    PROTOCOL_VERSION as PDF_RENDER_PROTOCOL_VERSION,
    RESULT_BYTES as PDF_RENDER_RESULT_BYTES,
    WALL_SECONDS as PDF_RENDER_WALL_SECONDS,
)
from reporting.pdf_candidate_qa import (
    MAX_PDF_BYTES, _MAX_JSON_NODES, PdfCandidateQAValidation,
    _snapshot_ir, validate_pdf_candidate_qa,
)
from reporting.pdf_qa import (
    GENERATED_PDF_AUTHOR, GENERATED_PDF_PRODUCT, GENERATED_PDF_METADATA_PROFILE,
    validate_pdf_candidate,
)

ROADMAP_ID = "RPT-08"
_PDF_RENDER_ENV_LOCK = threading.Lock()
_PDF_RENDER_ERRORS = frozenset({
    "pdf_engine_unavailable", "pdf_engine_version_mismatch",
    "pdf_render_failed", "pdf_engine_invalid_output",
    "pdf_candidate_budget_exceeded", "pdf_render_protocol_invalid",
})
_PDF_RENDER_LIMITS = {
    "memory_bytes": PDF_RENDER_MEMORY_BYTES,
    "cpu_seconds": PDF_RENDER_CPU_SECONDS,
    "file_bytes": PDF_RENDER_MAX_PDF_BYTES,
    "open_files": PDF_RENDER_OPEN_FILES,
}


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
            "conformance": deepcopy(self.conformance),
            "errors": list(self.errors),
        }


def _failure(error: str) -> AdapterResult:
    return AdapterResult(None, None, None, None, None, "DISABLED", None, None, (error,))


def _validate_ir(presentation_ir: object) -> bool:
    """Check component shape and the activated locale before any rendering."""
    if not isinstance(presentation_ir, Mapping):
        return False
    report_id = presentation_ir.get("report_id")
    locale_id = presentation_ir.get("locale_id")
    components = presentation_ir.get("components")
    if not isinstance(report_id, str) or not report_id:
        return False
    if not is_supported_report_locale(locale_id):
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


def _capture_adapter_ir(value: object) -> dict:
    """Bridge only structural Mapping wrappers, then capture bounded native JSON.

    Descendants retain the fixed QA input contract; tuples and arbitrary nested
    Mapping values are not coerced. Mutation during capture is unsupported.
    """
    remaining = _MAX_JSON_NODES
    key_chars = 0

    def capture_mapping(mapping: object) -> dict:
        nonlocal remaining, key_chars
        if not isinstance(mapping, Mapping):
            raise ValueError("invalid presentation mapping")
        remaining -= 1
        if remaining < 0 or len(mapping) > remaining // 2:
            raise ValueError("presentation input budget exceeded")
        captured = {}
        for key, child in mapping.items():
            remaining -= 2
            if remaining < 0 or type(key) is not str:
                raise ValueError("invalid presentation mapping")
            key_chars += len(key)
            if key_chars > MAX_PDF_BYTES:
                raise ValueError("presentation input budget exceeded")
            if key in captured:
                raise ValueError("duplicate presentation key")
            captured[key] = child
        return captured

    captured = capture_mapping(value)
    components = captured.get("components")
    if type(components) is not list or len(components) > remaining:
        raise ValueError("invalid presentation components")
    captured["components"] = [capture_mapping(component) for component in components]
    return _snapshot_ir(captured)


def _pdf_failure(html: str, html_sha256: str, reason: str) -> AdapterResult:
    """Retain generated HTML while withholding the rejected PDF and conformance."""
    return AdapterResult(
        html, html_sha256, None, None, "weasyprint:70.0", "DISABLED",
        reason, None, (reason,),
    )


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


def _validate_pdf_structure(pdf: bytes, *, expected_language: str) -> None:
    """Validate structure and the controlled metadata of generated candidate bytes."""
    if not isinstance(pdf, bytes) or not pdf.startswith(b"%PDF-1.7"):
        raise RuntimeError("pdf_engine_invalid_output")

    try:
        from importlib.metadata import version

        from pypdf import PdfReader
    except (ImportError, OSError) as exc:
        raise RuntimeError("pdf_validator_unavailable") from exc
    if version("pypdf") != "6.19.0":
        raise RuntimeError("pdf_validator_version_mismatch")

    metadata_result = validate_pdf_candidate(
        pdf_bytes=pdf,
        expected_pdf_sha256=hashlib.sha256(pdf).hexdigest(),
        expected_author=GENERATED_PDF_AUTHOR,
        expected_language=expected_language,
        metadata_profile=GENERATED_PDF_METADATA_PROFILE,
    )
    if not metadata_result.passed:
        if "pdf_structure_invalid" in metadata_result.errors or "encrypted_pdf_forbidden" in metadata_result.errors:
            raise RuntimeError("pdf_engine_invalid_output")
        raise RuntimeError("pdf_metadata_invalid")

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


def _start_pdf_render_worker(
    command: list[str], *, env: dict[str, str], pass_fds: tuple[int, ...] = ()
) -> subprocess.Popen:
    """Start one renderer in a fresh process group without captured streams."""
    return subprocess.Popen(
        command,
        cwd=Path(__file__).resolve().parents[1],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
        start_new_session=True,
        close_fds=True,
        pass_fds=pass_fds,
    )


def _terminate_pdf_render_group(pid: int) -> None:
    """Best-effort termination for the worker and every inherited descendant."""
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _wait_pdf_render_worker(
    process: subprocess.Popen, *, wall_seconds: float = 30
) -> int:
    """Wait for the renderer and guarantee process-group cleanup."""
    try:
        try:
            return process.wait(timeout=wall_seconds)
        except subprocess.TimeoutExpired as exc:
            _terminate_pdf_render_group(process.pid)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            raise RuntimeError("pdf_render_failed") from exc
    finally:
        _terminate_pdf_render_group(process.pid)


def _decode_pdf_render_result(
    result_bytes: bytes, *, expected_pdf_path: Path | int | None
) -> tuple[bytes | None, str | None]:
    """Validate the bounded worker protocol before exposing renderer output."""
    if type(result_bytes) is not bytes or len(result_bytes) > PDF_RENDER_RESULT_BYTES:
        raise RuntimeError("pdf_render_failed")
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate protocol field")
            result[key] = value
        return result

    try:
        record = json.loads(result_bytes.decode("ascii"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise RuntimeError("pdf_render_failed") from exc
    if (type(record) is not dict or type(record.get("protocol_version")) is not int
            or record["protocol_version"] != PDF_RENDER_PROTOCOL_VERSION):
        raise RuntimeError("pdf_render_failed")
    limits = record.get("limits")
    if (type(limits) is not dict or limits != _PDF_RENDER_LIMITS
            or any(type(value) is not int for value in limits.values())):
        raise RuntimeError("pdf_render_failed")

    status = record.get("status")
    if status == "FAIL":
        if set(record) != {"protocol_version", "status", "error", "limits"}:
            raise RuntimeError("pdf_render_failed")
        error = record.get("error")
        if type(error) is not str or error not in _PDF_RENDER_ERRORS:
            raise RuntimeError("pdf_render_failed")
        if record.get("limits") != _PDF_RENDER_LIMITS:
            raise RuntimeError("pdf_render_failed")
        return None, error

    if status != "PASS" or expected_pdf_path is None:
        raise RuntimeError("pdf_render_failed")
    if set(record) != {
        "protocol_version", "status", "pdf_bytes", "pdf_sha256", "limits"
    } or record.get("limits") != _PDF_RENDER_LIMITS:
        raise RuntimeError("pdf_render_failed")

    expected_size = record.get("pdf_bytes")
    expected_digest = record.get("pdf_sha256")
    if (
        type(expected_size) is not int
        or expected_size < 1
        or expected_size > PDF_RENDER_MAX_PDF_BYTES
        or type(expected_digest) is not str
        or len(expected_digest) != 64
    ):
        raise RuntimeError("pdf_render_failed")
    if any(char not in "0123456789abcdef" for char in expected_digest):
        raise RuntimeError("pdf_render_failed")
    try:
        fd = (os.dup(expected_pdf_path) if type(expected_pdf_path) is int else
              os.open(expected_pdf_path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size != expected_size:
                raise RuntimeError("pdf_render_failed")
            pdf = os.pread(fd, expected_size + 1, 0)
        finally:
            os.close(fd)
    except (OSError, ValueError) as exc:
        raise RuntimeError("pdf_render_failed") from exc
    if (
        len(pdf) != expected_size
        or not pdf.startswith(b"%PDF-1.7")
        or hashlib.sha256(pdf).hexdigest() != expected_digest
    ):
        raise RuntimeError("pdf_render_failed")
    return pdf, None


def _render_pdf(html: str, html_sha256: str) -> bytes:
    """Run native rendering only in the Linux bounded child, with unnamed I/O."""
    if sys.platform != "linux" or os.environ.get("OMNIGENIS_PDF_RENDERER_DISABLED") == "1":
        raise RuntimeError("pdf_engine_unavailable")
    if type(html) is not str or type(html_sha256) is not str or len(html_sha256) != 64:
        raise RuntimeError("pdf_render_failed")
    if len(html) > PDF_RENDER_MAX_HTML_BYTES:
        raise RuntimeError("pdf_render_input_too_large")
    try:
        html_bytes = html.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise RuntimeError("pdf_render_failed") from exc
    if len(html_bytes) > PDF_RENDER_MAX_HTML_BYTES:
        raise RuntimeError("pdf_render_input_too_large")
    if hashlib.sha256(html_bytes).hexdigest() != html_sha256:
        raise RuntimeError("pdf_render_failed")
    try:
        with (_PDF_RENDER_ENV_LOCK, tempfile.TemporaryFile() as request,
              tempfile.TemporaryFile() as candidate, tempfile.TemporaryFile() as result):
            handles = (request, candidate, result)
            fds = tuple(handle.fileno() for handle in handles)
            if any(os.fstat(fd).st_nlink != 0 for fd in fds):
                raise RuntimeError("pdf_render_failed")
            request.write(f"{PDF_RENDER_PROTOCOL_VERSION} {html_sha256}\n".encode("ascii"))
            request.write(html_bytes)
            request.flush()
            request.seek(0)
            env = {key: os.environ[key] for key in (
                "PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
                "FONTCONFIG_FILE", "FONTCONFIG_PATH",
            ) if key in os.environ}
            env["SOURCE_DATE_EPOCH"] = "0"
            process = _start_pdf_render_worker([
                sys.executable, "-I", str(Path(__file__).with_name("_pdf_render_worker.py")),
                *(str(fd) for fd in fds), str(os.getpid()),
            ], env=env, pass_fds=fds)
            code = _wait_pdf_render_worker(process, wall_seconds=PDF_RENDER_WALL_SECONDS)
            if code != 0 or os.fstat(result.fileno()).st_size > PDF_RENDER_RESULT_BYTES:
                raise RuntimeError("pdf_render_failed")
            result.seek(0)
            pdf, error = _decode_pdf_render_result(
                result.read(PDF_RENDER_RESULT_BYTES + 1), expected_pdf_path=candidate.fileno())
            if error is not None:
                raise RuntimeError(error)
            if pdf is None:
                raise RuntimeError("pdf_render_failed")
            return pdf
    except OSError as exc:
        raise RuntimeError("pdf_render_failed") from exc


def build_html_css_and_pdf_adapter(*, presentation_ir: object) -> AdapterResult:
    """Create one candidate from captured localized IR and require bounded QA.

    The native handoff is LocalizationResult.to_dict()["localized_ir"]. Root
    and component Mapping wrappers remain supported with native JSON descendants.
    READY covers the fixed candidate checks; it does not authorize report release.
    """
    try:
        presentation_ir = _capture_adapter_ir(presentation_ir)
        if not _validate_ir(presentation_ir):
            return _failure("presentation_ir_invalid")
        ir_digest = hashlib.sha256(json.dumps(
            presentation_ir, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")).hexdigest()
    except Exception:
        # Mapping implementations can raise arbitrary errors during capture.
        return _failure("presentation_ir_invalid")

    locale_id = presentation_ir["locale_id"]
    parts = [
        f'<!doctype html><html lang="{escape(locale_id, quote=True)}"><head><meta charset="utf-8">',
        f"<title>{GENERATED_PDF_PRODUCT}</title>",
        f'<meta name="author" content="{GENERATED_PDF_AUTHOR}">',
        f'<meta name="generator" content="{GENERATED_PDF_PRODUCT}">',
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
        if type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b"%PDF-1.7"):
            raise RuntimeError("pdf_engine_invalid_output")
        if len(pdf_bytes) > MAX_PDF_BYTES:
            raise RuntimeError("pdf_candidate_budget_exceeded")
        _validate_pdf_structure(pdf_bytes, expected_language=locale_id)
    except RuntimeError as exc:
        reason = str(exc)
        return _pdf_failure(html, digest, reason)
    except (TypeError, ValueError, UnicodeError):
        return _failure("pdf_render_failed")

    pdf_sha256 = hashlib.sha256(pdf_bytes).hexdigest()
    try:
        candidate_qa = validate_pdf_candidate_qa(
            presentation_ir=presentation_ir, expected_ir_sha256=ir_digest,
            pdf_bytes=pdf_bytes, expected_pdf_sha256=pdf_sha256,
        )
    except Exception:
        return _pdf_failure(html, digest, "pdf_candidate_qa_failed")
    try:
        if type(candidate_qa) is not PdfCandidateQAValidation:
            raise ValueError("invalid candidate QA result")
        # Recheck invariants rather than trusting a success-looking object.
        candidate_qa = PdfCandidateQAValidation(
            candidate_qa.pdf_sha256, candidate_qa.ir_sha256,
            candidate_qa.locale_id, candidate_qa.gates,
        )
        for actual, expected in (
            (candidate_qa.pdf_sha256, pdf_sha256),
            (candidate_qa.ir_sha256, ir_digest),
            (candidate_qa.locale_id, locale_id),
        ):
            if actual is not None and actual != expected:
                raise ValueError("candidate QA identity mismatch")
        if not candidate_qa.passed:
            return _pdf_failure(html, digest, "pdf_candidate_qa_blocked")
        qa_evidence = candidate_qa.to_dict()
    except Exception:
        return _pdf_failure(html, digest, "pdf_candidate_qa_invalid_result")
    conformance = {
        "status": "PASS",
        "component_count": len(component_ids),
        "component_ids": component_ids,
        "html_sha256": digest,
        "pdf_sha256": pdf_sha256,
        "pdf_adapter_status": "READY",
        "pdf_engine_id": "weasyprint:70.0",
        "pdf_validator_id": "pypdf:6.19.0",
        "pdf_metadata_profile": GENERATED_PDF_METADATA_PROFILE,
        "pdf_metadata_status": "PASS",
        "presentation_ir_sha256": ir_digest,
        "pdf_candidate_qa": qa_evidence,
        "release_authorization": "NOT_ESTABLISHED",
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
