"""Optional composition of native font relations and complete source inspection.

Both existing inspection chains keep their pinned profiles and guards. The
combined result binds unsigned observations to the same source and job; it
does not authenticate execution, qualify aggregate resources or release PDFs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
import os
import sys
from time import monotonic_ns

from reporting import pdf_inspection_job as legacy
from reporting import pdf_structured_source_job as structured
from reporting import pdf_tounicode_width_coverage as native
from reporting._pdf_native_launch_budget import NativeLaunchScope, require_no_active_scope
from reporting.pdf_structured_source_job import (
    PdfStructuredSourceResult, execute_pdf_structured_source_job,
)
from reporting.pdf_tounicode_width_coverage import (
    PdfToUnicodeWidthCoverage, inspect_pdf_tounicode_width_coverage,
)
from reporting.pdf_candidate_qa import _snapshot_ir
from reporting.pdf_content import _expected_content
from reporting.page_checkpoints import _json_bytes, _validate_context
from reporting.page_windows import plan_pdf_page_windows
from reporting.pdf_inspection_bundle import _pin

PROFILE_ID = "native-source-pdf-inspection-job-v1"
NATIVE_PROFILE_SHA256 = "0e9cd91a89366753dd85e3dd7adbd8b592928c459ff59cd91622a5bece4b5b0d"
STRUCTURED_PROFILE_SHA256 = "ef527ca30db7a034f6b11f896b11a09a9afedf4b91b899b9bceacfd4245828a5"
MAX_PAGES = 64
MAX_PDF_BYTES = 8 * 1024 * 1024
MAX_RESULT_BYTES = 304 * 1024
MAX_OUTER_STAGES = 2
ACCEPTANCE_NS = 300 * 1000 * 1000 * 1000
LANGUAGE = "en-US"
_DISABLE = "OMNIGENIS_PDF_NATIVE_SOURCE_JOB_DISABLED"


class PdfNativeSourceJobError(ValueError):
    """Content-free failure without a partial successful combined result."""


def native_source_job_profile() -> dict:
    """Return the detached finite composition contract and distinct child pins."""
    return {
        "schema_version": "1.0.0", "profile_id": PROFILE_ID,
        "language": LANGUAGE, "pdf_version": "1.7", "max_pages": MAX_PAGES,
        "max_pdf_bytes": MAX_PDF_BYTES, "max_result_bytes": MAX_RESULT_BYTES,
        "max_outer_stages": MAX_OUTER_STAGES, "acceptance_deadline_ns": ACCEPTANCE_NS,
        "native_width_profile_sha256": NATIVE_PROFILE_SHA256,
        "structured_source_job_profile_sha256": STRUCTURED_PROFILE_SHA256,
        "source_capture": "EXISTING_BOUNDED_NATIVE_JSON_SNAPSHOT",
        "retries": 0, "persistent_checkpoints": False,
        "hard_job_deadline_enforced": False,
        "aggregate_job_resources_qualified": False,
        "default_pipeline_activated": False, "release_authorized": False,
    }


PROFILE_SHA256 = sha256(_json_bytes(native_source_job_profile())).hexdigest()


def _profile(expected: str) -> None:
    """Reject outer drift and recursively validate both unchanged prerequisite profiles."""
    _pin(expected)
    if (sys.platform != "linux" or os.environ.get(_DISABLE) == "1"
            or expected != PROFILE_SHA256
            or sha256(_json_bytes(native_source_job_profile())).hexdigest() != PROFILE_SHA256
            or native.PROFILE_SHA256 != NATIVE_PROFILE_SHA256
            or structured.PROFILE_SHA256 != STRUCTURED_PROFILE_SHA256):
        raise ValueError("native source profile unavailable")
    native._profile()
    structured._profile(STRUCTURED_PROFILE_SHA256)


def _nonclaims() -> dict:
    """Preserve the native and source jobs' distinct unestablished qualifications."""
    return {
        **native._nonclaims(),
        "scientific_equivalence_verified": False,
        "semantic_roles_qualified": False, "visible_glyphs_verified": False,
        "full_accessibility_qualified": False, "finding_completeness_verified": False,
    }


@dataclass(frozen=True, slots=True, repr=False)
class PdfNativeSourceResult:
    """Sealed unsigned agreement of native relations and the complete structured job."""

    native_inspection: PdfToUnicodeWidthCoverage
    structured_inspection: PdfStructuredSourceResult
    expected_native_sha256: str
    expected_structured_sha256: str
    expected_text_sha256: str
    pdf_sha256: str
    ir_sha256: str
    plan_sha256: str
    page_count: int
    namespace_id: str
    job_id: str
    request_sha256: str
    resource_profile_sha256: str
    _sealed_sha256: str = field(init=False, repr=False, compare=False)

    def _validated_bytes(self) -> bytes:
        """Validate child seals, distinct profiles and every document, text-plan and job binding."""
        _profile(self.resource_profile_sha256)
        for value in (self.expected_native_sha256, self.expected_structured_sha256,
                      self.expected_text_sha256, self.pdf_sha256, self.ir_sha256,
                      self.plan_sha256, self.request_sha256):
            _pin(value)
        if (type(self.page_count) is not int or not 1 <= self.page_count <= MAX_PAGES
                or type(self.namespace_id) is not str or type(self.job_id) is not str
                or type(self.native_inspection) is not PdfToUnicodeWidthCoverage
                or type(self.structured_inspection) is not PdfStructuredSourceResult):
            raise ValueError("native source result type or domain")
        _validate_context(self.namespace_id, self.job_id, self.request_sha256,
                          self.resource_profile_sha256)
        native_bytes = self.native_inspection.to_bytes()
        structured_bytes = self.structured_inspection.to_bytes()
        if (sha256(native_bytes).hexdigest() != self.expected_native_sha256
                or sha256(structured_bytes).hexdigest() != self.expected_structured_sha256):
            raise ValueError("native source child pin mismatch")
        first, second = json.loads(native_bytes), json.loads(structured_bytes)
        identity = {"pdf_sha256": self.pdf_sha256, "ir_sha256": self.ir_sha256,
                    "page_count": self.page_count}
        original = second["source_inspection"]
        plans = (
            first["plan_sha256"], second["structure_tree"]["plan_sha256"],
            original["document_content"]["plan_sha256"],
            original["inspection_set"]["page_bundle"]["text_stream"]["plan_sha256"],
        )
        if (any(first[key] != value or second[key] != value for key, value in identity.items())
                or any(value != self.plan_sha256 for value in plans)
                or first["language"] != LANGUAGE or second["language"] != LANGUAGE
                or first["profile_sha256"] != NATIVE_PROFILE_SHA256
                or second["resource_profile_sha256"] != STRUCTURED_PROFILE_SHA256
                or any(second[key] != getattr(self, key) for key in
                       ("namespace_id", "job_id", "request_sha256"))
                or second["expected_text_sha256"] != self.expected_text_sha256):
            raise ValueError("native source child identity disagreement")
        result = {
            "schema_version": "1.0.0", "profile_id": PROFILE_ID,
            "status": "NATIVE_AND_STRUCTURED_SOURCE_RESULTS_BOUND", **identity,
            "plan_sha256": self.plan_sha256, "language": LANGUAGE,
            "namespace_id": self.namespace_id, "job_id": self.job_id,
            "request_sha256": self.request_sha256,
            "resource_profile_sha256": self.resource_profile_sha256,
            "native_width_profile_sha256": NATIVE_PROFILE_SHA256,
            "structured_source_job_profile_sha256": STRUCTURED_PROFILE_SHA256,
            "expected_text_sha256": self.expected_text_sha256,
            "native_inspection_sha256": self.expected_native_sha256,
            "structured_inspection_sha256": self.expected_structured_sha256,
            "native_inspection": first, "structured_inspection": second,
            "inspection_dimensions": second["inspection_dimensions"] +
                ["native_tounicode_same_font_explicit_width_coverage"],
            "shared_input_bindings_verified": True,
            "same_font_explicit_width_coverage_verified":
                first["same_font_explicit_width_coverage_valid"],
            "normalized_text_equivalence_verified": second["normalized_text_equivalence_verified"],
            "forward_reverse_linkage_verified": second["forward_reverse_linkage_verified"],
            **_nonclaims(), "release_authorization": "NOT_ESTABLISHED",
        }
        data = _json_bytes(result)
        if len(data) > MAX_RESULT_BYTES:
            raise ValueError("native source result byte budget")
        return data

    def __post_init__(self) -> None:
        """Seal valid metadata without allowing an altered retained object to be resealed."""
        try:
            digest = sha256(self._validated_bytes()).hexdigest()
            if hasattr(self, "_sealed_sha256") and self._sealed_sha256 != digest:
                raise ValueError("native source result changed")
            object.__setattr__(self, "_sealed_sha256", digest)
        except Exception:
            raise PdfNativeSourceJobError("pdf_native_source_result_invalid") from None

    def to_bytes(self) -> bytes:
        """Expose the original bounded representation after revalidating both retained children."""
        try:
            data = self._validated_bytes()
            if sha256(data).hexdigest() != self._sealed_sha256:
                raise ValueError("native source result changed")
            return data
        except Exception:
            raise PdfNativeSourceJobError("pdf_native_source_result_invalid") from None

    def to_dict(self) -> dict:
        """Return detached metadata with every inherited qualification limit intact."""
        return json.loads(self.to_bytes())

    @property
    def inspection_sha256(self) -> str:
        """Hash the sealed metadata without asserting authenticated execution."""
        return sha256(self.to_bytes()).hexdigest()


def execute_pdf_native_source_job(
    *, presentation_ir: object, pdf_bytes: object, expected_pdf_sha256: str,
    expected_ir_sha256: str, page_count: int, expected_language: str,
    namespace_id: str, job_id: str, request_sha256: str,
    expected_resource_profile_sha256: str,
) -> PdfNativeSourceResult:
    """Execute the pinned native chain, then the unchanged structured-source job.

    The caller supplies trusted source/job expectations, never receipts or an
    executor. Bounded native-JSON capture and comparisons detect persistent
    changes; concurrent mutate-and-restore behavior remains unsupported. The
    elapsed acceptance check does not preempt synchronous children or qualify
    aggregate CPU, RSS, scratch, descriptors or descendant-process budgets.
    """
    try:
        require_no_active_scope()
        _profile(expected_resource_profile_sha256)
        if (type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b"%PDF-1.7")
                or len(pdf_bytes) > MAX_PDF_BYTES or type(page_count) is not int
                or not 1 <= page_count <= MAX_PAGES or type(expected_language) is not str
                or expected_language != LANGUAGE or type(namespace_id) is not str
                or type(job_id) is not str):
            raise ValueError("native source input type or domain")
        for value in (expected_pdf_sha256, expected_ir_sha256, request_sha256):
            _pin(value)
        _validate_context(namespace_id, job_id, request_sha256, expected_resource_profile_sha256)
        captured = _snapshot_ir(presentation_ir)
        source_bytes = _json_bytes(captured)
        ir_digest, expected_text = _expected_content(captured)
        if (captured.get("locale_id") != LANGUAGE or ir_digest != expected_ir_sha256
                or sha256(pdf_bytes).hexdigest() != expected_pdf_sha256):
            raise ValueError("native source exact input mismatch")
        plan = plan_pdf_page_windows(
            pdf_sha256=expected_pdf_sha256, ir_sha256=expected_ir_sha256,
            page_count=page_count, admitted_page_budget=page_count,
            pages_per_window=legacy.TEXT_WIDTH, inspector_profile_id=legacy.TEXT_PROFILE,
        )
        plan_digest = plan.plan_sha256
        started = previous = monotonic_ns()
        if type(started) is not int or started < 0:
            raise ValueError("native source clock invalid")
    except Exception:
        raise PdfNativeSourceJobError("pdf_native_source_job_input_invalid") from None

    def check() -> None:
        """Recheck policies, plan, both source views and elapsed acceptance after each stage."""
        nonlocal previous
        _profile(expected_resource_profile_sha256)
        plan.__post_init__()
        if (plan.plan_sha256 != plan_digest
                or _json_bytes(_snapshot_ir(presentation_ir)) != source_bytes
                or _json_bytes(_snapshot_ir(captured)) != source_bytes):
            raise ValueError("native source input changed")
        current = monotonic_ns()
        if (type(current) is not int or current < previous
                or current - started >= ACCEPTANCE_NS):
            raise ValueError("native source acceptance deadline")
        previous = current

    launches = None
    try:
        launches = NativeLaunchScope(plan, len(pdf_bytes))
        launches.__enter__()
        check()
        first = inspect_pdf_tounicode_width_coverage(
            pdf_bytes=pdf_bytes, plan=plan,
            expected_plan_sha256=plan_digest, expected_language=LANGUAGE,
        )
        check()
        if type(first) is not PdfToUnicodeWidthCoverage:
            raise ValueError("native source first result type")
        first_digest = first.inspection_sha256
        record = first.to_dict()
        if any(record[key] != getattr(plan, key) for key in
               ("pdf_sha256", "ir_sha256", "plan_sha256", "page_count")):
            raise ValueError("native source first result identity")
        second = execute_pdf_structured_source_job(
            presentation_ir=captured, pdf_bytes=pdf_bytes,
            expected_pdf_sha256=expected_pdf_sha256, expected_ir_sha256=expected_ir_sha256,
            page_count=page_count, expected_language=LANGUAGE, namespace_id=namespace_id,
            job_id=job_id, request_sha256=request_sha256,
            expected_resource_profile_sha256=STRUCTURED_PROFILE_SHA256,
        )
        check()
        if (type(second) is not PdfStructuredSourceResult
                or first.inspection_sha256 != first_digest):
            raise ValueError("native source retained result changed")
        result = PdfNativeSourceResult(
            native_inspection=first, structured_inspection=second,
            expected_native_sha256=first_digest,
            expected_structured_sha256=second.inspection_sha256,
            expected_text_sha256=expected_text, pdf_sha256=expected_pdf_sha256,
            ir_sha256=expected_ir_sha256, plan_sha256=plan_digest, page_count=page_count,
            namespace_id=namespace_id, job_id=job_id, request_sha256=request_sha256,
            resource_profile_sha256=expected_resource_profile_sha256,
        )
        result.to_bytes()
        check()
        launches.require_complete()
        return result
    except Exception:
        raise PdfNativeSourceJobError("pdf_native_source_job_execution_failed") from None
    finally:
        if launches is not None:
            launches.close()
