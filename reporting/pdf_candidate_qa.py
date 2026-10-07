"""Run a fixed, bounded QA conjunction on one generated PDF candidate.

The caller supplies existing bytes and their localized presentation, never gate
results. No renderer is invoked. PASS covers only the five checks below; it is
not full accessibility, scientific validation, an OS sandbox or release approval.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import re
from types import MappingProxyType

from reporting._pdf_safety_worker import MAX_PAGES, MAX_PDF_BYTES, MAX_VISITS, POLICY_ID
from reporting._pdf_visual_worker import MAX_PIXELS_PER_PAGE, MAX_TOTAL_PIXELS
from reporting.pdf_accessibility import (
    PdfAccessibilityValidation, validate_pdf_accessibility_structure,
)
from reporting.pdf_content import PdfContentValidation, _expected_content, validate_pdf_text_content
from reporting.pdf_qa import (
    GENERATED_PDF_AUTHOR, GENERATED_PDF_METADATA_PROFILE, GENERATED_PDF_PRODUCT,
    PdfCandidateValidation, validate_pdf_candidate,
)
from reporting.pdf_safety import PdfSafetyValidation, validate_pdf_object_safety
from reporting.pdf_visual import PdfVisualValidation, validate_pdf_visual_geometry

PROFILE_ID = "omnigenis-generated-pdf-candidate-qa-v1"
_MAX_JSON_DEPTH = 64
_MAX_JSON_NODES = 100_000
_MAX_INTEGER_BITS = 4096
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_STAGES = (
    "identity_preflight", "object_safety", "controlled_metadata",
    "accessibility_prerequisites", "text_content", "visual_geometry",
)
_ERRORS = frozenset({
    "qa_presentation_ir_invalid", "qa_input_budget_exceeded",
    "qa_expected_ir_digest_invalid", "qa_ir_digest_mismatch",
    "qa_pdf_bytes_invalid", "qa_expected_pdf_digest_invalid",
    "qa_pdf_digest_mismatch", "qa_locale_unsupported",
    "qa_child_validation_failed", "qa_validator_result_invalid", "qa_validator_exception",
})
_ACCESSIBILITY_CLAIM = "PDF_UA_1_STRUCTURAL_PREREQUISITES_ONLY"
_CONTROLLED_METADATA = {
    "/Author": GENERATED_PDF_AUTHOR, "/Title": GENERATED_PDF_PRODUCT,
    "/Creator": GENERATED_PDF_PRODUCT, "/Producer": "WeasyPrint 70.0",
}


class _PreflightFailure(ValueError):
    """Carry only one internal, fixed failure code."""


class _ChildRejected(ValueError):
    """Separate a child's failed decision from malformed returned evidence."""


def _digest(value: object) -> bool:
    """Accept only exact native canonical SHA-256 strings."""
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _count(value: object, maximum: int) -> bool:
    """Reject Boolean, missing and out-of-budget numeric evidence."""
    return type(value) is int and 1 <= value <= maximum


def _snapshot_ir(value: object) -> dict:
    """Capture lossless native JSON with bounded traversal and canonical bytes.

    The byte limit is not a total-memory or execution-time limit. Active-path
    cycle detection permits aliases, but every expanded occurrence uses budget.
    Concurrent mutation of caller-owned input is outside this API's contract.
    """
    if type(value) is not dict:
        raise _PreflightFailure("qa_presentation_ir_invalid")
    nodes = scalar_size = 0
    active = set()

    def inspect(item: object, depth: int) -> None:
        """Reject unsupported types before any copying or JSON serialization."""
        nonlocal nodes, scalar_size
        nodes += 1
        if nodes > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
            raise _PreflightFailure("qa_input_budget_exceeded")
        kind = type(item)
        if kind is str:
            scalar_size += len(item)
            if scalar_size > MAX_PDF_BYTES:
                raise _PreflightFailure("qa_input_budget_exceeded")
            item.encode("utf-8")
        elif kind is int:
            if item.bit_length() > _MAX_INTEGER_BITS:
                raise _PreflightFailure("qa_input_budget_exceeded")
        elif kind is float:
            if not math.isfinite(item):
                raise _PreflightFailure("qa_presentation_ir_invalid")
        elif kind is bool or item is None:
            return
        elif kind is dict or kind is list:
            if id(item) in active:
                raise _PreflightFailure("qa_presentation_ir_invalid")
            if len(item) > _MAX_JSON_NODES:
                raise _PreflightFailure("qa_input_budget_exceeded")
            active.add(id(item))
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise _PreflightFailure("qa_presentation_ir_invalid")
                        inspect(key, depth + 1)
                        inspect(child, depth + 1)
                else:
                    for child in item:
                        inspect(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise _PreflightFailure("qa_presentation_ir_invalid")

    inspect(value, 0)
    encoder = json.JSONEncoder(
        sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
    )
    chunks = []
    byte_count = 0
    for chunk in encoder.iterencode(value):
        encoded = chunk.encode("utf-8")
        byte_count += len(encoded)
        if byte_count > MAX_PDF_BYTES:
            raise _PreflightFailure("qa_input_budget_exceeded")
        chunks.append(encoded)
    return json.loads(b"".join(chunks))


def _check_evidence(
    name: str, evidence: dict, *, pdf_sha256: str, ir_sha256: str,
    page_count: int | None, expected_text_sha256: str | None = None,
) -> None:
    """Validate a declared projection without accepting arbitrary child fields."""
    if name == "identity_preflight":
        valid = evidence == {
            "pdf_sha256": pdf_sha256, "ir_sha256": ir_sha256, "locale_id": "en-US",
        }
    elif name == "accessibility_prerequisites":
        valid = (
            set(evidence) == {
                "identity_binding", "invocation_pdf_sha256", "language",
                "marked", "struct_tree_root", "conformance_claim",
            }
            and evidence["identity_binding"] == "ENTRYPOINT_INVOCATION"
            and evidence["invocation_pdf_sha256"] == pdf_sha256
            and evidence["language"] == "en-US"
            and evidence["marked"] is True and evidence["struct_tree_root"] is True
            and evidence["conformance_claim"] == _ACCESSIBILITY_CLAIM
        )
    else:
        valid = (
            evidence.get("pdf_sha256") == pdf_sha256
            and _count(evidence.get("page_count"), MAX_PAGES)
            and (page_count is None or evidence["page_count"] == page_count)
        )
        common = {"pdf_sha256", "page_count"}
        if name == "object_safety":
            valid = valid and (
                set(evidence) == common | {"object_count", "policy_id", "conformance_scope"}
                and _count(evidence["object_count"], MAX_VISITS)
                and evidence["policy_id"] == POLICY_ID
                and evidence["conformance_scope"] == "REACHABLE_PDF_OBJECT_POLICY_ONLY"
            )
        elif name == "controlled_metadata":
            valid = valid and (
                set(evidence) == common | {"metadata_profile_id", "accessibility_prerequisites"}
                and evidence["metadata_profile_id"] == GENERATED_PDF_METADATA_PROFILE
                and evidence["accessibility_prerequisites"] == "PASS"
            )
        elif name == "text_content":
            valid = valid and (
                set(evidence) == common | {
                    "ir_sha256", "expected_text_sha256", "extracted_text_sha256", "conformance_scope",
                }
                and evidence["ir_sha256"] == ir_sha256
                and _digest(evidence["expected_text_sha256"])
                and evidence["extracted_text_sha256"] == evidence["expected_text_sha256"]
                and (expected_text_sha256 is None
                     or evidence["expected_text_sha256"] == expected_text_sha256)
                and evidence["conformance_scope"] == "PDF_TEXT_CONTENT_ONLY"
            )
        elif name == "visual_geometry":
            margin = evidence.get("min_edge_margin_px")
            pixels = evidence.get("total_pixels")
            valid = valid and (
                set(evidence) == common | {
                    "raster_sha256", "min_edge_margin_px", "total_pixels", "conformance_scope",
                }
                and _digest(evidence["raster_sha256"])
                and type(margin) is int and 2 <= margin <= 999
                and _count(pixels, MAX_TOTAL_PIXELS)
                and evidence["page_count"] * (2 * margin + 1) ** 2 <= pixels
                <= min(MAX_TOTAL_PIXELS, evidence["page_count"] * MAX_PIXELS_PER_PAGE)
                and evidence["conformance_scope"] == "PDF_RASTER_GEOMETRY_ONLY"
            )
        else:
            valid = False
    if not valid:
        raise ValueError("invalid candidate QA evidence")


@dataclass(frozen=True, slots=True)
class _Gate:
    """Immutable scalar projection; unexecuted and blocked gates have no evidence."""

    name: str
    status: str
    evidence: tuple[tuple[str, str | int | bool], ...] | None = None
    errors: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Keep nested output immutable and reject contradictory gate states."""
        if type(self.name) is not str or self.name not in _STAGES:
            raise ValueError("invalid candidate QA stage")
        if type(self.status) is not str or self.status not in {"PASS", "BLOCKED", "NOT_EXECUTED"}:
            raise ValueError("invalid candidate QA status")
        if type(self.errors) is not tuple or any(type(e) is not str or e not in _ERRORS for e in self.errors):
            raise ValueError("invalid candidate QA errors")
        if self.status == "PASS":
            if self.errors or type(self.evidence) is not tuple or not self.evidence:
                raise ValueError("missing candidate QA evidence")
            keys = set()
            for pair in self.evidence:
                if (type(pair) is not tuple or len(pair) != 2 or type(pair[0]) is not str
                        or pair[0] in keys or type(pair[1]) not in (str, int, bool)):
                    raise ValueError("invalid candidate QA projection")
                keys.add(pair[0])
        elif self.evidence is not None or len(self.errors) != (1 if self.status == "BLOCKED" else 0):
            raise ValueError("contradictory candidate QA state")


@dataclass(frozen=True, slots=True)
class PdfCandidateQAValidation:
    """Detached evidence returned by the fixed candidate QA entrypoint."""

    pdf_sha256: str | None
    ir_sha256: str | None
    locale_id: str | None
    gates: tuple[_Gate, ...]

    def __post_init__(self) -> None:
        """Enforce complete ordered evidence and a fail-fast state sequence."""
        if (type(self.gates) is not tuple or len(self.gates) != len(_STAGES)
                or any(type(gate) is not _Gate for gate in self.gates)
                or tuple(gate.name for gate in self.gates) != _STAGES):
            raise ValueError("invalid candidate QA gate sequence")
        if self.gates[0].status == "PASS":
            if (not _digest(self.pdf_sha256) or not _digest(self.ir_sha256)
                    or type(self.locale_id) is not str or self.locale_id != "en-US"):
                raise ValueError("invalid candidate QA identity")
        elif any(value is not None for value in (self.pdf_sha256, self.ir_sha256, self.locale_id)):
            raise ValueError("unverified candidate QA identity")
        blocked = False
        pages = None
        for gate in self.gates:
            if blocked:
                if gate.status != "NOT_EXECUTED":
                    raise ValueError("execution after blocked candidate QA gate")
            elif gate.status == "BLOCKED":
                blocked = True
            elif gate.status == "PASS":
                evidence = dict(gate.evidence)
                _check_evidence(
                    gate.name, evidence, pdf_sha256=self.pdf_sha256,
                    ir_sha256=self.ir_sha256, page_count=pages,
                )
                if gate.name == "object_safety":
                    pages = evidence["page_count"]
            else:
                raise ValueError("unexplained unexecuted candidate QA gate")

    @property
    def passed(self) -> bool:
        """Require every fixed stage to have executed and passed."""
        return all(gate.status == "PASS" for gate in self.gates)

    @property
    def errors(self) -> tuple[str, ...]:
        """Expose fixed aggregate errors only, never child text or exceptions."""
        return tuple(error for gate in self.gates for error in gate.errors)

    @property
    def page_count(self) -> int | None:
        """Claim a common page count only after the full conjunction passes."""
        return dict(self.gates[1].evidence)["page_count"] if self.passed else None

    @property
    def release_authorization(self) -> str:
        """Keep candidate QA separate from authorization to release a report."""
        return "NOT_ESTABLISHED"

    def to_dict(self) -> dict[str, object]:
        """Return fresh JSON-compatible structures with no input or child objects."""
        return {
            "profile_id": PROFILE_ID,
            "status": "PASS" if self.passed else "BLOCKED",
            "conformance_scope": "BOUNDED_GENERATED_PDF_CANDIDATE_QA_ONLY",
            "pdf_sha256": self.pdf_sha256, "ir_sha256": self.ir_sha256,
            "locale_id": self.locale_id, "page_count": self.page_count,
            "release_authorization": self.release_authorization,
            "errors": list(self.errors),
            "gates": {
                gate.name: {
                    "status": gate.status,
                    "evidence": dict(gate.evidence) if gate.evidence is not None else None,
                    "errors": list(gate.errors),
                } for gate in self.gates
            },
            "limitations": [
                "Only existing generated en-US semantic-section report candidates are supported.",
                "PASS covers passive-object policy, controlled metadata, accessibility prerequisites, text content and raster geometry.",
                "Accessibility is bound by invocation; its validator returns no independent PDF digest or page count.",
                "Full accessibility, scientific correctness, provenance, human visual review and release authorization are not established.",
                "Existing child budgets are preserved; metadata and accessibility execute in-process, without an overall sandbox or total time guarantee.",
                "IR input is limited to 8 MiB canonical UTF-8 JSON, depth 64, 100000 expanded nodes and 4096-bit integers.",
            ],
        }


def _project(name: str, child: object, pdf_sha256: str, ir_sha256: str) -> dict:
    """Copy only declared scalar fields from the exact expected result class."""
    expected = {
        "object_safety": PdfSafetyValidation,
        "controlled_metadata": PdfCandidateValidation,
        "accessibility_prerequisites": PdfAccessibilityValidation,
        "text_content": PdfContentValidation,
        "visual_geometry": PdfVisualValidation,
    }[name]
    if type(child) is not expected:
        raise ValueError("unexpected candidate QA result type")
    if (type(child.errors) is not tuple or len(child.errors) > 64
            or any(type(error) is not str or not error or len(error) > 128 for error in child.errors)):
        raise ValueError("invalid child error protocol")
    if name != "accessibility_prerequisites" and child.pdf_sha256 is not None:
        if not _digest(child.pdf_sha256) or child.pdf_sha256 != pdf_sha256:
            raise ValueError("foreign child candidate identity")
    if name == "text_content" and child.ir_sha256 is not None:
        if not _digest(child.ir_sha256) or child.ir_sha256 != ir_sha256:
            raise ValueError("foreign child presentation identity")
    if child.errors:
        raise _ChildRejected()
    if name == "accessibility_prerequisites":
        return {
            "identity_binding": "ENTRYPOINT_INVOCATION", "invocation_pdf_sha256": pdf_sha256,
            "language": child.language, "marked": child.marked,
            "struct_tree_root": child.struct_tree_root, "conformance_claim": child.conformance_claim,
        }
    evidence = {"pdf_sha256": child.pdf_sha256, "page_count": child.page_count}
    if name == "object_safety":
        evidence.update(
            object_count=child.object_count, policy_id=POLICY_ID,
            conformance_scope="REACHABLE_PDF_OBJECT_POLICY_ONLY",
        )
    elif name == "controlled_metadata":
        metadata = child.metadata
        if (type(metadata) not in (dict, MappingProxyType) or set(metadata) != set(_CONTROLLED_METADATA)
                or any(type(key) is not str or type(value) is not str
                       or value != _CONTROLLED_METADATA[key] for key, value in metadata.items())):
            raise ValueError("contradictory controlled metadata")
        evidence.update(
            metadata_profile_id=child.metadata_profile_id,
            accessibility_prerequisites=child.accessibility_prerequisites,
        )
    elif name == "text_content":
        evidence.update(
            ir_sha256=child.ir_sha256, expected_text_sha256=child.expected_text_sha256,
            extracted_text_sha256=child.extracted_text_sha256,
            conformance_scope="PDF_TEXT_CONTENT_ONLY",
        )
    elif name == "visual_geometry":
        evidence.update(
            raster_sha256=child.raster_sha256, min_edge_margin_px=child.min_edge_margin_px,
            total_pixels=child.total_pixels, conformance_scope="PDF_RASTER_GEOMETRY_ONLY",
        )
    return evidence


def validate_pdf_candidate_qa(
    *, presentation_ir: object, expected_ir_sha256: object,
    pdf_bytes: object, expected_pdf_sha256: object,
) -> PdfCandidateQAValidation:
    """Validate one immutable candidate through every fixed gate, stopping on failure."""
    pdf_digest = ir_digest = None
    gates = []

    def fail(name: str, error: str) -> PdfCandidateQAValidation:
        """Keep a PASS prefix, one safe failure, and an explicit unexecuted suffix."""
        gates.append(_Gate(name, "BLOCKED", errors=(error,)))
        gates.extend(_Gate(stage, "NOT_EXECUTED") for stage in _STAGES[len(gates):])
        return PdfCandidateQAValidation(
            pdf_digest, ir_digest, "en-US" if ir_digest is not None else None, tuple(gates),
        )

    try:
        if type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b"%PDF-"):
            raise _PreflightFailure("qa_pdf_bytes_invalid")
        if len(pdf_bytes) > MAX_PDF_BYTES:
            raise _PreflightFailure("qa_input_budget_exceeded")
        if not _digest(expected_pdf_sha256):
            raise _PreflightFailure("qa_expected_pdf_digest_invalid")
        actual_pdf_digest = hashlib.sha256(pdf_bytes).hexdigest()
        if actual_pdf_digest != expected_pdf_sha256:
            raise _PreflightFailure("qa_pdf_digest_mismatch")
        if not _digest(expected_ir_sha256):
            raise _PreflightFailure("qa_expected_ir_digest_invalid")
        snapshot = _snapshot_ir(presentation_ir)
        if snapshot.get("locale_id") != "en-US":
            raise _PreflightFailure("qa_locale_unsupported")
        actual_ir_digest, expected_text_digest = _expected_content(snapshot)
        if actual_ir_digest != expected_ir_sha256:
            raise _PreflightFailure("qa_ir_digest_mismatch")
    except _PreflightFailure as exc:
        return fail("identity_preflight", exc.args[0])
    except Exception:  # noqa: BLE001 - unsupported input must not expose caller content
        return fail("identity_preflight", "qa_presentation_ir_invalid")

    pdf_digest, ir_digest = actual_pdf_digest, actual_ir_digest
    gates.append(_Gate("identity_preflight", "PASS", (
        ("pdf_sha256", pdf_digest), ("ir_sha256", ir_digest), ("locale_id", "en-US"),
    )))
    calls = (
        lambda: validate_pdf_object_safety(pdf_bytes=pdf_bytes, expected_pdf_sha256=pdf_digest),
        lambda: validate_pdf_candidate(
            pdf_bytes=pdf_bytes, expected_pdf_sha256=pdf_digest,
            expected_author=GENERATED_PDF_AUTHOR, expected_language="en-US",
            metadata_profile=GENERATED_PDF_METADATA_PROFILE,
        ),
        lambda: validate_pdf_accessibility_structure(pdf_bytes=pdf_bytes, expected_language="en-US"),
        lambda: validate_pdf_text_content(
            presentation_ir=snapshot, expected_ir_sha256=ir_digest,
            pdf_bytes=pdf_bytes, expected_pdf_sha256=pdf_digest,
        ),
        lambda: validate_pdf_visual_geometry(pdf_bytes=pdf_bytes, expected_pdf_sha256=pdf_digest),
    )
    pages = None
    for name, call in zip(_STAGES[1:], calls, strict=True):
        try:
            child = call()
        except Exception:  # noqa: BLE001 - never retain validator exception messages
            return fail(name, "qa_validator_exception")
        try:
            evidence = _project(name, child, pdf_digest, ir_digest)
            if any(type(value) not in (str, int, bool) for value in evidence.values()):
                raise ValueError("invalid evidence scalar")
            _check_evidence(
                name, evidence, pdf_sha256=pdf_digest, ir_sha256=ir_digest,
                page_count=pages, expected_text_sha256=expected_text_digest,
            )
            gate = _Gate(name, "PASS", tuple(evidence.items()))
        except _ChildRejected:
            return fail(name, "qa_child_validation_failed")
        except Exception:  # noqa: BLE001 - malformed results are a closed protocol boundary
            return fail(name, "qa_validator_result_invalid")
        gates.append(gate)
        if name == "object_safety":
            pages = evidence["page_count"]
    return PdfCandidateQAValidation(pdf_digest, ir_digest, "en-US", tuple(gates))
