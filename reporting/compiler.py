"""Deterministic RPT-02 report-pack compiler."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from collections.abc import Mapping

from reporting.contracts import validate_rpt01_contracts

ROADMAP_ID = "RPT-02"


@dataclass(frozen=True)
class ReportPackCompileResult:
    report_id: str | None
    sections: tuple[dict[str, object], ...]
    pack_sha256: str | None
    errors: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, object]:
        return {
            "roadmap_id": ROADMAP_ID,
            "compile_status": "COMPILED" if self.passed else "FAIL",
            "report_id": self.report_id,
            "sections": list(self.sections),
            "pack_sha256": self.pack_sha256,
            "errors": list(self.errors),
        }


def _canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _failure(error: str, report_id: str | None = None) -> ReportPackCompileResult:
    return ReportPackCompileResult(
        report_id=report_id,
        sections=(),
        pack_sha256=None,
        errors=(error,),
    )


def _resolve_semantic_input(
    canonical_interpretation: object,
    semantic_input: str,
) -> tuple[bool, object]:
    if not isinstance(canonical_interpretation, Mapping):
        return False, None
    prefix = "canonical_interpretation."
    if not semantic_input.startswith(prefix):
        return False, None
    key = semantic_input[len(prefix):]
    if key not in canonical_interpretation:
        return False, None
    return True, canonical_interpretation[key]


def compile_report_pack(
    *,
    report_id: object,
    catalog: object,
    section_contracts: object,
    intended_use: object,
    report_capability_manifest: object,
    canonical_interpretation: object,
) -> ReportPackCompileResult:
    """Compile one canonical report pack without rendering or localization."""

    contracts = validate_rpt01_contracts(
        report_id=report_id,
        catalog=catalog,
        section_contracts=section_contracts,
        intended_use=intended_use,
        report_capability_manifest=report_capability_manifest,
    )
    if not contracts.passed:
        return _failure(
            contracts.errors[0] if contracts.errors else "report_contract_invalid",
            contracts.report_id,
        )

    compiled_sections: list[dict[str, object]] = []
    for section in contracts.sections:
        semantic_payload: dict[str, object] = {}
        for semantic_input in section.required_semantic_inputs:
            found, value = _resolve_semantic_input(
                canonical_interpretation,
                semantic_input,
            )
            if not found:
                return _failure(
                    "missing_required_semantic_input",
                    contracts.report_id,
                )
            semantic_payload[semantic_input] = value

        has_meaningful_content = any(
            value not in (None, "", [], {}, ())
            for value in semantic_payload.values()
        )
        compiled_sections.append(
            {
                "section_id": section.section_id,
                "title": section.title,
                "order": section.order,
                "required": section.required,
                "state": (
                    "PRESENT"
                    if has_meaningful_content
                    else section.empty_state_policy
                ),
                "semantic_payload": semantic_payload,
            }
        )

    canonical_pack = {
        "report_id": contracts.report_id,
        "contract_bundle_sha256": contracts.bundle_sha256,
        "sections": compiled_sections,
    }
    return ReportPackCompileResult(
        report_id=contracts.report_id,
        sections=tuple(compiled_sections),
        pack_sha256=_canonical_sha256(canonical_pack),
        errors=(),
    )
