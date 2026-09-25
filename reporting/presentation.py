"""RPT-04 renderer-neutral Presentation IR and semantic component registry."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from collections.abc import Mapping

ROADMAP_ID = "RPT-04"


@dataclass(frozen=True)
class PresentationResult:
    presentation_ir: dict[str, object] | None
    component_registry: dict[str, str] | None
    presentation_ir_sha256: str | None
    errors: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, object]:
        return {
            "roadmap_id": ROADMAP_ID,
            "status": "PASS" if self.passed else "FAIL",
            "presentation_ir": deepcopy(self.presentation_ir),
            "component_registry": deepcopy(self.component_registry),
            "presentation_ir_sha256": self.presentation_ir_sha256,
            "errors": list(self.errors),
        }


def _failure(error: str) -> PresentationResult:
    return PresentationResult(None, None, None, (error,))


def _sha256(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def build_presentation_ir(*, report_view_model: object) -> PresentationResult:
    if not isinstance(report_view_model, Mapping):
        return _failure("report_view_model_invalid")
    report_id = report_view_model.get("report_id")
    sections = report_view_model.get("sections")
    if not isinstance(report_id, str) or not report_id:
        return _failure("report_view_model_invalid")
    if not isinstance(sections, list) or not sections:
        return _failure("report_view_model_invalid")
    if any(not isinstance(section, Mapping) for section in sections):
        return _failure("report_view_model_invalid")

    components: list[dict[str, object]] = []
    registry: dict[str, str] = {}
    for section in sections:
        section_id = section.get("section_id")
        title = section.get("title")
        state = section.get("state")
        semantic_payload = section.get("semantic_payload")
        if (
            not isinstance(section_id, str)
            or not section_id
            or not isinstance(title, str)
            or not title
            or not isinstance(state, str)
            or not state
            or not isinstance(semantic_payload, Mapping)
        ):
            return _failure("report_view_model_invalid")
        if section_id in registry:
            return _failure("duplicate_component_id")
        registry[section_id] = "semantic-section"
        components.append(
            {
                "component_id": section_id,
                "component_type": "semantic-section",
                "title": title,
                "state": state,
                "content": deepcopy(dict(semantic_payload)),
            }
        )

    presentation_ir = {
        "report_id": report_id,
        "components": components,
    }
    try:
        digest = _sha256(presentation_ir)
    except (TypeError, ValueError):
        return _failure("presentation_ir_not_canonical")
    return PresentationResult(
        deepcopy(presentation_ir),
        deepcopy(registry),
        digest,
        (),
    )
