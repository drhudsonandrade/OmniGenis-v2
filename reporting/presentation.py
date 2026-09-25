"""RPT-04 renderer-neutral Presentation IR and semantic component registry."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from collections.abc import Mapping
from types import MappingProxyType

ROADMAP_ID = "RPT-04"


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return deepcopy(value)


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
            "presentation_ir": _thaw(self.presentation_ir),
            "component_registry": _thaw(self.component_registry),
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
    sections = _thaw(report_view_model.get("sections"))
    completeness_manifest = _thaw(report_view_model.get("completeness_manifest"))
    if not isinstance(report_id, str) or not report_id:
        return _failure("report_view_model_invalid")
    if not isinstance(sections, list) or not sections:
        return _failure("report_view_model_invalid")
    if any(not isinstance(section, Mapping) for section in sections):
        return _failure("report_view_model_invalid")
    if not isinstance(completeness_manifest, Mapping):
        return _failure("report_view_model_invalid")
    completeness_status = completeness_manifest.get("status")
    required_count = completeness_manifest.get("required_section_count")
    present_count = completeness_manifest.get("present_section_count")
    missing_required = completeness_manifest.get("missing_required_sections")
    if (
        not isinstance(completeness_status, str)
        or not isinstance(required_count, int)
        or not isinstance(present_count, int)
        or not isinstance(missing_required, list)
    ):
        return _failure("report_view_model_invalid")
    required_sections = [section for section in sections if section.get("required")]
    if (
        completeness_status != "COMPLETE"
        or missing_required
        or len(required_sections) != required_count
        or len(required_sections) != present_count
    ):
        return _failure("report_view_model_incomplete")
    orders = [section.get("order") for section in sections]
    if (
        any(not isinstance(order, int) for order in orders)
        or len(set(orders)) != len(orders)
        or orders != sorted(orders)
    ):
        return _failure("report_view_model_order_invalid")

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
        _freeze(presentation_ir),
        _freeze(registry),
        digest,
        (),
    )
