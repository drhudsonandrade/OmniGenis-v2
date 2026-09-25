"""RPT-07 primary renderer and controlled lifecycle profile."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from collections.abc import Mapping

ROADMAP_ID = "RPT-07"
_PRIMARY_RENDERER = "canonical-text-v1"
_SUPPORTED_LIFECYCLE_PROFILES = frozenset({"preview"})


@dataclass(frozen=True)
class RenderResult:
    renderer_id: str | None
    lifecycle_profile: str | None
    artifact_text: str | None
    artifact_sha256: str | None
    errors: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, object]:
        return {
            "roadmap_id": ROADMAP_ID,
            "status": "PASS" if self.passed else "FAIL",
            "renderer_id": self.renderer_id,
            "lifecycle_profile": self.lifecycle_profile,
            "artifact_text": self.artifact_text,
            "artifact_sha256": self.artifact_sha256,
            "errors": list(self.errors),
        }


def _failure(error: str) -> RenderResult:
    return RenderResult(None, None, None, None, (error,))


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
        title = component.get("title")
        state = component.get("state")
        content = component.get("content")
        if component.get("component_type") != "semantic-section":
            return False
        if not isinstance(component_id, str) or not component_id or component_id in seen:
            return False
        seen.add(component_id)
        if not isinstance(title, str) or not title:
            return False
        if not isinstance(state, str) or not state:
            return False
        if not isinstance(content, Mapping):
            return False
    return True


def render_primary(
    *,
    presentation_ir: object,
    renderer_id: object,
    lifecycle_profile: object,
) -> RenderResult:
    if renderer_id != _PRIMARY_RENDERER:
        return _failure("renderer_not_supported")
    if (
        not isinstance(lifecycle_profile, str)
        or lifecycle_profile not in _SUPPORTED_LIFECYCLE_PROFILES
    ):
        return _failure("lifecycle_profile_not_supported")
    if not _validate_ir(presentation_ir):
        return _failure("presentation_ir_invalid")

    lines = [
        f"Report: {presentation_ir['report_id']}",
        f"Lifecycle: {lifecycle_profile}",
    ]
    try:
        for component in presentation_ir["components"]:
            canonical_content = json.dumps(
                component["content"],
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
            lines.extend(
                [
                    "",
                    component["title"],
                    f"State: {component['state']}",
                    canonical_content,
                ]
            )
        artifact_text = "\n".join(lines) + "\n"
        digest = hashlib.sha256(artifact_text.encode("utf-8")).hexdigest()
    except (TypeError, ValueError, UnicodeEncodeError):
        return _failure("presentation_ir_invalid")
    return RenderResult(
        _PRIMARY_RENDERER,
        lifecycle_profile,
        artifact_text,
        digest,
        (),
    )
