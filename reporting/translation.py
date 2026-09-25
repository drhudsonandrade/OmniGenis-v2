"""RPT-06 translation orchestration with semantic-equivalence enforcement."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from collections.abc import Mapping
from types import MappingProxyType

ROADMAP_ID = "RPT-06"
_SUPPORTED_PAIRS = frozenset({("en-US", "en-US")})


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
class TranslationResult:
    translated_ir: dict[str, object] | None
    source_locale_id: str | None
    target_locale_id: str | None
    equivalence_status: str | None
    translation_sha256: str | None
    errors: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, object]:
        return {
            "roadmap_id": ROADMAP_ID,
            "status": "PASS" if self.passed else "FAIL",
            "translated_ir": _thaw(self.translated_ir),
            "source_locale_id": self.source_locale_id,
            "target_locale_id": self.target_locale_id,
            "equivalence_status": self.equivalence_status,
            "translation_sha256": self.translation_sha256,
            "errors": list(self.errors),
        }


def _failure(error: str) -> TranslationResult:
    return TranslationResult(None, None, None, None, None, (error,))


def _sha256(value: object) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _validate_ir(presentation_ir: object) -> bool:
    if not isinstance(presentation_ir, Mapping):
        return False
    report_id = presentation_ir.get("report_id")
    components = presentation_ir.get("components")
    if not isinstance(report_id, str) or not report_id:
        return False
    if not isinstance(components, list) or not components:
        return False
    seen_component_ids: set[str] = set()
    for component in components:
        if not isinstance(component, Mapping):
            return False
        if component.get("component_type") != "semantic-section":
            return False
        component_id = component.get("component_id")
        title = component.get("title")
        state = component.get("state")
        if not isinstance(component_id, str) or not component_id:
            return False
        if component_id in seen_component_ids:
            return False
        seen_component_ids.add(component_id)
        if not isinstance(title, str) or not title:
            return False
        if not isinstance(state, str) or not state:
            return False
        if not isinstance(component.get("content"), Mapping):
            return False
    return True


def orchestrate_translation(
    *,
    presentation_ir: object,
    source_locale_id: object,
    target_locale_id: object,
) -> TranslationResult:
    if (
        not isinstance(source_locale_id, str)
        or not isinstance(target_locale_id, str)
        or (source_locale_id, target_locale_id) not in _SUPPORTED_PAIRS
    ):
        return _failure("translation_pair_not_supported")
    if not _validate_ir(presentation_ir):
        return _failure("presentation_ir_invalid")

    translated_ir = deepcopy(dict(presentation_ir))
    source_contents = [
        deepcopy(component["content"]) for component in presentation_ir["components"]
    ]
    target_contents = [
        deepcopy(component["content"]) for component in translated_ir["components"]
    ]
    if source_contents != target_contents:
        return _failure("semantic_equivalence_failed")

    translated_ir["source_locale_id"] = source_locale_id
    translated_ir["target_locale_id"] = target_locale_id
    try:
        digest = _sha256(translated_ir)
    except (TypeError, ValueError):
        return _failure("translation_not_canonical")
    return TranslationResult(
        _freeze(translated_ir),
        source_locale_id,
        target_locale_id,
        "EQUIVALENT",
        digest,
        (),
    )
