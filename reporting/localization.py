"""RPT-05 controlled localization for renderer-neutral Presentation IR."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path

ROADMAP_ID = "RPT-05"
_LOCALE_ROOT = Path(__file__).resolve().parent / "locales"


@dataclass(frozen=True)
class LocalizationResult:
    locale_id: str | None
    localized_ir: dict[str, object] | None
    localized_ir_sha256: str | None
    errors: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, object]:
        return {
            "roadmap_id": ROADMAP_ID,
            "status": "PASS" if self.passed else "FAIL",
            "locale_id": self.locale_id,
            "localized_ir": deepcopy(self.localized_ir),
            "localized_ir_sha256": self.localized_ir_sha256,
            "errors": list(self.errors),
        }


def _failure(error: str, locale_id: str | None = None) -> LocalizationResult:
    return LocalizationResult(locale_id, None, None, (error,))


def _sha256(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _load_locale(locale_id: str) -> object:
    path = _LOCALE_ROOT / f"{locale_id}.v1.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def localize_presentation_ir(
    *,
    presentation_ir: object,
    locale_id: object,
) -> LocalizationResult:
    if not isinstance(locale_id, str) or not locale_id:
        return _failure("locale_not_supported")
    catalog = _load_locale(locale_id)
    if not isinstance(catalog, Mapping):
        return _failure("locale_not_supported", locale_id)
    labels = catalog.get("labels")
    if not isinstance(labels, Mapping):
        return _failure("locale_catalog_invalid", locale_id)
    if not isinstance(presentation_ir, Mapping):
        return _failure("presentation_ir_invalid", locale_id)
    report_id = presentation_ir.get("report_id")
    components = presentation_ir.get("components")
    if not isinstance(report_id, str) or not report_id:
        return _failure("presentation_ir_invalid", locale_id)
    if not isinstance(components, list) or not components:
        return _failure("presentation_ir_invalid", locale_id)
    if any(not isinstance(component, Mapping) for component in components):
        return _failure("presentation_ir_invalid", locale_id)

    localized_components: list[dict[str, object]] = []
    for component in components:
        component_id = component.get("component_id")
        if not isinstance(component_id, str) or component_id not in labels:
            return _failure("localization_key_missing", locale_id)
        localized = deepcopy(dict(component))
        localized["title"] = labels[component_id]
        localized_components.append(localized)

    localized_ir = {
        "report_id": report_id,
        "locale_id": locale_id,
        "components": localized_components,
    }
    try:
        digest = _sha256(localized_ir)
    except (TypeError, ValueError):
        return _failure("localized_ir_not_canonical", locale_id)
    return LocalizationResult(locale_id, deepcopy(localized_ir), digest, ())
