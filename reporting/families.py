"""RPT-10 report-family binding over canonical ReportViewModel objects."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import re
from types import MappingProxyType

ROADMAP_ID = "RPT-10"
CATALOG_ID = "e1a-report-family-catalog-v1"
_FAMILY_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def _freeze(value: object) -> object:
    """Recursively freeze mappings and sequences retained by the result."""
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: object) -> object:
    """Return a detached JSON-compatible copy of a frozen value."""
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return deepcopy(value)


def _sha256(value: object) -> str:
    """Return a deterministic SHA-256 over a JSON-compatible value."""
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _nonblank(value: object) -> bool:
    """Return whether a value is a non-empty string after trimming."""
    return isinstance(value, str) and bool(value.strip())


def _string_tuple(value: object) -> tuple[str, ...] | None:
    """Normalize one unique non-empty string array or return None."""
    if not isinstance(value, list) or not value:
        return None
    if not all(_nonblank(item) for item in value):
        return None
    if len(value) != len(set(value)):
        return None
    return tuple(value)


@dataclass(frozen=True)
class Rpt10Result:
    """Immutable result of binding one canonical report to one report family."""

    family_id: str | None
    report_id: str | None
    family_view_model: Mapping[str, object] | None
    family_view_model_sha256: str | None
    errors: tuple[str, ...]

    @property
    def passed(self) -> bool:
        """Return whether the family binding passed all RPT-10 checks."""
        return not self.errors

    def to_dict(self) -> dict[str, object]:
        """Return a detached JSON-compatible representation."""
        return {
            "roadmap_id": ROADMAP_ID,
            "status": "PASS" if self.passed else "FAIL",
            "family_id": self.family_id,
            "report_id": self.report_id,
            "family_view_model": _thaw(self.family_view_model),
            "family_view_model_sha256": self.family_view_model_sha256,
            "errors": list(self.errors),
        }


def _failure(error: str, *, report_id: str | None = None) -> Rpt10Result:
    """Build one fail-closed RPT-10 result."""
    return Rpt10Result(None, report_id, None, None, (error,))


def _validate_family_entry(value: object) -> Mapping[str, object] | None:
    """Validate the closed family descriptor shape used by the public catalog."""
    if not isinstance(value, Mapping):
        return None
    expected = {
        "schema_version",
        "family_id",
        "title",
        "report_ids",
        "required_capability_ids",
        "evaluated_analysis_class_ids",
    }
    if set(value) != expected:
        return None
    if value.get("schema_version") != "1.0.0":
        return None
    family_id = value.get("family_id")
    if (
        not _nonblank(family_id)
        or _FAMILY_ID.fullmatch(str(family_id)) is None
        or not _nonblank(value.get("title"))
    ):
        return None
    for key in (
        "report_ids",
        "required_capability_ids",
        "evaluated_analysis_class_ids",
    ):
        if _string_tuple(value.get(key)) is None:
            return None
    return value


def _family_for_report(
    family_catalog: object,
    report_id: str,
) -> tuple[Mapping[str, object] | None, str | None]:
    """Resolve exactly one family for one canonical report identifier."""
    if not isinstance(family_catalog, Mapping):
        return None, "family_catalog_invalid"
    if set(family_catalog) != {"schema_version", "catalog_id", "families"}:
        return None, "family_catalog_invalid"
    if (
        family_catalog.get("schema_version") != "1.0.0"
        or family_catalog.get("catalog_id") != CATALOG_ID
        or not isinstance(family_catalog.get("families"), list)
        or len(family_catalog["families"]) != 1
    ):
        return None, "family_catalog_invalid"

    validated = []
    family_ids = []
    for entry in family_catalog["families"]:
        parsed = _validate_family_entry(entry)
        if parsed is None:
            return None, "family_catalog_invalid"
        family_ids.append(str(parsed["family_id"]))
        validated.append(parsed)
    if len(family_ids) != len(set(family_ids)):
        return None, "family_catalog_invalid"

    matches = [
        entry for entry in validated
        if report_id in tuple(entry["report_ids"])
    ]
    if not matches:
        return None, "report_family_not_found"
    if len(matches) != 1:
        return None, "report_family_ambiguous"
    return matches[0], None


def _validate_capability_manifest(
    value: object,
    report_id: str,
) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    """Validate the existing report capability binding used by RPT-10."""
    if not isinstance(value, Mapping):
        return None
    if set(value) != {
        "schema_version",
        "report_id",
        "required_capability_ids",
        "evaluated_analysis_class_ids",
    }:
        return None
    if value.get("schema_version") != "1.0.0" or value.get("report_id") != report_id:
        return None
    capabilities = _string_tuple(value.get("required_capability_ids"))
    classes = _string_tuple(value.get("evaluated_analysis_class_ids"))
    if capabilities is None or classes is None:
        return None
    return capabilities, classes


def build_report_family_view_model(
    *,
    family_catalog: object,
    report_capability_manifest: object,
    rpt03_result: object,
) -> Rpt10Result:
    """Bind an existing canonical RPT-03 view model to one report family."""
    if not getattr(rpt03_result, "passed", False):
        return _failure("canonical_report_view_model_required")

    view_model = getattr(rpt03_result, "view_model", None)
    release_bundle = getattr(rpt03_result, "release_bundle", None)
    if not isinstance(view_model, Mapping) or not isinstance(release_bundle, Mapping):
        return _failure("canonical_report_view_model_required")

    report_id = view_model.get("report_id")
    if not _nonblank(report_id):
        return _failure("canonical_report_view_model_required")
    report_id = str(report_id)

    family, error = _family_for_report(family_catalog, report_id)
    if error is not None:
        return _failure(error, report_id=report_id)
    assert family is not None

    manifest = _validate_capability_manifest(report_capability_manifest, report_id)
    if manifest is None:
        return _failure("report_capability_manifest_invalid", report_id=report_id)
    capabilities, analysis_classes = manifest

    family_capabilities = tuple(family["required_capability_ids"])
    if family_capabilities != capabilities:
        return _failure("family_capability_mismatch", report_id=report_id)

    family_analysis_classes = tuple(family["evaluated_analysis_class_ids"])
    if family_analysis_classes != analysis_classes:
        return _failure("family_analysis_class_mismatch", report_id=report_id)

    report_view_model_sha256 = release_bundle.get("report_view_model_sha256")
    if (
        not isinstance(report_view_model_sha256, str)
        or len(report_view_model_sha256) != 64
        or any(character not in "0123456789abcdef" for character in report_view_model_sha256)
    ):
        return _failure("canonical_report_view_model_required", report_id=report_id)

    payload = {
        "family_id": family["family_id"],
        "family_title": family["title"],
        "report_id": report_id,
        "required_capability_ids": list(capabilities),
        "evaluated_analysis_class_ids": list(analysis_classes),
        "report_view_model_sha256": report_view_model_sha256,
        "report_view_model": _thaw(view_model),
    }
    try:
        digest = _sha256(payload)
    except (TypeError, ValueError):
        return _failure("family_view_model_not_serializable", report_id=report_id)

    return Rpt10Result(
        family_id=str(family["family_id"]),
        report_id=report_id,
        family_view_model=_freeze(payload),
        family_view_model_sha256=digest,
        errors=(),
    )
