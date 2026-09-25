"""Canonical RPT-03 ReportViewModel and immutable release bundle builder."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from collections.abc import Sequence

ROADMAP_ID = "RPT-03"


@dataclass(frozen=True)
class Rpt03Result:
    view_model: dict[str, object] | None
    completeness_manifest: dict[str, object] | None
    release_bundle: dict[str, object] | None
    errors: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, object]:
        return {
            "roadmap_id": ROADMAP_ID,
            "status": "PASS" if self.passed else "FAIL",
            "view_model": deepcopy(self.view_model),
            "completeness_manifest": deepcopy(self.completeness_manifest),
            "release_bundle": deepcopy(self.release_bundle),
            "errors": list(self.errors),
        }


def _failure(error: str) -> Rpt03Result:
    return Rpt03Result(None, None, None, (error,))


def _sha256(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def build_report_view_model_and_release_bundle(
    *,
    compiled_report_pack: object,
    artifact_ids: object,
) -> Rpt03Result:
    if not getattr(compiled_report_pack, "passed", False):
        return _failure("compiled_report_pack_invalid")
    if not isinstance(artifact_ids, Sequence) or isinstance(artifact_ids, (str, bytes)):
        return _failure("artifact_ids_required")

    normalized_artifact_ids = list(artifact_ids)
    if not normalized_artifact_ids or any(
        not isinstance(item, str) or not item
        for item in normalized_artifact_ids
    ):
        return _failure("artifact_ids_required")
    if len(normalized_artifact_ids) != len(set(normalized_artifact_ids)):
        return _failure("duplicate_artifact_ids")

    report_id = getattr(compiled_report_pack, "report_id", None)
    sections = deepcopy(list(getattr(compiled_report_pack, "sections", ())))
    pack_sha256 = getattr(compiled_report_pack, "pack_sha256", None)
    if not isinstance(report_id, str) or not report_id:
        return _failure("compiled_report_pack_invalid")
    if not isinstance(pack_sha256, str) or len(pack_sha256) != 64:
        return _failure("compiled_report_pack_invalid")
    if not sections:
        return _failure("compiled_report_pack_invalid")

    missing_required_sections = [
        section.get("section_id")
        for section in sections
        if section.get("required") and not section.get("state")
    ]
    completeness_manifest = {
        "status": "COMPLETE" if not missing_required_sections else "INCOMPLETE",
        "required_section_count": sum(
            1 for section in sections if section.get("required")
        ),
        "present_section_count": sum(
            1 for section in sections
            if section.get("required") and section.get("state")
        ),
        "missing_required_sections": missing_required_sections,
    }
    if missing_required_sections:
        return _failure("report_view_model_incomplete")

    view_model = {
        "report_id": report_id,
        "compiled_report_pack_sha256": pack_sha256,
        "sections": sections,
        "completeness_manifest": deepcopy(completeness_manifest),
    }
    try:
        view_model_sha256 = _sha256(view_model)
        bundle_payload = {
            "schema_version": "1.0.0",
            "release_bundle_id": f"{report_id}:{view_model_sha256[:16]}",
            "release_status": "READY",
            "artifact_ids": normalized_artifact_ids,
            "report_view_model_sha256": view_model_sha256,
            "compiled_report_pack_sha256": pack_sha256,
        }
        bundle_sha256 = _sha256(bundle_payload)
    except ValueError:
        return _failure("non_finite_view_model")
    except TypeError:
        return _failure("view_model_not_json_serializable")

    release_bundle = {
        **bundle_payload,
        "bundle_sha256": bundle_sha256,
    }
    return Rpt03Result(
        deepcopy(view_model),
        deepcopy(completeness_manifest),
        deepcopy(release_bundle),
        (),
    )
