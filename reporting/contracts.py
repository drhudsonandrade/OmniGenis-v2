"""Deterministic RPT-01 reporting contract validation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
import re

ROADMAP_ID = "RPT-01"
REPORT_ID = "e1a-small-variant-report"
CATALOG_ID = "e1a-report-catalog-v1"

_ALLOWED_SEMANTIC_INPUTS = frozenset(
    {
        "canonical_interpretation.identity",
        "canonical_interpretation.items",
        "canonical_interpretation.conflicts",
        "canonical_interpretation.limitations",
        "canonical_interpretation.provenance",
    }
)
_ALLOWED_EMPTY_POLICIES = frozenset(
    {
        "EXPLICIT_NOT_AVAILABLE",
        "EXPLICIT_NONE",
        "EXPLICIT_NO_CONFLICTS",
    }
)
_SECTION_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_HEX6 = re.compile(r"^[0-9A-Fa-f]{6}$")
_CANONICAL_PROHIBITED_CLAIMS = frozenset(
    {
        "Do not claim or establish a clinical diagnosis from this report contract.",
        "Do not recommend or select treatment from this report contract.",
    }
)
@dataclass(frozen=True)
class ReportSectionContractRecord:
    report_id: str
    section_id: str
    title: str
    order: int
    required: bool
    required_semantic_inputs: tuple[str, ...]
    empty_state_policy: str

    def to_dict(self) -> dict[str, object]:
        return {
            "report_id": self.report_id,
            "section_id": self.section_id,
            "title": self.title,
            "order": self.order,
            "required": self.required,
            "required_semantic_inputs": list(
                self.required_semantic_inputs
            ),
            "empty_state_policy": self.empty_state_policy,
        }


@dataclass(frozen=True)
class ReportIntendedUseRecord:
    report_id: str
    intended_use_id: str
    intended_use_category: str
    summary: str
    intended_audience: tuple[str, ...]
    clinical_use_status: str
    permitted_uses: tuple[str, ...]
    prohibited_claims: tuple[str, ...]
    confirmation_status: str
    locale_status: str

    def to_dict(self) -> dict[str, object]:
        return {
            "report_id": self.report_id,
            "intended_use_id": self.intended_use_id,
            "intended_use_category": self.intended_use_category,
            "summary": self.summary,
            "intended_audience": list(self.intended_audience),
            "clinical_use_status": self.clinical_use_status,
            "permitted_uses": list(self.permitted_uses),
            "prohibited_claims": list(self.prohibited_claims),
            "confirmation_status": self.confirmation_status,
            "locale_status": self.locale_status,
        }


@dataclass(frozen=True)
class Rpt01ContractBundleResult:
    report_id: str | None
    catalog_id: str | None
    code: str | None
    slug: str | None
    title: str | None
    purpose: str | None
    audience: str | None
    sections: tuple[ReportSectionContractRecord, ...]
    intended_use: ReportIntendedUseRecord | None
    required_capability_ids: tuple[str, ...]
    evaluated_analysis_class_ids: tuple[str, ...]
    bundle_sha256: str | None
    errors: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, object]:
        return {
            "roadmap_id": ROADMAP_ID,
            "contract_status": "VALIDATED" if self.passed else "FAIL",
            "report_id": self.report_id,
            "catalog_id": self.catalog_id,
            "code": self.code,
            "slug": self.slug,
            "title": self.title,
            "purpose": self.purpose,
            "audience": self.audience,
            "sections": [
                section.to_dict()
                for section in self.sections
            ],
            "intended_use": (
                self.intended_use.to_dict()
                if self.intended_use is not None
                else None
            ),
            "required_capability_ids": list(
                self.required_capability_ids
            ),
            "evaluated_analysis_class_ids": list(
                self.evaluated_analysis_class_ids
            ),
            "bundle_sha256": self.bundle_sha256,
            "errors": list(self.errors),
        }


def _nonblank(value: object) -> bool:
    return type(value) is str and bool(value.strip())


def _string_tuple(
    value: object,
) -> tuple[str, ...] | None:
    if not isinstance(value, list):
        return None
    if not all(_nonblank(item) for item in value):
        return None
    if len(value) != len(set(value)):
        return None
    return tuple(value)


def _canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _failure(
    error: str,
    *,
    report_id: str | None = None,
) -> Rpt01ContractBundleResult:
    return Rpt01ContractBundleResult(
        report_id=report_id,
        catalog_id=None,
        code=None,
        slug=None,
        title=None,
        purpose=None,
        audience=None,
        sections=(),
        intended_use=None,
        required_capability_ids=(),
        evaluated_analysis_class_ids=(),
        bundle_sha256=None,
        errors=(error,),
    )


def _catalog_entry(
    catalog: object,
    report_id: object,
) -> tuple[Mapping[str, object] | None, str | None]:
    if not isinstance(catalog, Mapping):
        return None, "catalog_invalid"
    if frozenset(catalog) != frozenset(
        {"schema_version", "catalog_id", "reports"}
    ):
        return None, "catalog_invalid"
    if (
        catalog.get("schema_version") != "1.0.0"
        or catalog.get("catalog_id") != CATALOG_ID
        or not isinstance(catalog.get("reports"), list)
    ):
        return None, "catalog_invalid"
    if not _nonblank(report_id):
        return None, "report_id_not_in_catalog"
    entries = [
        entry
        for entry in catalog["reports"]
        if isinstance(entry, Mapping)
        and entry.get("report_id") == report_id
    ]
    if len(entries) != 1:
        return None, "report_id_not_in_catalog"
    entry = entries[0]
    expected = frozenset(
        {
            "schema_version",
            "report_id",
            "code",
            "accent",
            "slug",
            "title",
            "tagline",
            "purpose",
            "audience",
            "sections",
        }
    )
    if frozenset(entry) != expected:
        return None, "catalog_invalid"
    text_fields = (
        "report_id",
        "code",
        "slug",
        "title",
        "tagline",
        "purpose",
        "audience",
    )
    if (
        entry.get("schema_version") != "1.0.0"
        or not all(_nonblank(entry.get(key)) for key in text_fields)
        or not _nonblank(entry.get("accent"))
        or _HEX6.fullmatch(str(entry.get("accent"))) is None
    ):
        return None, "catalog_invalid"
    section_titles = _string_tuple(entry.get("sections"))
    if section_titles is None or not section_titles:
        return None, "catalog_invalid"
    return entry, None


def _parse_sections(
    value: object,
    *,
    report_id: str,
    catalog_titles: tuple[str, ...],
) -> tuple[
    tuple[ReportSectionContractRecord, ...] | None,
    str | None,
]:
    if not isinstance(value, Mapping):
        return None, "section_contract_invalid"
    if frozenset(value) != frozenset(
        {"schema_version", "report_id", "sections"}
    ):
        return None, "section_contract_invalid"
    if value.get("report_id") != report_id:
        return None, "report_contract_binding_mismatch"
    raw_sections = value.get("sections")
    if (
        value.get("schema_version") != "1.0.0"
        or not isinstance(raw_sections, list)
        or not raw_sections
    ):
        return None, "section_contract_invalid"

    records: list[ReportSectionContractRecord] = []
    ids: set[str] = set()
    titles: set[str] = set()
    orders: set[int] = set()
    expected_keys = frozenset(
        {
            "schema_version",
            "report_id",
            "section_id",
            "title",
            "order",
            "required",
            "required_semantic_inputs",
            "empty_state_policy",
        }
    )
    for raw in raw_sections:
        if not isinstance(raw, Mapping):
            return None, "section_contract_invalid"
        if frozenset(raw) != expected_keys:
            return None, "section_contract_invalid"
        if raw.get("report_id") != report_id:
            return None, "report_contract_binding_mismatch"
        section_id = raw.get("section_id")
        title = raw.get("title")
        order = raw.get("order")
        required = raw.get("required")
        semantic_inputs = _string_tuple(
            raw.get("required_semantic_inputs")
        )
        empty_state = raw.get("empty_state_policy")
        if (
            raw.get("schema_version") != "1.0.0"
            or not _nonblank(section_id)
            or _SECTION_ID.fullmatch(section_id) is None
            or not _nonblank(title)
            or type(order) is not int
            or order <= 0
            or type(required) is not bool
            or semantic_inputs is None
            or type(empty_state) is not str
            or empty_state not in _ALLOWED_EMPTY_POLICIES
        ):
            return None, "section_contract_invalid"
        if any(
            item not in _ALLOWED_SEMANTIC_INPUTS
            for item in semantic_inputs
        ):
            return None, "section_semantic_input_not_allowed"
        if (
            section_id in ids
            or title in titles
            or order in orders
        ):
            return None, "section_contract_invalid"
        ids.add(section_id)
        titles.add(title)
        orders.add(order)
        records.append(
            ReportSectionContractRecord(
                report_id=report_id,
                section_id=section_id,
                title=title,
                order=order,
                required=required,
                required_semantic_inputs=semantic_inputs,
                empty_state_policy=str(empty_state),
            )
        )

    records.sort(key=lambda item: item.order)
    if tuple(item.order for item in records) != tuple(
        range(1, len(records) + 1)
    ):
        return None, "section_contract_invalid"
    if tuple(item.title for item in records) != catalog_titles:
        return None, "report_contract_binding_mismatch"
    return tuple(records), None
def _parse_intended_use(
    value: object,
    *,
    report_id: str,
) -> tuple[ReportIntendedUseRecord | None, str | None]:
    if not isinstance(value, Mapping):
        return None, "intended_use_invalid"
    expected_keys = frozenset(
        {
            "schema_version",
            "report_id",
            "intended_use_id",
            "intended_use_category",
            "summary",
            "intended_audience",
            "clinical_use_status",
            "permitted_uses",
            "prohibited_claims",
            "confirmation_status",
            "locale_status",
        }
    )
    if frozenset(value) != expected_keys:
        return None, "intended_use_invalid"
    if value.get("report_id") != report_id:
        return None, "report_contract_binding_mismatch"
    audience = _string_tuple(value.get("intended_audience"))
    permitted = _string_tuple(value.get("permitted_uses"))
    prohibited = _string_tuple(value.get("prohibited_claims"))
    if (
        value.get("schema_version") != "1.0.0"
        or not _nonblank(value.get("intended_use_id"))
        or _SECTION_ID.fullmatch(str(value.get("intended_use_id"))) is None
        or value.get("intended_use_category")
        != "TECHNICAL_E1A_VALIDATION"
        or not _nonblank(value.get("summary"))
        or audience is None
        or not audience
        or value.get("clinical_use_status")
        != "NOT_CLINICALLY_PROMOTED"
        or permitted is None
        or not permitted
        or prohibited is None
        or len(prohibited) != 2
        or frozenset(prohibited) != _CANONICAL_PROHIBITED_CLAIMS
        or value.get("confirmation_status")
        != "NOT_DEFINED_IN_RPT01"
        or value.get("locale_status")
        != "CANONICAL_ENGLISH_ONLY"
    ):
        return None, "intended_use_invalid"
    return (
        ReportIntendedUseRecord(
            report_id=report_id,
            intended_use_id=str(value["intended_use_id"]),
            intended_use_category="TECHNICAL_E1A_VALIDATION",
            summary=str(value["summary"]),
            intended_audience=audience,
            clinical_use_status="NOT_CLINICALLY_PROMOTED",
            permitted_uses=permitted,
            prohibited_claims=prohibited,
            confirmation_status="NOT_DEFINED_IN_RPT01",
            locale_status="CANONICAL_ENGLISH_ONLY",
        ),
        None,
    )


def _parse_capability_manifest(
    value: object,
    *,
    report_id: str,
) -> tuple[
    tuple[str, ...] | None,
    tuple[str, ...] | None,
    str | None,
]:
    if not isinstance(value, Mapping):
        return None, None, "report_capability_manifest_invalid"
    expected_keys = frozenset(
        {
            "schema_version",
            "report_id",
            "required_capability_ids",
            "evaluated_analysis_class_ids",
        }
    )
    if frozenset(value) != expected_keys:
        return None, None, "report_capability_manifest_invalid"
    if value.get("report_id") != report_id:
        return None, None, "report_contract_binding_mismatch"
    required = _string_tuple(value.get("required_capability_ids"))
    analysis = _string_tuple(value.get("evaluated_analysis_class_ids"))
    if (
        value.get("schema_version") != "1.0.0"
        or required != ("canonical-interpretation-object",)
        or analysis != ("germline-snv-small-indel",)
    ):
        return None, None, "report_capability_manifest_invalid"
    return required, analysis, None


def validate_rpt01_contracts(
    *,
    report_id: object,
    catalog: object,
    section_contracts: object,
    intended_use: object,
    report_capability_manifest: object,
) -> Rpt01ContractBundleResult:
    """Validate the single, non-rendering E1A RPT-01 contract bundle."""

    entry, error = _catalog_entry(catalog, report_id)
    if error is not None or entry is None:
        return _failure(
            error or "catalog_invalid",
            report_id=report_id if isinstance(report_id, str) else None,
        )
    bound_report_id = str(entry["report_id"])
    catalog_titles = tuple(entry["sections"])

    sections, error = _parse_sections(
        section_contracts,
        report_id=bound_report_id,
        catalog_titles=catalog_titles,
    )
    if error is not None or sections is None:
        return _failure(error or "section_contract_invalid", report_id=bound_report_id)

    intended, error = _parse_intended_use(
        intended_use,
        report_id=bound_report_id,
    )
    if error is not None or intended is None:
        return _failure(error or "intended_use_invalid", report_id=bound_report_id)

    required, analysis, error = _parse_capability_manifest(
        report_capability_manifest,
        report_id=bound_report_id,
    )
    if error is not None or required is None or analysis is None:
        return _failure(
            error or "report_capability_manifest_invalid",
            report_id=bound_report_id,
        )

    canonical_payload = {
        "catalog_entry": dict(entry),
        "sections": [section.to_dict() for section in sections],
        "intended_use": intended.to_dict(),
        "report_capability_manifest": dict(report_capability_manifest),
    }
    return Rpt01ContractBundleResult(
        report_id=bound_report_id,
        catalog_id=CATALOG_ID,
        code=str(entry["code"]),
        slug=str(entry["slug"]),
        title=str(entry["title"]),
        purpose=str(entry["purpose"]),
        audience=str(entry["audience"]),
        sections=sections,
        intended_use=intended,
        required_capability_ids=required,
        evaluated_analysis_class_ids=analysis,
        bundle_sha256=_canonical_sha256(canonical_payload),
        errors=(),
    )
