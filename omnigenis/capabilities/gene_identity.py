"""Stable HGNC gene identity over a pinned nomenclature snapshot."""

from __future__ import annotations

from collections.abc import Mapping
import csv
from dataclasses import dataclass
import hashlib
import io
import json
import re

CAPABILITY_ID = "hgnc-gene-identity"
CAPABILITY_VERSION = "1.0.0"
PROFILE_ID = "hgnc-gene-identity-2026-09-18-v1"
SOURCE_REGISTRY_ID = "source-registry-minimal-e1a-v1"
SOURCE_ID = "hgnc-gene-nomenclature"
SNAPSHOT_DATE = "2026-09-18"
RESOURCE_SNAPSHOT_ID = "hgnc-2026-09-18"

HGNC_APPROVED_SHA256 = "69bb5722d5a42bb355580deb2c9f197ce3d7f7d13807173b9674a7db65e52191"
HGNC_APPROVED_SIZE_BYTES = 16_940_274
HGNC_APPROVED_ROW_COUNT = 45_083
HGNC_WITHDRAWN_SHA256 = "9328a7361ed5149bf7901cae52c6c30b832b8ec55af22146ea296081278a3140"
HGNC_WITHDRAWN_SIZE_BYTES = 258_994
HGNC_WITHDRAWN_ROW_COUNT = 5_291
HGNC_BUNDLE_SHA256 = "e437feb98c084d34f4988f61d3d0556e59b9aa81e5d082830bfe83e969cdab94"
RULE_RESOURCE_CONTRACT = "HGNC_RESOURCE_CONTRACT"
RULE_RESOURCE_CONTENT = "HGNC_RESOURCE_CONTENT"
RULE_RESOURCE_STRUCTURE = "HGNC_RESOURCE_STRUCTURE"
RULE_QUERY = "GENE_QUERY_CONTRACT"
RULE_RESOLUTION = "GENE_IDENTITY_RESOLUTION"
RULE_LIFECYCLE = "GENE_LIFECYCLE"

_RULE_ORDER = (
    RULE_RESOURCE_CONTRACT,
    RULE_RESOURCE_CONTENT,
    RULE_RESOURCE_STRUCTURE,
    RULE_QUERY,
    RULE_RESOLUTION,
    RULE_LIFECYCLE,
)
_HEX = frozenset("0123456789abcdef")
_HGNC_ID = re.compile(r"^HGNC:[1-9][0-9]*$")
_APPROVED_REQUIRED = frozenset(
    {
        "hgnc_id",
        "symbol",
        "name",
        "locus_group",
        "locus_type",
        "status",
        "alias_symbol",
        "prev_symbol",
    }
)
_WITHDRAWN_REPLACEMENT_FIELD = (
    "MERGED_INTO_REPORT(S) (i.e HGNC_ID|SYMBOL|STATUS)"
)
_WITHDRAWN_REQUIRED = frozenset(
    {"HGNC_ID", "STATUS", "WITHDRAWN_SYMBOL", _WITHDRAWN_REPLACEMENT_FIELD}
)
@dataclass(frozen=True)
class GeneIdentityRuleResult:
    """One independently traceable gene-identity rule result."""

    rule_id: str
    status: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "status": self.status,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class GeneReplacementCandidate:
    """One explicit replacement candidate for a withdrawn HGNC record."""

    hgnc_id: str
    symbol: str
    status: str

    def to_dict(self) -> dict[str, str]:
        return {
            "hgnc_id": self.hgnc_id,
            "symbol": self.symbol,
            "status": self.status,
        }


@dataclass(frozen=True)
class GeneLifecycleRecord:
    """Lifecycle evidence for a withdrawn, merged, or split HGNC record."""

    hgnc_id: str
    status: str
    withdrawn_symbol: str
    replacement_candidates: tuple[GeneReplacementCandidate, ...]
    upstream_duplicate_replacement_candidates: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "hgnc_id": self.hgnc_id,
            "status": self.status,
            "withdrawn_symbol": self.withdrawn_symbol,
            "replacement_candidates": [
                candidate.to_dict()
                for candidate in self.replacement_candidates
            ],
            "upstream_duplicate_replacement_candidates": (
                self.upstream_duplicate_replacement_candidates
            ),
        }


@dataclass(frozen=True)
class CanonicalGeneIdentity:
    """Stable HGNC identity with mutable symbol/name kept as metadata."""

    canonical_gene_id: str
    approved_symbol: str
    approved_name: str
    locus_group: str
    locus_type: str
    resolution_basis: str
    resource_snapshot_id: str
    resource_bundle_sha256: str

    def to_dict(self) -> dict[str, str]:
        return {
            "canonical_gene_id": self.canonical_gene_id,
            "approved_symbol": self.approved_symbol,
            "approved_name": self.approved_name,
            "locus_group": self.locus_group,
            "locus_type": self.locus_type,
            "resolution_basis": self.resolution_basis,
            "resource_snapshot_id": self.resource_snapshot_id,
            "resource_bundle_sha256": self.resource_bundle_sha256,
        }


@dataclass(frozen=True)
class GeneIdentityResult:
    """Tool-neutral HGNC identity result for the initial E1A profile."""

    query: str | None
    gene: CanonicalGeneIdentity | None
    lifecycle: GeneLifecycleRecord | None
    rules: tuple[GeneIdentityRuleResult, ...]
    errors: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return (
            not self.errors
            and self.gene is not None
            and self.lifecycle is None
            and len(self.rules) == len(_RULE_ORDER)
            and all(rule.status == "PASS" for rule in self.rules)
        )

    def to_dict(self) -> dict[str, object]:
        if self.passed:
            canonical_status = "VERIFIED"
        elif self.lifecycle is not None:
            canonical_status = "WITHDRAWN_OR_REPLACED"
        else:
            canonical_status = "FAIL"
        return {
            "capability_id": CAPABILITY_ID,
            "capability_version": CAPABILITY_VERSION,
            "canonical_status": canonical_status,
            "canonical_payload": {
                "query": self.query,
                "gene": self.gene.to_dict() if self.gene else None,
                "lifecycle": (
                    self.lifecycle.to_dict()
                    if self.lifecycle is not None
                    else None
                ),
                "resource_snapshot_id": RESOURCE_SNAPSHOT_ID,
                "resource_bundle_sha256": HGNC_BUNDLE_SHA256,
                "rules": [rule.to_dict() for rule in self.rules],
                "errors": list(self.errors),
            },
            "availability": "AVAILABLE" if self.passed else "BLOCKED",
            "limitations": [
                "HGNC ID is canonical gene identity; approved symbol and name are display/search metadata.",
                "No variant-to-gene interval mapping or transcript/MANE selection is performed.",
                "No molecular consequence, HGVS, evidence federation, or clinical interpretation is performed.",
                "Withdrawn or merged/split records are preserved as lifecycle evidence and are not silently canonicalized.",
            ],
            "executor_id": "omnigenis.python-stdlib",
            "executor_version": CAPABILITY_VERSION,
            "adapter_version": None,
            "model_id": None,
            "resource_release": RESOURCE_SNAPSHOT_ID,
            "reference_bundle": None,
            "execution_profile": "hgnc-gene-identity-2026-09-18-v1",
            "raw_artifact_refs": [
                HGNC_APPROVED_SHA256,
                HGNC_WITHDRAWN_SHA256,
            ],
            "provenance_refs": [
                SOURCE_ID,
                PROFILE_ID,
            ],
        }


@dataclass(frozen=True)
class _ApprovedGene:
    hgnc_id: str
    symbol: str
    name: str
    locus_group: str
    locus_type: str
    aliases: tuple[str, ...]
    previous_symbols: tuple[str, ...]


@dataclass(frozen=True)
class _WithdrawnGene:
    hgnc_id: str
    status: str
    symbol: str
    replacements: tuple[GeneReplacementCandidate, ...]
    upstream_duplicate_replacements: bool
def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _is_nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HEX for character in value)
    )


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_sha256(value: object) -> str:
    return _sha256_bytes(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    )


def _rule(rule_id: str, passed: bool, detail: str) -> GeneIdentityRuleResult:
    return GeneIdentityRuleResult(
        rule_id=rule_id,
        status="PASS" if passed else "FAIL",
        detail=detail,
    )


def _rules(
    states: dict[str, tuple[bool, str]],
) -> tuple[GeneIdentityRuleResult, ...]:
    return tuple(
        _rule(
            rule_id,
            states.get(rule_id, (False, "not_run"))[0],
            states.get(rule_id, (False, "not_run"))[1],
        )
        for rule_id in _RULE_ORDER
    )


def _result(
    *,
    query: str | None,
    states: dict[str, tuple[bool, str]],
    errors: list[str],
    gene: CanonicalGeneIdentity | None = None,
    lifecycle: GeneLifecycleRecord | None = None,
) -> GeneIdentityResult:
    return GeneIdentityResult(
        query=query,
        gene=gene,
        lifecycle=lifecycle,
        rules=_rules(states),
        errors=tuple(errors),
    )
def _source_by_id(
    registry: Mapping[str, object],
    source_id: str,
) -> Mapping[str, object]:
    sources = registry.get("sources")
    if not isinstance(sources, list):
        return {}
    for item in sources:
        candidate = _mapping(item)
        if candidate.get("source_id") == source_id:
            return candidate
    return {}


def _resources_by_role(
    bom: Mapping[str, object],
) -> dict[str, Mapping[str, object]]:
    resources = bom.get("resources")
    if not isinstance(resources, list) or len(resources) != 2:
        return {}
    out: dict[str, Mapping[str, object]] = {}
    for item in resources:
        candidate = _mapping(item)
        role = candidate.get("role")
        if not isinstance(role, str) or role in out:
            return {}
        out[role] = candidate
    return out


def _resource_contract_verified(
    source_registry: object,
    resource_bom: object,
) -> bool:
    registry = _mapping(source_registry)
    bom = _mapping(resource_bom)
    source = _source_by_id(registry, SOURCE_ID)
    resources = _resources_by_role(bom)
    approved = resources.get("approved_gene_records", {})
    withdrawn = resources.get("withdrawn_gene_records", {})
    descriptor = _mapping(bom.get("bundle_descriptor"))
    declared_bundle = bom.get("bundle_sha256")

    resource_common = (
        "source_id",
        "source_url",
        "version_release",
        "license",
        "use_rights",
        "storage_mode",
        "lifecycle",
        "known_issues",
        "replacement_path",
    )
    approved_closed = all(
        _is_nonempty_string(approved.get(field))
        for field in resource_common
    )
    withdrawn_closed = all(
        _is_nonempty_string(withdrawn.get(field))
        for field in resource_common
    )
    expected_descriptor = {
        "profile_id": PROFILE_ID,
        "source_id": SOURCE_ID,
        "upstream_last_modified": SNAPSHOT_DATE,
        "approved_sha256": HGNC_APPROVED_SHA256,
        "approved_size_bytes": HGNC_APPROVED_SIZE_BYTES,
        "withdrawn_sha256": HGNC_WITHDRAWN_SHA256,
        "withdrawn_size_bytes": HGNC_WITHDRAWN_SIZE_BYTES,
    }
    source_ok = all(
        (
            registry.get("registry_id") == SOURCE_REGISTRY_ID,
            registry.get("schema_version") == "1.0.0",
            source.get("source_id") == SOURCE_ID,
            source.get("provider")
            == "HUGO Gene Nomenclature Committee (HGNC)",
            source.get("version_release")
            == "HGNC snapshot 2026-09-18",
            source.get("retrieval_date") == "2026-09-24",
            source.get("license") == "Creative Commons Zero (CC0)",
            source.get("rights_status") == "PUBLIC_DOMAIN_CC0",
            source.get("local_reference_use") == "ALLOWED",
            source.get("redistribution") == "ALLOWED_CC0",
            source.get("lifecycle") == "PINNED_BY_DIGEST",
            isinstance(source.get("source_url"), str)
            and source.get("source_url", "").startswith(
                "https://storage.googleapis.com/public-download-files/hgnc/"
            ),
            isinstance(source.get("terms_url"), str)
            and source.get("terms_url", "").startswith("https://"),
            _is_nonempty_string(source.get("limitations")),
            _is_nonempty_string(source.get("known_issues")),
            _is_nonempty_string(source.get("replacement_path")),
        )
    )
    resources_ok = all(
        (
            len(resources) == 2,
            approved.get("resource_id")
            == "hgnc-approved-complete-set-2026-09-18",
            withdrawn.get("resource_id")
            == "hgnc-withdrawn-set-2026-09-18",
            approved.get("source_id") == SOURCE_ID,
            withdrawn.get("source_id") == SOURCE_ID,
            approved.get("sha256") == HGNC_APPROVED_SHA256,
            approved.get("size_bytes") == HGNC_APPROVED_SIZE_BYTES,
            withdrawn.get("sha256") == HGNC_WITHDRAWN_SHA256,
            withdrawn.get("size_bytes") == HGNC_WITHDRAWN_SIZE_BYTES,
            approved.get("license") == "Creative Commons Zero (CC0)",
            withdrawn.get("license") == "Creative Commons Zero (CC0)",
            approved.get("use_rights") == "PUBLIC_DOMAIN_CC0",
            withdrawn.get("use_rights") == "PUBLIC_DOMAIN_CC0",
            approved.get("storage_mode")
            == "EXTERNAL_PRIVATE_CACHE_NOT_REPOSITORY",
            withdrawn.get("storage_mode")
            == "EXTERNAL_PRIVATE_CACHE_NOT_REPOSITORY",
            approved.get("lifecycle") == "PINNED",
            withdrawn.get("lifecycle") == "PINNED",
            approved_closed,
            withdrawn_closed,
        )
    )
    validation = _mapping(bom.get("validation"))
    validation_ok = all(
        (
            validation.get("approved_row_count")
            == HGNC_APPROVED_ROW_COUNT,
            validation.get("withdrawn_row_count")
            == HGNC_WITHDRAWN_ROW_COUNT,
            validation.get("approved_ids_unique") is True,
            validation.get("approved_symbols_unique") is True,
            validation.get("withdrawn_ids_unique") is True,
            validation.get("withdrawn_symbols_unique") is True,
        )
    )
    if descriptor != expected_descriptor or not _is_sha256(declared_bundle):
        return False
    bundle_ok = all(
        (
            bom.get("schema_version") == "1.0.0",
            bom.get("bom_id")
            == "scientific-resource-bom-hgnc-gene-identity-2026-09-18-v1",
            bom.get("profile_id") == PROFILE_ID,
            bom.get("source_registry_id") == SOURCE_REGISTRY_ID,
            bom.get("source_id") == SOURCE_ID,
            declared_bundle == _canonical_sha256(expected_descriptor),
            declared_bundle == HGNC_BUNDLE_SHA256,
        )
    )
    return source_ok and resources_ok and validation_ok and bundle_ok
def _split_symbols(value: object) -> tuple[str, ...]:
    if not isinstance(value, str) or not value:
        return ()
    return tuple(
        item.strip()
        for item in value.split("|")
        if item.strip()
    )


def _parse_approved(
    data: bytes,
) -> tuple[tuple[_ApprovedGene, ...], str | None]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return (), "hgnc_approved_encoding_invalid"
    reader = csv.DictReader(io.StringIO(text), delimiter="\t")
    if reader.fieldnames is None or not _APPROVED_REQUIRED.issubset(reader.fieldnames):
        return (), "hgnc_approved_columns_invalid"
    rows: list[_ApprovedGene] = []
    ids: set[str] = set()
    symbols: set[str] = set()
    try:
        for raw in reader:
            hgnc_id = (raw.get("hgnc_id") or "").strip()
            symbol = (raw.get("symbol") or "").strip()
            name = (raw.get("name") or "").strip()
            locus_group = (raw.get("locus_group") or "").strip()
            locus_type = (raw.get("locus_type") or "").strip()
            status = (raw.get("status") or "").strip()
            if (
                not _HGNC_ID.fullmatch(hgnc_id)
                or not symbol
                or not name
                or not locus_group
                or not locus_type
                or status != "Approved"
                or hgnc_id in ids
                or symbol in symbols
            ):
                return (), "hgnc_approved_structure_invalid"
            ids.add(hgnc_id)
            symbols.add(symbol)
            rows.append(
                _ApprovedGene(
                    hgnc_id=hgnc_id,
                    symbol=symbol,
                    name=name,
                    locus_group=locus_group,
                    locus_type=locus_type,
                    aliases=_split_symbols(raw.get("alias_symbol")),
                    previous_symbols=_split_symbols(raw.get("prev_symbol")),
                )
            )
    except (csv.Error, AttributeError, TypeError):
        return (), "hgnc_approved_structure_invalid"
    if len(rows) != HGNC_APPROVED_ROW_COUNT:
        return (), "hgnc_approved_row_count_mismatch"
    return tuple(rows), None


def _parse_replacements(
    value: str,
) -> tuple[tuple[GeneReplacementCandidate, ...], bool] | None:
    value = value.strip()
    if not value:
        return (), False
    out: list[GeneReplacementCandidate] = []
    seen: set[tuple[str, str, str]] = set()
    had_duplicate = False
    for item in value.split(","):
        parts = [part.strip() for part in item.split("|")]
        if len(parts) != 3:
            return None
        hgnc_id, symbol, status = parts
        if (
            not _HGNC_ID.fullmatch(hgnc_id)
            or not symbol
            or not status
        ):
            return None
        key = (hgnc_id, symbol, status)
        if key in seen:
            had_duplicate = True
            continue
        seen.add(key)
        out.append(
            GeneReplacementCandidate(
                hgnc_id=hgnc_id,
                symbol=symbol,
                status=status,
            )
        )
    return tuple(out), had_duplicate


def _parse_withdrawn(
    data: bytes,
) -> tuple[tuple[_WithdrawnGene, ...], str | None]:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return (), "hgnc_withdrawn_encoding_invalid"
    reader = csv.DictReader(io.StringIO(text), delimiter="\t")
    if reader.fieldnames is None or not _WITHDRAWN_REQUIRED.issubset(reader.fieldnames):
        return (), "hgnc_withdrawn_columns_invalid"
    rows: list[_WithdrawnGene] = []
    ids: set[str] = set()
    symbols: set[str] = set()
    try:
        for raw in reader:
            hgnc_id = (raw.get("HGNC_ID") or "").strip()
            status = (raw.get("STATUS") or "").strip()
            symbol = (raw.get("WITHDRAWN_SYMBOL") or "").strip()
            parsed_replacements = _parse_replacements(
                raw.get(_WITHDRAWN_REPLACEMENT_FIELD) or ""
            )
            if parsed_replacements is None:
                return (), "hgnc_withdrawn_structure_invalid"
            replacements, had_duplicate_replacements = parsed_replacements
            if (
                not _HGNC_ID.fullmatch(hgnc_id)
                or status not in {"Entry Withdrawn", "Merged/Split"}
                or not symbol
                or hgnc_id in ids
                or symbol in symbols
            ):
                return (), "hgnc_withdrawn_structure_invalid"
            if status == "Entry Withdrawn" and replacements:
                return (), "hgnc_withdrawn_structure_invalid"
            ids.add(hgnc_id)
            symbols.add(symbol)
            rows.append(
                _WithdrawnGene(
                    hgnc_id=hgnc_id,
                    status=status,
                    symbol=symbol,
                    replacements=replacements,
                    upstream_duplicate_replacements=(
                        had_duplicate_replacements
                    ),
                )
            )
    except (csv.Error, AttributeError, TypeError):
        return (), "hgnc_withdrawn_structure_invalid"
    if len(rows) != HGNC_WITHDRAWN_ROW_COUNT:
        return (), "hgnc_withdrawn_row_count_mismatch"
    return tuple(rows), None


def _resource_content_error(
    approved_tsv: object,
    withdrawn_tsv: object,
) -> str | None:
    if not isinstance(approved_tsv, bytes):
        return "hgnc_approved_content_invalid"
    if len(approved_tsv) != HGNC_APPROVED_SIZE_BYTES:
        return "hgnc_approved_size_mismatch"
    if _sha256_bytes(approved_tsv) != HGNC_APPROVED_SHA256:
        return "hgnc_approved_digest_mismatch"
    if not isinstance(withdrawn_tsv, bytes):
        return "hgnc_withdrawn_content_invalid"
    if len(withdrawn_tsv) != HGNC_WITHDRAWN_SIZE_BYTES:
        return "hgnc_withdrawn_size_mismatch"
    if _sha256_bytes(withdrawn_tsv) != HGNC_WITHDRAWN_SHA256:
        return "hgnc_withdrawn_digest_mismatch"
    return None
def _canonical_gene(
    row: _ApprovedGene,
    basis: str,
) -> CanonicalGeneIdentity:
    return CanonicalGeneIdentity(
        canonical_gene_id=row.hgnc_id,
        approved_symbol=row.symbol,
        approved_name=row.name,
        locus_group=row.locus_group,
        locus_type=row.locus_type,
        resolution_basis=basis,
        resource_snapshot_id=RESOURCE_SNAPSHOT_ID,
        resource_bundle_sha256=HGNC_BUNDLE_SHA256,
    )


def _lifecycle_record(row: _WithdrawnGene) -> GeneLifecycleRecord:
    return GeneLifecycleRecord(
        hgnc_id=row.hgnc_id,
        status=row.status,
        withdrawn_symbol=row.symbol,
        replacement_candidates=row.replacements,
        upstream_duplicate_replacement_candidates=(
            row.upstream_duplicate_replacements
        ),
    )


def resolve_gene_identity(
    query: object,
    *,
    approved_tsv: object,
    withdrawn_tsv: object,
    source_registry: object,
    resource_bom: object,
) -> GeneIdentityResult:
    """Resolve one human gene reference to stable HGNC identity using a pinned snapshot."""

    states: dict[str, tuple[bool, str]] = {}
    errors: list[str] = []
    if (
        not isinstance(query, str)
        or not query.strip()
        or len(query.strip()) > 128
        or any(ord(character) < 32 for character in query)
    ):
        states[RULE_QUERY] = (False, "gene_query_invalid")
        errors.append("gene_query_invalid")
        return _result(
            query=query if isinstance(query, str) else None,
            states=states,
            errors=errors,
        )
    normalized_query = query.strip()
    states[RULE_QUERY] = (True, "gene_query_valid")

    if not _resource_contract_verified(source_registry, resource_bom):
        states[RULE_RESOURCE_CONTRACT] = (
            False,
            "hgnc_resource_contract_not_verified",
        )
        errors.append("hgnc_resource_contract_not_verified")
        return _result(
            query=normalized_query,
            states=states,
            errors=errors,
        )
    states[RULE_RESOURCE_CONTRACT] = (
        True,
        "hgnc_source_and_bom_contract_verified",
    )

    content_error = _resource_content_error(
        approved_tsv,
        withdrawn_tsv,
    )
    if content_error is not None:
        states[RULE_RESOURCE_CONTENT] = (False, content_error)
        errors.append(content_error)
        return _result(
            query=normalized_query,
            states=states,
            errors=errors,
        )
    states[RULE_RESOURCE_CONTENT] = (
        True,
        "hgnc_resource_bytes_verified",
    )

    approved_rows, approved_error = _parse_approved(approved_tsv)
    if approved_error is not None:
        states[RULE_RESOURCE_STRUCTURE] = (False, approved_error)
        errors.append(approved_error)
        return _result(
            query=normalized_query,
            states=states,
            errors=errors,
        )
    withdrawn_rows, withdrawn_error = _parse_withdrawn(withdrawn_tsv)
    if withdrawn_error is not None:
        states[RULE_RESOURCE_STRUCTURE] = (False, withdrawn_error)
        errors.append(withdrawn_error)
        return _result(
            query=normalized_query,
            states=states,
            errors=errors,
        )
    states[RULE_RESOURCE_STRUCTURE] = (
        True,
        "hgnc_approved_and_withdrawn_structure_verified",
    )
    approved_by_id = {row.hgnc_id: row for row in approved_rows}
    approved_by_symbol = {row.symbol: row for row in approved_rows}
    withdrawn_by_id = {row.hgnc_id: row for row in withdrawn_rows}
    withdrawn_by_symbol = {row.symbol: row for row in withdrawn_rows}

    current = approved_by_id.get(normalized_query)
    if current is not None:
        states[RULE_RESOLUTION] = (True, "resolved_by_hgnc_id")
        states[RULE_LIFECYCLE] = (True, "current_approved_record")
        return _result(
            query=normalized_query,
            states=states,
            errors=errors,
            gene=_canonical_gene(current, "HGNC_ID"),
        )

    current = approved_by_symbol.get(normalized_query)
    if current is not None:
        states[RULE_RESOLUTION] = (
            True,
            "resolved_by_current_approved_symbol",
        )
        states[RULE_LIFECYCLE] = (True, "current_approved_record")
        return _result(
            query=normalized_query,
            states=states,
            errors=errors,
            gene=_canonical_gene(current, "APPROVED_SYMBOL"),
        )

    withdrawn = withdrawn_by_id.get(normalized_query)
    if withdrawn is None:
        withdrawn = withdrawn_by_symbol.get(normalized_query)
    if withdrawn is not None:
        states[RULE_RESOLUTION] = (
            False,
            "withdrawn_gene_identifier",
        )
        states[RULE_LIFECYCLE] = (
            True,
            "withdrawn_or_replaced_record_preserved",
        )
        errors.append("withdrawn_gene_identifier")
        return _result(
            query=normalized_query,
            states=states,
            errors=errors,
            lifecycle=_lifecycle_record(withdrawn),
        )

    historical: dict[str, tuple[_ApprovedGene, set[str]]] = {}
    for row in approved_rows:
        if normalized_query in row.previous_symbols:
            item = historical.setdefault(
                row.hgnc_id,
                (row, set()),
            )
            item[1].add("PREVIOUS_SYMBOL")
        if normalized_query in row.aliases:
            item = historical.setdefault(
                row.hgnc_id,
                (row, set()),
            )
            item[1].add("ALIAS_SYMBOL")

    if len(historical) > 1:
        states[RULE_RESOLUTION] = (False, "gene_symbol_ambiguous")
        states[RULE_LIFECYCLE] = (
            True,
            "no_current_lifecycle_transition_applied",
        )
        errors.append("gene_symbol_ambiguous")
        return _result(
            query=normalized_query,
            states=states,
            errors=errors,
        )

    if len(historical) == 1:
        row, bases = next(iter(historical.values()))
        basis = (
            "PREVIOUS_SYMBOL"
            if "PREVIOUS_SYMBOL" in bases
            else "ALIAS_SYMBOL"
        )
        states[RULE_RESOLUTION] = (
            True,
            "resolved_by_unique_historical_symbol",
        )
        states[RULE_LIFECYCLE] = (
            True,
            "current_approved_record_from_historical_symbol",
        )
        return _result(
            query=normalized_query,
            states=states,
            errors=errors,
            gene=_canonical_gene(row, basis),
        )

    states[RULE_RESOLUTION] = (False, "gene_identity_not_found")
    states[RULE_LIFECYCLE] = (
        True,
        "no_matching_current_or_withdrawn_record",
    )
    errors.append("gene_identity_not_found")
    return _result(
        query=normalized_query,
        states=states,
        errors=errors,
    )
