"""Closed, inert same-document navigation binding for sealed typed reports.

Source component IDs and section/finding target IDs are resolved only against
an already sealed en-US typed report projection. No URLs, PDF actions, page
numbers, external sources, HTML links, fonts or renderer resources are created.
Equal digests prove declared byte agreement, not scientific source correctness,
accessibility, report completeness, rights or authorization to release.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from reporting.bindings import ReportBindingError, _digest, _identity
from reporting.components import MAX_COMPONENT_ITEMS
from reporting.typed_html import TypedHtmlError, capture_typed_document

PROFILE_ID = "inert-internal-navigation-v1"
SCHEMA_VERSION = "1.0.0"
MAX_NAVIGATION_INTENTS = MAX_COMPONENT_ITEMS
TARGET_KINDS = frozenset(("section", "finding"))


class NavigationError(ValueError):
    """Content-free rejection of an invalid or unauthorized navigation declaration."""


def _id(value: object) -> None:
    try:
        _identity(value)
    except ReportBindingError:
        raise NavigationError("navigation_identifier_invalid") from None


def _sha(value: object) -> None:
    try:
        _digest(value)
    except ReportBindingError:
        raise NavigationError("navigation_digest_invalid") from None


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


@dataclass(frozen=True, slots=True, repr=False)
class NavigationIntent:
    """A requested semantic destination; never a clickable resource."""

    source_component_id: str
    target_kind: str
    target_id: str

    def __post_init__(self) -> None:
        _id(self.source_component_id)
        _id(self.target_id)
        if type(self.target_kind) is not str or self.target_kind not in TARGET_KINDS:
            raise NavigationError("navigation_target_kind_invalid")

    def to_dict(self) -> dict[str, str]:
        self.__post_init__()
        return {"source_component_id": self.source_component_id,
                "target_kind": self.target_kind, "target_id": self.target_id}


@dataclass(frozen=True, slots=True, repr=False)
class ResolvedNavigation:
    """A source and destination matched to exact known component identities."""

    source_component_id: str
    source_section_id: str
    target_kind: str
    target_id: str
    target_component_id: str
    target_section_id: str

    def __post_init__(self) -> None:
        for value in (self.source_component_id, self.source_section_id,
                      self.target_id, self.target_component_id, self.target_section_id):
            _id(value)
        if type(self.target_kind) is not str or self.target_kind not in TARGET_KINDS:
            raise NavigationError("navigation_target_kind_invalid")

    def requested(self) -> dict[str, str]:
        self.__post_init__()
        return {"source_component_id": self.source_component_id,
                "target_kind": self.target_kind, "target_id": self.target_id}

    def to_dict(self) -> dict[str, str]:
        self.__post_init__()
        return {"source_component_id": self.source_component_id,
                "source_section_id": self.source_section_id,
                "target_kind": self.target_kind, "target_id": self.target_id,
                "target_component_id": self.target_component_id,
                "target_section_id": self.target_section_id}


@dataclass(frozen=True, slots=True, repr=False)
class BoundNavigationReceipt:
    """Digest-bound inert records, detached from the source projection."""

    projection_sha256: str
    expected_intents_sha256: str
    intents: tuple[ResolvedNavigation, ...]

    def __post_init__(self) -> None:
        _sha(self.projection_sha256)
        _sha(self.expected_intents_sha256)
        if type(self.intents) is not tuple or len(self.intents) > MAX_NAVIGATION_INTENTS:
            raise NavigationError("navigation_budget_or_tuple_invalid")
        seen: set[tuple[str, str, str]] = set()
        for item in self.intents:
            if type(item) is not ResolvedNavigation:
                raise NavigationError("typed_resolved_navigation_required")
            item.__post_init__()
            key = (item.source_component_id, item.target_kind, item.target_id)
            if key in seen:
                raise NavigationError("duplicate_navigation_intent")
            seen.add(key)
        actual = hashlib.sha256(_canonical([x.requested() for x in self.intents])).hexdigest()
        if actual != self.expected_intents_sha256:
            raise NavigationError("navigation_expected_intents_digest_mismatch")

    def to_dict(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "schema_version": SCHEMA_VERSION,
            "profile_id": PROFILE_ID,
            "status": "STAGED_UNQUALIFIED",
            "conformance_scope": "EXACT_SECTION_AND_FINDING_ID_BINDING_ONLY",
            "projection_sha256": self.projection_sha256,
            "plan_sha256": self.expected_intents_sha256,
            "intent_count": len(self.intents),
            "intents": [r.to_dict() for r in self.intents],
            "pdf_destinations_activated": False,
            "html_links_activated": False,
            "page_numbers_resolved": False,
            "source_semantics_validated": False,
            "pdf_annotations_qualified": False,
            "renderer_activated": False,
            "release_authorization": "NOT_ESTABLISHED",
        }


def bind_internal_navigation(
    *, projection_ir: object, expected_projection_sha256: object,
    intents: tuple[NavigationIntent, ...], expected_intents_sha256: object,
) -> BoundNavigationReceipt:
    """Bind every declared target to the exact sealed projection, or reject all."""
    _sha(expected_projection_sha256)
    _sha(expected_intents_sha256)
    if type(intents) is not tuple or len(intents) > MAX_NAVIGATION_INTENTS:
        raise NavigationError("navigation_intent_budget_or_type_invalid")
    requested: list[dict[str, str]] = []
    keys: set[tuple[str, str, str]] = set()
    for item in intents:
        if type(item) is not NavigationIntent:
            raise NavigationError("typed_navigation_intent_required")
        item.__post_init__()
        record = item.to_dict()
        k = (item.source_component_id, item.target_kind, item.target_id)
        if k in keys:
            raise NavigationError("duplicate_navigation_intent")
        keys.add(k)
        requested.append(record)
    if hashlib.sha256(_canonical(requested)).hexdigest() != expected_intents_sha256:
        raise NavigationError("navigation_expected_intents_digest_mismatch")
    try:
        doc = capture_typed_document(projection_ir, expected_projection_sha256)
    except (TypedHtmlError, ValueError, TypeError):
        raise NavigationError("navigation_projection_binding_invalid") from None

    components = doc["components"]
    component_map = {c["component_id"]: c for c in components}
    present_sections = {s["section_id"] for s in doc["section_states"]
                        if s["availability"] == "PRESENT"}
    section_components: dict[str, list[dict]] = {}
    section_headings: dict[str, list[dict]] = {}
    findings: dict[str, list[dict]] = {}
    for c in components:
        sid = c["section_id"]
        section_components.setdefault(sid, []).append(c)
        if c["component_type"] == "section_heading":
            section_headings.setdefault(sid, []).append(c)
        if c["component_type"] == "findings_table":
            for row in c["rows"]:
                findings.setdefault(row["finding_id"], []).append(c)

    resolved: list[ResolvedNavigation] = []
    for intent in intents:
        source = component_map.get(intent.source_component_id)
        if source is None:
            raise NavigationError("navigation_source_component_not_present")
        if intent.target_kind == "section":
            if intent.target_id not in present_sections:
                raise NavigationError("navigation_target_section_not_present")
            headings = section_headings.get(intent.target_id, [])
            if len(headings) > 1:
                raise NavigationError("navigation_section_anchor_ambiguous")
            targets = headings or section_components.get(intent.target_id, [])
            if not targets:
                raise NavigationError("navigation_section_anchor_missing")
            target = targets[0]
        else:
            targets = findings.get(intent.target_id, [])
            if len(targets) != 1:
                raise NavigationError("navigation_finding_target_missing_or_ambiguous")
            target = targets[0]
        resolved.append(ResolvedNavigation(
            source_component_id=intent.source_component_id,
            source_section_id=source["section_id"],
            target_kind=intent.target_kind,
            target_id=intent.target_id,
            target_component_id=target["component_id"],
            target_section_id=target["section_id"],
        ))
    return BoundNavigationReceipt(expected_projection_sha256,
                                  expected_intents_sha256, tuple(resolved))
