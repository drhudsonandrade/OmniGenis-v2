"""Opt-in strict native generated-PDF structural parent/child role-edge inventory.

A bounded lexical check only: it does not qualify PDF/UA, reading order,
accessibility semantics, release, or activation of the default pipeline.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

from reporting.page_windows import PageWindowPlan
from reporting.pdf_text_windows import PROFILE_ID as TEXT_PROFILE
from reporting.pdf_object_graph import _canonical, _start, _unique_pairs, _wait
from reporting import pdf_structure_role_tokens as parent
from reporting import _pdf_structure_tree_worker as tree
from reporting._pdf_object_graph_worker import (
    CPU_SECONDS, IDENTITY_FIELDS, MAX_PDF_BYTES, MEMORY_BYTES, OPEN_FILES,
    PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES, _is_digest,
)
from reporting._pdf_structure_role_edges_worker import (
    EDGE_KEYS, EDGE_PAIRS, LANGUAGE, MAX_DOCUMENT_PAGES, MAX_TREE_DEPTH,
    MAX_TREE_VISITS, POLICY_ID, PROFILE_ID, STATUS,
    _identity, _identity_from_plan,
)

_LIMITS = {
    "memory_bytes": MEMORY_BYTES, "cpu_seconds": CPU_SECONDS,
    "file_bytes": RESULT_BYTES, "open_files": OPEN_FILES,
}
_FIXED_ENVELOPE = (64, 8 * 1024 * 1024, 64, 20000)
_FIXED_PARENT_SHA256 = "442117c837e9ef8b7a8afb7371b9e9dd876334a7147334ee8c7a1d59ed28de73"
_DISABLE = "OMNIGENIS_PDF_STRUCTURE_ROLE_EDGES_DISABLED"


class PdfStructureRoleEdgesError(ValueError):
    """No unverifiable generated native parent/child role edge is admitted."""


def _edge_pairs(value: object) -> tuple[tuple[str, int], ...]:
    """Accept an exact, sorted subset of allowed edges with positive counts."""
    if type(value) is dict:
        pairs = tuple(sorted(value.items()))
    elif type(value) is tuple:
        pairs = value
    else:
        raise ValueError("role edges must be a concrete mapping or immutable tuple")
    if (not pairs or len(pairs) > len(EDGE_KEYS)
            or any(type(pair) is not tuple or len(pair) != 2
                   or type(pair[0]) is not str or pair[0] not in EDGE_KEYS
                   or type(pair[1]) is not int or pair[1] < 1
                   for pair in pairs)
            or tuple(name for name, _ in pairs) !=
               tuple(sorted({name for name, _ in pairs}))):
        raise ValueError("role edge inventory outside bounded adjacency profile")
    return pairs


def structure_role_edges_profile() -> dict:
    """Exact current generated lexical adjacency subset, no accessibility claims."""
    return {
        "schema_version": "1.0.0",
        "profile_id": PROFILE_ID,
        "policy_id": POLICY_ID,
        "parser_version": PARSER_VERSION,
        "parent_role_profile_sha256": parent.PROFILE_SHA256,
        "parent_structure_policy_id": tree.POLICY_ID,
        "max_pages": MAX_DOCUMENT_PAGES,
        "max_pdf_bytes": MAX_PDF_BYTES,
        "max_tree_depth": MAX_TREE_DEPTH,
        "max_tree_visits": MAX_TREE_VISITS,
        "language": LANGUAGE,
        "supported_role_edges": [list(pair) for pair in EDGE_PAIRS],
        "root_sentinel": "ROOT",
        "conformance_scope": "KNOWN_GENERATED_PDF_ROLE_ADJACENCY_ONLY",
        "all_reachable_role_edges_inventoried": True,
        "semantic_role_appropriateness_verified": False,
        "reading_order_verified": False,
        "pdf_ua_qualified": False,
        "worker_results_authenticated": False,
        "all_file_revisions_inspected": False,
        "aggregate_job_resources_qualified": False,
        "default_pipeline_activated": False,
        "release_authorized": False,
    }


PROFILE_SHA256 = sha256(_canonical(structure_role_edges_profile())).hexdigest()


def _profile() -> None:
    """Fail closed on parser/dependency drift and on an explicit disable switch."""
    parent._profile()
    if (sys.platform != "linux" or os.environ.get(_DISABLE) == "1"
            or (MAX_DOCUMENT_PAGES, MAX_PDF_BYTES, MAX_TREE_DEPTH, MAX_TREE_VISITS)
               != _FIXED_ENVELOPE
            or (tree.MAX_DOCUMENT_PAGES, tree.MAX_PDF_BYTES, tree.MAX_TREE_DEPTH,
                tree.MAX_TREE_VISITS) != _FIXED_ENVELOPE
            or LANGUAGE != "en-US"
            or parent.PROFILE_SHA256 != _FIXED_PARENT_SHA256
            or sha256(_canonical(structure_role_edges_profile())).hexdigest()
               != PROFILE_SHA256):
        raise ValueError("native role adjacency profile disabled or changed")


@dataclass(frozen=True, slots=True, repr=False)
class PdfStructureRoleEdges:
    """Sealed unsigned inventory of role edges on one exact final generated PDF."""

    pdf_sha256: str
    ir_sha256: str
    plan_sha256: str
    page_count: int
    structure_elements: int
    mapped_mcids: int
    inspected_pages: int
    edge_counts: tuple[tuple[str, int], ...]
    _sealed_sha256: str = field(init=False, repr=False, compare=False)

    def _record(self) -> dict:
        _profile()
        _identity({key: getattr(self, key) for key in IDENTITY_FIELDS})
        pairs = _edge_pairs(self.edge_counts)
        if (type(self.structure_elements) is not int
                or type(self.mapped_mcids) is not int
                or type(self.inspected_pages) is not int
                or not 1 <= self.structure_elements <= MAX_TREE_VISITS
                or not self.page_count <= self.mapped_mcids <= MAX_TREE_VISITS
                or self.inspected_pages != self.page_count
                or sum(count for _, count in pairs) != self.structure_elements
                or dict(pairs).get("ROOT>/Document") != 1):
            raise ValueError("role edge counts do not close the element inventory")
        return {
            "schema_version": "1.0.0",
            "profile_id": PROFILE_ID, "policy_id": POLICY_ID,
            "status": STATUS, "parser_version": PARSER_VERSION,
            "language": LANGUAGE, "coverage_profile_sha256": PROFILE_SHA256,
            "parent_role_profile_sha256": parent.PROFILE_SHA256,
            "pdf_sha256": self.pdf_sha256, "ir_sha256": self.ir_sha256,
            "plan_sha256": self.plan_sha256, "page_count": self.page_count,
            "structure_elements": self.structure_elements,
            "mapped_mcids": self.mapped_mcids,
            "inspected_pages": self.inspected_pages,
            "edge_counts": dict(pairs),
            "conformance_scope": "KNOWN_GENERATED_PDF_ROLE_ADJACENCY_ONLY",
            "all_reachable_role_edges_inventoried": True,
            "semantic_role_appropriateness_verified": False,
            "reading_order_verified": False,
            "pdf_ua_qualified": False,
            "worker_results_authenticated": False,
            "all_file_revisions_inspected": False,
            "aggregate_job_resources_qualified": False,
            "default_pipeline_activated": False,
            "release_authorized": False,
            "release_authorization": "NOT_ESTABLISHED",
        }

    def __post_init__(self) -> None:
        try:
            raw = _canonical(self._record())
            if len(raw) > RESULT_BYTES:
                raise ValueError("role edge receipt budget")
            current = sha256(raw).hexdigest()
            if hasattr(self, "_sealed_sha256") and self._sealed_sha256 != current:
                raise ValueError("role edge receipt mutated")
            object.__setattr__(self, "_sealed_sha256", current)
        except Exception:
            raise PdfStructureRoleEdgesError("pdf_structure_role_edges_receipt_invalid") from None

    def to_bytes(self) -> bytes:
        try:
            raw = _canonical(self._record())
            if len(raw) > RESULT_BYTES or sha256(raw).hexdigest() != self._sealed_sha256:
                raise ValueError("role edge receipt changed")
            return raw
        except Exception:
            raise PdfStructureRoleEdgesError("pdf_structure_role_edges_receipt_invalid") from None

    def to_dict(self) -> dict:
        return json.loads(self.to_bytes())

    @property
    def inspection_sha256(self) -> str:
        """Local checksum of unsigned metadata, not a verified worker signature."""
        return sha256(self.to_bytes()).hexdigest()


def _decode(data: bytes, identity: dict) -> PdfStructureRoleEdges:
    """Reject invalid native envelopes, duplicate keys, identity, and edge totals."""
    try:
        _identity(identity)
        if type(data) is not bytes or not 0 < len(data) <= RESULT_BYTES:
            raise ValueError("role edge wire is out of range")
        record = json.loads(data.decode("ascii"), object_pairs_hook=_unique_pairs)
        if (type(record) is not dict or set(record) != {
                "protocol_version", "profile_id", "policy_id", "parser_version",
                "identity", "limits", "inspection"}
                or type(record["protocol_version"]) is not int
                or record["protocol_version"] != PROTOCOL_VERSION
                or record["profile_id"] != PROFILE_ID or record["policy_id"] != POLICY_ID
                or record["parser_version"] != PARSER_VERSION):
            raise ValueError("role edge protocol envelope changed")
        _identity(record["identity"])
        if record["identity"] != identity:
            raise ValueError("role edge PDF identity changed")
        limits = record["limits"]
        if (type(limits) is not dict or set(limits) != set(_LIMITS)
                or any(type(value) is not int or value != _LIMITS[key]
                       for key, value in limits.items())):
            raise ValueError("role edge worker resource budget changed")
        checked = record["inspection"]
        if (type(checked) is not dict or set(checked) != {
                "status", "structure_elements", "mapped_mcids",
                "inspected_pages", "edge_counts"} or checked["status"] != STATUS):
            raise ValueError("role edge inspection invalid")
        return PdfStructureRoleEdges(
            **identity,
            structure_elements=checked["structure_elements"],
            mapped_mcids=checked["mapped_mcids"],
            inspected_pages=checked["inspected_pages"],
            edge_counts=_edge_pairs(checked["edge_counts"]),
        )
    except Exception:
        raise PdfStructureRoleEdgesError("pdf_structure_role_edges_protocol_invalid") from None


def _run_worker(pdf: bytes, identity: dict) -> bytes:
    """Run confined native PDF inspection using isolated anonymous descriptors."""
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as result:
        fds = (source.fileno(), result.fileno())
        infos = [os.fstat(fd) for fd in fds]
        if (any(not stat.S_ISREG(info.st_mode) or info.st_nlink != 0
                or info.st_uid != os.geteuid() for info in infos)
                or (infos[0].st_dev, infos[0].st_ino) ==
                   (infos[1].st_dev, infos[1].st_ino)):
            raise ValueError("role edge native descriptor invalid")
        header = " ".join([str(PROTOCOL_VERSION), *(str(identity[key])
                          for key in IDENTITY_FIELDS)])
        source.write(header.encode("ascii") + b"\n")
        source.write(pdf)
        source.flush()
        process = _start(
            [sys.executable, "-I",
             str(Path(__file__).resolve().with_name("_pdf_structure_role_edges_worker.py")),
             str(fds[0]), str(fds[1]), str(os.getpid())],
            fds,
        )
        if _wait(process) != 0 or not 0 < os.fstat(result.fileno()).st_size <= RESULT_BYTES:
            raise ValueError("role edge native child failed")
        result.seek(0)
        return result.read(RESULT_BYTES + 1)


def inspect_pdf_structure_role_edges(
    *, pdf_bytes: object, plan: PageWindowPlan,
    expected_plan_sha256: str, expected_language: str,
) -> PdfStructureRoleEdges:
    """Inspect only exact pinned opt-in generated-PDF lexical structural role edges."""
    try:
        _profile()
        if (type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b"%PDF-1.7")
                or len(pdf_bytes) > MAX_PDF_BYTES or type(plan) is not PageWindowPlan
                or not _is_digest(expected_plan_sha256)
                or type(expected_language) is not str or expected_language != LANGUAGE):
            raise ValueError("role edge input not supported")
        plan.__post_init__()
        if (plan.plan_sha256 != expected_plan_sha256
                or plan.inspector_profile_id != TEXT_PROFILE
                or plan.page_count > MAX_DOCUMENT_PAGES
                or plan.pdf_sha256 != sha256(pdf_bytes).hexdigest()):
            raise ValueError("role edge plan and PDF differ")
        identity = _identity_from_plan(plan)
    except Exception:
        raise PdfStructureRoleEdgesError("pdf_structure_role_edges_input_invalid") from None
    try:
        receipt = _decode(_run_worker(pdf_bytes, identity), identity)
        plan.__post_init__()
        _profile()
        if plan.plan_sha256 != expected_plan_sha256:
            raise ValueError("role edge plan changed during execution")
        return receipt
    except Exception:
        raise PdfStructureRoleEdgesError("pdf_structure_role_edges_execution_failed") from None
