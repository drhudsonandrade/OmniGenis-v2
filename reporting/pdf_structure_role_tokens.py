"""Optional exact-PDF native role-token inventory for the current generated profile.

Role-token membership and complete structural counting are not a judgment of
semantic tag correctness, accessible reading order, PDF/UA or release fitness.
The existing native forward/reverse structure gate is required and unchanged.
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
from reporting import _pdf_structure_tree_worker as tree
from reporting._pdf_object_graph_worker import (
    CPU_SECONDS, IDENTITY_FIELDS, MAX_PDF_BYTES, MEMORY_BYTES, OPEN_FILES,
    PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES, _is_digest,
)
from reporting._pdf_structure_role_tokens_worker import (
    LANGUAGE, MAX_DOCUMENT_PAGES, MAX_TREE_DEPTH, MAX_TREE_VISITS,
    POLICY_ID, PROFILE_ID, ROLE_NAMES, STATUS, _identity, _identity_from_plan,
)

_LIMITS = {"memory_bytes": MEMORY_BYTES, "cpu_seconds": CPU_SECONDS,
           "file_bytes": RESULT_BYTES, "open_files": OPEN_FILES}
_FIXED_ENVELOPE = (64, 8 * 1024 * 1024, 64, 20000)
_DISABLE = "OMNIGENIS_PDF_STRUCTURE_ROLE_TOKENS_DISABLED"


class PdfStructureRoleTokensError(ValueError):
    """No unsupported or unverifiable native role inventory is admitted."""


def _role_pairs(value: object) -> tuple[tuple[str, int], ...]:
    """Admit only sorted, nonempty, unique positive current generated role tokens."""
    if type(value) is dict:
        pairs = tuple(sorted(value.items()))
    elif type(value) is tuple:
        pairs = value
    else:
        raise ValueError("role counts must be an exact mapping or immutable tuple")
    if (not pairs or len(pairs) > len(ROLE_NAMES)
            or any(type(pair) is not tuple or len(pair) != 2
                   or type(pair[0]) is not str or pair[0] not in ROLE_NAMES
                   or type(pair[1]) is not int or pair[1] < 1
                   for pair in pairs)
            or tuple(name for name, _ in pairs) !=
               tuple(sorted({name for name, _ in pairs}))):
        raise ValueError("role counts outside supported profile")
    return pairs


def structure_role_tokens_profile() -> dict:
    """Exact native lexical subset with all broader accessibility claims disabled."""
    return {"schema_version": "1.0.0", "profile_id": PROFILE_ID,
            "policy_id": POLICY_ID, "parser_version": PARSER_VERSION,
            "parent_structure_policy_id": tree.POLICY_ID,
            "max_pages": MAX_DOCUMENT_PAGES, "max_pdf_bytes": MAX_PDF_BYTES,
            "max_tree_depth": MAX_TREE_DEPTH, "max_tree_visits": MAX_TREE_VISITS,
            "language": LANGUAGE, "supported_role_tokens": list(ROLE_NAMES),
            "rolemap_supported": False,
            "document_role_must_be_unique_root_child": True,
            "conformance_scope": "KNOWN_GENERATED_PDF_ROLE_TOKENS_ONLY",
            "all_reachable_role_tokens_inventoried": True,
            "semantic_roles_qualified": False, "reading_order_verified": False,
            "alternate_text_quality_verified": False,
            "full_accessibility_qualified": False, "pdf_ua_qualified": False,
            "worker_results_authenticated": False, "all_file_revisions_inspected": False,
            "aggregate_job_resources_qualified": False,
            "default_pipeline_activated": False, "release_authorized": False}


PROFILE_SHA256 = sha256(_canonical(structure_role_tokens_profile())).hexdigest()


def _profile() -> None:
    """Fail closed on disabled or silently widened native bounds and policy drift."""
    if (sys.platform != "linux" or os.environ.get(_DISABLE) == "1"
            or (MAX_DOCUMENT_PAGES, MAX_PDF_BYTES, MAX_TREE_DEPTH, MAX_TREE_VISITS)
               != _FIXED_ENVELOPE
            or (tree.MAX_DOCUMENT_PAGES, tree.MAX_PDF_BYTES, tree.MAX_TREE_DEPTH,
                tree.MAX_TREE_VISITS) != _FIXED_ENVELOPE
            or LANGUAGE != "en-US"
            or sha256(_canonical(structure_role_tokens_profile())).hexdigest()
               != PROFILE_SHA256):
        raise ValueError("role tokens native profile disabled or changed")


@dataclass(frozen=True, slots=True, repr=False)
class PdfStructureRoleTokens:
    """Sealed unsigned counts for one exact final generated PDF, without content."""

    pdf_sha256: str
    ir_sha256: str
    plan_sha256: str
    page_count: int
    structure_elements: int
    mapped_mcids: int
    inspected_pages: int
    role_counts: tuple[tuple[str, int], ...]
    _sealed_sha256: str = field(init=False, repr=False, compare=False)

    def _record(self) -> dict:
        _profile()
        _identity({key: getattr(self, key) for key in IDENTITY_FIELDS})
        pairs = _role_pairs(self.role_counts)
        if (type(self.structure_elements) is not int
                or type(self.mapped_mcids) is not int
                or type(self.inspected_pages) is not int
                or not 1 <= self.structure_elements <= MAX_TREE_VISITS
                or not self.page_count <= self.mapped_mcids <= MAX_TREE_VISITS
                or self.inspected_pages != self.page_count
                or sum(count for _, count in pairs) != self.structure_elements
                or dict(pairs).get("/Document") != 1):
            raise ValueError("role counts do not close exact page/element inventory")
        return {"schema_version": "1.0.0", "profile_id": PROFILE_ID,
                "policy_id": POLICY_ID, "status": STATUS,
                "parser_version": PARSER_VERSION, "language": LANGUAGE,
                "coverage_profile_sha256": PROFILE_SHA256,
                "pdf_sha256": self.pdf_sha256, "ir_sha256": self.ir_sha256,
                "plan_sha256": self.plan_sha256, "page_count": self.page_count,
                "structure_elements": self.structure_elements,
                "mapped_mcids": self.mapped_mcids,
                "inspected_pages": self.inspected_pages,
                "role_counts": dict(pairs),
                "conformance_scope": "KNOWN_GENERATED_PDF_ROLE_TOKENS_ONLY",
                "all_reachable_role_tokens_inventoried": True,
                "document_role_must_be_unique_root_child": True,
                "semantic_roles_qualified": False, "reading_order_verified": False,
                "alternate_text_quality_verified": False,
                "full_accessibility_qualified": False, "pdf_ua_qualified": False,
                "worker_results_authenticated": False, "all_file_revisions_inspected": False,
                "aggregate_job_resources_qualified": False, "release_authorized": False,
                "release_authorization": "NOT_ESTABLISHED"}

    def __post_init__(self) -> None:
        try:
            data = _canonical(self._record())
            if len(data) > RESULT_BYTES:
                raise ValueError("role inventory receipt too large")
            current = sha256(data).hexdigest()
            if hasattr(self, "_sealed_sha256") and self._sealed_sha256 != current:
                raise ValueError("role inventory receipt mutated")
            object.__setattr__(self, "_sealed_sha256", current)
        except Exception:
            raise PdfStructureRoleTokensError("pdf_structure_role_tokens_receipt_invalid") from None

    def to_bytes(self) -> bytes:
        try:
            data = _canonical(self._record())
            if len(data) > RESULT_BYTES or sha256(data).hexdigest() != self._sealed_sha256:
                raise ValueError("role inventory receipt mutated")
            return data
        except Exception:
            raise PdfStructureRoleTokensError("pdf_structure_role_tokens_receipt_invalid") from None

    def to_dict(self) -> dict:
        return json.loads(self.to_bytes())

    @property
    def inspection_sha256(self) -> str:
        """A local digest of unsigned metadata, not a worker signature."""
        return sha256(self.to_bytes()).hexdigest()


def _decode(data: bytes, identity: dict) -> PdfStructureRoleTokens:
    """Validate the complete child protocol before constructing a sealed receipt."""
    try:
        _identity(identity)
        if type(data) is not bytes or not 0 < len(data) <= RESULT_BYTES:
            raise ValueError("role wire budget")
        record = json.loads(data.decode("ascii"), object_pairs_hook=_unique_pairs)
        if (type(record) is not dict or set(record) != {"protocol_version", "profile_id",
                "policy_id", "parser_version", "identity", "limits", "inspection"}
                or type(record["protocol_version"]) is not int
                or record["protocol_version"] != PROTOCOL_VERSION
                or record["profile_id"] != PROFILE_ID
                or record["policy_id"] != POLICY_ID
                or record["parser_version"] != PARSER_VERSION):
            raise ValueError("role wire shape or pin mismatch")
        _identity(record["identity"])
        if record["identity"] != identity:
            raise ValueError("role wire candidate differs")
        limits = record["limits"]
        if (type(limits) is not dict or set(limits) != set(_LIMITS)
                or any(type(value) is not int or value != _LIMITS[key]
                       for key, value in limits.items())):
            raise ValueError("role native limits changed")
        inspected = record["inspection"]
        if (type(inspected) is not dict or
                set(inspected) != {"status", "structure_elements", "mapped_mcids",
                                   "inspected_pages", "role_counts"}
                or inspected["status"] != STATUS):
            raise ValueError("role native shape/status invalid")
        return PdfStructureRoleTokens(**identity,
               structure_elements=inspected["structure_elements"],
               mapped_mcids=inspected["mapped_mcids"],
               inspected_pages=inspected["inspected_pages"],
               role_counts=_role_pairs(inspected["role_counts"]))
    except Exception:
        raise PdfStructureRoleTokensError("pdf_structure_role_tokens_protocol_invalid") from None


def _run_worker(pdf: bytes, identity: dict) -> bytes:
    """Use distinct anonymous job-owned descriptors under the existing worker guard."""
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as result:
        fds = (source.fileno(), result.fileno())
        infos = [os.fstat(fd) for fd in fds]
        if (any(not stat.S_ISREG(value.st_mode) or value.st_nlink != 0
                or value.st_uid != os.geteuid() for value in infos)
                or (infos[0].st_dev, infos[0].st_ino) ==
                   (infos[1].st_dev, infos[1].st_ino)):
            raise ValueError("role native owned file invalid")
        header = " ".join([str(PROTOCOL_VERSION), *(str(identity[key])
                             for key in IDENTITY_FIELDS)])
        source.write(header.encode("ascii") + b"\n")
        source.write(pdf)
        source.flush()
        process = _start([sys.executable, "-I",
            str(Path(__file__).resolve().with_name("_pdf_structure_role_tokens_worker.py")),
            str(fds[0]), str(fds[1]), str(os.getpid())], fds)
        if _wait(process) != 0 or not 0 < os.fstat(result.fileno()).st_size <= RESULT_BYTES:
            raise ValueError("role native worker failed")
        result.seek(0)
        return result.read(RESULT_BYTES + 1)


def inspect_pdf_structure_role_tokens(
    *, pdf_bytes: object, plan: PageWindowPlan,
    expected_plan_sha256: str, expected_language: str,
) -> PdfStructureRoleTokens:
    """Inventory only the old generated role subset on one exact, linked final PDF."""
    try:
        _profile()
        if (type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b"%PDF-1.7")
                or len(pdf_bytes) > MAX_PDF_BYTES or type(plan) is not PageWindowPlan
                or not _is_digest(expected_plan_sha256)
                or type(expected_language) is not str or expected_language != LANGUAGE):
            raise ValueError("role inventory input rejected")
        plan.__post_init__()
        if (plan.plan_sha256 != expected_plan_sha256
                or plan.inspector_profile_id != TEXT_PROFILE
                or plan.page_count > MAX_DOCUMENT_PAGES
                or plan.pdf_sha256 != sha256(pdf_bytes).hexdigest()):
            raise ValueError("role inventory plan/PDF mismatch")
        identity = _identity_from_plan(plan)
    except Exception:
        raise PdfStructureRoleTokensError("pdf_structure_role_tokens_input_invalid") from None
    try:
        receipt = _decode(_run_worker(pdf_bytes, identity), identity)
        plan.__post_init__()
        _profile()
        if plan.plan_sha256 != expected_plan_sha256:
            raise ValueError("role plan changed while inspecting")
        return receipt
    except Exception:
        raise PdfStructureRoleTokensError("pdf_structure_role_tokens_execution_failed") from None
