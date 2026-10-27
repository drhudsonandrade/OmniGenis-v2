"""Inspect bounded native parent/child /S role edges in an isolated PDF worker.

This exact generated-PDF lexical edge subset does not establish the semantic
appropriateness of a tag, accessible reading order, PDF/UA or release fitness.
"""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
from importlib.metadata import version
from io import BytesIO
import json
import os
from pathlib import Path
import stat
import sys

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reporting import _pdf_structure_role_tokens_worker as roles
from reporting import _pdf_structure_tree_worker as tree
from reporting._pdf_object_graph_worker import (
    MAX_PDF_BYTES, PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES,
    _lifetime, _limits, _read_request,
)
from reporting._pdf_process_sandbox import (
    enforce_pdf_landlock, enforce_pdf_network_filter,
)
from reporting._pdf_render_worker import _write_bytes


PROFILE_ID = "generated-pdf-structure-role-edges-v1"
POLICY_ID = "generated-pdf-role-adjacency-subset-v1"
STATUS = "STRUCTURE_ROLE_EDGES_INVENTORIED"
LANGUAGE = roles.LANGUAGE
MAX_DOCUMENT_PAGES = roles.MAX_DOCUMENT_PAGES
MAX_TREE_DEPTH = roles.MAX_TREE_DEPTH
MAX_TREE_VISITS = roles.MAX_TREE_VISITS
EDGE_PAIRS = (
    ("/Document", "/H1"), ("/Document", "/Sect"),
    ("/H1", "/Span"), ("/H2", "/Span"),
    ("/NonStruct", "/Span"), ("/P", "/Span"),
    ("/Sect", "/H2"), ("/Sect", "/NonStruct"),
    ("/Sect", "/P"), ("ROOT", "/Document"),
)
EDGE_KEYS = tuple(f"{parent}>{child}" for parent, child in EDGE_PAIRS)
_ALLOWED = frozenset(EDGE_KEYS)


def _identity(value: dict) -> None:
    """Keep the existing exact PDF/page/IR/plan request shape."""
    roles._identity(value)


def _identity_from_plan(plan: object) -> dict:
    """Reuse the unchanged primitive native request identity fields."""
    return roles._identity_from_plan(plan)


def _inspect(pdf: bytes, identity: dict) -> dict:
    """Count every native structural parent/child edge after the role-token gate."""
    _identity(identity)
    if (type(pdf) is not bytes or not pdf.startswith(b"%PDF-1.7")
            or len(pdf) > MAX_PDF_BYTES
            or sha256(pdf).hexdigest() != identity["pdf_sha256"]
            or version("pypdf") != PARSER_VERSION):
        raise ValueError("role edge input or parser drift")
    prerequisite = roles._inspect(pdf, identity)
    if (prerequisite["status"] != roles.STATUS
            or prerequisite["inspected_pages"] != identity["page_count"]):
        raise ValueError("role-token prerequisite incomplete")
    from pypdf import PdfReader
    from pypdf.generic import (
        ArrayObject, DictionaryObject, IndirectObject, NameObject, NumberObject,
    )
    reader = PdfReader(BytesIO(pdf), strict=True)
    if reader.is_encrypted or len(reader.pages) != identity["page_count"]:
        raise ValueError("role edge document identity changed")
    root_ref = reader.root_object.get("/StructTreeRoot")
    tree._key(root_ref, reader)
    root = root_ref.get_object()
    if (type(root) is not DictionaryObject
            or root.get("/Type") != "/StructTreeRoot"
            or "/RoleMap" in root):
        raise ValueError("role edge root or aliases not admitted")
    top = root.get("/K")
    if type(top) is not ArrayObject or not top:
        raise ValueError("role edge root children missing")

    pending = [(child, "ROOT", 1) for child in top]
    seen = set()
    counts: Counter[str] = Counter()
    roles_seen: Counter[str] = Counter()
    visits = 0
    while pending:
        ref, parent_role, depth = pending.pop()
        key = tree._key(ref, reader)
        visits += 1
        if key in seen or depth > MAX_TREE_DEPTH or visits > MAX_TREE_VISITS:
            raise ValueError("role edge cyclic or over-budget traversal")
        seen.add(key)
        node = ref.get_object()
        if type(node) is not DictionaryObject or node.get("/Type") != "/StructElem":
            raise ValueError("role edge child is not a structure element")
        name = node.get("/S")
        if type(name) is not NameObject or str(name) not in roles.ROLE_NAMES:
            raise ValueError("role edge child token not in prior native subset")
        role = str(name)
        edge = f"{parent_role}>{role}"
        if edge not in _ALLOWED or (role == "/Document") != (parent_role == "ROOT"):
            raise ValueError("role edge outside generated adjacency profile")
        counts[edge] += 1
        roles_seen[role] += 1

        raw = node.get("/K")
        if type(raw) is ArrayObject:
            if not raw:
                raise ValueError("empty role edge children")
            children = raw
        elif type(raw) in (IndirectObject, NumberObject):
            children = (raw,)
        else:
            raise ValueError("unsupported role edge child")
        visits += len(children)
        if visits > MAX_TREE_VISITS or len(pending) + len(children) > MAX_TREE_VISITS:
            raise ValueError("role edge child budget exceeded")
        for child in children:
            if type(child) is IndirectObject:
                tree._key(child, reader)
                pending.append((child, role, depth + 1))
            elif type(child) is not NumberObject:
                raise ValueError("role edge unsupported terminal")
    if (len(seen) != prerequisite["structure_elements"]
            or sum(counts.values()) != len(seen)
            or counts.get("ROOT>/Document") != 1
            or dict(roles_seen) != prerequisite["role_counts"]):
        raise ValueError("role edge inventory did not close native elements")
    return {
        "status": STATUS,
        "structure_elements": prerequisite["structure_elements"],
        "mapped_mcids": prerequisite["mapped_mcids"],
        "inspected_pages": prerequisite["inspected_pages"],
        "edge_counts": dict(sorted(counts.items())),
    }


def main(argv: list[str] | None = None) -> int:
    """Apply child-lifetime and Linux sandbox guards before reading the source."""
    argv = sys.argv if argv is None else argv
    if (sys.platform != "linux" or type(argv) is not list or len(argv) != 4
            or any(type(s) is not str or not s.isascii() or not s.isdecimal()
                   or len(s) > 10 for s in argv[1:])):
        return 64
    try:
        source, output, parent = map(int, argv[1:])
        if (any(str(n) != s for n, s in zip(
                (source, output, parent), argv[1:], strict=True))
                or min(source, output) < 3 or source == output
                or not 2 <= parent <= 2147483647):
            return 64
        infos = [os.fstat(fd) for fd in (source, output)]
        if (any(not stat.S_ISREG(v.st_mode) or v.st_nlink != 0
                or v.st_uid != os.geteuid() for v in infos)
                or (infos[0].st_dev, infos[0].st_ino)
                   == (infos[1].st_dev, infos[1].st_ino)
                or infos[1].st_size):
            return 64
        limits = _limits()
        _lifetime(parent)
        enforce_pdf_landlock(Path(__file__))
        enforce_pdf_network_filter()
        identity, pdf = _read_request(source)
        record = {
            "protocol_version": PROTOCOL_VERSION, "profile_id": PROFILE_ID,
            "policy_id": POLICY_ID, "parser_version": PARSER_VERSION,
            "identity": identity, "limits": limits,
            "inspection": _inspect(pdf, identity),
        }
        wire = json.dumps(
            record, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("ascii")
        if not 0 < len(wire) <= RESULT_BYTES:
            return 70
        _write_bytes(output, wire)
    except Exception:
        return 70
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
