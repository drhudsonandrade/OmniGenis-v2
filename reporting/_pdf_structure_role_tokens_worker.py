"""Strict lexical inventory of current generated PDF structure roles in a confined child.

This does not establish semantic appropriateness, logical reading order,
figure alternatives, complete accessibility, PDF/UA or release authorization.
The existing forward/reverse native structure gate remains a prerequisite.
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

from reporting import _pdf_structure_tree_worker as tree
from reporting._pdf_object_graph_worker import (
    IDENTITY_FIELDS, MAX_PDF_BYTES, PARSER_VERSION, PROTOCOL_VERSION,
    RESULT_BYTES, _lifetime, _limits, _read_request,
)
from reporting._pdf_process_sandbox import enforce_pdf_landlock, enforce_pdf_network_filter
from reporting._pdf_render_worker import _write_bytes

PROFILE_ID = "generated-pdf-structure-role-tokens-v1"
POLICY_ID = "generated-pdf-standard-role-token-subset-v1"
STATUS = "STRUCTURE_ROLE_TOKENS_INVENTORIED"
LANGUAGE = tree.LANGUAGE
MAX_DOCUMENT_PAGES = tree.MAX_DOCUMENT_PAGES
MAX_TREE_DEPTH = tree.MAX_TREE_DEPTH
MAX_TREE_VISITS = tree.MAX_TREE_VISITS
ROLE_NAMES = ("/Document", "/H1", "/H2", "/NonStruct", "/P", "/Sect", "/Span")


def _identity(value: dict) -> None:
    """Use the exact existing page/document request grammar, not any new admission."""
    tree._identity(value)


def _identity_from_plan(plan: object) -> dict:
    """Capture the existing four primitive exact native request identity fields."""
    result = {key: getattr(plan, key) for key in IDENTITY_FIELDS}
    _identity(result)
    return result


def _inspect(pdf: bytes, identity: dict) -> dict:
    """Inventory every already-connected native structure role once, with a closed token set."""
    _identity(identity)
    if (type(pdf) is not bytes or not pdf.startswith(b"%PDF-1.7")
            or len(pdf) > MAX_PDF_BYTES or sha256(pdf).hexdigest() != identity["pdf_sha256"]
            or version("pypdf") != PARSER_VERSION):
        raise ValueError("role inventory source/parser invalid")
    verified = tree._inspect(pdf, identity)
    if verified["status"] != tree.STATUS or verified["inspected_pages"] != identity["page_count"]:
        raise ValueError("role inventory prerequisite incomplete")
    from pypdf import PdfReader
    from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject, NameObject, NumberObject
    reader = PdfReader(BytesIO(pdf), strict=True)
    if reader.is_encrypted or len(reader.pages) != identity["page_count"]:
        raise ValueError("role inventory physical document mismatch")
    root_ref = reader.root_object.get("/StructTreeRoot")
    tree._key(root_ref, reader)
    root = root_ref.get_object()
    if (type(root) is not DictionaryObject or root.get("/Type") != "/StructTreeRoot"
            or "/RoleMap" in root):
        raise ValueError("role aliases or structural root outside current profile")
    children = root.get("/K")
    if type(children) is not ArrayObject or not children:
        raise ValueError("role inventory root children absent")
    pending = [(child, 1) for child in children]
    seen: set[tuple[int, int]] = set()
    counts: Counter[str] = Counter()
    visits = 0
    while pending:
        ref, depth = pending.pop()
        key = tree._key(ref, reader)
        visits += 1
        if key in seen or depth > MAX_TREE_DEPTH or visits > MAX_TREE_VISITS:
            raise ValueError("role inventory cycle or traversal/depth budget")
        seen.add(key)
        node = ref.get_object()
        if type(node) is not DictionaryObject or node.get("/Type") != "/StructElem":
            raise ValueError("role inventory nonstructural child")
        name = node.get("/S")
        if type(name) is not NameObject or str(name) not in ROLE_NAMES:
            raise ValueError("role token outside closed generated profile")
        if (str(name) == "/Document") != (depth == 1):
            raise ValueError("generated Document role must be the unique root child")
        counts[str(name)] += 1
        children = node.get("/K")
        if type(children) is ArrayObject:
            if not children:
                raise ValueError("empty role node")
            edges = children
        elif type(children) in (IndirectObject, NumberObject):
            edges = (children,)
        else:
            raise ValueError("unsupported role child")
        visits += len(edges)
        if visits > MAX_TREE_VISITS or len(pending) + len(edges) > MAX_TREE_VISITS:
            raise ValueError("role child visit budget")
        for child in edges:
            if type(child) is IndirectObject:
                tree._key(child, reader)
                pending.append((child, depth + 1))
            elif type(child) is not NumberObject or type(child) is bool:
                raise ValueError("unsupported role terminal")
    if (len(seen) != verified["structure_elements"]
            or sum(counts.values()) != verified["structure_elements"]
            or counts.get("/Document") != 1):
        raise ValueError("incomplete role inventory or Document root")
    return {"status": STATUS, "structure_elements": verified["structure_elements"],
            "mapped_mcids": verified["mapped_mcids"],
            "inspected_pages": verified["inspected_pages"],
            "role_counts": dict(sorted(counts.items()))}


def main(argv: list[str] | None = None) -> int:
    """Keep file-descriptor, parent-life, memory, CPU and network guards in the child."""
    argv = sys.argv if argv is None else argv
    if (sys.platform != "linux" or type(argv) is not list or len(argv) != 4
            or any(type(s) is not str or not s.isascii() or not s.isdecimal()
                   or len(s) > 10 for s in argv[1:])):
        return 64
    try:
        first, second, parent = map(int, argv[1:])
        if (any(str(n) != s for n, s in zip((first, second, parent), argv[1:], strict=True))
                or min(first, second) < 3 or first == second
                or not 2 <= parent <= 2147483647):
            return 64
        infos = [os.fstat(fd) for fd in (first, second)]
        if (any(not stat.S_ISREG(v.st_mode) or v.st_nlink != 0 or v.st_uid != os.geteuid()
                for v in infos)
                or (infos[0].st_dev, infos[0].st_ino) == (infos[1].st_dev, infos[1].st_ino)
                or infos[1].st_size):
            return 64
        limits = _limits()
        _lifetime(parent)
        enforce_pdf_landlock(Path(__file__))
        enforce_pdf_network_filter()
        identity, pdf = _read_request(first)
        result = {"protocol_version": PROTOCOL_VERSION,
                  "profile_id": PROFILE_ID, "policy_id": POLICY_ID,
                  "parser_version": PARSER_VERSION, "identity": identity,
                  "limits": limits, "inspection": _inspect(pdf, identity)}
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("ascii")
        if not 0 < len(encoded) <= RESULT_BYTES:
            return 70
        _write_bytes(second, encoded)
    except Exception:
        return 70
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
