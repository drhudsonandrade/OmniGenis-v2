"""Guard one bounded final-PDF page/ParentTree reference correspondence.

The profile checks only native page-parent slots and structural ancestry.
It does not parse all marked-content IDs, qualify structural roles, ascertain
reading order, validate all streams or release any report artifact.
"""
from __future__ import annotations

import hashlib
from importlib.metadata import version
from io import BytesIO
import json
import os
from pathlib import Path
import stat
import sys

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reporting._pdf_object_graph_worker import (
    CPU_SECONDS, IDENTITY_FIELDS, MAX_DOCUMENT_PAGES, MAX_PDF_BYTES,
    MAX_DEPTH, MAX_VISITS, MEMORY_BYTES, OPEN_FILES, PARSER_VERSION,
    PROTOCOL_VERSION, RESULT_BYTES, WALL_SECONDS, _is_digest, _lifetime,
    _limits, _read_request, _validate_identity,
)
from reporting._pdf_process_sandbox import enforce_pdf_landlock, enforce_pdf_network_filter
from reporting._pdf_render_worker import _write_bytes

PROFILE_ID = "generated-pdf-page-tag-parenttree-v1"
POLICY_ID = "page-tag-parenttree-references-v1"
LANGUAGE = "en-US"
STATUS = "PAGE_TAG_PARENTTREE_INSPECTED"


def _same_ref(first: object, second: object) -> bool:
    """Compare only native indirect object identities within one exact file."""
    from pypdf.generic import IndirectObject
    return (type(first) is IndirectObject and type(second) is IndirectObject
            and first.idnum == second.idnum and first.generation == second.generation
            and first.pdf is second.pdf)


def _root_ancestor(entry: object, root_ref: object, budget: list[int]) -> None:
    """Require a finite parent chain through actual structure elements to this root."""
    from pypdf.generic import DictionaryObject, IndirectObject, NameObject
    element = entry.get_object()
    seen: set[tuple[int, int]] = {(entry.idnum, entry.generation)}
    for _ in range(MAX_DEPTH):
        parent = element.get("/P")
        if type(parent) is not IndirectObject:
            raise ValueError("page tag parent chain not indirect")
        budget[0] += 1
        if budget[0] > MAX_VISITS:
            raise ValueError("page tag total visit budget")
        if _same_ref(parent, root_ref):
            return
        key = parent.idnum, parent.generation
        if key in seen:
            raise ValueError("page tag parent cycle")
        seen.add(key)
        element = parent.get_object()
        if (type(element) is not DictionaryObject
                or type(element.get("/Type")) is not NameObject
                or element.get("/Type") != "/StructElem"
                or type(element.get("/S")) is not NameObject):
            raise ValueError("page tag parent object invalid")
    raise ValueError("page tag parent depth budget")


def _inspect(pdf: bytes, identity: dict) -> dict:
    """Inspect bounded page keys and their actual linked structure-element references."""
    from pypdf import PdfReader
    from pypdf.generic import (
        ArrayObject, DictionaryObject, IndirectObject, NameObject, NumberObject,
    )
    from reporting.pdf_accessibility import validate_pdf_accessibility_structure
    _validate_identity(identity)
    if (type(pdf) is not bytes or not pdf.startswith(b"%PDF-1.7")
            or len(pdf) > MAX_PDF_BYTES or version("pypdf") != PARSER_VERSION
            or hashlib.sha256(pdf).hexdigest() != identity["pdf_sha256"]):
        raise ValueError("page tag document invalid")
    reader = PdfReader(BytesIO(pdf), strict=True)
    if reader.is_encrypted or len(reader.pages) != identity["page_count"]:
        raise ValueError("page tag physical document mismatch")
    prerequisites = validate_pdf_accessibility_structure(
        pdf_bytes=pdf, expected_language=LANGUAGE)
    if (not prerequisites.passed or prerequisites.language != LANGUAGE
            or prerequisites.marked is not True
            or prerequisites.struct_tree_root is not True):
        raise ValueError("page tag catalog prerequisites invalid")
    root = reader.root_object
    if (type(root) is not DictionaryObject
            or type(root.get("/Type")) is not NameObject
            or root.get("/Type") != "/Catalog"):
        raise ValueError("page tag catalog invalid")
    root_ref = root.get("/StructTreeRoot")
    if type(root_ref) is not IndirectObject:
        raise ValueError("page tag root reference missing")
    struct = root_ref.get_object()
    if (type(struct) is not DictionaryObject
            or type(struct.get("/Type")) is not NameObject
            or struct.get("/Type") != "/StructTreeRoot"
            or type(struct.get("/K")) is not ArrayObject
            or not struct["/K"]):
        raise ValueError("page tag structural root invalid")
    parent_ref = struct.get("/ParentTree")
    if type(parent_ref) is not IndirectObject:
        raise ValueError("page tag parent tree not indirect")
    parent_tree = parent_ref.get_object()
    if (type(parent_tree) is not DictionaryObject
            or set(parent_tree) != {"/Nums"}
            or type(parent_tree.get("/Nums")) is not ArrayObject):
        raise ValueError("page tag flat parent tree profile unavailable")
    nums = parent_tree["/Nums"]
    if len(nums) != 2 * identity["page_count"]:
        raise ValueError("page tag parent slots count mismatch")
    page_refs: dict[int, IndirectObject] = {}
    for page in reader.pages:
        key = page.get("/StructParents")
        page_ref = page.indirect_reference
        if (type(key) is not NumberObject or not 0 <= key < MAX_VISITS
                or key in page_refs or type(page_ref) is not IndirectObject):
            raise ValueError("page tag page parent identity invalid")
        page_refs[int(key)] = page_ref
    sorted_keys = sorted(page_refs)
    visited = [0]
    previous = -1
    slots = 0
    for i in range(0, len(nums), 2):
        key, values = nums[i], nums[i + 1]
        if (type(key) is not NumberObject or not previous < key < MAX_VISITS
                or int(key) != sorted_keys[i // 2]
                or type(values) is not ArrayObject or not 1 <= len(values) <= MAX_VISITS):
            raise ValueError("page tag parent tree slot invalid")
        previous = int(key)
        slots += 1
        for entry in values:
            visited[0] += 1
            if visited[0] > MAX_VISITS or type(entry) is not IndirectObject:
                raise ValueError("page tag parent entry budget/type")
            element = entry.get_object()
            if (type(element) is not DictionaryObject
                    or type(element.get("/Type")) is not NameObject
                    or element.get("/Type") != "/StructElem"
                    or type(element.get("/S")) is not NameObject
                    or not _same_ref(element.get("/Pg"), page_refs[int(key)])):
                raise ValueError("page tag element/page mismatch")
            _root_ancestor(entry, root_ref, visited)
    if slots != len(page_refs):
        raise ValueError("page tag physical coverage mismatch")
    return {"status": STATUS, "language": LANGUAGE,
            "tagged_pages": len(page_refs), "parent_tree_entries": slots}


def main(argv: list[str] | None = None) -> int:
    """Guard one anonymous request and write only a bounded successful count record."""
    argv = sys.argv if argv is None else argv
    if (sys.platform != "linux" or type(argv) is not list or len(argv) != 4
            or any(type(s) is not str for s in argv)):
        return 64
    try:
        if any(not s.isascii() or not s.isdecimal() or len(s) > 10 for s in argv[1:]):
            return 64
        first, second, parent = map(int, argv[1:])
        if (any(str(n) != s for n, s in zip((first, second, parent), argv[1:], strict=True))
                or min(first, second) < 3 or first == second or not 2 <= parent <= 2147483647):
            return 64
        infos = [os.fstat(fd) for fd in (first, second)]
        if any(not stat.S_ISREG(v.st_mode) or v.st_nlink != 0
               or v.st_uid != os.geteuid() for v in infos):
            return 64
        if ((infos[0].st_dev, infos[0].st_ino) == (infos[1].st_dev, infos[1].st_ino)
                or infos[1].st_size):
            return 64
        limits = _limits()
        _lifetime(parent)
        enforce_pdf_landlock(Path(__file__))
        enforce_pdf_network_filter()
        identity, pdf = _read_request(first)
        record = {"protocol_version": PROTOCOL_VERSION, "profile_id": PROFILE_ID,
                  "policy_id": POLICY_ID, "parser_version": PARSER_VERSION,
                  "identity": identity, "limits": limits, "inspection": _inspect(pdf, identity)}
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("ascii")
        if not 0 < len(encoded) <= RESULT_BYTES:
            return 70
        _write_bytes(second, encoded)
    except Exception:
        return 70
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
