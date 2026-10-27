"""Confined, opt-in generated PDF trailer/catalog and flat page-tree parity.

Only the current native PDF 1.7/en-US generator's single XRef subset is
admitted. No historical content, opaque payload, PDF/UA or release claim.
"""
from __future__ import annotations

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

from reporting import _pdf_xref_resolution_worker as previous
from reporting._pdf_object_graph_worker import (
    MAX_PDF_BYTES, PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES,
    _lifetime, _limits, _read_request,
)
from reporting._pdf_process_sandbox import enforce_pdf_landlock, enforce_pdf_network_filter
from reporting._pdf_render_worker import _write_bytes

PROFILE_ID = "generated-pdf-trailer-catalog-v1"
POLICY_ID = "generated-pdf-exact-xref-trailer-catalog-v1"
STATUS = "TRAILER_CATALOG_ADMITTED"
LANGUAGE = previous.LANGUAGE
MAX_DOCUMENT_PAGES = previous.MAX_DOCUMENT_PAGES
_TRAILER_KEYS = frozenset(("/Root", "/Info", "/ID", "/Size"))
_XREF_KEYS = frozenset(("/Type", "/Filter", "/Index", "/W", "/Root",
                        "/Info", "/ID", "/Size"))


def _identity(value: dict) -> None:
    previous._identity(value)


def _identity_from_plan(plan: object) -> dict:
    return previous._identity_from_plan(plan)


def _reference_id(ref: object, reader: object, indexed: set[int]) -> int:
    """Require an actual generation-zero native reference in this parser's map."""
    from pypdf.generic import IndirectObject
    if (type(ref) is not IndirectObject or ref.pdf is not reader
            or type(ref.idnum) is not int or type(ref.generation) is not int
            or ref.idnum <= 0 or ref.generation != 0
            or ref.idnum not in indexed):
        raise ValueError("foreign, unindexed or nonzero-generation reference")
    return ref.idnum


def _verify_trailer_catalog(
    reader: object, *, expected_pages: int,
    direct_count: int, compressed_count: int,
) -> dict:
    """Tie physical XRef trailer references to one native flat catalog tree."""
    from pypdf.generic import (
        ArrayObject, DictionaryObject, IndirectObject, NameObject, NumberObject,
        StreamObject, TextStringObject,
    )

    if (type(expected_pages) is not int
            or not 1 <= expected_pages <= MAX_DOCUMENT_PAGES
            or type(direct_count) is not int or type(compressed_count) is not int
            or not 2 <= direct_count <= 20000
            or not 1 <= compressed_count <= 20000
            or type(reader.xref) is not dict or set(reader.xref) != {0}
            or type(reader.xref[0]) is not dict
            or type(reader.xref_objStm) is not dict
            or len(reader.xref[0]) != direct_count
            or len(reader.xref_objStm) != compressed_count
            or reader.xref_free_entry != {}
            or not isinstance(reader.trailer, DictionaryObject)
            or set(reader.trailer) != _TRAILER_KEYS):
        raise ValueError("native trailer or map shape outside generated profile")
    direct = dict(reader.xref[0])
    compressed = dict(reader.xref_objStm)
    indexed = set(direct) | set(compressed)
    size = 1 + direct_count + compressed_count
    if (indexed != set(range(1, size))
            or set(direct) & set(compressed) or size > 20000
            or size - 1 not in direct or reader.is_encrypted):
        raise ValueError("native indexed catalog set is incomplete")

    xref = reader.get_object(IndirectObject(size - 1, 0, reader))
    if (not isinstance(xref, StreamObject) or set(xref) != _XREF_KEYS
            or type(xref.get("/Type")) is not NameObject
            or xref.get("/Type") != "/XRef"):
        raise ValueError("native single XRef trailer dictionary changed")
    root_ref = reader.trailer.raw_get("/Root")
    info_ref = reader.trailer.raw_get("/Info")
    root_id = _reference_id(root_ref, reader, indexed)
    info_id = _reference_id(info_ref, reader, indexed)
    if (root_id == info_id or root_id == size - 1 or info_id == size - 1
            or _reference_id(xref.raw_get("/Root"), reader, indexed) != root_id
            or _reference_id(xref.raw_get("/Info"), reader, indexed) != info_id):
        raise ValueError("native /Root or /Info reference differs from physical XRef")

    for trailer, physical in (
        (reader.trailer.raw_get("/Size"), xref.raw_get("/Size")),
        (reader.trailer.raw_get("/ID"), xref.raw_get("/ID")),
    ):
        if type(trailer) is not type(physical) or trailer != physical:
            raise ValueError("parser trailer scalar differs from XRef stream")
    size_value = reader.trailer.raw_get("/Size")
    ids = reader.trailer.raw_get("/ID")
    if (type(size_value) is not NumberObject or int(size_value) != size
            or type(ids) is not ArrayObject or len(ids) != 2
            or any(type(item) is not TextStringObject or len(item) != 32
                   for item in ids)):
        raise ValueError("generated /Size or /ID field out of profile")

    root = reader.get_object(root_ref)
    info = reader.get_object(info_ref)
    if (type(root) is not DictionaryObject
            or type(root.get("/Type")) is not NameObject
            or root.get("/Type") != "/Catalog"
            or type(info) is not DictionaryObject
            or "/Type" in info):
        raise ValueError("resolved catalog or info dictionary invalid")
    pages_ref = root.raw_get("/Pages")
    pages_id = _reference_id(pages_ref, reader, indexed)
    if pages_id in (root_id, info_id, size - 1):
        raise ValueError("catalog page-tree reference aliases another role")
    pages = reader.get_object(pages_ref)
    if (type(pages) is not DictionaryObject
            or pages.get("/Type") != "/Pages"
            or type(pages.get("/Count")) is not NumberObject
            or int(pages.get("/Count")) != expected_pages):
        raise ValueError("catalog physical page count differs")
    children = pages.raw_get("/Kids")
    if type(children) is not ArrayObject or len(children) != expected_pages:
        raise ValueError("generated flat page kids not complete")
    found = []
    for child in children:
        child_id = _reference_id(child, reader, indexed)
        obj = reader.get_object(child)
        if (child_id in (root_id, info_id, pages_id, size - 1)
                or type(obj) is not DictionaryObject
                or obj.get("/Type") != "/Page"
                or _reference_id(obj.raw_get("/Parent"), reader, indexed) != pages_id):
            raise ValueError("page child type, ownership or identity invalid")
        found.append(child_id)
    if len(set(found)) != expected_pages:
        raise ValueError("repeated physical page child")
    parsed = [page.indirect_reference for page in reader.pages]
    if (len(parsed) != expected_pages
            or [_reference_id(ref, reader, indexed) for ref in parsed] != found
            or reader.xref != {0: direct}
            or reader.xref_objStm != compressed
            or reader.xref_free_entry != {}):
        raise ValueError("parser page order or XRef recovery disagreed")
    return {
        "root_object_number": root_id,
        "info_object_number": info_id,
        "pages_root_object_number": pages_id,
        "catalog_page_count": expected_pages,
        "indexed_page_refs": len(found),
        "xref_trailer_values_match": True,
        "flat_page_tree_consistent": True,
    }


def _inspect(pdf: bytes, identity: dict) -> dict:
    """Require prior parser-resolution proof before catalog/trailer traversal."""
    try:
        _identity(identity)
        if (type(pdf) is not bytes or not pdf.startswith(b"%PDF-1.7")
                or not 0 < len(pdf) <= MAX_PDF_BYTES
                or sha256(pdf).hexdigest() != identity["pdf_sha256"]
                or version("pypdf") != PARSER_VERSION):
            raise ValueError("generated PDF/parser input changed")
        prior = previous._inspect(pdf, identity)
        if prior["status"] != previous.STATUS:
            raise ValueError("native XRef resolution prerequisite missing")
        from pypdf import PdfReader
        reader = PdfReader(BytesIO(pdf), strict=True)
        if reader.is_encrypted or len(reader.pages) != identity["page_count"]:
            raise ValueError("native catalog PDF page identity changed")
        detail = _verify_trailer_catalog(
            reader, expected_pages=identity["page_count"],
            direct_count=prior["parser_direct_entries"],
            compressed_count=prior["parser_compressed_entries"],
        )
        return {"status": STATUS, **detail}
    except Exception:
        raise ValueError("native_trailer_catalog_invalid") from None


def main(argv: list[str] | None = None) -> int:
    """Guard a fixed confined worker with anonymous owned source/result FDs."""
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
            "identity": identity, "limits": limits, "inspection": _inspect(pdf, identity),
        }
        encoded = json.dumps(
            record, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("ascii")
        if not 0 < len(encoded) <= RESULT_BYTES:
            return 70
        _write_bytes(output, encoded)
    except Exception:
        return 70
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
