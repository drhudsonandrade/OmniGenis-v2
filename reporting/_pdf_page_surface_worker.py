"""Confined, opt-in generated PDF page surface/resource reference parity.

Only native page dictionaries, RAW compressed stream references, outer resource
identities, finite boxes and structural slot numbers are checked. No stream
decode, inner font/image audit, reading-order or PDF/UA/release claim.
"""
from __future__ import annotations

from hashlib import sha256
from importlib.metadata import version
from io import BytesIO
import json
import math
import os
from pathlib import Path
import stat
import sys

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reporting import _pdf_trailer_catalog_worker as previous
from reporting._pdf_object_graph_worker import (
    MAX_PDF_BYTES, PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES,
    _lifetime, _limits, _read_request,
)
from reporting._pdf_process_sandbox import enforce_pdf_landlock, enforce_pdf_network_filter
from reporting._pdf_render_worker import _write_bytes

PROFILE_ID = "generated-pdf-page-surface-v1"
POLICY_ID = "generated-pdf-native-page-resource-surface-v1"
STATUS = "PAGE_SURFACE_ADMITTED"
LANGUAGE = previous.LANGUAGE
MAX_DOCUMENT_PAGES = previous.MAX_DOCUMENT_PAGES
_PAGE_KEYS = frozenset((
    "/Type", "/Parent", "/MediaBox", "/Contents", "/Resources",
    "/Tabs", "/StructParents", "/TrimBox", "/BleedBox",
))
_RESOURCE_KEYS = frozenset((
    "/ExtGState", "/XObject", "/Pattern", "/Shading", "/ColorSpace", "/Font",
))
_DIRECT_RESOURCE_KEYS = ("/ExtGState", "/XObject", "/Pattern", "/Shading")
_INDIRECT_RESOURCE_KEYS = ("/ColorSpace", "/Font")
_MAX_PAGE_SIDE_POINTS = 2000.0


def _identity(value: dict) -> None:
    previous._identity(value)


def _identity_from_plan(plan: object) -> dict:
    return previous._identity_from_plan(plan)


def _box(native: object, name: str) -> tuple[float, ...]:
    """Only finite, positive and bounded native generated rectangle scalars."""
    from pypdf.generic import ArrayObject, FloatObject, NumberObject
    value = native.raw_get(name)
    if (type(value) is not ArrayObject or len(value) != 4
            or any(type(item) not in (FloatObject, NumberObject) for item in value)):
        raise ValueError("unsupported native page box")
    numbers = tuple(float(item) for item in value)
    x0, y0, x1, y1 = numbers
    if (not all(math.isfinite(n) and 0 <= n <= _MAX_PAGE_SIDE_POINTS for n in numbers)
            or not 0 < x1 - x0 <= _MAX_PAGE_SIDE_POINTS
            or not 0 < y1 - y0 <= _MAX_PAGE_SIDE_POINTS):
        raise ValueError("native page box coordinates invalid")
    return numbers


def _verify_page_surface(
    reader: object, *, expected_pages: int, direct_count: int,
    compressed_count: int,
) -> dict:
    """Recheck the prior physical catalog, then inspect every page-local role."""
    from pypdf.generic import (
        DictionaryObject, IndirectObject, NameObject, NumberObject, StreamObject,
    )

    prior = previous._verify_trailer_catalog(
        reader, expected_pages=expected_pages,
        direct_count=direct_count, compressed_count=compressed_count,
    )
    direct = dict(reader.xref[0])
    compressed = dict(reader.xref_objStm)
    indexed = set(direct) | set(compressed)
    xref_id = direct_count + compressed_count
    reserved = {
        prior["root_object_number"], prior["info_object_number"],
        prior["pages_root_object_number"], xref_id,
    }
    native_pages = list(reader.pages)
    page_refs = [p.indirect_reference for p in native_pages]
    page_ids = [previous._reference_id(ref, reader, indexed) for ref in page_refs]
    if (len(page_ids) != expected_pages or len(set(page_ids)) != expected_pages
            or set(page_ids) & reserved):
        raise ValueError("native page identity conflicts with catalog role")
    reserved.update(page_ids)
    contents_seen: set[int] = set()
    resources_seen: set[int] = set()
    nested_seen: set[int] = set()
    slots: set[int] = set()

    for page_ref in page_refs:
        native = reader.get_object(page_ref)
        if (type(native) is not DictionaryObject or set(native) != _PAGE_KEYS
                or type(native.raw_get("/Type")) is not NameObject
                or native.raw_get("/Type") != "/Page"
                or previous._reference_id(native.raw_get("/Parent"), reader, indexed)
                   != prior["pages_root_object_number"]):
            raise ValueError("generated physical page dictionary differs")
        media = _box(native, "/MediaBox")
        if _box(native, "/TrimBox") != media or _box(native, "/BleedBox") != media:
            raise ValueError("generated page boxes disagree")
        if (type(native.raw_get("/Tabs")) is not NameObject
                or native.raw_get("/Tabs") != "/S"):
            raise ValueError("generated native tab-order declaration changed")
        slot = native.raw_get("/StructParents")
        if (type(slot) is not NumberObject
                or not 0 <= int(slot) < expected_pages or int(slot) in slots):
            raise ValueError("generated structure parent slot changed")
        slots.add(int(slot))

        content_ref = native.raw_get("/Contents")
        content_id = previous._reference_id(content_ref, reader, indexed)
        if content_id in reserved or content_id in contents_seen:
            raise ValueError("generated page content reference aliased")
        content = reader.get_object(content_ref)
        if (not isinstance(content, StreamObject)
                or set(content) != {"/Filter"}
                or type(content.get("/Filter")) is not NameObject
                or content.get("/Filter") != "/FlateDecode"
                or type(getattr(content, "_data", None)) is not bytes
                or not 0 < len(content._data) <= MAX_PDF_BYTES):
            raise ValueError("generated compressed page stream outside raw profile")
        contents_seen.add(content_id)

        resource_ref = native.raw_get("/Resources")
        resource_id = previous._reference_id(resource_ref, reader, indexed)
        if resource_id in reserved or resource_id in contents_seen:
            raise ValueError("generated page resource reference aliased")
        resources = reader.get_object(resource_ref)
        if type(resources) is not DictionaryObject or set(resources) != _RESOURCE_KEYS:
            raise ValueError("generated native outer resources changed")
        for key in _DIRECT_RESOURCE_KEYS:
            if type(resources.raw_get(key)) is not DictionaryObject:
                raise ValueError("generated direct resource category invalid")
        for key in _INDIRECT_RESOURCE_KEYS:
            nested_ref = resources.raw_get(key)
            nested_id = previous._reference_id(nested_ref, reader, indexed)
            if nested_id in reserved or nested_id == resource_id:
                raise ValueError("generated resource subcategory aliased")
            if type(reader.get_object(nested_ref)) is not DictionaryObject:
                raise ValueError("generated resource subcategory dictionary changed")
            nested_seen.add(nested_id)
        resources_seen.add(resource_id)

    if (slots != set(range(expected_pages))
            or len(contents_seen) != expected_pages
            or len(resources_seen) < 1
            or (contents_seen & resources_seen)
            or (contents_seen & nested_seen)
            or (resources_seen & nested_seen)
            or reader.xref != {0: direct}
            or reader.xref_objStm != compressed
            or reader.xref_free_entry != {}):
        raise ValueError("physical page roles, slots or parser indices disagree")
    return {
        "page_dictionary_count": expected_pages,
        "content_stream_count": len(contents_seen),
        "resource_reference_count": expected_pages,
        "distinct_resource_objects": len(resources_seen),
        "boxes_match": True,
        "content_references_indexed": True,
        "resource_references_indexed": True,
        "structure_slots_contiguous": True,
    }


def _inspect(pdf: bytes, identity: dict) -> dict:
    """Require the existing native trailer/catalog proof first."""
    try:
        _identity(identity)
        if (type(pdf) is not bytes or not pdf.startswith(b"%PDF-1.7")
                or not 0 < len(pdf) <= MAX_PDF_BYTES
                or sha256(pdf).hexdigest() != identity["pdf_sha256"]
                or version("pypdf") != PARSER_VERSION):
            raise ValueError("generated source/parser changed")
        prior = previous._inspect(pdf, identity)
        if prior["status"] != previous.STATUS:
            raise ValueError("prior trailer/catalog admission missing")
        from pypdf import PdfReader
        reader = PdfReader(BytesIO(pdf), strict=True)
        if reader.is_encrypted or len(reader.pages) != identity["page_count"]:
            raise ValueError("native generated page count changed")
        detail = _verify_page_surface(
            reader, expected_pages=identity["page_count"],
            direct_count=len(reader.xref[0]),
            compressed_count=len(reader.xref_objStm),
        )
        return {"status": STATUS, **detail}
    except Exception:
        raise ValueError("native_page_surface_invalid") from None


def main(argv: list[str] | None = None) -> int:
    """Receive only owned unlinked regular file descriptors in fixed confinement."""
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
        row = {
            "protocol_version": PROTOCOL_VERSION, "profile_id": PROFILE_ID,
            "policy_id": POLICY_ID, "parser_version": PARSER_VERSION,
            "identity": identity, "limits": limits, "inspection": _inspect(pdf, identity),
        }
        encoded = json.dumps(
            row, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        if not 0 < len(encoded) <= RESULT_BYTES:
            return 70
        _write_bytes(output, encoded)
    except Exception:
        return 70
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
