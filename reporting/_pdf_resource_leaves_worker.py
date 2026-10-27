"""Confined opt-in proof of native generated Type0/Lab resource leaves.

Only indexed reference roles, native generated dictionary shape and RAW
ToUnicode stream presence are admitted. Font programs, glyph mappings,
decoded streams, colorimetry and PDF/UA are explicitly not audited.
"""
from __future__ import annotations

from hashlib import sha256
from importlib.metadata import version
from io import BytesIO
import json
import math
import os
from pathlib import Path
import re
import stat
import sys

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reporting import _pdf_page_surface_worker as previous
from reporting._pdf_object_graph_worker import (
    MAX_PDF_BYTES, PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES,
    _lifetime, _limits, _read_request,
)
from reporting._pdf_process_sandbox import enforce_pdf_landlock, enforce_pdf_network_filter
from reporting._pdf_render_worker import _write_bytes

PROFILE_ID = "generated-pdf-resource-leaves-v1"
POLICY_ID = "generated-pdf-type0-lab-leaf-binding-v1"
STATUS = "RESOURCE_LEAVES_ADMITTED"
LANGUAGE = previous.LANGUAGE
MAX_DOCUMENT_PAGES = previous.MAX_DOCUMENT_PAGES
_FONT_KEYS = frozenset((
    "/Type", "/Subtype", "/BaseFont", "/ToUnicode", "/Encoding",
    "/DescendantFonts",
))
_CID_KEYS = frozenset((
    "/Type", "/Subtype", "/BaseFont", "/CIDSystemInfo",
    "/CIDToGIDMap", "/W", "/FontDescriptor",
))
_LAB_PRESETS = {
    "/lab-d50": (0.964296, 1.0, 0.825105),
    "/lab-d65": (0.950456, 1.0, 1.089058),
}
_NAME = re.compile(r"/[A-Z]{6}\Z", re.ASCII)
_BASE = re.compile(r"/[A-Z]{6}\+[A-Za-z0-9_.-]{1,80}\Z", re.ASCII)


def _identity(value: dict) -> None:
    previous._identity(value)


def _identity_from_plan(plan: object) -> dict:
    return previous._identity_from_plan(plan)


def _number(value: object) -> float:
    """A native finite scalar, not a string, bool or indirect replacement."""
    from pypdf.generic import FloatObject, NumberObject
    if type(value) not in (FloatObject, NumberObject):
        raise ValueError("generated Lab scalar has invalid type")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("generated Lab scalar is nonfinite")
    return number


def _lab_presets(colors: object) -> int:
    """Compare direct generated Lab presets with pinned finite native values."""
    from pypdf.generic import ArrayObject, DictionaryObject, NameObject
    if type(colors) is not DictionaryObject or set(colors) != set(_LAB_PRESETS):
        raise ValueError("generated Lab color category differs")
    for name, preset in _LAB_PRESETS.items():
        pair = colors.raw_get(name)
        if (type(pair) is not ArrayObject or len(pair) != 2
                or type(pair[0]) is not NameObject or pair[0] != "/Lab"
                or type(pair[1]) is not DictionaryObject
                or set(pair[1]) != {"/WhitePoint", "/Range"}):
            raise ValueError("generated Lab color preset shape changed")
        white = pair[1].raw_get("/WhitePoint")
        gamut = pair[1].raw_get("/Range")
        if (type(white) is not ArrayObject or len(white) != 3
                or type(gamut) is not ArrayObject or len(gamut) != 4
                or any(abs(_number(actual) - wanted) > 0.000001
                       for actual, wanted in zip(white, preset, strict=True))
                or tuple(_number(v) for v in gamut)
                   != (-125.0, 125.0, -125.0, 125.0)):
            raise ValueError("generated Lab whitepoint or gamut changed")
    return len(_LAB_PRESETS)


def _verify_resource_leaves(
    reader: object, *, expected_pages: int, direct_count: int,
    compressed_count: int,
) -> dict:
    """Chain native page proof, then reject mismatched inner resource roles."""
    from pypdf.generic import (
        ArrayObject, DictionaryObject, NameObject, NumberObject, StreamObject,
        TextStringObject,
    )

    predecessor = previous._verify_page_surface(
        reader, expected_pages=expected_pages,
        direct_count=direct_count, compressed_count=compressed_count,
    )
    if (predecessor["page_dictionary_count"] != expected_pages
            or predecessor["resource_references_indexed"] is not True):
        raise ValueError("native page/resource prerequisite missing")
    direct = dict(reader.xref[0])
    compressed = dict(reader.xref_objStm)
    indexed = set(direct) | set(compressed)
    reference_id = previous.previous._reference_id
    pages = list(reader.pages)
    upstream_roles: set[int] = set()
    catalog_ref = reader.trailer.raw_get("/Root")
    info_ref = reader.trailer.raw_get("/Info")
    pages_root_ref = reader.get_object(catalog_ref).raw_get("/Pages")
    upstream_roles.update({
        reference_id(catalog_ref, reader, indexed),
        reference_id(info_ref, reader, indexed),
        reference_id(pages_root_ref, reader, indexed),
        direct_count + compressed_count,  # Prior generated XRef stream identity.
    })
    for page in pages:
        native = reader.get_object(page.indirect_reference)
        upstream_roles.add(reference_id(page.indirect_reference, reader, indexed))
        upstream_roles.add(reference_id(native.raw_get("/Contents"), reader, indexed))
        res_ref = native.raw_get("/Resources")
        upstream_roles.add(reference_id(res_ref, reader, indexed))
        outer = reader.get_object(res_ref)
        upstream_roles.add(reference_id(outer.raw_get("/Font"), reader, indexed))
        upstream_roles.add(reference_id(outer.raw_get("/ColorSpace"), reader, indexed))

    claimed = set(upstream_roles)
    resource_ids: set[int] = set()
    font_count = 0
    cmap_count = 0
    cid_count = 0
    color_count = 0
    for page in pages:
        native = reader.get_object(page.indirect_reference)
        outer_ref = native.raw_get("/Resources")
        resource_id = reference_id(outer_ref, reader, indexed)
        if resource_id in resource_ids:
            continue  # Native generated pages normally share this exact dictionary.
        resource_ids.add(resource_id)
        outer = reader.get_object(outer_ref)
        fonts = reader.get_object(outer.raw_get("/Font"))
        colors = reader.get_object(outer.raw_get("/ColorSpace"))
        color_count += _lab_presets(colors)
        if (type(fonts) is not DictionaryObject or not 1 <= len(fonts) <= 32
                or any(type(key) is not NameObject or not _NAME.fullmatch(str(key))
                       for key in fonts)):
            raise ValueError("generated indexed font category changed")
        for font_key in fonts:
            font_ref = fonts.raw_get(font_key)
            font_id = reference_id(font_ref, reader, indexed)
            if font_id in claimed:
                raise ValueError("font object reference aliases another role")
            claimed.add(font_id)
            font = reader.get_object(font_ref)
            base = font.raw_get("/BaseFont") if type(font) is DictionaryObject and "/BaseFont" in font else None
            if (type(font) is not DictionaryObject or set(font) != _FONT_KEYS
                    or type(font.raw_get("/Type")) is not NameObject
                    or font.raw_get("/Type") != "/Font"
                    or type(font.raw_get("/Subtype")) is not NameObject
                    or font.raw_get("/Subtype") != "/Type0"
                    or type(font.raw_get("/Encoding")) is not NameObject
                    or font.raw_get("/Encoding") != "/Identity-H"
                    or type(base) is not NameObject or not _BASE.fullmatch(str(base))
                    or not str(base).startswith(str(font_key) + "+")):
                raise ValueError("generated Type0 font dictionary differs")
            font_count += 1

            cmap_ref = font.raw_get("/ToUnicode")
            cmap_id = reference_id(cmap_ref, reader, indexed)
            if cmap_id in claimed:
                raise ValueError("ToUnicode aliases another reference role")
            claimed.add(cmap_id)
            cmap = reader.get_object(cmap_ref)
            if (not isinstance(cmap, StreamObject) or set(cmap) != {"/Filter"}
                    or type(cmap.raw_get("/Filter")) is not NameObject
                    or cmap.raw_get("/Filter") != "/FlateDecode"
                    or type(getattr(cmap, "_data", None)) is not bytes
                    or not 0 < len(cmap._data) <= MAX_PDF_BYTES):
                raise ValueError("generated raw ToUnicode reference changed")
            cmap_count += 1

            descendants = font.raw_get("/DescendantFonts")
            if type(descendants) is not ArrayObject or len(descendants) != 1:
                raise ValueError("generated Type0 CID array changed")
            cid_ref = descendants[0]
            cid_id = reference_id(cid_ref, reader, indexed)
            if cid_id in claimed:
                raise ValueError("CID descendant aliases another reference role")
            claimed.add(cid_id)
            cid = reader.get_object(cid_ref)
            if (type(cid) is not DictionaryObject or set(cid) != _CID_KEYS
                    or type(cid.raw_get("/Type")) is not NameObject
                    or cid.raw_get("/Type") != "/Font"
                    or type(cid.raw_get("/Subtype")) is not NameObject
                    or cid.raw_get("/Subtype") != "/CIDFontType2"
                    or type(cid.raw_get("/BaseFont")) is not NameObject
                    or cid.raw_get("/BaseFont") != base
                    or type(cid.raw_get("/CIDToGIDMap")) is not NameObject
                    or cid.raw_get("/CIDToGIDMap") != "/Identity"
                    or type(cid.raw_get("/W")) is not ArrayObject
                    or not 0 < len(cid.raw_get("/W")) <= 4096):
                raise ValueError("generated CID descendant type or linkage changed")
            system = cid.raw_get("/CIDSystemInfo")
            if (type(system) is not DictionaryObject
                    or set(system) != {"/Registry", "/Ordering", "/Supplement"}
                    or type(system.raw_get("/Registry")) is not TextStringObject
                    or system.raw_get("/Registry") != "Adobe"
                    or type(system.raw_get("/Ordering")) is not TextStringObject
                    or system.raw_get("/Ordering") != "Identity"
                    or type(system.raw_get("/Supplement")) is not NumberObject
                    or system.raw_get("/Supplement") != 0):
                raise ValueError("generated CIDSystemInfo differs")
            descriptor_ref = cid.raw_get("/FontDescriptor")
            descriptor_id = reference_id(descriptor_ref, reader, indexed)
            descriptor = reader.get_object(descriptor_ref)
            if (descriptor_id in claimed or type(descriptor) is not DictionaryObject
                    or "/Type" not in descriptor
                    or type(descriptor.raw_get("/Type")) is not NameObject
                    or descriptor.raw_get("/Type") != "/FontDescriptor"):
                raise ValueError("generated FontDescriptor reference role changed")
            claimed.add(descriptor_id)
            cid_count += 1

    if (not 1 <= len(resource_ids) <= expected_pages
            or not 1 <= font_count <= len(resource_ids) * 32
            or cmap_count != font_count or cid_count != font_count
            or color_count != len(resource_ids) * len(_LAB_PRESETS)
            or reader.xref != {0: direct}
            or reader.xref_objStm != compressed
            or reader.xref_free_entry != {}):
        raise ValueError("generated leaf roles, counts or parser index changed")
    return {
        "resource_dictionary_count": len(resource_ids),
        "font_binding_count": font_count,
        "cid_descendant_reference_count": cid_count,
        "tounicode_stream_reference_count": cmap_count,
        "lab_color_space_count": color_count,
        "font_reference_roles_disjoint": True,
        "type0_cid_links_match": True,
        "lab_color_presets_match": True,
        "tounicode_raw_streams_indexed": True,
    }


def _inspect(pdf: bytes, identity: dict) -> dict:
    """Both upstream native surface and current indexed leaf checks must pass."""
    try:
        _identity(identity)
        if (type(pdf) is not bytes or not pdf.startswith(b"%PDF-1.7")
                or not 0 < len(pdf) <= MAX_PDF_BYTES
                or sha256(pdf).hexdigest() != identity["pdf_sha256"]
                or version("pypdf") != PARSER_VERSION):
            raise ValueError("generated source/parser differs")
        prior = previous._inspect(pdf, identity)
        if prior["status"] != previous.STATUS:
            raise ValueError("prior native page surface missing")
        from pypdf import PdfReader
        reader = PdfReader(BytesIO(pdf), strict=True)
        if reader.is_encrypted or len(reader.pages) != identity["page_count"]:
            raise ValueError("native generated page count differs")
        detail = _verify_resource_leaves(
            reader, expected_pages=identity["page_count"],
            direct_count=len(reader.xref[0]),
            compressed_count=len(reader.xref_objStm),
        )
        return {"status": STATUS, **detail}
    except Exception:
        raise ValueError("native_resource_leaves_invalid") from None


def main(argv: list[str] | None = None) -> int:
    """Only owned unlinked regular FDs are accepted under fixed confinement."""
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
            "identity": identity, "limits": limits,
            "inspection": _inspect(pdf, identity),
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
