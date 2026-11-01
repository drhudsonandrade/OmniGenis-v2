"""Confined opt-in native descriptor and raw embedded-font envelope check.

This inspects generated PDF object roles and scalar structure only. No font
program is decompressed, executed, decoded, licensed or semantically audited.
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

from reporting._pdf_document_byte_budget import LEGACY_MAX_PDF_BYTES as MAX_RAW_STREAM_BYTES
from reporting import _pdf_resource_leaves_worker as previous
from reporting._pdf_object_graph_worker import (
    MAX_PDF_BYTES, PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES,
    _lifetime, _limits, _read_request,
)
from reporting._pdf_trailer_catalog_worker import _reference_id
from reporting._pdf_process_sandbox import enforce_pdf_landlock, enforce_pdf_network_filter
from reporting._pdf_render_worker import _write_bytes

PROFILE_ID = "generated-pdf-font-descriptor-v1"
POLICY_ID = "generated-font-descriptor-raw-fontfile2-envelope-v1"
STATUS = "FONT_DESCRIPTOR_ENVELOPE_ADMITTED"
LANGUAGE = previous.LANGUAGE
MAX_DOCUMENT_PAGES = previous.MAX_DOCUMENT_PAGES
_DESCRIPTOR_KEYS = frozenset({
    "/Type", "/FontName", "/FontFamily", "/Flags", "/FontBBox",
    "/ItalicAngle", "/Ascent", "/Descent", "/CapHeight",
    "/StemV", "/StemH", "/FontFile2",
})
_FONTFILE_KEYS = frozenset({"/Length1", "/Filter"})
_METRIC_LIMIT = 16384.0


def _identity(value: dict) -> None:
    previous._identity(value)


def _identity_from_plan(plan: object) -> dict:
    return previous._identity_from_plan(plan)


def _native_metric(value: object) -> float:
    """Accept only finite native PDF numbers within a fixed scale envelope."""
    from pypdf.generic import FloatObject, NumberObject
    if type(value) not in (FloatObject, NumberObject):
        raise ValueError("generated font metric has invalid type")
    number = float(value)
    if not math.isfinite(number) or abs(number) > _METRIC_LIMIT:
        raise ValueError("generated font metric is nonfinite or unbounded")
    return number


def _descriptor_envelope(descriptor: object, expected_base: object) -> object:
    """Validate native generated descriptor shape; return raw FontFile2 ref."""
    from pypdf.generic import (
        ArrayObject, DictionaryObject, NameObject, NumberObject,
        TextStringObject,
    )
    if (type(descriptor) is not DictionaryObject
            or set(descriptor) != _DESCRIPTOR_KEYS
            or type(descriptor.raw_get("/Type")) is not NameObject
            or descriptor.raw_get("/Type") != "/FontDescriptor"
            or type(descriptor.raw_get("/FontName")) is not NameObject
            or descriptor.raw_get("/FontName") != expected_base):
        raise ValueError("generated descriptor keys or font name changed")
    family = descriptor.raw_get("/FontFamily")
    flags = descriptor.raw_get("/Flags")
    if (type(family) is not TextStringObject or not 1 <= len(family) <= 128
            or family != family.strip() or not family.isprintable()
            or type(flags) is not NumberObject or not 0 < int(flags) <= 65535):
        raise ValueError("generated font family or flags invalid")
    bbox = descriptor.raw_get("/FontBBox")
    if type(bbox) is not ArrayObject or len(bbox) != 4:
        raise ValueError("generated font bounding box invalid")
    x_min, y_min, x_max, y_max = (_native_metric(item) for item in bbox)
    if not (x_min < x_max and y_min < y_max):
        raise ValueError("generated font bounding box inverted")
    angle = _native_metric(descriptor.raw_get("/ItalicAngle"))
    ascent = _native_metric(descriptor.raw_get("/Ascent"))
    descent = _native_metric(descriptor.raw_get("/Descent"))
    cap = _native_metric(descriptor.raw_get("/CapHeight"))
    stem_v = _native_metric(descriptor.raw_get("/StemV"))
    stem_h = _native_metric(descriptor.raw_get("/StemH"))
    if not (-360 <= angle <= 360 and ascent > 0 and descent < 0
            and cap > 0 and stem_v > 0 and stem_h > 0):
        raise ValueError("generated font numeric descriptor invalid")
    return descriptor.raw_get("/FontFile2")


def _raw_fontfile2(stream: object) -> None:
    """Check the indexed raw Flate envelope without decompressing the bytes."""
    from pypdf.generic import EncodedStreamObject, NameObject, NumberObject
    if (type(stream) is not EncodedStreamObject
            or set(stream) != _FONTFILE_KEYS
            or type(stream.raw_get("/Filter")) is not NameObject
            or stream.raw_get("/Filter") != "/FlateDecode"
            or type(stream.raw_get("/Length1")) is not NumberObject
            or not 0 < int(stream.raw_get("/Length1")) <= MAX_RAW_STREAM_BYTES
            or type(getattr(stream, "_data", None)) is not bytes
            or not 6 <= len(stream._data) <= MAX_RAW_STREAM_BYTES):
        raise ValueError("generated embedded font stream envelope invalid")
    cmf, flg = stream._data[:2]
    if ((cmf & 0x0F) != 8 or (cmf >> 4) > 7
            or ((cmf << 8) | flg) % 31 != 0 or (flg & 0x20)):
        raise ValueError("generated embedded font raw Flate header invalid")


def _verify_font_descriptor(
    reader: object, *, expected_pages: int, direct_count: int,
    compressed_count: int,
) -> dict:
    """Chain resource-leaf proof and audit generated FontFile2 native roles."""
    predecessor = previous._verify_resource_leaves(
        reader, expected_pages=expected_pages,
        direct_count=direct_count, compressed_count=compressed_count,
    )
    from pypdf.generic import DictionaryObject

    direct = dict(reader.xref[0])
    compressed = dict(reader.xref_objStm)
    indexed = set(direct) | set(compressed)
    known: set[int] = {direct_count + compressed_count}
    root = reader.trailer.raw_get("/Root")
    info = reader.trailer.raw_get("/Info")
    pages_root = reader.get_object(root).raw_get("/Pages")
    for ref in (root, info, pages_root):
        known.add(_reference_id(ref, reader, indexed))
    descriptor_ids: set[int] = set()
    embedded_ids: set[int] = set()
    resource_ids: set[int] = set()
    for page in reader.pages:
        native = reader.get_object(page.indirect_reference)
        resources_ref = native.raw_get("/Resources")
        resources_id = _reference_id(resources_ref, reader, indexed)
        known.update({
            _reference_id(page.indirect_reference, reader, indexed),
            _reference_id(native.raw_get("/Contents"), reader, indexed),
            resources_id,
        })
        resources = reader.get_object(resources_ref)
        font_category_ref = resources.raw_get("/Font")
        color_category_ref = resources.raw_get("/ColorSpace")
        known.update({
            _reference_id(font_category_ref, reader, indexed),
            _reference_id(color_category_ref, reader, indexed),
        })
        if resources_id in resource_ids:
            continue
        resource_ids.add(resources_id)
        fonts = reader.get_object(font_category_ref)
        if type(fonts) is not DictionaryObject:
            raise ValueError("generated font resources not a dictionary")
        for font_key in fonts:
            font_ref = fonts.raw_get(font_key)
            font = reader.get_object(font_ref)
            cid_ref = font.raw_get("/DescendantFonts")[0]
            cid = reader.get_object(cid_ref)
            desc_ref = cid.raw_get("/FontDescriptor")
            desc_id = _reference_id(desc_ref, reader, indexed)
            known.update({
                _reference_id(font_ref, reader, indexed),
                _reference_id(font.raw_get("/ToUnicode"), reader, indexed),
                _reference_id(cid_ref, reader, indexed),
            })
            if desc_id in descriptor_ids:
                raise ValueError("generated FontDescriptor role reused")
            descriptor_ids.add(desc_id)
            fontfile_ref = _descriptor_envelope(
                reader.get_object(desc_ref), cid.raw_get("/BaseFont"),
            )
            fontfile_id = _reference_id(fontfile_ref, reader, indexed)
            if fontfile_id in embedded_ids:
                raise ValueError("generated FontFile2 role reused")
            embedded_ids.add(fontfile_id)
            _raw_fontfile2(reader.get_object(fontfile_ref))

    if (not embedded_ids.isdisjoint(known | descriptor_ids)
            or descriptor_ids & known
            or len(resource_ids) != predecessor["resource_dictionary_count"]
            or len(descriptor_ids) != predecessor["font_binding_count"]
            or len(embedded_ids) != len(descriptor_ids)
            or reader.xref != {0: direct}
            or reader.xref_objStm != compressed
            or reader.xref_free_entry != {}):
        raise ValueError("generated descriptor/embedded roles or index changed")
    return {
        "font_descriptor_envelope_count": len(descriptor_ids),
        "font_file2_raw_stream_count": len(embedded_ids),
        "descriptor_names_match": True,
        "descriptor_metrics_bounded": True,
        "font_file2_streams_indexed": True,
    }


def _inspect(pdf: bytes, identity: dict) -> dict:
    """Exact generated document identity and full native prerequisite chain."""
    try:
        _identity(identity)
        if (type(pdf) is not bytes or not pdf.startswith(b"%PDF-1.7")
                or not 0 < len(pdf) <= MAX_PDF_BYTES
                or sha256(pdf).hexdigest() != identity["pdf_sha256"]
                or version("pypdf") != PARSER_VERSION):
            raise ValueError("generated PDF/parser identity differs")
        prior = previous._inspect(pdf, identity)
        if prior["status"] != previous.STATUS:
            raise ValueError("native resource prerequisite missing")
        from pypdf import PdfReader
        reader = PdfReader(BytesIO(pdf), strict=True)
        if reader.is_encrypted or len(reader.pages) != identity["page_count"]:
            raise ValueError("generated native page count differs")
        return {
            "status": STATUS,
            **_verify_font_descriptor(
                reader, expected_pages=identity["page_count"],
                direct_count=len(reader.xref[0]),
                compressed_count=len(reader.xref_objStm),
            ),
        }
    except Exception:
        raise ValueError("native_font_descriptor_invalid") from None


def main(argv: list[str] | None = None) -> int:
    """Only owned unlinked input/output FDs under inherited confinement."""
    argv = sys.argv if argv is None else argv
    if (sys.platform != "linux" or type(argv) is not list or len(argv) != 4
            or any(type(v) is not str or not v.isascii() or not v.isdecimal()
                   or len(v) > 10 for v in argv[1:])):
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
            row, sort_keys=True, separators=(",", ":"),
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
