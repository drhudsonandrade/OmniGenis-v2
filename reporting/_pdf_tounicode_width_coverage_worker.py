"""Confined same-font explicit CID-width coverage for native ToUnicode sources.

Only relates bfchar source codes to the corresponding generated font's /W
entries. It does not verify width metrics, glyph programs, mapping meaning,
general PDF validity or accessibility. No decoded values leave the sandbox.
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
import zlib

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reporting import _pdf_tounicode_bfchar_sources_worker as previous
from reporting import _pdf_tounicode_cmap_frame_worker as frame
from reporting._pdf_cid_widths_worker import (
    MAX_CID_WIDTH_VALUES_PER_FONT, _width_array,
)
from reporting._pdf_object_graph_worker import (
    MAX_PDF_BYTES, PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES,
    _lifetime, _limits, _read_request,
)
from reporting._pdf_trailer_catalog_worker import _reference_id
from reporting._pdf_process_sandbox import enforce_pdf_landlock, enforce_pdf_network_filter
from reporting._pdf_render_worker import _write_bytes

PROFILE_ID = "generated-pdf-tounicode-width-coverage-v1"
POLICY_ID = "generated-native-tounicode-explicit-cid-width-coverage-v1"
STATUS = "TOUNICODE_WIDTH_COVERAGE_ADMITTED"
LANGUAGE = previous.LANGUAGE
MAX_DOCUMENT_PAGES = previous.MAX_DOCUMENT_PAGES
MAX_DECODED_CMAP_BYTES = previous.MAX_DECODED_CMAP_BYTES
MAX_TOTAL_DECODED_BYTES = previous.MAX_TOTAL_DECODED_BYTES
MAX_BFCHAR_BLOCKS = previous.MAX_BFCHAR_BLOCKS
MAX_BFCHAR_RECORDS = previous.MAX_BFCHAR_RECORDS
MAX_BFCHAR_PER_BLOCK = previous.MAX_BFCHAR_PER_BLOCK
MAX_UTF16BE_UNITS = previous.MAX_UTF16BE_UNITS


def _identity(value: dict) -> None:
    """Preserve the exact PDF, IR and page-plan identity."""
    previous._identity(value)


def _identity_from_plan(plan: object) -> dict:
    """Preserve the immutable inherited page-plan binding."""
    return previous._identity_from_plan(plan)


def _covered_sources(stream: object, width_array: object) -> tuple[int, int]:
    """Require each native source in this font's explicit CID-width set."""
    expected, _ = previous._native_unique_bfchar_sources(stream)
    _, width_count = _width_array(width_array)
    explicit: set[int] = set()
    for offset in range(0, len(width_array), 2):
        start = int(width_array[offset])
        explicit.update(range(start, start + len(width_array[offset + 1])))
    if len(explicit) != width_count:
        raise ValueError("native explicit CID-width accounting differs")
    inflater = zlib.decompressobj(wbits=zlib.MAX_WBITS)
    decoded = inflater.decompress(stream._data, MAX_DECODED_CMAP_BYTES + 1)
    if (not 1 <= len(decoded) <= MAX_DECODED_CMAP_BYTES
            or not inflater.eof or inflater.unused_data or inflater.unconsumed_tail
            or not decoded.startswith(frame._NATIVE_PREFIX)
            or not decoded.endswith(frame._NATIVE_SUFFIX)):
        raise ValueError("native width coverage CMap envelope differs")
    body = decoded[len(frame._NATIVE_PREFIX):-len(frame._NATIVE_SUFFIX)]
    covered = 0
    for row in body.split(b"\n"):
        if frame._BFCHAR_ROW.fullmatch(row) is None:
            continue
        if int(row[1:5], 16) not in explicit:
            raise ValueError("native ToUnicode source lacks same-font explicit width")
        covered += 1
        if covered > MAX_BFCHAR_RECORDS:
            raise ValueError("native width coverage source budget exceeded")
    if covered != expected:
        raise ValueError("native width coverage source accounting differs")
    return covered, width_count


def _verify_width_coverage(reader: object, *, expected_pages: int) -> dict:
    """Revalidate ancestors before checking each font's local relation."""
    from pypdf.generic import DictionaryObject

    direct = dict(reader.xref[0])
    compressed = dict(reader.xref_objStm)
    ancestor = previous._verify_bfchar_sources(reader, expected_pages=expected_pages)
    indexed = set(direct) | set(compressed)
    resources_seen: set[int] = set()
    fonts_total = covered_total = widths_total = 0
    for page in reader.pages:
        native = reader.get_object(page.indirect_reference)
        resources_ref = native.raw_get("/Resources")
        resources_id = _reference_id(resources_ref, reader, indexed)
        if resources_id in resources_seen:
            continue
        resources_seen.add(resources_id)
        resources = reader.get_object(resources_ref)
        fonts = reader.get_object(resources.raw_get("/Font"))
        if type(fonts) is not DictionaryObject:
            raise ValueError("native width coverage font resources differ")
        for font_ref in fonts.values():
            font = reader.get_object(font_ref)
            cmap = reader.get_object(font.raw_get("/ToUnicode"))
            cid = reader.get_object(font.raw_get("/DescendantFonts")[0])
            covered, widths = _covered_sources(cmap, cid.raw_get("/W"))
            fonts_total += 1
            covered_total += covered
            widths_total += widths
            if (fonts_total > 32 * expected_pages
                    or covered_total > MAX_BFCHAR_RECORDS
                    or widths_total > MAX_CID_WIDTH_VALUES_PER_FONT * fonts_total):
                raise ValueError("native width coverage aggregate budget exceeded")
    if (not fonts_total
            or fonts_total != ancestor["tounicode_stream_count"]
            or covered_total != ancestor["bfchar_source_count"]
            or covered_total != ancestor["bfchar_unique_source_count"]
            or not covered_total <= widths_total
            or reader.xref != {0: direct}
            or reader.xref_objStm != compressed
            or reader.xref_free_entry != {}):
        raise ValueError("native width coverage ancestor/index differs")
    return {
        "tounicode_stream_count": fonts_total,
        "cid_width_font_count": fonts_total,
        "bfchar_source_count": covered_total,
        "bfchar_covered_source_count": covered_total,
        "explicit_cid_width_count": widths_total,
        "same_font_explicit_width_coverage_valid": True,
    }


def _inspect(pdf: bytes, identity: dict) -> dict:
    """Bind exact source and all strict ancestors before width coverage."""
    try:
        _identity(identity)
        if (type(pdf) is not bytes or not pdf.startswith(b"%PDF-1.7")
                or not 0 < len(pdf) <= MAX_PDF_BYTES
                or sha256(pdf).hexdigest() != identity["pdf_sha256"]
                or version("pypdf") != PARSER_VERSION):
            raise ValueError("native width coverage input/parser differs")
        prior = previous._inspect(pdf, identity)
        if prior["status"] != previous.STATUS:
            raise ValueError("native bfchar source ancestor not admitted")
        from pypdf import PdfReader
        reader = PdfReader(BytesIO(pdf), strict=True)
        if reader.is_encrypted or len(reader.pages) != identity["page_count"]:
            raise ValueError("native width coverage page identity differs")
        return {"status": STATUS, **_verify_width_coverage(
            reader, expected_pages=identity["page_count"],
        )}
    except Exception:
        raise ValueError("native_tounicode_width_coverage_invalid") from None


def main(argv: list[str] | None = None) -> int:
    """Accept owned anonymous descriptors within the inherited Linux limits."""
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
        record = {
            "protocol_version": PROTOCOL_VERSION, "profile_id": PROFILE_ID,
            "policy_id": POLICY_ID, "parser_version": PARSER_VERSION,
            "identity": identity, "limits": limits,
            "inspection": _inspect(pdf, identity),
        }
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("ascii")
        if not 0 < len(encoded) <= RESULT_BYTES:
            return 70
        _write_bytes(output, encoded)
    except Exception:
        return 70
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
