"""Confined generated native ToUnicode bfchar source collision probe.

Adds per-CMap, 16-bit source uniqueness to the strict native frame and
well-formed UTF-16BE target ancestors. Does not determine Unicode mapping
meaning, glyph correctness, general CMap syntax or PDF/UA compliance.
No decoded CMap data or source code values leave the Linux sandbox.
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

from reporting import _pdf_tounicode_utf16be_targets_worker as previous
from reporting._pdf_object_graph_worker import (
    MAX_PDF_BYTES, PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES,
    _lifetime, _limits, _read_request,
)
from reporting._pdf_trailer_catalog_worker import _reference_id
from reporting._pdf_process_sandbox import (
    enforce_pdf_landlock, enforce_pdf_network_filter,
)
from reporting._pdf_render_worker import _write_bytes

PROFILE_ID = "generated-pdf-tounicode-bfchar-sources-v1"
POLICY_ID = "generated-native-tounicode-bfchar-source-uniqueness-v1"
STATUS = "TOUNICODE_BFCHAR_SOURCES_ADMITTED"
LANGUAGE = previous.LANGUAGE
MAX_DOCUMENT_PAGES = previous.MAX_DOCUMENT_PAGES
MAX_DECODED_CMAP_BYTES = previous.MAX_DECODED_CMAP_BYTES
MAX_TOTAL_DECODED_BYTES = previous.MAX_TOTAL_DECODED_BYTES
MAX_BFCHAR_BLOCKS = previous.MAX_BFCHAR_BLOCKS
MAX_BFCHAR_RECORDS = previous.MAX_BFCHAR_RECORDS
MAX_BFCHAR_PER_BLOCK = previous.MAX_BFCHAR_PER_BLOCK
MAX_UTF16BE_UNITS = previous.MAX_UTF16BE_UNITS


def _identity(value: dict) -> None:
    """Preserve the exact plan, PDF and IR identity from all ancestors."""
    previous._identity(value)


def _identity_from_plan(plan: object) -> dict:
    """Preserve the immutable prior page-plan binding."""
    return previous._identity_from_plan(plan)


def _native_unique_bfchar_sources(stream: object) -> tuple[int, int]:
    """Reject duplicate 16-bit source operands within one native CMap."""
    try:
        expected, _, _, _ = previous._native_utf16be_targets(stream)
    except ValueError:
        # The previous result also carries unit and scalar counters.
        raise ValueError("native_bfchar_source_uniqueness_invalid") from None
    try:
        frame = previous.previous
        inflater = zlib.decompressobj(wbits=zlib.MAX_WBITS)
        decoded = inflater.decompress(stream._data, MAX_DECODED_CMAP_BYTES + 1)
        if (not 1 <= len(decoded) <= MAX_DECODED_CMAP_BYTES
                or not inflater.eof or inflater.unused_data
                or inflater.unconsumed_tail
                or not decoded.startswith(frame._NATIVE_PREFIX)
                or not decoded.endswith(frame._NATIVE_SUFFIX)):
            raise ValueError("native bfchar source zlib or frame changed")
        body = decoded[len(frame._NATIVE_PREFIX):-len(frame._NATIVE_SUFFIX)]
        seen: set[int] = set()
        rows = 0
        for row in body.split(b"\n"):
            if frame._BFCHAR_ROW.fullmatch(row) is None:
                continue
            source = int(row[1:5], 16)
            if source in seen:
                raise ValueError("native bfchar duplicate source")
            seen.add(source)
            rows += 1
            if rows > MAX_BFCHAR_RECORDS:
                raise ValueError("native bfchar source budget exceeded")
        if rows != expected or len(seen) != expected:
            raise ValueError("native bfchar source accounting differs")
        return rows, len(seen)
    except Exception:
        raise ValueError("native_bfchar_source_uniqueness_invalid") from None


def _verify_bfchar_sources(reader: object, *, expected_pages: int) -> dict:
    """Revalidate UTF-16BE ancestor and admit only per-stream unique codes."""
    from pypdf.generic import DictionaryObject

    direct = dict(reader.xref[0])
    compressed = dict(reader.xref_objStm)
    ancestor = previous._verify_utf16be_targets(
        reader, expected_pages=expected_pages,
    )
    indexed = set(direct) | set(compressed)
    resources_seen: set[int] = set()
    streams = 0
    rows_total = 0
    uniques_total = 0
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
            raise ValueError("native generated font resources differ")
        for font_ref in fonts.values():
            font = reader.get_object(font_ref)
            cmap = reader.get_object(font.raw_get("/ToUnicode"))
            rows, uniques = _native_unique_bfchar_sources(cmap)
            rows_total += rows
            uniques_total += uniques
            streams += 1
            if (streams > 32 * expected_pages
                    or rows_total > MAX_BFCHAR_RECORDS
                    or uniques_total > MAX_BFCHAR_RECORDS):
                raise ValueError("aggregate native bfchar source budget exceeded")
    if (not streams
            or streams != ancestor["tounicode_stream_count"]
            or streams != ancestor["cmap_framed_stream_count"]
            or rows_total != ancestor["utf16be_target_count"]
            or uniques_total != rows_total
            or reader.xref != {0: direct}
            or reader.xref_objStm != compressed
            or reader.xref_free_entry != {}):
        raise ValueError("native bfchar source ancestor/count differs")
    return {
        "tounicode_stream_count": streams,
        "cmap_framed_stream_count": streams,
        "bfchar_source_count": rows_total,
        "bfchar_unique_source_count": uniques_total,
        "cmap_bfchar_source_uniqueness_valid": True,
    }

def _inspect(pdf: bytes, identity: dict) -> dict:
    """Require all strict ancestors before the local source collision check."""
    try:
        _identity(identity)
        if (type(pdf) is not bytes or not pdf.startswith(b"%PDF-1.7")
                or not 0 < len(pdf) <= MAX_PDF_BYTES
                or sha256(pdf).hexdigest() != identity["pdf_sha256"]
                or version("pypdf") != PARSER_VERSION):
            raise ValueError("native bfchar source input or parser differs")
        prior = previous._inspect(pdf, identity)
        if prior["status"] != previous.STATUS:
            raise ValueError("native UTF-16BE ancestor not admitted")
        from pypdf import PdfReader
        reader = PdfReader(BytesIO(pdf), strict=True)
        if reader.is_encrypted or len(reader.pages) != identity["page_count"]:
            raise ValueError("native bfchar source page identity differs")
        return {
            "status": STATUS,
            **_verify_bfchar_sources(
                reader, expected_pages=identity["page_count"],
            ),
        }
    except Exception:
        raise ValueError("native_bfchar_source_uniqueness_invalid") from None


def main(argv: list[str] | None = None) -> int:
    """Use only owned anonymous FDs and the inherited Linux sandbox."""
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
