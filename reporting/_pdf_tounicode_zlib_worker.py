"""Confined bounded zlib completion check for native generated ToUnicode streams.

Checks deflate completion and Adler-32 through zlib within strict decoded-byte
budgets. Decompressed CMap bytes stay in the worker; no CMap grammar, Unicode
mapping, glyph, reading-order or PDF/UA qualification is claimed.
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

from reporting import _pdf_tounicode_header_worker as previous
from reporting._pdf_object_graph_worker import (
    MAX_PDF_BYTES, PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES,
    _lifetime, _limits, _read_request,
)
from reporting._pdf_trailer_catalog_worker import _reference_id
from reporting._pdf_process_sandbox import (
    enforce_pdf_landlock, enforce_pdf_network_filter,
)
from reporting._pdf_render_worker import _write_bytes

PROFILE_ID = "generated-pdf-tounicode-zlib-v1"
POLICY_ID = "generated-native-tounicode-zlib-complete-v1"
STATUS = "TOUNICODE_ZLIB_COMPLETION_ADMITTED"
LANGUAGE = previous.LANGUAGE
MAX_DOCUMENT_PAGES = previous.MAX_DOCUMENT_PAGES
MAX_DECODED_CMAP_BYTES = 256 * 1024
MAX_TOTAL_DECODED_BYTES = 512 * 1024


def _identity(value: dict) -> None:
    """Validate the sealed source identity using the exact predecessor."""
    previous._identity(value)


def _identity_from_plan(plan: object) -> dict:
    """Extract the predecessor's strictly validated plan identity."""
    return previous._identity_from_plan(plan)


def _bounded_zlib_completion(stream: object) -> int:
    """Validate native zlib end, Adler-32 and budgets without parsing CMap."""
    previous._raw_zlib_header(stream)
    try:
        decompressor = zlib.decompressobj(wbits=zlib.MAX_WBITS)
        decoded = decompressor.decompress(
            stream._data, MAX_DECODED_CMAP_BYTES + 1,
        )
        if (not 1 <= len(decoded) <= MAX_DECODED_CMAP_BYTES
                or not decompressor.eof
                or decompressor.unused_data
                or decompressor.unconsumed_tail):
            raise ValueError("ToUnicode zlib stream not bounded and complete")
        return len(decoded)
    except Exception:
        raise ValueError("native ToUnicode zlib completion invalid") from None


def _verify_tounicode_zlib(
    reader: object, *, expected_pages: int, direct_count: int,
    compressed_count: int,
) -> dict:
    """Verify native CMap transport, exact predecessor count, finite total."""
    from pypdf.generic import DictionaryObject

    predecessor = previous._verify_tounicode_headers(
        reader, expected_pages=expected_pages,
        direct_count=direct_count, compressed_count=compressed_count,
    )
    direct = dict(reader.xref[0])
    compressed = dict(reader.xref_objStm)
    indexed = set(direct) | set(compressed)
    resources_seen: set[int] = set()
    stream_count = 0
    decoded_total = 0
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
            raise ValueError("native generated font resource category differs")
        for font_ref in fonts.values():
            font = reader.get_object(font_ref)
            cmap = reader.get_object(font.raw_get("/ToUnicode"))
            decoded_total += _bounded_zlib_completion(cmap)
            stream_count += 1
            if decoded_total > MAX_TOTAL_DECODED_BYTES:
                raise ValueError("total decoded ToUnicode bytes exceed budget")

    if (stream_count != predecessor["tounicode_stream_count"]
            or not 1 <= stream_count <= 32 * expected_pages
            or reader.xref != {0: direct}
            or reader.xref_objStm != compressed
            or reader.xref_free_entry != {}):
        raise ValueError("native ToUnicode zlib identity or count differs")
    return {
        "tounicode_stream_count": stream_count,
        "tounicode_completed_stream_count": stream_count,
        "tounicode_zlib_complete": True,
        "tounicode_zlib_adler32_verified": True,
    }


def _inspect(pdf: bytes, identity: dict) -> dict:
    """Repeat the exact header admission then check bounded zlib completion."""
    try:
        _identity(identity)
        if (type(pdf) is not bytes or not pdf.startswith(b"%PDF-1.7")
                or not 0 < len(pdf) <= MAX_PDF_BYTES
                or sha256(pdf).hexdigest() != identity["pdf_sha256"]
                or version("pypdf") != PARSER_VERSION):
            raise ValueError("ToUnicode zlib source or parser differs")
        prior = previous._inspect(pdf, identity)
        if prior["status"] != previous.STATUS:
            raise ValueError("ToUnicode zlib missing parent header admission")
        from pypdf import PdfReader
        reader = PdfReader(BytesIO(pdf), strict=True)
        if reader.is_encrypted or len(reader.pages) != identity["page_count"]:
            raise ValueError("native ToUnicode zlib page count differs")
        return {
            "status": STATUS,
            **_verify_tounicode_zlib(
                reader, expected_pages=identity["page_count"],
                direct_count=len(reader.xref[0]),
                compressed_count=len(reader.xref_objStm),
            ),
        }
    except Exception:
        raise ValueError("native_tounicode_zlib_invalid") from None


def main(argv: list[str] | None = None) -> int:
    """Execute inside inherited Linux sandbox with owned anonymous FDs."""
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
