"""Confined strict native bfchar CMap frame probe for generated PDFs.

Only a closed WeasyPrint-style ASCII prolog, codespace, bfchar blocks and
epilog are admitted. No Unicode, glyph, CMap execution or PDF/UA semantics
are evaluated, and decoded data never leaves the isolated worker process.
"""
from __future__ import annotations

from hashlib import sha256
from importlib.metadata import version
from io import BytesIO
import json
import os
from pathlib import Path
import re
import stat
import sys
import zlib

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reporting import _pdf_tounicode_zlib_worker as previous
from reporting._pdf_object_graph_worker import (
    MAX_PDF_BYTES, PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES,
    _lifetime, _limits, _read_request,
)
from reporting._pdf_trailer_catalog_worker import _reference_id
from reporting._pdf_process_sandbox import (
    enforce_pdf_landlock, enforce_pdf_network_filter,
)
from reporting._pdf_render_worker import _write_bytes

PROFILE_ID = "generated-pdf-tounicode-cmap-frame-v1"
POLICY_ID = "generated-native-tounicode-bfchar-frame-v1"
STATUS = "TOUNICODE_CMAP_FRAME_ADMITTED"
LANGUAGE = previous.LANGUAGE
MAX_DOCUMENT_PAGES = previous.MAX_DOCUMENT_PAGES
MAX_DECODED_CMAP_BYTES = previous.MAX_DECODED_CMAP_BYTES
MAX_TOTAL_DECODED_BYTES = previous.MAX_TOTAL_DECODED_BYTES
MAX_BFCHAR_BLOCKS = 256
MAX_BFCHAR_RECORDS = 16384
MAX_BFCHAR_PER_BLOCK = 100

_NATIVE_PREFIX = (
    b"/CIDInit /ProcSet findresource begin\n"
    b"12 dict begin\n"
    b"begincmap\n"
    b"/CIDSystemInfo\n"
    b"<< /Registry (Adobe)\n"
    b"/Ordering (UCS)\n"
    b"/Supplement 0\n"
    b">> def\n"
    b"/CMapName /Adobe-Identity-UCS def\n"
    b"/CMapType 2 def\n"
    b"1 begincodespacerange\n"
    b"<0000> <ffff>\n"
    b"endcodespacerange\n"
)
_NATIVE_SUFFIX = (
    b"endcmap\n"
    b"CMapName currentdict /CMap defineresource pop\n"
    b"end\nend"
)
_BFCHAR_ROW = re.compile(rb"<[0-9a-fA-F]{4}> <(?:[0-9a-fA-F]{4}){1,16}>")


def _identity(value: dict) -> None:
    """Validate exact sealed request identity via previous child."""
    previous._identity(value)


def _identity_from_plan(plan: object) -> dict:
    """Preserve validated immutable plan identity."""
    return previous._identity_from_plan(plan)


def _native_bfchar_frame(stream: object) -> tuple[int, int]:
    """Count native bfchar blocks and rows inside strict decoded budgets."""
    previous._bounded_zlib_completion(stream)
    try:
        decompressor = zlib.decompressobj(wbits=zlib.MAX_WBITS)
        decoded = decompressor.decompress(
            stream._data, MAX_DECODED_CMAP_BYTES + 1,
        )
        if (not 1 <= len(decoded) <= MAX_DECODED_CMAP_BYTES
                or not decompressor.eof or decompressor.unused_data
                or decompressor.unconsumed_tail
                or not decoded.startswith(_NATIVE_PREFIX)
                or not decoded.endswith(_NATIVE_SUFFIX)):
            raise ValueError("unsupported native ToUnicode bfchar framing")
        body = decoded[len(_NATIVE_PREFIX):-len(_NATIVE_SUFFIX)]
        lines = body.split(b"\n")
        if not lines or lines[-1] != b"":
            raise ValueError("native bfchar block terminator missing")
        i = 0
        blocks = 0
        records = 0
        while i < len(lines) - 1:
            marker = lines[i].split(b" ")
            if (len(marker) != 2 or marker[1] != b"beginbfchar"
                    or not marker[0].isascii()
                    or not marker[0].isdigit()):
                raise ValueError("unsupported native CMap operator")
            count = int(marker[0])
            if (not 1 <= count <= MAX_BFCHAR_PER_BLOCK
                    or str(count).encode("ascii") != marker[0]
                    or i + count + 1 >= len(lines) - 1):
                raise ValueError("invalid native bfchar block count")
            for row in lines[i + 1:i + count + 1]:
                if _BFCHAR_ROW.fullmatch(row) is None:
                    raise ValueError("invalid native bfchar row syntax")
            if lines[i + count + 1] != b"endbfchar":
                raise ValueError("native bfchar block not closed")
            blocks += 1
            records += count
            if (blocks > MAX_BFCHAR_BLOCKS
                    or records > MAX_BFCHAR_RECORDS):
                raise ValueError("native CMap record budget exceeded")
            i += count + 2
        if i != len(lines) - 1 or not blocks or not records:
            raise ValueError("native CMap framing incomplete")
        return blocks, records
    except Exception:
        raise ValueError("native_tounicode_bfchar_frame_invalid") from None


def _verify_tounicode_cmap_frame(
    reader: object, *, expected_pages: int, direct_count: int,
    compressed_count: int,
) -> dict:
    """Require native zlib ancestor and exact counted bfchar frames."""
    from pypdf.generic import DictionaryObject

    predecessor = previous._verify_tounicode_zlib(
        reader, expected_pages=expected_pages,
        direct_count=direct_count, compressed_count=compressed_count,
    )
    direct = dict(reader.xref[0])
    compressed = dict(reader.xref_objStm)
    indexed = set(direct) | set(compressed)
    resources_seen: set[int] = set()
    stream_count = 0
    block_count = 0
    record_count = 0
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
            raise ValueError("native generated font resource shape differs")
        for font_ref in fonts.values():
            font = reader.get_object(font_ref)
            cmap = reader.get_object(font.raw_get("/ToUnicode"))
            blocks, records = _native_bfchar_frame(cmap)
            block_count += blocks
            record_count += records
            stream_count += 1
            if (block_count > MAX_BFCHAR_BLOCKS
                    or record_count > MAX_BFCHAR_RECORDS):
                raise ValueError("total native bfchar budget exceeded")
    if (stream_count != predecessor["tounicode_stream_count"]
            or stream_count != predecessor["tounicode_completed_stream_count"]
            or not 1 <= stream_count <= 32 * expected_pages
            or reader.xref != {0: direct}
            or reader.xref_objStm != compressed
            or reader.xref_free_entry != {}):
        raise ValueError("native CMap ancestor identity or count differs")
    return {
        "tounicode_stream_count": stream_count,
        "cmap_framed_stream_count": stream_count,
        "cmap_bfchar_block_count": block_count,
        "cmap_bfchar_record_count": record_count,
        "cmap_native_bfchar_frame_valid": True,
    }


def _inspect(pdf: bytes, identity: dict) -> dict:
    """Repeat all ancestor checks before confined CMap ASCII framing."""
    try:
        _identity(identity)
        if (type(pdf) is not bytes or not pdf.startswith(b"%PDF-1.7")
                or not 0 < len(pdf) <= MAX_PDF_BYTES
                or sha256(pdf).hexdigest() != identity["pdf_sha256"]
                or version("pypdf") != PARSER_VERSION):
            raise ValueError("native CMap frame source or parser differs")
        prior = previous._inspect(pdf, identity)
        if prior["status"] != previous.STATUS:
            raise ValueError("native CMap frame ancestor not admitted")
        from pypdf import PdfReader
        reader = PdfReader(BytesIO(pdf), strict=True)
        if reader.is_encrypted or len(reader.pages) != identity["page_count"]:
            raise ValueError("native CMap frame page count differs")
        return {
            "status": STATUS,
            **_verify_tounicode_cmap_frame(
                reader, expected_pages=identity["page_count"],
                direct_count=len(reader.xref[0]),
                compressed_count=len(reader.xref_objStm),
            ),
        }
    except Exception:
        raise ValueError("native_tounicode_cmap_frame_invalid") from None


def main(argv: list[str] | None = None) -> int:
    """Inspect only in the inherited Linux FD and process sandbox."""
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
