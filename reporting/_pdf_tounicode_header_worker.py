"""Bounded native ToUnicode raw Flate-header inspection in an isolated worker.

Only the zlib CMF/FLG header of exact indexed generated streams is checked.
No decompression, CMap tokenization, Unicode mapping, text decoding,
reading-order, glyph or PDF/UA claim is made.
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

from reporting._pdf_document_byte_budget import LEGACY_MAX_PDF_BYTES
from reporting import _pdf_cid_widths_worker as previous
from reporting._pdf_object_graph_worker import (
    MAX_PDF_BYTES, PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES,
    _lifetime, _limits, _read_request,
)
from reporting._pdf_trailer_catalog_worker import _reference_id
from reporting._pdf_process_sandbox import (
    enforce_pdf_landlock, enforce_pdf_network_filter,
)
from reporting._pdf_render_worker import _write_bytes

PROFILE_ID = "generated-pdf-tounicode-header-v1"
POLICY_ID = "generated-native-tounicode-flate-header-v1"
STATUS = "TOUNICODE_FLATE_HEADER_ADMITTED"
LANGUAGE = previous.LANGUAGE
MAX_DOCUMENT_PAGES = previous.MAX_DOCUMENT_PAGES
MAX_RAW_CMAP_BYTES = LEGACY_MAX_PDF_BYTES


def _identity(value: dict) -> None:
    """Reuse the exact sealed CID-width source identity."""
    previous._identity(value)


def _identity_from_plan(plan: object) -> dict:
    """Extract the predecessor's strictly validated plan identity."""
    return previous._identity_from_plan(plan)


def _raw_zlib_header(stream: object) -> None:
    """Reject invalid CMF/FLG without decompressing raw CMap bytes."""
    from pypdf.generic import NameObject, StreamObject

    if (not isinstance(stream, StreamObject)
            or set(stream) != {"/Filter"}
            or type(stream.raw_get("/Filter")) is not NameObject
            or stream.raw_get("/Filter") != "/FlateDecode"
            or type(getattr(stream, "_data", None)) is not bytes
            or not 6 <= len(stream._data) <= MAX_RAW_CMAP_BYTES):
        raise ValueError("native generated ToUnicode raw stream differs")
    cmf, flg = stream._data[:2]
    if ((cmf & 0x0F) != 8 or (cmf >> 4) > 7
            or ((cmf << 8) | flg) % 31 != 0
            or (flg & 0x20) != 0):
        raise ValueError("native generated ToUnicode zlib header invalid")


def _verify_tounicode_headers(
    reader: object, *, expected_pages: int, direct_count: int,
    compressed_count: int,
) -> dict:
    """Count valid raw zlib headers after exact prior CIDFont /W proof."""
    from pypdf.generic import DictionaryObject

    predecessor = previous._verify_cid_widths(
        reader, expected_pages=expected_pages,
        direct_count=direct_count, compressed_count=compressed_count,
    )
    direct = dict(reader.xref[0])
    compressed = dict(reader.xref_objStm)
    indexed = set(direct) | set(compressed)
    resources_seen: set[int] = set()
    stream_count = 0
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
            _raw_zlib_header(cmap)
            stream_count += 1

    if (stream_count != predecessor["cid_width_font_count"]
            or not 1 <= stream_count <= 32 * expected_pages
            or reader.xref != {0: direct}
            or reader.xref_objStm != compressed
            or reader.xref_free_entry != {}):
        raise ValueError("generated ToUnicode header counts or index changed")
    return {
        "tounicode_stream_count": stream_count,
        "tounicode_checked_header_count": stream_count,
        "tounicode_headers_native": True,
    }


def _inspect(pdf: bytes, identity: dict) -> dict:
    """Admit only the pinned PDF whose CID width proof succeeded."""
    try:
        _identity(identity)
        if (type(pdf) is not bytes or not pdf.startswith(b"%PDF-1.7")
                or not 0 < len(pdf) <= MAX_PDF_BYTES
                or sha256(pdf).hexdigest() != identity["pdf_sha256"]
                or version("pypdf") != PARSER_VERSION):
            raise ValueError("ToUnicode native header source/parser differs")
        prior = previous._inspect(pdf, identity)
        if prior["status"] != previous.STATUS:
            raise ValueError("ToUnicode header missing CID /W prerequisite")
        from pypdf import PdfReader
        reader = PdfReader(BytesIO(pdf), strict=True)
        if reader.is_encrypted or len(reader.pages) != identity["page_count"]:
            raise ValueError("ToUnicode header native page count changed")
        return {
            "status": STATUS,
            **_verify_tounicode_headers(
                reader, expected_pages=identity["page_count"],
                direct_count=len(reader.xref[0]),
                compressed_count=len(reader.xref_objStm),
            ),
        }
    except Exception:
        raise ValueError("native_tounicode_header_invalid") from None


def main(argv: list[str] | None = None) -> int:
    """Run only inside the inherited Linux PDF sandbox and owned unlinked FDs."""
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
