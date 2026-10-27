"""Confined opt-in admission of generated PDF native CID /W arrays.

Only exact generated Type0/CIDFontType2 width-array structure is examined.
No embedded font is decoded, no glyph correctness is established, and no
general PDF accessibility or release claim is made.
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

from reporting import _pdf_font_descriptor_worker as previous
from reporting._pdf_object_graph_worker import (
    MAX_PDF_BYTES, PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES,
    _lifetime, _limits, _read_request,
)
from reporting._pdf_trailer_catalog_worker import _reference_id
from reporting._pdf_process_sandbox import enforce_pdf_landlock, enforce_pdf_network_filter
from reporting._pdf_render_worker import _write_bytes

PROFILE_ID = "generated-pdf-cid-widths-v1"
POLICY_ID = "generated-cid-native-width-arrays-v1"
STATUS = "CID_WIDTHS_ENVELOPE_ADMITTED"
LANGUAGE = previous.LANGUAGE
MAX_DOCUMENT_PAGES = previous.MAX_DOCUMENT_PAGES
MAX_CID_WIDTH_VALUES_PER_FONT = 4096
MAX_WIDTH_ARRAY_ENTRIES = 4096
MAX_CID = 65535
MAX_NATIVE_WIDTH = 16384


def _identity(value: dict) -> None:
    """Reuse the pinned prior worker's closed identity validation."""
    previous._identity(value)


def _identity_from_plan(plan: object) -> dict:
    """Extract the exact source identity from the admitted sealed plan."""
    return previous._identity_from_plan(plan)


def _width_array(value: object) -> tuple[int, int]:
    """Admit strictly ascending, bounded native `(CID, [widths])` runs."""
    from pypdf.generic import ArrayObject, FloatObject, NumberObject

    if (type(value) is not ArrayObject
            or not 2 <= len(value) <= MAX_WIDTH_ARRAY_ENTRIES
            or len(value) % 2):
        raise ValueError("generated CID width array shape changed")
    pair_count = 0
    value_count = 0
    last_cid = -1
    for offset in range(0, len(value), 2):
        start = value[offset]
        widths = value[offset + 1]
        if (type(start) is not NumberObject or type(widths) is not ArrayObject
                or not 1 <= len(widths) <= MAX_CID_WIDTH_VALUES_PER_FONT):
            raise ValueError("generated CID width pair type changed")
        cid = int(start)
        end = cid + len(widths) - 1
        if not last_cid < cid <= end <= MAX_CID:
            raise ValueError("generated CID width intervals overlap or exceed CID code space")
        for width in widths:
            if type(width) is NumberObject:
                if not 0 < int(width) <= MAX_NATIVE_WIDTH:
                    raise ValueError("generated CID width metric outside envelope")
            elif type(width) is FloatObject:
                scalar = float(width)
                if not math.isfinite(scalar) or not 0 < scalar <= MAX_NATIVE_WIDTH:
                    raise ValueError("generated CID width metric nonfinite or unbounded")
            else:
                raise ValueError("generated CID width metric is not native numeric")
        value_count += len(widths)
        if value_count > MAX_CID_WIDTH_VALUES_PER_FONT:
            raise ValueError("generated CID width aggregate exceeded")
        last_cid = end
        pair_count += 1
    return pair_count, value_count


def _verify_cid_widths(
    reader: object, *, expected_pages: int, direct_count: int,
    compressed_count: int,
) -> dict:
    """Chain exact native FontDescriptor proof, then count CID width arrays."""
    predecessor = previous._verify_font_descriptor(
        reader, expected_pages=expected_pages,
        direct_count=direct_count, compressed_count=compressed_count,
    )
    from pypdf.generic import DictionaryObject

    direct = dict(reader.xref[0])
    compressed = dict(reader.xref_objStm)
    indexed = set(direct) | set(compressed)
    resources_seen: set[int] = set()
    font_count = pair_count = value_count = 0
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
            raise ValueError("generated CID font category changed")
        for font_ref in fonts.values():
            font = reader.get_object(font_ref)
            cid = reader.get_object(font.raw_get("/DescendantFonts")[0])
            pairs, values = _width_array(cid.raw_get("/W"))
            font_count += 1
            pair_count += pairs
            value_count += values

    if (font_count != predecessor["font_descriptor_envelope_count"]
            or not 1 <= font_count <= 32 * expected_pages
            or not 1 <= pair_count <= 2048 * font_count
            or not 1 <= value_count <= MAX_CID_WIDTH_VALUES_PER_FONT * font_count
            or reader.xref != {0: direct}
            or reader.xref_objStm != compressed
            or reader.xref_free_entry != {}):
        raise ValueError("generated CID width counts or index changed")
    return {
        "cid_width_font_count": font_count,
        "cid_width_pair_count": pair_count,
        "cid_width_value_count": value_count,
        "cid_ranges_strictly_ascending": True,
        "cid_widths_natively_bounded": True,
    }


def _inspect(pdf: bytes, identity: dict) -> dict:
    """Bind exact source and every native font prerequisite before width proof."""
    try:
        _identity(identity)
        if (type(pdf) is not bytes or not pdf.startswith(b"%PDF-1.7")
                or not 0 < len(pdf) <= MAX_PDF_BYTES
                or sha256(pdf).hexdigest() != identity["pdf_sha256"]
                or version("pypdf") != PARSER_VERSION):
            raise ValueError("generated CID width source/parser differs")
        prior = previous._inspect(pdf, identity)
        if prior["status"] != previous.STATUS:
            raise ValueError("native FontDescriptor prerequisite missing")
        from pypdf import PdfReader
        reader = PdfReader(BytesIO(pdf), strict=True)
        if reader.is_encrypted or len(reader.pages) != identity["page_count"]:
            raise ValueError("generated native page count differs")
        return {
            "status": STATUS,
            **_verify_cid_widths(
                reader, expected_pages=identity["page_count"],
                direct_count=len(reader.xref[0]),
                compressed_count=len(reader.xref_objStm),
            ),
        }
    except Exception:
        raise ValueError("native_cid_widths_invalid") from None


def main(argv: list[str] | None = None) -> int:
    """Accept only owned, unlinked source/output FDs in fixed Linux bounds."""
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
