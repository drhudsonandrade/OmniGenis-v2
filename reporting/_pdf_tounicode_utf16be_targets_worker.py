"""Confined native ToUnicode bfchar UTF-16BE target code-unit shape probe.

Validates the limited generated CMap dialect only after the strict framing
ancestor. Counts UTF-16BE scalar-shaped sequences; does not establish Unicode
mapping correctness, glyph meaning, accessibility, PDF/UA or release authority.
Decoded CMap bytes and target values never leave the Linux sandbox.
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

from reporting import _pdf_tounicode_cmap_frame_worker as previous
from reporting._pdf_object_graph_worker import (
    MAX_PDF_BYTES, PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES,
    _lifetime, _limits, _read_request,
)
from reporting._pdf_trailer_catalog_worker import _reference_id
from reporting._pdf_process_sandbox import (
    enforce_pdf_landlock, enforce_pdf_network_filter,
)
from reporting._pdf_render_worker import _write_bytes

PROFILE_ID = "generated-pdf-tounicode-utf16be-targets-v1"
POLICY_ID = "generated-native-tounicode-utf16be-scalar-shape-v1"
STATUS = "TOUNICODE_UTF16BE_TARGETS_ADMITTED"
LANGUAGE = previous.LANGUAGE
MAX_DOCUMENT_PAGES = previous.MAX_DOCUMENT_PAGES
MAX_DECODED_CMAP_BYTES = previous.MAX_DECODED_CMAP_BYTES
MAX_TOTAL_DECODED_BYTES = previous.MAX_TOTAL_DECODED_BYTES
MAX_BFCHAR_BLOCKS = previous.MAX_BFCHAR_BLOCKS
MAX_BFCHAR_RECORDS = previous.MAX_BFCHAR_RECORDS
MAX_BFCHAR_PER_BLOCK = previous.MAX_BFCHAR_PER_BLOCK
MAX_UTF16BE_UNITS = MAX_BFCHAR_RECORDS * 16


def _identity(value: dict) -> None:
    """Preserve exact plan, PDF and IR digest identity through the ancestor."""
    previous._identity(value)


def _identity_from_plan(plan: object) -> dict:
    """Preserve validated immutable plan identity."""
    return previous._identity_from_plan(plan)


def _native_utf16be_targets(stream: object) -> tuple[int, int, int, int]:
    """Check UTF-16BE code-unit shape without decoding/releasing text."""
    try:
        _, expected_rows = previous._native_bfchar_frame(stream)
        decompressor = zlib.decompressobj(wbits=zlib.MAX_WBITS)
        decoded = decompressor.decompress(
            stream._data, MAX_DECODED_CMAP_BYTES + 1,
        )
        if (not 1 <= len(decoded) <= MAX_DECODED_CMAP_BYTES
                or not decompressor.eof or decompressor.unused_data
                or decompressor.unconsumed_tail):
            raise ValueError("native CMap zlib completion changed")
        body = decoded[
            len(previous._NATIVE_PREFIX):-len(previous._NATIVE_SUFFIX)
        ]
        targets = 0
        units_total = 0
        scalars_total = 0
        pairs_total = 0
        for row in body.split(b"\n"):
            if previous._BFCHAR_ROW.fullmatch(row) is None:
                continue
            _, raw_target = row.split(b" ", 1)
            binary = bytes.fromhex(raw_target[1:-1].decode("ascii"))
            if not 2 <= len(binary) <= 32 or len(binary) % 2:
                raise ValueError("unsupported UTF-16BE target width")
            units = [
                int.from_bytes(binary[i:i + 2], "big")
                for i in range(0, len(binary), 2)
            ]
            i = 0
            scalars = 0
            pairs = 0
            while i < len(units):
                unit = units[i]
                if 0xD800 <= unit <= 0xDBFF:
                    if (i + 1 >= len(units)
                            or not 0xDC00 <= units[i + 1] <= 0xDFFF):
                        raise ValueError("unpaired high UTF-16 surrogate")
                    pairs += 1
                    i += 2
                elif 0xDC00 <= unit <= 0xDFFF:
                    raise ValueError("unpaired low UTF-16 surrogate")
                else:
                    i += 1
                scalars += 1
            targets += 1
            units_total += len(units)
            scalars_total += scalars
            pairs_total += pairs
            if units_total > MAX_UTF16BE_UNITS:
                raise ValueError("UTF-16BE code-unit budget exceeded")
        if (targets != expected_rows
                or not targets <= scalars_total <= units_total
                or units_total - scalars_total != pairs_total):
            raise ValueError("native UTF-16BE target row accounting changed")
        return targets, units_total, scalars_total, pairs_total
    except Exception:
        raise ValueError("native_tounicode_utf16be_target_shape_invalid") from None


def _verify_utf16be_targets(reader: object, *, expected_pages: int) -> dict:
    """Repeat exact parent framing and admit only scalar-shaped target hex."""
    from pypdf.generic import DictionaryObject

    direct = dict(reader.xref[0])
    compressed = dict(reader.xref_objStm)
    ancestor = previous._verify_tounicode_cmap_frame(
        reader, expected_pages=expected_pages,
        direct_count=len(direct), compressed_count=len(compressed),
    )
    indexed = set(direct) | set(compressed)
    resources_seen: set[int] = set()
    streams = 0
    targets = 0
    units = 0
    scalars = 0
    pairs = 0
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
            a, b, c, e = _native_utf16be_targets(cmap)
            targets += a
            units += b
            scalars += c
            pairs += e
            streams += 1
            if (streams > 32 * expected_pages
                    or targets > MAX_BFCHAR_RECORDS
                    or units > MAX_UTF16BE_UNITS):
                raise ValueError("aggregate native UTF-16BE budget exceeded")
    if (not streams
            or streams != ancestor["tounicode_stream_count"]
            or streams != ancestor["cmap_framed_stream_count"]
            or targets != ancestor["cmap_bfchar_record_count"]
            or not targets <= scalars <= units
            or units - scalars != pairs
            or reader.xref != {0: direct}
            or reader.xref_objStm != compressed
            or reader.xref_free_entry != {}):
        raise ValueError("native UTF-16BE ancestor or count differs")
    return {
        "tounicode_stream_count": streams,
        "cmap_framed_stream_count": streams,
        "utf16be_target_count": targets,
        "utf16be_code_unit_count": units,
        "utf16be_scalar_count": scalars,
        "utf16be_surrogate_pair_count": pairs,
        "cmap_utf16be_scalar_shape_valid": True,
    }


def _inspect(pdf: bytes, identity: dict) -> dict:
    """Repeat all prior guards and the closed UTF-16BE shape check."""
    try:
        _identity(identity)
        if (type(pdf) is not bytes or not pdf.startswith(b"%PDF-1.7")
                or not 0 < len(pdf) <= MAX_PDF_BYTES
                or sha256(pdf).hexdigest() != identity["pdf_sha256"]
                or version("pypdf") != PARSER_VERSION):
            raise ValueError("native UTF-16BE source or parser differs")
        prior = previous._inspect(pdf, identity)
        if prior["status"] != previous.STATUS:
            raise ValueError("native CMap framing ancestor not admitted")
        from pypdf import PdfReader
        reader = PdfReader(BytesIO(pdf), strict=True)
        if reader.is_encrypted or len(reader.pages) != identity["page_count"]:
            raise ValueError("native UTF-16BE page identity differs")
        return {
            "status": STATUS,
            **_verify_utf16be_targets(
                reader, expected_pages=identity["page_count"],
            ),
        }
    except Exception:
        raise ValueError("native_tounicode_utf16be_target_shape_invalid") from None


def main(argv: list[str] | None = None) -> int:
    """Run only inside the existing anonymous-FD Linux sandbox."""
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
