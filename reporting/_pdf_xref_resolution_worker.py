"""Confined generated-PDF XRef parser-resolution parity on exact indexed objects.

A complete parser mapping and object resolution is not an audit of arbitrary
stream payloads, historical revisions, accessibility or report release.
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

from reporting import _pdf_xref_entries_worker as previous
from reporting._pdf_object_graph_worker import (
    MAX_PDF_BYTES, PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES,
    _lifetime, _limits, _read_request,
)
from reporting._pdf_process_sandbox import enforce_pdf_landlock, enforce_pdf_network_filter
from reporting._pdf_render_worker import _write_bytes

PROFILE_ID = "generated-pdf-xref-parser-resolution-v1"
POLICY_ID = "generated-pdf-strict-xref-parser-map-parity-v1"
STATUS = "XREF_PARSER_RESOLUTION_ADMITTED"
LANGUAGE = previous.LANGUAGE
MAX_DOCUMENT_PAGES = previous.MAX_DOCUMENT_PAGES


def _identity(value: dict) -> None:
    previous._identity(value)


def _identity_from_plan(plan: object) -> dict:
    return previous._identity_from_plan(plan)


def _verify_parser_maps(reader: object, direct: dict, compressed: dict) -> tuple[int, int]:
    """Reject parser recovery, conflicting maps or any unresolved indexed object."""
    from pypdf.generic import DictionaryObject, IndirectObject, NullObject
    if (type(direct) is not dict or type(compressed) is not dict
            or not direct or not compressed or set(direct) & set(compressed)
            or type(reader.xref) is not dict or set(reader.xref) != {0}
            or type(reader.xref[0]) is not dict or reader.xref[0] != direct
            or type(reader.xref_objStm) is not dict or reader.xref_objStm != compressed
            or reader.xref_free_entry != {}):
        raise ValueError("parser repaired or disagreed with physical XRef maps")
    direct_resolved = 0
    for number in sorted(direct):
        if (type(number) is not int or type(direct[number]) is not int
                or number <= 0 or direct[number] <= 0):
            raise ValueError("invalid native direct reference")
        value = reader.get_object(IndirectObject(number, 0, reader))
        if value is None or isinstance(value, NullObject):
            raise ValueError("indexed native direct object is not resolvable")
        direct_resolved += 1
    compressed_resolved = 0
    for number in sorted(compressed):
        owner_index = compressed[number]
        if (type(number) is not int or number <= 0
                or type(owner_index) is not tuple or len(owner_index) != 2
                or any(type(v) is not int for v in owner_index)
                or owner_index[0] not in direct or owner_index[1] < 0):
            raise ValueError("invalid compressed object owner or index")
        value = reader.get_object(IndirectObject(number, 0, reader))
        if type(value) is not DictionaryObject:
            raise ValueError("indexed generated compressed dictionary did not resolve")
        compressed_resolved += 1
    if (reader.xref != {0: direct} or reader.xref_objStm != compressed
            or reader.xref_free_entry != {}):
        raise ValueError("parser recovered additional objects while resolving")
    return direct_resolved, compressed_resolved


def _inspect(pdf: bytes, identity: dict) -> dict:
    """Compare all raw XRef pointers to the strict native parser and resolution."""
    try:
        _identity(identity)
        if (type(pdf) is not bytes or not pdf.startswith(b"%PDF-1.7")
                or not 0 < len(pdf) <= MAX_PDF_BYTES
                or sha256(pdf).hexdigest() != identity["pdf_sha256"]
                or version("pypdf") != PARSER_VERSION):
            raise ValueError("parser resolution source/profile changed")
        prior = previous._inspect(pdf, identity)
        if prior["status"] != previous.STATUS:
            raise ValueError("native physical XRef proof missing")
        from pypdf import PdfReader
        from pypdf.generic import ArrayObject, IndirectObject, NumberObject, StreamObject

        reader = PdfReader(BytesIO(pdf), strict=True)
        if reader.is_encrypted or len(reader.pages) != identity["page_count"]:
            raise ValueError("parser rejected document identity")
        xref = reader.get_object(IndirectObject(
            prior["xref_entry_count"] - 1, 0, reader,
        ))
        if not isinstance(xref, StreamObject) or xref.get("/Type") != "/XRef":
            raise ValueError("generated XRef stream not resolvable")
        size, widths = xref.get("/Size"), xref.get("/W")
        if (type(size) is not NumberObject or int(size) != prior["xref_entry_count"]
                or type(widths) is not ArrayObject or len(widths) != 3
                or any(type(n) is not NumberObject for n in widths)):
            raise ValueError("native XRef widths changed")
        values = tuple(int(n) for n in widths)
        width = sum(values)
        raw = xref.get_data()
        if (width < 3 or width > previous.MAX_ENTRY_WIDTH
                or len(raw) != width * int(size)):
            raise ValueError("XRef native record boundary changed")
        direct, compressed = {}, {}
        for number in range(int(size)):
            segment = raw[number * width:(number + 1) * width]
            cursor = 0
            fields = []
            for length in values:
                fields.append(int.from_bytes(segment[cursor:cursor + length], "big"))
                cursor += length
            kind, target, index = fields
            if kind == 1:
                direct[number] = target
            elif kind == 2:
                compressed[number] = (target, index)
            elif kind != 0 or number != 0:
                raise ValueError("unrecognized XRef entry")
        if (len(direct) != prior["direct_entry_count"]
                or len(compressed) != prior["compressed_entry_count"]
                or 1 + len(direct) + len(compressed) != int(size)):
            raise ValueError("parser XRef counts mismatch native predecessor")
        direct_resolved, compressed_resolved = _verify_parser_maps(
            reader, direct, compressed,
        )
        return {
            "status": STATUS,
            "parser_direct_entries": len(direct),
            "parser_compressed_entries": len(compressed),
            "direct_objects_resolved": direct_resolved,
            "compressed_objects_resolved": compressed_resolved,
            "parser_xref_mapping_consistent": True,
            "all_indexed_objects_resolved": True,
        }
    except Exception:
        raise ValueError("native_xref_parser_resolution_invalid") from None


def main(argv: list[str] | None = None) -> int:
    """Accept owned unlinked source/result files in a confined, fixed child."""
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
        if (any(not stat.S_ISREG(info.st_mode) or info.st_nlink != 0
                or info.st_uid != os.geteuid() for info in infos)
                or (infos[0].st_dev, infos[0].st_ino)
                   == (infos[1].st_dev, infos[1].st_ino)
                or infos[1].st_size):
            return 64
        limits = _limits()
        _lifetime(parent)
        enforce_pdf_landlock(Path(__file__))
        enforce_pdf_network_filter()
        identity, pdf = _read_request(source)
        result = {
            "protocol_version": PROTOCOL_VERSION, "profile_id": PROFILE_ID,
            "policy_id": POLICY_ID, "parser_version": PARSER_VERSION,
            "identity": identity, "limits": limits,
            "inspection": _inspect(pdf, identity),
        }
        raw = json.dumps(
            result, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("ascii")
        if not 0 < len(raw) <= RESULT_BYTES:
            return 70
        _write_bytes(output, raw)
    except Exception:
        return 70
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
