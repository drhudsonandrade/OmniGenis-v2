"""Admit generated PDF XRef entry maps only when physical references agree.

This strict additive subset does not audit all opaque objects, earlier revisions,
PDF/UA, aggregate process trees or clinical/report release.
"""
from __future__ import annotations

from collections import defaultdict
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

from reporting import _pdf_single_revision_worker as previous
from reporting._pdf_object_graph_worker import (
    MAX_PDF_BYTES, PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES,
    _lifetime, _limits, _read_request,
)
from reporting._pdf_process_sandbox import (
    enforce_pdf_landlock, enforce_pdf_network_filter,
)
from reporting._pdf_render_worker import _write_bytes


PROFILE_ID = "generated-pdf-xref-entry-map-v1"
POLICY_ID = "generated-pdf-physical-xref-entry-consistency-v1"
STATUS = "XREF_ENTRY_MAP_ADMITTED"
LANGUAGE = previous.LANGUAGE
MAX_DOCUMENT_PAGES = previous.MAX_DOCUMENT_PAGES
MAX_ENTRIES = 20000
MAX_ENTRY_WIDTH = 17
MAX_DECODED_OBJECT_STREAM = MAX_PDF_BYTES


def _identity(value: dict) -> None:
    previous._identity(value)


def _identity_from_plan(plan: object) -> dict:
    return previous._identity_from_plan(plan)


def _inspect(pdf: bytes, identity: dict) -> dict:
    """Check every physical XRef entry and each generated ObjStm index."""
    try:
        _identity(identity)
        if (type(pdf) is not bytes or not 0 < len(pdf) <= MAX_PDF_BYTES
                or sha256(pdf).hexdigest() != identity["pdf_sha256"]
                or version("pypdf") != PARSER_VERSION):
            raise ValueError("wrong generated PDF identity or parser")
        admission = previous._inspect(pdf, identity)
        if admission["status"] != previous.STATUS:
            raise ValueError("prior native single revision incomplete")
        from pypdf import PdfReader
        from pypdf.generic import (
            ArrayObject, IndirectObject, NameObject, NumberObject, StreamObject,
        )

        reader = PdfReader(BytesIO(pdf), strict=True)
        if reader.is_encrypted or len(reader.pages) != identity["page_count"]:
            raise ValueError("native document page/encryption identity mismatch")
        xref_number = admission["xref_object_number"]
        xref_position = admission["xref_offset"]
        xref = reader.get_object(IndirectObject(xref_number, 0, reader))
        if not isinstance(xref, StreamObject) or xref.get("/Type") != "/XRef":
            raise ValueError("native XRef object is absent")
        if (type(xref.get("/Filter")) is not NameObject
                or xref.get("/Filter") != "/FlateDecode"):
            raise ValueError("generated XRef filter not admitted")
        size = xref.get("/Size")
        widths = xref.get("/W")
        indices = xref.get("/Index")
        if (type(size) is not NumberObject
                or not 1 < int(size) <= MAX_ENTRIES
                or type(widths) is not ArrayObject or len(widths) != 3
                or any(type(w) is not NumberObject for w in widths)
                or type(indices) is not ArrayObject or len(indices) != 2
                or any(type(i) is not NumberObject for i in indices)
                or int(indices[0]) != 0 or int(indices[1]) != int(size)):
            raise ValueError("XRef entry shape outside generated profile")
        w = tuple(int(item) for item in widths)
        width = sum(w)
        if (w[0] != 1 or not 1 <= w[1] <= 8 or not 1 <= w[2] <= 8
                or not 1 <= width <= MAX_ENTRY_WIDTH):
            raise ValueError("unsupported XRef byte widths")
        count = int(size)
        if xref_number != count - 1:
            raise ValueError("final generated XRef object ID not last entry")
        decoded = xref.get_data()
        if (type(decoded) is not bytes or len(decoded) != count * width
                or not 0 < len(decoded) <= MAX_ENTRIES * MAX_ENTRY_WIDTH):
            raise ValueError("XRef decompressed record size not exact")

        direct = {}
        compressed = defaultdict(dict)
        free = 0
        seen_physical = set()
        for obj in range(count):
            segment = memoryview(decoded)[obj * width:(obj + 1) * width]
            i = 0
            fields = []
            for n in w:
                fields.append(int.from_bytes(segment[i:i + n], "big"))
                i += n
            kind, target, auxiliary = fields
            if kind == 0:
                if (obj != 0 or target != 0 or auxiliary != 65535 or free):
                    raise ValueError("unsupported generated free entry")
                free = 1
            elif kind == 1:
                if (obj == 0 or auxiliary != 0 or target < 9
                        or target > xref_position
                        or (obj == xref_number) != (target == xref_position)
                        or target in seen_physical):
                    raise ValueError("direct object pointer or generation invalid")
                header = f"{obj} 0 obj\n".encode("ascii")
                if pdf[target:target + len(header)] != header:
                    raise ValueError("direct XRef pointer mismatches physical header")
                seen_physical.add(target)
                direct[obj] = target
            elif kind == 2:
                if (obj == 0 or obj == xref_number
                        or not 1 <= target < count or auxiliary >= MAX_ENTRIES
                        or auxiliary in compressed[target]):
                    raise ValueError("compressed entry owner/index invalid")
                compressed[target][auxiliary] = obj
            else:
                raise ValueError("unsupported XRef entry type")
        if free != 1 or len(direct) < 2 or not compressed:
            raise ValueError("incomplete generated direct/compressed XRef map")
        if direct.get(xref_number) != xref_position:
            raise ValueError("physical final startxref self-pointer changed")

        compressed_count = 0
        for owner, objects in compressed.items():
            if owner not in direct:
                raise ValueError("compressed entry owner is not physically direct")
            stream = reader.get_object(IndirectObject(owner, 0, reader))
            if (not isinstance(stream, StreamObject)
                    or stream.get("/Type") != "/ObjStm"):
                raise ValueError("compressed owner is not native /ObjStm")
            n = stream.get("/N")
            first = stream.get("/First")
            if (type(n) is not NumberObject or type(first) is not NumberObject
                    or not 1 <= int(n) <= MAX_ENTRIES
                    or int(n) != len(objects) or
                    set(objects) != set(range(int(n)))):
                raise ValueError("incomplete compressed-owner index inventory")
            content = stream.get_data()
            if (type(content) is not bytes
                    or not int(first) < len(content) <= MAX_DECODED_OBJECT_STREAM):
                raise ValueError("compressed object stream content exceeds envelope")
            header_tokens = content[:int(first)].split()
            if (len(header_tokens) != 2 * int(n)
                    or any(not token.isdigit() or len(token) > 10
                           for token in header_tokens)):
                raise ValueError("object stream index header malformed")
            previous_offset = -1
            for index in range(int(n)):
                object_number = int(header_tokens[2 * index])
                offset = int(header_tokens[2 * index + 1])
                if (objects[index] != object_number
                        or offset <= previous_offset
                        or not 0 <= offset < len(content) - int(first)):
                    raise ValueError("object stream indices differ from XRef")
                previous_offset = offset
            compressed_count += len(objects)
        return {
            "status": STATUS,
            "xref_entry_count": count,
            "free_entry_count": free,
            "direct_entry_count": len(direct),
            "compressed_entry_count": compressed_count,
            "object_stream_count": len(compressed),
            "decoded_entry_bytes": len(decoded),
            "direct_headers_verified": len(direct),
            "object_stream_indices_verified": compressed_count,
            "xref_entry_map_consistent": True,
        }
    except Exception:
        raise ValueError("native_xref_entry_map_invalid") from None


def main(argv: list[str] | None = None) -> int:
    """Confined child accepts only owned unlinked regular descriptors."""
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
        record = {
            "protocol_version": PROTOCOL_VERSION,
            "profile_id": PROFILE_ID,
            "policy_id": POLICY_ID,
            "parser_version": PARSER_VERSION,
            "identity": identity, "limits": limits,
            "inspection": _inspect(pdf, identity),
        }
        raw = json.dumps(
            record, sort_keys=True, separators=(",", ":"),
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
