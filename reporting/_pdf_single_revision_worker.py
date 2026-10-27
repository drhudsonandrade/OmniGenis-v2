"""Conservative native single-xref-stream admission for generated PDF 1.7.

Not a general PDF history parser, opaque object auditor, accessibility gate
or release mechanism. A false rejection of unsupported PDFs is intentional.
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

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reporting import _pdf_structure_role_edges_worker as edges
from reporting._pdf_object_graph_worker import (
    MAX_PDF_BYTES, PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES,
    _lifetime, _limits, _read_request,
)
from reporting._pdf_process_sandbox import (
    enforce_pdf_landlock, enforce_pdf_network_filter,
)
from reporting._pdf_render_worker import _write_bytes


PROFILE_ID = "generated-pdf-single-xref-revision-v1"
POLICY_ID = "generated-pdf-strict-single-xref-stream-v1"
STATUS = "SINGLE_XREF_REVISION_ADMITTED"
LANGUAGE = edges.LANGUAGE
MAX_DOCUMENT_PAGES = edges.MAX_DOCUMENT_PAGES
_FINAL = re.compile(rb"\nstartxref\n([1-9][0-9]{0,7})\n%%EOF\n\Z")
_XREF_OBJECT = re.compile(rb"([1-9][0-9]{0,7}) 0 obj\n")


def _identity(value: dict) -> None:
    """Require the original native four-field immutable request identity."""
    edges._identity(value)


def _identity_from_plan(plan: object) -> dict:
    return edges._identity_from_plan(plan)


def _inspect(pdf: bytes, identity: dict) -> dict:
    """Admit exactly one physically located final xref stream and EOF marker."""
    try:
        _identity(identity)
        if (type(pdf) is not bytes or not pdf.startswith(b"%PDF-1.7")
                or not 0 < len(pdf) <= MAX_PDF_BYTES
                or sha256(pdf).hexdigest() != identity["pdf_sha256"]
                or version("pypdf") != PARSER_VERSION):
            raise ValueError("single-xref source/profile invalid")
        if pdf.count(b"startxref") != 1 or pdf.count(b"%%EOF") != 1:
            raise ValueError("multiple or concealed revision markers")
        tail = _FINAL.search(pdf)
        if tail is None:
            raise ValueError("noncanonical final trailer or trailing data")
        offset = int(tail.group(1))
        if offset <= len(b"%PDF-1.7\n") or offset >= tail.start():
            raise ValueError("xref offset does not point inside original document")
        object_header = _XREF_OBJECT.match(pdf[offset:offset + 30])
        if object_header is None:
            raise ValueError("xref start does not locate an indirect stream object")
        object_number = int(object_header.group(1))
        if not 0 < object_number <= 20000:
            raise ValueError("xref object number outside bounded generated profile")

        from pypdf import PdfReader
        from pypdf.generic import (
            ArrayObject, IndirectObject, NameObject, NumberObject, StreamObject,
        )
        reader = PdfReader(BytesIO(pdf), strict=True)
        if reader.is_encrypted or len(reader.pages) != identity["page_count"]:
            raise ValueError("native page count or encryption invalid")
        xref = reader.get_object(IndirectObject(object_number, 0, reader))
        if (not isinstance(xref, StreamObject)
                or type(xref.get("/Type")) is not NameObject
                or xref.get("/Type") != "/XRef"
                or "/Prev" in xref or "/XRefStm" in xref
                or "/Prev" in reader.trailer or "/XRefStm" in reader.trailer):
            raise ValueError("final native xref is not standalone")
        size = xref.get("/Size")
        widths = xref.get("/W")
        indices = xref.get("/Index")
        if (type(size) is not NumberObject or not 1 < int(size) <= 20000
                or type(widths) is not ArrayObject or len(widths) != 3
                or any(type(w) is not NumberObject or not 0 <= int(w) <= 8
                       for w in widths)
                or type(indices) is not ArrayObject or len(indices) != 2
                or any(type(v) is not NumberObject for v in indices)
                or int(indices[0]) != 0 or int(indices[1]) != int(size)
                or "/Root" not in xref):
            raise ValueError("xref stream dictionary not in generated subset")
        return {
            "status": STATUS, "xref_offset": offset,
            "xref_object_number": object_number,
            "xref_marker_pairs": 1,
        }
    except Exception:
        raise ValueError("native_single_xref_revision_invalid") from None


def main(argv: list[str] | None = None) -> int:
    """Run only as an owned, confined fixed native child with anonymous files."""
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
        wire = json.dumps(
            record, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("ascii")
        if not 0 < len(wire) <= RESULT_BYTES:
            return 70
        _write_bytes(output, wire)
    except Exception:
        return 70
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
