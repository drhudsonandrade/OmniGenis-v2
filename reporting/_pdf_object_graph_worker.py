"""Guarded effective-object inspection for sealed generated PDF documents.

Reuse the existing passive policy across the complete effective trailer graph,
not a page window. Unreachable historical objects and opaque stream payloads are
not examined. This does not qualify text, rendering, metadata, accessibility,
all file revisions, aggregate job resources or release.
"""
from __future__ import annotations

import hashlib
from importlib.metadata import version
from io import BytesIO
import json
import os
from pathlib import Path
import signal
import stat
import sys

if __name__ == "__main__":
    # Isolated startup trusts only the resolved deployment source root.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reporting import _pdf_safety_worker as safety
from reporting._pdf_process_sandbox import enforce_pdf_landlock, enforce_pdf_network_filter
from reporting._pdf_render_worker import _arm_worker_lifetime, _write_bytes

PROFILE_ID = "generated-pdf-effective-object-graph-v1"
POLICY_ID = "passive-report-pdf-v1"
PARSER_VERSION = "6.19.0"
PROTOCOL_VERSION = 1
MAX_PDF_BYTES = 8 * 1024 * 1024
MAX_DOCUMENT_PAGES = 512
MAX_VISITS = 20000
MAX_DEPTH = 64
MEMORY_BYTES = 256 * 1024 * 1024
CPU_SECONDS = 5
WALL_SECONDS = 10
OPEN_FILES = 128
RESULT_BYTES = 4096
HEADER_BYTES = 256
IDENTITY_FIELDS = ("pdf_sha256", "ir_sha256", "plan_sha256", "page_count")
STATUS = "PASSIVE_EFFECTIVE_GRAPH_INSPECTED"


def _is_digest(value: object) -> bool:
    """Accept only an exact lowercase SHA-256 value without normalization."""
    return (type(value) is str and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _validate_identity(identity: object) -> None:
    """Validate the closed independently declared document identity and page budget."""
    if type(identity) is not dict or set(identity) != set(IDENTITY_FIELDS):
        raise ValueError("object graph identity shape")
    if any(not _is_digest(identity[k]) for k in IDENTITY_FIELDS[:3]):
        raise ValueError("object graph identity digest")
    count = identity["page_count"]
    if type(count) is not int or not 1 <= count <= MAX_DOCUMENT_PAGES:
        raise ValueError("object graph identity page count")


def _limits() -> dict[str, int]:
    """Apply finite per-process limits before importing or invoking the PDF parser."""
    import resource
    for key, value in ((resource.RLIMIT_AS, MEMORY_BYTES), (resource.RLIMIT_CPU, CPU_SECONDS),
                       (resource.RLIMIT_FSIZE, RESULT_BYTES), (resource.RLIMIT_NOFILE, OPEN_FILES),
                       (resource.RLIMIT_CORE, 0)):
        resource.setrlimit(key, (value, value))
    return {"memory_bytes": resource.getrlimit(resource.RLIMIT_AS)[0],
            "cpu_seconds": resource.getrlimit(resource.RLIMIT_CPU)[0],
            "file_bytes": resource.getrlimit(resource.RLIMIT_FSIZE)[0],
            "open_files": resource.getrlimit(resource.RLIMIT_NOFILE)[0]}


def _lifetime(parent: int) -> None:
    """Bind the worker to its launching parent and the independent fixed timer."""
    _arm_worker_lifetime(parent)
    signal.setitimer(signal.ITIMER_REAL, WALL_SECONDS)


def _read_request(fd: int) -> tuple[dict, bytes]:
    """Read one bounded anonymous request with exact ASCII identity and PDF bytes."""
    before = os.fstat(fd)
    if not 0 < before.st_size <= MAX_PDF_BYTES + HEADER_BYTES:
        raise ValueError("object graph request budget")
    with os.fdopen(os.dup(fd), "rb") as source:
        source.seek(0)
        header = source.readline(HEADER_BYTES + 1)
        pdf = source.read(MAX_PDF_BYTES + 1)
    after = os.fstat(fd)
    if any(getattr(before, key) != getattr(after, key)
           for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")):
        raise ValueError("object graph request changed")
    if (not header.endswith(b"\n") or len(header) > HEADER_BYTES
            or len(header) + len(pdf) != before.st_size
            or not pdf.startswith(b"%PDF-1.7") or len(pdf) > MAX_PDF_BYTES):
        raise ValueError("object graph request shape")
    fields = header[:-1].decode("ascii").split(" ")
    if len(fields) != 5 or fields[0] != str(PROTOCOL_VERSION):
        raise ValueError("object graph request version")
    identity = dict(zip(IDENTITY_FIELDS, fields[1:], strict=True))
    raw = identity["page_count"]
    if not raw.isascii() or not raw.isdecimal() or len(raw) > 3:
        raise ValueError("object graph request integer")
    identity["page_count"] = int(raw)
    if str(identity["page_count"]) != raw:
        raise ValueError("object graph request noncanonical count")
    _validate_identity(identity)
    if hashlib.sha256(pdf).hexdigest() != identity["pdf_sha256"]:
        raise ValueError("object graph request digest")
    return identity, pdf


def _inspect(pdf: bytes, identity: dict) -> dict:
    """Reuse the unchanged deny policy on every effective trailer-reachable reference."""
    _validate_identity(identity)
    if (version("pypdf") != PARSER_VERSION or safety.PARSER_VERSION != PARSER_VERSION
            or safety.POLICY_ID != POLICY_ID or safety.MAX_VISITS != MAX_VISITS
            or safety.MAX_DEPTH != MAX_DEPTH or safety.MAX_PDF_BYTES != MAX_PDF_BYTES):
        raise ValueError("object graph parser or policy mismatch")
    from pypdf import PdfReader
    from pypdf.generic import DictionaryObject, NameObject
    reader = PdfReader(BytesIO(pdf), strict=True)
    if reader.is_encrypted:
        raise ValueError("object graph encrypted input")
    root = reader.root_object
    if (not isinstance(root, DictionaryObject) or "/Type" not in root
            or not isinstance(root["/Type"], NameObject) or root["/Type"] != "/Catalog"
            or len(reader.pages) != identity["page_count"]):
        raise ValueError("object graph document identity mismatch")
    count, findings = safety.inspect_graph(reader.trailer)
    if findings:
        raise ValueError("object graph passive policy rejected")
    if type(count) is not int or not identity["page_count"] <= count <= MAX_VISITS:
        raise ValueError("object graph count invalid")
    return {"status": STATUS, "object_count": count}


def main(argv: list[str] | None = None) -> int:
    """Inspect one sealed generated document; failures emit no successful protocol record."""
    argv = sys.argv if argv is None else argv
    if sys.platform != "linux" or len(argv) != 4:
        return 64
    try:
        request_fd, result_fd, parent = map(int, argv[1:])
        if min(request_fd, result_fd) < 3 or request_fd == result_fd:
            return 64
        infos = [os.fstat(fd) for fd in (request_fd, result_fd)]
        if any(not stat.S_ISREG(i.st_mode) or i.st_nlink != 0 or i.st_uid != os.geteuid()
               for i in infos):
            return 64
        if ((infos[0].st_dev, infos[0].st_ino) == (infos[1].st_dev, infos[1].st_ino)
                or infos[1].st_size):
            return 64
        limits = _limits()
        _lifetime(parent)
        enforce_pdf_landlock(Path(__file__))
        enforce_pdf_network_filter()
        identity, pdf = _read_request(request_fd)
        inspection = _inspect(pdf, identity)
        record = {"protocol_version": PROTOCOL_VERSION, "profile_id": PROFILE_ID,
                  "policy_id": POLICY_ID, "parser_version": PARSER_VERSION,
                  "identity": identity, "limits": limits, "inspection": inspection}
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("ascii")
        if not 0 < len(encoded) <= RESULT_BYTES:
            return 70
        _write_bytes(result_fd, encoded)
    except Exception:  # Never return parser messages, candidate data or partial evidence.
        return 70
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
