"""Inspect controlled document metadata and catalog-level tag prerequisites.

Only the current Info, catalog language and document XMP policy plus the existing
catalog accessibility prerequisites are applied. No page-local metadata, tag
semantics, full accessibility, text equivalence or release is qualified here.
Existing document byte, XMP and process limits remain unchanged.
"""
from __future__ import annotations

import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import stat
import sys

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reporting._pdf_object_graph_worker import (
    CPU_SECONDS, IDENTITY_FIELDS, MAX_DOCUMENT_PAGES, MAX_PDF_BYTES, MEMORY_BYTES,
    OPEN_FILES, PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES, WALL_SECONDS,
    _is_digest, _lifetime, _limits, _read_request, _validate_identity,
)
from reporting._pdf_process_sandbox import enforce_pdf_landlock, enforce_pdf_network_filter
from reporting._pdf_render_worker import _write_bytes

PROFILE_ID = "generated-pdf-document-metadata-v1"
METADATA_PROFILE_ID = "omnigenis-generated-pdf-metadata-v1"
LANGUAGE = "en-US"
STATUS = "DOCUMENT_METADATA_INSPECTED"


def _inspect(pdf: bytes, identity: dict) -> dict:
    """Reuse both unchanged validators and return only fixed successful prerequisite flags."""
    _validate_identity(identity)
    if (type(pdf) is not bytes or not pdf.startswith(b"%PDF-1.7")
            or len(pdf) > MAX_PDF_BYTES or hashlib.sha256(pdf).hexdigest() != identity["pdf_sha256"]
            or version("pypdf") != PARSER_VERSION):
        raise ValueError("document metadata candidate invalid")
    from reporting.pdf_qa import (
        GENERATED_PDF_AUTHOR, GENERATED_PDF_METADATA_PROFILE, validate_pdf_candidate,
    )
    from reporting.pdf_accessibility import validate_pdf_accessibility_structure
    if GENERATED_PDF_METADATA_PROFILE != METADATA_PROFILE_ID:
        raise ValueError("document metadata policy mismatch")
    metadata = validate_pdf_candidate(
        pdf_bytes=pdf, expected_pdf_sha256=identity["pdf_sha256"],
        expected_author=GENERATED_PDF_AUTHOR, expected_language=LANGUAGE,
        metadata_profile=METADATA_PROFILE_ID,
    )
    if (not metadata.passed or metadata.pdf_sha256 != identity["pdf_sha256"]
            or type(metadata.page_count) is not int or metadata.page_count != identity["page_count"]
            or metadata.metadata_profile_id != METADATA_PROFILE_ID):
        raise ValueError("document metadata rejected")
    accessibility = validate_pdf_accessibility_structure(pdf_bytes=pdf, expected_language=LANGUAGE)
    if (not accessibility.passed or accessibility.language != LANGUAGE
            or accessibility.marked is not True or accessibility.struct_tree_root is not True):
        raise ValueError("document catalog prerequisites rejected")
    return {"status": STATUS, "metadata_profile_id": METADATA_PROFILE_ID,
            "language": LANGUAGE, "marked": True, "struct_tree_root": True}


def main(argv: list[str] | None = None) -> int:
    """Guard one exact anonymous request; any failure emits no successful inspection record."""
    argv = sys.argv if argv is None else argv
    if (sys.platform != "linux" or type(argv) is not list or len(argv) != 4
            or any(type(v) is not str for v in argv)):
        return 64
    try:
        if any(not s.isascii() or not s.isdecimal() or len(s) > 10 for s in argv[1:]):
            return 64
        request_fd, result_fd, parent = map(int, argv[1:])
        if (any(str(n) != s for n, s in zip((request_fd, result_fd, parent), argv[1:], strict=True))
                or min(request_fd, result_fd) < 3 or request_fd == result_fd
                or not 2 <= parent <= 2147483647):
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
                  "parser_version": PARSER_VERSION, "identity": identity,
                  "limits": limits, "inspection": inspection}
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("ascii")
        if not 0 < len(encoded) <= RESULT_BYTES:
            return 70
        _write_bytes(result_fd, encoded)
    except Exception:
        return 70
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
