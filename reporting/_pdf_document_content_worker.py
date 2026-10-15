"""Guarded whole-document text hashing for one optional 64-page generated profile.

Reuse only the existing physical-break normalization. Every physical page must
contain extractable text; this is not visual, semantic, accessibility or release
qualification. No text or parser message is returned across the worker boundary.
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

if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reporting._pdf_content_worker import normalize_stream
from reporting._pdf_object_graph_worker import (
    CPU_SECONDS, IDENTITY_FIELDS, MAX_PDF_BYTES, MEMORY_BYTES, OPEN_FILES,
    PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES, WALL_SECONDS,
    _is_digest, _limits, _lifetime, _read_request, _validate_identity,
)
from reporting._pdf_process_sandbox import enforce_pdf_landlock, enforce_pdf_network_filter
from reporting._pdf_render_worker import _write_bytes

PROFILE_ID = 'generated-pdf-document-content-v1'
POLICY_ID = 'semantic-section-normalized-whole-text-v1'
STATUS = 'DOCUMENT_TEXT_DIGEST_INSPECTED'
MAX_DOCUMENT_PAGES = 64
MAX_DECODED_BYTES = 8 * 1024 * 1024
MAX_TEXT_CHARS = 1024 * 1024
LANGUAGE = 'en-US'


def _identity(identity: object) -> None:
    """Apply the existing exact identity grammar under a narrower 64-page class."""
    _validate_identity(identity)
    if identity['page_count'] > MAX_DOCUMENT_PAGES:
        raise ValueError('document content page budget')


def _inspect(pdf: bytes, identity: dict) -> dict:
    """Hash normalized extracted text from every page in order, within finite budgets."""
    _identity(identity)
    if (type(pdf) is not bytes or not pdf.startswith(b'%PDF-1.7')
            or len(pdf) > MAX_PDF_BYTES or sha256(pdf).hexdigest() != identity['pdf_sha256']
            or version('pypdf') != PARSER_VERSION):
        raise ValueError('document content input or parser identity')
    from pypdf import PdfReader
    reader = PdfReader(BytesIO(pdf), strict=True)
    if reader.is_encrypted or len(reader.pages) != identity['page_count']:
        raise ValueError('document content physical count or encryption')
    decoded_bytes = text_chars = text_bytes = 0
    hashed = sha256()
    for page in reader.pages:
        content = page.get_contents()
        if content is None:
            raise ValueError('document content missing stream')
        decoded = content.get_data()
        if type(decoded) is not bytes:
            raise ValueError('document content stream type')
        decoded_bytes += len(decoded)
        if decoded_bytes > MAX_DECODED_BYTES:
            raise ValueError('document content decoded budget')
        text = page.extract_text()
        if type(text) is not str or not text.strip():
            raise ValueError('document content empty page text')
        text_chars += len(text)
        if text_chars > MAX_TEXT_CHARS:
            raise ValueError('document content text budget')
        encoded = normalize_stream(text).encode('utf-8')
        text_bytes += len(encoded)
        if not encoded or text_bytes > 4 * MAX_TEXT_CHARS:
            raise ValueError('document content normalized byte budget')
        hashed.update(encoded)
    return {'status': STATUS, 'text_sha256': hashed.hexdigest(),
            'inspected_pages': identity['page_count'], 'decoded_bytes': decoded_bytes,
            'text_chars': text_chars, 'text_bytes': text_bytes}


def main(argv: list[str] | None = None) -> int:
    """Apply descriptor, lifetime and kernel guards before reading candidate bytes."""
    argv = sys.argv if argv is None else argv
    if (sys.platform != 'linux' or type(argv) is not list or len(argv) != 4
            or any(type(v) is not str or not v.isascii() or not v.isdecimal()
                   or len(v) > 10 for v in argv[1:])):
        return 64
    try:
        first, second, parent = map(int, argv[1:])
        if (any(str(n) != v for n, v in zip((first, second, parent), argv[1:], strict=True))
                or min(first, second) < 3 or first == second or not 2 <= parent <= 2147483647):
            return 64
        infos = [os.fstat(fd) for fd in (first, second)]
        if (any(not stat.S_ISREG(s.st_mode) or s.st_nlink != 0 or s.st_uid != os.geteuid()
                for s in infos)
                or (infos[0].st_dev, infos[0].st_ino) == (infos[1].st_dev, infos[1].st_ino)
                or infos[1].st_size):
            return 64
        limits = _limits()
        _lifetime(parent)
        enforce_pdf_landlock(Path(__file__))
        enforce_pdf_network_filter()
        identity, pdf = _read_request(first)
        inspection = _inspect(pdf, identity)
        record = {'protocol_version': PROTOCOL_VERSION, 'profile_id': PROFILE_ID,
                  'policy_id': POLICY_ID, 'parser_version': PARSER_VERSION,
                  'identity': identity, 'limits': limits, 'inspection': inspection}
        encoded = json.dumps(record, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=True, allow_nan=False).encode('ascii')
        if not 0 < len(encoded) <= RESULT_BYTES:
            return 70
        _write_bytes(second, encoded)
    except Exception:
        return 70
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
