"""Confined physical-page text partitions for an explicit technical composition.

No extracted text leaves this worker. The receipt concerns normalized text and
physical pages, not visual glyph positions, scientific meaning or authorization.
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

from reporting._pdf_document_content_worker import (
    CPU_SECONDS, IDENTITY_FIELDS, MAX_DECODED_BYTES, MAX_DOCUMENT_PAGES,
    MAX_PDF_BYTES, MAX_TEXT_CHARS, MEMORY_BYTES, OPEN_FILES, PARSER_VERSION,
    PROTOCOL_VERSION, RESULT_BYTES, WALL_SECONDS, _identity, _limits, _lifetime,
    _read_request, normalize_stream,
)
from reporting._pdf_process_sandbox import enforce_pdf_landlock, enforce_pdf_network_filter
from reporting._pdf_render_worker import _write_bytes

PROFILE_ID = 'final-document-page-locations-v1'
POLICY_ID = 'semantic-section-physical-page-partition-v1'
STATUS = 'FINAL_DOCUMENT_PAGE_PARTITION_INSPECTED'


def _inspect(pdf: bytes, identity: dict) -> dict:
    """Measure every physical page with the existing parser, normalization and caps."""
    _identity(identity)
    if (type(pdf) is not bytes or not pdf.startswith(b'%PDF-1.7')
            or len(pdf) > MAX_PDF_BYTES or sha256(pdf).hexdigest() != identity['pdf_sha256']
            or version('pypdf') != PARSER_VERSION):
        raise ValueError('final location input invalid')
    from pypdf import PdfReader
    reader = PdfReader(BytesIO(pdf), strict=True)
    if reader.is_encrypted or len(reader.pages) != identity['page_count']:
        raise ValueError('final location physical pages invalid')
    decoded_bytes = text_chars = text_bytes = 0
    whole = sha256(); partition = sha256(); lengths = []
    for number, page in enumerate(reader.pages, 1):
        content = page.get_contents()
        if content is None:
            raise ValueError('final location missing stream')
        decoded = content.get_data()
        if type(decoded) is not bytes:
            raise ValueError('final location stream invalid')
        decoded_bytes += len(decoded)
        if decoded_bytes > MAX_DECODED_BYTES:
            raise ValueError('final location decoded limit')
        text = page.extract_text()
        if type(text) is not str or not text.strip():
            raise ValueError('final location empty page')
        text_chars += len(text)
        if text_chars > MAX_TEXT_CHARS:
            raise ValueError('final location text limit')
        encoded = normalize_stream(text).encode('utf-8')
        text_bytes += len(encoded)
        if not encoded or text_bytes > 4 * MAX_TEXT_CHARS:
            raise ValueError('final location normalized limit')
        lengths.append(len(encoded)); whole.update(encoded)
        partition.update(f'{number}:{len(encoded)}:'.encode('ascii'))
        partition.update(encoded)
    return {'status': STATUS, 'inspected_pages': identity['page_count'],
        'decoded_bytes': decoded_bytes, 'text_chars': text_chars, 'text_bytes': text_bytes,
        'text_sha256': whole.hexdigest(), 'page_byte_lengths': lengths,
        'page_partition_sha256': partition.hexdigest()}


def main(argv: list[str] | None = None) -> int:
    """Apply fixed descriptor and kernel guards before reading any candidate bytes."""
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
