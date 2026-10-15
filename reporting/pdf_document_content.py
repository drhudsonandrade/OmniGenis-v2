"""Optional exact whole-document text equality against current semantic-section IR.

The source projection and CR/LF/form-feed normalization are reused unchanged.
Candidate parsing occurs only in the guarded child. Equality of extracted text
does not establish glyph visibility, scientific meaning, accessibility, finding
completeness or release authority. Default validation and job routes are untouched.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

from reporting.pdf_content import _expected_content
from reporting.page_windows import PageWindowPlan
from reporting.pdf_text_windows import PROFILE_ID as TEXT_PROFILE
from reporting.pdf_object_graph import _canonical, _start, _unique_pairs, _wait
from reporting._pdf_document_content_worker import (
    CPU_SECONDS, IDENTITY_FIELDS, LANGUAGE, MAX_DECODED_BYTES, MAX_DOCUMENT_PAGES,
    MAX_PDF_BYTES, MAX_TEXT_CHARS, MEMORY_BYTES, OPEN_FILES, PARSER_VERSION,
    POLICY_ID, PROFILE_ID, PROTOCOL_VERSION, RESULT_BYTES, STATUS, _identity, _is_digest,
)

_LIMITS = {'memory_bytes': MEMORY_BYTES, 'cpu_seconds': CPU_SECONDS,
           'file_bytes': RESULT_BYTES, 'open_files': OPEN_FILES}
_DISABLE = 'OMNIGENIS_PDF_DOCUMENT_CONTENT_DISABLED'


class PdfDocumentContentError(ValueError):
    """Fixed content-free rejection; no failure returns partial equality evidence."""


def _counts(record: dict, pages: int) -> None:
    """Require native bounded counts and an exact complete physical-page count."""
    if (any(type(record[k]) is not int for k in
            ('inspected_pages', 'decoded_bytes', 'text_chars', 'text_bytes'))
            or record['inspected_pages'] != pages
            or not 0 < record['decoded_bytes'] <= MAX_DECODED_BYTES
            or not pages <= record['text_chars'] <= MAX_TEXT_CHARS
            or not pages <= record['text_bytes'] <= 4 * record['text_chars']):
        raise ValueError('document text counts invalid')


@dataclass(frozen=True, slots=True, repr=False)
class PdfDocumentContentInspection:
    """Sealed unsigned text-only equality record, never an authenticated release permit."""

    pdf_sha256: str
    ir_sha256: str
    plan_sha256: str
    page_count: int
    expected_text_sha256: str
    extracted_text_sha256: str
    inspected_pages: int
    decoded_bytes: int
    text_chars: int
    text_bytes: int
    _sealed_sha256: str = field(init=False, repr=False, compare=False)

    def _record(self) -> dict:
        """Validate every native field and expose only identities, counts and exact nonclaims."""
        identity = {k: getattr(self, k) for k in IDENTITY_FIELDS}
        _identity(identity)
        if (not _is_digest(self.expected_text_sha256)
                or not _is_digest(self.extracted_text_sha256)
                or self.expected_text_sha256 != self.extracted_text_sha256):
            raise ValueError('document content equality not established')
        counts = {k: getattr(self, k) for k in
                  ('inspected_pages', 'decoded_bytes', 'text_chars', 'text_bytes')}
        _counts(counts, self.page_count)
        return {'schema_version': '1.0.0', 'profile_id': PROFILE_ID,
                'policy_id': POLICY_ID, 'status': 'DOCUMENT_SOURCE_TEXT_MATCHED',
                **identity, **counts, 'parser_version': PARSER_VERSION, 'language': LANGUAGE,
                'expected_text_sha256': self.expected_text_sha256,
                'extracted_text_sha256': self.extracted_text_sha256,
                'conformance_scope': 'CURRENT_SEMANTIC_SECTION_IR_NORMALIZED_TEXT_ONLY',
                'normalization': 'IGNORE_CR_LF_FORM_FEED_ONLY',
                'normalized_text_equivalence_verified': True,
                'scientific_equivalence_verified': False, 'visible_glyphs_verified': False,
                'full_accessibility_qualified': False, 'finding_completeness_verified': False,
                'worker_results_authenticated': False, 'all_file_revisions_inspected': False,
                'aggregate_job_resources_qualified': False, 'release_authorized': False,
                'release_authorization': 'NOT_ESTABLISHED'}

    def __post_init__(self) -> None:
        """Seal direct construction; reject contradictory evidence or in-place resealing."""
        try:
            encoded = _canonical(self._record())
            if len(encoded) > RESULT_BYTES:
                raise ValueError('content receipt budget')
            digest = sha256(encoded).hexdigest()
            if hasattr(self, '_sealed_sha256') and self._sealed_sha256 != digest:
                raise ValueError('content receipt mutated')
            object.__setattr__(self, '_sealed_sha256', digest)
        except Exception:
            raise PdfDocumentContentError('pdf_document_content_receipt_invalid') from None

    def to_bytes(self) -> bytes:
        """Revalidate retained fields and return only the originally sealed record."""
        try:
            data = _canonical(self._record())
            if len(data) > RESULT_BYTES or sha256(data).hexdigest() != self._sealed_sha256:
                raise ValueError('content receipt mutated')
            return data
        except Exception:
            raise PdfDocumentContentError('pdf_document_content_receipt_invalid') from None

    def to_dict(self) -> dict:
        """Return detached content-free metadata, not raw source or extracted text."""
        return json.loads(self.to_bytes())

    @property
    def inspection_sha256(self) -> str:
        """Hash the sealed revalidated record without claiming worker authentication."""
        return sha256(self.to_bytes()).hexdigest()


def _decode(data: bytes, expected: dict) -> dict:
    """Reject ambiguous JSON, foreign profiles, mismatched identities and invalid counts."""
    try:
        _identity(expected)
        if type(data) is not bytes or not 0 < len(data) <= RESULT_BYTES:
            raise ValueError('content protocol size')
        record = json.loads(data.decode('ascii'), object_pairs_hook=_unique_pairs)
        if (type(record) is not dict or set(record) != {'protocol_version', 'profile_id',
                'policy_id', 'parser_version', 'identity', 'limits', 'inspection'}
                or type(record['protocol_version']) is not int
                or record['protocol_version'] != PROTOCOL_VERSION
                or record['profile_id'] != PROFILE_ID or record['policy_id'] != POLICY_ID
                or record['parser_version'] != PARSER_VERSION):
            raise ValueError('content protocol shape or profile')
        _identity(record['identity'])
        if record['identity'] != expected:
            raise ValueError('content protocol document identity')
        limits = record['limits']
        if (type(limits) is not dict or set(limits) != set(_LIMITS)
                or any(type(v) is not int or v != _LIMITS[k] for k, v in limits.items())):
            raise ValueError('content worker limits')
        found = record['inspection']
        if (type(found) is not dict or set(found) != {'status', 'text_sha256',
                'inspected_pages', 'decoded_bytes', 'text_chars', 'text_bytes'}
                or found['status'] != STATUS or not _is_digest(found['text_sha256'])):
            raise ValueError('content protocol result')
        _counts(found, expected['page_count'])
        return found
    except Exception:
        raise PdfDocumentContentError('pdf_document_content_protocol_invalid') from None


def _run_worker(pdf: bytes, identity: dict) -> bytes:
    """Use the unchanged reviewed launcher with two distinct anonymous owned files."""
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as result:
        fds = source.fileno(), result.fileno()
        infos = [os.fstat(fd) for fd in fds]
        if (any(not stat.S_ISREG(s.st_mode) or s.st_nlink != 0 or s.st_uid != os.geteuid()
                for s in infos)
                or (infos[0].st_dev, infos[0].st_ino) == (infos[1].st_dev, infos[1].st_ino)):
            raise ValueError('content protocol files not distinct anonymous owned regular files')
        header = ' '.join([str(PROTOCOL_VERSION), *(str(identity[k]) for k in IDENTITY_FIELDS)])
        source.write(header.encode('ascii') + b'\n'); source.write(pdf); source.flush()
        worker = Path(__file__).resolve().with_name('_pdf_document_content_worker.py')
        process = _start([sys.executable, '-I', str(worker), str(fds[0]), str(fds[1]),
                          str(os.getpid())], fds)
        if _wait(process) != 0 or not 0 < os.fstat(result.fileno()).st_size <= RESULT_BYTES:
            raise ValueError('document content worker failed')
        result.seek(0)
        return result.read(RESULT_BYTES + 1)


def inspect_pdf_document_content(
    *, presentation_ir: object, pdf_bytes: object, plan: PageWindowPlan,
    expected_plan_sha256: str, expected_ir_sha256: str, expected_language: str,
) -> PdfDocumentContentInspection:
    """Compare every page with independently projected source, retaining all non-text gates.

    This optional 64-page class uses the existing normalized semantic-section
    contract only. It does not consume caller-provided extracted digests, change
    default routes or establish that supplied source expectations are trustworthy.
    """
    try:
        if (sys.platform != 'linux' or os.environ.get(_DISABLE) == '1'
                or type(expected_language) is not str or expected_language != LANGUAGE
                or type(presentation_ir) is not dict or presentation_ir.get('locale_id') != LANGUAGE
                or type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b'%PDF-1.7')
                or len(pdf_bytes) > MAX_PDF_BYTES or type(plan) is not PageWindowPlan
                or not _is_digest(expected_plan_sha256) or not _is_digest(expected_ir_sha256)):
            raise ValueError('document content admission invalid')
        ir_digest, expected_text = _expected_content(presentation_ir)
        plan.__post_init__()
        if (ir_digest != expected_ir_sha256 or plan.ir_sha256 != expected_ir_sha256
                or plan.plan_sha256 != expected_plan_sha256
                or plan.inspector_profile_id != TEXT_PROFILE
                or plan.pdf_sha256 != sha256(pdf_bytes).hexdigest()):
            raise ValueError('document content exact source or plan mismatch')
        identity = {k: getattr(plan, k) for k in IDENTITY_FIELDS}
        _identity(identity)
    except Exception:
        raise PdfDocumentContentError('pdf_document_content_input_invalid') from None
    try:
        found = _decode(_run_worker(pdf_bytes, identity), identity)
        if found['text_sha256'] != expected_text:
            raise ValueError('document source text mismatch')
        plan.__post_init__()
        if (plan.plan_sha256 != expected_plan_sha256
                or _expected_content(presentation_ir) != (ir_digest, expected_text)
                or os.environ.get(_DISABLE) == '1'):
            raise ValueError('source plan or activation changed during execution')
        return PdfDocumentContentInspection(**identity,
            expected_text_sha256=expected_text, extracted_text_sha256=found['text_sha256'],
            **{k: found[k] for k in ('inspected_pages', 'decoded_bytes', 'text_chars', 'text_bytes')})
    except Exception:
        raise PdfDocumentContentError('pdf_document_content_execution_failed') from None
