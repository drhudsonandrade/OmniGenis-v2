"""Optional exact forward structure-tree linkage on guarded generated PDF candidates.

The adapter returns sealed unsigned counts only. Structural ownership is not
semantic role validation, accessible reading order, complete visual coverage or
report-release authority. Existing inspectors and default routes are unchanged.
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

from reporting.page_windows import PageWindowPlan
from reporting.pdf_text_windows import PROFILE_ID as TEXT_PROFILE
from reporting.pdf_object_graph import _canonical, _start, _unique_pairs, _wait
from reporting._pdf_structure_tree_worker import (
    CPU_SECONDS, IDENTITY_FIELDS, LANGUAGE, MAX_DOCUMENT_PAGES, MAX_PDF_BYTES,
    MAX_TREE_DEPTH, MAX_TREE_VISITS, MEMORY_BYTES, OPEN_FILES, PARSER_VERSION,
    POLICY_ID, PROFILE_ID, PROTOCOL_VERSION, RESULT_BYTES, STATUS,
    _identity, _identity_from_plan, _is_digest,
)

_LIMITS = {'memory_bytes': MEMORY_BYTES, 'cpu_seconds': CPU_SECONDS,
           'file_bytes': RESULT_BYTES, 'open_files': OPEN_FILES}
_COUNTS = ('structure_elements', 'mapped_mcids', 'max_tree_depth',
           'traversal_visits', 'inspected_pages')
_DISABLE = 'OMNIGENIS_PDF_STRUCTURE_TREE_DISABLED'


class PdfStructureTreeError(ValueError):
    """Fixed content-free failure; no rejected candidate receives partial linkage evidence."""


@dataclass(frozen=True, slots=True, repr=False)
class PdfStructureTreeInspection:
    """Sealed unsigned observations of supported forward and reverse structural links."""

    pdf_sha256: str
    ir_sha256: str
    plan_sha256: str
    page_count: int
    structure_elements: int
    mapped_mcids: int
    max_tree_depth: int
    traversal_visits: int
    inspected_pages: int
    _sealed_sha256: str = field(init=False, repr=False, compare=False)

    def _record(self) -> dict:
        """Validate bounded native counts and preserve all non-linkage qualifications."""
        identity = {key: getattr(self, key) for key in IDENTITY_FIELDS}
        _identity(identity)
        counts = {key: getattr(self, key) for key in _COUNTS}
        if (any(type(v) is not int for v in counts.values())
                or not 1 <= self.max_tree_depth <= min(MAX_TREE_DEPTH, self.structure_elements)
                or not self.page_count <= self.mapped_mcids <= MAX_TREE_VISITS
                or not self.structure_elements + self.mapped_mcids <= self.traversal_visits <= MAX_TREE_VISITS
                or self.inspected_pages != self.page_count):
            raise ValueError('structure count relations invalid')
        return {'schema_version': '1.0.0', 'profile_id': PROFILE_ID,
                'policy_id': POLICY_ID, 'status': STATUS, **identity, **counts,
                'parser_version': PARSER_VERSION, 'language': LANGUAGE,
                'conformance_scope': 'REACHABLE_FORWARD_K_PARENT_AND_PAGE_MCID_LINKAGE_ONLY',
                'forward_reverse_linkage_verified': True,
                'prior_page_and_parsed_mcid_gates_applied': True,
                'semantic_roles_qualified': False, 'reading_order_verified': False,
                'full_accessibility_qualified': False, 'visible_content_covered': False,
                'text_equivalence_verified': False, 'scientific_equivalence_verified': False,
                'worker_results_authenticated': False, 'all_file_revisions_inspected': False,
                'aggregate_job_resources_qualified': False, 'release_authorized': False,
                'release_authorization': 'NOT_ESTABLISHED'}

    def __post_init__(self) -> None:
        """Seal direct construction without permitting in-place repinning after mutation."""
        try:
            data = _canonical(self._record())
            if len(data) > RESULT_BYTES:
                raise ValueError('structure receipt byte budget')
            digest = sha256(data).hexdigest()
            if hasattr(self, '_sealed_sha256') and self._sealed_sha256 != digest:
                raise ValueError('structure receipt modified')
            object.__setattr__(self, '_sealed_sha256', digest)
        except Exception:
            raise PdfStructureTreeError('pdf_structure_tree_receipt_invalid') from None

    def to_bytes(self) -> bytes:
        """Revalidate retained fields and expose only the originally sealed metadata."""
        try:
            data = _canonical(self._record())
            if len(data) > RESULT_BYTES or sha256(data).hexdigest() != self._sealed_sha256:
                raise ValueError('structure receipt modified')
            return data
        except Exception:
            raise PdfStructureTreeError('pdf_structure_tree_receipt_invalid') from None

    def to_dict(self) -> dict:
        """Return detached digest/count metadata, never raw structure attributes or content."""
        return json.loads(self.to_bytes())

    @property
    def inspection_sha256(self) -> str:
        """Hash the exact metadata without implying signature or worker authentication."""
        return sha256(self.to_bytes()).hexdigest()


def _decode(data: bytes, expected: dict) -> PdfStructureTreeInspection:
    """Reject duplicate JSON, extra keys, mismatched identities and unbounded native counts."""
    try:
        _identity(expected)
        if type(data) is not bytes or not 0 < len(data) <= RESULT_BYTES:
            raise ValueError('structure protocol byte bound')
        record = json.loads(data.decode('ascii'), object_pairs_hook=_unique_pairs)
        if (type(record) is not dict or set(record) != {'protocol_version', 'profile_id',
                'policy_id', 'parser_version', 'identity', 'limits', 'inspection'}
                or type(record['protocol_version']) is not int
                or record['protocol_version'] != PROTOCOL_VERSION
                or record['profile_id'] != PROFILE_ID or record['policy_id'] != POLICY_ID
                or record['parser_version'] != PARSER_VERSION):
            raise ValueError('structure protocol shape or pin mismatch')
        _identity(record['identity'])
        if record['identity'] != expected:
            raise ValueError('structure protocol document mismatch')
        limits = record['limits']
        if (type(limits) is not dict or set(limits) != set(_LIMITS)
                or any(type(v) is not int or v != _LIMITS[k] for k, v in limits.items())):
            raise ValueError('structure protocol resource mismatch')
        found = record['inspection']
        if type(found) is not dict or set(found) != {'status', *_COUNTS} or found['status'] != STATUS:
            raise ValueError('structure result shape')
        return PdfStructureTreeInspection(**expected, **{key: found[key] for key in _COUNTS})
    except Exception:
        raise PdfStructureTreeError('pdf_structure_tree_protocol_invalid') from None


def _run_worker(pdf: bytes, identity: dict) -> bytes:
    """Launch the existing bounded process wrapper with distinct anonymous owned files."""
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as result:
        fds = source.fileno(), result.fileno()
        infos = [os.fstat(fd) for fd in fds]
        if (any(not stat.S_ISREG(v.st_mode) or v.st_nlink != 0 or v.st_uid != os.geteuid()
                for v in infos)
                or (infos[0].st_dev, infos[0].st_ino) == (infos[1].st_dev, infos[1].st_ino)):
            raise ValueError('structure protocol files invalid')
        header = ' '.join([str(PROTOCOL_VERSION), *(str(identity[key]) for key in IDENTITY_FIELDS)])
        source.write(header.encode('ascii') + b'\n'); source.write(pdf); source.flush()
        process = _start([sys.executable, '-I',
            str(Path(__file__).resolve().with_name('_pdf_structure_tree_worker.py')),
            str(fds[0]), str(fds[1]), str(os.getpid())], fds)
        if _wait(process) != 0 or not 0 < os.fstat(result.fileno()).st_size <= RESULT_BYTES:
            raise ValueError('structure native worker failure')
        result.seek(0)
        return result.read(RESULT_BYTES + 1)


def inspect_pdf_structure_tree(
    *, pdf_bytes: object, plan: PageWindowPlan,
    expected_plan_sha256: str, expected_language: str,
) -> PdfStructureTreeInspection:
    """Validate supported forward hierarchy and reverse ownership for one exact final PDF.

    This optional adapter does not rewrite input, activate a coordinator or
    authenticate externally supplied source/job expectations. It never relaxes
    the previous page/MCID prerequisite or any default renderer profile.
    """
    try:
        if (sys.platform != 'linux' or os.environ.get(_DISABLE) == '1'
                or type(expected_language) is not str or expected_language != LANGUAGE
                or type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b'%PDF-1.7')
                or len(pdf_bytes) > MAX_PDF_BYTES or type(plan) is not PageWindowPlan
                or not _is_digest(expected_plan_sha256)):
            raise ValueError('structure input domain invalid')
        plan.__post_init__()
        if (plan.plan_sha256 != expected_plan_sha256
                or plan.inspector_profile_id != TEXT_PROFILE
                or plan.page_count > MAX_DOCUMENT_PAGES
                or plan.pdf_sha256 != sha256(pdf_bytes).hexdigest()):
            raise ValueError('structure exact plan mismatch')
        identity = _identity_from_plan(plan)
    except Exception:
        raise PdfStructureTreeError('pdf_structure_tree_input_invalid') from None
    try:
        result = _decode(_run_worker(pdf_bytes, identity), identity)
        plan.__post_init__()
        if plan.plan_sha256 != expected_plan_sha256 or os.environ.get(_DISABLE) == '1':
            raise ValueError('structure plan or activation changed')
        return result
    except Exception:
        raise PdfStructureTreeError('pdf_structure_tree_execution_failed') from None
