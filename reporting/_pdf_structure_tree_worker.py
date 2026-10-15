"""Guard the complete supported forward structural hierarchy and reverse MCID links.

Only root-reachable /K edges, immediate /P ownership and physical-page MCID
membership are qualified. Roles, attributes, alternate text, reading order,
visible content, historical revisions and report release remain outside scope.
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

from reporting import _pdf_mcid_coverage_worker as mcids
from reporting._pdf_object_graph_worker import (
    CPU_SECONDS, IDENTITY_FIELDS, MAX_PDF_BYTES, MEMORY_BYTES, OPEN_FILES,
    PARSER_VERSION, PROTOCOL_VERSION, RESULT_BYTES, WALL_SECONDS,
    _is_digest, _lifetime, _limits, _read_request, _validate_identity,
)
from reporting._pdf_process_sandbox import enforce_pdf_landlock, enforce_pdf_network_filter
from reporting._pdf_render_worker import _write_bytes

PROFILE_ID = 'generated-pdf-forward-structure-tree-v1'
POLICY_ID = 'forward-k-parent-and-mcid-linkage-v1'
STATUS = 'STRUCTURE_TREE_LINKAGE_INSPECTED'
LANGUAGE = 'en-US'
MAX_DOCUMENT_PAGES = 64
MAX_TREE_DEPTH = 64
MAX_TREE_VISITS = 20000


def _identity(value: dict) -> None:
    """Reuse the closed request grammar under the narrower complete-tree page class."""
    _validate_identity(value)
    if value['page_count'] > MAX_DOCUMENT_PAGES:
        raise ValueError('structure tree page class exceeded')


def _identity_from_plan(plan: object) -> dict:
    """Project a caller-revalidated plan into the shared fixed wire-identity fields."""
    identity = {key: getattr(plan, key) for key in IDENTITY_FIELDS}
    _identity(identity)
    return identity


def _key(ref: object, reader: object) -> tuple[int, int]:
    """Require a native indirect reference belonging to this exact parser instance."""
    from pypdf.generic import IndirectObject
    if (type(ref) is not IndirectObject or ref.pdf is not reader
            or type(ref.idnum) is not int or ref.idnum <= 0
            or type(ref.generation) is not int or ref.generation < 0):
        raise ValueError('structure reference not in exact document')
    return ref.idnum, ref.generation


def _inspect(pdf: bytes, identity: dict) -> dict:
    """Require the existing MCID gate, then match every supported forward and reverse edge."""
    _identity(identity)
    if (type(pdf) is not bytes or not pdf.startswith(b'%PDF-1.7')
            or len(pdf) > MAX_PDF_BYTES or sha256(pdf).hexdigest() != identity['pdf_sha256']
            or version('pypdf') != PARSER_VERSION):
        raise ValueError('structure input or parser identity invalid')
    prerequisite = mcids._inspect(pdf, identity)
    if (prerequisite['status'] != mcids.STATUS
            or prerequisite['inspected_pages'] != identity['page_count']):
        raise ValueError('structure prerequisite not complete')
    from pypdf import PdfReader
    from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject, NameObject, NumberObject
    reader = PdfReader(BytesIO(pdf), strict=True)
    if reader.is_encrypted or len(reader.pages) != identity['page_count']:
        raise ValueError('structure physical document mismatch')
    root_ref = reader.root_object.get('/StructTreeRoot')
    _key(root_ref, reader)
    root = root_ref.get_object()
    if type(root) is not DictionaryObject or root.get('/Type') != '/StructTreeRoot':
        raise ValueError('structure root invalid')
    pages = {}
    page_keys = {}
    for page in reader.pages:
        key = _key(page.indirect_reference, reader)
        number = page.get('/StructParents')
        if type(number) is not NumberObject or key in pages or int(number) in page_keys:
            raise ValueError('structure physical page key invalid')
        pages[key] = page
        page_keys[int(number)] = key
    parent_tree = root['/ParentTree'].get_object()
    nums = parent_tree.get('/Nums')
    if type(nums) is not ArrayObject or len(nums) != 2 * len(pages):
        raise ValueError('structure reverse number tree shape')
    visits = 0

    def spend(amount: int = 1) -> None:
        """Charge reverse slots, structural nodes and child entries to one finite traversal."""
        nonlocal visits
        visits += amount
        if visits > MAX_TREE_VISITS:
            raise ValueError('structure traversal visit budget')

    expected = {}
    for i in range(0, len(nums), 2):
        number, entries = nums[i], nums[i + 1]
        if (type(number) is not NumberObject or int(number) not in page_keys
                or type(entries) is not ArrayObject or not entries):
            raise ValueError('structure reverse entry profile')
        spend(len(entries))
        page_key = page_keys[int(number)]
        for index, entry in enumerate(entries):
            slot = page_key, index
            if slot in expected:
                raise ValueError('structure reverse slot repeated')
            expected[slot] = _key(entry, reader)
    children = root.get('/K')
    if type(children) is not ArrayObject or not children:
        raise ValueError('structure root children unavailable')
    spend(len(children))
    pending = [(child, root_ref, 1) for child in children]
    seen = set()
    observed = set()
    deepest = 0
    while pending:
        ref, parent, depth = pending.pop()
        ref_key = _key(ref, reader)
        if ref_key in seen or depth > MAX_TREE_DEPTH:
            raise ValueError('structure cycle shared node or depth budget')
        seen.add(ref_key)
        spend()
        deepest = max(deepest, depth)
        node = ref.get_object()
        if (type(node) is not DictionaryObject or type(node.get('/Type')) is not NameObject
                or node.get('/Type') != '/StructElem' or type(node.get('/S')) is not NameObject
                or _key(node.get('/P'), reader) != _key(parent, reader)):
            raise ValueError('structure element type or immediate ownership invalid')
        physical = None
        if '/Pg' in node:
            physical = _key(node.get('/Pg'), reader)
            if physical not in pages:
                raise ValueError('structure node page not physical')
        raw = node.get('/K')
        if type(raw) is ArrayObject:
            if not raw:
                raise ValueError('structure empty child group')
            kids = raw
        elif type(raw) in (IndirectObject, NumberObject):
            kids = (raw,)
        else:
            raise ValueError('structure child representation unsupported')
        spend(len(kids))
        for child in kids:
            if type(child) is IndirectObject:
                _key(child, reader)
                if len(pending) >= MAX_TREE_VISITS:
                    raise ValueError('structure pending budget')
                pending.append((child, ref, depth + 1))
            elif type(child) is NumberObject:
                if physical is None or not 0 <= child < MAX_TREE_VISITS:
                    raise ValueError('structure terminal MCID or explicit page invalid')
                slot = physical, int(child)
                if slot in observed or expected.get(slot) != ref_key:
                    raise ValueError('structure terminal reverse ownership mismatch')
                observed.add(slot)
            else:
                raise ValueError('structure child type unsupported')
    if (not seen or observed != set(expected)
            or len(observed) != prerequisite['matched_mcids']):
        raise ValueError('structure forward reverse coverage mismatch')
    return {'status': STATUS, 'structure_elements': len(seen),
            'mapped_mcids': len(observed), 'max_tree_depth': deepest,
            'traversal_visits': visits, 'inspected_pages': len(pages)}


def main(argv: list[str] | None = None) -> int:
    """Establish every native guard before reading; failed jobs write no success payload."""
    argv = sys.argv if argv is None else argv
    if (sys.platform != 'linux' or type(argv) is not list or len(argv) != 4
            or any(type(s) is not str or not s.isascii() or not s.isdecimal()
                   or len(s) > 10 for s in argv[1:])):
        return 64
    try:
        first, second, parent = map(int, argv[1:])
        if (any(str(n) != s for n, s in zip((first, second, parent), argv[1:], strict=True))
                or min(first, second) < 3 or first == second or not 2 <= parent <= 2147483647):
            return 64
        infos = [os.fstat(fd) for fd in (first, second)]
        if (any(not stat.S_ISREG(v.st_mode) or v.st_nlink != 0 or v.st_uid != os.geteuid()
                for v in infos)
                or (infos[0].st_dev, infos[0].st_ino) == (infos[1].st_dev, infos[1].st_ino)
                or infos[1].st_size):
            return 64
        limits = _limits()
        _lifetime(parent)
        enforce_pdf_landlock(Path(__file__))
        enforce_pdf_network_filter()
        identity, pdf = _read_request(first)
        result = {'protocol_version': PROTOCOL_VERSION, 'profile_id': PROFILE_ID,
                  'policy_id': POLICY_ID, 'parser_version': PARSER_VERSION,
                  'identity': identity, 'limits': limits, 'inspection': _inspect(pdf, identity)}
        encoded = json.dumps(result, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=True, allow_nan=False).encode('ascii')
        if not 0 < len(encoded) <= RESULT_BYTES:
            return 70
        _write_bytes(second, encoded)
    except Exception:
        return 70
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
