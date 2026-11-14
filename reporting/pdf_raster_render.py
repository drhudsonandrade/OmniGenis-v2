"""Explicit qualification-only raster rendering with the original confined worker.

This entrypoint produces a candidate, not a complete report or a released PDF.
Its resources are preloaded digest-bound PNGs. It preserves the two legacy
renderer protocols and budgets. Source/rights assertions, whole-job aggregate
resources, content equivalence, visual semantics and accessibility remain
separate checks. No filename, URL fetcher callback, renderer or output path is
accepted. No retry, fallback, PDF rewrite or post-render padding is performed.
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

from reporting import _pdf_render_worker as worker
from reporting.pdf_raster_resources import (
    RasterBundle, MAX_BUNDLE_BYTES, _canonical, _digest, read_bundle, resource_profile,
)

PROFILE_ID = 'preloaded-png-render-v1'
MODE = 'native-preloaded-png-v1'
PROTOCOL_VERSION = 3
_QUALIFICATION = 'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE'
_DISABLE = 'OMNIGENIS_PDF_PRELOADED_RASTER_DISABLED'
_FIXED_PROFILE_SHA256 = '5391bdae627341ce95c351093bfc2a6dc2575e48203f9ee4bd4581c6ec1eb0de'


class RasterRenderError(ValueError):
    """A fixed failure code that withholds candidate bytes and private error text."""


def _require(value: bool) -> None:
    """Reject an incomplete render boundary without exposing the rejected values."""
    if not value:
        raise RasterRenderError('preloaded_raster_render_invalid')


def raster_render_profile() -> dict:
    """Pin the explicit extension while preserving every original renderer limit."""
    return {**worker.native_render_profile(), 'profile_id': PROFILE_ID,
        'protocol_version': PROTOCOL_VERSION, 'mode': MODE,
        'resource_profile_sha256': sha256(_canonical(resource_profile())).hexdigest(),
        'input_binding': 'EXACT_HTML_AND_RESOURCE_BUNDLE_SHA256',
        'resource_descriptor': 'BORROWED_ANONYMOUS_REGULAR_FILE',
        'qualification_only': True, 'resources_authorized_for_release': False,
        'content_equivalence_verified': False, 'visual_semantics_verified': False,
        'accessibility_qualified': False}


def profile_sha256() -> str:
    """Identify the declared profile and reject runtime constant drift."""
    digest = sha256(_canonical(raster_render_profile())).hexdigest()
    _require(digest == _FIXED_PROFILE_SHA256)
    return digest


def _require_policy() -> None:
    """No caller can silently enable this mode through a resource or document."""
    _require(os.environ.get(_QUALIFICATION) == 'qualification-only')
    for name in (_DISABLE, 'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED',
                 'OMNIGENIS_PDF_RENDERER_DISABLED'):
        _require(os.environ.get(name) != '1')
    profile_sha256()


def _strict(raw: bytes) -> dict:
    """Refuse duplicate keys and nonfinite protocol numbers."""
    def unique(pairs):
        """Refuse repeated response keys before they can overwrite prior values."""
        value = {}
        for key, item in pairs:
            _require(key not in value); value[key] = item
        return value
    def invalid(_text):
        """Reject nonfinite JSON values without echoing the supplied content."""
        raise RasterRenderError('preloaded_raster_render_invalid')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def read_raster_inputs(request_fd: int, resource_fd: int) -> tuple[str, str, RasterBundle]:
    """Read one exact bounded request and resource descriptor after OS confinement."""
    _require_policy()
    request_size = os.fstat(request_fd).st_size
    _require(133 <= request_size <= worker.HTML_BYTES + 132)
    raw = os.pread(request_fd, request_size + 1, 0)
    _require(len(raw) == request_size)
    header, newline, html = raw.partition(b'\n')
    _require(newline == b'\n' and len(header) == 131 and header.startswith(b'3 '))
    fields = header.decode('ascii').split(' ')
    _require(len(fields) == 3 and fields[0] == '3')
    html_sha, resource_sha = fields[1:]
    _digest(html_sha); _digest(resource_sha)
    _require(len(html) <= worker.HTML_BYTES and sha256(html).hexdigest() == html_sha)
    count = os.fstat(resource_fd).st_size
    _require(8 <= count <= MAX_BUNDLE_BYTES)
    data = os.pread(resource_fd, count + 1, 0)
    _require(len(data) == count)
    bundle = read_bundle(data, expected_sha256=resource_sha)
    return html.decode('utf-8'), html_sha, bundle


@dataclass(frozen=True)
class RasterPdfCandidate:
    """Sealed private render bytes with exact provenance digests and explicit nonclaims."""
    _pdf: bytes = field(repr=False)
    html_sha256: str
    resources_sha256: str
    page_count: int
    resource_count: int
    _seal: str = field(init=False, repr=False, compare=False)

    def _metadata(self) -> dict:
        """Recheck the complete retained bytes before exposing candidate metadata."""
        _require(type(self) is RasterPdfCandidate)
        _digest(self.html_sha256); _digest(self.resources_sha256)
        _require(type(self._pdf) is bytes and self._pdf.startswith(b'%PDF-1.7')
                 and 0 < len(self._pdf) <= worker.NATIVE_PDF_BYTES)
        _require(type(self.page_count) is int and 1 <= self.page_count <= worker.NATIVE_MAX_PAGES)
        _require(type(self.resource_count) is int and 1 <= self.resource_count <= 3)
        return {'profile_id': PROFILE_ID, 'profile_sha256': profile_sha256(),
            'html_sha256': self.html_sha256, 'resources_sha256': self.resources_sha256,
            'pdf_sha256': sha256(self._pdf).hexdigest(), 'pdf_bytes': len(self._pdf),
            'page_count': self.page_count, 'resource_count': self.resource_count,
            'qualification_only': True, 'release_authorized': False,
            'aggregate_job_resources_qualified': False, 'content_equivalence_verified': False,
            'visual_semantics_verified': False, 'accessibility_qualified': False}

    def __post_init__(self) -> None:
        """Seal once; later validation cannot bless changed retained candidate data."""
        value = sha256(_canonical(self._metadata())).hexdigest()
        _require(not hasattr(self, '_seal') or self._seal == value)
        object.__setattr__(self, '_seal', value)

    def to_dict(self) -> dict:
        """Return detached metadata only after validating its original seal."""
        value = self._metadata(); _require(sha256(_canonical(value)).hexdigest() == self._seal)
        return value

    @property
    def pdf_bytes(self) -> bytes:
        """Expose only the originally sealed private candidate, never a repaired PDF."""
        self.to_dict(); return self._pdf

    @property
    def pdf_sha256(self) -> str:
        """Identify the complete private artifact after current integrity checks."""
        return self.to_dict()['pdf_sha256']


def _decode(data: bytes, fd: int, html_sha: str, resources_sha: str, count: int) -> RasterPdfCandidate:
    """Require an exact complete child response and the same anonymous output bytes."""
    _require(type(data) is bytes and 0 < len(data) <= worker.RESULT_BYTES)
    record = _strict(data)
    keys = {'protocol_version', 'profile_id', 'profile_sha256', 'status', 'pdf_bytes',
            'pdf_sha256', 'limits', 'html_sha256', 'page_count', 'resources_sha256', 'resource_count'}
    _require(type(record) is dict and set(record) == keys)
    _require(type(record['protocol_version']) is int and record['protocol_version'] == PROTOCOL_VERSION
             and record['profile_id'] == PROFILE_ID and record['profile_sha256'] == profile_sha256()
             and record['status'] == 'PASS')
    expected_limits = {'memory_bytes': worker.MEMORY_BYTES, 'cpu_seconds': worker.CPU_SECONDS,
                       'file_bytes': worker.NATIVE_PDF_BYTES, 'open_files': worker.OPEN_FILES}
    limits = record['limits']
    _require(type(limits) is dict and set(limits) == set(expected_limits)
             and all(type(value) is int for value in limits.values()) and limits == expected_limits)
    _require(record['html_sha256'] == html_sha and record['resources_sha256'] == resources_sha)
    _require(type(record['resource_count']) is int and record['resource_count'] == count)
    size = record['pdf_bytes']
    _require(type(size) is int and 0 < size <= worker.NATIVE_PDF_BYTES)
    st = os.fstat(fd); _require(stat.S_ISREG(st.st_mode) and st.st_nlink == 0 and st.st_size == size)
    raw = os.pread(fd, size + 1, 0)
    _digest(record['pdf_sha256'])
    _require(len(raw) == size and sha256(raw).hexdigest() == record['pdf_sha256'])
    return RasterPdfCandidate(raw, html_sha, resources_sha, record['page_count'], count)


def _render_preloaded_raster_pdf(*, html: str, expected_html_sha256: str,
        resources: RasterBundle, expected_resources_sha256: str,
        observe_processes: bool) -> tuple[RasterPdfCandidate, dict | None]:
    """Render once in the fixed child with finite descriptors and no external resources.

    HTML is a trusted compiler output, not an arbitrary user document. Digest
    equality does not authenticate its source. Content/safety/rights qualification
    and whole-job accounting remain separate from this render-only operation.
    """
    try:
        _require(type(observe_processes) is bool)
        _require_policy(); _digest(expected_html_sha256); _digest(expected_resources_sha256)
        _require(type(html) is str and 0 < len(html) <= worker.HTML_BYTES and type(resources) is RasterBundle)
        encoded = html.encode('utf-8')
        _require(len(encoded) <= worker.HTML_BYTES and sha256(encoded).hexdigest() == expected_html_sha256)
        payload = resources.to_bytes(); _require(sha256(payload).hexdigest() == expected_resources_sha256)
        from reporting import adapters
        if observe_processes:
            from reporting import _pdf_final_document_observation as observation
        with (adapters._PDF_RENDER_ENV_LOCK, tempfile.TemporaryFile() as request,
              tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as response,
              tempfile.TemporaryFile() as resource_file):
            fds = tuple(f.fileno() for f in (request, output, response, resource_file))
            _require(all(stat.S_ISREG(os.fstat(fd).st_mode) and os.fstat(fd).st_nlink == 0 for fd in fds))
            request.write(f'3 {expected_html_sha256} {expected_resources_sha256}\n'.encode('ascii'))
            request.write(encoded); request.flush(); request.seek(0)
            resource_file.write(payload); resource_file.flush(); resource_file.seek(0)
            env = {key: os.environ[key] for key in (
                'PATH', 'HOME', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TZ', 'FONTCONFIG_FILE', 'FONTCONFIG_PATH',
            ) if key in os.environ}
            env.update(SOURCE_DATE_EPOCH='0', OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE='qualification-only')
            command = [sys.executable, '-I', '-B', str(Path(__file__).with_name('_pdf_render_worker.py')),
                       *(str(fd) for fd in fds[:3]), str(os.getpid()), MODE, str(fds[3])]
            process = adapters._start_pdf_render_worker(command, env=env, pass_fds=fds)
            observed = None
            if observe_processes:
                observed = observation.capture_spawn(process, command, 'render')
            code = adapters._wait_pdf_render_worker(process, wall_seconds=worker.WALL_SECONDS)
            if observe_processes:
                observed = observation.observe_exit(process, observed, code)
            _require(code == 0 and os.fstat(response.fileno()).st_size <= worker.RESULT_BYTES)
            response.seek(0)
            result = _decode(response.read(worker.RESULT_BYTES + 1), output.fileno(),
                expected_html_sha256, expected_resources_sha256, len(resources.assets))
            _require_policy(); _require(resources.bundle_sha256 == expected_resources_sha256)
            if observe_processes:
                observed = observation.render_record(observed, result)
            return result, observed
    except Exception:
        raise RasterRenderError('preloaded_raster_render_failed') from None


def render_preloaded_raster_pdf(*, html: str, expected_html_sha256: str,
        resources: RasterBundle, expected_resources_sha256: str) -> RasterPdfCandidate:
    """Keep the original result-only rendering contract and default behavior."""
    result, _ = _render_preloaded_raster_pdf(html=html, expected_html_sha256=expected_html_sha256,
        resources=resources, expected_resources_sha256=expected_resources_sha256, observe_processes=False)
    return result


def render_observed_preloaded_raster_pdf(*, html: str, expected_html_sha256: str,
        resources: RasterBundle, expected_resources_sha256: str) -> tuple[RasterPdfCandidate, dict]:
    """Observe the same fixed owned child without changing its wire or budgets.

    The detached unsigned record describes only this direct worker. It does not
    authenticate execution, qualify descendants/resources or authorize release.
    Observation failure preserves owned-child cleanup and returns no candidate.
    """
    result, observed = _render_preloaded_raster_pdf(html=html, expected_html_sha256=expected_html_sha256,
        resources=resources, expected_resources_sha256=expected_resources_sha256, observe_processes=True)
    _require(type(observed) is dict)
    return result, observed
