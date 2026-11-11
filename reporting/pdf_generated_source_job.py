"""Explicit bounded generated-PDF candidates, distinct from default readiness.

Rendering and physical page discovery use the existing guarded child. The
optional wire does not accept caller budgets or authenticate worker execution.
Candidate bytes remain private content; metadata alone never authorizes release.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
from subprocess import Popen as _Process
import sys
import tempfile
from time import monotonic_ns

from reporting import _pdf_render_worker as render_worker
from reporting import pdf_inspection_job as legacy
from reporting import pdf_native_source_job as native_source
from reporting._pdf_native_launch_budget import require_no_active_scope
from reporting._pdf_process_lifecycle import _observe as _observe_owned
from reporting.adapters import (
    _PDF_RENDER_ENV_LOCK, _start_pdf_render_worker, _wait_pdf_render_worker,
    _capture_adapter_ir, _validate_ir, _semantic_html,
)
from reporting.page_checkpoints import _json_bytes, _validate_context
from reporting.page_windows import plan_pdf_page_windows
from reporting.pdf_content import _expected_content
from reporting.pdf_inspection_bundle import _pin
from reporting.pdf_native_source_job import PdfNativeSourceResult, execute_pdf_native_source_job

RENDER_PROFILE_SHA256 = sha256(_json_bytes(render_worker.native_render_profile())).hexdigest()
_RENDER_LIMITS = {"memory_bytes": 1073741824, "cpu_seconds": 20,
                  "file_bytes": 16777216, "open_files": 128}
_RENDER_RESULT_BYTES = 64 * 1024
_RENDER_PDF_BYTES = 16 * 1024 * 1024
_RENDER_HTML_BYTES = 64 * 1024 * 1024
_RENDER_PAGES = 64
_RENDER_ERRORS = frozenset({
    "pdf_engine_unavailable", "pdf_engine_version_mismatch", "pdf_render_failed",
    "pdf_engine_invalid_output", "pdf_candidate_budget_exceeded", "pdf_render_protocol_invalid",
    "pdf_candidate_page_budget_exceeded", "pdf_page_discovery_failed",
})


class PdfGeneratedSourceJobError(ValueError):
    """Content-free refusal with no exposed partial candidate or release result."""


def _render_profile() -> None:
    """Require the unchanged closed optional profile and inherited disable policy."""
    parent_bounds = (_RENDER_PAGES, _RENDER_PDF_BYTES, _RENDER_HTML_BYTES, _RENDER_RESULT_BYTES)
    if (any(type(value) is not int for value in parent_bounds)
            or parent_bounds != (64, 16777216, 67108864, 65536)
            or type(_RENDER_LIMITS) is not dict
            or _RENDER_LIMITS != {'memory_bytes': 1073741824, 'cpu_seconds': 20,
                                  'file_bytes': 16777216, 'open_files': 128}
            or any(type(value) is not int for value in _RENDER_LIMITS.values())):
        raise ValueError('generated render parent profile changed')
    if (sys.platform != 'linux' or os.environ.get('OMNIGENIS_PDF_RENDERER_DISABLED') == '1'
            or sha256(_json_bytes(render_worker.native_render_profile())).hexdigest() != RENDER_PROFILE_SHA256):
        raise ValueError('generated render profile unavailable')


@dataclass(frozen=True, slots=True, repr=False)
class PdfRenderedCandidate:
    """Sealed private bytes and bounded unsigned physical-page observations."""

    _pdf_bytes: bytes
    html_sha256: str
    pdf_sha256: str
    page_count: int
    profile_sha256: str
    _sealed_sha256: str = field(init=False, repr=False, compare=False)

    def _validated_bytes(self) -> bytes:
        """Bind byte identity and exact finite metadata without parsing in the parent."""
        _render_profile()
        for value in (self.html_sha256, self.pdf_sha256, self.profile_sha256):
            _pin(value)
        if (type(self._pdf_bytes) is not bytes or not self._pdf_bytes.startswith(b'%PDF-1.7')
                or not 1 <= len(self._pdf_bytes) <= _RENDER_PDF_BYTES
                or sha256(self._pdf_bytes).hexdigest() != self.pdf_sha256
                or type(self.page_count) is not int or not 1 <= self.page_count <= _RENDER_PAGES
                or self.profile_sha256 != RENDER_PROFILE_SHA256):
            raise ValueError('generated render result invalid')
        return _json_bytes({
            'schema_version': '1.0.0', 'profile_id': 'generated-native-source-render-v1',
            'status': 'GENERATED_CANDIDATE_PHYSICAL_PAGES_OBSERVED',
            'profile_sha256': self.profile_sha256, 'html_sha256': self.html_sha256,
            'pdf_sha256': self.pdf_sha256, 'pdf_byte_count': len(self._pdf_bytes),
            'page_count': self.page_count, 'release_authorized': False,
            'aggregate_job_resources_qualified': False, 'default_pipeline_activated': False,
            'authenticated_worker_execution': False,
        })

    def __post_init__(self) -> None:
        """Seal once, refusing to reseal altered retained evidence."""
        try:
            digest = sha256(self._validated_bytes()).hexdigest()
            if hasattr(self, '_sealed_sha256') and self._sealed_sha256 != digest:
                raise ValueError('rendered candidate changed')
            object.__setattr__(self, '_sealed_sha256', digest)
        except Exception:
            raise PdfGeneratedSourceJobError('pdf_generated_render_result_invalid') from None

    def to_bytes(self) -> bytes:
        """Recheck the retained seal before returning content-free canonical metadata."""
        try:
            data = self._validated_bytes()
            if sha256(data).hexdigest() != self._sealed_sha256:
                raise ValueError('rendered candidate changed')
            return data
        except Exception:
            raise PdfGeneratedSourceJobError('pdf_generated_render_result_invalid') from None

    def to_dict(self) -> dict:
        """Return detached metadata, never the PDF or source content."""
        return json.loads(self.to_bytes())

    @property
    def pdf_bytes(self) -> bytes:
        """Expose private candidate content only after rechecking its original seal."""
        self.to_bytes()
        return self._pdf_bytes

    @property
    def result_sha256(self) -> str:
        """Identify the sealed render metadata without claiming authentication."""
        return sha256(self.to_bytes()).hexdigest()


def _decode_render_result(data: bytes, *, candidate_fd: int,
                          expected_html_sha256: str) -> PdfRenderedCandidate:
    """Validate a closed optional receipt and its anonymous output descriptor."""
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate render field')
            result[key] = value
        return result

    def reject_constant(_value):
        raise ValueError('invalid render JSON')

    try:
        _render_profile()
        _pin(expected_html_sha256)
        if type(data) is not bytes or not 1 <= len(data) <= _RENDER_RESULT_BYTES:
            raise ValueError('render response budget')
        record = json.loads(data.decode('ascii'), object_pairs_hook=unique, parse_constant=reject_constant)
        if (type(record) is not dict or type(record.get('protocol_version')) is not int
                or record['protocol_version'] != 2
                or record.get('profile_id') != 'generated-native-source-render-v1'
                or record.get('profile_sha256') != RENDER_PROFILE_SHA256
                or type(record.get('limits')) is not dict or record['limits'] != _RENDER_LIMITS
                or any(type(value) is not int for value in record['limits'].values())):
            raise ValueError('render response profile')
        common = {'protocol_version', 'profile_id', 'profile_sha256', 'status', 'limits'}
        if record.get('status') == 'FAIL':
            if set(record) != common | {'error'} or record.get('error') not in _RENDER_ERRORS:
                raise ValueError('render failure response')
            raise PdfGeneratedSourceJobError('pdf_generated_render_failed')
        if (record.get('status') != 'PASS'
                or set(record) != common | {'html_sha256', 'pdf_bytes', 'pdf_sha256', 'page_count'}
                or record['html_sha256'] != expected_html_sha256
                or type(record['pdf_bytes']) is not int or not 1 <= record['pdf_bytes'] <= _RENDER_PDF_BYTES
                or type(record['page_count']) is not int or not 1 <= record['page_count'] <= _RENDER_PAGES
                or type(candidate_fd) is not int or candidate_fd < 3):
            raise ValueError('render response type or identity')
        _pin(record['pdf_sha256'])
        info = os.fstat(candidate_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 0 or info.st_size != record['pdf_bytes']:
            raise ValueError('render output descriptor')
        pdf = os.pread(candidate_fd, record['pdf_bytes'] + 1, 0)
        if len(pdf) != record['pdf_bytes']:
            raise ValueError('render output size')
        return PdfRenderedCandidate(pdf, expected_html_sha256, record['pdf_sha256'],
                                    record['page_count'], RENDER_PROFILE_SHA256)
    except PdfGeneratedSourceJobError:
        raise
    except Exception:
        raise PdfGeneratedSourceJobError('pdf_generated_render_result_invalid') from None


def _observe_render_spawn(process: object, command: list[str]) -> dict:
    """Observe one actual unreaped render child, not an authenticated kernel launch.

    The existing waitable-child check retains its PID through the later owned
    group cleanup. Timestamps are local observations, not exact kernel events.
    Source hashes describe controlled files, not hostile concurrent execution.
    """
    if (not isinstance(process, _Process) or type(process.pid) is not int
            or process.pid <= 1 or process.args != command or process.returncode is not None):
        raise ValueError('render observed child identity')
    _observe_owned(process)
    if os.getpgid(process.pid) != process.pid:
        raise ValueError('render observed process group')
    current = monotonic_ns()
    if type(current) is not int or current < 0:
        raise ValueError('render observed clock')
    worker = Path(__file__).with_name('_pdf_render_worker.py')
    return {'kind': 'render', 'worker': worker.name,
            'worker_source_sha256': sha256(worker.read_bytes()).hexdigest(),
            'parent_pid': os.getpid(), 'pid': process.pid,
            'spawn_monotonic_ns': current}


def _render_pdf_candidate(html: str, html_sha256: str, *,
                          observe_processes: bool) -> tuple[PdfRenderedCandidate, dict | None]:
    """Share the unchanged rendering wire with optional direct-child observations."""
    try:
        if type(observe_processes) is not bool:
            raise ValueError('render observation mode')
        _render_profile()
        _pin(html_sha256)
        if type(html) is not str or len(html) > _RENDER_HTML_BYTES:
            raise ValueError('render HTML budget')
        encoded = html.encode('utf-8')
        if len(encoded) > _RENDER_HTML_BYTES or sha256(encoded).hexdigest() != html_sha256:
            raise ValueError('render HTML identity')
        with (_PDF_RENDER_ENV_LOCK, tempfile.TemporaryFile() as request,
              tempfile.TemporaryFile() as candidate, tempfile.TemporaryFile() as result):
            fds = tuple(handle.fileno() for handle in (request, candidate, result))
            if any(not stat.S_ISREG(os.fstat(fd).st_mode) or os.fstat(fd).st_nlink != 0 for fd in fds):
                raise ValueError('render protocol storage')
            request.write(f'2 {html_sha256}\n'.encode('ascii'))
            request.write(encoded)
            request.flush()
            request.seek(0)
            env = {key: os.environ[key] for key in (
                'PATH', 'HOME', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TZ', 'FONTCONFIG_FILE', 'FONTCONFIG_PATH',
            ) if key in os.environ}
            env['SOURCE_DATE_EPOCH'] = '0'
            command = [
                sys.executable, '-I', '-B', str(Path(__file__).with_name('_pdf_render_worker.py')),
                *(str(fd) for fd in fds), str(os.getpid()), 'native-source-v1',
            ]
            process = _start_pdf_render_worker(command, env=env, pass_fds=fds)
            observation = None
            if observe_processes:
                try:
                    observation = _observe_render_spawn(process, command)
                except BaseException as failure:
                    if isinstance(process, _Process):
                        try:
                            _wait_pdf_render_worker(process, wall_seconds=0)
                        except BaseException as cleanup:
                            raise failure from cleanup
                    raise
            code = _wait_pdf_render_worker(process, wall_seconds=30)
            if code != 0 or os.fstat(result.fileno()).st_size > _RENDER_RESULT_BYTES:
                raise ValueError('render lifecycle or response budget')
            if observe_processes:
                current = monotonic_ns()
                if (type(code) is not int or process.returncode != code
                        or type(current) is not int or current < observation['spawn_monotonic_ns']):
                    raise ValueError('render observed exit or clock')
                observation.update(exit_monotonic_ns=current, exit_code=code)
            result.seek(0)
            rendered = _decode_render_result(result.read(_RENDER_RESULT_BYTES + 1),
                candidate_fd=candidate.fileno(), expected_html_sha256=html_sha256)
            if observe_processes:
                observation.update({
                    'request_header_sha256': sha256(f'2 {html_sha256}\n'.encode('ascii')).hexdigest(),
                    'html_sha256': html_sha256, 'pdf_sha256': rendered.pdf_sha256,
                    'page_count': rendered.page_count, 'render_sha256': rendered.result_sha256,
                    'profile_sha256': rendered.profile_sha256,
                })
                observation['observation_sha256'] = sha256(_json_bytes(observation)).hexdigest()
            return rendered, observation
    except Exception:
        raise PdfGeneratedSourceJobError('pdf_generated_render_failed') from None


def render_pdf_candidate(html: str, html_sha256: str) -> PdfRenderedCandidate:
    """Render using the original result-only contract without process recording."""
    rendered, _ = _render_pdf_candidate(html, html_sha256, observe_processes=False)
    return rendered


PROFILE_ID = 'generated-source-pdf-inspection-job-v1'
NATIVE_SOURCE_PROFILE_SHA256 = 'dd29be3ecc903308a9bbe8b44b1fdbb57e6b5d18e5dde6918738e4bce194038c'
MAX_PAGES = 64
MAX_PDF_BYTES = 16 * 1024 * 1024
MAX_RESULT_BYTES = 320 * 1024
ACCEPTANCE_NS = 330 * 1000 * 1000 * 1000
LANGUAGE = 'en-US'
_DISABLE = 'OMNIGENIS_PDF_GENERATED_SOURCE_JOB_DISABLED'
OBSERVATION_SCHEMA = 'generated-source-job-process-observation/v1'
MAX_OBSERVATION_BYTES = 96 * 1024


def generated_source_job_profile() -> dict:
    """Describe generation and same-artifact inspection, not default delivery readiness."""
    return {
        'schema_version': '1.0.0', 'profile_id': PROFILE_ID,
        'language': LANGUAGE, 'pdf_version': '1.7', 'max_pages': MAX_PAGES,
        'max_pdf_bytes': MAX_PDF_BYTES, 'max_result_bytes': MAX_RESULT_BYTES,
        'max_outer_stages': 2, 'acceptance_deadline_ns': ACCEPTANCE_NS,
        'render_profile_sha256': RENDER_PROFILE_SHA256,
        'native_source_job_profile_sha256': NATIVE_SOURCE_PROFILE_SHA256,
        'source_capture': 'EXISTING_BOUNDED_SEMANTIC_SECTION_ADAPTER_SNAPSHOT',
        'source_json_bytes': 8388608, 'source_json_depth': 64,
        'source_json_nodes': 100000, 'source_integer_bits': 4096,
        'expected_text_chars': 1048576, 'html_bytes': 67108864,
        'physical_pages': 'DISCOVERED_IN_GUARDED_RENDER_CHILD_AND_RECHECKED_BY_NATIVE_INSPECTION',
        'retries': 0, 'persistent_checkpoints': False,
        'hard_job_deadline_enforced': False, 'aggregate_job_resources_qualified': False,
        'default_pipeline_activated': False, 'release_authorized': False,
    }


PROFILE_SHA256 = sha256(_json_bytes(generated_source_job_profile())).hexdigest()


def _profile(expected: str) -> None:
    """Pin the outer contract and recursively enforce both inherited policy chains."""
    _pin(expected)
    if (sys.platform != 'linux' or os.environ.get(_DISABLE) == '1'
            or expected != PROFILE_SHA256
            or sha256(_json_bytes(generated_source_job_profile())).hexdigest() != PROFILE_SHA256
            or native_source.PROFILE_SHA256 != NATIVE_SOURCE_PROFILE_SHA256):
        raise ValueError('generated source job profile unavailable')
    _render_profile()
    native_source._profile(NATIVE_SOURCE_PROFILE_SHA256)


@dataclass(frozen=True, slots=True, repr=False)
class PdfGeneratedSourceResult:
    """Retain private generated bytes with sealed, unsigned same-artifact observations."""

    rendered_candidate: PdfRenderedCandidate
    native_inspection: PdfNativeSourceResult
    expected_render_sha256: str
    expected_inspection_sha256: str
    expected_text_sha256: str
    ir_sha256: str
    html_sha256: str
    plan_sha256: str
    namespace_id: str
    job_id: str
    request_sha256: str
    resource_profile_sha256: str
    _sealed_sha256: str = field(init=False, repr=False, compare=False)

    def _validated_bytes(self) -> bytes:
        """Revalidate retained children, exact source/job bindings and the finite result budget."""
        _profile(self.resource_profile_sha256)
        for value in (self.expected_render_sha256, self.expected_inspection_sha256,
                      self.expected_text_sha256, self.ir_sha256, self.html_sha256,
                      self.plan_sha256, self.request_sha256):
            _pin(value)
        if (type(self.rendered_candidate) is not PdfRenderedCandidate
                or type(self.native_inspection) is not PdfNativeSourceResult
                or type(self.namespace_id) is not str or type(self.job_id) is not str):
            raise ValueError('generated source result type')
        _validate_context(self.namespace_id, self.job_id, self.request_sha256,
                          self.resource_profile_sha256)
        render_bytes = self.rendered_candidate.to_bytes()
        inspection_bytes = self.native_inspection.to_bytes()
        if (sha256(render_bytes).hexdigest() != self.expected_render_sha256
                or sha256(inspection_bytes).hexdigest() != self.expected_inspection_sha256):
            raise ValueError('generated source retained child changed')
        first, second = json.loads(render_bytes), json.loads(inspection_bytes)
        identity = {'pdf_sha256': first['pdf_sha256'], 'page_count': first['page_count'],
                    'ir_sha256': self.ir_sha256, 'plan_sha256': self.plan_sha256,
                    'expected_text_sha256': self.expected_text_sha256,
                    'namespace_id': self.namespace_id, 'job_id': self.job_id,
                    'request_sha256': self.request_sha256}
        if (first['html_sha256'] != self.html_sha256
                or first['profile_sha256'] != RENDER_PROFILE_SHA256
                or second['resource_profile_sha256'] != NATIVE_SOURCE_PROFILE_SHA256
                or second['language'] != LANGUAGE
                or any(second[key] != value for key, value in identity.items())):
            raise ValueError('generated source stage identity disagreement')
        record = {
            'schema_version': '1.0.0', 'profile_id': PROFILE_ID,
            'status': 'GENERATED_CANDIDATE_AND_NATIVE_SOURCE_BOUND', **identity,
            'html_sha256': self.html_sha256, 'language': LANGUAGE,
            'resource_profile_sha256': self.resource_profile_sha256,
            'render_profile_sha256': RENDER_PROFILE_SHA256,
            'native_source_job_profile_sha256': NATIVE_SOURCE_PROFILE_SHA256,
            'render_sha256': self.expected_render_sha256,
            'native_inspection_sha256': self.expected_inspection_sha256,
            'rendered_candidate': first, 'native_inspection': second,
            'shared_input_bindings_verified': True,
            'normalized_text_equivalence_verified': second['normalized_text_equivalence_verified'],
            **native_source._nonclaims(),
            'authenticated_worker_execution': False,
            'hard_job_deadline_enforced': False, 'aggregate_job_resources_qualified': False,
            'default_pipeline_activated': False, 'release_authorized': False,
            'release_authorization': 'NOT_ESTABLISHED',
        }
        data = _json_bytes(record)
        if len(data) > MAX_RESULT_BYTES:
            raise ValueError('generated source result byte budget')
        return data

    def __post_init__(self) -> None:
        """Seal once without permitting altered retained evidence to be resealed."""
        try:
            digest = sha256(self._validated_bytes()).hexdigest()
            if hasattr(self, '_sealed_sha256') and digest != self._sealed_sha256:
                raise ValueError('generated source result changed')
            object.__setattr__(self, '_sealed_sha256', digest)
        except Exception:
            raise PdfGeneratedSourceJobError('pdf_generated_source_result_invalid') from None

    def to_bytes(self) -> bytes:
        """Expose only original sealed metadata, never source, HTML or candidate content."""
        try:
            data = self._validated_bytes()
            if sha256(data).hexdigest() != self._sealed_sha256:
                raise ValueError('generated source result changed')
            return data
        except Exception:
            raise PdfGeneratedSourceJobError('pdf_generated_source_result_invalid') from None

    def to_dict(self) -> dict:
        """Return detached content-free metadata after rechecking every retained seal."""
        return json.loads(self.to_bytes())

    @property
    def pdf_bytes(self) -> bytes:
        """Expose private successful candidate bytes only after complete result validation."""
        self.to_bytes()
        return self.rendered_candidate.pdf_bytes

    @property
    def pdf_sha256(self) -> str:
        """Identify the exact generated-and-inspected private candidate."""
        return self.to_dict()['pdf_sha256']

    @property
    def page_count(self) -> int:
        """Expose only the physical count agreed by both sealed stages."""
        return self.to_dict()['page_count']

    @property
    def result_sha256(self) -> str:
        """Identify unsigned result metadata, without claiming execution authentication."""
        return sha256(self.to_bytes()).hexdigest()


def _execute_pdf_generated_source_job(
    *, presentation_ir: object, expected_ir_sha256: str, expected_language: str,
    namespace_id: str, job_id: str, request_sha256: str,
    expected_resource_profile_sha256: str, observe_processes: bool,
    observe_raster_children: bool = False,
) -> tuple[PdfGeneratedSourceResult, dict | None]:
    """Generate one whole candidate and inspect those exact bytes, without retries.

    Only the existing captured semantic-section/en-US source is accepted. Native
    parsing stays in guarded children. The native inspector owns its launch
    scope; this bridge must not nest one. The 330-second post-admission check is
    an acceptance deadline, not preemption or aggregate resource qualification.
    Persistent source changes are detected; concurrent mutate-and-restore is
    unsupported. Failed stages return no successful result or candidate bytes.
    """
    try:
        require_no_active_scope()
        if (type(observe_processes) is not bool or type(observe_raster_children) is not bool
                or (observe_raster_children and not observe_processes)):
            raise ValueError('generated source observation mode')
        _profile(expected_resource_profile_sha256)
        if (type(expected_language) is not str or expected_language != LANGUAGE
                or type(namespace_id) is not str or type(job_id) is not str):
            raise ValueError('generated source input type or domain')
        _pin(expected_ir_sha256)
        _validate_context(namespace_id, job_id, request_sha256, expected_resource_profile_sha256)
        captured = _capture_adapter_ir(presentation_ir)
        if not _validate_ir(captured) or captured.get('locale_id') != LANGUAGE:
            raise ValueError('generated source contract not supported')
        source_bytes = _json_bytes(captured)
        ir_digest, expected_text = _expected_content(captured)
        if ir_digest != expected_ir_sha256:
            raise ValueError('generated source identity mismatch')
        started = previous = monotonic_ns()
        if type(started) is not int or started < 0:
            raise ValueError('generated source clock invalid')
    except Exception:
        raise PdfGeneratedSourceJobError('pdf_generated_source_job_input_invalid') from None

    def check() -> None:
        """Recheck policies and both bounded source views before accepting each stage."""
        nonlocal previous
        _profile(expected_resource_profile_sha256)
        if (_json_bytes(_capture_adapter_ir(presentation_ir)) != source_bytes
                or _json_bytes(_capture_adapter_ir(captured)) != source_bytes):
            raise ValueError('generated source changed')
        current = monotonic_ns()
        if (type(current) is not int or current < previous
                or current - started >= ACCEPTANCE_NS):
            raise ValueError('generated source acceptance deadline')
        previous = current

    try:
        check()
        html, html_digest, _components = _semantic_html(captured)
        render_observation = native_observation = None
        if observe_processes:
            rendered, render_observation = _render_pdf_candidate(html, html_digest, observe_processes=True)
        else:
            rendered = render_pdf_candidate(html, html_digest)
        check()
        if type(rendered) is not PdfRenderedCandidate:
            raise ValueError('generated render result type')
        render_digest = rendered.result_sha256
        if rendered.html_sha256 != html_digest:
            raise ValueError('generated render HTML mismatch')
        pdf = rendered.pdf_bytes
        plan = plan_pdf_page_windows(
            pdf_sha256=rendered.pdf_sha256, ir_sha256=expected_ir_sha256,
            page_count=rendered.page_count, admitted_page_budget=rendered.page_count,
            pages_per_window=legacy.TEXT_WIDTH, inspector_profile_id=legacy.TEXT_PROFILE,
        )
        plan_digest = plan.plan_sha256
        inspector = (native_source.execute_raster_observed_pdf_native_source_job if observe_raster_children
                     else native_source.execute_observed_pdf_native_source_job
                     if observe_processes else execute_pdf_native_source_job)
        inspected = inspector(
            presentation_ir=captured, pdf_bytes=pdf, expected_pdf_sha256=rendered.pdf_sha256,
            expected_ir_sha256=expected_ir_sha256, page_count=rendered.page_count,
            expected_language=LANGUAGE, namespace_id=namespace_id, job_id=job_id,
            request_sha256=request_sha256, expected_resource_profile_sha256=NATIVE_SOURCE_PROFILE_SHA256,
        )
        if observe_processes:
            if type(inspected) is not tuple or len(inspected) != 2:
                raise ValueError('generated native observation pair')
            inspected, native_observation = inspected
        raster_ledger = None
        if observe_raster_children:
            from reporting._pdf_raster_job_observation import validate_native
            nested = validate_native(inspected, native_observation)
            native_observation = nested['direct_observation']
            raster_ledger = nested['raster_child_ledger']
        check()
        if type(inspected) is not PdfNativeSourceResult or rendered.result_sha256 != render_digest:
            raise ValueError('generated source child type or mutation')
        result = PdfGeneratedSourceResult(
            rendered_candidate=rendered, native_inspection=inspected,
            expected_render_sha256=render_digest, expected_inspection_sha256=inspected.inspection_sha256,
            expected_text_sha256=expected_text, ir_sha256=expected_ir_sha256,
            html_sha256=html_digest, plan_sha256=plan_digest, namespace_id=namespace_id,
            job_id=job_id, request_sha256=request_sha256,
            resource_profile_sha256=expected_resource_profile_sha256,
        )
        result.to_bytes()
        check()
        observation = (_generated_process_observation(result, render_observation, native_observation)
                       if observe_processes else None)
        if observe_raster_children:
            from reporting._pdf_raster_job_observation import compose_generated
            observation = compose_generated(result, observation, raster_ledger)
        if observe_processes:
            check()
            if result.result_sha256 != observation['generated_result_sha256']:
                raise ValueError('generated observed result changed')
        return result, observation
    except Exception:
        raise PdfGeneratedSourceJobError('pdf_generated_source_job_execution_failed') from None


def _generated_process_observation(result: PdfGeneratedSourceResult, render: dict,
                                   native: dict) -> dict:
    """Bind unsigned direct renderer/inspector data without promoting reservations.

    Each upstream observation is internally produced, never caller supplied.
    Digests and identity checks establish consistency, not authentication or
    protection against hostile code in the parent process.
    """
    def verify_digest(record, field):
        """Reject malformed or changed descriptive metadata before composition."""
        if type(record) is not dict:
            raise ValueError('generated observation type')
        digest = record.get(field)
        _pin(digest)
        if sha256(_json_bytes({k: v for k, v in record.items() if k != field})).hexdigest() != digest:
            raise ValueError('generated observation digest')

    result_bytes = result.to_bytes()
    verify_digest(render, 'observation_sha256')
    verify_digest(native, 'observation_sha256')
    if (len(_json_bytes(native)) > native_source.MAX_OBSERVATION_BYTES
            or native.get('schema') != native_source.OBSERVATION_SCHEMA
            or native.get('state') != 'COMPLETE_DIRECT_INSPECTION_JOB_OBSERVED'
            or native.get('inspection_sha256') != result.expected_inspection_sha256
            or native.get('resource_profile_sha256') != NATIVE_SOURCE_PROFILE_SHA256):
        raise ValueError('generated native observation identity')
    for name in ('pdf_sha256', 'ir_sha256', 'plan_sha256', 'page_count',
                 'namespace_id', 'job_id', 'request_sha256'):
        if native.get(name) != getattr(result, name):
            raise ValueError('generated native observation binding')
    if (render.get('kind') != 'render' or render.get('worker') != '_pdf_render_worker.py'
            or render.get('parent_pid') != os.getpid() or type(render.get('pid')) is not int
            or render['pid'] <= 1 or type(render.get('exit_code')) is not int or render['exit_code'] != 0
            or render.get('render_sha256') != result.expected_render_sha256
            or render.get('profile_sha256') != RENDER_PROFILE_SHA256
            or render.get('html_sha256') != result.html_sha256
            or render.get('pdf_sha256') != result.pdf_sha256
            or render.get('page_count') != result.page_count
            or render.get('request_header_sha256') != sha256(f'2 {result.html_sha256}\n'.encode('ascii')).hexdigest()):
        raise ValueError('generated render observation binding')
    for name in ('spawn_monotonic_ns', 'exit_monotonic_ns'):
        if type(render.get(name)) is not int or render[name] < 0:
            raise ValueError('generated render observation clock')
    if render['exit_monotonic_ns'] < render['spawn_monotonic_ns']:
        raise ValueError('generated render observation clock order')
    _pin(render.get('worker_source_sha256'))
    ledger = native.get('direct_process_ledger')
    verify_digest(ledger, 'ledger_sha256')
    expected = 21 + (result.page_count + 15) // 16 + (result.page_count + 3) // 4
    rows = ledger.get('processes')
    if (type(rows) is not list or len(rows) != expected
            or any(type(ledger.get(name)) is not int or ledger[name] != expected
                   for name in ('observed_spawns', 'observed_exits'))
            or ledger.get('declared_retries') != 0):
        raise ValueError('generated direct process counts')
    for row in rows:
        if (type(row) is not dict or row.get('parent_pid') != render['parent_pid']
                or type(row.get('pid')) is not int or row['pid'] <= 1
                or type(row.get('exit_code')) is not int or row['exit_code'] != 0
                or type(row.get('spawn_monotonic_ns')) is not int
                or row['spawn_monotonic_ns'] < render['exit_monotonic_ns']
                or any(row.get(name) != getattr(result, name)
                       for name in ('pdf_sha256', 'ir_sha256', 'page_count'))):
            raise ValueError('generated direct process identity')
    value = {
        'schema': OBSERVATION_SCHEMA, 'state': 'DIRECT_GENERATED_JOB_PROCESSES_OBSERVED',
        'generated_result_sha256': sha256(result_bytes).hexdigest(),
        **{name: getattr(result, name) for name in (
            'pdf_sha256', 'ir_sha256', 'html_sha256', 'plan_sha256', 'page_count',
            'namespace_id', 'job_id', 'request_sha256', 'resource_profile_sha256',
        )},
        'render_process': render, 'native_observation': native,
        'observed_direct_spawns': expected + 1, 'observed_direct_exits': expected + 1,
        'declared_retries': 0, 'render_direct_child_observed': True,
        'nested_processes_observed': False, 'external_observer_measured': False,
        'whole_graph_observed': False, 'authenticated_worker_execution': False,
        'aggregate_job_resources_qualified': False, 'native_profile_qualified': False,
        'default_pipeline_activated': False, 'release_authorized': False,
    }
    value['observation_sha256'] = sha256(_json_bytes(value)).hexdigest()
    encoded = _json_bytes(value)
    if len(encoded) > MAX_OBSERVATION_BYTES:
        raise ValueError('generated process observation byte budget')
    return json.loads(encoded)


def execute_pdf_generated_source_job(
    *, presentation_ir: object, expected_ir_sha256: str, expected_language: str,
    namespace_id: str, job_id: str, request_sha256: str,
    expected_resource_profile_sha256: str,
) -> PdfGeneratedSourceResult:
    """Generate the unchanged private candidate without optional process recording."""
    result, _ = _execute_pdf_generated_source_job(
        presentation_ir=presentation_ir, expected_ir_sha256=expected_ir_sha256,
        expected_language=expected_language, namespace_id=namespace_id, job_id=job_id,
        request_sha256=request_sha256,
        expected_resource_profile_sha256=expected_resource_profile_sha256,
        observe_processes=False,
    )
    return result


def execute_observed_pdf_generated_source_job(
    *, presentation_ir: object, expected_ir_sha256: str, expected_language: str,
    namespace_id: str, job_id: str, request_sha256: str,
    expected_resource_profile_sha256: str,
) -> tuple[PdfGeneratedSourceResult, dict]:
    """Observe the direct renderer and inspectors of one unchanged generating job.

    Return the private candidate and a bounded detached observation only after
    actual owned-child completion and final source/policy checks. No caller
    callback, worker, receipt or budget is admitted. Failures return no partial
    pair. Nested helpers, external-observer costs, whole-graph enforcement and
    release remain unqualified. No service, tracing, privilege, persistent
    storage, retry or default behavior is activated.
    """
    result, observation = _execute_pdf_generated_source_job(
        presentation_ir=presentation_ir, expected_ir_sha256=expected_ir_sha256,
        expected_language=expected_language, namespace_id=namespace_id, job_id=job_id,
        request_sha256=request_sha256,
        expected_resource_profile_sha256=expected_resource_profile_sha256,
        observe_processes=True,
    )
    if observation is None:
        raise PdfGeneratedSourceJobError('pdf_generated_source_job_execution_failed')
    return result, observation


def execute_raster_observed_pdf_generated_source_job(
    *, presentation_ir: object, expected_ir_sha256: str, expected_language: str,
    namespace_id: str, job_id: str, request_sha256: str,
    expected_resource_profile_sha256: str,
) -> tuple[PdfGeneratedSourceResult, dict]:
    """Generate once and bind actual raster children to that same complete result.

    The optional envelope links the original direct renderer/inspector record
    and fixed raster probe/page children. No rerender, tracer, helper timer,
    service, privilege or default activation is added. Arbitrary descendants,
    external observer costs, aggregate enforcement and release stay unqualified.
    """
    result, observation = _execute_pdf_generated_source_job(
        presentation_ir=presentation_ir, expected_ir_sha256=expected_ir_sha256,
        expected_language=expected_language, namespace_id=namespace_id, job_id=job_id,
        request_sha256=request_sha256,
        expected_resource_profile_sha256=expected_resource_profile_sha256,
        observe_processes=True, observe_raster_children=True,
    )
    if observation is None:
        raise PdfGeneratedSourceJobError('pdf_generated_source_job_execution_failed')
    return result, observation
