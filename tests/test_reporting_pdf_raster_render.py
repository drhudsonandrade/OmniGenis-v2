"""The optional raster renderer keeps the original renderer modes unchanged."""
from importlib import util, import_module
from hashlib import sha256
import unittest
from unittest.mock import patch


class RasterRenderAdmissionTests(unittest.TestCase):
    def setUp(self):
        """Require the explicit operation instead of silently using legacy rendering."""
        self.assertIsNotNone(util.find_spec('reporting.pdf_raster_render'), 'explicit preloaded PNG render operation missing')
        self.m = import_module('reporting.pdf_raster_render')

    def test_original_renderer_profiles_are_preserved(self):
        """The new opt-in route leaves old protocol and resource values intact."""
        from reporting import _pdf_render_worker as w
        self.assertEqual(w.PROTOCOL_VERSION, 1); self.assertEqual(w.NATIVE_PROTOCOL_VERSION, 2)
        self.assertEqual(w.PDF_BYTES, 8 * 1024 * 1024); self.assertEqual(w.NATIVE_PDF_BYTES, 16 * 1024 * 1024)
        self.assertEqual(w.CPU_SECONDS, 20); self.assertEqual(w.WALL_SECONDS, 30)

    def test_disabled_mode_rejects_before_launch(self):
        """Absent qualification selection consumes no renderer process."""
        from reporting import adapters
        with patch.dict('os.environ', {}, clear=True), patch.object(adapters, '_start_pdf_render_worker') as launch:
            with self.assertRaises(self.m.RasterRenderError):
                self.m.render_preloaded_raster_pdf(html='<p>test</p>', expected_html_sha256='a' * 64,
                    resources=None, expected_resources_sha256='b' * 64)
            launch.assert_not_called()


class RasterNativeTests(unittest.TestCase):
    def setUp(self):
        """Enable only the explicit qualification route for a single synthetic PNG."""
        import os
        from reporting import pdf_raster_render, pdf_raster_resources
        from tests.test_reporting_pdf_raster_resources import png
        self.m = pdf_raster_render; self.resources = pdf_raster_resources
        raw = png(); self.bundle = self.resources.RasterBundle((self.resources.RasterAsset(
            'synthetic-raster', raw, sha256(raw).hexdigest(), 2, 2, 'a' * 64, 'b' * 64),))
        self.env = patch.dict(os.environ, {'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE': 'qualification-only'})
        self.env.start(); self.addCleanup(self.env.stop)
        for key in ('OMNIGENIS_PDF_PRELOADED_RASTER_DISABLED', 'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED',
                    'OMNIGENIS_PDF_RENDERER_DISABLED'):
            os.environ.pop(key, None)

    def html(self, image=True, uri=None):
        """Use fixed compiler-like HTML and explicit decorative PNG references."""
        resource = self.bundle.assets[0].uri if uri is None else uri
        return ('<!doctype html><html lang="en-US"><head><meta charset="utf-8">'
                '<title>OmniGenis</title><meta name="author" content="Hudson Silva Andrade">'
                '<style>body{font-family:Lato}</style>'
                '</head><body><h1>Synthetic resource qualification</h1><p>Exact source text.</p>'
                + (f'<img src="{resource}" alt="" role="presentation" width="64" height="64">' if image else '')
                + '</body></html>')

    def render(self, html):
        """Invoke the real client and original subprocess lifecycle, never a mock renderer."""
        return self.m.render_preloaded_raster_pdf(html=html,
            expected_html_sha256=sha256(html.encode()).hexdigest(), resources=self.bundle,
            expected_resources_sha256=self.bundle.bundle_sha256)

    def test_real_preloaded_png_renders_without_external_fetch(self):
        """Actual confined rendering consumes the exact resource and returns one intact PDF."""
        try:
            result = self.render(self.html())
        except self.m.RasterRenderError as exc:
            self.fail('real preloaded raster render unavailable: ' + str(exc))
        self.assertEqual(result.page_count, 1)
        self.assertTrue(result.pdf_bytes.startswith(b'%PDF-1.7'))
        self.assertEqual(result.resources_sha256, self.bundle.bundle_sha256)
        self.assertEqual(result.pdf_sha256, sha256(result.pdf_bytes).hexdigest())
        self.assertFalse(result.to_dict()['release_authorized'])

    def test_unused_resource_is_not_successful_rendering(self):
        """A PNG cannot inflate the resource bundle without being requested by rendering."""
        with self.assertRaises(self.m.RasterRenderError): self.render(self.html(image=False))

    def test_real_external_resource_request_is_denied(self):
        """No file/network/data fallback is available to the new native mode."""
        for uri in ('file:///etc/passwd', 'https://example.invalid/image.png', 'data:image/png;base64,AA=='):
            with self.subTest(uri=uri), self.assertRaises(self.m.RasterRenderError): self.render(self.html(uri=uri))


class LargeRasterGenerationTests(unittest.TestCase):
    """Use the actual product entrypoint, not a patched renderer or edited final PDF."""
    actual = None

    @classmethod
    def generate(cls):
        """Create owned, visible deterministic raster inputs before normal serialization."""
        if cls.actual is not None:
            return cls.actual
        import json
        import struct
        import zlib
        from hashlib import shake_256
        from reporting import adapters, pdf_raster_render as render, pdf_raster_resources as resources
        from tests.test_reporting_pdf_generated_source_job import source
        size = 1024
        assets = []
        def chunk(kind, data):
            """Encode one synthetic PNG chunk with its independent length and CRC."""
            return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 0xffffffff)
        for index in range(3):
            specification = ('owned-synthetic-rgb-render-qualification-v1:' + str(index)).encode()
            pixels = shake_256(specification).digest(size * size * 3)
            scanlines = b''.join(b'\0' + pixels[row * size * 3:(row + 1) * size * 3] for row in range(size))
            raw = (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', size, size, 8, 2, 0, 0, 0))
                   + chunk(b'IDAT', zlib.compress(scanlines)) + chunk(b'IEND', b''))
            assets.append(resources.RasterAsset('synthetic-raster-' + str(index), raw,
                sha256(raw).hexdigest(), size, size, sha256(specification).hexdigest(),
                sha256(b'OWNED_DETERMINISTIC_SYNTHETIC_QUALIFICATION_DATA_NO_THIRD_PARTY_CONTENT').hexdigest()))
        bundle = resources.RasterBundle(tuple(assets))
        ir = source(1680)
        ir['qualification_resource_bundle_sha256'] = bundle.bundle_sha256
        for index, asset in enumerate(assets):
            ir['components'].append({'component_id': 'raster-qualification-' + str(index),
                'component_type': 'semantic-section', 'title': 'Synthetic raster qualification ' + str(index + 1),
                'state': 'PRESENT', 'content': {'purpose': 'Decorative rendering qualification only; no scientific measurement.',
                    'resource_sha256': asset.expected_sha256, 'source_sha256': asset.source_sha256,
                    'rights_sha256': asset.rights_sha256, 'width_px': 1024, 'height_px': 1024}})
        before = json.dumps(ir, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
        html, _, _ = adapters._semantic_html(ir)
        for index, asset in enumerate(assets):
            marker = '<section data-component="raster-qualification-' + str(index) + '">'
            style = ('break-before:page;min-height:750px;background-repeat:no-repeat;'
                     'background-position:center bottom;background-size:512px 512px;'
                     "background-image:url('" + asset.uri + "')")
            assert html.count(marker) == 1
            html = html.replace(marker, marker[:-1] + ' style="' + style + '">')
        with patch.dict('os.environ', {'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE': 'qualification-only'}):
            result = render.render_preloaded_raster_pdf(html=html,
                expected_html_sha256=sha256(html.encode()).hexdigest(), resources=bundle,
                expected_resources_sha256=bundle.bundle_sha256)
        assert before == json.dumps(ir, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
        cls.actual = ir, html, bundle, result
        return cls.actual

    def test_actual_complete_generation_exceeds_both_thresholds(self):
        """The ordinary resource-input path produces one large PDF with visible source images."""
        import json
        from io import BytesIO
        from pypdf import PdfReader
        from pypdf.generic import ContentStream
        from hashlib import shake_256
        ir, html, bundle, result = self.generate()
        raw = result.pdf_bytes
        self.assertGreater(result.page_count, 32); self.assertLessEqual(result.page_count, 64)
        self.assertGreater(len(raw), 8 * 1024 * 1024); self.assertLessEqual(len(raw), 16 * 1024 * 1024)
        self.assertEqual(raw.count(b'startxref'), 1); self.assertEqual(raw.count(b'%%EOF'), 1)
        reader = PdfReader(BytesIO(raw), strict=True); self.assertEqual(len(reader.pages), result.page_count)
        expected = {sha256(shake_256(('owned-synthetic-rgb-render-qualification-v1:' + str(i)).encode())
                    .digest(1024 * 1024 * 3)).hexdigest() for i in range(3)}
        painted = set()
        image_uses = 0
        for page in reader.pages:
            pending = [(page.get_contents(), page['/Resources'], 0)]
            while pending:
                stream, page_resources, depth = pending.pop()
                self.assertLess(depth, 8, 'synthetic paint traversal exceeded its finite bound')
                xobjects = page_resources.get('/XObject', {})
                xobjects = xobjects.get_object() if hasattr(xobjects, 'get_object') else xobjects
                for args, operator in ContentStream(stream, reader).operations:
                    if operator != b'Do':
                        continue
                    image = xobjects[args[0]].get_object()
                    if image.get('/Subtype') == '/Form':
                        pending.append((image, image['/Resources'], depth + 1))
                        continue
                    self.assertEqual(image.get('/Subtype'), '/Image')
                    self.assertEqual((image['/Width'], image['/Height']), (1024, 1024))
                    image_uses += 1
                    self.assertLessEqual(image_uses, 3)
                    painted.add(sha256(image.get_data()).hexdigest())
        self.assertEqual(image_uses, 3)
        self.assertEqual(painted, expected)
        self.assertEqual(result.resources_sha256, bundle.bundle_sha256)
        self.assertEqual(result.html_sha256, sha256(html.encode()).hexdigest())
        print(json.dumps({'actual_generated_pages': result.page_count, 'pdf_bytes': len(raw),
            'pdf_sha256': result.pdf_sha256, 'painted_exact_resource_count': len(painted),
            'renderer_patched': False, 'pdf_rewritten': False, 'release_authorized': False}), flush=True)

    def test_same_generated_large_pdf_passes_full_native_source_inspection(self):
        """All native pages and global structures belong to the same genuine generated file."""
        from reporting import pdf_native_source_job as native
        from reporting.pdf_content import _expected_content
        ir, html, bundle, result = self.generate()
        before = result.pdf_bytes
        inspected = native.execute_pdf_native_source_job(presentation_ir=ir, pdf_bytes=before,
            expected_pdf_sha256=result.pdf_sha256, expected_ir_sha256=_expected_content(ir)[0],
            page_count=result.page_count, expected_language='en-US', namespace_id='synthetic-raster-qualification',
            job_id='synthetic-large-raster', request_sha256='d' * 64,
            expected_resource_profile_sha256=native.PROFILE_SHA256)
        data = inspected.to_dict()
        self.assertEqual(data['pdf_sha256'], result.pdf_sha256)
        self.assertEqual(data['page_count'], result.page_count)
        self.assertTrue(data['normalized_text_equivalence_verified'])
        self.assertFalse(data['release_authorized'])
        self.assertEqual(result.pdf_bytes, before)


class RasterResponseTypeTests(unittest.TestCase):
    """Equal-looking numbers never substitute for exact child resource-limit types."""
    def test_limit_types_are_exact_native_integers(self):
        """A floating-point limit cannot satisfy the integer-only response contract."""
        import json
        import tempfile
        from reporting import pdf_raster_render as render
        from reporting import _pdf_render_worker as worker
        raw = b'%PDF-1.7\nsynthetic-protocol-fixture'
        limits = {'memory_bytes': worker.MEMORY_BYTES, 'cpu_seconds': worker.CPU_SECONDS,
                  'file_bytes': worker.NATIVE_PDF_BYTES, 'open_files': worker.OPEN_FILES}
        record = {'protocol_version': 3, 'profile_id': render.PROFILE_ID,
            'profile_sha256': render.profile_sha256(), 'status': 'PASS', 'pdf_bytes': len(raw),
            'pdf_sha256': sha256(raw).hexdigest(), 'limits': limits, 'html_sha256': 'a' * 64,
            'page_count': 1, 'resources_sha256': 'b' * 64, 'resource_count': 1}
        with tempfile.TemporaryFile() as output:
            output.write(raw); output.flush()
            for key in limits:
                changed = {**record, 'limits': {**limits, key: float(limits[key])}}
                with self.subTest(field=key), self.assertRaises(render.RasterRenderError):
                    render._decode(json.dumps(changed).encode(), output.fileno(), 'a' * 64, 'b' * 64, 1)


class RasterProtocolAdversarialTests(unittest.TestCase):
    """Bind actual descriptor bytes to strict response and request metadata."""
    def setUp(self):
        """Use a deterministic protocol fixture, not a qualified PDF or mocked success."""
        import tempfile
        from reporting import pdf_raster_render as render
        from reporting import _pdf_render_worker as worker
        self.m = render; self.worker = worker; self.raw = b'%PDF-1.7\nsynthetic-wire-only'
        self.output = tempfile.TemporaryFile(); self.addCleanup(self.output.close)
        self.output.write(self.raw); self.output.flush()
        self.record = {'protocol_version': 3, 'profile_id': render.PROFILE_ID,
            'profile_sha256': render.profile_sha256(), 'status': 'PASS', 'pdf_bytes': len(self.raw),
            'pdf_sha256': sha256(self.raw).hexdigest(), 'limits': {
                'memory_bytes': worker.MEMORY_BYTES, 'cpu_seconds': worker.CPU_SECONDS,
                'file_bytes': worker.NATIVE_PDF_BYTES, 'open_files': worker.OPEN_FILES},
            'html_sha256': 'a' * 64, 'page_count': 1, 'resources_sha256': 'b' * 64, 'resource_count': 1}

    def decode(self, record):
        """Call the same exact decoder used after the real child exits successfully."""
        import json
        return self.m._decode(json.dumps(record).encode(), self.output.fileno(), 'a' * 64, 'b' * 64, 1)

    def test_complete_wire_roundtrip_and_retained_mutation(self):
        """The result seal is consistency only, and detects changed retained payloads."""
        result = self.decode(self.record); self.assertEqual(result.pdf_bytes, self.raw)
        object.__setattr__(result, 'resources_sha256', 'c' * 64)
        with self.assertRaises(self.m.RasterRenderError): result.to_dict()

    def test_closed_fields_and_noninteger_counts_refuse(self):
        """Protocol identity and all count types remain closed and exact."""
        from copy import deepcopy
        changes = ({'extra': 1}, {'protocol_version': True}, {'protocol_version': 2},
            {'status': 'FAIL'}, {'profile_id': 'other'}, {'profile_sha256': '0' * 64},
            {'pdf_bytes': True}, {'pdf_bytes': len(self.raw) + 1}, {'pdf_sha256': '0' * 64},
            {'html_sha256': 'c' * 64}, {'resources_sha256': 'c' * 64}, {'resource_count': True},
            {'resource_count': 2}, {'page_count': True}, {'page_count': 0}, {'page_count': 65},
            {'page_count': 1.0}, {'limits': []}, {'limits': {}})
        for change in changes:
            record = deepcopy(self.record); record.update(change)
            with self.subTest(field=next(iter(change))), self.assertRaises(self.m.RasterRenderError): self.decode(record)
        for key in self.record:
            record = deepcopy(self.record); del record[key]
            with self.subTest(missing=key), self.assertRaises(self.m.RasterRenderError): self.decode(record)

    def test_duplicate_json_and_nonfinite_response_refuse(self):
        """Duplicate keys and nonfinite values never form an accepted child response."""
        import json
        raw = json.dumps(self.record).encode()
        for altered in (raw[:-1] + b',"status":"PASS"}', b'NaN', raw.replace(b'"page_count": 1', b'"page_count": NaN')):
            with self.assertRaises((self.m.RasterRenderError, ValueError)):
                self.m._decode(altered, self.output.fileno(), 'a' * 64, 'b' * 64, 1)

    def test_forged_output_size_and_hash_refuse(self):
        """A previously valid response cannot authenticate different output bytes."""
        import os
        os.ftruncate(self.output.fileno(), 2)
        with self.assertRaises(self.m.RasterRenderError): self.decode(self.record)

    def test_disable_and_wrong_input_hash_precede_child_creation(self):
        """Invalid inputs or current disable flags refuse before any child starts."""
        import os
        from reporting import adapters, pdf_raster_resources
        from tests.test_reporting_pdf_raster_resources import png
        raw = png(); bundle = pdf_raster_resources.RasterBundle((pdf_raster_resources.RasterAsset(
            'fixture', raw, sha256(raw).hexdigest(), 2, 2, 'c' * 64, 'd' * 64),))
        with patch.dict(os.environ, {'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE': 'qualification-only'}), \
                patch.object(adapters, '_start_pdf_render_worker') as launch:
            for flag in ('OMNIGENIS_PDF_PRELOADED_RASTER_DISABLED',
                         'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED', 'OMNIGENIS_PDF_RENDERER_DISABLED'):
                with patch.dict(os.environ, {flag: '1'}), self.assertRaises(self.m.RasterRenderError):
                    self.m.render_preloaded_raster_pdf(html='test', expected_html_sha256=sha256(b'test').hexdigest(),
                        resources=bundle, expected_resources_sha256=bundle.bundle_sha256)
            for html_sha, bundle_sha in (('0' * 64, bundle.bundle_sha256), (sha256(b'test').hexdigest(), '0' * 64)):
                with self.assertRaises(self.m.RasterRenderError):
                    self.m.render_preloaded_raster_pdf(html='test', expected_html_sha256=html_sha,
                        resources=bundle, expected_resources_sha256=bundle_sha)
            launch.assert_not_called()

    def test_profile_budget_drift_refuses(self):
        """Changing optional parent limits cannot retain the pinned profile identity."""
        for key in ('NATIVE_MAX_PAGES', 'NATIVE_PDF_BYTES', 'WALL_SECONDS', 'CPU_SECONDS'):
            with patch.object(self.worker, key, getattr(self.worker, key) + 1), self.assertRaises(self.m.RasterRenderError):
                self.m.profile_sha256()


class RasterFailureProtocolTests(unittest.TestCase):
    """Denied raster fetches keep their typed failure envelope without broad catches."""
    setUp = RasterNativeTests.setUp
    html = RasterNativeTests.html

    def worker_failure(self, uri):
        """Launch the real guarded worker and inspect only its anonymous response files."""
        import os
        import sys
        import tempfile
        from pathlib import Path
        from reporting import adapters, _pdf_render_worker as worker
        html = self.html(uri=uri).encode('utf-8')
        with (tempfile.TemporaryFile() as request, tempfile.TemporaryFile() as output,
              tempfile.TemporaryFile() as response, tempfile.TemporaryFile() as resources):
            fds = tuple(f.fileno() for f in (request, output, response, resources))
            header = f'3 {sha256(html).hexdigest()} {self.bundle.bundle_sha256}\n'.encode('ascii')
            request.write(header + html); request.flush(); request.seek(0)
            resources.write(self.bundle.to_bytes()); resources.flush(); resources.seek(0)
            env = {k: os.environ[k] for k in ('PATH', 'HOME', 'LANG', 'LC_ALL', 'LC_CTYPE',
                'TZ', 'FONTCONFIG_FILE', 'FONTCONFIG_PATH') if k in os.environ}
            env.update(SOURCE_DATE_EPOCH='0', OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE='qualification-only')
            command = [sys.executable, '-I', '-B', str(Path(worker.__file__).resolve()),
                *(str(fd) for fd in fds[:3]), str(os.getpid()), self.m.MODE, str(fds[3])]
            child = adapters._start_pdf_render_worker(command, env=env, pass_fds=fds)
            code = adapters._wait_pdf_render_worker(child, wall_seconds=worker.WALL_SECONDS)
            response.seek(0)
            return code, os.fstat(output.fileno()).st_size, response.read(worker.RESULT_BYTES + 1)

    def test_denied_urls_return_version_three_failure_record_without_pdf(self):
        """File, network and data URI refusals produce a complete FAIL record and no PDF."""
        import json
        from reporting import _pdf_render_worker as worker
        for uri in ('file:///etc/passwd', 'https://example.invalid/image.png', 'data:image/png;base64,AA=='):
            with self.subTest(uri=uri):
                code, output_size, raw = self.worker_failure(uri)
                self.assertEqual(output_size, 0)
                self.assertEqual(code, 0, 'denied raster URL escaped without its failure envelope')
                record = json.loads(raw)
                self.assertEqual(record, {'protocol_version': 3, 'profile_id': self.m.PROFILE_ID,
                    'profile_sha256': self.m.profile_sha256(), 'status': 'FAIL', 'error': 'pdf_render_failed',
                    'limits': {'memory_bytes': worker.MEMORY_BYTES, 'cpu_seconds': worker.CPU_SECONDS,
                        'file_bytes': worker.NATIVE_PDF_BYTES, 'open_files': worker.OPEN_FILES}})

    def test_legacy_fatal_fetch_propagation_is_preserved(self):
        """The opt-in failure record fix does not change legacy URL-refusal behavior."""
        record = self.isolated_exception('FatalURLFetchingError', resources=False)
        self.assertEqual(record, {
            'schema': 'renderer-exception-test-v1',
            'exception': 'FatalURLFetchingError', 'write_pdf_calls': 1,
        })

    def test_process_control_base_exceptions_are_not_swallowed(self):
        """Only the named fetch failure is handled; interrupts and process exits still escape."""
        for resources in (False, True):
            for exception in ('KeyboardInterrupt', 'SystemExit'):
                with self.subTest(resources=resources, exception=exception):
                    record = self.isolated_exception(exception, resources=resources)
                    self.assertEqual(record, {
                        'schema': 'renderer-exception-test-v1',
                        'exception': exception, 'write_pdf_calls': 1,
                    })

    def isolated_exception(self, exception, *, resources):
        """Observe the exact exception outside main in a fresh fully guarded child."""
        import json
        import os
        from pathlib import Path
        import sys
        import tempfile
        from reporting import adapters, _pdf_render_worker as worker

        child_code = r'''
import builtins
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(sys.argv[1]).resolve()))
from reporting import _pdf_render_worker as worker

expected = sys.argv[2]
has_resources = sys.argv[3] == '1'
fds = tuple(map(int, sys.argv[4:-1]))
parent = int(sys.argv[-1])
assert len(fds) == (4 if has_resources else 3)
assert not any(name == 'weasyprint' or name.startswith('weasyprint.')
               for name in sys.modules)
injected = {'KeyboardInterrupt': KeyboardInterrupt(), 'SystemExit': SystemExit(17)}.get(expected)
original_import = builtins.__import__
patched = False
calls = 0
original_write_pdf = None

def observed_write_pdf(*args, **kwargs):
    global calls
    calls += 1
    if injected is not None:
        raise injected
    return original_write_pdf(*args, **kwargs)

def delayed_observer(name, *args, **kwargs):
    global patched, original_write_pdf
    result = original_import(name, *args, **kwargs)
    module = sys.modules.get('weasyprint')
    html_type = getattr(module, 'HTML', None)
    if not patched and html_type is not None:
        original_write_pdf = html_type.write_pdf
        html_type.write_pdf = observed_write_pdf
        patched = True
    return result

argv = [str(Path(worker.__file__).resolve()),
        *(str(fd) for fd in fds[:3]), str(parent)]
if has_resources:
    argv.extend((worker.RASTER_MODE, str(fds[3])))
observed = None
builtins.__import__ = delayed_observer
try:
    try:
        worker.main(argv)
    except BaseException as error:
        observed = error
finally:
    builtins.__import__ = original_import
assert patched and calls == 1, 'actual write_pdf boundary was not reached once'
if injected is not None:
    assert observed is injected, 'the injected cancellation did not propagate'
else:
    urls = sys.modules.get('weasyprint.urls')
    fatal = getattr(urls, 'FatalURLFetchingError', None)
    assert fatal is not None and type(observed) is fatal, 'a different failure cannot satisfy URL refusal'
assert os.fstat(fds[1]).st_size == 0 and os.fstat(fds[2]).st_size == 0
# This is test observation after an escaped exception, never a product receipt.
worker._write_result(fds[2], {'schema': 'renderer-exception-test-v1',
    'exception': type(observed).__name__, 'write_pdf_calls': calls})
'''
        html = self.html(uri='file:///etc/passwd' if exception == 'FatalURLFetchingError' else None)
        encoded = html.encode('utf-8')
        with (tempfile.TemporaryFile() as request, tempfile.TemporaryFile() as output,
              tempfile.TemporaryFile() as response, tempfile.TemporaryFile() as resource_file):
            fds = tuple(f.fileno() for f in (request, output, response))
            digest = sha256(encoded).hexdigest()
            if resources:
                header = f'3 {digest} {self.bundle.bundle_sha256}\n'
                resource_file.write(self.bundle.to_bytes())
                resource_file.flush()
                resource_file.seek(0)
                fds += (resource_file.fileno(),)
            else:
                header = f'1 {digest}\n'
            request.write(header.encode('ascii') + encoded)
            request.flush()
            request.seek(0)
            env = {key: os.environ[key] for key in (
                'PATH', 'HOME', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TZ',
                'FONTCONFIG_FILE', 'FONTCONFIG_PATH',
            ) if key in os.environ}
            env.update(SOURCE_DATE_EPOCH='0', OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE='qualification-only')
            command = [sys.executable, '-I', '-B', '-c', child_code,
                       str(Path(worker.__file__).resolve().parents[1]),
                       exception, '1' if resources else '0',
                       *(str(fd) for fd in fds), str(os.getpid())]
            child = adapters._start_pdf_render_worker(command, env=env, pass_fds=fds)
            code = adapters._wait_pdf_render_worker(child, wall_seconds=worker.WALL_SECONDS)
            self.assertEqual(code, 0, 'guarded child did not observe the exact requested exception')
            self.assertEqual(os.fstat(output.fileno()).st_size, 0)
            self.assertLessEqual(os.fstat(response.fileno()).st_size, worker.RESULT_BYTES)
            response.seek(0)
            return json.loads(response.read(worker.RESULT_BYTES + 1))


if __name__ == '__main__': unittest.main()
