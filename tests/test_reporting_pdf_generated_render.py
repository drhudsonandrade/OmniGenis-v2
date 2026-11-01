"""Keep optional physical-page rendering separate from the legacy PDF wire."""
from __future__ import annotations

from hashlib import sha256
import importlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from reporting import adapters


ROOT = Path(__file__).resolve().parents[1]
PROFILE_ID = "generated-native-source-render-v1"


def html_pages(count):
    """Produce explicit synthetic pages without external resources or PDF padding."""
    return ('<!doctype html><html lang="en-US"><head><title>OmniGenis</title>'
            '<meta name="author" content="Hudson Silva Andrade">'
            '<meta name="generator" content="OmniGenis">'
            '<style>section+section{break-before:page}</style></head><body>'
            + ''.join(f'<section>Physical page {number:03d}</section>'
                      for number in range(1, count + 1)) + '</body></html>')


class GeneratedRenderTests(unittest.TestCase):
    """The selected protocol alone changes the finite output class and page discovery."""

    def bridge(self):
        """Fail an assertion, not an import error, until the boundary exists."""
        self.assertIsNotNone(importlib.util.find_spec("reporting.pdf_generated_source_job"),
                             "optional generated candidate transport is missing")
        return importlib.import_module("reporting.pdf_generated_source_job")

    def run_worker(self, html, *, version=2, mode="native-source-v1", digest=None):
        """Launch the real guarded child with anonymous, bounded protocol storage."""
        digest = sha256(html.encode()).hexdigest() if digest is None else digest
        with (tempfile.TemporaryFile() as request, tempfile.TemporaryFile() as candidate,
              tempfile.TemporaryFile() as result):
            request.write(f"{version} {digest}\n".encode("ascii") + html.encode())
            request.flush()
            fds = (request.fileno(), candidate.fileno(), result.fileno())
            command = [sys.executable, "-I", "-B", str(ROOT / 'reporting/_pdf_render_worker.py'),
                       *(str(fd) for fd in fds), str(os.getpid())]
            if mode is not None:
                command.append(mode)
            process = adapters._start_pdf_render_worker(command, env=os.environ.copy(), pass_fds=fds)
            code = adapters._wait_pdf_render_worker(process, wall_seconds=35)
            self.assertLessEqual(os.fstat(result.fileno()).st_size, 64 * 1024)
            result.seek(0)
            candidate.seek(0)
            return code, result.read(64 * 1024 + 1), candidate.read(16 * 1024 * 1024 + 1)

    def test_optional_worker_discovers_physical_pages_in_guarded_child(self):
        """Missing opt-in mode or an invented page count breaks this real fixture."""
        html = html_pages(2)
        code, raw, pdf = self.run_worker(html)
        self.assertEqual(code, 0, "closed optional render mode is unavailable")
        record = json.loads(raw)
        self.assertEqual(record['status'], 'PASS')
        self.assertEqual(record['protocol_version'], 2)
        self.assertEqual(record['profile_id'], PROFILE_ID)
        self.assertEqual(record['html_sha256'], sha256(html.encode()).hexdigest())
        self.assertEqual(record['page_count'], 2)
        self.assertEqual(record['pdf_bytes'], len(pdf))
        self.assertEqual(record['pdf_sha256'], sha256(pdf).hexdigest())
        self.assertEqual(record['limits'], {'memory_bytes': 1073741824, 'cpu_seconds': 20,
                                             'file_bytes': 16777216, 'open_files': 128})
        from io import BytesIO
        from pypdf import PdfReader
        self.assertEqual(len(PdfReader(BytesIO(pdf), strict=True).pages), 2)

    def test_sixty_four_pages_return_complete_bytes(self):
        """The selected profile must not truncate an admitted 64-page candidate."""
        code, raw, pdf = self.run_worker(html_pages(64))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(raw)['page_count'], 64)
        self.assertEqual(json.loads(raw)['pdf_sha256'], sha256(pdf).hexdigest())

    def test_sixty_five_pages_withhold_all_candidate_bytes(self):
        """A small PDF still cannot cross the optional 64-page ceiling."""
        code, raw, pdf = self.run_worker(html_pages(65))
        self.assertEqual(code, 0)
        record = json.loads(raw)
        self.assertEqual(record['status'], 'FAIL')
        self.assertEqual(record['error'], 'pdf_candidate_page_budget_exceeded')
        self.assertEqual(pdf, b'')

    def test_legacy_wire_and_rendered_bytes_stay_unchanged(self):
        """A protocol upgrade cannot silently replace the legacy schema or PDF content."""
        html = html_pages(1)
        legacy_code, legacy_raw, legacy_pdf = self.run_worker(html, version=1, mode=None)
        self.assertEqual(legacy_code, 0)
        legacy = json.loads(legacy_raw)
        self.assertEqual(set(legacy), {'protocol_version', 'status', 'pdf_bytes', 'pdf_sha256', 'limits'})
        self.assertEqual(legacy['protocol_version'], 1)
        self.assertEqual(legacy['limits']['file_bytes'], 8388608)
        code, raw, pdf = self.run_worker(html)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(raw)['status'], 'PASS')
        self.assertEqual(pdf, legacy_pdf)

    def test_protocol_crossing_or_unknown_sentinel_cannot_render(self):
        """Mode selection never follows an untrusted request or an arbitrary argument."""
        for version, mode in ((1, 'native-source-v1'), (2, None), (2, 'other'), (3, 'native-source-v1')):
            with self.subTest(version=version, mode=mode):
                code, raw, pdf = self.run_worker(html_pages(1), version=version, mode=mode)
                self.assertEqual(pdf, b'')
                if code == 0:
                    self.assertEqual(json.loads(raw)['status'], 'FAIL')
                else:
                    self.assertEqual(code, 64)

    def test_wrong_html_digest_is_content_free_and_has_no_pdf(self):
        """An unchanged-looking request with the wrong identity never reaches rendering."""
        code, raw, pdf = self.run_worker(html_pages(1), digest='0' * 64)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(raw)['error'], 'pdf_render_protocol_invalid')
        self.assertNotIn(b'Physical page', raw)
        self.assertEqual(pdf, b'')

    def test_real_transport_does_not_load_native_libraries_in_parent(self):
        """Rendering and page discovery stay out of the unsandboxed caller process."""
        module = self.bridge()
        import builtins
        original = builtins.__import__
        def guarded(name, *args, **kwargs):
            if name.split('.')[0] in {'pypdf', 'weasyprint'}:
                raise AssertionError('native library imported in parent')
            return original(name, *args, **kwargs)
        html = html_pages(2)
        with patch('builtins.__import__', side_effect=guarded):
            result = module.render_pdf_candidate(html, sha256(html.encode()).hexdigest())
        self.assertEqual(result.page_count, 2)
        self.assertEqual(result.pdf_sha256, sha256(result.pdf_bytes).hexdigest())
        self.assertNotIn('pdf_bytes', result.to_dict())

    def test_cold_module_import_does_not_load_native_libraries(self):
        """A fresh parent import must not hide native parsing before the call guard starts."""
        self.bridge()
        code = '''
import builtins
original = builtins.__import__
def guarded(name, *args, **kwargs):
    if name.split('.')[0] in {'pypdf', 'weasyprint'}:
        raise AssertionError('native library imported in parent')
    return original(name, *args, **kwargs)
builtins.__import__ = guarded
import reporting.pdf_generated_source_job
'''
        process = subprocess.run([sys.executable, '-B', '-c', code], cwd=ROOT,
                                 capture_output=True, timeout=15, check=False)
        self.assertEqual(process.returncode, 0, process.stderr.decode()[:500])

    def test_real_receipt_rejects_all_identity_and_shape_substitutions(self):
        """Equal-looking JSON does not waive exact identities, integer types or closed fields."""
        module = self.bridge()
        html = html_pages(1)
        code, raw, pdf = self.run_worker(html)
        self.assertEqual(code, 0)
        record = json.loads(raw)
        changes = [
            {'protocol_version': 1}, {'protocol_version': True}, {'protocol_version': 2.0},
            {'profile_id': 'legacy'}, {'profile_sha256': '0' * 64},
            {'html_sha256': '0' * 64}, {'pdf_sha256': '0' * 64},
            {'pdf_bytes': True}, {'pdf_bytes': len(pdf) + 1}, {'pdf_bytes': 16777217},
            {'page_count': True}, {'page_count': 0}, {'page_count': 65}, {'page_count': 1.0},
            {'unexpected': 'private'}, {'limits': {**record['limits'], 'file_bytes': 8388608}},
            {'limits': {**record['limits'], 'cpu_seconds': 20.0}},
        ]
        for change in changes:
            with self.subTest(change=change), tempfile.TemporaryFile() as candidate:
                candidate.write(pdf)
                candidate.flush()
                with self.assertRaises(module.PdfGeneratedSourceJobError):
                    module._decode_render_result(json.dumps({**record, **change}).encode(),
                                                 candidate_fd=candidate.fileno(),
                                                 expected_html_sha256=sha256(html.encode()).hexdigest())
        for encoded in (b'{}', b'not-json', raw[:-1] + b',"status":"PASS"}', b' ' * 65537):
            with self.subTest(encoded_size=len(encoded)), tempfile.TemporaryFile() as candidate:
                candidate.write(pdf)
                candidate.flush()
                with self.assertRaises(module.PdfGeneratedSourceJobError):
                    module._decode_render_result(encoded, candidate_fd=candidate.fileno(),
                                                 expected_html_sha256=sha256(html.encode()).hexdigest())

    def test_missing_or_altered_pdf_is_not_a_valid_render_receipt(self):
        """A valid receipt cannot certify a missing, changed or differently sized descriptor."""
        module = self.bridge()
        html = html_pages(1)
        code, raw, pdf = self.run_worker(html)
        self.assertEqual(code, 0)
        for data in (b'', pdf + b'x', pdf[:-1] + b'x'):
            with self.subTest(size=len(data)), tempfile.TemporaryFile() as candidate:
                candidate.write(data)
                candidate.flush()
                with self.assertRaises(module.PdfGeneratedSourceJobError):
                    module._decode_render_result(raw, candidate_fd=candidate.fileno(),
                                                 expected_html_sha256=sha256(html.encode()).hexdigest())

    def test_oversized_receipt_refuses_pdf_read(self):
        """A declared file above 16 MiB is rejected before reading its contents."""
        module = self.bridge()
        html = html_pages(1)
        code, raw, _pdf = self.run_worker(html)
        self.assertEqual(code, 0)
        record = json.loads(raw)
        record['pdf_bytes'] = 16777217
        with tempfile.TemporaryFile() as candidate, patch.object(os, 'pread') as read:
            with self.assertRaises(module.PdfGeneratedSourceJobError):
                module._decode_render_result(json.dumps(record).encode(), candidate_fd=candidate.fileno(),
                                             expected_html_sha256=sha256(html.encode()).hexdigest())
        read.assert_not_called()

    def test_parent_bound_drift_cannot_relabel_sixty_five_pages(self):
        """A widened parent constant cannot retain the approved 64-page identity."""
        module = self.bridge()
        html = html_pages(1)
        code, raw, pdf = self.run_worker(html)
        self.assertEqual(code, 0)
        record = json.loads(raw)
        record['page_count'] = 65
        with tempfile.TemporaryFile() as candidate, patch.object(module, '_RENDER_PAGES', 65):
            candidate.write(pdf)
            candidate.flush()
            with self.assertRaises(module.PdfGeneratedSourceJobError):
                module._decode_render_result(json.dumps(record).encode(),
                    candidate_fd=candidate.fileno(), expected_html_sha256=sha256(html.encode()).hexdigest())

    def test_all_parent_render_limits_and_types_are_profile_pinned(self):
        """Parent validation cannot drift independently from the closed worker profile."""
        module = self.bridge()
        changes = [
            ('_RENDER_PAGES', 65), ('_RENDER_PAGES', 64.0),
            ('_RENDER_PDF_BYTES', 16777217), ('_RENDER_PDF_BYTES', 16777216.0),
            ('_RENDER_HTML_BYTES', 67108865), ('_RENDER_RESULT_BYTES', 65537),
            ('_RENDER_LIMITS', {**module._RENDER_LIMITS, 'cpu_seconds': 21}),
            ('_RENDER_LIMITS', {**module._RENDER_LIMITS, 'cpu_seconds': 20.0}),
            ('RENDER_PROFILE_SHA256', '0' * 64),
        ]
        for name, value in changes:
            with self.subTest(name=name, value=value), patch.object(module, name, value):
                with self.assertRaises(ValueError):
                    module._render_profile()

    def test_render_failures_and_disable_never_return_candidate(self):
        """No storage, child startup or disable failure leaks partial output or OS details."""
        module = self.bridge()
        html = html_pages(1)
        digest = sha256(html.encode()).hexdigest()
        with patch.dict(os.environ, {'OMNIGENIS_PDF_RENDERER_DISABLED': '1'}):
            with self.assertRaises(module.PdfGeneratedSourceJobError):
                module.render_pdf_candidate(html, digest)
        with patch.object(module, '_start_pdf_render_worker', side_effect=RuntimeError('PRIVATE')):
            with self.assertRaisesRegex(module.PdfGeneratedSourceJobError, '^pdf_generated_render_failed$'):
                module.render_pdf_candidate(html, digest)

    def test_lifecycle_refusal_precedes_valid_response_decode(self):
        """Even complete valid child output cannot override a wait/cleanup refusal."""
        module = self.bridge()
        def refuse_after_reaping(process, *, wall_seconds):
            adapters._wait_pdf_render_worker(process, wall_seconds=wall_seconds)
            raise RuntimeError('PRIVATE-LIFECYCLE')
        html = html_pages(1)
        with patch.object(module, '_wait_pdf_render_worker', side_effect=refuse_after_reaping), \
                patch.object(module, '_decode_render_result', wraps=module._decode_render_result) as decode:
            with self.assertRaisesRegex(module.PdfGeneratedSourceJobError, '^pdf_generated_render_failed$'):
                module.render_pdf_candidate(html, sha256(html.encode()).hexdigest())
        decode.assert_not_called()


if __name__ == '__main__':
    unittest.main()
