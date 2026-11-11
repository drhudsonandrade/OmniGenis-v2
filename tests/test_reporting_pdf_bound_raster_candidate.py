"""Request-bound raster composition preserves sources and rejects caller rendering code."""
from hashlib import sha256
from importlib import import_module, util
import os
import unittest
from unittest.mock import patch

from reporting import pdf_bound_candidate as bound_source
from reporting import pdf_generated_source_job as generated
from reporting import pdf_native_source_job as native
from reporting import pdf_raster_render as raster
from reporting import pdf_raster_resources as resources
from tests.test_reporting_pdf_bound_candidate import bound_request, source, IDS, canonical
from tests.test_reporting_pdf_raster_resources import png

MODE = 'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE'
DISABLE = 'OMNIGENIS_PDF_BOUND_RASTER_DISABLED'


def bundle(count=1):
    """Make owned, deterministic RGB inputs with explicit provenance declarations."""
    assets = []
    for i in range(count):
        raw = png(value=30 + i)
        assets.append(resources.RasterAsset('synthetic-' + str(i), raw,
            sha256(raw).hexdigest(), 2, 2, sha256(('synthetic-source-' + str(i)).encode()).hexdigest(),
            sha256(b'owned-synthetic-qualification-content').hexdigest()))
    return resources.RasterBundle(tuple(assets))


class BoundRasterProjectionTests(unittest.TestCase):
    """Use actual source contracts before admitting any native work."""
    def setUp(self):
        """Assert missing API as a real RED failure before building the proposed boundary."""
        self.assertIsNotNone(util.find_spec('reporting.pdf_bound_raster_candidate'),
                             'request-bound raster composition is missing')
        self.m = import_module('reporting.pdf_bound_raster_candidate')
        self.bound = bound_request()
        self.assets = bundle()
        env = patch.dict(os.environ, {MODE: 'qualification-only'})
        env.start(); self.addCleanup(env.stop)
        for key in (DISABLE, 'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED',
                    'OMNIGENIS_PDF_PRELOADED_RASTER_DISABLED', 'OMNIGENIS_PDF_RENDERER_DISABLED'):
            os.environ.pop(key, None)

    def arguments(self, **changes):
        """Bind expectations independently from retained request and resource identities."""
        values = dict(bound_request=self.bound, resources=self.assets,
            expected_request_sha256=self.bound.request.request_sha256,
            expected_resources_sha256=self.assets.bundle_sha256,
            expected_resource_profile_sha256=self.m.PROFILE_SHA256)
        values.update(changes)
        return values

    def prepare(self, **changes):
        """Exercise the actual product projection, never substitute caller HTML."""
        return self.m.prepare_bound_raster_candidate(**self.arguments(**changes))

    def test_preserves_original_five_components_and_source_methodology(self):
        """Decorative resources cannot replace or mutate an admitted item or method."""
        original, original_binding = bound_source._prepare(self.bound, generated.PROFILE_SHA256,
                                                          'technical-assembly-v1')
        before = self.bound.sources.canonical_result_bytes
        ir, html, binding = self.prepare()
        self.assertEqual(ir['components'][:5], original['presentation_ir']['components'])
        self.assertEqual(binding['source_projection'], original_binding)
        self.assertEqual(self.bound.sources.canonical_result_bytes, before)
        self.assertEqual(binding['request_sha256'], self.bound.request.request_sha256)
        self.assertEqual(binding['finding_count'], 2)
        self.assertEqual(binding['source_ir_sha256'], original['expected_ir_sha256'])
        self.assertEqual(binding['html_sha256'], sha256(html.encode()).hexdigest())
        self.assertNotEqual(binding['ir_sha256'], original['expected_ir_sha256'])
        self.assertIn(self.assets.assets[0].uri, html)

    def test_empty_inventory_stays_explicit_none(self):
        """A decorated source with zero findings remains explicitly empty."""
        document, _ = source(); document['canonical_payload']['items'] = []
        document['canonical_payload']['interpretation_item_count'] = 0; document['raw_artifact_refs'] = []
        self.bound = bound_request(document, finding_ids=())
        ir, _, binding = self.prepare()
        self.assertEqual(binding['finding_count'], 0)
        self.assertEqual(ir['components'][1]['state'], 'EXPLICIT_NONE')
        self.assertEqual(ir['components'][1]['content']['canonical_interpretation.items'], [])

    def test_one_finding_preserves_exact_admitted_item(self):
        """A one-item source stays complete without inventing another item."""
        document, _ = source(); document['canonical_payload']['items'] = document['canonical_payload']['items'][:1]
        document['canonical_payload']['interpretation_item_count'] = 1
        document['raw_artifact_refs'] = document['raw_artifact_refs'][:1]
        self.bound = bound_request(document, finding_ids=IDS[:1])
        ir, _, binding = self.prepare()
        self.assertEqual(binding['finding_count'], 1)
        self.assertEqual(ir['components'][1]['content']['canonical_interpretation.items'], document['canonical_payload']['items'])

    def test_resource_inventory_is_complete_and_separately_accounted(self):
        """Resource appendices never contribute to the scientific finding count."""
        self.assets = bundle(3); ir, html, binding = self.prepare()
        self.assertEqual((len(ir['components']), binding['finding_count'], binding['resource_count']), (8, 2, 3))
        self.assertEqual(len(binding['resource_sections']), 3)
        for i, asset in enumerate(self.assets.assets):
            component = ir['components'][5 + i]
            self.assertEqual(component['component_id'], 'qualification-raster-' + str(i + 1))
            self.assertEqual(component['content']['resource'], asset.metadata())
            self.assertIn('no scientific interpretation', component['content']['purpose'])
            self.assertEqual(html.count(asset.uri), 1)
            self.assertEqual(binding['resource_sections'][i]['resource_sha256'], asset.expected_sha256)

    def test_projection_is_deterministic_and_returns_detached_values(self):
        """Changing a returned value cannot alter the request or later output."""
        first = self.prepare(); before = canonical(first[0]); first[0]['components'][0]['title'] = 'MUTATED'
        again = self.prepare()
        self.assertEqual(canonical(again[0]), before)
        self.assertNotEqual(first[0]['components'][0]['title'], again[0]['components'][0]['title'])
        self.assertEqual(first[1:], again[1:])

    def test_foreign_request_and_wrong_request_digest_refuse(self):
        """Matching resources cannot authenticate a different request or case."""
        original = self.bound.request.request_sha256
        with self.assertRaises(self.m.PdfBoundRasterError):
            self.prepare(bound_request=bound_request(request_id='FOREIGN-REQUEST'), expected_request_sha256=original)
        for wrong in ('0' * 64, True, original.upper(), None):
            with self.subTest(value=wrong), self.assertRaises(self.m.PdfBoundRasterError):
                self.prepare(expected_request_sha256=wrong)

    def test_wrong_resource_digest_or_different_bundle_refuses(self):
        """The independent expected bundle cannot be recomputed from substituted inputs."""
        expected = self.assets.bundle_sha256
        with self.assertRaises(self.m.PdfBoundRasterError): self.prepare(expected_resources_sha256='0' * 64)
        with self.assertRaises(self.m.PdfBoundRasterError):
            self.prepare(resources=bundle(2), expected_resources_sha256=expected)

    def test_changed_resource_rights_are_not_resealed(self):
        """A changed declaration invalidates its original seal, not a legal-rights checker."""
        arguments = self.arguments()
        object.__setattr__(self.assets.assets[0], 'rights_sha256', 'c' * 64)
        with self.assertRaises(self.m.PdfBoundRasterError):
            self.m.prepare_bound_raster_candidate(**arguments)

    def test_changed_canonical_source_is_not_admitted(self):
        """The inherited immutable source checks are required on every call."""
        object.__setattr__(self.bound.sources, 'canonical_result_bytes', b'{}')
        with self.assertRaises(self.m.PdfBoundRasterError): self.prepare()

    def test_unknown_resource_or_profile_type_refuses(self):
        """Duck-typed inputs and another composition profile cannot bypass admission."""
        for update in ({'resources': None}, {'resources': {}}, {'bound_request': {}},
                       {'expected_resource_profile_sha256': generated.PROFILE_SHA256},
                       {'expected_resource_profile_sha256': '0' * 64}):
            with self.subTest(field=next(iter(update))), self.assertRaises(self.m.PdfBoundRasterError): self.prepare(**update)

    def test_explicit_and_inherited_disable_flags_precede_native_work(self):
        """The optional route cannot enable itself or override inherited disable switches."""
        for flag in (DISABLE, 'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED',
                     'OMNIGENIS_PDF_PRELOADED_RASTER_DISABLED', 'OMNIGENIS_PDF_RENDERER_DISABLED'):
            with patch.dict(os.environ, {flag: '1'}), self.assertRaises(self.m.PdfBoundRasterError): self.prepare()
        os.environ.pop(MODE)
        with self.assertRaises(self.m.PdfBoundRasterError): self.prepare()

    def test_no_caller_html_styles_or_executor_can_be_injected(self):
        """Ordinary caller markup and CSS are rejected by the fixed data-only signature."""
        for update in ({'html': '<p>caller content</p>'}, {'css': 'body{font-weight:bold}'},
                       {'renderer': lambda: None}, {'page_count': 1}):
            with self.subTest(field=next(iter(update))), self.assertRaises(TypeError):
                self.m.prepare_bound_raster_candidate(**self.arguments(), **update)

    def test_no_resource_or_scientific_authority_is_inferred(self):
        """Technical consistency is not release, resource rights or clinical authority."""
        _, _, binding = self.prepare()
        for key in ('release_authorized', 'supported_execution', 'upstream_authorization_validated',
                    'resource_rights_authenticated', 'resource_source_authenticated',
                    'aggregate_job_resources_qualified', 'default_pipeline_activated',
                    'visual_semantics_verified', 'accessibility_qualified'):
            self.assertIs(binding[key], False)

    def test_profile_budget_drift_refuses(self):
        """The fixed outer bound cannot silently expand accepted resource work."""
        with patch.object(self.m, 'ACCEPTANCE_NS', self.m.ACCEPTANCE_NS + 1), self.assertRaises(self.m.PdfBoundRasterError): self.prepare()


class BoundRasterFailureTests(unittest.TestCase):
    """Fault injection is negative coverage, separate from actual native positive proof."""
    setUp = BoundRasterProjectionTests.setUp
    arguments = BoundRasterProjectionTests.arguments
    prepare = BoundRasterProjectionTests.prepare

    def fake_candidate(self):
        """Construct a protocol fixture, never evidence of actual successful rendering."""
        _, html, _ = self.prepare()
        return raster.RasterPdfCandidate(b'%PDF-1.7\nsynthetic-negative-fixture',
            sha256(html.encode()).hexdigest(), self.assets.bundle_sha256, 1, 1)

    def test_render_failure_is_once_and_content_free(self):
        """A refusal never invokes inspection or returns private failure contents."""
        with patch.object(raster, 'render_preloaded_raster_pdf', side_effect=ValueError('PRIVATE-CONTENT')) as render, \
                patch.object(native, 'execute_pdf_native_source_job') as inspect:
            with self.assertRaises(self.m.PdfBoundRasterError) as error: self.m.execute_bound_raster_candidate(**self.arguments())
        self.assertEqual(str(error.exception), 'pdf_bound_raster_execution_unverified')
        self.assertEqual(render.call_count, 1); inspect.assert_not_called()

    def test_forged_renderer_identity_is_refused_before_inspection(self):
        """A retained render object must match the prepared HTML and resource digests."""
        item = raster.RasterPdfCandidate(b'%PDF-1.7\nsynthetic-negative-fixture', '0' * 64, self.assets.bundle_sha256, 1, 1)
        with patch.object(raster, 'render_preloaded_raster_pdf', return_value=item) as render, \
                patch.object(native, 'execute_pdf_native_source_job') as inspect:
            with self.assertRaises(self.m.PdfBoundRasterError): self.m.execute_bound_raster_candidate(**self.arguments())
        self.assertEqual(render.call_count, 1); inspect.assert_not_called()

    def test_source_change_after_render_blocks_next_stage(self):
        """Persistent source drift invalidates the next stage before inspection launches."""
        item = self.fake_candidate()
        def changed(**_args):
            """Deliberately mutate retained input after producing the negative fixture."""
            object.__setattr__(self.bound.sources, 'canonical_result_bytes', b'{}'); return item
        arguments = self.arguments()
        with patch.object(raster, 'render_preloaded_raster_pdf', side_effect=changed), \
                patch.object(native, 'execute_pdf_native_source_job') as inspect:
            with self.assertRaises(self.m.PdfBoundRasterError): self.m.execute_bound_raster_candidate(**arguments)
        inspect.assert_not_called()

    def test_native_failure_returns_no_success_and_does_not_retry(self):
        """One inspection failure cannot trigger another renderer invocation or success."""
        item = self.fake_candidate()
        with patch.object(raster, 'render_preloaded_raster_pdf', return_value=item) as render, \
                patch.object(native, 'execute_pdf_native_source_job', side_effect=ValueError('native failed')) as inspect:
            with self.assertRaises(self.m.PdfBoundRasterError): self.m.execute_bound_raster_candidate(**self.arguments())
        self.assertEqual(render.call_count, 1); self.assertEqual(inspect.call_count, 1)

    def test_outer_deadline_stops_before_inspection(self):
        """Rendering cannot consume the outer acceptance interval and then inspect."""
        item = self.fake_candidate()
        with patch.object(raster, 'render_preloaded_raster_pdf', return_value=item), \
                patch.object(self.m.time, 'monotonic_ns', side_effect=[0, 1, self.m.ACCEPTANCE_NS + 1]), \
                patch.object(native, 'execute_pdf_native_source_job') as inspect:
            with self.assertRaises(self.m.PdfBoundRasterError): self.m.execute_bound_raster_candidate(**self.arguments())
        inspect.assert_not_called()


class BoundRasterNativeTests(unittest.TestCase):
    """One genuine source-bound complete candidate supplies positive native evidence."""
    actual_result = None
    actual_failure = None
    setUp = BoundRasterProjectionTests.setUp
    arguments = BoundRasterProjectionTests.arguments
    prepare = BoundRasterProjectionTests.prepare

    def actual(self):
        """Generate one known synthetic many-item source; never rerun a failed fixture."""
        from copy import deepcopy
        from hashlib import shake_256
        import struct
        import zlib
        if type(self).actual_failure is not None:
            self.fail('genuine fixture previously failed: ' + type(self).actual_failure)
        if type(self).actual_result is None:
            document, _ = source()
            template = document['canonical_payload']['items'][0]
            items = []
            for i in range(96):
                item = deepcopy(template)
                item['canonical_variant_id'] = 'omnigenis:small-variant:v1:sha256:' + sha256(
                    ('owned-synthetic-bound-raster-finding-' + str(i)).encode()).hexdigest()
                items.append(item)
            document['canonical_payload']['items'] = items
            document['canonical_payload']['interpretation_item_count'] = len(items)
            document['raw_artifact_refs'] = [item['evidence_sha256'] for item in items]
            document['limitations'].append('Synthetic reporting qualification only; no real person or clinical use.')
            bound = bound_request(document, finding_ids=tuple(item['canonical_variant_id'] for item in items))
            assets = []
            def chunk(kind, data):
                """Encode an independently generated PNG chunk and CRC."""
                return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 0xffffffff)
            for i in range(3):
                spec = ('owned-synthetic-bound-raster-resource-v1:' + str(i)).encode()
                pixels = shake_256(spec).digest(1024 * 1024 * 3)
                scanlines = b''.join(b'\0' + pixels[y * 3072:(y + 1) * 3072] for y in range(1024))
                raw = (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 1024, 1024, 8, 2, 0, 0, 0))
                       + chunk(b'IDAT', zlib.compress(scanlines)) + chunk(b'IEND', b''))
                assets.append(resources.RasterAsset('synthetic-long-' + str(i), raw, sha256(raw).hexdigest(),
                    1024, 1024, sha256(spec).hexdigest(), sha256(b'OWNED_SYNTHETIC_DECORATIVE_TEST_DATA').hexdigest()))
            resource_set = resources.RasterBundle(tuple(assets))
            arguments = dict(bound_request=bound, resources=resource_set,
                expected_request_sha256=bound.request.request_sha256,
                expected_resources_sha256=resource_set.bundle_sha256,
                expected_resource_profile_sha256=self.m.PROFILE_SHA256)
            source_before = bound.sources.canonical_result_bytes
            try:
                result = self.m.execute_bound_raster_candidate(**arguments)
                self.assertEqual(bound.sources.canonical_result_bytes, source_before)
                type(self).actual_result = result, arguments, document
            except Exception as failure:
                type(self).actual_failure = type(failure).__name__ + ': ' + str(failure)
                raise
        return type(self).actual_result

    def test_real_source_bound_long_pdf_is_complete_and_same_artifact_inspected(self):
        """All declared items, method and resources bind to the one real unmodified PDF."""
        import json
        (rendered, inspected, binding), arguments, document = self.actual()
        ir, html, prepared = self.m.prepare_bound_raster_candidate(**arguments)
        self.assertGreater(rendered.page_count, 32)
        self.assertLessEqual(rendered.page_count, 64)
        self.assertGreater(len(rendered.pdf_bytes), 8 * 1024 * 1024)
        self.assertLessEqual(len(rendered.pdf_bytes), 16 * 1024 * 1024)
        self.assertEqual(binding['finding_count'], 96)
        self.assertEqual(binding['resource_count'], 3)
        self.assertEqual(ir['components'][1]['content']['canonical_interpretation.items'], document['canonical_payload']['items'])
        self.assertEqual(prepared['source_projection']['methodology_profile'], 'technical-assembly-v1')
        native_result = inspected.to_dict()
        for key in ('pdf_sha256', 'page_count', 'ir_sha256', 'request_sha256', 'namespace_id', 'job_id'):
            self.assertEqual(native_result[key], binding[key])
        self.assertTrue(native_result['normalized_text_equivalence_verified'])
        self.assertEqual(inspected.inspection_sha256, binding['native_inspection_sha256'])
        self.assertEqual(sha256(rendered.pdf_bytes).hexdigest(), binding['pdf_sha256'])
        self.assertEqual(sha256(html.encode()).hexdigest(), binding['html_sha256'])
        self.assertEqual(rendered.resources_sha256, arguments['expected_resources_sha256'])
        self.assertFalse(binding['resource_rights_authenticated'])
        self.assertFalse(binding['release_authorized'])
        self.assertFalse(binding['aggregate_job_resources_qualified'])
        print(json.dumps({'source_bound_pages': rendered.page_count, 'pdf_bytes': len(rendered.pdf_bytes),
            'pdf_sha256': rendered.pdf_sha256, 'findings': 96, 'resources': 3,
            'request_sha256': binding['request_sha256'], 'same_artifact_inspected': True,
            'renderer_patched': False, 'pdf_rewritten': False, 'release_authorized': False}), flush=True)

    def test_exact_owned_pixels_are_painted_in_the_same_source_bound_pdf(self):
        """Actual page-to-form-to-image painting uses all three owned pixel arrays."""
        from io import BytesIO
        from hashlib import shake_256
        from pypdf import PdfReader
        from pypdf.generic import ContentStream
        (rendered, _, _), _, _ = self.actual()
        reader = PdfReader(BytesIO(rendered.pdf_bytes), strict=True)
        self.assertEqual(len(reader.pages), rendered.page_count)
        expected = {sha256(shake_256(('owned-synthetic-bound-raster-resource-v1:' + str(i)).encode())
                    .digest(1024 * 1024 * 3)).hexdigest() for i in range(3)}
        painted = set(); uses = 0
        for page in reader.pages:
            pending = [(page.get_contents(), page['/Resources'], 0)]
            while pending:
                stream, page_resources, depth = pending.pop()
                self.assertLess(depth, 8)
                xobjects = page_resources.get('/XObject', {})
                xobjects = xobjects.get_object() if hasattr(xobjects, 'get_object') else xobjects
                for args, op in ContentStream(stream, reader).operations:
                    if op != b'Do':
                        continue
                    item = xobjects[args[0]].get_object()
                    if item.get('/Subtype') == '/Form':
                        pending.append((item, item['/Resources'], depth + 1))
                    else:
                        self.assertEqual(item.get('/Subtype'), '/Image')
                        self.assertEqual((item['/Width'], item['/Height']), (1024, 1024))
                        uses += 1; self.assertLessEqual(uses, 3)
                        painted.add(sha256(item.get_data()).hexdigest())
        self.assertEqual(uses, 3)
        self.assertEqual(painted, expected)
        self.assertEqual(rendered.pdf_bytes.count(b'%%EOF'), 1)

    def test_foreign_or_inconsistent_native_result_metadata_is_refused(self):
        """Negative injection cannot relabel an otherwise sealed native outcome."""
        from copy import deepcopy
        (rendered, inspected, _), arguments, _ = self.actual()
        actual = inspected.to_dict()
        for key, value in (('request_sha256', '0' * 64), ('pdf_sha256', '0' * 64),
                           ('ir_sha256', '0' * 64), ('page_count', 1), ('job_id', 'FOREIGN'),
                           ('namespace_id', 'FOREIGN'), ('resource_profile_sha256', '0' * 64),
                           ('expected_text_sha256', '0' * 64), ('normalized_text_equivalence_verified', False)):
            changed = deepcopy(actual); changed[key] = value
            with self.subTest(field=key), \
                    patch.object(raster, 'render_preloaded_raster_pdf', return_value=rendered), \
                    patch.object(native, 'execute_pdf_native_source_job', return_value=inspected), \
                    patch.object(native.PdfNativeSourceResult, 'to_dict', return_value=changed):
                with self.assertRaises(self.m.PdfBoundRasterError): self.m.execute_bound_raster_candidate(**arguments)

    def test_source_change_after_inspection_withholds_the_candidate(self):
        """Post-inspection drift still blocks success and leaves the prior source proof intact."""
        from dataclasses import replace
        (rendered, inspected, _), arguments, _ = self.actual()
        bound = arguments['bound_request']
        original_sources = bound.sources
        replacement = replace(bound, sources=original_sources)
        altered = {**arguments, 'bound_request': replacement}
        def change_after_inspection(**_values):
            """Inject a distinct retained request reference only after the child returns."""
            object.__setattr__(replacement, 'request', replace(bound.request, request_id='FOREIGN'))
            return inspected
        with patch.object(raster, 'render_preloaded_raster_pdf', return_value=rendered), \
                patch.object(native, 'execute_pdf_native_source_job', side_effect=change_after_inspection):
            with self.assertRaises(self.m.PdfBoundRasterError): self.m.execute_bound_raster_candidate(**altered)
        self.assertEqual(bound.request.request_sha256, arguments['expected_request_sha256'])


class BoundRasterLayoutTests(unittest.TestCase):
    """Physical breaks bound renderer work without changing normalized source text."""
    setUp = BoundRasterProjectionTests.setUp
    arguments = BoundRasterProjectionTests.arguments
    prepare = BoundRasterProjectionTests.prepare

    def test_large_canonical_paragraph_is_physically_bounded_and_lossless(self):
        """A single unbounded preformatted line is a product-layout regression."""
        import json
        from html.parser import HTMLParser
        document, _ = source()
        document['limitations'].append(('Synthetic <tag> & "quoted" data \\u2603 é 漢字. ' * 400))
        self.bound = bound_request(document)
        ir, html, binding = self.prepare()
        class Capture(HTMLParser):
            """Read the real emitted preformatted text, including entity-decoded characters."""
            def __init__(self):
                """Initialize bounded source-text collection for the actual generated markup."""
                super().__init__(convert_charrefs=True)
                self.blocks = []; self.current = []; self.inside = False
            def handle_starttag(self, tag, attrs):
                """Begin capture only for a genuine preformatted source section."""
                if tag == 'pre': self.current = []; self.inside = True
            def handle_endtag(self, tag):
                """Close the current source block at its matching preformatted boundary."""
                if tag == 'pre': self.blocks.append(''.join(self.current)); self.inside = False
            def handle_data(self, value):
                """Retain every decoded text character within the selected source block."""
                if self.inside: self.current.append(value)
        parsed = Capture(); parsed.feed(html)
        self.assertEqual(len(parsed.blocks), len(ir['components']))
        for component, text in zip(ir['components'], parsed.blocks):
            expected = json.dumps(component['content'], sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
            self.assertEqual(text.replace('\n', ''), expected)
            self.assertLessEqual(max(map(len, text.splitlines())), 60)
            self.assertEqual(json.loads(text.replace('\n', '')), component['content'])
        self.assertEqual(binding['html_sha256'], sha256(html.encode()).hexdigest())

    def test_bound_layout_policy_has_a_fixed_profile_identity(self):
        """A selected physical-line bound is part of the profile, not mutable caller CSS."""
        profile = self.m.bound_raster_candidate_profile()
        self.assertEqual(profile.get('max_json_physical_line_codepoints'), 60)
        self.assertEqual(profile.get('source_text_transformation'), 'INSERT_PHYSICAL_LF_ONLY_BEFORE_HTML_ESCAPE')


class BoundRasterVisualLineTests(unittest.TestCase):
    """Check actual native line breaking, not only nominal compiler string lengths."""
    setUp = BoundRasterProjectionTests.setUp
    arguments = BoundRasterProjectionTests.arguments
    prepare = BoundRasterProjectionTests.prepare

    def test_ascii_json_physical_lines_are_not_soft_wrapped_again(self):
        """All full-width ASCII source lines fit the actual selected page typography."""
        from html.parser import HTMLParser
        from io import BytesIO
        from pypdf import PdfReader
        class Capture(HTMLParser):
            """Capture decoded preformatted text without creating or changing source values."""
            def __init__(self):
                """Initialize bounded source-text collection for the actual generated markup."""
                super().__init__(convert_charrefs=True)
                self.blocks = []; self.inside = False; self.current = []
            def handle_starttag(self, tag, attrs):
                """Begin capture only for a genuine preformatted source section."""
                if tag == 'pre': self.inside = True; self.current = []
            def handle_endtag(self, tag):
                """Close the current source block at its matching preformatted boundary."""
                if tag == 'pre': self.blocks.append(''.join(self.current)); self.inside = False
            def handle_data(self, value):
                """Retain every decoded text character within the selected source block."""
                if self.inside: self.current.append(value)
        _, html, binding = self.prepare()
        parsed = Capture(); parsed.feed(html)
        actual = raster.render_preloaded_raster_pdf(html=html, expected_html_sha256=binding['html_sha256'],
            resources=self.assets, expected_resources_sha256=self.assets.bundle_sha256)
        reader = PdfReader(BytesIO(actual.pdf_bytes), strict=True)
        lines = [line for page in reader.pages for line in page.extract_text().splitlines()]
        source_lines = parsed.blocks[0].splitlines()
        self.assertGreater(len(source_lines), 20)
        for line in source_lines:
            self.assertIn(line, lines, 'canonical line suffered an additional physical wrap')


class BoundRasterManifestTests(unittest.TestCase):
    """The published composition contract pins actual sources and narrow nonclaims."""
    def manifest(self):
        """Read the actual product manifest; absence is an explicit regression failure."""
        import json
        from pathlib import Path
        path = Path(__file__).resolve().parents[1] / 'reporting/pdf-bound-raster-candidate.v1.json'
        self.assertTrue(path.is_file(), 'composition source/profile manifest is missing')
        return json.loads(path.read_bytes())

    def test_manifest_pins_actual_profile_and_source_bytes(self):
        """A stale profile or source digest cannot be described as this implementation."""
        from pathlib import Path
        from reporting import pdf_bound_raster_candidate as module
        manifest = self.manifest()
        self.assertEqual(manifest['profile'], module.bound_raster_candidate_profile())
        self.assertEqual(manifest['profile_sha256'], module.PROFILE_SHA256)
        self.assertEqual(sha256(canonical(manifest['profile'])).hexdigest(), module.PROFILE_SHA256)
        root = Path(__file__).resolve().parents[1]
        self.assertGreaterEqual(len(manifest['source_sha256']), 8)
        for name, digest in manifest['source_sha256'].items():
            self.assertFalse(Path(name).is_absolute())
            self.assertNotIn('..', Path(name).parts)
            self.assertEqual(sha256((root / name).read_bytes()).hexdigest(), digest)

    def test_manifest_keeps_release_and_resource_nonclaims_explicit(self):
        """Synthetic local execution never establishes clinical, rights or release authority."""
        manifest = self.manifest()
        for key in ('default_pipeline_activated', 'supported_execution', 'release_authorized',
                    'scientific_activation', 'resource_rights_authenticated', 'aggregate_job_resources_qualified'):
            self.assertIs(manifest[key], False)
        self.assertEqual(manifest['language'], 'en-US')
        self.assertEqual(manifest['family'], 'e1a-small-variant-report')
        self.assertEqual(manifest['integration_mode'], 'EXPLICIT_QUALIFICATION_ONLY')
        self.assertTrue(manifest['known_limitations'])


if __name__ == '__main__': unittest.main()
