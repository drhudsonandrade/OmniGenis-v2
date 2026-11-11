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


def long_raster_inputs(module):
    """Build owned synthetic long input data without any rendering or persistence."""
    from copy import deepcopy
    from hashlib import shake_256
    import struct
    import zlib
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
        expected_resource_profile_sha256=module.PROFILE_SHA256)
    return arguments, document


class BoundRasterNativeTests(unittest.TestCase):
    """One genuine source-bound complete candidate supplies positive native evidence."""
    actual_result = None
    actual_failure = None
    setUp = BoundRasterProjectionTests.setUp
    arguments = BoundRasterProjectionTests.arguments
    prepare = BoundRasterProjectionTests.prepare

    def actual(self):
        """Generate one known synthetic many-item source; never rerun a failed fixture."""
        if type(self).actual_failure is not None:
            self.fail('genuine fixture previously failed: ' + type(self).actual_failure)
        if type(self).actual_result is None:
            arguments, document = long_raster_inputs(self.m)
            bound = arguments['bound_request']
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



class BoundRasterStorageTests(unittest.TestCase):
    """Private roundtrip behavior; injected faults do not establish native qualification."""
    stored_result = None
    stored_failure = None
    arguments = BoundRasterProjectionTests.arguments

    def setUp(self):
        """Require the new behavior before any fixture can execute or claim storage."""
        from pathlib import Path
        import tempfile
        BoundRasterProjectionTests.setUp(self)
        self.assertTrue(callable(getattr(self.m, 'execute_stored_bound_raster_candidate', None)),
                        'source-bound raster private roundtrip is missing')
        self.assertTrue(callable(getattr(self.m, 'read_stored_bound_raster_candidate', None)),
                        'source-bound raster explicit recovery is missing')
        self.storage = import_module('reporting.pdf_candidate_store')
        self.receipts = import_module('reporting._pdf_job_durable_receipt')
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.run_id = '7' * 32

    def execute(self, **changes):
        """Call the complete consumer with independent input and profile expectations."""
        values = dict(**self.arguments(), directory=self.root, run_id=self.run_id,
                      expected_storage_profile_sha256=self.m.STORAGE_PROFILE_SHA256)
        values.update(changes)
        return self.m.execute_stored_bound_raster_candidate(**values)

    def recover(self, **changes):
        """Retain output expectations separately from the files being recovered."""
        values = dict(**self.arguments(), directory=self.root, run_id=self.run_id,
                      expected_storage_profile_sha256=self.m.STORAGE_PROFILE_SHA256,
                      expected_result_sha256=self.expected_result,
                      expected_pdf_sha256=self.expected_pdf)
        values.update(changes)
        return self.m.read_stored_bound_raster_candidate(**values)

    def pair(self):
        """Reuse genuine native output solely for fast storage fault injection."""
        from dataclasses import replace
        helper = BoundRasterNativeTests('test_real_source_bound_long_pdf_is_complete_and_same_artifact_inspected')
        helper.m = self.m
        pair, arguments, _ = helper.actual()
        self.bound = replace(arguments['bound_request'])
        self.assets = resources.RasterBundle(tuple(replace(a) for a in arguments['resources'].assets))
        self.expected_pdf = pair[0].pdf_sha256
        self.expected_result = sha256(canonical({
            'render_result': pair[0].to_dict(), 'native_inspection': pair[1].to_dict(),
            'binding': pair[2]})).hexdigest()
        return pair

    def genuine(self):
        """Execute one complete real long roundtrip; a failed fixture is never retried."""
        from pathlib import Path
        import tempfile
        if type(self).stored_failure is not None:
            self.fail('genuine stored fixture previously failed: ' + type(self).stored_failure)
        if type(self).stored_result is None:
            temporary = tempfile.TemporaryDirectory()
            type(self).addClassCleanup(temporary.cleanup)
            directory = Path(temporary.name)
            arguments, document = long_raster_inputs(self.m)
            before = arguments['bound_request'].sources.canonical_result_bytes
            try:
                pdf, manifest = self.m.execute_stored_bound_raster_candidate(
                    **arguments, directory=directory, run_id=self.run_id,
                    expected_storage_profile_sha256=self.m.STORAGE_PROFILE_SHA256)
                self.assertEqual(arguments['bound_request'].sources.canonical_result_bytes, before)
                type(self).stored_result = pdf, manifest, directory, arguments, document
            except Exception as failure:
                type(self).stored_failure = type(failure).__name__ + ': ' + str(failure)
                raise
        return type(self).stored_result

    def stage(self):
        """Copy one actual committed synthetic bundle into a fresh private fault fixture."""
        from pathlib import Path
        from dataclasses import replace
        import tempfile
        import shutil
        pdf, manifest, source_root, arguments, _ = self.genuine()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        shutil.copytree(source_root / self.run_id, self.root / self.run_id)
        self.bound = replace(arguments['bound_request'])
        self.assets = resources.RasterBundle(tuple(replace(a) for a in arguments['resources'].assets))
        self.expected_result = manifest['result_sha256']
        self.expected_pdf = manifest['pdf_sha256']
        return pdf, manifest

    def snapshot(self):
        """Compare content, inode, permissions and write times without changing files."""
        result = {}
        for path in sorted(self.root.rglob('*')):
            info = path.lstat()
            result[str(path.relative_to(self.root))] = (
                info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
                sha256(path.read_bytes()).hexdigest() if path.is_file() else None)
        return result

    def test_genuine_long_roundtrip_preserves_complete_bound_candidate(self):
        """The public consumer actually renders, inspects, persists and reads the same PDF."""
        import json
        pdf, manifest, directory, arguments, document = self.genuine()
        result = manifest['result']
        binding = result['binding']
        self.assertGreater(manifest['page_count'], 32)
        self.assertLessEqual(manifest['page_count'], 64)
        self.assertGreater(len(pdf), 8 * 1024 * 1024)
        self.assertLessEqual(len(pdf), 16 * 1024 * 1024)
        self.assertEqual(manifest['pdf_sha256'], sha256(pdf).hexdigest())
        self.assertEqual(manifest['pdf_bytes'], len(pdf))
        self.assertEqual(manifest['result_sha256'], sha256(canonical(result)).hexdigest())
        self.assertEqual((binding['finding_count'], binding['resource_count']), (96, 3))
        self.assertEqual(binding['request_sha256'], arguments['expected_request_sha256'])
        self.assertEqual(binding['resources_sha256'], arguments['expected_resources_sha256'])
        self.assertEqual(result['native_inspection']['pdf_sha256'], manifest['pdf_sha256'])
        self.assertTrue(result['native_inspection']['normalized_text_equivalence_verified'])
        ir, _, _ = self.m.prepare_bound_raster_candidate(**arguments)
        self.assertEqual(ir['components'][1]['content']['canonical_interpretation.items'],
                         document['canonical_payload']['items'])
        run = directory / self.run_id
        self.assertEqual((run / 'candidate.pdf').read_bytes(), pdf)
        self.assertEqual((run / 'manifest.json').read_bytes(), canonical(manifest))
        self.assertEqual(set(p.name for p in run.iterdir()),
                         {'candidate.pdf', 'manifest.json', self.run_id + '.json'})
        for path in run.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(run.stat().st_mode & 0o777, 0o700)
        for key in ('release_authorized', 'supported_execution', 'default_pipeline_activated'):
            self.assertIs(manifest[key], False)
        print(json.dumps({'stored_bound_pages': manifest['page_count'], 'pdf_bytes': len(pdf),
            'pdf_sha256': manifest['pdf_sha256'], 'result_sha256': manifest['result_sha256'],
            'findings': 96, 'resources': 3, 'real_roundtrip': True,
            'pdf_rewritten': False, 'release_authorized': False}), flush=True)

    def test_recovery_is_exact_detached_and_performs_no_work_or_writes(self):
        """Explicit repeated reads preserve all original filesystem identities."""
        expected_pdf, expected_manifest = self.stage()
        before = self.snapshot()
        with patch.object(self.m, 'execute_bound_raster_candidate', side_effect=AssertionError('render forbidden')), \
                patch.object(native, 'execute_pdf_native_source_job', side_effect=AssertionError('inspect forbidden')), \
                patch.object(self.storage, '_write_data', side_effect=AssertionError('write forbidden')), \
                patch.object(self.receipts, 'write_job_receipt', side_effect=AssertionError('commit forbidden')):
            pdf, manifest = self.recover()
            self.assertEqual((pdf, manifest), (expected_pdf, expected_manifest))
            manifest['result']['binding']['finding_count'] = 0
            self.assertEqual(self.recover(), (expected_pdf, expected_manifest))
        self.assertEqual(self.snapshot(), before)

    def test_fresh_process_recovers_with_independent_expectations_without_execution(self):
        """A new interpreter rebuilds the original inputs and only reads the committed bytes."""
        from pathlib import Path
        import json
        import subprocess
        import sys
        expected_pdf, _ = self.stage()
        before = self.snapshot()
        program = '''
import json,sys
from pathlib import Path
from hashlib import sha256
from unittest.mock import patch
from reporting import pdf_bound_raster_candidate as m
from tests.test_reporting_pdf_bound_raster_candidate import long_raster_inputs
values=json.loads(sys.argv[1])
arguments,_=long_raster_inputs(m)
with patch.object(m,'execute_bound_raster_candidate',side_effect=AssertionError('render forbidden')), patch.object(m.native,'execute_pdf_native_source_job',side_effect=AssertionError('inspect forbidden')), patch.object(m.storage,'_write_data',side_effect=AssertionError('write forbidden')), patch.object(m.receipts,'write_job_receipt',side_effect=AssertionError('commit forbidden')):
    pdf,manifest=m.read_stored_bound_raster_candidate(**arguments,directory=Path(values['directory']),run_id=values['run_id'],expected_result_sha256=values['result'],expected_pdf_sha256=values['pdf'],expected_storage_profile_sha256=values['profile'])
print(json.dumps({'pdf':sha256(pdf).hexdigest(),'result':manifest['result_sha256'],'pages':manifest['page_count']}))
'''
        result = subprocess.run([sys.executable, '-B', '-c', program, json.dumps({
            'directory': str(self.root), 'run_id': self.run_id, 'result': self.expected_result,
            'pdf': self.expected_pdf, 'profile': self.m.STORAGE_PROFILE_SHA256})],
            cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True,
            timeout=45, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['pdf'], sha256(expected_pdf).hexdigest())
        self.assertEqual(json.loads(result.stdout)['result'], self.expected_result)
        self.assertEqual(self.snapshot(), before)

    def test_wrong_inputs_and_profiles_refuse_before_claim_or_render(self):
        """Foreign source expectations cannot create an attempt or invoke native work."""
        changes = ({'expected_request_sha256': '0' * 64},
                   {'expected_resources_sha256': '0' * 64},
                   {'expected_resource_profile_sha256': generated.PROFILE_SHA256},
                   {'expected_storage_profile_sha256': self.m.PROFILE_SHA256},
                   {'expected_storage_profile_sha256': True})
        with patch.object(self.m, 'execute_bound_raster_candidate') as execute:
            for values in changes:
                with self.subTest(values=values), self.assertRaises(self.m.PdfBoundRasterError):
                    self.execute(**values)
            execute.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_invalid_run_and_storage_root_refuse_before_render(self):
        """Malformed identifiers and nonprivate directories cannot admit execution."""
        from pathlib import Path
        with patch.object(self.m, 'execute_bound_raster_candidate') as execute:
            for value in ('../run', 'a' * 31, 'A' * 32, True, None):
                with self.subTest(run=value), self.assertRaises(self.m.PdfBoundRasterError):
                    self.execute(run_id=value)
            for value in (str(self.root), Path('relative'), None):
                with self.subTest(root=value), self.assertRaises(self.m.PdfBoundRasterError):
                    self.execute(directory=value)
            self.root.chmod(0o755)
            with self.assertRaises(self.m.PdfBoundRasterError): self.execute()
            execute.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_default_and_inherited_disable_refuse_before_storage(self):
        """The optional store cannot enable its candidate or receipt prerequisites."""
        with patch.object(self.m, 'execute_bound_raster_candidate') as execute:
            for key in (DISABLE, 'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED',
                        'OMNIGENIS_PDF_PRELOADED_RASTER_DISABLED'):
                with patch.dict(os.environ, {key: '1'}), self.assertRaises(self.m.PdfBoundRasterError):
                    self.execute()
            with patch.dict(os.environ):
                os.environ.pop(MODE, None)
                with self.assertRaises(self.m.PdfBoundRasterError): self.execute()
            execute.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_consumed_empty_and_completed_runs_never_render_again(self):
        """Only the explicit recovery API may return a previously committed candidate."""
        (self.root / self.run_id).mkdir(mode=0o700)
        with patch.object(self.m, 'execute_bound_raster_candidate') as execute:
            with self.assertRaises(self.m.PdfBoundRasterError): self.execute()
            execute.assert_not_called()
        self.stage()
        before = self.snapshot()
        with patch.object(self.m, 'execute_bound_raster_candidate') as execute:
            with self.assertRaises(self.m.PdfBoundRasterError): self.execute()
            execute.assert_not_called()
        self.assertEqual(self.snapshot(), before)

    def test_generation_failure_consumes_once_and_returns_fixed_refusal(self):
        """A failed render attempt is neither deleted nor automatically reexecuted."""
        with patch.object(self.m, 'execute_bound_raster_candidate', side_effect=ValueError('PRIVATE-CONTENT')) as execute:
            with self.assertRaises(self.m.PdfBoundRasterError) as error: self.execute()
            self.assertEqual(str(error.exception), 'pdf_bound_raster_store_execution_unverified')
            with self.assertRaises(self.m.PdfBoundRasterError): self.execute()
        self.assertEqual(execute.call_count, 1)
        self.assertTrue((self.root / self.run_id).is_dir())
        self.assertFalse((self.root / self.run_id / (self.run_id + '.json')).exists())

    def test_concurrent_same_run_admits_one_generator(self):
        """Contending requests cannot execute or overwrite the same private attempt twice."""
        from concurrent.futures import ThreadPoolExecutor
        import threading
        pair = self.pair()
        entered = threading.Event()
        release = threading.Event()
        def generator(**_values):
            """Hold the one admitted attempt while a contender encounters its directory."""
            entered.set()
            if not release.wait(10): raise AssertionError('test contender did not finish')
            return pair
        def attempt():
            """Return a simple outcome while retaining exceptions for assertions."""
            try: return self.execute()
            except self.m.PdfBoundRasterError: return None
        with patch.object(self.m, 'execute_bound_raster_candidate', side_effect=generator) as execute:
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(attempt)
                self.assertTrue(entered.wait(10))
                second = pool.submit(attempt)
                try: self.assertIsNone(second.result(timeout=10))
                finally: release.set()
                self.assertIsNotNone(first.result(timeout=20))
            self.assertEqual(execute.call_count, 1)

    def test_foreign_binding_and_promoted_scope_refuse_before_commit(self):
        """No missing, extra or substituted source/output binding can be committed."""
        from copy import deepcopy
        from pathlib import Path
        import tempfile
        pair = self.pair()
        changes = [('request_sha256', '0' * 64), ('namespace_id', 'FOREIGN'),
                   ('job_id', 'FOREIGN'), ('ir_sha256', '0' * 64),
                   ('resources_sha256', '0' * 64), ('page_count', 1),
                   ('native_inspection_sha256', '0' * 64),
                   ('original_source_components_preserved', False), ('release_authorized', True),
                   ('unrecognized', 'extra')]
        for key, value in changes:
            with tempfile.TemporaryDirectory() as temporary:
                changed = deepcopy(pair[2]); changed[key] = value
                with self.subTest(field=key), \
                        patch.object(self.m, 'execute_bound_raster_candidate', return_value=(*pair[:2], changed)), \
                        self.assertRaises(self.m.PdfBoundRasterError):
                    self.execute(directory=Path(temporary))
                self.assertFalse((Path(temporary) / self.run_id / (self.run_id + '.json')).exists())

    def test_foreign_rendered_pdf_or_resource_binding_refuses(self):
        """A sealed object from another rendering cannot inherit this native result."""
        from pathlib import Path
        import tempfile
        pair = self.pair()
        for item in (raster.RasterPdfCandidate(pair[0].pdf_bytes + b'\nchanged',
                         pair[0].html_sha256, pair[0].resources_sha256, pair[0].page_count, 3),
                     raster.RasterPdfCandidate(pair[0].pdf_bytes, '0' * 64,
                         pair[0].resources_sha256, pair[0].page_count, 3)):
            with tempfile.TemporaryDirectory() as temporary, \
                    patch.object(self.m, 'execute_bound_raster_candidate', return_value=(item, pair[1], pair[2])), \
                    self.assertRaises(self.m.PdfBoundRasterError):
                self.execute(directory=Path(temporary))

    def test_changed_native_context_or_scope_is_not_stored(self):
        """The consumer validates native metadata even when a fault bypasses its seal."""
        from copy import deepcopy
        from pathlib import Path
        import tempfile
        pair = self.pair()
        for key, value in (('request_sha256', '0' * 64), ('page_count', 1),
                           ('resource_profile_sha256', generated.PROFILE_SHA256),
                           ('normalized_text_equivalence_verified', False), ('release_authorized', True)):
            data = deepcopy(pair[1].to_dict()); data[key] = value
            with tempfile.TemporaryDirectory() as temporary, \
                    patch.object(self.m, 'execute_bound_raster_candidate', return_value=pair), \
                    patch.object(native.PdfNativeSourceResult, 'to_bytes', return_value=canonical(data)), \
                    self.subTest(field=key), self.assertRaises(self.m.PdfBoundRasterError):
                self.execute(directory=Path(temporary))

    def test_partial_write_is_preserved_without_commit_or_reexecution(self):
        """An incomplete data file remains evidence and cannot be repaired by retry."""
        pair = self.pair()
        real = self.storage._write_data
        def partial(fd, name, data, limit):
            """Inject a partial first file before refusing the write."""
            real(fd, name, data[:20], limit)
            raise OSError('private write failure')
        with patch.object(self.m, 'execute_bound_raster_candidate', return_value=pair), \
                patch.object(self.storage, '_write_data', side_effect=partial):
            with self.assertRaises(self.m.PdfBoundRasterError): self.execute()
        run = self.root / self.run_id
        self.assertEqual((run / 'candidate.pdf').stat().st_size, 20)
        self.assertFalse((run / (self.run_id + '.json')).exists())
        with self.assertRaises(self.m.PdfBoundRasterError): self.recover()
        with patch.object(self.m, 'execute_bound_raster_candidate') as execute:
            with self.assertRaises(self.m.PdfBoundRasterError): self.execute()
            execute.assert_not_called()

    def test_zero_progress_write_cannot_commit(self):
        """The inherited write loop refuses a zero-byte write instead of spinning."""
        pair = self.pair()
        with patch.object(self.m, 'execute_bound_raster_candidate', return_value=pair), \
                patch.object(self.storage.os, 'write', return_value=0):
            with self.assertRaises(self.m.PdfBoundRasterError): self.execute()
        self.assertFalse((self.root / self.run_id / (self.run_id + '.json')).exists())

    def test_file_sync_failure_cannot_commit(self):
        """Data must be synced before the success marker can exist."""
        import stat
        pair = self.pair()
        real = os.fsync
        def fail(fd):
            """Fail only a regular data file, after the run directory was claimed."""
            if stat.S_ISREG(os.fstat(fd).st_mode): raise OSError('file sync refused')
            return real(fd)
        with patch.object(self.m, 'execute_bound_raster_candidate', return_value=pair), \
                patch.object(os, 'fsync', side_effect=fail):
            with self.assertRaises(self.m.PdfBoundRasterError): self.execute()
        self.assertFalse((self.root / self.run_id / (self.run_id + '.json')).exists())

    def test_data_directory_sync_failure_cannot_commit(self):
        """Synced data file contents alone do not establish a committed bundle."""
        import stat
        pair = self.pair()
        real = os.fsync
        def fail(fd):
            """Target the directory sync after both data files have been written."""
            if stat.S_ISDIR(os.fstat(fd).st_mode) and set(os.listdir(fd)) == {'candidate.pdf', 'manifest.json'}:
                raise OSError('data directory sync refused')
            return real(fd)
        with patch.object(self.m, 'execute_bound_raster_candidate', return_value=pair), \
                patch.object(os, 'fsync', side_effect=fail):
            with self.assertRaises(self.m.PdfBoundRasterError): self.execute()
        self.assertFalse((self.root / self.run_id / (self.run_id + '.json')).exists())

    def test_receipt_commits_only_after_exact_data_readback(self):
        """The actual receipt writer sees both exact closed data files and no marker."""
        pair = self.pair()
        real = self.receipts.write_job_receipt
        def commit(directory, run_id, state, result_sha256):
            """Inspect the publication boundary, then use the unchanged real writer."""
            import json
            self.assertEqual(set(p.name for p in directory.iterdir()), {'candidate.pdf', 'manifest.json'})
            self.assertEqual((directory / 'candidate.pdf').read_bytes(), pair[0].pdf_bytes)
            manifest = json.loads((directory / 'manifest.json').read_bytes())
            self.assertEqual(result_sha256, sha256(canonical(manifest['result'])).hexdigest())
            self.assertEqual((run_id, state), (self.run_id, 'SUCCEEDED'))
            return real(directory, run_id, state, result_sha256)
        with patch.object(self.m, 'execute_bound_raster_candidate', return_value=pair), \
                patch.object(self.receipts, 'write_job_receipt', side_effect=commit) as writer:
            self.execute()
        self.assertEqual(writer.call_count, 1)

    def test_precommit_failure_is_not_recoverable(self):
        """Complete data without the exact terminal receipt is not an accepted artifact."""
        pair = self.pair()
        with patch.object(self.m, 'execute_bound_raster_candidate', return_value=pair), \
                patch.object(self.receipts, 'write_job_receipt', side_effect=OSError('commit failed')):
            with self.assertRaises(self.m.PdfBoundRasterError): self.execute()
        self.assertTrue((self.root / self.run_id / 'manifest.json').exists())
        with self.assertRaises(self.m.PdfBoundRasterError): self.recover()

    def test_postcommit_failure_requires_explicit_exact_recovery(self):
        """An exception after a valid commit returns no success and never repeats native work."""
        pair = self.pair()
        real = self.receipts.write_job_receipt
        def committed(*args):
            """Inject the failure after the real fsynced receipt returns."""
            real(*args)
            raise OSError('postcommit failure')
        with patch.object(self.m, 'execute_bound_raster_candidate', return_value=pair), \
                patch.object(self.receipts, 'write_job_receipt', side_effect=committed):
            with self.assertRaises(self.m.PdfBoundRasterError): self.execute()
        before = self.snapshot()
        with patch.object(self.m, 'execute_bound_raster_candidate', side_effect=AssertionError('no retry')):
            self.assertEqual(self.recover()[0], pair[0].pdf_bytes)
        self.assertEqual(self.snapshot(), before)

    def test_interrupt_before_commit_leaves_no_accepted_bundle(self):
        """A nonordinary interruption preserves the consumed attempt without success."""
        pair = self.pair()
        with patch.object(self.m, 'execute_bound_raster_candidate', return_value=pair), \
                patch.object(self.receipts, 'write_job_receipt', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt): self.execute()
        with self.assertRaises(self.m.PdfBoundRasterError): self.recover()

    def test_corrupt_pdf_manifest_or_receipt_is_never_repaired(self):
        """Independent original digests reject corruption in every stored component."""
        for name in ('candidate.pdf', 'manifest.json', self.run_id + '.json'):
            self.stage()
            path = self.root / self.run_id / name
            path.write_bytes(path.read_bytes() + b'changed')
            before = self.snapshot()
            with self.subTest(name=name), self.assertRaises(self.m.PdfBoundRasterError): self.recover()
            self.assertEqual(self.snapshot(), before)

    def test_missing_or_extra_files_refuse_as_incomplete(self):
        """A valid receipt alone cannot turn a partial or foreign directory into a bundle."""
        for name in ('candidate.pdf', 'manifest.json', self.run_id + '.json', 'extra'):
            self.stage()
            path = self.root / self.run_id / name
            if name == 'extra': path.write_bytes(b'foreign')
            else: path.unlink()
            with self.subTest(name=name), self.assertRaises(self.m.PdfBoundRasterError): self.recover()

    def test_unknown_missing_and_promoted_manifest_fields_refuse(self):
        """The persisted manifest is a closed protocol rather than extensible caller metadata."""
        from copy import deepcopy
        for change in ('unknown', 'missing', 'release', 'page', 'result-extra'):
            _, original = self.stage()
            manifest = deepcopy(original)
            if change == 'unknown': manifest['unknown'] = 1
            elif change == 'missing': del manifest['pdf_bytes']
            elif change == 'release': manifest['release_authorized'] = True
            elif change == 'page': manifest['page_count'] = 1
            else: manifest['result']['extra'] = 'unsupported'
            (self.root / self.run_id / 'manifest.json').write_bytes(canonical(manifest))
            with self.subTest(change=change), self.assertRaises(self.m.PdfBoundRasterError): self.recover()

    def test_duplicate_and_noncanonical_manifest_encoding_refuses(self):
        """Recovery never normalizes ambiguous fields into an apparently valid result."""
        for change in ('duplicate', 'whitespace', 'nonfinite'):
            self.stage()
            path = self.root / self.run_id / 'manifest.json'
            raw = path.read_bytes()
            if change == 'duplicate': raw = b'{"schema":"foreign",' + raw[1:]
            elif change == 'whitespace': raw += b'\n'
            else: raw = raw.replace(b'"pdf_bytes":', b'"pdf_bytes":NaN,"duplicate_pdf_bytes":', 1)
            path.write_bytes(raw)
            with self.subTest(change=change), self.assertRaises(self.m.PdfBoundRasterError): self.recover()

    def test_wrong_recovery_expectations_are_read_only_refusals(self):
        """Stored metadata never supplies its own supposedly independent output expectation."""
        self.stage()
        before = self.snapshot()
        for values in ({'expected_pdf_sha256': '0' * 64},
                       {'expected_result_sha256': '0' * 64},
                       {'expected_request_sha256': '0' * 64},
                       {'expected_resources_sha256': '0' * 64},
                       {'expected_storage_profile_sha256': self.m.PROFILE_SHA256}):
            with self.subTest(values=values), self.assertRaises(self.m.PdfBoundRasterError):
                self.recover(**values)
        self.assertEqual(self.snapshot(), before)

    def test_symlink_and_hardlink_files_are_refused(self):
        """Neither a target substitution nor an aliased inode is a private committed file."""
        for kind in ('symlink', 'hardlink'):
            self.stage()
            path = self.root / self.run_id / 'candidate.pdf'
            other = self.root / 'outside.pdf'
            if kind == 'symlink':
                path.rename(other); path.symlink_to(other)
            else: os.link(path, other)
            with self.subTest(kind=kind), self.assertRaises(self.m.PdfBoundRasterError): self.recover()

    def test_symlink_root_and_run_refuse_before_native_work(self):
        """The current path must resolve through owned directories without following links."""
        root_link = self.root / 'alias'
        root_link.symlink_to(self.root, target_is_directory=True)
        with patch.object(self.m, 'execute_bound_raster_candidate') as execute:
            with self.assertRaises(self.m.PdfBoundRasterError): self.execute(directory=root_link)
            (self.root / self.run_id).symlink_to(self.root, target_is_directory=True)
            with self.assertRaises(self.m.PdfBoundRasterError): self.execute()
            execute.assert_not_called()

    def test_same_bytes_inode_replacement_during_read_refuses(self):
        """Rechecking content alone cannot accept a replaced file in the read transaction."""
        self.stage()
        real = self.storage._read_data
        replaced = False
        def read(fd, name, limit):
            """Replace the manifest after its first successful anchored read."""
            nonlocal replaced
            data = real(fd, name, limit)
            if name == 'manifest.json' and not replaced:
                replaced = True
                path = self.root / self.run_id / name
                path.unlink(); path.write_bytes(data); path.chmod(0o600)
            return data
        with patch.object(self.storage, '_read_data', side_effect=read), self.assertRaises(self.m.PdfBoundRasterError):
            self.recover()
        self.assertTrue(replaced)

    def test_source_drift_after_generation_prevents_commit(self):
        """A once-valid native output cannot bypass a changed retained request."""
        from dataclasses import replace
        pair = self.pair()
        def changed(**_values):
            """Change only this fixture's retained request after the native stage."""
            object.__setattr__(self.bound, 'request', replace(self.bound.request, request_id='FOREIGN'))
            return pair
        with patch.object(self.m, 'execute_bound_raster_candidate', side_effect=changed):
            with self.assertRaises(self.m.PdfBoundRasterError): self.execute()
        self.assertFalse((self.root / self.run_id / (self.run_id + '.json')).exists())

    def test_resource_drift_during_commit_withholds_success(self):
        """Persisted equality cannot override changed current resource declarations."""
        pair = self.pair()
        real = self.receipts.write_job_receipt
        asset = self.assets.assets[0]
        previous = asset.rights_sha256
        def changed(*args):
            """Mutate an independently cloned asset after the commit completes."""
            result = real(*args)
            object.__setattr__(asset, 'rights_sha256', '0' * 64)
            return result
        try:
            with patch.object(self.m, 'execute_bound_raster_candidate', return_value=pair), \
                    patch.object(self.receipts, 'write_job_receipt', side_effect=changed):
                with self.assertRaises(self.m.PdfBoundRasterError): self.execute()
        finally: object.__setattr__(asset, 'rights_sha256', previous)
        self.assertEqual(self.recover()[0], pair[0].pdf_bytes)

    def test_disable_during_commit_and_recovery_withholds_return(self):
        """Live policy is rechecked after writes and after a full read transaction."""
        pair = self.pair()
        real_commit = self.receipts.write_job_receipt
        def committed(*args):
            """Disable only after the real commit, without deleting the bundle."""
            value = real_commit(*args); os.environ[DISABLE] = '1'; return value
        with patch.dict(os.environ), \
                patch.object(self.m, 'execute_bound_raster_candidate', return_value=pair), \
                patch.object(self.receipts, 'write_job_receipt', side_effect=committed):
            with self.assertRaises(self.m.PdfBoundRasterError): self.execute()
        self.assertEqual(self.recover()[0], pair[0].pdf_bytes)
        real_read = self.storage._read_data
        def read(*args):
            """Disable after a data read to exercise the final policy check."""
            value = real_read(*args); os.environ[DISABLE] = '1'; return value
        before = self.snapshot()
        with patch.dict(os.environ), patch.object(self.storage, '_read_data', side_effect=read), \
                self.assertRaises(self.m.PdfBoundRasterError):
            self.recover()
        self.assertEqual(self.snapshot(), before)


    def test_file_replacement_during_final_source_check_is_refused(self):
        """A late persistent replacement remains detectable through the final source check."""
        self.stage()
        real = self.m._storage_unchanged
        replaced = False
        def check(*args):
            """Replace a file with equal bytes after the current source has been checked."""
            nonlocal replaced
            real(*args)
            if not replaced:
                replaced = True
                path = self.root / self.run_id / 'manifest.json'
                data = path.read_bytes()
                path.unlink(); path.write_bytes(data); path.chmod(0o600)
        with patch.object(self.m, '_storage_unchanged', side_effect=check), \
                self.assertRaises(self.m.PdfBoundRasterError):
            self.recover()
        self.assertTrue(replaced)


    def test_written_pdf_replacement_during_manifest_write_prevents_commit(self):
        """The first data file must retain its identity while the second is written."""
        pair = self.pair()
        real = self.storage._write_data
        replaced = False
        def write(fd, name, data, limit):
            """Inject a persistent equal-byte substitution after the other file write."""
            nonlocal replaced
            real(fd, name, data, limit)
            if name == 'manifest.json':
                replaced = True
                path = self.root / self.run_id / 'candidate.pdf'
                previous = path.read_bytes()
                path.unlink(); path.write_bytes(previous); path.chmod(0o600)
        with patch.object(self.m, 'execute_bound_raster_candidate', return_value=pair), \
                patch.object(self.storage, '_write_data', side_effect=write):
            with self.assertRaises(self.m.PdfBoundRasterError): self.execute()
        self.assertTrue(replaced)
        self.assertFalse((self.root / self.run_id / (self.run_id + '.json')).exists())

    def test_precommit_source_check_cannot_replace_written_manifest(self):
        """The successful receipt must bind the originally written and synced data files."""
        pair = self.pair()
        real = self.m._storage_unchanged
        replaced = False
        def check(*args):
            """Replace equal manifest bytes during the source check preceding commit."""
            nonlocal replaced
            real(*args)
            run = self.root / self.run_id
            path = run / 'manifest.json'
            if path.exists() and not (run / (self.run_id + '.json')).exists() and not replaced:
                replaced = True
                previous = path.read_bytes()
                path.unlink(); path.write_bytes(previous); path.chmod(0o600)
        with patch.object(self.m, 'execute_bound_raster_candidate', return_value=pair), \
                patch.object(self.m, '_storage_unchanged', side_effect=check):
            with self.assertRaises(self.m.PdfBoundRasterError): self.execute()
        self.assertTrue(replaced)
        self.assertFalse((self.root / self.run_id / (self.run_id + '.json')).exists())

    def test_final_execution_source_check_preserves_every_committed_member(self):
        """No late replacement, deletion or corruption can escape after committed readback."""
        from pathlib import Path
        import tempfile
        pair = self.pair()
        real_read = self.m._read_stored
        real_check = self.m._storage_unchanged
        for name in ('candidate.pdf', 'manifest.json', self.run_id + '.json'):
            for mutation in ('replace-equal', 'delete', 'change'):
                with tempfile.TemporaryDirectory() as temporary:
                    self.root = Path(temporary)
                    read_completed = False
                    changed = False
                    def read(*args):
                        """Identify completion of the actual full committed read transaction."""
                        nonlocal read_completed
                        value = real_read(*args)
                        read_completed = True
                        return value
                    def check(*args):
                        """Change a named member during execution's remaining source validation."""
                        nonlocal changed
                        real_check(*args)
                        if read_completed and not changed:
                            changed = True
                            path = self.root / self.run_id / name
                            previous = path.read_bytes()
                            if mutation == 'change': path.write_bytes(previous + b'changed')
                            else:
                                path.unlink()
                                if mutation == 'replace-equal':
                                    path.write_bytes(previous); path.chmod(0o600)
                    with self.subTest(name=name, mutation=mutation), \
                            patch.object(self.m, 'execute_bound_raster_candidate', return_value=pair), \
                            patch.object(self.m, '_read_stored', side_effect=read), \
                            patch.object(self.m, '_storage_unchanged', side_effect=check):
                        with self.assertRaises(self.m.PdfBoundRasterError): self.execute()
                    self.assertTrue(changed)

    def test_descriptor_balance_after_success_and_refusal(self):
        """Repeated accepted and rejected read transactions close every owned descriptor."""
        from pathlib import Path
        self.stage()
        before = len(list(Path('/proc/self/fd').iterdir()))
        for _ in range(3):
            self.recover()
            with self.assertRaises(self.m.PdfBoundRasterError):
                self.recover(expected_pdf_sha256='0' * 64)
        self.assertEqual(len(list(Path('/proc/self/fd').iterdir())), before)

    def test_storage_profile_retains_original_envelopes_and_manifest_pins(self):
        """The storage extension cannot silently change rendering or file admission limits."""
        from reporting import pdf_candidate_store as storage
        manifest = BoundRasterManifestTests().manifest()
        profile = self.m.bound_raster_storage_profile()
        self.assertEqual(manifest['storage_profile'], profile)
        self.assertEqual(manifest['storage_profile_sha256'], self.m.STORAGE_PROFILE_SHA256)
        self.assertEqual(sha256(canonical(profile)).hexdigest(), self.m.STORAGE_PROFILE_SHA256)
        self.assertEqual(profile['candidate_profile_sha256'], self.m.PROFILE_SHA256)
        self.assertEqual((profile['max_pdf_bytes'], profile['max_manifest_bytes']),
                         (storage.MAX_PDF_BYTES, storage.MAX_MANIFEST_BYTES))
        self.assertFalse(profile['release_authorized'])
        self.assertFalse(profile['aggregate_job_resources_qualified'])
        self.assertFalse(profile['power_loss_durability_qualified'])


if __name__ == '__main__': unittest.main()
