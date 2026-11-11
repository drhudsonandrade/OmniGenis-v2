"""Preloaded raster bundles keep exact PNG bytes and deny external resolution."""
from dataclasses import FrozenInstanceError
from hashlib import sha256
from importlib import import_module, util
import json
import struct
import unittest
import zlib


def png(width=2, height=2, value=31, *, extra=b''):
    """Build a synthetic RGB PNG independently of the implementation."""
    def chunk(kind, data):
        """Encode one synthetic PNG chunk with its independent length and CRC."""
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 0xffffffff)
    raw = (b'\0' + bytes([value]) * width * 3) * height
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b'') + extra)


class RasterResourceTests(unittest.TestCase):
    def setUp(self):
        """Fail clearly before relying on the new opt-in contract."""
        self.assertIsNotNone(util.find_spec('reporting.pdf_raster_resources'), 'preloaded raster resource boundary missing')
        self.m = import_module('reporting.pdf_raster_resources')

    def asset(self, **changes):
        """Supply immutable bytes and independent exact expected metadata."""
        raw = changes.pop('png_bytes', png())
        values = dict(asset_id='synthetic-raster', png_bytes=raw, expected_sha256=sha256(raw).hexdigest(),
                      width_px=2, height_px=2, source_sha256='a' * 64, rights_sha256='b' * 64)
        values.update(changes)
        return self.m.RasterAsset(**values)

    def bundle(self):
        """Create the smallest independently pinned immutable resource inventory."""
        return self.m.RasterBundle((self.asset(),))

    def test_exact_immutable_roundtrip(self):
        """All original asset bytes and metadata survive the exact binary framing."""
        bundle = self.bundle(); raw = bundle.to_bytes()
        restored = self.m.read_bundle(raw, expected_sha256=sha256(raw).hexdigest())
        self.assertEqual(restored.to_bytes(), raw)
        self.assertEqual(restored.assets[0].png_bytes, png())
        self.assertEqual(bundle.bundle_sha256, sha256(raw).hexdigest())
        with self.assertRaises(FrozenInstanceError): bundle.assets = ()

    def test_wrong_digest_rejected(self):
        """A correct PNG cannot cross a mismatched independent content expectation."""
        with self.assertRaises(self.m.RasterResourceError): self.asset(expected_sha256='0' * 64)

    def test_declared_geometry_rejected(self):
        """Declared dimensions must match the actual bounded PNG header."""
        for field in ('width_px', 'height_px'):
            with self.subTest(field=field), self.assertRaises(self.m.RasterResourceError): self.asset(**{field: 3})

    def test_types_and_opaque_ids_are_strict(self):
        """Coercible values and path-shaped identifiers are not admitted."""
        for change in ({'width_px': True}, {'height_px': 2.0}, {'asset_id': '../private'},
                       {'asset_id': 'a/b'}, {'png_bytes': bytearray(png())},
                       {'source_sha256': 'A' * 64}, {'rights_sha256': None}):
            with self.subTest(field=next(iter(change))), self.assertRaises(self.m.RasterResourceError): self.asset(**change)

    def test_png_crc_and_trailing_data_rejected(self):
        """Container corruption and surplus bytes cannot become a valid resource."""
        for raw in (png() + b'extra', png()[:-2], png()[:33] + b'broken', b'not PNG'):
            with self.subTest(size=len(raw)), self.assertRaises(self.m.RasterResourceError): self.asset(png_bytes=raw)

    def test_wrong_bundle_digest_and_trailing_bytes_rejected(self):
        """The outer identity and exact envelope end are independently required."""
        raw = self.bundle().to_bytes()
        for data, digest in ((raw, '0' * 64), (raw + b'junk', sha256(raw + b'junk').hexdigest())):
            with self.assertRaises(self.m.RasterResourceError): self.m.read_bundle(data, expected_sha256=digest)

    def test_framing_truncation_refused(self):
        """No prefix of a valid envelope can be returned as a complete bundle."""
        raw = self.bundle().to_bytes()
        for cut in (0, 7, 12, len(raw) - 1):
            data = raw[:cut]
            with self.subTest(cut=cut), self.assertRaises(self.m.RasterResourceError):
                self.m.read_bundle(data, expected_sha256=sha256(data).hexdigest())

    def test_duplicate_assets_and_mutable_collection_rejected(self):
        """The resource set is a finite immutable tuple of unique exact declarations."""
        asset = self.asset()
        for values in ([asset], (), (asset, asset), (asset,) * 4):
            with self.subTest(count=len(values)), self.assertRaises(self.m.RasterResourceError): self.m.RasterBundle(values)

    def test_duplicate_digest_under_different_id_rejected(self):
        """Aliases cannot inflate resource counts or repeat the same retained bytes."""
        with self.assertRaises(self.m.RasterResourceError):
            self.m.RasterBundle((self.asset(), self.asset(asset_id='another')))

    def test_tampered_retained_object_refused(self):
        """A changed source or rights reference cannot reuse an earlier object seal."""
        bundle = self.bundle(); object.__setattr__(bundle.assets[0], 'rights_sha256', 'c' * 64)
        with self.assertRaises(self.m.RasterResourceError): bundle.to_bytes()

    def test_external_and_lookalike_uris_are_denied(self):
        """Only a literal preloaded resource key is resolvable, with no fallback."""
        bundle = self.bundle(); fetcher = self.m.make_fetcher(bundle)
        uri = bundle.assets[0].uri
        for url in ('https://example.invalid/a.png', 'file:///etc/passwd', 'data:image/png;base64,AA==',
                    uri + '?x=1', uri + '#x', uri.upper(), 'omnigenis-raster:' + '0' * 64):
            with self.subTest(url=url), self.assertRaises(self.m.RasterResourceError): fetcher.fetch(url)

    def test_only_exact_preloaded_resource_is_returned(self):
        """Each response contains the original bytes and records exact use."""
        bundle = self.bundle(); fetcher = self.m.make_fetcher(bundle)
        with self.assertRaises(self.m.RasterResourceError): fetcher.require_complete()
        response = fetcher.fetch(bundle.assets[0].uri)
        self.assertEqual(response.read(), png())
        response.close(); fetcher.require_complete()

    def test_no_resource_rights_or_release_authority_inferred(self):
        """Byte consistency is not legal authority, source authentication or release."""
        profile = self.m.resource_profile()
        for key in ('rights_authenticated', 'source_authenticated', 'release_authorized', 'default_pipeline_activated'):
            self.assertIs(profile[key], False)
        self.assertEqual(profile['max_assets'], 3)
        self.assertEqual(profile['max_asset_bytes'], 4 * 1024 * 1024)

    def test_all_three_different_resources_required(self):
        """The exact declared inventory must all be requested before success."""
        assets = tuple(self.asset(asset_id='asset-' + str(i), png_bytes=png(value=i)) for i in range(3))
        bundle = self.m.RasterBundle(assets); fetcher = self.m.make_fetcher(bundle)
        for asset in assets[:2]: fetcher.fetch(asset.uri).close()
        with self.assertRaises(self.m.RasterResourceError): fetcher.require_complete()
        fetcher.fetch(assets[-1].uri).close(); fetcher.require_complete()


class RasterBundleAdversarialTests(unittest.TestCase):
    """Additional wire and budget checks use native malformed values, not external I/O."""
    setUp = RasterResourceTests.setUp
    asset = RasterResourceTests.asset
    bundle = RasterResourceTests.bundle

    def wire(self, metadata, payload=b''):
        """Make an independently framed candidate for strict decoder refusals."""
        return b'ORP1' + struct.pack('>I', len(metadata)) + metadata + payload

    def refuse(self, raw):
        """Keep the outer digest correct so the inner shape must actually reject."""
        with self.assertRaises(self.m.RasterResourceError):
            self.m.read_bundle(raw, expected_sha256=sha256(raw).hexdigest())

    def test_duplicate_and_noncanonical_metadata_refuse(self):
        """Rehashing malformed metadata cannot bypass exact canonical framing."""
        raw = self.bundle().to_bytes(); size = struct.unpack_from('>I', raw, 4)[0]
        metadata, payload = raw[8:8 + size], raw[8 + size:]
        for altered in (metadata + b' ', metadata[:-1] + b',"schema":"preloaded-png-bundle-v1"}',
                        b'NaN', b'[]', b'{"assets":[],"schema":"unknown"}'):
            with self.subTest(size=len(altered)): self.refuse(self.wire(altered, payload))

    def test_declared_size_type_fields_and_geometry_refuse(self):
        """Correct outer hashes do not excuse altered inner resource declarations."""
        raw = self.bundle().to_bytes(); size = struct.unpack_from('>I', raw, 4)[0]
        original = json.loads(raw[8:8 + size]); payload = raw[8 + size:]
        changes = ({'png_size_bytes': True}, {'png_size_bytes': len(payload) - 1},
                   {'width_px': 2.0}, {'height_px': 3}, {'extra': 'field'},
                   {'source_sha256': 'invalid'}, {'rights_sha256': None})
        for change in changes:
            metadata = json.loads(json.dumps(original)); metadata['assets'][0].update(change)
            encoded = json.dumps(metadata, sort_keys=True, separators=(',', ':')).encode()
            with self.subTest(field=next(iter(change))): self.refuse(self.wire(encoded, payload))

    def test_oversized_encoded_payload_refuses_before_png_parse(self):
        """Encoded limits apply before decompression or resource interpretation."""
        from unittest.mock import patch
        raw = b'x' * (4 * 1024 * 1024 + 1)
        with patch.object(self.m, '_inspect_png_container') as parser:
            with self.assertRaises(self.m.RasterResourceError): self.asset(png_bytes=raw)
        parser.assert_not_called()

    def test_pixel_budget_refuses_before_deflate(self):
        """Oversized dimensions are rejected before any zlib decompression."""
        from unittest.mock import patch
        raw = png(); header = struct.pack('>IIBBBBB', 16384, 16384, 8, 2, 0, 0, 0)
        altered = raw[:16] + header + struct.pack('>I', zlib.crc32(b'IHDR' + header) & 0xffffffff) + raw[33:]
        with patch('reporting.png_inspection.zlib.decompressobj') as decode:
            with self.assertRaises(self.m.RasterResourceError):
                self.asset(png_bytes=altered, width_px=16384, height_px=16384)
        decode.assert_not_called()

    def test_unsupported_chunks_and_concatenated_zlib_refuse(self):
        """Unapproved PNG metadata and extra deflate members remain forbidden."""
        def chunk(kind, value):
            """Encode one synthetic PNG chunk with its independent length and CRC."""
            return struct.pack('>I', len(value)) + kind + value + struct.pack('>I', zlib.crc32(kind + value) & 0xffffffff)
        raw = png(); data_len = struct.unpack_from('>I', raw, 33)[0]
        compressed = raw[41:41 + data_len]
        for altered in (raw[:33] + chunk(b'tEXt', b'private') + raw[33:],
                        raw[:33] + chunk(b'IDAT', compressed + zlib.compress(b'extra')) + raw[-12:]):
            with self.assertRaises(self.m.RasterResourceError): self.asset(png_bytes=altered)

    def test_resolver_does_not_open_any_external_handler(self):
        """Accepted and rejected resource lookups never invoke the general opener."""
        from unittest.mock import patch
        fetcher = self.m.make_fetcher(self.bundle())
        with patch('urllib.request.OpenerDirector.open', side_effect=AssertionError('external open')) as opened:
            response = fetcher.fetch(self.bundle().assets[0].uri)
            self.assertEqual(response.read(), png()); response.close()
            with self.assertRaises(self.m.RasterResourceError): fetcher.fetch('https://example.invalid/a')
        opened.assert_not_called()


if __name__ == '__main__': unittest.main()
