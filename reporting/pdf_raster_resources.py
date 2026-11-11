"""Exact preloaded PNG resources for an explicitly selected qualification renderer.

This boundary resolves immutable bytes, not paths or general URLs. It reuses the
existing bounded PNG container grammar. Declared source and rights digests prove
consistency only; no legal authority, pixel sanitization, visual equivalence,
scientific meaning, supported release or default renderer activation is inferred.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
import re
import struct

from reporting.png_inspection import _inspect_png_container, MAX_ENCODED_BYTES, MAX_PIXEL_COUNT

MAX_ASSETS = 3
MAX_TOTAL_BYTES = 3 * MAX_ENCODED_BYTES
MAX_TOTAL_PIXELS = 3 * MAX_PIXEL_COUNT
MAX_METADATA_BYTES = 16 * 1024
MAX_BUNDLE_BYTES = MAX_TOTAL_BYTES + MAX_METADATA_BYTES + 8
_MAGIC = b'ORP1'
_SCHEMA = 'preloaded-png-bundle-v1'
_FIELDS = frozenset(('asset_id', 'sha256', 'png_size_bytes', 'width_px', 'height_px',
                     'source_sha256', 'rights_sha256'))


class RasterResourceError(ValueError):
    """A fixed refusal that never exposes resource content or private locations."""


def _require(value: bool) -> None:
    """Refuse unverifiable resource structure without reflecting its values."""
    if not value:
        raise RasterResourceError('preloaded_raster_resource_invalid')


def _digest(value: object) -> None:
    """Require a native, unnormalized lowercase SHA-256 identifier."""
    _require(type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None)


def _canonical(value: object) -> bytes:
    """Use the existing deterministic compact UTF-8 JSON representation."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


def resource_profile() -> dict:
    """Declare finite resource admission separately from rights or release approval."""
    return {'profile_id': _SCHEMA, 'max_assets': MAX_ASSETS,
        'max_asset_bytes': MAX_ENCODED_BYTES, 'max_asset_pixels': MAX_PIXEL_COUNT,
        'max_total_bytes': MAX_TOTAL_BYTES, 'max_total_pixels': MAX_TOTAL_PIXELS,
        'max_metadata_bytes': MAX_METADATA_BYTES, 'media_type': 'image/png',
        'resolver': 'EXACT_PRELOADED_SHA256_URI_ONLY_NO_FALLBACK',
        'every_resource_must_be_requested': True, 'source_authenticated': False,
        'rights_authenticated': False, 'default_pipeline_activated': False,
        'release_authorized': False}


@dataclass(frozen=True)
class RasterAsset:
    """One exact finite PNG plus independently supplied declaration digests."""
    asset_id: str
    png_bytes: bytes = field(repr=False)
    expected_sha256: str
    width_px: int
    height_px: int
    source_sha256: str
    rights_sha256: str
    _seal: str = field(init=False, repr=False, compare=False)

    def _metadata(self) -> dict:
        """Verify the original bytes and their finite geometry before returning metadata."""
        _require(type(self) is RasterAsset)
        _require(type(self.asset_id) is str and re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,79}', self.asset_id) is not None)
        for value in (self.expected_sha256, self.source_sha256, self.rights_sha256):
            _digest(value)
        _require(type(self.png_bytes) is bytes and 8 <= len(self.png_bytes) <= MAX_ENCODED_BYTES)
        _require(sha256(self.png_bytes).hexdigest() == self.expected_sha256)
        try:
            _inspect_png_container(self.png_bytes, self.width_px, self.height_px)
        except Exception:
            raise RasterResourceError('preloaded_raster_resource_invalid') from None
        return {'asset_id': self.asset_id, 'sha256': self.expected_sha256,
            'png_size_bytes': len(self.png_bytes), 'width_px': self.width_px,
            'height_px': self.height_px, 'source_sha256': self.source_sha256,
            'rights_sha256': self.rights_sha256}

    def __post_init__(self) -> None:
        """Seal once and refuse attempts to silently reseal a retained changed object."""
        digest = sha256(_canonical(self._metadata())).hexdigest()
        _require(not hasattr(self, '_seal') or self._seal == digest)
        object.__setattr__(self, '_seal', digest)

    def metadata(self) -> dict:
        """Return detached verified metadata, never a mutable internal record."""
        value = self._metadata()
        _require(sha256(_canonical(value)).hexdigest() == self._seal)
        return value

    @property
    def uri(self) -> str:
        """Expose the sole exact resource identifier, not a filesystem or network URL."""
        self.metadata()
        return 'omnigenis-raster:' + self.expected_sha256


@dataclass(frozen=True)
class RasterBundle:
    """A closed, ordered, immutable resource set with aggregate preflight limits."""
    assets: tuple[RasterAsset, ...]
    _seal: str = field(init=False, repr=False, compare=False)

    def _wire(self) -> bytes:
        """Reject aggregate overflow before parsing or copying each resource payload."""
        _require(type(self) is RasterBundle and type(self.assets) is tuple
                 and 1 <= len(self.assets) <= MAX_ASSETS)
        _require(all(type(asset) is RasterAsset for asset in self.assets))
        _require(all(type(a.png_bytes) is bytes and type(a.width_px) is int
                     and type(a.height_px) is int for a in self.assets))
        _require(sum(len(a.png_bytes) for a in self.assets) <= MAX_TOTAL_BYTES)
        _require(sum(a.width_px * a.height_px for a in self.assets) <= MAX_TOTAL_PIXELS)
        records = [a.metadata() for a in self.assets]
        _require(len({r['asset_id'] for r in records}) == len(records)
                 and len({r['sha256'] for r in records}) == len(records))
        metadata = _canonical({'schema': _SCHEMA, 'assets': records})
        _require(len(metadata) <= MAX_METADATA_BYTES)
        return _MAGIC + struct.pack('>I', len(metadata)) + metadata + b''.join(a.png_bytes for a in self.assets)

    def __post_init__(self) -> None:
        """Seal the complete canonical envelope and all original resource bytes."""
        digest = sha256(self._wire()).hexdigest()
        _require(not hasattr(self, '_seal') or self._seal == digest)
        object.__setattr__(self, '_seal', digest)

    def to_bytes(self) -> bytes:
        """Revalidate before returning the exact bounded descriptor payload."""
        raw = self._wire(); _require(sha256(raw).hexdigest() == self._seal)
        return raw

    @property
    def bundle_sha256(self) -> str:
        """Identify the exact retained bundle after current integrity checks."""
        return sha256(self.to_bytes()).hexdigest()


def read_bundle(raw: bytes, *, expected_sha256: str) -> RasterBundle:
    """Decode exact canonical framing without paths, arbitrary iterables or fallback."""
    try:
        _digest(expected_sha256)
        _require(type(raw) is bytes and 8 <= len(raw) <= MAX_BUNDLE_BYTES
                 and raw[:4] == _MAGIC and sha256(raw).hexdigest() == expected_sha256)
        size = struct.unpack_from('>I', raw, 4)[0]
        _require(0 < size <= MAX_METADATA_BYTES and 8 + size < len(raw))
        def unique(pairs):
            """Reject duplicate JSON keys instead of silently replacing prior fields."""
            out = {}
            for key, value in pairs:
                _require(key not in out); out[key] = value
            return out
        def invalid_number(_value):
            """Reject floats and nonfinite numbers in the integer-only resource protocol."""
            raise RasterResourceError('preloaded_raster_resource_invalid')
        metadata = json.loads(raw[8:8 + size], object_pairs_hook=unique,
                              parse_float=invalid_number, parse_constant=invalid_number)
        _require(type(metadata) is dict and set(metadata) == {'schema', 'assets'}
                 and metadata['schema'] == _SCHEMA and type(metadata['assets']) is list
                 and 1 <= len(metadata['assets']) <= MAX_ASSETS)
        _require(_canonical(metadata) == raw[8:8 + size])
        position = 8 + size; assets = []
        for row in metadata['assets']:
            _require(type(row) is dict and set(row) == _FIELDS)
            count = row['png_size_bytes']
            _require(type(count) is int and 8 <= count <= MAX_ENCODED_BYTES
                     and position + count <= len(raw))
            assets.append(RasterAsset(row['asset_id'], raw[position:position + count], row['sha256'],
                row['width_px'], row['height_px'], row['source_sha256'], row['rights_sha256']))
            position += count
        _require(position == len(raw))
        bundle = RasterBundle(tuple(assets)); _require(bundle.to_bytes() == raw)
        return bundle
    except Exception:
        raise RasterResourceError('preloaded_raster_resource_invalid') from None


def make_fetcher(bundle: RasterBundle):
    """Construct an exact in-memory resolver only; never call an external handler.

    Native image decoding occurs later inside the resource-limited render worker.
    This resolver grants no legal, scientific or final-publication authority.
    """
    _require(type(bundle) is RasterBundle)
    bundle.to_bytes()
    from weasyprint.urls import URLFetcher, URLFetcherResponse
    resources = {asset.uri: asset.png_bytes for asset in bundle.assets}

    class PreloadedFetcher(URLFetcher):
        """Never fall back to network, file, data, redirected or lookalike resources."""
        def __init__(self):
            super().__init__(allowed_protocols=(), allow_redirects=False, fail_on_errors=True)
            self._used = set()

        def fetch(self, url, headers=None):
            """Serve only a literal member of the sealed resource inventory."""
            _require(type(url) is str and url in resources and headers in (None, {}))
            self._used.add(url)
            return URLFetcherResponse(url, resources[url], {'Content-Type': 'image/png'})

        def require_complete(self):
            """Unused payloads cannot silently inflate a supposedly consumed bundle."""
            _require(self._used == set(resources))

    return PreloadedFetcher()
