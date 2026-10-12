"""Inert, bounded structural admission for an explicitly tiny static SVG subset.

This is NOT a general SVG sanitizer, safe renderer resource, logo rights review,
visual-fidelity check, font/profile activation or report/clinical authorization.
Only synthetic/preloaded exact-byte sources are accepted. Existing PDF resource
and action-deny profiles remain unchanged; no markup or bytes leave this module.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
import xml.etree.ElementTree as ET

from reporting.asset_registry import (
    AssetManifest, AssetRegistryError, bind_staged_asset_inventory,
)

SCHEMA_VERSION = "1.0.0"
INSPECTION_PROFILE = "staged-static-svg-subset-v1"
MAX_ENCODED_BYTES = 512 * 1024
MAX_ELEMENTS = 512
MAX_DEPTH = 16
MAX_PATH_COUNT = 256
MAX_PATH_CHARS = 4096
MAX_TOTAL_PATH_CHARS = 32768
MAX_DIMENSION = 16384
MAX_PIXELS = 4_000_000

NS = "http://www.w3.org/2000/svg"
TAG_PREFIX = "{" + NS + "}"
_VIEWBOX = re.compile(r"0 0 ([1-9][0-9]{0,4}) ([1-9][0-9]{0,4})\Z", re.ASCII)
_UINT = re.compile(r"(?:0|[1-9][0-9]{0,4})\Z", re.ASCII)
_PAINT = re.compile(r"(?:#[0-9a-fA-F]{6}|none)\Z", re.ASCII)
_PATH_CHARS = re.compile(r"[MLHVCSQTAmmlhvcsqtazAZ0-9+\-.,\s]+\Z", re.ASCII)
_ALLOWED_SHAPES = frozenset({"path", "rect", "circle"})
_ALLOWED = _ALLOWED_SHAPES | {"svg", "g"}


class SvgInspectionError(ValueError):
    """Content-free, stable error category for an unqualified SVG candidate."""


def _reject(kind: str) -> None:
    raise SvgInspectionError(kind)


def _uint(value: object, minimum: int, maximum: int) -> int:
    if type(value) is not str or not _UINT.fullmatch(value):
        _reject("svg_numeric_field_invalid")
    parsed = int(value)
    if not minimum <= parsed <= maximum:
        _reject("svg_numeric_budget_exceeded")
    return parsed


def _paint(value: object) -> None:
    if type(value) is not str or not _PAINT.fullmatch(value):
        _reject("svg_paint_not_in_static_subset")


def _validate_element(element: ET.Element, name: str, width: int, height: int) -> int:
    attrs = element.attrib
    allowed = {
        "svg": frozenset({"width", "height", "viewBox"}),
        "g": frozenset({"fill", "stroke"}),
        "path": frozenset({"d", "fill", "stroke", "stroke-width"}),
        "rect": frozenset({"x", "y", "width", "height", "fill", "stroke", "stroke-width"}),
        "circle": frozenset({"cx", "cy", "r", "fill", "stroke", "stroke-width"}),
    }[name]
    if any(type(key) is not str or key not in allowed for key in attrs):
        _reject("svg_unapproved_attribute")
    for key in ("fill", "stroke"):
        if key in attrs:
            _paint(attrs[key])
    if "stroke-width" in attrs:
        if "stroke" not in attrs or attrs["stroke"] == "none":
            _reject("svg_stroke_width_without_stroke")
        _uint(attrs["stroke-width"], 1, 32)
    if name in _ALLOWED_SHAPES and "fill" not in attrs:
        _reject("svg_shape_fill_required")
    if name == "path":
        value = attrs.get("d")
        if type(value) is not str or not 1 <= len(value) <= MAX_PATH_CHARS:
            _reject("svg_path_budget_invalid")
        if not _PATH_CHARS.fullmatch(value) or value[0] not in ("M", "m"):
            _reject("svg_path_syntax_outside_subset")
        return len(value)
    if name == "rect":
        if not {"x", "y", "width", "height"} <= attrs.keys():
            _reject("svg_rect_geometry_missing")
        for k in ("x", "y"):
            _uint(attrs[k], 0, MAX_DIMENSION)
        for k in ("width", "height"):
            _uint(attrs[k], 1, MAX_DIMENSION)
    if name == "circle":
        if not {"cx", "cy", "r"} <= attrs.keys():
            _reject("svg_circle_geometry_missing")
        for k in ("cx", "cy"):
            _uint(attrs[k], 0, MAX_DIMENSION)
        _uint(attrs["r"], 1, MAX_DIMENSION)
    return 0


@dataclass(frozen=True, slots=True, repr=False)
class SvgInspectionReceipt:
    asset_id: str
    asset_manifest_sha256: str
    input_sha256: str
    encoded_size_bytes: int
    width_px: int
    height_px: int
    element_count: int
    path_count: int
    shape_count: int
    total_path_chars: int

    def __post_init__(self) -> None:
        if type(self.asset_id) is not str or not self.asset_id:
            _reject("svg_receipt_id_invalid")
        if any(type(h) is not str or len(h) != 64 or
               any(c not in "0123456789abcdef" for c in h)
               for h in (self.asset_manifest_sha256, self.input_sha256)):
            _reject("svg_receipt_digest_invalid")
        for n, lower, upper in (
            (self.encoded_size_bytes, 1, MAX_ENCODED_BYTES),
            (self.width_px, 1, MAX_DIMENSION),
            (self.height_px, 1, MAX_DIMENSION),
            (self.element_count, 2, MAX_ELEMENTS),
            (self.shape_count, 1, MAX_ELEMENTS - 1),
            (self.path_count, 0, MAX_PATH_COUNT),
            (self.total_path_chars, 0, MAX_TOTAL_PATH_CHARS),
        ):
            if type(n) is not int or not lower <= n <= upper:
                _reject("svg_receipt_bounds_invalid")
        if self.width_px * self.height_px > MAX_PIXELS or self.path_count > self.shape_count:
            _reject("svg_receipt_geometry_or_count_invalid")
        if self.path_count == 0 and self.total_path_chars != 0:
            _reject("svg_receipt_path_chars_invalid")
        if self.path_count and self.total_path_chars < self.path_count:
            _reject("svg_receipt_path_chars_invalid")

    def to_dict(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "schema_version": SCHEMA_VERSION,
            "profile_id": INSPECTION_PROFILE,
            "status": "SVG_STRUCTURALLY_INSPECTED_UNQUALIFIED",
            "conformance_scope": "BOUNDED_STATIC_SVG_SUBSET_STRUCTURE_ONLY",
            "asset_id": self.asset_id,
            "asset_manifest_sha256": self.asset_manifest_sha256,
            "input_sha256": self.input_sha256,
            "encoded_size_bytes": self.encoded_size_bytes,
            "width_px": self.width_px,
            "height_px": self.height_px,
            "element_count": self.element_count,
            "path_count": self.path_count,
            "shape_count": self.shape_count,
            "total_path_chars": self.total_path_chars,
            "original_bytes_retained": False,
            "svg_sanitized": False,
            "brand_rights_verified": False,
            "source_authenticated": False,
            "visual_fidelity_verified": False,
            "accessibility_qualified": False,
            "renderer_activated": False,
            "asset_activated": False,
            "full_os_sandbox_claim": False,
            "release_authorization": "NOT_ESTABLISHED",
        }


def inspect_staged_svg(
    *, expected_manifest: AssetManifest, resolved_manifest: AssetManifest,
    svg_bytes: bytes,
) -> SvgInspectionReceipt:
    """Validate exact preloaded bytes and reject all SVG outside the inert subset."""
    if type(svg_bytes) is not bytes or not 8 <= len(svg_bytes) <= MAX_ENCODED_BYTES:
        _reject("svg_encoded_budget_or_type_invalid")
    if type(expected_manifest) is not AssetManifest or type(resolved_manifest) is not AssetManifest:
        _reject("svg_typed_asset_manifest_required")
    try:
        bind_staged_asset_inventory(
            expected_manifest=expected_manifest,
            resolved_manifest=resolved_manifest,
            supplied_bytes=(svg_bytes,),
        )
    except AssetRegistryError:
        _reject("svg_exact_asset_binding_failed")
    asset = expected_manifest.assets[0]
    if asset.role != "brand-logo" or asset.media_type != "image/svg+xml":
        _reject("svg_asset_role_not_admitted")

    # Reject XML syntactic expansion, alternate namespaces and instructions
    # before invoking the parser. This subset does not use XML entities.
    try:
        text = svg_bytes.decode("ascii")
    except UnicodeDecodeError:
        _reject("svg_non_ascii_input_outside_subset")
    if any(token in text for token in ("<!", "<?", "&", "xmlns:")):
        _reject("svg_xml_declaration_or_entity_forbidden")
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, ValueError):
        _reject("svg_xml_structure_invalid")
    if root.tag != TAG_PREFIX + "svg":
        _reject("svg_default_root_namespace_required")
    if set(root.attrib) != {"width", "height", "viewBox"}:
        _reject("svg_root_attributes_invalid")
    width = _uint(root.attrib["width"], 1, MAX_DIMENSION)
    height = _uint(root.attrib["height"], 1, MAX_DIMENSION)
    v = _VIEWBOX.fullmatch(root.attrib["viewBox"])
    if not v or int(v.group(1)) != width or int(v.group(2)) != height:
        _reject("svg_viewbox_outside_exact_source_geometry")
    if width != asset.declared_width_px or height != asset.declared_height_px:
        _reject("svg_declared_dimensions_mismatch")
    if width * height > MAX_PIXELS:
        _reject("svg_pixel_budget_exceeded")

    stack = [(root, 0)]
    nodes = shapes = paths = path_chars = 0
    while stack:
        el, depth = stack.pop()
        nodes += 1
        if nodes > MAX_ELEMENTS or depth > MAX_DEPTH:
            _reject("svg_node_depth_budget_exceeded")
        if type(el.tag) is not str or not el.tag.startswith(TAG_PREFIX):
            _reject("svg_unknown_xml_namespace")
        name = el.tag[len(TAG_PREFIX):]
        if name not in _ALLOWED:
            _reject("svg_element_not_in_static_subset")
        if name == "svg" and el is not root:
            _reject("svg_nested_root_forbidden")
        if (el.text is not None and el.text.strip()) or (el.tail is not None and el.tail.strip()):
            _reject("svg_text_nodes_outside_subset")
        path_chars += _validate_element(el, name, width, height)
        if name in _ALLOWED_SHAPES:
            shapes += 1
        if name == "path":
            paths += 1
        if paths > MAX_PATH_COUNT or path_chars > MAX_TOTAL_PATH_CHARS:
            _reject("svg_path_resource_budget_exceeded")
        for child in reversed(list(el)):
            stack.append((child, depth + 1))
    if not shapes:
        _reject("svg_no_static_geometry")
    return SvgInspectionReceipt(
        asset_id=asset.asset_id,
        asset_manifest_sha256=expected_manifest.manifest_sha256,
        input_sha256=hashlib.sha256(svg_bytes).hexdigest(),
        encoded_size_bytes=len(svg_bytes),
        width_px=width, height_px=height,
        element_count=nodes, path_count=paths, shape_count=shapes,
        total_path_chars=path_chars,
    )
