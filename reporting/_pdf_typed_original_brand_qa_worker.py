"""Confined complete native accounting for the separate typed/original-brand QA."""
from __future__ import annotations

from decimal import Decimal
from hashlib import sha256
from importlib.metadata import version
from io import BytesIO
import logging
import os
from pathlib import Path
import re
import signal
import stat
import sys
import xml.etree.ElementTree as ET
import zlib

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reporting import typed_original_brand_qa as qa
from reporting import pdf_typed_observation as contract
from reporting import _pdf_typed_observation_worker as native
from reporting import _pdf_safety_worker as passive
from reporting._pdf_original_svg_layout_worker import _inspect_figure
from reporting._pdf_resource_leaves_worker import _lab_presets
from reporting._pdf_process_sandbox import enforce_pdf_landlock, enforce_pdf_network_filter
from reporting._pdf_render_worker import _arm_worker_lifetime, _write_bytes

require = qa.require
IDENTITY = tuple(map(Decimal, ("1", "0", "0", "1", "0", "0")))


def _limits() -> dict:
    """Install the combined QA profile's finite process limits before input."""
    import resource

    values = (
        (resource.RLIMIT_AS, qa.LIMITS["memory_bytes"]),
        (resource.RLIMIT_CPU, qa.LIMITS["cpu_seconds"]),
        (resource.RLIMIT_FSIZE, qa.LIMITS["file_bytes"]),
        (resource.RLIMIT_NOFILE, qa.LIMITS["open_files"]),
        (resource.RLIMIT_CORE, 0),
    )
    for key, value in values:
        resource.setrlimit(key, (value, value))
    require(all(resource.getrlimit(key) == (value, value) for key, value in values))
    limits = {
        "memory_bytes": resource.getrlimit(resource.RLIMIT_AS)[0],
        "cpu_seconds": resource.getrlimit(resource.RLIMIT_CPU)[0],
        "file_bytes": resource.getrlimit(resource.RLIMIT_FSIZE)[0],
        "open_files": resource.getrlimit(resource.RLIMIT_NOFILE)[0],
    }
    require(limits == qa.LIMITS)
    return limits


def _lifetime(parent: int) -> None:
    """Retain parent-death binding and the combined QA profile's fixed timer."""
    _arm_worker_lifetime(parent)
    signal.setitimer(signal.ITIMER_REAL, qa.WALL_SECONDS)


def _identifier(value):
    """Keep byte-string identity in the existing bounded opaque string field."""
    from pypdf.generic import TextStringObject
    require(type(value) is TextStringObject)
    data = value.original_bytes
    require(type(data) is bytes and 0 < len(data) <= 128)
    return data.decode("latin-1")


def _structure_id_tree(reader, value, expected):
    """Reconcile the flat name index with the admitted original-byte ID map."""
    from pypdf.generic import ArrayObject
    index = native._dictionary(value, reader)
    require(set(index) == {"/Names"})
    names = index.raw_get("/Names")
    require(type(names) is ArrayObject and len(names) == 2 * len(expected)
            and len(names) <= contract.MAX_VISITS)
    observed, previous = {}, None
    for offset in range(0, len(names), 2):
        identifier = _identifier(names[offset]).encode("latin-1")
        reference = tuple(native._ref(names[offset + 1], reader))
        require((previous is None or previous < identifier)
                and identifier in expected and reference == expected[identifier])
        observed[identifier] = reference
        previous = identifier
    require(observed == expected)


def _structure(reader, pages):
    from pypdf.generic import (
        ArrayObject, DictionaryObject, IndirectObject, NameObject,
        NumberObject, TextStringObject,
    )
    root_ref = reader.root_object.raw_get("/StructTreeRoot")
    root = native._dictionary(root_ref, reader)
    require({"/Type", "/K", "/ParentTree"} <= set(root)
            <= {"/Type", "/K", "/ParentTree", "/IDTree"}
            and root.raw_get("/Type") == "/StructTreeRoot")
    trace = {"root_reference": native._ref(root_ref, reader), "root_children_form": "",
             "root_children": [], "nodes": [], "pages": [], "fonts": []}
    page_keys = {}
    page_refs = {tuple(native._ref(ref, reader)) for ref, _, _ in pages}
    for index, (ref, page, _) in enumerate(pages):
        require("/Annots" not in page)
        number = page.raw_get("/StructParents")
        require(type(number) is NumberObject and 0 <= number < contract.MAX_VISITS
                and int(number) not in page_keys)
        page_keys[int(number)] = ref
        trace["pages"].append({
            "index": index, "reference": native._ref(ref, reader),
            "struct_parents": int(number), "mcid_owners": [],
            "font_resources": [], "graphics_states": [], "events": [], "runs": []})
    parent = native._dictionary(root.raw_get("/ParentTree"), reader)
    require(set(parent) == {"/Nums"})
    nums = parent.raw_get("/Nums")
    require(type(nums) is ArrayObject and len(nums) == 2 * len(pages))
    reverse, owner_total, previous = {}, 0, -1
    for i in range(0, len(nums), 2):
        number, owners = nums[i:i + 2]
        require(type(number) is NumberObject and int(number) in page_keys
                and int(number) > previous and int(number) not in reverse
                and type(owners) is ArrayObject and 0 < len(owners) <= contract.MAX_VISITS)
        previous = int(number)
        owner_total += len(owners)
        require(owner_total <= contract.MAX_VISITS)
        reverse[int(number)] = [
            {"mcid": j, "structure_reference": native._ref(owner, reader)}
            for j, owner in enumerate(owners)]
    for page in trace["pages"]:
        page["mcid_owners"] = reverse[page["struct_parents"]]
    seen, attributes, figures = set(), set(), set()
    visits = 0

    def kids(raw):
        if type(raw) is ArrayObject:
            require(len(raw) <= contract.MAX_VISITS)
            return "array", list(raw)
        if type(raw) is IndirectObject:
            return "reference", [raw]
        require(type(raw) is NumberObject)
        return "mcid", [raw]

    def walk(ref, parent_ref, depth):
        nonlocal visits
        key = tuple(native._ref(ref, reader))
        require(key not in seen and depth <= contract.MAX_DEPTH)
        seen.add(key)
        obj = native._dictionary(ref, reader)
        require({"/Type", "/S", "/P", "/K"} <= set(obj)
                and set(obj) <= {"/Type", "/S", "/P", "/K", "/Pg", "/A", "/ID", "/Alt"}
                and type(obj.raw_get("/Type")) is NameObject
                and obj.raw_get("/Type") == "/StructElem"
                and type(obj.raw_get("/S")) is NameObject
                and native._ref(obj.raw_get("/P"), reader) == native._ref(parent_ref, reader))
        role = str(obj.raw_get("/S"))
        require(role in set(contract.ROLES) | {"/Div", "/Sect", "/Figure", "/NonStruct"})
        form, children = kids(obj.raw_get("/K"))
        visits += 1 + len(children)
        require(visits <= contract.MAX_VISITS)
        row = {
            "reference": list(key), "parent": native._ref(parent_ref, reader), "role": role,
            "page_reference": native._ref(obj.raw_get("/Pg"), reader) if "/Pg" in obj else None,
            "children_form": form, "children": [], "table_attribute": False,
            "native_id": None, "headers": [], "alternate_text": None, "figure_bbox": None}
        if role in {"/TH", "/TD"}:
            attribute = obj.raw_get("/A")
            require(type(attribute) is DictionaryObject
                    and set(attribute) == ({"/O"} if role == "/TH" else {"/O", "/Headers"})
                    and type(attribute.raw_get("/O")) is NameObject
                    and attribute.raw_get("/O") == "/Table" and "/Alt" not in obj)
            row["table_attribute"] = True
            attributes.add(id(obj))
            if role == "/TH":
                value = obj.raw_get("/ID")
                require(type(value) is TextStringObject and 0 < len(value) <= 128)
                row["native_id"] = _identifier(value)
            else:
                values = attribute.raw_get("/Headers")
                require("/ID" not in obj and type(values) is ArrayObject and len(values) == 1
                        and type(values[0]) is TextStringObject and 0 < len(values[0]) <= 128)
                row["headers"] = [_identifier(values[0])]
        elif role == "/Figure":
            require("/ID" not in obj and type(obj.raw_get("/Alt")) is TextStringObject
                    and str(obj.raw_get("/Alt")) == qa.LOGO_ALT)
            _inspect_figure(obj, page_refs)
            row["alternate_text"] = str(obj.raw_get("/Alt"))
            row["figure_bbox"] = [native._number(v) for v in obj.raw_get("/A").raw_get("/BBox")]
            attributes.add(id(obj))
            figures.add(id(obj))
        else:
            require(not {"/A", "/ID", "/Alt"}.intersection(obj))
        trace["nodes"].append(row)
        for ordinal, child in enumerate(children):
            if type(child) is IndirectObject:
                row["children"].append(
                    {"ordinal": ordinal, "kind": "node", "reference": native._ref(child, reader)})
                walk(child, ref, depth + 1)
            else:
                require(type(child) is NumberObject and 0 <= child < contract.MAX_VISITS)
                row["children"].append({"ordinal": ordinal, "kind": "mcid", "value": int(child)})

    form, roots = kids(root.raw_get("/K"))
    require(form != "mcid" and len(roots) == 1)
    trace["root_children_form"] = form
    trace["root_children"] = [native._ref(ref, reader) for ref in roots]
    walk(roots[0], root_ref, 1)
    require(len(figures) == 1)
    qa.project_text_trace(trace)
    expected = {}
    for node in trace["nodes"]:
        if node["native_id"] is not None:
            identifier = node["native_id"].encode("latin-1")
            require(identifier not in expected)
            expected[identifier] = tuple(node["reference"])
    require(not expected or "/IDTree" in root)
    if "/IDTree" in root:
        _structure_id_tree(reader, root.raw_get("/IDTree"), expected)
    return trace, attributes, figures


def _passive(reader, attributes, figures):
    """Permit attributes only on the exact validated Table/Figure objects."""
    from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject, NameObject, PdfObject, StreamObject
    pending, references, containers = [(reader.trailer, 0)], set(), set()
    visits = 0
    while pending:
        value, depth = pending.pop()
        require(depth <= contract.MAX_DEPTH)
        if type(value) is IndirectObject:
            key = tuple(native._ref(value, reader))
            if key in references:
                continue
            references.add(key)
            value = value.get_object()
        require(isinstance(value, PdfObject) and not isinstance(value, IndirectObject))
        if isinstance(value, (DictionaryObject, ArrayObject)):
            if id(value) in containers:
                continue
            containers.add(id(value))
        visits += 1
        require(visits <= contract.MAX_VISITS)
        children = ()
        if isinstance(value, DictionaryObject):
            require(all(type(k) is NameObject for k in value))
            names = {}
            for name in ("/Type", "/Subtype", "/S"):
                if name in value:
                    require(type(value.raw_get(name)) is NameObject)
                    names[name] = str(value.raw_get(name))
            forbidden = passive._ACTION_KEYS.intersection(value)
            if "/A" in forbidden and id(value) in attributes:
                forbidden -= {"/A"}
            require(not forbidden and names.get("/Type") != "/Action"
                    and names.get("/S") not in passive._ACTION_TYPES
                    and not passive._ATTACHMENT_KEYS.intersection(value)
                    and names.get("/Type") not in {"/Filespec", "/EmbeddedFile"}
                    and names.get("/Subtype") != "/FileAttachment"
                    and not passive._FORM_KEYS.intersection(value)
                    and names.get("/Subtype") != "/Widget"
                    and not passive._MEDIA_KEYS.intersection(value)
                    and names.get("/Subtype") not in passive._MEDIA_SUBTYPES
                    and not {"/ActualText", "/E", "/RoleMap", "/ClassMap", "/Annots"}.intersection(value)
                    and ("/Alt" not in value or id(value) in figures))
            require(not isinstance(value, StreamObject)
                    or not {"/F", "/FFilter", "/FDecodeParms"}.intersection(value))
            children = value.values()
        elif isinstance(value, ArrayObject):
            children = value
        for child in children:
            require(len(pending) < contract.MAX_VISITS)
            pending.append((child, depth + 1))


def _inflate(stream, maximum):
    from pypdf.generic import NameObject, StreamObject
    require(isinstance(stream, StreamObject) and type(stream._data) is bytes
            and 0 < len(stream._data) <= contract.MAX_PDF_BYTES
            and type(stream.raw_get("/Filter")) is NameObject
            and stream.raw_get("/Filter") == "/FlateDecode")
    inflater = zlib.decompressobj()
    data = inflater.decompress(stream._data, maximum + 1)
    require(0 < len(data) <= maximum and inflater.eof
            and not inflater.unused_data and not inflater.unconsumed_tail)
    return data


def _dna_image(image):
    from pypdf.generic import BooleanObject, DictionaryObject, NameObject, NumberObject
    require(set(image) == {"/Type", "/Subtype", "/Width", "/Height", "/ColorSpace",
                           "/BitsPerComponent", "/Interpolate", "/Filter", "/DecodeParms"})
    for key, value in (("/Type", "/XObject"), ("/Subtype", "/Image"), ("/ColorSpace", "/DeviceRGB")):
        require(type(image.raw_get(key)) is NameObject and image.raw_get(key) == value)
    for key, value in (("/Width", 324), ("/Height", 1154), ("/BitsPerComponent", 8)):
        require(type(image.raw_get(key)) is NumberObject and int(image.raw_get(key)) == value)
    require(type(image.raw_get("/Interpolate")) is BooleanObject and image.raw_get("/Interpolate").value is True)
    params = image.raw_get("/DecodeParms")
    require(type(params) is DictionaryObject and set(params) == {"/Predictor", "/Columns", "/Colors"})
    require(all(type(params.raw_get(k)) is NumberObject and int(params.raw_get(k)) == v
                for k, v in (("/Predictor", 15), ("/Columns", 324), ("/Colors", 3))))
    stride, height = 972, 1154
    filtered = _inflate(image, height * (stride + 1))
    require(len(filtered) == height * (stride + 1))
    previous, pixels = bytearray(stride), bytearray()
    for y in range(height):
        start = y * (stride + 1)
        kind = filtered[start]
        require(kind in range(5))
        row = bytearray(filtered[start + 1:start + 1 + stride])
        for x in range(stride):
            left, above = row[x - 3] if x >= 3 else 0, previous[x]
            upper_left = previous[x - 3] if x >= 3 else 0
            predictor = 0
            if kind == 1:
                predictor = left
            elif kind == 2:
                predictor = above
            elif kind == 3:
                predictor = (left + above) // 2
            elif kind == 4:
                p = left + above - upper_left
                distances = (abs(p - left), abs(p - above), abs(p - upper_left))
                predictor = (left, above, upper_left)[distances.index(min(distances))]
            row[x] = (row[x] + predictor) & 255
        pixels.extend(row)
        previous = row
    require(len(pixels) == 1121688 and sha256(pixels).hexdigest() == qa.DNA_RGB_SHA256)


def _operations(data, reader):
    from pypdf.generic import ContentStream, DecodedStreamObject
    decoded = DecodedStreamObject()
    decoded.set_data(data)
    stream = ContentStream(decoded, reader, forced_encoding="bytes")
    require(0 < len(stream.operations) <= contract.MAX_OPERATIONS)
    return stream.operations


def _numbers(args, count):
    require(type(args) is list and len(args) == count)
    return [native._number(v) for v in args]


def _form(ref, reader, fonts, forms):
    from pypdf.generic import ArrayObject, BooleanObject, DictionaryObject, NameObject, StreamObject
    key = tuple(native._ref(ref, reader))
    if key in forms:
        return
    require(not forms)
    obj = ref.get_object()
    require(isinstance(obj, StreamObject) and set(obj) == {
        "/Type", "/Subtype", "/BBox", "/Resources", "/Group", "/Filter"})
    require(obj.raw_get("/Type") == "/XObject" and obj.raw_get("/Subtype") == "/Form")
    box = obj.raw_get("/BBox")
    require(type(box) is ArrayObject and len(box) == 4)
    coordinates = [Decimal(native._number(v)) for v in box]
    require(coordinates[0:2] == [0, 0] and 0 < coordinates[2] <= 1200 and 0 < coordinates[3] <= 1600)
    group = obj.raw_get("/Group")
    require(type(group) is DictionaryObject and set(group) == {"/Type", "/S", "/I", "/CS"}
            and group.raw_get("/Type") == "/Group" and group.raw_get("/S") == "/Transparency"
            and type(group.raw_get("/I")) is BooleanObject and group.raw_get("/I").value is True
            and type(group.raw_get("/CS")) is NameObject
            and group.raw_get("/CS") == "/DeviceRGB")
    resources = native._dictionary(obj.raw_get("/Resources"), reader)
    require(set(resources) == {"/Font", "/ExtGState", "/XObject", "/Pattern", "/Shading", "/ColorSpace"})
    for empty in ("/ExtGState", "/Pattern", "/Shading"):
        require(not native._dictionary(resources.raw_get(empty), reader))
    _lab_presets(native._dictionary(resources.raw_get("/ColorSpace"), reader))
    declared_fonts = native._dictionary(resources.raw_get("/Font"), reader)
    require(1 <= len(declared_fonts) <= contract.MAX_FONTS)
    for name, font_ref in declared_fonts.items():
        require(type(name) is NameObject and tuple(native._ref(font_ref, reader)) in fonts)
    images = native._dictionary(resources.raw_get("/XObject"), reader)
    require(len(images) == 1)
    image_name, image_ref = next(iter(images.items()))
    require(type(image_name) is NameObject)
    native._ref(image_ref, reader)
    _dna_image(image_ref.get_object())
    data = _inflate(obj, 4096)
    ops = _operations(data, reader)
    require([op for _, op in ops] == [b"cm", b"cm", b"Do"])
    first = tuple(map(Decimal, _numbers(ops[0][0], 6)))
    second = tuple(map(Decimal, _numbers(ops[1][0], 6)))
    # Fixed 753.88976 pt cover panel serialized in CSS px by the qualified renderer.
    dna_height = Decimal("1005.186347")
    require(first[:4] == (1, 0, 0, 1) and all(abs(x) <= 1600 for x in first[4:])
            and second[1:3] == (0, 0) and second[4] == 0
            and second[3] == -dna_height and second[5] == dna_height
            and abs(second[0] - dna_height * Decimal(324) / Decimal(1154)) <= Decimal("0.000001")
            and len(ops[2][0]) == 1 and type(ops[2][0][0]) is NameObject
            and ops[2][0][0] == image_name)
    image_bounds = _rectangle((Decimal(0), Decimal(0), Decimal(1), Decimal(1)),
                              _ctm(second, _ctm(first, IDENTITY)))
    form_bounds = _rectangle((coordinates[0], coordinates[1],
                              coordinates[2] - coordinates[0],
                              coordinates[3] - coordinates[1]), IDENTITY)
    require(_contains(form_bounds, image_bounds))
    forms[key] = {"image": native._ref(image_ref, reader), "sha256": sha256(data).hexdigest(),
                  "image_bounds": image_bounds}


def _resources(resources, reader, fonts, forms, page):
    from pypdf.generic import NameObject
    require(set(resources) == {"/Font", "/ExtGState", "/XObject", "/Pattern", "/Shading", "/ColorSpace"})
    _lab_presets(native._dictionary(resources.raw_get("/ColorSpace"), reader))
    for empty in ("/Pattern", "/Shading"):
        require(not native._dictionary(resources.raw_get(empty), reader))
    font_resources = native._dictionary(resources.raw_get("/Font"), reader)
    require(1 <= len(font_resources) <= contract.MAX_FONTS)
    for name, ref in font_resources.items():
        require(type(name) is NameObject and 1 <= len(name) <= 128)
        key = tuple(native._ref(ref, reader))
        if key not in fonts:
            require(len(fonts) < contract.MAX_FONTS)
            fonts[key] = native._font(ref, reader)
        page["font_resources"].append({"name": str(name), "reference": list(key)})
    require(sum(f["cmap_decoded_bytes"] for f in fonts.values()) <= contract.MAX_CMAP_TOTAL
            and sum(len(f["mapping"]) for f in fonts.values()) <= contract.MAX_CMAP_RECORDS)
    states = native._dictionary(resources.raw_get("/ExtGState"), reader)
    require(1 <= len(states) <= 3)
    for name, ref in states.items():
        require(type(name) is NameObject and 1 <= len(name) <= 128)
        state = native._dictionary(ref, reader)
        require(set(state) in ({"/ca"}, {"/CA"}))
        require(all(float(native._number(state.raw_get(k))) == 1 for k in state))
        page["graphics_states"].append({
            "name": str(name), "fill_alpha": native._number(state.raw_get("/ca")) if "/ca" in state else None,
            "stroke_alpha": native._number(state.raw_get("/CA")) if "/CA" in state else None})
    xobjects = native._dictionary(resources.raw_get("/XObject"), reader)
    require(len(xobjects) == 1)
    for name, ref in xobjects.items():
        require(type(name) is NameObject and 1 <= len(name) <= 128)
        _form(ref, reader, fonts, forms)
    return states, xobjects


def _ctm(new, current):
    a, b, c, d, e, f = new
    A, B, C, D, E, F = current
    return (a*A+b*C, a*B+b*D, c*A+d*C, c*B+d*D, e*A+f*C+E, e*B+f*D+F)


def _determinant(matrix):
    return matrix[0] * matrix[3] - matrix[1] * matrix[2]


def _point(point, matrix):
    x, y = point
    a, b, c, d, e, f = matrix
    return a * x + c * y + e, b * x + d * y + f


def _rectangle(values, matrix):
    x, y, width, height = values
    return tuple(_point(point, matrix) for point in (
        (x, y), (x + width, y), (x + width, y + height), (x, y + height)))


def _contains(outer, inner):
    """Containment only for the admitted affine rectangle; no general path clipping."""
    def side(first, second, point):
        return ((second[0] - first[0]) * (point[1] - first[1])
                - (second[1] - first[1]) * (point[0] - first[0]))
    direction = side(outer[0], outer[1], outer[2])
    return direction != 0 and all(
        side(outer[i], outer[(i + 1) % 4], point) * direction >= 0
        for point in inner for i in range(4))


def _effective_crop_box(page, reader):
    """Resolve CropBox only on the already validated raw page-tree path."""
    root = native._dictionary(reader.root_object.raw_get("/Pages"), reader)
    node, seen = page, set()
    for _ in range(contract.MAX_DEPTH):
        if "/CropBox" in node:
            return node.raw_get("/CropBox")
        if node is root:
            return None
        parent = node.raw_get("/Parent")
        key = tuple(native._ref(parent, reader))
        require(key not in seen)
        seen.add(key)
        node = native._dictionary(parent, reader)
    require(False)


def _footer_declared_geometry(block, resources, reader, ctm, media):
    """Bind declared PDF advances and typographic boxes, not glyph contours or ink.

    The existing Type0/Identity-H font admission supplies bounded explicit /W
    runs. Ascent/descent and widths are PDF declarations: this does not decode
    FontFile2, authenticate outlines, or establish actual painted-ink bounds.
    """
    from pypdf.generic import ByteStringObject, NumberObject

    require([op.decode("ascii") for _, op in block] == list(qa.PAGINATION_OPERATORS))
    matrix = tuple(map(Decimal, _numbers(block[3][0], 6)))
    font_name, size_value = block[4][0]
    size = Decimal(native._number(size_value))
    effective = _ctm(matrix, ctm)
    # WeasyPrint's PDF scale is 72/96; draw_text reverses the CSS text y-axis.
    scale, half_decimal = Decimal("0.75"), Decimal("0.0000005")
    require(effective[:4] == (scale, Decimal(0), Decimal(0), scale))
    # Existing 8.6pt footer -> integer Pango units -> pydyf's six decimal places.
    exact_size = Decimal(int(Decimal("8.6") / scale * 1024)) / 1024
    require(size == exact_size.quantize(Decimal("0.000001")))
    font_map = native._dictionary(resources.raw_get("/Font"), reader)
    require(font_name in font_map)
    font = native._dictionary(font_map.raw_get(font_name), reader)
    cid = native._dictionary(font.raw_get("/DescendantFonts")[0], reader)
    descriptor = native._dictionary(cid.raw_get("/FontDescriptor"), reader)
    ascent = Decimal(native._number(descriptor.raw_get("/Ascent")))
    descent = Decimal(native._number(descriptor.raw_get("/Descent")))
    require(descent < 0 < ascent)
    widths = {}
    declared = cid.raw_get("/W")
    # native._font already checked the ascending, disjoint 4096-value envelope.
    for offset in range(0, len(declared), 2):
        first = int(declared[offset])
        for index, value in enumerate(declared[offset + 1]):
            require(type(value) is NumberObject)
            widths[first + index] = Decimal(int(value))
    pen, glyphs, points, maximum_extent = Decimal(0), 0, [], Decimal(0)
    shown = block[5][0][0]
    for item in shown:
        if type(item) is NumberObject:
            pen -= Decimal(int(item))
            continue
        require(type(item) is ByteStringObject)
        data = bytes(item)
        require(0 < len(data) and len(data) % 2 == 0)
        for offset in range(0, len(data), 2):
            glyphs += 1
            require(glyphs <= 64)
            code = int.from_bytes(data[offset:offset + 2], "big")
            require(code in widths)
            width = widths[code]
            points.extend(_rectangle(
                (pen * size / 1000, descent * size / 1000,
                 width * size / 1000, (ascent - descent) * size / 1000), effective))
            maximum_extent = max(maximum_extent, abs(pen), abs(pen + width))
            pen += width
    require(glyphs > 0 and pen > 0)
    maximum_extent = max(maximum_extent, abs(pen))
    x0, y0 = min(p[0] for p in points), min(p[1] for p in points)
    x1, y1 = max(p[0] for p in points), max(p[1] for p in points)
    bounds = _rectangle((x0, y0, x1 - x0, y1 - y0), IDENTITY)
    # draw/text.py rounds /W and truncates each TJ kerning to an integer.
    # One unit per glyph bounds truncation; one more bounds the final rounded
    # logical edge. Add the exact Tf serialization error and half a serialized
    # decimal unit for Tm and the page edge. This is a data-derived bound, not
    # an arbitrary coordinate tolerance; it never relaxes physical clipping.
    allowance = (scale * (
        exact_size * (glyphs + 1) / 1000
        + abs(exact_size - size) * maximum_extent / 1000 + half_decimal)
        + half_decimal)
    margin = Decimal(44)
    left, bottom, right, top = media
    require(right - left > 2 * margin and top - bottom > margin)
    target_right = right - margin
    advance = _point((pen * size / 1000, Decimal(0)), effective)
    advance_right = advance[0]
    require(abs(advance_right - target_right) <= allowance
            and abs(x1 - target_right) <= allowance)
    region = _rectangle((left + margin, bottom,
                         right - left - 2 * margin + allowance, margin), IDENTITY)
    require(_contains(region, bounds))
    # Active clips and page boxes contain the endpoint without an allowance.
    return (*bounds, advance)


def _paint_geometry(operations, page, reader, forms, xobjects, figure_points, resources):
    """Check brand paints, footer boxes and the advance against active rectangles."""
    from pypdf.generic import ArrayObject
    ctm, stack, clip = IDENTITY, [], ()
    path, pending_clip = None, False
    require("/MediaBox" in page)
    boxes = [page.raw_get("/MediaBox")]
    crop_box = _effective_crop_box(page, reader)
    if crop_box is not None:
        boxes.append(crop_box)
    media = None
    for box in boxes:
        require(type(box) is ArrayObject and len(box) == 4)
        x0, y0, x1, y1 = (Decimal(native._number(v)) for v in box)
        require(x0 < x1 and y0 < y1)
        if media is None:
            media = x0, y0, x1, y1
        clip = (_rectangle((x0, y0, x1 - x0, y1 - y0), IDENTITY), clip)
    for ordinal, (args, op) in enumerate(operations):
        if op == b"q":
            require(len(stack) < contract.MAX_DEPTH)
            stack.append((ctm, clip))
        elif op == b"Q":
            require(bool(stack))
            ctm, clip = stack.pop()
        elif op == b"cm":
            ctm = _ctm(tuple(map(Decimal, _numbers(args, 6))), ctm)
        elif op == b"re":
            rectangle = _rectangle(tuple(map(Decimal, _numbers(args, 4))), ctm)
            path = rectangle if path is None else False
        elif op in {b"m", b"l", b"h"}:
            path = False
        elif op in {b"W", b"W*"}:
            pending_clip = True
        elif op in {b"n", b"S", b"f", b"f*"}:
            if pending_clip:
                require(path is not None)
                clip = None if clip is None or path is False else (path, clip)
            path, pending_clip = None, False
        elif op == b"BDC" and args[0] == "/Figure":
            require(_determinant(ctm) != 0 and clip is not None)
            points, declared_box = figure_points[int(args[1].raw_get("/MCID"))]
            logo = tuple(_point(point, ctm) for point in points)
            x0, y0, x1, y1 = declared_box
            require(_contains(_rectangle((x0, y0, x1 - x0, y1 - y0), IDENTITY), logo))
            inherited = clip
            while inherited:
                bounds, inherited = inherited
                require(_contains(bounds, logo))
        elif op == b"BDC" and args[0] == "/Artifact":
            require(_determinant(ctm) != 0 and clip is not None
                    and path is None and not pending_clip)
            footer = _footer_declared_geometry(
                operations[ordinal + 1:ordinal + 8], resources, reader, ctm, media)
            inherited = clip
            while inherited:
                bounds, inherited = inherited
                require(_contains(bounds, footer))
        elif op == b"Do":
            require(_determinant(ctm) != 0 and clip is not None
                    and path is None and not pending_clip)
            form = forms[tuple(native._ref(xobjects.raw_get(args[0]), reader))]
            image = tuple(_point(point, ctm) for point in form["image_bounds"])
            inherited = clip
            while inherited:
                bounds, inherited = inherited
                require(_contains(bounds, image))
    require(not stack and path is None and not pending_clip)


def _logo_source():
    """Derive the six admitted path/paint/group records from the pinned SVG."""
    svg = (qa.ROOT / "reporting/assets/omnigenis_logo.svg").read_bytes()
    require(sha256(svg).hexdigest() == "29983790bef75837d683a392515ed35d0410d919d49b6c52a7121f7659770c51")
    root = ET.fromstring(svg)
    ns = "{http://www.w3.org/2000/svg}"
    require(root.tag == ns + "svg" and root.attrib["viewBox"] == "0 0 1054 340")
    parents = {child: parent for parent in root.iter() for child in parent}
    paths = [e for e in root.iter() if e.tag == ns + "path"]
    groups = [e for e in root.iter() if e.tag == ns + "g"]
    require(len(paths) == 6 and len(groups) == 2)
    matrices = []
    for group in groups:
        match = re.fullmatch(r"translate\(([+-]?\d+(?:\.\d+)?) ([+-]?\d+(?:\.\d+)?)\) scale\(([+-]?\d+(?:\.\d+)?)\)", group.attrib["transform"])
        require(match is not None)
        x, y, scale = map(Decimal, match.groups())
        matrices.append((scale, Decimal(0), Decimal(0), scale, x, y))
    expected = []
    for path in paths:
        commands = path.attrib["d"]
        tokens = re.findall(r"[MLZ]|[+-]?(?:\d+(?:\.\d+)?|\.\d+)", commands, re.ASCII)
        require("".join(tokens) == re.sub(r"[\s,]", "", commands))
        drawing, cursor = [(b"m", (Decimal(0), Decimal(0)))], 0
        while cursor < len(tokens):
            action = tokens[cursor]
            require(action in {"M", "L", "Z"})
            if action == "Z":
                drawing.append((b"h", ()))
                cursor += 1
            else:
                require(cursor + 2 < len(tokens))
                drawing.append((b"m" if action == "M" else b"l",
                                (Decimal(tokens[cursor+1]), Decimal(tokens[cursor+2]))))
                cursor += 3
        color = path.attrib["fill"]
        require(re.fullmatch(r"#[0-9A-Fa-f]{6}", color) is not None)
        paint = tuple((Decimal(int(color[i:i+2], 16)) / 255).quantize(Decimal("0.000001"))
                      for i in (1, 3, 5))
        group = parents[path]
        require(group in groups)
        rule = path.attrib.get("fill-rule", group.attrib.get("fill-rule", "nonzero"))
        require(rule in {"nonzero", "evenodd"})
        expected.append((tuple(drawing), paint, b"f*" if rule == "evenodd" else b"f", groups.index(group)))
    require(sum(len(v[0]) for v in expected) == 506)
    return expected, matrices


def _figure(operations, states):
    from pypdf.generic import ArrayObject, NameObject, NumberObject
    expected, groups = _logo_source()
    allowed = {b"q", b"Q", b"gs", b"cm", b"rg", b"d", b"J", b"j", b"M", b"m", b"l", b"h", b"f", b"f*"}
    stack, drawing, paths, matrices = [], [], [], []
    color = group = None
    ctm, updates, selected_states = IDENTITY, 0, []
    for args, op in operations:
        require(op in allowed and type(args) is list)
        require(not drawing or op in {b"m", b"l", b"h", b"f", b"f*"})
        if op == b"q":
            require(not args and len(stack) < contract.MAX_DEPTH)
            stack.append((color, group, ctm))
        elif op == b"Q":
            require(not args and bool(stack))
            color, group, ctm = stack.pop()
        elif op == b"gs":
            require(len(args) == 1 and type(args[0]) is NameObject and args[0] in states)
            state = states.raw_get(args[0]).get_object()
            require(set(state) == {"/ca"} and float(native._number(state.raw_get("/ca"))) == 1)
            selected_states.append(str(args[0]))
        elif op == b"rg":
            color = tuple(Decimal(v) for v in _numbers(args, 3))
            require(all(0 <= v <= 1 for v in color))
            updates += 1
        elif op == b"cm":
            matrix = tuple(Decimal(v) for v in _numbers(args, 6))
            matrices.append(matrix)
            ctm = _ctm(matrix, ctm)
            if matrix in groups:
                group = groups.index(matrix)
        elif op == b"d":
            require(len(args) == 2 and type(args[0]) is ArrayObject and not args[0]
                    and type(args[1]) is NumberObject and int(args[1]) == 0)
        elif op in {b"J", b"j", b"M"}:
            require(len(args) == 1 and type(args[0]) is NumberObject
                    and int(args[0]) == (4 if op == b"M" else 0))
        elif op in {b"m", b"l", b"h"}:
            values = _numbers(args, 0 if op == b"h" else 2)
            drawing.append((op, tuple(Decimal(v) for v in values)))
        else:
            require(not args and updates == 1 and color is not None and group is not None)
            paths.append((tuple(drawing), color, op, group, ctm))
            drawing, updates = [], 0
    require(not stack and not drawing and updates == 0
            and len(matrices) == 5 and matrices[-2:] == groups
            and len(paths) == len(expected) and len(selected_states) == 7
            and set(selected_states) == {"/a1", "/a1.0"})
    wrapper = IDENTITY
    for matrix in matrices[:3]:
        wrapper = _ctm(matrix, wrapper)
    require(_determinant(wrapper) != 0)
    painted = []
    for observed, source in zip(paths, expected, strict=True):
        require(observed[:4] == source and observed[4] == _ctm(groups[source[3]], wrapper))
        # The pinned renderer's leading move starts an empty, unpainted subpath.
        painted.extend(_point(values, observed[4]) for op, values in observed[0][1:]
                       if op in {b"m", b"l"})
    require(bool(painted))
    return tuple(painted)


def _artifact(operations, states, xobjects):
    from pypdf.generic import NameObject
    allowed = {b"q", b"Q", b"m", b"l", b"W*", b"n", b"gs", b"rg",
               b"re", b"f*", b"W", b"f", b"RG", b"w", b"S", b"Do"}
    depth, paints, path, clip = 0, 0, False, False
    for args, op in operations:
        require(op in allowed and type(args) is list)
        require(not path or op in {b"m", b"l", b"re", b"W", b"W*", b"n", b"S", b"f", b"f*"})
        require(not clip or op in {b"n", b"S", b"f", b"f*"})
        if op in {b"q", b"Q"}:
            require(not args)
            depth += 1 if op == b"q" else -1
            require(0 <= depth <= contract.MAX_DEPTH)
        elif op in {b"m", b"l", b"re", b"rg", b"RG", b"w"}:
            values = list(map(float, _numbers(args, {b"m": 2, b"l": 2, b"re": 4, b"rg": 3, b"RG": 3, b"w": 1}[op])))
            if op in {b"m", b"re"}:
                path = True
            elif op == b"l":
                require(path)
            if op in {b"rg", b"RG"}:
                require(all(0 <= v <= 1 for v in values))
            if op == b"w":
                require(values[0] > 0)
        elif op in {b"gs", b"Do"}:
            require(len(args) == 1 and type(args[0]) is NameObject)
            require(args[0] in (states if op == b"gs" else xobjects))
            if op == b"Do":
                require(not path)
            paints += op == b"Do"
        else:
            require(not args and path)
            if op in {b"W", b"W*"}:
                clip = True
            else:
                path, clip = False, False
    require(depth == 0 and not path and not clip)
    if paints:
        require(paints == 1 and [op for _, op in operations] == [b"re", b"W", b"n", b"Do"])
    return paints


def _text_event(args, op, ordinal):
    from pypdf.generic import ArrayObject, ByteStringObject, DictionaryObject, NameObject, NumberObject
    name = op.decode("ascii")
    require(name in contract.OPERATORS and type(args) is list)
    if name in {"q", "Q", "BT", "ET", "EMC"}:
        require(not args)
        operands = []
    elif name == "BDC":
        require(len(args) == 2 and type(args[0]) is NameObject and args[0] == "/Span"
                and type(args[1]) is DictionaryObject and set(args[1]) == {"/MCID"}
                and type(args[1].raw_get("/MCID")) is NumberObject)
        operands = [int(args[1].raw_get("/MCID"))]
    elif name in {"cm", "Tm", "rg"}:
        operands = _numbers(args, 3 if name == "rg" else 6)
    elif name == "gs":
        require(len(args) == 1 and type(args[0]) is NameObject)
        operands = [str(args[0])]
    elif name == "Tf":
        require(len(args) == 2 and type(args[0]) is NameObject)
        operands = [str(args[0]), native._number(args[1])]
    else:
        require(name == "TJ" and len(args) == 1 and type(args[0]) is ArrayObject
                and 1 <= len(args[0]) <= contract.MAX_OPERATIONS)
        operands = [["codes", bytes(v).hex()] if type(v) is ByteStringObject
                    else ["adjust", native._number(v)] for v in args[0]]
    return {"ordinal": ordinal, "operator": name, "operands": operands}


def _op_digest(operations):
    from pypdf.generic import ArrayObject, NameObject
    def value(v):
        if type(v) is NameObject:
            return ["name", str(v)]
        if type(v) is ArrayObject:
            return ["array", [value(x) for x in v]]
        return ["number", native._number(v)]
    return sha256(qa.canonical([[op.decode("ascii"), [value(v) for v in args]]
                               for args, op in operations])).hexdigest()


def _page_labels(reader, count):
    """Observe the explicit flat decimal labels, never the parser's defaults."""
    from pypdf.generic import ArrayObject, DictionaryObject, NameObject, NumberObject
    root = reader.root_object
    require("/PageLabels" in root)
    labels = native._dictionary(root.raw_get("/PageLabels"), reader)
    require(set(labels) == {"/Nums"})
    values = labels.raw_get("/Nums")
    require(type(values) is ArrayObject and len(values) == 2
            and type(values[0]) is NumberObject and int(values[0]) == 0
            and type(values[1]) is DictionaryObject and set(values[1]) == {"/S", "/St"}
            and type(values[1].raw_get("/S")) is NameObject and values[1].raw_get("/S") == "/D"
            and type(values[1].raw_get("/St")) is NumberObject and int(values[1].raw_get("/St")) == 1)
    actual = reader.page_labels
    require(actual == [str(i) for i in range(1, count + 1)])
    return actual


def _page(page, obj, resources, reader, fonts, forms, roles, remaining):
    from pypdf.generic import DictionaryObject, IndirectObject, NameObject, NumberObject
    states, xobjects = _resources(resources, reader, fonts, forms, page)
    content_ref = obj.raw_get("/Contents")
    page["contents_reference"] = native._ref(content_ref, reader)
    data = native._stream_bytes(content_ref.get_object(), remaining)
    page["content_sha256"] = sha256(data).hexdigest()
    page["decoded_stream_bytes"] = len(data)
    ops = _operations(data, reader)
    page["original_operator_count"] = len(ops)
    page["projected_operator_ordinals"] = []
    page["graphic_blocks"] = []
    page["pagination_blocks"] = []
    page["outside_operator_ordinals"] = []
    owners = {m["mcid"]: tuple(m["structure_reference"]) for m in page["mcid_owners"]}
    used, index, outside_depth = set(), 0, 0
    figure_points = {}
    outside_path = outside_clip = False
    while index < len(ops):
        args, op = ops[index]
        require(type(args) is list)
        if op in {b"BDC", b"BMC"}:
            require(not outside_path and not outside_clip)
            start = index
            kind, mcid = None, None
            if op == b"BDC":
                require(len(args) == 2 and type(args[0]) is NameObject
                        and type(args[1]) is DictionaryObject)
                if args[0] == "/Artifact":
                    require(set(args[1]) == {"/Type", "/Subtype"}
                            and type(args[1].raw_get("/Type")) is NameObject
                            and args[1].raw_get("/Type") == "/Pagination"
                            and type(args[1].raw_get("/Subtype")) is NameObject
                            and args[1].raw_get("/Subtype") == "/Footer"
                            and not page["pagination_blocks"])
                    kind = "pagination"
                else:
                    require(args[0] in {"/Span", "/Figure"} and set(args[1]) == {"/MCID"}
                            and type(args[1].raw_get("/MCID")) is NumberObject)
                    mcid = int(args[1].raw_get("/MCID"))
                    require(mcid in owners and mcid not in used and roles[owners[mcid]] == str(args[0]))
                    used.add(mcid)
                    kind = "text" if args[0] == "/Span" else "figure"
            else:
                require(len(args) == 1 and type(args[0]) is NameObject and args[0] == "/Artifact")
                kind = "artifact"
            index += 1
            while index < len(ops) and ops[index][1] != b"EMC":
                require(ops[index][1] not in {b"BMC", b"BDC"})
                index += 1
            require(index < len(ops) and not ops[index][0])
            block = ops[start + 1:index]
            if kind == "text":
                for original_ordinal in range(start, index + 1):
                    a, o = ops[original_ordinal]
                    page["events"].append(_text_event(a, o, len(page["events"])))
                    page["projected_operator_ordinals"].append(original_ordinal)
            elif kind == "pagination":
                require([o.decode("ascii") for _, o in block] == list(qa.PAGINATION_OPERATORS))
                events = [_text_event(a, o, ordinal) for ordinal, (a, o) in enumerate(block)]
                page["pagination_blocks"].append({
                    "kind": "pagination", "type": "Pagination", "subtype": "Footer",
                    "first_operator": start, "last_operator": index,
                    "events": events, "sha256": sha256(qa.canonical(events)).hexdigest()})
            else:
                if kind == "figure":
                    figure = native._dictionary(IndirectObject(*owners[mcid], reader), reader)
                    box = tuple(Decimal(native._number(v))
                                for v in figure.raw_get("/A").raw_get("/BBox"))
                    figure_points[mcid] = (_figure(block, states), box)
                    paints = 0
                else:
                    paints = _artifact(block, states, xobjects)
                page["graphic_blocks"].append({
                    "kind": kind, "first_operator": start, "last_operator": index,
                    "mcid": mcid, "dna_paints": paints, "sha256": _op_digest(block)})
            index += 1
            continue
        require(op in {b"q", b"Q", b"cm", b"re", b"W", b"n"})
        require(not outside_path or op in {b"re", b"W", b"n"})
        require(not outside_clip or op == b"n")
        if op in {b"q", b"Q"}:
            require(not args)
            outside_depth += 1 if op == b"q" else -1
            require(0 <= outside_depth <= contract.MAX_DEPTH)
        elif op in {b"cm", b"re"}:
            _numbers(args, 6 if op == b"cm" else 4)
            if op == b"re":
                outside_path = True
        else:
            require(not args and outside_path)
            if op == b"W":
                outside_clip = True
            else:
                outside_path = outside_clip = False
        page["outside_operator_ordinals"].append(index)
        index += 1
    require(outside_depth == 0 and not outside_path and not outside_clip
            and used == set(owners) and len(page["pagination_blocks"]) == 1)
    _paint_geometry(ops, obj, reader, forms, xobjects, figure_points, resources)
    text_page = dict(page)
    text_page["mcid_owners"] = [v for v in page["mcid_owners"] if roles[tuple(v["structure_reference"])] == "/Span"]
    page["runs"] = contract._replay(text_page, fonts)


def inspect(pdf, digest, limits):
    from pypdf import PdfReader
    require(version("pypdf") == contract.PARSER_VERSION)
    profile = qa.profile_sha256()
    class RefuseWarning(logging.Handler):
        def emit(self, _record):
            raise ValueError("combined PDF parser warning")
    guard = RefuseWarning(level=logging.WARNING)
    logger = logging.getLogger("pypdf")
    logger.addHandler(guard)
    try:
        reader = PdfReader(BytesIO(pdf), strict=True)
        require(not reader.is_encrypted)
        pages = native._page_tree(reader)
        contract.require_pdf_document_budget(len(pdf), len(pages))
        labels = _page_labels(reader, len(pages))
        trace, attributes, figures = _structure(reader, pages)
        _passive(reader, attributes, figures)
        fonts, forms, decoded = {}, {}, 0
        nodes = {tuple(n["reference"]): n for n in trace["nodes"]}
        roles = {key: node["role"] for key, node in nodes.items()}
        document = nodes[tuple(trace["root_children"][0])]
        dna_page = nodes[tuple(document["children"][0]["reference"])]["page_reference"]
        for page, (_, obj, resources) in zip(trace["pages"], pages, strict=True):
            _page(page, obj, resources, reader, fonts, forms, roles,
                  contract.MAX_STREAM_BYTES - decoded)
            require(all(not block["dna_paints"] or page["reference"] == dna_page
                        for block in page["graphic_blocks"]))
            decoded += page["decoded_stream_bytes"]
        trace["fonts"] = list(fonts.values())
        require(len(forms) == 1)
        graphics = {
            "figure_count": sum(b["kind"] == "figure" for p in trace["pages"] for b in p["graphic_blocks"]),
            "artifact_count": sum(b["kind"] == "artifact" for p in trace["pages"] for b in p["graphic_blocks"]),
            "dna_paints": sum(b["dna_paints"] for p in trace["pages"] for b in p["graphic_blocks"]),
            "dna_rgb_sha256": qa.DNA_RGB_SHA256,
            "operations": sum(p["original_operator_count"] for p in trace["pages"]) + 3,
            "form_operations": 3,
        }
        result = {
            "schema_version": "1.0.0", "profile_id": qa.PROFILE_ID,
            "profile_sha256": profile, "status": "NATIVE_TYPED_BRAND_ACCOUNTED",
            "pdf_sha256": digest, "pdf_byte_count": len(pdf), "page_count": len(pages),
            "limits": limits, "trace": trace, "graphics": graphics, "page_labels": labels,
        }
        qa._validate_native(result, pdf, profile)
        require(qa.profile_sha256() == profile)
        return result
    finally:
        logger.removeHandler(guard)


def main(argv=None):
    argv = sys.argv if argv is None else argv
    if (sys.platform != "linux" or not sys.flags.isolated or not sys.dont_write_bytecode
            or os.environ.get("OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE") != "qualification-only"
            or any(os.environ.get(key) == "1" for key in qa.DISABLE_FLAGS)
            or type(argv) is not list or len(argv) != 4
            or any(type(v) is not str or not v.isascii() or not v.isdecimal() or len(v) > 10 for v in argv[1:])):
        return 64
    try:
        source, output, parent = map(int, argv[1:])
        require(all(str(n) == s for n, s in zip((source, output, parent), argv[1:], strict=True))
                and min(source, output) >= 3 and source != output and 2 <= parent <= 2147483647)
        infos = [os.fstat(fd) for fd in (source, output)]
        require(all(stat.S_ISREG(v.st_mode) and v.st_nlink == 0 and v.st_uid == os.geteuid() for v in infos)
                and (infos[0].st_dev, infos[0].st_ino) != (infos[1].st_dev, infos[1].st_ino)
                and infos[1].st_size == 0)
        limits = _limits()
        _lifetime(parent)
        enforce_pdf_landlock(Path(__file__))
        enforce_pdf_network_filter()
        digest, pdf = native._read_request(source)
        result = inspect(pdf, digest, limits)
        data = qa.canonical(result)
        require(0 < len(data) <= contract.RESULT_BYTES)
        _write_bytes(output, data)
        return 0
    except Exception:
        return 70


if __name__ == "__main__":
    raise SystemExit(main())
