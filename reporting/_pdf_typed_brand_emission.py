"""Finite pre-serialization structure emission for the typed original-brand route."""
from contextlib import contextmanager
from decimal import Decimal, localcontext
from hashlib import sha256
from importlib.metadata import distribution
import json
import os
import stat
from math import isfinite
from pathlib import Path
import re
import sys

PROFILE_ID = "typed-original-brand-render-v1"
MODE = "native-typed-original-brand-v1"
ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "reporting/pdf-typed-brand-render.v1.json"
LEGACY_HASH = "5391bdae627341ce95c351093bfc2a6dc2575e48203f9ee4bd4581c6ec1eb0de"
SOURCES = (
    "reporting/_pdf_typed_brand_emission.py", "reporting/_pdf_typed_brand_render_worker.py",
    "reporting/pdf_typed_brand_render.py", "reporting/typed_original_brand_pdf.py",
    "reporting/pdf-raster-render.v1.json", "reporting/pdf_font_selection.py",
    "reporting/pdf_raster_render.py", "reporting/pdf_raster_resources.py",
    "reporting/_pdf_render_worker.py", "reporting/_pdf_process_sandbox.py",
    "reporting/_pdf_process_lifecycle.py", "reporting/adapters.py", "reporting/png_inspection.py",
    "reporting/_pdf_native_launch_budget.py", "reporting/_pdf_document_byte_budget.py",
    "reporting/page_windows.py", "reporting/bindings.py", "reporting/contracts.py",
    "reporting/_pdf_original_dna_png_admission.py", "requirements-reporting.lock",
    "reporting/internal_navigation.py", "reporting/typed_html.py", "reporting/editorial_typed_pdf.py",
)
ENGINES = {
    "weasyprint/pdf/tags.py": "fae488b773686ea7fb685967c78a5b011854b88b61377f426ffb4e9ec00d76d2",
    "weasyprint/pdf/__init__.py": "426e0855db0473121bf70666b3c6c5fbd9ebfe832741d31a3689e8b10a14281f",
    "weasyprint/document.py": "f08f91af64563f5fb27596828891fb326262511a56e4ace714e5a960898024c8",
    "pydyf/__init__.py": "f0cdb619c0de7cd40e04fce1927411d98fc2186b509db6cfa93a142c755a08fd",
    "weasyprint/pdf/stream.py": "4faf9169d1970d4688b9cf41f733659ca6b1c4c098707c64f67c47a07309e81e",
    "weasyprint/draw/__init__.py": "fb6fcee79a80059c72a3142ef941d4968e3aeeddc8fbbcac2e8519e8be55e348",
    "weasyprint/css/targets.py": "dc7a175f80bbca473564d4462cc60a240c6f4a45456e83165de73dd2c5d574b8",
    "weasyprint/formatting_structure/build.py": "335ad8b541295d6b9c5b71830d5184cd692f730d7b83ba5bac39fdb5aea23c87",
    "weasyprint/formatting_structure/boxes.py": "8ffd28ab74a149f0097208fcba6a80df0c8bb01e8fd4f9ced95d11b7e9807e23",
    "weasyprint/draw/text.py": "c9a450aa209277e760227e1fed2da492647bd28e5a5ebc4c9d8aaedecc400d77",
    "weasyprint/text/line_break.py": "1f5a855ad992e0bebaf5512d2b806fd991090e0e91bf79d3d5a3a0176b22af97",
    "weasyprint/text/ffi.py": "530e83118f7841d2791678ece23d5e43a7a24150ee1ea64bb4ba70c70b3eb5da",
    "weasyprint/layout/absolute.py": "240e268cec1e66dda1f87aec6bdd671e7bf36439c5fa09de32965f717893ba07",
    "weasyprint/layout/block.py": "9457dca0528c378f3ff6dd2ca5126d04ca017542de2fb77b1db48c3073401085",
}
CONTRACT = {
    "schema_version": "1.0.0", "profile_id": PROFILE_ID, "mode": MODE, "protocol_version": 3,
    "inherited_profile_sha256": LEGACY_HASH, "versions": {"weasyprint": "70.0", "pydyf": "0.12.1"},
    "engine_sources": ENGINES, "qualification_only": True, "release_authorized": False,
    "default_pipeline_activated": False, "aggregate_job_resources_qualified": False,
    "limits": {"memory_bytes": 1073741824, "cpu_seconds": 20, "wall_seconds": 30,
               "open_files": 128, "html_bytes": 67108864, "pdf_bytes": 16777216,
               "pages": 64, "response_bytes": 65536, "structure_depth": 64,
               "structure_charge": 20000, "ids": 10000, "id_bytes": 128, "figures": 1},
}


def require(condition):
    if not condition:
        raise ValueError("typed brand emission refused")


def _bounded_file(path, limit, *, retain=False):
    """Hash one bounded regular descriptor and reject changes across the read."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    fd = os.open(path, flags)
    try:
        first = os.fstat(fd)
        require(stat.S_ISREG(first.st_mode) and 0 < first.st_size <= limit)
        digest = sha256()
        content = bytearray()
        consumed = 0
        while consumed < first.st_size:
            chunk = os.read(fd, min(8192, first.st_size - consumed))
            require(bool(chunk))
            consumed += len(chunk)
            digest.update(chunk)
            if retain:
                content.extend(chunk)
        last = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        def identity(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                    info.st_mtime_ns, info.st_ctime_ns)
        require(identity(first) == identity(last) == identity(named))
        return bytes(content), digest.hexdigest()
    finally:
        os.close(fd)


def _manifest():
    from reporting.pdf_raster_render import _strict
    raw, manifest_digest = _bounded_file(MANIFEST, 16384, retain=True)
    data = _strict(raw.decode("ascii"))
    require(type(data) is dict and set(data) == set(CONTRACT) | {"sources"})
    fixed = {key: data[key] for key in CONTRACT}
    require(json.dumps(fixed, sort_keys=True) == json.dumps(CONTRACT, sort_keys=True))
    require(type(data["sources"]) is dict and set(data["sources"]) == set(SOURCES))
    for name in SOURCES:
        path = ROOT / name
        require(not path.is_symlink() and path.resolve().is_relative_to(ROOT)
                and _bounded_file(path, 65536)[1] == data["sources"][name])
    for package, version in CONTRACT["versions"].items():
        dist = distribution(package)
        require(dist.version == version)
        for name, expected in ENGINES.items():
            if name.startswith(package + "/"):
                require(_bounded_file(Path(dist.locate_file(name)), 65536)[1] == expected)
    return data, manifest_digest


def require_source_manifest() -> dict:
    return _manifest()[0]


def profile_sha256() -> str:
    return _manifest()[1]


def _owned(pdf, ref, cls):
    require(type(ref) is bytes and len(ref) <= 20 and re.fullmatch(rb"[1-9][0-9]* 0 R", ref))
    index = int(ref.split()[0])
    require(index < len(pdf.objects))
    obj = pdf.objects[index]
    require(isinstance(obj, cls) and obj.number == index and obj.free == "n"
            and obj.generation == 0 and obj.reference == ref)
    return obj


def _numeric(value):
    import pydyf
    require(type(value) in (int, float) and -10**12 <= value <= 10**12 and isfinite(value))
    return Decimal(pydyf._to_bytes(value).decode("ascii"))


def _page_sizes(document, pdf):
    import pydyf
    require(_owned(pdf, pdf.catalog.reference, pydyf.Dictionary) is pdf.catalog
            and pdf.catalog.get("Type") == "/Catalog")
    pages = pdf.pages
    count = pages["Count"]
    require(_owned(pdf, pdf.catalog["Pages"], pydyf.Dictionary) is pages
            and pages["Type"] == "/Pages" and type(count) is int
            and 1 <= count <= 64 and count == len(document.pages)
            and type(pages["Kids"]) is pydyf.Array and len(pages["Kids"]) == count * 3
            and all(key not in pages for key in ("Rotate", "UserUnit", "CropBox")))
    sizes = {}
    for i, layout in enumerate(document.pages):
        n, generation, marker = pages["Kids"][i * 3:i * 3 + 3]
        require(type(n) is int and 0 < n < len(pdf.objects) and type(generation) is int
                and generation == 0 and marker == "R")
        ref = f"{n} 0 R".encode("ascii")
        page = _owned(pdf, ref, pydyf.Dictionary)
        require(ref not in sizes and page["Type"] == "/Page" and page["Parent"] == pages.reference
                and all(key not in page for key in ("Rotate", "UserUnit", "CropBox")))
        require(len(layout.bleed) == 4 and all(key in layout.bleed for key in ("top", "bottom", "left", "right"))
                and all(type(v) in (int, float) and v == 0 for v in layout.bleed.values()))
        _numeric(layout.width)
        _numeric(layout.height)
        width, height = _numeric(layout.width * 0.75), _numeric(layout.height * 0.75)
        require(width > 0 and height > 0)
        for key in ("MediaBox", "TrimBox", "BleedBox"):
            box = page[key]
            require(type(box) is pydyf.Array and len(box) == 4
                    and tuple(map(_numeric, box)) == (0, 0, width, height))
        stream = _owned(pdf, page["Contents"], pydyf.Stream)
        h = pydyf._to_bytes(layout.height * 0.75)
        require(stream.stream[:3] == [b"1 0 0 -1 0 " + h + b" cm", b"q", b"0.75 0 0 0.75 0 0 cm"])
        sizes[ref] = width, height
    return sizes


def _untransformed_layout(document):
    """Admit the fixed no-CSS-transform layout before changing PDF structure."""
    from weasyprint.formatting_structure.boxes import Box, TableBox
    from weasyprint.layout.absolute import AbsolutePlaceholder

    limits = CONTRACT["limits"]
    try:
        pending = [(page._page_box, 1) for page in document.pages]
        charge = len(pending)
        require(1 <= charge <= limits["pages"])
        while pending:
            box, depth = pending.pop()
            if type(box) is AbsolutePlaceholder:
                box = object.__getattribute__(box, "_box")
                require(not isinstance(box, AbsolutePlaceholder))
            require(isinstance(box, Box) and depth <= limits["structure_depth"])
            transform, children = box.style["transform"], box.children
            require(type(transform) is tuple and not transform
                    and box.transformation_matrix is None
                    and type(children) in (tuple, list))
            column_groups = box.column_groups if isinstance(box, TableBox) else ()
            require(type(column_groups) in (tuple, list))
            fanout = len(children) + len(column_groups)
            require(not fanout or depth < limits["structure_depth"])
            # Charge each root once and each child node plus its incoming edge.
            # This reserves the entire fanout before extending the finite stack.
            require(fanout <= (limits["structure_charge"] - charge) // 2)
            charge += 2 * fanout
            pending.extend((child, depth + 1)
                           for group in (children, column_groups) for child in group)
    except (AttributeError, KeyError, TypeError):
        require(False)


def _box(attr, size):
    import pydyf
    require(type(attr) is pydyf.Dictionary and attr.number is None
            and len(attr) == 2 and "BBox" in attr and attr.get("O") == "/Layout")
    box = attr["BBox"]
    require(type(box) is pydyf.Array and len(box) == 4)
    x0, y0, x1, y1 = map(_numeric, box)
    w, h = size
    with localcontext() as ctx:
        ctx.prec = 48
        s = Decimal("0.75")
        result = (s*x0, h-s*y1, s*x1, h-s*y0)
    require(0 <= result[0] < result[2] <= w and 0 <= result[1] < result[3] <= h)
    return pydyf.Array([format(number, "f").encode("ascii") for number in result])


def _identifier(obj):
    import pydyf
    require(type(obj) is pydyf.String and type(obj.string) is str and 1 <= len(obj.string) <= 128
            and re.fullmatch(r"[1-9][0-9]*-(?:0|[1-9][0-9]*)-(?:0|[1-9][0-9]*)", obj.string))
    return obj.string.encode("ascii")


def emit_structure(document, pdf) -> dict:
    import pydyf
    require(type(pdf) is pydyf.PDF)
    sizes = _page_sizes(document, pdf)
    _untransformed_layout(document)
    root = _owned(pdf, pdf.catalog["StructTreeRoot"], pydyf.Dictionary)
    require(root["Type"] == "/StructTreeRoot" and "IDTree" not in root and
            type(root["K"]) is pydyf.Array and len(root["K"]) == 1)
    parent_tree = _owned(pdf, root["ParentTree"], pydyf.Dictionary)
    require(parent_tree is not root and len(parent_tree) == 1 and "Nums" in parent_tree)
    nums = parent_tree["Nums"]
    require(type(nums) is pydyf.Array and len(nums) == 2 * len(sizes))
    owner_count = 0
    for page_index in range(len(sizes)):
        key, owners = nums[2 * page_index:2 * page_index + 2]
        require(type(key) is int and key == page_index and type(owners) is pydyf.Array)
        owner_count += len(owners)
        require(owner_count <= 20000)
        for reference in owners:
            owner = _owned(pdf, reference, pydyf.Dictionary)
            require(owner.get("Type") == "/StructElem")
    pending = [(root["K"][0], root.reference, 1, None)]
    seen, ids, headers = set(), {}, []
    figure = None
    charge = 0
    while pending:
        ref, parent, depth, table = pending.pop()
        node = _owned(pdf, ref, pydyf.Dictionary)
        require(node is not parent_tree and depth <= 64 and ref not in seen and node["Type"] == "/StructElem" and node["P"] == parent)
        seen.add(ref)
        role = node["S"]
        if depth == 1:
            require(role == "/Document" and "Pg" not in node)
        else:
            require(role != "/Document" and node["Pg"] in sizes)
        if role == "/Table":
            table = node.number
        if role == "/Figure":
            require(figure is None)
            converted = _box(node["A"], sizes[node["Pg"]])
            figure = node, pydyf.Dictionary({"O": "/Layout", "BBox": converted})
        if role == "/TH" or "ID" in node:
            require(role == "/TH" and table is not None and "ID" in node)
            identifier = _identifier(node["ID"])
            require(identifier.startswith(f"{table}-".encode()) and identifier not in ids
                    and len(ids) < 10000)
            ids[identifier] = node["ID"], ref
        attr = node.get("A")
        if role in ("/TH", "/TD"):
            require(type(attr) is pydyf.Dictionary and attr.get("O") == "/Table"
                    and ("Headers" in attr) == (role == "/TD"))
        if attr is not None:
            require(role in ("/TH", "/TD", "/Figure") and type(attr) is pydyf.Dictionary)
            if "Headers" in attr:
                values = attr["Headers"]
                require(role == "/TD" and table is not None and attr.get("O") == "/Table"
                        and type(values) is pydyf.Array and 0 < len(values)
                        and len(headers) + len(values) <= 20000)
                headers.extend((_identifier(value), value, table) for value in values)
        kids = node["K"]
        require(type(kids) is pydyf.Array)
        charge += 1 + len(kids)
        require(charge <= 20000)
        for child in kids:
            if type(child) is int:
                require(0 <= child < 20000)
            else:
                require(type(child) is bytes and depth < 64)
                pending.append((child, ref, depth + 1, table))
    require(figure is not None)
    for key, value, table in headers:
        require(key in ids and ids[key][0] is value and key.startswith(f"{table}-".encode()))
    if ids:
        names = pydyf.Array([item for key in sorted(ids) for item in ids[key]])
        index = pydyf.Dictionary({"Names": names})
        pdf.add_object(index)
        root["IDTree"] = index.reference
    figure_node, layout = figure
    figure_node["A"] = layout
    return {"figure_count": 1, "id_count": len(ids)}


def _compose_finisher(original):
    used = False

    def finisher(selection, document, pdf):
        nonlocal used
        require(not used)
        used = True
        original(selection, document, pdf)
        emit_structure(document, pdf)

    finisher._typed_brand = True
    return finisher


def _editorial_source(page_box):
    """Recognize only one full-IR marker on the first source-body section."""
    roots = [child for child in page_box.children if child.element_tag == "html"]
    require(len(roots) <= 1)
    if not roots or roots[0].element is None:
        return roots[0] if roots else None, None, None
    root = roots[0].element
    marked = []
    for charge, element in enumerate(root.iter(), 1):
        if "data-editorial-ir-sha256" in element.attrib:
            marked.append(element)
            require(len(marked) == 1)
    if not marked:
        return roots[0], None, None
    require(charge <= CONTRACT["limits"]["structure_charge"])
    cover = marked[0]
    value = cover.get("data-editorial-ir-sha256")
    bodies = [element for element in root if element.tag == "body"]
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value)
            and len(bodies) == 1 and len(bodies[0]) > 0
            and bodies[0][0] is cover and cover.tag == "section"
            and not (bodies[0].text or "").strip())
    return roots[0], cover, value


def _editorial_cover_title(page_box, cover_box):
    """Refuse title boxes or glyph ink outside the space left by the originals."""
    from weasyprint.formatting_structure import boxes
    from weasyprint.layout.absolute import AbsolutePlaceholder
    from weasyprint.text.ffi import FROM_UNITS, ffi, pango

    def unwrap(box):
        return object.__getattribute__(box, "_box") if type(box) is AbsolutePlaceholder else box

    def rectangle(x, y, width, height):
        # Compare the same finite decimal coordinates admitted for serialization.
        x0, y0, w, h = map(_numeric, (x, y, width, height))
        require(w >= 0 and h >= 0)
        return x0, y0, _numeric(x + width), _numeric(y + height)

    def border(box):
        return rectangle(box.border_box_x(), box.border_box_y(),
                         box.border_width(), box.border_height())

    def inside(inner, outer):
        require(outer[0] <= inner[0] <= inner[2] <= outer[2]
                and outer[1] <= inner[1] <= inner[3] <= outer[3])

    require(type(cover_box) is boxes.BlockBox and cover_box.element_tag == "section")
    page_area = rectangle(page_box.content_box_x(), page_box.content_box_y(),
                          page_box.width, page_box.height)
    cover_area = rectangle(cover_box.content_box_x(), cover_box.content_box_y(),
                           cover_box.width, cover_box.height)
    inside(cover_area, page_area)
    source_titles = [element for element in cover_box.element if element.tag == "h1"]
    require(len(source_titles) == 1)
    require(len(cover_box.children) <= CONTRACT["limits"]["structure_charge"])
    children = [unwrap(box) for box in cover_box.children]

    def bound_child(element):
        matches = [box for box in children if box.element is element]
        require(len(matches) == 1 and type(matches[0]) is boxes.BlockBox
                and matches[0].element_tag == element.tag)
        return matches[0]

    title = bound_child(source_titles[0])
    # An absolute title can continue on another page while its first fragment fits.
    # Sliced decorations mark either incomplete edge before any page is painted.
    require(not title.remove_decoration_sides)
    original_boxes = []
    for name in ("original-dna", "original-logo"):
        elements = [element for element in cover_box.element
                    if element.tag == "div" and element.get("data-brand") == name]
        require(len(elements) == 1)
        original_boxes.append(border(bound_child(elements[0])))
        inside(original_boxes[-1], cover_area)
    dna, logo = original_boxes
    # The existing white gaps remain available for safe glyph overhang.
    title_area = dna[2], logo[3], cover_area[2], cover_area[3]
    require(title_area[0] < title_area[2] and title_area[1] < title_area[3])
    inside(border(title), title_area)
    require(bool(title.children) and len(title.children) <= CONTRACT["limits"]["structure_charge"])
    charge, text_count = 1, 0
    for line in title.children:
        require(type(line) is boxes.LineBox and line.element is source_titles[0]
                and len(line.children) <= CONTRACT["limits"]["structure_charge"] - charge)
        charge += 1 + len(line.children)
        require(charge <= CONTRACT["limits"]["structure_charge"])
        inside(border(line), title_area)
        for text in line.children:
            require(type(text) is boxes.TextBox and text.element is source_titles[0]
                    and not text.children)
            text_count += 1
            inside(border(text), title_area)
            layout = text.pango_layout
            layout.reactivate(text.style)
            try:
                # draw_text uses this same final line, single-paragraph mode and baseline.
                pango.pango_layout_set_single_paragraph_mode(layout.layout, True)
                first_line, next_line = layout.get_first_line()
                require(first_line != ffi.NULL and next_line is None)
                ink = ffi.new("PangoRectangle *")
                try:
                    pango.pango_layout_line_get_extents(first_line, ink, ffi.NULL)
                    inside(rectangle(
                        text.position_x + ink.x * FROM_UNITS,
                        text.position_y + text.baseline + ink.y * FROM_UNITS,
                        ink.width * FROM_UNITS, ink.height * FROM_UNITS), title_area)
                finally:
                    ffi.release(ink)
            finally:
                layout.deactivate()
    require(text_count > 0)


def _editorial_navigation_row(page_box, row):
    """Refuse a sliced or out-of-page generated contents paragraph before paint."""
    from weasyprint.formatting_structure import boxes

    require(type(row) is boxes.BlockBox and row.element_tag == "p"
            and row.element is not None and row.element.get("data-editorial-nav-target"))
    # The pinned layout marks both incomplete and continued slice edges, even
    # when an oversized break-inside:avoid paragraph's partial box fits a page.
    require(row.style["box_decoration_break"] == "slice" and not row.remove_decoration_sides)

    def rectangle(x, y, width, height):
        x0, y0, w, h = map(_numeric, (x, y, width, height))
        require(w >= 0 and h >= 0)
        return x0, y0, _numeric(x + width), _numeric(y + height)

    page = rectangle(page_box.content_box_x(), page_box.content_box_y(),
                     page_box.width, page_box.height)
    bounds = rectangle(row.border_box_x(), row.border_box_y(),
                       row.border_width(), row.border_height())
    require(page[0] <= bounds[0] <= bounds[2] <= page[2]
            and page[1] <= bounds[1] <= bounds[3] <= page[3])


def _editorial_footer(page_box, expected):
    """Admit the exact unwrapped bottom-right text; no other margin content."""
    from weasyprint.formatting_structure import boxes
    margins = [box for box in page_box.children if isinstance(box, boxes.MarginBox)]
    require(len(margins) == 1)
    margin = margins[0]
    require(type(margin) is boxes.MarginBox and margin.at_keyword == "@bottom-right"
            and margin.element is None and len(margin.children) == 1)
    line = margin.children[0]
    require(type(line) is boxes.LineBox and len(line.children) == 1)
    text = line.children[0]
    require(type(text) is boxes.TextBox and not text.children and text.element is None
            and type(text.text) is str and text.text == expected)
    return margin, text


def _install_editorial_after_font_bootstrap():
    """Install one finite footer route inside the already admitted render child."""
    require(sys.flags.isolated and sys.dont_write_bytecode
            and Path(sys.argv[0]).resolve() == Path(__file__).with_name("_pdf_typed_brand_render_worker.py"))
    import pydyf
    import weasyprint.document as document_module
    import weasyprint.pdf.tags as tag_module
    import weasyprint.pdf.stream as stream_module
    from weasyprint.formatting_structure import boxes

    original_draw = document_module.draw_page
    original_build = tag_module._build_box_tree
    original_marked = stream_module.Stream.marked
    require(not getattr(original_draw, "_typed_brand_editorial", False))
    pages, margins, texts = [], {}, {}
    source_root, source_cover, source_ir = None, None, None

    def draw_page(page_box, stream):
        nonlocal source_root, source_cover, source_ir
        html, cover, ir = _editorial_source(page_box)
        if not pages:
            source_root = html.element if html is not None else None
            source_cover, source_ir = cover, ir
        else:
            require(ir == source_ir)
        page_index = len(pages)
        require(page_index < CONTRACT["limits"]["pages"] and page_box not in pages)
        pages.append(page_box)
        if source_ir is None:
            original_draw(page_box, stream)
            return
        require(html is not None and html.element is source_root
                and cover is source_cover and stream._tags is not None)
        cover_present = False
        for charge, box in enumerate(page_box.descendants(), 1):
            require(charge <= CONTRACT["limits"]["structure_charge"])
            cover_present = cover_present or box.element is cover
            if (type(box) is boxes.BlockBox and box.element_tag == "p"
                    and box.element is not None
                    and box.element.get("data-editorial-nav-target") is not None):
                _editorial_navigation_row(page_box, box)
        if page_index == 0:
            bodies = [box for box in html.children if box.element_tag == "body"]
            require(len(bodies) == 1 and bool(bodies[0].children) and cover_present
                    and bodies[0].children[0].element is cover
                    and bodies[0].children[0].element_tag == "section")
            _editorial_cover_title(page_box, bodies[0].children[0])
        else:
            require(not cover_present)
        expected = "OmniGenis | " + source_ir[:12] + " | " + str(page_index + 1)
        margin, text = _editorial_footer(page_box, expected)
        require(margin not in margins and text not in texts)
        slot = {"page": page_index, "stream": stream, "text": text, "drawn": False, "tagged": False}
        margins[margin], texts[text] = slot, slot
        original_draw(page_box, stream)
        require(slot["drawn"] and text not in stream._tags)

    def build_box_tree(box, parent, pdf, page_number, nums, annotations, tags):
        if source_ir is not None and isinstance(box, boxes.MarginBox):
            require(box in margins)
            slot = margins[box]
            require(slot["page"] == page_number and slot["drawn"] and not slot["tagged"]
                    and all(descendant not in tags for descendant in box.descendants()))
            slot["tagged"] = True
            return
        yield from original_build(box, parent, pdf, page_number, nums, annotations, tags)

    @contextmanager
    def marked(self, box, tag):
        if box not in texts:
            with original_marked(self, box, tag):
                yield
            return
        slot = texts[box]
        require(slot["stream"] is self and tag == "Span" and self._tags is not None
                and box not in self._tags and not slot["drawn"])
        slot["drawn"] = True
        pydyf.Stream.begin_marked_content(self, "Artifact", pydyf.Dictionary({
            "Type": "/Pagination", "Subtype": "/Footer"}))
        try:
            yield
        finally:
            pydyf.Stream.end_marked_content(self)

    def finish(document, pdf):
        require(pages == [page._page_box for page in document.pages])
        if source_ir is None:
            return
        require(1 <= len(pages) <= CONTRACT["limits"]["pages"] and len(margins) == len(pages)
                and len(texts) == len(pages) and all(slot["drawn"] and slot["tagged"] for slot in margins.values())
                and "PageLabels" not in pdf.catalog)
        pdf.catalog["PageLabels"] = pydyf.Dictionary({
            "Nums": pydyf.Array([0, pydyf.Dictionary({"S": "/D", "St": 1})])})

    draw_page._typed_brand_editorial = True
    document_module.draw_page = draw_page
    tag_module._build_box_tree = build_box_tree
    stream_module.Stream.marked = marked
    return finish


def install_in_isolated_render_worker() -> None:
    from reporting.pdf_font_selection import LatoFontSelection
    require(sys.flags.isolated and sys.dont_write_bytecode and
            Path(sys.argv[0]).resolve() == Path(__file__).with_name("_pdf_typed_brand_render_worker.py")
            and not getattr(LatoFontSelection.finisher, "_typed_brand", False))
    original_enter = LatoFontSelection.__enter__
    composed = _compose_finisher(LatoFontSelection.finisher)
    finish_editorial = None

    def enter(selection):
        nonlocal finish_editorial
        require(finish_editorial is None)
        active = original_enter(selection)
        finish_editorial = _install_editorial_after_font_bootstrap()
        return active

    def finisher(selection, document, pdf):
        require(finish_editorial is not None)
        composed(selection, document, pdf)
        finish_editorial(document, pdf)

    finisher._typed_brand = True
    LatoFontSelection.__enter__ = enter
    LatoFontSelection.finisher = finisher
