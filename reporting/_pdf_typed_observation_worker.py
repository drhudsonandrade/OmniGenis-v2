"""Confined physical observation of one exact typed PDF, with no source matching."""
from __future__ import annotations

from decimal import Decimal
from hashlib import sha256
from importlib.metadata import version
from io import BytesIO
import json
import logging
import os
from pathlib import Path
import stat
import sys
import zlib

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reporting import pdf_typed_observation as contract
from reporting import _pdf_safety_worker as passive
from reporting import _pdf_tounicode_cmap_frame_worker as cmap_frame
from reporting._pdf_tounicode_width_coverage_worker import _covered_sources
from reporting._pdf_structure_tree_worker import _key
from reporting._pdf_object_graph_worker import _lifetime
from reporting._pdf_process_sandbox import enforce_pdf_landlock, enforce_pdf_network_filter
from reporting._pdf_render_worker import _write_bytes

_require = contract._require


def _limits() -> dict:
    """Install finite process limits before reading candidate data or importing pypdf."""
    import resource

    values = (
        (resource.RLIMIT_AS, contract.LIMITS["memory_bytes"]),
        (resource.RLIMIT_CPU, contract.LIMITS["cpu_seconds"]),
        (resource.RLIMIT_FSIZE, contract.RESULT_BYTES),
        (resource.RLIMIT_NOFILE, contract.LIMITS["open_files"]),
        (resource.RLIMIT_CORE, 0),
    )
    for key, value in values:
        resource.setrlimit(key, (value, value))
    result = {
        "memory_bytes": resource.getrlimit(resource.RLIMIT_AS)[0],
        "cpu_seconds": resource.getrlimit(resource.RLIMIT_CPU)[0],
        "file_bytes": resource.getrlimit(resource.RLIMIT_FSIZE)[0],
        "open_files": resource.getrlimit(resource.RLIMIT_NOFILE)[0],
    }
    _require(result == contract.LIMITS)
    return result


def _read_request(fd: int) -> tuple[str, bytes]:
    before = os.fstat(fd)
    _require(contract.HEADER_BYTES < before.st_size <= contract.MAX_PDF_BYTES + contract.HEADER_BYTES)
    with os.fdopen(os.dup(fd), "rb") as source:
        source.seek(0)
        header = source.read(contract.HEADER_BYTES)
        pdf = source.read(contract.MAX_PDF_BYTES + 1)
    after = os.fstat(fd)
    _require(all(getattr(before, name) == getattr(after, name)
                 for name in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")))
    _require(header[:2] == b"1 " and header[-1:] == b"\n"
             and len(header) == contract.HEADER_BYTES
             and len(header) + len(pdf) == before.st_size
             and pdf.startswith(b"%PDF-1.7") and 0 < len(pdf) <= contract.MAX_PDF_BYTES)
    digest = header[2:-1].decode("ascii")
    _require(contract._DIGEST.fullmatch(digest) is not None and sha256(pdf).hexdigest() == digest)
    return digest, pdf


def _ref(ref: object, reader: object) -> list[int]:
    result = list(_key(ref, reader))
    contract._reference(result)
    return result


def _dictionary(value: object, reader: object) -> object:
    from pypdf.generic import DictionaryObject, IndirectObject

    if type(value) is IndirectObject:
        _ref(value, reader)
        value = value.get_object()
    _require(type(value) is DictionaryObject)
    return value


def _number(value: object) -> str:
    from pypdf.generic import FloatObject, NumberObject

    _require(type(value) in (NumberObject, FloatObject))
    # Preserve the parsed binary64 value; pypdf str() rounds for PDF writing.
    # Original source lexemes are not available from ContentStream operands.
    text = (str(int(value)) if type(value) is NumberObject
            else format(Decimal(repr(float(value))), "f"))
    contract._num(text)
    return text


def _page_tree(reader: object) -> list:
    """Traverse raw Kids before a convenience page iterator can omit invalid children."""
    from pypdf.generic import ArrayObject, NameObject, NumberObject

    root = reader.root_object
    _require(type(root.raw_get("/Type")) is NameObject and root.raw_get("/Type") == "/Catalog")
    seen, leaves = set(), []
    visits = 0

    def walk(ref: object, parent: object, resources: object, depth: int) -> int:
        nonlocal visits
        key = tuple(_ref(ref, reader))
        _require(key not in seen and depth <= contract.MAX_DEPTH)
        seen.add(key)
        visits += 1
        _require(visits <= contract.MAX_VISITS)
        node = _dictionary(ref, reader)
        if parent is not None:
            _require(_ref(node.raw_get("/Parent"), reader) == _ref(parent, reader))
        _require(type(node.raw_get("/Type")) is NameObject)
        if "/Resources" in node:
            resources = _dictionary(node.raw_get("/Resources"), reader)
        if node.raw_get("/Type") == "/Page":
            _require(resources is not None and "/Kids" not in node and len(leaves) < contract.MAX_PAGES)
            leaves.append((ref, node, resources))
            return 1
        _require(node.raw_get("/Type") == "/Pages")
        kids, count = node.raw_get("/Kids"), node.raw_get("/Count")
        _require(type(kids) is ArrayObject and 0 < len(kids) <= contract.MAX_VISITS
                 and type(count) is NumberObject and 1 <= count <= contract.MAX_PAGES)
        visits += len(kids)
        _require(visits <= contract.MAX_VISITS)
        actual = sum(walk(child, ref, resources, depth + 1) for child in kids)
        _require(actual == int(count))
        return actual

    walk(root.raw_get("/Pages"), None, None, 1)
    _require(bool(leaves))
    return leaves


def _structure(reader: object, native_pages: list) -> tuple[dict, set]:
    from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject, NameObject, NumberObject, TextStringObject

    root_ref = reader.root_object.raw_get("/StructTreeRoot")
    root = _dictionary(root_ref, reader)
    _require(set(root) == {"/Type", "/K", "/ParentTree"}
             and type(root.raw_get("/Type")) is NameObject and root.raw_get("/Type") == "/StructTreeRoot")
    trace = {"root_reference": _ref(root_ref, reader), "root_children": [],
             "root_children_form": "", "nodes": [], "pages": [], "fonts": []}
    page_keys = {}
    for index, (ref, page, _) in enumerate(native_pages):
        number = page.raw_get("/StructParents")
        _require(type(number) is NumberObject and 0 <= number < contract.MAX_VISITS
                 and int(number) not in page_keys)
        page_keys[int(number)] = tuple(_ref(ref, reader))
        trace["pages"].append({
            "index": index, "reference": _ref(ref, reader), "struct_parents": int(number),
            "mcid_owners": [], "font_resources": [], "graphics_states": [],
            "events": [], "runs": [],
        })
    parent_tree = _dictionary(root.raw_get("/ParentTree"), reader)
    _require(set(parent_tree) == {"/Nums"})
    nums = parent_tree.raw_get("/Nums")
    _require(type(nums) is ArrayObject and len(nums) == 2 * len(native_pages))
    reverse = {}
    for offset in range(0, len(nums), 2):
        number, owners = nums[offset:offset + 2]
        _require(type(number) is NumberObject and int(number) in page_keys
                 and int(number) not in reverse and type(owners) is ArrayObject
                 and 0 < len(owners) <= contract.MAX_VISITS)
        reverse[int(number)] = [{"mcid": i, "structure_reference": _ref(owner, reader)}
                                for i, owner in enumerate(owners)]
    for page in trace["pages"]:
        page["mcid_owners"] = reverse[page["struct_parents"]]
    seen, verified_attributes = set(), set()
    visits = sum(len(p["mcid_owners"]) for p in trace["pages"])

    def children(raw: object) -> tuple[str, list]:
        if type(raw) is ArrayObject:
            _require(len(raw) <= contract.MAX_VISITS)
            return "array", list(raw)
        if type(raw) is IndirectObject:
            return "reference", [raw]
        _require(type(raw) is NumberObject)
        return "mcid", [raw]

    def walk(ref: object, parent: object, depth: int) -> None:
        nonlocal visits
        key = tuple(_ref(ref, reader))
        _require(key not in seen and depth <= contract.MAX_DEPTH)
        seen.add(key)
        node = _dictionary(ref, reader)
        _require({"/Type", "/S", "/P", "/K"} <= set(node)
                 and set(node) <= {"/Type", "/S", "/P", "/K", "/Pg", "/A", "/ID"}
                 and type(node.raw_get("/Type")) is NameObject and node.raw_get("/Type") == "/StructElem"
                 and type(node.raw_get("/S")) is NameObject and node.raw_get("/S") in contract.ROLES
                 and _ref(node.raw_get("/P"), reader) == _ref(parent, reader))
        role = str(node.raw_get("/S"))
        form, kids = children(node.raw_get("/K"))
        visits += 1 + len(kids)
        _require(visits <= contract.MAX_VISITS)
        row = {"reference": list(key), "parent": _ref(parent, reader), "role": role,
               "page_reference": _ref(node.raw_get("/Pg"), reader) if "/Pg" in node else None,
               "children_form": form, "children": [], "table_attribute": False,
               "native_id": None, "headers": []}
        if role in {"/TH", "/TD"}:
            attribute = node.raw_get("/A")
            _require(type(attribute) is DictionaryObject
                     and set(attribute) == ({"/O"} if role == "/TH" else {"/O", "/Headers"})
                     and type(attribute.raw_get("/O")) is NameObject and attribute.raw_get("/O") == "/Table")
            row["table_attribute"] = True
            verified_attributes.add(id(node))
            if role == "/TH":
                value = node.raw_get("/ID")
                _require(type(value) is TextStringObject and 0 < len(value) <= 128)
                row["native_id"] = str(value)
            else:
                headers = attribute.raw_get("/Headers")
                _require("/ID" not in node and type(headers) is ArrayObject and len(headers) == 1
                         and all(type(h) is TextStringObject and 0 < len(h) <= 128 for h in headers))
                row["headers"] = [str(h) for h in headers]
        else:
            _require("/A" not in node and "/ID" not in node)
        trace["nodes"].append(row)
        for ordinal, child in enumerate(kids):
            if type(child) is IndirectObject:
                row["children"].append({"ordinal": ordinal, "kind": "node", "reference": _ref(child, reader)})
                walk(child, ref, depth + 1)
            else:
                _require(type(child) is NumberObject and 0 <= child < contract.MAX_VISITS)
                row["children"].append({"ordinal": ordinal, "kind": "mcid", "value": int(child)})

    form, roots = children(root.raw_get("/K"))
    _require(form != "mcid" and len(roots) == 1)
    trace["root_children_form"] = form
    trace["root_children"] = [_ref(ref, reader) for ref in roots]
    for ref in roots:
        walk(ref, root_ref, 1)
    contract._structure(trace)
    return trace, verified_attributes


def _passive_graph(reader: object, verified_attributes: set) -> None:
    """Retain denial rules; /A is allowed only on exact verified table cell objects."""
    from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject, NameObject, PdfObject, StreamObject

    pending, references, containers = [(reader.trailer, 0)], set(), set()
    visits = 0
    while pending:
        value, depth = pending.pop()
        _require(depth <= contract.MAX_DEPTH)
        if type(value) is IndirectObject:
            key = tuple(_ref(value, reader))
            if key in references:
                continue
            references.add(key)
            value = value.get_object()
        _require(isinstance(value, PdfObject) and not isinstance(value, IndirectObject))
        if isinstance(value, (DictionaryObject, ArrayObject)):
            if id(value) in containers:
                continue
            containers.add(id(value))
        visits += 1
        _require(visits <= contract.MAX_VISITS)
        children = ()
        if isinstance(value, DictionaryObject):
            _require(all(type(k) is NameObject for k in value))
            names = {}
            for name in ("/Type", "/Subtype", "/S"):
                if name in value:
                    discriminator = value.raw_get(name)
                    _require(type(discriminator) is NameObject)
                    names[name] = str(discriminator)
            forbidden = passive._ACTION_KEYS.intersection(value)
            if "/A" in forbidden and id(value) in verified_attributes:
                forbidden = forbidden - {"/A"}
            _require(not forbidden and names.get("/Type") != "/Action"
                     and names.get("/S") not in passive._ACTION_TYPES
                     and not passive._ATTACHMENT_KEYS.intersection(value)
                     and names.get("/Type") not in {"/Filespec", "/EmbeddedFile"}
                     and names.get("/Subtype") != "/FileAttachment"
                     and not passive._FORM_KEYS.intersection(value)
                     and names.get("/Subtype") != "/Widget"
                     and not passive._MEDIA_KEYS.intersection(value)
                     and names.get("/Subtype") not in passive._MEDIA_SUBTYPES
                     and not {"/ActualText", "/Alt", "/E", "/RoleMap", "/ClassMap"}.intersection(value))
            _require(not isinstance(value, StreamObject)
                     or not {"/F", "/FFilter", "/FDecodeParms"}.intersection(value))
            children = value.values()
        elif isinstance(value, ArrayObject):
            children = value
        for child in children:
            _require(len(pending) < contract.MAX_VISITS)
            pending.append((child, depth + 1))


def _stream_bytes(stream: object, maximum: int) -> bytes:
    """Bound inflation before allocating a decoded content/CMap stream."""
    from pypdf.generic import NameObject, StreamObject

    _require(isinstance(stream, StreamObject) and set(stream) <= {"/Filter"}
             and type(stream._data) is bytes and 0 < len(stream._data) <= contract.MAX_PDF_BYTES
             and 0 < maximum <= contract.MAX_STREAM_BYTES)
    if "/Filter" in stream:
        _require(type(stream.raw_get("/Filter")) is NameObject and stream.raw_get("/Filter") == "/FlateDecode")
        inflater = zlib.decompressobj()
        data = inflater.decompress(stream._data, maximum + 1)
        _require(inflater.eof and not inflater.unused_data and not inflater.unconsumed_tail)
    else:
        data = stream._data
    _require(0 < len(data) <= maximum)
    return data


def _font(ref: object, reader: object) -> dict:
    from pypdf.generic import ArrayObject, DictionaryObject, NameObject, NumberObject, TextStringObject

    font = _dictionary(ref, reader)
    _require(set(font) == {"/Type", "/Subtype", "/BaseFont", "/ToUnicode", "/Encoding", "/DescendantFonts"})
    for name, expected in (("/Type", "/Font"), ("/Subtype", "/Type0"), ("/Encoding", "/Identity-H")):
        _require(type(font.raw_get(name)) is NameObject and font.raw_get(name) == expected)
    base = font.raw_get("/BaseFont")
    _require(type(base) is NameObject and 1 <= len(base) <= 128)
    children = font.raw_get("/DescendantFonts")
    _require(type(children) is ArrayObject and len(children) == 1)
    cid_ref, cmap_ref = children[0], font.raw_get("/ToUnicode")
    cid = _dictionary(cid_ref, reader)
    _require(set(cid) == {"/Type", "/Subtype", "/BaseFont", "/CIDSystemInfo", "/CIDToGIDMap", "/W", "/FontDescriptor"})
    for name, expected in (("/Type", "/Font"), ("/Subtype", "/CIDFontType2"),
                           ("/BaseFont", base), ("/CIDToGIDMap", "/Identity")):
        _require(type(cid.raw_get(name)) is NameObject and cid.raw_get(name) == expected)
    info = cid.raw_get("/CIDSystemInfo")
    _require(type(info) is DictionaryObject and set(info) == {"/Registry", "/Ordering", "/Supplement"}
             and type(info.raw_get("/Registry")) is TextStringObject and info.raw_get("/Registry") == "Adobe"
             and type(info.raw_get("/Ordering")) is TextStringObject and info.raw_get("/Ordering") == "Identity"
             and type(info.raw_get("/Supplement")) is NumberObject and info.raw_get("/Supplement") == 0)
    descriptor = _dictionary(cid.raw_get("/FontDescriptor"), reader)
    _require(descriptor.get("/Type") == "/FontDescriptor" and descriptor.get("/FontName") == base)
    _ref(cmap_ref, reader)
    cmap = cmap_ref.get_object()
    count, widths = _covered_sources(cmap, cid.raw_get("/W"))
    data = _stream_bytes(cmap, contract.MAX_CMAP_BYTES)
    mapping = []
    for line in data[len(cmap_frame._NATIVE_PREFIX):-len(cmap_frame._NATIVE_SUFFIX)].split(b"\n"):
        if cmap_frame._BFCHAR_ROW.fullmatch(line):
            code, text = line.split(b" ")
            mapping.append([code[1:-1].decode("ascii").lower(),
                            bytes.fromhex(text[1:-1].decode("ascii")).decode("utf-16-be", "strict")])
    _require(len(mapping) == count and len(dict(mapping)) == count)
    return {"reference": _ref(ref, reader), "base_font": str(base),
            "cid_reference": _ref(cid_ref, reader), "cmap_reference": _ref(cmap_ref, reader),
            "cmap_sha256": sha256(data).hexdigest(), "cmap_decoded_bytes": len(data),
            "explicit_cid_width_count": widths, "mapping": mapping}


def _page_stream(page: dict, native: object, resources: object, reader: object, fonts: dict, remaining: int) -> None:
    from pypdf.generic import ArrayObject, ByteStringObject, ContentStream, DecodedStreamObject, DictionaryObject, NameObject, NumberObject

    _require(set(resources) <= {"/Font", "/ColorSpace", "/ExtGState", "/XObject", "/Pattern", "/Shading"})
    for empty in ("/XObject", "/Pattern", "/Shading"):
        if empty in resources:
            _require(not _dictionary(resources.raw_get(empty), reader))
    font_resources = _dictionary(resources.raw_get("/Font"), reader)
    _require(1 <= len(font_resources) <= contract.MAX_FONTS)
    for name, ref in font_resources.items():
        _require(type(name) is NameObject and 1 <= len(name) <= 128)
        key = tuple(_ref(ref, reader))
        if key not in fonts:
            _require(len(fonts) < contract.MAX_FONTS)
            fonts[key] = _font(ref, reader)
            _require(sum(f["cmap_decoded_bytes"] for f in fonts.values()) <= contract.MAX_CMAP_TOTAL
                     and sum(len(f["mapping"]) for f in fonts.values()) <= contract.MAX_CMAP_RECORDS)
        page["font_resources"].append({"name": str(name), "reference": list(key)})
    states = _dictionary(resources.raw_get("/ExtGState"), reader) if "/ExtGState" in resources else {}
    _require(len(states) <= contract.MAX_VISITS)
    for name, value in states.items():
        _require(type(name) is NameObject and 1 <= len(name) <= 128)
        state = _dictionary(value, reader)
        _require(set(state) and set(state) <= {"/ca", "/CA"})
        page["graphics_states"].append({
            "name": str(name), "fill_alpha": _number(state.raw_get("/ca")) if "/ca" in state else None,
            "stroke_alpha": _number(state.raw_get("/CA")) if "/CA" in state else None,
        })
    content_ref = native.raw_get("/Contents")
    page["contents_reference"] = _ref(content_ref, reader)
    data = _stream_bytes(content_ref.get_object(), remaining)
    page["decoded_stream_bytes"], page["content_sha256"] = len(data), sha256(data).hexdigest()
    decoded = DecodedStreamObject()
    decoded.set_data(data)
    stream = ContentStream(decoded, reader, forced_encoding="bytes")
    _require(0 < len(stream.operations) <= contract.MAX_OPERATIONS)
    for ordinal, (args, operator) in enumerate(stream.operations):
        op = operator.decode("ascii")
        _require(op in contract.OPERATORS and type(args) is list)
        if op in {"q", "Q", "BT", "ET", "EMC"}:
            _require(not args)
            operands = []
        elif op == "BDC":
            _require(len(args) == 2 and type(args[0]) is NameObject and args[0] == "/Span"
                     and type(args[1]) is DictionaryObject and set(args[1]) == {"/MCID"}
                     and type(args[1].raw_get("/MCID")) is NumberObject)
            operands = [int(args[1].raw_get("/MCID"))]
        elif op in {"cm", "Tm", "rg"}:
            _require(len(args) == (3 if op == "rg" else 6))
            operands = [_number(v) for v in args]
        elif op == "gs":
            _require(len(args) == 1 and type(args[0]) is NameObject)
            operands = [str(args[0])]
        elif op == "Tf":
            _require(len(args) == 2 and type(args[0]) is NameObject)
            operands = [str(args[0]), _number(args[1])]
        else:
            _require(op == "TJ" and len(args) == 1 and type(args[0]) is ArrayObject
                     and 1 <= len(args[0]) <= contract.MAX_OPERATIONS)
            operands = [["codes", bytes(v).hex()] if type(v) is ByteStringObject
                        else ["adjust", _number(v)] for v in args[0]]
        page["events"].append({"ordinal": ordinal, "operator": op, "operands": operands})
    page["runs"] = contract._replay(page, fonts)


def _inspect(pdf: bytes, digest: str, limits: dict) -> dict:
    _require(version("pypdf") == contract.PARSER_VERSION)
    profile_sha = contract._profile()

    class RefuseWarning(logging.Handler):
        def emit(self, _record: object) -> None:
            raise ValueError("typed PDF parser warning")

    guard = RefuseWarning(level=logging.WARNING)
    logger = logging.getLogger("pypdf")
    logger.addHandler(guard)
    try:
        from pypdf import PdfReader
        reader = PdfReader(BytesIO(pdf), strict=True)
        _require(not reader.is_encrypted)
        native_pages = _page_tree(reader)
        contract.require_pdf_document_budget(len(pdf), len(native_pages))
        trace, attributes = _structure(reader, native_pages)
        _passive_graph(reader, attributes)
        fonts, decoded, operations, text_bytes = {}, 0, 0, 0
        for page, (_, native, resources) in zip(trace["pages"], native_pages, strict=True):
            _page_stream(page, native, resources, reader, fonts, contract.MAX_STREAM_BYTES - decoded)
            decoded += page["decoded_stream_bytes"]
            operations += len(page["events"])
            text_bytes += sum(r["utf8_bytes"] for r in page["runs"])
            _require(operations <= contract.MAX_OPERATIONS and text_bytes <= contract.MAX_TEXT_BYTES)
        trace["fonts"] = list(fonts.values())
        counts = contract._structure(trace)
        counts.update({
            "fonts": len(fonts), "cmap_records": sum(len(f["mapping"]) for f in fonts.values()),
            "cmap_decoded_bytes": sum(f["cmap_decoded_bytes"] for f in fonts.values()),
            "decoded_stream_bytes": decoded, "operations": operations, "decoded_text_bytes": text_bytes,
            "glyph_codes": sum(r["glyph_codes"] for p in trace["pages"] for r in p["runs"]),
            "text_scalars": sum(r["scalars"] for p in trace["pages"] for r in p["runs"]),
        })
        _require(contract._profile() == profile_sha)
        return {
            "schema_version": "1.0.0", "profile_id": contract.PROFILE_ID,
            "status": contract.STATUS, "source_association": "NOT_ESTABLISHED",
            "pdf_sha256": digest, "pdf_byte_count": len(pdf), "page_count": len(native_pages),
            "parser_version": contract.PARSER_VERSION, "profile_sha256": profile_sha,
            "limits": limits, "counts": counts, "trace": trace,
            **{name: False for name in contract.NONCLAIMS},
        }
    finally:
        logger.removeHandler(guard)


def main(argv: list[str] | None = None) -> int:
    """Establish resource/lifetime/filesystem/network guards before candidate reads."""
    argv = sys.argv if argv is None else argv
    if (sys.platform != "linux" or not sys.flags.isolated or not sys.dont_write_bytecode
            or type(argv) is not list or len(argv) != 4
            or any(type(v) is not str or not v.isascii() or not v.isdecimal()
                   or len(v) > 10 for v in argv[1:])):
        return 64
    try:
        source, output, parent = map(int, argv[1:])
        _require(all(str(n) == s for n, s in zip((source, output, parent), argv[1:], strict=True))
                 and min(source, output) >= 3 and source != output and 2 <= parent <= 2147483647)
        infos = [os.fstat(fd) for fd in (source, output)]
        _require(all(stat.S_ISREG(v.st_mode) and v.st_nlink == 0
                     and v.st_uid == os.geteuid() for v in infos)
                 and (infos[0].st_dev, infos[0].st_ino) != (infos[1].st_dev, infos[1].st_ino)
                 and infos[1].st_size == 0)
        limits = _limits()
        _lifetime(parent)
        enforce_pdf_landlock(Path(__file__))
        enforce_pdf_network_filter()
        digest, pdf = _read_request(source)
        observation = _inspect(pdf, digest, limits)
        encoded = contract._canonical({"protocol_version": 1, "observation": observation})
        _require(0 < len(encoded) <= contract.RESULT_BYTES)
        _write_bytes(output, encoded)
        return 0
    except Exception:
        return 70


if __name__ == "__main__":
    raise SystemExit(main())
