"""Confined native structure/folio checks of an immutable branded candidate.

This is a bounded extension, not a patch to the default Span-only V1 observer.
It does not certify human reading order, PDF/UA, or source-asset raster identity.
"""
from __future__ import annotations

from hashlib import sha256
from importlib.metadata import version
from io import BytesIO
from pathlib import Path
import os
import stat
import sys

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reporting import _pdf_typed_observation_worker as typed
from reporting import _pdf_safety_worker as passive
from reporting import pdf_original_brand_pagination_composite as composite
from reporting import pdf_typed_observation as contract
from reporting._pdf_content_worker import normalize_stream
from reporting import _pdf_tounicode_cmap_frame_worker as cmap_frame
from reporting._pdf_tounicode_width_coverage_worker import _covered_sources
from reporting._pdf_original_svg_layout_worker import _find_exact_layout
from reporting._pdf_process_sandbox import enforce_pdf_landlock, enforce_pdf_network_filter
from reporting._pdf_render_worker import _write_bytes


def _require(value: object) -> None:
    if not value:
        raise ValueError("brand pagination observation refused")


def _labels(reader: object) -> list[str]:
    from pypdf.generic import ArrayObject, DictionaryObject, NameObject, NumberObject

    root = reader.root_object
    _require("/PageLabels" in root)
    label_object = typed._dictionary(root.raw_get("/PageLabels"), reader)
    _require(set(label_object) == {"/Nums"})
    nums = label_object.raw_get("/Nums")
    _require(type(nums) is ArrayObject and len(nums) == 2
             and type(nums[0]) is NumberObject and int(nums[0]) == 0
             and type(nums[1]) is DictionaryObject and set(nums[1]) == {"/S", "/St"}
             and type(nums[1].raw_get("/S")) is NameObject
             and nums[1].raw_get("/S") == "/D"
             and type(nums[1].raw_get("/St")) is NumberObject
             and int(nums[1].raw_get("/St")) == 1)
    labels = list(reader.page_labels)
    _require(labels == [str(i) for i in range(1, len(reader.pages) + 1)])
    return labels


def _footer_mapping(ref: object, reader: object) -> dict[str, str]:
    """Validate both native CID ref and renderer's direct CID dictionary form.

    A strict direct-dictionary successor is needed for branded vector pages;
    the original typed profile continues refusing that distinct object shape.
    All other font and CMap differences remain fail-closed.
    """
    from pypdf.generic import (
        ArrayObject, DictionaryObject, IndirectObject, NameObject,
        NumberObject, TextStringObject,
    )

    font = typed._dictionary(ref, reader)
    descendants = font.raw_get("/DescendantFonts")
    _require(type(descendants) is ArrayObject and len(descendants) == 1)
    cid_ref = descendants[0]
    if type(cid_ref) is IndirectObject:
        return dict(typed._font(ref, reader)["mapping"])
    _require(type(cid_ref) is DictionaryObject)
    _require(set(font) == {"/Type", "/Subtype", "/BaseFont", "/ToUnicode",
                            "/Encoding", "/DescendantFonts"})
    _require(font.raw_get("/Type") == "/Font"
             and font.raw_get("/Subtype") == "/Type0"
             and font.raw_get("/Encoding") == "/Identity-H")
    base = font.raw_get("/BaseFont")
    _require(type(base) is NameObject and 1 <= len(base) <= 128)
    cid = cid_ref
    _require(set(cid) == {"/Type", "/Subtype", "/BaseFont", "/CIDSystemInfo",
                          "/CIDToGIDMap", "/W", "/FontDescriptor"})
    _require(cid.raw_get("/Type") == "/Font"
             and cid.raw_get("/Subtype") == "/CIDFontType2"
             and cid.raw_get("/BaseFont") == base
             and cid.raw_get("/CIDToGIDMap") == "/Identity")
    info = cid.raw_get("/CIDSystemInfo")
    _require(type(info) is DictionaryObject
             and set(info) == {"/Registry", "/Ordering", "/Supplement"}
             and type(info.raw_get("/Registry")) is TextStringObject
             and info.raw_get("/Registry") == "Adobe"
             and type(info.raw_get("/Ordering")) is TextStringObject
             and info.raw_get("/Ordering") == "Identity"
             and type(info.raw_get("/Supplement")) is NumberObject
             and int(info.raw_get("/Supplement")) == 0)
    descriptor = typed._dictionary(cid.raw_get("/FontDescriptor"), reader)
    _require(descriptor.get("/Type") == "/FontDescriptor"
             and descriptor.get("/FontName") == base)
    cmap_ref = font.raw_get("/ToUnicode")
    typed._ref(cmap_ref, reader)
    cmap = cmap_ref.get_object()
    count, _ = _covered_sources(cmap, cid.raw_get("/W"))
    data = typed._stream_bytes(cmap, contract.MAX_CMAP_BYTES)
    _require(data.startswith(cmap_frame._NATIVE_PREFIX)
             and data.endswith(cmap_frame._NATIVE_SUFFIX))
    mapping: dict[str, str] = {}
    lines = data[len(cmap_frame._NATIVE_PREFIX):-len(cmap_frame._NATIVE_SUFFIX)].split(b"\n")
    for line in lines:
        if cmap_frame._BFCHAR_ROW.fullmatch(line):
            code, value = line.split(b" ")
            key = code[1:-1].decode("ascii").lower()
            _require(key not in mapping)
            mapping[key] = bytes.fromhex(value[1:-1].decode("ascii")).decode("utf-16-be", "strict")
    _require(len(mapping) == count and 0 < count <= contract.MAX_CMAP_RECORDS)
    return mapping


def _one_folio(page: object, reader: object, expected: str, stream: object) -> tuple[str, int, int]:
    """Verify the literal marked graphic artifact and its pinned ToUnicode text."""
    from pypdf.generic import (
        ArrayObject, ByteStringObject, ContentStream, DictionaryObject,
        FloatObject, NameObject, NumberObject,
    )

    _require(type(stream) is ContentStream and stream.pdf is reader
             and stream.forced_encoding == "bytes")
    ops = list(stream.operations)
    _require(0 < len(ops) <= contract.MAX_OPERATIONS)
    found = []
    depth = 0
    decorative_artifacts = 0
    decorative_active = False
    decorative_drawing = 0
    idx = 0
    while idx < len(ops):
        args, operator = ops[idx]
        _require(type(args) is list)
        if operator == b"BDC":
            _require(len(args) == 2 and type(args[0]) is NameObject)
            if args[0] == "/Artifact":
                _require(depth == 0 and not found
                         and type(args[1]) is DictionaryObject
                         and set(args[1]) == {"/Type", "/Subtype"}
                         and args[1].raw_get("/Type") == "/Pagination"
                         and args[1].raw_get("/Subtype") == "/Footer")
                sequence = ops[idx + 1:idx + 9]
                _require(len(sequence) == 8
                         and [op for _, op in sequence] == [
                             b"gs", b"rg", b"BT", b"Tm", b"Tf", b"TJ", b"ET", b"EMC"])
                _require(len(sequence[0][0]) == 1
                         and type(sequence[0][0][0]) is NameObject
                         and len(sequence[1][0]) == 3
                         and all(type(v) in (NumberObject, FloatObject)
                                 and 0 <= float(v) <= 1 for v in sequence[1][0])
                         and not sequence[2][0]
                         and len(sequence[3][0]) == 6
                         and all(type(v) in (NumberObject, FloatObject)
                                 for v in sequence[3][0])
                         and len(sequence[4][0]) == 2
                         and type(sequence[4][0][0]) is NameObject
                         and type(sequence[4][0][1]) in (NumberObject, FloatObject)
                         and float(sequence[4][0][1]) > 0
                         and len(sequence[5][0]) == 1
                         and type(sequence[5][0][0]) is ArrayObject
                         and 0 < len(sequence[5][0][0]) <= contract.MAX_OPERATIONS
                         and not sequence[6][0] and not sequence[7][0])
                found.append(sequence)
                idx += 9
                continue
            _require(args[0] in ("/Span", "/Figure"))
            _require(type(args[1]) is DictionaryObject and set(args[1]) == {"/MCID"}
                     and type(args[1].raw_get("/MCID")) is NumberObject)
            depth += 1
            _require(depth <= 64)
        elif operator == b"EMC":
            _require(depth > 0 and not args)
            depth -= 1
            if decorative_active and depth == 0:
                decorative_active = False
        elif operator == b"BMC":
            _require(len(args) == 1 and type(args[0]) is NameObject
                     and args[0] == "/Artifact" and depth == 0
                     and not decorative_active and decorative_artifacts == 0)
            decorative_artifacts += 1
            decorative_active = True
            depth = 1
        elif operator == b"Do" and decorative_active:
            _require(len(args) == 1 and type(args[0]) is NameObject)
            decorative_drawing += 1
        idx += 1
    _require(depth == 0 and len(found) == 1
             and decorative_artifacts <= 1
             and (decorative_artifacts == 0 or decorative_drawing >= 1))
    sequence = found[0]

    state_name = sequence[0][0][0]
    font_name = sequence[4][0][0]
    resources = page["/Resources"]
    states = resources.get("/ExtGState", {})
    _require(state_name in states)
    fonts = resources["/Font"]
    _require(font_name in fonts)
    mapping = _footer_mapping(fonts.raw_get(font_name), reader)
    result = []
    for value in sequence[5][0][0]:
        if type(value) in (NumberObject, FloatObject):
            typed._number(value)
        else:
            _require(type(value) is ByteStringObject and 0 < len(bytes(value)) <= contract.MAX_TEXT_BYTES)
            encoded = bytes(value).hex()
            _require(len(encoded) % 4 == 0)
            for offset in range(0, len(encoded), 4):
                _require(encoded[offset:offset + 4] in mapping)
                result.append(mapping[encoded[offset:offset + 4]])
    decoded = "".join(result)
    _require(decoded == expected)
    return decoded, len(ops), decorative_artifacts


def _page_observation(page: object, reader: object, expected: str) -> tuple[str, int, int, str]:
    """Reuse one bytes-encoded parse; restore the exact raw content reference."""
    from pypdf.generic import ContentStream, NameObject

    content = page.get_contents()
    _require(content is not None)
    stream = ContentStream(content, reader, forced_encoding="bytes")
    found, count, decorated = _one_folio(page, reader, expected, stream)
    original = page.raw_get("/Contents")
    page[NameObject("/Contents")] = stream
    try:
        text = normalize_stream(page.extract_text())
    finally:
        page[NameObject("/Contents")] = original
    return found, count, decorated, text


def inspect(pdf: bytes, digest: str) -> dict:
    """Inspect the same bytes without post-render modification or 32-page cap."""
    from pypdf import PdfReader
    from pypdf.generic import NameObject

    _require(version("pypdf") == "7.1.0"
             and type(pdf) is bytes and pdf.startswith(b"%PDF-1.7")
             and 0 < len(pdf) <= contract.MAX_PDF_BYTES
             and sha256(pdf).hexdigest() == digest)
    reader = PdfReader(BytesIO(pdf), strict=True)
    _require(not reader.is_encrypted and 1 <= len(reader.pages) <= 64)
    labels = _labels(reader)
    page_refs = set()
    for page in reader.pages:
        _require("/Annots" not in page and page.indirect_reference is not None)
        ref = page.indirect_reference
        page_refs.add((ref.idnum, ref.generation))
    _require(len(page_refs) == len(reader.pages))

    # The existing exact Figure /Layout predicate is source-pinned and does
    # not enforce the old 32-page document class. This new child separately
    # binds 64 pages/16 MiB before invoking it.
    permitted = _find_exact_layout(reader.trailer, page_refs)
    _, findings = passive.inspect_graph(reader.trailer)
    _require("pdf_actions_forbidden" in findings)
    # Only the parser's ephemeral object graph is normalized, never PDF bytes.
    del permitted[NameObject("/A")]
    _, findings = passive.inspect_graph(reader.trailer)
    _require(not findings)

    numbers = []
    operations = 0
    text_hash = sha256()
    text_characters = 0
    decorations = 0
    for number, page in enumerate(reader.pages, start=1):
        found, count, decorated, text = _page_observation(page, reader, str(number))
        numbers.append(found)
        operations += count
        decorations += decorated
        _require(type(text) is str and text.endswith(str(number)))
        exact_content = text[:-len(str(number))]
        _require(bool(exact_content.strip()))
        text_characters += len(exact_content)
        _require(text_characters <= 1048576)
        text_hash.update(exact_content.encode("utf-8"))
        _require(operations <= contract.MAX_OPERATIONS)
    _require(numbers == labels and decorations == 1)
    return {
        "status": "OBSERVED_BRAND_PAGINATION_COMPOSITE",
        "profile_id": composite.OBSERVER_ID,
        "pdf_sha256": digest,
        "page_count": len(reader.pages),
        "figure_layout_count": 1,
        "literal_artifact_numbers": numbers,
        "annotation_count": 0,
        "decorative_artifact_count": decorations,
        "extracted_text_sha256": text_hash.hexdigest(),
        "text_characters": text_characters,
        "release_authorized": False,
        "source_asset_bytes_authenticated_from_pdf": False,
        "human_assistive_accessibility_verified": False,
    }


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv if argv is None else argv
    if (sys.platform != "linux" or not sys.flags.isolated or not sys.dont_write_bytecode
            or type(argv) is not list or len(argv) != 4
            or any(type(arg) is not str or not arg.isascii() or not arg.isdecimal()
                   or len(arg) > 10 for arg in argv[1:])):
        return 64
    try:
        source, output, parent = map(int, argv[1:])
        _require(min(source, output) >= 3 and source != output and parent >= 2)
        files = [os.fstat(fd) for fd in (source, output)]
        _require(all(stat.S_ISREG(f.st_mode) and f.st_nlink == 0
                     and f.st_uid == os.geteuid() for f in files)
                 and files[0].st_ino != files[1].st_ino and files[1].st_size == 0)
        typed._limits()
        typed._lifetime(parent)
        enforce_pdf_landlock(Path(__file__))
        enforce_pdf_network_filter()
        composite._admit()
        digest, pdf = typed._read_request(source)
        result = inspect(pdf, digest)
        encoded = contract._canonical(result)
        _require(0 < len(encoded) <= contract.RESULT_BYTES)
        _write_bytes(output, encoded)
        return 0
    except Exception:
        return 70


if __name__ == "__main__":
    raise SystemExit(main())
