"""Verify fixed font selection, physical type sizes, and text in real PDFs."""

from __future__ import annotations

from copy import deepcopy
from html.parser import HTMLParser
from io import BytesIO
import json
from math import hypot
from pathlib import Path
import unittest

from reporting import adapters, compiler, localization, presentation, viewmodel


ROOT = Path(__file__).resolve().parents[1]
A4_POINTS = (595.27559, 841.88976)
LEFT_INSET_POINTS = 44.0
POSITION_TOLERANCE = 0.25
LATO_REVISION_FIXED_16_16 = 132055
LATO_VERSION = "Version 2.015; 2015-08-06; http://www.latofonts.com/"


def native_localization():
    """Exercise the existing empty synthetic report through its native stages."""
    def load(relative):
        return json.loads((ROOT / relative).read_text(encoding="utf-8"))

    compiled = compiler.compile_report_pack(
        report_id="e1a-small-variant-report",
        catalog=load("reporting/catalog.v1.json"),
        section_contracts=load("reporting/sections/e1a-small-variant-report.v1.json"),
        intended_use=load("reporting/intended-use/e1a-small-variant-report.v1.json"),
        report_capability_manifest=load("reporting/capabilities/e1a-small-variant-report.v1.json"),
        canonical_interpretation={
            "identity": {"sample_id": "SYNTHETIC-001"},
            "items": [],
            "conflicts": [],
            "limitations": ["Synthetic fixture only"],
            "provenance": [{"source_id": "synthetic"}],
        },
    )
    model = viewmodel.build_report_view_model_and_release_bundle(
        compiled_report_pack=compiled,
        artifact_ids=["canonical-interpretation:synthetic-001"],
    )
    ir = presentation.build_presentation_ir(
        report_view_model=model.view_model,
    ).to_dict()["presentation_ir"]
    return localization.localize_presentation_ir(presentation_ir=ir, locale_id="en-US")


class _BodyText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.in_body = False
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag == "body":
            self.in_body = True

    def handle_endtag(self, tag):
        if tag == "body":
            self.in_body = False

    def handle_data(self, data):
        if self.in_body:
            self.parts.append(data)


def normalized_text(text):
    """Ignore layout whitespace without normalizing or replacing source tokens."""
    return "".join(character for character in text if not character.isspace())


def embedded_font_identity(program):
    """Read actual embedded bytes, independently of PDF font-name declarations."""
    from fontTools.ttLib import TTFont

    if program[:4] != b"\x00\x01\x00\x00":
        raise AssertionError("expected a TrueType FontFile2 program")
    with TTFont(BytesIO(program), lazy=False) as font:
        names = font["name"]
        return {
            "family": names.getDebugName(1),
            "subfamily": names.getDebugName(2),
            "postscript": names.getDebugName(6),
            "version": names.getDebugName(5),
            "revision_fixed_16_16": round(font["head"].fontRevision * 65536),
            "units_per_em": font["head"].unitsPerEm,
            "weight": font["OS/2"].usWeightClass,
        }


def page_fonts(page):
    """Require embedded programs for every font resource in this small fixture."""
    result = {}
    resources = page["/Resources"].get_object()["/Font"].get_object()
    for resource_name, reference in resources.items():
        font = reference.get_object()
        descendants = font.get("/DescendantFonts")
        if descendants is not None:
            if len(descendants) != 1:
                raise AssertionError("unexpected descendant-font structure")
            font = descendants[0].get_object()
        descriptor = font["/FontDescriptor"].get_object()
        program = descriptor["/FontFile2"].get_object().get_data()
        result[str(resource_name)] = embedded_font_identity(program)
    return result


def displayed_text(page):
    """Observe font and physical geometry immediately before real text shows."""
    fonts = page_fonts(page)
    state = {"font": None, "size": None}
    stack = []
    records = []

    def visit(operator, operands, cm, tm):
        if operator == b"q":
            stack.append(state.copy())
        elif operator == b"Q":
            if not stack:
                raise AssertionError("unbalanced PDF graphics-state restore")
            state.clear()
            state.update(stack.pop())
        elif operator == b"Tf":
            state.update(font=str(operands[0]), size=float(operands[1]))
        elif operator in (b"Tj", b"TJ"):
            strings = operands if operator == b"Tj" else operands[0]
            if not any(isinstance(value, (bytes, str)) and value for value in strings):
                return
            if state["font"] not in fonts or state["size"] is None:
                raise AssertionError("text show has no identified embedded font")
            # PDF uses the row-vector composition text matrix * current matrix.
            x = tm[4] * cm[0] + tm[5] * cm[2] + cm[4]
            y = tm[4] * cm[1] + tm[5] * cm[3] + cm[5]
            vertical_x = tm[2] * cm[0] + tm[3] * cm[2]
            vertical_y = tm[2] * cm[1] + tm[3] * cm[3]
            records.append({
                "x": float(x),
                "y": float(y),
                "size_pt": abs(state["size"]) * hypot(vertical_x, vertical_y),
                "font": fonts[state["font"]],
            })
        elif operator in (b"'", b'"'):
            raise AssertionError("observer does not handle implicit text-line moves")

    text = page.extract_text(visitor_operand_before=visit)
    if stack:
        raise AssertionError("unbalanced PDF graphics-state save")
    if not records:
        raise AssertionError("real PDF contains no observed text-show operation")
    return text, records


class FixedLatoPdfIntegrationTests(unittest.TestCase):
    """Reuse one real positive render and require a separate negative refusal."""

    @classmethod
    def setUpClass(cls):
        from pypdf import PdfReader

        localized = native_localization()
        if not localized.passed:
            raise AssertionError(localized.errors)
        cls.ir = localized.to_dict()["localized_ir"]
        cls.html, cls.digest, identifiers = adapters._semantic_html(cls.ir)
        if identifiers != [part["component_id"] for part in cls.ir["components"]]:
            raise AssertionError("synthetic component order changed")
        cls.pdf = adapters._render_pdf(cls.html, cls.digest)
        cls.reader = PdfReader(BytesIO(cls.pdf), strict=True)
        cls.observed = [displayed_text(page) for page in cls.reader.pages]

    def test_real_pdf_uses_lato_regular_and_bold_programs(self):
        """Declaring a family or renaming a PDF font dictionary cannot hide fallback."""
        unique = {}
        for page_index, (text, records) in enumerate(self.observed):
            self.assertTrue(text.strip())
            for record in records:
                font = record["font"]
                identity = tuple(font[field] for field in (
                    "family", "subfamily", "postscript", "version",
                    "revision_fixed_16_16", "units_per_em", "weight",
                ))
                unique.setdefault(identity, (font, page_index + 1))
        used = set()
        for font, first_page in unique.values():
            used.add(font["subfamily"])
            with self.subTest(first_page=first_page, font=font["postscript"]):
                self.assertEqual(font["family"], "Lato")
                self.assertIn((font["subfamily"], font["postscript"], font["weight"]), {
                    ("Regular", "Lato-Regular", 400),
                    ("Bold", "Lato-Bold", 700),
                })
                self.assertEqual(font["revision_fixed_16_16"], LATO_REVISION_FIXED_16_16)
                self.assertEqual(font["units_per_em"], 2000)
                # Subsets can omit optional name records. Full source-byte
                # admission is checked separately from this PDF observation.
                if font["version"] is not None:
                    self.assertEqual(font["version"], LATO_VERSION)
        self.assertEqual(used, {"Regular", "Bold"})

    def test_a4_left_inset_and_effective_title_and_body_sizes(self):
        """Measure actual PDF geometry rather than comparing stylesheet strings."""
        for page in self.reader.pages:
            self.assertEqual(int(page.get("/Rotate", 0)), 0)
            self.assertEqual(float(page.get("/UserUnit", 1)), 1.0)
            self.assertAlmostEqual(float(page.mediabox.left), 0, delta=0.01)
            self.assertAlmostEqual(float(page.mediabox.bottom), 0, delta=0.01)
            self.assertAlmostEqual(float(page.mediabox.width), A4_POINTS[0], delta=0.01)
            self.assertAlmostEqual(float(page.mediabox.height), A4_POINTS[1], delta=0.01)
        text, records = self.observed[0]
        self.assertTrue(text.lstrip().startswith(self.ir["report_id"]))
        first = records[0]
        self.assertEqual(first["font"]["subfamily"], "Bold")
        self.assertAlmostEqual(first["size_pt"], 25.0, delta=0.01)
        self.assertAlmostEqual(first["x"], LEFT_INSET_POINTS, delta=POSITION_TOLERANCE)
        regular = [record for _, rows in self.observed for record in rows
                   if record["font"]["subfamily"] == "Regular"]
        self.assertTrue(regular, "fixture must exercise actual regular body/pre text")
        for record in regular:
            self.assertAlmostEqual(record["size_pt"], 10.7, delta=0.01)

    def test_generated_pdf_preserves_complete_semantic_body_text(self):
        expected = _BodyText()
        expected.feed(self.html)
        expected.close()
        self.assertTrue(expected.parts)
        self.assertEqual(
            normalized_text("".join(text for text, _ in self.observed)),
            normalized_text("".join(expected.parts)),
        )

    def test_unsupported_scalar_refuses_without_returning_a_pdf(self):
        """U+1F600 is absent from both admitted static Lato Unicode cmaps."""
        ir = deepcopy(self.ir)
        ir["components"][0]["title"] += " \U0001f600"
        html, digest, _ = adapters._semantic_html(ir)
        self.assertIn("\U0001f600", html, "the negative must reach the worker unchanged")
        with self.assertRaises(RuntimeError) as caught:
            adapters._render_pdf(html, digest)
        self.assertEqual(str(caught.exception), "pdf_render_failed")
