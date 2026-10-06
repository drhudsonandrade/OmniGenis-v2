from __future__ import annotations
import hashlib
from io import BytesIO
import unittest

from pypdf import PdfReader, PdfWriter
from pypdf.generic import (
    ArrayObject, BooleanObject, DictionaryObject, FloatObject, NameObject,
    NullObject, NumberObject, TextStringObject,
)

from reporting.adapters import _render_pdf
from reporting.pdf_accessibility import validate_pdf_accessibility_structure


def synthetic_tagged_pdf(
    *, language="en-US", marked=True, struct_tree=True, mark_info=True,
    indirect_language=False,
):
    """Create a minimal synthetic PDF carrying selected accessibility markers."""
    writer=PdfWriter()
    writer.add_blank_page(width=612,height=792)
    if language is not None:
        language_value=TextStringObject(language)
        if indirect_language:
            language_value=writer._add_object(language_value)
        writer.root_object[NameObject("/Lang")]=language_value
    if mark_info:
        writer.root_object[NameObject("/MarkInfo")]=DictionaryObject({
            NameObject("/Marked"):BooleanObject(marked),
        })
    if struct_tree:
        writer.root_object[NameObject("/StructTreeRoot")]=DictionaryObject({
            NameObject("/Type"):NameObject("/StructTreeRoot"),
        })
    out=BytesIO(); writer.write(out); return out.getvalue()


class Rpt12PdfAccessibilityTests(unittest.TestCase):
    def test_renderer_emits_tagged_pdf_prerequisites(self):
        """The pinned renderer emits PDF/UA-1 structural prerequisites."""
        html='<!doctype html><html lang="en-US"><head><meta charset="utf-8"><title>Synthetic</title></head><body><h1>Synthetic</h1><p>Body</p></body></html>'
        pdf=_render_pdf(html,hashlib.sha256(html.encode()).hexdigest())
        result=validate_pdf_accessibility_structure(pdf_bytes=pdf,expected_language="en-US")
        self.assertTrue(result.passed,result.errors)
        self.assertTrue(result.marked)
        self.assertTrue(result.struct_tree_root)
        self.assertEqual(result.language,"en-US")
        self.assertEqual(result.conformance_claim,"PDF_UA_1_STRUCTURAL_PREREQUISITES_ONLY")

    def test_missing_or_false_markinfo_fails_closed(self):
        """Missing or false /MarkInfo /Marked cannot pass."""
        for pdf in (
            synthetic_tagged_pdf(marked=False),
            synthetic_tagged_pdf(mark_info=False),
        ):
            with self.subTest():
                result=validate_pdf_accessibility_structure(pdf_bytes=pdf,expected_language="en-US")
                self.assertFalse(result.passed)
                self.assertIn("pdf_not_marked",result.errors)

    @staticmethod
    def _pdf_with_marked_value(value, *, indirect=False):
        """Serialize a chosen PDF object as the Marked value without coercion."""
        reader=PdfReader(BytesIO(synthetic_tagged_pdf()),strict=True)
        writer=PdfWriter()
        writer.clone_document_from_reader(reader)
        marked=writer._add_object(value) if indirect else value
        writer.root_object["/MarkInfo"][NameObject("/Marked")]=marked
        out=BytesIO()
        writer.write(out)
        return out.getvalue()

    def test_non_boolean_marked_values_fail_closed(self):
        """Truthy strings, numbers, names, containers, and null are not PDF true."""
        invalid=(
            TextStringObject("false"),TextStringObject("true"),NumberObject(1),
            FloatObject(1.0),NameObject("/True"),NullObject(),
            ArrayObject([BooleanObject(True)]),
            DictionaryObject({NameObject("/value"):BooleanObject(True)}),
        )
        for value in invalid:
            with self.subTest(pdf_type=type(value).__name__,value=repr(value)):
                result=validate_pdf_accessibility_structure(
                    pdf_bytes=self._pdf_with_marked_value(value),expected_language="en-US",
                )
                self.assertFalse(result.passed)
                self.assertFalse(result.marked)
                self.assertIn("pdf_not_marked",result.errors)

    def test_indirect_boolean_marked_values_are_resolved(self):
        """An indirect false stays false; an indirect true remains accepted."""
        for expected in (False,True):
            with self.subTest(expected=expected):
                result=validate_pdf_accessibility_structure(
                    pdf_bytes=self._pdf_with_marked_value(BooleanObject(expected),indirect=True),
                    expected_language="en-US",
                )
                self.assertEqual(result.marked,expected)
                self.assertEqual(result.passed,expected)

    @staticmethod
    def _pdf_with_struct_type(value, *, indirect=False):
        """Serialize a selected object as the structure root Type without coercion."""
        reader=PdfReader(BytesIO(synthetic_tagged_pdf()),strict=True)
        writer=PdfWriter()
        writer.clone_document_from_reader(reader)
        value=writer._add_object(value) if indirect else value
        writer.root_object["/StructTreeRoot"][NameObject("/Type")]=value
        out=BytesIO()
        writer.write(out)
        return out.getvalue()

    def test_structure_root_type_requires_pdf_name(self):
        """Text, numbers, null, and containers cannot impersonate the root name."""
        invalid=(
            TextStringObject("/StructTreeRoot"), NameObject("/Other"),
            NumberObject(1), NullObject(), ArrayObject([NameObject("/StructTreeRoot")]),
            DictionaryObject({NameObject("/Type"):NameObject("/StructTreeRoot")}),
        )
        for value in invalid:
            for indirect in (False,True):
                with self.subTest(pdf_type=type(value).__name__,indirect=indirect):
                    result=validate_pdf_accessibility_structure(
                        pdf_bytes=self._pdf_with_struct_type(value,indirect=indirect),
                        expected_language="en-US",
                    )
                    self.assertFalse(result.passed)
                    self.assertFalse(result.struct_tree_root)
                    self.assertIn("pdf_struct_tree_missing",result.errors)

    def test_direct_and_indirect_structure_root_name_are_accepted(self):
        """Reference resolution preserves the required PDF name type."""
        for indirect in (False,True):
            with self.subTest(indirect=indirect):
                result=validate_pdf_accessibility_structure(
                    pdf_bytes=self._pdf_with_struct_type(NameObject("/StructTreeRoot"),indirect=indirect),
                    expected_language="en-US",
                )
                self.assertTrue(result.passed,result.errors)
                self.assertTrue(result.struct_tree_root)

    def test_missing_struct_tree_root_fails_closed(self):
        """A tagged claim requires a document structure tree."""
        result=validate_pdf_accessibility_structure(
            pdf_bytes=synthetic_tagged_pdf(struct_tree=False),expected_language="en-US",
        )
        self.assertFalse(result.passed)
        self.assertIn("pdf_struct_tree_missing",result.errors)

    def test_public_adapter_emits_catalog_language_from_localized_ir(self):
        """The adapter entrypoint propagates the localized IR language into PDF /Lang."""
        from reporting.adapters import build_html_css_and_pdf_adapter
        presentation={
            "report_id":"synthetic-accessibility-report",
            "locale_id":"en-US",
            "components":[{
                "component_id":"summary",
                "component_type":"semantic-section",
                "title":"Summary",
                "state":"PRESENT",
                "content":{"text":"Synthetic"},
            }],
        }
        adapter=build_html_css_and_pdf_adapter(presentation_ir=presentation)
        self.assertTrue(adapter.passed,adapter.errors)
        self.assertIn('<html lang="en-US">',adapter.html)
        result=validate_pdf_accessibility_structure(
            pdf_bytes=adapter.pdf_bytes,expected_language="en-US",
        )
        self.assertTrue(result.passed,result.errors)
        self.assertEqual(result.language,"en-US")

    def test_public_adapter_rejects_unlocalized_ir_for_pdf_ua(self):
        """PDF/UA rendering requires an explicit locale from the localization stage."""
        from reporting.adapters import build_html_css_and_pdf_adapter
        presentation={
            "report_id":"synthetic-accessibility-report",
            "components":[{
                "component_id":"summary",
                "component_type":"semantic-section",
                "title":"Summary",
                "state":"PRESENT",
                "content":{"text":"Synthetic"},
            }],
        }
        adapter=build_html_css_and_pdf_adapter(presentation_ir=presentation)
        self.assertFalse(adapter.passed)
        self.assertIn("presentation_ir_invalid",adapter.errors)

    def test_adapter_rejects_malformed_and_inactive_locales(self):
        """Only an explicitly enabled report locale may reach PDF rendering."""
        from reporting.adapters import build_html_css_and_pdf_adapter
        invalid=(None,"","   ","not a language","pt-BR","en-US-extra", " en-US ","en_US",123,True,[],{})
        for locale in invalid:
            with self.subTest(locale=repr(locale)):
                presentation={
                    "report_id":"synthetic-accessibility-report",
                    "locale_id":locale,
                    "components":[{
                        "component_id":"summary","component_type":"semantic-section",
                        "title":"Summary","state":"PRESENT","content":{"text":"Synthetic"},
                    }],
                }
                result=build_html_css_and_pdf_adapter(presentation_ir=presentation)
                self.assertFalse(result.passed)
                self.assertIn("presentation_ir_invalid",result.errors)
                self.assertIsNone(result.pdf_bytes)

    def test_accessibility_rejects_malformed_and_inactive_expected_locales(self):
        """Matching invalid language text cannot establish a bounded locale pass."""
        invalid=("","   ","not a language","pt-BR","en-US-extra"," en-US ","en_US",None,123,True,[],{})
        for locale in invalid:
            with self.subTest(locale=repr(locale)):
                pdf_language=locale if isinstance(locale,str) else "en-US"
                result=validate_pdf_accessibility_structure(
                    pdf_bytes=synthetic_tagged_pdf(language=pdf_language),
                    expected_language=locale,
                )
                self.assertFalse(result.passed)
                self.assertIn("pdf_accessibility_language_mismatch",result.errors)

    def test_indirect_catalog_language_is_resolved(self):
        """An indirect /Lang text string is resolved before language comparison."""
        result=validate_pdf_accessibility_structure(
            pdf_bytes=synthetic_tagged_pdf(language="en-US",indirect_language=True),
            expected_language="en-US",
        )
        self.assertTrue(result.passed,result.errors)
        self.assertEqual(result.language,"en-US")

    def test_catalog_language_must_match(self):
        """Structural accessibility uses the catalog language."""
        result=validate_pdf_accessibility_structure(
            pdf_bytes=synthetic_tagged_pdf(language="pt-BR"),expected_language="en-US",
        )
        self.assertFalse(result.passed)
        self.assertIn("pdf_accessibility_language_mismatch",result.errors)

    def test_malformed_or_encrypted_pdf_fails_closed(self):
        """Malformed and encrypted PDFs never receive an accessibility pass."""
        malformed=validate_pdf_accessibility_structure(
            pdf_bytes=b"%PDF-1.7\nbroken",expected_language="en-US",
        )
        self.assertFalse(malformed.passed)
        self.assertIn("pdf_accessibility_structure_invalid",malformed.errors)

        writer=PdfWriter(); writer.add_blank_page(width=612,height=792); writer.encrypt("synthetic")
        out=BytesIO(); writer.write(out)
        encrypted=validate_pdf_accessibility_structure(
            pdf_bytes=out.getvalue(),expected_language="en-US",
        )
        self.assertFalse(encrypted.passed)
        self.assertIn("encrypted_pdf_forbidden",encrypted.errors)


if __name__=="__main__":
    unittest.main()
