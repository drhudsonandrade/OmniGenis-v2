from __future__ import annotations
import hashlib
from io import BytesIO
import unittest

from pypdf import PdfReader, PdfWriter
from pypdf.generic import BooleanObject, DictionaryObject, NameObject, TextStringObject

from reporting.adapters import _render_pdf
from reporting.pdf_accessibility import validate_pdf_accessibility_structure


def synthetic_tagged_pdf(*, language="en-US", marked=True, struct_tree=True, mark_info=True):
    """Create a minimal synthetic PDF carrying selected accessibility markers."""
    writer=PdfWriter()
    writer.add_blank_page(width=612,height=792)
    if language is not None:
        writer.root_object[NameObject("/Lang")]=TextStringObject(language)
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

    def test_missing_struct_tree_root_fails_closed(self):
        """A tagged claim requires a document structure tree."""
        result=validate_pdf_accessibility_structure(
            pdf_bytes=synthetic_tagged_pdf(struct_tree=False),expected_language="en-US",
        )
        self.assertFalse(result.passed)
        self.assertIn("pdf_struct_tree_missing",result.errors)

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
