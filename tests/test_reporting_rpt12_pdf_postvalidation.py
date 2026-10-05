from __future__ import annotations
import ast
import hashlib
from pathlib import Path
from io import BytesIO
import unittest

from reporting.pdf_qa import validate_pdf_candidate


def make_pdf(*, metadata=None, language=None, encrypted=False, xmp=None):
    """Create a synthetic PDF with independent Info and catalog language entries."""
    from pypdf import PdfWriter
    from pypdf.generic import NameObject, TextStringObject
    out=BytesIO()
    writer=PdfWriter()
    writer.add_blank_page(width=612,height=792)
    if metadata:
        writer.add_metadata(metadata)
    if language is not None:
        writer.root_object[NameObject("/Lang")]=TextStringObject(language)
    if xmp is not None:
        writer.xmp_metadata=xmp
        writer.root_object["/Metadata"].update({
            NameObject("/Type"):NameObject("/Metadata"),
            NameObject("/Subtype"):NameObject("/XML"),
        })
    if encrypted:
        writer.encrypt("synthetic-password")
    writer.write(out)
    return out.getvalue()


def make_xmp(fragment):
    """Wrap synthetic custom XML values in a valid document-level XMP packet."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<x:xmpmeta xmlns:x="adobe:ns:meta/">'
        '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        '<rdf:Description rdf:about="" xmlns:custom="urn:omnigenis:synthetic:xmp">'
        + fragment + '</rdf:Description></rdf:RDF></x:xmpmeta>'
    ).encode("utf-8")


class Rpt12PdfPostValidationTests(unittest.TestCase):
    def test_valid_candidate_passes_integrity_structure_and_metadata_prerequisites(self):
        """Accept valid bytes, matching digest and author, and the catalog language."""
        pdf=make_pdf(metadata={"/Title":"Synthetic OmniGenis report","/Author":"Hudson Silva Andrade"},language="en-US")
        digest=hashlib.sha256(pdf).hexdigest()
        result=validate_pdf_candidate(
            pdf_bytes=pdf,expected_pdf_sha256=digest,
            expected_author="Hudson Silva Andrade",expected_language="en-US",
        )
        self.assertTrue(result.passed,result.errors)
        self.assertEqual(result.pdf_sha256,digest)
        self.assertEqual(result.page_count,1)
        self.assertEqual(result.metadata["/Author"],"Hudson Silva Andrade")
        self.assertEqual(result.accessibility_prerequisites,"PASS")

    def test_digest_mismatch_fails_closed(self):
        """Reject candidate bytes whose digest differs from the declared digest."""
        pdf=make_pdf(metadata={"/Author":"Hudson Silva Andrade"},language="en-US")
        result=validate_pdf_candidate(
            pdf_bytes=pdf,expected_pdf_sha256="0"*64,
            expected_author="Hudson Silva Andrade",expected_language="en-US",
        )
        self.assertFalse(result.passed)
        self.assertIn("pdf_digest_mismatch",result.errors)

    def test_encrypted_pdf_fails_closed(self):
        """Reject encrypted candidates before metadata or page validation."""
        pdf=make_pdf(encrypted=True)
        result=validate_pdf_candidate(
            pdf_bytes=pdf,expected_pdf_sha256=hashlib.sha256(pdf).hexdigest(),
            expected_author="Hudson Silva Andrade",expected_language="en-US",
        )
        self.assertFalse(result.passed)
        self.assertIn("encrypted_pdf_forbidden",result.errors)

    def test_missing_or_wrong_required_metadata_fails_closed(self):
        """Reject a mismatched author and catalog language independently."""
        pdf=make_pdf(metadata={"/Author":"Unexpected"},language="pt-BR")
        result=validate_pdf_candidate(
            pdf_bytes=pdf,expected_pdf_sha256=hashlib.sha256(pdf).hexdigest(),
            expected_author="Hudson Silva Andrade",expected_language="en-US",
        )
        self.assertFalse(result.passed)
        self.assertIn("pdf_author_mismatch",result.errors)
        self.assertIn("pdf_language_mismatch",result.errors)

    def test_sensitive_metadata_is_rejected(self):
        """Reject local paths or credential-like values in the Info dictionary."""
        pdf=make_pdf(metadata={
            "/Author":"Hudson Silva Andrade",
            "/Subject":"generated at /srv/private/worktree with token=secret",
        },language="en-US")
        result=validate_pdf_candidate(
            pdf_bytes=pdf,expected_pdf_sha256=hashlib.sha256(pdf).hexdigest(),
            expected_author="Hudson Silva Andrade",expected_language="en-US",
        )
        self.assertFalse(result.passed)
        self.assertIn("pdf_metadata_sensitive",result.errors)

    def test_info_only_language_does_not_satisfy_catalog_requirement(self):
        """An Info dictionary language cannot replace the document catalog language."""
        pdf=make_pdf(metadata={"/Author":"Hudson Silva Andrade","/Lang":"en-US"})
        result=validate_pdf_candidate(
            pdf_bytes=pdf,expected_pdf_sha256=hashlib.sha256(pdf).hexdigest(),
            expected_author="Hudson Silva Andrade",expected_language="en-US",
        )
        self.assertFalse(result.passed)
        self.assertIn("pdf_language_mismatch",result.errors)
        self.assertEqual(result.accessibility_prerequisites,"BLOCKED")

    def test_catalog_language_is_authoritative_over_info_language(self):
        """A contradictory Info value never overrides the catalog's language."""
        for catalog,info,accepted in (("en-US","pt-BR",True),("pt-BR","en-US",False)):
            with self.subTest(catalog=catalog,info=info):
                pdf=make_pdf(metadata={"/Author":"Hudson Silva Andrade","/Lang":info},language=catalog)
                result=validate_pdf_candidate(
                    pdf_bytes=pdf,expected_pdf_sha256=hashlib.sha256(pdf).hexdigest(),
                    expected_author="Hudson Silva Andrade",expected_language="en-US",
                )
                self.assertEqual(result.passed,accepted,result.errors)

    def test_benign_document_xmp_is_accepted_without_retaining_its_values(self):
        """Inspect benign XMP without copying its custom contents into the result."""
        pdf=make_pdf(
            metadata={"/Author":"Hudson Silva Andrade"},language="en-US",
            xmp=make_xmp('<custom:description>Synthetic XMP fixture</custom:description>'),
        )
        result=validate_pdf_candidate(
            pdf_bytes=pdf,expected_pdf_sha256=hashlib.sha256(pdf).hexdigest(),
            expected_author="Hudson Silva Andrade",expected_language="en-US",
        )
        self.assertTrue(result.passed,result.errors)
        self.assertNotIn("Synthetic XMP fixture",str(result.to_dict()))

    def test_sensitive_values_in_document_xmp_are_rejected(self):
        """Scan XMP text, escaped text, CDATA, custom attributes, and comments."""
        fragments=(
            '<custom:value>token=synthetic</custom:value>',
            '<custom:token>synthetic</custom:token>',
            '<custom:value>&#116;oken&#61;synthetic</custom:value>',
            '<custom:value>to<![CDATA[ken=synthetic]]></custom:value>',
            '<custom:value>/home/synthetic/work</custom:value>',
            '<custom:value>&#47;home&#47;synthetic&#47;work</custom:value>',
            '<custom:value custom:path="/home/synthetic/work" />',
            '<custom:value custom:token="synthetic" />',
            '<!-- token=synthetic -->',
        )
        for fragment in fragments:
            with self.subTest(fragment=fragment):
                pdf=make_pdf(
                    metadata={"/Author":"Hudson Silva Andrade"},language="en-US",
                    xmp=make_xmp(fragment),
                )
                result=validate_pdf_candidate(
                    pdf_bytes=pdf,expected_pdf_sha256=hashlib.sha256(pdf).hexdigest(),
                    expected_author="Hudson Silva Andrade",expected_language="en-US",
                )
                self.assertFalse(result.passed)
                self.assertIn("pdf_metadata_sensitive",result.errors)

    def test_unreadable_or_unsafe_document_xmp_fails_closed(self):
        """Malformed, RDF-less, or DTD-bearing XMP cannot receive acceptance."""
        packets=(
            b"not XML",
            b"<xmp>Missing RDF root</xmp>",
            b'<!DOCTYPE x [<!ENTITY fixture "synthetic">]>'
            + make_xmp('<custom:value>&fixture;</custom:value>').split(b'?>',1)[1],
        )
        for packet in packets:
            with self.subTest(packet=packet):
                pdf=make_pdf(
                    metadata={"/Author":"Hudson Silva Andrade"},language="en-US",xmp=packet,
                )
                result=validate_pdf_candidate(
                    pdf_bytes=pdf,expected_pdf_sha256=hashlib.sha256(pdf).hexdigest(),
                    expected_author="Hudson Silva Andrade",expected_language="en-US",
                )
                self.assertFalse(result.passed)
                self.assertIn("pdf_xmp_invalid",result.errors)

    def test_reviewed_functions_have_docstrings(self):
        """Every function in the candidate validator and its tests has a docstring."""
        root=Path(__file__).resolve().parents[1]
        missing=[]
        for relative in ("reporting/pdf_qa.py","tests/test_reporting_rpt12_pdf_postvalidation.py"):
            tree=ast.parse((root/relative).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and not ast.get_docstring(node):
                    missing.append(f"{relative}:{node.name}")
        self.assertEqual(missing,[])

    def test_malformed_pdf_fails_closed(self):
        """Block malformed candidate bytes without leaking parser exceptions."""
        pdf=b"%PDF-1.7\nbroken"
        result=validate_pdf_candidate(
            pdf_bytes=pdf,expected_pdf_sha256=hashlib.sha256(pdf).hexdigest(),
            expected_author="Hudson Silva Andrade",expected_language="en-US",
        )
        self.assertFalse(result.passed)
        self.assertIn("pdf_structure_invalid",result.errors)

if __name__=="__main__":
    unittest.main()
