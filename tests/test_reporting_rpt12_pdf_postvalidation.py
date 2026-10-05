from __future__ import annotations
import hashlib
from io import BytesIO
import unittest

from reporting.pdf_qa import validate_pdf_candidate


def make_pdf(*, metadata=None, encrypted=False):
    from pypdf import PdfWriter
    out=BytesIO()
    writer=PdfWriter()
    writer.add_blank_page(width=612,height=792)
    if metadata:
        writer.add_metadata(metadata)
    if encrypted:
        writer.encrypt("synthetic-password")
    writer.write(out)
    return out.getvalue()


class Rpt12PdfPostValidationTests(unittest.TestCase):
    def test_valid_candidate_passes_integrity_structure_and_metadata_prerequisites(self):
        pdf=make_pdf(metadata={"/Title":"Synthetic OmniGenis report","/Author":"Hudson Silva Andrade","/Lang":"en-US"})
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
        pdf=make_pdf(metadata={"/Author":"Hudson Silva Andrade","/Lang":"en-US"})
        result=validate_pdf_candidate(
            pdf_bytes=pdf,expected_pdf_sha256="0"*64,
            expected_author="Hudson Silva Andrade",expected_language="en-US",
        )
        self.assertFalse(result.passed)
        self.assertIn("pdf_digest_mismatch",result.errors)

    def test_encrypted_pdf_fails_closed(self):
        pdf=make_pdf(encrypted=True)
        result=validate_pdf_candidate(
            pdf_bytes=pdf,expected_pdf_sha256=hashlib.sha256(pdf).hexdigest(),
            expected_author="Hudson Silva Andrade",expected_language="en-US",
        )
        self.assertFalse(result.passed)
        self.assertIn("encrypted_pdf_forbidden",result.errors)

    def test_missing_or_wrong_required_metadata_fails_closed(self):
        pdf=make_pdf(metadata={"/Author":"Unexpected","/Lang":"pt-BR"})
        result=validate_pdf_candidate(
            pdf_bytes=pdf,expected_pdf_sha256=hashlib.sha256(pdf).hexdigest(),
            expected_author="Hudson Silva Andrade",expected_language="en-US",
        )
        self.assertFalse(result.passed)
        self.assertIn("pdf_author_mismatch",result.errors)
        self.assertIn("pdf_language_mismatch",result.errors)

    def test_sensitive_metadata_is_rejected(self):
        pdf=make_pdf(metadata={
            "/Author":"Hudson Silva Andrade","/Lang":"en-US",
            "/Subject":"generated at /srv/private/worktree with token=secret",
        })
        result=validate_pdf_candidate(
            pdf_bytes=pdf,expected_pdf_sha256=hashlib.sha256(pdf).hexdigest(),
            expected_author="Hudson Silva Andrade",expected_language="en-US",
        )
        self.assertFalse(result.passed)
        self.assertIn("pdf_metadata_sensitive",result.errors)

    def test_malformed_pdf_fails_closed(self):
        pdf=b"%PDF-1.7\nbroken"
        result=validate_pdf_candidate(
            pdf_bytes=pdf,expected_pdf_sha256=hashlib.sha256(pdf).hexdigest(),
            expected_author="Hudson Silva Andrade",expected_language="en-US",
        )
        self.assertFalse(result.passed)
        self.assertIn("pdf_structure_invalid",result.errors)

if __name__=="__main__":
    unittest.main()
