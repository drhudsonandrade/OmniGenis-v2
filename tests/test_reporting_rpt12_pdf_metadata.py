"""Controlled metadata and privacy regressions for generated PDF candidates."""

from __future__ import annotations

import hashlib
from io import BytesIO
import json
import tracemalloc
import unittest
import zlib
from unittest.mock import patch

from reporting.adapters import build_html_css_and_pdf_adapter
from reporting.pdf_qa import validate_pdf_candidate

AUTHOR = "Hudson Silva Andrade"
PRODUCT = "OmniGenis"
PROFILE = "omnigenis-generated-pdf-metadata-v1"


def presentation():
    """Return a minimal supported synthetic presentation."""
    return {
        "report_id": "SYNTHETIC-PRIVATE-REPORT-ID",
        "locale_id": "en-US",
        "components": [{
            "component_type": "semantic-section",
            "component_id": "summary",
            "title": "Synthetic summary",
            "state": "PRESENT",
            "content": {"text": "Synthetic metadata regression content."},
        }],
    }


def info_pdf(**entries):
    """Create a synthetic Info-only candidate for the generic validator."""
    from pypdf import PdfWriter
    from pypdf.generic import NameObject, TextStringObject

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    writer.add_metadata({"/Author": AUTHOR, **entries})
    writer.root_object[NameObject("/Lang")] = TextStringObject("en-US")
    output = BytesIO()
    writer.write(output)
    return output.getvalue()


def validate(pdf, **overrides):
    """Validate a candidate against its exact digest and approved identities."""
    values = {
        "pdf_bytes": pdf,
        "expected_pdf_sha256": hashlib.sha256(pdf).hexdigest(),
        "expected_author": AUTHOR,
        "expected_language": "en-US",
    }
    values.update(overrides)
    return validate_pdf_candidate(**values)


class PdfMetadataRegressions(unittest.TestCase):
    """Exercise defects in real generated output and returned evidence."""

    def test_generated_pdf_carries_approved_metadata(self):
        """Native generation must emit fixed author and product identities."""
        from pypdf import PdfReader

        result = build_html_css_and_pdf_adapter(presentation_ir=presentation())
        self.assertTrue(result.passed, result.errors)
        reader = PdfReader(BytesIO(result.pdf_bytes), strict=True)
        self.assertEqual(reader.metadata.get("/Author"), AUTHOR)
        self.assertEqual(reader.metadata.get("/Title"), PRODUCT)
        self.assertEqual(reader.metadata.get("/Creator"), PRODUCT)
        self.assertEqual(reader.metadata.get("/Producer"), "WeasyPrint 70.0")

    def test_blocked_evidence_retains_no_sensitive_info(self):
        """Neither the result object nor its JSON may retain rejected values."""
        marker = "SYNTHETIC-REDACTION-MARKER"
        result = validate(info_pdf(**{"/Subject": "token=" + marker}))
        self.assertFalse(result.passed)
        self.assertIn("pdf_metadata_sensitive", result.errors)
        self.assertEqual(dict(result.metadata), {})
        self.assertNotIn(marker, repr(result))
        self.assertNotIn(marker, json.dumps(result.to_dict()))

    def test_success_evidence_retains_no_arbitrary_info(self):
        """Passing generic hygiene must not copy arbitrary title metadata."""
        marker = "SYNTHETIC-PRIVATE-TITLE"
        result = validate(info_pdf(**{"/Title": marker}))
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(result.metadata["/Author"], AUTHOR)
        self.assertNotIn(marker, repr(result))
        self.assertNotIn(marker, json.dumps(result.to_dict()))

    def test_digest_errors_stop_before_pdf_parsing(self):
        """Invalid or mismatched identity must not invoke the PDF parser."""
        pdf = info_pdf()
        for digest in ("0" * 64, "invalid", None):
            with self.subTest(digest=digest):
                with patch("pypdf.PdfReader") as parser:
                    result = validate(pdf, expected_pdf_sha256=digest)
                    parser.assert_not_called()
                self.assertFalse(result.passed)
                self.assertEqual(dict(result.metadata), {})
                self.assertIsNone(result.page_count)

    def test_metadata_failure_keeps_prerequisites_blocked(self):
        """Sensitive metadata cannot leave a passing prerequisite status."""
        result = validate(info_pdf(**{"/Subject": "token=SYNTHETIC-BLOCK"}))
        self.assertFalse(result.passed)
        self.assertEqual(result.accessibility_prerequisites, "BLOCKED")



def rewrite_candidate(pdf, *, updates=None, remove=(), xmp=None, language=None,
                      remove_xmp=False, stream_field=None):
    """Alter selected metadata surfaces without rebuilding visible report content."""
    from pypdf import PdfWriter
    from pypdf.generic import NameObject, TextStringObject

    writer = PdfWriter(clone_from=BytesIO(pdf))
    writer.pdf_header = pdf.splitlines()[0]
    metadata = dict(writer.metadata)
    metadata.update(updates or {})
    for key in remove:
        metadata.pop(key, None)
    writer.metadata = metadata
    if language is not None:
        writer.root_object[NameObject("/Lang")] = TextStringObject(language)
    if remove_xmp:
        del writer.root_object[NameObject("/Metadata")]
    elif xmp is not None:
        writer.xmp_metadata = xmp
        writer.root_object["/Metadata"].update({
            NameObject("/Type"): NameObject("/Metadata"),
            NameObject("/Subtype"): NameObject("/XML"),
        })
    if stream_field is not None:
        writer.root_object["/Metadata"][NameObject("/Unexpected")] = TextStringObject(stream_field)
    output = BytesIO()
    writer.write(output)
    return output.getvalue()


def raw_xmp_candidate(pdf, raw, *, filter_value=None, indirect_filter=False,
                      decode_params=False):
    """Install an exact encoded stream without asking the PDF writer to decode it."""
    from pypdf import PdfWriter
    from pypdf.generic import DictionaryObject, NameObject, StreamObject

    writer = PdfWriter(clone_from=BytesIO(pdf))
    writer.pdf_header = pdf.splitlines()[0]
    stream = StreamObject()
    stream.set_data(raw)
    stream.update({
        NameObject("/Type"): NameObject("/Metadata"),
        NameObject("/Subtype"): NameObject("/XML"),
    })
    if filter_value is not None:
        value = NameObject(filter_value) if isinstance(filter_value, str) else filter_value
        stream[NameObject("/Filter")] = writer._add_object(value) if indirect_filter else value
    if decode_params:
        stream[NameObject("/DecodeParms")] = DictionaryObject()
    writer.root_object[NameObject("/Metadata")] = writer._add_object(stream)
    output = BytesIO()
    writer.write(output)
    return output.getvalue()


class GeneratedPdfMetadataProfileTests(unittest.TestCase):
    """Validate the actual pinned renderer output and independent metadata mutations."""

    @classmethod
    def setUpClass(cls):
        """Render one real controlled candidate shared by the mutation fixtures."""
        from pypdf import PdfReader

        cls.rendered = build_html_css_and_pdf_adapter(presentation_ir=presentation())
        if not cls.rendered.passed:
            raise AssertionError(cls.rendered.errors)
        cls.pdf = cls.rendered.pdf_bytes
        cls.reader = PdfReader(BytesIO(cls.pdf), strict=True)
        cls.xmp = cls.reader.root_object["/Metadata"].get_data().decode("utf-8")

    def strict(self, pdf, **overrides):
        """Apply the declared generated-document profile to exact candidate bytes."""
        return validate(pdf, metadata_profile=PROFILE, **overrides)

    def assertBlocked(self, pdf):
        """Check blocking and content-free rejection evidence."""
        result = self.strict(pdf)
        self.assertFalse(result.passed)
        self.assertEqual(dict(result.metadata), {})
        self.assertEqual(result.accessibility_prerequisites, "BLOCKED")
        self.assertEqual(result.to_dict()["release_authorization"], "NOT_ESTABLISHED")
        return result

    def appended(self, fragment):
        """Add one RDF description or node while preserving the native namespace scope."""
        return self.xmp.replace("</rdf:RDF>", fragment + "</rdf:RDF>").encode("utf-8")

    def test_real_and_equivalent_candidates_pass_exact_profile(self):
        """Actual output and equivalent metadata encoding preserve the same contract."""
        candidates = (
            self.pdf,
            rewrite_candidate(self.pdf),
            rewrite_candidate(self.pdf, xmp=self.xmp.encode("utf-8")),
        )
        for pdf in candidates:
            with self.subTest(digest=hashlib.sha256(pdf).hexdigest()):
                result = self.strict(pdf)
                self.assertTrue(result.passed, result.errors)
                self.assertEqual(result.pdf_sha256, hashlib.sha256(pdf).hexdigest())
                self.assertEqual(result.to_dict()["metadata_profile_id"], PROFILE)
                self.assertEqual(dict(result.metadata), {
                    "/Author": AUTHOR, "/Title": PRODUCT,
                    "/Creator": PRODUCT, "/Producer": "WeasyPrint 70.0",
                })

    def test_native_xmp_and_catalog_preserve_truthful_identity(self):
        """Native XMP agrees with Info; the activated locale stays in the catalog."""
        xmp = self.reader.xmp_metadata
        self.assertEqual(xmp.dc_creator, [AUTHOR])
        self.assertEqual(xmp.dc_title, {"x-default": PRODUCT})
        self.assertEqual(xmp.xmp_creator_tool, PRODUCT)
        self.assertEqual(xmp.pdf_producer, "WeasyPrint 70.0")
        self.assertEqual(xmp.dc_language, [])
        self.assertEqual(self.reader.root_object["/Lang"], "en-US")
        self.assertNotIn(presentation()["report_id"], self.xmp)
        self.assertNotIn(presentation()["report_id"], str(dict(self.reader.metadata)))
        self.assertEqual(self.rendered.conformance["pdf_metadata_status"], "PASS")
        self.assertEqual(self.rendered.conformance["pdf_metadata_profile"], PROFILE)
        self.assertEqual(self.rendered.conformance["release_authorization"], "NOT_ESTABLISHED")

    def test_required_info_fields_cannot_be_missing(self):
        """Each of the four Info fields is required by the generated profile."""
        for key in ("/Author", "/Title", "/Creator", "/Producer"):
            with self.subTest(key=key):
                self.assertBlocked(rewrite_candidate(self.pdf, remove=(key,)))

    def test_each_info_identity_is_checked(self):
        """A changed author, product, application or producer independently blocks."""
        for key in ("/Author", "/Title", "/Creator", "/Producer"):
            with self.subTest(key=key):
                self.assertBlocked(rewrite_candidate(self.pdf, updates={key: "Unexpected identity"}))

    def test_unknown_info_fields_are_outside_the_profile(self):
        """Benign custom metadata and redundant Info language are not admitted."""
        for key, value in (("/Subject", "Synthetic subject"), ("/Custom", "Synthetic custom"),
                           ("/Lang", "en-US")):
            with self.subTest(key=key):
                self.assertBlocked(rewrite_candidate(self.pdf, updates={key: value}))

    def test_info_metadata_names_are_included_in_hygiene(self):
        """Sensitive metadata keys cannot evade hygiene by using a plain value."""
        result = validate(info_pdf(**{"/token": "SYNTHETIC-PRIVATE-KEY-MARKER"}))
        self.assertFalse(result.passed)
        self.assertIn("pdf_metadata_sensitive", result.errors)
        self.assertEqual(dict(result.metadata), {})
        self.assertNotIn("SYNTHETIC-PRIVATE-KEY-MARKER", repr(result))

    def test_document_xmp_is_required_for_generated_profile(self):
        """Info alone cannot satisfy the explicitly selected generated profile."""
        self.assertBlocked(rewrite_candidate(self.pdf, remove_xmp=True))
        self.assertBlocked(info_pdf())

    def test_each_xmp_identity_is_checked(self):
        """A changed XMP property cannot be hidden behind correct Info values."""
        replacements = (
            ('pdfuaid:part="1"', 'pdfuaid:part="2"'),
            ('pdf:Producer="WeasyPrint 70.0"', 'pdf:Producer="WeasyPrint 69.0"'),
            ('>OmniGenis</rdf:li>', '>Unexpected</rdf:li>'),
            ('>Hudson Silva Andrade</rdf:li>', '>Unexpected</rdf:li>'),
            ('<xmp:CreatorTool>OmniGenis', '<xmp:CreatorTool>Unexpected'),
        )
        for old, new in replacements:
            with self.subTest(old=old):
                self.assertIn(old, self.xmp)
                self.assertBlocked(rewrite_candidate(self.pdf, xmp=self.xmp.replace(old, new).encode()))

    def test_duplicate_properties_and_subjects_are_rejected(self):
        """Duplicates and nonempty subjects cannot bypass normalized property getters."""
        fragments = (
            '<rdf:Description rdf:about="" pdf:Producer="WeasyPrint 70.0"/>',
            '<rdf:Description rdf:about="" pdf:Producer="Unexpected"/>',
            '<rdf:Description rdf:about=""><xmp:CreatorTool>OmniGenis</xmp:CreatorTool></rdf:Description>',
            '<rdf:Description rdf:about="urn:synthetic:other" pdf:Producer="Unexpected"/>',
            '<rdf:Description rdf:about=""><pdf:Producer>Unexpected</pdf:Producer></rdf:Description>',
            '<rdf:Description rdf:about="" xmp:CreatorTool="Unexpected"/>',
        )
        for fragment in fragments:
            with self.subTest(fragment=fragment):
                self.assertBlocked(rewrite_candidate(self.pdf, xmp=self.appended(fragment)))

    def test_repeated_title_and_author_items_are_rejected(self):
        """Language alternatives and creator lists cannot conceal additional values."""
        mutations = (
            self.xmp.replace(
                '<rdf:li xml:lang="x-default">OmniGenis</rdf:li>',
                '<rdf:li xml:lang="x-default">Unexpected</rdf:li>'
                '<rdf:li xml:lang="x-default">OmniGenis</rdf:li>',
            ),
            self.xmp.replace(
                '<rdf:li xml:lang="x-default">OmniGenis</rdf:li>',
                '<rdf:li xml:lang="en-US">OmniGenis</rdf:li>',
            ),
            self.xmp.replace(
                '<rdf:li>Hudson Silva Andrade</rdf:li>',
                '<rdf:li>Hudson Silva Andrade</rdf:li><rdf:li>Unexpected</rdf:li>',
            ),
        )
        for packet in mutations:
            with self.subTest(packet=packet):
                self.assertBlocked(rewrite_candidate(self.pdf, xmp=packet.encode()))

    def test_additional_rdf_roots_and_wrong_namespaces_are_rejected(self):
        """The complete XMP document is checked, not only the parser's first RDF root."""
        second_rdf = (
            '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" '
            'xmlns:pdf="http://ns.adobe.com/pdf/1.3/">'
            '<rdf:Description rdf:about="" pdf:Producer="Unexpected"/></rdf:RDF>'
        )
        mutations = (
            self.xmp.replace("</x:xmpmeta>", second_rdf + "</x:xmpmeta>"),
            self.xmp.replace("http://purl.org/dc/elements/1.1/", "urn:synthetic:wrong-dc"),
        )
        for packet in mutations:
            with self.subTest(packet=packet):
                self.assertBlocked(rewrite_candidate(self.pdf, xmp=packet.encode()))

    def test_unexpected_xml_data_never_enters_evidence(self):
        """Unknown XML properties, attributes, comments and instructions all block."""
        marker = "SYNTHETIC-PRIVATE-XMP-MARKER"
        packets = (
            self.appended('<rdf:Description rdf:about=""><xmp:Unexpected>' + marker
                          + '</xmp:Unexpected></rdf:Description>'),
            self.appended('<rdf:Description rdf:about="" xmp:Unexpected="' + marker + '"/>'),
            self.appended("<!-- " + marker + " -->"),
            self.xmp.replace("</x:xmpmeta>", "<?unexpected " + marker + "?></x:xmpmeta>").encode(),
            self.xmp.replace('xml:lang="x-default"', 'xml:lang="x-default" extra="' + marker + '"').encode(),
        )
        for packet in packets:
            with self.subTest(packet=packet):
                result = self.assertBlocked(rewrite_candidate(self.pdf, xmp=packet))
                self.assertNotIn(marker, repr(result))
                self.assertNotIn(marker, json.dumps(result.to_dict()))

    def test_xpacket_positions_match_the_native_wrapper(self):
        """Opening and closing packet instructions must enclose the XMP root."""
        opening = '<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>'
        closing = '<?xpacket end="r"?>'
        root = self.xmp.replace(opening, "").replace(closing, "")
        packets = (
            opening + "\n" + closing + "\n" + root,
            root + "\n" + opening + "\n" + closing,
        )
        for packet in packets:
            with self.subTest(packet=packet):
                self.assertBlocked(rewrite_candidate(self.pdf, xmp=packet.encode()))

    def test_metadata_stream_dictionary_is_bounded(self):
        """Unexpected fields in the document metadata stream also block."""
        marker = "SYNTHETIC-STREAM-MARKER"
        result = self.assertBlocked(rewrite_candidate(self.pdf, stream_field=marker))
        self.assertNotIn(marker, repr(result))

    def test_unsafe_or_malformed_xmp_is_blocked(self):
        """Malformed XML and entity-bearing packets cannot satisfy the profile."""
        packets = (
            b"not XML",
            b'<!DOCTYPE x [<!ENTITY marker "synthetic">]>' + self.xmp.encode(),
        )
        for packet in packets:
            with self.subTest(packet=packet):
                self.assertBlocked(rewrite_candidate(self.pdf, xmp=packet))

    def test_metadata_budgets_fail_closed(self):
        """Bound candidate bytes, decoded XMP bytes, and XML node/depth counts."""
        large_pdf = b"%PDF-1.7\n" + b" " * (8 * 1024 * 1024)
        with patch("pypdf.PdfReader") as parser:
            result = self.strict(large_pdf)
            parser.assert_not_called()
        self.assertIn("pdf_metadata_budget_exceeded", result.errors)
        packets = (
            self.xmp.replace("</x:xmpmeta>", " " * (64 * 1024) + "</x:xmpmeta>"),
            self.xmp.replace("</rdf:RDF>", '<rdf:Description rdf:about=""/>' * 128 + "</rdf:RDF>"),
            self.xmp.replace(
                "<xmp:CreatorTool>OmniGenis</xmp:CreatorTool>",
                "<xmp:CreatorTool>" + "<xmp:Nested>" * 9 + PRODUCT
                + "</xmp:Nested>" * 9 + "</xmp:CreatorTool>",
            ),
        )
        for packet in packets:
            with self.subTest(length=len(packet)):
                result = self.assertBlocked(rewrite_candidate(self.pdf, xmp=packet.encode()))
                self.assertIn("pdf_metadata_budget_exceeded", result.errors)

    def test_profile_and_identity_inputs_are_not_inferred(self):
        """Unknown profiles, inactive locales and other authors fail before parsing."""
        cases = (
            {"metadata_profile": "unknown"},
            {"metadata_profile": []},
            {"metadata_profile": {}},
            {"expected_author": "Unexpected"},
            {"expected_author": None},
            *({"expected_language": language} for language in ("pt-BR", "en", "en-us", "", None, [], 1)),
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                values = {"metadata_profile": PROFILE, **overrides}
                with patch("pypdf.PdfReader") as parser:
                    result = validate(self.pdf, **values)
                    parser.assert_not_called()
                self.assertFalse(result.passed)
                self.assertEqual(dict(result.metadata), {})

    def test_catalog_language_must_match_activated_profile(self):
        """Correct Info and XMP do not override a mismatched document language."""
        result = self.assertBlocked(rewrite_candidate(self.pdf, language="pt-BR"))
        self.assertIn("pdf_language_mismatch", result.errors)

    def test_adapter_withholds_a_candidate_that_fails_metadata(self):
        """Renderer output is checked before bytes and conformance are exposed."""
        marker = "SYNTHETIC-ADAPTER-REJECTION-MARKER"
        tampered = rewrite_candidate(self.pdf, updates={"/Subject": "token=" + marker})
        with patch("reporting.adapters._render_pdf", return_value=tampered):
            result = build_html_css_and_pdf_adapter(presentation_ir=presentation())
        self.assertFalse(result.passed)
        self.assertEqual(result.errors, ("pdf_metadata_invalid",))
        self.assertIsNone(result.pdf_bytes)
        self.assertIsNone(result.pdf_sha256)
        self.assertIsNone(result.conformance)
        self.assertNotIn(marker, repr(result))

    def test_visible_content_and_tagging_survive_metadata_generation(self):
        """Controlled metadata preserves the existing PDF structure and report text."""
        self.assertTrue(self.pdf.startswith(b"%PDF-1.7"))
        self.assertIn("/StructTreeRoot", self.reader.root_object)
        self.assertTrue(self.reader.root_object["/MarkInfo"]["/Marked"])
        text = "\n".join(page.extract_text() for page in self.reader.pages)
        self.assertIn(presentation()["report_id"], text)
        self.assertIn("Synthetic summary", text)
        self.assertIn("Synthetic metadata regression content.", text)


    def test_native_xmp_avoids_the_original_encoded_decoder(self):
        """Native metadata must pass without invoking the original stream decoder."""
        from pypdf.generic import EncodedStreamObject

        original = EncodedStreamObject.get_data

        def reject_metadata_decode(stream):
            """Permit unrelated PDF parsing while detecting unbounded XMP decoding."""
            if stream.get("/Type") == "/Metadata":
                raise AssertionError("unbounded_metadata_decode")
            return original(stream)

        with patch.object(EncodedStreamObject, "get_data", reject_metadata_decode):
            result = self.strict(self.pdf)
        self.assertTrue(result.passed, result.errors)

    def test_compressed_xmp_budget_caps_peak_allocation(self):
        """A tiny compressed stream must not allocate its 16 MiB expanded payload."""
        compressed = zlib.compress(b" " * (16 * 1024 * 1024))
        pdf = raw_xmp_candidate(self.pdf, compressed, filter_value="/FlateDecode")
        tracemalloc.start()
        try:
            result = self.strict(pdf)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertIn("pdf_metadata_budget_exceeded", result.errors)
        self.assertEqual(dict(result.metadata), {})
        self.assertLess(peak, 4 * 1024 * 1024)

    def test_strict_xml_budgets_precede_generic_value_scanning(self):
        """Over-budget node and depth trees are rejected before value collection."""
        packets = (
            self.appended('<rdf:Description rdf:about=""/>' * 128),
            self.xmp.replace(
                "<xmp:CreatorTool>OmniGenis</xmp:CreatorTool>",
                "<xmp:CreatorTool>" + "<xmp:Nested>" * 9 + PRODUCT
                + "</xmp:Nested>" * 9 + "</xmp:CreatorTool>",
            ).encode(),
        )
        for packet in packets:
            with self.subTest(length=len(packet)):
                pdf = rewrite_candidate(self.pdf, xmp=packet)
                with patch("reporting.pdf_qa._xmp_metadata_values") as scan:
                    result = self.strict(pdf)
                    scan.assert_not_called()
                self.assertIn("pdf_metadata_budget_exceeded", result.errors)

    def test_xmp_exact_byte_boundary_and_one_byte_overflow(self):
        """Both supported encodings accept 64 KiB and reject one extra byte."""
        size = 64 * 1024
        padded = self.xmp.replace(
            "</rdf:RDF>", " " * (size - len(self.xmp.encode())) + "</rdf:RDF>"
        ).encode()
        self.assertEqual(len(padded), size)
        for filtered in (False, True):
            with self.subTest(filtered=filtered):
                encode = zlib.compress if filtered else lambda value: value
                options = {"filter_value": "/FlateDecode"} if filtered else {}
                valid = raw_xmp_candidate(self.pdf, encode(padded), **options)
                self.assertTrue(self.strict(valid).passed)
                oversized = raw_xmp_candidate(self.pdf, encode(padded + b" "), **options)
                with patch("pypdf.xmp.XmpInformation") as parser:
                    result = self.strict(oversized)
                    parser.assert_not_called()
                self.assertIn("pdf_metadata_budget_exceeded", result.errors)

    def test_invalid_or_incomplete_flate_streams_are_rejected(self):
        """The bounded profile accepts one complete zlib member without recovery."""
        compressed = zlib.compress(self.xmp.encode())
        cases = {
            "truncated": compressed[:-1],
            "checksum": compressed[:-1] + bytes([compressed[-1] ^ 1]),
            "trailing": compressed + b"unexpected",
            "concatenated": compressed + zlib.compress(b"unexpected"),
        }
        for name, raw in cases.items():
            with self.subTest(case=name):
                self.assertBlocked(raw_xmp_candidate(self.pdf, raw, filter_value="/FlateDecode"))

    def test_unsupported_filter_representations_are_rejected(self):
        """Filter chains, other codecs, indirect names and parameters are excluded."""
        from pypdf.generic import ArrayObject, NameObject

        compressed = zlib.compress(self.xmp.encode())
        candidates = (
            raw_xmp_candidate(
                self.pdf, compressed,
                filter_value=ArrayObject([NameObject("/FlateDecode")]),
            ),
            raw_xmp_candidate(
                self.pdf, self.xmp.encode().hex().encode() + b">",
                filter_value="/ASCIIHexDecode",
            ),
            raw_xmp_candidate(
                self.pdf, compressed, filter_value="/FlateDecode", indirect_filter=True,
            ),
            raw_xmp_candidate(
                self.pdf, compressed, filter_value="/FlateDecode", decode_params=True,
            ),
        )
        for index, pdf in enumerate(candidates):
            with self.subTest(case=index):
                self.assertBlocked(pdf)


if __name__ == "__main__":
    unittest.main()
