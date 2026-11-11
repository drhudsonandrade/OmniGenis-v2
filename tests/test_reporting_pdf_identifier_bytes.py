"""Original-byte identity for generated PDF trailer identifiers, without PDF edits."""
from io import BytesIO
from hashlib import sha256
import unittest

from pypdf import PdfReader
from pypdf.generic import (ArrayObject, ByteStringObject, IndirectObject, NameObject,
                          NullObject, NumberObject, TextStringObject, create_string_object)
from reporting import adapters
from reporting import _pdf_trailer_catalog_worker as worker
from tests.test_reporting_pdf_generated_source_job import canonical, source


class PdfIdentifierByteTests(unittest.TestCase):
    """Keep exact physical parity and finite byte limits independent of text decoding."""

    @classmethod
    def setUpClass(cls):
        """Generate the original one-observation regression without changing its data."""
        cls.ir = source(1)
        cls.source_bytes = canonical(cls.ir)
        candidate = adapters.build_html_css_and_pdf_adapter(presentation_ir=cls.ir)
        if not candidate.passed or candidate.pdf_status != 'READY':
            raise AssertionError('unchanged default fixture did not render')
        cls.pdf = candidate.pdf_bytes

    def reader(self):
        """Parse known synthetic output independently for each mutation case."""
        return PdfReader(BytesIO(self.pdf), strict=True)

    def xref(self, reader):
        """Resolve the physical stream already used by the native verifier."""
        size = 1 + len(reader.xref[0]) + len(reader.xref_objStm)
        return reader.get_object(IndirectObject(size - 1, 0, reader))

    def verify(self, reader):
        """Use the same complete catalog verifier as the native worker."""
        return worker._verify_trailer_catalog(reader, expected_pages=1,
            direct_count=len(reader.xref[0]), compressed_count=len(reader.xref_objStm))

    def bind_ids(self, reader, trailer, physical):
        """Keep trailer and physical parser objects independent in negative controls."""
        reader.trailer[NameObject('/ID')] = trailer
        self.xref(reader)[NameObject('/ID')] = physical

    def test_original_generated_binary_ids_are_admitted_without_rewriting(self):
        """The previously refused real PDF keeps its exact source and byte identities."""
        reader = self.reader()
        ids = reader.trailer.raw_get('/ID')
        self.assertEqual([type(v) for v in ids], [ByteStringObject, TextStringObject])
        self.assertEqual([len(v.original_bytes) for v in ids], [32, 32])
        before = sha256(self.pdf).hexdigest()
        try:
            result = self.verify(reader)
        except ValueError as exc:
            self.fail('valid original identifier bytes refused: ' + str(exc))
        self.assertTrue(result['xref_trailer_values_match'])
        self.assertEqual(result['catalog_page_count'], 1)
        self.assertEqual(sha256(self.pdf).hexdigest(), before)
        self.assertEqual(canonical(self.ir), self.source_bytes)

    def test_byte_and_decoded_representations_compare_original_bytes(self):
        """Parser scalar subclasses cannot replace raw-byte identity semantics."""
        reader = self.reader()
        self.bind_ids(reader, ArrayObject([ByteStringObject(b'A' * 32), TextStringObject('B' * 32)]),
            ArrayObject([TextStringObject('A' * 32), ByteStringObject(b'B' * 32)]))
        try:
            result = self.verify(reader)
        except ValueError as exc:
            self.fail('matching original bytes rejected by text subtype: ' + str(exc))
        self.assertTrue(result['xref_trailer_values_match'])

    def test_utf16_decoded_identifier_uses_original_byte_count(self):
        """A BOM may decode 32 original bytes into fewer characters."""
        raw = b'\xfe\xff' + b'\x00A' * 15
        decoded = create_string_object(raw)
        self.assertIs(type(decoded), TextStringObject)
        self.assertEqual(len(decoded), 15)
        self.assertEqual(decoded.original_bytes, raw)
        reader = self.reader()
        self.bind_ids(reader, ArrayObject([decoded, ByteStringObject(b'B' * 32)]),
            ArrayObject([ByteStringObject(raw), TextStringObject('B' * 32)]))
        try:
            self.verify(reader)
        except ValueError as exc:
            self.fail('32-byte BOM-decoded identifier refused: ' + str(exc))

    def test_character_count_cannot_hide_excess_original_bytes(self):
        """Thirty-two decoded characters are not necessarily thirty-two bytes."""
        reader = self.reader()
        value = create_string_object(b'\xfe\xff' + b'\x00A' * 32)
        self.assertEqual(len(value), 32)
        self.assertEqual(len(value.original_bytes), 66)
        self.bind_ids(reader, ArrayObject([value, TextStringObject('B' * 32)]),
            ArrayObject([value, TextStringObject('B' * 32)]))
        with self.assertRaises(ValueError):
            self.verify(reader)

    def test_wrong_length_byte_strings_fail_closed(self):
        """Both fields retain the exact finite generated-identifier length."""
        for length in (0, 1, 16, 31, 33, 64, 1024):
            with self.subTest(length=length):
                reader = self.reader()
                pair = ArrayObject([ByteStringObject(b'A' * length), ByteStringObject(b'B' * 32)])
                self.bind_ids(reader, pair, ArrayObject(pair))
                with self.assertRaises(ValueError):
                    self.verify(reader)

    def test_equal_decoded_text_cannot_hide_different_original_bytes(self):
        """Physical parity compares the captured bytes even if decoded text compares equal."""
        reader = self.reader()
        trailer = TextStringObject('A' * 32)
        physical = TextStringObject('A' * 32)
        physical._original_bytes = b'C' * 32
        self.assertEqual(trailer, physical)
        self.bind_ids(reader, ArrayObject([trailer, TextStringObject('B' * 32)]),
            ArrayObject([physical, TextStringObject('B' * 32)]))
        with self.assertRaises(ValueError):
            self.verify(reader)

    def test_indirect_non_string_and_python_values_are_refused(self):
        """Only direct parser string objects are admitted, never coercible values."""
        values = [NumberObject(32), NameObject('/A'), NullObject(), ArrayObject(), 'A' * 32, b'A' * 32]
        for value in values:
            with self.subTest(kind=type(value).__name__):
                reader = self.reader()
                pair = ArrayObject([value, TextStringObject('B' * 32)])
                self.bind_ids(reader, pair, ArrayObject(pair))
                with self.assertRaises(ValueError):
                    self.verify(reader)
        reader = self.reader()
        pair = ArrayObject([reader.trailer.raw_get('/Root'), TextStringObject('B' * 32)])
        self.bind_ids(reader, pair, ArrayObject(pair))
        with self.assertRaises(ValueError):
            self.verify(reader)

    def test_id_arrays_require_exact_shape_on_both_surfaces(self):
        """Missing or surplus identifiers cannot be normalized into a valid pair."""
        valid = ArrayObject([TextStringObject('A' * 32), TextStringObject('B' * 32)])
        for invalid in (ArrayObject(), ArrayObject(valid[:1]), ArrayObject([*valid, valid[0]]), TextStringObject('A' * 32)):
            for side in ('trailer', 'physical'):
                with self.subTest(kind=type(invalid).__name__, side=side, length=len(invalid)):
                    reader = self.reader()
                    self.bind_ids(reader, invalid if side == 'trailer' else valid,
                                  invalid if side == 'physical' else valid)
                    with self.assertRaises(ValueError):
                        self.verify(reader)

    def test_reordered_identifiers_refuse(self):
        """The two identifier positions are not an unordered set."""
        reader = self.reader()
        pair = ArrayObject([TextStringObject('A' * 32), TextStringObject('B' * 32)])
        self.bind_ids(reader, pair, ArrayObject(reversed(pair)))
        with self.assertRaises(ValueError):
            self.verify(reader)

    def test_legacy_ascii_ids_preserve_catalog_result(self):
        """Already-admitted string identifiers retain the same bounded catalog proof."""
        reader = self.reader()
        pair = ArrayObject([TextStringObject('A' * 32), TextStringObject('B' * 32)])
        self.bind_ids(reader, pair, ArrayObject(pair))
        result = self.verify(reader)
        self.assertEqual(result['catalog_page_count'], 1)
        self.assertTrue(result['flat_page_tree_consistent'])
        self.assertNotIn('release_authorized', result)
