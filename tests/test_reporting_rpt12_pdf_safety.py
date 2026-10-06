"""Synthetic contract tests for the passive-report PDF object policy."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
import importlib
import importlib.util
from io import BytesIO
import json
import subprocess
import unittest
from unittest.mock import patch

from pypdf import PdfReader, PdfWriter
from pypdf.generic import (
    ArrayObject, DictionaryObject, NameObject, NullObject, NumberObject,
    TextStringObject, DecodedStreamObject, IndirectObject,
)
from reporting.adapters import build_html_css_and_pdf_adapter


def digest(data: bytes) -> str:
    """Bind a synthetic candidate to its exact bytes."""
    return hashlib.sha256(data).hexdigest()


def source_ir() -> dict:
    """Return inert localized report text with no personal or genomic data."""
    return {"report_id": "synthetic-passive-report", "locale_id": "en-US", "components": [
        {"component_id": "summary", "component_type": "semantic-section", "title": "Summary",
         "state": "PRESENT", "content": {"text": "SYNTHETIC-ONLY"}},
    ]}


def render(ir: dict) -> bytes:
    """Obtain real candidate bytes through the existing public adapter."""
    result = build_html_css_and_pdf_adapter(presentation_ir=ir)
    if not result.passed:
        raise AssertionError(result.errors)
    return result.pdf_bytes


def serialized(writer: PdfWriter) -> bytes:
    """Serialize a generated fixture in memory, without opening its actions."""
    stream = BytesIO()
    writer.write(stream)
    return stream.getvalue()


def blank(*, pages: int = 1, encrypted: bool = False) -> bytes:
    """Create a structural fixture independently of the production renderer."""
    writer = PdfWriter()
    for _ in range(pages):
        writer.add_blank_page(width=612, height=792)
    if encrypted:
        writer.encrypt("synthetic-test-only")
    return serialized(writer)


class PdfObjectSafetyTests(unittest.TestCase):
    """Check policy decisions against real direct and indirect PDF objects."""

    @classmethod
    def setUpClass(cls):
        """Render a passive baseline once; no mutated PDF is displayed or executed."""
        cls.pdf = render(source_ir())

    def setUp(self):
        """Expose a missing implementation as an explicit contract failure."""
        self.assertIsNotNone(importlib.util.find_spec("reporting.pdf_safety"),
                             "Passive PDF object policy is not implemented")
        self.module = importlib.import_module("reporting.pdf_safety")

    def check(self, pdf=None, **overrides):
        """Run the real resource-limited worker with a fresh candidate identity."""
        data = self.pdf if pdf is None else pdf
        args = {"pdf_bytes": data, "expected_pdf_sha256": digest(data)}
        args.update(overrides)
        return self.module.validate_pdf_object_safety(**args)

    def writer(self):
        """Clone only the synthetic passive baseline for negative mutations."""
        writer = PdfWriter()
        writer.clone_document_from_reader(PdfReader(BytesIO(self.pdf), strict=True))
        return writer

    def test_real_candidate_passes_with_content_free_bound_evidence(self):
        """A passive report yields bounded evidence, never a release authorization."""
        result = self.check()
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(result.pdf_sha256, digest(self.pdf))
        self.assertGreater(result.object_count, 0)
        self.assertEqual(result.page_count, 1)
        record = result.to_dict()
        self.assertEqual(record["policy_id"], "passive-report-pdf-v1")
        self.assertEqual(record["conformance_scope"], "REACHABLE_PDF_OBJECT_POLICY_ONLY")
        self.assertEqual(record["release_authorization"], "NOT_ESTABLISHED")
        self.assertNotIn("SYNTHETIC-ONLY", json.dumps(record))
        self.assertEqual(record, self.check().to_dict())

    def test_existing_canonical_pipeline_remains_passive(self):
        """Compiler, localized model, outline and tagged output satisfy this profile."""
        from tests.test_reporting_rpt08_html_pdf_conformance import Rpt08HtmlPdfConformanceTests
        scenario = Rpt08HtmlPdfConformanceTests(); scenario.setUp()
        result = self.check(render(scenario.presentation))
        self.assertTrue(result.passed, result.errors)

    def test_action_keys_fail_even_when_empty_or_indirect(self):
        """Conservative action exclusions depend on object keys, not payload truthiness."""
        for key in ("/OpenAction", "/AA", "/A", "/JS", "/JavaScript"):
            for indirect in (False, True):
                with self.subTest(key=key, indirect=indirect):
                    writer = self.writer()
                    value = NullObject()
                    writer.root_object[NameObject(key)] = writer._add_object(value) if indirect else value
                    result = self.check(serialized(writer))
                    self.assertFalse(result.passed)
                    self.assertIn("pdf_actions_forbidden", result.errors)

    def test_nested_page_and_unknown_actions_are_blocked(self):
        """Unknown actions and additional page actions cannot hide in nested arrays."""
        for subtype in ("/JavaScript", "/Launch", "/URI", "/GoToR", "/UnknownAction"):
            with self.subTest(subtype=subtype):
                writer = self.writer()
                action = DictionaryObject({NameObject("/S"): NameObject(subtype)})
                annotation = DictionaryObject({NameObject("/Type"): NameObject("/Annot"),
                    NameObject("/Subtype"): NameObject("/Link"), NameObject("/A"): writer._add_object(action)})
                writer.pages[0][NameObject("/Annots")] = ArrayObject([writer._add_object(annotation)])
                result = self.check(serialized(writer))
                self.assertFalse(result.passed)
                self.assertIn("pdf_actions_forbidden", result.errors)

    def test_javascript_name_tree_is_detected(self):
        """The dependency's real JavaScript-name-tree encoding is rejected."""
        from pypdf.actions import JavaScript
        writer = self.writer(); writer.add_open_action(JavaScript("void 0;"))
        result = self.check(serialized(writer))
        self.assertFalse(result.passed)
        self.assertIn("pdf_actions_forbidden", result.errors)

    def test_attachments_and_associated_file_relationships_are_blocked(self):
        """Real attachments and empty associated-file declarations fail closed."""
        writer = self.writer(); writer.add_attachment("synthetic.bin", b"fixture")
        self.assertIn("pdf_embedded_files_forbidden", self.check(serialized(writer)).errors)
        for key in ("/AF", "/EF", "/EmbeddedFiles"):
            with self.subTest(key=key):
                writer = self.writer(); writer.pages[0][NameObject(key)] = ArrayObject()
                self.assertIn("pdf_embedded_files_forbidden", self.check(serialized(writer)).errors)

    def test_forms_and_interactive_media_are_blocked(self):
        """Empty form declarations and media annotations remain outside the profile."""
        for key in ("/AcroForm", "/XFA"):
            with self.subTest(key=key):
                writer = self.writer(); writer.root_object[NameObject(key)] = DictionaryObject()
                self.assertIn("pdf_forms_forbidden", self.check(serialized(writer)).errors)
        for subtype in ("/RichMedia", "/Screen", "/Movie", "/Sound", "/3D", "/Widget", "/FileAttachment"):
            with self.subTest(subtype=subtype):
                writer = self.writer()
                annot = DictionaryObject({NameObject("/Type"): NameObject("/Annot"), NameObject("/Subtype"): NameObject(subtype)})
                writer.pages[0][NameObject("/Annots")] = ArrayObject([writer._add_object(annot)])
                self.assertFalse(self.check(serialized(writer)).passed)

    def test_external_stream_is_rejected_without_loading_it(self):
        """A stream backed by an external file is rejected from its dictionary alone."""
        writer = self.writer(); stream = DecodedStreamObject(); stream.set_data(b"q Q")
        stream[NameObject("/F")] = TextStringObject("https://example.invalid/synthetic")
        writer.pages[0][NameObject("/Contents")] = writer._add_object(stream)
        result = self.check(serialized(writer))
        self.assertFalse(result.passed)
        self.assertIn("pdf_external_stream_forbidden", result.errors)
        self.assertNotIn("example.invalid", json.dumps(result.to_dict()))

    def test_plain_report_text_is_not_mistaken_for_an_action(self):
        """Action names appearing in the rendered text have no execution semantics."""
        ir = source_ir(); ir["components"][0]["content"]["text"] = "/JS /JavaScript /OpenAction /A are plain words"
        result = self.check(render(ir))
        self.assertTrue(result.passed, result.errors)

    def test_shared_cycles_terminate_and_do_not_hide_actions(self):
        """Reused references terminate while every reachable dictionary is inspected."""
        for hazardous in (False, True):
            with self.subTest(hazardous=hazardous):
                writer = self.writer(); node = DictionaryObject(); ref = writer._add_object(node)
                node[NameObject("/Cycle")] = ref
                if hazardous:
                    node[NameObject("/AA")] = DictionaryObject()
                writer.root_object[NameObject("/SyntheticGraph")] = ArrayObject([ref, ref])
                result = self.check(serialized(writer))
                self.assertEqual(result.passed, not hazardous, result.errors)

    def test_missing_reference_and_malformed_discriminators_fail(self):
        """Broken references and non-name dictionary types cannot look like a pass."""
        writer = self.writer()
        writer.root_object[NameObject("/SyntheticGraph")] = IndirectObject(999999, 0, writer)
        self.assertFalse(self.check(serialized(writer)).passed)
        writer = self.writer()
        writer.root_object[NameObject("/Type")] = TextStringObject("/Catalog")
        self.assertFalse(self.check(serialized(writer)).passed)

    def test_bad_identity_blocks_before_worker(self):
        """Only the exact canonical candidate digest can authorize inspection."""
        for expected, error in (("0" * 64, "pdf_digest_mismatch"), (None, "expected_pdf_digest_invalid"),
                                ("G" * 64, "expected_pdf_digest_invalid")):
            with self.subTest(expected=expected), patch.object(self.module.subprocess, "run") as child:
                result = self.check(expected_pdf_sha256=expected)
                self.assertFalse(result.passed)
                self.assertIn(error, result.errors)
                child.assert_not_called()

    def test_malformed_encrypted_and_zero_page_candidates_are_blocked(self):
        """Structural failures are not counted as a passive-object attestation."""
        for pdf in (b"%PDF-1.7\nbroken", blank(pages=0), blank(encrypted=True)):
            with self.subTest(length=len(pdf)):
                self.assertFalse(self.check(pdf).passed)

    def test_byte_page_graph_and_depth_budgets_fail_closed(self):
        """A resource limit produces BLOCKED rather than an incomplete clean scan."""
        from reporting import _pdf_safety_worker as worker
        candidates = [b"%PDF-1.7\n" + b"0" * worker.MAX_PDF_BYTES, blank(pages=worker.MAX_PAGES + 1)]
        writer = self.writer()
        writer.root_object[NameObject("/SyntheticGraph")] = ArrayObject([NumberObject(i) for i in range(worker.MAX_VISITS + 1)])
        candidates.append(serialized(writer))
        writer = self.writer(); node = DictionaryObject()
        for _ in range(worker.MAX_DEPTH + 1):
            node = DictionaryObject({NameObject("/Child"): writer._add_object(node)})
        writer.root_object[NameObject("/SyntheticGraph")] = writer._add_object(node)
        candidates.append(serialized(writer))
        for pdf in candidates:
            with self.subTest(size=len(pdf)):
                result = self.check(pdf)
                self.assertFalse(result.passed)
                self.assertIn("pdf_safety_budget_exceeded", result.errors)

    def test_worker_failures_are_not_success(self):
        """Timeout, process failure and malformed replies cannot produce PASS."""
        for exc in (OSError("synthetic"), subprocess.TimeoutExpired("synthetic", 10)):
            with self.subTest(kind=type(exc).__name__), patch.object(self.module.subprocess, "run", side_effect=exc):
                self.assertFalse(self.check().passed)
        for code, data in ((-9, b""), (0, b"not JSON"), (0, b'{"status":"PASS"}'), (0, b"x" * 4097)):
            with self.subTest(code=code, length=len(data)), patch.object(self.module.subprocess, "run", return_value=subprocess.CompletedProcess([], code, data)):
                self.assertFalse(self.check().passed)

    def test_worker_success_requires_exact_identity_and_integer_counts(self):
        """A claimed worker success must satisfy the complete bounded protocol."""
        template = {"status": "PASS", "pdf_sha256": digest(self.pdf), "page_count": 1, "object_count": 10, "errors": []}
        changes = ({"pdf_sha256": "0" * 64}, {"page_count": True}, {"object_count": 0},
                   {"status": "SKIPPED"}, {"errors": ["unknown"]}, {"extra": "unexpected"})
        for change in changes:
            with self.subTest(change=change):
                record = {**template, **change}
                with patch.object(self.module.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(record).encode())):
                    result = self.check()
                self.assertFalse(result.passed)
                self.assertIn("pdf_safety_worker_invalid_response", result.errors)

    def test_public_evidence_is_immutable_and_needs_success_proof(self):
        """The public constructor rejects incomplete success-looking evidence."""
        with self.assertRaises(ValueError):
            self.module.PdfSafetyValidation(None, None, None, ())
        result = self.check(); self.assertTrue(result.passed, result.errors)
        with self.assertRaises(FrozenInstanceError):
            result.page_count = 50
        data = result.to_dict(); data["errors"].append("mutated")
        self.assertEqual(result.errors, ())

    def test_extractor_version_is_pinned(self):
        """An unactivated parser version cannot yield a policy pass."""
        from reporting import _pdf_safety_worker as worker
        with patch.object(worker, "version", return_value="0.0.0"):
            result = worker.inspect_document(self.pdf)
        self.assertEqual(result["errors"], ["pdf_safety_parser_version_mismatch"])


if __name__ == "__main__":
    unittest.main()
