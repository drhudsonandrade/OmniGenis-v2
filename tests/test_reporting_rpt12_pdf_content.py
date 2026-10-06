"""Contract and regression tests for bounded PDF text content verification."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
import importlib
import importlib.util
from io import BytesIO
import json
import subprocess
import unittest
from unittest.mock import patch

from pypdf import PdfWriter
from pypdf.generic import DecodedStreamObject, NameObject

from reporting.adapters import build_html_css_and_pdf_adapter


def digest(data: bytes) -> str:
    """Compute the declared content identity of one synthetic artifact."""
    return hashlib.sha256(data).hexdigest()


def ir_digest(ir: object) -> str:
    """Use the existing localization canonical JSON encoding for fixture identity."""
    return digest(json.dumps(ir, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8"))


def synthetic_ir() -> dict:
    """Return multiple distinguishable sections without any real genomic data."""
    return {
        "report_id": "synthetic-content-report", "locale_id": "en-US",
        "components": [
            {"component_id": "summary", "component_type": "semantic-section",
             "title": "Summary", "state": "PRESENT",
             "content": {"label": "SYNTHETIC-CONTENT-ONLY", "value": 1.25}},
            {"component_id": "limitations", "component_type": "semantic-section",
             "title": "Limitations", "state": "PRESENT",
             "content": {"limitations": ["Synthetic fixture only"]}},
        ],
    }


def render(ir: dict) -> bytes:
    """Exercise the real public adapter rather than simulate extracted PDF text."""
    result = build_html_css_and_pdf_adapter(presentation_ir=ir)
    if not result.passed:
        raise AssertionError(result.errors)
    return result.pdf_bytes


def blank_pdf(*, pages: int = 1, encrypted: bool = False) -> bytes:
    """Serialize synthetic blank or encrypted PDF bytes in memory only."""
    writer = PdfWriter()
    for _ in range(pages):
        writer.add_blank_page(width=612, height=792)
    if encrypted:
        writer.encrypt("synthetic-test-password")
    stream = BytesIO()
    writer.write(stream)
    return stream.getvalue()


class Rpt12PdfContentTests(unittest.TestCase):
    """Bind expected report content to independently parsed candidate bytes."""

    @classmethod
    def setUpClass(cls):
        """Render one stable synthetic candidate for the boundary test cases."""
        cls.ir = synthetic_ir()
        cls.pdf = render(cls.ir)

    def setUp(self):
        """Fail explicitly while the requested verification contract is absent."""
        self.assertIsNotNone(importlib.util.find_spec("reporting.pdf_content"),
                             "PDF text content verification is not implemented")
        self.module = importlib.import_module("reporting.pdf_content")

    def check(self, **overrides):
        """Run the real gate with independently bound expected input and candidate."""
        args = {"presentation_ir": self.ir, "expected_ir_sha256": ir_digest(self.ir),
                "pdf_bytes": self.pdf, "expected_pdf_sha256": digest(self.pdf)}
        args.update(overrides)
        return self.module.validate_pdf_text_content(**args)

    def test_generated_pdf_matches_exact_localized_input(self):
        """A freshly rendered candidate verifies without being promoted to FINAL."""
        result = self.check()
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(result.ir_sha256, ir_digest(self.ir))
        self.assertEqual(result.pdf_sha256, digest(self.pdf))
        self.assertEqual(result.expected_text_sha256, result.extracted_text_sha256)
        self.assertEqual(result.to_dict()["conformance_scope"], "PDF_TEXT_CONTENT_ONLY")
        self.assertEqual(result.to_dict()["release_authorization"], "NOT_ESTABLISHED")

    def test_existing_canonical_pipeline_roundtrip(self):
        """The actual compiler, view model and localization fixture verifies end to end."""
        from tests import test_reporting_rpt08_html_pdf_conformance as fixture
        scenario = fixture.Rpt08HtmlPdfConformanceTests()
        scenario.setUp()
        pdf = render(scenario.presentation)
        result = self.check(presentation_ir=scenario.presentation,
                            expected_ir_sha256=ir_digest(scenario.presentation),
                            pdf_bytes=pdf, expected_pdf_sha256=digest(pdf))
        self.assertTrue(result.passed, result.errors)

    def test_wrapped_payload_preserves_spaces_and_json_escapes(self):
        """Physical wraps may disappear, but semantic JSON spaces and escapes may not."""
        ir = deepcopy(self.ir)
        ir["components"][0]["content"]["text"] = "A  B " + "alpha beta gamma " * 25 + "\nquoted \"text\""
        pdf = render(ir)
        result = self.check(presentation_ir=ir, expected_ir_sha256=ir_digest(ir),
                            pdf_bytes=pdf, expected_pdf_sha256=digest(pdf))
        self.assertTrue(result.passed, result.errors)

    def test_omission_duplication_reordering_and_changed_values_fail(self):
        """A valid new digest cannot hide changed report text from the expected IR."""
        changes = []
        ir = deepcopy(self.ir); ir["components"].pop(); changes.append(ir)
        ir = deepcopy(self.ir); ir["components"].reverse(); changes.append(ir)
        ir = deepcopy(self.ir); ir["components"][0]["content"]["value"] = 12.5; changes.append(ir)
        ir = deepcopy(self.ir); ir["report_id"] = "another-report"; changes.append(ir)
        ir = deepcopy(self.ir); ir["components"][0]["state"] = "NOT_ASSESSED"; changes.append(ir)
        ir = deepcopy(self.ir); extra = deepcopy(ir["components"][0]); extra["component_id"] = "duplicate"; ir["components"].append(extra); changes.append(ir)
        for index, changed in enumerate(changes):
            with self.subTest(index=index):
                pdf = render(changed)
                result = self.check(pdf_bytes=pdf, expected_pdf_sha256=digest(pdf))
                self.assertFalse(result.passed)
                self.assertIn("pdf_text_content_mismatch", result.errors)

    def test_semantic_spaces_are_not_folded(self):
        """Double spaces in a JSON value remain distinguishable from a single space."""
        original = deepcopy(self.ir); original["components"][0]["content"]["label"] = "A  B"
        changed = deepcopy(original); changed["components"][0]["content"]["label"] = "A B"
        pdf = render(changed)
        result = self.check(presentation_ir=original, expected_ir_sha256=ir_digest(original),
                            pdf_bytes=pdf, expected_pdf_sha256=digest(pdf))
        self.assertFalse(result.passed)
        self.assertIn("pdf_text_content_mismatch", result.errors)

    def test_digest_errors_block_before_extraction(self):
        """Bad or mismatched identities cannot reach the parser process."""
        cases = [({"expected_pdf_sha256": "0" * 64}, "pdf_digest_mismatch"),
                 ({"expected_ir_sha256": "0" * 64}, "presentation_ir_digest_mismatch"),
                 ({"expected_pdf_sha256": None}, "expected_pdf_digest_invalid"),
                 ({"expected_ir_sha256": "not-a-digest"}, "expected_ir_digest_invalid")]
        for overrides, error in cases:
            with self.subTest(error=error), patch.object(self.module.subprocess, "run") as call:
                result = self.check(**overrides)
                self.assertFalse(result.passed)
                self.assertIn(error, result.errors)
                call.assert_not_called()

    def test_malformed_unlocalized_or_noncanonical_input_fails(self):
        """Only JSON-compatible localized semantic sections are an expected source."""
        invalid = [None, {}, {**self.ir, "locale_id": "pt-BR"},
                   {**self.ir, "locale_id": []}, {**self.ir, "components": []}]
        repeated = deepcopy(self.ir); repeated["components"][1]["component_id"] = "summary"; invalid.append(repeated)
        nonfinite = deepcopy(self.ir); nonfinite["components"][0]["content"]["value"] = float("nan"); invalid.append(nonfinite)
        for ir in invalid:
            with self.subTest(ir=repr(ir)):
                result = self.check(presentation_ir=ir)
                self.assertFalse(result.passed)
                self.assertIn("presentation_ir_invalid", result.errors)

    def test_encrypted_malformed_and_zero_page_candidates_fail(self):
        """Unreadable content never receives a content-equivalence attestation."""
        for pdf, error in [(blank_pdf(encrypted=True), "encrypted_pdf_forbidden"),
                           (b"%PDF-1.7\nbroken", "pdf_content_structure_invalid"),
                           (blank_pdf(pages=0), "pdf_content_structure_invalid")]:
            with self.subTest(error=error):
                result = self.check(pdf_bytes=pdf, expected_pdf_sha256=digest(pdf))
                self.assertFalse(result.passed)
                self.assertIn(error, result.errors)

    def test_blank_page_is_not_treated_as_verified_text(self):
        """Empty or image-only text extraction cannot satisfy a report manifest."""
        pdf = blank_pdf()
        result = self.check(pdf_bytes=pdf, expected_pdf_sha256=digest(pdf))
        self.assertFalse(result.passed)
        self.assertIn("pdf_content_text_missing", result.errors)

    def test_byte_and_page_budgets_fail_closed(self):
        """Oversized candidates are rejected rather than partly inspected."""
        from reporting import _pdf_content_worker as worker
        for pdf in (b"%PDF-1.7\n" + b"0" * worker.MAX_PDF_BYTES,
                    blank_pdf(pages=worker.MAX_PAGES + 1)):
            with self.subTest(size=len(pdf)):
                result = self.check(pdf_bytes=pdf, expected_pdf_sha256=digest(pdf))
                self.assertFalse(result.passed)
                self.assertIn("pdf_content_budget_exceeded", result.errors)

    def test_decoded_stream_budget_is_checked_before_text_parsing(self):
        """A small compressed input cannot bypass the decoded-content budget."""
        from reporting import _pdf_content_worker as worker
        writer = PdfWriter(); page = writer.add_blank_page(width=612, height=792)
        stream = DecodedStreamObject()
        stream.set_data(b"q\n" * (worker.MAX_DECODED_BYTES // 2 + 1))
        page[NameObject("/Contents")] = writer._add_object(stream.flate_encode())
        data = BytesIO(); writer.write(data); pdf = data.getvalue()
        self.assertLess(len(pdf), worker.MAX_PDF_BYTES)
        result = self.check(pdf_bytes=pdf, expected_pdf_sha256=digest(pdf))
        self.assertFalse(result.passed)
        self.assertIn("pdf_content_budget_exceeded", result.errors)

    def test_timeout_and_failed_worker_are_not_passes(self):
        """Unavailable, timed-out or invalid worker results stay blocked."""
        scenarios = [(subprocess.TimeoutExpired("synthetic-worker", 10), "pdf_content_worker_timeout"),
                     (OSError("synthetic failure"), "pdf_content_worker_unavailable")]
        for exc, error in scenarios:
            with self.subTest(error=error), patch.object(self.module.subprocess, "run", side_effect=exc):
                result = self.check()
                self.assertFalse(result.passed)
                self.assertIn(error, result.errors)
        for returncode, data in [(-9, b""), (0, b"not JSON"), (0, b'{"status":"PASS"}')]:
            with self.subTest(returncode=returncode), patch.object(self.module.subprocess, "run", return_value=subprocess.CompletedProcess([], returncode, data)):
                self.assertFalse(self.check().passed)

    def test_evidence_is_immutable_and_contains_no_report_text(self):
        """The public validation record retains digests, not extracted personal text."""
        result = self.check(); self.assertTrue(result.passed, result.errors)
        exposed = result.to_dict()
        self.assertNotIn("SYNTHETIC-CONTENT-ONLY", json.dumps(exposed))
        self.assertNotIn("synthetic-content-report", json.dumps(exposed))
        exposed["errors"].append("tampered")
        self.assertEqual(result.errors, ())
        with self.assertRaises(FrozenInstanceError):
            result.page_count = 999

    def test_public_result_cannot_claim_pass_without_evidence(self):
        """An empty success-looking record violates the result constructor invariant."""
        with self.assertRaises(ValueError):
            self.module.PdfContentValidation(None, None, None, None, None, ())

    def test_actual_multipage_output_preserves_content_order(self):
        """All generated pages contribute to one complete ordered content digest."""
        ir = deepcopy(self.ir)
        ir["components"] = []
        for index in range(20):
            ir["components"].append({
                "component_id": f"section-{index}", "component_type": "semantic-section",
                "title": f"Synthetic section {index}", "state": "PRESENT",
                "content": {"index": index, "text": "alpha beta gamma " * 14},
            })
        pdf = render(ir)
        result = self.check(presentation_ir=ir, expected_ir_sha256=ir_digest(ir),
                            pdf_bytes=pdf, expected_pdf_sha256=digest(pdf))
        self.assertTrue(result.passed, result.errors)
        self.assertGreater(result.page_count, 1)

    def test_canonical_source_rejects_json_key_and_shape_coercion(self):
        """Expected source identities cannot silently coerce non-JSON key or array types."""
        for payload in ({1: "synthetic"}, {"items": ("synthetic",)}):
            with self.subTest(payload=repr(payload)):
                ir = deepcopy(self.ir)
                ir["components"][0]["content"] = payload
                result = self.check(presentation_ir=ir, expected_ir_sha256=ir_digest(ir))
                self.assertFalse(result.passed)
                self.assertIn("presentation_ir_invalid", result.errors)

    def test_extractor_version_drift_is_rejected(self):
        """The worker uses only the already activated pypdf version."""
        from reporting import _pdf_content_worker as worker
        with patch.object(worker, "version", return_value="0.0.0"):
            result = worker.extract_document(self.pdf)
        self.assertEqual(result["errors"], ["pdf_content_extractor_version_mismatch"])


if __name__ == "__main__":
    unittest.main()
