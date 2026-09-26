from __future__ import annotations

import importlib
import json
from pathlib import Path
import hashlib
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
REPORT_ID = "e1a-small-variant-report"


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


class Rpt08HtmlPdfConformanceTests(unittest.TestCase):
    def setUp(self) -> None:
        compiler = importlib.import_module("reporting.compiler")
        viewmodel = importlib.import_module("reporting.viewmodel")
        presentation = importlib.import_module("reporting.presentation")
        interpretation = {
            "identity": {"sample_id": "SYNTHETIC-001"},
            "items": [],
            "conflicts": [],
            "limitations": ["Synthetic fixture only"],
            "provenance": [{"source_id": "synthetic"}],
        }
        compiled = compiler.compile_report_pack(
            report_id=REPORT_ID,
            catalog=load_json(ROOT / "reporting" / "catalog.v1.json"),
            section_contracts=load_json(ROOT / "reporting" / "sections" / "e1a-small-variant-report.v1.json"),
            intended_use=load_json(ROOT / "reporting" / "intended-use" / "e1a-small-variant-report.v1.json"),
            report_capability_manifest=load_json(ROOT / "reporting" / "capabilities" / "e1a-small-variant-report.v1.json"),
            canonical_interpretation=interpretation,
        )
        rpt03 = viewmodel.build_report_view_model_and_release_bundle(
            compiled_report_pack=compiled,
            artifact_ids=["canonical-interpretation:synthetic-001"],
        )
        self.presentation = presentation.build_presentation_ir(
            report_view_model=rpt03.view_model,
        ).to_dict()["presentation_ir"]

    def adapt(self, **overrides):
        module = importlib.import_module("reporting.adapters")
        values = {"presentation_ir": self.presentation}
        values.update(overrides)
        with patch(
            "reporting.adapters._render_pdf",
            return_value=b"%PDF-1.7\nsynthetic-default\n%%EOF\n",
        ):
            return module.build_html_css_and_pdf_adapter(**values)

    def test_html_css_adapter_is_deterministic_and_escaped(self):
        result = self.adapt()
        self.assertTrue(result.passed, result.errors)
        self.assertTrue(result.html.startswith("<!doctype html>"))
        self.assertIn("<style>", result.html)
        self.assertEqual(len(result.html_sha256), 64)

    def test_conformance_harness_binds_component_count_and_order(self):
        result = self.adapt()
        self.assertEqual(result.conformance["status"], "PASS")
        self.assertEqual(result.conformance["component_count"], 5)
        self.assertEqual(
            result.conformance["component_ids"],
            [component["component_id"] for component in self.presentation["components"]],
        )

    def test_pdf_adapter_binds_generated_pdf(self):
        fake_pdf = b"%PDF-1.7\nsynthetic-fixture\n%%EOF\n"
        module = importlib.import_module("reporting.adapters")
        with patch("reporting.adapters._render_pdf", return_value=fake_pdf):
            result = module.build_html_css_and_pdf_adapter(
                presentation_ir=self.presentation
            )
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(result.pdf_status, "READY")
        self.assertIsNone(result.pdf_reason)
        self.assertEqual(result.pdf_bytes, fake_pdf)
        self.assertEqual(
            result.pdf_sha256,
            hashlib.sha256(fake_pdf).hexdigest(),
        )
        self.assertEqual(result.pdf_engine_id, "weasyprint:70.0")

    @unittest.skipUnless(
        importlib.util.find_spec("weasyprint"),
        "pinned PDF engine not installed",
    )
    def test_pinned_weasyprint_engine_generates_deterministic_pdf(self):
        module = importlib.import_module("reporting.adapters")
        first = module.build_html_css_and_pdf_adapter(
            presentation_ir=self.presentation
        )
        second = module.build_html_css_and_pdf_adapter(
            presentation_ir=self.presentation
        )
        self.assertTrue(first.passed, first.errors)
        self.assertEqual(first.pdf_status, "READY")
        self.assertTrue(first.pdf_bytes.startswith(b"%PDF-1.7"))
        self.assertEqual(first.pdf_sha256, second.pdf_sha256)
        self.assertEqual(first.pdf_bytes, second.pdf_bytes)

    def test_pdf_engine_unavailable_fails_closed(self):
        module = importlib.import_module("reporting.adapters")
        with patch(
            "reporting.adapters._render_pdf",
            side_effect=RuntimeError("pdf_engine_unavailable"),
        ):
            result = module.build_html_css_and_pdf_adapter(
                presentation_ir=self.presentation
            )
        self.assertFalse(result.passed)
        self.assertIn("pdf_engine_unavailable", result.errors)
        self.assertIsNone(result.pdf_bytes)

    def test_malformed_ir_fails_closed(self):
        bad = json.loads(json.dumps(self.presentation))
        bad["components"][0]["component_id"] = ""
        result = self.adapt(presentation_ir=bad)
        self.assertFalse(result.passed)
        self.assertIn("presentation_ir_invalid", result.errors)

    def test_semantic_payload_is_not_interpreted_as_markup(self):
        bad = json.loads(json.dumps(self.presentation))
        bad["components"][0]["content"] = {"text": "<script>alert(1)</script>"}
        result = self.adapt(presentation_ir=bad)
        self.assertTrue(result.passed, result.errors)
        self.assertNotIn("<script>alert(1)</script>", result.html)
        self.assertIn("&lt;script&gt;", result.html)


if __name__ == "__main__":
    unittest.main()
