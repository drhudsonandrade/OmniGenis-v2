from __future__ import annotations

import importlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
REPORT_ID = "e1a-small-variant-report"


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


class Rpt05LocalizationTests(unittest.TestCase):
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
        )
        self.assertTrue(self.presentation.passed, self.presentation.errors)

    def localize(self, **overrides):
        module = importlib.import_module("reporting.localization")
        values = {
            "presentation_ir": self.presentation.to_dict()["presentation_ir"],
            "locale_id": "en-US",
        }
        values.update(overrides)
        return module.localize_presentation_ir(**values)

    def test_localizes_only_controlled_presentation_labels(self):
        result = self.localize()
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(result.locale_id, "en-US")
        self.assertEqual(
            result.localized_ir["components"][0]["title"],
            "Identity and provenance",
        )
        self.assertEqual(len(result.localized_ir_sha256), 64)

    def test_semantic_content_is_preserved_verbatim(self):
        result = self.localize()
        source = self.presentation.to_dict()["presentation_ir"]
        self.assertEqual(
            result.localized_ir["components"][0]["content"],
            source["components"][0]["content"],
        )

    def test_unknown_locale_fails_closed(self):
        result = self.localize(locale_id="xx-INVALID")
        self.assertFalse(result.passed)
        self.assertIn("locale_not_supported", result.errors)

    def test_unknown_component_label_fails_closed(self):
        source = self.presentation.to_dict()["presentation_ir"]
        source["components"][0]["component_id"] = "unknown-component"
        result = self.localize(presentation_ir=source)
        self.assertFalse(result.passed)
        self.assertIn("localization_key_missing", result.errors)

    def test_localization_is_deterministic_and_renderer_neutral(self):
        first = self.localize().to_dict()
        second = self.localize().to_dict()
        self.assertEqual(first, second)
        serialized = json.dumps(first, sort_keys=True).lower()
        for forbidden in ("renderer_id", "html", "css", "pdf"):
            self.assertNotIn(forbidden, serialized)


if __name__ == "__main__":
    unittest.main()
