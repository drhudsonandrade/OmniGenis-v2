from __future__ import annotations

import importlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
REPORT_ID = "e1a-small-variant-report"


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


class Rpt04PresentationIrTests(unittest.TestCase):
    def setUp(self) -> None:
        compiler = importlib.import_module("reporting.compiler")
        viewmodel = importlib.import_module("reporting.viewmodel")
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
        self.rpt03 = viewmodel.build_report_view_model_and_release_bundle(
            compiled_report_pack=compiled,
            artifact_ids=["canonical-interpretation:synthetic-001"],
        )
        self.assertTrue(self.rpt03.passed, self.rpt03.errors)

    def build(self, **overrides):
        module = importlib.import_module("reporting.presentation")
        values = {"report_view_model": self.rpt03.to_dict()["view_model"]}
        values.update(overrides)
        return module.build_presentation_ir(**values)

    def test_builds_deterministic_presentation_ir_in_section_order(self):
        result = self.build()
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(result.presentation_ir["report_id"], REPORT_ID)
        self.assertEqual(
            [component["component_id"] for component in result.presentation_ir["components"]],
            [
                "identity-and-provenance",
                "verified-source-interpretations",
                "unresolved-evidence-conflicts",
                "limitations-and-not-assessed",
                "sources-and-versioning",
            ],
        )
        self.assertEqual(len(result.presentation_ir_sha256), 64)

    def test_registry_uses_semantic_components_not_renderer_markup(self):
        result = self.build()
        registry = result.component_registry
        self.assertEqual(registry["identity-and-provenance"], "semantic-section")
        serialized = json.dumps(result.to_dict(), sort_keys=True).lower()
        for forbidden in ("html", "css", "pdf", "renderer_id", "locale_id"):
            self.assertNotIn(forbidden, serialized)

    def test_invalid_view_model_fails_closed(self):
        self.assertIn("report_view_model_invalid", self.build(report_view_model={}).errors)
        self.assertIn(
            "report_view_model_invalid",
            self.build(report_view_model={"report_id": REPORT_ID, "sections": ["bad"]}).errors,
        )

    def test_output_is_snapshot_isolated(self):
        result = self.build()
        original = json.loads(json.dumps(result.to_dict()))
        exposed = result.to_dict()
        exposed["presentation_ir"]["components"][0]["title"] = "MUTATED"
        self.assertEqual(result.to_dict(), original)

    def test_build_is_deterministic(self):
        self.assertEqual(self.build().to_dict(), self.build().to_dict())


if __name__ == "__main__":
    unittest.main()
