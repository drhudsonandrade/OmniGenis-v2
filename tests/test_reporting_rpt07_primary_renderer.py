from __future__ import annotations

import importlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
REPORT_ID = "e1a-small-variant-report"


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


class Rpt07PrimaryRendererTests(unittest.TestCase):
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

    def render(self, **overrides):
        module = importlib.import_module("reporting.renderer")
        values = {
            "presentation_ir": self.presentation,
            "renderer_id": "canonical-text-v1",
            "lifecycle_profile": "preview",
        }
        values.update(overrides)
        return module.render_primary(**values)

    def test_primary_renderer_emits_deterministic_text_artifact(self):
        result = self.render()
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(result.renderer_id, "canonical-text-v1")
        self.assertEqual(result.lifecycle_profile, "preview")
        self.assertIn("Identity and provenance", result.artifact_text)
        self.assertEqual(len(result.artifact_sha256), 64)

    def test_renderer_preserves_component_order(self):
        result = self.render()
        positions = [
            result.artifact_text.index(title)
            for title in (
                "Identity and provenance",
                "Verified source interpretations",
                "Unresolved evidence conflicts",
                "Limitations and not assessed",
                "Sources and versioning",
            )
        ]
        self.assertEqual(positions, sorted(positions))

    def test_unsupported_renderer_and_lifecycle_fail_closed(self):
        self.assertIn(
            "renderer_not_supported",
            self.render(renderer_id="unknown").errors,
        )
        self.assertIn(
            "lifecycle_profile_not_supported",
            self.render(lifecycle_profile="release").errors,
        )

    def test_malformed_presentation_ir_fails_closed(self):
        bad = json.loads(json.dumps(self.presentation))
        bad["components"][0]["title"] = ""
        self.assertIn(
            "presentation_ir_invalid",
            self.render(presentation_ir=bad).errors,
        )

    def test_rpt07_does_not_emit_html_css_or_pdf(self):
        result = self.render()
        serialized = json.dumps(result.to_dict(), sort_keys=True).lower()
        for forbidden in ("html", "css", "pdf"):
            self.assertNotIn(forbidden, serialized)


if __name__ == "__main__":
    unittest.main()
