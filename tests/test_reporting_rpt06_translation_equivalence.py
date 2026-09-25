from __future__ import annotations

import importlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
REPORT_ID = "e1a-small-variant-report"


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


class Rpt06TranslationEquivalenceTests(unittest.TestCase):
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

    def translate(self, **overrides):
        module = importlib.import_module("reporting.translation")
        values = {
            "presentation_ir": self.presentation,
            "source_locale_id": "en-US",
            "target_locale_id": "en-US",
        }
        values.update(overrides)
        return module.orchestrate_translation(**values)

    def test_identity_translation_proves_semantic_equivalence(self):
        result = self.translate()
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(result.equivalence_status, "EQUIVALENT")
        self.assertEqual(len(result.translation_sha256), 64)

    def test_semantic_payload_is_identical_across_translation(self):
        result = self.translate()
        source = self.presentation["components"]
        target = result.to_dict()["translated_ir"]["components"]
        self.assertEqual(
            [component["content"] for component in source],
            [component["content"] for component in target],
        )

    def test_retained_translation_ir_is_immutable_after_hashing(self):
        result = self.translate()
        original = result.to_dict()
        with self.assertRaises(TypeError):
            result.translated_ir["components"][0]["title"] = "MUTATED"
        self.assertEqual(result.to_dict(), original)

    def test_empty_and_duplicate_component_identity_fail_closed(self):
        empty = json.loads(json.dumps(self.presentation))
        empty["components"][0]["component_id"] = ""
        self.assertIn(
            "presentation_ir_invalid",
            self.translate(presentation_ir=empty).errors,
        )

        duplicate = json.loads(json.dumps(self.presentation))
        duplicate["components"][1]["component_id"] = duplicate["components"][0]["component_id"]
        self.assertIn(
            "presentation_ir_invalid",
            self.translate(presentation_ir=duplicate).errors,
        )

    def test_empty_title_and_state_fail_closed(self):
        for field in ("title", "state"):
            bad = json.loads(json.dumps(self.presentation))
            bad["components"][0][field] = ""
            self.assertIn(
                "presentation_ir_invalid",
                self.translate(presentation_ir=bad).errors,
            )

    def test_unsupported_translation_pair_fails_closed(self):
        result = self.translate(target_locale_id="pt-BR")
        self.assertFalse(result.passed)
        self.assertIn("translation_pair_not_supported", result.errors)

    def test_malformed_presentation_ir_fails_closed(self):
        bad = json.loads(json.dumps(self.presentation))
        bad["components"][0].pop("content")
        result = self.translate(presentation_ir=bad)
        self.assertFalse(result.passed)
        self.assertIn("presentation_ir_invalid", result.errors)

    def test_translation_is_deterministic_and_renderer_neutral(self):
        first = self.translate().to_dict()
        second = self.translate().to_dict()
        self.assertEqual(first, second)
        serialized = json.dumps(first, sort_keys=True).lower()
        for forbidden in ("renderer_id", "html", "css", "pdf"):
            self.assertNotIn(forbidden, serialized)


if __name__ == "__main__":
    unittest.main()
