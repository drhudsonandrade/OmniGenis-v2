from __future__ import annotations

import importlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
REPORT_ID = "e1a-small-variant-report"


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


class Rpt03ViewModelReleaseBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        compiler = importlib.import_module("reporting.compiler")
        catalog = load_json(ROOT / "reporting" / "catalog.v1.json")
        sections = load_json(
            ROOT / "reporting" / "sections" / "e1a-small-variant-report.v1.json"
        )
        intended_use = load_json(
            ROOT / "reporting" / "intended-use" / "e1a-small-variant-report.v1.json"
        )
        capability = load_json(
            ROOT / "reporting" / "capabilities" / "e1a-small-variant-report.v1.json"
        )
        interpretation = {
            "identity": {"sample_id": "SYNTHETIC-001"},
            "items": [],
            "conflicts": [],
            "limitations": ["Synthetic fixture only"],
            "provenance": [{"source_id": "synthetic"}],
        }
        self.compiled = compiler.compile_report_pack(
            report_id=REPORT_ID,
            catalog=catalog,
            section_contracts=sections,
            intended_use=intended_use,
            report_capability_manifest=capability,
            canonical_interpretation=interpretation,
        )
        self.assertTrue(self.compiled.passed, self.compiled.errors)

    def build(self, **overrides):
        module = importlib.import_module("reporting.viewmodel")
        values = {
            "compiled_report_pack": self.compiled,
            "artifact_ids": ["canonical-interpretation:synthetic-001"],
        }
        values.update(overrides)
        return module.build_report_view_model_and_release_bundle(**values)

    def test_builds_canonical_view_model_and_complete_release_bundle(self):
        result = self.build()
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(result.view_model["report_id"], REPORT_ID)
        self.assertEqual(len(result.view_model["sections"]), 5)
        self.assertEqual(result.completeness_manifest["status"], "COMPLETE")
        self.assertEqual(result.release_bundle["release_status"], "READY")
        self.assertEqual(len(result.release_bundle["bundle_sha256"]), 64)

    def test_completeness_manifest_binds_every_required_section(self):
        result = self.build()
        manifest = result.to_dict()["completeness_manifest"]
        self.assertEqual(manifest["required_section_count"], 5)
        self.assertEqual(manifest["present_section_count"], 5)
        self.assertEqual(manifest["missing_required_sections"], [])

    def test_release_bundle_is_deterministic(self):
        first = self.build().to_dict()
        second = self.build().to_dict()
        self.assertEqual(first, second)

    def test_release_bundle_is_snapshot_isolated(self):
        result = self.build()
        original = json.loads(json.dumps(result.to_dict()))
        exposed = result.to_dict()
        exposed["view_model"]["sections"][0]["title"] = "MUTATED"
        exposed["release_bundle"]["artifact_ids"].append("MUTATED")
        self.assertEqual(result.to_dict(), original)

    def test_retained_payloads_cannot_be_mutated_after_hashing(self):
        result = self.build()
        original = result.to_dict()
        with self.assertRaises(TypeError):
            result.view_model["sections"][0]["title"] = "MUTATED"
        with self.assertRaises(TypeError):
            result.release_bundle["release_status"] = "MUTATED"
        self.assertEqual(result.to_dict(), original)

    def test_non_mapping_section_fails_closed(self):
        module = importlib.import_module("reporting.viewmodel")
        bad = type(
            "BadPack",
            (),
            {
                "passed": True,
                "report_id": REPORT_ID,
                "pack_sha256": "a" * 64,
                "sections": ("not-a-mapping",),
            },
        )()
        result = module.build_report_view_model_and_release_bundle(
            compiled_report_pack=bad,
            artifact_ids=["synthetic"],
        )
        self.assertFalse(result.passed)
        self.assertIn("compiled_report_pack_invalid", result.errors)

    def test_invalid_compiled_pack_fails_closed(self):
        module = importlib.import_module("reporting.viewmodel")
        bad = type("BadPack", (), {"passed": False})()
        result = module.build_report_view_model_and_release_bundle(
            compiled_report_pack=bad,
            artifact_ids=["synthetic"],
        )
        self.assertFalse(result.passed)
        self.assertIn("compiled_report_pack_invalid", result.errors)

    def test_empty_or_duplicate_artifact_ids_fail_closed(self):
        self.assertIn("artifact_ids_required", self.build(artifact_ids=[]).errors)
        self.assertIn(
            "duplicate_artifact_ids",
            self.build(artifact_ids=["a", "a"]).errors,
        )

    def test_rpt03_does_not_render_localize_or_build_presentation_ir(self):
        serialized = json.dumps(self.build().to_dict(), sort_keys=True).lower()
        for forbidden in ("presentation_ir", "renderer_id", "pdf", "html", "locale_id"):
            self.assertNotIn(forbidden, serialized)


if __name__ == "__main__":
    unittest.main()
