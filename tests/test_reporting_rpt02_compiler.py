from __future__ import annotations

import importlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
REPORT_ID = "e1a-small-variant-report"


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


class Rpt02CompilerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = load_json(ROOT / "reporting" / "catalog.v1.json")
        self.sections = load_json(
            ROOT / "reporting" / "sections" / "e1a-small-variant-report.v1.json"
        )
        self.intended_use = load_json(
            ROOT / "reporting" / "intended-use" / "e1a-small-variant-report.v1.json"
        )
        self.capability = load_json(
            ROOT / "reporting" / "capabilities" / "e1a-small-variant-report.v1.json"
        )
        self.interpretation = {
            "identity": {"sample_id": "SYNTHETIC-001"},
            "items": [],
            "conflicts": [],
            "limitations": ["Synthetic fixture only"],
            "provenance": [{"source_id": "synthetic"}],
        }

    def compile(self, **overrides):
        module = importlib.import_module("reporting.compiler")
        values = {
            "report_id": REPORT_ID,
            "catalog": self.catalog,
            "section_contracts": self.sections,
            "intended_use": self.intended_use,
            "report_capability_manifest": self.capability,
            "canonical_interpretation": self.interpretation,
        }
        values.update(overrides)
        return module.compile_report_pack(**values)

    def test_compiles_deterministic_section_payloads_in_contract_order(self):
        result = self.compile()
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(result.report_id, REPORT_ID)
        self.assertEqual(
            [section["section_id"] for section in result.sections],
            [
                "identity-and-provenance",
                "verified-source-interpretations",
                "unresolved-evidence-conflicts",
                "limitations-and-not-assessed",
                "sources-and-versioning",
            ],
        )
        self.assertIsInstance(result.pack_sha256, str)
        self.assertEqual(len(result.pack_sha256), 64)

    def test_empty_states_are_explicit_and_never_silently_omitted(self):
        result = self.compile()
        by_id = {section["section_id"]: section for section in result.sections}
        self.assertEqual(
            by_id["verified-source-interpretations"]["state"],
            "EXPLICIT_NONE",
        )
        self.assertEqual(
            by_id["unresolved-evidence-conflicts"]["state"],
            "EXPLICIT_NO_CONFLICTS",
        )
        self.assertEqual(len(result.sections), 5)

    def test_missing_required_semantic_input_fails_closed(self):
        bad = dict(self.interpretation)
        bad.pop("identity")
        result = self.compile(canonical_interpretation=bad)
        self.assertFalse(result.passed)
        self.assertIn("missing_required_semantic_input", result.errors)

    def test_unknown_interpretation_field_is_not_projected_into_pack(self):
        enriched = dict(self.interpretation)
        enriched["untrusted_extra"] = {"secret": "must-not-appear"}
        result = self.compile(canonical_interpretation=enriched)
        serialized = json.dumps(result.to_dict(), sort_keys=True)
        self.assertNotIn("untrusted_extra", serialized)
        self.assertNotIn("must-not-appear", serialized)

    def test_compiler_does_not_render_localize_or_release(self):
        result = self.compile()
        serialized = json.dumps(result.to_dict(), sort_keys=True).lower()
        for forbidden in (
            "presentation_ir",
            "renderer_id",
            "pdf",
            "html",
            "release_bundle",
            "locale_id",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_compilation_is_deterministic(self):
        first = self.compile().to_dict()
        second = self.compile().to_dict()
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
