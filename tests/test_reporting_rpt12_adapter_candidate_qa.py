"""Verify candidate QA at the native generated-PDF creation boundary."""

from __future__ import annotations

from collections import UserDict
from copy import copy, deepcopy
from dataclasses import replace
from io import BytesIO
import hashlib
import json
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
import unittest
from unittest.mock import patch

from reporting import adapters, compiler, localization, presentation, viewmodel
from reporting import pdf_candidate_qa as qa
from reporting.pdf_candidate_qa import PROFILE_ID

ROOT = Path(__file__).resolve().parents[1]


def native_localization():
    """Use the existing synthetic report pack through its actual native stages."""
    def load(relative):
        return json.loads((ROOT / relative).read_text(encoding="utf-8"))

    compiled = compiler.compile_report_pack(
        report_id="e1a-small-variant-report",
        catalog=load("reporting/catalog.v1.json"),
        section_contracts=load("reporting/sections/e1a-small-variant-report.v1.json"),
        intended_use=load("reporting/intended-use/e1a-small-variant-report.v1.json"),
        report_capability_manifest=load("reporting/capabilities/e1a-small-variant-report.v1.json"),
        canonical_interpretation={
            "identity": {"sample_id": "SYNTHETIC-001"},
            "items": [], "conflicts": [],
            "limitations": ["Synthetic fixture only"],
            "provenance": [{"source_id": "synthetic"}],
        },
    )
    model = viewmodel.build_report_view_model_and_release_bundle(
        compiled_report_pack=compiled,
        artifact_ids=["canonical-interpretation:synthetic-001"],
    )
    ir = presentation.build_presentation_ir(
        report_view_model=model.view_model,
    ).to_dict()["presentation_ir"]
    return localization.localize_presentation_ir(presentation_ir=ir, locale_id="en-US")


def canonical_digest(value):
    """Calculate the source identity independently of the adapter and QA."""
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")).hexdigest()


class AdapterCandidateQAIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.localized = native_localization()
        if not cls.localized.passed:
            raise AssertionError(cls.localized.errors)
        cls.ir = cls.localized.to_dict()["localized_ir"]
        cls.good = adapters.build_html_css_and_pdf_adapter(presentation_ir=cls.ir)
        if not cls.good.passed:
            raise AssertionError(cls.good.errors)
        cls.good_qa = qa.validate_pdf_candidate_qa(
            presentation_ir=cls.ir, expected_ir_sha256=canonical_digest(cls.ir),
            pdf_bytes=cls.good.pdf_bytes, expected_pdf_sha256=cls.good.pdf_sha256,
        )
        if not cls.good_qa.passed:
            raise AssertionError(cls.good_qa.errors)

    def test_native_report_requires_all_real_candidate_qa_gates(self):
        with patch.object(adapters, "_render_pdf", wraps=adapters._render_pdf) as render:
            result = adapters.build_html_css_and_pdf_adapter(presentation_ir=self.ir)
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(render.call_count, 1)
        self.assertIn("pdf_candidate_qa", result.conformance)
        qa = result.conformance["pdf_candidate_qa"]
        self.assertEqual(qa["profile_id"], PROFILE_ID)
        self.assertEqual(qa["status"], "PASS")
        self.assertEqual(list(qa["gates"]), [
            "identity_preflight", "object_safety", "controlled_metadata",
            "accessibility_prerequisites", "text_content", "visual_geometry",
        ])
        self.assertTrue(all(gate["status"] == "PASS" for gate in qa["gates"].values()))
        self.assertEqual(qa["ir_sha256"], self.localized.localized_ir_sha256)
        self.assertEqual(qa["ir_sha256"], canonical_digest(self.ir))
        self.assertEqual(qa["pdf_sha256"], hashlib.sha256(result.pdf_bytes).hexdigest())
        self.assertEqual(qa["pdf_sha256"], result.pdf_sha256)
        self.assertEqual(result.conformance["presentation_ir_sha256"], qa["ir_sha256"])
        self.assertEqual(qa["release_authorization"], "NOT_ESTABLISHED")
        self.assertEqual(result.conformance["release_authorization"], "NOT_ESTABLISHED")

    def assert_rejected(self, result, reason):
        self.assertFalse(result.passed)
        self.assertEqual(result.pdf_status, "DISABLED")
        self.assertEqual(result.pdf_reason, reason)
        self.assertEqual(result.errors, (reason,))
        self.assertIsNone(result.pdf_bytes)
        self.assertIsNone(result.pdf_sha256)
        self.assertIsNone(result.conformance)
        self.assertTrue(result.html.startswith("<!doctype html>"))
        self.assertEqual(result.html_sha256, hashlib.sha256(result.html.encode()).hexdigest())
        record = result.to_dict()
        self.assertIsNone(record["pdf_sha256"])
        self.assertIsNone(record["conformance"])
        self.assertNotIn("pdf_bytes", record)

    def test_structural_mapping_wrappers_preserve_native_identity(self):
        components = deepcopy(self.ir)
        components["components"] = [UserDict(component) for component in components["components"]]
        for source in (MappingProxyType(self.ir), components, UserDict(components)):
            with (
                self.subTest(wrapper=type(source).__name__),
                patch.object(adapters, "_render_pdf", return_value=self.good.pdf_bytes),
                patch.object(adapters, "validate_pdf_candidate_qa", wraps=qa.validate_pdf_candidate_qa) as validate,
            ):
                result = adapters.build_html_css_and_pdf_adapter(presentation_ir=source)
            self.assertTrue(result.passed, result.errors)
            self.assertEqual(result.html, self.good.html)
            self.assertEqual(result.conformance["presentation_ir_sha256"], canonical_digest(self.ir))
            captured = validate.call_args.kwargs["presentation_ir"]
            self.assertIs(type(captured), dict)
            self.assertTrue(all(type(component) is dict for component in captured["components"]))
            self.assertEqual(captured, self.ir)

    def test_caller_mutation_during_render_cannot_change_captured_input(self):
        source = deepcopy(self.ir)
        expected = deepcopy(source)

        def render_once(html, html_sha256):
            source["report_id"] = "SYNTHETIC-AFTER-CAPTURE"
            source["components"][0]["content"]["changed"] = True
            return self.good.pdf_bytes

        with (
            patch.object(adapters, "_render_pdf", side_effect=render_once) as render,
            patch.object(adapters, "validate_pdf_candidate_qa", wraps=qa.validate_pdf_candidate_qa) as validate,
        ):
            result = adapters.build_html_css_and_pdf_adapter(presentation_ir=source)
        self.assertTrue(result.passed, result.errors)
        render.assert_called_once()
        validate.assert_called_once()
        values = validate.call_args.kwargs
        self.assertIsNot(values["presentation_ir"], source)
        self.assertEqual(values["presentation_ir"], expected)
        self.assertEqual(values["expected_ir_sha256"], canonical_digest(expected))
        self.assertIs(values["pdf_bytes"], self.good.pdf_bytes)
        self.assertEqual(values["expected_pdf_sha256"], hashlib.sha256(self.good.pdf_bytes).hexdigest())
        self.assertEqual(result.html, self.good.html)
        self.assertNotIn("SYNTHETIC-AFTER-CAPTURE", result.html)

    def test_invalid_or_unbounded_ir_stops_before_render(self):
        cycle = deepcopy(self.ir)
        cycle["cycle"] = cycle
        deep = deepcopy(self.ir)
        child = deep
        for _ in range(70):
            child["nested"] = {}
            child = child["nested"]
        oversized = deepcopy(self.ir)
        oversized["extra"] = "x" * (qa.MAX_PDF_BYTES + 1)
        non_string_key = deepcopy(self.ir)
        non_string_key["components"][0]["content"][1] = "not a JSON key"
        non_finite = deepcopy(self.ir)
        non_finite["components"][0]["content"]["number"] = float("nan")
        tuple_components = deepcopy(self.ir)
        tuple_components["components"] = tuple(tuple_components["components"])
        nested_mapping = deepcopy(self.ir)
        nested_mapping["components"][0]["content"] = UserDict({"text": "unsupported wrapper"})
        cases = {
            "cycle": cycle, "depth": deep, "bytes": oversized,
            "key": non_string_key, "non_finite": non_finite,
            "tuple_components": tuple_components, "nested_mapping": nested_mapping,
            "frozen_localization": self.localized.localized_ir,
        }
        for name, source in cases.items():
            with (
                self.subTest(case=name),
                patch.object(adapters, "_render_pdf") as render,
                patch.object(adapters, "validate_pdf_candidate_qa") as validate,
            ):
                result = adapters.build_html_css_and_pdf_adapter(presentation_ir=source)
            self.assertEqual(result.errors, ("presentation_ir_invalid",))
            self.assertIsNone(result.html)
            self.assertIsNone(result.pdf_bytes)
            render.assert_not_called()
            validate.assert_not_called()

    def test_mapping_exceptions_are_contained_before_render(self):
        class BrokenMapping(UserDict):
            def items(self):
                raise RuntimeError("SYNTHETIC-PRIVATE-MAPPING-ERROR")

        with patch.object(adapters, "_render_pdf") as render:
            result = adapters.build_html_css_and_pdf_adapter(presentation_ir=BrokenMapping(self.ir))
        self.assertEqual(result.errors, ("presentation_ir_invalid",))
        self.assertNotIn("SYNTHETIC-PRIVATE", json.dumps(result.to_dict()))
        render.assert_not_called()

    def test_underreported_mapping_iteration_is_bounded_before_snapshot(self):
        class UnderreportedMapping(UserDict):
            seen = 0

            def items(self):
                for number in range(100_000):
                    self.seen += 1
                    yield "field-" + str(number), None

        source = UnderreportedMapping()
        with (
            patch.object(adapters, "_MAX_JSON_NODES", 64),
            patch.object(adapters, "_snapshot_ir") as snapshot,
            patch.object(adapters, "_render_pdf") as render,
        ):
            result = adapters.build_html_css_and_pdf_adapter(presentation_ir=source)
        self.assertEqual(result.errors, ("presentation_ir_invalid",))
        self.assertLessEqual(source.seen, 32)
        snapshot.assert_not_called()
        render.assert_not_called()

    def test_oversized_mapping_key_stops_before_recursive_snapshot(self):
        class OversizedKeyMapping(UserDict):
            def items(self):
                yield from super().items()
                yield "x" * (qa.MAX_PDF_BYTES + 1), None

        with (
            patch.object(adapters, "_snapshot_ir") as snapshot,
            patch.object(adapters, "_render_pdf") as render,
        ):
            result = adapters.build_html_css_and_pdf_adapter(presentation_ir=OversizedKeyMapping(self.ir))
        self.assertEqual(result.errors, ("presentation_ir_invalid",))
        snapshot.assert_not_called()
        render.assert_not_called()

    def test_invalid_or_oversized_pdf_stops_before_legacy_parser(self):
        class BytesSubclass(bytes):
            pass

        candidates = [
            (bytearray(self.good.pdf_bytes), "pdf_engine_invalid_output"),
            (BytesSubclass(self.good.pdf_bytes), "pdf_engine_invalid_output"),
            (b"not a PDF", "pdf_engine_invalid_output"),
            (b"%PDF-1.7" + b"0" * qa.MAX_PDF_BYTES, "pdf_candidate_budget_exceeded"),
        ]
        for candidate, reason in candidates:
            with (
                self.subTest(kind=type(candidate).__name__, reason=reason),
                patch.object(adapters, "_render_pdf", return_value=candidate) as render,
                patch.object(adapters, "_validate_pdf_structure") as legacy,
                patch.object(adapters, "validate_pdf_candidate_qa") as validate,
            ):
                result = adapters.build_html_css_and_pdf_adapter(presentation_ir=self.ir)
            self.assert_rejected(result, reason)
            render.assert_called_once()
            legacy.assert_not_called()
            validate.assert_not_called()

    def test_render_failure_does_not_invoke_qa(self):
        with (
            patch.object(adapters, "_render_pdf", side_effect=RuntimeError("pdf_engine_unavailable")),
            patch.object(adapters, "validate_pdf_candidate_qa") as validate,
        ):
            result = adapters.build_html_css_and_pdf_adapter(presentation_ir=self.ir)
        self.assert_rejected(result, "pdf_engine_unavailable")
        validate.assert_not_called()

    def test_qa_exception_uses_fixed_error_without_disclosing_exception(self):
        with (
            patch.object(adapters, "_render_pdf", return_value=self.good.pdf_bytes),
            patch.object(adapters, "validate_pdf_candidate_qa",
                         side_effect=RuntimeError("SYNTHETIC-PRIVATE-QA-ERROR")),
        ):
            result = adapters.build_html_css_and_pdf_adapter(presentation_ir=self.ir)
        self.assert_rejected(result, "pdf_candidate_qa_failed")
        self.assertNotIn("SYNTHETIC-PRIVATE", json.dumps(result.to_dict()))

    def test_success_looking_untyped_or_subclassed_qa_results_are_rejected(self):
        class QAResultSubclass(qa.PdfCandidateQAValidation):
            pass

        subclass = QAResultSubclass(
            self.good_qa.pdf_sha256, self.good_qa.ir_sha256,
            self.good_qa.locale_id, self.good_qa.gates,
        )
        for value in (None, {}, SimpleNamespace(passed=True), subclass):
            with (
                self.subTest(kind=type(value).__name__),
                patch.object(adapters, "_render_pdf", return_value=self.good.pdf_bytes),
                patch.object(adapters, "validate_pdf_candidate_qa", return_value=value),
            ):
                result = adapters.build_html_css_and_pdf_adapter(presentation_ir=self.ir)
            self.assert_rejected(result, "pdf_candidate_qa_invalid_result")

    def test_independently_hashed_inputs_reject_stale_typed_qa_identities(self):
        for field, original in (
            ("pdf_sha256", self.good_qa.pdf_sha256),
            ("ir_sha256", self.good_qa.ir_sha256),
        ):
            replacement = "0" * 64
            gates = tuple(replace(gate, evidence=tuple(
                (key, replacement if value == original else value)
                for key, value in gate.evidence
            )) for gate in self.good_qa.gates)
            stale = replace(self.good_qa, gates=gates, **{field: replacement})
            self.assertTrue(stale.passed)
            with (
                self.subTest(field=field),
                patch.object(adapters, "_render_pdf", return_value=self.good.pdf_bytes),
                patch.object(adapters, "validate_pdf_candidate_qa", return_value=stale),
            ):
                result = adapters.build_html_css_and_pdf_adapter(presentation_ir=self.ir)
            self.assert_rejected(result, "pdf_candidate_qa_invalid_result")

    def test_forged_nested_qa_protocol_cannot_publish_success_or_private_errors(self):
        gate = self.good_qa.gates[0]
        corruptions = [
            ("errors", ("SYNTHETIC-PRIVATE-GATE-ERROR",)),
            ("errors", ["qa_validator_exception"]),
            ("evidence", list(gate.evidence)),
            ("evidence", gate.evidence + gate.evidence + gate.evidence),
        ]
        for field, value in corruptions:
            malformed_gate = copy(gate)
            object.__setattr__(malformed_gate, field, value)
            malformed = copy(self.good_qa)
            object.__setattr__(malformed, "gates", (malformed_gate,) + self.good_qa.gates[1:])
            with (
                self.subTest(field=field, kind=type(value).__name__),
                patch.object(adapters, "_render_pdf", return_value=self.good.pdf_bytes),
                patch.object(adapters, "validate_pdf_candidate_qa", return_value=malformed),
            ):
                result = adapters.build_html_css_and_pdf_adapter(presentation_ir=self.ir)
            self.assert_rejected(result, "pdf_candidate_qa_invalid_result")
            self.assertNotIn("SYNTHETIC-PRIVATE", json.dumps(result.to_dict()))

    def test_hostile_qa_containers_are_rejected_without_iteration(self):
        class UntrustedIterable:
            iterated = False

            def __iter__(self):
                self.iterated = True
                raise AssertionError("untrusted evidence must not be consumed")

        for field in ("gates", "evidence", "errors"):
            value = UntrustedIterable()
            malformed = copy(self.good_qa)
            if field == "gates":
                object.__setattr__(malformed, field, value)
            else:
                gate = copy(self.good_qa.gates[0])
                object.__setattr__(gate, field, value)
                object.__setattr__(malformed, "gates", (gate,) + self.good_qa.gates[1:])
            with (
                self.subTest(field=field),
                patch.object(adapters, "_render_pdf", return_value=self.good.pdf_bytes),
                patch.object(adapters, "validate_pdf_candidate_qa", return_value=malformed),
            ):
                result = adapters.build_html_css_and_pdf_adapter(presentation_ir=self.ir)
            self.assert_rejected(result, "pdf_candidate_qa_invalid_result")
            self.assertFalse(value.iterated)

    def test_real_candidate_failures_withhold_artifacts_after_legacy_validation(self):
        from pypdf import PdfWriter
        from pypdf.generic import DictionaryObject, NameObject, RectangleObject

        def modified(change):
            writer = PdfWriter(clone_from=BytesIO(self.good.pdf_bytes))
            writer.pdf_header = self.good.pdf_bytes.splitlines()[0]
            change(writer)
            output = BytesIO()
            writer.write(output)
            return output.getvalue()

        def active(writer):
            writer.root_object[NameObject("/OpenAction")] = DictionaryObject()

        def large_page(writer):
            writer.pages[0][NameObject("/MediaBox")] = RectangleObject((0, 0, 20000, 20000))

        altered = deepcopy(self.ir)
        altered["components"][0]["content"]["changed"] = True
        cases = [
            ("object_safety", self.ir, modified(active)),
            ("text_content", altered, self.good.pdf_bytes),
            ("visual_geometry", self.ir, modified(large_page)),
        ]
        for stage, ir, pdf in cases:
            # Each fixture passes the old boundary and fails a new real QA gate.
            adapters._validate_pdf_structure(pdf, expected_language="en-US")
            observations = []

            def validate(**values):
                result = qa.validate_pdf_candidate_qa(**values)
                observations.append(result)
                return result

            with (
                self.subTest(stage=stage),
                patch.object(adapters, "_render_pdf", return_value=pdf) as render,
                patch.object(adapters, "validate_pdf_candidate_qa", side_effect=validate) as conjunction,
            ):
                result = adapters.build_html_css_and_pdf_adapter(presentation_ir=ir)
            self.assert_rejected(result, "pdf_candidate_qa_blocked")
            render.assert_called_once()
            conjunction.assert_called_once()
            self.assertIs(conjunction.call_args.kwargs["pdf_bytes"], pdf)
            gates = observations[0].to_dict()["gates"]
            blocked = [name for name, gate in gates.items() if gate["status"] == "BLOCKED"]
            self.assertEqual(blocked, [stage])

    def test_serialized_success_conformance_is_detached_and_content_free(self):
        record = self.good.to_dict()
        evidence = record["conformance"]["pdf_candidate_qa"]
        self.assertNotIn("SYNTHETIC-001", json.dumps(evidence))
        evidence["gates"]["object_safety"]["errors"].append("changed")
        evidence["limitations"].clear()
        self.assertEqual(self.good.conformance["pdf_candidate_qa"]["gates"]["object_safety"]["errors"], [])
        self.assertTrue(self.good.conformance["pdf_candidate_qa"]["limitations"])


if __name__ == "__main__":
    unittest.main()
