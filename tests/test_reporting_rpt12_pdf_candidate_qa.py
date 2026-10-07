"""Acceptance checks for one immutable generated PDF and its exact presentation."""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
from copy import copy, deepcopy
from dataclasses import FrozenInstanceError, replace
from decimal import Decimal
from io import BytesIO
import math
import hashlib
import json
import unittest
from unittest.mock import patch

from reporting.adapters import build_html_css_and_pdf_adapter
from reporting import pdf_candidate_qa as qa
from reporting.pdf_candidate_qa import validate_pdf_candidate_qa


def presentation():
    """Return only synthetic content with identifiable redaction markers."""
    return {
        "report_id": "SYNTHETIC-PRIVATE-CANDIDATE-ID",
        "locale_id": "en-US",
        "components": [{
            "component_type": "semantic-section",
            "component_id": "summary",
            "title": "Synthetic summary",
            "state": "PRESENT",
            "content": {"text": "SYNTHETIC-PRIVATE-CONTENT", "value": 42},
        }],
    }


def digest_ir(ir):
    """Compute the independently specified canonical JSON input identity."""
    canonical = json.dumps(
        ir, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


STEPS = (
    ("object_safety", "validate_pdf_object_safety"),
    ("controlled_metadata", "validate_pdf_candidate"),
    ("accessibility_prerequisites", "validate_pdf_accessibility_structure"),
    ("text_content", "validate_pdf_text_content"),
    ("visual_geometry", "validate_pdf_visual_geometry"),
)
STAGE_NAMES = ("identity_preflight",) + tuple(name for name, _ in STEPS)


def changed_result(result, **changes):
    """Simulate a malformed future child protocol, including constructor bypass."""
    modified = copy(result)
    for field, value in changes.items():
        object.__setattr__(modified, field, value)
    return modified


def modified_pdf(pdf, change):
    """Rewrite only the selected synthetic PDF surface."""
    from pypdf import PdfWriter

    writer = PdfWriter(clone_from=BytesIO(pdf))
    writer.pdf_header = pdf.splitlines()[0]
    change(writer)
    output = BytesIO()
    writer.write(output)
    return output.getvalue()


class PdfCandidateQAAcceptanceTests(unittest.TestCase):
    """Use a native candidate to exercise the complete public entrypoint."""

    @classmethod
    def setUpClass(cls):
        """Build the shared synthetic candidate through the pinned renderer."""
        cls.ir = presentation()
        rendered = build_html_css_and_pdf_adapter(presentation_ir=cls.ir)
        if not rendered.passed:
            raise AssertionError(rendered.errors)
        cls.pdf = rendered.pdf_bytes
        cls.pdf_sha256 = hashlib.sha256(cls.pdf).hexdigest()
        cls.ir_sha256 = digest_ir(cls.ir)
        cls.native_results = {
            "object_safety": qa.validate_pdf_object_safety(
                pdf_bytes=cls.pdf, expected_pdf_sha256=cls.pdf_sha256,
            ),
            "controlled_metadata": qa.validate_pdf_candidate(
                pdf_bytes=cls.pdf, expected_pdf_sha256=cls.pdf_sha256,
                expected_author="Hudson Silva Andrade", expected_language="en-US",
                metadata_profile="omnigenis-generated-pdf-metadata-v1",
            ),
            "accessibility_prerequisites": qa.validate_pdf_accessibility_structure(
                pdf_bytes=cls.pdf, expected_language="en-US",
            ),
            "text_content": qa.validate_pdf_text_content(
                presentation_ir=cls.ir, expected_ir_sha256=cls.ir_sha256,
                pdf_bytes=cls.pdf, expected_pdf_sha256=cls.pdf_sha256,
            ),
            "visual_geometry": qa.validate_pdf_visual_geometry(
                pdf_bytes=cls.pdf, expected_pdf_sha256=cls.pdf_sha256,
            ),
        }
        if not all(result.passed for result in cls.native_results.values()):
            raise AssertionError("native candidate fixture failed a required validator")

    def validate(self, **overrides):
        """Invoke the public seam with an exact independently hashed candidate."""
        values = {
            "presentation_ir": deepcopy(self.ir),
            "expected_ir_sha256": self.ir_sha256,
            "pdf_bytes": self.pdf,
            "expected_pdf_sha256": self.pdf_sha256,
        }
        values.update(overrides)
        return validate_pdf_candidate_qa(**values)

    def test_native_candidate_passes_all_five_required_validators(self):
        """Require the real validators, consistent identities and no release promotion."""
        result = self.validate()
        self.assertTrue(result.passed, result.errors)
        record = result.to_dict()
        self.assertEqual(record["status"], "PASS")
        self.assertEqual(record["pdf_sha256"], self.pdf_sha256)
        self.assertEqual(record["ir_sha256"], self.ir_sha256)
        self.assertEqual(record["locale_id"], "en-US")
        self.assertEqual(record["page_count"], 1)
        self.assertEqual(record["release_authorization"], "NOT_ESTABLISHED")
        self.assertEqual(list(record["gates"]), [
            "identity_preflight", "object_safety", "controlled_metadata",
            "accessibility_prerequisites", "text_content", "visual_geometry",
        ])
        self.assertTrue(all(g["status"] == "PASS" for g in record["gates"].values()))


    @contextmanager
    def children(self, replacements=None, *, real=False):
        """Replace only collaboration boundaries, or observe the real validators."""
        replacements = replacements or {}
        with ExitStack() as stack:
            mocks = {}
            for stage, name in STEPS:
                if stage in replacements:
                    options = {"return_value": replacements[stage]}
                elif real:
                    options = {"wraps": getattr(qa, name)}
                else:
                    options = {"return_value": self.native_results[stage]}
                mocks[stage] = stack.enter_context(patch.object(qa, name, **options))
            yield mocks

    def assert_stopped(self, result, stage, mocks=None, error=None):
        """Require one blocked stage, completed predecessors and untouched successors."""
        self.assertFalse(result.passed)
        record = result.to_dict()
        self.assertEqual(record["release_authorization"], "NOT_ESTABLISHED")
        self.assertIsNone(record["page_count"])
        index = STAGE_NAMES.index(stage)
        for number, name in enumerate(STAGE_NAMES):
            gate = record["gates"][name]
            self.assertEqual(gate["status"], (
                "PASS" if number < index else "BLOCKED" if number == index else "NOT_EXECUTED"
            ))
            if number >= index:
                self.assertIsNone(gate["evidence"])
            if number > index:
                self.assertEqual(gate["errors"], [])
            if mocks is not None and name != "identity_preflight":
                if number <= index:
                    mocks[name].assert_called_once()
                else:
                    mocks[name].assert_not_called()
        if error is not None:
            self.assertEqual(record["gates"][stage]["errors"], [error])

    def preflight(self, ir, expected_digest=None):
        """Prove preflight acceptance without parsing a large boundary fixture."""
        rejected = changed_result(
            self.native_results["object_safety"], page_count=None, object_count=None,
            errors=("pdf_actions_forbidden",),
        )
        with self.children({"object_safety": rejected}) as mocks:
            result = self.validate(
                presentation_ir=ir,
                expected_ir_sha256=digest_ir(ir) if expected_digest is None else expected_digest,
            )
            stage = "object_safety" if result.to_dict()["gates"]["identity_preflight"]["status"] == "PASS" else "identity_preflight"
            self.assert_stopped(result, stage, mocks)
        return result

    def test_fixed_order_and_same_byte_invocation(self):
        """Observe each real call and the explicitly invocation-bound accessibility record."""
        original = deepcopy(self.ir)
        order = []
        with self.children(real=True) as mocks:
            for stage, mock in mocks.items():
                function = mock._mock_wraps

                def observe(*, _stage=stage, _function=function, **kwargs):
                    order.append(_stage)
                    return _function(**kwargs)

                mock.side_effect = observe
            result = self.validate(presentation_ir=original)
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(order, list(STAGE_NAMES[1:]))
        for mock in mocks.values():
            self.assertIs(mock.call_args.kwargs["pdf_bytes"], self.pdf)
        snapshot = mocks["text_content"].call_args.kwargs["presentation_ir"]
        self.assertIsNot(snapshot, original)
        self.assertEqual(snapshot, original)
        self.assertEqual(original, self.ir)
        evidence = result.to_dict()["gates"]["accessibility_prerequisites"]["evidence"]
        self.assertEqual(evidence["identity_binding"], "ENTRYPOINT_INVOCATION")
        self.assertEqual(evidence["invocation_pdf_sha256"], self.pdf_sha256)
        self.assertNotIn("pdf_sha256", evidence)
        self.assertNotIn("page_count", evidence)

    def test_invalid_expected_identities_stop_before_validators(self):
        """Missing, noncanonical and mismatched digests never reach a PDF validator."""
        cases = (
            ({"expected_pdf_sha256": None}, "qa_expected_pdf_digest_invalid"),
            ({"expected_pdf_sha256": "A" * 64}, "qa_expected_pdf_digest_invalid"),
            ({"expected_pdf_sha256": "0" * 64}, "qa_pdf_digest_mismatch"),
            ({"expected_pdf_sha256": self.pdf_sha256 + "\n"}, "qa_expected_pdf_digest_invalid"),
            ({"expected_ir_sha256": None}, "qa_expected_ir_digest_invalid"),
            ({"expected_ir_sha256": "invalid"}, "qa_expected_ir_digest_invalid"),
            ({"expected_ir_sha256": "0" * 64}, "qa_ir_digest_mismatch"),
            ({"expected_ir_sha256": self.ir_sha256.upper()}, "qa_expected_ir_digest_invalid"),
        )
        for values, error in cases:
            with self.subTest(fields=tuple(values)), self.children() as mocks:
                result = self.validate(**values)
                self.assert_stopped(result, "identity_preflight", mocks, error)
                self.assertIsNone(result.pdf_sha256)
                self.assertIsNone(result.ir_sha256)

    def test_mutable_or_invalid_pdf_input_is_rejected_before_validators(self):
        """The shared candidate must be immutable native bytes within its byte budget."""
        class BytesSubclass(bytes):
            pass

        for pdf in (None, bytearray(self.pdf), memoryview(self.pdf), BytesSubclass(self.pdf),
                    b"invalid", b"%PDF-" + b" " * (8 * 1024 * 1024)):
            with self.subTest(kind=type(pdf).__name__), self.children() as mocks:
                result = self.validate(pdf_bytes=pdf)
                self.assert_stopped(
                    result, "identity_preflight", mocks,
                    "qa_input_budget_exceeded" if type(pdf) is bytes and len(pdf) > 8 * 1024 * 1024
                    else "qa_pdf_bytes_invalid",
                )

    def test_invalid_ir_types_and_values_stop_before_validators(self):
        """Reject lossy conversion, unsupported native types and malformed Unicode."""
        class DictSubclass(dict):
            pass

        class StringSubclass(str):
            pass

        class ListSubclass(list):
            pass

        class IntSubclass(int):
            pass

        invalid = (
            (), [], DictSubclass(self.ir),
            {**self.ir, 1: "non-string-key"},
            {**self.ir, "extra": (1, 2)},
            {**self.ir, "extra": {1}},
            {**self.ir, "extra": b"bytes"},
            {**self.ir, "extra": Decimal("1.0")},
            {**self.ir, "extra": StringSubclass("text")},
            {**self.ir, "extra": ListSubclass([1])},
            {**self.ir, "extra": IntSubclass(1)},
            {**self.ir, "extra": float("nan")},
            {**self.ir, "extra": float("inf")},
            {**self.ir, "extra": -float("inf")},
            {**self.ir, "extra": "\ud800"},
        )
        for number, ir in enumerate(invalid):
            with self.subTest(case=number), self.children() as mocks:
                result = self.validate(presentation_ir=ir)
                self.assert_stopped(result, "identity_preflight", mocks, "qa_presentation_ir_invalid")

    def test_schema_and_unactivated_locales_fail_preflight(self):
        """Reuse the content input contract and keep the conjunction limited to en-US."""
        invalid = (
            {**self.ir, "locale_id": "pt-BR"},
            {**self.ir, "locale_id": "en-us"},
            {**self.ir, "locale_id": None},
            {**self.ir, "components": []},
            {**self.ir, "report_id": ""},
            {**self.ir, "components": [self.ir["components"][0]] * 2},
        )
        for number, ir in enumerate(invalid):
            with self.subTest(case=number), self.children() as mocks:
                result = self.validate(presentation_ir=ir, expected_ir_sha256=digest_ir(ir))
                self.assert_stopped(
                    result, "identity_preflight", mocks,
                    "qa_locale_unsupported" if number < 3 else "qa_presentation_ir_invalid",
                )

    def test_lossless_scalar_types_and_key_order_are_preserved(self):
        """Canonicalization preserves numeric distinctions and unnormalized Unicode."""
        ir = deepcopy(self.ir)
        ir["extra"] = {
            "boolean": True, "integer": 1, "float": 1.0, "negative_zero": -0.0,
            "unicode": "e\u0301 \u00e9", "escaped": "\"\\\n",
        }
        reordered = dict(reversed(list(ir.items())))
        reordered["extra"] = dict(reversed(list(ir["extra"].items())))
        self.assertEqual(digest_ir(ir), digest_ir(reordered))
        with self.children() as mocks:
            mocks["text_content"].return_value = changed_result(
                self.native_results["text_content"], ir_sha256=digest_ir(ir),
            )
            result = self.validate(presentation_ir=reordered, expected_ir_sha256=digest_ir(ir))
        self.assertTrue(result.passed, result.errors)
        copied = mocks["text_content"].call_args.kwargs["presentation_ir"]["extra"]
        self.assertIs(type(copied["boolean"]), bool)
        self.assertIs(type(copied["integer"]), int)
        self.assertIs(type(copied["float"]), float)
        self.assertEqual(math.copysign(1, copied["negative_zero"]), -1)
        self.assertEqual(copied["unicode"], ir["extra"]["unicode"])
        self.assertNotEqual(digest_ir({"x": True}), digest_ir({"x": 1}))
        self.assertNotEqual(digest_ir({"x": 1}), digest_ir({"x": 1.0}))

    def test_aliases_are_accepted_but_direct_and_indirect_cycles_fail(self):
        """Charge repeated acyclic values while recognizing only active-path cycles."""
        alias = {"value": [1, True]}
        ir = {**self.ir, "extra": [alias, alias]}
        self.assertEqual(self.preflight(ir).to_dict()["gates"]["identity_preflight"]["status"], "PASS")
        direct = []
        direct.append(direct)
        left, right = [], []
        left.append(right)
        right.append(left)
        for cycle in (direct, left):
            with self.subTest(kind="cycle"):
                result = self.preflight({**self.ir, "extra": cycle}, self.ir_sha256)
                self.assertEqual(result.errors, ("qa_presentation_ir_invalid",))

    def test_shared_graph_expansion_consumes_the_node_budget(self):
        """A small aliased graph cannot bypass the expanded-occurrence limit."""
        value = []
        for _ in range(17):
            value = [value, value]
        result = self.preflight({**self.ir, "extra": value}, self.ir_sha256)
        self.assertEqual(result.errors, ("qa_input_budget_exceeded",))

    def test_json_depth_boundary_and_one_over(self):
        """Accept the declared depth and reject the first deeper value."""
        for depth, expected in ((63, "PASS"), (64, "BLOCKED")):
            value = None
            for _ in range(depth):
                value = [value]
            result = self.preflight({**self.ir, "extra": value})
            self.assertEqual(result.to_dict()["gates"]["identity_preflight"]["status"], expected)

    def test_expanded_node_boundary_and_one_over(self):
        """The fixture plus its extra key and list accounts for 24 base nodes."""
        for count, expected in ((99_976, "PASS"), (99_977, "BLOCKED")):
            result = self.preflight({**self.ir, "extra": [None] * count})
            self.assertEqual(result.to_dict()["gates"]["identity_preflight"]["status"], expected)

    def test_integer_magnitude_boundary_and_one_over(self):
        """Bound conversion without changing the interpreter's integer limits."""
        for value, expected in (((1 << 4096) - 1, "PASS"), (1 << 4096, "BLOCKED")):
            result = self.preflight({**self.ir, "extra": value})
            self.assertEqual(result.to_dict()["gates"]["identity_preflight"]["status"], expected)

    def test_exact_canonical_byte_budget_includes_utf8_and_json_escapes(self):
        """Accept 8 MiB of canonical bytes and reject an added byte for each encoding."""
        limit = 8 * 1024 * 1024
        ir = {**self.ir, "extra": ""}
        overhead = len(json.dumps(
            ir, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
        ).encode("utf-8"))
        available = limit - overhead
        for scalar, width in (("x", 1), ("\u00e9", 2), ("\\", 2)):
            with self.subTest(width=width, escaped=scalar == "\\"):
                payload = scalar * (available // width) + "x" * (available % width)
                result = self.preflight({**self.ir, "extra": payload})
                self.assertEqual(result.to_dict()["gates"]["identity_preflight"]["status"], "PASS")
                result = self.preflight({**self.ir, "extra": payload + "x"})
                self.assertEqual(result.errors, ("qa_input_budget_exceeded",))

    def test_oversized_scalar_stops_before_json_encoding(self):
        """The traversal rejects excessive scalar size before allocating encoded JSON."""
        with patch.object(qa.json.JSONEncoder, "iterencode") as encoder, self.children() as mocks:
            result = self.validate(presentation_ir={**self.ir, "extra": "x" * (8 * 1024 * 1024 + 1)})
            self.assert_stopped(result, "identity_preflight", mocks)
            encoder.assert_not_called()

    def test_each_real_child_failure_stops_the_remaining_sequence(self):
        """Use actual PDF/IR changes, leaving all earlier real gates in place."""
        from pypdf.generic import DictionaryObject, NameObject, RectangleObject

        def active(writer):
            writer.root_object[NameObject("/OpenAction")] = DictionaryObject()

        def metadata(writer):
            info = dict(writer.metadata)
            info["/Title"] = "SYNTHETIC-PRIVATE-METADATA"
            writer.metadata = info

        def accessibility(writer):
            del writer.root_object[NameObject("/MarkInfo")]

        def visual(writer):
            writer.pages[0][NameObject("/MediaBox")] = RectangleObject((0, 0, 20000, 20000))

        altered_ir = deepcopy(self.ir)
        altered_ir["components"][0]["content"]["value"] = 43
        cases = (
            ("object_safety", modified_pdf(self.pdf, active), self.ir),
            ("controlled_metadata", modified_pdf(self.pdf, metadata), self.ir),
            ("accessibility_prerequisites", modified_pdf(self.pdf, accessibility), self.ir),
            ("text_content", self.pdf, altered_ir),
            ("visual_geometry", modified_pdf(self.pdf, visual), self.ir),
        )
        for stage, pdf, ir in cases:
            with self.subTest(stage=stage), self.children(real=True) as mocks:
                result = self.validate(
                    presentation_ir=ir, expected_ir_sha256=digest_ir(ir),
                    pdf_bytes=pdf, expected_pdf_sha256=hashlib.sha256(pdf).hexdigest(),
                )
                self.assert_stopped(result, stage, mocks, "qa_child_validation_failed")
                self.assertNotIn("SYNTHETIC-PRIVATE-METADATA", repr(result))
                self.assertNotIn("SYNTHETIC-PRIVATE-METADATA", json.dumps(result.to_dict()))

    def test_missing_swapped_mapping_and_subclass_results_cannot_pass(self):
        """A passed property is insufficient without the exact child result type."""
        class SafetySubclass(qa.PdfSafetyValidation):
            pass

        result = self.native_results["object_safety"]
        subclass = SafetySubclass(result.pdf_sha256, result.page_count, result.object_count, ())
        for malformed in (None, {}, {"passed": True}, object(),
                          self.native_results["controlled_metadata"], subclass):
            with self.subTest(kind=type(malformed).__name__), self.children({"object_safety": malformed}) as mocks:
                result = self.validate()
                self.assert_stopped(result, "object_safety", mocks, "qa_validator_result_invalid")

    def test_success_looking_child_evidence_must_match_the_candidate(self):
        """Reject stale identities, missing fields, incorrect types and contradictory profiles."""
        cases = (
            ("object_safety", {"pdf_sha256": "0" * 64}),
            ("object_safety", {"pdf_sha256": None}),
            ("object_safety", {"page_count": True}),
            ("object_safety", {"page_count": 0}),
            ("object_safety", {"page_count": 33}),
            ("object_safety", {"object_count": True}),
            ("object_safety", {"object_count": 20_001}),
            ("controlled_metadata", {"page_count": 2}),
            ("controlled_metadata", {"page_count": None}),
            ("controlled_metadata", {"metadata_profile_id": None}),
            ("controlled_metadata", {"metadata_profile_id": "unrelated-profile"}),
            ("controlled_metadata", {"accessibility_prerequisites": "BLOCKED"}),
            ("controlled_metadata", {"metadata": {}}),
            ("controlled_metadata", {"metadata": {
                **dict(self.native_results["controlled_metadata"].metadata), "/Subject": "SYNTHETIC-PRIVATE-EXTRA",
            }}),
            ("controlled_metadata", {"metadata": {
                **dict(self.native_results["controlled_metadata"].metadata), "/Producer": "Unexpected",
            }}),
            ("accessibility_prerequisites", {"language": "SYNTHETIC-PRIVATE-LANGUAGE"}),
            ("accessibility_prerequisites", {"marked": 1}),
            ("accessibility_prerequisites", {"struct_tree_root": 1}),
            ("accessibility_prerequisites", {"conformance_claim": "FULL_PDF_UA"}),
            ("text_content", {"ir_sha256": "0" * 64}),
            ("text_content", {"ir_sha256": None}),
            ("text_content", {"page_count": 2}),
            ("text_content", {"expected_text_sha256": "0" * 64, "extracted_text_sha256": "0" * 64}),
            ("text_content", {"extracted_text_sha256": None}),
            ("visual_geometry", {"page_count": 2}),
            ("visual_geometry", {"raster_sha256": None}),
            ("visual_geometry", {"min_edge_margin_px": 1}),
            ("visual_geometry", {"min_edge_margin_px": 10 ** 100}),
            ("visual_geometry", {"total_pixels": True}),
            ("visual_geometry", {"total_pixels": 1}),
            ("visual_geometry", {"total_pixels": 4_000_001}),
            ("visual_geometry", {"min_edge_margin_px": 999, "total_pixels": 3_996_000}),
        )
        for stage, values in cases:
            malformed = changed_result(self.native_results[stage], **values)
            with self.subTest(stage=stage, fields=tuple(values)), self.children({stage: malformed}) as mocks:
                result = self.validate()
                self.assert_stopped(result, stage, mocks, "qa_validator_result_invalid")
                self.assertNotIn("SYNTHETIC-PRIVATE", repr(result))

    def test_physically_possible_visual_metric_boundaries_are_accepted(self):
        """Do not reject native lower and upper pixel/margin consistency boundaries."""
        for margin, pixels in ((2, 25), (999, 3_996_001), (999, 4_000_000)):
            visual = changed_result(
                self.native_results["visual_geometry"],
                min_edge_margin_px=margin, total_pixels=pixels,
            )
            with self.subTest(margin=margin, pixels=pixels), self.children({"visual_geometry": visual}):
                result = self.validate()
                self.assertTrue(result.passed, result.errors)

    def test_blocked_child_foreign_identities_are_malformed_evidence(self):
        """Reconcile available identities even when a child rejects the candidate."""
        for stage in ("object_safety", "controlled_metadata", "text_content", "visual_geometry"):
            changes = {"pdf_sha256": "0" * 64, "errors": ("pdf_structure_invalid",)}
            child = changed_result(self.native_results[stage], **changes)
            with self.subTest(stage=stage), self.children({stage: child}) as mocks:
                result = self.validate()
                self.assert_stopped(result, stage, mocks, "qa_validator_result_invalid")
        child = changed_result(
            self.native_results["text_content"], ir_sha256="0" * 64,
            errors=("pdf_text_content_mismatch",),
        )
        with self.children({"text_content": child}) as mocks:
            self.assert_stopped(self.validate(), "text_content", mocks, "qa_validator_result_invalid")

    def test_blocked_content_can_have_partial_evidence_or_missing_identities(self):
        """Discard legitimate failure metrics without turning them into completed QA evidence."""
        for values in (
            {"extracted_text_sha256": "0" * 64},
            {"pdf_sha256": None, "ir_sha256": None, "page_count": None,
             "expected_text_sha256": None, "extracted_text_sha256": None},
        ):
            child = changed_result(
                self.native_results["text_content"], errors=("pdf_text_content_mismatch",), **values,
            )
            with self.children({"text_content": child}) as mocks:
                result = self.validate()
                self.assert_stopped(result, "text_content", mocks, "qa_child_validation_failed")

    def test_child_exceptions_are_redacted_and_stop_every_later_call(self):
        """Unexpected validator failures expose one fixed error without their message."""
        marker = "SYNTHETIC-PRIVATE-EXCEPTION"
        for stage, _ in STEPS:
            with self.subTest(stage=stage), self.children() as mocks:
                mocks[stage].side_effect = RuntimeError(marker)
                result = self.validate()
                self.assert_stopped(result, stage, mocks, "qa_validator_exception")
                self.assertNotIn(marker, repr(result))
                self.assertNotIn(marker, json.dumps(result.to_dict()))

    def test_arbitrary_child_errors_and_failed_language_are_not_retained(self):
        """Child error text and rejected language never become aggregate diagnostic content."""
        marker = "SYNTHETIC-PRIVATE-CHILD-VALUE"
        for stage, values in (
            ("text_content", {"errors": (marker,)}),
            ("accessibility_prerequisites", {"language": marker, "errors": (marker,)}),
        ):
            child = changed_result(self.native_results[stage], **values)
            with self.children({stage: child}) as mocks:
                result = self.validate()
                self.assert_stopped(result, stage, mocks, "qa_child_validation_failed")
                self.assertNotIn(marker, repr(result))
                self.assertNotIn(marker, json.dumps(result.to_dict()))

    def test_malformed_child_errors_are_not_treated_as_a_success(self):
        """Reject a mutable, non-string or excessive error protocol."""
        for errors in ([], ("",), (object(),), ("x" * 129,), ("x",) * 65):
            child = changed_result(self.native_results["text_content"], errors=errors)
            with self.subTest(kind=type(errors).__name__), self.children({"text_content": child}) as mocks:
                self.assert_stopped(self.validate(), "text_content", mocks, "qa_validator_result_invalid")

    def test_caller_mutation_after_snapshot_does_not_change_content_input(self):
        """The content gate sees the captured dictionary after the caller changes its copy."""
        ir = deepcopy(self.ir)

        def change_caller(**kwargs):
            ir["components"][0]["content"]["value"] = 999
            return self.native_results["object_safety"]

        with self.children() as mocks:
            mocks["object_safety"].side_effect = change_caller
            # Use the original function, not the patched module attribute.
            from reporting.pdf_content import validate_pdf_text_content
            mocks["text_content"].side_effect = validate_pdf_text_content
            result = self.validate(presentation_ir=ir)
        self.assertTrue(result.passed, result.errors)
        self.assertEqual(mocks["text_content"].call_args.kwargs["presentation_ir"], self.ir)
        self.assertEqual(ir["components"][0]["content"]["value"], 999)

    def test_result_and_serialization_are_detached_immutable_and_redacted(self):
        """Inputs, nested records and returned dictionaries cannot alter retained evidence."""
        ir = deepcopy(self.ir)
        with self.children():
            result = self.validate(presentation_ir=ir)
        before = result.to_dict()
        self.assertEqual(ir, self.ir)
        ir["components"][0]["content"]["text"] = "CHANGED"
        serialized = result.to_dict()
        serialized["gates"]["object_safety"]["evidence"]["pdf_sha256"] = "0" * 64
        serialized["gates"]["text_content"]["errors"].append("CHANGED")
        serialized["limitations"].append("CHANGED")
        self.assertEqual(result.to_dict(), before)
        with self.assertRaises(FrozenInstanceError):
            result.pdf_sha256 = "0" * 64
        with self.assertRaises(FrozenInstanceError):
            result.gates[1].status = "BLOCKED"
        with self.assertRaises(TypeError):
            result.gates[1].evidence[0] = ("pdf_sha256", "0" * 64)
        self.assertNotIn("SYNTHETIC-PRIVATE", repr(result))
        self.assertNotIn("SYNTHETIC-PRIVATE", json.dumps(result.to_dict()))
        self.assertNotIn("metadata", before["gates"]["controlled_metadata"]["evidence"])
        self.assertEqual(result.release_authorization, "NOT_ESTABLISHED")

    def test_result_constructor_rejects_missing_reordered_and_contradictory_gates(self):
        """Immutable records cannot manufacture success through an invalid stage sequence."""
        with self.children():
            result = self.validate()
        gates = result.gates
        for values in (
            {"gates": gates[:-1]}, {"gates": tuple(reversed(gates))},
            {"gates": (gates[0], gates[1], gates[1], *gates[3:])},
            {"gates": list(gates)}, {"pdf_sha256": "0" * 64},
            {"gates": (
                gates[0], replace(gates[1], status="BLOCKED", evidence=None,
                                  errors=("qa_child_validation_failed",)), *gates[2:],
            )},
        ):
            with self.subTest(fields=tuple(values)), self.assertRaises(ValueError):
                replace(result, **values)

    def test_result_constructor_rejects_locale_subclasses(self):
        """Direct construction must not retain an arbitrary locale object."""
        class Locale(str):
            pass

        with self.children():
            result = self.validate()
        with self.assertRaises(ValueError):
            replace(result, locale_id=Locale("en-US"))


if __name__ == "__main__":
    unittest.main()
