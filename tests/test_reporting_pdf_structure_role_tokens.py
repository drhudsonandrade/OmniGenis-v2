"""Current generated PDF role-token inventory; no semantic/PDF-UA promotion."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
import importlib
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from pypdf.generic import DictionaryObject, NameObject
from reporting.page_windows import plan_pdf_page_windows
from reporting.pdf_structure_tree import inspect_pdf_structure_tree
from reporting.pdf_text_windows import PROFILE_ID as TEXT_PROFILE
from tests.test_reporting_pdf_document_content import changed_pdf
from tests.test_reporting_pdf_source_inspection_job import generated_job_case
from tests.test_reporting_pdf_structure_tree import first_leaf, structure


ROOT = Path(__file__).resolve().parents[1]
ALLOWED = ("/Document", "/H1", "/H2", "/NonStruct", "/P", "/Sect", "/Span")


class PdfStructureRoleTokensTests(unittest.TestCase):
    """Only all native lexical roles in a previously linked exact PDF can be recorded."""

    cases = None

    def setUp(self):
        """A missing product boundary is the deliberate test-first RED."""
        self.assertIsNotNone(importlib.util.find_spec("reporting.pdf_structure_role_tokens"),
                             "role-token inventory module is missing")
        self.m = importlib.import_module("reporting.pdf_structure_role_tokens")
        self.worker = importlib.import_module("reporting._pdf_structure_role_tokens_worker")
        if self.__class__.cases is None:
            self.__class__.cases = {n: generated_job_case(n)[1] for n in (1, 33, 64)}
        self.pdf = self.cases[1]
        self.plan = self.plan_for(self.pdf, 1)

    @staticmethod
    def plan_for(pdf, pages):
        """Set an independent final-file digest and the real native page-window profile."""
        return plan_pdf_page_windows(pdf_sha256=sha256(pdf).hexdigest(),
            ir_sha256="a" * 64, page_count=pages, admitted_page_budget=pages,
            pages_per_window=16, inspector_profile_id=TEXT_PROFILE)

    def inspect(self, **changes):
        args = dict(pdf_bytes=self.pdf, plan=self.plan,
                    expected_plan_sha256=self.plan.plan_sha256,
                    expected_language="en-US")
        return self.m.inspect_pdf_structure_role_tokens(**{**args, **changes})

    def reject(self, mutation):
        pdf = changed_pdf(self.pdf, mutation)
        plan = self.plan_for(pdf, 1)
        with self.assertRaises(self.m.PdfStructureRoleTokensError):
            self.inspect(pdf_bytes=pdf, plan=plan, expected_plan_sha256=plan.plan_sha256)

    def test_native_one_thirty_three_sixty_four_complete_role_counts(self):
        """Every supported physical page contributes its full known synthetic role inventory."""
        for pages, pdf in self.cases.items():
            with self.subTest(pages=pages):
                plan = self.plan_for(pdf, pages)
                result = self.inspect(pdf_bytes=pdf, plan=plan,
                                      expected_plan_sha256=plan.plan_sha256)
                actual = result.to_dict()
                expected = {"/Document": 1, "/H1": 1, "/H2": pages,
                            "/NonStruct": pages, "/P": pages,
                            "/Sect": pages, "/Span": 3 * pages + 1}
                self.assertEqual(actual["role_counts"], expected)
                self.assertEqual(actual["structure_elements"], 7 * pages + 3)
                self.assertEqual(actual["mapped_mcids"], 3 * pages + 1)
                self.assertEqual(actual["inspected_pages"], pages)
                self.assertEqual(actual["status"], "STRUCTURE_ROLE_TOKENS_INVENTORIED")
                self.assertTrue(actual["all_reachable_role_tokens_inventoried"])
                self.assertTrue(actual["document_role_must_be_unique_root_child"])
                for field in ("semantic_roles_qualified", "reading_order_verified",
                              "full_accessibility_qualified", "release_authorized",
                              "worker_results_authenticated"):
                    self.assertFalse(actual[field])

    def test_unknown_native_role_is_rejected_even_after_rehashing(self):
        """A valid reverse/forward ownership does not legitimize a custom role token."""
        self.reject(lambda writer: first_leaf(writer).get_object().__setitem__(
            NameObject("/S"), NameObject("/CustomRole")))

    def test_rolemap_alias_is_rejected_under_narrow_generated_profile(self):
        """An alias-to-standard role mapping is outside the explicit native token subset."""
        def alias(writer):
            structure(writer)[1][NameObject("/RoleMap")] = DictionaryObject({
                NameObject("/CustomRole"): NameObject("/Span")})
        self.reject(alias)

    def test_missing_document_root_role_is_rejected(self):
        """Known individual role names cannot excuse absence of the Document hierarchy role."""
        self.reject(lambda writer: structure(writer)[3].__setitem__(
            NameObject("/S"), NameObject("/Sect")))

    def test_document_role_must_be_direct_child_of_structural_root(self):
        """One misplaced Document token with unchanged counts and valid links is rejected."""
        def swap_roles(writer):
            document = structure(writer)[3]
            first = document["/K"][0].get_object()
            document_role, first_role = document["/S"], first["/S"]
            document[NameObject("/S")] = first_role
            first[NameObject("/S")] = document_role
        candidate = changed_pdf(self.pdf, swap_roles)
        plan = self.plan_for(candidate, 1)
        args = dict(pdf_bytes=candidate, plan=plan,
                    expected_plan_sha256=plan.plan_sha256, expected_language="en-US")
        self.assertEqual(inspect_pdf_structure_tree(**args).structure_elements, 10)
        with self.assertRaises(self.m.PdfStructureRoleTokensError):
            self.m.inspect_pdf_structure_role_tokens(**args)

    def test_foreign_plan_pdf_locale_and_wrong_input_type_fail_closed(self):
        """Bad types reject prelaunch; physical page-count mismatch rejects in the child."""
        foreign = self.plan_for(self.pdf, 2)
        with patch.object(self.m, "_run_worker") as native:
            for change in (dict(expected_plan_sha256="f" * 64), dict(plan={}),
                           dict(pdf_bytes=bytearray(self.pdf)),
                           dict(pdf_bytes=self.cases[33]),
                           dict(expected_language="pt-BR")):
                with self.subTest(change=list(change)):
                    with self.assertRaises(self.m.PdfStructureRoleTokensError):
                        self.inspect(**change)
            self.assertEqual(native.call_count, 0)
        # Physical page counts require the confined PDF parser, not the parent.
        with self.assertRaises(self.m.PdfStructureRoleTokensError):
            self.inspect(plan=foreign, expected_plan_sha256=foreign.plan_sha256)

    def test_sixty_five_page_and_over_sixteen_mib_not_silently_admitted(self):
        """The parser refuses declarations above either finite execution ceiling."""
        foreign = self.plan_for(self.pdf, 65)
        overflow = b"%PDF-1.7" + b"x" * 16777209
        overflow_plan = self.plan_for(overflow, 1)
        with patch.object(self.m, "_run_worker") as native:
            for change in (dict(plan=foreign, expected_plan_sha256=foreign.plan_sha256),
                           dict(pdf_bytes=overflow, plan=overflow_plan, expected_plan_sha256=overflow_plan.plan_sha256)):
                with self.assertRaises(self.m.PdfStructureRoleTokensError):
                    self.inspect(**change)
            native.assert_not_called()

    def test_corrupt_and_encrypted_native_pdf_fail_without_receipts(self):
        """Unparseable and encrypted final documents cannot earn an inventory."""
        for candidate in (b"%PDF-1.7\nnot a pdf",
                          changed_pdf(self.pdf, lambda w: w.encrypt("fixture-only"))):
            plan = self.plan_for(candidate, 1)
            with self.assertRaises(self.m.PdfStructureRoleTokensError):
                self.inspect(pdf_bytes=candidate, plan=plan,
                             expected_plan_sha256=plan.plan_sha256)

    def test_disable_before_and_during_native_work_rejects_without_partial_success(self):
        """Explicit disable is checked both before child launch and after native result."""
        key = "OMNIGENIS_PDF_STRUCTURE_ROLE_TOKENS_DISABLED"
        with patch.dict(os.environ, {key: "1"}), patch.object(self.m, "_run_worker") as native:
            with self.assertRaises(self.m.PdfStructureRoleTokensError): self.inspect()
            native.assert_not_called()
        original = self.m._run_worker
        def flip(pdf, identity):
            output = original(pdf, identity)
            os.environ[key] = "1"
            return output
        with patch.dict(os.environ), patch.object(self.m, "_run_worker", side_effect=flip):
            with self.assertRaises(self.m.PdfStructureRoleTokensError): self.inspect()

    def test_native_wire_duplicate_extra_and_wrong_counts_are_rejected(self):
        """Malformed worker output fails closed even if it shares a caller's plan hash."""
        identity = self.worker._identity_from_plan(self.plan)
        real = json.loads(self.m._run_worker(self.pdf, identity))
        variants = []
        v = json.loads(json.dumps(real)); v["extra"] = True; variants.append(v)
        v = json.loads(json.dumps(real)); v["inspection"]["structure_elements"] += 1; variants.append(v)
        v = json.loads(json.dumps(real)); v["inspection"]["structure_elements"] = True; variants.append(v)
        v = json.loads(json.dumps(real)); v["inspection"]["role_counts"]["/Span"] = True; variants.append(v)
        v = json.loads(json.dumps(real)); v["inspection"]["role_counts"]["/CustomRole"] = 1; variants.append(v)
        v = json.loads(json.dumps(real)); v["inspection"]["inspected_pages"] = True; variants.append(v)
        v = json.loads(json.dumps(real)); v["identity"]["pdf_sha256"] = "f" * 64; variants.append(v)
        v = json.loads(json.dumps(real)); v["limits"]["memory_bytes"] += 1; variants.append(v)
        v = json.loads(json.dumps(real)); v["parser_version"] = "unpinned"; variants.append(v)
        v = json.loads(json.dumps(real)); v["protocol_version"] += 1; variants.append(v)
        for variant in variants:
            with self.subTest(shape=list(variant)):
                encoded = json.dumps(variant, sort_keys=True).encode("ascii")
                with patch.object(self.m, "_run_worker", return_value=encoded):
                    with self.assertRaises(self.m.PdfStructureRoleTokensError):
                        self.inspect()
        encoded = self.m._run_worker(self.pdf, identity)
        duplicate = encoded.replace(b'"profile_id":',
                                    b'"profile_id":"forged","profile_id":', 1)
        self.assertNotEqual(duplicate, encoded)
        nested_duplicate = encoded.replace(b'"/Document":1,',
                                           b'"/Document":1,"/Document":1,', 1)
        self.assertNotEqual(nested_duplicate, encoded)
        for malformed in (duplicate, nested_duplicate, encoded + b"\xff",
                          encoded + b" " * (self.m.RESULT_BYTES + 1)):
            with self.subTest(malformed_bytes=len(malformed)):
                with patch.object(self.m, "_run_worker", return_value=malformed):
                    with self.assertRaises(self.m.PdfStructureRoleTokensError):
                        self.inspect()

    def test_existing_typed_receipt_cannot_be_resealed_after_mutation(self):
        """An originally sealed receipt never accepts a changed count or role."""
        result = self.inspect()
        self.assertEqual(result.inspection_sha256, sha256(result.to_bytes()).hexdigest())
        with self.assertRaises(FrozenInstanceError):
            result.structure_elements = 999
        object.__setattr__(result, "structure_elements", 999)
        with self.assertRaises(self.m.PdfStructureRoleTokensError):
            result.to_dict()

    def test_stale_page_plan_changed_while_worker_executes_is_rejected(self):
        """The parent rechecks the retained plan after the independent child returns."""
        original = self.m._run_worker
        def alter(pdf, identity):
            output = original(pdf, identity)
            object.__setattr__(self.plan, "ir_sha256", "f" * 64)
            return output
        with patch.object(self.m, "_run_worker", side_effect=alter):
            with self.assertRaises(self.m.PdfStructureRoleTokensError): self.inspect()

    def test_unavailable_or_dead_child_cannot_yield_partial_role_counts(self):
        """Worker failure is a content-free blocked result, never partial success."""
        with patch.object(self.m, "_run_worker", side_effect=OSError("synthetic failure")):
            with self.assertRaises(self.m.PdfStructureRoleTokensError):
                self.inspect()

    def test_no_pdf_parser_executes_in_parent_process(self):
        """The parent boundary never parses PDF bytes outside the isolated child."""
        with patch("pypdf.PdfReader", side_effect=AssertionError("parent parser forbidden")):
            self.assertEqual(self.inspect().page_count, 1)

    def test_pinned_profile_manifest_and_unchanged_old_native_contracts(self):
        """The manifest owns only lexical metadata and keeps all older claims unchanged."""
        manifest = json.loads((ROOT / "reporting/pdf-structure-role-tokens.v1.json").read_text())
        profile = self.m.structure_role_tokens_profile()
        self.assertEqual(manifest, profile)
        self.assertEqual(tuple(profile["supported_role_tokens"]), ALLOWED)
        self.assertTrue(profile["document_role_must_be_unique_root_child"])
        self.assertEqual(profile["max_pages"], 64)
        self.assertEqual(profile["max_pdf_bytes"], 16 * 1024 * 1024)
        self.assertFalse(profile["pdf_ua_qualified"])
        self.assertFalse(profile["reading_order_verified"])
        self.assertFalse(profile["default_pipeline_activated"])
        self.assertEqual(sha256(self.m._canonical(profile)).hexdigest(),
                         self.m.PROFILE_SHA256)
        self.assertEqual(len(self.inspect().role_counts), 7)


if __name__ == "__main__":
    unittest.main()
