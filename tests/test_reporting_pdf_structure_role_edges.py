"""Opt-in generated PDF role-edge inventory, without semantic accessibility claims."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
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
from reporting.pdf_text_windows import PROFILE_ID as TEXT_PROFILE
from reporting.pdf_structure_role_tokens import inspect_pdf_structure_role_tokens
from tests.test_reporting_pdf_document_content import changed_pdf
from tests.test_reporting_pdf_source_inspection_job import generated_job_case
from tests.test_reporting_pdf_structure_tree import structure


ROOT = Path(__file__).resolve().parents[1]
EDGES = (
    "/Document>/H1", "/Document>/Sect", "/H1>/Span", "/H2>/Span",
    "/NonStruct>/Span", "/P>/Span", "/Sect>/H2", "/Sect>/NonStruct",
    "/Sect>/P", "ROOT>/Document",
)


class PdfStructureRoleEdgesTests(unittest.TestCase):
    """Known role token counts cannot conceal unexpected structural edges."""

    cases = None

    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("reporting.pdf_structure_role_edges"),
            "generated role-edge inventory module is missing",
        )
        self.m = importlib.import_module("reporting.pdf_structure_role_edges")
        self.worker = importlib.import_module("reporting._pdf_structure_role_edges_worker")
        if self.__class__.cases is None:
            self.__class__.cases = {n: generated_job_case(n)[1] for n in (1, 33, 64)}
        self.pdf = self.cases[1]
        self.plan = self.plan_for(self.pdf, 1)

    @staticmethod
    def plan_for(pdf, pages):
        return plan_pdf_page_windows(
            pdf_sha256=sha256(pdf).hexdigest(), ir_sha256="a" * 64,
            page_count=pages, admitted_page_budget=pages,
            pages_per_window=16, inspector_profile_id=TEXT_PROFILE,
        )

    def inspect(self, **change):
        values = dict(pdf_bytes=self.pdf, plan=self.plan,
                      expected_plan_sha256=self.plan.plan_sha256,
                      expected_language="en-US")
        return self.m.inspect_pdf_structure_role_edges(**{**values, **change})

    def altered(self, mutation):
        pdf = changed_pdf(self.pdf, mutation)
        plan = self.plan_for(pdf, 1)
        return dict(pdf_bytes=pdf, plan=plan,
                    expected_plan_sha256=plan.plan_sha256,
                    expected_language="en-US")

    def test_native_one_thirty_three_sixty_four_page_adjacency_closes(self):
        for pages, pdf in self.cases.items():
            with self.subTest(pages=pages):
                plan = self.plan_for(pdf, pages)
                receipt = self.inspect(pdf_bytes=pdf, plan=plan,
                                       expected_plan_sha256=plan.plan_sha256)
                data = receipt.to_dict()
                expected = {
                    "/Document>/H1": 1, "/Document>/Sect": pages,
                    "/H1>/Span": 1, "/H2>/Span": pages,
                    "/NonStruct>/Span": pages, "/P>/Span": pages,
                    "/Sect>/H2": pages, "/Sect>/NonStruct": pages,
                    "/Sect>/P": pages, "ROOT>/Document": 1,
                }
                self.assertEqual(data["edge_counts"], expected)
                self.assertEqual(data["structure_elements"], 7 * pages + 3)
                self.assertEqual(sum(data["edge_counts"].values()), 7 * pages + 3)
                self.assertEqual(data["mapped_mcids"], 3 * pages + 1)
                self.assertEqual(data["inspected_pages"], pages)
                self.assertTrue(data["all_reachable_role_edges_inventoried"])
                for key in ("semantic_role_appropriateness_verified",
                            "reading_order_verified", "pdf_ua_qualified",
                            "default_pipeline_activated", "release_authorized"):
                    self.assertFalse(data[key])

    def test_known_role_swap_passes_old_inventory_but_fails_new_edge_gate(self):
        """A rehashed, linked PDF with all old role counts can still have wrong edges."""
        def swap(writer):
            document = structure(writer)[3]
            heading = document["/K"][0].get_object()
            span = heading["/K"][0].get_object()
            heading[NameObject("/S")] = NameObject("/Span")
            span[NameObject("/S")] = NameObject("/H1")
        candidate = self.altered(swap)
        old = inspect_pdf_structure_role_tokens(**candidate).to_dict()
        self.assertEqual(old["structure_elements"], 10)
        self.assertEqual(old["role_counts"]["/H1"], 1)
        self.assertEqual(old["role_counts"]["/Span"], 4)
        with self.assertRaises(self.m.PdfStructureRoleEdgesError):
            self.m.inspect_pdf_structure_role_edges(**candidate)

    def test_existing_rolemap_and_unknown_token_guard_remains_mandatory(self):
        def alias(writer):
            structure(writer)[1][NameObject("/RoleMap")] = DictionaryObject({
                NameObject("/Local"): NameObject("/Span")})
        candidate = self.altered(alias)
        with self.assertRaises(self.m.PdfStructureRoleEdgesError):
            self.m.inspect_pdf_structure_role_edges(**candidate)
        candidate = self.altered(lambda writer: structure(writer)[3]["/K"][0]
                                 .get_object().__setitem__(
                                     NameObject("/S"), NameObject("/Unknown")))
        with self.assertRaises(self.m.PdfStructureRoleEdgesError):
            self.m.inspect_pdf_structure_role_edges(**candidate)

    def test_pdf_plan_locale_type_and_unsupported_size_reject_before_native(self):
        """Reject malformed inputs and over-budget candidates before launching workers."""
        foreign = self.plan_for(self.pdf, 65)
        overflow = b"%PDF-1.7" + b"x" * 16777209
        overflow_plan = self.plan_for(overflow, 1)
        with patch.object(self.m, "_run_worker") as worker:
            for change in (
                dict(pdf_bytes=bytearray(self.pdf)),
                dict(pdf_bytes=self.cases[33]),
                dict(plan={}),
                dict(expected_plan_sha256="f" * 64),
                dict(expected_language="pt-BR"),
                dict(plan=foreign, expected_plan_sha256=foreign.plan_sha256),
                dict(pdf_bytes=overflow, plan=overflow_plan, expected_plan_sha256=overflow_plan.plan_sha256),
            ):
                with self.subTest(changed=tuple(change)):
                    with self.assertRaises(self.m.PdfStructureRoleEdgesError):
                        self.inspect(**change)
            worker.assert_not_called()

    def test_disabled_before_and_after_child_rejects(self):
        key = "OMNIGENIS_PDF_STRUCTURE_ROLE_EDGES_DISABLED"
        with patch.dict(os.environ, {key: "1"}), patch.object(self.m, "_run_worker") as native:
            with self.assertRaises(self.m.PdfStructureRoleEdgesError):
                self.inspect()
            native.assert_not_called()
        original = self.m._run_worker
        def disable_after(pdf, identity):
            wire = original(pdf, identity)
            os.environ[key] = "1"
            return wire
        with patch.dict(os.environ), patch.object(
            self.m, "_run_worker", side_effect=disable_after,
        ):
            with self.assertRaises(self.m.PdfStructureRoleEdgesError):
                self.inspect()

    def test_corrupt_and_encrypted_native_documents_fail_closed(self):
        for pdf in (b"%PDF-1.7\ninvalid", changed_pdf(
            self.pdf, lambda writer: writer.encrypt("fixture-only"),
        )):
            plan = self.plan_for(pdf, 1)
            with self.assertRaises(self.m.PdfStructureRoleEdgesError):
                self.inspect(pdf_bytes=pdf, plan=plan,
                             expected_plan_sha256=plan.plan_sha256)

    def test_worker_unavailable_is_not_partial_success(self):
        with patch.object(self.m, "_run_worker", side_effect=OSError("native unavailable")):
            with self.assertRaises(self.m.PdfStructureRoleEdgesError):
                self.inspect()

    def test_parent_never_parses_pdf(self):
        with patch("pypdf.PdfReader", side_effect=AssertionError("parent PDF parser forbidden")):
            self.assertEqual(self.inspect().page_count, 1)

    def test_native_wire_rejects_malformed_edges_identity_and_limits(self):
        identity = self.worker._identity_from_plan(self.plan)
        real = json.loads(self.m._run_worker(self.pdf, identity))
        versions = []
        def variant(mutate):
            obj = json.loads(json.dumps(real))
            mutate(obj)
            versions.append(obj)
        variant(lambda x: x.update({"unexpected": True}))
        variant(lambda x: x["inspection"]["edge_counts"].update({"/Foreign>/Span": 1}))
        variant(lambda x: x["inspection"]["edge_counts"].update({"ROOT>/Document": 2}))
        variant(lambda x: x["inspection"]["edge_counts"].update({"/H1>/Span": True}))
        variant(lambda x: x["inspection"]["edge_counts"].pop("/Sect>/H2"))
        variant(lambda x: x["inspection"].update({"structure_elements": 11}))
        variant(lambda x: x["inspection"].update({"inspected_pages": True}))
        variant(lambda x: x["identity"].update({"pdf_sha256": "f" * 64}))
        variant(lambda x: x["limits"].update({"memory_bytes": -1}))
        variant(lambda x: x.update({"parser_version": "unversioned"}))
        variant(lambda x: x.update({"protocol_version": -1}))
        for obj in versions:
            with self.subTest(keys=sorted(obj)):
                wire = json.dumps(obj, sort_keys=True).encode("ascii")
                with patch.object(self.m, "_run_worker", return_value=wire):
                    with self.assertRaises(self.m.PdfStructureRoleEdgesError):
                        self.inspect()
        wire = self.m._run_worker(self.pdf, identity)
        duplicate = wire.replace(
            b'"profile_id":', b'"profile_id":"forged","profile_id":', 1,
        )
        nested = wire.replace(
            b'"/Document>/H1":1,',
            b'"/Document>/H1":1,"/Document>/H1":1,', 1,
        )
        self.assertNotEqual(nested, wire)
        for malformed in (duplicate, nested, wire + b"\xff",
                          wire + b"x" * (self.m.RESULT_BYTES + 1)):
            with patch.object(self.m, "_run_worker", return_value=malformed):
                with self.assertRaises(self.m.PdfStructureRoleEdgesError):
                    self.inspect()

    def test_receipt_cannot_be_resealed_after_mutation(self):
        value = self.inspect()
        self.assertEqual(value.inspection_sha256, sha256(value.to_bytes()).hexdigest())
        with self.assertRaises(FrozenInstanceError):
            value.structure_elements = 88
        object.__setattr__(value, "structure_elements", 88)
        with self.assertRaises(self.m.PdfStructureRoleEdgesError):
            value.to_dict()

    def test_plan_changed_during_worker_is_rejected(self):
        actual = self.m._run_worker
        def change(pdf, identity):
            result = actual(pdf, identity)
            object.__setattr__(self.plan, "ir_sha256", "f" * 64)
            return result
        with patch.object(self.m, "_run_worker", side_effect=change):
            with self.assertRaises(self.m.PdfStructureRoleEdgesError):
                self.inspect()

    def test_manifest_and_dependency_profiles_are_not_silently_widened(self):
        """Pin the selected finite profile, dependency identities and unqualified claims."""
        manifest = json.loads(
            (ROOT / "reporting/pdf-structure-role-edges.v1.json").read_text(),
        )
        profile = self.m.structure_role_edges_profile()
        self.assertEqual(manifest, profile)
        self.assertEqual(tuple(self.worker.EDGE_KEYS), EDGES)
        self.assertEqual(profile["max_pages"], 64)
        self.assertEqual(profile["max_pdf_bytes"], 16 * 1024 * 1024)
        self.assertEqual(profile["parent_role_profile_sha256"],
                         importlib.import_module(
                             "reporting.pdf_structure_role_tokens").PROFILE_SHA256)
        self.assertEqual(
            sha256(self.m._canonical(profile)).hexdigest(), self.m.PROFILE_SHA256,
        )
        self.assertFalse(profile["pdf_ua_qualified"])
        self.assertFalse(profile["default_pipeline_activated"])
        self.assertFalse(profile["release_authorized"])


if __name__ == "__main__":
    unittest.main()
