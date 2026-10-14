"""Exact tagged-PDF MCID-to-ParentTree content linkage, not PDF/UA release."""
from __future__ import annotations

from contextlib import ExitStack
from io import BytesIO
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
from unittest.mock import patch
import unittest

from pypdf import PdfWriter, PdfReader
from pypdf.generic import (ArrayObject, DecodedStreamObject, NameObject,
                           NullObject, NumberObject, TextStringObject)
from reporting.page_windows import plan_pdf_page_windows
from reporting.pdf_text_windows import PROFILE_ID as TEXT_PROFILE
from reporting.adapters import build_html_css_and_pdf_adapter
from tests.test_reporting_pdf_page_tags import tagged_pdf, mutate, tree
from tests.test_reporting_rpt12_pdf_metadata import presentation

ROOT=Path(__file__).resolve().parents[1]
PROFILE="generated-pdf-mcid-parenttree-v1"
POLICY="page-mcid-parenttree-consistency-v1"

def digest(data):
    return hashlib.sha256(data).hexdigest()

def content_mutation(pdf, change):
    """Mutate only generated synthetic page instructions, never user input."""
    def transform(writer):
        page=writer.pages[0]
        original=page.get_contents().get_data()
        changed=change(original)
        assert isinstance(changed,bytes) and changed!=original
        stream=DecodedStreamObject()
        stream.set_data(changed)
        page[NameObject("/Contents")]=writer._add_object(stream)
    return mutate(pdf,transform)

class PdfMcidCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        native=build_html_css_and_pdf_adapter(presentation_ir=presentation())
        assert native.passed,native.errors
        cls.one=native.pdf_bytes
        cls.two=tagged_pdf(2)
        cls.long=tagged_pdf(33)

    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("reporting.pdf_mcid_coverage"),
                             "MCID-to-parent-tree inspector not yet implemented")
        self.m=importlib.import_module("reporting.pdf_mcid_coverage")
        self.worker=importlib.import_module("reporting._pdf_mcid_coverage_worker")
        self.pdf=self.two
        self.plan=self.make_plan(self.pdf,2)

    def make_plan(self,pdf,count):
        return plan_pdf_page_windows(
            pdf_sha256=digest(pdf),ir_sha256="c"*64,
            page_count=count,admitted_page_budget=count,
            pages_per_window=16,inspector_profile_id=TEXT_PROFILE)

    def inspect(self,**args):
        params={"pdf_bytes":self.pdf,"plan":self.plan,
                "expected_plan_sha256":self.plan.plan_sha256,
                "expected_language":"en-US"}
        params.update(args)
        return self.m.inspect_pdf_mcid_coverage(**params)

    def reject(self,pdf,count=2):
        plan=self.make_plan(pdf,count)
        with self.assertRaises(self.m.PdfMcidCoverageError) as result:
            self.inspect(pdf_bytes=pdf,plan=plan,expected_plan_sha256=plan.plan_sha256)
        self.assertNotIn("Synthetic tagged page",str(result.exception))

    def identity(self):
        return {"pdf_sha256":self.plan.pdf_sha256,
                "ir_sha256":self.plan.ir_sha256,
                "plan_sha256":self.plan.plan_sha256,
                "page_count":self.plan.page_count}

    def good_response(self):
        return {"protocol_version":1,"profile_id":PROFILE,
                "policy_id":POLICY,"parser_version":"6.19.0",
                "identity":self.identity(),
                "limits":{"memory_bytes":268435456,"cpu_seconds":5,
                          "file_bytes":4096,"open_files":128},
                "inspection":{"status":"PAGE_MCID_PARENTTREE_INSPECTED",
                              "matched_mcids":2,"decoded_bytes":646,
                              "inspected_pages":2}}

    def test_native_one_two_and_thirty_three_page_documents(self):
        for pdf,count in ((self.one,1),(self.two,2),(self.long,33)):
            with self.subTest(pages=count):
                plan=self.make_plan(pdf,count)
                result=self.inspect(pdf_bytes=pdf,plan=plan,
                                    expected_plan_sha256=plan.plan_sha256)
                self.assertEqual(result.page_count,count)
                self.assertGreaterEqual(result.matched_mcids,count)
                self.assertEqual(result.inspected_pages,count)
                self.assertLessEqual(result.decoded_bytes,8388608)
                self.assertFalse(result.to_dict()["pdf_ua_qualified"])
                self.assertFalse(result.to_dict()["release_authorized"])

    def test_duplicate_mcid_instruction_rejected(self):
        self.reject(content_mutation(self.two,lambda b:b+b"\n/Span <</MCID 0>> BDC\nEMC\n"))

    def test_mcid_gap_and_unmapped_instruction_rejected(self):
        self.reject(content_mutation(self.two,lambda b:b.replace(b"/MCID 0",b"/MCID 1",1)))
        self.reject(content_mutation(self.two,lambda b:b+b"\n/Span <</MCID 1>> BDC\nEMC\n"))

    def test_missing_mcid_and_invalid_native_type_rejected(self):
        for replacement in (b"/MCID (0)",b"/MCID -1",b"/MCI 0"):
            with self.subTest(replacement=replacement):
                self.reject(content_mutation(self.two,lambda b:b.replace(b"/MCID 0",replacement,1)))

    def test_unbalanced_marked_sequences_rejected(self):
        self.reject(content_mutation(self.two,lambda b:b+b"\nEMC\n"))
        self.reject(content_mutation(self.two,lambda b:b.replace(b"\nEMC\n",b"\n",1)))

    def test_ambiguous_bdc_and_unsupported_bmc_rejected(self):
        self.reject(content_mutation(self.two,lambda b:b.replace(b"/Span",b"/Unknown",1)))
        self.reject(content_mutation(self.two,lambda b:b.replace(b"/Span",b"/Artifact",1)
                                      .replace(b"BDC",b"BMC",1)))

    def test_parent_tree_orphan_entry_rejected(self):
        def add(writer):
            _,p=tree(writer)
            a=p["/Nums"][1].get_object()
            a.append(a[0])
        self.reject(mutate(self.two,add))

    def test_wrong_structure_element_mcid_index_and_type_rejected(self):
        for value in (ArrayObject([NumberObject(1)]),TextStringObject("0")):
            def change(writer):
                _,p=tree(writer)
                p["/Nums"][1].get_object()[0].get_object()[NameObject("/K")]=value
            self.reject(mutate(self.two,change))

    def test_reused_page_structparent_guard_remains_mandatory(self):
        def absent(writer):
            del writer.pages[0][NameObject("/StructParents")]
        self.reject(mutate(self.two,absent))
        def wrong(writer):
            _,p=tree(writer)
            p["/Nums"][1]=ArrayObject([NullObject()])
        self.reject(mutate(self.two,wrong))

    def test_extra_blank_pages_never_gain_a_false_receipt(self):
        from tests.test_reporting_pdf_document_metadata import metadata_fixture
        self.reject(metadata_fixture(self.one,33),33)

    def test_wrong_plan_digest_count_and_locale_fail_closed(self):
        with self.assertRaises(self.m.PdfMcidCoverageError):
            self.inspect(expected_plan_sha256="f"*64)
        with self.assertRaises(self.m.PdfMcidCoverageError):
            self.inspect(expected_language="pt-BR")
        with self.assertRaises(self.m.PdfMcidCoverageError):
            self.inspect(pdf_bytes=self.one)
        with self.assertRaises(self.m.PdfMcidCoverageError):
            self.inspect(plan=self.make_plan(self.two,1))

    def test_disable_switch_fails_closed_without_fallback(self):
        with patch.dict(os.environ,{"OMNIGENIS_PDF_MCID_COVERAGE_DISABLED":"1"}):
            with self.assertRaises(self.m.PdfMcidCoverageError):
                self.inspect()

    def test_malformed_and_unsupported_pdf_version_block(self):
        for candidate in (b"not a pdf", self.two.replace(b"%PDF-1.7",b"%PDF-1.6",1)):
            with self.assertRaises(self.m.PdfMcidCoverageError):
                self.inspect(pdf_bytes=candidate)

    def test_response_shape_identity_and_native_counts_fail_closed(self):
        base=self.good_response()
        for change in ({"profile_id":"foreign"}, {"identity":{"page_count":4}},
                       {"inspection":{"matched_mcids":True}},
                       {"limits":{"open_files":999}}):
            item=json.loads(json.dumps(base))
            for key,value in change.items():
                if key in ("identity","inspection","limits"):item[key].update(value)
                else:item[key]=value
            with self.assertRaises(self.m.PdfMcidCoverageError):
                self.m._decode(json.dumps(item).encode(),self.identity())

    def test_duplicate_json_fields_and_unbounded_response_rejected(self):
        normal=json.dumps(self.good_response()).encode()
        duplicate=normal.replace(b'"status":',b'"status": "fake", "status":',1)
        for data in (duplicate,normal+b" "*4096,b"",None):
            with self.assertRaises(self.m.PdfMcidCoverageError):
                self.m._decode(data,self.identity())

    def test_digest_and_receipt_are_bounded_and_explicitly_unqualified(self):
        result=self.inspect()
        a=result.to_dict()
        self.assertEqual(len(result.inspection_sha256),64)
        self.assertEqual(a["status"],"PAGE_MCID_PARENTTREE_INSPECTED")
        self.assertFalse(a["full_struct_tree_verified"])
        self.assertFalse(a["whole_visual_content_covered"])
        self.assertFalse(a["aggregate_job_resources_qualified"])
        self.assertFalse(a["worker_results_authenticated"])
        self.assertFalse(a["release_authorized"])
        self.assertEqual(a["release_authorization"],"NOT_ESTABLISHED")

    def test_opaque_worker_failure_is_never_a_receipt(self):
        with patch.object(self.m,"_run_worker",side_effect=OSError("SYNTHETIC_PRIVATE_TEXT")):
            with self.assertRaises(self.m.PdfMcidCoverageError) as result:self.inspect()
        self.assertNotIn("SYNTHETIC_PRIVATE_TEXT",str(result.exception))

    def test_guard_failure_precedes_candidate_read(self):
        from unittest.mock import patch as mock
        with ExitStack() as stack:
            stack.enter_context(mock.object(self.worker,"_read_request",side_effect=AssertionError("read")))
            stack.enter_context(mock.object(self.worker,"enforce_pdf_landlock",side_effect=OSError("denied")))
            # Guard ordering is inspected by source as well as tested through mocked native main.
            self.assertLess(
                Path(self.worker.__file__).read_text().index("enforce_pdf_landlock(Path(__file__))"),
                Path(self.worker.__file__).read_text().index("_read_request(first)"))

    def test_manifest_pinned_and_default_route_unchanged(self):
        from reporting._pdf_safety_worker import MAX_PAGES
        manifest=json.loads((ROOT/"reporting/pdf-mcid-coverage-engine.v1.json").read_text())
        self.assertEqual(MAX_PAGES,32)
        self.assertEqual(manifest["parser_version"],"6.19.0")
        self.assertEqual(manifest["resource_budget"]["pages"],512)
        self.assertEqual(manifest["resource_budget"]["decoded_bytes"],8388608)
        self.assertFalse(manifest["default_pipeline_activated"])
        self.assertFalse(manifest["release_authorized"])
        self.assertEqual(manifest["source_code_copied"],False)

if __name__=="__main__":
    unittest.main()
