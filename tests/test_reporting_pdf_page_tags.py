"""Native exact-page parent-tree correspondence for controlled generated PDF output."""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import FrozenInstanceError, replace
from io import BytesIO
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from pypdf import PdfReader, PdfWriter
from pypdf.generic import ArrayObject, DictionaryObject, NameObject, NumberObject, NullObject, TextStringObject
from reporting.adapters import build_html_css_and_pdf_adapter
from reporting.page_windows import plan_pdf_page_windows
from reporting.pdf_text_windows import PROFILE_ID as TEXT_PROFILE
from tests.test_reporting_rpt12_pdf_metadata import presentation
from tests.test_reporting_pdf_document_metadata import metadata_fixture

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "generated-pdf-page-tag-parenttree-v1"
POLICY = "page-tag-parenttree-references-v1"


def digest(data):
    """Identify synthetic exact bytes and not personally identifying content."""
    return hashlib.sha256(data).hexdigest()


def tagged_pdf(pages):
    """Create actual two-plus-page PDF/UA-marked synthetic pages with the pinned renderer."""
    from weasyprint import HTML
    assert 1 <= pages <= 33
    paragraphs = "".join(
        '<p style="break-before:page">Synthetic tagged page %d</p>' % i
        for i in range(1, pages + 1))
    html = '<html lang="en-US"><body>' + paragraphs + '</body></html>'
    pdf = HTML(string=html).write_pdf(
        pdf_variant="pdf/ua-1", pdf_identifier=bytes.fromhex("a" * 32))
    assert pdf.startswith(b"%PDF-1.7")
    assert len(PdfReader(BytesIO(pdf), strict=True).pages) == pages
    return pdf


def mutate(pdf, change):
    """Modify only synthetic PDF structures, never a real user report."""
    writer = PdfWriter(clone_from=BytesIO(pdf))
    writer.pdf_header = b"%PDF-1.7"
    change(writer)
    out = BytesIO()
    writer.write(out)
    return out.getvalue()


def tree(writer):
    """Return the root structural dictionary and flat parent tree in a synthetic clone."""
    s = writer.root_object["/StructTreeRoot"].get_object()
    p = s["/ParentTree"].get_object()
    return s, p


class PdfPageTagParentTests(unittest.TestCase):
    """Exact-page correspondence is not semantic accessibility certification."""

    @classmethod
    def setUpClass(cls):
        """Build native tagged fixtures before any assertions on new code."""
        generated = build_html_css_and_pdf_adapter(presentation_ir=presentation())
        if not generated.passed:
            raise AssertionError(generated.errors)
        cls.seed = generated.pdf_bytes
        cls.two = tagged_pdf(2)
        cls.thirty_three = tagged_pdf(33)

    def setUp(self):
        """Require the new opt-in module as a genuine missing-implementation RED."""
        self.assertIsNotNone(importlib.util.find_spec("reporting.pdf_page_tags"),
                             "page tag parent-tree inspection adapter missing")
        self.m = importlib.import_module("reporting.pdf_page_tags")
        self.w = importlib.import_module("reporting._pdf_page_tags_worker")
        self.pdf = self.two
        self.plan = self.make_plan(self.pdf, 2)

    def make_plan(self, pdf, page_count):
        """Bind the same actual PDF identity and sealed plan as the existing window engine."""
        return plan_pdf_page_windows(
            pdf_sha256=digest(pdf), ir_sha256="b" * 64,
            page_count=page_count, admitted_page_budget=page_count,
            pages_per_window=16, inspector_profile_id=TEXT_PROFILE)

    def inspect(self, **changes):
        """Use a guarded actual worker unless the test explicitly patches execution."""
        params = {"pdf_bytes": self.pdf, "plan": self.plan,
                  "expected_plan_sha256": self.plan.plan_sha256,
                  "expected_language": "en-US"}
        params.update(changes)
        return self.m.inspect_pdf_page_tag_parents(**params)

    def rejected(self, pdf, count=2):
        """Require a content-free failure on a newly hash-bound synthetic PDF."""
        plan = self.make_plan(pdf, count)
        with self.assertRaises(self.m.PdfPageTagError) as caught:
            self.inspect(pdf_bytes=pdf, plan=plan,
                         expected_plan_sha256=plan.plan_sha256)
        self.assertNotIn("SYNTHETIC_PRIVATE", str(caught.exception))

    def identity(self):
        """Detach the four-field worker document identity."""
        return {"pdf_sha256":self.plan.pdf_sha256, "ir_sha256":self.plan.ir_sha256,
                "plan_sha256":self.plan.plan_sha256, "page_count":self.plan.page_count}

    def response(self):
        """Create a synthetic protocol response for strict decoder-negative tests."""
        return {"protocol_version": 1, "profile_id": PROFILE,
                "policy_id": POLICY, "parser_version": "6.19.0",
                "identity": self.identity(),
                "limits": {"memory_bytes":268435456, "cpu_seconds":5,
                           "file_bytes":4096, "open_files":128},
                "inspection": {"status":"PAGE_TAG_PARENTTREE_INSPECTED",
                               "language":"en-US", "tagged_pages":2,
                               "parent_tree_entries":2}}

    def test_native_one_two_and_thirty_three_page_tagged_documents(self):
        """Real generated PDF tag-parent entry maps match all declared physical pages."""
        for pdf, count in ((self.seed, 1), (self.two, 2), (self.thirty_three, 33)):
            with self.subTest(pages=count):
                plan = self.make_plan(pdf, count)
                result = self.inspect(pdf_bytes=pdf, plan=plan,
                                      expected_plan_sha256=plan.plan_sha256)
                self.assertEqual(result.page_count, count)
                self.assertEqual(result.tagged_pages, count)
                self.assertEqual(result.parent_tree_entries, count)
                self.assertEqual(result.pdf_sha256, digest(pdf))
                self.assertEqual(result.to_dict()["status"], "PAGE_TAG_PARENTTREE_INSPECTED")

    def test_metadata_prerequisites_reused(self):
        """The unchanged catalog prerequisite validator is applied inside the worker."""
        from reporting.pdf_accessibility import validate_pdf_accessibility_structure
        result = validate_pdf_accessibility_structure(
            pdf_bytes=self.two, expected_language="en-US")
        self.assertTrue(result.passed)
        receipt = self.inspect().to_dict()
        self.assertEqual(receipt["language"], result.language)
        self.assertIs(receipt["catalog_prerequisites_met"], True)

    def test_expanded_blank_pages_do_not_gain_false_tag_coverage(self):
        """A synthetic expanded PDF does not acquire parent-tree references automatically."""
        self.rejected(metadata_fixture(self.seed, 33), 33)

    def test_missing_or_noninteger_page_structparents_rejected(self):
        """Every physical page must supply a native nonnegative integer page-parent key."""
        def missing(writer):
            """Modify only synthetic PDF internals for a rejection check."""
            del writer.pages[0]["/StructParents"]
        self.rejected(mutate(self.two, missing))
        for value in (TextStringObject("0"), NumberObject(-1)):
            def changed(writer):
                """Modify only synthetic PDF internals for a rejection check."""
                writer.pages[0][NameObject("/StructParents")] = value
            self.rejected(mutate(self.two, changed))

    def test_duplicate_page_parent_keys_rejected(self):
        """Two physical pages cannot masquerade as the same parent-tree slot."""
        def change(writer):
            """Modify only synthetic PDF internals for a rejection check."""
            writer.pages[1][NameObject("/StructParents")] = NumberObject(0)
        self.rejected(mutate(self.two, change))

    def test_missing_parenttree_and_flat_nums_rejected(self):
        """Neither missing nor unsupported hierarchical maps can claim this narrow profile."""
        def absent(writer):
            """Modify only synthetic PDF internals for a rejection check."""
            del writer.root_object["/StructTreeRoot"].get_object()["/ParentTree"]
        self.rejected(mutate(self.two, absent))
        def kids(writer):
            """Modify only synthetic PDF internals for a rejection check."""
            _, p = tree(writer)
            del p["/Nums"]
            p[NameObject("/Kids")] = ArrayObject([])
        self.rejected(mutate(self.two, kids))
        def empty(writer):
            """Modify only synthetic PDF internals for a rejection check."""
            _, p = tree(writer)
            p[NameObject("/Nums")] = ArrayObject([])
        self.rejected(mutate(self.two, empty))

    def test_missing_duplicate_and_unsorted_parenttree_keys_rejected(self):
        """The map uses exactly one strictly increasing native key for each page."""
        for mutation in ("missing", "duplicate", "reverse", "extra"):
            def change(writer):
                """Modify only synthetic PDF internals for a rejection check."""
                _, p = tree(writer)
                nums = p["/Nums"]
                if mutation == "missing":
                    del nums[2:4]
                elif mutation == "duplicate":
                    nums[2] = NumberObject(0)
                elif mutation == "reverse":
                    nums[:] = [nums[2], nums[3], nums[0], nums[1]]
                else:
                    nums.extend([NumberObject(100), ArrayObject([NullObject()])])
            self.rejected(mutate(self.two, change))

    def test_empty_null_and_wrong_parenttree_values_rejected(self):
        """Each slot must contain at least one actual typed structure reference."""
        for mutation in ("empty", "null", "text"):
            def change(writer):
                """Modify only synthetic PDF internals for a rejection check."""
                _, p = tree(writer)
                nums = p["/Nums"]
                if mutation == "empty":
                    nums[1] = ArrayObject([])
                elif mutation == "null":
                    nums[1] = ArrayObject([NullObject()])
                else:
                    nums[1] = TextStringObject("SYNTHETIC_PRIVATE")
            self.rejected(mutate(self.two, change))

    def test_foreign_page_reference_rejected(self):
        """A structure element for page zero cannot refer to page one."""
        def wrong(writer):
            """Modify only synthetic PDF internals for a rejection check."""
            _, p = tree(writer)
            record = p["/Nums"][1][0].get_object()
            record[NameObject("/Pg")] = writer.pages[1].indirect_reference
        self.rejected(mutate(self.two, wrong))

    def test_wrong_structelem_type_and_missing_pg_rejected(self):
        """Every enumerated parent object is a structure element tied to an actual page."""
        for mutation in ("type", "page"):
            def change(writer):
                """Modify only synthetic PDF internals for a rejection check."""
                _, p = tree(writer)
                elem = p["/Nums"][1][0].get_object()
                if mutation == "type":
                    elem[NameObject("/Type")] = NameObject("/Annot")
                else:
                    del elem["/Pg"]
            self.rejected(mutate(self.two, change))

    def test_broken_or_cyclic_parent_ancestry_rejected(self):
        """Every page element must climb through bounded structural parents to this root."""
        def self_cycle(writer):
            """Modify only synthetic PDF internals for a rejection check."""
            _, p = tree(writer)
            entry = p["/Nums"][1][0]
            entry.get_object()[NameObject("/P")] = entry
        self.rejected(mutate(self.two, self_cycle))
        def missing(writer):
            """Modify only synthetic PDF internals for a rejection check."""
            _, p = tree(writer)
            elem = p["/Nums"][1][0].get_object()
            del elem["/P"]
        self.rejected(mutate(self.two, missing))

    def test_missing_or_wrong_catalog_prerequisites_rejected(self):
        """Only the existing en-US marked structural profile is admitted."""
        for mutation in ("language", "mark", "root"):
            def change(writer):
                """Modify only synthetic PDF internals for a rejection check."""
                if mutation == "language":
                    writer.root_object[NameObject("/Lang")] = TextStringObject("pt-BR")
                elif mutation == "mark":
                    writer.root_object.pop("/MarkInfo")
                else:
                    writer.root_object[NameObject("/StructTreeRoot")] = DictionaryObject({})
            self.rejected(mutate(self.two, change))

    def test_encrypted_malformed_and_version_other_than_17_rejected(self):
        """Malformed, encrypted, and non-PDF-1.7 content cannot yield a receipt."""
        def encrypted(writer):
            """Modify only synthetic PDF internals for a rejection check."""
            writer.encrypt("synthetic")
        self.rejected(mutate(self.two, encrypted))
        self.rejected(b"%PDF-1.7\ntruncated")
        with self.assertRaises(self.m.PdfPageTagError):
            self.inspect(pdf_bytes=self.two.replace(b"%PDF-1.7", b"%PDF-1.6", 1))

    def test_wrong_digest_wrong_plan_and_page_count_rejected(self):
        """All independently declared identities and actual physical counts are required."""
        for change in ({"expected_plan_sha256":"c"*64},
                       {"pdf_bytes":self.two+b"\n"},
                       {"plan":{}},
                       {"plan":self.make_plan(self.two,1),
                        "expected_plan_sha256":self.make_plan(self.two,1).plan_sha256}):
            with self.assertRaises(self.m.PdfPageTagError):
                self.inspect(**change)

    def test_page_and_byte_caps_are_not_expanded(self):
        """513-page declarations and an oversized PDF are rejected before worker creation."""
        plan = self.make_plan(self.two,513)
        with patch.object(self.m, "_run_worker") as run:
            with self.assertRaises(self.m.PdfPageTagError):
                self.inspect(plan=plan, expected_plan_sha256=plan.plan_sha256)
            run.assert_not_called()
        with patch.object(self.m, "_run_worker") as run:
            with self.assertRaises(self.m.PdfPageTagError):
                self.inspect(pdf_bytes=b"%PDF-1.7" + b"x" * (8*1024*1024))
            run.assert_not_called()

    def test_only_current_locale_accepted(self):
        """Unsupported locale values never reach the guarded parser."""
        for value in (None, "pt-BR", "en-US ", True):
            with patch.object(self.m, "_run_worker") as run:
                with self.assertRaises(self.m.PdfPageTagError):
                    self.inspect(expected_language=value)
                run.assert_not_called()

    def test_disable_fails_closed(self):
        """The optional module can be disabled without permissive fallback."""
        with patch.dict(os.environ, {"OMNIGENIS_PDF_PAGE_TAGS_DISABLED":"1"}), \
             patch.object(self.m,"_run_worker") as run:
            with self.assertRaises(self.m.PdfPageTagError):
                self.inspect()
            run.assert_not_called()

    def test_no_pdf_parser_in_the_calling_process(self):
        """Untrusted parsing occurs only behind the guarded worker boundary."""
        with patch("pypdf.PdfReader",side_effect=AssertionError("host parser")):
            self.assertEqual(self.inspect().tagged_pages,2)

    def test_protocol_strict_shape_and_limits(self):
        """No extra fields or changed finite resource claims may be decoded."""
        r=self.response()
        self.assertEqual(self.m._decode(json.dumps(r).encode(),self.identity()).page_count,2)
        for key,value in (("profile_id","foreign"),("parser_version","0"),("protocol_version",True),
                          ("policy_id","foreign"),("unknown",True)):
            record=self.response(); record[key]=value
            with self.assertRaises(self.m.PdfPageTagError):
                self.m._decode(json.dumps(record).encode(),self.identity())
        record=self.response();record["limits"]["memory_bytes"]=0
        with self.assertRaises(self.m.PdfPageTagError):
            self.m._decode(json.dumps(record).encode(),self.identity())

    def test_protocol_tag_counts_are_native_and_exact(self):
        """Truthy counts or one missing page cannot become all-page evidence."""
        for field,value in (("tagged_pages",1),("tagged_pages",True),
                            ("parent_tree_entries",0),("parent_tree_entries",2.0),
                            ("language","pt-BR"),("status","PASS")):
            record=self.response();record["inspection"][field]=value
            with self.assertRaises(self.m.PdfPageTagError):
                self.m._decode(json.dumps(record).encode(),self.identity())

    def test_duplicate_json_nonbytes_and_overbudget_response_rejected(self):
        """Ambiguous, unreadable, or excessive native responses are not evidence."""
        raw=json.dumps(self.response()).encode()
        duplicate=raw[:-1]+b',"protocol_version":1}'
        for value in (b"",b"\xff",b"x"*4097,duplicate,bytearray(raw)):
            with self.assertRaises(self.m.PdfPageTagError):
                self.m._decode(value,self.identity())

    def test_input_and_receipt_do_not_leak_metadata_or_semantic_claims(self):
        """Only exact page/reference counts leave the worker; no full PDF/UA claim is inferred."""
        r=self.inspect()
        self.assertEqual(r.page_count,2)
        self.assertEqual(r.to_dict()["inspection_scope"],
                         "PAGE_STRUCTPARENTS_PARENTTREE_REFERENCE_COHERENCE_ONLY")
        for name in ("all_marked_content_covered","semantic_tag_tree_verified",
                     "reading_order_verified","full_accessibility_qualified",
                     "all_metadata_channels_inspected","aggregate_job_resources_qualified",
                     "worker_results_authenticated","release_authorized"):
            self.assertIs(r.to_dict()[name],False)
        self.assertEqual(r.to_dict()["release_authorization"],"NOT_ESTABLISHED")
        self.assertNotIn("SYNTHETIC_PRIVATE",json.dumps(r.to_dict()))
        with self.assertRaises(FrozenInstanceError):
            r.tagged_pages=100
        with self.assertRaises(self.m.PdfPageTagError):
            replace(r,tagged_pages=True)

    def test_digest_determinism_and_detached_record(self):
        """Repeat inspection gives an identical unsigned record but never authenticates a job."""
        a=self.inspect();b=self.inspect()
        self.assertEqual(a.inspection_sha256,b.inspection_sha256)
        record=a.to_dict();record["tagged_pages"]=0
        self.assertEqual(a.to_dict()["tagged_pages"],2)

    def test_native_error_is_content_free(self):
        """Untrusted worker failures cannot reveal private values in exceptions."""
        with patch.object(self.m,"_run_worker",side_effect=OSError("SYNTHETIC_PRIVATE")):
            with self.assertRaises(self.m.PdfPageTagError) as caught:
                self.inspect()
            self.assertNotIn("SYNTHETIC_PRIVATE",str(caught.exception))

    def test_native_guard_failure_precedes_pdf_read(self):
        """Each required process confinement guard blocks before bytes are consumed."""
        for blocked in ("_limits","_lifetime","enforce_pdf_landlock",
                        "enforce_pdf_network_filter"):
            with tempfile.TemporaryFile() as src,tempfile.TemporaryFile() as dest,ExitStack() as stack:
                for name in ("_limits","_lifetime","enforce_pdf_landlock",
                             "enforce_pdf_network_filter"):
                    stack.enter_context(patch.object(self.w,name,
                        side_effect=RuntimeError("blocked") if name==blocked else None))
                reader=stack.enter_context(patch.object(self.w,"_read_request",
                    side_effect=AssertionError("unexpected read")))
                code=self.w.main(["worker",str(src.fileno()),str(dest.fileno()),str(os.getpid())])
                self.assertEqual(code,70)
                reader.assert_not_called()
                self.assertEqual(os.fstat(dest.fileno()).st_size,0)

    def test_anonymous_protocol_output_and_stale_parent_rejected(self):
        """Aliased, named or populated descriptors and stale parents cannot write success."""
        with tempfile.TemporaryFile() as src,tempfile.TemporaryFile() as dest,\
             tempfile.NamedTemporaryFile() as named:
            dest.write(b"prior");dest.flush()
            for first,second in ((src.fileno(),src.fileno()),
                                 (src.fileno(),dest.fileno()),
                                 (named.fileno(),src.fileno())):
                self.assertEqual(self.w.main(
                    ["worker",str(first),str(second),str(os.getpid())]),64)
        with tempfile.TemporaryFile() as src,tempfile.TemporaryFile() as dest:
            child=subprocess.run([sys.executable,"-I",
                str(ROOT/"reporting/_pdf_page_tags_worker.py"),
                str(src.fileno()),str(dest.fileno()),str(os.getpid()+1000000)],
                pass_fds=(src.fileno(),dest.fileno()),capture_output=True,timeout=15)
            self.assertNotEqual(child.returncode,0)
            self.assertEqual(child.stdout,b"")
            self.assertEqual(os.fstat(dest.fileno()).st_size,0)

    def test_native_worker_releases_parent_descriptors(self):
        """Finished guarded child does not leak file descriptors on the host."""
        before=len(os.listdir("/proc/self/fd"))
        self.inspect();self.inspect()
        self.assertEqual(len(os.listdir("/proc/self/fd")),before)

    def test_manifest_pins_existing_deps_and_limits(self):
        """One additive profile retains reviewed parser version, validators and finite limits."""
        manifest=json.loads((ROOT/"reporting/pdf-page-tags-engine.v1.json").read_text())
        self.assertEqual(manifest["profile_id"],PROFILE)
        self.assertEqual(manifest["parser_version"],"6.19.0")
        self.assertFalse(manifest["default_pipeline_activated"])
        self.assertEqual(manifest["resource_budget"]["pages"],512)
        self.assertEqual(manifest["resource_budget"]["pdf_bytes"],8388608)
        for name,hash_value in manifest["reused_source_sha256"].items():
            self.assertEqual(digest((ROOT/name).read_bytes()),hash_value)

    def test_default_whole_pdf_limit_remains_32(self):
        """The original default safety route remains strictly bounded."""
        from reporting._pdf_safety_worker import MAX_PAGES
        self.assertEqual(MAX_PAGES,32)

if __name__=="__main__":
    unittest.main()
