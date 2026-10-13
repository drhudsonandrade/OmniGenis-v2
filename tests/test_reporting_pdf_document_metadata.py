"""Synthetic native metadata and catalog-prerequisite inspection controls."""
from __future__ import annotations

import ast
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, replace
import hashlib
import importlib
import importlib.util
from io import BytesIO
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import zlib

from reporting.adapters import build_html_css_and_pdf_adapter
from reporting.page_windows import plan_pdf_page_windows
from reporting.pdf_text_windows import PROFILE_ID as TEXT_PROFILE
from tests.test_reporting_rpt12_pdf_metadata import presentation, rewrite_candidate, raw_xmp_candidate

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "generated-pdf-document-metadata-v1"


def digest(data):
    """Hash synthetic bytes without retaining report data in evidence."""
    return hashlib.sha256(data).hexdigest()


def metadata_fixture(seed, pages):
    """Expand a synthetic page tree; this does not create fully tagged long reports."""
    from pypdf import PdfWriter
    writer = PdfWriter(clone_from=BytesIO(seed))
    writer.pdf_header = b"%PDF-1.7"
    while len(writer.pages) < pages:
        writer.add_blank_page(width=612, height=792)
    output = BytesIO(); writer.write(output)
    return output.getvalue()


def mutate(pdf, change):
    """Apply one synthetic PDF mutation while preserving other source surfaces."""
    from pypdf import PdfWriter
    writer = PdfWriter(clone_from=BytesIO(pdf)); writer.pdf_header = b"%PDF-1.7"
    change(writer)
    output = BytesIO(); writer.write(output)
    return output.getvalue()


class PdfDocumentMetadataTests(unittest.TestCase):
    """Require exact native metadata identity without claiming whole-report quality."""

    @classmethod
    def setUpClass(cls):
        """Build one existing native fixture and its synthetic thirty-three-page variant."""
        result = build_html_css_and_pdf_adapter(presentation_ir=presentation())
        if not result.passed:
            raise AssertionError(result.errors)
        cls.seed = result.pdf_bytes
        cls.pdf = metadata_fixture(cls.seed, 33)

    def setUp(self):
        """Make absent implementation an explicit RED boundary failure."""
        self.assertIsNotNone(importlib.util.find_spec("reporting.pdf_document_metadata"),
                             "exact document metadata adapter is missing")
        self.m = importlib.import_module("reporting.pdf_document_metadata")
        self.w = importlib.import_module("reporting._pdf_document_metadata_worker")
        self.plan = self.make_plan(self.pdf, 33)

    def make_plan(self, pdf, pages):
        """Use the existing independently declared text plan as document identity."""
        return plan_pdf_page_windows(pdf_sha256=digest(pdf), ir_sha256="b" * 64,
            page_count=pages, admitted_page_budget=pages, pages_per_window=16,
            inspector_profile_id=TEXT_PROFILE)

    def inspect(self, **changes):
        """Invoke the actual adapter unless an individual negative test replaces its worker."""
        args = dict(pdf_bytes=self.pdf, plan=self.plan,
                    expected_plan_sha256=self.plan.plan_sha256, expected_language="en-US")
        args.update(changes)
        return self.m.inspect_pdf_document_metadata(**args)

    def reject(self, pdf, pages=33):
        """Require content-free native failure on a freshly identity-bound mutated candidate."""
        plan = self.make_plan(pdf, pages)
        with self.assertRaises(self.m.PdfDocumentMetadataError) as caught:
            self.inspect(pdf_bytes=pdf, plan=plan, expected_plan_sha256=plan.plan_sha256)
        self.assertNotIn("SYNTHETIC-PRIVATE", str(caught.exception))

    def identity(self):
        """Detach the exact four-field document protocol identity."""
        return dict(pdf_sha256=self.plan.pdf_sha256, ir_sha256=self.plan.ir_sha256,
                    plan_sha256=self.plan.plan_sha256, page_count=33)

    def response(self):
        """Construct explicit protocol data only for decoder-negative controls."""
        return dict(protocol_version=1, profile_id=PROFILE, parser_version="6.19.0",
            identity=self.identity(), limits=dict(memory_bytes=268435456, cpu_seconds=5,
                file_bytes=4096, open_files=128), inspection=dict(status="DOCUMENT_METADATA_INSPECTED",
                metadata_profile_id="omnigenis-generated-pdf-metadata-v1", language="en-US",
                marked=True, struct_tree_root=True))

    def test_real_native_small_and_long_catalog_inspection(self):
        """The guarded worker measures every declared physical count through the existing policy."""
        for count in (1, 33, 64, 129, 300, 512):
            pdf = metadata_fixture(self.seed, count); plan = self.make_plan(pdf, count)
            receipt = self.inspect(pdf_bytes=pdf, plan=plan, expected_plan_sha256=plan.plan_sha256)
            self.assertEqual(receipt.page_count, count)
            self.assertEqual(receipt.pdf_sha256, digest(pdf))
            self.assertEqual(receipt.to_dict()["status"], "DOCUMENT_METADATA_INSPECTED")

    def test_native_receipt_matches_unmodified_metadata_policies(self):
        """The adapter preserves approved metadata decisions rather than inventing a new policy."""
        from reporting.pdf_qa import validate_pdf_candidate, GENERATED_PDF_AUTHOR, GENERATED_PDF_METADATA_PROFILE
        from reporting.pdf_accessibility import validate_pdf_accessibility_structure
        q = validate_pdf_candidate(pdf_bytes=self.pdf, expected_pdf_sha256=digest(self.pdf),
            expected_author=GENERATED_PDF_AUTHOR, expected_language="en-US",
            metadata_profile=GENERATED_PDF_METADATA_PROFILE)
        a = validate_pdf_accessibility_structure(pdf_bytes=self.pdf, expected_language="en-US")
        self.assertTrue(q.passed and a.passed)
        result = self.inspect().to_dict()
        self.assertEqual(result["page_count"], q.page_count)
        self.assertEqual(result["metadata_profile_id"], q.metadata_profile_id)
        self.assertIs(result["marked"], a.marked)
        self.assertIs(result["struct_tree_root"], a.struct_tree_root)

    def test_wrong_info_values_rejected(self):
        """Every approved Info identity is independently required."""
        for key in ("/Author", "/Title", "/Creator", "/Producer"):
            self.reject(rewrite_candidate(self.pdf, updates={key: "SYNTHETIC-PRIVATE-VALUE"}))

    def test_missing_or_extra_info_rejected(self):
        """Required fields cannot be absent and extra benign fields cannot be smuggled in."""
        for key in ("/Author", "/Title", "/Creator", "/Producer"):
            self.reject(rewrite_candidate(self.pdf, remove=(key,)))
        self.reject(rewrite_candidate(self.pdf, updates={"/Subject": "synthetic extra"}))

    def test_missing_or_malformed_document_xmp_rejected(self):
        """Missing or malformed global XMP cannot yield an inspection record."""
        self.reject(rewrite_candidate(self.pdf, remove_xmp=True))
        self.reject(raw_xmp_candidate(self.pdf, b"not xml"))

    def test_changed_or_extended_xmp_rejected(self):
        """All global controlled XML properties remain bound to the existing profile."""
        from pypdf import PdfReader
        raw = PdfReader(BytesIO(self.pdf)).root_object["/Metadata"].get_data()
        self.reject(raw_xmp_candidate(self.pdf, raw.replace(b"OmniGenis", b"Different")))
        extra = b'<rdf:Description rdf:about=""><xmp:Other>SYNTHETIC-PRIVATE</xmp:Other></rdf:Description>'
        self.reject(raw_xmp_candidate(self.pdf, raw.replace(b"</rdf:RDF>", extra + b"</rdf:RDF>")))

    def test_xmp_decoding_budget_is_not_expanded(self):
        """Both plain and compressed excessive XMP fail under the current decoded-byte bound."""
        self.reject(raw_xmp_candidate(self.pdf, b"x" * 65537))
        self.reject(raw_xmp_candidate(self.pdf, zlib.compress(b"x" * 65537), filter_value="/FlateDecode"))

    def test_xmp_unsupported_filters_and_fields_rejected(self):
        """Unqualified decoding and stream fields cannot bypass the controlled XMP path."""
        self.reject(raw_xmp_candidate(self.pdf, b"abc", filter_value="/ASCIIHexDecode"))
        self.reject(rewrite_candidate(self.pdf, stream_field="synthetic"))

    def test_wrong_catalog_language_rejected(self):
        """The candidate locale must match the one already activated en-US profile."""
        for language in ("pt-BR", "en-US ", "SYNTHETIC-PRIVATE"):
            self.reject(rewrite_candidate(self.pdf, language=language))

    def test_false_or_missing_tag_mark_rejected(self):
        """The marked prerequisite is a real PDF Boolean, not truthy metadata."""
        from pypdf.generic import NameObject, BooleanObject, NumberObject
        for value in (BooleanObject(False), NumberObject(1)):
            def change(writer):
                """Replace the catalog mark in a synthetic fixture."""
                writer.root_object["/MarkInfo"][NameObject("/Marked")] = value
            self.reject(mutate(self.pdf, change))
        def remove(writer):
            """Remove the prerequisite mark dictionary."""
            del writer.root_object["/MarkInfo"]
        self.reject(mutate(self.pdf, remove))

    def test_invalid_or_missing_structure_root_rejected(self):
        """Catalog root presence and its PDF Name type remain mandatory."""
        from pypdf.generic import NameObject, TextStringObject
        def change(writer):
            """Replace the root type with an impermissible PDF string."""
            writer.root_object["/StructTreeRoot"][NameObject("/Type")] = TextStringObject("/StructTreeRoot")
        self.reject(mutate(self.pdf, change))
        def remove(writer):
            """Delete the catalog structure reference."""
            del writer.root_object["/StructTreeRoot"]
        self.reject(mutate(self.pdf, remove))

    def test_catalog_prerequisites_do_not_claim_complete_tag_tree(self):
        """A root-only fixture explicitly cannot prove per-page tag coverage or reading order."""
        from pypdf.generic import NameObject, DictionaryObject
        def root_only(writer):
            """Retain only a correctly typed but otherwise empty tag root."""
            writer.root_object[NameObject("/StructTreeRoot")] = DictionaryObject({NameObject("/Type"):NameObject("/StructTreeRoot")})
        pdf = mutate(self.pdf, root_only); plan = self.make_plan(pdf, 33)
        result = self.inspect(pdf_bytes=pdf, plan=plan, expected_plan_sha256=plan.plan_sha256).to_dict()
        self.assertFalse(result["semantic_tag_tree_verified"])
        self.assertFalse(result["full_accessibility_qualified"])

    def test_page_local_metadata_is_outside_declared_scope(self):
        """This operation makes no sanitization claim for page-local metadata channels."""
        from pypdf.generic import NameObject, TextStringObject
        def page_metadata(writer):
            """Add a synthetic page-local value not examined by document metadata rules."""
            writer.pages[-1][NameObject("/Metadata")] = TextStringObject("SYNTHETIC-PRIVATE-PAGE")
        pdf = mutate(self.pdf, page_metadata); plan = self.make_plan(pdf, 33)
        result = self.inspect(pdf_bytes=pdf, plan=plan, expected_plan_sha256=plan.plan_sha256).to_dict()
        self.assertFalse(result["all_metadata_channels_inspected"])
        self.assertNotIn("SYNTHETIC-PRIVATE", json.dumps(result))

    def test_object_actions_are_not_metadata_safety_qualification(self):
        """Separate effective-graph safety remains required even after valid metadata."""
        from pypdf.generic import NameObject, DictionaryObject, TextStringObject
        def action(writer):
            """Insert a synthetic action without executing it."""
            writer.root_object[NameObject("/OpenAction")] = DictionaryObject({NameObject("/S"):NameObject("/JavaScript"),NameObject("/JS"):TextStringObject("synthetic")})
        pdf = mutate(self.pdf, action); plan = self.make_plan(pdf, 33)
        result = self.inspect(pdf_bytes=pdf, plan=plan, expected_plan_sha256=plan.plan_sha256).to_dict()
        self.assertFalse(result["whole_pdf_safety_qualified"])

    def test_encryption_and_malformed_pdf_rejected(self):
        """Neither encrypted nor broken structure creates a successful metadata receipt."""
        def encrypt(writer):
            """Encrypt only synthetic bytes for a rejection control."""
            writer.encrypt("synthetic")
        self.reject(mutate(self.pdf, encrypt))
        self.reject(b"%PDF-1.7\nbroken")

    def test_actual_page_count_must_match_declaration(self):
        """The guarded validator's measured count must equal the pinned declaration."""
        plan = self.make_plan(self.pdf, 32)
        with self.assertRaises(self.m.PdfDocumentMetadataError):
            self.inspect(plan=plan, expected_plan_sha256=plan.plan_sha256)

    def test_over_budget_pdf_rejected_before_hashing(self):
        """Byte admission prevents hashing or subprocess work for excessive candidates."""
        with patch.object(self.m.hashlib, "sha256", side_effect=AssertionError("hash")), patch.object(self.m, "_run_worker") as run:
            with self.assertRaises(self.m.PdfDocumentMetadataError):
                self.inspect(pdf_bytes=b"%PDF-1.7\n" + b"x" * (8 * 1024 * 1024))
            run.assert_not_called()

    def test_non_native_inputs_and_other_versions_rejected(self):
        """Caller coercion and unqualified PDF versions are not accepted."""
        for value in (None, bytearray(self.pdf), "%PDF-1.7", self.pdf.replace(b"%PDF-1.7", b"%PDF-1.6", 1)):
            with self.assertRaises(self.m.PdfDocumentMetadataError): self.inspect(pdf_bytes=value)

    def test_declared_page_budget_cannot_expand(self):
        """A 513-page plan is rejected before any native invocation."""
        plan = self.make_plan(self.pdf, 513)
        with patch.object(self.m, "_run_worker") as run:
            with self.assertRaises(self.m.PdfDocumentMetadataError): self.inspect(plan=plan, expected_plan_sha256=plan.plan_sha256)
            run.assert_not_called()

    def test_foreign_expected_plan_or_pdf_rejected(self):
        """The caller must independently pin the exact plan and candidate."""
        for change in (dict(expected_plan_sha256="c" * 64),dict(pdf_bytes=self.pdf+b"\n"),dict(plan={})):
            with self.assertRaises(self.m.PdfDocumentMetadataError): self.inspect(**change)

    def test_locale_activation_is_not_expanded(self):
        """Unsupported and non-native language expectations fail before process startup."""
        for value in ("pt-BR", "en-US ", None, True):
            with patch.object(self.m, "_run_worker") as run:
                with self.assertRaises(self.m.PdfDocumentMetadataError): self.inspect(expected_language=value)
                run.assert_not_called()

    def test_disable_is_fail_closed(self):
        """Disabling this optional adapter withholds inspection without affecting defaults."""
        with patch.dict(os.environ, {"OMNIGENIS_PDF_DOCUMENT_METADATA_DISABLED":"1"}), patch.object(self.m, "_run_worker") as run:
            with self.assertRaises(self.m.PdfDocumentMetadataError): self.inspect()
            run.assert_not_called()

    def test_no_host_pdf_parser(self):
        """Candidate parsing belongs to the isolated worker, never the caller process."""
        with patch("pypdf.PdfReader", side_effect=AssertionError("host parser")):
            self.assertEqual(self.inspect().page_count, 33)

    def test_response_is_closed_and_exact(self):
        """A valid strict protocol decodes; extra or foreign top-level fields do not."""
        result = self.m._decode(json.dumps(self.response()).encode(), self.identity())
        self.assertEqual(result.page_count,33)
        for change in ({"extra":True},{"profile_id":"foreign"},{"parser_version":"0"},{"protocol_version":True}):
            value=self.response(); value.update(change)
            with self.assertRaises(self.m.PdfDocumentMetadataError): self.m._decode(json.dumps(value).encode(),self.identity())

    def test_response_identity_and_limits_are_strict(self):
        """Foreign digests, bool counts and unreported limits cannot become metadata evidence."""
        for field,value in (("pdf_sha256","c"*64),("ir_sha256","c"*64),("plan_sha256","c"*64),("page_count",True)):
            record=self.response();record["identity"][field]=value
            with self.assertRaises(self.m.PdfDocumentMetadataError):self.m._decode(json.dumps(record).encode(),self.identity())
        for field in self.response()["limits"]:
            record=self.response();record["limits"][field]=0
            with self.assertRaises(self.m.PdfDocumentMetadataError):self.m._decode(json.dumps(record).encode(),self.identity())

    def test_response_cannot_claim_false_or_integer_tag_flags(self):
        """Only complete true prerequisite flags in the correct profile are accepted."""
        for field,value in (("marked",False),("marked",1),("struct_tree_root",False),("language","pt-BR"),("metadata_profile_id","foreign"),("status","PASS")):
            record=self.response();record["inspection"][field]=value
            with self.assertRaises(self.m.PdfDocumentMetadataError):self.m._decode(json.dumps(record).encode(),self.identity())

    def test_duplicate_json_and_empty_or_oversized_response_rejected(self):
        """Duplicate fields and non-bounded data cannot override protocol identities."""
        raw=json.dumps(self.response()).encode();duplicate=raw[:-1]+b',"protocol_version":1}'
        for value in (b"",b"x"*4097,duplicate,bytearray(raw),b"\xff"):
            with self.assertRaises(self.m.PdfDocumentMetadataError):self.m._decode(value,self.identity())

    def test_post_execution_plan_mutation_rejected(self):
        """Successful worker bytes cannot conceal a concurrently replaced frozen expectation."""
        def changed(pdf, identity):
            """Simulate a caller mutation during native work without launching a process."""
            object.__setattr__(self.plan,"ir_sha256","c"*64)
            return json.dumps(self.response()).encode()
        with patch.object(self.m,"_run_worker",side_effect=changed):
            with self.assertRaises(self.m.PdfDocumentMetadataError):self.inspect()

    def test_failures_never_leak_internal_details(self):
        """A native error or missing reply cannot produce success or raw diagnostics."""
        for failure in (OSError("SYNTHETIC-PRIVATE"),ValueError("SYNTHETIC-PRIVATE")):
            with patch.object(self.m,"_run_worker",side_effect=failure):
                with self.assertRaises(self.m.PdfDocumentMetadataError) as caught:self.inspect()
                self.assertNotIn("SYNTHETIC-PRIVATE",str(caught.exception))

    def test_receipt_is_frozen_detached_and_deterministic(self):
        """Simple receipt construction is validated and does not create portable authority."""
        a=self.inspect();b=self.inspect();self.assertEqual(a.inspection_sha256,b.inspection_sha256)
        with self.assertRaises(FrozenInstanceError):a.page_count=1
        record=a.to_dict();record["page_count"]=1;self.assertEqual(a.to_dict()["page_count"],33)
        with self.assertRaises(self.m.PdfDocumentMetadataError):replace(a,page_count=True)

    def test_scope_flags_remain_unqualified(self):
        """Valid document metadata never implies full PDF, science, tags or release approval."""
        record=self.inspect().to_dict()
        for key in ("worker_results_authenticated","whole_pdf_safety_qualified","semantic_tag_tree_verified","full_accessibility_qualified","all_metadata_channels_inspected","aggregate_job_resources_qualified","release_authorized"):
            self.assertIs(record[key],False)
        self.assertEqual(record["release_authorization"],"NOT_ESTABLISHED")
        self.assertNotIn("metadata",record)

    def test_native_calls_do_not_leak_parent_descriptors(self):
        """The parent releases request/result handles after native completion."""
        before=len(os.listdir("/proc/self/fd"));self.inspect();self.inspect()
        self.assertEqual(len(os.listdir("/proc/self/fd")),before)

    def test_worker_guard_failure_prevents_candidate_read(self):
        """Mandatory guard errors occur before any request is read or evidence is written."""
        for guard in ("_limits","_lifetime","enforce_pdf_landlock","enforce_pdf_network_filter"):
            with tempfile.TemporaryFile() as source,tempfile.TemporaryFile() as result,ExitStack() as stack:
                for name in ("_limits","_lifetime","enforce_pdf_landlock","enforce_pdf_network_filter"):
                    stack.enter_context(patch.object(self.w,name,side_effect=RuntimeError("guard") if name==guard else None))
                read=stack.enter_context(patch.object(self.w,"_read_request",side_effect=AssertionError("read")))
                code=self.w.main(["worker",str(source.fileno()),str(result.fileno()),str(os.getpid())])
                self.assertEqual(code,70);read.assert_not_called();self.assertEqual(os.fstat(result.fileno()).st_size,0)

    def test_named_aliased_and_populated_result_fds_rejected(self):
        """Protocol files must be separate anonymous empty-output owned regular objects."""
        with tempfile.TemporaryFile() as source,tempfile.TemporaryFile() as result,tempfile.NamedTemporaryFile() as named:
            result.write(b"prior");result.flush()
            for first,second in ((source.fileno(),source.fileno()),(source.fileno(),result.fileno()),(named.fileno(),source.fileno())):
                with patch.object(self.w,"_limits") as limits:
                    self.assertEqual(self.w.main(["worker",str(first),str(second),str(os.getpid())]),64)
                    limits.assert_not_called()

    def test_stale_parent_native_rejected_without_output(self):
        """The actual isolated worker rejects a different live-parent expectation."""
        with tempfile.TemporaryFile() as source,tempfile.TemporaryFile() as result:
            child=subprocess.run([sys.executable,"-I",str(ROOT/"reporting/_pdf_document_metadata_worker.py"),str(source.fileno()),str(result.fileno()),str(os.getpid()+1000000)],pass_fds=(source.fileno(),result.fileno()),capture_output=True,timeout=15)
            self.assertNotEqual(child.returncode,0);self.assertEqual(child.stdout,b"");self.assertEqual(os.fstat(result.fileno()).st_size,0)

    def test_default_page_limit_unchanged(self):
        """The existing whole-file safety route still refuses this thirty-three-page fixture."""
        from reporting._pdf_safety_worker import inspect_document,MAX_PAGES
        self.assertEqual(MAX_PAGES,32);self.assertEqual(inspect_document(self.pdf)["status"],"BLOCKED")
        self.assertEqual(self.inspect().page_count,33)

    def test_manifest_pins_unchanged_rules_and_dependencies(self):
        """The optional profile identifies the exact existing validators and finite budgets."""
        manifest=json.loads((ROOT/"reporting/pdf-document-metadata-engine.v1.json").read_text())
        self.assertEqual(manifest["profile_id"],PROFILE);self.assertFalse(manifest["default_pipeline_activated"])
        self.assertEqual(manifest["parser_version"],"6.19.0")
        self.assertEqual(manifest["resource_budget"]["pages"],512)
        self.assertEqual(manifest["resource_budget"]["pdf_bytes"],8*1024*1024)
        for path,value in manifest["reused_source_sha256"].items():self.assertEqual(digest((ROOT/path).read_bytes()),value)

    def test_all_added_functions_have_docstrings(self):
        """Every new function states its scope before external review."""
        for name in ("reporting/pdf_document_metadata.py","reporting/_pdf_document_metadata_worker.py","tests/test_reporting_pdf_document_metadata.py"):
            for node in ast.walk(ast.parse((ROOT/name).read_text())):
                if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):self.assertTrue(ast.get_docstring(node),f"{name}:{node.name}")


if __name__ == "__main__":
    unittest.main()
