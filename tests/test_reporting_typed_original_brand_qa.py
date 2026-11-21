"""Same-artifact combined typed/original-brand QA behavior, using synthetic inputs."""
from __future__ import annotations

from copy import deepcopy
from contextlib import ExitStack, contextmanager
from decimal import Decimal
from hashlib import sha256
from io import BytesIO
import importlib
import importlib.util
import json
import multiprocessing
import os
import re
from pathlib import Path
import unittest
import tempfile
from types import SimpleNamespace
import zlib
from unittest.mock import patch

from pypdf import PdfReader, PdfWriter
from pypdf.generic import (ArrayObject, ByteStringObject, ContentStream, DecodedStreamObject,
                           DictionaryObject, FloatObject, NameObject, NumberObject, TextStringObject)
from reporting.brand_assets import BoundBrandAssets
from reporting.typed_original_brand_pdf import render_typed_original_brand_pdf
from reporting.typed_pdf_source import prepare_typed_pdf_source
from test_reporting_typed_pdf_source import document, digest
from test_reporting_typed_projection import context

ROOT = Path(__file__).resolve().parents[1]
FLAGS = {
    "OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE": "qualification-only",
    "OMNIGENIS_TYPED_ORIGINAL_BRAND_QA_DISABLED": "",
    "OMNIGENIS_TYPED_BRAND_RENDER_DISABLED": "",
    "OMNIGENIS_TYPED_ORIGINAL_BRAND_PDF_DISABLED": "",
    "OMNIGENIS_TYPED_EDITORIAL_PDF_DISABLED": "",
    "OMNIGENIS_PDF_PRELOADED_RASTER_DISABLED": "",
    "OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED": "",
    "OMNIGENIS_PDF_RENDERER_DISABLED": "",
    "OMNIGENIS_TYPED_PDF_OBSERVATION_DISABLED": "",
    "OMNIGENIS_PDF_RASTER_WINDOWS_DISABLED": "",
    "OMNIGENIS_PDF_DOCUMENT_METADATA_DISABLED": "",
}


def _install_flat_id_tree(writer):
    """Index only an explicitly prepared fixture, preserving each key's original bytes."""
    pairs = []
    def visit(value):
        value = value.get_object()
        if isinstance(value, DictionaryObject):
            if value.get("/Type") == "/StructElem" and "/ID" in value:
                identifier = value.raw_get("/ID")
                if type(identifier) is TextStringObject:
                    original = identifier.original_bytes
                elif type(identifier) is ByteStringObject:
                    original = bytes(identifier)
                else:
                    raise ValueError("synthetic_id_tree_control_refused")
                pairs.append((original, identifier, value.indirect_reference))
            if "/K" in value:
                visit(value.raw_get("/K"))
        elif isinstance(value, ArrayObject):
            for child in value:
                visit(child)
    root = writer._root_object["/StructTreeRoot"]
    visit(root)
    pairs.sort(key=lambda row: row[0])
    if len({original for original, _, _ in pairs}) != len(pairs):
        raise ValueError("synthetic_id_tree_control_refused")
    names = ArrayObject([value for _, identifier, reference in pairs
                         for value in (identifier, reference)])
    root[NameObject("/IDTree")] = writer._add_object(
        DictionaryObject({NameObject("/Names"): names}))


@contextmanager
def _temporary_profile_tree(module, *, inherited=False):
    """Use real private copies while the original observer audit stays active."""
    source_root = module.ROOT
    manifest_name = module.MANIFEST.relative_to(source_root)
    names = set(module.SOURCE_FILES) | {str(manifest_name)}
    if inherited:
        prior_name = module.prior._PROFILE_FILE.relative_to(source_root)
        prior_manifest = json.loads(module.prior._PROFILE_FILE.read_bytes())
        names.update(prior_manifest["source_sha256"])
        names.add(str(prior_name))
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for name in sorted(names):
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((source_root / name).read_bytes())
        with ExitStack() as stack:
            stack.enter_context(patch.object(module, "ROOT", root))
            stack.enter_context(patch.object(module, "MANIFEST", root / manifest_name))
            if inherited:
                stack.enter_context(patch.object(module.prior, "ROOT", root))
                stack.enter_context(patch.object(module.prior, "_PROFILE_FILE", root / prior_name))
            yield root


@contextmanager
def _observe_profile_file_reads(paths, *, after_read=None):
    """Observe real entrypoint I/O and clean up any descriptor a regression leaks."""
    paths = set(paths)
    records, opened = [], {}
    real_open, real_read, real_close = os.open, os.read, os.close
    real_read_bytes = Path.read_bytes

    def opened_file(path, flags, *args, **kwargs):
        descriptor = real_open(path, flags, *args, **kwargs)
        path = Path(os.fsdecode(path))
        if path in paths:
            record = dict(path=path, flags=flags, requests=[], returned=[],
                          legacy=False, closed=False)
            records.append(record)
            opened[descriptor] = record
        return descriptor

    def read_file(descriptor, count):
        data = real_read(descriptor, count)
        record = opened.get(descriptor)
        if record is not None:
            record["requests"].append(count)
            if after_read is not None:
                data = after_read(record["path"], data)
            record["returned"].append(len(data))
        return data

    def closed_file(descriptor):
        result = real_close(descriptor)
        record = opened.pop(descriptor, None)
        if record is not None:
            record["closed"] = True
        return result

    def read_path(path):
        data = real_read_bytes(path)
        if path in paths:
            record = dict(path=path, flags=None, requests=[-1], returned=[],
                          legacy=True, closed=True)
            records.append(record)
            if after_read is not None:
                data = after_read(path, data)
            record["returned"].append(len(data))
        return data

    with patch.object(os, "open", opened_file), patch.object(os, "read", read_file), \
            patch.object(os, "close", closed_file), patch.object(Path, "read_bytes", read_path):
        try:
            yield records
        finally:
            # Keep closed=False as evidence even after restoring test isolation.
            for descriptor in tuple(opened):
                real_close(descriptor)


class TypedOriginalBrandQATests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        asset = ROOT / "reporting/assets"
        cls.assets = BoundBrandAssets(
            logo_svg=(asset / "omnigenis_logo.svg").read_bytes(),
            dna_png=(asset / "dna_column.png").read_bytes(),
            permission_notice=(asset / "brand-permission.md").read_bytes())
        cls.bundle = cls.assets.to_dict()["bundle_sha256"]
        cls.fixtures = {}
        cls.pristine_fixtures = {}

    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("reporting.typed_original_brand_qa"),
                             "combined typed/original-brand same-PDF QA is missing")
        self.m = importlib.import_module("reporting.typed_original_brand_qa")
        mode = patch.dict(os.environ, FLAGS)
        mode.start()
        self.addCleanup(mode.stop)

    def fixture(self, count=2, *, navigation=False):
        key = (count, "navigation") if navigation else count
        if key not in self.fixtures:
            source = self.navigation_source(count) if navigation else document(count)
            rendered, _ = render_typed_original_brand_pdf(
                presentation_ir=source, expected_ir_sha256=digest(source),
                assets=self.assets, expected_brand_bundle_sha256=self.bundle)
            pristine = rendered.pdf_bytes
            self.pristine_fixtures[key] = source, pristine
            self.fixtures[key] = source, pristine
        source, pdf = self.fixtures[key]
        return deepcopy(source), pdf

    @staticmethod
    def navigation_source(count):
        """Bind two real section headings separated by content-driven layout."""
        from reporting.components import (
            FindingRow, FindingsTable, TableColumn, TextComponent,
            build_typed_report_projection, component_content_sha256,
        )
        request, ledger = context(count)
        parts = (
            TextComponent("title", "identity", "document_title", "Technical report"),
            TextComponent("identity-heading", "identity", "section_heading", "Record identity"),
            # Keep the fixture bounded; the test checks distinct observed heading pages.
            TextComponent("identity-text", "identity", "paragraph",
                          " ".join(["Synthetic identity context only."] * 160)),
            TextComponent("heading", "findings", "section_heading", "Declared findings"),
            TextComponent("intro", "findings", "paragraph", "Synthetic values only."),
            FindingsTable("table", "findings", "All declared synthetic findings",
                (TableColumn("variant", "Variant"), TableColumn("value", "Value")),
                tuple(FindingRow(f, (f"NM_000001.1:c.{i + 1}A>G", "0.12345678901234567890"))
                      for i, f in enumerate(request.plan.expected_finding_ids))),
        )
        return build_typed_report_projection(
            request=request, ledger=ledger,
            projection_request_sha256=request.request.request_sha256,
            expected_content_sha256=component_content_sha256(parts), components=parts).to_dict()

    def arguments(self, count=2, *, navigation=False):
        source, pdf = self.fixture(count, navigation=navigation)
        expectation = prepare_typed_pdf_source(
            presentation_ir=source, expected_ir_sha256=digest(source))
        return dict(
            presentation_ir=source, expected_ir_sha256=digest(source),
            expected_source_expectation_sha256=expectation.expectation_sha256,
            assets=self.assets, expected_brand_bundle_sha256=self.bundle,
            pdf_bytes=pdf, expected_pdf_sha256=sha256(pdf).hexdigest(),
            expected_profile_sha256=self.m.profile_sha256())

    def run_qa(self, args=None):
        return self.m.validate_typed_original_brand_candidate(
            **(self.arguments() if args is None else args))

    def test_untouched_producer_indexes_headers_and_emits_logo_in_page_space(self):
        _, pdf = self.fixture()
        reader = PdfReader(BytesIO(pdf), strict=True)
        root = reader.root_object["/StructTreeRoot"]
        with self.subTest(obligation="header-index"):
            self.assertIn("/IDTree", root)
        page = reader.pages[0]
        figure = next(node for node in self.nodes(SimpleNamespace(_root_object=reader.root_object))
                      if node["/S"] == "/Figure")
        box = figure["/A"]["/BBox"]
        transform = ContentStream(page.raw_get("/Contents"), reader).operations[0][0]
        with self.subTest(obligation="page-space-logo"):
            # The actual original logo is placed in the top half of the first page.
            self.assertGreater(float(box[1]), float(transform[-1]) / 2)
        with self.subTest(obligation="same-artifact-qa"):
            self.assertEqual(self.run_qa(self.arguments()).to_dict()["pdf_sha256"],
                             sha256(pdf).hexdigest())

    def test_wrapped_cover_title_preserves_every_source_space(self):
        """Bind one wrapped title to real PDF runs without inventing whitespace."""
        from reporting.components import (
            FindingRow, FindingsTable, TableColumn, TextComponent,
            build_typed_report_projection, component_content_sha256,
        )
        title = "A demonstration report that preserves every literal space in a wrapped title"
        request, ledger = context(1)
        parts = (
            TextComponent("title", "identity", "document_title", title),
            TextComponent("heading", "findings", "section_heading", "Demonstration findings"),
            TextComponent("intro", "findings", "paragraph", "Demonstration values only."),
            FindingsTable(
                "table", "findings", "Declared demonstration findings",
                (TableColumn("identifier", "Identifier"), TableColumn("value", "Value")),
                (FindingRow(request.plan.expected_finding_ids[0], ("DEMO-001", "0.1")),)),
        )
        source = build_typed_report_projection(
            request=request, ledger=ledger,
            projection_request_sha256=request.request.request_sha256,
            expected_content_sha256=component_content_sha256(parts),
            components=parts).to_dict()
        ir_sha = digest(source)
        expectation = prepare_typed_pdf_source(
            presentation_ir=source, expected_ir_sha256=ir_sha)
        title_unit = expectation.to_dict()["units"][0]
        self.assertEqual(title_unit["kind"], "document_title")
        self.assertEqual(title_unit["utf8_bytes"], len(title.encode("utf-8")))
        self.assertEqual(title_unit["text_sha256"], sha256(title.encode("utf-8")).hexdigest())
        rendered, _ = render_typed_original_brand_pdf(
            presentation_ir=source, expected_ir_sha256=ir_sha,
            assets=self.assets, expected_brand_bundle_sha256=self.bundle)
        pdf, pdf_sha = rendered.pdf_bytes, rendered.pdf_sha256
        observations = []
        original_worker = self.m._run_worker

        def retain_observation(candidate_bytes, candidate_sha):
            self.assertEqual(candidate_bytes, pdf)
            self.assertEqual(candidate_sha, pdf_sha)
            raw = original_worker(candidate_bytes, candidate_sha)
            observations.append(json.loads(raw))
            return raw

        with patch.object(self.m, "_run_worker", side_effect=retain_observation):
            result = self.run_qa(dict(
                presentation_ir=source, expected_ir_sha256=ir_sha,
                expected_source_expectation_sha256=expectation.expectation_sha256,
                assets=self.assets, expected_brand_bundle_sha256=self.bundle,
                pdf_bytes=pdf, expected_pdf_sha256=pdf_sha,
                expected_profile_sha256=self.m.profile_sha256())).to_dict()
        self.assertEqual(len(observations), 1)
        self.assertEqual(result["pdf_sha256"], pdf_sha)
        self.assertEqual(result["ir_sha256"], ir_sha)
        self.assertEqual(result["source_expectation_sha256"], expectation.expectation_sha256)
        trace = observations[0]["trace"]
        nodes = {tuple(node["reference"]): node for node in trace["nodes"]}
        headings = [node for node in nodes.values() if node["role"] == "/H1"]
        self.assertEqual(len(headings), 1)
        heading = headings[0]
        page = next(page for page in trace["pages"]
                    if page["reference"] == heading["page_reference"])
        runs = {run["mcid"]: run for run in page["runs"]}
        fragments = []
        for child in heading["children"]:
            self.assertEqual(child["kind"], "node")
            span = nodes[tuple(child["reference"])]
            self.assertEqual(span["role"], "/Span")
            self.assertEqual(span["page_reference"], heading["page_reference"])
            self.assertEqual(len(span["children"]), 1)
            run = runs[span["children"][0]["value"]]
            self.assertEqual(run["structure_reference"], span["reference"])
            fragments.append(run["text"])
        self.assertGreater(len(fragments), 1)
        literal = "".join(fragments)
        self.assertEqual(literal, title)
        self.assertEqual(len(literal.encode("utf-8")), title_unit["utf8_bytes"])
        self.assertEqual(sha256(literal.encode("utf-8")).hexdigest(), title_unit["text_sha256"])

    def test_generated_editorial_ids_do_not_reserve_source_component_ids(self):
        from dataclasses import replace
        from reporting.components import (
            FindingRow, FindingsTable, TableColumn, TextComponent,
            build_typed_report_projection, component_content_sha256,
        )
        request, ledger = context(1)
        parts = (
            TextComponent("fixed-navigation-title", "identity", "document_title", "Technical report"),
            TextComponent("fixed-navigation-0", "findings", "section_heading", "Declared findings"),
            TextComponent("fixed-brand-0", "findings", "paragraph", "Synthetic values only."),
            FindingsTable(
                "fixed-brand-1", "findings", "Declared synthetic findings",
                (TableColumn("identifier", "Identifier"), TableColumn("value", "Value")),
                (FindingRow(request.plan.expected_finding_ids[0], ("SYNTHETIC-001", "0.1")),)),
        )
        ledger = replace(ledger, represented=tuple(
            replace(finding, component_ids=(parts[-1].component_id,))
            for finding in ledger.represented))
        source = build_typed_report_projection(
            request=request, ledger=ledger,
            projection_request_sha256=request.request.request_sha256,
            expected_content_sha256=component_content_sha256(parts), components=parts).to_dict()
        ir_sha = digest(source)
        expectation = prepare_typed_pdf_source(
            presentation_ir=source, expected_ir_sha256=ir_sha)
        rendered, _ = render_typed_original_brand_pdf(
            presentation_ir=source, expected_ir_sha256=ir_sha,
            assets=self.assets, expected_brand_bundle_sha256=self.bundle)
        associations = []
        associate = self.m._associate

        def retain_association(manifest, physical, document):
            result = associate(manifest, physical, document)
            associations.append(result)
            return result

        with patch.object(self.m, "_associate", side_effect=retain_association):
            receipt = self.run_qa(dict(
                presentation_ir=source, expected_ir_sha256=ir_sha,
                expected_source_expectation_sha256=expectation.expectation_sha256,
                assets=self.assets, expected_brand_bundle_sha256=self.bundle,
                pdf_bytes=rendered.pdf_bytes, expected_pdf_sha256=rendered.pdf_sha256,
                expected_profile_sha256=self.m.profile_sha256())).to_dict()
        self.assertEqual(receipt["ir_sha256"], ir_sha)
        self.assertEqual(receipt["source_expectation_sha256"], expectation.expectation_sha256)
        self.assertEqual(receipt["pdf_sha256"], rendered.pdf_sha256)
        self.assertIs(receipt["complete_literal_source_accounting"], True)
        self.assertEqual(len(associations), 1)
        navigation = associations[0]["editorial_navigation"]
        self.assertEqual(len(navigation), 1)
        self.assertEqual(navigation[0]["source_component_id"], "fixed-navigation-0")
        self.assertEqual(navigation[0]["source_section_id"], "findings")

    def test_full_multipage_source_brand_and_every_page_bind_to_exact_caller_bytes(self):
        args = self.arguments(96)
        before = bytes(args["pdf_bytes"])
        self.assertEqual(before, self.pristine_fixtures[96][1])
        result = self.run_qa(args).to_dict()
        self.assertEqual(result["status"], "TYPED_ORIGINAL_BRAND_CANDIDATE_INSPECTED")
        self.assertEqual(result["pdf_sha256"], sha256(before).hexdigest())
        self.assertEqual(args["pdf_bytes"], before)
        self.assertEqual(result["ir_sha256"], args["expected_ir_sha256"])
        self.assertEqual(result["represented_findings"], 96)
        self.assertEqual(result["source_units"], 198)
        self.assertEqual(result["brand_text_units"], 2)
        self.assertEqual(result["navigation_entries"], 1)
        self.assertEqual(result["pagination_pages"], result["page_count"])
        self.assertEqual(result["coverage"]["pagination_blocks"], result["page_count"])
        self.assertEqual(result["coverage"]["accounted_brand_wrapper_nodes"], 6)
        self.assertEqual(result["coverage"]["accounted_navigation_wrapper_nodes"], 1)
        self.assertEqual(result["figure_count"], 1)
        self.assertEqual(result["dna_image_count"], 1)
        self.assertEqual(result["original_credit_count"], 1)
        self.assertGreaterEqual(result["page_count"], 3)
        self.assertEqual(result["raster_inspected_pages"], result["page_count"])
        self.assertEqual(set(result["stages"].values()), {"PASS"})
        self.assertTrue(result["complete_literal_source_accounting"])
        self.assertTrue(result["complete_native_structure_accounting"])
        for key in ("visual_semantic_parity_verified", "human_assistive_accessibility_verified",
                    "whole_job_resources_qualified", "pdf_ua_certified",
                    "source_asset_bytes_authenticated_from_pdf", "release_authorized"):
            self.assertIs(result[key], False)

    def refuse(self, args):
        with self.assertRaisesRegex(self.m.TypedOriginalBrandQAError,
                                    "^typed_original_brand_qa_refused$"):
            self.run_qa(args)

    def rewritten(self, mutate=lambda writer: None, count=2, *, navigation=False):
        args = self.arguments(count, navigation=navigation)
        writer = PdfWriter(clone_from=PdfReader(BytesIO(args["pdf_bytes"]), strict=True))
        writer.pdf_header = b"%PDF-1.7"
        mutate(writer)
        output = BytesIO()
        writer.write(output)
        args["pdf_bytes"] = output.getvalue()
        args["expected_pdf_sha256"] = sha256(args["pdf_bytes"]).hexdigest()
        return args

    @staticmethod
    def nodes(writer):
        result = []
        def visit(value):
            value = value.get_object()
            if isinstance(value, DictionaryObject):
                if value.get("/Type") == "/StructElem":
                    result.append(value)
                if "/K" in value:
                    visit(value.raw_get("/K"))
            elif isinstance(value, ArrayObject):
                for child in value:
                    visit(child)
        visit(writer._root_object.raw_get("/StructTreeRoot"))
        return result

    @staticmethod
    def edit_page(writer, index, mutate):
        page = writer.pages[index]
        content = ContentStream(page.raw_get("/Contents"), writer, forced_encoding="bytes")
        mutate(content.operations)
        replacement = DecodedStreamObject()
        replacement.set_data(content.get_data())
        page[NameObject("/Contents")] = writer._add_object(replacement)

    def footer_range(self, operations):
        """Locate the exact admitted footer, not the final arbitrary TJ."""
        starts = [i for i, (args, op) in enumerate(operations)
                  if op == b"BDC" and len(args) == 2 and args[0] == "/Artifact"
                  and isinstance(args[1], DictionaryObject)
                  and args[1].get("/Type") == "/Pagination"
                  and args[1].get("/Subtype") == "/Footer"]
        self.assertEqual(len(starts), 1)
        start = starts[0]
        end = next(i for i in range(start + 1, len(operations))
                   if operations[i][1] == b"EMC")
        return start, end

    def text_slots(self, writer, node):
        """Resolve a named structural subtree to its actual page/Span MCIDs."""
        pages = {(page.indirect_reference.idnum, page.indirect_reference.generation): index
                 for index, page in enumerate(writer.pages)}
        slots = []
        def visit(value):
            value = value.get_object()
            if isinstance(value, ArrayObject):
                for child in value:
                    visit(child)
            elif isinstance(value, DictionaryObject):
                if value.get("/S") == "/Span":
                    children = value["/K"]
                    if isinstance(children, ArrayObject):
                        self.assertEqual(len(children), 1)
                        children = children[0]
                    self.assertIs(type(children), NumberObject)
                    page = value.raw_get("/Pg")
                    slots.append((pages[(page.idnum, page.generation)], int(children)))
                elif "/K" in value:
                    visit(value.raw_get("/K"))
        visit(node)
        self.assertTrue(slots)
        return slots

    def span_range(self, operations, mcid):
        starts = [i for i, (args, op) in enumerate(operations)
                  if op == b"BDC" and args[0] == "/Span"
                  and args[1].get("/MCID") == mcid]
        self.assertEqual(len(starts), 1)
        start = starts[0]
        end = next(i for i in range(start + 1, len(operations))
                   if operations[i][1] == b"EMC")
        return start, end

    @staticmethod
    def operation_floor(receipt):
        # Existing logo/DNA/Form floor543; each footer adds BDC +7 events +EMC.
        return 7 * receipt["coverage"]["text_mcids"] + 543 + 9 * receipt["pagination_pages"]

    def change_first_glyph(self, operands, replacement=None):
        """Change an actual CID, preserving the TJ container and byte length."""
        parts = operands[0]
        strings = [(index, bytes(value)) for index, value in enumerate(parts)
                   if type(value) is ByteStringObject and len(value) >= 2]
        self.assertTrue(strings)
        index, raw = strings[0]
        self.assertEqual(len(raw) % 2, 0)
        if replacement is None:
            replacement = next(value[offset:offset + 2] for _, value in strings
                               for offset in range(0, len(value), 2)
                               if value[offset:offset + 2] != raw[:2])
        self.assertEqual(len(replacement), 2)
        self.assertNotEqual(replacement, raw[:2])
        parts[index] = ByteStringObject(replacement + raw[2:])

    def page_with_multiple_spans(self, writer):
        for index, page in enumerate(writer.pages):
            operations = ContentStream(page.raw_get("/Contents"), writer,
                                       forced_encoding="bytes").operations
            if sum(op == b"BDC" and args[0] == "/Span" for args, op in operations) >= 2:
                return index
        self.fail("fixture needs an actual page with at least two source spans")

    def native_record(self, count=2, *, navigation=False):
        if not hasattr(self, "_native_records"):
            self._native_records = {}
        key = (count, "navigation") if navigation else count
        if key not in self._native_records:
            args = self.arguments(count, navigation=navigation)
            raw = self.m._run_worker(args["pdf_bytes"], args["expected_pdf_sha256"])
            self._native_records[key] = self.m.prior._loads(raw.decode("ascii"))
        return deepcopy(self._native_records[key])

    def test_valid_rewritten_control_and_receipt_remain_immutable_and_scoped(self):
        args = self.rewritten()
        receipt = self.run_qa(args)
        result = receipt.to_dict()
        self.assertEqual(result["pdf_sha256"], args["expected_pdf_sha256"])
        self.assertEqual(result["source_units"], 10)
        self.assertEqual(result["represented_findings"], 2)
        self.assertEqual(result["raster_inspected_pages"], result["page_count"])
        result["stages"]["source_identity"] = "FAIL"
        self.assertEqual(receipt.to_dict()["stages"]["source_identity"], "PASS")
        for key in self.m.NONCLAIMS:
            self.assertIs(receipt.to_dict()[key], False)
            bad = receipt.to_dict()
            bad[key] = True
            with self.subTest(claim=key), self.assertRaises(Exception):
                self.m.TypedOriginalBrandQA(self.m.canonical(bad))
        bad = receipt.to_dict()
        bad["status"] = "FINAL"
        with self.assertRaises(Exception):
            self.m.TypedOriginalBrandQA(self.m.canonical(bad))

    def test_source_expectation_digest_requires_exact_string_and_value(self):
        args = self.arguments()
        expected = args["expected_source_expectation_sha256"]
        self.assertIs(type(expected), str)
        self.assertEqual(self.run_qa(args).to_dict()["source_expectation_sha256"], expected)
        comparisons = []
        class EqualToAnyDigest:
            def __eq__(self, other):
                comparisons.append(other)
                return True
        class DigestString(str):
            pass
        wrong = ("0" if expected[0] != "0" else "1") + expected[1:]
        for case, value in (
                ("equality-spoof", EqualToAnyDigest()), ("str-subclass", DigestString(expected)),
                ("malformed", "not-a-digest"), ("wrong-value", wrong)):
            candidate = dict(args, expected_source_expectation_sha256=value)
            with self.subTest(case=case), patch.object(
                    self.m, "_run_worker", wraps=self.m._run_worker) as launch:
                self.refuse(candidate)
                launch.assert_not_called()
                if case == "equality-spoof":
                    self.assertEqual(comparisons, [])

    def test_wrong_identity_and_disabled_mode_refuse_before_native_launch(self):
        for name in ("expected_ir_sha256", "expected_source_expectation_sha256",
                     "expected_brand_bundle_sha256", "expected_pdf_sha256",
                     "expected_profile_sha256"):
            args = self.arguments()
            args[name] = "0" * 64
            with self.subTest(identity=name), patch.object(self.m, "_run_worker") as launch:
                self.refuse(args)
                launch.assert_not_called()
        for name, value in (("OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE", ""),
                            ("OMNIGENIS_TYPED_ORIGINAL_BRAND_QA_DISABLED", "1")):
            with self.subTest(flag=name), patch.dict(os.environ, {name: value}), \
                    patch.object(self.m, "_run_worker") as launch:
                self.refuse(self.arguments())
                launch.assert_not_called()

    def test_freshly_sealed_changed_literal_and_missing_or_extra_findings_refuse(self):
        for source in (document(2, paragraph="SYNTHETIC-SENTINEL-REJECT"),
                       document(1), document(3)):
            args = self.arguments()
            args["presentation_ir"] = source
            args["expected_ir_sha256"] = digest(source)
            args["expected_source_expectation_sha256"] = prepare_typed_pdf_source(
                presentation_ir=source, expected_ir_sha256=digest(source)).expectation_sha256
            with self.subTest(source_sha256=args["expected_ir_sha256"]):
                self.refuse(args)

    def test_native_parent_tree_requires_ascending_key_pairs(self):
        control = self.rewritten(count=96)
        self.assertEqual(self.run_qa(control).to_dict()["represented_findings"], 96)
        def reorder(writer):
            nums = writer._root_object["/StructTreeRoot"]["/ParentTree"]["/Nums"]
            self.assertGreaterEqual(len(nums), 4)
            keys = [int(nums[i]) for i in range(0, len(nums), 2)]
            self.assertEqual(keys, sorted(keys))
            first = list(nums[0:4])
            nums[0:4] = [first[2], first[3], first[0], first[1]]
            self.assertEqual([int(nums[0]), int(nums[2])], [keys[1], keys[0]])
        self.refuse(self.rewritten(reorder, count=96))

    def test_native_id_tree_matches_declared_table_identifiers(self):
        from pypdf.generic import IndirectObject
        from reporting import _pdf_typed_original_brand_qa_worker as worker
        def declared(reader):
            nodes = self.nodes(SimpleNamespace(_root_object=reader.root_object))
            return {node["/ID"].original_bytes:
                    (node.indirect_reference.idnum, node.indirect_reference.generation)
                    for node in nodes if "/ID" in node}
        def parse_structure(args):
            reader = PdfReader(BytesIO(args["pdf_bytes"]), strict=True)
            trace, _, _ = worker._structure(reader, worker.native._page_tree(reader))
            self.assertEqual({node["native_id"].encode("latin-1"): tuple(node["reference"])
                              for node in trace["nodes"] if node["native_id"] is not None},
                             declared(reader))
            return reader
        for indirect in (False, True):
            def container(writer):
                root = writer._root_object["/StructTreeRoot"]
                index = root["/IDTree"]
                root[NameObject("/IDTree")] = writer._add_object(index) if indirect else index
            with self.subTest(valid_index_indirect=indirect):
                args = self.rewritten(container)
                reader = parse_structure(args)
                self.assertIs(type(reader.root_object["/StructTreeRoot"].raw_get("/IDTree")),
                              IndirectObject if indirect else DictionaryObject)
                self.assertEqual(self.run_qa(args).to_dict()["represented_findings"], 2)

        baseline = PdfReader(BytesIO(self.arguments()["pdf_bytes"]), strict=True)
        expected = declared(baseline)
        self.assertEqual(len(expected), 2)
        content = tuple(page["/Contents"].get_data() for page in baseline.pages)
        index = baseline.root_object["/StructTreeRoot"].raw_get("/IDTree")
        worker._structure_id_tree(baseline, DictionaryObject({NameObject("/Names"): ArrayObject()}), {})
        with patch.object(worker.contract, "MAX_VISITS", 2 * len(expected) - 1):
            with patch.object(worker, "_identifier", side_effect=AssertionError("length guard must precede keys")):
                with self.assertRaisesRegex(ValueError, "^typed original-brand QA refused$"):
                    worker._structure_id_tree(baseline, index, expected)
        foreign = PdfReader(BytesIO(self.arguments()["pdf_bytes"]), strict=True)
        with self.assertRaises(ValueError):
            worker._structure_id_tree(
                baseline, foreign.root_object["/StructTreeRoot"].raw_get("/IDTree"), expected)

        def corrupt(writer, mode):
            root = writer._root_object["/StructTreeRoot"]
            index = root["/IDTree"]
            names = index["/Names"]
            if mode == "missing":
                del root["/IDTree"]
            elif mode == "empty":
                names.clear()
            elif mode == "short":
                del names[-2:]
            elif mode == "extra":
                names.extend([TextStringObject("unknown-index-id"), names[1]])
            elif mode == "duplicate":
                names[2:4] = names[0:2]
            elif mode == "unsorted":
                names[0:4] = names[2:4] + names[0:2]
            elif mode == "wrong-target":
                names[1], names[3] = names[3], names[1]
            elif mode == "page-target":
                names[1] = writer.pages[0].indirect_reference
            elif mode == "direct-target":
                names[1] = names[1].get_object()
            elif mode == "raw-byte-mismatch":
                names[0] = ByteStringObject(b"\xfe\xff" + str(names[0]).encode("utf-16-be"))
                pairs = sorted(zip(names[::2], names[1::2]),
                               key=lambda pair: bytes(pair[0]) if type(pair[0]) is ByteStringObject
                               else pair[0].original_bytes)
                names[:] = [value for pair in pairs for value in pair]
            elif mode == "names-type":
                index[NameObject("/Names")] = DictionaryObject()
            elif mode == "indirect-names":
                index[NameObject("/Names")] = writer._add_object(names)
            elif mode == "kids-outside-profile":
                index[NameObject("/Limits")] = ArrayObject([names[0], names[-2]])
                root[NameObject("/IDTree")] = DictionaryObject({
                    NameObject("/Kids"): ArrayObject([root.raw_get("/IDTree")])})
            elif mode == "limits-outside-profile":
                index[NameObject("/Limits")] = ArrayObject([names[0], names[-2]])
            else:
                self.fail("unknown fixture index mutation")
        for mode in ("missing", "empty", "short", "extra", "duplicate", "unsorted",
                     "wrong-target", "page-target", "direct-target", "raw-byte-mismatch",
                     "names-type", "indirect-names", "kids-outside-profile", "limits-outside-profile"):
            with self.subTest(invalid_index=mode):
                args = self.rewritten(lambda writer: corrupt(writer, mode))
                reader = PdfReader(BytesIO(args["pdf_bytes"]), strict=True)
                self.assertEqual(declared(reader), expected)
                self.assertEqual(tuple(page["/Contents"].get_data() for page in reader.pages), content)
                with self.assertRaises(ValueError):
                    worker._structure(reader, worker.native._page_tree(reader))
                if mode in {"missing", "wrong-target"}:
                    self.refuse(args)

        def mixed_encodings(writer):
            nodes = self.nodes(writer)
            headers = [node for node in nodes if node["/S"] == "/TH"]
            self.assertEqual(len(headers), 2)
            replacements = {str(header["/ID"]): identifier for header, identifier in zip(
                headers, (ByteStringObject(b"z"), ByteStringObject(b"\xfe\xff\x00a")), strict=True)}
            for node in nodes:
                if node["/S"] == "/TH":
                    node[NameObject("/ID")] = replacements[str(node["/ID"])]
                elif node["/S"] == "/TD":
                    references = node["/A"]["/Headers"]
                    references[0] = replacements[str(references[0])]
            _install_flat_id_tree(writer)
        mixed = self.rewritten(mixed_encodings)
        reader = parse_structure(mixed)
        keys = reader.root_object["/StructTreeRoot"]["/IDTree"]["/Names"][::2]
        self.assertEqual([key.original_bytes for key in keys], [b"z", b"\xfe\xff\x00a"])
        self.assertEqual([str(key) for key in keys], ["z", "a"])
        self.assertNotEqual([str(key) for key in keys], sorted(str(key) for key in keys))
        self.assertEqual(self.run_qa(mixed).to_dict()["represented_findings"], 2)

    def test_table_header_identifiers_match_original_bytes(self):
        raw_identifier = b"\x00raw-header"
        def encoded(value):
            return ByteStringObject(b"\xfe\xff" + str(value).encode("utf-16-be"))
        def change(writer, mode):
            nodes = self.nodes(writer)
            if mode == "headers-only":
                cell = next(n for n in nodes if n["/S"] == "/TD")
                cell["/A"]["/Headers"][0] = encoded(cell["/A"]["/Headers"][0])
            elif mode == "ids-only":
                header = next(n for n in nodes if n["/S"] == "/TH")
                header[NameObject("/ID")] = encoded(header["/ID"])
            elif mode == "matching-utf16":
                for node in nodes:
                    if node["/S"] == "/TH":
                        node[NameObject("/ID")] = encoded(str(node["/ID"]) + "\u0100")
                    elif node["/S"] == "/TD":
                        node["/A"]["/Headers"][0] = encoded(
                            str(node["/A"]["/Headers"][0]) + "\u0100")
            elif mode == "matching-nontext-outside-profile":
                header = next(n for n in nodes if n["/S"] == "/TH")
                original_id = str(header["/ID"])
                header[NameObject("/ID")] = ByteStringObject(raw_identifier)
                for node in nodes:
                    if node["/S"] == "/TD":
                        references = node["/A"]["/Headers"]
                        for index, reference in enumerate(references):
                            if str(reference) == original_id:
                                references[index] = ByteStringObject(raw_identifier)
            _install_flat_id_tree(writer)
        for mode in ("ascii", "matching-utf16", "headers-only", "ids-only",
                     "matching-nontext-outside-profile"):
            args = self.rewritten(lambda writer: change(writer, mode))
            reader = PdfReader(BytesIO(args["pdf_bytes"]), strict=True)
            nodes = self.nodes(SimpleNamespace(_root_object=reader.root_object))
            headers = {str(n["/ID"]): n["/ID"] for n in nodes if n["/S"] == "/TH"}
            mismatches = []
            nontext_pairs = 0
            for cell in (n for n in nodes if n["/S"] == "/TD"):
                reference = cell["/A"]["/Headers"][0]
                header = headers[str(reference)]
                if type(reference) is ByteStringObject:
                    self.assertEqual(mode, "matching-nontext-outside-profile")
                    self.assertIs(type(header), ByteStringObject)
                    self.assertEqual(bytes(reference), raw_identifier)
                    self.assertEqual(bytes(header), raw_identifier)
                    nontext_pairs += 1
                    mismatches.append(False)
                else:
                    self.assertIs(type(reference), TextStringObject)
                    self.assertIs(type(header), TextStringObject)
                    self.assertEqual(str(reference), str(header))
                    if mode == "matching-utf16":
                        self.assertIn("\u0100", str(reference))
                        self.assertTrue(reference.original_bytes.startswith(b"\xfe\xff"))
                        self.assertTrue(reference.original_bytes.endswith(b"\x01\x00"))
                    mismatches.append(reference.original_bytes != header.original_bytes)
            with self.subTest(mode=mode):
                if mode in {"ascii", "matching-utf16"}:
                    self.assertFalse(any(mismatches))
                    self.assertEqual(self.run_qa(args).to_dict()["represented_findings"], 2)
                elif mode == "matching-nontext-outside-profile":
                    self.assertGreater(nontext_pairs, 0)
                    self.assertFalse(any(mismatches))
                    self.refuse(args)
                else:
                    self.assertTrue(any(mismatches))
                    self.refuse(args)

        from jsonschema.exceptions import ValidationError
        args = self.arguments()
        native = self.native_record()
        header = next(n for n in native["trace"]["nodes"] if n["role"] == "/TH")
        previous = header["native_id"]
        header["native_id"] = "\u0100"
        matched = 0
        for node in native["trace"]["nodes"]:
            for index, identifier in enumerate(node["headers"]):
                if identifier == previous:
                    node["headers"][index] = "\u0100"
                    matched += 1
        self.assertGreater(matched, 0)
        self.m.project_text_trace(native["trace"])
        for boundary in ("schema", "parent"):
            with self.subTest(forged_native_identifier=boundary):
                with self.assertRaises(ValidationError):
                    if boundary == "schema":
                        self.m._schema(native, "native")
                    else:
                        self.m._validate_native(
                            native, args["pdf_bytes"], args["expected_profile_sha256"])

    def test_native_table_owner_and_figure_attribute_surface_refuse(self):
        def wrong_header(writer):
            cell = next(n for n in self.nodes(writer) if n["/S"] == "/TD")
            cell["/A"][NameObject("/Headers")] = ArrayObject([TextStringObject("foreign-header")])
        def duplicate_owner(writer):
            nums = writer._root_object["/StructTreeRoot"]["/ParentTree"]["/Nums"]
            owners = nums[1]
            owners[-1] = owners[0]
        def action_attribute(writer):
            figure = next(n for n in self.nodes(writer) if n["/S"] == "/Figure")
            figure["/A"][NameObject("/S")] = NameObject("/JavaScript")
        def catalog_action(writer):
            writer._root_object[NameObject("/OpenAction")] = DictionaryObject({
                NameObject("/S"): NameObject("/JavaScript"),
                NameObject("/JS"): TextStringObject("SYNTHETIC-SENTINEL-REJECT")})
        def foreign_navigation_wrapper(writer):
            paragraph = next(n for n in self.nodes(writer) if n["/S"] == "/P"
                             and n["/P"]["/S"] == "/Document")
            children = paragraph["/K"]
            self.assertTrue(all(child.get_object()["/S"] == "/Span" for child in children))
            wrapper = DictionaryObject({
                NameObject("/Type"): NameObject("/StructElem"),
                NameObject("/S"): NameObject("/NonStruct"),
                NameObject("/P"): paragraph.indirect_reference,
                NameObject("/Pg"): paragraph.raw_get("/Pg"),
                NameObject("/K"): children,
            })
            reference = writer._add_object(wrapper)
            for child in children:
                child.get_object()[NameObject("/P")] = reference
            paragraph[NameObject("/K")] = ArrayObject([reference])
        def cover_title_order(writer):
            document_node = next(n for n in self.nodes(writer) if n["/S"] == "/Document")
            cover = document_node["/K"][0].get_object()
            self.assertEqual([child.get_object()["/S"] for child in cover["/K"]],
                             ["/Div", "/Div", "/H1"])
            cover["/K"][1], cover["/K"][2] = cover["/K"][2], cover["/K"][1]
        for mutate in (wrong_header, duplicate_owner, action_attribute, catalog_action,
                       foreign_navigation_wrapper, cover_title_order):
            with self.subTest(mutation=mutate.__name__):
                self.refuse(self.rewritten(mutate))

    def test_logo_alternate_text_and_native_path_substitution_refuse(self):
        def wrong_alt(writer):
            figure = next(n for n in self.nodes(writer) if n["/S"] == "/Figure")
            figure[NameObject("/Alt")] = TextStringObject("SYNTHETIC-SENTINEL-REJECT")
        def wrong_path(writer):
            def alter(ops):
                inside = False
                for args, op in ops:
                    if op == b"BDC" and args[0] == "/Figure":
                        inside = True
                    elif inside and op == b"m":
                        args[0] = FloatObject(float(args[0]) + 1)
                        return
                self.fail("fixture logo path absent")
            self.edit_page(writer, 0, alter)
        for mutate in (wrong_alt, wrong_path):
            with self.subTest(mutation=mutate.__name__):
                self.refuse(self.rewritten(mutate))

    def test_figure_bbox_contains_the_actual_logo_geometry(self):
        from reporting import _pdf_typed_original_brand_qa_worker as worker
        def layout_box(writer):
            figure = next(n for n in self.nodes(writer) if n["/S"] == "/Figure")
            x0, y0, x1, y1 = map(float, figure["/A"]["/BBox"])
            page = writer.pages[0]
            h = float(ContentStream(page.raw_get("/Contents"), writer).operations[0][0][-1])
            values = (x0 / .75, (h-y1) / .75, x1 / .75, (h-y0) / .75)
            figure["/A"][NameObject("/BBox")] = ArrayObject([FloatObject(v) for v in values])

        coordinate_space = self.rewritten(layout_box)
        with self.subTest(candidate="css-coordinate-box-outside-page"):
            from reporting._pdf_original_svg_layout_worker import _Refusal
            reader = PdfReader(BytesIO(coordinate_space["pdf_bytes"]), strict=True)
            pages = worker.native._page_tree(reader)
            with self.assertRaisesRegex(_Refusal, "^pdf_svg_layout_invalid$"):
                worker._structure(reader, pages)
            self.refuse(coordinate_space)

        def undersized_page_box(writer):
            figure = next(n for n in self.nodes(writer) if n["/S"] == "/Figure")
            x0, y0, x1, y1 = map(float, figure["/A"]["/BBox"])
            values = (x0, y0, (x0 + x1) / 2, y1)
            figure["/A"][NameObject("/BBox")] = ArrayObject([FloatObject(v) for v in values])

        index_only = self.rewritten(undersized_page_box)
        reader = PdfReader(BytesIO(index_only["pdf_bytes"]), strict=True)
        original_figure = next(n for n in self.nodes(
            SimpleNamespace(_root_object=reader.root_object)) if n["/S"] == "/Figure")
        producer_box = [float(v) for v in original_figure["/A"]["/BBox"]]
        pages = worker.native._page_tree(reader)
        trace, attributes, figures = worker._structure(reader, pages)
        worker._passive(reader, attributes, figures)
        roles = {tuple(node["reference"]): node["role"] for node in trace["nodes"]}
        figure = next(node for node in trace["nodes"] if node["role"] == "/Figure")
        self.assertEqual([float(v) for v in figure["figure_bbox"]], producer_box)
        x0, y0, x1, y1 = map(Decimal, figure["figure_bbox"])
        declared_box = worker._rectangle((x0, y0, x1 - x0, y1 - y0), worker.IDENTITY)
        with patch.object(worker, "_contains", wraps=worker._contains) as contains:
            with self.assertRaisesRegex(ValueError, "^typed original-brand QA refused$"):
                worker._page(trace["pages"][0], pages[0][1], pages[0][2], reader,
                             {}, {}, roles, worker.contract.MAX_STREAM_BYTES)
            self.assertGreaterEqual(contains.call_count, 1)
            self.assertEqual(contains.call_args.args[0], declared_box)
        self.assertTrue(all(worker._contains(*call.args) for call in contains.call_args_list[:-1]))
        self.assertFalse(worker._contains(*contains.call_args.args))
        with self.subTest(candidate="in-page-box-with-insufficient-logo-coverage"):
            self.refuse(index_only)
        def box(writer, mode):
            figure = next(n for n in self.nodes(writer) if n["/S"] == "/Figure")
            corrected = [float(v) for v in figure["/A"]["/BBox"]]
            if mode == "full-page":
                values = [float(v) for v in writer.pages[0].mediabox]
            elif mode == "undersized-page-box":
                values = producer_box
            elif mode == "disjoint":
                values = [0, 0, 1, 1]
            elif mode == "partial":
                values = list(corrected)
                values[2] = (values[0] + values[2]) / 2
            else:
                return
            self.assertLess(values[0], values[2])
            self.assertLess(values[1], values[3])
            figure["/A"][NameObject("/BBox")] = ArrayObject([FloatObject(v) for v in values])
        for mode in ("corrected-synthetic", "full-page"):
            with self.subTest(control=mode):
                args = self.rewritten(lambda writer: box(writer, mode))
                self.assertEqual(self.run_qa(args).to_dict()["figure_count"], 1)
        for mode in ("undersized-page-box", "disjoint", "partial"):
            with self.subTest(mode=mode):
                self.refuse(self.rewritten(lambda writer: box(writer, mode)))

    def test_logo_paint_requires_containment_in_active_clips_and_page(self):
        def paint(writer, case):
            def alter(ops):
                start = next(i for i, (args, op) in enumerate(ops)
                             if op == b"BDC" and args[0] == "/Figure")
                end = next(i for i in range(start + 1, len(ops)) if ops[i][1] == b"EMC")
                if case == "translated-outside-page":
                    matrix = next(args for args, op in ops[start + 1:end] if op == b"cm")
                    matrix[4] = NumberObject(1000)
                    return
                payload = [([], b"q")]
                if case == "unknown-active-clip":
                    payload.extend([
                        ([NameObject("/Artifact")], b"BMC"),
                        ([NumberObject(0), NumberObject(0)], b"m"),
                        ([NumberObject(1), NumberObject(0)], b"l"),
                        ([NumberObject(0), NumberObject(1)], b"l"),
                        ([], b"W"), ([], b"n"), ([], b"EMC")])
                else:
                    rectangle = (0, 0, 1200, 1600) if case == "containing" else (0, 0, 1, 1)
                    payload.extend([
                        ([NumberObject(v) for v in rectangle], b"re"), ([], b"W"), ([], b"n")])
                if case == "restored":
                    payload.append(([], b"Q"))
                else:
                    ops.insert(end + 1, ([], b"Q"))
                ops[start:start] = payload
            self.edit_page(writer, 0, alter)
        for case in ("containing", "restored"):
            with self.subTest(control=case):
                args = self.rewritten(lambda writer: paint(writer, case))
                self.assertEqual(self.run_qa(args).to_dict()["figure_count"], 1)
        for case in ("excluding-active-clip", "unknown-active-clip", "translated-outside-page"):
            with self.subTest(case=case):
                self.refuse(self.rewritten(lambda writer: paint(writer, case)))

    def test_inherited_cropbox_uses_nearest_explicit_page_tree_value(self):
        from reporting import _pdf_typed_original_brand_qa_worker as worker
        def change(writer, case):
            leaves = list(writer.pages)
            root_ref = writer._root_object.raw_get("/Pages")
            root = root_ref.get_object()
            for page in leaves:
                page[NameObject("/CropBox")] = deepcopy(page.raw_get("/MediaBox"))
            first = leaves[0]
            full = deepcopy(first.raw_get("/MediaBox"))
            tiny = ArrayObject([NumberObject(v) for v in (0, 0, 1, 1)])
            del first["/CropBox"]
            root[NameObject("/CropBox")] = deepcopy(
                tiny if case in {"root-excludes", "leaf-overrides-root",
                                 "nearest-overrides-root"} else full)
            if case == "leaf-overrides-root":
                first[NameObject("/CropBox")] = full
            elif case in {"nearest-overrides-root", "nearest-excludes"}:
                self.assertEqual(first.raw_get("/Parent"), root_ref)
                first_ref = first.indirect_reference
                nearest = DictionaryObject({
                    NameObject("/Type"): NameObject("/Pages"),
                    NameObject("/Parent"): root_ref,
                    NameObject("/Kids"): ArrayObject([first_ref]),
                    NameObject("/Count"): NumberObject(1),
                    NameObject("/CropBox"): deepcopy(
                        full if case == "nearest-overrides-root" else tiny),
                })
                nearest_ref = writer._add_object(nearest)
                kids = root.raw_get("/Kids")
                position = next(i for i, child in enumerate(kids) if child == first_ref)
                kids[position] = nearest_ref
                first[NameObject("/Parent")] = nearest_ref
        for case in ("root-contains", "leaf-overrides-root", "nearest-overrides-root",
                     "root-excludes", "nearest-excludes"):
            args = self.rewritten(lambda writer: change(writer, case))
            reader = PdfReader(BytesIO(args["pdf_bytes"]), strict=True)
            pages = worker.native._page_tree(reader)
            leaf = pages[0][1]
            self.assertIn("/MediaBox", leaf)
            self.assertEqual("/CropBox" in leaf, case == "leaf-overrides-root")
            parent = leaf.raw_get("/Parent").get_object()
            self.assertIn("/CropBox", parent)
            full = list(leaf.raw_get("/MediaBox"))
            effective = leaf.raw_get("/CropBox") if "/CropBox" in leaf else parent.raw_get("/CropBox")
            self.assertEqual(list(effective),
                             [0, 0, 1, 1] if case in {"root-excludes", "nearest-excludes"} else full)
            if case == "leaf-overrides-root":
                self.assertEqual(list(parent.raw_get("/CropBox")), [0, 0, 1, 1])
            if case.startswith("nearest-"):
                self.assertEqual(parent["/Count"], 1)
                self.assertEqual(len(parent["/Kids"]), 1)
                ancestor = parent.raw_get("/Parent").get_object()
                self.assertEqual(list(ancestor.raw_get("/CropBox")),
                                 [0, 0, 1, 1] if case == "nearest-overrides-root" else full)
            with self.subTest(case=case):
                if case in {"root-excludes", "nearest-excludes"}:
                    with self.assertRaises(ValueError):
                        self.m._run_worker(args["pdf_bytes"], args["expected_pdf_sha256"])
                else:
                    raw = self.m._run_worker(args["pdf_bytes"], args["expected_pdf_sha256"])
                    native = self.m.prior._loads(raw.decode("ascii"))
                    self.assertEqual(native["page_count"], len(pages))
                    self.m._validate_native(
                        native, args["pdf_bytes"], args["expected_profile_sha256"])

    def test_singular_logo_wrapper_and_outer_transforms_refuse(self):
        for context in ("wrapper-0", "wrapper-1", "wrapper-2", "outer"):
            def collapse(writer):
                def alter(ops):
                    start = next(i for i, (args, op) in enumerate(ops)
                                 if op == b"BDC" and args[0] == "/Figure")
                    end = next(i for i in range(start + 1, len(ops)) if ops[i][1] == b"EMC")
                    if context == "outer":
                        ops.insert(end + 1, ([], b"Q"))
                        ops[start:start] = [
                            ([], b"q"),
                            ([NumberObject(v) for v in (0, 0, 0, 1, 0, 0)], b"cm")]
                    else:
                        matrices = [args for args, op in ops[start + 1:end] if op == b"cm"]
                        self.assertEqual(len(matrices), 5)
                        matrix = matrices[int(context[-1])]
                        matrix[0] = NumberObject(0)
                        matrix[1] = NumberObject(0)
                self.edit_page(writer, 0, alter)
            with self.subTest(context=context):
                self.refuse(self.rewritten(collapse))

    @staticmethod
    def dna_block_range(ops):
        paint = next(i for i, (_, op) in enumerate(ops) if op == b"Do")
        start = max(i for i in range(paint) if ops[i][1] == b"BMC"
                    and ops[i][0] == ["/Artifact"])
        end = next(i for i in range(paint + 1, len(ops)) if ops[i][1] == b"EMC")
        return start, end

    def test_dna_paint_requires_containing_local_inherited_and_form_clips(self):
        def inherited(writer, rectangle, restored=False):
            def alter(ops):
                start, end = self.dna_block_range(ops)
                payload = [
                    ([], b"q"), ([NumberObject(v) for v in rectangle], b"re"),
                    ([], b"W"), ([], b"n")]
                if restored:
                    payload.append(([], b"Q"))
                else:
                    ops.insert(end + 1, ([], b"Q"))
                ops[start:start] = payload
            self.edit_page(writer, 0, alter)

        for restored in (False, True):
            rectangle = (0, 0, 1, 1) if restored else (0, 0, 1200, 1600)
            with self.subTest(control_restored=restored):
                control = self.rewritten(lambda writer: inherited(writer, rectangle, restored))
                self.assertEqual(self.run_qa(control).to_dict()["dna_image_count"], 1)
        for case in ("empty-local", "excluding-local", "excluding-inherited",
                     "unknown-inherited", "clipping-form-bbox", "shifted-form-image"):
            def clip(writer):
                if case == "excluding-inherited":
                    inherited(writer, (0, 0, 1, 1))
                elif case == "unknown-inherited":
                    def alter(ops):
                        start, end = self.dna_block_range(ops)
                        ops.insert(end + 1, ([], b"Q"))
                        ops[start:start] = [
                            ([], b"q"), ([NameObject("/Artifact")], b"BMC"),
                            ([NumberObject(0), NumberObject(0)], b"m"),
                            ([NumberObject(1), NumberObject(0)], b"l"),
                            ([NumberObject(0), NumberObject(1)], b"l"),
                            ([], b"W"), ([], b"n"), ([], b"EMC")]
                    self.edit_page(writer, 0, alter)
                elif case in {"clipping-form-bbox", "shifted-form-image"}:
                    form = next(iter(writer.pages[0]["/Resources"]["/XObject"].values())).get_object()
                    if case == "clipping-form-bbox":
                        form[NameObject("/BBox")] = ArrayObject(
                            [NumberObject(v) for v in (0, 0, 1, 1)])
                    else:
                        content = ContentStream(form, writer, forced_encoding="bytes")
                        self.assertEqual([op for _, op in content.operations], [b"cm", b"cm", b"Do"])
                        content.operations[0][0][4] = NumberObject(1000)
                        form._data = zlib.compress(content.get_data())
                else:
                    def alter(ops):
                        start, end = self.dna_block_range(ops)
                        index = next(i for i in range(start + 1, end) if ops[i][1] == b"re")
                        rectangle = (0, 0, 0, 0) if case == "empty-local" else (0, 0, 1, 1)
                        ops[index] = ([NumberObject(v) for v in rectangle], b"re")
                    self.edit_page(writer, 0, alter)
            with self.subTest(case=case):
                self.refuse(self.rewritten(clip))

    def test_dna_paint_must_remain_on_its_structural_page(self):
        def relocate(writer):
            self.assertGreater(len(writer.pages), 1)
            moved = []
            def remove(ops):
                start, end = self.dna_block_range(ops)
                moved.extend(deepcopy(ops[start:end + 1]))
                del ops[start:end + 1]
            self.edit_page(writer, 0, remove)
            self.assertTrue(moved)
            def insert(ops):
                self.assertEqual(ops[-1][1], b"Q")
                ops[-1:-1] = [([], b"q"), *moved, ([], b"Q")]
            self.edit_page(writer, -1, insert)
        args = self.rewritten(relocate, count=96)
        from reporting import _pdf_typed_original_brand_qa_worker as worker
        reader = PdfReader(BytesIO(args["pdf_bytes"]), strict=True)
        pages = worker.native._page_tree(reader)
        trace, attributes, figures = worker._structure(reader, pages)
        worker._passive(reader, attributes, figures)
        nodes = {tuple(node["reference"]): node for node in trace["nodes"]}
        roles = {key: node["role"] for key, node in nodes.items()}
        document_node = nodes[tuple(trace["root_children"][0])]
        cover = nodes[tuple(document_node["children"][0]["reference"])]
        self.assertEqual(cover["role"], "/Sect")
        dna_page = cover["page_reference"]
        fonts, forms, decoded = {}, {}, 0
        for page, (_, obj, resources) in zip(trace["pages"], pages, strict=True):
            worker._page(page, obj, resources, reader, fonts, forms, roles,
                         worker.contract.MAX_STREAM_BYTES - decoded)
            decoded += page["decoded_stream_bytes"]
        paints = [(page["reference"], block["dna_paints"])
                  for page in trace["pages"] for block in page["graphic_blocks"]
                  if block["dna_paints"]]
        self.assertEqual(len(trace["pages"]), len(pages))
        self.assertEqual(sum(count for _, count in paints), 1)
        self.assertEqual(paints[0][0], trace["pages"][-1]["reference"])
        self.assertEqual(dna_page, trace["pages"][0]["reference"])
        self.assertTrue(all(reference != dna_page for reference, _ in paints))
        self.refuse(args)

    def test_changed_dna_pixel_and_missing_or_duplicate_paint_refuse(self):
        def pixel(writer):
            form = next(iter(writer.pages[0]["/Resources"]["/XObject"].values())).get_object()
            image = next(iter(form["/Resources"]["/XObject"].values())).get_object()
            data = bytearray(zlib.decompress(image._data))
            data[1] ^= 1
            image._data = zlib.compress(data)
        self.refuse(self.rewritten(pixel))
        for duplicate in (False, True):
            def paint(writer):
                def alter(ops):
                    index = next(i for i, (_, op) in enumerate(ops) if op == b"Do")
                    if duplicate:
                        ops.insert(index, deepcopy(ops[index]))
                    else:
                        del ops[index]
                self.edit_page(writer, 0, alter)
            with self.subTest(duplicate=duplicate):
                self.refuse(self.rewritten(paint))

    def test_missing_or_duplicated_required_credit_refuses(self):
        for duplicate in (False, True):
            def credit(writer):
                document_node = next(n for n in self.nodes(writer) if n["/S"] == "/Document")
                credit_section = document_node["/K"][-1].get_object()
                self.assertEqual(credit_section["/S"], "/Sect")
                children = [child.get_object() for child in credit_section["/K"]]
                self.assertEqual([child["/S"] for child in children], ["/H2", "/P"])
                page_index, mcid = self.text_slots(writer, children[1])[-1]
                def alter(ops):
                    start, end = self.span_range(ops, mcid)
                    index = max(i for i in range(start + 1, end) if ops[i][1] == b"TJ")
                    footer_start, footer_end = self.footer_range(ops)
                    self.assertFalse(footer_start <= index <= footer_end)
                    if duplicate:
                        ops.insert(index, deepcopy(ops[index]))
                    else:
                        del ops[index]
                self.edit_page(writer, page_index, alter)
            with self.subTest(duplicate=duplicate):
                self.refuse(self.rewritten(credit))

    def test_footer_declared_geometry_requires_position_clips_and_page_bounds(self):
        """Keep every footer code while changing only its declared physical layout."""
        from reporting import _pdf_typed_original_brand_qa_worker as worker

        self.assertIs(self.run_qa().to_dict()["complete_literal_source_accounting"], True)

        def change(writer, case):
            page = writer.pages[-1]
            if case in {"crop", "media"}:
                key = "/CropBox" if case == "crop" else "/MediaBox"
                box = deepcopy(page.raw_get("/MediaBox"))
                box[1] = NumberObject(44)
                page[NameObject(key)] = box
                return

            def alter(ops):
                start, end = self.footer_range(ops)
                shown = next(args[0] for args, op in ops[start + 1:end] if op == b"TJ")
                original_codes = [bytes(item) for item in shown if type(item) is ByteStringObject]
                matrix = next(args for args, op in ops[start + 1:end] if op == b"Tm")
                endpoint_clip = None
                if case in {"endpoint-containing-clip", "endpoint-excluding-clip"}:
                    self.assertEqual(list(matrix[:4]), [1, 0, 0, -1])
                    font_name, size = next(args for args, op in ops[start + 1:end] if op == b"Tf")
                    font = page["/Resources"]["/Font"][font_name]
                    widths = font["/DescendantFonts"][0].get_object()["/W"]
                    widths = {int(widths[offset]) + index: int(value)
                              for offset in range(0, len(widths), 2)
                              for index, value in enumerate(widths[offset + 1])}
                    pen = rightmost = 0
                    for item in shown:
                        if type(item) is NumberObject:
                            pen -= int(item)
                        else:
                            self.assertIs(type(item), ByteStringObject)
                            for offset in range(0, len(item), 2):
                                pen += widths[int.from_bytes(item[offset:offset + 2], "big")]
                                rightmost = max(rightmost, pen)
                    # Place the endpoint one declared font unit beyond every
                    # glyph rectangle. The clip splits that unit for refusal,
                    # or contains one further unit for the positive control.
                    shown.append(NumberObject(pen - rightmost - 1))
                    units = Decimal(2) if case == "endpoint-containing-clip" else Decimal("0.5")
                    endpoint_clip = (Decimal(str(matrix[4]))
                                     + Decimal(str(size)) * (rightmost + units) / 1000)
                if case == "tm-left":
                    matrix[4] = FloatObject(float(matrix[4]) - 100)
                elif case == "tm-body":
                    matrix[5] = FloatObject(float(matrix[5]) - 100)
                elif case == "outside-page":
                    matrix[4] = FloatObject(float(matrix[4]) + 2000)
                elif case == "tj-displaced":
                    # Restore the final pen while leaving all declared glyph boxes
                    # displaced: checking only the advance endpoint is insufficient.
                    shown.insert(0, NumberObject(10000))
                    shown.append(NumberObject(-10000))
                else:
                    payload = [([], b"q")]
                    if case in {"outer-translation", "outer-shear"}:
                        values = (1, 0, 0, 1, 0, -100) if case == "outer-translation" else (1, 0, 1, 1, 0, 0)
                        payload.append(([NumberObject(value) for value in values], b"cm"))
                    else:
                        rectangle = (0, 0, 1200, 1600) if case == "containing-clip" else (0, 0, 1, 1)
                        if endpoint_clip is not None:
                            rectangle = (0, 0, endpoint_clip, 1600)
                        payload.extend([
                            ([NumberObject(value) if type(value) is int else FloatObject(value)
                              for value in rectangle], b"re"),
                            ([], b"W"), ([], b"n")])
                    if case == "restored-clip":
                        payload.append(([], b"Q"))
                    else:
                        ops.insert(end + 1, ([], b"Q"))
                    ops[start:start] = payload
                first, last = self.footer_range(ops)
                current = next(args[0] for args, op in ops[first + 1:last] if op == b"TJ")
                self.assertEqual([bytes(item) for item in current if type(item) is ByteStringObject],
                                 original_codes)
            self.edit_page(writer, -1, alter)

        for case in ("containing-clip", "restored-clip", "endpoint-containing-clip"):
            with self.subTest(control=case):
                receipt = self.run_qa(self.rewritten(lambda writer: change(writer, case))).to_dict()
                self.assertIs(receipt["complete_literal_source_accounting"], True)
        for case in ("tm-left", "tm-body", "outside-page", "outer-translation", "outer-shear",
                     "excluding-clip", "crop", "media", "tj-displaced", "endpoint-excluding-clip"):
            with self.subTest(refusal=case):
                args = self.rewritten(lambda writer: change(writer, case))
                if case == "endpoint-excluding-clip":
                    reader = PdfReader(BytesIO(args["pdf_bytes"]), strict=True)
                    pages = worker.native._page_tree(reader)
                    trace, attributes, figures = worker._structure(reader, pages)
                    worker._passive(reader, attributes, figures)
                    roles = {tuple(node["reference"]): node["role"] for node in trace["nodes"]}
                    with patch.object(worker, "_contains", wraps=worker._contains) as contains:
                        with self.assertRaisesRegex(ValueError, "^typed original-brand QA refused$"):
                            worker._page(trace["pages"][-1], pages[-1][1], pages[-1][2], reader,
                                         {}, {}, roles, worker.contract.MAX_STREAM_BYTES)
                    self.assertTrue(all(worker._contains(*call.args)
                                        for call in contains.call_args_list[:-1]))
                    clip, footer = contains.call_args.args
                    # Returning five points means the unchanged alignment and
                    # typographic-region checks succeeded before this clip test.
                    self.assertEqual(len(footer), 5)
                    self.assertTrue(worker._contains(clip, footer[:4]))
                    self.assertFalse(worker._contains(clip, footer[-1:]))
                self.refuse(args)

    def test_footers_require_exact_identity_once_on_each_physical_page(self):
        args = self.arguments()
        original = self.native_record()
        self.m._validate_native(original, args["pdf_bytes"], args["expected_profile_sha256"])
        self.assertGreater(original["page_count"], 1)
        for page in original["trace"]["pages"]:
            self.assertEqual(len(page["pagination_blocks"]), 1)
        for mode in ("missing", "duplicate", "wrong-page", "wrong-identity"):
            def alter_footer(writer):
                source = ContentStream(writer.pages[0].raw_get("/Contents"), writer,
                                       forced_encoding="bytes").operations
                first, last = self.footer_range(source)
                donor = deepcopy(source[first:last + 1])
                def alter(ops):
                    start, end = self.footer_range(ops)
                    if mode == "missing":
                        del ops[start:end + 1]
                    elif mode == "duplicate":
                        ops[end + 1:end + 1] = deepcopy(ops[start:end + 1])
                    elif mode == "wrong-page":
                        ops[start:end + 1] = donor
                    else:
                        tj = next(i for i in range(start + 1, end) if ops[i][1] == b"TJ")
                        self.change_first_glyph(ops[tj][0])
                self.edit_page(writer, -1, alter)
            with self.subTest(footer=mode):
                self.refuse(self.rewritten(alter_footer))

        fonts = {tuple(font["reference"]): font for font in original["trace"]["fonts"]}
        def declared_widths(font):
            # The original native observation admitted these explicit CID /W runs.
            declared = font["/DescendantFonts"][0].get_object()["/W"]
            return {int(declared[offset]) + index: int(value)
                    for offset in range(0, len(declared), 2)
                    for index, value in enumerate(declared[offset + 1])}

        reader = PdfReader(BytesIO(args["pdf_bytes"]), strict=True)
        prefix_start, footer_fonts = len("OmniGenis | "), []
        for page_index, page in enumerate(original["trace"]["pages"]):
            events = page["pagination_blocks"][0]["events"]
            font_name = events[4]["operands"][0]
            reference = next(item["reference"] for item in page["font_resources"]
                             if item["name"] == font_name)
            mapping = dict(fonts[tuple(reference)]["mapping"])
            widths = declared_widths(reader.pages[page_index]["/Resources"]["/Font"][font_name])
            cursor, prefix = 0, {}
            for kind, value in events[5]["operands"]:
                if kind == "codes":
                    for offset in range(0, len(value), 4):
                        code = value[offset:offset + 4]
                        text = mapping[code]
                        if prefix_start <= cursor < prefix_start + 12 and len(text) == 1:
                            prefix[cursor] = code, text
                        cursor += len(text)
            footer_fonts.append((mapping, widths, prefix))

        # Change identity alone: derive a distinct hex glyph with the same /W
        # advance in every footer font, without assuming tabular digit metrics.
        selection = None
        for position, (_, old) in footer_fonts[0][2].items():
            replacements = sorted({text for text in footer_fonts[0][0].values()
                                   if len(text) == 1 and text in "0123456789abcdef" and text != old})
            for replacement in replacements:
                codes = []
                for mapping, widths, prefix in footer_fonts:
                    prior = prefix.get(position)
                    if prior is None or prior[1] != old:
                        break
                    matches = [code for code, text in sorted(mapping.items())
                               if text == replacement and widths[int(code, 16)] == widths[int(prior[0], 16)]]
                    if not matches:
                        break
                    codes.append(bytes.fromhex(matches[0]))
                if len(codes) == len(footer_fonts):
                    selection = position, old, replacement, codes
                    break
            if selection is not None:
                break
        self.assertIsNotNone(selection, "same-PDF footers need a distinct equal-width hex substitution")
        position, old, replacement, replacement_codes = selection
        self.assertIn(old, "0123456789abcdef")
        self.assertIn(replacement, "0123456789abcdef")
        expected_prefix = args["expected_ir_sha256"][:12]
        offset = position - prefix_start
        foreign_prefix = expected_prefix[:offset] + replacement + expected_prefix[offset + 1:]
        self.assertNotEqual(foreign_prefix, expected_prefix)

        def foreign_source(writer):
            for page_index, native_page in enumerate(original["trace"]["pages"]):
                def alter(ops, native_page=native_page, page_index=page_index):
                    start, end = self.footer_range(ops)
                    tf = next(i for i in range(start + 1, end) if ops[i][1] == b"Tf")
                    reference = next(item["reference"] for item in native_page["font_resources"]
                                     if item["name"] == str(ops[tf][0][0]))
                    cmap = dict(fonts[tuple(reference)]["mapping"])
                    code = replacement_codes[page_index]
                    self.assertEqual(cmap[code.hex()], replacement)
                    widths = declared_widths(writer.pages[page_index]["/Resources"]["/Font"][ops[tf][0][0]])
                    tj = next(i for i in range(start + 1, end) if ops[i][1] == b"TJ")
                    cursor = 0
                    for index, part in enumerate(ops[tj][0][0]):
                        if type(part) is not ByteStringObject:
                            continue
                        raw = bytes(part)
                        for byte in range(0, len(raw), 2):
                            text = cmap[raw[byte:byte + 2].hex()]
                            if cursor == position:
                                self.assertEqual(text, old)
                                self.assertEqual(widths[int.from_bytes(raw[byte:byte + 2], "big")],
                                                 widths[int.from_bytes(code, "big")])
                                # Preserve Tm, every TJ adjustment and all other glyph codes.
                                ops[tj][0][0][index] = ByteStringObject(raw[:byte] + code + raw[byte + 2:])
                                return
                            cursor += len(text)
                    self.fail("bound source-prefix glyph absent from actual footer")
                self.edit_page(writer, page_index, alter)
        candidate = self.rewritten(foreign_source)
        raw = self.m._run_worker(candidate["pdf_bytes"], candidate["expected_pdf_sha256"])
        observed = self.m.prior._loads(raw.decode("ascii"))
        self.m._validate_native(observed, candidate["pdf_bytes"], candidate["expected_profile_sha256"])
        for number, page in enumerate(observed["trace"]["pages"], 1):
            actual_fonts = {tuple(font["reference"]): font for font in observed["trace"]["fonts"]}
            literal = self.m._pagination_text(page, page["pagination_blocks"][0], actual_fonts)
            self.assertEqual(literal, "OmniGenis | " + foreign_prefix + " | " + str(number))
        with self.subTest(footer="foreign-source-prefix"), patch.object(
                self.m, "_run_worker", return_value=raw), patch.object(
                self.m, "inspect_pdf_document_metadata") as metadata:
            self.refuse(candidate)
            metadata.assert_not_called()

    def test_footer_color_requires_declared_rgb_even_after_resealing(self):
        expected = (0.270588, 0.364706, 0.45098)
        original = self.native_record()
        for page in original["trace"]["pages"]:
            block = page["pagination_blocks"][0]
            colors = [event["operands"] for event in block["events"]
                      if event["operator"] == "rg"]
            self.assertEqual(len(colors), 1)
            self.assertEqual(tuple(self.m.prior._num(value) for value in colors[0]), expected)

        def white_footer(writer):
            def alter(ops):
                start, end = self.footer_range(ops)
                colors = [i for i in range(start + 1, end) if ops[i][1] == b"rg"]
                self.assertEqual(len(colors), 1)
                color = colors[0]
                self.assertEqual(tuple(float(value) for value in ops[color][0]), expected)
                ops[color] = ([FloatObject(1), FloatObject(1), FloatObject(1)], b"rg")
            self.edit_page(writer, 0, alter)

        candidate = self.rewritten(white_footer)
        self.assertNotEqual(candidate["expected_pdf_sha256"], self.arguments()["expected_pdf_sha256"])
        with patch.object(self.m, "inspect_pdf_document_metadata") as metadata:
            self.refuse(candidate)
            metadata.assert_not_called()

    def test_footer_grammar_fonts_and_native_event_digest_are_closed(self):
        original = self.native_record()
        self.assertNotIn("ffff", {code for font in original["trace"]["fonts"]
                                  for code, _ in font["mapping"]})
        for mode in ("wrong-type", "wrong-subtype", "owned-footer", "unknown-operator",
                     "unknown-font", "unmapped-glyph"):
            def corrupt(writer):
                def alter(ops):
                    start, end = self.footer_range(ops)
                    if mode == "wrong-type":
                        ops[start][0][1][NameObject("/Type")] = NameObject("/Layout")
                    elif mode == "wrong-subtype":
                        ops[start][0][1][NameObject("/Subtype")] = NameObject("/Header")
                    elif mode == "owned-footer":
                        ops[start][0][1][NameObject("/MCID")] = NumberObject(0)
                    elif mode == "unknown-operator":
                        ops.insert(start + 1, ([], b"BX"))
                    elif mode == "unknown-font":
                        tf = next(i for i in range(start + 1, end) if ops[i][1] == b"Tf")
                        name = NameObject("/MissingFooterFont")
                        self.assertNotIn(name, writer.pages[0]["/Resources"]["/Font"])
                        ops[tf][0][0] = name
                    else:
                        tj = next(i for i in range(start + 1, end) if ops[i][1] == b"TJ")
                        self.change_first_glyph(ops[tj][0], b"\xff\xff")
                self.edit_page(writer, 0, alter)
            with self.subTest(footer=mode):
                self.refuse(self.rewritten(corrupt))
        native = deepcopy(original)
        block = native["trace"]["pages"][0]["pagination_blocks"][0]
        observed = block["sha256"]
        block["sha256"] = ("0" if observed[0] != "0" else "1") + observed[1:]
        self.m._schema(native, "native")
        with self.subTest(footer="changed-event-digest"), patch.object(
                self.m, "_run_worker", return_value=self.m.canonical(native)):
            self.refuse(self.arguments())

    def test_page_labels_require_explicit_one_based_decimal_numbering(self):
        args = self.arguments(96)
        reader = PdfReader(BytesIO(args["pdf_bytes"]), strict=True)
        self.assertIn("/PageLabels", reader.root_object)
        self.assertEqual(reader.page_labels, [str(i) for i in range(1, len(reader.pages) + 1)])
        for mode in ("missing", "wrong-start", "roman"):
            def labels(writer):
                if mode == "missing":
                    del writer._root_object["/PageLabels"]
                    return
                nums = writer._root_object["/PageLabels"]["/Nums"]
                self.assertEqual(len(nums), 2)
                self.assertEqual(nums[0], 0)
                record = nums[1].get_object()
                if mode == "wrong-start":
                    record[NameObject("/St")] = NumberObject(2)
                else:
                    record[NameObject("/S")] = NameObject("/R")
            with self.subTest(page_labels=mode):
                self.refuse(self.rewritten(labels, count=96))

    def test_wrapped_navigation_entries_continue_across_pages_with_atomic_suffixes(self):
        """Use one real PDF to bind continued contents and every printed page suffix."""
        from dataclasses import replace
        from reporting.completeness import SectionAvailability
        from reporting.components import (
            FindingRow, FindingsTable, TableColumn, TextComponent,
            build_typed_report_projection, component_content_sha256,
        )
        request, ledger = context(1)
        section_ids = tuple(f"navigation-{i:02d}" for i in range(47)) + ("findings",)
        present = ("identity",) + section_ids
        plan = replace(request.plan, expected_section_ids=present + ("optional",),
                       required_section_ids=present)
        snapshot = replace(request.request, completeness_plan_sha256=plan.plan_sha256)
        request = replace(request, request=snapshot, resolved_request=snapshot, plan=plan)
        ledger = replace(ledger, plan=plan, projection_plan_sha256=plan.plan_sha256,
                         section_states=tuple(SectionAvailability(section, "PRESENT")
                                              for section in present) + (ledger.section_states[-1],))
        labels = [f"Navigation section {i:02d}" if i < 40 else
                  f"Wrapped navigation section {i:02d}" + " literal" * (i - 22)
                  for i in range(47)] + ["Declared findings"]
        parts = [TextComponent("title", "identity", "document_title", "Technical report")]
        for index, (section, label) in enumerate(zip(section_ids, labels, strict=True)):
            parts.extend((
                TextComponent(f"heading-{index:02d}", section, "section_heading", label),
                TextComponent(f"paragraph-{index:02d}", section, "paragraph", "Synthetic context.")))
        parts.append(FindingsTable(
            "table", "findings", "Declared synthetic findings",
            (TableColumn("identifier", "Identifier"), TableColumn("value", "Value")),
            (FindingRow(request.plan.expected_finding_ids[0], ("SYNTHETIC-001", "0.1")),)))
        parts = tuple(parts)
        source = build_typed_report_projection(
            request=request, ledger=ledger,
            projection_request_sha256=request.request.request_sha256,
            expected_content_sha256=component_content_sha256(parts), components=parts).to_dict()
        ir_sha = digest(source)
        expectation = prepare_typed_pdf_source(presentation_ir=source, expected_ir_sha256=ir_sha)
        rendered, _ = render_typed_original_brand_pdf(
            presentation_ir=source, expected_ir_sha256=ir_sha,
            assets=self.assets, expected_brand_bundle_sha256=self.bundle)
        observations, associations = [], []
        inspect_native, associate = self.m._run_worker, self.m._associate

        def retain_observation(pdf_bytes, pdf_sha256):
            raw = inspect_native(pdf_bytes, pdf_sha256)
            observations.append(raw)
            return raw

        def retain_association(*args):
            value = associate(*args)
            associations.append(value)
            return value

        with patch.object(self.m, "_run_worker", side_effect=retain_observation) as inspected, \
                patch.object(self.m, "_associate", side_effect=retain_association):
            receipt = self.run_qa(dict(
                presentation_ir=source, expected_ir_sha256=ir_sha,
                expected_source_expectation_sha256=expectation.expectation_sha256,
                assets=self.assets, expected_brand_bundle_sha256=self.bundle,
                pdf_bytes=rendered.pdf_bytes, expected_pdf_sha256=rendered.pdf_sha256,
                expected_profile_sha256=self.m.profile_sha256())).to_dict()
            inspected.assert_called_once_with(rendered.pdf_bytes, rendered.pdf_sha256)
        self.assertEqual(len(observations), 1)
        self.assertEqual(len(associations), 1)
        self.assertEqual(receipt["pdf_sha256"], rendered.pdf_sha256)
        self.assertEqual(receipt["ir_sha256"], ir_sha)
        self.assertEqual(receipt["source_expectation_sha256"], expectation.expectation_sha256)
        self.assertEqual(receipt["native_observation_sha256"], sha256(observations[0]).hexdigest())
        self.assertEqual(receipt["navigation_entries"], len(labels))
        self.assertEqual(receipt["coverage"]["accounted_navigation_wrapper_nodes"], len(labels))
        native = self.m.prior._loads(observations[0].decode("ascii"))
        trace = native["trace"]
        nodes = {tuple(node["reference"]): node for node in trace["nodes"]}
        pages = {tuple(page["reference"]): page for page in trace["pages"]}

        def children(node):
            self.assertTrue(all(child["kind"] == "node" for child in node["children"]))
            return [nodes[tuple(child["reference"])] for child in node["children"]]

        def literal(node):
            if node["role"] == "/Span":
                page = pages[tuple(node["page_reference"])]
                self.assertEqual(len(node["children"]), 1)
                mcid = node["children"][0]["value"]
                runs = [run for run in page["runs"] if run["mcid"] == mcid]
                self.assertEqual(len(runs), 1)
                self.assertEqual(runs[0]["structure_reference"], node["reference"])
                return runs[0]["text"]
            return "".join(literal(child) for child in children(node))

        top = children(nodes[tuple(trace["root_children"][0])])
        navigation_end = 1
        while navigation_end < len(top) - 1 and top[navigation_end]["role"] == "/Sect":
            navigation_end += 1
        sections = top[1:navigation_end]
        self.assertGreater(len(sections), 1)
        fragments = [children(section) for section in sections]
        self.assertGreaterEqual(len(fragments[0]), 2)
        self.assertEqual(fragments[0][0]["role"], "/H2")
        self.assertTrue(all(fragment for fragment in fragments))
        self.assertTrue(all(node["role"] == "/P" for node in fragments[0][1:]))
        self.assertTrue(all(node["role"] == "/P" for fragment in fragments[1:] for node in fragment))
        for section, fragment in zip(sections, fragments, strict=True):
            self.assertTrue(all(node["parent"] == section["reference"]
                                and node["page_reference"] == section["page_reference"] for node in fragment))
        fragment_pages = [pages[tuple(section["page_reference"])]["index"] for section in sections]
        self.assertEqual(fragment_pages, sorted(set(fragment_pages)))
        self.assertGreaterEqual(fragment_pages[0], 1)
        self.assertLess(fragment_pages[-1], len(trace["pages"]) - 1)
        navigation = [node for fragment in fragments for node in fragment]
        self.assertEqual(literal(navigation[0]), "Contents")
        self.assertEqual(sections[0]["page_reference"], navigation[0]["page_reference"])
        self.assertEqual(receipt["coverage"]["accounted_brand_wrapper_nodes"], 5 + len(sections))
        self.assertEqual(receipt["coverage"]["native_nodes"], receipt["coverage"]["projected_nodes"]
                         + 5 + len(sections) + len(labels))
        entries = navigation[1:]
        self.assertEqual(len(entries), len(labels))
        indexes = [pages[tuple(entry["page_reference"])]["index"] for entry in entries]
        self.assertEqual(indexes, sorted(indexes))
        self.assertGreaterEqual(indexes[0], 1)
        self.assertGreater(len(set(indexes)), 1)
        targets = [node for node in top[navigation_end:-1] if node["role"] == "/H2"]
        self.assertEqual(len(targets), len(labels))
        links = associations[0]["editorial_navigation"]
        self.assertEqual(len(links), len(labels))
        wrapped = 0
        for index, (label, entry, target, link) in enumerate(zip(
                labels, entries, targets, links, strict=True)):
            spans = children(entry)
            self.assertTrue(all(span["role"] == "/Span" for span in spans[:-1]))
            self.assertEqual(spans[-1]["role"], "/NonStruct")
            suffix = children(spans[-1])
            self.assertEqual([span["role"] for span in suffix], ["/Span"])
            self.assertTrue(all(span["page_reference"] == entry["page_reference"]
                                for span in spans + suffix))
            wrapped += len(spans[:-1]) > 1
            self.assertEqual("".join(literal(span) for span in spans[:-1]), label)
            self.assertEqual(literal(target), label)
            target_page = pages[tuple(target["page_reference"])]["index"]
            printed = label + " | " + str(target_page + 1)
            self.assertEqual(literal(suffix[0]), " | " + str(target_page + 1))
            self.assertEqual(literal(entry), printed)
            self.assertEqual(link["source_component_id"], f"heading-{index:02d}")
            self.assertEqual(link["source_section_id"], section_ids[index])
            self.assertEqual(link["navigation_page_index"], indexes[index])
            self.assertEqual(link["target_page_index"], target_page)
            self.assertEqual(link["target_container_reference"], target["reference"])
            self.assertEqual(link["navigation_container_reference"], entry["reference"])
            self.assertEqual(link["printed_reference_sha256"], sha256(printed.encode()).hexdigest())
        self.assertGreater(wrapped, 0)

        for mode in ("section-page", "continuation-page", "cross-page-span",
                     "backward-fragment-order", "continuation-heading"):
            bad = deepcopy(trace)
            changed = {tuple(node["reference"]): node for node in bad["nodes"]}
            if mode == "section-page":
                changed[tuple(sections[0]["reference"])]["page_reference"] = bad["pages"][0]["reference"]
            elif mode == "continuation-page":
                changed[tuple(sections[-1]["reference"])]["page_reference"] = sections[0]["page_reference"]
            elif mode == "cross-page-span":
                span = children(entries[0])[0]
                changed[tuple(span["reference"])]["page_reference"] = entries[-1]["page_reference"]
            elif mode == "backward-fragment-order":
                first, last = fragment_pages[0], fragment_pages[-1]
                bad["pages"][first], bad["pages"][last] = bad["pages"][last], bad["pages"][first]
                for index, page in enumerate(bad["pages"]):
                    page["index"] = index
                # Keep every node, parent, Pg, MCID and owner unchanged. Only the
                # declared physical ordering of the two existing body pages changes.
                self.assertEqual(bad["nodes"], trace["nodes"])
                self.assertEqual(bad["pages"][0], trace["pages"][0])
                self.assertEqual(bad["pages"][-1], trace["pages"][-1])
                for page in bad["pages"]:
                    self.assertEqual(page["mcid_owners"], pages[tuple(page["reference"])]["mcid_owners"])
                reordered = {tuple(page["reference"]): page["index"] for page in bad["pages"]}
                order = [reordered[tuple(section["page_reference"])] for section in sections]
                self.assertNotEqual(order, sorted(set(order)))
            else:
                changed[tuple(fragments[-1][0]["reference"])]["role"] = "/H2"
            with self.subTest(refusal=mode), self.assertRaises(ValueError):
                self.m.project_text_trace(bad)

    def test_navigation_text_and_references_bind_actual_source_heading_pages(self):
        args = self.arguments(navigation=True)
        observations = []
        inspect_native = self.m._run_worker

        def retain_observation(pdf_bytes, pdf_sha256):
            raw = inspect_native(pdf_bytes, pdf_sha256)
            observations.append(raw)
            return raw

        with patch.object(self.m, "_run_worker", side_effect=retain_observation) as inspected:
            receipt = self.run_qa(args).to_dict()
            inspected.assert_called_once_with(args["pdf_bytes"], args["expected_pdf_sha256"])
        self.assertEqual(len(observations), 1)
        self.assertEqual(sha256(observations[0]).hexdigest(), receipt["native_observation_sha256"])
        self.assertEqual(receipt["navigation_entries"], 2)
        self.assertEqual(receipt["coverage"]["accounted_navigation_wrapper_nodes"], 2)
        native = self.m.prior._loads(observations[0].decode("ascii"))
        nodes = {tuple(node["reference"]): node for node in native["trace"]["nodes"]}
        pages = {tuple(page["reference"]): page for page in native["trace"]["pages"]}
        def literal(node):
            values = []
            for child in node["children"]:
                if child["kind"] == "node":
                    values.append(literal(nodes[tuple(child["reference"])]))
                else:
                    page = pages[tuple(node["page_reference"])]
                    values.extend(run["text"] for run in page["runs"] if run["mcid"] == child["value"])
            return "".join(values)
        target_pages = {}
        for label in ("Record identity", "Declared findings"):
            matched = [node for node in nodes.values() if node["role"] == "/H2" and literal(node) == label]
            self.assertEqual(len(matched), 1)
            target_pages[label] = pages[tuple(matched[0]["page_reference"])]["index"] + 1
        self.assertNotEqual(target_pages["Record identity"], target_pages["Declared findings"])
        for mode in ("missing-label", "wrong-label", "swapped-page-references"):
            def navigation(writer):
                document_node = next(n for n in self.nodes(writer) if n["/S"] == "/Document")
                section = document_node["/K"][1].get_object()
                children = [child.get_object() for child in section["/K"]]
                self.assertEqual([child["/S"] for child in children], ["/H2", "/P", "/P"])
                slots = [self.text_slots(writer, row) for row in children[1:]]
                if mode == "swapped-page-references":
                    tails, data = [row[-1] for row in slots], []
                    for page_index, mcid in tails:
                        ops = ContentStream(writer.pages[page_index].raw_get("/Contents"), writer,
                                            forced_encoding="bytes").operations
                        start, end = self.span_range(ops, mcid)
                        shows = [operands for operands, op in ops[start + 1:end] if op == b"TJ"]
                        self.assertEqual(len(shows), 1)
                        data.append(deepcopy(shows[0]))
                    self.assertNotEqual(data[0], data[1])
                    for index, (page_index, mcid) in enumerate(tails):
                        def swap(ops, mcid=mcid, payload=data[1 - index]):
                            start, end = self.span_range(ops, mcid)
                            tj = next(i for i in range(start + 1, end) if ops[i][1] == b"TJ")
                            ops[tj] = (deepcopy(payload), b"TJ")
                        self.edit_page(writer, page_index, swap)
                else:
                    page_index, mcid = slots[0][0]
                    def alter(ops):
                        start, end = self.span_range(ops, mcid)
                        tj = next(i for i in range(start + 1, end) if ops[i][1] == b"TJ")
                        if mode == "missing-label":
                            del ops[tj]
                        else:
                            self.change_first_glyph(ops[tj][0])
                    self.edit_page(writer, page_index, alter)
            candidate = self.rewritten(navigation, navigation=True)
            if mode == "missing-label":
                with self.subTest(navigation=mode):
                    self.refuse(candidate)
                continue
            raw = self.m._run_worker(candidate["pdf_bytes"], candidate["expected_pdf_sha256"])
            observed = self.m.prior._loads(raw.decode("ascii"))
            self.m._validate_native(observed, candidate["pdf_bytes"], candidate["expected_profile_sha256"])
            with self.subTest(navigation=mode), patch.object(
                    self.m, "_run_worker", return_value=raw), patch.object(
                    self.m, "inspect_pdf_document_metadata") as metadata:
                self.refuse(candidate)
                metadata.assert_not_called()

    def test_navigation_suffix_span_owns_the_complete_generated_suffix(self):
        def move_separator(writer):
            document_node = next(node for node in self.nodes(writer) if node["/S"] == "/Document")
            section = document_node["/K"][1].get_object()
            row = section["/K"][1].get_object()
            slots = self.text_slots(writer, row)
            self.assertEqual(len(slots), 2)
            (page_index, label_mcid), (suffix_page, suffix_mcid) = slots
            self.assertEqual(page_index, suffix_page)

            def alter(ops):
                ranges = [self.span_range(ops, mcid) for mcid in (label_mcid, suffix_mcid)]
                shows, fonts = [], []
                for start, end in ranges:
                    shown = [i for i in range(start + 1, end) if ops[i][1] == b"TJ"]
                    selected = [args for args, op in ops[start + 1:end] if op == b"Tf"]
                    self.assertEqual(len(shown), 1)
                    self.assertEqual(len(selected), 1)
                    shows.append(shown[0])
                    fonts.append(selected[0])
                self.assertEqual(fonts[0], fonts[1])
                label_parts, suffix_parts = (ops[index][0][0] for index in shows)
                prefix, tail = ArrayObject(), ArrayObject()
                remaining = 2 * len(" | ")
                for part in suffix_parts:
                    if type(part) is ByteStringObject:
                        value = bytes(part)
                        self.assertEqual(len(value) % 2, 0)
                        take = min(remaining, len(value))
                        if take:
                            prefix.append(ByteStringObject(value[:take]))
                            remaining -= take
                        if take < len(value):
                            tail.append(ByteStringObject(value[take:]))
                    else:
                        (prefix if remaining else tail).append(deepcopy(part))
                self.assertEqual(remaining, 0)
                self.assertTrue(tail)
                label_parts.extend(prefix)
                ops[shows[1]][0][0] = tail
            self.edit_page(writer, page_index, alter)

        candidate = self.rewritten(move_separator, navigation=True)
        raw = self.m._run_worker(candidate["pdf_bytes"], candidate["expected_pdf_sha256"])
        native = self.m.prior._loads(raw.decode("ascii"))
        self.m._validate_native(native, candidate["pdf_bytes"], candidate["expected_profile_sha256"])
        nodes = {tuple(node["reference"]): node for node in native["trace"]["nodes"]}
        pages = {tuple(page["reference"]): page for page in native["trace"]["pages"]}

        def literal(node):
            values = []
            for child in node["children"]:
                if child["kind"] == "node":
                    values.append(literal(nodes[tuple(child["reference"])]))
                else:
                    page = pages[tuple(node["page_reference"])]
                    values.extend(run["text"] for run in page["runs"] if run["mcid"] == child["value"])
            return "".join(values)

        document_node = nodes[tuple(native["trace"]["root_children"][0])]
        section = nodes[tuple(document_node["children"][1]["reference"])]
        row = nodes[tuple(section["children"][1]["reference"])]
        parts = [nodes[tuple(child["reference"])] for child in row["children"]]
        self.assertEqual([part["role"] for part in parts], ["/Span", "/NonStruct"])
        targets = [node for node in nodes.values()
                   if node["role"] == "/H2" and literal(node) == "Record identity"]
        self.assertEqual(len(targets), 1)
        printed_page = str(pages[tuple(targets[0]["page_reference"])]["index"] + 1)
        self.assertEqual(literal(parts[0]), "Record identity | ")
        self.assertEqual(literal(parts[1]), printed_page)
        self.assertEqual(literal(row), "Record identity | " + printed_page)
        with patch.object(self.m, "_run_worker", return_value=raw), patch.object(
                self.m, "inspect_pdf_document_metadata") as metadata:
            self.refuse(candidate)
            metadata.assert_not_called()

    def test_unknown_operators_in_every_dispatch_context_refuse(self):
        for context in ("outside", "/Span", "/Figure", "/Artifact"):
            def unsupported(writer):
                def alter(ops):
                    if context == "outside":
                        ops.insert(0, ([], b"BX"))
                        return
                    for i, (args, op) in enumerate(ops):
                        if op in {b"BMC", b"BDC"} and args[0] == context:
                            ops.insert(i + 1, ([], b"BX"))
                            return
                    self.fail("fixture dispatch context absent")
                self.edit_page(writer, 0, alter)
            with self.subTest(context=context):
                self.refuse(self.rewritten(unsupported))

    def test_native_operator_accounting_holes_and_overlaps_refuse(self):
        args = self.arguments()
        original = self.native_record()
        self.m._validate_native(original, args["pdf_bytes"], args["expected_profile_sha256"])
        for overlap in (False, True):
            native = deepcopy(original)
            page = native["trace"]["pages"][0]
            if overlap:
                mapped = set(page["projected_operator_ordinals"])
                _, ordinal, index = min(
                    (max(block["first_operator"] - ordinal, ordinal - block["last_operator"], 0),
                     ordinal, index)
                    for index, block in enumerate(page["graphic_blocks"]) for ordinal in mapped)
                block = page["graphic_blocks"][index]
                block["first_operator"] = min(block["first_operator"], ordinal)
                block["last_operator"] = max(block["last_operator"], ordinal)
                span = set(range(block["first_operator"], block["last_operator"] + 1))
                self.assertLess(block["first_operator"], block["last_operator"])
                self.assertEqual(span.intersection(mapped), {ordinal})
                self.assertTrue(all(
                    not span.intersection(range(other["first_operator"], other["last_operator"] + 1))
                    for other_index, other in enumerate(page["graphic_blocks"]) if other_index != index))
                page["outside_operator_ordinals"] = [
                    value for value in page["outside_operator_ordinals"] if value not in span]
                covered = mapped | set(page["outside_operator_ordinals"])
                for graphic in (*page["graphic_blocks"], *page["pagination_blocks"]):
                    covered.update(range(graphic["first_operator"], graphic["last_operator"] + 1))
                self.assertEqual(covered, set(range(page["original_operator_count"])))
            else:
                del page["outside_operator_ordinals"][0]
            self.assertEqual(native["trace"]["nodes"], original["trace"]["nodes"])
            self.assertEqual(page["mcid_owners"], original["trace"]["pages"][0]["mcid_owners"])
            self.m._schema(native, "native")
            self.m.project_text_trace(native["trace"])
            with self.subTest(overlap=overlap), patch.object(
                    self.m, "_run_worker", return_value=self.m.canonical(native)):
                self.refuse(args)

    def test_native_decoded_page_stream_bytes_obey_aggregate_budget(self):
        args = self.arguments(96)
        original = self.native_record(96)
        self.m._validate_native(original, args["pdf_bytes"], args["expected_profile_sha256"])
        boundary = deepcopy(original)
        pages = boundary["trace"]["pages"]
        self.assertGreater(len(pages), 1)
        self.assertEqual(len({tuple(page["contents_reference"]) for page in pages}), len(pages))
        limit = self.m.prior.MAX_STREAM_BYTES
        pages[0]["decoded_stream_bytes"] = limit - sum(
            page["decoded_stream_bytes"] for page in pages[1:])
        self.assertTrue(all(0 < page["decoded_stream_bytes"] <= limit for page in pages))
        self.assertEqual(sum(page["decoded_stream_bytes"] for page in pages), limit)
        self.m._schema(boundary, "native")
        self.m._validate_native(boundary, args["pdf_bytes"], args["expected_profile_sha256"])
        bad = deepcopy(boundary)
        bad["trace"]["pages"][0]["decoded_stream_bytes"] += 1
        self.assertEqual(sum(page["decoded_stream_bytes"] for page in bad["trace"]["pages"]),
                         limit + 1)
        for observed, source in zip(bad["trace"]["pages"], original["trace"]["pages"], strict=True):
            self.assertTrue(0 < observed["decoded_stream_bytes"] <= limit)
            self.assertEqual({key: value for key, value in observed.items()
                              if key != "decoded_stream_bytes"},
                             {key: value for key, value in source.items()
                              if key != "decoded_stream_bytes"})
        self.m._schema(bad, "native")
        self.m.prior._reference_consistency(bad["trace"])
        projected, _ = self.m.project_text_trace(bad["trace"])
        fonts = {self.m.prior._reference(font["reference"]): font for font in projected["fonts"]}
        for page in projected["pages"]:
            self.assertEqual(self.m.prior._replay(page, fonts), page["runs"])
        with self.assertRaises(ValueError):
            self.m._validate_native(bad, args["pdf_bytes"], args["expected_profile_sha256"])
        with patch.object(self.m, "_run_worker", return_value=self.m.canonical(bad)):
            self.refuse(args)

    def test_native_reference_categories_remain_disjoint_with_valid_sharing(self):
        def shared_font(writer):
            fonts = writer.pages[0]["/Resources"]["/Font"]
            original_font = next(iter(fonts.values())).get_object()
            duplicate = DictionaryObject(dict(original_font))
            fonts[NameObject("/SharedFontControl")] = writer._add_object(duplicate)
        args = self.rewritten(shared_font)
        raw = self.m._run_worker(args["pdf_bytes"], args["expected_pdf_sha256"])
        original = self.m.prior._loads(raw.decode("ascii"))
        fonts = original["trace"]["fonts"]
        self.assertLess(len({tuple(f["cid_reference"]) for f in fonts}), len(fonts))
        self.assertLess(len({tuple(f["cmap_reference"]) for f in fonts}), len(fonts))
        self.m._validate_native(original, args["pdf_bytes"], args["expected_profile_sha256"])
        trace = original["trace"]
        figure = next(n for n in trace["nodes"] if n["role"] == "/Figure")
        aliases = {
            "root": trace["root_reference"],
            "removed-figure-node": figure["reference"],
            "page": trace["pages"][0]["reference"],
            "contents": trace["pages"][0]["contents_reference"],
            "type0-font": fonts[0]["reference"],
            "cmap": fonts[0]["cmap_reference"],
        }
        for category, reference in aliases.items():
            native = deepcopy(original)
            native["trace"]["fonts"][0]["cid_reference"] = list(reference)
            with self.subTest(category=category):
                self.m._schema(native, "native")
                self.m.project_text_trace(native["trace"])
                with self.assertRaises(ValueError):
                    self.m._validate_native(
                        native, args["pdf_bytes"], args["expected_profile_sha256"])
        groups = {}
        for font in fonts:
            groups.setdefault(tuple(font["cmap_reference"]), []).append(font)
        unshared = next(group for group in groups.values() if len(group) == 1)
        shared = next(group for group in groups.values() if len(group) > 1)
        for mode, group in (("unshared-record", unshared), ("all-shared-records", shared)):
            native = deepcopy(original)
            target = tuple(group[0]["cmap_reference"])
            affected = []
            for font in native["trace"]["fonts"]:
                if tuple(font["cmap_reference"]) == target:
                    mapping = dict(font["mapping"])
                    font["mapping"].append(deepcopy(font["mapping"][0]))
                    self.assertEqual(dict(font["mapping"]), mapping)
                    self.assertEqual(len(font["mapping"]), len(mapping) + 1)
                    affected.append(font["reference"])
            self.assertEqual(len(affected), len(group))
            self.m._schema(native, "native")
            self.m.prior._reference_consistency(native["trace"])
            projected, _ = self.m.project_text_trace(native["trace"])
            bound = {self.m.prior._reference(font["reference"]): font
                     for font in projected["fonts"]}
            for page in projected["pages"]:
                self.assertEqual(self.m.prior._replay(page, bound), page["runs"])
            with self.subTest(duplicate_cmap=mode, boundary="parent"):
                with self.assertRaises(ValueError):
                    self.m._validate_native(
                        native, args["pdf_bytes"], args["expected_profile_sha256"])
            with self.subTest(duplicate_cmap=mode, boundary="public"), patch.object(
                    self.m, "_run_worker", return_value=self.m.canonical(native)):
                self.refuse(args)

    def test_projected_span_ordinals_are_contiguous_only_within_spans(self):
        target = {}
        def with_gap(writer):
            def alter(ops):
                starts = [i for i, (args, op) in enumerate(ops)
                          if op == b"BDC" and args[0] == "/Span"]
                self.assertGreaterEqual(len(starts), 2)
                ops[starts[1]:starts[1]] = [([], b"q"), ([], b"Q")]
            target["index"] = self.page_with_multiple_spans(writer)
            self.edit_page(writer, target["index"], alter)
        args = self.rewritten(with_gap)
        raw = self.m._run_worker(args["pdf_bytes"], args["expected_pdf_sha256"])
        original = self.m.prior._loads(raw.decode("ascii"))
        self.m._validate_native(original, args["pdf_bytes"], args["expected_profile_sha256"])
        native = deepcopy(original)
        page = native["trace"]["pages"][target["index"]]
        mapped = page["projected_operator_ordinals"]
        starts = [i for i, event in enumerate(page["events"]) if event["operator"] == "BDC"]
        ends = [i for i, event in enumerate(page["events"]) if event["operator"] == "EMC"]
        self.assertEqual(len(starts), len(ends))
        self.assertGreaterEqual(len(starts), 2)
        self.assertGreater(mapped[starts[1]], mapped[ends[0]] + 1)
        start = starts[1]
        lower = mapped[start - 1]
        earlier = [ordinal for ordinal in page["outside_operator_ordinals"]
                   if lower < ordinal < mapped[start]]
        self.assertTrue(earlier)
        outside = max(earlier)
        previous = mapped[start]
        mapped[start] = outside
        page["outside_operator_ordinals"].remove(outside)
        page["outside_operator_ordinals"].append(previous)
        page["outside_operator_ordinals"].sort()
        self.assertEqual(mapped, sorted(set(mapped)))
        self.assertEqual(page["outside_operator_ordinals"],
                         sorted(set(page["outside_operator_ordinals"])))
        self.assertGreater(mapped[start + 1], mapped[start] + 1)
        covered = set(mapped)
        self.assertFalse(covered.intersection(page["outside_operator_ordinals"]))
        covered.update(page["outside_operator_ordinals"])
        for block in (*page["graphic_blocks"], *page["pagination_blocks"]):
            span = set(range(block["first_operator"], block["last_operator"] + 1))
            self.assertFalse(covered.intersection(span))
            covered.update(span)
        self.assertEqual(covered, set(range(page["original_operator_count"])))
        self.assertEqual(page["events"], original["trace"]["pages"][target["index"]]["events"])
        self.assertEqual(page["runs"], original["trace"]["pages"][target["index"]]["runs"])
        self.m._schema(native, "native")
        self.m.project_text_trace(native["trace"])
        with self.assertRaises(ValueError):
            self.m._validate_native(native, args["pdf_bytes"], args["expected_profile_sha256"])

    def test_graphic_blocks_must_match_figure_page_mcid_and_unowned_artifacts(self):
        args = self.arguments(96)
        original = self.native_record(96)
        _, counts = self.m._validate_native(
            original, args["pdf_bytes"], args["expected_profile_sha256"])
        self.assertEqual(counts["figure_count"], 1)
        self.assertGreater(len(original["trace"]["pages"]), 1)
        for case in ("figure-null", "figure-text-owner", "figure-wrong-page", "artifact-owned"):
            native = deepcopy(original)
            pages = native["trace"]["pages"]
            figure = next(b for b in pages[0]["graphic_blocks"] if b["kind"] == "figure")
            figure_mcid = figure["mcid"]
            if case == "figure-null":
                figure["mcid"] = None
            elif case == "figure-text-owner":
                figure["mcid"] = next(
                    owner["mcid"] for owner in pages[0]["mcid_owners"]
                    if owner["mcid"] != figure_mcid)
            elif case == "figure-wrong-page":
                other = next(b for b in pages[1]["graphic_blocks"]
                             if b["kind"] == "artifact" and b["dna_paints"] == 0)
                figure["kind"], figure["mcid"] = "artifact", None
                other["kind"], other["mcid"] = "figure", figure_mcid
            else:
                artifact = next(b for b in pages[0]["graphic_blocks"] if b["kind"] == "artifact")
                artifact["mcid"] = figure_mcid
            with self.subTest(case=case):
                self.m._schema(native, "native")
                self.m.project_text_trace(native["trace"])
                with self.assertRaises(ValueError):
                    self.m._validate_native(
                        native, args["pdf_bytes"], args["expected_profile_sha256"])

    def test_native_graphic_intervals_match_the_admitted_grammar(self):
        args = self.arguments(96)
        original = self.native_record(96)
        self.m._validate_native(original, args["pdf_bytes"], args["expected_profile_sha256"])
        for case in ("dna-five", "dna-seven", "figure-533"):
            native = deepcopy(original)
            page = native["trace"]["pages"][0]
            block = next(b for b in page["graphic_blocks"]
                         if (b["kind"] == "figure" if case == "figure-533"
                             else b["dna_paints"] == 1))
            outside = page["outside_operator_ordinals"]
            length = block["last_operator"] - block["first_operator"] + 1
            if case == "figure-533":
                self.assertGreaterEqual(length, 534)
                last = block["first_operator"] + 532
                outside.extend(range(last + 1, block["last_operator"] + 1))
                block["last_operator"] = last
            else:
                self.assertEqual(length, 6)
                if case == "dna-five":
                    outside.append(block["first_operator"])
                    block["first_operator"] += 1
                else:
                    adjacent = [ordinal for ordinal in
                                (block["first_operator"] - 1, block["last_operator"] + 1)
                                if ordinal in outside]
                    self.assertTrue(adjacent)
                    ordinal = adjacent[0]
                    outside.remove(ordinal)
                    if ordinal < block["first_operator"]:
                        block["first_operator"] = ordinal
                    else:
                        block["last_operator"] = ordinal
            outside.sort()
            self.assertEqual(block["last_operator"] - block["first_operator"] + 1,
                             {"dna-five": 5, "dna-seven": 7, "figure-533": 533}[case])
            for current in native["trace"]["pages"]:
                covered = set(current["projected_operator_ordinals"])
                for graphic in (*current["graphic_blocks"], *current["pagination_blocks"]):
                    interval = set(range(graphic["first_operator"],
                                         graphic["last_operator"] + 1))
                    self.assertFalse(covered.intersection(interval))
                    covered.update(interval)
                remaining = current["outside_operator_ordinals"]
                self.assertEqual(remaining, sorted(set(remaining)))
                self.assertFalse(covered.intersection(remaining))
                covered.update(remaining)
                self.assertEqual(covered, set(range(current["original_operator_count"])))
            self.assertEqual(native["graphics"], original["graphics"])
            self.assertEqual(native["trace"]["nodes"], original["trace"]["nodes"])
            self.m._schema(native, "native")
            self.m.project_text_trace(native["trace"])
            with self.subTest(case=case):
                with self.assertRaises(ValueError):
                    self.m._validate_native(
                        native, args["pdf_bytes"], args["expected_profile_sha256"])

    def test_native_dna_paint_requires_its_artifact_page(self):
        args = self.arguments(96)
        original = self.native_record(96)
        self.m._validate_native(original, args["pdf_bytes"], args["expected_profile_sha256"])
        self.assertGreater(len(original["trace"]["pages"]), 1)
        for case in ("figure", "non-cover-page-artifact"):
            native = deepcopy(original)
            pages = native["trace"]["pages"]
            donor = next(b for b in pages[0]["graphic_blocks"] if b["dna_paints"] == 1)
            receiver = (next(b for b in pages[0]["graphic_blocks"] if b["kind"] == "figure")
                        if case == "figure" else
                        next(b for page in pages[1:] for b in page["graphic_blocks"]
                             if b["kind"] == "artifact" and b["dna_paints"] == 0))
            donor["dna_paints"], receiver["dna_paints"] = 0, 1
            with self.subTest(receiver=case):
                self.assertEqual(sum(b["dna_paints"] for p in pages for b in p["graphic_blocks"]),
                                 native["graphics"]["dna_paints"])
                self.m._schema(native, "native")
                self.m.project_text_trace(native["trace"])
                with self.assertRaises(ValueError):
                    self.m._validate_native(
                        native, args["pdf_bytes"], args["expected_profile_sha256"])

    def test_receipt_requires_every_page_rasterized_even_after_resealing(self):
        receipt = self.run_qa()
        bad = receipt.to_dict()
        bad["page_count"] = 2
        bad["raster_inspected_pages"] = 1
        self.assertEqual(set(bad["stages"].values()), {"PASS"})
        self.m._schema(bad)
        payload = self.m.canonical(bad)
        with self.assertRaises(ValueError):
            self.m.TypedOriginalBrandQA(payload)
        object.__setattr__(receipt, "_payload", payload)
        object.__setattr__(receipt, "_sealed_sha256", sha256(payload).hexdigest())
        with self.assertRaises(ValueError):
            receipt.to_dict()

    def test_receipt_source_units_cover_title_and_represented_findings(self):
        source = self.run_qa().to_dict()
        for findings, actual_units in ((0, 6), (1, 8), (96, 198)):
            presentation = document(findings)
            produced = prepare_typed_pdf_source(
                presentation_ir=presentation, expected_ir_sha256=digest(presentation)).to_dict()
            with self.subTest(producer_findings=findings):
                self.assertEqual(produced["counts"]["represented_findings"], findings)
                self.assertEqual(len(produced["units"]), actual_units)
                headings = sum(unit["kind"] == "section_heading" for unit in produced["units"])
                self.assertGreaterEqual(actual_units, (1 if findings == 0 else findings + 3) + headings)
        for case in ("missing-title-or-findings", "missing-table-units", "short-pdf",
                     "too-few-text-mcids", "too-few-projected-nodes", "too-many-pages",
                     "too-few-operations"):
            bad = deepcopy(source)
            coverage = bad["coverage"]
            if case == "missing-title-or-findings":
                bad["source_units"] = 1
            elif case == "missing-table-units":
                bad["source_units"] = bad["represented_findings"] + 1
            elif case == "short-pdf":
                bad["pdf_byte_count"] = 7
            elif case == "too-few-text-mcids":
                coverage["text_mcids"] = (bad["source_units"] + bad["brand_text_units"]
                                          + 1 + 2 * bad["navigation_entries"] - 1)
                coverage["native_mcids"] = coverage["text_mcids"] + coverage["figure_count"]
            elif case == "too-few-projected-nodes":
                coverage["projected_nodes"] = (coverage["text_mcids"]
                                               + bad["source_units"] + bad["brand_text_units"] + 1 + bad["navigation_entries"])
                coverage["native_nodes"] = (coverage["projected_nodes"]
                                            + coverage["accounted_brand_wrapper_nodes"] + coverage["accounted_navigation_wrapper_nodes"])
            elif case == "too-many-pages":
                bad["page_count"] = coverage["text_mcids"] + 1
                bad["raster_inspected_pages"] = bad["page_count"]
                bad["pagination_pages"] = coverage["pagination_blocks"] = bad["page_count"]
                window = self.m.RASTER_PAGES_PER_WINDOW
                bad["raster_window_count"] = (bad["page_count"] + window - 1) // window
            else:
                coverage["operations"] = self.operation_floor(bad) - 1
            self.m._schema(bad)
            payload = self.m.canonical(bad)
            with self.subTest(case=case, operation="constructor"):
                with self.assertRaises(ValueError):
                    self.m.TypedOriginalBrandQA(payload)
            with self.subTest(case=case, operation="resealed-to-dict"):
                receipt = self.m.TypedOriginalBrandQA(self.m.canonical(source))
                object.__setattr__(receipt, "_payload", payload)
                object.__setattr__(receipt, "_sealed_sha256", sha256(payload).hexdigest())
                with self.assertRaises(ValueError):
                    receipt.to_dict()

        boundary = deepcopy(source)
        coverage = boundary["coverage"]
        limit = self.m.prior.MAX_VISITS
        # Keep the projected-node and operation bounds feasible while isolating
        # the independent traversal charge at its exact limit and one above it.
        coverage["text_mcids"] = limit // 10
        coverage["native_mcids"] = coverage["text_mcids"] + coverage["figure_count"]
        coverage["native_nodes"] = (limit + 1 - coverage["native_mcids"]) // 2
        coverage["projected_nodes"] = (coverage["native_nodes"]
                                       - coverage["accounted_brand_wrapper_nodes"] - coverage["accounted_navigation_wrapper_nodes"])
        charge = 2 * coverage["native_nodes"] - 1 + coverage["native_mcids"]
        adjustment = limit - charge
        self.assertIn(adjustment, (0, 1))
        coverage["native_mcids"] += adjustment
        coverage["text_mcids"] += adjustment
        coverage["operations"] = self.operation_floor(boundary) + 7
        self.assertEqual(2 * coverage["native_nodes"] - 1 + coverage["native_mcids"], limit)
        self.assertLessEqual(coverage["projected_nodes"], 1 + 6 * coverage["text_mcids"])
        self.assertLessEqual(coverage["operations"], self.m.prior.MAX_OPERATIONS)
        self.m._schema(boundary)
        self.assertEqual(self.m.TypedOriginalBrandQA(
            self.m.canonical(boundary)).to_dict(), boundary)
        bad = deepcopy(boundary)
        coverage = bad["coverage"]
        coverage["native_mcids"] += 1
        coverage["text_mcids"] += 1
        self.assertEqual(2 * coverage["native_nodes"] - 1 + coverage["native_mcids"], limit + 1)
        self.assertEqual(coverage["native_nodes"], coverage["projected_nodes"]
                         + coverage["accounted_brand_wrapper_nodes"] + coverage["accounted_navigation_wrapper_nodes"])
        self.assertEqual(coverage["native_mcids"], coverage["text_mcids"]
                         + coverage["figure_count"])
        text_units = bad["source_units"] + bad["brand_text_units"] + 1 + bad["navigation_entries"]
        self.assertGreaterEqual(bad["source_units"],
                                (bad["represented_findings"] + 3 if bad["represented_findings"] else 1)
                                + bad["navigation_entries"])
        self.assertGreaterEqual(bad["pdf_byte_count"], 8)
        self.assertGreaterEqual(coverage["text_mcids"], text_units + bad["navigation_entries"])
        self.assertGreaterEqual(coverage["projected_nodes"],
                                coverage["text_mcids"] + text_units + 1)
        self.assertLessEqual(coverage["projected_nodes"], 1 + 6 * coverage["text_mcids"])
        self.assertLessEqual(coverage["operations"], self.m.prior.MAX_OPERATIONS)
        self.assertGreaterEqual(coverage["text_mcids"], bad["page_count"])
        self.assertGreaterEqual(coverage["operations"], self.operation_floor(bad))
        self.m._schema(bad)
        payload = self.m.canonical(bad)
        with self.subTest(graph_visit_budget="constructor"):
            with self.assertRaises(ValueError):
                self.m.TypedOriginalBrandQA(payload)
        with self.subTest(graph_visit_budget="resealed-to-dict"):
            receipt = self.m.TypedOriginalBrandQA(self.m.canonical(boundary))
            object.__setattr__(receipt, "_payload", payload)
            object.__setattr__(receipt, "_sealed_sha256", sha256(payload).hexdigest())
            with self.assertRaises(ValueError):
                receipt.to_dict()
        self.assertGreaterEqual(
            bad["coverage"]["projected_nodes"],
            bad["coverage"]["text_mcids"] + text_units + 1
            + (bad["represented_findings"] + 4 if bad["represented_findings"] else 0))
        for findings in (0, 1, 2, 96):
            exact = deepcopy(source)
            exact["represented_findings"] = findings
            exact["source_units"] = (findings + 3 if findings else 1) + exact["navigation_entries"]
            exact["page_count"] = exact["raster_inspected_pages"] = 2
            exact["raster_window_count"] = 1
            coverage = exact["coverage"]
            exact["pagination_pages"] = coverage["pagination_blocks"] = 2
            text_units = exact["source_units"] + exact["brand_text_units"] + 1 + exact["navigation_entries"]
            coverage["text_mcids"] = text_units + exact["navigation_entries"]
            coverage["native_mcids"] = coverage["text_mcids"] + coverage["figure_count"]
            # Each source/brand unit has a text container and at least one Span;
            # findings additionally require their body TRs and four table wrappers.
            base_nodes = coverage["text_mcids"] + text_units + 1
            table_nodes = findings + 4 if findings else 0
            coverage["projected_nodes"] = base_nodes + table_nodes
            coverage["native_nodes"] = (coverage["projected_nodes"]
                                        + coverage["accounted_brand_wrapper_nodes"] + coverage["accounted_navigation_wrapper_nodes"])
            coverage["operations"] = self.operation_floor(exact)
            self.m._schema(exact)
            with self.subTest(findings=findings, node_bound="exact-minimum"):
                self.assertEqual(self.m.TypedOriginalBrandQA(
                    self.m.canonical(exact)).to_dict(), exact)
            # Isolate the missing suffix MCID while keeping the other counters feasible.
            missing_suffix = deepcopy(exact)
            missing_coverage = missing_suffix["coverage"]
            missing_coverage["text_mcids"] -= 1
            missing_coverage["native_mcids"] -= 1
            self.assertEqual(missing_coverage["text_mcids"],
                             text_units + missing_suffix["navigation_entries"] - 1)
            self.assertGreaterEqual(missing_coverage["text_mcids"], text_units)
            self.assertEqual(missing_coverage["native_mcids"],
                             missing_coverage["text_mcids"] + missing_coverage["figure_count"])
            self.assertGreaterEqual(missing_coverage["projected_nodes"],
                                    missing_coverage["text_mcids"] + text_units + 1 + table_nodes)
            self.assertLessEqual(missing_coverage["projected_nodes"],
                                 1 + 6 * missing_coverage["text_mcids"])
            self.assertGreaterEqual(missing_coverage["text_mcids"], missing_suffix["page_count"])
            self.assertGreaterEqual(missing_coverage["operations"], self.operation_floor(missing_suffix))
            self.m._schema(missing_suffix)
            payload = self.m.canonical(missing_suffix)
            with self.subTest(findings=findings, mcid_floor="one-below", boundary="constructor"):
                with self.assertRaises(ValueError):
                    self.m.TypedOriginalBrandQA(payload)
            with self.subTest(findings=findings, mcid_floor="one-below", boundary="resealed-to-dict"):
                receipt = self.m.TypedOriginalBrandQA(self.m.canonical(exact))
                object.__setattr__(receipt, "_payload", payload)
                object.__setattr__(receipt, "_sealed_sha256", sha256(payload).hexdigest())
                with self.assertRaises(ValueError):
                    receipt.to_dict()
            missing_heading = deepcopy(exact)
            missing_heading["source_units"] -= 1
            self.m._schema(missing_heading)
            payload = self.m.canonical(missing_heading)
            with self.subTest(findings=findings, source_floor="one-below", boundary="constructor"):
                with self.assertRaises(ValueError):
                    self.m.TypedOriginalBrandQA(payload)
            with self.subTest(findings=findings, source_floor="one-below", boundary="resealed-to-dict"):
                receipt = self.m.TypedOriginalBrandQA(self.m.canonical(exact))
                object.__setattr__(receipt, "_payload", payload)
                object.__setattr__(receipt, "_sealed_sha256", sha256(payload).hexdigest())
                with self.assertRaises(ValueError):
                    receipt.to_dict()
            lower = [("one-below-minimum", base_nodes + table_nodes - 1)]
            if findings:
                lower.append(("four-table-wrappers-without-finding-rows", base_nodes + 4))
            for mode, projected_nodes in lower:
                bad = deepcopy(exact)
                coverage = bad["coverage"]
                coverage["projected_nodes"] = projected_nodes
                coverage["native_nodes"] = (projected_nodes
                                            + coverage["accounted_brand_wrapper_nodes"] + coverage["accounted_navigation_wrapper_nodes"])
                self.assertLess(projected_nodes, base_nodes + table_nodes)
                self.assertEqual(coverage["native_mcids"], coverage["text_mcids"] + 1)
                self.assertEqual(coverage["operations"], self.operation_floor(bad))
                self.assertLessEqual(2 * coverage["native_nodes"] - 1
                                     + coverage["native_mcids"], self.m.prior.MAX_VISITS)
                self.m._schema(bad)
                payload = self.m.canonical(bad)
                with self.subTest(findings=findings, node_bound=mode, boundary="constructor"):
                    with self.assertRaises(ValueError):
                        self.m.TypedOriginalBrandQA(payload)
                with self.subTest(findings=findings, node_bound=mode, boundary="resealed-to-dict"):
                    receipt = self.m.TypedOriginalBrandQA(self.m.canonical(exact))
                    object.__setattr__(receipt, "_payload", payload)
                    object.__setattr__(receipt, "_sealed_sha256", sha256(payload).hexdigest())
                    with self.assertRaises(ValueError):
                        receipt.to_dict()

        def navigation_boundary(fragment_count, page_count, entries, *,
                                source_units=None, text_mcids=None):
            value = deepcopy(source)
            value["represented_findings"] = 0
            value["navigation_entries"] = entries
            value["source_units"] = 1 + entries if source_units is None else source_units
            value["page_count"] = value["raster_inspected_pages"] = value["pagination_pages"] = page_count
            value["raster_window_count"] = (page_count + self.m.RASTER_PAGES_PER_WINDOW - 1) // self.m.RASTER_PAGES_PER_WINDOW
            coverage = value["coverage"]
            coverage["accounted_brand_wrapper_nodes"] = 5 + fragment_count
            coverage["accounted_navigation_wrapper_nodes"] = entries
            coverage["pagination_blocks"] = page_count
            units = value["source_units"] + value["brand_text_units"] + 1 + entries
            coverage["text_mcids"] = (
                max(units + entries, page_count) if text_mcids is None else text_mcids)
            coverage["native_mcids"] = coverage["text_mcids"] + coverage["figure_count"]
            coverage["projected_nodes"] = coverage["text_mcids"] + units + 1
            coverage["native_nodes"] = (coverage["projected_nodes"]
                                        + coverage["accounted_brand_wrapper_nodes"] + entries)
            coverage["operations"] = self.operation_floor(value)
            return value

        for fragments, page_count, entries in ((1, 2, 1), (2, 3, 2), (63, 64, 63)):
            exact = navigation_boundary(fragments, page_count, entries)
            self.m._schema(exact)
            with self.subTest(fragment_count=fragments, boundary="exact"):
                self.assertEqual(self.m.TypedOriginalBrandQA(self.m.canonical(exact)).to_dict(), exact)
        # Sparse controls isolate page/navigation obligations from the
        # independent source-unit floor, including two contents fragments.
        for fragments, pages, entries, source_units, minimum in (
                (1, 8, 1, 3, 11), (2, 8, 2, 4, 12)):
            exact = navigation_boundary(
                fragments, pages, entries, source_units=source_units, text_mcids=minimum)
            units = source_units + exact["brand_text_units"] + 1 + entries
            self.assertGreater(minimum, units + entries)
            self.assertGreater(minimum, pages)
            self.m._schema(exact)
            with self.subTest(fragment_count=fragments, text_mcid_bound="exact"):
                self.assertEqual(self.m.TypedOriginalBrandQA(
                    self.m.canonical(exact)).to_dict(), exact)
            bad = navigation_boundary(
                fragments, pages, entries, source_units=source_units, text_mcids=minimum - 1)
            self.assertGreaterEqual(bad["coverage"]["text_mcids"], units + entries)
            self.assertGreaterEqual(bad["coverage"]["text_mcids"], pages)
            self.m._schema(bad)
            payload = self.m.canonical(bad)
            with self.subTest(fragment_count=fragments, text_mcid_bound="one-below",
                              boundary="constructor"), self.assertRaises(ValueError):
                self.m.TypedOriginalBrandQA(payload)
            receipt = self.m.TypedOriginalBrandQA(self.m.canonical(exact))
            object.__setattr__(receipt, "_payload", payload)
            object.__setattr__(receipt, "_sealed_sha256", sha256(payload).hexdigest())
            with self.subTest(fragment_count=fragments, text_mcid_bound="one-below",
                              boundary="resealed-to-dict"), self.assertRaises(ValueError):
                receipt.to_dict()
        for mode, parameters in (("pages", (2, 3, 3)), ("entries", (1, 3, 1))):
            exact = navigation_boundary(*parameters)
            self.assertEqual(self.m.TypedOriginalBrandQA(self.m.canonical(exact)).to_dict(), exact)
            bad = deepcopy(exact)
            coverage = bad["coverage"]
            coverage["accounted_brand_wrapper_nodes"] += 1
            coverage["native_nodes"] += 1
            self.m._schema(bad)
            self.assertEqual(coverage["native_nodes"], coverage["projected_nodes"]
                             + coverage["accounted_brand_wrapper_nodes"] + coverage["accounted_navigation_wrapper_nodes"])
            if mode == "pages":
                self.assertGreater(coverage["accounted_brand_wrapper_nodes"], bad["page_count"] + 4)
                self.assertLessEqual(coverage["accounted_brand_wrapper_nodes"], 5 + bad["navigation_entries"])
            else:
                self.assertGreater(coverage["accounted_brand_wrapper_nodes"], 5 + bad["navigation_entries"])
                self.assertLessEqual(coverage["accounted_brand_wrapper_nodes"], bad["page_count"] + 4)
            payload = self.m.canonical(bad)
            with self.subTest(fragment_bound=mode, boundary="constructor"), self.assertRaises(ValueError):
                self.m.TypedOriginalBrandQA(payload)
            receipt = self.m.TypedOriginalBrandQA(self.m.canonical(exact))
            object.__setattr__(receipt, "_payload", payload)
            object.__setattr__(receipt, "_sealed_sha256", sha256(payload).hexdigest())
            with self.subTest(fragment_bound=mode, boundary="resealed-to-dict"), self.assertRaises(ValueError):
                receipt.to_dict()

    def test_shared_content_requires_identical_native_operator_accounting(self):
        from reporting import _pdf_typed_original_brand_qa_worker as worker
        baseline = self.native_record(96)
        nodes = {tuple(node["reference"]): node for node in baseline["trace"]["nodes"]}
        signatures = {}
        pair = None
        for page in baseline["trace"]["pages"][1:]:
            roles = tuple(nodes[tuple(owner["structure_reference"])]["role"]
                          for owner in page["mcid_owners"])
            if roles in signatures:
                pair = signatures[roles], page["index"]
                break
            signatures[roles] = page["index"]
        self.assertIsNotNone(pair, "two actual non-cover pages need equal native MCID roles")
        donor, receiver = pair

        def shared_pages(writer):
            self.edit_page(writer, donor, lambda ops: ops.extend([([], b"q"), ([], b"Q")]))
            writer.pages[receiver][NameObject("/Contents")] = writer.pages[donor].raw_get("/Contents")

        args = self.rewritten(shared_pages, count=96)
        reader = PdfReader(BytesIO(args["pdf_bytes"]), strict=True)
        pages = worker.native._page_tree(reader)
        trace, attributes, figures = worker._structure(reader, pages)
        worker._passive(reader, attributes, figures)
        roles = {tuple(node["reference"]): node["role"] for node in trace["nodes"]}
        fonts, forms, decoded = {}, {}, 0
        for page, (_, obj, resources) in zip(trace["pages"], pages, strict=True):
            worker._page(page, obj, resources, reader, fonts, forms, roles,
                         worker.contract.MAX_STREAM_BYTES - decoded)
            decoded += page["decoded_stream_bytes"]
        trace["fonts"] = list(fonts.values())
        self.assertEqual(len(forms), 1)
        # This is a generic native-reference control assembled from actual parsed
        # bytes, not an accepted editorial worker result. Repeated whole streams
        # now repeat a physical folio and must fail the editorial validator.
        original = deepcopy(baseline)
        original.update(pdf_sha256=args["expected_pdf_sha256"],
                        pdf_byte_count=len(args["pdf_bytes"]), trace=trace,
                        page_labels=reader.page_labels)
        original["graphics"].update(
            figure_count=sum(b["kind"] == "figure" for p in trace["pages"] for b in p["graphic_blocks"]),
            artifact_count=sum(b["kind"] == "artifact" for p in trace["pages"] for b in p["graphic_blocks"]),
            dna_paints=sum(b["dna_paints"] for p in trace["pages"] for b in p["graphic_blocks"]),
            operations=sum(p["original_operator_count"] for p in trace["pages"]) + 3)
        self.m._schema(original, "native")
        self.m.prior._reference_consistency(trace)
        first, second = trace["pages"][donor], trace["pages"][receiver]
        self.assertNotEqual(first["reference"], second["reference"])
        self.assertEqual(first["contents_reference"], second["contents_reference"])
        self.assertNotEqual(first["mcid_owners"], second["mcid_owners"])
        for name in ("content_sha256", "decoded_stream_bytes", "events",
                     "original_operator_count", "projected_operator_ordinals",
                     "outside_operator_ordinals", "graphic_blocks", "pagination_blocks"):
            self.assertEqual(first[name], second[name])
        with self.assertRaises(ValueError):
            self.m._validate_native(original, args["pdf_bytes"], args["expected_profile_sha256"])
        self.refuse(args)
        count = second["original_operator_count"]
        self.assertEqual(second["outside_operator_ordinals"][-2:], [count - 2, count - 1])

        for case in ("extra-outside-pair", "relocated-outside-pair",
                     "graphic-block-digest", "pagination-event-only"):
            native = deepcopy(original)
            page = native["trace"]["pages"][receiver]
            if case == "extra-outside-pair":
                page["outside_operator_ordinals"].extend([count, count + 1])
                page["original_operator_count"] += 2
                native["graphics"]["operations"] += 2
            elif case == "relocated-outside-pair":
                page["projected_operator_ordinals"] = [
                    ordinal + 2 for ordinal in page["projected_operator_ordinals"]]
                page["outside_operator_ordinals"] = [0, 1] + [
                    ordinal + 2 for ordinal in page["outside_operator_ordinals"] if ordinal < count - 2]
                for block in (*page["graphic_blocks"], *page["pagination_blocks"]):
                    block["first_operator"] += 2
                    block["last_operator"] += 2
            elif case == "graphic-block-digest":
                block = page["graphic_blocks"][0]
                self.assertEqual(block["kind"], "artifact")
                value = block["sha256"]
                block["sha256"] = ("0" if value[0] != "0" else "1") + value[1:]
            else:
                block = page["pagination_blocks"][0]
                color = block["events"][1]
                self.assertEqual(color["operator"], "rg")
                color["operands"][0] = "0" if color["operands"][0] != "0" else "1"
                block["sha256"] = sha256(self.m.canonical(block["events"])).hexdigest()
            with self.subTest(shared_stream_disagreement=case):
                self.m._schema(native, "native")
                self.m.prior._reference_consistency(native["trace"])
                covered = set(page["projected_operator_ordinals"])
                for block in (*page["graphic_blocks"], *page["pagination_blocks"]):
                    interval = set(range(block["first_operator"], block["last_operator"] + 1))
                    self.assertFalse(covered.intersection(interval))
                    covered.update(interval)
                self.assertFalse(covered.intersection(page["outside_operator_ordinals"]))
                covered.update(page["outside_operator_ordinals"])
                self.assertEqual(covered, set(range(page["original_operator_count"])))
                # The shared-stream guard must refuse before the later graph/
                # folio check. The latter remains active and is never mocked.
                with patch.object(self.m, "project_text_trace", wraps=self.m.project_text_trace) as project:
                    with self.assertRaises(ValueError):
                        self.m._validate_native(native, args["pdf_bytes"], args["expected_profile_sha256"])
                    project.assert_not_called()
                with patch.object(self.m, "_run_worker", return_value=self.m.canonical(native)) as launch, (
                        patch.object(self.m, "inspect_pdf_document_metadata")) as metadata:
                    self.refuse(args)
                    launch.assert_called_once_with(args["pdf_bytes"], args["expected_pdf_sha256"])
                    metadata.assert_not_called()

    def test_receipt_projected_nodes_are_bounded_by_matched_span_grammar(self):
        genuine = self.run_qa(self.arguments(0)).to_dict()
        self.assertEqual(self.m.TypedOriginalBrandQA(
            self.m.canonical(genuine)).to_dict(), genuine)
        self.assertLessEqual(genuine["coverage"]["projected_nodes"],
                             1 + 6 * genuine["coverage"]["text_mcids"])

        # These counter controls test necessary receipt invariants; they are not
        # newly observed PDF results or proof of worker-result authentication.
        boundary = deepcopy(genuine)
        coverage = boundary["coverage"]
        maximum = 1 + 6 * coverage["text_mcids"]
        coverage["projected_nodes"] = maximum
        coverage["native_nodes"] = maximum + coverage["accounted_brand_wrapper_nodes"] + coverage["accounted_navigation_wrapper_nodes"]
        self.m._schema(boundary)
        self.assertEqual(self.m.TypedOriginalBrandQA(
            self.m.canonical(boundary)).to_dict(), boundary)

        bad = deepcopy(boundary)
        coverage = bad["coverage"]
        coverage["projected_nodes"] += 1
        coverage["native_nodes"] += 1
        self.assertEqual(coverage["projected_nodes"], maximum + 1)
        self.assertEqual(coverage["native_nodes"], coverage["projected_nodes"]
                         + coverage["accounted_brand_wrapper_nodes"] + coverage["accounted_navigation_wrapper_nodes"])
        self.assertEqual(coverage["native_mcids"], coverage["text_mcids"]
                         + coverage["figure_count"])
        self.assertLessEqual(2 * coverage["native_nodes"] - 1
                             + coverage["native_mcids"], self.m.prior.MAX_VISITS)
        text_units = bad["source_units"] + bad["brand_text_units"] + 1 + bad["navigation_entries"]
        table_nodes = bad["represented_findings"] + 4 if bad["represented_findings"] else 0
        self.assertGreaterEqual(coverage["projected_nodes"],
                                coverage["text_mcids"] + text_units + 1 + table_nodes)
        self.assertGreaterEqual(coverage["text_mcids"], text_units + bad["navigation_entries"])
        self.assertGreaterEqual(coverage["text_mcids"], bad["page_count"])
        self.assertGreaterEqual(coverage["operations"], self.operation_floor(bad))
        self.m._schema(bad)
        payload = self.m.canonical(bad)
        with self.subTest(boundary="constructor"):
            with self.assertRaises(ValueError):
                self.m.TypedOriginalBrandQA(payload)
        with self.subTest(boundary="resealed-to-dict"):
            receipt = self.m.TypedOriginalBrandQA(self.m.canonical(genuine))
            object.__setattr__(receipt, "_payload", payload)
            object.__setattr__(receipt, "_sealed_sha256", sha256(payload).hexdigest())
            with self.assertRaises(ValueError):
                receipt.to_dict()

    def test_receipt_window_count_matches_four_page_boundaries(self):
        source = self.run_qa().to_dict()
        for pages, windows, wrong_windows in ((4, 1, 2), (5, 2, 1)):
            valid = deepcopy(source)
            valid.update(page_count=pages, raster_inspected_pages=pages,
                         raster_window_count=windows, pagination_pages=pages)
            valid["coverage"]["pagination_blocks"] = pages
            with self.subTest(page_count=pages, operation="valid"):
                self.assertEqual(self.m.TypedOriginalBrandQA(
                    self.m.canonical(valid)).to_dict()["raster_window_count"], windows)
            bad = dict(valid, raster_window_count=wrong_windows)
            self.m._schema(bad)
            self.assertEqual(bad["raster_inspected_pages"], bad["page_count"])
            self.assertEqual(bad["stages"]["all_page_raster"], "PASS")
            payload = self.m.canonical(bad)
            with self.subTest(page_count=pages, operation="constructor"):
                with self.assertRaises(ValueError):
                    self.m.TypedOriginalBrandQA(payload)
            with self.subTest(page_count=pages, operation="resealed-to-dict"):
                receipt = self.m.TypedOriginalBrandQA(self.m.canonical(valid))
                object.__setattr__(receipt, "_payload", payload)
                object.__setattr__(receipt, "_sealed_sha256", sha256(payload).hexdigest())
                with self.assertRaises(ValueError):
                    receipt.to_dict()
        for counter in ("native_nodes", "native_mcids", "accounted_navigation_wrapper_nodes", "pagination_blocks"):
            bad = deepcopy(source)
            bad["coverage"][counter] += 1
            self.m._schema(bad)
            payload = self.m.canonical(bad)
            with self.subTest(coverage=counter, operation="constructor"):
                with self.assertRaises(ValueError):
                    self.m.TypedOriginalBrandQA(payload)
            with self.subTest(coverage=counter, operation="resealed-to-dict"):
                receipt = self.m.TypedOriginalBrandQA(self.m.canonical(source))
                object.__setattr__(receipt, "_payload", payload)
                object.__setattr__(receipt, "_sealed_sha256", sha256(payload).hexdigest())
                with self.assertRaises(ValueError):
                    receipt.to_dict()

    def test_wrong_language_and_cross_plan_metadata_refuse(self):
        def wrong_language(writer):
            writer._root_object[NameObject("/Lang")] = TextStringObject("pt-BR")
        self.refuse(self.rewritten(wrong_language))
        original = self.m.inspect_pdf_document_metadata
        def wrong_plan(**kwargs):
            receipt = original(**kwargs)
            return type(receipt)(pdf_sha256=receipt.pdf_sha256, ir_sha256=receipt.ir_sha256,
                                 plan_sha256="0" * 64, page_count=receipt.page_count)
        with patch.object(self.m, "inspect_pdf_document_metadata", side_effect=wrong_plan):
            self.refuse(self.arguments())

    def test_late_raster_failure_returns_no_partial_success(self):
        original = self.m.inspect_pdf_raster_window
        seen = []
        def fail_second(**kwargs):
            seen.append(kwargs["window_index"])
            if len(seen) == 2:
                raise ValueError("SYNTHETIC-SENTINEL-REJECT")
            return original(**kwargs)
        with patch.object(self.m, "inspect_pdf_raster_window", side_effect=fail_second):
            self.refuse(self.arguments(96))
        self.assertEqual(seen, [0, 1])

    def test_worker_refusal_and_malformed_result_are_content_free(self):
        for response in (b'{"status":"PASS"}', b'{"private":"SYNTHETIC-SENTINEL-REJECT"'):
            with self.subTest(response=response), patch.object(self.m, "_run_worker", return_value=response):
                self.refuse(self.arguments())
        args = self.arguments()
        native = self.native_record()
        self.assertEqual(native["limits"], self.m.LIMITS)
        stale = deepcopy(native)
        stale["limits"]["cpu_seconds"] = 5
        with patch.object(self.m, "_run_worker", return_value=self.m.canonical(stale)):
            self.refuse(args)
        response = self.m.canonical(native)
        self.m._schema(self.m.prior._loads(response.decode("ascii")), "native")
        process = object()
        def complete_output(command, **kwargs):
            output_fd = kwargs["pass_fds"][1]
            self.assertEqual(command[-2], str(output_fd))
            self.assertEqual(os.write(output_fd, response), len(response))
            return process
        for code in (0, 70):
            with self.subTest(exit_code=code), \
                    patch.object(self.m.subprocess, "Popen", side_effect=complete_output) as launch, \
                    patch.object(self.m, "wait_owned_process_group", return_value=code) as wait:
                if code == 0:
                    self.assertEqual(self.m._run_worker(args["pdf_bytes"], args["expected_pdf_sha256"]),
                                     response)
                else:
                    with self.assertRaises(ValueError):
                        self.m._run_worker(args["pdf_bytes"], args["expected_pdf_sha256"])
                launch.assert_called_once()
                wait.assert_called_once_with(
                    process, wall_seconds=self.m.WALL_SECONDS, cleanup_seconds=self.m.CLEANUP_SECONDS)

    def test_guard_failure_precedes_request_read_and_output(self):
        from reporting import _pdf_typed_original_brand_qa_worker as worker
        for guard in ("enforce_pdf_landlock", "enforce_pdf_network_filter"):
            with self.subTest(guard=guard), tempfile.TemporaryFile() as source, \
                    tempfile.TemporaryFile() as output, \
                    patch.object(worker.sys, "flags", SimpleNamespace(isolated=1)), \
                    patch.object(worker.sys, "dont_write_bytecode", True), \
                    patch.object(worker, "_limits", return_value={}), \
                    patch.object(worker, "_lifetime"), \
                    patch.object(worker, "enforce_pdf_landlock") as landlock, \
                    patch.object(worker, "enforce_pdf_network_filter") as network, \
                    patch.object(worker.native, "_read_request") as read, \
                    patch.object(worker, "_write_bytes") as write:
                order = []
                landlock.side_effect = lambda *_args, **_kwargs: order.append("landlock")
                network.side_effect = lambda *_args, **_kwargs: order.append("network")
                selected = landlock if guard == "enforce_pdf_landlock" else network
                def refused(*_args, **_kwargs):
                    order.append("landlock" if guard == "enforce_pdf_landlock" else "network")
                    raise ValueError("guard refused")
                selected.side_effect = refused
                code = worker.main(["worker", str(source.fileno()), str(output.fileno()), str(os.getpid())])
                self.assertEqual(code, 70)
                selected.assert_called_once()
                read.assert_not_called()
                write.assert_not_called()
                if guard == "enforce_pdf_landlock":
                    network.assert_not_called()
                    self.assertEqual(order, ["landlock"])
                else:
                    landlock.assert_called_once()
                    self.assertEqual(order, ["landlock", "network"])

    def test_changed_postflight_brand_contract_refuses(self):
        original = self.m.prepare_typed_original_brand_pdf
        calls = []
        def changed(**kwargs):
            html, bundle, record = original(**kwargs)
            calls.append(True)
            if len(calls) == 2:
                record = {**record, "html_sha256": "0" * 64}
            return html, bundle, record
        with patch.object(self.m, "prepare_typed_original_brand_pdf", side_effect=changed):
            self.refuse(self.arguments())
        self.assertEqual(len(calls), 2)

    def test_graphics_state_changes_precede_open_paths(self):
        def change(writer, context, after_path):
            def alter(ops):
                self.assertEqual(ops[-1][1], b"Q")
                rectangle = ([NumberObject(v) for v in (100, 200, 10, 10)], b"re")
                state = (([NumberObject(1)], b"w") if context == "artifact" else
                         ([NumberObject(v) for v in (1, 0, 0, 1, 0, 0)], b"cm"))
                body = [rectangle, state] if after_path else [state, rectangle]
                if context == "artifact":
                    payload = [
                        ([NameObject("/Artifact")], b"BMC"), ([], b"q"),
                        *body, ([], b"S"), ([], b"Q"), ([], b"EMC")]
                else:
                    payload = [([], b"q"), *body, ([], b"n"), ([], b"Q")]
                ops[-1:-1] = payload
            self.edit_page(writer, 0, alter)
        for context in ("artifact", "outside"):
            with self.subTest(context=context, position="before-path"):
                control = self.rewritten(lambda writer: change(writer, context, False))
                self.assertEqual(self.run_qa(control).to_dict()["figure_count"], 1)
            with self.subTest(context=context, position="after-path"):
                self.refuse(self.rewritten(lambda writer: change(writer, context, True)))

    def test_unfinished_graphic_paths_cannot_enter_the_logo_figure(self):
        for context in ("artifact-path", "artifact-clip", "outside"):
            def leak(writer):
                def alter(ops):
                    index = next(i for i, (args, op) in enumerate(ops)
                                 if op == b"BDC" and args[0] == "/Figure")
                    rect = ([NumberObject(0), NumberObject(0), NumberObject(100), NumberObject(100)], b"re")
                    if context == "outside":
                        payload = [rect]
                    else:
                        payload = [([NameObject("/Artifact")], b"BMC"), rect]
                        if context == "artifact-clip":
                            payload.append(([], b"W"))
                        payload.append(([], b"EMC"))
                    ops[index:index] = payload
                self.edit_page(writer, 0, alter)
            with self.subTest(context=context):
                self.refuse(self.rewritten(leak))

    def test_form_color_space_requires_a_native_name(self):
        def malformed(writer):
            form = next(iter(writer.pages[0]["/Resources"]["/XObject"].values())).get_object()
            form["/Group"][NameObject("/CS")] = TextStringObject("/DeviceRGB")
        self.refuse(self.rewritten(malformed))

    def test_profile_special_files_refuse_without_blocking(self):
        context = multiprocessing.get_context("fork")
        for kind in ("FIFO-with-no-writer", "symlink", "directory"):
            for role in ("manifest", "source"):
                with self.subTest(target=role, kind=kind), _temporary_profile_tree(self.m) as root:
                    target = self.m.MANIFEST if role == "manifest" else (
                        root / "reporting/pdf_typed_brand_render.py")
                    if kind == "symlink":
                        original = target.with_name(target.name + ".original")
                        target.rename(original)
                        target.symlink_to(original.name)
                    else:
                        target.unlink()
                        if kind == "directory":
                            target.mkdir()
                        else:
                            os.mkfifo(target, 0o600)
                    reader, writer = context.Pipe(duplex=False)

                    def audit():
                        reader.close()
                        try:
                            value = self.m.profile_sha256()
                        except (ValueError, OSError) as error:
                            writer.send(("refused", type(error).__name__))
                        except BaseException as error:
                            writer.send(("unexpected", type(error).__name__))
                        else:
                            writer.send(("returned", value))
                        finally:
                            writer.close()

                    process = context.Process(target=audit)
                    started = False
                    try:
                        process.start()
                        started = True
                        writer.close()
                        process.join(5)
                        if process.is_alive():
                            process.kill()
                            process.join(5)
                            self.assertFalse(process.is_alive(), "profile probe was not reaped")
                            self.fail("profile audit blocked on a special file")
                        self.assertEqual(process.exitcode, 0)
                        self.assertTrue(reader.poll(), "profile probe returned no outcome")
                        self.assertEqual(reader.recv()[0], "refused")
                    finally:
                        if started and process.is_alive():
                            process.kill()
                            process.join(5)
                        reader.close()
                        writer.close()
                        if not started or not process.is_alive():
                            process.close()

    def test_profile_manifest_and_source_size_caps_precede_reads(self):
        for role, size in (("manifest", 16385), ("source", 262145)):
            with self.subTest(target=role), _temporary_profile_tree(self.m) as root:
                target = self.m.MANIFEST if role == "manifest" else (
                    root / "reporting/pdf_typed_brand_render.py")
                target.write_bytes(b"x" * size)
                with _observe_profile_file_reads({target}) as records:
                    with self.assertRaises(ValueError):
                        self.m.profile_sha256()
                self.assertTrue(all(not item["requests"] for item in records),
                                "oversized body was read before refusal")
                self.assertTrue(all(item["closed"] for item in records))

    def test_profile_bounded_reads_preserve_exact_digests(self):
        for exact_cap in (False, True):
            with self.subTest(source_at_cap=exact_cap), _temporary_profile_tree(self.m) as root:
                if exact_cap:
                    name = "tests/test_reporting_typed_original_brand_qa.py"
                    target = root / name
                    original = target.read_bytes()
                    self.assertLess(len(original), 262144)
                    payload = original + b"\n" * (262144 - len(original))
                    target.write_bytes(payload)
                    manifest = json.loads(self.m.MANIFEST.read_bytes())
                    manifest["sources"][name] = sha256(payload).hexdigest()
                    self.m.MANIFEST.write_bytes(json.dumps(manifest, sort_keys=True).encode("ascii"))
                raw = self.m.MANIFEST.read_bytes()
                paths = {root / name for name in self.m.SOURCE_FILES} | {self.m.MANIFEST}
                sizes = {path: path.stat().st_size for path in paths}
                self.assertEqual(sizes[root / "reporting/assets/dna_column.png"], 164799)
                with _observe_profile_file_reads(paths) as records:
                    actual = self.m.profile_sha256()
                self.assertEqual(actual, sha256(raw).hexdigest())
                self.assertEqual({item["path"] for item in records}, paths)
                for item in records:
                    self.assertFalse(item["legacy"], "unbounded Path.read_bytes reached QA input")
                    self.assertTrue(item["closed"])
                    self.assertEqual(item["flags"] & os.O_ACCMODE, os.O_RDONLY)
                    for flag in (os.O_NOFOLLOW, os.O_NONBLOCK, os.O_CLOEXEC):
                        self.assertTrue(item["flags"] & flag)
                    self.assertTrue(item["requests"])
                    self.assertTrue(all(0 < count <= 8192 for count in item["requests"]))
                    self.assertEqual(sum(item["returned"]), sizes[item["path"]])

    def test_profile_source_read_changes_refuse_and_close_descriptor(self):
        for case in ("short-read-before-declared-EOF", "growth-during-read",
                     "same-size-rewrite-during-read", "named-file-replacement-during-read"):
            with self.subTest(case=case), _temporary_profile_tree(self.m) as root:
                target = root / "reporting/pdf_typed_brand_render.py"
                original, before = target.read_bytes(), target.stat()
                changed = []

                def change(path, data):
                    if path != target or changed:
                        return data
                    changed.append(True)
                    if case == "short-read-before-declared-EOF":
                        return b""
                    if case == "growth-during-read":
                        with target.open("ab") as output:
                            output.write(b"\n")
                    elif case == "same-size-rewrite-during-read":
                        target.write_bytes(bytes([original[0] ^ 1]) + original[1:])
                        os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns + 1000000000))
                    else:
                        replacement = target.with_name(target.name + ".replacement")
                        replacement.write_bytes(original)
                        os.replace(replacement, target)
                    return data

                with _observe_profile_file_reads({target}, after_read=change) as records:
                    with self.assertRaises(ValueError):
                        self.m.profile_sha256()
                self.assertEqual(changed, [True])
                self.assertTrue(records)
                self.assertTrue(all(item["closed"] for item in records))

    def test_combined_execution_budget_is_bound_to_its_own_profile(self):
        inherited = deepcopy(self.m.prior.LIMITS)
        original = json.loads(self.m.MANIFEST.read_bytes())
        self.assertEqual(original["limits"], self.m.LIMITS)
        self.assertEqual(original["wall_seconds"], self.m.WALL_SECONDS)
        self.assertEqual(original["cleanup_seconds"], self.m.CLEANUP_SECONDS)
        self.assertEqual(inherited["cpu_seconds"], 5)
        self.assertEqual(self.m.LIMITS["cpu_seconds"], 20)
        cases = (
            ("limits", {**self.m.LIMITS, "cpu_seconds": 5}),
            ("limits", {**self.m.LIMITS, "cpu_seconds": -1}),
            ("limits", {**self.m.LIMITS, "cpu_seconds": 20.0}),
            ("wall_seconds", 10),
            ("cleanup_seconds", 3),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value), _temporary_profile_tree(self.m):
                changed = json.loads(self.m.MANIFEST.read_bytes())
                changed[field] = value
                self.m.MANIFEST.write_text(json.dumps(changed), encoding="ascii")
                with self.assertRaises(ValueError):
                    self.m.profile_sha256()
        for field in ("limits", "wall_seconds", "cleanup_seconds"):
            with self.subTest(missing=field), _temporary_profile_tree(self.m):
                changed = json.loads(self.m.MANIFEST.read_bytes())
                del changed[field]
                self.m.MANIFEST.write_text(json.dumps(changed), encoding="ascii")
                with self.assertRaises(ValueError):
                    self.m.profile_sha256()
        self.assertEqual(self.m.prior.LIMITS, inherited)

    def test_new_profile_pins_the_executed_original_brand_dependencies(self):
        for name in ("reporting/brand_assets.py", "reporting/pdf_original_brand_inclusion.py",
                     "reporting/_pdf_original_dna_png_admission.py", "reporting/internal_navigation.py"):
            with self.subTest(source=name), _temporary_profile_tree(self.m) as root:
                self.assertEqual(self.m.profile_sha256(), sha256(self.m.MANIFEST.read_bytes()).hexdigest())
                target = root / name
                target.write_bytes(target.read_bytes() + b"\n")
                with self.assertRaises(ValueError):
                    self.m.profile_sha256()
        for case in ("missing", "wrong"):
            with self.subTest(identifier_policy=case), _temporary_profile_tree(self.m):
                invalid = json.loads(self.m.MANIFEST.read_bytes())
                if case == "missing":
                    invalid.pop("table_identifier_policy", None)
                else:
                    invalid["table_identifier_policy"] = "UNSUPPORTED_IDENTIFIER_POLICY"
                self.m.MANIFEST.write_bytes(json.dumps(invalid, sort_keys=True).encode("ascii"))
                with self.assertRaises(ValueError):
                    self.m.profile_sha256()

    def test_validly_resealed_inherited_profile_cannot_keep_the_combined_identity(self):
        before = self.m.profile_sha256()
        inherited = self.m.prior._profile()
        with _temporary_profile_tree(self.m, inherited=True) as root:
            profile = self.m.prior._PROFILE_FILE
            source = root / "reporting/pdf_document_metadata.py"
            changed = source.read_bytes() + b"\n# temporary dependency change\n"
            source.write_bytes(changed)
            manifest = json.loads(profile.read_bytes())
            manifest["source_sha256"]["reporting/pdf_document_metadata.py"] = sha256(changed).hexdigest()
            profile.write_bytes(json.dumps(manifest).encode("ascii"))
            self.assertNotEqual(self.m.prior._profile(), inherited)
            with self.assertRaises(ValueError):
                self.m._admit(before)

    def test_native_logo_coordinate_precision_is_not_rounded_away(self):
        def changed_coordinate(writer):
            page = writer.pages[0]
            data = page["/Contents"].get_data()
            start = data.index(b"/Figure")
            end = data.index(b"EMC", start)
            block = data[start:end]
            pattern = rb"(?<![0-9.])354\.1(?=\s)"
            self.assertIsNotNone(re.search(pattern, block))
            changed = re.sub(pattern, b"354.100000001", block, count=1)
            self.assertNotEqual(changed, block)
            replacement = DecodedStreamObject()
            replacement.set_data(data[:start] + changed + data[end:])
            page[NameObject("/Contents")] = writer._add_object(replacement)
        self.refuse(self.rewritten(changed_coordinate))

    def test_new_worker_rejects_invalid_descriptor_relationships_before_input(self):
        from reporting import _pdf_typed_original_brand_qa_worker as worker
        for case in ("same", "alias", "named-input", "named-output", "populated-output"):
            with self.subTest(case=case), ExitStack() as stack:
                source = stack.enter_context(tempfile.TemporaryFile())
                output = stack.enter_context(tempfile.TemporaryFile())
                source_fd, output_fd = source.fileno(), output.fileno()
                if case == "same":
                    output_fd = source_fd
                elif case == "alias":
                    output_fd = os.dup(source_fd)
                    stack.callback(os.close, output_fd)
                elif case == "named-input":
                    source_fd = stack.enter_context(tempfile.NamedTemporaryFile()).fileno()
                elif case == "named-output":
                    output_fd = stack.enter_context(tempfile.NamedTemporaryFile()).fileno()
                else:
                    output.write(b"existing")
                    output.flush()
                with patch.object(worker.sys, "flags", SimpleNamespace(isolated=1)), \
                        patch.object(worker.sys, "dont_write_bytecode", True), \
                        patch.object(worker, "_limits") as limits, \
                        patch.object(worker.native, "_read_request") as read, \
                        patch.object(worker, "enforce_pdf_landlock") as landlock, \
                        patch.object(worker, "_write_bytes") as write:
                    code = worker.main(["worker", str(source_fd), str(output_fd), str(os.getpid())])
                    self.assertEqual(code, 70)
                    limits.assert_not_called()
                    read.assert_not_called()
                    landlock.assert_not_called()
                    write.assert_not_called()


    def test_native_cmap_aggregate_budgets_count_shared_font_records(self):
        def shared_fonts(writer):
            resources = writer.pages[0]["/Resources"]["/Font"]
            source = next(iter(resources.values())).get_object()
            for index in range(4):
                name = NameObject("/SharedBudgetFont" + str(index))
                self.assertNotIn(name, resources)
                resources[name] = writer._add_object(DictionaryObject(dict(source)))
        args = self.rewritten(shared_fonts)
        raw = self.m._run_worker(args["pdf_bytes"], args["expected_pdf_sha256"])
        original = self.m.prior._loads(raw.decode("ascii"))
        self.m._validate_native(original, args["pdf_bytes"], args["expected_profile_sha256"])

        def groups(native, key):
            result = {}
            for font in native["trace"]["fonts"]:
                result.setdefault(tuple(font[key]), []).append(font)
            return result

        initial = groups(original, "cmap_reference")
        shared = next(key for key, members in initial.items() if len(members) >= 5)
        single = next(key for key, members in initial.items() if len(members) == 1)
        self.assertLess(len(initial), len(original["trace"]["fonts"]))

        def pad_mapping(members, size):
            mapping = deepcopy(members[0]["mapping"])
            used = {code for code, _ in mapping}
            self.assertTrue(len(mapping) <= size <= 4096)
            for number in range(65536):
                if len(mapping) == size:
                    break
                code = format(number, "04x")
                if code not in used:
                    mapping.append([code, "Z"])
                    used.add(code)
            self.assertEqual(len(mapping), size)
            for font in members:
                font["mapping"] = deepcopy(mapping)

        def cover_widths(native):
            for members in groups(native, "cid_reference").values():
                width_count = max(max(font["explicit_cid_width_count"], len(font["mapping"]))
                                  for font in members)
                self.assertLessEqual(width_count, 4096)
                for font in members:
                    font["explicit_cid_width_count"] = width_count

        def unchanged_replay(native):
            self.assertEqual(native["trace"]["pages"], original["trace"]["pages"])
            self.assertEqual(native["trace"]["nodes"], original["trace"]["nodes"])
            self.assertEqual(native["graphics"], original["graphics"])
            self.m._schema(native, "native")
            self.m.prior._reference_consistency(native["trace"])
            projected, _ = self.m.project_text_trace(native["trace"])
            fonts = {self.m.prior._reference(font["reference"]): font
                     for font in projected["fonts"]}
            for font in fonts.values():
                self.assertEqual(len(dict(font["mapping"])), len(font["mapping"]))
                self.assertLessEqual(len(font["mapping"]), font["explicit_cid_width_count"])
                self.assertTrue(0 < font["cmap_decoded_bytes"] <= self.m.prior.MAX_CMAP_BYTES)
            for page in projected["pages"]:
                self.assertEqual(self.m.prior._replay(page, fonts), page["runs"])

        for budget, limit in (("bytes", self.m.prior.MAX_CMAP_TOTAL),
                              ("records", self.m.prior.MAX_CMAP_RECORDS)):
            with self.subTest(budget=budget):
                boundary = deepcopy(original)
                by_cmap = groups(boundary, "cmap_reference")
                measure = (lambda font: font["cmap_decoded_bytes"]) if budget == "bytes" else (
                    lambda font: len(font["mapping"]))
                other = sum(measure(font) for key, members in by_cmap.items()
                            if key != shared for font in members)
                amount, remainder = divmod(limit - other, len(by_cmap[shared]))
                if budget == "bytes":
                    for font in by_cmap[shared]:
                        font["cmap_decoded_bytes"] = amount
                    by_cmap[single][0]["cmap_decoded_bytes"] += remainder
                else:
                    pad_mapping(by_cmap[shared], amount)
                    pad_mapping(by_cmap[single], measure(by_cmap[single][0]) + remainder)
                    cover_widths(boundary)
                self.assertEqual(sum(measure(font) for font in boundary["trace"]["fonts"]), limit)
                unchanged_replay(boundary)
                self.m._validate_native(boundary, args["pdf_bytes"], args["expected_profile_sha256"])

                bad = deepcopy(boundary)
                by_cmap = groups(bad, "cmap_reference")
                if budget == "bytes":
                    by_cmap[single][0]["cmap_decoded_bytes"] += 1
                else:
                    pad_mapping(by_cmap[single], measure(by_cmap[single][0]) + 1)
                    cover_widths(bad)
                self.assertEqual(sum(measure(font) for font in bad["trace"]["fonts"]), limit + 1)
                # Counting shared objects only once would incorrectly admit this packet.
                self.assertLessEqual(sum(measure(members[0]) for members in by_cmap.values()), limit)
                if budget == "bytes":
                    self.assertLessEqual(sum(len(font["mapping"]) for font in bad["trace"]["fonts"]),
                                         self.m.prior.MAX_CMAP_RECORDS)
                else:
                    self.assertLessEqual(sum(font["cmap_decoded_bytes"]
                                             for font in bad["trace"]["fonts"]),
                                         self.m.prior.MAX_CMAP_TOTAL)
                unchanged_replay(bad)
                with self.assertRaises(ValueError):
                    self.m._validate_native(bad, args["pdf_bytes"], args["expected_profile_sha256"])
                payload = self.m.canonical(bad)
                self.assertLessEqual(len(payload), self.m.prior.RESULT_BYTES)
                with patch.object(self.m, "_run_worker", return_value=payload) as worker, patch.object(
                        self.m, "inspect_pdf_document_metadata") as metadata:
                    self.refuse(args)
                    worker.assert_called_once_with(args["pdf_bytes"], args["expected_pdf_sha256"])
                    metadata.assert_not_called()

    def test_native_font_mapping_requires_widths_and_utf16_units(self):
        args = self.arguments()
        original = self.native_record()
        self.m._validate_native(original, args["pdf_bytes"], args["expected_profile_sha256"])

        def unchanged_replay(native):
            self.assertEqual(native["trace"]["pages"], original["trace"]["pages"])
            self.assertEqual(native["trace"]["nodes"], original["trace"]["nodes"])
            self.assertEqual(native["graphics"], original["graphics"])
            self.m._schema(native, "native")
            self.m.prior._reference_consistency(native["trace"])
            projected, _ = self.m.project_text_trace(native["trace"])
            fonts = {self.m.prior._reference(font["reference"]): font
                     for font in projected["fonts"]}
            self.assertLessEqual(sum(len(font["mapping"]) for font in fonts.values()),
                                 self.m.prior.MAX_CMAP_RECORDS)
            self.assertLessEqual(sum(font["cmap_decoded_bytes"] for font in fonts.values()),
                                 self.m.prior.MAX_CMAP_TOTAL)
            for font in fonts.values():
                self.assertEqual(len(dict(font["mapping"])), len(font["mapping"]))
            for page in projected["pages"]:
                self.assertEqual(self.m.prior._replay(page, fonts), page["runs"])

        def refuse_native(native):
            unchanged_replay(native)
            with self.assertRaises(ValueError):
                self.m._validate_native(native, args["pdf_bytes"], args["expected_profile_sha256"])
            with patch.object(self.m, "_run_worker", return_value=self.m.canonical(native)) as worker, (
                    patch.object(self.m, "inspect_pdf_document_metadata")) as metadata:
                self.refuse(args)
                worker.assert_called_once_with(args["pdf_bytes"], args["expected_pdf_sha256"])
                metadata.assert_not_called()

        largest = max(original["trace"]["fonts"], key=lambda font: len(font["mapping"]))
        cid = largest["cid_reference"]
        width_count = len(largest["mapping"])
        self.assertGreater(width_count, 1)
        boundary = deepcopy(original)
        for font in boundary["trace"]["fonts"]:
            if font["cid_reference"] == cid:
                font["explicit_cid_width_count"] = width_count
        unchanged_replay(boundary)
        self.m._validate_native(boundary, args["pdf_bytes"], args["expected_profile_sha256"])
        bad = deepcopy(boundary)
        for font in bad["trace"]["fonts"]:
            if font["cid_reference"] == cid:
                font["explicit_cid_width_count"] = width_count - 1
        with self.subTest(mapping="width-count-one-below"):
            refuse_native(bad)

        cmap = largest["cmap_reference"]
        known = {code for font in original["trace"]["fonts"] if font["cmap_reference"] == cmap
                 for code, _ in font["mapping"]}
        unused = next(format(number, "04x") for number in range(65536)
                      if format(number, "04x") not in known)
        affected = {tuple(font["reference"]) for font in original["trace"]["fonts"]
                    if font["cmap_reference"] == cmap}
        used = {value[offset:offset + 4] for page in original["trace"]["pages"]
                for run in page["runs"] if tuple(run["font_reference"]) in affected
                for kind, value in run["parts"] if kind == "codes"
                for offset in range(0, len(value), 4)}
        self.assertNotIn(unused, used)

        def unused_mapping(text):
            native = deepcopy(original)
            cid_groups = {}
            for font in native["trace"]["fonts"]:
                if font["cmap_reference"] == cmap:
                    font["mapping"].append([unused, text])
                cid_groups.setdefault(tuple(font["cid_reference"]), []).append(font)
            for members in cid_groups.values():
                width = max(max(font["explicit_cid_width_count"], len(font["mapping"]))
                            for font in members)
                self.assertLessEqual(width, 4096)
                for font in members:
                    font["explicit_cid_width_count"] = width
                    self.assertLessEqual(len(font["mapping"]), width)
            return native

        for text in ("Z", "a" * 16, "\U0001f600" * 8):
            with self.subTest(valid_utf16_units=len(text.encode("utf-16-be")) // 2):
                native = unused_mapping(text)
                unchanged_replay(native)
                self.m._validate_native(native, args["pdf_bytes"], args["expected_profile_sha256"])
        overflow = "\U0001f600" * 8 + "a"
        self.assertEqual(len(overflow.encode("utf-16-be")) // 2, 17)
        for label, text in (("seventeen-utf16-units", overflow), ("unpaired-surrogate", "\ud800")):
            self.assertLessEqual(len(text), 16)
            with self.subTest(invalid_unused_mapping=label):
                refuse_native(unused_mapping(text))

    def test_projected_events_must_stay_inside_native_spans(self):
        pairs, target = {}, {}
        def outside_pairs(writer):
            def alter(operations):
                starts = [index for index, (operands, op) in enumerate(operations)
                          if op == b"BDC" and operands[0] == "/Span"]
                self.assertGreaterEqual(len(starts), 2)
                count = len(operations)
                pairs.update(prefix=0, between=starts[1] + 2, suffix=count + 4)
                for index in (count, starts[1], 0):
                    operations[index:index] = [([], b"q"), ([], b"Q")]
            target["index"] = self.page_with_multiple_spans(writer)
            self.edit_page(writer, target["index"], alter)
        args = self.rewritten(outside_pairs)
        raw = self.m._run_worker(args["pdf_bytes"], args["expected_pdf_sha256"])
        original = self.m.prior._loads(raw.decode("ascii"))
        self.m._validate_native(original, args["pdf_bytes"], args["expected_profile_sha256"])
        original_page = original["trace"]["pages"][target["index"]]
        for first in pairs.values():
            self.assertTrue({first, first + 1}.issubset(original_page["outside_operator_ordinals"]))
        for position, first in pairs.items():
            with self.subTest(projected_outside_pair=position):
                native = deepcopy(original)
                page = native["trace"]["pages"][target["index"]]
                index = sum(ordinal < first for ordinal in page["projected_operator_ordinals"])
                if index:
                    self.assertEqual(page["events"][index - 1]["operator"], "EMC")
                if index < len(page["events"]):
                    self.assertEqual(page["events"][index]["operator"], "BDC")
                page["events"][index:index] = [
                    {"ordinal": 0, "operator": "q", "operands": []},
                    {"ordinal": 0, "operator": "Q", "operands": []}]
                for ordinal, event in enumerate(page["events"]):
                    event["ordinal"] = ordinal
                page["projected_operator_ordinals"][index:index] = [first, first + 1]
                page["outside_operator_ordinals"] = [ordinal for ordinal in page["outside_operator_ordinals"]
                                                    if ordinal not in {first, first + 1}]
                for run in page["runs"]:
                    if run["operator_ordinal"] >= index:
                        run["operator_ordinal"] += 2
                mapped = page["projected_operator_ordinals"]
                self.assertEqual(mapped, sorted(set(mapped)))
                starts = [i for i, event in enumerate(page["events"]) if event["operator"] == "BDC"]
                ends = [i for i, event in enumerate(page["events"]) if event["operator"] == "EMC"]
                self.assertEqual(len(starts), len(ends))
                for begin, end in zip(starts, ends, strict=True):
                    self.assertEqual(mapped[begin:end + 1], list(range(mapped[begin], mapped[end] + 1)))
                covered = set(mapped)
                self.assertFalse(covered.intersection(page["outside_operator_ordinals"]))
                covered.update(page["outside_operator_ordinals"])
                for block in (*page["graphic_blocks"], *page["pagination_blocks"]):
                    interval = set(range(block["first_operator"], block["last_operator"] + 1))
                    self.assertFalse(covered.intersection(interval))
                    covered.update(interval)
                self.assertEqual(covered, set(range(page["original_operator_count"])))
                self.assertEqual(native["trace"]["nodes"], original["trace"]["nodes"])
                self.assertEqual(native["trace"]["fonts"], original["trace"]["fonts"])
                self.assertEqual(native["graphics"], original["graphics"])
                self.assertEqual(page["graphic_blocks"], original_page["graphic_blocks"])
                self.assertEqual(page["mcid_owners"], original_page["mcid_owners"])
                for observed, source in zip(page["runs"], original_page["runs"], strict=True):
                    self.assertEqual({key: value for key, value in observed.items() if key != "operator_ordinal"},
                                     {key: value for key, value in source.items() if key != "operator_ordinal"})
                self.m._schema(native, "native")
                self.m.prior._reference_consistency(native["trace"])
                projected, _ = self.m.project_text_trace(native["trace"])
                fonts = {self.m.prior._reference(font["reference"]): font for font in projected["fonts"]}
                for projected_page in projected["pages"]:
                    self.assertEqual(self.m.prior._replay(projected_page, fonts), projected_page["runs"])
                with self.assertRaises(ValueError):
                    self.m._validate_native(native, args["pdf_bytes"], args["expected_profile_sha256"])
                with patch.object(self.m, "_run_worker", return_value=self.m.canonical(native)) as worker, (
                        patch.object(self.m, "inspect_pdf_document_metadata")) as metadata:
                    self.refuse(args)
                    worker.assert_called_once_with(args["pdf_bytes"], args["expected_pdf_sha256"])
                    metadata.assert_not_called()

    def test_native_graphics_states_require_bounded_opaque_inventory(self):
        from jsonschema.exceptions import ValidationError

        args = self.arguments()
        original = self.native_record()
        self.m._validate_native(original, args["pdf_bytes"], args["expected_profile_sha256"])
        states = [
            {"name": "/InventoryState0", "fill_alpha": "1.0", "stroke_alpha": None},
            {"name": "/InventoryState1", "fill_alpha": None, "stroke_alpha": "1.000"},
            {"name": "/InventoryState2", "fill_alpha": "1", "stroke_alpha": None},
            {"name": "/InventoryState3", "fill_alpha": None, "stroke_alpha": "1"}]

        def inventory(count):
            native = deepcopy(original)
            page = native["trace"]["pages"][0]
            page["graphics_states"] = deepcopy(states[:count])
            for event in page["events"]:
                if event["operator"] == "gs":
                    event["operands"] = [states[0]["name"]]
            for block in page["pagination_blocks"]:
                for event in block["events"]:
                    if event["operator"] == "gs":
                        event["operands"] = [states[0]["name"]]
                block["sha256"] = sha256(self.m.canonical(block["events"])).hexdigest()
            return native

        def unchanged_replay(native):
            self.m.prior._reference_consistency(native["trace"])
            projected, _ = self.m.project_text_trace(native["trace"])
            fonts = {self.m.prior._reference(font["reference"]): font for font in projected["fonts"]}
            for page, before in zip(projected["pages"], original["trace"]["pages"], strict=True):
                self.assertEqual(page["runs"], before["runs"])
                self.assertEqual(self.m.prior._replay(page, fonts), page["runs"])
                self.assertEqual(page["projected_operator_ordinals"], before["projected_operator_ordinals"])
                self.assertEqual(page["outside_operator_ordinals"], before["outside_operator_ordinals"])
                self.assertEqual(page["graphic_blocks"], before["graphic_blocks"])
            self.assertEqual(native["trace"]["nodes"], original["trace"]["nodes"])
            self.assertEqual(native["trace"]["fonts"], original["trace"]["fonts"])
            self.assertEqual(native["graphics"], original["graphics"])

        def public_refusal(native):
            with patch.object(self.m, "_run_worker", return_value=self.m.canonical(native)) as worker, (
                    patch.object(self.m, "inspect_pdf_document_metadata")) as metadata:
                self.refuse(args)
                worker.assert_called_once_with(args["pdf_bytes"], args["expected_pdf_sha256"])
                metadata.assert_not_called()

        for count in (1, 3):
            with self.subTest(valid_inventory=count):
                native = inventory(count)
                self.m._schema(native, "native")
                unchanged_replay(native)
                self.m._validate_native(native, args["pdf_bytes"], args["expected_profile_sha256"])
        for count, validator in ((0, "minItems"), (4, "maxItems")):
            with self.subTest(invalid_inventory=count):
                native = inventory(count)
                with self.assertRaises(ValidationError) as caught:
                    self.m._schema(native, "native")
                self.assertEqual(caught.exception.validator, validator)
                self.assertEqual(list(caught.exception.absolute_path),
                                 ["trace", "pages", 0, "graphics_states"])
                with self.assertRaises(ValidationError):
                    self.m._validate_native(native, args["pdf_bytes"], args["expected_profile_sha256"])
                public_refusal(native)
        for label, fill, stroke in (("fractional-fill", "0.5", None),
                                    ("fractional-stroke", None, ".5"),
                                    ("both-alphas-present", "1", "1")):
            with self.subTest(invalid_unused_state=label):
                native = inventory(3)
                unused = native["trace"]["pages"][0]["graphics_states"][2]
                self.assertFalse(any(event["operator"] == "gs" and event["operands"] == [unused["name"]]
                                     for event in native["trace"]["pages"][0]["events"]))
                unused["fill_alpha"], unused["stroke_alpha"] = fill, stroke
                self.m._schema(native, "native")
                unchanged_replay(native)
                with self.assertRaises(ValueError):
                    self.m._validate_native(native, args["pdf_bytes"], args["expected_profile_sha256"])
                public_refusal(native)


if __name__ == "__main__":
    unittest.main()
