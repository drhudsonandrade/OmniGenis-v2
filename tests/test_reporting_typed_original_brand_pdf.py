"""Opt-in original OmniGenis branding over an admitted typed editorial PDF."""
from __future__ import annotations

from hashlib import sha256
from io import BytesIO
import importlib
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from pypdf import PdfReader

from reporting.brand_assets import BoundBrandAssets, REQUIRED_CREDIT_EN
from reporting.components import (TextComponent, FindingsTable, FindingRow,
                                  TableColumn, build_typed_report_projection,
                                  component_content_sha256)
from test_reporting_typed_projection import context
from reporting.editorial_typed_pdf import prepare_editorial_typed_html
from reporting.pdf_raster_resources import RasterAsset
from test_reporting_typed_pdf_source import document, digest


ROOT = Path(__file__).resolve().parents[1]
ASSET_ROOT = ROOT / "reporting" / "assets"


class TypedOriginalBrandPdfTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = {
            "logo_svg": (ASSET_ROOT / "omnigenis_logo.svg").read_bytes(),
            "dna_png": (ASSET_ROOT / "dna_column.png").read_bytes(),
            "permission_notice": (ASSET_ROOT / "brand-permission.md").read_bytes(),
        }
        cls.assets = BoundBrandAssets(**cls.sources)
        cls.bundle_sha = cls.assets.to_dict()["bundle_sha256"]

    def setUp(self):
        self.m = importlib.import_module("reporting.typed_original_brand_pdf")
        self.source = document(2)
        self.expected_ir_sha = digest(self.source)
        self.mode = patch.dict(os.environ, {
            "OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE": "qualification-only",
            "OMNIGENIS_TYPED_ORIGINAL_BRAND_PDF_DISABLED": "",
            "OMNIGENIS_TYPED_BRAND_RENDER_DISABLED": "",
            "OMNIGENIS_TYPED_EDITORIAL_PDF_DISABLED": "",
            "OMNIGENIS_PDF_PRELOADED_RASTER_DISABLED": "",
            "OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED": "",
            "OMNIGENIS_PDF_RENDERER_DISABLED": "",
        })
        self.mode.start()
        self.addCleanup(self.mode.stop)

    def arguments(self):
        return {
            "presentation_ir": self.source,
            "expected_ir_sha256": self.expected_ir_sha,
            "assets": self.assets,
            "expected_brand_bundle_sha256": self.bundle_sha,
        }

    def _editorial_native_fixture(self):
        """Observe the actual unchanged producer bytes with the existing native worker."""
        import json
        from reporting import typed_original_brand_qa as qa
        candidate, _ = self.m.render_typed_original_brand_pdf(**self.arguments())
        observation = json.loads(qa._run_worker(candidate.pdf_bytes, candidate.pdf_sha256))
        return candidate, observation, PdfReader(BytesIO(candidate.pdf_bytes), strict=True)

    def test_editorial_cover_places_the_original_dna_on_the_first_page(self):
        candidate, observation, reader = self._editorial_native_fixture()
        paints = [sum(block["dna_paints"] for block in page["graphic_blocks"])
                  for page in observation["trace"]["pages"]]
        self.assertEqual(paints, [1] + [0] * (candidate.page_count - 1))
        self.assertIn("Technical report", reader.pages[0].extract_text())
        self.assertNotIn("Original decorative OmniGenis DNA illustration",
                         "\n".join(page.extract_text() for page in reader.pages))


    def _source_with_cover_title(self, title, *, heading=True, heading_text="Findings"):
        request, ledger = context(1, "SYNTHETIC-CASE")
        components = (
            TextComponent("title", "identity", "document_title", title),
            *((TextComponent("heading", "findings", "section_heading", heading_text),)
              if heading else ()),
            FindingsTable("table", "findings", "Synthetic findings",
                (TableColumn("variant", "Variant"), TableColumn("value", "Value")),
                (FindingRow(request.plan.expected_finding_ids[0],
                            ("NM_000001.1:c.1A>G", "0.1")),)),
        )
        return build_typed_report_projection(
            request=request, ledger=ledger,
            projection_request_sha256=request.request.request_sha256,
            expected_content_sha256=component_content_sha256(components),
            components=components).to_dict()

    def test_cover_title_overflow_refuses_instead_of_returning_a_clipped_candidate(self):
        titles = ("\n".join(["Explicit cover line"] * 18), "Wrapped cover title " * 60)
        self.assertNotIn("\n", titles[1])
        for title in titles:
            with self.subTest(explicit_lines="\n" in title):
                source = self._source_with_cover_title(title)
                args = self.arguments() | {
                    "presentation_ir": source, "expected_ir_sha256": digest(source)}
                html, _, staged = self.m.prepare_typed_original_brand_pdf(**args)
                self.assertEqual(staged["status"], "STAGED_TYPED_ORIGINAL_BRAND_CANDIDATE")
                self.assertEqual(staged["source_ir_sha256"], args["expected_ir_sha256"])
                self.assertEqual(staged["html_sha256"], sha256(html.encode("utf-8")).hexdigest())
                with self.assertRaisesRegex(
                        self.m.TypedOriginalBrandError, "^typed_original_brand_pdf_unavailable$"):
                    self.m.render_typed_original_brand_pdf(**args)

    def test_section_heading_explicit_breaks_refuse_before_candidate(self):
        labels = ("Findings\nSummary", "Findings\rSummary", "Findings\r\nSummary",
                  "Findings\tSummary", "\n".join(["Explicit navigation line"] * 128))
        for label in labels:
            with self.subTest(label=repr(label)):
                source = self._source_with_cover_title("Technical report", heading_text=label)
                args = self.arguments() | {
                    "presentation_ir": source, "expected_ir_sha256": digest(source)}
                _, generic = prepare_editorial_typed_html(
                    presentation_ir=source, expected_ir_sha256=args["expected_ir_sha256"])
                self.assertEqual(generic["source_ir_sha256"], args["expected_ir_sha256"])
                with patch.object(self.m, "render_typed_brand_pdf") as render:
                    for operation in (self.m.prepare_typed_original_brand_pdf,
                                      self.m.render_typed_original_brand_pdf):
                        with self.assertRaisesRegex(
                                self.m.TypedOriginalBrandError,
                                "^typed_original_brand_pdf_unavailable$"):
                            operation(**args)
                    render.assert_not_called()

    def test_oversized_navigation_entry_stages_but_refuses_render(self):
        label = "Wrapped navigation label " * 512
        self.assertNotIn("\n", label)
        source = self._source_with_cover_title("Technical report", heading_text=label)
        args = self.arguments() | {
            "presentation_ir": source, "expected_ir_sha256": digest(source)}
        html, _, staged = self.m.prepare_typed_original_brand_pdf(**args)
        self.assertEqual(staged["status"], "STAGED_TYPED_ORIGINAL_BRAND_CANDIDATE")
        self.assertEqual(staged["source_ir_sha256"], args["expected_ir_sha256"])
        self.assertEqual(staged["html_sha256"], sha256(html.encode("utf-8")).hexdigest())
        self.assertEqual(staged["navigation_entry_count"], 1)
        self.assertIn('<p data-editorial-nav-target="#heading">' + label + '</p>', html)
        with patch.object(self.m, "render_typed_brand_pdf",
                          wraps=self.m.render_typed_brand_pdf) as render:
            with self.assertRaisesRegex(
                    self.m.TypedOriginalBrandError, "^typed_original_brand_pdf_unavailable$"):
                self.m.render_typed_original_brand_pdf(**args)
            render.assert_called_once()

    def test_heading_free_generic_source_refuses_before_original_brand_render(self):
        source = self._source_with_cover_title("Technical report", heading=False)
        source_sha = digest(source)
        html, _ = prepare_editorial_typed_html(
            presentation_ir=source, expected_ir_sha256=source_sha)
        self.assertNotIn("<h2 ", html)
        with patch.object(self.m, "render_typed_brand_pdf") as render:
            with self.assertRaisesRegex(
                    self.m.TypedOriginalBrandError, "^typed_original_brand_pdf_unavailable$"):
                self.m.render_typed_original_brand_pdf(**(self.arguments() | {
                    "presentation_ir": source, "expected_ir_sha256": source_sha}))
            render.assert_not_called()

    def test_editorial_folios_bind_the_report_identity_and_every_physical_page(self):
        candidate, _ = self.m.render_typed_original_brand_pdf(**self.arguments())
        reader = PdfReader(BytesIO(candidate.pdf_bytes), strict=True)
        self.assertIn("/PageLabels", reader.root_object)
        self.assertEqual(reader.page_labels, [str(i) for i in range(1, len(reader.pages) + 1)])
        for number, page in enumerate(reader.pages, 1):
            folios = [line.strip() for line in page.extract_text().splitlines()
                      if line.strip().startswith("OmniGenis | ")]
            self.assertEqual(folios, ["OmniGenis | " + self.expected_ir_sha[:12] + " | " + str(number)])

    def test_editorial_navigation_matches_the_final_heading_page_without_annotations(self):
        _, observation, reader = self._editorial_native_fixture()
        trace = observation["trace"]
        nodes = {tuple(node["reference"]): node for node in trace["nodes"]}
        pages = {tuple(page["reference"]): page for page in trace["pages"]}

        def literal(node):
            parts = []
            for child in node["children"]:
                if child["kind"] == "node":
                    parts.append(literal(nodes[tuple(child["reference"])]))
                else:
                    page = pages[tuple(node["page_reference"])]
                    parts.extend(run["text"] for run in page["runs"]
                                 if run["mcid"] == child["value"])
            return "".join(parts)

        headings = [node for node in nodes.values()
                    if node["role"] == "/H2" and literal(node) == "Declared findings"]
        self.assertEqual(len(headings), 1)
        number = pages[tuple(headings[0]["page_reference"] )]["index"] + 1
        entries = [line.strip() for page in reader.pages for line in page.extract_text().splitlines()
                   if line.strip().startswith("Declared findings | ")]
        self.assertEqual(entries, ["Declared findings | " + str(number)])
        self.assertTrue(all("/Annots" not in page for page in reader.pages))

    def test_exact_original_asset_bytes_and_one_credit_are_in_prepared_markup(self):
        typed_html, typed_record = prepare_editorial_typed_html(
            presentation_ir=self.source, expected_ir_sha256=self.expected_ir_sha)
        html, resources, record = self.m.prepare_typed_original_brand_pdf(
            **self.arguments())
        self.assertEqual(record["typed_editorial_html_sha256"],
                         typed_record["html_sha256"])
        self.assertEqual(html.count(self.sources["logo_svg"].decode("utf-8")), 1)
        self.assertEqual(html.count(REQUIRED_CREDIT_EN), 1)
        self.assertEqual(html.count(resources.assets[0].uri), 1)
        self.assertIn('data-brand="original-logo"', html)
        self.assertIn("Technical report", html)
        self.assertIn("All declared synthetic findings", html)
        self.assertIn('scope="col"', html)
        self.assertEqual(record["logo_original_sha256"],
                         sha256(self.sources["logo_svg"]).hexdigest())
        self.assertEqual(record["dna_original_sha256"],
                         sha256(self.sources["dna_png"]).hexdigest())
        self.assertEqual(record["html_sha256"], sha256(html.encode()).hexdigest())
        self.assertEqual(record["brand_bundle_sha256"], self.bundle_sha)
        self.assertEqual(resources.assets[0].png_bytes, self.sources["dna_png"])
        self.assertIs(type(resources.assets[0]), RasterAsset)
        self.assertEqual(typed_html.count("<table"), html.count("<table"))
        for flag in ("release_authorized", "default_pipeline_activated",
                     "visual_equivalence_verified", "human_accessibility_verified",
                     "whole_job_resources_qualified", "pdf_ua_certified"):
            self.assertIs(record[flag], False)

    def test_navigation_reuses_exact_source_anchors_without_activating_links(self):
        html, _, record = self.m.prepare_typed_original_brand_pdf(**self.arguments())
        headings = [c for c in self.source["components"]
                    if c["component_type"] == "section_heading"]
        self.assertEqual(record["navigation_entry_count"], len(headings))
        for heading in headings:
            self.assertIn('data-editorial-nav-target="#' + heading["component_id"] + '"', html)
        self.assertNotIn("<a ", html)
        self.assertIn('target-counter(attr(data-editorial-nav-target),page)', html)
        self.assertIn('data-editorial-ir-sha256="' + self.expected_ir_sha + '"', html)

    def test_navigation_labels_remain_inert_escaped_source_text(self):
        request, ledger = context(1, "SYNTHETIC-CASE")
        label = 'Findings <section> & "label"'
        components = (
            TextComponent("title", "identity", "document_title", "Technical report"),
            TextComponent("heading", "findings", "section_heading", label),
            FindingsTable("table", "findings", "Synthetic findings",
                (TableColumn("variant", "Variant"), TableColumn("value", "Value")),
                (FindingRow(request.plan.expected_finding_ids[0],
                            ("NM_000001.1:c.1A>G", "0.1")),)),
        )
        source = build_typed_report_projection(
            request=request, ledger=ledger,
            projection_request_sha256=request.request.request_sha256,
            expected_content_sha256=component_content_sha256(components),
            components=components).to_dict()
        html, _, _ = self.m.prepare_typed_original_brand_pdf(**(self.arguments() | {
            "presentation_ir": source, "expected_ir_sha256": digest(source)}))
        self.assertIn('Findings &lt;section&gt; &amp; &quot;label&quot;</p>', html)
        self.assertNotIn(label, html)

    def test_ambiguous_source_section_heading_refuses_before_render(self):
        request, ledger = context(1, "SYNTHETIC-CASE")
        components = (
            TextComponent("title", "identity", "document_title", "Technical report"),
            TextComponent("heading-first", "findings", "section_heading", "First"),
            TextComponent("heading-second", "findings", "section_heading", "Second"),
            FindingsTable("table", "findings", "Synthetic findings",
                (TableColumn("variant", "Variant"), TableColumn("value", "Value")),
                (FindingRow(request.plan.expected_finding_ids[0],
                            ("NM_000001.1:c.1A>G", "0.1")),)),
        )
        source = build_typed_report_projection(
            request=request, ledger=ledger,
            projection_request_sha256=request.request.request_sha256,
            expected_content_sha256=component_content_sha256(components),
            components=components).to_dict()
        with patch.object(self.m, "render_typed_brand_pdf") as render:
            with self.assertRaises(self.m.TypedOriginalBrandError):
                self.m.render_typed_original_brand_pdf(**(self.arguments() | {
                    "presentation_ir": source, "expected_ir_sha256": digest(source)}))
            render.assert_not_called()

    def test_originals_and_semantics_survive_single_typed_brand_render(self):
        pdf, record = self.m.render_typed_original_brand_pdf(**self.arguments())
        self.assertTrue(pdf.pdf_bytes.startswith(b"%PDF-1.7"))
        self.assertEqual(record["render_profile_id"], "typed-original-brand-render-v1")
        self.assertEqual(pdf.to_dict()["profile_id"], record["render_profile_id"])
        self.assertEqual(pdf.to_dict()["profile_sha256"], record["render_profile_sha256"])
        self.assertEqual(sha256(pdf.pdf_bytes).hexdigest(), pdf.pdf_sha256)
        self.assertEqual(record["pdf_sha256"], pdf.pdf_sha256)
        self.assertGreater(pdf.page_count, 0)
        self.assertLessEqual(pdf.page_count, 64)
        reader = PdfReader(BytesIO(pdf.pdf_bytes), strict=True)
        self.assertEqual(len(reader.pages), pdf.page_count)
        text = "\n".join(page.extract_text() or "" for page in reader.pages)
        for literal in ("Technical report", "Declared findings",
                        "All declared synthetic findings", "Variant", "Value",
                        "NM_000001.1:c.1A>G", "NM_000001.1:c.2A>G"):
            self.assertIn(literal, text)
        self.assertEqual(text.count(REQUIRED_CREDIT_EN), 1)
        self.assertFalse(record["release_authorized"])
        self.assertFalse(record["human_accessibility_verified"])

    def test_disable_retained_during_source_postflight_withholds_candidate(self):
        from reporting import _pdf_typed_brand_emission as emission
        from reporting.pdf_typed_brand_render import TypedBrandPdfCandidate
        prepare = self.m.prepare_typed_original_brand_pdf
        calls = []
        def preparation(**kwargs):
            value = prepare(**kwargs)
            calls.append(True)
            if len(calls) == 2:
                os.environ["OMNIGENIS_TYPED_BRAND_RENDER_DISABLED"] = "1"
            return value
        def sealed(**kwargs):
            return TypedBrandPdfCandidate(b"%PDF-1.7 synthetic boundary fixture",
                kwargs["expected_html_sha256"], kwargs["expected_resources_sha256"],
                1, 1, emission.profile_sha256())
        with (patch.object(self.m, "prepare_typed_original_brand_pdf", side_effect=preparation),
              patch.object(self.m, "render_typed_brand_pdf", side_effect=sealed),
              self.assertRaises(self.m.TypedOriginalBrandError)):
            self.m.render_typed_original_brand_pdf(**self.arguments())
        self.assertEqual(len(calls), 2)

    def test_nested_render_refuses_before_preparation_and_poisons_next_valid_launch(self):
        from reporting._pdf_native_launch_budget import NativeLaunchScope
        from reporting.page_windows import plan_pdf_page_windows
        from test_reporting_pdf_native_launch_budget import launch_one, launch_specs
        sample = b"%PDF-1.7 synthetic"
        plan = plan_pdf_page_windows(pdf_sha256=sha256(sample).hexdigest(), ir_sha256="a"*64,
            page_count=1, admitted_page_budget=1, pages_per_window=16,
            inspector_profile_id="generated-pdf-text-window-v1")
        with (NativeLaunchScope(plan, len(sample)),
              patch.object(self.m, "prepare_typed_original_brand_pdf", wraps=self.m.prepare_typed_original_brand_pdf) as prepare,
              patch.object(self.m, "render_typed_brand_pdf") as render):
            with self.assertRaisesRegex(self.m.TypedOriginalBrandError, "^typed_original_brand_pdf_unavailable$"):
                self.m.render_typed_original_brand_pdf(**(self.arguments() | {"expected_brand_bundle_sha256": None}))
            prepare.assert_not_called()
            render.assert_not_called()
            with self.assertRaises(ValueError):
                launch_one(launch_specs(plan)[0], sample)

    def test_variable_length_content_remains_complete_with_original_assets(self):
        """Brand composition never truncates the source's admitted finding rows."""
        source = document(60)
        pdf, record = self.m.render_typed_original_brand_pdf(
            **(self.arguments() | {"presentation_ir": source,
                                   "expected_ir_sha256": digest(source)}))
        reader = PdfReader(BytesIO(pdf.pdf_bytes), strict=True)
        pages = [page.extract_text() or "" for page in reader.pages]
        text = "\n".join(pages)
        for i in range(1, 61):
            with self.subTest(row=i):
                self.assertEqual(text.count(f"NM_000001.1:c.{i}A>G"), 1)
        for page in pages:
            if "NM_000001.1:c." in page:
                self.assertIn("Variant", page)
                self.assertIn("Value", page)
        self.assertEqual(text.count(REQUIRED_CREDIT_EN), 1)
        self.assertGreater(pdf.page_count, 2)
        self.assertFalse(record["release_authorized"])

    def test_required_credit_is_in_a_labeled_section_on_the_same_page(self):
        """The source permission requires a credits/information section."""
        html, _, _ = self.m.prepare_typed_original_brand_pdf(**self.arguments())
        label = '<section data-brand-credit-section="original"'
        self.assertEqual(html.count(label), 1)
        credit_section = html.split(label, 1)[1].split("</section>", 1)[0]
        self.assertIn("Visual asset credits", credit_section)
        self.assertEqual(credit_section.count(REQUIRED_CREDIT_EN), 1)
        pdf, _ = self.m.render_typed_original_brand_pdf(**self.arguments())
        pages = [page.extract_text() or ""
                 for page in PdfReader(BytesIO(pdf.pdf_bytes), strict=True).pages]
        self.assertTrue(any("Visual asset credits" in page and
                            REQUIRED_CREDIT_EN in page for page in pages))

    def test_raster_uri_in_admitted_plain_text_does_not_become_a_resource(self):
        """A declared literal URI in a paragraph is not a second CSS fetch."""
        dna_sha = sha256(self.sources["dna_png"]).hexdigest()
        source = document(1, paragraph="Synthetic literal: omnigenis-raster:" + dna_sha)
        html, resources, _ = self.m.prepare_typed_original_brand_pdf(
            **(self.arguments() | {"presentation_ir": source,
                                   "expected_ir_sha256": digest(source)}))
        uri = resources.assets[0].uri
        self.assertIn("Synthetic literal: " + uri, html)
        self.assertEqual(html.count("background-image:url('" + uri + "')"), 1)

    def test_wrapped_duplicate_credit_is_refused_before_render(self):
        """Whitespace cannot disguise an existing required legal notice."""
        wrapped = REQUIRED_CREDIT_EN.replace(". Used", ".\nUsed")
        source = document(1, paragraph=wrapped)
        with patch.object(self.m, "render_typed_brand_pdf",
                          side_effect=AssertionError("unexpected render")) as render:
            with self.assertRaises(self.m.TypedOriginalBrandError):
                self.m.render_typed_original_brand_pdf(
                    **(self.arguments() | {"presentation_ir": source,
                                           "expected_ir_sha256": digest(source)}))
            render.assert_not_called()

    def test_credit_split_across_adjacent_paragraphs_refuses_pre_render(self):
        """Two adjacent typed paragraphs cannot hide a duplicate legal notice."""
        request, ledger = context(1, 'SYNTHETIC-CASE')
        first, second = REQUIRED_CREDIT_EN.split('. Used ', 1)
        row_id = request.plan.expected_finding_ids[0]
        parts = (
            TextComponent('title', 'identity', 'document_title', 'Technical report'),
            TextComponent('heading', 'findings', 'section_heading', 'Declared findings'),
            TextComponent('credit-first-half', 'findings', 'paragraph', first + '.'),
            TextComponent('credit-second-half', 'findings', 'paragraph', 'Used ' + second),
            FindingsTable('table', 'findings', 'Synthetic findings',
                (TableColumn('variant', 'Variant'), TableColumn('value', 'Value')),
                (FindingRow(row_id, ('NM_000001.1:c.1A>G', '0.1')),)),
        )
        source = build_typed_report_projection(
            request=request, ledger=ledger,
            projection_request_sha256=request.request.request_sha256,
            expected_content_sha256=component_content_sha256(parts),
            components=parts).to_dict()
        kwargs = self.arguments() | {'presentation_ir': source,
                                     'expected_ir_sha256': digest(source)}
        with patch.object(self.m, 'render_typed_brand_pdf',
                          side_effect=AssertionError('unexpected render')) as renderer:
            with self.assertRaises(self.m.TypedOriginalBrandError):
                self.m.prepare_typed_original_brand_pdf(**kwargs)
            with self.assertRaises(self.m.TypedOriginalBrandError):
                self.m.render_typed_original_brand_pdf(**kwargs)
            renderer.assert_not_called()

        # The same notice halves are not adjacent source text when separated by
        # a paragraph. Generated contents rows retain their visible page suffix
        # boundary, so copying the labels must not manufacture a second notice.
        separated = (
            parts[0],
            TextComponent('first-label', 'identity', 'section_heading', first + '.'),
            TextComponent('label-separator', 'identity', 'paragraph', 'Synthetic context.'),
            TextComponent('second-label', 'findings', 'section_heading', 'Used ' + second),
            parts[-1],
        )
        source = build_typed_report_projection(
            request=request, ledger=ledger,
            projection_request_sha256=request.request.request_sha256,
            expected_content_sha256=component_content_sha256(separated),
            components=separated).to_dict()
        args = self.arguments() | {'presentation_ir': source,
                                  'expected_ir_sha256': digest(source)}
        source_html, _ = prepare_editorial_typed_html(
            presentation_ir=source, expected_ir_sha256=args['expected_ir_sha256'])
        self.assertEqual(self.m._credit_count(source_html), 0)
        html, _, staged = self.m.prepare_typed_original_brand_pdf(**args)
        self.assertEqual(staged['status'], 'STAGED_TYPED_ORIGINAL_BRAND_CANDIDATE')
        self.assertEqual(staged['navigation_entry_count'], 2)
        self.assertEqual(staged['original_credit_count'], 1)
        self.assertEqual(self.m._credit_count(html), 1)

    def test_soft_hyphen_hidden_duplicate_credit_refuses_before_render(self):
        """An invisible U+00AD cannot conceal a duplicate owner's notice."""
        paragraph = REQUIRED_CREDIT_EN.replace("Logo", "Lo\u00adgo", 1)
        source = document(1, paragraph=paragraph)
        kwargs = self.arguments() | {
            "presentation_ir": source,
            "expected_ir_sha256": digest(source),
        }
        with patch.object(self.m, "render_typed_brand_pdf",
                          side_effect=AssertionError("unexpected render")) as render:
            with self.assertRaises(self.m.TypedOriginalBrandError):
                self.m.prepare_typed_original_brand_pdf(**kwargs)
            with self.assertRaises(self.m.TypedOriginalBrandError):
                self.m.render_typed_original_brand_pdf(**kwargs)
            render.assert_not_called()

    def test_carriage_return_encoded_duplicate_credit_is_refused(self):
        """An HTML-encoded carriage return cannot hide a second notice."""
        wrapped = REQUIRED_CREDIT_EN.replace(". Used", ".\rUsed")
        source = document(1, paragraph=wrapped)
        with patch.object(self.m, "render_typed_brand_pdf",
                          side_effect=AssertionError("unexpected render")) as render:
            with self.assertRaises(self.m.TypedOriginalBrandError):
                self.m.render_typed_original_brand_pdf(
                    **(self.arguments() | {"presentation_ir": source,
                                           "expected_ir_sha256": digest(source)}))
            render.assert_not_called()

    def test_positive_fixture_is_independent_of_inherited_disable_flags(self):
        """setUp explicitly supplies the opt-in test environment."""
        flags = (
            "OMNIGENIS_TYPED_ORIGINAL_BRAND_PDF_DISABLED",
            "OMNIGENIS_TYPED_EDITORIAL_PDF_DISABLED",
            "OMNIGENIS_PDF_PRELOADED_RASTER_DISABLED",
            "OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED",
            "OMNIGENIS_PDF_RENDERER_DISABLED",
        )
        with patch.dict(os.environ, dict.fromkeys(flags, "1")):
            case = type(self)("test_exact_original_asset_bytes_and_one_credit_are_in_prepared_markup")
            case.setUp()
            try:
                html, _, record = case.m.prepare_typed_original_brand_pdf(
                    **case.arguments())
                self.assertIn("Technical report", html)
                self.assertFalse(record["release_authorized"])
            finally:
                case.doCleanups()

    def test_invalid_identity_or_disabled_profile_refuses_before_render(self):
        with patch.object(self.m, "render_typed_brand_pdf",
                          side_effect=AssertionError("unexpected rendering")) as render:
            for invalid in ("0" * 64, self.bundle_sha.upper(), None):
                with self.subTest(invalid=invalid):
                    kwargs=self.arguments()
                    kwargs["expected_brand_bundle_sha256"]=invalid
                    with self.assertRaises(self.m.TypedOriginalBrandError):
                        self.m.render_typed_original_brand_pdf(**kwargs)
            kwargs=self.arguments()
            kwargs["expected_ir_sha256"]="0" * 64
            with self.assertRaises(self.m.TypedOriginalBrandError):
                self.m.render_typed_original_brand_pdf(**kwargs)
            with patch.dict(os.environ, {
                    "OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE": ""}):
                with self.assertRaises(self.m.TypedOriginalBrandError):
                    self.m.render_typed_original_brand_pdf(**self.arguments())
            with patch.dict(os.environ, {
                    "OMNIGENIS_TYPED_ORIGINAL_BRAND_PDF_DISABLED": "1"}):
                with self.assertRaises(self.m.TypedOriginalBrandError):
                    self.m.render_typed_original_brand_pdf(**self.arguments())
            render.assert_not_called()

    def test_tampered_originals_and_mutated_result_do_not_gain_authority(self):
        original=self.sources["dna_png"]
        altered=BoundBrandAssets.__new__(BoundBrandAssets)
        for name,data in self.sources.items():
            object.__setattr__(altered,name,
                               data[:-1] + bytes([data[-1]^1]) if name=="dna_png" else data)
        with self.assertRaises(self.m.TypedOriginalBrandError):
            self.m.prepare_typed_original_brand_pdf(
                **(self.arguments() | {"assets":altered}))
        _, _, first=self.m.prepare_typed_original_brand_pdf(**self.arguments())
        first["release_authorized"]=True
        _, _, second=self.m.prepare_typed_original_brand_pdf(**self.arguments())
        self.assertFalse(second["release_authorized"])
        self.assertEqual(self.sources["dna_png"],original)


    def test_native_activation_during_final_policy_audit_withholds_real_candidate(self):
        from contextlib import ExitStack
        from reporting._pdf_native_launch_budget import NativeLaunchScope
        from reporting.page_windows import plan_pdf_page_windows
        # Keep a real untouched producer candidate; this check grants no final QA.
        candidate, _ = self.m.render_typed_original_brand_pdf(**self.arguments())
        plan = plan_pdf_page_windows(pdf_sha256=candidate.pdf_sha256, ir_sha256=self.expected_ir_sha,
            page_count=candidate.page_count, admitted_page_budget=candidate.page_count,
            pages_per_window=16, inspector_profile_id="generated-pdf-text-window-v1")
        scope = NativeLaunchScope(plan, len(candidate.pdf_bytes))
        audited = []
        audit = self.m.require_render_policy
        with ExitStack() as stack:
            def activate_during_audit():
                result = audit()
                stack.enter_context(scope)
                audited.append(True)
                return result
            stack.enter_context(patch.object(self.m, "render_typed_brand_pdf", return_value=candidate))
            stack.enter_context(patch.object(self.m, "require_render_policy", side_effect=activate_during_audit))
            with self.assertRaisesRegex(self.m.TypedOriginalBrandError, "^typed_original_brand_pdf_unavailable$"):
                self.m.render_typed_original_brand_pdf(**self.arguments())
            self.assertEqual(audited, [True])
            self.assertTrue(scope._invalid)


if __name__=="__main__":
    unittest.main()
