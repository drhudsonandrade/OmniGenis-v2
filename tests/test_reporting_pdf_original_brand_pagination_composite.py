"""Opt-in original brand and pagination composite; no V1 or release effects."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from unittest.mock import patch
import os
import unittest

from pypdf import PdfReader, PdfWriter
from pypdf.generic import (
    ArrayObject, ContentStream, DecodedStreamObject, DictionaryObject,
    NameObject, TextStringObject,
)

from reporting.brand_assets import BoundBrandAssets, REQUIRED_CREDIT_EN
from reporting import pdf_original_brand_pagination_composite as composite
from reporting.pdf_original_brand_pagination_composite import (
    CompositeCandidateError, render_original_brand_paginated_candidate,
    observe_original_brand_paginated_candidate,
    inspect_original_brand_paginated_raster_geometry,
)
from tests.test_reporting_pdf_bound_candidate import bound_request, source

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "reporting/assets"
QUALIFICATION = "OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE"
DISABLE = "OMNIGENIS_PDF_ORIGINAL_BRAND_PAGINATION_DISABLED"


def long_bound_request():
    """Use owned synthetic test data; do not retain any identifiable genome."""
    document, _ = source()
    template = document["canonical_payload"]["items"][0]
    entries = []
    for index in range(96):
        row = deepcopy(template)
        row["canonical_variant_id"] = "omnigenis:small-variant:v1:sha256:" + sha256(
            f"owned-synthetic-brand-pagination-{index}".encode()).hexdigest()
        entries.append(row)
    document["canonical_payload"]["items"] = entries
    document["canonical_payload"]["interpretation_item_count"] = len(entries)
    document["raw_artifact_refs"] = [entry["evidence_sha256"] for entry in entries]
    document["limitations"].append("Synthetic reporting QA only; no clinical use.")
    request = bound_request(document, finding_ids=tuple(row["canonical_variant_id"] for row in entries))
    return request, document


class BrandPaginationCompositeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.originals = {
            "logo_svg": (ASSETS / "omnigenis_logo.svg").read_bytes(),
            "dna_png": (ASSETS / "dna_column.png").read_bytes(),
            "permission_notice": (ASSETS / "brand-permission.md").read_bytes(),
        }
        cls.assets = BoundBrandAssets(**cls.originals)
        cls.bundle_sha = cls.assets.to_dict()["bundle_sha256"]

    def render(self, request=None, **overrides):
        if request is None:
            request = bound_request()
        values = dict(bound_request=request, assets=self.assets,
                      expected_brand_bundle_sha256=self.bundle_sha)
        values.update(overrides)
        with patch.dict(os.environ, {QUALIFICATION: "qualification-only"}):
            return render_original_brand_paginated_candidate(**values)

    def test_small_source_renders_original_artwork_and_every_page_folio(self):
        candidate = self.render()
        meta = candidate.summary()
        self.assertEqual(meta["status"], "OPT_IN_BRAND_PAGINATION_CANDIDATE")
        self.assertIs(meta["release_authorized"], False)
        self.assertEqual(meta["original_logo_sha256"], sha256(self.originals["logo_svg"]).hexdigest())
        self.assertEqual(meta["original_dna_sha256"], sha256(self.originals["dna_png"]).hexdigest())
        self.assertEqual(meta["brand_bundle_sha256"], self.bundle_sha)
        reader = PdfReader(BytesIO(candidate.pdf_bytes), strict=True)
        self.assertEqual(reader.page_labels, [str(i) for i in range(1, len(reader.pages) + 1)])
        self.assertIn("/PageLabels", reader.root_object)
        text = " ".join(" ".join(page.extract_text() for page in reader.pages).split())
        self.assertEqual(text.count(REQUIRED_CREDIT_EN), 1)
        self.assertGreaterEqual(sum(len(page.images) for page in reader.pages), 1)
        with patch.dict(os.environ, {QUALIFICATION: "qualification-only"}):
            observation = observe_original_brand_paginated_candidate(candidate)
        self.assertEqual(observation["status"], "OBSERVED_BRAND_PAGINATION_COMPOSITE")
        self.assertEqual(observation["pdf_sha256"], candidate.pdf_sha256)
        self.assertEqual(observation["figure_layout_count"], 1)
        self.assertIs(observation["source_text_equivalence_verified"], True)
        self.assertIs(observation["all_page_visual_raster_verified"], False)
        self.assertEqual(observation["literal_artifact_numbers"], reader.page_labels)
        for denied in ("release_authorized", "human_assistive_accessibility_verified",
                       "source_asset_bytes_authenticated_from_pdf"):
            self.assertIs(observation[denied], False)

    def test_96_synthetic_rows_qualified_without_32_page_legacy_truncation(self):
        request, _ = long_bound_request()
        candidate = self.render(request=request)
        self.assertGreater(candidate.page_count, 32)
        self.assertLessEqual(candidate.page_count, 64)
        with patch.dict(os.environ, {QUALIFICATION: "qualification-only"}):
            observation = observe_original_brand_paginated_candidate(candidate)
        self.assertEqual(len(observation["literal_artifact_numbers"]), candidate.page_count)
        self.assertIs(observation["source_text_equivalence_verified"], True)
        self.assertEqual(observation["pdf_sha256"], candidate.pdf_sha256)
        with patch.dict(os.environ, {QUALIFICATION: "qualification-only"}):
            raster = inspect_original_brand_paginated_raster_geometry(candidate)
        self.assertEqual(raster["status"], "ALL_PAGE_RASTER_GEOMETRY_OBSERVED_ONLY")
        self.assertEqual(raster["inspected_pages"], candidate.page_count)
        self.assertTrue(raster["all_page_raster_geometry_covered"])
        self.assertEqual(raster["windows"][0]["first_page"], 1)
        self.assertEqual(raster["windows"][-1]["last_page"], candidate.page_count)
        self.assertFalse(raster["semantic_visual_equivalence_verified"])
        self.assertFalse(raster["aggregate_job_resources_qualified"])

    def test_reused_page_parse_preserves_text_and_restores_exact_content(self):
        from reporting import _pdf_original_brand_pagination_observer_worker as worker
        from reporting._pdf_content_worker import normalize_stream

        candidate = self.render()
        reader = PdfReader(BytesIO(candidate.pdf_bytes), strict=True)
        for number, page in enumerate(reader.pages, start=1):
            with self.subTest(page=number):
                original = page.raw_get("/Contents")
                expected_text = normalize_stream(page.extract_text())
                parsed = ContentStream(page.get_contents(), reader, forced_encoding="bytes")
                expected_count = len(parsed.operations)
                serialized = ContentStream(None, reader, forced_encoding="bytes")
                serialized.operations = deepcopy(parsed.operations)
                serialized_data = serialized.get_data()
                page_payloads = {page.get_contents().get_data(), serialized_data}
                # A second page parse may see pypdf's serialization of the same
                # operators. Neither top-level payload may identify a Form parse.
                for ref in page["/Resources"].get("/XObject", {}).values():
                    form = ref.get_object()
                    if form.get("/Subtype") == "/Form":
                        self.assertNotIn(form.get_data(), page_payloads)
                parses = []
                original_parse = ContentStream._parse_content_stream

                def count_page_parse(content, data, *, payloads=page_payloads,
                                     observed=parses, parse=original_parse):
                    if data.getvalue() in payloads:
                        observed.append(content)
                    return parse(content, data)

                with patch.object(ContentStream, "_parse_content_stream", new=count_page_parse):
                    found, count, decorated, text = worker._page_observation(
                        page, reader, str(number))
                self.assertEqual(len(parses), 1)
                self.assertEqual(found, str(number))
                self.assertEqual(count, expected_count)
                self.assertIn(decorated, (0, 1))
                self.assertEqual(text, expected_text)
                self.assertIs(page.raw_get("/Contents"), original)
                # Demonstrate that a fresh parse of the independently serialized
                # top-level operators is observable as a second page parse.
                replay = ContentStream(None, reader, forced_encoding="bytes")
                replay.set_data(serialized_data)
                with patch.object(ContentStream, "_parse_content_stream", new=count_page_parse):
                    self.assertEqual(len(replay.operations), expected_count)
                self.assertEqual(len(parses), 2)
                with patch.object(page, "extract_text", side_effect=ValueError("extraction refused")):
                    with self.assertRaisesRegex(ValueError, "extraction refused"):
                        worker._page_observation(page, reader, str(number))
                self.assertIs(page.raw_get("/Contents"), original)

    def test_wrong_asset_identity_and_disable_are_fail_closed(self):
        with self.assertRaises(CompositeCandidateError):
            self.render(expected_brand_bundle_sha256="0" * 64)
        with patch.dict(os.environ, {QUALIFICATION: "qualification-only", DISABLE: "1"}):
            with self.assertRaises(CompositeCandidateError):
                render_original_brand_paginated_candidate(
                    bound_request=bound_request(), assets=self.assets,
                    expected_brand_bundle_sha256=self.bundle_sha)

    def test_source_manifest_and_renderer_disable_are_fail_closed(self):
        with patch.object(composite, "_SOURCE_FILES", ("reporting/unapproved.py",)):
            with self.assertRaises(CompositeCandidateError):
                self.render()
        with patch.dict(os.environ, {
            QUALIFICATION: "qualification-only", "OMNIGENIS_PDF_RENDERER_DISABLED": "1",
        }):
            with self.assertRaises(CompositeCandidateError):
                self.render()

    def test_observer_rejects_resealed_metadata_mismatch_and_pdf_violations(self):
        candidate = self.render()
        with self.assertRaises(CompositeCandidateError):
            replace(candidate, expected_text_sha256="0" * 64)
        with self.assertRaises(CompositeCandidateError):
            replace(candidate, ir_sha256="f" * 64)
        with self.assertRaises(CompositeCandidateError):
            replace(candidate, _source_ir_bytes=b"{}")

        def mutated_pdf(change):
            writer = PdfWriter(clone_from=PdfReader(BytesIO(candidate.pdf_bytes), strict=True))
            writer.pdf_header = "%PDF-1.7"
            change(writer)
            result = BytesIO()
            writer.write(result)
            return replace(candidate, _pdf=result.getvalue())

        def altered_footer(writer):
            page = writer.pages[0]
            stream = ContentStream(page.get_contents(), writer, forced_encoding="bytes")
            found = 0
            for args, op in stream.operations:
                if (op == b"BDC" and len(args) == 2 and args[0] == "/Artifact"
                        and args[1].get("/Subtype") == "/Footer"):
                    args[1][NameObject("/Subtype")] = NameObject("/Header")
                    found += 1
            self.assertEqual(found, 1)
            page[NameObject("/Contents")] = writer._add_object(stream)

        def corrupted_cmap(writer):
            fonts = writer.pages[0]["/Resources"]["/Font"]
            for ref in fonts.values():
                font = ref.get_object()
                if "/ToUnicode" in font:
                    stream = DecodedStreamObject()
                    stream.set_data(b"not a ToUnicode CMap")
                    font[NameObject("/ToUnicode")] = writer._add_object(stream)
                    return
            self.fail("synthetic fixture must contain a ToUnicode CMap")

        attacks = {
            "missing PageLabels": mutated_pdf(lambda w: w._root_object.pop(
                NameObject("/PageLabels"), None)),
            "unapproved page annotations": mutated_pdf(lambda w: w.pages[0].__setitem__(
                NameObject("/Annots"), ArrayObject())),
            "embedded PDF JavaScript": mutated_pdf(lambda w: w._root_object.__setitem__(
                NameObject("/OpenAction"), DictionaryObject({
                    NameObject("/S"): NameObject("/JavaScript"),
                    NameObject("/JS"): TextStringObject("app.alert('blocked')"),
                }))),
            "tampered footer artifact": mutated_pdf(altered_footer),
            "corrupt ToUnicode CMap": mutated_pdf(corrupted_cmap),
            "missing one source page": mutated_pdf(lambda w: w.remove_page(0)),
        }
        with patch.dict(os.environ, {QUALIFICATION: "qualification-only"}):
            for label, attack in attacks.items():
                with self.subTest(label=label), self.assertRaises(CompositeCandidateError):
                    observe_original_brand_paginated_candidate(attack)
            with patch.dict(os.environ, {DISABLE: "1"}):
                with self.assertRaises(CompositeCandidateError):
                    observe_original_brand_paginated_candidate(candidate)
                with self.assertRaises(CompositeCandidateError):
                    inspect_original_brand_paginated_raster_geometry(candidate)


if __name__ == "__main__":
    unittest.main()
