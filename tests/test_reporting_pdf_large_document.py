"""Real complete large-PDF inspection and finite byte/page admission controls."""
from __future__ import annotations

from functools import lru_cache
from hashlib import sha256, shake_256
from io import BytesIO
import json
import time
import unittest
from unittest.mock import patch

from reporting import pdf_native_source_job as native
from reporting.pdf_content import _expected_content
from tests.test_reporting_pdf_source_inspection_job import generated_job_case

MIB = 1024 * 1024
IMAGE_SIDE = 1792
IMAGE_SEED = b"synthetic-complete-pdf-visible-rgb-fixture-v1"


@lru_cache(maxsize=4)
def generated_large_case(pages: int, hostile: str | None = None) -> tuple[dict, bytes]:
    """Paint one real deterministic RGB asset before the sole final serialization."""
    import pydyf
    from weasyprint import HTML

    if type(pages) is not int or pages not in (33, 64):
        raise ValueError("large synthetic fixture page class")
    if hostile not in (None, "last_page_action", "catalog_action"):
        raise ValueError("large synthetic fixture mutation")
    pixels = shake_256(IMAGE_SEED).digest(IMAGE_SIDE * IMAGE_SIDE * 3)

    def finish(document, pdf):
        """Keep the generated text/tags while painting the shared image as an artifact."""
        def resolve(reference):
            """Resolve only an exact generation-zero pydyf object reference."""
            fields = reference.split()
            assert len(fields) == 3 and fields[1:] == [b"0", b"R"]
            obj = pdf.objects[int(fields[0])]
            assert obj.reference == reference
            return obj

        kids = pdf.pages["Kids"]
        assert len(kids) == pages * 3
        assert kids[1::3] == [0] * pages and kids[2::3] == ["R"] * pages
        image = pydyf.Stream([pixels], pydyf.Dictionary({
            "Type": "/XObject", "Subtype": "/Image",
            "Width": IMAGE_SIDE, "Height": IMAGE_SIDE,
            "ColorSpace": "/DeviceRGB", "BitsPerComponent": 8,
        }), compress=True)
        pdf.add_object(image)
        if hostile == "catalog_action":
            pdf.catalog["OpenAction"] = pydyf.Dictionary()
        for index, number in enumerate(kids[::3]):
            page = pdf.objects[number]
            assert page["Type"] == "/Page"
            if hostile == "last_page_action" and index == pages - 1:
                page["AA"] = pydyf.Dictionary()
            resources = resolve(page["Resources"])
            resources["XObject"]["FixturePixels"] = image.reference
            contents = resolve(page["Contents"])
            contents.stream.extend([
                b"/Artifact BMC", b"q", b"48 0 0 48 72 500 cm",
                b"/FixturePixels Do", b"Q", b"EMC",
            ])

    original = HTML.write_pdf

    def with_asset(self, *args, **kwargs):
        """Attach the fixture finisher without changing the product renderer."""
        assert kwargs.get("finisher") is None
        return original(self, *args, **{**kwargs, "finisher": finish})

    with patch.object(HTML, "write_pdf", new=with_asset):
        return generated_job_case(pages)


class PdfLargeDocumentTests(unittest.TestCase):
    """Require a complete real artifact and refuse finite-class violations."""

    def arguments(self, pages: int) -> dict:
        """Bind the public job to independently measured complete fixture bytes."""
        ir, pdf = generated_large_case(pages)
        return dict(
            presentation_ir=json.loads(json.dumps(ir)), pdf_bytes=pdf,
            expected_pdf_sha256=sha256(pdf).hexdigest(),
            expected_ir_sha256=_expected_content(ir)[0], page_count=pages,
            expected_language="en-US", namespace_id="synthetic-large-pdf",
            job_id=f"synthetic-large-{pages}", request_sha256="c" * 64,
            expected_resource_profile_sha256=native.PROFILE_SHA256,
        )

    def test_large_fixture_is_one_complete_painted_document(self):
        """The bytes above eight MiB belong to a reachable image painted on every page."""
        from pypdf import PdfReader
        from pypdf.generic import ContentStream
        ir, pdf = generated_large_case(33)
        self.assertGreater(len(pdf), 8 * MIB)
        self.assertLessEqual(len(pdf), 16 * MIB)
        self.assertEqual(pdf.count(b"startxref"), 1)
        self.assertEqual(pdf.count(b"%%EOF"), 1)
        reader = PdfReader(BytesIO(pdf), strict=True)
        self.assertEqual(len(reader.pages), 33)
        expected = sha256(shake_256(IMAGE_SEED).digest(IMAGE_SIDE * IMAGE_SIDE * 3)).hexdigest()
        references = set()
        for page in reader.pages:
            ref = page["/Resources"]["/XObject"].raw_get("/FixturePixels")
            references.add((ref.idnum, ref.generation))
            image = ref.get_object()
            self.assertEqual((image["/Subtype"], image["/Width"], image["/Height"],
                              image["/ColorSpace"], image["/BitsPerComponent"]),
                             ("/Image", IMAGE_SIDE, IMAGE_SIDE, "/DeviceRGB", 8))
            self.assertEqual(sha256(image.get_data()).hexdigest(), expected)
            operations = ContentStream(page.get_contents(), reader).operations
            paint = [args for args, op in operations if op == b"Do"]
            self.assertEqual(paint, [["/FixturePixels"]])
            self.assertEqual(operations[-6:], [(["/Artifact"], b"BMC"), ([], b"q"),
                ([48, 0, 0, 48, 72, 500], b"cm"), (["/FixturePixels"], b"Do"),
                ([], b"Q"), ([], b"EMC")])
        self.assertEqual(len(references), 1)
        self.assertEqual(len(ir["components"]), 33)

    def test_real_large_native_job_covers_all_pages_and_global_structure(self):
        """One final artifact over both thresholds passes every real native inspection."""
        for pages in (33, 64):
            with self.subTest(pages=pages):
                args = self.arguments(pages)
                started = time.monotonic()
                try:
                    result = native.execute_pdf_native_source_job(**args)
                except native.PdfNativeSourceJobError as error:
                    self.fail(f"LARGE_DOCUMENT_NATIVE_ADMISSION: {error}")
                data = result.to_dict()
                structured = data["structured_inspection"]
                source = structured["source_inspection"]
                inspection = source["inspection_set"]
                bundle = inspection["page_bundle"]
                self.assertEqual(data["pdf_sha256"], args["expected_pdf_sha256"])
                self.assertEqual(data["page_count"], pages)
                self.assertTrue(data["normalized_text_equivalence_verified"])
                self.assertTrue(data["forward_reverse_linkage_verified"])
                self.assertTrue(data["same_font_explicit_width_coverage_verified"])
                self.assertEqual(source["document_content"]["inspected_pages"], pages)
                self.assertEqual(bundle["pdf_sha256"], args["expected_pdf_sha256"])
                for key in ("text_stream", "raster_stream"):
                    self.assertEqual(bundle[key]["represented_pages"], pages)
                self.assertFalse(data["aggregate_job_resources_qualified"])
                self.assertFalse(data["release_authorized"])
                print(json.dumps({"large_fixture_pages": pages,
                    "pdf_bytes": len(args["pdf_bytes"]),
                    "pdf_sha256": args["expected_pdf_sha256"],
                    "inspection_sha256": result.inspection_sha256,
                    "elapsed_seconds": time.monotonic() - started}), flush=True)

    def test_expanded_byte_page_policy_has_two_finite_envelopes(self):
        """The expanded class never admits more than 64 pages or 16 MiB."""
        import importlib
        import importlib.util
        self.assertIsNotNone(importlib.util.find_spec("reporting._pdf_document_byte_budget"),
                             "finite paired PDF byte/page admission is missing")
        budget = importlib.import_module("reporting._pdf_document_byte_budget")
        for size, pages in ((1, 1), (8 * MIB, 512), (8 * MIB + 1, 64), (16 * MIB, 64)):
            with self.subTest(size=size, pages=pages):
                budget.require_pdf_document_budget(size, pages)
        for size, pages in ((0, 1), (8 * MIB + 1, 65), (16 * MIB + 1, 1),
                            (1, 513), (True, 1), (1, True), (MIB, 0)):
            with self.subTest(size=size, pages=pages), self.assertRaises(ValueError):
                budget.require_pdf_document_budget(size, pages)
        profile = budget.document_byte_budget_profile()
        self.assertEqual(profile["legacy"], {"max_pdf_bytes": 8 * MIB, "max_pages": 512})
        self.assertEqual(profile["expanded"], {"max_pdf_bytes": 16 * MIB, "max_pages": 64})
        profile["expanded"]["max_pages"] = 512
        self.assertEqual(budget.document_byte_budget_profile()["expanded"]["max_pages"], 64)

    def test_large_standalone_plans_outside_class_never_launch(self):
        """A larger byte allowance cannot silently widen standalone 512-page support."""
        from reporting import pdf_object_graph, pdf_text_windows, pdf_raster_windows
        from reporting import pdf_document_metadata, pdf_page_tags, pdf_mcid_coverage
        from reporting.page_windows import plan_pdf_page_windows
        _, pdf = generated_large_case(33)
        cases = (
            (pdf_object_graph, "inspect_pdf_object_graph", {}),
            (pdf_document_metadata, "inspect_pdf_document_metadata", {"expected_language": "en-US"}),
            (pdf_page_tags, "inspect_pdf_page_tag_parents", {"expected_language": "en-US"}),
            (pdf_mcid_coverage, "inspect_pdf_mcid_coverage", {"expected_language": "en-US"}),
            (pdf_text_windows, "inspect_pdf_text_window", {"window_index": 0}),
            (pdf_raster_windows, "inspect_pdf_raster_window", {"window_index": 0}),
        )
        for module, name, extra in cases:
            selected = pdf_raster_windows if module is pdf_raster_windows else pdf_text_windows
            plan = plan_pdf_page_windows(pdf_sha256=sha256(pdf).hexdigest(), ir_sha256="b" * 64,
                page_count=65, admitted_page_budget=65, pages_per_window=selected.MAX_WINDOW_PAGES,
                inspector_profile_id=selected.PROFILE_ID)
            with self.subTest(adapter=name), patch.object(module, "_run_worker") as worker:
                with self.assertRaises(ValueError):
                    getattr(module, name)(pdf_bytes=pdf, plan=plan,
                        expected_plan_sha256=plan.plan_sha256, **extra)
                worker.assert_not_called()

    def test_composed_job_refuses_overflow_and_foreign_pins_before_launch(self):
        """Over-budget bytes/pages and foreign artifact/profile expectations never invoke stages."""
        args = self.arguments(33)
        overflow = b"%PDF-1.7" + b"x" * 16777209
        for change in ({"pdf_bytes": overflow, "expected_pdf_sha256": sha256(overflow).hexdigest()},
                       {"page_count": 65}, {"expected_pdf_sha256": "f" * 64},
                       {"expected_resource_profile_sha256": "e184a018dc547f5749f3f28c88f8003b142de1bf4709a63e345e850109c2f2e1"}):
            with self.subTest(changed=tuple(change)), \
                    patch.object(native, "inspect_pdf_tounicode_width_coverage") as first:
                with self.assertRaises(native.PdfNativeSourceJobError):
                    native.execute_pdf_native_source_job(**{**args, **change})
                first.assert_not_called()

    def test_default_render_and_qa_budgets_stay_at_eight_mib(self):
        """Optional inspection admission does not activate a larger product renderer or QA."""
        from reporting import _pdf_render_worker, _pdf_safety_worker, pdf_candidate_qa
        from reporting import _pdf_document_content_worker, _pdf_text_window_worker
        self.assertEqual(_pdf_render_worker.PDF_BYTES, 8 * MIB)
        self.assertEqual(_pdf_safety_worker.MAX_PDF_BYTES, 8 * MIB)
        self.assertEqual(pdf_candidate_qa.MAX_PDF_BYTES, 8 * MIB)
        self.assertEqual(pdf_candidate_qa.MAX_PAGES, 32)
        self.assertEqual(_pdf_document_content_worker.MAX_DECODED_BYTES, 8 * MIB)
        self.assertEqual(_pdf_text_window_worker.MAX_DECODED_BYTES, 8 * MIB)

    def test_inner_object_and_cmap_stream_budgets_do_not_expand(self):
        """A larger complete file retains the smaller decoded-object and raw-CMap guards."""
        from reporting import _pdf_xref_entries_worker, _pdf_tounicode_header_worker
        from pypdf.generic import EncodedStreamObject, NameObject
        self.assertEqual(_pdf_xref_entries_worker.MAX_DECODED_OBJECT_STREAM, 8 * MIB)
        stream = EncodedStreamObject()
        stream[NameObject("/Filter")] = NameObject("/FlateDecode")
        stream._data = b"\x78\x9c" + b"x" * (8 * MIB - 1)
        with self.assertRaises(ValueError):
            _pdf_tounicode_header_worker._raw_zlib_header(stream)

    def test_constructed_graph_receipt_cannot_bind_an_out_of_class_pair(self):
        """Unsigned receipts cannot bind a large 65-page preflight that execution refuses."""
        from reporting import document_plan, document_graph_probe, pdf_object_graph
        _, pdf = generated_large_case(33)
        document = document_plan.build_pdf_document_preflight(pdf_bytes=pdf,
            expected_pdf_sha256=sha256(pdf).hexdigest(), expected_ir_sha256="b" * 64,
            declared_page_count=65, namespace_id="synthetic-large-pdf", job_id="large-boundary",
            request_sha256="c" * 64,
            expected_preflight_profile_sha256=document_plan.PROFILE_SHA256)
        inspection = pdf_object_graph.PdfObjectGraphInspection(pdf_sha256=document.pdf_sha256,
            ir_sha256=document.ir_sha256, plan_sha256=document.text_plan.plan_sha256,
            page_count=65, object_count=65)
        with self.assertRaises(document_graph_probe.PdfDocumentGraphProbeError):
            document_graph_probe.PdfDocumentGraphProbe(document=document, inspection=inspection,
                expected_preflight_sha256=document.preflight_sha256,
                probe_profile_sha256=document_graph_probe.PROFILE_SHA256)

    def test_large_metadata_uses_same_policy_while_default_remains_bounded(self):
        """Controlled Info/catalog/XMP checks accept the optional class only inside its worker."""
        from reporting import pdf_document_metadata, pdf_qa, pdf_text_windows
        from reporting.page_windows import plan_pdf_page_windows
        ir, pdf = generated_large_case(33)
        ordinary = pdf_qa.validate_pdf_candidate(pdf_bytes=pdf,
            expected_pdf_sha256=sha256(pdf).hexdigest(), expected_author=pdf_qa.GENERATED_PDF_AUTHOR,
            expected_language="en-US", metadata_profile=pdf_qa.GENERATED_PDF_METADATA_PROFILE)
        self.assertFalse(ordinary.passed)
        self.assertIn("pdf_metadata_budget_exceeded", ordinary.errors)
        plan = plan_pdf_page_windows(pdf_sha256=sha256(pdf).hexdigest(),
            ir_sha256=_expected_content(ir)[0], page_count=33, admitted_page_budget=33,
            pages_per_window=16, inspector_profile_id=pdf_text_windows.PROFILE_ID)
        try:
            observed = pdf_document_metadata.inspect_pdf_document_metadata(pdf_bytes=pdf,
                plan=plan, expected_plan_sha256=plan.plan_sha256, expected_language="en-US")
        except pdf_document_metadata.PdfDocumentMetadataError as error:
            self.fail(f"LARGE_METADATA_ADMISSION: {error}")
        self.assertEqual(observed.pdf_sha256, sha256(pdf).hexdigest())
        self.assertEqual(observed.page_count, 33)

    def test_large_late_page_and_catalog_actions_fail_without_partial_result(self):
        """Forbidden content beyond the original byte/page class is still inspected."""
        from pypdf import PdfReader
        for mutation in ("last_page_action", "catalog_action"):
            ir, pdf = generated_large_case(33, mutation)
            args = {**self.arguments(33), "pdf_bytes": pdf,
                    "expected_pdf_sha256": sha256(pdf).hexdigest()}
            self.assertGreater(len(pdf), 8 * MIB)
            reader = PdfReader(BytesIO(pdf), strict=True)
            if mutation == "last_page_action":
                self.assertIn("/AA", reader.pages[-1])
            else:
                self.assertIn("/OpenAction", reader.trailer["/Root"])
            with self.subTest(mutation=mutation):
                with self.assertRaises(native.PdfNativeSourceJobError):
                    native.execute_pdf_native_source_job(**args)

    def test_worker_readers_enforce_the_same_byte_page_pair(self):
        """An exact descriptor digest cannot authorize a large document above 64 pages."""
        from tempfile import TemporaryFile
        from reporting import _pdf_object_graph_worker as graph_worker
        from reporting import _pdf_text_window_worker as text_worker
        _, pdf = generated_large_case(33)
        for module in (graph_worker, text_worker):
            fields = ["1", sha256(pdf).hexdigest(), "b" * 64, "c" * 64, "65"]
            if module is text_worker:
                fields += ["0", "1", "16"]
            with self.subTest(worker=module.__name__), TemporaryFile() as source:
                source.write(" ".join(fields).encode("ascii") + b"\n" + pdf)
                source.flush()
                with self.assertRaises(ValueError):
                    module._read_request(source.fileno())
