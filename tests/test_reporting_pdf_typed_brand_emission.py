"""Independent synthetic pydyf structures for the opt-in typed-brand finisher."""
from types import SimpleNamespace
import unittest

import pydyf


def fixture(with_ids=True):
    pdf = pydyf.PDF()
    pages = []
    def layout_box(tag, children=()):
        from weasyprint.formatting_structure.boxes import Box
        box = Box(tag, {"transform": ()}, None)
        box.children = list(children)
        return box

    for height in (100, 200):
        stream = pydyf.Stream([f"1 0 0 -1 0 {height * 3 // 4} cm".encode(),
                               b"q", b"0.75 0 0 0.75 0 0 cm"])
        pdf.add_object(stream)
        rectangle = (0, 0, 75, height * 3 // 4)
        page = pydyf.Dictionary({"Type": "/Page", "Parent": pdf.pages.reference,
                                 "Contents": stream.reference})
        for key in ("MediaBox", "TrimBox", "BleedBox"):
            page[key] = pydyf.Array(rectangle)
        pdf.add_page(page)
        pages.append(SimpleNamespace(width=100, height=height,
                     bleed=dict.fromkeys(("left", "right", "top", "bottom"), 0),
                     _page_box=layout_box("page", [layout_box("html", [layout_box("body")])])))
    pages[1]._page_box.children[0].children[0].children.append(
        layout_box("{http://www.w3.org/2000/svg}svg"))
    pdf.info["Title"] = pydyf.String("Synthetic metadata")
    tree = pydyf.Dictionary({"Nums": pydyf.Array([0, pydyf.Array(), 1, pydyf.Array()])})
    pdf.add_object(tree)
    root = pydyf.Dictionary({"Type": "/StructTreeRoot", "ParentTree": tree.reference,
                             "K": pydyf.Array()})
    pdf.add_object(root)
    pdf.catalog["StructTreeRoot"] = root.reference

    def node(role, parent):
        obj = pydyf.Dictionary({"Type": "/StructElem", "S": role, "K": pydyf.Array(),
                                "P": parent.reference})
        if role != "/Document":
            obj["Pg"] = pdf.page_references[1]
        pdf.add_object(obj)
        parent["K"].append(obj.reference)
        return obj

    document = node("/Document", root)
    figure = node("/Figure", document)
    figure["A"] = pydyf.Dictionary({"O": "/Layout", "BBox": pydyf.Array(
        [1.000001, 2.000001, 3.000001, 4.000001])})
    tree["Nums"][3].append(figure.reference)
    headers = []
    if with_ids:
        table = node("/Table", document)
        row = node("/TR", table)
        for value in ("2", "10"):
            header = node("/TH", row)
            header["A"] = pydyf.Dictionary({"O": "/Table"})
            header["ID"] = pydyf.String(f"{table.number}-0-{value}")
            headers.append(header)
        cell = node("/TD", row)
        cell["A"] = pydyf.Dictionary({"O": "/Table", "Headers": pydyf.Array(
            [header["ID"] for header in headers])})
    return SimpleNamespace(pages=pages), pdf, root, figure, headers


class TypedBrandEmissionTests(unittest.TestCase):
    def test_fractional_box_on_second_page_and_byte_sorted_original_ids(self):
        from reporting._pdf_typed_brand_emission import emit_structure
        document, pdf, root, figure, headers = fixture()
        objects = tuple(pdf.objects)
        parent_tree = root["ParentTree"]
        parent_object = pdf.objects[int(parent_tree.split()[0])]
        parent_content = parent_object.data
        metadata = pdf.info.data
        streams = [(obj, obj.data) for obj in pdf.objects if isinstance(obj, pydyf.Stream)]
        cell_headers = pdf.objects[-1]["A"]["Headers"]
        header_objects = tuple(cell_headers)
        header_data = cell_headers.data
        emit_structure(document, pdf)
        self.assertEqual(figure["A"]["BBox"], [b"0.75000075", b"146.99999925",
                                               b"2.25000075", b"148.49999925"])
        names = pdf.objects[-1]["Names"]
        self.assertIs(names[0], headers[1]["ID"])
        self.assertIs(names[2], headers[0]["ID"])
        self.assertEqual(names[1::2], [headers[1].reference, headers[0].reference])
        self.assertEqual(root["IDTree"], pdf.objects[-1].reference)
        self.assertEqual(parent_object.data, parent_content)
        self.assertEqual(pdf.info.data, metadata)
        self.assertEqual([obj.data for obj, _ in streams], [data for _, data in streams])
        self.assertIs(objects[-1]["A"]["Headers"], cell_headers)
        self.assertEqual(cell_headers.data, header_data)
        self.assertEqual(len(cell_headers), len(header_objects))
        for actual, original in zip(cell_headers, header_objects):
            self.assertIs(actual, original)
        self.assertEqual(parent_tree, root["ParentTree"])
        self.assertTrue(all(a is b for a, b in zip(objects, pdf.objects)))
        with self.assertRaises(ValueError):
            emit_structure(document, pdf)

    def test_class_map_alias_retains_original_layout_rectangle(self):
        from reporting._pdf_typed_brand_emission import emit_structure
        document, pdf, root, figure, _ = fixture()
        shared = figure["A"]
        original_box = shared["BBox"]
        original_bytes = shared.data
        root["ClassMap"] = pydyf.Dictionary({"LogoLayout": shared})
        emit_structure(document, pdf)
        self.assertIs(root["ClassMap"]["LogoLayout"], shared)
        self.assertIs(shared["BBox"], original_box)
        self.assertEqual(shared.data, original_bytes)
        self.assertIsNot(figure["A"], shared)
        self.assertEqual(figure["A"]["BBox"][0], b"0.75000075")

    def test_parent_tree_cannot_overlap_structure_or_use_foreign_shape(self):
        from reporting._pdf_typed_brand_emission import emit_structure
        for case in ("root", "element", "extra-key", "not-array", "missing-page-pair"):
            with self.subTest(case=case):
                document, pdf, root, figure, _ = fixture()
                tree = pdf.objects[int(root["ParentTree"].split()[0])]
                if case == "root":
                    root["ParentTree"] = root.reference
                elif case == "element":
                    root["ParentTree"] = figure.reference
                elif case == "extra-key":
                    tree["Extra"] = 0
                elif case == "not-array":
                    tree["Nums"] = pydyf.Dictionary()
                else:
                    del tree["Nums"][-2:]
                before = (figure["A"].data, root.data, tree.data, len(pdf.objects))
                with self.assertRaises(ValueError):
                    emit_structure(document, pdf)
                self.assertEqual(before, (figure["A"].data, root.data, tree.data, len(pdf.objects)))
                self.assertNotIn("IDTree", root)

    def test_owner_arrays_require_bounded_indirect_structure_references(self):
        from reporting._pdf_typed_brand_emission import emit_structure
        for case in ("inline-figure", "nested-array", "wrong-reference", "foreign", "budget"):
            with self.subTest(case=case):
                document, pdf, root, figure, _ = fixture()
                tree = pdf.objects[int(root["ParentTree"].split()[0])]
                owners = tree["Nums"][3]
                if case == "inline-figure":
                    owners[0] = figure
                elif case == "nested-array":
                    owners[0] = pydyf.Array([figure.reference])
                elif case == "wrong-reference":
                    owners[0] = pdf.pages.reference
                elif case == "foreign":
                    owners[0] = b"999999 0 R"
                else:
                    tree["Nums"][1].extend([figure.reference] * 10000)
                    owners.extend([figure.reference] * 10000)
                before = (figure.data, root.data, tree.data, len(pdf.objects))
                with self.assertRaises(ValueError):
                    emit_structure(document, pdf)
                self.assertEqual(before, (figure.data, root.data, tree.data, len(pdf.objects)))

    def test_zero_ids_does_not_create_index_and_cannot_emit_twice(self):
        from reporting._pdf_typed_brand_emission import emit_structure
        document, pdf, root, figure, _ = fixture(False)
        count = len(pdf.objects)
        emit_structure(document, pdf)
        self.assertNotIn("IDTree", root)
        self.assertEqual(len(pdf.objects), count)
        with self.assertRaises(ValueError):
            emit_structure(document, pdf)

    def test_invalid_graphs_refuse_before_mutating_structure(self):
        from reporting._pdf_typed_brand_emission import emit_structure
        for case in ("cycle", "foreign", "duplicate", "missing-id", "unicode",
                     "index", "zero-figures", "wrong-page", "rotation", "bleed",
                     "reversed", "nonfinite", "traversal", "depth", "two-figures",
                     "long-id", "bad-mcid", "missing-headers", "foreign-header", "transform",
                     "owned-attribute", "shared-attribute"):
            with self.subTest(case=case):
                document, pdf, root, figure, headers = fixture()
                if case == "cycle":
                    figure["K"].append(figure.reference)
                elif case == "foreign":
                    figure["K"].append(b"9999999 0 R")
                elif case == "duplicate":
                    headers[0]["ID"] = headers[1]["ID"]
                elif case == "missing-id":
                    del headers[1]["ID"]
                elif case == "unicode":
                    headers[1]["ID"] = pydyf.String("é")
                elif case == "index":
                    root["IDTree"] = root["ParentTree"]
                elif case == "zero-figures":
                    figure["S"] = "/Div"
                elif case == "wrong-page":
                    figure["Pg"] = root.reference
                elif case == "rotation":
                    pdf.objects[4]["Rotate"] = 90
                elif case == "bleed":
                    document.pages[0].bleed["left"] = 1
                elif case == "reversed":
                    figure["A"]["BBox"][0] = 4
                elif case == "nonfinite":
                    figure["A"]["BBox"][0] = float("inf")
                elif case == "owned-attribute":
                    pdf.add_object(figure["A"])
                elif case == "shared-attribute":
                    doc = pdf.objects[int(figure["P"].split()[0])]
                    doc["A"] = figure["A"]
                elif case == "depth":
                    parent = figure
                    for _ in range(64):
                        child = pydyf.Dictionary({"Type": "/StructElem", "S": "/Div",
                            "K": pydyf.Array(), "P": parent.reference, "Pg": figure["Pg"]})
                        pdf.add_object(child)
                        parent["K"].append(child.reference)
                        parent = child
                elif case == "two-figures":
                    other = pydyf.Dictionary(figure)
                    pdf.add_object(other)
                    pdf.objects[int(figure["P"].split()[0])]["K"].append(other.reference)
                elif case == "long-id":
                    headers[1]["ID"] = pydyf.String("1" * 129)
                elif case == "bad-mcid":
                    figure["K"].append(True)
                elif case == "missing-headers":
                    del pdf.objects[-1]["A"]["Headers"]
                elif case == "foreign-header":
                    value = pdf.objects[-1]["A"]["Headers"][0]
                    pdf.objects[-1]["A"]["Headers"][0] = pydyf.String(value.string)
                elif case == "transform":
                    pdf.objects[3].stream[2] = b"1 0 0 1 0 0 cm"
                else:
                    figure["K"].extend([1] * 20000)
                box = figure["A"]["BBox"]
                count = len(pdf.objects)
                with self.assertRaises(ValueError):
                    emit_structure(document, pdf)
                self.assertIs(figure["A"]["BBox"], box)
                self.assertEqual(len(pdf.objects), count)

    def test_shared_nonfigure_reference_refuses_before_mutation(self):
        from reporting._pdf_typed_brand_emission import emit_structure
        document, pdf, root, figure, headers = fixture()
        parent = pdf.objects[int(root["K"][0].split()[0])]
        shared = pydyf.Dictionary({"Type": "/StructElem", "S": "/Div",
            "P": parent.reference, "Pg": figure["Pg"], "K": pydyf.Array()})
        pdf.add_object(shared)
        parent["K"].extend([shared.reference, shared.reference])
        self.assertEqual(len(root["K"]), 1)
        self.assertEqual(parent["S"], "/Document")
        self.assertEqual(len(headers), 2)
        objects = tuple(pdf.objects)
        snapshots = [(obj, obj.data) for obj in objects
                     if isinstance(obj, (pydyf.Dictionary, pydyf.Stream))]
        layout, box, parent_tree = figure["A"], figure["A"]["BBox"], root["ParentTree"]
        with self.assertRaises(ValueError):
            emit_structure(document, pdf)
        self.assertEqual(len(pdf.objects), len(objects))
        self.assertTrue(all(before is after for before, after in zip(objects, pdf.objects)))
        self.assertEqual([obj.data for obj, _ in snapshots], [data for _, data in snapshots])
        self.assertIs(figure["A"], layout)
        self.assertIs(figure["A"]["BBox"], box)
        self.assertEqual(root["ParentTree"], parent_tree)
        self.assertNotIn("IDTree", root)

    def test_wide_distinct_non_id_references_enforce_traversal_budget(self):
        from reporting._pdf_typed_brand_emission import emit_structure
        document, pdf, root, figure, headers = fixture()
        parent = pdf.objects[int(root["K"][0].split()[0])]
        for _ in range(10001):
            item = pydyf.Dictionary({"Type": "/StructElem", "S": "/Div",
                "P": parent.reference, "Pg": figure["Pg"], "K": pydyf.Array()})
            pdf.add_object(item)
            parent["K"].append(item.reference)
        self.assertEqual(len(root["K"]), 1)
        self.assertEqual(parent["S"], "/Document")
        self.assertEqual(len(headers), 2)
        objects = tuple(pdf.objects)
        snapshots = [(obj, obj.data) for obj in objects
                     if isinstance(obj, (pydyf.Dictionary, pydyf.Stream))]
        layout, box, parent_tree = figure["A"], figure["A"]["BBox"], root["ParentTree"]
        with self.assertRaises(ValueError):
            emit_structure(document, pdf)
        self.assertEqual(len(pdf.objects), len(objects))
        self.assertTrue(all(before is after for before, after in zip(objects, pdf.objects)))
        self.assertEqual([obj.data for obj, _ in snapshots], [data for _, data in snapshots])
        self.assertIs(figure["A"], layout)
        self.assertIs(figure["A"]["BBox"], box)
        self.assertEqual(root["ParentTree"], parent_tree)
        self.assertNotIn("IDTree", root)


    def test_composed_finisher_validates_fonts_once_before_emission(self):
        from reporting._pdf_typed_brand_emission import _compose_finisher
        document, pdf, root, figure, _ = fixture()
        called = []
        selection = object()
        def original(owner, doc, candidate):
            self.assertIs(owner, selection)
            self.assertIs(doc, document)
            self.assertIs(candidate, pdf)
            self.assertNotIn("IDTree", root)
            called.append(True)
        wrapped = _compose_finisher(original)
        wrapped(selection, document, pdf)
        self.assertIn("IDTree", root)
        with self.assertRaises(ValueError):
            wrapped(selection, document, pdf)
        self.assertEqual(called, [True])


    def test_figure_and_ancestor_transforms_refuse_before_structure_mutation(self):
        from reporting._pdf_typed_brand_emission import emit_structure
        from weasyprint.css.properties import Dimension
        from weasyprint.layout.absolute import AbsolutePlaceholder
        from weasyprint.matrix import Matrix

        for case in ("figure", "body-ancestor", "html-ancestor", "placeholder-descendant"):
            with self.subTest(case=case):
                document, pdf, root, figure, _ = fixture()
                page_box = document.pages[1]._page_box
                html_box = page_box.children[0]
                body_box = html_box.children[0]
                figure_box = body_box.children[0]
                transformed = {"figure": figure_box, "body-ancestor": body_box,
                               "html-ancestor": html_box,
                               "placeholder-descendant": figure_box}[case]
                if case == "placeholder-descendant":
                    html_box.children[0] = AbsolutePlaceholder(body_box)
                transformed.style["transform"] = (
                    ("translate", (Dimension(40, "px"), Dimension(0, "px"))),)
                transformed.transformation_matrix = Matrix(e=40)
                page = pdf.objects[int(figure["Pg"].split()[0])]
                stream = pdf.objects[int(page["Contents"].split()[0])]
                prefix = tuple(stream.stream[:3])
                stream.stream.extend([b"q", b"1 0 0 1 40 0 cm",
                                      b"/Figure <</MCID 0>> BDC", b"EMC", b"Q"])
                self.assertEqual(tuple(stream.stream[:3]), prefix)
                self.assertEqual(prefix, (b"1 0 0 -1 0 150 cm", b"q",
                                          b"0.75 0 0 0.75 0 0 cm"))
                objects = tuple(pdf.objects)
                snapshots = [(obj, obj.data) for obj in objects
                             if isinstance(obj, (pydyf.Dictionary, pydyf.Stream))]
                layout, box = figure["A"], figure["A"]["BBox"]
                parent_tree = root["ParentTree"]
                with self.assertRaisesRegex(ValueError, "^typed brand emission refused$"):
                    emit_structure(document, pdf)
                self.assertEqual(len(pdf.objects), len(objects))
                self.assertTrue(all(before is after for before, after in
                                    zip(objects, pdf.objects)))
                self.assertEqual([obj.data for obj, _ in snapshots],
                                 [data for _, data in snapshots])
                self.assertIs(figure["A"], layout)
                self.assertIs(figure["A"]["BBox"], box)
                self.assertEqual(root["ParentTree"], parent_tree)
                self.assertNotIn("IDTree", root)

    def test_layout_transform_admission_refuses_unknown_or_unbounded_tree(self):
        from reporting._pdf_typed_brand_emission import emit_structure
        from weasyprint.formatting_structure.boxes import (
            Box, TableBox, TableColumnBox, TableColumnGroupBox)
        from weasyprint.layout.absolute import AbsolutePlaceholder
        from weasyprint.matrix import Matrix

        def layout_box(children=()):
            box = Box("div", {"transform": ()}, None)
            box.children = list(children)
            return box

        positive = {"depth-at-limit", "charge-at-limit", "valid-placeholder",
                    "valid-column-groups"}
        cases = ("missing-page-box", "missing-transform", "malformed-transform",
                 "css-identity", "matrix-only", "malformed-children",
                 "placeholder-cycle", "cycle", "depth-over-limit",
                 "charge-over-limit", "depth-at-limit", "charge-at-limit",
                 "valid-placeholder", "transformed-column-descendant",
                 "missing-column-groups", "malformed-column-groups",
                 "combined-column-fanout-over-limit", "valid-column-groups")
        for case in cases:
            with self.subTest(case=case):
                document, pdf, root, figure, _ = fixture()
                page_box = document.pages[1]._page_box
                html_box = page_box.children[0]
                body_box = html_box.children[0]
                figure_box = body_box.children[0]
                if case == "missing-page-box":
                    del document.pages[1]._page_box
                elif case == "missing-transform":
                    del figure_box.style["transform"]
                elif case == "malformed-transform":
                    figure_box.style["transform"] = []
                elif case == "css-identity":
                    figure_box.style["transform"] = (("matrix", (1, 0, 0, 1, 0, 0)),)
                elif case == "matrix-only":
                    figure_box.transformation_matrix = Matrix()
                elif case == "malformed-children":
                    figure_box.children = iter(())
                elif case == "placeholder-cycle":
                    placeholder = AbsolutePlaceholder(figure_box)
                    object.__setattr__(placeholder, "_box", placeholder)
                    body_box.children[0] = placeholder
                elif case == "cycle":
                    body_box.children = [body_box]
                elif case in ("depth-at-limit", "depth-over-limit"):
                    current = figure_box
                    for _ in range(60 if case == "depth-at-limit" else 61):
                        current = layout_box([current])
                    body_box.children = [current]
                elif case in ("charge-at-limit", "charge-over-limit"):
                    first_body = document.pages[0]._page_box.children[0].children[0]
                    first_body.children = [
                        layout_box() for _ in range(9994 if case == "charge-at-limit" else 9995)]
                elif case == "valid-placeholder":
                    html_box.children[0] = AbsolutePlaceholder(body_box)
                else:
                    table_box = TableBox("table", {"transform": ()}, None, ())
                    column_box = TableColumnBox("col", {"transform": ()}, None, ())
                    column_group = TableColumnGroupBox(
                        "colgroup", {"transform": ()}, None, (column_box,))
                    table_box.column_groups = (column_group,)
                    first_body = document.pages[0]._page_box.children[0].children[0]
                    first_body.children.append(table_box)
                    if case == "transformed-column-descendant":
                        column_box.style["transform"] = (("matrix", (1, 0, 0, 1, 40, 0)),)
                        column_box.transformation_matrix = Matrix(e=40)
                    elif case == "missing-column-groups":
                        del table_box.column_groups
                    elif case == "malformed-column-groups":
                        table_box.column_groups = iter(())
                    elif case == "combined-column-fanout-over-limit":
                        table_box.children = [layout_box() for _ in range(4997)]
                        table_box.column_groups = [
                            TableColumnGroupBox("colgroup", {"transform": ()}, None, ())
                            for _ in range(4997)]
                objects = tuple(pdf.objects)
                snapshots = [(obj, obj.data) for obj in objects
                             if isinstance(obj, (pydyf.Dictionary, pydyf.Stream))]
                layout, box = figure["A"], figure["A"]["BBox"]
                parent_tree = root["ParentTree"]
                if case in positive:
                    self.assertEqual(emit_structure(document, pdf),
                                     {"figure_count": 1, "id_count": 2})
                    self.assertIn("IDTree", root)
                    self.assertEqual(figure["A"]["BBox"],
                                     [b"0.75000075", b"146.99999925",
                                      b"2.25000075", b"148.49999925"])
                else:
                    with self.assertRaisesRegex(ValueError, "^typed brand emission refused$"):
                        emit_structure(document, pdf)
                    self.assertEqual(len(pdf.objects), len(objects))
                    self.assertTrue(all(before is after for before, after in
                                        zip(objects, pdf.objects)))
                    self.assertEqual([obj.data for obj, _ in snapshots],
                                     [data for _, data in snapshots])
                    self.assertIs(figure["A"], layout)
                    self.assertIs(figure["A"]["BBox"], box)
                    self.assertEqual(root["ParentTree"], parent_tree)
                    self.assertNotIn("IDTree", root)



class TypedBrandRouteTests(unittest.TestCase):
    def setUp(self):
        from hashlib import sha256
        from unittest.mock import patch
        from reporting import pdf_typed_brand_render as route
        from reporting.pdf_raster_resources import RasterAsset, RasterBundle
        from test_reporting_pdf_raster_resources import png
        self.route = route
        raw = png()
        self.bundle = RasterBundle((RasterAsset("synthetic", raw, sha256(raw).hexdigest(),
                                                2, 2, "a" * 64, "b" * 64),))
        self.args = dict(html="synthetic", expected_html_sha256=sha256(b"synthetic").hexdigest(),
                         resources=self.bundle, expected_resources_sha256=self.bundle.bundle_sha256)
        self.enterContext(patch.dict("os.environ", {
            **dict.fromkeys(route.DISABLE, ""),
            "OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE": "qualification-only"}))
        self.profile = route.require_policy()
        self.pdf = b"%PDF-1.7 synthetic transport fixture"
        self.record = dict(protocol_version=3, profile_id="typed-original-brand-render-v1",
            profile_sha256=self.profile, status="PASS", pdf_bytes=len(self.pdf),
            pdf_sha256=sha256(self.pdf).hexdigest(), limits={
                "memory_bytes": 1073741824, "cpu_seconds": 20, "file_bytes": 16777216,
                "open_files": 128}, html_sha256=self.args["expected_html_sha256"],
            page_count=1, resources_sha256=self.bundle.bundle_sha256, resource_count=1)

    def scope(self):
        from reporting._pdf_native_launch_budget import NativeLaunchScope
        from reporting.page_windows import plan_pdf_page_windows
        plan = plan_pdf_page_windows(pdf_sha256="a"*64, ir_sha256="b"*64,
                 page_count=1, admitted_page_budget=1, pages_per_window=16,
                 inspector_profile_id="generated-pdf-text-window-v1")
        return NativeLaunchScope(plan, len(self.pdf))

    def test_active_owner_and_foreign_thread_refuse_before_input_or_descriptors(self):
        from concurrent.futures import ThreadPoolExecutor
        from unittest.mock import patch
        for foreign in (False, True):
            with self.subTest(foreign=foreign), self.scope() as scope, patch(
                    "tempfile.TemporaryFile") as descriptor:
                def enter():
                    with self.assertRaisesRegex(ValueError, "^typed_brand_render_refused$"):
                        self.route.render_typed_brand_pdf(**(self.args | {"html": None}))
                if foreign:
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        pool.submit(enter).result()
                else:
                    enter()
                descriptor.assert_not_called()
                self.assertTrue(scope._invalid)
                with self.assertRaises(ValueError):
                    scope.require_complete()

    def test_missing_disabled_and_drifted_manifest_refuse_before_launch(self):
        import tempfile
        from pathlib import Path
        import json
        from unittest.mock import patch
        from reporting import adapters
        from reporting import _pdf_typed_brand_emission as core
        with tempfile.TemporaryDirectory() as directory, patch.object(
                adapters, "_start_pdf_render_worker") as launch:
            path = Path(directory) / "profile.json"
            data = core.require_source_manifest()
            self.assertIn("reporting/_pdf_original_dna_png_admission.py", data["sources"])
            for case in ("absent", "source", "engine", "flag"):
                with self.subTest(case=case):
                    if case == "source":
                        data["sources"]["reporting/adapters.py"] = "0" * 64
                        path.write_text(json.dumps(data))
                    if case == "engine":
                        data = core.require_source_manifest()
                        data["engine_sources"]["weasyprint/document.py"] = "0" * 64
                        path.write_text(json.dumps(data))
                    with (patch.object(core, "MANIFEST", core.MANIFEST if case == "flag" else path),
                          patch.dict("os.environ", {"OMNIGENIS_TYPED_BRAND_RENDER_DISABLED":
                                                    "1" if case == "flag" else ""}),
                          self.assertRaisesRegex(ValueError, "^typed_brand_render_refused$")):
                        self.route.render_typed_brand_pdf(**self.args)
            launch.assert_not_called()

    def test_closed_response_exact_anonymous_output_and_retained_seal(self):
        import json
        import tempfile
        from copy import deepcopy
        with tempfile.TemporaryFile() as output:
            output.write(self.pdf)
            output.flush()
            def decode(raw):
                return self.route._decode(raw, output.fileno(), self.args["expected_html_sha256"],
                                          self.bundle.bundle_sha256, 1, self.profile)
            candidate = decode(json.dumps(self.record).encode())
            self.assertEqual(candidate.pdf_bytes, self.pdf)
            self.assertIs(candidate.to_dict()["default_pipeline_activated"], False)
            for key, value in (("profile_id", "preloaded-png-render-v1"), ("status", "SKIP"),
                               ("protocol_version", 3.0), ("pdf_sha256", "a"*64),
                               ("page_count", True), ("page_count", 65), ("pdf_bytes", 1),
                               ("html_sha256", "a"*64), ("resources_sha256", "b"*64),
                               ("resource_count", True), ("extra", True)):
                with self.subTest(field=key, value=value), self.assertRaises(ValueError):
                    decode(json.dumps(self.record | {key:value}).encode())
            invalid = deepcopy(self.record)
            invalid["limits"]["cpu_seconds"] = 20.0
            for raw in (json.dumps(invalid).encode(), b'{"x":0,"x":1}', b'{"x":NaN}',
                        b" " * 65537, b"\xff", b"{}"):
                with self.assertRaises(ValueError):
                    decode(raw)
            object.__setattr__(candidate, "_pdf", self.pdf + b"changed")
            with self.assertRaises(ValueError):
                candidate.to_dict()
        with tempfile.NamedTemporaryFile() as linked:
            linked.write(self.pdf)
            linked.flush()
            with self.assertRaises(ValueError):
                self.route._decode(json.dumps(self.record).encode(), linked.fileno(),
                    self.args["expected_html_sha256"], self.bundle.bundle_sha256, 1, self.profile)

    def test_child_failure_or_late_change_closes_all_four_descriptors(self):
        from contextlib import ExitStack
        import json
        import os
        from pathlib import Path
        from unittest.mock import patch
        from reporting import adapters
        for case in ("failed", "late-disable", "active-scope", "resources"):
            with self.subTest(case=case), ExitStack() as stack:
                fds = []
                marker = object()
                def start(command, *, pass_fds, env, before_spawn):
                    before_spawn()
                    fds.extend(pass_fds)
                    self.assertEqual(len(set(fds)), 4)
                    self.assertEqual(command[1:3], ["-I", "-B"])
                    self.assertEqual(Path(command[3]).name, "_pdf_typed_brand_render_worker.py")
                    self.assertEqual(command[-2], "native-typed-original-brand-v1")
                    self.assertEqual(env["OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE"], "qualification-only")
                    os.pwrite(fds[1], self.pdf, 0)
                    os.pwrite(fds[2], json.dumps(self.record).encode(), 0)
                    return marker
                scope = self.scope()
                if case == "active-scope":
                    decode = self.route._decode
                    def activate_after_wait(*args):
                        stack.enter_context(scope)
                        return decode(*args)
                    stack.enter_context(patch.object(self.route, "_decode", side_effect=activate_after_wait))
                waited = []
                def wait(process, *, wall_seconds, cleanup_observer):
                    waited.append(process)
                    self.assertIs(process, marker)
                    self.assertEqual(wall_seconds, 30)
                    if case == "late-disable":
                        stack.enter_context(patch.dict("os.environ", {"OMNIGENIS_TYPED_BRAND_RENDER_DISABLED":"1"}))
                    elif case == "resources":
                        original = self.bundle.assets
                        stack.callback(object.__setattr__, self.bundle, "assets", original)
                        object.__setattr__(self.bundle, "assets", ())
                    status = 1 if case == "failed" else 0
                    cleanup_observer(status)
                    return status
                stack.enter_context(patch.object(adapters, "_start_pdf_render_worker", side_effect=start))
                stack.enter_context(patch.object(adapters, "_wait_pdf_render_worker", new=wait))
                with self.assertRaisesRegex(ValueError, "^typed_brand_render_refused$"):
                    self.route.render_typed_brand_pdf(**self.args)
                self.assertEqual(waited, [marker])
                if case == "active-scope":
                    self.assertTrue(scope._invalid)
                self.assertEqual(len(fds), 4)
                for fd in fds:
                    with self.assertRaises(OSError):
                        os.fstat(fd)

    def test_disable_or_mode_change_during_profile_hash_refuses(self):
        import os
        from unittest.mock import patch
        from reporting import _pdf_typed_brand_emission as core
        for key in (*self.route.DISABLE, "OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE"):
            with self.subTest(key=key), patch.dict(os.environ):
                def changed():
                    os.environ[key] = "1"
                    return self.profile
                with patch.object(core, "profile_sha256", side_effect=changed), self.assertRaises(ValueError):
                    self.route.require_policy()

    def test_typed_wait_excludes_native_activation(self):
        import threading
        from unittest.mock import patch
        from reporting import adapters
        observed = []
        def check(phase):
            results = []
            def challenger():
                scope = self.scope()
                try:
                    with scope:
                        pass
                except ValueError:
                    results.append(scope._invalid)
                else:
                    results.append(False)
            thread = threading.Thread(target=challenger, daemon=True)
            thread.start()
            thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(results, [True])
            observed.append(phase)
        def start(*a, **k):
            k["before_spawn"]()
            check("launch")
            return object()
        def wait(process, *, wall_seconds, cleanup_observer):
            check("owned wait and cleanup")
            cleanup_observer(1)
            return 1
        with (patch.object(adapters, "_start_pdf_render_worker", side_effect=start),
              patch.object(adapters, "_wait_pdf_render_worker", new=wait),
              self.assertRaises(ValueError)):
            self.route.render_typed_brand_pdf(**self.args)
        self.assertEqual(observed, ["launch", "owned wait and cleanup"])
        with self.scope():
            pass

    def test_profile_sources_use_bounded_descriptor_reads(self):
        from pathlib import Path
        from unittest.mock import patch
        from reporting import _pdf_typed_brand_emission as core
        with patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded path read")):
            self.assertEqual(core.profile_sha256(), self.profile)

    def test_bounded_file_refuses_nonregular_oversized_and_changed_descriptors(self):
        import os
        from pathlib import Path
        import tempfile
        from unittest.mock import patch
        from reporting import _pdf_typed_brand_emission as core
        real_open, real_read = os.open, os.read
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profile"
            for case in ("fifo", "oversized", "grow", "truncate", "replace", "symlink"):
                with self.subTest(case=case):
                    if case == "fifo":
                        os.mkfifo(path)
                    elif case == "symlink":
                        path.symlink_to(Path(tmp) / "unavailable")
                    else:
                        path.write_bytes(b"abcde" if case == "oversized" else b"abcd")
                    captured, sizes = [], []
                    def open_regular(name, flags):
                        required = os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
                        self.assertEqual(flags & required, required)
                        fd = real_open(name, flags)
                        captured.append(fd)
                        return fd
                    def read(fd, size):
                        sizes.append(size)
                        if case == "grow":
                            with path.open("ab") as changed:
                                changed.write(b"e")
                        elif case == "truncate":
                            with path.open("wb"):
                                pass
                        elif case == "replace":
                            path.unlink()
                            path.write_bytes(b"abcd")
                        else:
                            self.fail("read crossed initial type or size refusal")
                        return real_read(fd, size)
                    with (patch.object(os, "open", side_effect=open_regular),
                          patch.object(os, "read", side_effect=read),
                          self.assertRaises((OSError, ValueError))):
                        core._bounded_file(path, 4, retain=True)
                    self.assertLessEqual(sum(sizes), 4)
                    for fd in captured:
                        with self.assertRaises(OSError):
                            os.fstat(fd)
                    path.unlink()

    def test_profiles_bind_each_file_category_to_its_descriptor_budget(self):
        from unittest.mock import patch
        from reporting import _pdf_typed_brand_emission as core
        with patch.object(core, "_bounded_file", wraps=core._bounded_file) as bounded:
            self.assertEqual(core.profile_sha256(), self.profile)
        calls = bounded.call_args_list
        self.assertEqual(calls[0].args, (core.MANIFEST, 16384))
        self.assertEqual(calls[0].kwargs, {"retain": True})
        source_end = 1 + len(core.SOURCES)
        self.assertEqual([call.args for call in calls[1:source_end]],
                         [(core.ROOT / name, 65536) for name in core.SOURCES])
        engine_names = [name for package in core.CONTRACT["versions"]
                        for name in core.ENGINES if name.startswith(package + "/")]
        self.assertEqual(len(calls[source_end:]), len(engine_names))
        for name, call in zip(engine_names, calls[source_end:]):
            self.assertTrue(str(call.args[0]).endswith(name))
            self.assertEqual(call.args[1], 65536)

    def test_actual_worker_entry_orders_audit_and_finisher_after_startup_guards(self):
        import json
        from pathlib import Path
        import subprocess
        import sys
        root = Path(self.route.__file__).resolve().parents[1]
        # Run module-global child adaptations only in a disposable isolated interpreter.
        program = """
import json, os, runpy, sys, tempfile
from contextlib import ExitStack
from pathlib import Path
sys.path.insert(0, sys.argv[1])
case = sys.argv[2]
from reporting import _pdf_render_worker as base, _pdf_process_sandbox as sandbox
from reporting import _pdf_typed_brand_emission as core, pdf_typed_brand_render as route
from reporting import pdf_raster_render as inherited
events = []
def stage(label):
    def run(*a, **k):
        events.append(label)
        if label == case or label == "request":
            raise ValueError("fixture stop")
        return {}
    return run
base._apply_resource_limits = stage("limits")
base._arm_worker_lifetime = stage("lifetime")
sandbox.enforce_pdf_landlock = stage("landlock")
sandbox.enforce_pdf_network_filter = stage("network")
route.require_policy = stage("audit")
core.install_in_isolated_render_worker = stage("finisher")
inherited.read_raster_inputs = stage("request")
base._failure = lambda *a, **k: 1
with ExitStack() as stack:
    fds = [stack.enter_context(tempfile.TemporaryFile()).fileno() for _ in range(4)]
    if case == "descriptor":
        fds[1] = fds[0]
    script = Path(core.__file__).with_name("_pdf_typed_brand_render_worker.py")
    sys.argv = [str(script), *map(str, fds[:3]), str(os.getpid()), core.MODE, str(fds[3])]
    try:
        runpy.run_path(str(script), run_name="__main__")
    except SystemExit:
        pass
print(json.dumps(events))
"""
        order = ["limits", "lifetime", "landlock", "network", "audit", "finisher", "request"]
        for case in ("descriptor", "network", "audit", "request"):
            with self.subTest(case=case):
                completed = subprocess.run([sys.executable, "-I", "-B", "-c", program,
                                            str(root), case], capture_output=True,
                                           check=True, text=True, timeout=10)
                expected = [] if case == "descriptor" else order[:order.index(case) + 1]
                self.assertEqual(json.loads(completed.stdout), expected)

    def test_postflight_hash_disable_withholds_result_after_settled_child(self):
        from contextlib import ExitStack
        import os
        from unittest.mock import patch
        from reporting import adapters, _pdf_typed_brand_emission as core
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ))
            def stale():
                os.environ["OMNIGENIS_TYPED_BRAND_RENDER_DISABLED"] = "1"
                return self.profile
            def decode(*args):
                stack.enter_context(patch.object(core, "profile_sha256", side_effect=stale))
                return object()
            stack.enter_context(patch.object(self.route, "_decode", side_effect=decode))
            def launched(*args, **kwargs):
                kwargs["before_spawn"]()
                return object()
            start = stack.enter_context(patch.object(adapters, "_start_pdf_render_worker", side_effect=launched))
            waits = []
            def wait(process, *, wall_seconds, cleanup_observer):
                waits.append(wall_seconds)
                cleanup_observer(0)
                return 0
            stack.enter_context(patch.object(adapters, "_wait_pdf_render_worker", new=wait))
            with self.assertRaisesRegex(ValueError, "^typed_brand_render_refused$"):
                self.route.render_typed_brand_pdf(**self.args)
            start.assert_called_once()
            self.assertEqual(waits, [30])
            with self.scope():
                pass

    def test_ambiguous_launch_wait_and_handoff_preserve_custody(self):
        from contextlib import ExitStack
        import dis
        import inspect
        import sys
        from unittest.mock import patch
        from reporting import adapters, _pdf_native_launch_budget as budget
        fn = self.route._run_owned_child
        lines, first = inspect.getsourcelines(fn)
        handoff = first + next(i for i, line in enumerate(lines)
                               if line.strip() == "status = waiter(process, wall_seconds=wall, cleanup_observer=observer)")
        site = {op.opname: op.offset for op in dis.get_instructions(fn)
                if op.positions.lineno == handoff}
        for case in ("uncertain-start", "no-handle", "wait-error", "wait-noninteger",
                     "handoff-settled", "handoff-unsettled", "call-boundary",
                     "post-return", "classifier-failure"):
            with self.subTest(case=case), ExitStack() as stack:
                self.assertIsNone(budget._TYPED_RENDER)
                stack.enter_context(patch.object(budget, "_TYPED_RENDER", None))
                handle = SimpleNamespace(returncode=None)
                calls = []
                interruption = KeyboardInterrupt("interrupted known handle")
                def start(*a, **k):
                    k["before_spawn"]()
                    if case == "uncertain-start":
                        raise KeyboardInterrupt("uncertain launch")
                    return None if case == "no-handle" else handle
                def wait(child, *, wall_seconds, cleanup_observer):
                    self.assertIs(child, handle)
                    calls.append(wall_seconds)
                    if case in ("wait-error", "handoff-unsettled"):
                        raise RuntimeError("cleanup unconfirmed")
                    if case == "wait-noninteger":
                        cleanup_observer(True)
                        return True
                    cleanup_observer(0)
                    return 0
                stack.enter_context(patch.object(adapters, "_start_pdf_render_worker", side_effect=start))
                stack.enter_context(patch.object(adapters, "_wait_pdf_render_worker", new=wait))
                if case == "classifier-failure":
                    stack.enter_context(patch.object(self.route, "_confirmed_pre_wait", side_effect=SystemExit))
                injected = case.startswith("handoff") or case in ("call-boundary", "post-return", "classifier-failure")
                if injected:
                    def interrupt(frame, event, arg):
                        if frame.f_code is fn.__code__:
                            frame.f_trace_opcodes = case in ("call-boundary", "post-return")
                            if frame.f_trace_opcodes:
                                trap = site["CALL"] if case == "call-boundary" else site["STORE_FAST"]
                                if event == "opcode" and frame.f_lasti == trap:
                                    raise interruption
                            elif event == "line" and frame.f_lineno == handoff:
                                raise interruption
                        return interrupt
                    # CPython 3.12 enables opcode tracing when a frame requests
                    # opcode events before the trace function is installed.
                    test_frame = sys._getframe()
                    stack.callback(setattr, test_frame, "f_trace_opcodes", test_frame.f_trace_opcodes)
                    test_frame.f_trace_opcodes = case in ("call-boundary", "post-return")
                    stack.callback(sys.settrace, sys.gettrace())
                    sys.settrace(interrupt)
                expected_error = (KeyboardInterrupt if injected or case == "uncertain-start" else
                                  ValueError if case in ("wait-noninteger", "no-handle") else RuntimeError)
                with self.assertRaises(expected_error) as error:
                    fn([], {}, ())
                if injected:
                    self.assertIs(error.exception, interruption)
                expected_waits = ([0] if case.startswith("handoff") else
                                  [30] if case.startswith("wait-") or case == "post-return" else [])
                self.assertEqual(calls, expected_waits)
                if case in ("handoff-settled", "post-return"):
                    with self.scope():
                        pass
                else:
                    self.assertEqual(budget._TYPED_RENDER.phase, "quarantined")
                    with self.assertRaises(ValueError), self.scope():
                        pass
                    with self.assertRaises(ValueError), budget.reserve_standalone_typed_render():
                        pass

    def test_native_activation_during_final_policy_refuses_before_spawn(self):
        from contextlib import ExitStack
        from unittest.mock import patch
        from reporting import adapters
        from test_reporting_pdf_native_launch_budget import launch_one, launch_specs
        from reporting._pdf_native_launch_budget import NativeLaunchScope
        from reporting.page_windows import plan_pdf_page_windows
        from hashlib import sha256
        plan = plan_pdf_page_windows(pdf_sha256=sha256(self.pdf).hexdigest(), ir_sha256="b"*64,
            page_count=1, admitted_page_budget=1, pages_per_window=16,
            inspector_profile_id="generated-pdf-text-window-v1")
        scope = NativeLaunchScope(plan, len(self.pdf))
        with ExitStack() as stack:
            active = []
            policy = self.route.require_policy
            def enter_before_reserve():
                digest = policy()
                if active:
                    stack.enter_context(scope)
                active.append(True)
                return digest
            stack.enter_context(patch.object(self.route, "require_policy", side_effect=enter_before_reserve))
            start = stack.enter_context(patch.object(adapters, "_start_pdf_render_worker"))
            with self.assertRaisesRegex(ValueError, "^typed_brand_render_refused$"):
                self.route.render_typed_brand_pdf(**self.args)
            self.assertEqual(len(active), 2)
            start.assert_not_called()
            with self.assertRaises(ValueError):
                launch_one(launch_specs(plan)[0], self.pdf)

    def test_uncertified_wait_shape_refuses_before_launch(self):
        from unittest.mock import patch
        from reporting import adapters
        with (patch.object(self.route.dis, "get_instructions", return_value=()),
              patch.object(adapters, "_start_pdf_render_worker") as start):
            with self.assertRaises(ValueError):
                self.route._run_owned_child([], {}, ())
            start.assert_not_called()
            with self.scope():
                pass

    def test_uncertain_traceback_evidence_never_authorizes_cleanup(self):
        controller, waiter, other = object(), object(), object()
        def traceback_record(code, offset, following=None):
            return SimpleNamespace(tb_frame=SimpleNamespace(f_code=code), tb_lasti=offset, tb_next=following)
        pre = traceback_record(controller, 24)
        entered = traceback_record(waiter, 0)
        deep = pre
        for _ in range(32):
            deep = traceback_record(other, 24, deep)
        for tb in (None, traceback_record(other, 24), traceback_record(controller, 26),
                   traceback_record(controller, 24, pre), traceback_record(controller, 24, entered), deep):
            with self.subTest(traceback=tb):
                error = SimpleNamespace(__traceback__=tb)
                self.assertFalse(self.route._confirmed_pre_wait(error, controller, waiter, {24}))


    def test_child_audit_failure_writes_bounded_fail_without_profile_reaudit(self):
        import json
        from pathlib import Path
        import subprocess
        import sys
        root = Path(self.route.__file__).resolve().parents[1]
        program = """
import json, os, runpy, sys, tempfile
from contextlib import ExitStack
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from reporting import _pdf_render_worker as base, _pdf_process_sandbox as sandbox
from reporting import _pdf_typed_brand_emission as core, pdf_typed_brand_render as route
from reporting import pdf_raster_render as inherited
events = []
limits = {"memory_bytes":1073741824,"cpu_seconds":20,"file_bytes":16777216,"open_files":128}
def stage(name, result=None):
    def run(*args, **kwargs):
        events.append(name)
        return result
    return run
base._apply_resource_limits = stage("limits", limits)
base._arm_worker_lifetime = stage("lifetime")
sandbox.enforce_pdf_landlock = stage("landlock")
sandbox.enforce_pdf_network_filter = stage("network")
def forbidden(*args, **kwargs):
    raise AssertionError("failure repeated an audit or crossed input admission")
scenario = sys.argv[2]
audit = route.require_policy
def checked_audit():
    events.append("audit")
    if scenario == "audit":
        raise ValueError("PRIVATE source drift detail")
    digest = audit()
    core.profile_sha256 = forbidden
    return digest
def failed_reader(*args, **kwargs):
    events.append("reader")
    raise ValueError("PRIVATE input detail")
route.require_policy = checked_audit
base.native_render_profile_sha256 = forbidden
if scenario == "audit":
    core.profile_sha256 = forbidden
inherited.read_raster_inputs = failed_reader
core.install_in_isolated_render_worker = stage("finisher")
base._render = forbidden
with ExitStack() as stack:
    files = [stack.enter_context(tempfile.TemporaryFile()) for _ in range(4)]
    fds = [file.fileno() for file in files]
    script = Path(core.__file__).with_name("_pdf_typed_brand_render_worker.py")
    sys.argv = [str(script), *map(str, fds[:3]), str(os.getpid()), core.MODE, str(fds[3])]
    try:
        runpy.run_path(str(script), run_name="__main__")
    except SystemExit as stopped:
        code = stopped.code
    raw = os.pread(fds[2], 65537, 0)
    print(json.dumps({"code":code,"record":json.loads(raw),"bytes":len(raw),
                      "pdf_bytes":os.fstat(fds[1]).st_size,"events":events}))
"""
        import tempfile
        for scenario in ("audit", "reader"):
            with self.subTest(scenario=scenario):
                result = subprocess.run([sys.executable, "-I", "-B", "-c", program, str(root), scenario],
                                        capture_output=True, text=True, check=True, timeout=10)
                observed = json.loads(result.stdout)
                self.assertEqual(observed["code"], 0)
                stages = ["limits", "lifetime", "landlock", "network", "audit"]
                if scenario == "reader":
                    stages += ["finisher", "reader"]
                self.assertEqual(observed["events"], stages)
                self.assertEqual(observed["pdf_bytes"], 0)
                self.assertLessEqual(observed["bytes"], 65536)
                expected = {"protocol_version": 1, "status": "FAIL",
                    "error": "pdf_render_protocol_invalid",
                    "limits": {"memory_bytes": 1073741824, "cpu_seconds": 20,
                               "file_bytes": 16777216, "open_files": 128}}
                if scenario == "reader":
                    expected.update(protocol_version=3, profile_id="typed-original-brand-render-v1",
                                    profile_sha256=self.profile)
                self.assertEqual(observed["record"], expected)
                self.assertNotIn("PRIVATE", result.stdout)
                with tempfile.TemporaryFile() as output, self.assertRaises(ValueError):
                    self.route._decode(json.dumps(observed["record"]).encode(), output.fileno(),
                        self.args["expected_html_sha256"], self.bundle.bundle_sha256, 1, self.profile)

    def test_prelaunch_preparation_failure_releases_reserved_custody(self):
        import errno
        import os
        from contextlib import ExitStack
        from unittest.mock import patch
        from reporting import adapters, _pdf_native_launch_budget as budget
        self.enterContext(patch.object(budget, "_TYPED_RENDER", None))
        failed = OSError(errno.EMFILE, "descriptor capacity")
        for stage in ("stdio", "cwd"):
            with self.subTest(stage=stage), ExitStack() as stack:
                if stage == "stdio":
                    preparation = stack.enter_context(patch("builtins.open", side_effect=failed))
                else:
                    preparation = stack.enter_context(patch.object(adapters.Path, "resolve", side_effect=failed))
                spawn = stack.enter_context(patch.object(adapters.subprocess, "Popen", side_effect=failed))
                with self.assertRaises(OSError) as caught:
                    self.route._run_owned_child([], {}, ())
                self.assertIs(caught.exception, failed)
                if stage == "stdio":
                    preparation.assert_called_once_with(os.devnull, "r+b", buffering=0)
                else:
                    preparation.assert_called_once_with()
                spawn.assert_not_called()
            self.assertIsNone(budget._TYPED_RENDER)
            with self.scope():
                pass
            with budget.reserve_standalone_typed_render():
                pass

    def test_confirmed_timeout_cleanup_releases_custody_without_a_result(self):
        import subprocess
        from unittest.mock import patch
        from reporting import adapters, _pdf_native_launch_budget as budget
        from test_reporting_pdf_process_lifecycle import real_child
        self.enterContext(patch.object(budget, "_TYPED_RENDER", None))
        original = adapters._wait_pdf_render_worker
        with real_child("import time; time.sleep(30)") as child:
            def launch(*args, **kwargs):
                if "before_spawn" in kwargs:
                    kwargs["before_spawn"]()
                return child
            def wait(process, *, wall_seconds, cleanup_observer=None):
                options = {} if cleanup_observer is None else {"cleanup_observer": cleanup_observer}
                return original(process, wall_seconds=0.02, **options)
            with (patch.object(adapters, "_start_pdf_render_worker", side_effect=launch),
                  patch.object(adapters, "_wait_pdf_render_worker", new=wait),
                  self.assertRaisesRegex(RuntimeError, "^pdf_render_failed$") as caught):
                self.route._run_owned_child([], {}, ())
            self.assertIsInstance(caught.exception.__cause__, subprocess.TimeoutExpired)
            self.assertEqual(child.returncode, -9)
        self.assertIsNone(budget._TYPED_RENDER)
        with self.scope():
            pass

    def test_proved_pre_wait_timeout_cleanup_preserves_original_interruption(self):
        import inspect
        import sys
        from contextlib import ExitStack
        from unittest.mock import patch
        from reporting import adapters, _pdf_native_launch_budget as budget
        from test_reporting_pdf_process_lifecycle import real_child
        self.enterContext(patch.object(budget, "_TYPED_RENDER", None))
        fn = self.route._run_owned_child
        lines, first = inspect.getsourcelines(fn)
        handoff = first + next(i for i, line in enumerate(lines)
            if line.strip().startswith("status = waiter(process, wall_seconds=wall"))
        interruption = KeyboardInterrupt("known pre-wait boundary")
        original = adapters._wait_pdf_render_worker
        calls = []
        with real_child("import time; time.sleep(30)") as child, ExitStack() as stack:
            def launch(*args, **kwargs):
                if "before_spawn" in kwargs:
                    kwargs["before_spawn"]()
                return child
            def wait(process, *, wall_seconds, cleanup_observer=None):
                calls.append(wall_seconds)
                options = {} if cleanup_observer is None else {"cleanup_observer": cleanup_observer}
                return original(process, wall_seconds=wall_seconds, **options)
            def interrupt(frame, event, arg):
                if frame.f_code is fn.__code__ and event == "line" and frame.f_lineno == handoff:
                    raise interruption
                return interrupt
            stack.enter_context(patch.object(adapters, "_start_pdf_render_worker", side_effect=launch))
            stack.enter_context(patch.object(adapters, "_wait_pdf_render_worker", new=wait))
            stack.callback(sys.settrace, sys.gettrace())
            sys.settrace(interrupt)
            with self.assertRaises(KeyboardInterrupt) as caught:
                fn([], {}, ())
            self.assertIs(caught.exception, interruption)
            self.assertEqual(calls, [0])
            self.assertEqual(child.returncode, -9)
        self.assertIsNone(budget._TYPED_RENDER)
        with self.scope():
            pass

    def test_actual_adapter_pre_lifecycle_interrupt_reaps_and_releases_custody(self):
        from contextlib import ExitStack
        import dis
        import inspect
        import os
        import sys
        from unittest.mock import patch
        from reporting import adapters, _pdf_native_launch_budget as budget
        from reporting import _pdf_process_lifecycle as lifecycle
        from test_reporting_pdf_process_lifecycle import (
            REAL_WAITID, WAIT_FLAGS, real_child, signal_observer)
        adapter_code = adapters._wait_pdf_render_worker.__code__
        lifecycle_code = lifecycle.wait_owned_process_group.__code__
        self.assertIs(adapters.wait_owned_process_group, lifecycle.wait_owned_process_group)
        lines, first = inspect.getsourcelines(adapters._wait_pdf_render_worker)
        options_line = first + next(i for i, line in enumerate(lines)
                                   if line.strip().startswith("options = "))
        instructions = tuple(dis.get_instructions(adapter_code, adaptive=False, show_caches=False))
        delegation = [i for i, op in enumerate(instructions) if op.opname == "CALL_FUNCTION_EX"]
        self.assertEqual(len(delegation), 1)
        prefix = instructions[delegation[0] - 1]
        self.assertEqual(prefix.opname, "DICT_MERGE")
        for case in ("options-line", "last-prefix-opcode"):
            with self.subTest(case=case), patch.object(budget, "_TYPED_RENDER", None):
                with real_child("import time; time.sleep(30)") as child, ExitStack() as stack:
                    interruption = KeyboardInterrupt("adapter interrupted before lifecycle delegation")
                    adapter_calls, lifecycle_calls, observations = [], [], []
                    trapped = []
                    def launch(*args, **kwargs):
                        kwargs["before_spawn"]()
                        return child
                    def profile(frame, event, arg):
                        if event == "call" and frame.f_code in (adapter_code, lifecycle_code):
                            self.assertIs(frame.f_locals["process"], child)
                            calls = adapter_calls if frame.f_code is adapter_code else lifecycle_calls
                            calls.append(frame.f_locals["wall_seconds"])
                    def interrupt(frame, event, arg):
                        if frame.f_code is adapter_code:
                            frame.f_trace_opcodes = case == "last-prefix-opcode"
                            at_prefix = (event == "opcode" and frame.f_lasti == prefix.offset
                                         if case == "last-prefix-opcode" else
                                         event == "line" and frame.f_lineno == options_line)
                            if at_prefix and not trapped:
                                trapped.append(frame.f_lasti)
                                raise interruption
                        return interrupt
                    start = stack.enter_context(patch.object(
                        adapters, "_start_pdf_render_worker", side_effect=launch))
                    stack.enter_context(signal_observer(child, observations))
                    test_frame = sys._getframe()
                    stack.callback(setattr, test_frame, "f_trace_opcodes", test_frame.f_trace_opcodes)
                    test_frame.f_trace_opcodes = case == "last-prefix-opcode"
                    stack.callback(sys.setprofile, sys.getprofile())
                    stack.callback(sys.settrace, sys.gettrace())
                    sys.setprofile(profile)
                    sys.settrace(interrupt)
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        self.route._run_owned_child([], {}, ())
                    self.assertIs(caught.exception, interruption)
                    start.assert_called_once()
                    self.assertEqual(len(trapped), 1)
                    self.assertEqual(adapter_calls, [30, 0])
                    self.assertEqual(lifecycle_calls, [0])
                    self.assertEqual(child.returncode, -9)
                    with self.assertRaises(ChildProcessError):
                        REAL_WAITID(os.P_PID, child.pid, WAIT_FLAGS)
                    self.assertEqual([kind for kind, _, _ in observations if kind == "group"], ["group"])
                    self.assertTrue(all(owned for _, owned, _ in observations), observations)
                self.assertIsNone(budget._TYPED_RENDER)
                with self.scope():
                    pass
                with budget.reserve_standalone_typed_render():
                    pass

    def test_actual_adapter_delegation_boundary_never_retries_cleanup(self):
        from contextlib import ExitStack
        import dis
        import os
        import sys
        from unittest.mock import patch
        from reporting import adapters, _pdf_native_launch_budget as budget
        from reporting import _pdf_process_lifecycle as lifecycle
        from test_reporting_pdf_process_lifecycle import REAL_WAITID, WAIT_FLAGS, real_child
        adapter_code = adapters._wait_pdf_render_worker.__code__
        lifecycle_code = lifecycle.wait_owned_process_group.__code__
        calls = [op.offset for op in dis.get_instructions(adapter_code, adaptive=False, show_caches=False)
                 if op.opname == "CALL_FUNCTION_EX"]
        self.assertEqual(len(calls), 1)
        for case in ("delegation-call", "entered-lifecycle"):
            with self.subTest(case=case), patch.object(budget, "_TYPED_RENDER", None):
                with real_child("import time; time.sleep(30)") as child, ExitStack() as stack:
                    interruption = KeyboardInterrupt("lifecycle entry is not a cleanup receipt")
                    adapter_calls, lifecycle_calls, trapped = [], [], []
                    def launch(*args, **kwargs):
                        kwargs["before_spawn"]()
                        return child
                    def profile(frame, event, arg):
                        if event == "call" and frame.f_code in (adapter_code, lifecycle_code):
                            self.assertIs(frame.f_locals["process"], child)
                            seen = adapter_calls if frame.f_code is adapter_code else lifecycle_calls
                            seen.append(frame.f_locals["wall_seconds"])
                    def interrupt(frame, event, arg):
                        if frame.f_code is adapter_code:
                            frame.f_trace_opcodes = case == "delegation-call"
                        at_boundary = (case == "delegation-call" and frame.f_code is adapter_code
                                       and event == "opcode" and frame.f_lasti == calls[0])
                        inside_lifecycle = (case == "entered-lifecycle" and frame.f_code is lifecycle_code
                                            and event == "line")
                        if (at_boundary or inside_lifecycle) and not trapped:
                            trapped.append(frame.f_lasti)
                            raise interruption
                        return interrupt
                    start = stack.enter_context(patch.object(
                        adapters, "_start_pdf_render_worker", side_effect=launch))
                    test_frame = sys._getframe()
                    stack.callback(setattr, test_frame, "f_trace_opcodes", test_frame.f_trace_opcodes)
                    test_frame.f_trace_opcodes = case == "delegation-call"
                    stack.callback(sys.setprofile, sys.getprofile())
                    stack.callback(sys.settrace, sys.gettrace())
                    sys.setprofile(profile)
                    sys.settrace(interrupt)
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        self.route._run_owned_child([], {}, ())
                    self.assertIs(caught.exception, interruption)
                    start.assert_called_once()
                    self.assertEqual(len(trapped), 1)
                    self.assertEqual(adapter_calls, [30])
                    self.assertEqual(lifecycle_calls, [] if case == "delegation-call" else [30])
                    self.assertIsNone(child.returncode)
                    self.assertIsNone(REAL_WAITID(os.P_PID, child.pid, WAIT_FLAGS))
                    self.assertEqual(budget._TYPED_RENDER.phase, "quarantined")
                    with self.assertRaises(ValueError), self.scope():
                        pass
                    with self.assertRaises(ValueError), budget.reserve_standalone_typed_render():
                        pass

    def test_unknown_waiter_frame_cannot_authorize_adapter_prefix_recovery(self):
        from contextlib import ExitStack
        import inspect
        import os
        import sys
        from unittest.mock import patch
        from reporting import adapters, _pdf_native_launch_budget as budget
        from reporting import _pdf_process_lifecycle as lifecycle
        from test_reporting_pdf_process_lifecycle import REAL_WAITID, WAIT_FLAGS, real_child
        original = adapters._wait_pdf_render_worker
        lifecycle_code = lifecycle.wait_owned_process_group.__code__
        lines, first = inspect.getsourcelines(original)
        options_line = first + next(i for i, line in enumerate(lines)
                                   if line.strip().startswith("options = "))
        with patch.object(budget, "_TYPED_RENDER", None):
            with real_child("import time; time.sleep(30)") as child, ExitStack() as stack:
                interruption = KeyboardInterrupt("an unknown wrapper interrupts the proof chain")
                waiter_calls, lifecycle_calls, trapped = [], [], []
                def launch(*args, **kwargs):
                    kwargs["before_spawn"]()
                    return child
                def wait(process, *, wall_seconds, cleanup_observer):
                    waiter_calls.append(wall_seconds)
                    return original(process, wall_seconds=wall_seconds, cleanup_observer=cleanup_observer)
                def profile(frame, event, arg):
                    if event == "call" and frame.f_code is lifecycle_code:
                        lifecycle_calls.append(frame.f_locals["wall_seconds"])
                def interrupt(frame, event, arg):
                    if (frame.f_code is original.__code__ and event == "line"
                            and frame.f_lineno == options_line and not trapped):
                        trapped.append(frame.f_lasti)
                        raise interruption
                    return interrupt
                start = stack.enter_context(patch.object(
                    adapters, "_start_pdf_render_worker", side_effect=launch))
                stack.enter_context(patch.object(adapters, "_wait_pdf_render_worker", new=wait))
                stack.callback(sys.setprofile, sys.getprofile())
                stack.callback(sys.settrace, sys.gettrace())
                sys.setprofile(profile)
                sys.settrace(interrupt)
                with self.assertRaises(KeyboardInterrupt) as caught:
                    self.route._run_owned_child([], {}, ())
                self.assertIs(caught.exception, interruption)
                start.assert_called_once()
                self.assertEqual(len(trapped), 1)
                self.assertEqual(waiter_calls, [30])
                self.assertEqual(lifecycle_calls, [])
                self.assertIsNone(child.returncode)
                self.assertIsNone(REAL_WAITID(os.P_PID, child.pid, WAIT_FLAGS))
                self.assertEqual(budget._TYPED_RENDER.phase, "quarantined")
                with self.assertRaises(ValueError), self.scope():
                    pass
                with self.assertRaises(ValueError), budget.reserve_standalone_typed_render():
                    pass


    def test_failed_group_cleanup_keeps_reaped_child_custody_quarantined(self):
        from unittest.mock import patch
        from reporting import adapters, _pdf_native_launch_budget as budget
        from test_reporting_pdf_process_lifecycle import real_child, signal_observer
        original = adapters._wait_pdf_render_worker
        with patch.object(budget, "_TYPED_RENDER", None):
            with real_child("import time; time.sleep(30)") as child:
                def launch(*args, **kwargs):
                    if "before_spawn" in kwargs:
                        kwargs["before_spawn"]()
                    return child
                def wait(process, *, wall_seconds, cleanup_observer=None):
                    options = {} if cleanup_observer is None else {"cleanup_observer": cleanup_observer}
                    return original(process, wall_seconds=0.02, **options)
                with (patch.object(adapters, "_start_pdf_render_worker", side_effect=launch),
                      patch.object(adapters, "_wait_pdf_render_worker", new=wait),
                      signal_observer(child, [], group_error=PermissionError("group refused")),
                      self.assertRaises(RuntimeError)):
                    self.route._run_owned_child([], {}, ())
                self.assertEqual(child.returncode, -9)
            self.assertEqual(budget._TYPED_RENDER.phase, "quarantined")
            with self.assertRaises(ValueError), self.scope():
                pass

    def test_integer_wait_without_cleanup_receipt_cannot_return_a_result(self):
        from unittest.mock import patch
        from reporting import adapters, _pdf_native_launch_budget as budget
        def launch(*args, **kwargs):
            if "before_spawn" in kwargs:
                kwargs["before_spawn"]()
            return object()
        def wait(process, *, wall_seconds, cleanup_observer=None):
            return 0
        with patch.object(budget, "_TYPED_RENDER", None):
            with (patch.object(adapters, "_start_pdf_render_worker", side_effect=launch),
                  patch.object(adapters, "_wait_pdf_render_worker", new=wait),
                  self.assertRaises(ValueError)):
                self.route._run_owned_child([], {}, ())
            self.assertEqual(budget._TYPED_RENDER.phase, "quarantined")

    def _observe_child_final_profile(self, scenario):
        import base64
        import json
        from pathlib import Path
        import subprocess
        import sys
        root = Path(self.route.__file__).resolve().parents[1]
        fixture_input = {"html": self.args["html"],
                         "resources_base64": base64.b64encode(self.bundle.to_bytes()).decode("ascii"),
                         "pdf_base64": base64.b64encode(self.pdf).decode("ascii")}
        # The existing startup seams and deterministic renderer do not qualify
        # native rendering, resource limits, lifetime, Landlock or network policy.
        program = r"""
import base64, json, os, runpy, stat, sys, tempfile
from contextlib import ExitStack
from hashlib import sha256
from pathlib import Path
sys.path.insert(0, sys.argv[1])
scenario = sys.argv[2]
fixture = json.loads(sys.argv[3])
from reporting import _pdf_render_worker as base, _pdf_process_sandbox as sandbox
from reporting import _pdf_typed_brand_emission as core, pdf_typed_brand_render as route
events, audits, admissions = [], [], []
after_render = False
html_bytes = fixture["html"].encode("utf-8")
resource_bytes = base64.b64decode(fixture["resources_base64"], validate=True)
pdf_fixture = base64.b64decode(fixture["pdf_base64"], validate=True)
html_digest = sha256(html_bytes).hexdigest()
resource_digest = sha256(resource_bytes).hexdigest()
raw_a = core.MANIFEST.read_bytes()
raw_b = raw_a + b"\n"
assert 0 < len(raw_b) <= 16384 and json.loads(raw_a) == json.loads(raw_b)
digest_a, digest_b = sha256(raw_a).hexdigest(), sha256(raw_b).hexdigest()
assert digest_a != digest_b
limits = {"memory_bytes": base.MEMORY_BYTES, "cpu_seconds": base.CPU_SECONDS,
          "file_bytes": base.NATIVE_PDF_BYTES, "open_files": base.OPEN_FILES}
def startup(name, result=None):
    def observe(*args, **kwargs):
        events.append(name)
        return result
    return observe
base._apply_resource_limits = startup("limits_fixture", limits)
base._arm_worker_lifetime = startup("lifetime_fixture")
sandbox.enforce_pdf_landlock = startup("landlock_fixture")
sandbox.enforce_pdf_network_filter = startup("network_fixture")
original_profile = core.profile_sha256
def observed_profile():
    phase = "after_render" if after_render else "before_render"
    try:
        digest = original_profile()
    except Exception:
        audits.append({"phase": phase, "status": "refused"})
        raise
    audits.append({"phase": phase, "status": "verified", "digest": digest})
    return digest
core.profile_sha256 = observed_profile
original_policy = route.require_policy
def observed_admission():
    digest = original_policy()
    admissions.append(digest)
    return digest
route.require_policy = observed_admission
with tempfile.TemporaryDirectory(prefix="typed-brand-profile-") as directory, ExitStack() as stack:
    manifest = Path(directory) / "profile.json"
    manifest.write_bytes(raw_b if scenario == "drift" else raw_a)
    core.MANIFEST = manifest
    def render_fixture(html, digest, **options):
        global after_render
        assert html == fixture["html"] and digest == html_digest
        assert options["resources"].bundle_sha256 == resource_digest
        assert options["max_pdf_bytes"] == base.NATIVE_PDF_BYTES
        events.append("render_fixture")
        manifest.write_bytes(b"{" if scenario == "audit_failure" else raw_a)
        after_render = True
        return pdf_fixture, None
    def page_count_fixture(pdf):
        assert pdf == pdf_fixture
        events.append("page_count_fixture")
        return 1, None
    base._render = render_fixture
    base._discover_page_count = page_count_fixture
    files = [stack.enter_context(tempfile.TemporaryFile()) for _ in range(4)]
    fds = [file.fileno() for file in files]
    anonymous = len(set(fds)) == 4 and all(
        stat.S_ISREG(os.fstat(fd).st_mode) and os.fstat(fd).st_nlink == 0 for fd in fds)
    files[0].write(f"3 {html_digest} {resource_digest}\n".encode("ascii") + html_bytes)
    files[0].flush()
    files[0].seek(0)
    files[3].write(resource_bytes)
    files[3].flush()
    files[3].seek(0)
    script = Path(core.__file__).with_name("_pdf_typed_brand_render_worker.py")
    sys.argv = [str(script), *map(str, fds[:3]), str(os.getppid()), core.MODE, str(fds[3])]
    try:
        runpy.run_path(str(script), run_name="__main__")
    except SystemExit as stopped:
        code = stopped.code
    response = os.pread(fds[2], base.RESULT_BYTES + 1, 0)
    pdf = os.pread(fds[1], base.NATIVE_PDF_BYTES + 1, 0)
    observation = {"code": code, "record": json.loads(response) if response else None,
                   "response_bytes": len(response), "pdf_bytes": len(pdf),
                   "pdf_base64": base64.b64encode(pdf).decode("ascii"),
                   "digest_a": digest_a, "digest_b": digest_b,
                   "admissions": admissions, "audits": audits, "events": events,
                   "anonymous_descriptors": anonymous, "isolated": sys.flags.isolated,
                   "dont_write_bytecode": sys.dont_write_bytecode}
print(json.dumps(observation))
"""
        completed = subprocess.run([sys.executable, "-I", "-B", "-c", program,
                                    str(root), scenario, json.dumps(fixture_input)],
                                   capture_output=True, text=True, check=True, timeout=20)
        observed = json.loads(completed.stdout)
        self.assertEqual(observed["isolated"], 1)
        self.assertTrue(observed["dont_write_bytecode"])
        self.assertTrue(observed["anonymous_descriptors"])
        self.assertEqual(observed["digest_a"], self.profile)
        self.assertNotEqual(observed["digest_a"], observed["digest_b"])
        self.assertEqual(observed["events"], ["limits_fixture", "lifetime_fixture",
                         "landlock_fixture", "network_fixture", "render_fixture",
                         "page_count_fixture"])
        return observed

    def test_child_profile_drift_after_admission_refuses_pass(self):
        observed = self._observe_child_final_profile("drift")
        self.assertEqual(observed["admissions"], [observed["digest_b"]])
        self.assertEqual(observed["audits"], [
            {"phase": "before_render", "status": "verified", "digest": observed["digest_b"]},
            {"phase": "before_render", "status": "verified", "digest": observed["digest_b"]},
            {"phase": "after_render", "status": "verified", "digest": observed["digest_a"]},
        ])
        self.assertEqual(observed["code"], 70, observed)
        self.assertEqual(observed["pdf_bytes"], 0)
        self.assertEqual(observed["response_bytes"], 0)
        self.assertIsNone(observed["record"])

    def test_child_final_profile_audit_preserves_match_and_refuses_failure(self):
        import base64
        for scenario in ("stable", "audit_failure"):
            with self.subTest(scenario=scenario):
                observed = self._observe_child_final_profile(scenario)
                self.assertEqual(observed["admissions"], [self.profile])
                expected_audits = [
                    {"phase": "before_render", "status": "verified", "digest": self.profile},
                    {"phase": "before_render", "status": "verified", "digest": self.profile},
                ]
                if scenario == "stable":
                    expected_audits.append({"phase": "after_render", "status": "verified",
                                            "digest": self.profile})
                    self.assertEqual(observed["code"], 0)
                    self.assertEqual(observed["record"], self.record)
                    self.assertGreater(observed["response_bytes"], 0)
                    self.assertLessEqual(observed["response_bytes"], 65536)
                    self.assertEqual(base64.b64decode(observed["pdf_base64"], validate=True), self.pdf)
                else:
                    expected_audits.append({"phase": "after_render", "status": "refused"})
                    self.assertEqual(observed["code"], 70)
                    self.assertEqual(observed["pdf_bytes"], 0)
                    self.assertEqual(observed["response_bytes"], 0)
                    self.assertIsNone(observed["record"])
                self.assertEqual(observed["audits"], expected_audits)


class EditorialBrandEmissionTests(unittest.TestCase):
    def source_page(self, marked=True):
        from xml.etree.ElementTree import Element, SubElement
        from weasyprint.formatting_structure.boxes import Box
        root = Element("html")
        SubElement(root, "head")
        body = SubElement(root, "body")
        cover = SubElement(body, "section")
        if marked:
            cover.set("data-editorial-ir-sha256", "a" * 64)
        cover_box = Box("section", {}, cover)
        body_box = Box("body", {}, body)
        body_box.children = [cover_box]
        html_box = Box("html", {}, root)
        html_box.children = [body_box]
        page = Box("page", {}, None)
        page.children = [html_box]
        return page, root, body, cover

    def footer_page(self):
        from weasyprint.formatting_structure.boxes import Box, LineBox, MarginBox, TextBox
        expected = "OmniGenis | " + "a" * 12 + " | 2"
        text = TextBox(None, {}, None, expected)
        line = LineBox(None, {}, None, [text])
        margin = MarginBox("@bottom-right", {})
        margin.children = [line]
        page = Box("page", {}, None)
        page.children = [margin]
        return page, margin, line, text, expected

    def test_editorial_source_binds_full_ir_to_first_source_section(self):
        from reporting._pdf_typed_brand_emission import _editorial_source
        page, root, body, cover = self.source_page()
        html, admitted, digest = _editorial_source(page)
        self.assertIs(html, page.children[0])
        self.assertIs(html.element, root)
        self.assertIs(admitted, body[0])
        self.assertIs(admitted, cover)
        self.assertEqual(digest, "a" * 64)

    def test_unmarked_or_synthetic_legacy_page_does_not_opt_in(self):
        from reporting._pdf_typed_brand_emission import _editorial_source
        page, _, _, _ = self.source_page(marked=False)
        html = page.children[0]
        self.assertEqual(_editorial_source(page), (html, None, None))
        html.element = None
        self.assertEqual(_editorial_source(page), (html, None, None))
        page.children = []
        self.assertEqual(_editorial_source(page), (None, None, None))

    def test_invalid_duplicate_or_late_editorial_markers_refuse(self):
        from xml.etree.ElementTree import Element, SubElement
        from reporting._pdf_typed_brand_emission import _editorial_source
        for case in ("short", "uppercase", "newline", "empty", "duplicate",
                     "late", "nested", "wrong-tag", "outside-body", "prior-text"):
            with self.subTest(case=case):
                page, root, body, cover = self.source_page()
                if case in ("short", "uppercase", "newline", "empty"):
                    cover.set("data-editorial-ir-sha256", {
                        "short": "a" * 63, "uppercase": "A" * 64,
                        "newline": "a" * 64 + "\n", "empty": ""}[case])
                elif case == "duplicate":
                    SubElement(body, "section", {"data-editorial-ir-sha256": "a" * 64})
                elif case == "late":
                    body.insert(0, Element("p"))
                elif case == "nested":
                    body.remove(cover)
                    SubElement(body, "div").append(cover)
                elif case == "wrong-tag":
                    cover.tag = "div"
                elif case == "outside-body":
                    body.remove(cover)
                    root[0].append(cover)
                else:
                    body.text = "Unaccounted cover prefix"
                with self.assertRaises(ValueError):
                    _editorial_source(page)

    def test_editorial_marker_scan_refuses_excess_source_nodes(self):
        from xml.etree.ElementTree import SubElement
        from reporting._pdf_typed_brand_emission import _editorial_source
        for marked in (False, True):
            with self.subTest(editorial_opt_in=marked):
                page, _, body, _ = self.source_page(marked=marked)
                for _ in range(20000):
                    SubElement(body, "span")
                if marked:
                    with self.assertRaises(ValueError):
                        _editorial_source(page)
                else:
                    self.assertEqual(_editorial_source(page),
                                     (page.children[0], None, None))


    def test_cover_title_keeps_original_art_clear_and_allows_safe_ink_overhang(self):
        from unittest.mock import Mock, patch
        from xml.etree.ElementTree import Element, SubElement
        from weasyprint.formatting_structure import boxes
        from weasyprint.layout.absolute import AbsolutePlaceholder
        from reporting._pdf_typed_brand_emission import _editorial_cover_title

        def geometry(box, x, y, width, height):
            box.position_x, box.position_y = x, y
            box.width, box.height = width, height
            for side in ("left", "right", "top", "bottom"):
                setattr(box, "margin_" + side, 0)
                setattr(box, "padding_" + side, 0)
                setattr(box, "border_" + side + "_width", 0)
            return box

        cases = (
            ("normal", (5, -50, 190, 50), (350, 400), True),
            ("safe-gap-overhang", (-20, -100, 210, 100), (350, 400), True),
            ("ink-in-dna", (-70, -50, 190, 50), (350, 400), False),
            ("ink-in-logo", (5, -180, 190, 50), (350, 400), False),
            ("box-in-dna", (5, -50, 190, 50), (280, 400), False),
            ("box-in-logo", (5, -50, 190, 50), (350, 280), False),
        )
        for name, extents, title_position, admitted in cases:
            with self.subTest(name=name):
                source = Element("section")
                dna_source = SubElement(source, "div", {"data-brand": "original-dna"})
                logo_source = SubElement(source, "div", {"data-brand": "original-logo"})
                title_source = SubElement(source, "h1")
                text = geometry(boxes.TextBox("h1", {}, title_source, "Cover title"),
                                350, 400, 200, 60)
                text.baseline = 60
                layout = SimpleNamespace(
                    layout=object(), reactivate=Mock(), deactivate=Mock(),
                    get_first_line=Mock(return_value=(object(), None)))
                text.pango_layout = layout
                line = geometry(boxes.LineBox("h1", {}, title_source, [text]),
                                350, 400, 500, 80)
                title = geometry(boxes.BlockBox("h1", {}, title_source, [line]),
                                 *title_position, 500, 100)
                dna = geometry(boxes.BlockBox("div", {}, dna_source, []),
                               50, 50, 250, 900)
                logo = geometry(boxes.BlockBox("div", {}, logo_source, []),
                                350, 200, 300, 100)
                cover = geometry(boxes.BlockBox("section", {}, source,
                    [AbsolutePlaceholder(box) for box in (dna, logo, title)]),
                    50, 50, 900, 900)
                page = geometry(boxes.Box("page", {}, None), 0, 0, 1000, 1000)

                def measure(_line, ink, _logical):
                    ink.x, ink.y, ink.width, ink.height = extents

                with patch("weasyprint.text.ffi.pango") as pango, \
                     patch("weasyprint.text.ffi.FROM_UNITS", 1):
                    pango.pango_layout_line_get_extents.side_effect = measure
                    if admitted:
                        _editorial_cover_title(page, cover)
                    else:
                        with self.assertRaises(ValueError):
                            _editorial_cover_title(page, cover)
                    if name.startswith("box-"):
                        pango.pango_layout_line_get_extents.assert_not_called()
                        layout.reactivate.assert_not_called()
                    else:
                        pango.pango_layout_line_get_extents.assert_called_once()
                        layout.deactivate.assert_called_once()

    def test_navigation_row_requires_complete_in_page_layout(self):
        from xml.etree.ElementTree import Element
        from weasyprint.formatting_structure import boxes
        from reporting._pdf_typed_brand_emission import _editorial_navigation_row

        def geometry(box, x, y, width, height):
            box.position_x, box.position_y = x, y
            box.width, box.height = width, height
            for side in ("left", "right", "top", "bottom"):
                setattr(box, "margin_" + side, 0)
                setattr(box, "padding_" + side, 0)
                setattr(box, "border_" + side + "_width", 0)
            return box

        cases = (
            ("normal", (100, 100, 700, 40), set(), "slice", True),
            ("multiline", (100, 100, 700, 240), set(), "slice", True),
            ("exact-page-boundary", (50, 50, 800, 1100), set(), "slice", True),
            ("incomplete-bottom", (100, 100, 700, 40), {"bottom"}, "slice", False),
            ("continued-top", (100, 100, 700, 40), {"top"}, "slice", False),
            ("continued-middle", (100, 100, 700, 40), {"top", "bottom"}, "slice", False),
            ("outside-left", (49, 100, 700, 40), set(), "slice", False),
            ("outside-top", (100, 49, 700, 40), set(), "slice", False),
            ("outside-right", (100, 100, 751, 40), set(), "slice", False),
            ("outside-bottom", (100, 1100, 700, 51), set(), "slice", False),
            ("unadmitted-cloned-decoration", (100, 100, 700, 40), set(), "clone", False),
        )
        for name, bounds, removed, decoration, admitted in cases:
            with self.subTest(case=name):
                page = geometry(boxes.Box("page", {}, None), 50, 50, 800, 1100)
                element = Element("p", {"data-editorial-nav-target": "#heading"})
                row = geometry(boxes.BlockBox("p", {"box_decoration_break": decoration},
                                               element, []), *bounds)
                row.remove_decoration_sides = removed
                if admitted:
                    _editorial_navigation_row(page, row)
                else:
                    with self.assertRaises(ValueError):
                        _editorial_navigation_row(page, row)

    def test_exact_footer_admits_only_one_generated_text_leaf(self):
        from reporting._pdf_typed_brand_emission import _editorial_footer
        page, margin, _, text, expected = self.footer_page()
        admitted_margin, admitted_text = _editorial_footer(page, expected)
        self.assertIs(admitted_margin, margin)
        self.assertIs(admitted_text, text)
        self.assertEqual(text.children, [])
        self.assertIsNone(text.element)

    def test_extra_wrapped_or_forged_footer_content_refuses(self):
        from xml.etree.ElementTree import Element
        from weasyprint.formatting_structure.boxes import Box, InlineBox, MarginBox
        from reporting._pdf_typed_brand_emission import _editorial_footer
        for case in ("missing", "duplicate", "other-margin", "position", "margin-element",
                     "missing-line", "extra-line", "wrong-line", "wrapped", "extra-text",
                     "wrong-identity", "wrong-page", "text-child", "text-element"):
            with self.subTest(case=case):
                page, margin, line, text, expected = self.footer_page()
                if case == "missing":
                    page.children = []
                elif case == "duplicate":
                    page.children.append(margin)
                elif case == "other-margin":
                    page.children.append(MarginBox("@top-left", {}))
                elif case == "position":
                    margin.at_keyword = "@bottom-left"
                elif case == "margin-element":
                    margin.element = Element("p")
                elif case == "missing-line":
                    margin.children = []
                elif case == "extra-line":
                    margin.children.append(line)
                elif case == "wrong-line":
                    margin.children = [Box(None, {}, None)]
                elif case == "wrapped":
                    line.children = [InlineBox(None, {}, None, [text])]
                elif case == "extra-text":
                    line.children = [text, text.copy_with_text("forged")]
                elif case == "wrong-identity":
                    text.text = "OmniGenis | " + "b" * 12 + " | 2"
                elif case == "wrong-page":
                    text.text = "OmniGenis | " + "a" * 12 + " | 3"
                elif case == "text-child":
                    text.children = [Box(None, {}, None)]
                else:
                    text.element = Element("p")
                with self.assertRaises(ValueError):
                    _editorial_footer(page, expected)

    def test_editorial_hook_installation_refuses_outside_exact_child(self):
        import sys
        from unittest.mock import patch
        import weasyprint.document as document_module
        import weasyprint.pdf.tags as tag_module
        import weasyprint.pdf.stream as stream_module
        from reporting import _pdf_typed_brand_emission as core
        from reporting.pdf_font_selection import LatoFontSelection
        before = (document_module.draw_page, tag_module._build_box_tree,
                  stream_module.Stream.marked, LatoFontSelection.__enter__,
                  LatoFontSelection.finisher)
        with patch.object(sys, "argv", ["unadmitted-editorial-test-entry"]):
            for install in (core.install_in_isolated_render_worker,
                            core._install_editorial_after_font_bootstrap):
                with self.assertRaises(ValueError):
                    install()
        after = (document_module.draw_page, tag_module._build_box_tree,
                 stream_module.Stream.marked, LatoFontSelection.__enter__,
                 LatoFontSelection.finisher)
        self.assertTrue(all(a is b for a, b in zip(before, after)))
