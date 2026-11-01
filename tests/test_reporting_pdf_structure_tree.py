"""Forward structural ownership and reverse page/MCID correspondence on synthetic PDFs."""
from __future__ import annotations

import ast
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
import importlib
import importlib.util
import json
import os
from pathlib import Path
from tempfile import TemporaryFile, NamedTemporaryFile
import unittest
from unittest.mock import patch

from pypdf.generic import (
    ArrayObject, BooleanObject, DictionaryObject, NameObject, NullObject,
    NumberObject, TextStringObject,
)
from reporting.page_windows import plan_pdf_page_windows
from reporting.pdf_text_windows import PROFILE_ID as TEXT_PROFILE
from reporting.pdf_mcid_coverage import inspect_pdf_mcid_coverage
from tests.test_reporting_pdf_document_content import changed_pdf
from tests.test_reporting_pdf_source_inspection_job import generated_job_case

ROOT = Path(__file__).resolve().parents[1]


def structure(writer):
    """Locate only the existing generated structural root and document in a fixture."""
    root_ref = writer._root_object.get('/StructTreeRoot')
    root = root_ref.get_object()
    document_ref = root['/K'][0]
    return root_ref, root, document_ref, document_ref.get_object()


def first_leaf(writer):
    """Return the first page's actual reverse-map leaf, not a guessed object number."""
    _, root, _, _ = structure(writer)
    return root['/ParentTree'].get_object()['/Nums'][1][0]


class PdfStructureTreeTests(unittest.TestCase):
    """Partial reverse ancestry cannot replace complete supported forward-tree linkage."""

    cases = None

    def setUp(self):
        """Observe the missing boundary as RED before constructing native fixtures."""
        self.assertIsNotNone(importlib.util.find_spec('reporting.pdf_structure_tree'),
                             'forward structural tree inspector is missing')
        self.m = importlib.import_module('reporting.pdf_structure_tree')
        self.worker = importlib.import_module('reporting._pdf_structure_tree_worker')
        if self.__class__.cases is None:
            self.__class__.cases = {n: generated_job_case(n)[1] for n in (1, 33, 64)}
        self.pdf = self.cases[1]
        self.plan = self.plan_for(self.pdf, 1)

    def plan_for(self, pdf, pages):
        """Supply independently fixed source and exact candidate/document plan identities."""
        return plan_pdf_page_windows(pdf_sha256=sha256(pdf).hexdigest(),
            ir_sha256='a' * 64, page_count=pages, admitted_page_budget=pages,
            pages_per_window=16, inspector_profile_id=TEXT_PROFILE)

    def inspect(self, **changes):
        """Call only the public native adapter with independently alterable expectations."""
        args = dict(pdf_bytes=self.pdf, plan=self.plan,
                    expected_plan_sha256=self.plan.plan_sha256, expected_language='en-US')
        return self.m.inspect_pdf_structure_tree(**{**args, **changes})

    def reject(self, change, *, prior_accepts=False):
        """A rehashed candidate with broken linkage must not receive a new success receipt."""
        candidate = changed_pdf(self.pdf, change)
        plan = self.plan_for(candidate, 1)
        args = dict(pdf_bytes=candidate, plan=plan,
                    expected_plan_sha256=plan.plan_sha256, expected_language='en-US')
        if prior_accepts:
            self.assertEqual(inspect_pdf_mcid_coverage(**args).matched_mcids, 4)
        with self.assertRaises(self.m.PdfStructureTreeError):
            self.m.inspect_pdf_structure_tree(**args)

    def test_native_one_thirty_three_and_sixty_four_pages(self):
        """Traverse the complete supported forward hierarchy for each real synthetic file."""
        for pages, pdf in self.cases.items():
            with self.subTest(pages=pages):
                plan = self.plan_for(pdf, pages)
                result = self.inspect(pdf_bytes=pdf, plan=plan,
                                      expected_plan_sha256=plan.plan_sha256)
                record = result.to_dict()
                self.assertEqual(record['inspected_pages'], pages)
                self.assertEqual(record['mapped_mcids'], 3 * pages + 1)
                self.assertGreater(record['structure_elements'], record['mapped_mcids'])
                self.assertLessEqual(record['traversal_visits'], 20000)
                self.assertLessEqual(record['max_tree_depth'], 64)
                self.assertFalse(record['full_accessibility_qualified'])
                self.assertFalse(record['release_authorized'])

    def test_reverse_slot_without_forward_child_is_rejected(self):
        """An intact upward parent chain is insufficient when its forward child is absent."""
        def remove(writer):
            """Remove the heading branch but retain all original reverse references."""
            del structure(writer)[3]['/K'][0]
        self.reject(remove, prior_accepts=True)

    def test_immediate_parent_must_match_actual_forward_owner(self):
        """A different valid root-reaching ancestor is not the child's actual parent."""
        def reparent(writer):
            """Leave the heading's child list intact while skipping it in the upward link."""
            first_leaf(writer).get_object()[NameObject('/P')] = structure(writer)[2]
        self.reject(reparent, prior_accepts=True)

    def test_duplicate_structural_child_references_are_rejected(self):
        """The same node cannot have two positions even under one valid parent."""
        def duplicate(writer):
            """Append an already-owned heading child to its current parent again."""
            children = structure(writer)[3]['/K']
            children.append(children[0])
        self.reject(duplicate, prior_accepts=True)

    def test_duplicate_root_children_are_rejected(self):
        """The structural document cannot appear twice below the same root."""
        def duplicate(writer):
            """Duplicate the generated document reference in the root child array."""
            root = structure(writer)[1]
            root['/K'].append(root['/K'][0])
        self.reject(duplicate, prior_accepts=True)

    def test_cycle_in_a_forward_only_branch_is_rejected(self):
        """Unmapped branches must still be traversed, with cycles rejected finitely."""
        def cycle(writer):
            """Add an otherwise unobserved node whose child reference points to itself."""
            _, _, doc_ref, doc = structure(writer)
            node = DictionaryObject({NameObject('/Type'): NameObject('/StructElem'),
                NameObject('/S'): NameObject('/Sect'), NameObject('/P'): doc_ref})
            ref = writer._add_object(node)
            node[NameObject('/K')] = ArrayObject([ref])
            doc['/K'].append(ref)
        self.reject(cycle, prior_accepts=True)

    def test_extra_forward_mcid_must_match_reverse_owner(self):
        """A second element cannot claim a valid page MCID owned by another element."""
        def extra(writer):
            """Add a second terminal structure element for the first physical-page MCID."""
            _, _, doc_ref, doc = structure(writer)
            node = DictionaryObject({NameObject('/Type'): NameObject('/StructElem'),
                NameObject('/S'): NameObject('/Span'), NameObject('/P'): doc_ref,
                NameObject('/Pg'): writer.pages[0].indirect_reference,
                NameObject('/K'): ArrayObject([NumberObject(0)])})
            doc['/K'].append(writer._add_object(node))
        self.reject(extra, prior_accepts=True)

    def test_empty_or_missing_forward_group_is_not_complete(self):
        """An empty group cannot silently disconnect still-present page observations."""
        def empty(writer):
            """Retain the document node but remove all of its forward child links."""
            structure(writer)[3][NameObject('/K')] = ArrayObject()
        def missing(writer):
            """Delete the document child key without touching the page parent tree."""
            del structure(writer)[3][NameObject('/K')]
        self.reject(empty, prior_accepts=True)
        self.reject(missing, prior_accepts=True)

    def test_direct_or_unsupported_child_objects_are_rejected(self):
        """Only explicit indirect structure nodes or native numeric content IDs are supported."""
        for child in (NullObject(), BooleanObject(True), TextStringObject('0'),
                      DictionaryObject(), ArrayObject([NumberObject(0)])):
            with self.subTest(kind=type(child).__name__):
                def append(writer):
                    """Append one unsupported synthetic child form to a valid group."""
                    structure(writer)[3]['/K'].append(child)
                self.reject(append, prior_accepts=True)

    def test_wrong_type_on_an_unmapped_forward_node_is_rejected(self):
        """Unmapped side branches are not exempt from native structural typing."""
        def extra(writer):
            """An OBJR-like node is outside the declared structural-element profile."""
            _, _, doc_ref, doc = structure(writer)
            obj = DictionaryObject({NameObject('/Type'): NameObject('/OBJR'),
                NameObject('/P'): doc_ref, NameObject('/K'): ArrayObject([NumberObject(0)])})
            doc['/K'].append(writer._add_object(obj))
        self.reject(extra, prior_accepts=True)

    def test_declared_group_page_must_be_a_physical_page(self):
        """Even nonterminal nodes cannot carry a foreign or non-page page reference."""
        def wrong(writer):
            """Replace a heading's optional page reference with its document reference."""
            _, _, doc_ref, doc = structure(writer)
            doc['/K'][0].get_object()[NameObject('/Pg')] = doc_ref
        self.reject(wrong, prior_accepts=True)

    def test_unchanged_mcid_prerequisite_is_required(self):
        """A rejected prerequisite prevents even the later structural parser from starting."""
        identity = self.worker._identity_from_plan(self.plan)
        with patch.object(self.worker.mcids, '_inspect', side_effect=ValueError('blocked')) as earlier:
            with patch('pypdf.PdfReader') as parser:
                with self.assertRaises(ValueError): self.worker._inspect(self.pdf, identity)
                earlier.assert_called_once(); parser.assert_not_called()

    def test_tree_visit_and_depth_budgets_fail_closed(self):
        """Actual forward traversal stops under independently narrowed finite test budgets."""
        identity = self.worker._identity_from_plan(self.plan)
        for budget in ('MAX_TREE_VISITS', 'MAX_TREE_DEPTH'):
            with patch.object(self.worker, budget, 1):
                with self.assertRaises(ValueError): self.worker._inspect(self.pdf, identity)

    def test_wrong_pdf_ir_plan_and_page_count_never_pass(self):
        """Foreign expectations and falsely declared physical counts cannot bind a receipt."""
        for change in ({'expected_plan_sha256': 'e' * 64}, {'plan': {}},
                       {'pdf_bytes': self.cases[33]}, {'expected_language': 'pt-BR'}):
            with self.assertRaises(self.m.PdfStructureTreeError): self.inspect(**change)
        plan = self.plan_for(self.pdf, 2)
        with self.assertRaises(self.m.PdfStructureTreeError):
            self.inspect(plan=plan, expected_plan_sha256=plan.plan_sha256)

    def test_sixty_five_pages_and_mutable_input_do_not_launch(self):
        """The optional 64-page boundary cannot silently inherit the generic 512-page class."""
        plan = self.plan_for(self.pdf, 65)
        overflow = b"%PDF-1.7" + b"x" * 16777209
        overflow_plan = self.plan_for(overflow, 1)
        with patch.object(self.m, '_run_worker') as native:
            for change in ({'plan': plan, 'expected_plan_sha256': plan.plan_sha256},
                           {'pdf_bytes': bytearray(self.pdf)},
                           {"pdf_bytes": overflow, "plan": overflow_plan, "expected_plan_sha256": overflow_plan.plan_sha256}):
                with self.assertRaises(self.m.PdfStructureTreeError): self.inspect(**change)
            native.assert_not_called()

    def test_malformed_encrypted_and_foreign_pdf_rejected(self):
        """Unreadable, encrypted or wrong-version candidates expose no success metadata."""
        self.reject(lambda writer: writer.encrypt('synthetic-only'))
        for pdf in (b'invalid', self.pdf.replace(b'%PDF-1.7', b'%PDF-1.6', 1)):
            with self.assertRaises(self.m.PdfStructureTreeError): self.inspect(pdf_bytes=pdf)

    def test_disable_prevents_execution_and_late_acceptance(self):
        """Independent disabling is checked before launch and after the worker returns."""
        key = 'OMNIGENIS_PDF_STRUCTURE_TREE_DISABLED'
        with patch.dict(os.environ, {key: '1'}), patch.object(self.m, '_run_worker') as native:
            with self.assertRaises(self.m.PdfStructureTreeError): self.inspect()
            native.assert_not_called()
        original = self.m._run_worker
        def change(pdf, identity):
            """Return genuine worker evidence while independently disabling acceptance."""
            output = original(pdf, identity); os.environ[key] = '1'; return output
        with patch.dict(os.environ), patch.object(self.m, '_run_worker', side_effect=change):
            with self.assertRaises(self.m.PdfStructureTreeError): self.inspect()

    def test_plan_is_rechecked_after_native_work(self):
        """Mutating a frozen plan during execution cannot preserve a stale expectation."""
        original = self.m._run_worker
        def change(pdf, identity):
            """Alter only the synthetic plan after obtaining a real child result."""
            output = original(pdf, identity)
            object.__setattr__(self.plan, 'ir_sha256', 'e' * 64)
            return output
        with patch.object(self.m, '_run_worker', side_effect=change):
            with self.assertRaises(self.m.PdfStructureTreeError): self.inspect()

    def test_no_pdf_parser_executes_in_the_adapter_process(self):
        """A real native call succeeds with the parent PDF parser explicitly blocked."""
        with patch('pypdf.PdfReader', side_effect=AssertionError('parent parser forbidden')):
            self.assertEqual(self.inspect().page_count, 1)

    def test_unknown_parser_never_substitutes_for_the_pin(self):
        """The inspector rejects an unsupported parser before processing the candidate."""
        with patch.object(self.worker, 'version', return_value='foreign'):
            with self.assertRaises(ValueError):
                self.worker._inspect(self.pdf, self.worker._identity_from_plan(self.plan))

    def test_closed_worker_protocol_and_native_count_types(self):
        """Unknown fields, identities, profiles, limits and Boolean counts fail closed."""
        identity = self.worker._identity_from_plan(self.plan)
        raw = self.m._run_worker(self.pdf, identity)
        self.assertEqual(self.m._decode(raw, identity).page_count, 1)
        for group, key, value in ((None, 'extra', 1), (None, 'profile_id', 'unknown'),
                ('identity', 'ir_sha256', 'f' * 64), ('limits', 'cpu_seconds', 99),
                ('inspection', 'structure_elements', True), ('inspection', 'mapped_mcids', 0),
                ('inspection', 'max_tree_depth', 65), ('inspection', 'inspected_pages', 2)):
            altered = json.loads(raw)
            (altered if group is None else altered[group])[key] = value
            with self.assertRaises(self.m.PdfStructureTreeError):
                self.m._decode(json.dumps(altered).encode(), identity)

    def test_duplicate_keys_and_oversized_protocol_rejected(self):
        """A successful-looking payload cannot hide ambiguous JSON or surplus bytes."""
        identity = self.worker._identity_from_plan(self.plan)
        raw = self.m._run_worker(self.pdf, identity)
        for value in (b'', None, raw + b' ' * 4096,
                      raw.replace(b'"profile_id":', b'"profile_id":"x","profile_id":', 1)):
            with self.assertRaises(self.m.PdfStructureTreeError): self.m._decode(value, identity)

    def test_guards_precede_read_and_emit_no_success_on_failure(self):
        """Run the actual entrypoint and assert each required guard and no candidate read."""
        for failure in ('landlock', 'network'):
            with self.subTest(guard=failure), ExitStack() as stack:
                source = stack.enter_context(TemporaryFile()); result = stack.enter_context(TemporaryFile())
                stack.enter_context(patch.object(self.worker, '_limits', return_value={}))
                stack.enter_context(patch.object(self.worker, '_lifetime'))
                landlock = stack.enter_context(patch.object(self.worker, 'enforce_pdf_landlock'))
                network = stack.enter_context(patch.object(self.worker, 'enforce_pdf_network_filter'))
                read = stack.enter_context(patch.object(self.worker, '_read_request'))
                (landlock if failure == 'landlock' else network).side_effect = OSError('blocked')
                code = self.worker.main(['worker', str(source.fileno()), str(result.fileno()), str(os.getpid())])
                self.assertEqual(code, 70); read.assert_not_called(); landlock.assert_called_once()
                if failure == 'network': network.assert_called_once()
                else: network.assert_not_called()
                self.assertEqual(os.fstat(result.fileno()).st_size, 0)

    def test_named_or_aliased_protocol_files_are_rejected_before_limits(self):
        """Only distinct anonymous owned regular files may reach native process setup."""
        with TemporaryFile() as anonymous, NamedTemporaryFile() as named:
            with patch.object(self.worker, '_limits') as limits:
                for first, second in ((anonymous.fileno(), anonymous.fileno()),
                                      (named.fileno(), anonymous.fileno())):
                    self.assertEqual(self.worker.main(['worker', str(first), str(second), str(os.getpid())]), 64)
                limits.assert_not_called()

    def test_worker_failures_do_not_expose_parser_or_candidate_data(self):
        """An opaque exception cannot escape as text or as a partial successful receipt."""
        with patch.object(self.m, '_run_worker', side_effect=RuntimeError('SYNTHETIC_PRIVATE_TEXT')):
            with self.assertRaises(self.m.PdfStructureTreeError) as caught: self.inspect()
        self.assertNotIn('SYNTHETIC_PRIVATE_TEXT', str(caught.exception))

    def test_receipt_is_sealed_frozen_detached_and_content_free(self):
        """Returned counts cannot be edited or silently repinned into another observation."""
        result = self.inspect(); before = result.to_bytes()
        self.assertEqual(result.inspection_sha256, sha256(before).hexdigest())
        self.assertNotIn(b'SYNTHETIC-TEXT-REPORT', before)
        with self.assertRaises(FrozenInstanceError): result.structure_elements = 1
        detached = result.to_dict(); detached['mapped_mcids'] = 999
        self.assertEqual(result.to_bytes(), before)
        object.__setattr__(result, 'structure_elements', result.structure_elements + 1)
        with self.assertRaises(self.m.PdfStructureTreeError): result.to_bytes()
        with self.assertRaises(self.m.PdfStructureTreeError): result.__post_init__()

    def test_direct_receipt_rejects_contradictory_counts(self):
        """Even direct construction must respect page, tree-depth and finite visit relations."""
        result = self.inspect()
        for change in ({'structure_elements': 0}, {'mapped_mcids': False},
                       {'max_tree_depth': 65}, {'traversal_visits': 0}, {'inspected_pages': 2}):
            with self.assertRaises(self.m.PdfStructureTreeError): replace(result, **change)

    def test_no_semantics_science_authentication_or_release_claim(self):
        """Bidirectional structural linkage alone is not full accessibility or release."""
        record = self.inspect().to_dict()
        for key in ('semantic_roles_qualified', 'reading_order_verified',
                    'full_accessibility_qualified', 'visible_content_covered',
                    'worker_results_authenticated', 'aggregate_job_resources_qualified',
                    'all_file_revisions_inspected', 'release_authorized'):
            self.assertIs(record[key], False)
        self.assertEqual(record['release_authorization'], 'NOT_ESTABLISHED')

    def test_manifest_defaults_source_hashes_and_docstrings(self):
        """No existing profile or source is modified to accommodate the new optional guard."""
        from reporting._pdf_safety_worker import MAX_PAGES
        from reporting.pdf_source_inspection_job import MAX_PAGES as JOB_PAGES
        manifest = json.loads((ROOT / 'reporting/pdf-structure-tree-engine.v1.json').read_text())
        self.assertEqual(MAX_PAGES, 32); self.assertEqual(JOB_PAGES, 64)
        self.assertEqual(manifest['resource_budget']['pages'], 64)
        self.assertEqual(manifest['resource_budget']['tree_depth'], 64)
        self.assertEqual(manifest['parser_version'], '6.19.0')
        self.assertFalse(manifest['default_pipeline_activated'])
        self.assertFalse(manifest['source_job_changed'])
        for name, digest in manifest['reused_source_sha256'].items():
            self.assertEqual(sha256((ROOT / name).read_bytes()).hexdigest(), digest)
        for name in ('reporting/pdf_structure_tree.py', 'reporting/_pdf_structure_tree_worker.py',
                     'tests/test_reporting_pdf_structure_tree.py'):
            for node in ast.walk(ast.parse((ROOT / name).read_text())):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.assertTrue(ast.get_docstring(node), name + ':' + node.name)


if __name__ == '__main__':
    unittest.main()
