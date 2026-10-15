"""Exact document/job metadata composition, synthetic negatives and native receipts."""
from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
import importlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import patch

from reporting.pdf_inspection_bundle import bind_pdf_inspection_bundle
from reporting.pdf_document_metadata import PdfDocumentMetadataInspection, inspect_pdf_document_metadata
from reporting.pdf_page_tags import PdfPageTagInspection, inspect_pdf_page_tag_parents
from reporting.pdf_mcid_coverage import PdfMcidCoverageInspection, inspect_pdf_mcid_coverage
from reporting.page_checkpoints import resume_page_checkpoint
from reporting.page_windows import plan_pdf_page_windows
from reporting.pdf_text_windows import inspect_pdf_text_window, PROFILE_ID as TEXT_PROFILE
from reporting.pdf_raster_windows import inspect_pdf_raster_window, PROFILE_ID as RASTER_PROFILE
from reporting.pdf_object_graph import inspect_pdf_object_graph
from tests.test_reporting_pdf_inspection_bundle import synthetic_inputs, packaged

ROOT=Path(__file__).resolve().parents[1]


def assembled(page_bundle, metadata, tags, mcids):
    """Supply independent test pins; matching hashes are not authenticated provenance."""
    return {'page_bundle':page_bundle,'document_metadata':metadata,'page_tags':tags,
            'mcid_coverage':mcids,'expected_page_bundle_sha256':page_bundle.bundle_sha256,
            'expected_metadata_sha256':metadata.inspection_sha256,
            'expected_page_tags_sha256':tags.inspection_sha256,
            'expected_mcid_sha256':mcids.inspection_sha256,'expected_language':'en-US'}


def synthetic_set(pages=33, text_width=16, raster_width=4):
    """Fabricate metadata only; these objects never demonstrate actual worker execution."""
    bundle=bind_pdf_inspection_bundle(**synthetic_inputs(pages,text_width,raster_width))
    plan=bundle.text_checkpoint.plan
    identity={k:getattr(plan,k) for k in ('pdf_sha256','ir_sha256','plan_sha256','page_count')}
    metadata=PdfDocumentMetadataInspection(**identity)
    tags=PdfPageTagInspection(**identity,tagged_pages=pages,parent_tree_entries=pages)
    mcids=PdfMcidCoverageInspection(**identity,matched_mcids=pages,decoded_bytes=100*pages,inspected_pages=pages)
    return assembled(bundle,metadata,tags,mcids)


def native_set(pages):
    """Run every existing inspector on one controlled synthetic final file, without fragments."""
    from weasyprint import HTML
    from weasyprint.urls import URLFetcher
    from pypdf import PdfReader
    from io import BytesIO
    if pages not in (1,33):
        raise ValueError('fixture pages outside tested native examples')
    html=('<html lang="en-US"><head><title>OmniGenis</title>'
          '<meta name="author" content="Hudson Silva Andrade">'
          '<meta name="generator" content="OmniGenis"></head><body>'
          +''.join('<p style="break-before:page">Synthetic inspection set page %d</p>'%i
                   for i in range(1,pages+1))+'</body></html>')
    pdf=HTML(string=html,url_fetcher=URLFetcher(allowed_protocols=(),allow_redirects=False,
             fail_on_errors=True)).write_pdf(pdf_variant='pdf/ua-1',pdf_version='1.7',
                                            pdf_identifier=bytes.fromhex('a'*64))
    assert len(PdfReader(BytesIO(pdf),strict=True).pages)==pages
    plans=[plan_pdf_page_windows(pdf_sha256=sha256(pdf).hexdigest(),ir_sha256='b'*64,
            page_count=pages,admitted_page_budget=pages,pages_per_window=width,
            inspector_profile_id=profile) for width,profile in ((16,TEXT_PROFILE),(4,RASTER_PROFILE))]
    text,raster=plans
    texts=tuple(inspect_pdf_text_window(pdf_bytes=pdf,plan=text,window_index=i,
            expected_plan_sha256=text.plan_sha256) for i in range(text.window_count))
    rasters=tuple(inspect_pdf_raster_window(pdf_bytes=pdf,plan=raster,window_index=i,
            expected_plan_sha256=raster.plan_sha256) for i in range(raster.window_count))
    graph=inspect_pdf_object_graph(pdf_bytes=pdf,plan=text,expected_plan_sha256=text.plan_sha256)
    args=packaged(text,raster,texts,rasters,graph)
    for key in ('text_checkpoint','raster_checkpoint'):
        checkpoint=args[key]
        args[key]=resume_page_checkpoint(checkpoint_bytes=checkpoint.to_bytes(),
            expected_checkpoint_sha256=checkpoint.checkpoint_sha256,expected_plan=checkpoint.plan,
            namespace_id=checkpoint.namespace_id,job_id=checkpoint.job_id,
            expected_request_sha256=checkpoint.request_sha256,
            expected_resource_profile_sha256=checkpoint.resource_profile_sha256)
    bundle=bind_pdf_inspection_bundle(**args)
    common={'pdf_bytes':pdf,'plan':text,'expected_plan_sha256':text.plan_sha256,'expected_language':'en-US'}
    return assembled(bundle,inspect_pdf_document_metadata(**common),inspect_pdf_page_tag_parents(**common),
                     inspect_pdf_mcid_coverage(**common))


class PdfInspectionSetTests(unittest.TestCase):
    """All existing receipt dimensions must belong to the pinned page bundle."""

    def setUp(self):
        """Observe RED as an explicit missing-feature assertion, not an import error."""
        self.assertIsNotNone(importlib.util.find_spec('reporting.pdf_inspection_set'),
                             'exact PDF inspection-set binder missing')
        self.m=importlib.import_module('reporting.pdf_inspection_set')
        self.args=synthetic_set()

    def bind(self,**changes):
        """Call the public boundary with one independently alterable expected input."""
        return self.m.bind_pdf_inspection_set(**{**self.args,**changes})

    def test_all_six_dimensions_are_bound_to_one_job(self):
        """Keep complete page evidence together with all three later document inspectors."""
        d=self.bind().to_dict()
        self.assertEqual(d['status'],'INSPECTION_SET_METADATA_BOUND')
        self.assertEqual(d['page_count'],33)
        self.assertEqual(d['namespace_id'],'synthetic-namespace')
        self.assertEqual(d['job_id'],'synthetic-job')
        self.assertEqual(d['language'],'en-US')
        self.assertEqual(d['inspection_dimensions'],['text','raster','object_graph','document_metadata','page_tags','mcid_linkage'])
        self.assertEqual(d['page_bundle'],self.args['page_bundle'].to_dict())
        self.assertEqual(set(d['document_receipts']),{'metadata','page_tags','mcid_coverage'})

    def test_real_native_one_and_thirty_three_page_full_sets(self):
        """Observe every page and every inspector on the same final PDF after checkpoint restore."""
        for pages in (1,33):
            with self.subTest(pages=pages):
                args=native_set(pages)
                result=self.m.bind_pdf_inspection_set(**args)
                data=result.to_dict()
                self.assertEqual(data['page_count'],pages)
                for role in ('text','raster'):
                    stream=data['page_bundle'][role+'_stream']
                    represented=[p for r in stream['receipts'] for p in range(r['first_page'],r['last_page']+1)]
                    self.assertEqual(represented,list(range(1,pages+1)))
                for role,key in (('metadata','document_metadata'),('page_tags','page_tags'),('mcid_coverage','mcid_coverage')):
                    self.assertEqual(data['document_receipts'][role]['inspection_sha256'],args[key].inspection_sha256)
                self.assertFalse(data['release_authorized'])

    def test_every_expected_hash_is_required_exactly(self):
        """Do not accept inferred, missing, nonnative or mismatched expectation hashes."""
        for key in ('expected_page_bundle_sha256','expected_metadata_sha256','expected_page_tags_sha256','expected_mcid_sha256'):
            for value in (None,True,'','A'*64,'f'*64):
                with self.subTest(key=key,value=value),self.assertRaises(self.m.PdfInspectionSetError):
                    self.bind(**{key:value})

    def test_every_receipt_is_mandatory_and_typed(self):
        """Generic success dictionaries cannot replace native result types."""
        for key in ('page_bundle','document_metadata','page_tags','mcid_coverage'):
            for value in (None,{},self.args[key].to_dict(),True):
                with self.subTest(key=key),self.assertRaises(self.m.PdfInspectionSetError):
                    self.bind(**{key:value})

    def test_different_document_dimensions_rejected_even_when_repinned(self):
        """Each added receipt must match the same PDF, source IR, physical count and text plan."""
        pins={'document_metadata':'expected_metadata_sha256','page_tags':'expected_page_tags_sha256','mcid_coverage':'expected_mcid_sha256'}
        for role,pin in pins.items():
            for field in ('pdf_sha256','ir_sha256','plan_sha256'):
                changed=replace(self.args[role],**{field:'e'*64})
                with self.subTest(role=role,field=field),self.assertRaises(self.m.PdfInspectionSetError):
                    self.bind(**{role:changed,pin:changed.inspection_sha256})
            changed=synthetic_set(34)[role]
            with self.subTest(role=role,field='page_count'),self.assertRaises(self.m.PdfInspectionSetError):
                self.bind(**{role:changed,pin:changed.inspection_sha256})

    def test_raster_plan_does_not_replace_the_document_text_plan(self):
        """Document-level receipts bind the text plan even though raster coverage is also required."""
        for role,pin in (('document_metadata','expected_metadata_sha256'),('page_tags','expected_page_tags_sha256'),('mcid_coverage','expected_mcid_sha256')):
            changed=replace(self.args[role],plan_sha256=self.args['page_bundle'].raster_checkpoint.plan.plan_sha256)
            with self.assertRaises(self.m.PdfInspectionSetError):
                self.bind(**{role:changed,pin:changed.inspection_sha256})

    def test_wrong_or_unsupported_locale_is_not_a_fallback(self):
        """The current exact en-US receipt profile must not claim additional locales."""
        for locale in ('pt-BR','en-us','en-US ',None,True):
            with self.assertRaises(self.m.PdfInspectionSetError):self.bind(expected_language=locale)

    def test_swapped_receipt_roles_are_rejected(self):
        """Equal document IDs do not make different policy checks interchangeable."""
        for role,other in (('document_metadata','page_tags'),('page_tags','mcid_coverage'),('mcid_coverage','document_metadata')):
            with self.assertRaises(self.m.PdfInspectionSetError):self.bind(**{role:self.args[other]})

    def test_foreign_job_bundle_cannot_keep_the_expected_pin(self):
        """Changing the context of both checkpoints cannot retain the original job identity."""
        bundle=self.args['page_bundle']
        fields={k:getattr(bundle,k) for k in bundle.__dataclass_fields__ if not k.startswith('_')}
        for role in ('text','raster'):
            key=role+'_checkpoint';cp=replace(fields[key],job_id='other-job')
            fields[key]=cp;fields['expected_'+role+'_checkpoint_sha256']=cp.checkpoint_sha256
        changed=bind_pdf_inspection_bundle(**fields)
        with self.assertRaises(self.m.PdfInspectionSetError):self.bind(page_bundle=changed)

    def test_incomplete_nested_range_evidence_cannot_be_serialized(self):
        """A previously valid bundle is rechecked instead of treating its old digest as proof."""
        bundle=self.args['page_bundle']
        object.__setattr__(bundle,'raster_inspections',bundle.raster_inspections[:-1])
        with self.assertRaises(self.m.PdfInspectionSetError):self.bind()

    def test_mutated_metadata_receipt_detected_after_binding(self):
        """Cached success cannot hide a nested document identity change."""
        result=self.bind()
        object.__setattr__(self.args['document_metadata'],'pdf_sha256','e'*64)
        for getter in (result.to_dict,result.to_bytes,lambda:result.inspection_set_sha256):
            with self.assertRaises(self.m.PdfInspectionSetError):getter()

    def test_mutated_tag_or_mcid_receipt_detected(self):
        """Invalid counts or foreign plans cannot keep a successful composite result."""
        for role in ('page_tags','mcid_coverage'):
            self.args=synthetic_set();result=self.bind()
            object.__setattr__(self.args[role],'plan_sha256','e'*64)
            with self.assertRaises(self.m.PdfInspectionSetError):result.to_dict()

    def test_original_seal_rejects_in_place_repinning(self):
        """Even a valid alternate count and matching new pin cannot repurpose a bound instance."""
        result=self.bind()
        changed=replace(self.args['mcid_coverage'],decoded_bytes=3301)
        object.__setattr__(result,'mcid_coverage',changed)
        object.__setattr__(result,'expected_mcid_sha256',changed.inspection_sha256)
        for getter in (result.to_bytes,result.__post_init__):
            with self.assertRaises(self.m.PdfInspectionSetError):getter()

    def test_direct_constructor_and_subclasses_do_not_bypass_validation(self):
        """Exact supported classes and constructor checks are required at every public entry."""
        with self.assertRaises(self.m.PdfInspectionSetError):
            self.m.PdfInspectionSet(**{**self.args,'document_metadata':None})
        class ForeignMetadata(PdfDocumentMetadataInspection):
            """Test-only subclass, deliberately outside the exact internal contract."""
        m=self.args['document_metadata']
        with self.assertRaises(self.m.PdfInspectionSetError):
            self.bind(document_metadata=ForeignMetadata(m.pdf_sha256,m.ir_sha256,m.plan_sha256,m.page_count))

    def test_deterministic_bytes_and_hash(self):
        """The digest covers the exact repeatable canonical representation."""
        first,second=self.bind(),self.bind()
        self.assertEqual(first.to_bytes(),second.to_bytes())
        self.assertEqual(first.inspection_set_sha256,sha256(first.to_bytes()).hexdigest())
        self.assertEqual(json.loads(first.to_bytes()),first.to_dict())

    def test_frozen_and_detached_outputs(self):
        """Callers cannot edit retained state by changing a returned dictionary."""
        result=self.bind()
        with self.assertRaises(FrozenInstanceError):result.expected_language='pt-BR'
        data=result.to_dict();data['document_receipts']['metadata']['record']['page_count']=1
        self.assertEqual(result.to_dict()['document_receipts']['metadata']['record']['page_count'],33)
        self.assertNotIn('synthetic-job',repr(result))

    def test_bounded_set_output_never_truncates(self):
        """A byte-budget failure rejects the whole metadata set."""
        with patch.object(self.m,'MAX_SET_BYTES',16):
            with self.assertRaises(self.m.PdfInspectionSetError):self.bind()

    def test_maximal_cardinality_is_metadata_only_and_finite(self):
        """512 one-page synthetic receipts exercise storage bounds, not native qualification."""
        args=synthetic_set(512,1,1)
        result=self.m.bind_pdf_inspection_set(**args)
        self.assertLessEqual(len(result.to_bytes()),272*1024)
        self.assertEqual(result.to_dict()['page_bundle']['raster_stream']['window_count'],512)

    def test_no_filesystem_subprocess_or_network_in_binding(self):
        """The binder reuses supplied records only and never starts or persists inspections."""
        with patch.object(subprocess,'Popen',side_effect=AssertionError('execution')), \
             patch.object(os,'open',side_effect=AssertionError('filesystem')), \
             patch.object(socket,'socket',side_effect=AssertionError('network')):
            self.assertEqual(self.bind().to_dict()['page_count'],33)

    def test_no_authentication_science_or_release_claims(self):
        """Joining partial structural observations cannot promote clinical or output authority."""
        d=self.bind().to_dict()
        for key in ('native_execution_performed','worker_results_authenticated','whole_pdf_safety_qualified',
                    'finding_completeness_verified','text_equivalence_verified','accessibility_qualified',
                    'aggregate_job_resources_qualified','release_authorized'):
            self.assertIs(d[key],False)
        self.assertEqual(d['release_authorization'],'NOT_ESTABLISHED')

    def test_failures_are_content_free(self):
        """An invalid receipt cannot expose its fields or nested exception data."""
        object.__setattr__(self.args['document_metadata'],'pdf_sha256','SYNTHETIC_PRIVATE_VALUE')
        with self.assertRaises(self.m.PdfInspectionSetError) as caught:self.bind()
        self.assertEqual(str(caught.exception),'pdf_inspection_set_invalid')
        self.assertIsNone(caught.exception.__cause__)

    def test_existing_route_and_docstrings_remain_explicit(self):
        """No default activation, missing documentation or hidden source dependencies are introduced."""
        from reporting._pdf_safety_worker import MAX_PAGES
        self.assertEqual(MAX_PAGES,32)
        tree=ast.parse((ROOT/'reporting/pdf_inspection_set.py').read_text())
        for node in ast.walk(tree):
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                self.assertTrue(ast.get_docstring(node),node.name)


if __name__=='__main__':
    unittest.main()
