"""Synthetic fail-closed checks for inert, pinned HTTPS citation candidates."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator
from reporting.bindings import ReportArtifactBinding

ROOT = Path(__file__).resolve().parents[1]


def digest(value: str) -> str:
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


class ReferenceCandidateTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('reporting.reference_links'),
                             'reference candidate module is missing')
        self.m = importlib.import_module('reporting.reference_links')
        self.a = self.record('REF-A', 'https://example.org/research/abc')
        self.b = self.record('REF-B', 'https://pubmed.ncbi.nlm.nih.gov/12345678')
        self.expected = self.catalog((self.a, self.b))
        self.resolved = self.catalog((self.record('REF-A', self.a.href),
                                      self.record('REF-B', self.b.href)))

    def record(self, identity: str, href: str, **changes):
        value = dict(reference_id=identity, href=href,
                     host_name=href.split('/')[2] if href.startswith('https://') else 'example.org',
                     href_sha256=digest(href),
                     source_reference=ReportArtifactBinding('SOURCE-' + identity, 'a'*64),
                     policy_reference=ReportArtifactBinding('POLICY-' + identity, 'b'*64))
        value.update(changes)
        return self.m.ReferenceCandidate(**value)

    def catalog(self, refs, hosts=('example.org','pubmed.ncbi.nlm.nih.gov')):
        return self.m.StagedReferenceCatalog(references=refs, declared_hosts=hosts)

    def bind(self, *, expected=None, resolved=None, expected_digest=None):
        x = self.expected if expected is None else expected
        return self.m.bind_reference_candidates(
            expected_catalog=x,
            resolved_catalog=self.resolved if resolved is None else resolved,
            expected_catalog_sha256=x.catalog_sha256 if expected_digest is None else expected_digest)

    def reject(self, **kwargs):
        with self.assertRaises(self.m.ReferenceCandidateError):
            self.bind(**kwargs)

    def test_immutable_catalog_bound_to_independently_pinned_digest(self):
        receipt=self.bind()
        self.assertEqual(receipt.to_dict()['status'], 'STAGED_UNQUALIFIED')
        self.assertEqual(receipt.to_dict()['reference_count'], 2)
        self.assertEqual(receipt.to_dict()['catalog_sha256'], self.expected.catalog_sha256)

    def test_external_links_remain_disabled_even_for_valid_candidate(self):
        d=self.bind().to_dict()
        for k in ('source_authenticity_verified','source_relevance_reviewed',
                  'source_rights_verified','host_policy_authenticated',
                  'pdf_annotation_profile_qualified','renderer_activated',
                  'links_activated','network_access_performed'):
            self.assertFalse(d[k], k)
        self.assertEqual(d['release_authorization'],'NOT_ESTABLISHED')
        self.assertEqual(d['conformance_scope'],'HTTPS_CANDIDATE_SYNTAX_AND_BINDING_ONLY')

    def test_receipt_has_no_live_url_or_case_payload(self):
        s=repr(self.bind().to_dict())
        self.assertNotIn('https://',s)
        self.assertNotIn('pubmed.ncbi',s)
        self.assertNotIn('/research/abc',s)

    def test_built_in_canonical_digest_is_repeatable(self):
        self.assertEqual(self.expected.catalog_sha256,self.resolved.catalog_sha256)

    def test_changed_href_without_digest_update_rejected(self):
        with self.assertRaises(self.m.ReferenceCandidateError):
            replace(self.a,href='https://example.org/research/changed')

    def test_foreign_expected_catalog_digest_rejected(self):
        self.reject(expected_digest='f'*64)

    def test_stale_resolved_catalog_rejected(self):
        changed=self.catalog((self.a,self.record('REF-B','https://pubmed.ncbi.nlm.nih.gov/changed')))
        self.reject(resolved=changed)

    def test_declaration_of_host_not_upstream_trust(self):
        d=self.bind().to_dict()
        self.assertEqual(d['declared_host_count'],2)
        self.assertFalse(d['host_policy_authenticated'])

    def test_unknown_unlisted_subdomain_is_rejected(self):
        rec=self.record('REF-X','https://evil.example.org/path')
        with self.assertRaises(self.m.ReferenceCandidateError):
            self.catalog((rec,),('example.org',))

    def test_explicit_host_mismatch_is_rejected(self):
        with self.assertRaises(self.m.ReferenceCandidateError):
            self.record('REF-X','https://example.org/x',host_name='not-example.org')

    def test_bad_schemes_credentials_ports_and_protocol_relative_rejected(self):
        values=('http://example.org/x','javascript:alert(1)','file:///etc/passwd',
                'data:text/plain,abc','https://user:pass@example.org/x',
                'https://example.org:443/x','//example.org/x','HTTPS://example.org/x',
                'https:\\\\example.org\\path')
        for value in values:
            with self.subTest(value=value),self.assertRaises(self.m.ReferenceCandidateError):
                self.record('REF-X',value)

    def test_percent_encoding_queries_fragments_and_backslashes_rejected(self):
        values=('https://example.org/%2e%2e/private','https://example.org/p?q=1',
                'https://example.org/p#fragment','https://example.org/x%2fy',
                'https://example.org/foo\\bar','https://example.org/a//b',
                'https://example.org/./a','https://example.org/a/../b')
        for value in values:
            with self.subTest(value=value),self.assertRaises(self.m.ReferenceCandidateError):
                self.record('REF-X',value)

    def test_non_ascii_unicode_and_punycode_rejected(self):
        values=('https://exámple.org/ref','https://xn--example-b5a.org/ref',
                'https://example.org/café','https://example.org/a\u202eb',
                'https://example.org/\u00e9')
        for value in values:
            with self.subTest(value=value),self.assertRaises(self.m.ReferenceCandidateError):
                self.record('REF-X',value)

    def test_private_loopback_and_special_names_are_rejected(self):
        values=('https://localhost/a','https://myrouter.local/a',
                'https://10.0.0.1/a','https://127.0.0.1/a',
                'https://host.internal/a','https://some.onion/a')
        for value in values:
            with self.subTest(value=value),self.assertRaises(self.m.ReferenceCandidateError):
                self.record('REF-X',value)

    def test_uppercase_host_cannot_be_silently_normalized(self):
        with self.assertRaises(self.m.ReferenceCandidateError):
            self.record('REF-X','https://Example.org/a')

    def test_control_characters_whitespace_and_unicode_host_rejected(self):
        for value in ('https://example.org/a\nb','https://example.org/a b',
                      'https://example.org/a\x00b','https://example.org/\tb'):
            with self.subTest(value=repr(value)),self.assertRaises(self.m.ReferenceCandidateError):
                self.record('REF-X',value)

    def test_non_https_ip_literal_and_foreign_netloc_rejected(self):
        for value in ('https://[::1]/x','https://192.0.2.1/x',
                      'https://localhost.localdomain/x','https://-evil.org/x',
                      'https://evil-.org/x'):
            with self.subTest(value=value),self.assertRaises(self.m.ReferenceCandidateError):
                self.record('REF-X',value)

    def test_duplicate_identifiers_and_urls_are_rejected(self):
        for other in (self.record('REF-A','https://pubmed.ncbi.nlm.nih.gov/12345678'),
                      self.record('REF-C',self.a.href)):
            with self.assertRaises(self.m.ReferenceCandidateError):
                self.catalog((self.a,other))

    def test_invalid_reference_or_policy_binding_rejected(self):
        for key in ('source_reference','policy_reference'):
            with self.subTest(key=key),self.assertRaises(self.m.ReferenceCandidateError):
                self.record('REF-X','https://example.org/x',**{key:None})

    def test_same_source_and_policy_identity_rejected(self):
        with self.assertRaises(self.m.ReferenceCandidateError):
            self.record('REF-X','https://example.org/x',
                        source_reference=ReportArtifactBinding('SAME','a'*64),
                        policy_reference=ReportArtifactBinding('SAME','b'*64))

    def test_missing_explicit_expected_digest_rejected(self):
        with self.assertRaises(self.m.ReferenceCandidateError):
            self.m.BoundReferenceCandidates(self.expected,self.resolved,None)

    def test_manifest_rejects_forged_profile_and_language(self):
        for key,value in (('schema_version','v999'),('profile_id','renderable-citations'),
                          ('locale_id','pt-BR')):
            with self.subTest(key=key):
                forged=self.catalog((self.a,))
                object.__setattr__(forged,key,value)
                with self.assertRaises(self.m.ReferenceCandidateError):
                    forged.catalog_sha256

    def test_strict_tuples_and_counts_reject_mutable_foreign_values(self):
        with self.assertRaises(self.m.ReferenceCandidateError):
            self.catalog([self.a])
        with self.assertRaises(self.m.ReferenceCandidateError):
            self.catalog(())
        with self.assertRaises(self.m.ReferenceCandidateError):
            self.catalog((self.a,),['example.org'])
        with self.assertRaises(self.m.ReferenceCandidateError):
            self.catalog((self.a,),())

    def test_duplicate_and_extra_host_declarations_rejected(self):
        for hosts in (('example.org','example.org'),('example.org','localhost'),
                      ('example.org','evil-.org')):
            with self.subTest(hosts=hosts), self.assertRaises(self.m.ReferenceCandidateError):
                self.catalog((self.a,),hosts)

    def test_oversized_link_refuses_before_hashing(self):
        huge='https://example.org/' + 'a'*4000
        with patch.object(self.m.hashlib,'sha256',side_effect=AssertionError('MUST_NOT_HASH')):
            with self.assertRaises(self.m.ReferenceCandidateError):
                replace(self.a, href=huge, href_sha256='a'*64)

    def test_bounded_catalog_rejects_count_before_indices(self):
        with self.assertRaises(self.m.ReferenceCandidateError):
            self.catalog((self.a,)*129)

    def test_duplicate_hosts_not_sorted_or_normalized(self):
        with self.assertRaises(self.m.ReferenceCandidateError):
            self.catalog((self.a,),('example.org','example.org'))

    def test_nested_mutation_after_capture_fails_closed(self):
        forged=self.record('REF-X','https://example.org/x')
        object.__setattr__(forged,'host_name','evil.org')
        with self.assertRaises(self.m.ReferenceCandidateError):
            self.catalog((forged,))

    def test_catalog_export_detached_and_records_exact_order(self):
        b=self.bind()
        d=b.to_dict()
        self.assertEqual([v['reference_id'] for v in d['references']],['REF-A','REF-B'])
        d['references'].clear()
        self.assertEqual(len(b.to_dict()['references']),2)
        with self.assertRaises(FrozenInstanceError):
            b.expected_catalog = None

    def test_source_records_unchanged_by_binding(self):
        old=(self.a.href,self.a.href_sha256,self.expected.catalog_sha256)
        self.bind()
        self.assertEqual(old,(self.a.href,self.a.href_sha256,self.expected.catalog_sha256))

    def test_no_dns_network_disk_or_process_activity(self):
        with patch.object(socket,'getaddrinfo',side_effect=AssertionError('DNS forbidden')),\
             patch.object(subprocess,'Popen',side_effect=AssertionError('subprocess forbidden')),\
             patch.object(Path,'read_bytes',side_effect=AssertionError('read forbidden')):
            self.assertEqual(self.bind().to_dict()['reference_count'],2)

    def test_synthetic_stress_128_records_no_top_n_truncation(self):
        records=tuple(self.record('REF-'+str(i),'https://example.org/ref/'+str(i))
                      for i in range(128))
        c=self.catalog(records,('example.org',))
        b=self.m.BoundReferenceCandidates(c,c,c.catalog_sha256)
        self.assertEqual(b.to_dict()['reference_count'],128)

    def test_errors_never_echo_secret_url_path(self):
        private='https://example.org/PRIVATE_SENTINEL'
        with self.assertRaises(self.m.ReferenceCandidateError) as exc:
            self.record('REF-X',private,href_sha256='0'*64)
        self.assertNotIn('PRIVATE_SENTINEL',str(exc.exception))

    def test_evidence_schema_is_closed_and_matches_result(self):
        schema=json.loads((ROOT/'schemas/report-reference-candidate.v1.schema.json').read_text())
        Draft202012Validator.check_schema(schema)
        self.assertFalse(list(Draft202012Validator(schema).iter_errors(self.bind().to_dict())))

    def test_schema_rejects_forged_authorization_and_runtime_enabled(self):
        schema=json.loads((ROOT/'schemas/report-reference-candidate.v1.schema.json').read_text())
        check=Draft202012Validator(schema)
        for field,value in (('links_activated',True),('source_rights_verified',True),
                            ('release_authorization','AUTHORIZED'),('pdf_annotation_profile_qualified',True)):
            with self.subTest(field=field):
                forged={**self.bind().to_dict(),field:value}
                self.assertTrue(list(check.iter_errors(forged)))

    def test_schema_disallows_urls_and_unexpected_fields_in_receipt(self):
        schema=json.loads((ROOT/'schemas/report-reference-candidate.v1.schema.json').read_text())
        check=Draft202012Validator(schema)
        bad={**self.bind().to_dict(),'url':'https://example.org/x'}
        self.assertTrue(list(check.iter_errors(bad)))
        d=self.bind().to_dict()
        d['references'][0]['href']='https://example.org/evil'
        self.assertTrue(list(check.iter_errors(d)))

    def test_legacy_pdf_adapter_rejects_candidate_evidence(self):
        from reporting.adapters import build_html_css_and_pdf_adapter
        res=build_html_css_and_pdf_adapter(presentation_ir=self.bind().to_dict())
        self.assertFalse(res.passed)
        self.assertIsNone(res.pdf_bytes)


if __name__=='__main__':
    unittest.main()
