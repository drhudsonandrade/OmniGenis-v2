"""Complete caller snapshots cross a bounded data-only request boundary.

The transport contract below is specified independently of its implementation.
Only the final integration test performs the real complete stored operation.
Its synthetic source/resources come from test utilities, never product imports.
"""
from copy import deepcopy
from hashlib import sha256
from importlib import import_module, util
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from reporting import pdf_final_document_candidate as final
from reporting import pdf_native_source_job as native
from reporting import pdf_qualification_job as qualification
from reporting import pdf_raster_render as raster
from reporting import pdf_raster_resources as raster_resources
from reporting.bindings import BoundReportSources, MAX_SNAPSHOT_BYTES
from reporting.completeness import ReportCompletenessPlan
from reporting.requests import BoundReportRequest, ReportRequestSnapshot
from reporting._pdf_job_durable_receipt import read_job_receipt
from tests.test_reporting_pdf_bound_candidate import bound_request, source, IDS, SECTIONS
from tests.test_reporting_pdf_bound_raster_candidate import bundle, long_raster_inputs


MAGIC = b'OFD1'
SCHEMA = 'source-bound-final-document-request/v1'
CANDIDATE_PROFILE_SHA256 = '1af6e60d9409bd9c8fb635a01b05e7d60715340f6f421332b3137f841c010dc7'
STORAGE_PROFILE_SHA256 = '42ade56489d026cd3b87581115dae6da19efb26d6fd0a0a77c6d8748f028b767'
MODE = 'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE'
DISABLE_FLAGS = (
    'OMNIGENIS_PDF_FINAL_DOCUMENT_DISABLED',
    'OMNIGENIS_PDF_BOUND_RASTER_DISABLED',
    'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED',
    'OMNIGENIS_PDF_PRELOADED_RASTER_DISABLED',
    'OMNIGENIS_PDF_RENDERER_DISABLED',
)
SEGMENTS = ('canonical_result', 'evidence_snapshot', 'resources')
CANARY = 'PRIVATE-REQUEST-CONTENT-MUST-NOT-ESCAPE'
_ACTUAL = {}


def canonical(value):
    """Encode test-owned metadata without consulting the new product codec."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def framed(metadata, parts, *, metadata_bytes=None):
    """Build the specified wire independently, including deliberate bad frames."""
    raw = canonical(metadata) if metadata_bytes is None else metadata_bytes
    return MAGIC + struct.pack('>I', len(raw)) + raw + b''.join(parts)


def captured_metadata(bound, assets):
    """Capture both upstream assertions and the unmodified source segments."""
    parts = (bound.sources.canonical_result_bytes,
             bound.sources.evidence_snapshot_bytes, assets.to_bytes())
    metadata = {
        'schema': SCHEMA,
        'request': bound.request.to_dict(),
        'resolved_request': bound.resolved_request.to_dict(),
        'expected_source_binding': bound.sources.expected_binding.to_dict(),
        'resolved_source_binding': bound.sources.resolved_binding.to_dict(),
        'plan': bound.plan.to_dict(),
        'resource_profile_sha256': CANDIDATE_PROFILE_SHA256,
        'storage_profile_sha256': STORAGE_PROFILE_SHA256,
        'segments': {name: {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
                     for name, raw in zip(SEGMENTS, parts)},
    }
    return metadata, parts


def maximum_metadata():
    """Derive the ceiling from the exact fixed schema and existing field bounds.

    All seven source identifiers may occupy 256 ASCII bytes. Each snapshot has
    two request identifiers and seven artifact references, including the three
    source roles. Both source bindings and both request snapshots are retained.
    The complete operation permits 128 findings, the fixed five sections and no
    exclusions. This shape is a byte-bound witness, not an admissible request.
    """
    digest = 'f' * 64
    def identifier(role):
        """Give distinct roles their full inherited identifier width."""
        return role.ljust(256, 'x')
    def reference(role):
        """Preserve distinct artifact roles while maximizing encoded width."""
        return {'artifact_id': identifier(role), 'sha256': digest}
    binding = {
        'schema_version': '1.0.0', 'report_id': 'e1a-small-variant-report',
        'identity': {key: identifier(key) for key in (
            'namespace_id', 'case_id', 'subject_id', 'sample_id', 'analysis_id',
            'analysis_revision', 'specimen_id')},
        'input_artifact': reference('input'), 'canonical_result': reference('canonical'),
        'evidence_snapshot': reference('evidence'), 'reference_bundle_sha256': digest,
    }
    request = {
        'schema_version': '1.0.0', 'request_id': identifier('request'),
        'requester_id': identifier('requester'), 'source_binding': binding,
        'completeness_plan_sha256': digest,
        'report_contract_bundle_sha256': digest,
        'locale_id': 'en-US', 'intended_use_id': 'e1a-technical-validation',
        'locale_pack': reference('locale'), 'policy_record': reference('policy'),
        'consent_status': 'VERIFIED', 'consent_record': reference('consent'),
        'review_state': 'APPROVED', 'review_record': reference('review'),
    }
    return {
        'schema': SCHEMA, 'request': request, 'resolved_request': request,
        'expected_source_binding': binding, 'resolved_source_binding': binding,
        'plan': {
            'schema_version': '1.0.0', 'source_binding_sha256': digest,
            'expected_finding_ids': [identifier('finding-' + str(index))
                                     for index in range(128)],
            'expected_section_ids': list(SECTIONS),
            'required_section_ids': list(SECTIONS), 'upstream_exclusions': [],
        },
        'resource_profile_sha256': digest, 'storage_profile_sha256': digest,
        'segments': {
            'canonical_result': {'bytes': MAX_SNAPSHOT_BYTES, 'sha256': digest},
            'evidence_snapshot': {'bytes': MAX_SNAPSHOT_BYTES, 'sha256': digest},
            'resources': {'bytes': raster_resources.MAX_BUNDLE_BYTES,
                          'sha256': digest},
        },
    }


def rebind_metadata(metadata, parts):
    """Reseal test mutations so a negative case reaches its intended invariant."""
    for name, raw in zip(SEGMENTS, parts):
        metadata['segments'][name] = {'bytes': len(raw),
                                      'sha256': sha256(raw).hexdigest()}
    binding = metadata['expected_source_binding']
    binding['canonical_result']['sha256'] = sha256(parts[0]).hexdigest()
    binding['evidence_snapshot']['sha256'] = sha256(parts[1]).hexdigest()
    metadata['resolved_source_binding'] = deepcopy(binding)
    metadata['plan']['source_binding_sha256'] = sha256(canonical(binding)).hexdigest()
    plan_digest = sha256(canonical(metadata['plan'])).hexdigest()
    for role in ('request', 'resolved_request'):
        metadata[role]['source_binding'] = deepcopy(binding)
        metadata[role]['completeness_plan_sha256'] = plan_digest


class Inputs:
    """Use existing admitted synthetic types and one private temporary root."""

    def setUp(self):
        """Missing public behavior must be an explicit RED assertion."""
        self.assertIsNotNone(util.find_spec('reporting.pdf_final_document_request'),
                             'complete final-document request transport is missing')
        self.m = import_module('reporting.pdf_final_document_request')
        for name in ('encode_final_document_request', 'decode_final_document_request',
                     'execute_stored_final_document_request'):
            self.assertTrue(callable(getattr(self.m, name, None)), name + ' is missing')
        environment = patch.dict(os.environ, {MODE: 'qualification-only'})
        environment.start()
        self.addCleanup(environment.stop)
        for name in DISABLE_FLAGS:
            os.environ.pop(name, None)
        self.bound = bound_request()
        self.assets = bundle()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.run_id = 'd' * 32
        self.metadata, self.parts = captured_metadata(self.bound, self.assets)
        self.packet = framed(self.metadata, self.parts)

    def expectations(self, packet=None, **changes):
        """Keep caller expectations separate from values inside the packet."""
        raw = self.packet if packet is None or type(packet) is not bytes else packet
        result = {
            'expected_envelope_sha256': sha256(raw).hexdigest(),
            'expected_request_sha256': self.bound.request.request_sha256,
            'expected_resources_sha256': self.assets.bundle_sha256,
            'expected_resource_profile_sha256': CANDIDATE_PROFILE_SHA256,
            'expected_storage_profile_sha256': STORAGE_PROFILE_SHA256,
        }
        result.update(changes)
        return result

    def encode(self, **changes):
        """Capture actual bound types through the proposed public encoder."""
        values = dict(bound_request=self.bound, resources=self.assets,
                      expected_resource_profile_sha256=CANDIDATE_PROFILE_SHA256,
                      expected_storage_profile_sha256=STORAGE_PROFILE_SHA256)
        values.update(changes)
        return self.m.encode_final_document_request(**values)

    def decode(self, packet=None, **changes):
        """Call the public decoder with independently retained expectations."""
        raw = self.packet if packet is None else packet
        return self.m.decode_final_document_request(
            raw, **self.expectations(raw, **changes))

    def refused(self, packet, **changes):
        """A malformed caller packet must fail before claiming or native work."""
        before = tuple(self.directory.iterdir())
        with patch.object(final, 'execute_observed_stored_final_document_candidate',
                          side_effect=AssertionError('unexpected complete execution')) as execute, \
                patch.object(qualification, '_run_directory',
                             side_effect=AssertionError('unexpected attempt claim')) as claim:
            with self.assertRaises(ValueError) as error:
                self.m.execute_stored_final_document_request(
                    packet, **self.expectations(packet, **changes),
                    directory=self.directory, run_id=self.run_id)
        self.assertRegex(str(error.exception), r'^[a-z][a-z0-9_]*$')
        self.assertNotIn(CANARY, str(error.exception))
        self.assertIsNone(error.exception.__cause__)
        self.assertEqual(tuple(self.directory.iterdir()), before)
        execute.assert_not_called()
        claim.assert_not_called()


class FinalDocumentRequestCodecTests(Inputs, unittest.TestCase):
    """Reject ambiguous frames without normalizing caller source contents."""

    def test_encoder_matches_the_independently_specified_closed_wire(self):
        """Changing field roles, source order or canonical encoding breaks binding."""
        self.assertEqual(self.encode(), self.packet)
        bound, assets = self.decode()
        self.assertIs(type(bound), BoundReportRequest)
        self.assertIs(type(bound.request), ReportRequestSnapshot)
        self.assertIs(type(bound.sources), BoundReportSources)
        self.assertIs(type(bound.plan), ReportCompletenessPlan)
        self.assertIs(type(assets), raster_resources.RasterBundle)
        self.assertEqual(bound.request, self.bound.request)
        self.assertEqual(bound.resolved_request, self.bound.resolved_request)
        self.assertEqual(bound.sources, self.bound.sources)
        self.assertEqual(bound.plan, self.bound.plan)
        self.assertEqual(assets.to_bytes(), self.parts[2])
        self.assertIsNot(bound, self.bound)
        self.assertIsNot(assets, self.assets)

    def test_opaque_evidence_whitespace_survives_capture_and_decode(self):
        """Reserializing the opaque evidence snapshot would change bound bytes."""
        raw = b' \n' + self.parts[1] + b'\n'
        parts = (self.parts[0], raw, self.parts[2])
        metadata = deepcopy(self.metadata)
        rebind_metadata(metadata, parts)
        packet = framed(metadata, parts)
        bound, assets = self.decode(packet, expected_request_sha256=sha256(
            canonical(metadata['request'])).hexdigest())
        self.assertEqual(bound.sources.evidence_snapshot_bytes, raw)
        self.assertEqual(bound.sources.canonical_result_bytes, self.parts[0])
        self.assertEqual(self.m.encode_final_document_request(
            bound_request=bound, resources=assets,
            expected_resource_profile_sha256=CANDIDATE_PROFILE_SHA256,
            expected_storage_profile_sha256=STORAGE_PROFILE_SHA256), packet)

    def test_noncanonical_canonical_result_is_not_normalized_into_admission(self):
        """The transport preserves the existing canonical-source admission rule."""
        parts = (b' ' + self.parts[0], self.parts[1], self.parts[2])
        metadata = deepcopy(self.metadata)
        rebind_metadata(metadata, parts)
        self.refused(framed(metadata, parts), expected_request_sha256=sha256(
            canonical(metadata['request'])).hexdigest())

    def test_each_independent_expectation_is_required(self):
        """Recomputed payload identities cannot replace retained caller expectations."""
        for field in self.expectations():
            for wrong in ('0' * 64, 'F' * 64, True, None, ' ' + 'f' * 64):
                with self.subTest(field=field, wrong=wrong):
                    self.refused(self.packet, **{field: wrong})

    def test_non_bytes_and_mutable_packets_are_refused(self):
        """A borrowed mutable buffer cannot become an admitted immutable snapshot."""
        for packet in (None, True, '', bytearray(self.packet), memoryview(self.packet)):
            with self.subTest(kind=type(packet).__name__):
                self.refused(packet)

    def test_magic_truncation_and_trailing_bytes_are_refused(self):
        """No prefix, suffix or incomplete segment is accepted as the exact request."""
        for packet in (b'', self.packet[:3], self.packet[:7], b'BAD1' + self.packet[4:],
                       self.packet[:-1], self.packet + b'x',
                       MAGIC + struct.pack('>I', 0) + self.packet[8:],
                       MAGIC + struct.pack('>I', 0xffffffff) + self.packet[8:]):
            with self.subTest(size=len(packet), prefix=packet[:8]):
                self.refused(packet)

    def test_unknown_or_missing_fields_cannot_select_execution_behavior(self):
        """Closed metadata excludes paths, callbacks, alternate executors and URLs."""
        paths = (
            (), ('request',), ('resolved_request',), ('expected_source_binding',),
            ('resolved_source_binding',), ('request', 'source_binding', 'identity'),
            ('request', 'policy_record'), ('plan',), ('segments',),
            ('segments', 'canonical_result'),
        )
        for path in paths:
            metadata = deepcopy(self.metadata)
            target = metadata
            for key in path:
                target = target[key]
            target['caller_executor'] = CANARY
            with self.subTest(path=path):
                self.refused(framed(metadata, self.parts))
        for key in self.metadata:
            metadata = deepcopy(self.metadata)
            del metadata[key]
            with self.subTest(missing=key):
                self.refused(framed(metadata, self.parts))
        for key in ('directory', 'run_id', 'renderer', 'resource_budget', 'input_url'):
            metadata = deepcopy(self.metadata)
            metadata[key] = CANARY
            with self.subTest(execution_selection=key):
                self.refused(framed(metadata, self.parts))

    def test_duplicate_keys_noncanonical_json_and_noninteger_lengths_refuse(self):
        """JSON aliases must not hide an alternate field value or length."""
        raw = canonical(self.metadata)
        count = b'"bytes":' + str(len(self.parts[0])).encode()
        malformed = (
            b'{"schema":"' + SCHEMA.encode() + b'",' + raw[1:],
            raw.replace(b'"request_id":',
                        b'"request_id":"' + CANARY.encode() + b'","request_id":', 1),
            b' ' + raw,
            raw.replace(count, b'"bytes":true', 1),
            raw.replace(count, b'"bytes":1.0', 1),
            raw.replace(count, b'"bytes":NaN', 1),
            raw.replace(count, b'"bytes":Infinity', 1),
        )
        for metadata_bytes in malformed:
            with self.subTest(metadata_sha256=sha256(metadata_bytes).hexdigest()):
                self.refused(framed(self.metadata, self.parts,
                                    metadata_bytes=metadata_bytes))

    def test_each_raw_segment_is_exactly_bound(self):
        """A matching envelope hash does not excuse source or resource substitution."""
        for index in range(3):
            parts = list(self.parts)
            parts[index] = parts[index][:-1] + bytes([parts[index][-1] ^ 1])
            with self.subTest(segment=SEGMENTS[index]):
                self.refused(framed(self.metadata, parts))
        self.refused(framed(self.metadata, (self.parts[1], self.parts[0], self.parts[2])))

    def test_declared_segment_lengths_and_hashes_cannot_be_reinterpreted(self):
        """Exact declared lengths prevent shifting bytes between adjacent sources."""
        for name in SEGMENTS:
            for field, value in (('bytes', 0), ('bytes', -1), ('sha256', '0' * 64)):
                metadata = deepcopy(self.metadata)
                metadata['segments'][name][field] = value
                with self.subTest(segment=name, field=field, value=value):
                    self.refused(framed(metadata, self.parts))
        metadata = deepcopy(self.metadata)
        metadata['segments']['canonical_result']['bytes'] += 1
        metadata['segments']['evidence_snapshot']['bytes'] -= 1
        self.refused(framed(metadata, self.parts))

    def test_resolved_request_and_source_roles_cannot_be_collapsed(self):
        """A foreign resolved request/source must fail even when its envelope matches."""
        for role, path in (
                ('resolved_request', ('request_id',)),
                ('resolved_source_binding', ('identity', 'case_id'))):
            metadata = deepcopy(self.metadata)
            target = metadata[role]
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = CANARY
            with self.subTest(role=role):
                self.refused(framed(metadata, self.parts))

    def test_unready_workflow_and_unsupported_request_scope_refuse(self):
        """Resealing a request cannot enable a locale, intended use or workflow state."""
        for field, value in (
                ('locale_id', 'pt-BR'), ('intended_use_id', 'clinical-final'),
                ('consent_status', 'WITHDRAWN'), ('review_state', 'PENDING'),
                ('consent_record', None), ('review_record', None),
                ('request_id', 'x' * 257), ('requester_id', True),
                ('schema_version', '2.0.0')):
            metadata = deepcopy(self.metadata)
            metadata['request'][field] = value
            metadata['resolved_request'][field] = value
            with self.subTest(field=field, value=value):
                self.refused(framed(metadata, self.parts),
                             expected_request_sha256=sha256(
                                 canonical(metadata['request'])).hexdigest())
        metadata = deepcopy(self.metadata)
        metadata['expected_source_binding']['report_id'] = 'foreign-report-family'
        rebind_metadata(metadata, self.parts)
        self.refused(framed(metadata, self.parts), expected_request_sha256=sha256(
            canonical(metadata['request'])).hexdigest())

    def test_plan_inventory_and_fixed_sections_are_revalidated(self):
        """Rebinding a plan digest must not admit exclusions or incomplete inventory."""
        changes = (
            ('expected_finding_ids', list(IDS[:1])),
            ('expected_finding_ids', list(IDS) + ['FOREIGN-FINDING']),
            ('expected_section_ids', list(SECTIONS[:-1])),
            ('required_section_ids', list(SECTIONS[:-1])),
            ('upstream_exclusions', [{'finding_id': IDS[0],
                'policy_record': self.metadata['request']['policy_record'],
                'reason_code': 'SYNTHETIC-EXCLUSION'}]),
        )
        for field, value in changes:
            metadata = deepcopy(self.metadata)
            metadata['plan'][field] = value
            rebind_metadata(metadata, self.parts)
            with self.subTest(field=field, value=value):
                self.refused(framed(metadata, self.parts),
                             expected_request_sha256=sha256(
                                 canonical(metadata['request'])).hexdigest())

    def test_profile_selection_cannot_come_from_the_payload(self):
        """An arbitrary but well-formed profile digest cannot select another runtime."""
        for field in ('resource_profile_sha256', 'storage_profile_sha256'):
            metadata = deepcopy(self.metadata)
            metadata[field] = 'a' * 64
            with self.subTest(field=field):
                self.refused(framed(metadata, self.parts))
                self.refused(framed(metadata, self.parts),
                             **{'expected_' + field: 'a' * 64})

    def test_above_existing_finding_limit_is_refused_before_execution(self):
        """A complete but larger inventory cannot raise the inherited 128-finding cap."""
        document, _ = source()
        template = document['canonical_payload']['items'][0]
        items = []
        for index in range(129):
            item = deepcopy(template)
            item['canonical_variant_id'] = 'omnigenis:small-variant:v1:sha256:' + sha256(
                ('synthetic-request-cap-' + str(index)).encode()).hexdigest()
            items.append(item)
        document['canonical_payload']['items'] = items
        document['canonical_payload']['interpretation_item_count'] = len(items)
        document['raw_artifact_refs'] = [item['evidence_sha256'] for item in items]
        bound = bound_request(document, finding_ids=tuple(
            item['canonical_variant_id'] for item in items))
        metadata, parts = captured_metadata(bound, self.assets)
        self.refused(framed(metadata, parts),
                     expected_request_sha256=bound.request.request_sha256)

    def test_encoder_revalidates_retained_types_and_mutated_source_bytes(self):
        """Direct callers cannot bypass constructor checks after retaining an object."""
        for changes in ({'bound_request': {}}, {'resources': {}},
                        {'expected_resource_profile_sha256': '0' * 64},
                        {'expected_storage_profile_sha256': '0' * 64}):
            with self.subTest(field=next(iter(changes))), self.assertRaises(ValueError):
                self.encode(**changes)
        object.__setattr__(self.bound.sources, 'canonical_result_bytes', CANARY.encode())
        with self.assertRaises(ValueError) as error:
            self.encode()
        self.assertNotIn(CANARY, str(error.exception))

    def test_metadata_and_envelope_limits_follow_the_closed_existing_bounds(self):
        """A broad new quota or JSON-first parse would weaken bounded admission."""
        metadata_limit = len(canonical(maximum_metadata()))
        request_limit = (8 + metadata_limit + 2 * MAX_SNAPSHOT_BYTES
                         + raster_resources.MAX_BUNDLE_BYTES)
        self.assertEqual(self.m.MAX_METADATA_BYTES, metadata_limit)
        self.assertEqual(self.m.MAX_REQUEST_BYTES, request_limit)
        packets = (
            MAGIC + struct.pack('>I', metadata_limit + 1) + b'x' * (metadata_limit + 1),
            self.packet + b'x' * (request_limit + 1 - len(self.packet)),
        )
        for packet in packets:
            with self.subTest(size=len(packet)), \
                    patch.object(json, 'loads',
                                 side_effect=AssertionError('oversized JSON decoded')) as parse:
                self.refused(packet)
            parse.assert_not_called()

    def test_each_segment_ceiling_precedes_request_reconstruction(self):
        """A frame within its total ceiling still needs independent segment caps."""
        limits = (MAX_SNAPSHOT_BYTES, MAX_SNAPSHOT_BYTES,
                  raster_resources.MAX_BUNDLE_BYTES)
        for index, limit in enumerate(limits):
            parts = list(self.parts)
            parts[index] += b' ' * (limit + 1 - len(parts[index]))
            metadata = deepcopy(self.metadata)
            rebind_metadata(metadata, parts)
            packet = framed(metadata, parts)
            changes = {'expected_request_sha256': sha256(
                           canonical(metadata['request'])).hexdigest()}
            if index == 2:
                changes['expected_resources_sha256'] = sha256(parts[2]).hexdigest()
            with self.subTest(segment=SEGMENTS[index]), \
                    patch.object(ReportRequestSnapshot, '__post_init__',
                                 side_effect=AssertionError('oversized source reconstructed')) as build:
                self.refused(packet, **changes)
            build.assert_not_called()


class FinalDocumentRequestAdmissionTests(Inputs, unittest.TestCase):
    """The new entrypoint preserves existing policy and one-operation semantics."""

    def test_qualification_policy_and_inherited_disable_flags_precede_claims(self):
        """A data transport cannot activate itself or bypass a disabled predecessor."""
        os.environ.pop(MODE)
        self.refused(self.packet)
        os.environ[MODE] = 'qualification-only'
        for flag in DISABLE_FLAGS:
            with self.subTest(flag=flag), patch.dict(os.environ, {flag: '1'}):
                self.refused(self.packet)

    def test_caller_code_paths_and_resource_budgets_are_not_parameters(self):
        """The fixed signature must not expose a second execution-control channel."""
        for changes in ({'html': CANARY}, {'renderer': lambda: None},
                        {'callback': lambda: None}, {'input_path': CANARY},
                        {'resource_budget': {}}, {'final_release': True}):
            with self.subTest(field=next(iter(changes))), \
                    patch.object(final, 'execute_observed_stored_final_document_candidate',
                                 side_effect=AssertionError('unexpected complete execution')) as execute, \
                    self.assertRaises(TypeError):
                self.m.execute_stored_final_document_request(self.packet,
                    **self.expectations(), directory=self.directory, run_id=self.run_id, **changes)
            execute.assert_not_called()
        self.assertEqual(tuple(self.directory.iterdir()), ())

    def test_complete_operation_failure_is_content_free_and_is_not_retried(self):
        """A failed fixed consumer returns neither private failure text nor a result."""
        with patch.object(final, 'execute_observed_stored_final_document_candidate',
                          side_effect=ValueError(CANARY)) as execute:
            with self.assertRaises(ValueError) as error:
                self.m.execute_stored_final_document_request(
                    self.packet, **self.expectations(), directory=self.directory,
                    run_id=self.run_id)
        self.assertRegex(str(error.exception), r'^[a-z][a-z0-9_]*$')
        self.assertNotIn(CANARY, str(error.exception))
        self.assertIsNone(error.exception.__cause__)
        self.assertEqual(execute.call_count, 1)
        arguments = execute.call_args.kwargs
        self.assertEqual(arguments['bound_request'], self.bound)
        self.assertEqual(arguments['resources'].to_bytes(), self.assets.to_bytes())
        self.assertEqual(arguments['directory'], self.directory)
        self.assertEqual(arguments['run_id'], self.run_id)
        for key, value in self.expectations().items():
            if key != 'expected_envelope_sha256':
                self.assertEqual(arguments[key], value)


class FinalDocumentRequestRealConsumerTests(Inputs, unittest.TestCase):
    """One real long operation proves that the packet drives stored generation."""

    def test_real_complete_packet_consumer_retains_exact_independent_recovery(self):
        """The full consumer must create the actual same-PDF result and recover it."""
        arguments, _ = long_raster_inputs(final)
        bound = arguments['bound_request']
        assets = arguments['resources']
        packet = self.m.encode_final_document_request(
            bound_request=bound, resources=assets,
            expected_resource_profile_sha256=CANDIDATE_PROFILE_SHA256,
            expected_storage_profile_sha256=STORAGE_PROFILE_SHA256)
        expected = dict(expected_envelope_sha256=sha256(packet).hexdigest(),
                        expected_request_sha256=bound.request.request_sha256,
                        expected_resources_sha256=assets.bundle_sha256,
                        expected_resource_profile_sha256=CANDIDATE_PROFILE_SHA256,
                        expected_storage_profile_sha256=STORAGE_PROFILE_SHA256)
        pdf, manifest, observed = self.m.execute_stored_final_document_request(
            packet, **expected, directory=self.directory, run_id=self.run_id)
        self.assertGreater(len(pdf), 8 * 1024 * 1024)
        self.assertLessEqual(len(pdf), 16 * 1024 * 1024)
        self.assertGreater(manifest['page_count'], 32)
        self.assertLessEqual(manifest['page_count'], 64)
        result = manifest['result']
        binding = result['binding']
        self.assertEqual(binding['source_projection']['request_sha256'],
                         expected['expected_request_sha256'])
        self.assertEqual(binding['finding_count'], 96)
        self.assertEqual(len(binding['layout']['final_page_map']['findings']), 96)
        self.assertEqual(len(binding['layout']['final_page_map']['sections']), 9)
        self.assertTrue(binding['layout']['converged'])
        self.assertEqual(binding['layout']['native_inspection_invocations'], 1)
        expected_pdf = sha256(pdf).hexdigest()
        expected_result = sha256(canonical(result)).hexdigest()
        self.assertEqual(manifest['pdf_sha256'], expected_pdf)
        self.assertEqual(manifest['result_sha256'], expected_result)
        self.assertEqual(result['native_inspection']['pdf_sha256'], expected_pdf)
        self.assertTrue(result['native_inspection']['normalized_text_equivalence_verified'])
        self.assertEqual(observed['pdf_sha256'], expected_pdf)
        self.assertEqual(observed['result_sha256'], expected_result)
        self.assertEqual(observed['manifest_sha256'], sha256(canonical(manifest)).hexdigest())
        self.assertEqual(observed['observed_total_spawns'], observed['observed_total_exits'])
        self.assertGreater(observed['observed_total_spawns'], 0)
        self.assertEqual(observed['declared_retries'], 0)
        for value in (manifest, observed):
            for key in ('release_authorized', 'supported_execution',
                        'default_pipeline_activated'):
                self.assertIs(value[key], False)
        self.assertIs(observed['aggregate_job_resources_qualified'], False)

        run = self.directory / self.run_id
        self.assertEqual(sorted(path.name for path in run.iterdir()),
                         ['candidate.pdf', self.run_id + '.json', 'manifest.json'])
        receipt = read_job_receipt(run, self.run_id, 'SUCCEEDED', expected_result)
        self.assertFalse(receipt['release_authorized'])
        before = {path.name: (path.stat().st_ino, path.stat().st_mtime_ns,
                             path.stat().st_ctime_ns, sha256(path.read_bytes()).hexdigest())
                  for path in run.iterdir()}
        fresh_bound, fresh_assets = self.m.decode_final_document_request(packet, **expected)
        self.assertEqual(fresh_bound.sources.canonical_result_bytes,
                         bound.sources.canonical_result_bytes)
        recovery = dict(bound_request=fresh_bound, resources=fresh_assets,
                        expected_request_sha256=expected['expected_request_sha256'],
                        expected_resources_sha256=expected['expected_resources_sha256'],
                        expected_resource_profile_sha256=CANDIDATE_PROFILE_SHA256,
                        expected_storage_profile_sha256=STORAGE_PROFILE_SHA256,
                        directory=self.directory, run_id=self.run_id,
                        expected_result_sha256=expected_result,
                        expected_pdf_sha256=expected_pdf)
        with patch.object(raster, 'render_preloaded_raster_pdf') as render, \
                patch.object(native, 'execute_pdf_native_source_job') as inspect, \
                patch.object(final, '_run_locations') as locate, \
                patch.object(final.previous, '_write_stored_data') as write, \
                patch.object(final.previous, '_write_stored_receipt') as commit:
            recovered = final.read_stored_final_document_candidate(**recovery)
            self.assertEqual(recovered, (pdf, manifest))
            for field in ('expected_result_sha256', 'expected_pdf_sha256'):
                with self.subTest(field=field), self.assertRaises(final.PdfFinalDocumentError):
                    final.read_stored_final_document_candidate(
                        **{**recovery, field: '0' * 64})
            for operation in (render, inspect, locate, write, commit):
                operation.assert_not_called()
        after = {path.name: (path.stat().st_ino, path.stat().st_mtime_ns,
                            path.stat().st_ctime_ns, sha256(path.read_bytes()).hexdigest())
                 for path in run.iterdir()}
        self.assertEqual(after, before)
        # Retain this successful operation for the test controller; never rerun
        # native work merely to collect the already verified process evidence.
        _ACTUAL.update(packet=packet, pdf=pdf, manifest=manifest, observed=observed,
                       expected={**expected, 'expected_pdf_sha256': expected_pdf,
                                 'expected_result_sha256': expected_result})


if __name__ == '__main__':
    unittest.main()
