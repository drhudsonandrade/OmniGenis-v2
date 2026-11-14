"""Bounded literal association of typed source units and observed PDF text.

This opt-in operation consumes independently expected source, observation and PDF
digests. It does not render or inspect a PDF, authenticate its worker, activate an
adapter, establish visible glyphs or authorize release. Its positive claim is the
unique complete role/order/literal-consistent mapping within this closed profile,
not the historical origin of indistinguishable source identities.

Only characterized positive containers, page-boundary paragraph continuations,
whole table rows and dense split rows are admitted. Empty/sparse carried cells,
split headings/captions and inferred whitespace are unsupported. Each output
record is charged before allocation; exhaustion refuses the complete operation.
"""
from __future__ import annotations

from dataclasses import InitVar, dataclass, field
from hashlib import sha256
import itertools
import json
import re

from reporting.pdf_typed_observation import (
    RESULT_BYTES as MAX_OBSERVATION_BYTES,
    TypedPdfObservation,
)
from reporting.typed_pdf_source import prepare_typed_pdf_source

PROFILE_ID = 'typed-report-pdf-association-v1'
MAX_SOURCE_UNITS = 20000
MAX_MAPPING_ITEMS = 20000
MAX_RESULT_BYTES = 4 * 1024 * 1024
_DIGEST = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
_ROLES = {'document_title': '/H1', 'section_heading': '/H2', 'paragraph': '/P'}
_NONCLAIMS = (
    'source_authenticity_verified', 'historical_source_origin_verified',
    'rendered_glyphs_verified', 'visual_layout_verified', 'reading_order_verified',
    'accessibility_qualified', 'scientific_equivalence_verified',
    'aggregate_job_resources_qualified', 'worker_results_authenticated',
    'release_authorized',
)


class TypedPdfAssociationError(ValueError):
    """Content-free refusal; no partial association or release claim is returned."""


def _require(value: bool) -> None:
    if not value:
        raise ValueError('typed_pdf_association_refused')


def _canonical(value: object) -> bytes:
    """Bound the actual serialized output, including structural evidence."""
    output = bytearray()
    encoder = json.JSONEncoder(sort_keys=True, separators=(',', ':'),
                               ensure_ascii=True, allow_nan=False)
    for part in encoder.iterencode(value):
        encoded = part.encode('ascii')
        _require(len(output) + len(encoded) <= MAX_RESULT_BYTES)
        output.extend(encoded)
    return bytes(output)


class _Accumulator:
    """Keep one occurrence's literal bytes within its own source-unit boundary."""

    def __init__(self, matcher: _Matcher, unit: dict, kind: str = 'PRIMARY'):
        self.matcher, self.unit = matcher, unit
        self.byte_count = self.scalar_count = 0
        self.hasher = sha256()
        target = matcher.units[unit['ordinal']]['occurrences']
        _require((kind == 'PRIMARY' and not target)
                 or (kind == 'REPEATED_TABLE_HEADER'
                     and unit['kind'] == 'table_header' and bool(target)))
        matcher.charge()
        self.record = {'ordinal': len(target), 'kind': kind, 'segments': []}
        target.append(self.record)

    def append(self, node: dict) -> None:
        segment, runs = self.matcher.container(node)
        byte_count = sum(run['utf8_bytes'] for run in runs)
        scalar_count = sum(run['scalars'] for run in runs)
        _require(byte_count > 0 and scalar_count > 0
                 and self.byte_count + byte_count <= self.unit['utf8_bytes']
                 and self.scalar_count + scalar_count <= self.unit['scalars'])
        for run in runs:
            self.hasher.update(run['text'].encode('utf-8'))
        self.byte_count += byte_count
        self.scalar_count += scalar_count
        self.record['segments'].append(segment)

    @property
    def complete(self) -> bool:
        return self.byte_count == self.unit['utf8_bytes']

    def finish(self) -> None:
        _require(self.complete and self.scalar_count == self.unit['scalars']
                 and self.hasher.hexdigest() == self.unit['text_sha256'])


class _Matcher:
    """Linear structural matching with forced positive-container endpoints."""

    def __init__(self, source: dict, physical: dict):
        self.source, self.physical = source, physical
        trace = physical['trace']
        self.nodes = {tuple(n['reference']): n for n in trace['nodes']}
        self.pages = {tuple(p['reference']): p for p in trace['pages']}
        self.runs = {(tuple(p['reference']), r['mcid']): r
                     for p in trace['pages'] for r in p['runs']}
        self.used_nodes, self.used_runs = set(), set()
        self.mapping_items = self.container_count = 0
        self.header_repetitions = 0
        self.units, self.table_segments, self.row_segments = [], [], []
        for unit in source['units']:
            self.charge()
            self.units.append({
                'source_unit_ordinal': unit['ordinal'], 'kind': unit['kind'],
                'utf8_bytes': unit['utf8_bytes'], 'scalars': unit['scalars'],
                'text_sha256': unit['text_sha256'], 'occurrences': [],
            })
        document = self.nodes[tuple(trace['root_children'][0])]
        self.take(document, '/Document')
        self.top = self.children(document)
        self.cursor = 0
        page_indexes = [self.page_index(n) for n in self.top]
        _require(page_indexes == sorted(page_indexes)
                 and set(page_indexes) == set(range(physical['page_count'])))
        ordered_spans = {ref: [] for ref in self.pages}
        for node in trace['nodes']:
            if node['role'] == '/Span':
                ordered_spans[tuple(node['page_reference'])].append(
                    (tuple(node['reference']), node['children'][0]['value']))
        for ref, page in self.pages.items():
            _require(ordered_spans[ref] == [
                (tuple(run['structure_reference']), run['mcid'])
                for run in page['runs']])

    def charge(self) -> None:
        """Charge unit, occurrence, container, fragment, table or row records."""
        _require(self.mapping_items < MAX_MAPPING_ITEMS)
        self.mapping_items += 1

    def take(self, node: dict, role: str) -> None:
        reference = tuple(node['reference'])
        _require(node['role'] == role and reference not in self.used_nodes)
        self.used_nodes.add(reference)

    def children(self, node: dict) -> list[dict]:
        _require(all(child['kind'] == 'node' for child in node['children']))
        return [self.nodes[tuple(child['reference'])] for child in node['children']]

    def page_index(self, node: dict) -> int:
        return self.pages[tuple(node['page_reference'])]['index']

    def next_top(self, role: str) -> dict:
        _require(self.cursor < len(self.top))
        node = self.top[self.cursor]
        _require(node['role'] == role)
        self.cursor += 1
        return node

    def container(self, node: dict) -> tuple[dict, list[dict]]:
        """Assign every Span, including zero-text Spans, to this whole container."""
        _require(node['role'] in {'/H1', '/H2', '/P', '/Caption', '/TH', '/TD'})
        self.take(node, node['role'])
        self.charge()
        page_ref = tuple(node['page_reference'])
        fragments, runs = [], []
        for span in self.children(node):
            self.take(span, '/Span')
            mcid = span['children'][0]['value']
            key = page_ref, mcid
            _require(key not in self.used_runs)
            run = self.runs[key]
            _require(run['structure_reference'] == span['reference'])
            self.used_runs.add(key)
            self.charge()
            fragments.append({
                'run_ordinal': run['ordinal'], 'operator_ordinal': run['operator_ordinal'],
                'mcid': mcid, 'span_reference': list(span['reference']),
            })
            runs.append(run)
        self.container_count += 1
        return {
            'page_index': self.page_index(node),
            'page_reference': list(node['page_reference']),
            'container_reference': list(node['reference']),
            'fragments': fragments,
        }, runs

    def simple(self, unit: dict) -> None:
        role = _ROLES[unit['kind']]
        occurrence = _Accumulator(self, unit)
        previous_page = None
        while True:
            node = self.next_top(role)
            page = self.page_index(node)
            if previous_page is not None:
                _require(unit['kind'] == 'paragraph' and page == previous_page + 1)
            occurrence.append(node)
            if occurrence.complete:
                occurrence.finish()
                return
            _require(unit['kind'] == 'paragraph')
            previous_page = page

    def table(self, units: list[dict]) -> None:
        caption = units[0]
        _require(caption['kind'] == 'table_caption')
        headers = list(itertools.takewhile(
            lambda unit: unit['kind'] == 'table_header', units[1:]))
        width = len(headers)
        _require(width > 0)
        cells = units[1 + width:]
        _require(len(cells) % width == 0)
        row_count = len(cells) // width
        row_ordinal = table_ordinal = row_segment_ordinal = 0
        accumulators = None
        previous_page = None
        while True:
            table = self.next_top('/Table')
            self.take(table, '/Table')
            page = self.page_index(table)
            if previous_page is not None:
                _require(page == previous_page + 1)
            groups = self.children(table)
            roles = ['/Caption', '/THead', '/TBody'] if table_ordinal == 0 else ['/THead', '/TBody']
            _require([g['role'] for g in groups] == roles)
            caption_ref = None
            if table_ordinal == 0:
                occurrence = _Accumulator(self, caption)
                occurrence.append(groups[0])
                occurrence.finish()
                caption_ref = list(groups[0]['reference'])
            head, body = groups[-2:]
            self.take(head, '/THead')
            self.take(body, '/TBody')
            head_rows = self.children(head)
            _require(len(head_rows) == 1)
            header_row = head_rows[0]
            self.take(header_row, '/TR')
            physical_headers = self.children(header_row)
            _require(len(physical_headers) == width
                     and all(h['role'] == '/TH' for h in physical_headers))
            for unit, node in zip(headers, physical_headers, strict=True):
                kind = 'PRIMARY' if table_ordinal == 0 else 'REPEATED_TABLE_HEADER'
                occurrence = _Accumulator(self, unit, kind)
                occurrence.append(node)
                occurrence.finish()
                if table_ordinal:
                    self.header_repetitions += 1
            self.charge()
            self.table_segments.append({
                'component_ordinal': caption['component_ordinal'],
                'segment_ordinal': table_ordinal,
                'page_index': page, 'page_reference': list(table['page_reference']),
                'table_reference': list(table['reference']),
                'caption_reference': caption_ref,
                'thead_reference': list(head['reference']),
                'header_row_reference': list(header_row['reference']),
                'tbody_reference': list(body['reference']),
                'header_unit_ordinals': [u['ordinal'] for u in headers],
            })
            rows = self.children(body)
            if row_count == 0:
                _require(table_ordinal == 0 and not rows)
                return
            _require(bool(rows))
            for physical_row_ordinal, row in enumerate(rows):
                _require(row_ordinal < row_count)
                self.take(row, '/TR')
                physical_cells = self.children(row)
                _require(len(physical_cells) == width
                         and all(td['role'] == '/TD' for td in physical_cells))
                source_cells = cells[row_ordinal * width:(row_ordinal + 1) * width]
                if accumulators is None:
                    accumulators = [_Accumulator(self, unit) for unit in source_cells]
                    row_segment_ordinal = 0
                for accumulator, td, th in zip(
                        accumulators, physical_cells, physical_headers, strict=True):
                    _require(td['headers'] == [th['native_id']])
                    accumulator.append(td)
                self.charge()
                self.row_segments.append({
                    'component_ordinal': caption['component_ordinal'],
                    'row_ordinal': row_ordinal, 'segment_ordinal': row_segment_ordinal,
                    'table_segment_ordinal': table_ordinal,
                    'page_index': page, 'row_reference': list(row['reference']),
                    'source_unit_ordinals': [u['ordinal'] for u in source_cells],
                    'cell_references': [list(td['reference']) for td in physical_cells],
                })
                complete = [acc.complete for acc in accumulators]
                if all(complete):
                    for accumulator in accumulators:
                        accumulator.finish()
                    row_ordinal += 1
                    accumulators = None
                else:
                    # Dense continuation only: no completed/sparse carried column.
                    _require(not any(complete) and physical_row_ordinal == len(rows) - 1)
                    row_segment_ordinal += 1
            if row_ordinal == row_count:
                _require(accumulators is None)
                return
            table_ordinal += 1
            previous_page = page

    def match(self) -> None:
        for _ordinal, group in itertools.groupby(
                self.source['units'], key=lambda unit: unit['component_ordinal']):
            units = list(group)
            if units[0]['kind'] == 'table_caption':
                self.table(units)
            else:
                _require(len(units) == 1 and units[0]['kind'] in _ROLES)
                self.simple(units[0])
        _require(self.cursor == len(self.top)
                 and self.used_nodes == set(self.nodes)
                 and self.used_runs == set(self.runs)
                 and all(unit['occurrences'] for unit in self.units))

    def counts(self) -> dict:
        return {
            'source_units': len(self.units),
            'components': self.source['counts']['components'],
            'represented_findings': self.source['counts']['represented_findings'],
            'table_rows': self.source['counts']['table_rows'],
            'table_segments': len(self.table_segments), 'row_segments': len(self.row_segments),
            'header_repetitions': self.header_repetitions,
            'physical_fragments': len(self.used_runs), 'physical_nodes': len(self.used_nodes),
            'container_segments': self.container_count, 'mapping_items': self.mapping_items,
        }


def _associate(presentation_ir, expected_ir_sha256, expected_source_expectation_sha256,
               observation, expected_observation_sha256, expected_pdf_sha256) -> dict:
    for value in (expected_ir_sha256, expected_source_expectation_sha256,
                  expected_observation_sha256, expected_pdf_sha256):
        _require(type(value) is str and _DIGEST.fullmatch(value) is not None)
    _require(type(observation) is TypedPdfObservation)
    # An exact-class instance can still be forged with object.__new__. Bound its
    # captured immutable slot before calling any hashing or parsing boundary.
    payload = object.__getattribute__(observation, '_payload')
    _require(type(payload) is bytes and 0 < len(payload) <= MAX_OBSERVATION_BYTES)
    source = prepare_typed_pdf_source(
        presentation_ir=presentation_ir, expected_ir_sha256=expected_ir_sha256)
    _require(source.expectation_sha256 == expected_source_expectation_sha256)
    manifest = source.to_dict()
    _require(0 < len(manifest['units']) <= MAX_SOURCE_UNITS)
    admitted = TypedPdfObservation(payload)
    _require(admitted.observation_sha256 == expected_observation_sha256)
    physical = admitted.to_dict()
    _require(physical['pdf_sha256'] == expected_pdf_sha256)
    matcher = _Matcher(manifest, physical)
    matcher.match()
    result = {
        'schema_version': '1.0.0', 'profile_id': PROFILE_ID,
        'status': 'LITERAL_SOURCE_ASSOCIATED',
        'conformance_scope': 'ORDERED_TYPED_SOURCE_TO_PHYSICAL_DECLARED_TEXT_ONLY',
        'literal_text_policy': 'SOURCE_LITERAL_UTF8_NO_NORMALIZATION',
        'source_expectation_sha256': source.expectation_sha256,
        'observation_sha256': admitted.observation_sha256,
        'pdf_sha256': physical['pdf_sha256'], 'pdf_byte_count': physical['pdf_byte_count'],
        'page_count': physical['page_count'],
        'observer_profile_sha256': physical['profile_sha256'],
        'source_counts': manifest['counts'], 'counts': matcher.counts(),
        'claims': {
            'literal_hashes_matched': True, 'complete_physical_coverage': True,
            'unique_mapping_within_profile': True,
            **{key: False for key in _NONCLAIMS},
        },
        'units': matcher.units, 'table_segments': matcher.table_segments,
        'row_segments': matcher.row_segments,
    }
    for key in ('ir_sha256', 'request_sha256', 'source_binding_sha256', 'plan_sha256',
                'ledger_sha256', 'content_sha256', 'section_states_sha256'):
        result[key] = manifest[key]
    return result


@dataclass(frozen=True, slots=True, repr=False)
class TypedPdfAssociation:
    """Immutable association evidence; construction always performs admission."""

    presentation_ir: InitVar[object]
    expected_ir_sha256: InitVar[object]
    expected_source_expectation_sha256: InitVar[object]
    observation: InitVar[object]
    expected_observation_sha256: InitVar[object]
    expected_pdf_sha256: InitVar[object]
    association_sha256: str = field(init=False)
    _serialized: bytes = field(init=False, repr=False)

    def __post_init__(self, presentation_ir, expected_ir_sha256,
                      expected_source_expectation_sha256, observation,
                      expected_observation_sha256, expected_pdf_sha256):
        try:
            result = _associate(
                presentation_ir, expected_ir_sha256, expected_source_expectation_sha256,
                observation, expected_observation_sha256, expected_pdf_sha256)
            serialized = _canonical(result)
            object.__setattr__(self, '_serialized', serialized)
            object.__setattr__(self, 'association_sha256', sha256(serialized).hexdigest())
        except Exception:
            raise TypedPdfAssociationError('typed_pdf_association_refused') from None

    def to_bytes(self) -> bytes:
        """Return canonical immutable evidence without duplicating report text."""
        return self._serialized

    def to_dict(self) -> dict:
        """Return detached private structural evidence."""
        return json.loads(self._serialized)

    def summary(self) -> dict:
        """Expose bindings, counts and claims without source IDs or references."""
        result = self.to_dict()
        for key in ('units', 'table_segments', 'row_segments'):
            result.pop(key)
        result['association_sha256'] = self.association_sha256
        return result

    def __repr__(self) -> str:
        return f"TypedPdfAssociation(association_sha256='{self.association_sha256}')"


def associate_typed_pdf(*, presentation_ir: object, expected_ir_sha256: object,
                        expected_source_expectation_sha256: object, observation: object,
                        expected_observation_sha256: object,
                        expected_pdf_sha256: object) -> TypedPdfAssociation:
    """Associate complete declared literals only; never render or release a PDF."""
    return TypedPdfAssociation(
        presentation_ir, expected_ir_sha256, expected_source_expectation_sha256,
        observation, expected_observation_sha256, expected_pdf_sha256)
