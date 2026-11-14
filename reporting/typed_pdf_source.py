"""Bounded ordered source expectations for a future typed PDF content observer.

The existing sealed projection supplies every source identity and literal value.
This module records logical units before rendering; it does not observe a PDF,
assign physical fragments, normalize whitespace, qualify repeated headers or
activate an adapter. Every unit digest covers unchanged UTF-8 text. The manifest
digest also covers unit boundaries, order, source locators and context bindings.

Only the current technical en-US projection is admitted. Scientific correctness,
source authenticity, rendered-content equivalence, visual layout, accessibility
and release authorization remain unestablished. The manifest contains source
identifiers and is not a public diagnostic. Summaries and failures omit them.

Finite source and output budgets reject the complete operation on exhaustion.
These admission bounds do not establish native or whole-job resource isolation.
Concurrent capture of mutable live application state is not supported.
"""
from __future__ import annotations

from dataclasses import InitVar, dataclass, field
import hashlib
import json

from reporting.components import MAX_COMPONENT_ITEMS
from reporting.typed_html import TypedHtmlError, capture_typed_document

PROFILE_ID = 'typed-report-pdf-source-v1'
MAX_SOURCE_UNITS = MAX_COMPONENT_ITEMS
MAX_EXPECTATION_BYTES = 64 * 1024 * 1024
_COUNT_KEYS = ('components', 'represented_findings', 'table_rows',
               'not_present_sections', 'source_units',
               'literal_utf8_bytes', 'literal_scalars')


class TypedPdfSourceError(ValueError):
    """A content-free failure; no accepted prefix or PDF claim is returned."""


def _canonical(value: object) -> bytes:
    """Bound canonical output while encoding the already admitted native data."""
    encoder = json.JSONEncoder(sort_keys=True, separators=(',', ':'),
                               ensure_ascii=False, allow_nan=False)
    output = bytearray()
    for part in encoder.iterencode(value):
        encoded = part.encode('utf-8')
        if len(output) + len(encoded) > MAX_EXPECTATION_BYTES:
            raise TypedPdfSourceError('typed_pdf_source_output_budget_exceeded')
        output.extend(encoded)
    return bytes(output)


def _manifest(doc: dict, ir_sha256: str) -> dict:
    """Derive logical units solely from the captured source, never from output."""
    units = []
    byte_count = 0
    scalar_count = 0

    def append(component, component_ordinal, kind, text, *,
               row_ordinal=None, column_ordinal=None,
               finding_id=None, column_id=None):
        """Keep equal text at different source locations as distinct units."""
        nonlocal byte_count, scalar_count
        if len(units) >= MAX_SOURCE_UNITS:
            raise TypedPdfSourceError('typed_pdf_source_unit_budget_exceeded')
        literal = text.encode('utf-8')
        byte_count += len(literal)
        scalar_count += len(text)
        units.append({
            'ordinal': len(units), 'kind': kind,
            'component_ordinal': component_ordinal,
            'component_id': component['component_id'],
            'section_id': component['section_id'],
            'row_ordinal': row_ordinal, 'column_ordinal': column_ordinal,
            'finding_id': finding_id, 'column_id': column_id,
            'utf8_bytes': len(literal), 'scalars': len(text),
            'text_sha256': hashlib.sha256(literal).hexdigest(),
        })

    for component_ordinal, component in enumerate(doc['components']):
        kind = component['component_type']
        if kind != 'findings_table':
            append(component, component_ordinal, kind, component['text'])
            continue
        append(component, component_ordinal, 'table_caption', component['caption'])
        for column_ordinal, column in enumerate(component['columns']):
            append(component, component_ordinal, 'table_header', column['label'],
                   column_ordinal=column_ordinal, column_id=column['column_id'])
        for row_ordinal, row in enumerate(component['rows']):
            for column_ordinal, (column, cell) in enumerate(
                    zip(component['columns'], row['cells'], strict=True)):
                append(component, component_ordinal, 'table_cell', cell,
                       row_ordinal=row_ordinal, column_ordinal=column_ordinal,
                       finding_id=row['finding_id'], column_id=column['column_id'])

    counts = dict(doc['counts'])
    counts.update({
        'not_present_sections': sum(s['availability'] != 'PRESENT'
                                    for s in doc['section_states']),
        'source_units': len(units),
        'literal_utf8_bytes': byte_count, 'literal_scalars': scalar_count,
    })
    result = {
        'schema_version': '1.0.0', 'profile_id': PROFILE_ID,
        'status': 'PREPARED',
        'conformance_scope': 'ORDERED_TYPED_SOURCE_EXPECTATION_ONLY',
        'literal_text_policy': 'SOURCE_LITERAL_UTF8_NO_NORMALIZATION',
        'physical_mapping': 'NOT_ESTABLISHED',
        'release_authorization': 'NOT_ESTABLISHED',
        'report_id': doc['report_id'], 'locale_id': doc['locale_id'],
        'source_semantics_validated': False,
        'rendered_content_validated': False,
        'visual_layout_validated': False, 'accessibility_validated': False,
        'ir_sha256': ir_sha256,
        'section_states_sha256': hashlib.sha256(
            _canonical(doc['section_states'])).hexdigest(),
        'counts': counts, 'units': units,
    }
    for key in ('request_sha256', 'source_binding_sha256', 'plan_sha256',
                'ledger_sha256', 'content_sha256'):
        result[key] = doc[key]
    return result


@dataclass(frozen=True, slots=True, repr=False)
class TypedPdfSourceExpectation:
    """Immutable source expectation; construction always admits the sealed input."""

    presentation_ir: InitVar[object]
    expected_ir_sha256: InitVar[object]
    ir_sha256: str = field(init=False)
    expectation_sha256: str = field(init=False)
    _serialized: bytes = field(init=False)
    _counts: tuple[int, ...] = field(init=False)

    def __post_init__(self, presentation_ir, expected_ir_sha256):
        """Capture through the existing boundary without retaining mutable handles."""
        try:
            doc = capture_typed_document(presentation_ir, expected_ir_sha256)
        except TypedHtmlError:
            raise TypedPdfSourceError('typed_pdf_source_input_invalid') from None
        manifest = _manifest(doc, expected_ir_sha256)
        encoded = _canonical(manifest)
        object.__setattr__(self, 'ir_sha256', expected_ir_sha256)
        object.__setattr__(self, 'expectation_sha256', hashlib.sha256(encoded).hexdigest())
        object.__setattr__(self, '_serialized', encoded)
        object.__setattr__(self, '_counts',
                           tuple(manifest['counts'][key] for key in _COUNT_KEYS))

    def to_dict(self) -> dict[str, object]:
        """Return a detached manifest with source identities but no literal text."""
        return json.loads(self._serialized)

    def summary(self) -> dict[str, object]:
        """Expose counts and bindings without source identifiers or report text."""
        return {
            'profile_id': PROFILE_ID, 'status': 'PREPARED',
            'conformance_scope': 'ORDERED_TYPED_SOURCE_EXPECTATION_ONLY',
            'ir_sha256': self.ir_sha256,
            'expectation_sha256': self.expectation_sha256,
            'counts': dict(zip(_COUNT_KEYS, self._counts, strict=True)),
        }


def prepare_typed_pdf_source(*, presentation_ir: object,
                            expected_ir_sha256: object) -> TypedPdfSourceExpectation:
    """Prepare source expectations only; never render, inspect or publish a PDF."""
    return TypedPdfSourceExpectation(presentation_ir, expected_ir_sha256)
