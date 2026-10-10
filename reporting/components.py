"""Closed, opt-in plain-text and findings-table projection contracts.

Inputs are already localized, upstream-authorized declarations. Matching their
request, content and ledger digests proves consistency, not source authenticity,
scientific correctness, translation review or final report release. This module
neither parses scientific payloads nor executes markup, expressions or URLs.

The initial contract supports the existing en-US technical report only. It is not
accepted by the current semantic-section renderer. A later coordinated adapter,
localization and content-QA profile must qualify actual rendering. Output retains
safe structured metadata, not the source/request objects used during assembly.

Finite item, UTF-8 byte, scalar and token budgets reject whole inputs. They are
admission guards, not editorial page/row limits or silent truncation. They do not
claim complete operation-level process isolation or aggregate execution budgets.
"""
from __future__ import annotations

from dataclasses import InitVar, dataclass, field
import hashlib
import json

from reporting.bindings import ReportBindingError, _digest, _identity
from reporting.completeness import ReportCompletenessError, ReportProjectionLedger
from reporting.requests import BoundReportRequest, ReportRequestError

COMPONENT_TYPES = frozenset({'document_title', 'section_heading', 'paragraph', 'findings_table'})
_TEXT_TYPES = COMPONENT_TYPES - {'findings_table'}
MAX_COMPONENT_ITEMS = 100_000
MAX_COMPONENT_TEXT_BYTES = 8 * 1024 * 1024
MAX_TEXT_BYTES = 64 * 1024
MAX_PROTECTED_TOKENS = 64


class ComponentError(ValueError):
    """Fixed content-free failure; no partial projection is a successful result."""


def _identifier(value: object) -> None:
    """Use the existing opaque-ID grammar without normalization or coercion."""
    try:
        _identity(value)
    except ReportBindingError:
        raise ComponentError('invalid_component_identifier') from None


def _sha256(value: object) -> None:
    """Accept only the project's exact lowercase SHA-256 representation."""
    try:
        _digest(value)
    except ReportBindingError:
        raise ComponentError('invalid_component_digest') from None


def _tuple(value: object) -> None:
    """Reject mutable/foreign iterables before iteration or copying."""
    if type(value) is not tuple:
        raise ComponentError('immutable_component_tuple_required')
    if len(value) > MAX_COMPONENT_ITEMS:
        raise ComponentError('component_budget_exceeded')


class _Budget:
    """Count all expanded records and text before building indexes or JSON."""

    def __init__(self) -> None:
        self.items = 0
        self.bytes = 0

    def add(self, count: int) -> None:
        """Admit an exact tuple length or fixed record overhead."""
        self.items += count
        if self.items > MAX_COMPONENT_ITEMS:
            raise ComponentError('component_budget_exceeded')

    def text(self, value: object, *, identifier: bool = False) -> None:
        """Keep text exact while refusing invalid Unicode and hidden controls."""
        self.add(1)
        if identifier:
            _identifier(value)
        elif type(value) is not str:
            raise ComponentError('plain_component_text_required')
        if len(value) > MAX_TEXT_BYTES:
            raise ComponentError('component_budget_exceeded')
        if not value.strip():
            raise ComponentError('plain_component_text_required')
        if any((ord(c) < 32 and c not in '\t\r\n') or ord(c) == 127
               or 0xD800 <= ord(c) <= 0xDFFF or 0x202A <= ord(c) <= 0x202E
               or 0x2066 <= ord(c) <= 0x2069 for c in value):
            raise ComponentError('invalid_component_text')
        size = len(value.encode('utf-8'))
        self.bytes += size
        if size > MAX_TEXT_BYTES or self.bytes > MAX_COMPONENT_TEXT_BYTES:
            raise ComponentError('component_budget_exceeded')


def _tokens(values: tuple[str, ...], texts: tuple[str, ...], budget: _Budget) -> None:
    """Bound token matching and preserve every declared token literally."""
    _tuple(values)
    if len(values) > MAX_PROTECTED_TOKENS:
        raise ComponentError('component_budget_exceeded')
    for value in values:
        budget.text(value)
    if len(values) != len(set(values)):
        raise ComponentError('duplicate_protected_token')
    # NUL is forbidden in every admitted value; a token cannot cross cell borders.
    combined = '\x00'.join(texts)
    if any(value not in combined for value in values):
        raise ComponentError('protected_component_token_missing')


def _locale(value: object) -> None:
    """A locale string is not permission to activate another language profile."""
    if type(value) is not str or value != 'en-US':
        raise ComponentError('component_locale_not_supported')


@dataclass(frozen=True, slots=True, repr=False)
class TextComponent:
    """One typed title, heading or paragraph; markup-like text stays literal."""

    component_id: str
    section_id: str
    component_type: str
    text: str
    protected_tokens: tuple[str, ...] = ()
    locale_id: str = 'en-US'

    def __post_init__(self) -> None:
        """Use the same validation for direct construction and whole documents."""
        _admit_components((self,))

    def to_dict(self) -> dict[str, object]:
        """Expose plain text only, with neither raw HTML nor executable fields."""
        return {'component_id': self.component_id, 'section_id': self.section_id,
                'component_type': self.component_type, 'locale_id': self.locale_id,
                'availability': 'PRESENT', 'text_format': 'plain', 'text': self.text,
                'protected_tokens': list(self.protected_tokens)}


@dataclass(frozen=True, slots=True, repr=False)
class TableColumn:
    """A stable column identity and an accessible plain-text header."""

    column_id: str
    label: str

    def __post_init__(self) -> None:
        """Reject unsupported labels rather than printing coerced objects."""
        budget = _Budget()
        budget.text(self.column_id, identifier=True)
        budget.text(self.label)

    def to_dict(self) -> dict[str, str]:
        """Return detached column metadata."""
        return {'column_id': self.column_id, 'label': self.label}


@dataclass(frozen=True, slots=True, repr=False)
class FindingRow:
    """One stable finding and its unchanged, already formatted display cells."""

    finding_id: str
    cells: tuple[str, ...]
    protected_tokens: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Validate bounded literal cells; table width is checked by the table."""
        _row(self, _Budget())

    def to_dict(self) -> dict[str, object]:
        """Preserve cell order and original numeric/identifier strings."""
        return {'finding_id': self.finding_id, 'cells': list(self.cells),
                'protected_tokens': list(self.protected_tokens)}


def _row(row: FindingRow, budget: _Budget) -> None:
    """Count a typed row and every cell, including repeated string references."""
    if type(row) is not FindingRow:
        raise ComponentError('typed_finding_row_required')
    budget.add(1)
    budget.text(row.finding_id, identifier=True)
    _tuple(row.cells)
    if not row.cells:
        raise ComponentError('finding_cells_required')
    for cell in row.cells:
        budget.text(cell)
    _tokens(row.protected_tokens, row.cells, budget)


@dataclass(frozen=True, slots=True, repr=False)
class FindingsTable:
    """A complete rectangular finding table with caption and stable row IDs."""

    component_id: str
    section_id: str
    caption: str
    columns: tuple[TableColumn, ...]
    rows: tuple[FindingRow, ...]
    locale_id: str = 'en-US'
    component_type: str = field(default='findings_table', init=False)

    def __post_init__(self) -> None:
        """Admit all rows, then check exact dimensions and unique identities."""
        _admit_components((self,))

    def to_dict(self) -> dict[str, object]:
        """Return all rows, never a page-limited or top-N selection."""
        return {'component_id': self.component_id, 'section_id': self.section_id,
                'component_type': self.component_type, 'locale_id': self.locale_id,
                'availability': 'PRESENT', 'text_format': 'plain', 'caption': self.caption,
                'columns': [c.to_dict() for c in self.columns],
                'rows': [r.to_dict() for r in self.rows]}


def _admit_components(components: tuple[TextComponent | FindingsTable, ...]) -> None:
    """Validate a closed nonrecursive graph under one expanded content budget."""
    _tuple(components)
    budget = _Budget()
    budget.add(len(components))
    for component in components:
        if type(component) not in (TextComponent, FindingsTable):
            raise ComponentError('typed_component_required')
        budget.text(component.component_id, identifier=True)
        budget.text(component.section_id, identifier=True)
        _locale(component.locale_id)
        if type(component) is TextComponent:
            if type(component.component_type) is not str or component.component_type not in _TEXT_TYPES:
                raise ComponentError('component_type_not_supported')
            budget.text(component.text)
            _tokens(component.protected_tokens, (component.text,), budget)
        else:
            if type(component.component_type) is not str or component.component_type != 'findings_table':
                raise ComponentError('component_type_not_supported')
            budget.text(component.caption)
            _tuple(component.columns)
            _tuple(component.rows)
            budget.add(len(component.columns))
            if not component.columns:
                raise ComponentError('table_columns_required')
            for column in component.columns:
                if type(column) is not TableColumn:
                    raise ComponentError('typed_table_column_required')
                budget.text(column.column_id, identifier=True)
                budget.text(column.label)
            for row in component.rows:
                _row(row, budget)
    # All graph content has been admitted before lookup collections are allocated.
    ids = [c.component_id for c in components]
    if len(ids) != len(set(ids)):
        raise ComponentError('duplicate_component_id')
    for component in components:
        if type(component) is FindingsTable:
            column_ids = [c.column_id for c in component.columns]
            row_ids = [r.finding_id for r in component.rows]
            if len(column_ids) != len(set(column_ids)) or len(row_ids) != len(set(row_ids)):
                raise ComponentError('duplicate_table_identity')
            if any(len(row.cells) != len(component.columns) for row in component.rows):
                raise ComponentError('table_width_mismatch')


def _hash(value: object) -> str:
    """Use the existing compact sorted UTF-8 encoding for admitted metadata."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode('utf-8')).hexdigest()


def component_content_sha256(components: tuple[TextComponent | FindingsTable, ...]) -> str:
    """Pin the exact ordered typed content after its finite admission checks."""
    _admit_components(components)
    return _hash([c.to_dict() for c in components])


@dataclass(frozen=True, slots=True, repr=False)
class TypedReportProjection:
    """Content and safe binding metadata; input request/source objects are not retained."""

    request: InitVar[BoundReportRequest]
    ledger: InitVar[ReportProjectionLedger]
    projection_request_sha256: str
    expected_content_sha256: str
    components: tuple[TextComponent | FindingsTable, ...]
    _source_sha256: str = field(init=False)
    _plan_sha256: str = field(init=False)
    _ledger_sha256: str = field(init=False)
    _report_id: str = field(init=False)
    _section_states: tuple = field(init=False)
    _finding_count: int = field(init=False)

    def __post_init__(self, request: BoundReportRequest, ledger: ReportProjectionLedger) -> None:
        """Check content, context and every declared locator before exposing a result."""
        content_sha = component_content_sha256(self.components)
        _sha256(self.projection_request_sha256)
        _sha256(self.expected_content_sha256)
        if content_sha != self.expected_content_sha256:
            raise ComponentError('component_content_digest_mismatch')
        if type(request) is not BoundReportRequest or type(ledger) is not ReportProjectionLedger:
            raise ComponentError('bound_request_and_ledger_required')
        try:
            BoundReportRequest.__post_init__(request)
            ReportProjectionLedger.__post_init__(ledger)
        except (ReportRequestError, ReportCompletenessError, ReportBindingError):
            raise ComponentError('projection_upstream_boundary_invalid') from None
        if self.projection_request_sha256 != request.request.request_sha256:
            raise ComponentError('projection_request_mismatch')
        if request.sources != ledger.sources or request.plan != ledger.plan:
            raise ComponentError('projection_ledger_context_mismatch')
        if not self.components or self.components[0].component_type != 'document_title':
            raise ComponentError('document_title_required_first')
        if sum(c.component_type == 'document_title' for c in self.components) != 1:
            raise ComponentError('document_title_not_unique')
        states = {s.section_id: s.availability for s in ledger.section_states}
        present = {k for k, v in states.items() if v == 'PRESENT'}
        actual_sections = {c.section_id for c in self.components}
        if actual_sections != present:
            raise ComponentError('component_section_coverage_mismatch')
        order = {s: i for i, s in enumerate(ledger.plan.expected_section_ids)}
        positions = [order[c.section_id] for c in self.components]
        if positions != sorted(positions):
            raise ComponentError('component_section_order_mismatch')
        tables = {c.component_id: c for c in self.components if type(c) is FindingsTable}
        expected_rows = {key: [] for key in tables}
        table_order = {key: index for index, key in enumerate(tables)}
        for finding in ledger.represented:
            previous_position = -1
            for component_id in finding.component_ids:
                table = tables.get(component_id)
                if table is None or table.section_id != finding.section_id:
                    raise ComponentError('finding_component_locator_mismatch')
                position = table_order[component_id]
                if position <= previous_position:
                    raise ComponentError('finding_component_order_mismatch')
                previous_position = position
                expected_rows[component_id].append(finding.finding_id)
        for key, table in tables.items():
            if [row.finding_id for row in table.rows] != expected_rows[key]:
                raise ComponentError('finding_table_accounting_mismatch')
        object.__setattr__(self, '_source_sha256', request.request.source_binding.binding_sha256)
        object.__setattr__(self, '_plan_sha256', request.plan.plan_sha256)
        object.__setattr__(self, '_ledger_sha256', ledger.ledger_sha256)
        object.__setattr__(self, '_report_id', request.request.source_binding.report_id)
        object.__setattr__(self, '_section_states', ledger.section_states)
        object.__setattr__(self, '_finding_count', len(ledger.represented))

    def _metadata(self) -> dict[str, object]:
        """Expose only context digests, derived counts and truthful validation scope."""
        return {'schema_version': '1.0.0', 'profile_id': 'typed-report-projection-v1',
                'status': 'PROJECTED', 'conformance_scope': 'DECLARED_TYPED_PROJECTION_ONLY',
                'release_authorization': 'NOT_ESTABLISHED', 'source_semantics_validated': False,
                'rendered_content_validated': False, 'report_id': self._report_id, 'locale_id': 'en-US',
                'request_sha256': self.projection_request_sha256, 'source_binding_sha256': self._source_sha256,
                'plan_sha256': self._plan_sha256, 'ledger_sha256': self._ledger_sha256,
                'content_sha256': self.expected_content_sha256,
                'counts': {'components': len(self.components), 'represented_findings': self._finding_count,
                           'table_rows': sum(len(c.rows) for c in self.components if type(c) is FindingsTable)}}

    def to_dict(self) -> dict[str, object]:
        """Return a detached typed document, with no scientific bytes or live handles."""
        return {**self._metadata(), 'section_states': [s.to_dict() for s in self._section_states],
                'components': [c.to_dict() for c in self.components]}

    @property
    def projection_sha256(self) -> str:
        """Hash the full typed content and its immutable binding metadata."""
        return _hash(self.to_dict())

    def summary(self) -> dict[str, object]:
        """Return content-free counts and hashes, never report text or case IDs."""
        return {**self._metadata(), 'projection_sha256': self.projection_sha256}


def build_typed_report_projection(
    *, request: BoundReportRequest, ledger: ReportProjectionLedger,
    projection_request_sha256: str, expected_content_sha256: str,
    components: tuple[TextComponent | FindingsTable, ...],
) -> TypedReportProjection:
    """Bind admitted typed content without activating rendering or final delivery."""
    return TypedReportProjection(request, ledger, projection_request_sha256,
                                 expected_content_sha256, components)
