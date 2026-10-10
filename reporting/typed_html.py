"""Bounded semantic HTML preparation for the current typed reporting profile.

Callers supply already sealed native projection JSON and an independently pinned
digest. This checks declared structure and text, not source authenticity, science,
translation review, visual layout, PDF accessibility or release authorization.
Concurrent capture of mutable live application state is not supported.

Only inert HTML is prepared. No CSS, fonts, assets, URLs, scripts, file access,
network calls or native renderer are used. The existing PDF profile is unchanged.
Unavailable sections remain in the digest-bound projection sidecar; this module
does not invent explanatory prose or claim that a final report is complete.
"""
from __future__ import annotations

from dataclasses import InitVar, dataclass, field
from html import escape
from html.parser import HTMLParser
import hashlib
import json

from reporting.bindings import ReportBindingError, _digest
from reporting.components import (
    FindingRow, FindingsTable, TableColumn, TextComponent,
    MAX_COMPONENT_ITEMS, MAX_TEXT_BYTES, component_content_sha256,
)
from reporting.completeness import SectionAvailability
from reporting.pdf_candidate_qa import _snapshot_ir
from reporting._pdf_render_worker import HTML_BYTES as MAX_HTML_BYTES

PROFILE_ID = 'typed-report-html-preparation-v1'
_MAX_EVENTS = 8 * MAX_COMPONENT_ITEMS + 64
_END = object()


class TypedHtmlError(ValueError):
    """A fixed, content-free error; no partial HTML is a validated candidate."""


def _canonical(value: object) -> bytes:
    """Use established encoding only after the existing finite JSON admission."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def _require_digest(value: object) -> None:
    """Reject padded, coerced or otherwise unsupported digest representations."""
    try:
        _digest(value)
    except ReportBindingError:
        raise TypedHtmlError('typed_html_digest_invalid') from None


def _list(value: object) -> list:
    """Require native lists; no arbitrary iterable is coerced across this boundary."""
    if type(value) is not list:
        raise TypedHtmlError('typed_html_ir_invalid')
    return value


def capture_typed_document(value: object, expected_sha256: object) -> dict:
    """Capture and validate the sealed typed record without retaining source handles.

    This reuses component and section contracts. The expected digest binds the
    whole existing projection, including context and declared accounting. It does
    not independently repeat authenticated assembly or scientific admission.
    """
    _require_digest(expected_sha256)
    try:
        doc = _snapshot_ir(value)
        if hashlib.sha256(_canonical(doc)).hexdigest() != expected_sha256:
            raise TypedHtmlError('typed_html_ir_digest_mismatch')
        fixed = {'schema_version': '1.0.0', 'profile_id': 'typed-report-projection-v1',
                 'status': 'PROJECTED', 'conformance_scope': 'DECLARED_TYPED_PROJECTION_ONLY',
                 'release_authorization': 'NOT_ESTABLISHED', 'report_id': 'e1a-small-variant-report',
                 'locale_id': 'en-US'}
        flags = ('source_semantics_validated', 'rendered_content_validated')
        hashes = ('request_sha256', 'source_binding_sha256', 'plan_sha256',
                  'ledger_sha256', 'content_sha256')
        if set(doc) != set(fixed) | set(flags) | set(hashes) | {'counts', 'components', 'section_states'}:
            raise TypedHtmlError('typed_html_ir_invalid')
        if any(type(doc[k]) is not str or doc[k] != v for k, v in fixed.items()):
            raise TypedHtmlError('typed_html_profile_not_supported')
        if any(doc[k] is not False for k in flags):
            raise TypedHtmlError('typed_html_ir_invalid')
        for key in hashes:
            _require_digest(doc[key])
        records = _list(doc['components'])
        reconstructed = []
        for record in records:
            if type(record) is not dict:
                raise TypedHtmlError('typed_html_ir_invalid')
            if record['component_type'] == 'findings_table':
                columns = tuple(TableColumn(**c) for c in _list(record['columns']))
                rows = tuple(FindingRow(r['finding_id'], tuple(_list(r['cells'])),
                             tuple(_list(r['protected_tokens']))) for r in _list(record['rows']))
                item = FindingsTable(record['component_id'], record['section_id'],
                    record['caption'], columns, rows, record['locale_id'])
            else:
                item = TextComponent(record['component_id'], record['section_id'],
                    record['component_type'], record['text'], tuple(_list(record['protected_tokens'])),
                    record['locale_id'])
            if item.to_dict() != record:
                raise TypedHtmlError('typed_html_ir_invalid')
            reconstructed.append(item)
        if component_content_sha256(tuple(reconstructed)) != doc['content_sha256']:
            raise TypedHtmlError('typed_html_content_digest_mismatch')
        if not records or records[0]['component_type'] != 'document_title':
            raise TypedHtmlError('typed_html_ir_invalid')
        if sum(r['component_type'] == 'document_title' for r in records) != 1:
            raise TypedHtmlError('typed_html_ir_invalid')
        states = tuple(SectionAvailability(**s) for s in _list(doc['section_states']))
        if not states or any(s.availability in ('BLOCKED', 'UNKNOWN') for s in states):
            raise TypedHtmlError('typed_html_ir_invalid')
        section_ids = [s.section_id for s in states]
        if len(section_ids) != len(set(section_ids)):
            raise TypedHtmlError('typed_html_ir_invalid')
        if {r['section_id'] for r in records} != {s.section_id for s in states if s.availability == 'PRESENT'}:
            raise TypedHtmlError('typed_html_ir_invalid')
        section_order = {sid: i for i, sid in enumerate(section_ids)}
        positions = [section_order[r['section_id']] for r in records]
        if positions != sorted(positions):
            raise TypedHtmlError('typed_html_ir_invalid')
        row_ids = [r['finding_id'] for c in records if c['component_type'] == 'findings_table' for r in c['rows']]
        counts = {'components': len(records), 'represented_findings': len(set(row_ids)), 'table_rows': len(row_ids)}
        if type(doc['counts']) is not dict or doc['counts'] != counts or any(type(n) is not int for n in doc['counts'].values()):
            raise TypedHtmlError('typed_html_ir_invalid')
        return doc
    except TypedHtmlError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        raise TypedHtmlError('typed_html_ir_invalid') from None


def _escaped(text: str) -> str:
    """Escape inert text once; encode CR so HTML newline handling cannot erase it."""
    return escape(text, quote=True).replace('\r', '&#13;')


def _emit_typed_html(doc: dict) -> str:
    """Serialize only the fixed semantic markup, with a finite expansion budget."""
    parts = []
    size = 0

    def append(text: str) -> None:
        """Reject whole output on exhaustion rather than retain an accepted prefix."""
        nonlocal size
        size += len(text.encode('utf-8'))
        if size > MAX_HTML_BYTES:
            raise TypedHtmlError('typed_html_output_budget_exceeded')
        parts.append(text)

    append('<!doctype html><html lang="en-US"><head><meta charset="utf-8">'
           '<title>OmniGenis</title></head><body>')
    for c in doc['components']:
        attrs = f'id="{_escaped(c["component_id"])}" data-section="{_escaped(c["section_id"])}"'
        kind = c['component_type']
        if kind != 'findings_table':
            tag = {'document_title': 'h1', 'section_heading': 'h2', 'paragraph': 'p'}[kind]
            append(f'<{tag} {attrs}>{_escaped(c["text"])}</{tag}>')
            continue
        append(f'<table {attrs}><caption>{_escaped(c["caption"])}</caption><thead><tr>')
        for column in c['columns']:
            append(f'<th scope="col" data-column="{_escaped(column["column_id"])}">{_escaped(column["label"])}</th>')
        append('</tr></thead><tbody>')
        for row in c['rows']:
            append(f'<tr data-finding="{_escaped(row["finding_id"])}">')
            for cell in row['cells']:
                append(f'<td>{_escaped(cell)}</td>')
            append('</tr>')
        append('</tbody></table>')
    append('</body></html>')
    return ''.join(parts)


def _expected_events(doc: dict):
    """Describe expected structure/text independently of HTML escaping/serialization."""
    yield ('declaration', 'doctype html')
    yield ('start', 'html', (('lang', 'en-US'),))
    yield ('start', 'head', ())
    yield ('start', 'meta', (('charset', 'utf-8'),))
    yield ('start', 'title', ())
    yield ('text', 'OmniGenis')
    yield ('end', 'title')
    yield ('end', 'head')
    yield ('start', 'body', ())
    for component in doc['components']:
        kind = component['component_type']
        attrs = (('id', component['component_id']), ('data-section', component['section_id']))
        if kind in ('document_title', 'section_heading', 'paragraph'):
            tag = 'h1' if kind == 'document_title' else 'h2' if kind == 'section_heading' else 'p'
            yield ('start', tag, attrs)
            yield ('text', component['text'])
            yield ('end', tag)
        else:
            yield ('start', 'table', attrs)
            yield ('start', 'caption', ())
            yield ('text', component['caption'])
            yield ('end', 'caption')
            yield ('start', 'thead', ())
            yield ('start', 'tr', ())
            for column in component['columns']:
                yield ('start', 'th', (('scope', 'col'), ('data-column', column['column_id'])))
                yield ('text', column['label'])
                yield ('end', 'th')
            yield ('end', 'tr')
            yield ('end', 'thead')
            yield ('start', 'tbody', ())
            for row in component['rows']:
                yield ('start', 'tr', (('data-finding', row['finding_id']),))
                for cell in row['cells']:
                    yield ('start', 'td', ())
                    yield ('text', cell)
                    yield ('end', 'td')
                yield ('end', 'tr')
            yield ('end', 'tbody')
            yield ('end', 'table')
    yield ('end', 'body')
    yield ('end', 'html')


class _EventChecker(HTMLParser):
    """Compare a bounded complete event stream, without browser or URL execution."""

    def __init__(self, doc: dict) -> None:
        super().__init__(convert_charrefs=True)
        self.expected = iter(_expected_events(doc))
        self.parts = []
        self.text_size = 0
        self.events = 0
        self.digest = hashlib.sha256()

    def _consume(self, event: tuple) -> None:
        """Reject the first structural/content mismatch without echoing report data."""
        self.events += 1
        if self.events > _MAX_EVENTS or event != next(self.expected, _END):
            raise TypedHtmlError('typed_html_content_mismatch')
        self.digest.update(_canonical(event) + b'\n')

    def _flush(self) -> None:
        """Coalesce adjacent parser text fragments while preserving every character."""
        if self.parts:
            self._consume(('text', ''.join(self.parts)))
            self.parts.clear()
            self.text_size = 0

    def handle_starttag(self, tag, attrs):
        """Match tag and all attributes, including duplicates and semantic scopes."""
        self._flush()
        self._consume(('start', tag, tuple(attrs)))

    def handle_endtag(self, tag):
        """Exact expected nesting/order is enforced by the event sequence."""
        self._flush()
        self._consume(('end', tag))

    def handle_data(self, data):
        """Bound each expanded text record before retaining parser fragments."""
        if len(data) > MAX_TEXT_BYTES:
            raise TypedHtmlError('typed_html_text_budget_exceeded')
        self.text_size += len(data.encode('utf-8'))
        if self.text_size > MAX_TEXT_BYTES:
            raise TypedHtmlError('typed_html_text_budget_exceeded')
        if data:
            self.parts.append(data)

    def handle_decl(self, decl):
        """Allow only the exact non-network doctype in its expected location."""
        self._flush()
        self._consume(('declaration', decl))

    def handle_startendtag(self, tag, attrs):
        """Do not silently reinterpret self-closing syntax for this fixed grammar."""
        raise TypedHtmlError('typed_html_markup_not_supported')

    def handle_comment(self, data):
        """No hidden report channel is part of the admitted HTML profile."""
        raise TypedHtmlError('typed_html_markup_not_supported')

    def handle_pi(self, data):
        """Processing instructions are never admitted."""
        raise TypedHtmlError('typed_html_markup_not_supported')

    def unknown_decl(self, data):
        """Unknown declarations fail instead of becoming an uninspected region."""
        raise TypedHtmlError('typed_html_markup_not_supported')

    def finish(self) -> str:
        """Require every expected event; an unfinished stream is never success."""
        self.close()
        self._flush()
        if next(self.expected, _END) is not _END:
            raise TypedHtmlError('typed_html_content_mismatch')
        return self.digest.hexdigest()


def _check_html_events(doc: dict, html: str) -> str:
    """Inspect all emitted structure/text through an independent parser path."""
    checker = _EventChecker(doc)
    checker.feed(html)
    return checker.finish()


@dataclass(frozen=True, slots=True, repr=False)
class TypedHtmlValidation:
    """Validated HTML-only evidence; input contents are not retained in this record."""

    presentation_ir: InitVar[object]
    expected_ir_sha256: InitVar[object]
    html: InitVar[object]
    expected_html_sha256: InitVar[object]
    ir_sha256: str = field(init=False)
    html_sha256: str = field(init=False)
    semantic_sha256: str = field(init=False)
    _counts: tuple[int, int, int, int] = field(init=False)

    def __post_init__(self, presentation_ir, expected_ir_sha256, html, expected_html_sha256):
        """Direct construction runs the same identity, budget and semantic checks."""
        doc = capture_typed_document(presentation_ir, expected_ir_sha256)
        _require_digest(expected_html_sha256)
        if type(html) is not str or len(html) > MAX_HTML_BYTES:
            raise TypedHtmlError('typed_html_output_invalid')
        try:
            encoded = html.encode('utf-8')
        except UnicodeError:
            raise TypedHtmlError('typed_html_output_invalid') from None
        if len(encoded) > MAX_HTML_BYTES:
            raise TypedHtmlError('typed_html_output_budget_exceeded')
        if hashlib.sha256(encoded).hexdigest() != expected_html_sha256:
            raise TypedHtmlError('typed_html_output_digest_mismatch')
        semantic = _check_html_events(doc, html)
        counts = doc['counts']
        object.__setattr__(self, 'ir_sha256', expected_ir_sha256)
        object.__setattr__(self, 'html_sha256', expected_html_sha256)
        object.__setattr__(self, 'semantic_sha256', semantic)
        object.__setattr__(self, '_counts', (counts['components'], counts['represented_findings'],
            counts['table_rows'], sum(s['availability'] != 'PRESENT' for s in doc['section_states'])))

    @property
    def passed(self) -> bool:
        """Only a successfully validated construction can produce this evidence."""
        return True

    def to_dict(self) -> dict[str, object]:
        """Expose detached counts/digests with explicit limits on validation claims."""
        return {'schema_version': '1.0.0', 'profile_id': PROFILE_ID, 'status': 'PASS',
                'conformance_scope': 'TYPED_HTML_STRUCTURE_AND_TEXT_ONLY', 'locale_id': 'en-US',
                'release_authorization': 'NOT_ESTABLISHED', 'pdf_validated': False,
                'visual_layout_validated': False, 'source_semantics_validated': False,
                'ir_sha256': self.ir_sha256, 'html_sha256': self.html_sha256,
                'semantic_sha256': self.semantic_sha256,
                'counts': dict(zip(('components', 'represented_findings', 'table_rows', 'not_present_sections'), self._counts))}


def validate_typed_html(*, presentation_ir: object, expected_ir_sha256: object,
                        html: object, expected_html_sha256: object) -> TypedHtmlValidation:
    """Validate one complete bounded HTML candidate; never render or publish it."""
    return TypedHtmlValidation(presentation_ir, expected_ir_sha256, html, expected_html_sha256)


def prepare_typed_html(*, presentation_ir: object, expected_ir_sha256: object) -> tuple[str, TypedHtmlValidation]:
    """Emit inert markup then independently verify the exact candidate before return."""
    doc = capture_typed_document(presentation_ir, expected_ir_sha256)
    html = _emit_typed_html(doc)
    html_digest = hashlib.sha256(html.encode('utf-8')).hexdigest()
    proof = validate_typed_html(presentation_ir=doc, expected_ir_sha256=expected_ir_sha256,
                               html=html, expected_html_sha256=html_digest)
    if (type(proof) is not TypedHtmlValidation or proof.ir_sha256 != expected_ir_sha256
            or proof.html_sha256 != html_digest or proof.passed is not True):
        raise TypedHtmlError('typed_html_evidence_invalid')
    return html, proof
