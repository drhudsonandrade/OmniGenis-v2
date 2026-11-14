"""Opt-in physical typed-PDF trace; source equivalence and release remain unestablished.

The full trace contains report text and is private caller data. Use summary()
for content-free engineering reporting. This module does not activate an adapter.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

from reporting._pdf_document_byte_budget import require_pdf_document_budget
from reporting._pdf_native_launch_budget import require_no_active_scope
from reporting.pdf_object_graph import _start, _wait

PROFILE_ID = "typed-pdf-physical-observation-v1"
PARSER_VERSION = "7.1.0"
STATUS = "PHYSICAL_TEXT_OBSERVED"
MAX_PDF_BYTES = 16777216
MAX_PAGES = 64
HEADER_BYTES = 67
RESULT_BYTES = 4194304
MAX_STREAM_BYTES = 8388608
MAX_TEXT_BYTES = 2097152
MAX_DEPTH = 64
MAX_VISITS = 20000
MAX_OPERATIONS = 20000
MAX_FONTS = 32
MAX_CMAP_BYTES = 262144
MAX_CMAP_TOTAL = 524288
MAX_CMAP_RECORDS = 16384
LIMITS = {"memory_bytes": 268435456, "cpu_seconds": 5,
          "file_bytes": RESULT_BYTES, "open_files": 128}
ROLES = ("/Document", "/H1", "/H2", "/P", "/Table", "/Caption",
         "/THead", "/TBody", "/TR", "/TH", "/TD", "/Span")
OPERATORS = ("q", "Q", "cm", "gs", "rg", "BDC", "BT", "Tm", "Tf", "TJ", "ET", "EMC")
NONCLAIMS = (
    "source_text_equivalence_verified", "rendered_glyphs_verified",
    "reading_order_verified", "accessibility_qualified",
    "scientific_equivalence_verified", "aggregate_job_resources_qualified",
    "worker_results_authenticated", "release_authorized",
)
ROOT = Path(__file__).resolve().parents[1]
_PROFILE_FILE = ROOT / "reporting/pdf-typed-observation.v1.json"
_SCHEMA_FILE = ROOT / "schemas/report-typed-pdf-observation.v1.schema.json"
_SOURCE_KEYS_SHA256 = "6c677bb76a0d87d96f18e1aa25c03c968f3dcd3b7631d168119dca83995b9e05"
_NUMBER = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)\Z", re.ASCII)
_CODE = re.compile(r"(?:[0-9a-f]{4})*\Z", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_CHILD_ROLES = {
    "/Document": {"/H1", "/H2", "/P", "/Table"},
    "/H1": {"/Span"}, "/H2": {"/Span"}, "/P": {"/Span"},
    "/Table": {"/Caption", "/THead", "/TBody"},
    "/Caption": {"/Span"}, "/THead": {"/TR"}, "/TBody": {"/TR"},
    "/TR": {"/TH", "/TD"}, "/TH": {"/Span"}, "/TD": {"/Span"},
    "/Span": set(),
}


class TypedPdfObservationError(ValueError):
    """A content-free refusal; never an incomplete or qualified observation."""


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError("typed physical observation refused")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _unique_pairs(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def _reject_number(_value: str) -> None:
    raise ValueError("noncanonical JSON number")


def _loads(data: str) -> object:
    return json.loads(data, object_pairs_hook=_unique_pairs,
                      parse_float=_reject_number, parse_constant=_reject_number)


def _profile_contract() -> dict:
    """Fixed scope; the manifest binds code and schema without activating a pipeline."""
    return {
        "schema_version": "1.0.0", "profile_id": PROFILE_ID,
        "parser_version": PARSER_VERSION, "protocol_version": 1,
        "default_pipeline_activated": False,
        "aggregate_job_resources_qualified": False,
        "release_authorized": False,
        "source_association": "NOT_ESTABLISHED",
        "text_policy": "EXACT_SAME_FONT_BFCHAR_UTF16BE_NO_POSITIONING_INFERENCE",
        "numeric_policy": "PARSER_BINARY64_ROUNDTRIP_DECIMAL_NOT_SOURCE_LEXEMES",
        "structure_policy": "ORDERED_NATIVE_K_AND_REVERSE_PARENT_TREE",
        "graphics_policy": "OUTSIDE_FRAGMENTS_OR_COLOR_ALPHA_BEFORE_BT",
        "passive_policy": "EFFECTIVE_GRAPH_DENIALS_WITH_VERIFIED_TABLE_ATTRIBUTES_ONLY",
        "roles": list(ROLES), "operators": list(OPERATORS),
        "limits": dict(LIMITS), "wall_seconds": 10,
        "budgets": {
            "pdf_bytes": MAX_PDF_BYTES, "pages": MAX_PAGES,
            "request_header_bytes": HEADER_BYTES, "result_bytes": RESULT_BYTES,
            "decoded_stream_bytes": MAX_STREAM_BYTES, "decoded_text_bytes": MAX_TEXT_BYTES,
            "tree_depth": MAX_DEPTH, "tree_visits": MAX_VISITS,
            "operations": MAX_OPERATIONS, "fonts": MAX_FONTS,
            "cmap_stream_bytes": MAX_CMAP_BYTES, "cmap_total_bytes": MAX_CMAP_TOTAL,
            "cmap_records": MAX_CMAP_RECORDS,
        },
    }


def _profile() -> str:
    """Fail closed on a disabled observer, altered contract or unbound source path."""
    _require(os.environ.get("OMNIGENIS_TYPED_PDF_OBSERVATION_DISABLED") != "1")
    raw = _PROFILE_FILE.read_bytes()
    _require(len(raw) <= 65536 and not _PROFILE_FILE.is_symlink())
    profile = _loads(raw.decode("ascii"))
    _require(type(profile) is dict and set(profile) == set(_profile_contract()) | {"source_sha256"})
    sources = profile["source_sha256"]
    _require(type(sources) is dict and
             sha256(_canonical(sorted(sources))).hexdigest() == _SOURCE_KEYS_SHA256)
    _require(_canonical({k: v for k, v in profile.items() if k != "source_sha256"})
             == _canonical(_profile_contract()))
    for name, digest in sources.items():
        _require(type(digest) is str and _DIGEST.fullmatch(digest) is not None)
        path = ROOT / name
        _require(not path.is_symlink() and path.resolve().is_relative_to(ROOT)
                 and sha256(path.read_bytes()).hexdigest() == digest)
    return sha256(_canonical(profile)).hexdigest()


def _num(value: object) -> float:
    _require(type(value) is str and len(value) <= 64 and _NUMBER.fullmatch(value) is not None)
    number = float(value)
    _require(math.isfinite(number))
    return number


def _reference(value: object) -> tuple[int, int]:
    _require(type(value) is list and len(value) == 2
             and type(value[0]) is int and 1 <= value[0] <= 2147483647
             and type(value[1]) is int and 0 <= value[1] <= 65535)
    return tuple(value)


def _structure(trace: dict) -> dict:
    """Reconcile ordered forward edges, physical pages, table links and reverse owners."""
    pages = {_reference(p["reference"]): p for p in trace["pages"]}
    nodes = {_reference(n["reference"]): n for n in trace["nodes"]}
    root = _reference(trace["root_reference"])
    _require(len(pages) == len(trace["pages"]) and len(nodes) == len(trace["nodes"]))
    _require(root not in nodes and root not in pages and not set(nodes).intersection(pages))
    expected = {}
    seen = []
    visited = set()
    table_for = {}
    headers = {}
    visits = sum(len(p["mcid_owners"]) for p in trace["pages"])
    _require(visits <= MAX_VISITS)

    def walk(ref: tuple, parent: tuple, page: tuple | None, table: tuple | None, depth: int) -> None:
        nonlocal visits
        _require(ref in nodes and ref not in visited and depth <= MAX_DEPTH)
        visited.add(ref)
        seen.append(ref)
        node = nodes[ref]
        visits += 1 + len(node["children"])
        _require(visits <= MAX_VISITS and _reference(node["parent"]) == parent)
        role = node["role"]
        current_page = None if node["page_reference"] is None else _reference(node["page_reference"])
        _require(role in ROLES)
        if parent == root:
            _require(role == "/Document" and current_page is None)
        else:
            _require(role != "/Document" and current_page in pages)
            _require(role in _CHILD_ROLES[nodes[parent]["role"]])
            _require(page is None or page == current_page)
        if role == "/Table":
            table = ref
        table_for[ref] = table
        children = node["children"]
        form = node["children_form"]
        _require(form in {"array", "reference", "mcid"})
        if form != "array":
            _require(len(children) == 1 and
                     children[0]["kind"] == ("node" if form == "reference" else "mcid"))
        if not children:
            _require(role == "/TBody" and form == "array")
        if role in {"/TH", "/TD"}:
            _require(node["table_attribute"] is True and table is not None)
            parent_row = nodes[parent]
            group = nodes[_reference(parent_row["parent"])]
            _require(parent_row["role"] == "/TR"
                     and group["role"] == ("/THead" if role == "/TH" else "/TBody"))
            if role == "/TH":
                native_id = node["native_id"]
                _require(type(native_id) is str and native_id not in headers and not node["headers"])
                headers[native_id] = (table, current_page)
            else:
                _require(node["native_id"] is None and len(node["headers"]) == 1)
        else:
            _require(node["table_attribute"] is False and node["native_id"] is None and not node["headers"])
        if role == "/Span":
            _require(len(children) == 1 and children[0]["kind"] == "mcid")
        for ordinal, child in enumerate(children):
            _require(child["ordinal"] == ordinal)
            if child["kind"] == "node":
                walk(_reference(child["reference"]), ref, current_page, table, depth + 1)
            else:
                _require(child["kind"] == "mcid" and role == "/Span"
                         and type(child["value"]) is int and 0 <= child["value"] < MAX_VISITS)
                slot = current_page, child["value"]
                _require(slot not in expected)
                expected[slot] = ref

    roots = trace["root_children"]
    _require(trace["root_children_form"] in {"array", "reference"} and len(roots) == 1)
    walk(_reference(roots[0]), root, None, None, 1)
    _require(seen == [_reference(n["reference"]) for n in trace["nodes"]])
    observed = {}
    for index, page in enumerate(trace["pages"]):
        pkey = _reference(page["reference"])
        _require(page["index"] == index)
        for mcid, owner in enumerate(page["mcid_owners"]):
            _require(owner["mcid"] == mcid)
            observed[(pkey, mcid)] = _reference(owner["structure_reference"])
    _require(expected == observed and observed)
    _require(len({p["struct_parents"] for p in trace["pages"]}) == len(pages))
    for ref, node in nodes.items():
        for header in node["headers"]:
            _require(headers.get(header) == (table_for[ref], _reference(node["page_reference"])))
    return {"structure_nodes": len(nodes), "mcids": len(expected), "structure_visits": visits}


def _replay(page: dict, fonts: dict) -> list[dict]:
    """Account for every text-show event without synthesizing text from positions."""
    bindings = {f["name"]: _reference(f["reference"]) for f in page["font_resources"]}
    states = {s["name"]: s for s in page["graphics_states"]}
    owners = {m["mcid"]: m["structure_reference"] for m in page["mcid_owners"]}
    _require(len(bindings) == len(page["font_resources"]) and bindings
             and len(states) == len(page["graphics_states"]))
    _require(all(ref in fonts for ref in bindings.values()))
    for state in states.values():
        _require(state["fill_alpha"] is not None or state["stroke_alpha"] is not None)
        for value in (state["fill_alpha"], state["stroke_alpha"]):
            _require(value is None or 0 <= _num(value) <= 1)
    stage, depth, mcid = "outside", 0, None
    runs, used = [], set()
    matrix, prefix = [], []
    resource = size = None
    text_bytes = 0
    for ordinal, event in enumerate(page["events"]):
        _require(event["ordinal"] == ordinal and event["operator"] in OPERATORS)
        op, args = event["operator"], event["operands"]
        if op in {"q", "Q", "cm", "gs", "rg"}:
            _require(stage == "outside" or (stage == "BT" and op in {"gs", "rg"}))
            if stage == "BT":
                _require((op == "gs" and not prefix) or (op == "rg" and prefix in ([], ["gs"])))
                prefix.append(op)
            if op in {"q", "Q"}:
                _require(not args)
                depth += 1 if op == "q" else -1
                _require(0 <= depth <= MAX_DEPTH)
            elif op == "cm":
                _require(len(args) == 6)
                for value in args:
                    _num(value)
            elif op == "rg":
                _require(len(args) == 3 and all(0 <= _num(v) <= 1 for v in args))
            else:
                _require(len(args) == 1 and args[0] in states)
            continue
        if op == "BDC":
            _require(stage == "outside" and len(args) == 1
                     and type(args[0]) is int and args[0] in owners and args[0] not in used)
            mcid, prefix = args[0], []
            used.add(mcid)
            stage = "BT"
        elif op == "BT":
            _require(stage == "BT" and not args)
            stage = "Tm"
        elif op == "Tm":
            _require(stage == "Tm" and len(args) == 6)
            for value in args:
                _num(value)
            matrix, stage = list(args), "Tf"
        elif op == "Tf":
            _require(stage == "Tf" and len(args) == 2 and args[0] in bindings and _num(args[1]) > 0)
            resource, size, stage = args[0], args[1], "TJ"
        elif op == "TJ":
            _require(stage == "TJ" and 1 <= len(args) <= MAX_OPERATIONS)
            font_ref = bindings[resource]
            cmap = dict(fonts[font_ref]["mapping"])
            pieces, glyphs, run_bytes = [], 0, 0
            for part in args:
                _require(type(part) is list and len(part) == 2 and type(part[1]) is str)
                kind, value = part
                if kind == "adjust":
                    _num(value)
                else:
                    _require(kind == "codes" and _CODE.fullmatch(value) is not None)
                    glyphs += len(value) // 4
                    for offset in range(0, len(value), 4):
                        code = value[offset:offset + 4]
                        _require(code in cmap)
                        value_text = cmap[code]
                        run_bytes += len(value_text.encode("utf-8"))
                        _require(text_bytes + run_bytes <= MAX_TEXT_BYTES)
                        pieces.append(value_text)
            text = "".join(pieces)
            byte_count = len(text.encode("utf-8"))
            text_bytes += byte_count
            _require(text_bytes <= MAX_TEXT_BYTES)
            runs.append({
                "ordinal": len(runs), "text_object": len(runs), "operator_ordinal": ordinal,
                "mcid": mcid, "structure_reference": list(owners[mcid]),
                "font_reference": list(font_ref), "font_resource": resource,
                "font_size": size, "text_matrix": matrix, "parts": args,
                "text": text, "utf8_bytes": byte_count, "scalars": len(text),
                "glyph_codes": glyphs,
            })
            stage = "ET"
        elif op == "ET":
            _require(stage == "ET" and not args)
            stage = "EMC"
        elif op == "EMC":
            _require(stage == "EMC" and not args)
            stage, mcid = "outside", None
    _require(stage == "outside" and depth == 0 and used == set(owners))
    return runs


def _reference_consistency(trace: dict) -> None:
    """Reject impossible cross-category aliases and contradictory shared-object facts."""
    categories = [
        [trace["root_reference"]],
        [n["reference"] for n in trace["nodes"]],
        [p["reference"] for p in trace["pages"]],
        [p["contents_reference"] for p in trace["pages"]],
        [f["reference"] for f in trace["fonts"]],
        [f["cid_reference"] for f in trace["fonts"]],
        [f["cmap_reference"] for f in trace["fonts"]],
    ]
    owner = {}
    for category, references in enumerate(categories):
        for reference in references:
            key = _reference(reference)
            _require(key not in owner or owner[key] == category)
            owner[key] = category
    shared = {}
    for records, reference_field, fields in [
        (trace["pages"], "contents_reference",
         ("content_sha256", "decoded_stream_bytes", "events")),
        (trace["fonts"], "cid_reference",
         ("base_font", "explicit_cid_width_count")),
        (trace["fonts"], "cmap_reference",
         ("cmap_sha256", "cmap_decoded_bytes", "mapping")),
    ]:
        for record in records:
            key = _reference(record[reference_field])
            facts = _canonical({name: record[name] for name in fields})
            _require(key not in shared or shared[key] == facts)
            shared[key] = facts


def _validate(body: dict, digest: str, byte_count: int, profile_sha: str) -> None:
    """Validate the closed schema, then rederive all exported text and ownership."""
    from jsonschema import Draft202012Validator

    schema = json.loads(_SCHEMA_FILE.read_text(encoding="ascii"), object_pairs_hook=_unique_pairs)
    Draft202012Validator(schema).validate(body)
    _require(body["pdf_sha256"] == digest and body["pdf_byte_count"] == byte_count
             and body["profile_sha256"] == profile_sha and body["limits"] == LIMITS)
    require_pdf_document_budget(byte_count, body["page_count"])
    trace = body["trace"]
    _reference_consistency(trace)
    _require(len(trace["pages"]) == body["page_count"])
    counts = _structure(trace)
    fonts = {_reference(f["reference"]): f for f in trace["fonts"]}
    occupied = {_reference(trace["root_reference"])} | {
        _reference(n["reference"]) for n in trace["nodes"]} | {
        _reference(p["reference"]) for p in trace["pages"]}
    _require(not occupied.intersection(fonts))
    _require(len(fonts) == len(trace["fonts"]) and 1 <= len(fonts) <= MAX_FONTS)
    for font in fonts.values():
        mapping = dict(font["mapping"])
        _require(len(mapping) == len(font["mapping"]) and len(mapping) <= font["explicit_cid_width_count"])
        for text in mapping.values():
            _require(1 <= len(text.encode("utf-16-be", "strict")) // 2 <= 16)
    counts.update({
        "fonts": len(fonts), "cmap_records": sum(len(f["mapping"]) for f in fonts.values()),
        "cmap_decoded_bytes": sum(f["cmap_decoded_bytes"] for f in fonts.values()),
        "decoded_stream_bytes": sum(p["decoded_stream_bytes"] for p in trace["pages"]),
        "operations": sum(len(p["events"]) for p in trace["pages"]),
        "decoded_text_bytes": 0, "glyph_codes": 0, "text_scalars": 0,
    })
    for page in trace["pages"]:
        runs = _replay(page, fonts)
        _require(runs == page["runs"])
        counts["decoded_text_bytes"] += sum(r["utf8_bytes"] for r in runs)
        counts["glyph_codes"] += sum(r["glyph_codes"] for r in runs)
        counts["text_scalars"] += sum(r["scalars"] for r in runs)
        _require(counts["decoded_text_bytes"] <= MAX_TEXT_BYTES)
    _require(counts == body["counts"]
             and counts["decoded_stream_bytes"] <= MAX_STREAM_BYTES
             and counts["decoded_text_bytes"] <= MAX_TEXT_BYTES
             and counts["operations"] <= MAX_OPERATIONS
             and counts["cmap_records"] <= MAX_CMAP_RECORDS
             and counts["cmap_decoded_bytes"] <= MAX_CMAP_TOTAL)


@dataclass(frozen=True, slots=True, repr=False)
class TypedPdfObservation:
    """Immutable private bytes; digests are checksums, not worker authentication."""

    _payload: bytes = field(repr=False)
    observation_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        try:
            _require(type(self._payload) is bytes and 0 < len(self._payload) <= RESULT_BYTES)
            value = _loads(self._payload.decode("ascii"))
            _validate(value, value["pdf_sha256"], value["pdf_byte_count"], _profile())
            _require(_canonical(value) == self._payload)
            object.__setattr__(self, "observation_sha256", sha256(self._payload).hexdigest())
        except Exception:
            raise TypedPdfObservationError("typed_pdf_observation_protocol_invalid") from None

    def to_bytes(self) -> bytes:
        """Return sealed private content. Call summary() for engineering logs."""
        try:
            _profile()
            _require(sha256(self._payload).hexdigest() == self.observation_sha256)
            return self._payload
        except Exception:
            raise TypedPdfObservationError("typed_pdf_observation_protocol_invalid") from None

    def to_dict(self) -> dict:
        """Return a detached private trace; this contains decoded report text."""
        return json.loads(self.to_bytes())

    def summary(self) -> dict:
        """Return only identity, finite counts and explicit nonclaims."""
        value = self.to_dict()
        value.pop("trace")
        value["observation_sha256"] = sha256(self._payload).hexdigest()
        return value

    def __repr__(self) -> str:
        return f"TypedPdfObservation(observation_sha256='{self.observation_sha256}')"


def _decode(data: bytes, expected_pdf_sha256: str, expected_pdf_byte_count: int) -> TypedPdfObservation:
    try:
        profile_sha = _profile()
        _require(type(expected_pdf_sha256) is str and _DIGEST.fullmatch(expected_pdf_sha256) is not None
                 and type(expected_pdf_byte_count) is int and 0 < expected_pdf_byte_count <= MAX_PDF_BYTES)
        _require(type(data) is bytes and 0 < len(data) <= RESULT_BYTES)
        frame = _loads(data.decode("ascii"))
        _require(type(frame) is dict and set(frame) == {"protocol_version", "observation"}
                 and type(frame["protocol_version"]) is int and frame["protocol_version"] == 1)
        body = frame["observation"]
        _validate(body, expected_pdf_sha256, expected_pdf_byte_count, profile_sha)
        return TypedPdfObservation(_canonical(body))
    except Exception:
        raise TypedPdfObservationError("typed_pdf_observation_protocol_invalid") from None


def _run_worker(pdf: bytes, digest: str) -> bytes:
    """Use separate owned anonymous regular files and the existing bounded lifecycle."""
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as output:
        fds = (source.fileno(), output.fileno())
        infos = [os.fstat(fd) for fd in fds]
        _require(all(stat.S_ISREG(v.st_mode) and v.st_nlink == 0
                     and v.st_uid == os.geteuid() for v in infos)
                 and (infos[0].st_dev, infos[0].st_ino) != (infos[1].st_dev, infos[1].st_ino))
        source.write(b"1 " + digest.encode("ascii") + b"\n" + pdf)
        source.flush()
        process = _start([
            sys.executable, "-I", "-B", str(Path(__file__).with_name("_pdf_typed_observation_worker.py")),
            str(fds[0]), str(fds[1]), str(os.getpid()),
        ], fds)
        _require(_wait(process) == 0 and 0 < os.fstat(fds[1]).st_size <= RESULT_BYTES)
        output.seek(0)
        return output.read(RESULT_BYTES + 1)


def observe_typed_pdf(*, pdf_bytes: object, expected_pdf_sha256: object) -> TypedPdfObservation:
    """Observe declared physical text only; no source plan or source identifiers are accepted."""
    try:
        require_no_active_scope()
        profile_sha = _profile()
        _require(type(pdf_bytes) is bytes and pdf_bytes.startswith(b"%PDF-1.7")
                 and 0 < len(pdf_bytes) <= MAX_PDF_BYTES
                 and type(expected_pdf_sha256) is str and _DIGEST.fullmatch(expected_pdf_sha256) is not None
                 and sha256(pdf_bytes).hexdigest() == expected_pdf_sha256)
    except Exception:
        raise TypedPdfObservationError("typed_pdf_observation_input_invalid") from None
    try:
        result = _decode(_run_worker(pdf_bytes, expected_pdf_sha256),
                         expected_pdf_sha256, len(pdf_bytes))
        _require(_profile() == profile_sha)
        require_no_active_scope()
        return result
    except Exception:
        raise TypedPdfObservationError("typed_pdf_observation_execution_failed") from None
