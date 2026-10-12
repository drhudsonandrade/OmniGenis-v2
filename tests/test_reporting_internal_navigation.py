"""Synthetic strict binding tests for inert internal section/finding navigation."""
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
from test_reporting_typed_html import document, digest

ROOT = Path(__file__).resolve().parents[1]


def canonical(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")).hexdigest()


class InternalNavigationTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("reporting.internal_navigation"),
                             "inert internal navigation binding is missing")
        self.m = importlib.import_module("reporting.internal_navigation")
        self.doc = document(count=2)
        self.doc_sha = digest(self.doc)
        self.intents = (
            self.m.NavigationIntent("title", "section", "findings"),
            self.m.NavigationIntent("intro", "finding", "F0"),
        )

    def nav_sha(self, intents=None):
        values = self.intents if intents is None else intents
        return canonical([i.to_dict() for i in values])

    def bind(self, *, doc=None, projection_sha=None, intents=None, expected_intents_sha=None):
        value = self.doc if doc is None else doc
        values = self.intents if intents is None else intents
        return self.m.bind_internal_navigation(
            projection_ir=value,
            expected_projection_sha256=self.doc_sha if projection_sha is None else projection_sha,
            intents=values,
            expected_intents_sha256=self.nav_sha(values) if expected_intents_sha is None
            else expected_intents_sha,
        )

    def reject(self, **changes):
        with self.assertRaises(self.m.NavigationError):
            self.bind(**changes)

    def test_two_id_bound_intents_preserve_exact_order(self):
        record = self.bind().to_dict()
        self.assertEqual(record["intent_count"], 2)
        self.assertEqual([x["target_kind"] for x in record["intents"]], ["section", "finding"])
        self.assertEqual([x["target_id"] for x in record["intents"]], ["findings", "F0"])
        self.assertEqual(record["status"], "STAGED_UNQUALIFIED")

    def test_canonical_section_targets_heading_not_page_number(self):
        link = self.bind().to_dict()["intents"][0]
        self.assertEqual((link["target_component_id"], link["target_section_id"]),
                         ("heading", "findings"))
        self.assertEqual(link["source_section_id"], "identity")

    def test_canonical_finding_targets_existent_parent_table(self):
        link = self.bind().to_dict()["intents"][1]
        self.assertEqual((link["target_component_id"], link["target_section_id"]),
                         ("table", "findings"))
        self.assertEqual(link["source_section_id"], "findings")

    def test_title_only_identity_section_can_be_targeted(self):
        link = self.m.NavigationIntent("heading", "section", "identity")
        receipt = self.bind(intents=(link,)).to_dict()["intents"][0]
        self.assertEqual(receipt["target_component_id"], "title")

    def test_all_navigation_is_inert_and_unreleased(self):
        r = self.bind().to_dict()
        for key in ("pdf_destinations_activated", "html_links_activated",
                    "page_numbers_resolved", "source_semantics_validated",
                    "pdf_annotations_qualified", "renderer_activated"):
            self.assertIs(r[key], False, key)
        self.assertEqual(r["release_authorization"], "NOT_ESTABLISHED")
        self.assertEqual(r["conformance_scope"], "EXACT_SECTION_AND_FINDING_ID_BINDING_ONLY")

    def test_no_active_uris_or_untrusted_markup_in_receipt(self):
        r = repr(self.bind().to_dict())
        for forbidden in ("https://", "<a ", "<script", "href=", "/URI", "/GoTo"):
            self.assertNotIn(forbidden, r)
        self.assertFalse(self.bind().to_dict()["page_numbers_resolved"])
        for intent in self.bind().to_dict()["intents"]:
            self.assertNotIn("page_number", intent)
            self.assertNotIn("href", intent)

    def test_expected_projection_digest_independently_required(self):
        self.reject(projection_sha="0"*64)
        self.reject(projection_sha="A"*64)
        with self.assertRaises(self.m.NavigationError):
            self.m.bind_internal_navigation(projection_ir=self.doc,
                expected_projection_sha256=None, intents=self.intents,
                expected_intents_sha256=self.nav_sha())

    def test_expected_intent_digest_independently_required(self):
        self.reject(expected_intents_sha="f"*64)
        self.reject(expected_intents_sha="F"*64)
        with self.assertRaises(self.m.NavigationError):
            self.m.bind_internal_navigation(projection_ir=self.doc,
                expected_projection_sha256=self.doc_sha, intents=self.intents,
                expected_intents_sha256=None)

    def test_modified_text_and_protected_tokens_do_not_pass_stale_projection(self):
        modified = json.loads(json.dumps(self.doc))
        modified["components"][2]["text"] = "Other case's text."
        self.reject(doc=modified)

    def test_rehashing_mutated_projection_does_not_bypass_declared_components(self):
        modified = json.loads(json.dumps(self.doc))
        modified["components"][1]["section_id"] = "identity"
        self.reject(doc=modified, projection_sha=digest(modified))

    def test_intent_digest_changes_with_order(self):
        rev = tuple(reversed(self.intents))
        self.assertNotEqual(self.nav_sha(self.intents), self.nav_sha(rev))
        self.reject(intents=rev, expected_intents_sha=self.nav_sha())

    def test_duplicate_intents_are_rejected(self):
        self.reject(intents=(self.intents[0], self.intents[0]))

    def test_distinct_targets_from_same_source_are_admitted(self):
        choices = (self.m.NavigationIntent("title", "finding", "F0"),
                   self.m.NavigationIntent("title", "finding", "F1"))
        self.assertEqual(self.bind(intents=choices).to_dict()["intent_count"], 2)

    def test_section_target_without_present_section_is_rejected(self):
        self.reject(intents=(self.m.NavigationIntent("title", "section", "unknown"),))

    def test_finding_target_missing_is_rejected(self):
        self.reject(intents=(self.m.NavigationIntent("intro", "finding", "F-NOT-THERE"),))

    def test_foreign_source_component_rejected(self):
        self.reject(intents=(self.m.NavigationIntent("FOREIGN", "section", "findings"),))

    def test_foreign_http_reference_does_not_become_internal_identifier(self):
        for x in ("https://example.org/x", "../private", "file:///private", "/GoTo"):
            with self.subTest(value=x), self.assertRaises(self.m.NavigationError):
                self.m.NavigationIntent("title", "section", x)

    def test_supported_target_kinds_are_exact(self):
        for x in ("page", "url", "external", "component", "SECTION", "section ", "", True):
            with self.subTest(value=x), self.assertRaises(self.m.NavigationError):
                self.m.NavigationIntent("title", x, "findings")

    def test_intent_source_and_target_id_validation(self):
        for k, v in (("source_component_id", ""), ("source_component_id", True),
                     ("target_id", ""), ("target_id", None), ("target_id", "has spaces")):
            with self.subTest(k=k, v=v), self.assertRaises(self.m.NavigationError):
                self.m.NavigationIntent(**{**self.intents[0].to_dict(), k: v})

    def test_frozen_intent_direct_constructor_blocks_unknown_keys(self):
        with self.assertRaises(TypeError):
            self.m.NavigationIntent("title", "section", "findings",
                                    href="https://evil.invalid")

    def test_only_tuple_of_exact_native_intents_admitted(self):
        for values in ([self.intents[0]], ({"source_component_id": "title"},),
                       ("title",), None):
            with self.subTest(kind=type(values)), self.assertRaises(self.m.NavigationError):
                self.bind(intents=values, expected_intents_sha="a"*64)

    def test_direct_constructor_forgery_is_rechecked(self):
        intent = self.m.NavigationIntent("title", "section", "findings")
        object.__setattr__(intent, "target_kind", "external")
        with self.assertRaises(self.m.NavigationError):
            self.bind(intents=(intent,), expected_intents_sha="a"*64)

    def test_input_is_immutable_even_when_a_caller_mutates_their_copy(self):
        before = digest(self.doc)
        record = self.bind()
        self.doc["components"][0]["text"] = "Mutated afterwards"
        self.assertEqual(record.to_dict()["projection_sha256"], before)
        self.assertEqual(record.to_dict()["intent_count"], 2)

    def test_receipt_frozen_and_detached(self):
        record = self.bind()
        with self.assertRaises(FrozenInstanceError):
            record.projection_sha256 = "0"*64
        detached = record.to_dict()
        detached["intents"].clear()
        self.assertEqual(len(record.to_dict()["intents"]), 2)

    def test_receipt_detects_direct_forged_internal_record(self):
        record = self.bind()
        intent = record.intents[0]
        object.__setattr__(intent, "target_kind", "external")
        with self.assertRaises(self.m.NavigationError):
            record.to_dict()

    def test_zero_navigation_intents_is_valid_without_invention(self):
        r = self.bind(intents=()).to_dict()
        self.assertEqual(r["intent_count"], 0)
        self.assertEqual(r["intents"], [])
        self.assertFalse(r["renderer_activated"])

    def test_5000_synthetic_finding_targets_no_top_n_truncation(self):
        doc = document(count=5000)
        ints = tuple(self.m.NavigationIntent("title", "finding", f"F{i}")
                     for i in range(5000))
        r = self.bind(doc=doc, projection_sha=digest(doc),
                      intents=ints).to_dict()
        self.assertEqual(r["intent_count"], 5000)
        self.assertEqual(r["intents"][-1]["target_id"], "F4999")
        self.assertEqual(r["intents"][-1]["target_component_id"], "table")

    def test_hard_cap_refuses_without_silent_truncation(self):
        bogus = (self.intents[0],) * (self.m.MAX_NAVIGATION_INTENTS + 1)
        with self.assertRaises(self.m.NavigationError):
            self.bind(intents=bogus, expected_intents_sha="a"*64)

    def test_no_network_process_or_disk_access_from_runtime(self):
        with patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process forbidden")), \
             patch.object(Path, "read_bytes", side_effect=AssertionError("disk forbidden")):
            self.assertEqual(self.bind().to_dict()["intent_count"], 2)

    def test_error_messages_never_echo_untrusted_text(self):
        bad = "https://PRIVATE_SENTINEL.invalid"
        with self.assertRaises(self.m.NavigationError) as cm:
            self.m.NavigationIntent("title", "section", bad)
        self.assertNotIn("PRIVATE_SENTINEL", str(cm.exception))

    def test_output_schema_matches_and_is_closed(self):
        schema = json.loads((ROOT/"schemas/report-internal-navigation.v1.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        self.assertFalse(list(Draft202012Validator(schema).iter_errors(self.bind().to_dict())))

    def test_schema_blocks_forged_authorization_flags(self):
        schema = json.loads((ROOT/"schemas/report-internal-navigation.v1.schema.json").read_text())
        validator = Draft202012Validator(schema)
        for key,value in (("renderer_activated",True),("pdf_destinations_activated",True),
                          ("release_authorization","AUTHORIZED"),("pdf_annotations_qualified",True),
                          ("href","https://evil.invalid")):
            d = {**self.bind().to_dict(), key:value}
            with self.subTest(key=key):
                self.assertTrue(list(validator.iter_errors(d)))

    def test_schema_rejects_activated_link_fields(self):
        schema = json.loads((ROOT/"schemas/report-internal-navigation.v1.schema.json").read_text())
        validator = Draft202012Validator(schema)
        d = self.bind().to_dict()
        d["intents"][0]["page_index"] = 1
        self.assertTrue(list(validator.iter_errors(d)))

    def test_existing_pdf_adapter_rejects_inert_navigation_receipt(self):
        from reporting.adapters import build_html_css_and_pdf_adapter
        r = build_html_css_and_pdf_adapter(presentation_ir=self.bind().to_dict())
        self.assertFalse(r.passed)
        self.assertIsNone(r.pdf_bytes)


if __name__ == "__main__":
    unittest.main()
