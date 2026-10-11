"""Synthetic tests for a fail-closed, staging-only editorial asset integrity boundary."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import builtins
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator
from reporting.bindings import ReportArtifactBinding

ROOT = Path(__file__).resolve().parents[1]
LOGO = b'<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0"/></svg>'
DNA = b'\x89PNG\r\n\x1a\nSYNTHETIC_OPAQUE_PNG_BYTES'


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class StagedAssetTests(unittest.TestCase):
    """Do not conflate exact bytes with rights, sanitization or renderer safety."""

    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("reporting.asset_registry"),
                             "staged asset boundary is missing")
        self.m = importlib.import_module("reporting.asset_registry")
        self.logo = self.declaration("SYNTHETIC-LOGO", "brand-logo",
                                     "image/svg+xml", LOGO)
        self.dna = self.declaration("SYNTHETIC-DNA", "dna-illustration",
                                    "image/png", DNA)
        self.expected = self.m.AssetManifest((self.logo, self.dna))
        self.resolved = self.m.AssetManifest((
            self.declaration("SYNTHETIC-LOGO", "brand-logo", "image/svg+xml", LOGO),
            self.declaration("SYNTHETIC-DNA", "dna-illustration", "image/png", DNA),
        ))

    def declaration(self, identity, role, media_type, payload, **changes):
        source_id = "SYNTHETIC-SOURCE-" + hashlib.sha256(identity.encode()).hexdigest()[:12]
        d = dict(asset_id=identity, role=role, media_type=media_type,
                 sha256=digest(payload), size_bytes=len(payload),
                 declared_width_px=512, declared_height_px=512,
                 source_reference=ReportArtifactBinding(source_id, digest(payload)),
                 rights_reference=ReportArtifactBinding("SYNTHETIC-RIGHTS", "1" * 64))
        d.update(changes)
        return self.m.AssetDeclaration(**d)

    def bind(self, *, expected=None, resolved=None, payloads=None):
        return self.m.bind_staged_asset_inventory(
            expected_manifest=expected if expected is not None else self.expected,
            resolved_manifest=resolved if resolved is not None else self.resolved,
            supplied_bytes=(LOGO, DNA) if payloads is None else payloads)

    def reject(self, **changes):
        with self.assertRaises(self.m.AssetRegistryError):
            self.bind(**changes)

    def test_equal_independent_manifests_match_and_validate_bytes(self):
        self.assertIsNot(self.expected, self.resolved)
        b = self.bind()
        self.assertEqual(b.to_dict()["status"], "PINNED_UNQUALIFIED")
        self.assertEqual(b.to_dict()["asset_count"], 2)
        self.assertEqual(b.to_dict()["total_bytes"], len(LOGO) + len(DNA))

    def test_never_claims_legal_security_font_link_or_report_qualification(self):
        d = self.bind().to_dict()
        for name in ("rights_verified", "media_sanitized", "dimensions_verified",
                     "renderer_activated", "font_profile_qualified", "links_activated"):
            self.assertIs(d[name], False, name)
        self.assertEqual(d["release_authorization"], "NOT_ESTABLISHED")
        self.assertEqual(d["conformance_scope"], "OPAQUE_ASSET_BYTE_INTEGRITY_ONLY")

    def test_actual_bytes_are_not_retained_or_exposed(self):
        b = self.bind()
        text = repr(b.to_dict()) + repr(b)
        self.assertNotIn("SYNTHETIC_OPAQUE_PNG_BYTES", text)
        self.assertNotIn('<svg xmlns', text)
        self.assertFalse(hasattr(b, "supplied_bytes"))
        self.assertEqual(b.to_dict()["source_bytes_retained"], False)

    def test_malicious_svg_is_only_pinned_and_never_declared_safe(self):
        hostile = b'<svg><script>PRIVATE_SCRIPT</script><image href="https://evil.invalid"/></svg>'
        x = self.declaration("SYNTHETIC-LOGO", "brand-logo", "image/svg+xml", hostile)
        b = self.bind(expected=self.m.AssetManifest((x,)),
                      resolved=self.m.AssetManifest((x,)), payloads=(hostile,))
        self.assertFalse(b.to_dict()["media_sanitized"])
        self.assertFalse(b.to_dict()["renderer_activated"])
        self.assertNotIn("PRIVATE_SCRIPT", repr(b.to_dict()))

    def test_content_hash_mismatch_rejected(self):
        self.reject(payloads=(LOGO + b"altered", DNA))

    def test_content_size_mismatch_rejected(self):
        wrong = replace(self.logo, size_bytes=len(LOGO) + 1)
        self.reject(expected=self.m.AssetManifest((wrong, self.dna)),
                    resolved=self.m.AssetManifest((wrong, self.dna)))

    def test_expected_and_resolved_manifest_must_agree(self):
        altered = replace(self.dna, rights_reference=ReportArtifactBinding("OTHER", "9"*64))
        self.reject(resolved=self.m.AssetManifest((self.logo, altered)))

    def test_wrong_source_sha256_is_rejected_even_if_asset_digest_matches(self):
        with self.assertRaises(self.m.AssetRegistryError):
            replace(self.logo, source_reference=ReportArtifactBinding("SOURCE", "2"*64))

    def test_source_and_rights_records_are_distinct(self):
        with self.assertRaises(self.m.AssetRegistryError):
            self.declaration("SYNTHETIC-X", "brand-logo", "image/svg+xml", LOGO,
                             rights_reference=ReportArtifactBinding(
                                 "SYNTHETIC-SOURCE-" + hashlib.sha256(b"SYNTHETIC-X").hexdigest()[:12], digest(LOGO)))

    def test_missing_rights_reference_fails(self):
        with self.assertRaises(self.m.AssetRegistryError):
            self.declaration("SYNTHETIC-X", "brand-logo", "image/svg+xml", LOGO,
                             rights_reference=None)

    def test_not_claiming_reviewed_rights_from_record_presence(self):
        data = self.bind().to_dict()
        self.assertFalse(data["rights_verified"])
        self.assertTrue(all("rights_reference" in a for a in data["assets"]))

    def test_unknown_role_not_admitted(self):
        with self.assertRaises(self.m.AssetRegistryError):
            self.declaration("SYNTHETIC-X", "background", "image/png", DNA)

    def test_role_to_media_kind_is_exact(self):
        with self.assertRaises(self.m.AssetRegistryError):
            self.declaration("SYNTHETIC-X", "brand-logo", "image/png", DNA)

    def test_unqualified_fonts_and_unsupported_formats_rejected(self):
        for media in ("font/ttf", "image/jpeg", "image/gif", "text/html", "image/svg+xml; charset=utf-8"):
            with self.subTest(media=media), self.assertRaises(self.m.AssetRegistryError):
                self.declaration("SYNTHETIC-X", "dna-illustration", media, DNA)

    def test_duplicate_role_is_rejected(self):
        second = self.declaration("SYNTHETIC-OTHER", "brand-logo", "image/svg+xml", LOGO)
        with self.assertRaises(self.m.AssetRegistryError):
            self.m.AssetManifest((self.logo, second))

    def test_duplicate_identifier_is_rejected(self):
        other = replace(self.dna, asset_id=self.logo.asset_id)
        with self.assertRaises(self.m.AssetRegistryError):
            self.m.AssetManifest((self.logo, other))

    def test_only_strict_nonempty_bounded_tuple_admitted(self):
        for entries in ([], (), [self.logo], (self.logo, self.dna, self.logo)):
            with self.subTest(entries=str(type(entries))), self.assertRaises(self.m.AssetRegistryError):
                self.m.AssetManifest(entries)

    def test_extra_missing_or_misordered_payloads_rejected(self):
        for data in ((LOGO,), (LOGO,DNA,b'X'), (DNA,LOGO)):
            with self.subTest(count=len(data)):
                self.reject(payloads=data)

    def test_mutable_payload_containers_and_foreign_values_rejected(self):
        for value in ([LOGO, DNA], (bytearray(LOGO), DNA), (memoryview(LOGO), DNA)):
            with self.subTest(kind=type(value)), self.assertRaises(self.m.AssetRegistryError):
                self.bind(payloads=value)

    def test_boolean_and_negative_dimensions_and_lengths_rejected(self):
        for name, value in (("size_bytes",True), ("size_bytes",0), ("size_bytes",-1),
                            ("declared_width_px",False), ("declared_height_px",0),
                            ("declared_width_px",99999999)):
            with self.subTest(name=name,value=value), self.assertRaises(self.m.AssetRegistryError):
                self.declaration("SYNTHETIC-X", "brand-logo", "image/svg+xml", LOGO, **{name:value})

    def test_invalid_opaque_ids_and_digest_not_normalized(self):
        for bad in ("../escape", "https://example.com/x", "foo/bar", "", "with space"):
            with self.subTest(bad=bad), self.assertRaises(self.m.AssetRegistryError):
                self.declaration(bad, "brand-logo", "image/svg+xml", LOGO)
        with self.assertRaises(self.m.AssetRegistryError):
            self.declaration("SYNTHETIC-X", "brand-logo", "image/svg+xml", LOGO, sha256="F"*64)

    def test_unexpected_fields_cannot_supply_urls_or_paths(self):
        for field in ("url", "file_path", "stylesheet", "svg_source"):
            with self.subTest(field=field), self.assertRaises(TypeError):
                self.declaration("SYNTHETIC-X", "brand-logo", "image/svg+xml", LOGO, **{field:"https://evil.invalid"})

    def test_nested_direct_constructor_revalidation_prevents_tamper(self):
        altered = self.declaration("SYNTHETIC-LOGO", "brand-logo", "image/svg+xml", LOGO)
        object.__setattr__(altered, "role", "foreign")
        with self.assertRaises(self.m.AssetRegistryError):
            self.m.AssetManifest((altered,))

    def test_direct_bound_constructor_rejects_tampered_manifest(self):
        altered = self.m.AssetManifest((self.logo,))
        object.__setattr__(altered, "assets", (self.logo, self.logo))
        with self.assertRaises(self.m.AssetRegistryError):
            self.m.BoundAssetInventory(altered, altered, (LOGO,LOGO))

    def test_budget_refuses_before_hashing_oversized_bytes(self):
        with patch.object(self.m, "MAX_SINGLE_ASSET_BYTES", 10):
            with patch.object(self.m.hashlib, "sha256", side_effect=AssertionError("MUST_NOT_HASH")):
                with self.assertRaises(self.m.AssetRegistryError):
                    self.bind()

    def test_total_budget_is_not_silent_truncation(self):
        with patch.object(self.m, "MAX_TOTAL_ASSET_BYTES", len(LOGO) + len(DNA) - 1):
            self.reject()

    def test_manifest_digest_changes_with_any_metadata(self):
        original = self.expected.manifest_sha256
        changed = self.m.AssetManifest((replace(self.logo, declared_width_px=256), self.dna))
        self.assertNotEqual(original, changed.manifest_sha256)

    def test_same_records_have_stable_manifest_digest(self):
        self.assertEqual(self.expected.manifest_sha256, self.resolved.manifest_sha256)
        self.assertEqual(self.bind().to_dict()["manifest_sha256"], self.expected.manifest_sha256)

    def test_exact_record_order_preserved_without_selection(self):
        entries = self.bind().to_dict()["assets"]
        self.assertEqual([r["role"] for r in entries], ["brand-logo","dna-illustration"])

    def test_frozen_objects_and_detached_export(self):
        b = self.bind()
        with self.assertRaises(FrozenInstanceError):
            b.expected_manifest = None
        d=b.to_dict()
        d["assets"].clear()
        self.assertEqual(len(b.to_dict()["assets"]), 2)

    def test_no_disk_network_or_subprocess_resolution(self):
        import pathlib,subprocess,urllib.request
        with patch.object(pathlib.Path, "read_bytes", side_effect=AssertionError("filesystem forbidden")),\
             patch.object(subprocess, "Popen", side_effect=AssertionError("process forbidden")),\
             patch.object(urllib.request, "urlopen", side_effect=AssertionError("network forbidden")):
            self.assertEqual(self.bind().to_dict()["asset_count"], 2)

    def test_source_bytes_and_caller_owned_references_stay_unchanged(self):
        before = (digest(LOGO), digest(DNA), self.expected.manifest_sha256)
        self.bind()
        self.assertEqual(before, (digest(LOGO),digest(DNA),self.expected.manifest_sha256))

    def test_errors_never_echo_original_payload(self):
        bad = b"PRIVATE_ASSET_BYTES_SENTINEL"
        wrong = self.declaration("SYNTHETIC-LOGO", "brand-logo", "image/svg+xml", bad)
        with self.assertRaises(self.m.AssetRegistryError) as raised:
            self.bind(expected=self.m.AssetManifest((wrong,)),
                      resolved=self.m.AssetManifest((wrong,)),payloads=(bad+b'x',))
        self.assertNotIn("PRIVATE_ASSET_BYTES_SENTINEL", str(raised.exception))

    def test_schema_is_closed_and_matches_actual_export(self):
        schema=json.loads((ROOT/"schemas/report-staged-asset-inventory.v1.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        self.assertFalse(list(Draft202012Validator(schema).iter_errors(self.bind().to_dict())))

    def test_schema_blocks_fabricated_release(self):
        schema=json.loads((ROOT/"schemas/report-staged-asset-inventory.v1.schema.json").read_text())
        validator=Draft202012Validator(schema);d=self.bind().to_dict()
        for name,value in (("renderer_activated",True),("rights_verified",True),
                           ("release_authorization","AUTHORIZED"),("conformance_scope","RENDERED")):
            with self.subTest(name=name):
                mutated={**d,name:value}
                self.assertTrue(list(validator.iter_errors(mutated)),name)

    def test_schema_blocks_unknown_fields_and_role_media_mismatch(self):
        schema=json.loads((ROOT/"schemas/report-staged-asset-inventory.v1.schema.json").read_text())
        v=Draft202012Validator(schema);d=self.bind().to_dict()
        d["published"]=True;self.assertTrue(list(v.iter_errors(d)))
        d=self.bind().to_dict();d["assets"][0]["media_type"]="image/png"
        self.assertTrue(list(v.iter_errors(d)))

    def test_schema_has_no_external_references(self):
        text=(ROOT/"schemas/report-staged-asset-inventory.v1.schema.json").read_text()
        self.assertNotIn('"http',text.replace('"https://json-schema.org/draft/2020-12/schema"',''))
        self.assertNotIn('remote',text.lower())

    def test_manifest_profile_and_schema_version_are_not_forgeable(self):
        for attr, value in (("schema_version", "9.9.9"), ("profile_id", "ACTIVE_RENDERER")):
            with self.subTest(attr=attr):
                m=self.m.AssetManifest((self.logo,))
                object.__setattr__(m, attr, value)
                with self.assertRaises(self.m.AssetRegistryError):
                    self.m.BoundAssetInventory(m, m, (LOGO,))

    def test_nested_rights_identity_is_rechecked_after_forgery(self):
        d=self.declaration("SYNTHETIC-LOGO", "brand-logo", "image/svg+xml", LOGO)
        object.__setattr__(d.rights_reference, "artifact_id", "../unsafe")
        with self.assertRaises(self.m.AssetRegistryError):
            self.m.AssetManifest((d,))

    def test_legacy_pdf_path_does_not_accept_asset_inventory(self):
        from reporting.adapters import build_html_css_and_pdf_adapter
        result=build_html_css_and_pdf_adapter(presentation_ir=self.bind().to_dict())
        self.assertFalse(result.passed)
        self.assertIsNone(result.pdf_bytes)


if __name__ == "__main__":
    unittest.main()
