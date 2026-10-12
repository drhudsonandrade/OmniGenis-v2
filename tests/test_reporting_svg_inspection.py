"""Synthetic, fail-closed SVG preflight coverage. No real logo is loaded."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
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
from reporting.asset_registry import AssetDeclaration, AssetManifest
from reporting.bindings import ReportArtifactBinding

ROOT = Path(__file__).resolve().parents[1]
NS = "http://www.w3.org/2000/svg"
PATH = '<path d="M0 0 L16 16 Z" fill="#112233"/>'
RECT = '<rect x="0" y="0" width="16" height="16" fill="#aabbcc"/>'
CIRCLE = '<circle cx="8" cy="8" r="4" fill="#ffffff"/>'


def svg(body: str = PATH, *, attrs: str = 'width="16" height="16" viewBox="0 0 16 16"') -> bytes:
    return (f'<svg xmlns="{NS}" {attrs}>{body}</svg>').encode("utf-8")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class SvgPreflightTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("reporting.svg_inspection"),
                             "staged static SVG inspection boundary is missing")
        self.m = importlib.import_module("reporting.svg_inspection")
        self.good = svg()
        self.expected = self.manifest(self.good)
        self.resolved = self.manifest(self.good)

    def manifest(self, raw: bytes, *, width: int = 16, height: int = 16,
                 role: str = "brand-logo", media: str = "image/svg+xml") -> AssetManifest:
        h = sha(raw)
        asset = AssetDeclaration("SYNTHETIC-LOGO", role, media, h, len(raw),
                                 width, height, ReportArtifactBinding("SYNTHETIC-LOGO-SOURCE", h),
                                 ReportArtifactBinding("SYNTHETIC-LOGO-RIGHTS", "a"*64))
        return AssetManifest((asset,))

    def inspect(self, raw: bytes | None = None, *, expected=None, resolved=None):
        content = self.good if raw is None else raw
        if expected is None:
            expected = self.expected if raw is None else self.manifest(content)
        if resolved is None:
            resolved = self.resolved if raw is None else self.manifest(content)
        return self.m.inspect_staged_svg(
            expected_manifest=expected, resolved_manifest=resolved, svg_bytes=content)

    def reject(self, raw: bytes):
        with self.assertRaises(self.m.SvgInspectionError):
            if not raw:
                self.inspect(raw, expected=self.expected, resolved=self.resolved)
            else:
                self.inspect(raw)

    def test_inert_simple_static_path(self):
        evidence = self.inspect().to_dict()
        self.assertEqual(evidence["status"], "SVG_STRUCTURALLY_INSPECTED_UNQUALIFIED")
        self.assertEqual((evidence["width_px"], evidence["height_px"]), (16,16))
        self.assertEqual((evidence["path_count"], evidence["element_count"]), (1,2))

    def test_inert_shapes_and_groups(self):
        raw = svg('<g>'+PATH+RECT+CIRCLE+'</g>')
        e = self.inspect(raw).to_dict()
        self.assertEqual(e["element_count"], 5)
        self.assertEqual(e["path_count"], 1)
        self.assertEqual(e["shape_count"], 3)

    def test_whitelisted_hex_colors_and_none(self):
        for color in ('#010203','#ABCDEF','none'):
            with self.subTest(color=color):
                self.assertEqual(self.inspect(svg(PATH.replace('#112233',color))).to_dict()["shape_count"],1)

    def test_nonpainted_stroke_with_bounded_width(self):
        raw=svg('<path d="M1 1 L15 15" fill="none" stroke="#112233" stroke-width="2"/>')
        self.assertEqual(self.inspect(raw).to_dict()["shape_count"],1)

    def test_receipt_never_retains_svg_bytes_or_markup(self):
        receipt=self.inspect()
        summary=repr(receipt)+repr(receipt.to_dict())
        self.assertNotIn('<svg',summary)
        self.assertNotIn('<path',summary)
        self.assertFalse(hasattr(receipt,"svg_bytes"))
        self.assertIs(receipt.to_dict()["original_bytes_retained"],False)

    def test_scope_explicitly_disclaims_security_and_rights(self):
        d=self.inspect().to_dict()
        for field in ('svg_sanitized','brand_rights_verified','source_authenticated',
                      'visual_fidelity_verified','accessibility_qualified',
                      'renderer_activated','asset_activated','full_os_sandbox_claim'):
            self.assertIs(d[field],False,field)
        self.assertEqual(d["release_authorization"],"NOT_ESTABLISHED")

    def test_expected_and_independent_resolved_manifest_bound(self):
        e=self.inspect().to_dict()
        self.assertEqual(e["input_sha256"],sha(self.good))
        self.assertEqual(e["asset_manifest_sha256"],self.expected.manifest_sha256)

    def test_manifest_mismatch_rejected(self):
        altered=svg(RECT)
        with self.assertRaises(self.m.SvgInspectionError):
            self.inspect(expected=self.expected,resolved=self.manifest(altered))

    def test_modified_source_fails_even_if_structurally_valid(self):
        with self.assertRaises(self.m.SvgInspectionError):
            self.inspect(svg(CIRCLE),expected=self.expected,resolved=self.resolved)

    def test_logo_role_not_dna_or_other_media(self):
        raw=svg()
        with self.assertRaises(self.m.SvgInspectionError):
            manifest=self.manifest(raw,role="dna-illustration",media="image/png")
            self.inspect(raw,expected=manifest,resolved=manifest)

    def test_input_type_is_exact_immutable_bytes(self):
        for value in (bytearray(self.good),memoryview(self.good),[self.good],None):
            with self.subTest(kind=type(value)):
                with self.assertRaises(self.m.SvgInspectionError):
                    self.m.inspect_staged_svg(expected_manifest=self.expected,
                                              resolved_manifest=self.resolved,svg_bytes=value)

    def test_empty_bad_signature_and_non_ascii_rejected(self):
        for raw in (b"",b"<!DOCTYPE html>",b"GIF89a",b"\xef\xbb\xbf"+self.good,
                    svg('<path d="M0 0 L1 1" fill="#112233"/>').replace(b'<path',b'\xc3\xa9<path')):
            with self.subTest(n=len(raw)):
                self.reject(raw)

    def test_doctype_entities_and_xml_declarations_rejected(self):
        cases=(b'<?xml version="1.0"?>'+self.good,
               b'<!DOCTYPE svg [<!ENTITY xx "malicious">]>'+self.good,
               svg('<path d="M0 0" fill="&xx;"/>'),
               svg(PATH.replace('M0 0','M&amp;0 0')))
        for raw in cases:
            with self.subTest(n=len(raw)):
                self.reject(raw)

    def test_comments_and_processing_instructions_rejected(self):
        for raw in (svg('<!-- comment -->'+PATH),svg('<?xml-stylesheet href="evil"?>'+PATH)):
            self.reject(raw)

    def test_foreign_namespace_and_xlink_rejected(self):
        for raw in (svg(PATH).replace(NS.encode(),b'https://foreign.invalid/ns'),
                    svg(PATH).replace(b'<svg ',b'<svg xmlns:xlink="http://www.w3.org/1999/xlink" '),
                    b'<x:svg xmlns:x="'+NS.encode()+b'" width="16" height="16" viewBox="0 0 16 16">'+PATH.encode()+b'</x:svg>'):
            self.reject(raw)

    def test_malformed_xml_and_unclosed_nodes_rejected(self):
        for raw in (self.good[:-6],svg('<path d="M0 0" fill="#112233">'),svg('<path>')):
            self.reject(raw)

    def test_forbidden_dynamic_markup(self):
        bodies=(
            '<script>alert(1)</script>'+PATH,
            '<foreignObject><p>evil</p></foreignObject>'+PATH,
            '<image href="https://evil.invalid/x.png"/>'+PATH,
            '<style>path{fill:red}</style>'+PATH,
            '<defs><linearGradient id="g"/></defs>'+PATH,
            '<text>PRIVATE</text>'+PATH,
            '<filter id="f"/>'+PATH,
            '<use href="#source"/>'+PATH,
            '<a href="https://evil.invalid">'+PATH+'</a>',
        )
        for body in bodies:
            with self.subTest(body=body[:35]):
                self.reject(svg(body))

    def test_forbidden_executable_style_and_resource_attributes(self):
        for key,value in (('onload','javascript:alert(1)'),('style','fill:red'),
                          ('href','https://evil.invalid'),('class','arbitrary'),
                          ('id','script'),('transform','rotate(30)'),('filter','url(#f)')):
            with self.subTest(attribute=key):
                self.reject(svg(PATH.replace(' fill=',f' {key}="{value}" fill=')))

    def test_url_paint_reference_and_css_keywords_rejected(self):
        for color in ('url(#x)','red','currentColor','#GGGGGG','none;url(evil)'):
            with self.subTest(color=color):
                self.reject(svg(PATH.replace('#112233',color)))

    def test_root_requires_viewbox_width_and_height(self):
        for attrs in ('viewBox="0 0 16 16"','width="16" height="16"',
                      'width="16" viewBox="0 0 16 16"',
                      'height="16" viewBox="0 0 16 16"'):
            with self.subTest(attrs=attrs):
                self.reject(svg(attrs=attrs))

    def test_root_viewbox_format_cannot_be_normalized(self):
        for value in ('0 0 17 16','1 0 16 16','0 0 -16 16','0,0,16,16',
                      '0 0 16 16 5','0 0 0 16','0 0 16 0'):
            self.reject(svg(attrs=f'width="16" height="16" viewBox="{value}"'))

    def test_root_dimensions_are_bound_to_source_declaration(self):
        altered=self.manifest(self.good,width=12,height=16)
        with self.assertRaises(self.m.SvgInspectionError):
            self.inspect(expected=altered,resolved=altered)

    def test_root_unknown_attributes_rejected(self):
        for attr in ('preserveAspectRatio="none"','version="1.1"','style="display:none"',
                     'onload="alert(1)"'):
            self.reject(svg(attrs=f'width="16" height="16" viewBox="0 0 16 16" {attr}'))

    def test_group_unknown_attrs_rejected(self):
        for attr in ('id="g"','transform="translate(1)"','style="fill:red"'):
            self.reject(svg('<g '+attr+'>'+PATH+'</g>'))

    def test_shape_invalid_required_numeric_fields(self):
        for raw in (svg('<rect x="0" y="0" width="-1" height="16" fill="#ffffff"/>'),
                    svg('<rect x="0" y="0" width="100%" height="16" fill="#ffffff"/>'),
                    svg('<circle cx="8" cy="8" r="-5" fill="#ffffff"/>'),
                    svg('<circle cx="8" cy="8" r="none" fill="#ffffff"/>')):
            self.reject(raw)

    def test_bad_path_chars_and_empty_d_rejected(self):
        for d in ('','M0 0;alert(1)','M0 0 L16 16 /','M0 0 &injected;',
                  'M0 0 e 1','M0 0 url(#x)'):
            self.reject(svg(f'<path d="{d}" fill="#112233"/>'))

    def test_path_rejects_incomplete_trailing_commands_with_whitespace(self):
        for data in ("M0 0 L", "M0 0 L ", "M0 0 L\t", "M0 0 L\n",
                     "M0 0 L1", "M0 0 Z M1", "M0 0 H", "M0 0 V"):
            with self.subTest(data=data):
                self.reject(svg(f'<path d="{data}" fill="#112233"/>'))

    def test_path_rejects_incomplete_groups_before_later_commands(self):
        for data in ("M0 0 L M0 0", "M0 0 C1 2 3 4 5 L1 1",
                     "M0 0 Q1 2 3 Z", "M0 0 H V1", "M0 0 Z L M1 1",
                     "M0 0 A1 2 3 0 1 M1 1", "M0 0 M1 L2 2"):
            with self.subTest(data=data):
                self.reject(svg(f'<path d="{data}" fill="#112233"/>'))

    def test_each_nonclose_command_requires_whole_operand_groups(self):
        arities = {"M": 2, "L": 2, "H": 1, "V": 1, "C": 6,
                   "S": 4, "Q": 4, "T": 2, "A": 7}
        for command, count in arities.items():
            for letter in (command, command.lower()):
                for operands in (count - 1, 0):
                    data = "M0 0 " + letter + " ".join(["0"] * operands)
                    with self.subTest(command=letter, operands=operands):
                        self.reject(svg(f'<path d="{data}" fill="#112233"/>'))
                if count > 1:
                    data = "M0 0 " + letter + " ".join(["0"] * (count + 1))
                    with self.subTest(command=letter, repeated_incomplete=True):
                        self.reject(svg(f'<path d="{data}" fill="#112233"/>'))
        self.reject(svg('<path d="M0 0 Z 1 2" fill="#112233"/>'))

    def test_path_accepts_complete_explicit_and_repeated_groups(self):
        arguments = {"M": "1 2", "L": "1 2", "H": "1", "V": "2",
                     "C": "1 2 3 4 5 6", "S": "1 2 3 4", "Q": "1 2 3 4",
                     "T": "1 2", "A": "1 2 3 0 1 4 5"}
        for command, args in arguments.items():
            for letter in (command, command.lower()):
                for repeated in (args, args + " " + args):
                    data = "M0 0 " + letter + repeated + " Z"
                    with self.subTest(command=letter, args=repeated):
                        self.assertEqual(self.inspect(svg(
                            f'<path d="{data}" fill="#112233"/>')).to_dict()["path_count"], 1)
        self.assertEqual(self.inspect(svg(
            '<path d="M0 0 Z M1 1 L2 2 Z " fill="#112233"/>')).to_dict()["path_count"], 1)

    def test_path_rejects_invalid_separators_and_unconsumed_tokens(self):
        for data in ("M,0 0", "M0 0,L1 2", "M0 0 L,1 2", "M0 0 L1,,2",
                     "M0 0 L1 2,", "M0 0 L+ 1", "M0 0 L1 .", "M0 0 L1 --2",
                     "M0 0 L1..2", "M0 0 L1. 2", "M0 0 Z,", "M0 0 Z,L1 2"):
            with self.subTest(data=data):
                self.reject(svg(f'<path d="{data}" fill="#112233"/>'))

    def test_path_keeps_supported_compact_signed_and_decimal_numbers(self):
        for data in ("M0.6.5", "M.5 .5 L1.25,2.5", "M0 0L+1-2",
                     "M0 0L1.2.3", "M0 0 L-1,-2", "m0 0l16 16z",
                     "M0 0 L1 1\n\t", "M0 0 H1 2 3 V4 5 6"):
            with self.subTest(data=data):
                self.assertEqual(self.inspect(svg(
                    f'<path d="{data}" fill="#112233"/>')).to_dict()["path_count"], 1)

    def test_path_arc_flags_are_literal_zero_or_one_in_each_group(self):
        for args in ("1 2 3 2 1 4 5", "1 2 3 0 2 4 5", "1 2 3 -1 0 4 5",
                     "1 2 3 0.0 1 4 5", "1 2 3 0 1.0 4 5"):
            for prefix in ("M0 0 A", "M0 0 A1 2 3 0 1 4 5 "):
                with self.subTest(args=args, prefix=prefix):
                    self.reject(svg(f'<path d="{prefix}{args}" fill="#112233"/>'))

    def test_path_grammar_preserves_exact_input_binding_without_rewriting(self):
        raw = svg('<path d="M0 0 L1 1 2 2 Z " fill="#112233"/>')
        expected = self.manifest(raw)
        before = (sha(raw), expected.manifest_sha256)
        evidence = self.inspect(raw, expected=expected, resolved=expected).to_dict()
        self.assertEqual(evidence["input_sha256"], before[0])
        self.assertEqual(evidence["asset_manifest_sha256"], before[1])
        self.assertEqual(before, (sha(raw), expected.manifest_sha256))
        self.assertFalse(evidence["renderer_activated"])

    def test_path_operand_scanning_respects_original_character_budget(self):
        data = "M0 0" + " " * (4096 - 4)
        result = self.inspect(svg(f'<path d="{data}" fill="#112233"/>')).to_dict()
        self.assertEqual(result["total_path_chars"], 4096)
        self.reject(svg(f'<path d="{data} " fill="#112233"/>'))

    def test_path_length_and_total_budget(self):
        self.reject(svg('<path d="M'+ '0 '*2200 +'" fill="#112233"/>'))
        body=''.join('<path d="M'+ '0 '*2000 +'" fill="#112233"/>' for _ in range(9))
        self.reject(svg(body))

    def test_path_count_budget(self):
        many=''.join(PATH for _ in range(257))
        self.reject(svg(many))
        approved=''.join(PATH for _ in range(256))
        self.assertEqual(self.inspect(svg(approved)).to_dict()["path_count"],256)

    def test_many_siblings_over_node_budget(self):
        body=''.join(CIRCLE for _ in range(512))
        self.reject(svg(body))

    def test_deep_nested_groups_rejected(self):
        raw=svg('<g>'*18+PATH+'</g>'*18)
        self.reject(raw)

    def test_missing_geometry_rejected(self):
        for raw in (svg(''),svg('<g></g>'),svg('<g><g></g></g>')):
            self.reject(raw)

    def test_whitespace_text_outside_geometry_rejected(self):
        self.reject(svg('SECRET'+PATH))
        self.reject(svg(PATH+'PRIVATE'))
        self.reject(svg('<g>'+PATH+'PRIVATE</g>'))

    def test_source_encoded_size_budget_before_xml_parse(self):
        with patch.object(self.m,"MAX_ENCODED_BYTES",len(self.good)-1):
            with patch.object(self.m.ET,"fromstring",side_effect=AssertionError("XML must not parse")):
                with self.assertRaises(self.m.SvgInspectionError):
                    self.inspect()

    def test_no_filesystem_network_or_subprocess(self):
        with patch.object(Path,"read_bytes",side_effect=AssertionError("disk forbidden")),\
             patch.object(socket,"getaddrinfo",side_effect=AssertionError("DNS forbidden")),\
             patch.object(subprocess,"Popen",side_effect=AssertionError("process forbidden")):
            self.assertEqual(self.inspect().to_dict()["shape_count"],1)

    def test_source_bytes_unchanged(self):
        before=(sha(self.good),self.expected.manifest_sha256)
        self.inspect()
        self.assertEqual(before,(sha(self.good),self.expected.manifest_sha256))

    def test_error_messages_do_not_expose_markup(self):
        with self.assertRaises(self.m.SvgInspectionError) as c:
            self.reject_if_suspicious(svg('<script>PRIVATE_SENTINEL</script>'+PATH))
        self.assertNotIn('PRIVATE_SENTINEL',str(c.exception))

    def reject_if_suspicious(self, content):
        return self.inspect(content)

    def test_receipt_is_frozen_and_detached(self):
        x=self.inspect()
        with self.assertRaises(FrozenInstanceError):
            x.width_px=100
        d=x.to_dict()
        d['asset_id']='FOREIGN'
        self.assertEqual(x.to_dict()['asset_id'],'SYNTHETIC-LOGO')

    def test_closed_evidence_schema_accepts_receipt(self):
        schema=json.loads((ROOT/"schemas/report-svg-inspection.v1.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        self.assertFalse(list(Draft202012Validator(schema).iter_errors(self.inspect().to_dict())))

    def test_schema_rejects_false_rights_or_activation(self):
        schema=json.loads((ROOT/"schemas/report-svg-inspection.v1.schema.json").read_text())
        validator=Draft202012Validator(schema)
        for key,value in [('svg_sanitized',True),('brand_rights_verified',True),
                          ('renderer_activated',True),('release_authorization','AUTHORIZED'),
                          ('external_url','https://evil.invalid')]:
            with self.subTest(field=key):
                d={**self.inspect().to_dict(),key:value}
                self.assertTrue(list(validator.iter_errors(d)))

    def test_existing_pdf_adapter_rejects_svg_receipt(self):
        from reporting.adapters import build_html_css_and_pdf_adapter
        result=build_html_css_and_pdf_adapter(presentation_ir=self.inspect().to_dict())
        self.assertFalse(result.passed)
        self.assertIsNone(result.pdf_bytes)


if __name__=="__main__":
    unittest.main()
