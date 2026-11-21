"""Opt-in original logo/DNA resource binding for a typed editorial PDF candidate.

Composes only the exact source-approved original assets and mandatory owner credit
over the already validated en-US typed editorial HTML. The existing confined
preloaded-raster worker performs the only rendering. No default delivery,
clinical/scientific claims, new executor, PDF/UA or visual parity is established.

This original-brand editorial profile requires at least one section heading with
an unambiguous source section anchor for its printed contents. Carriage returns and line feeds in section headings are refused before staging:
the exact literal association profile does not represent those explicit breaks.
Natural line wrapping remains supported. The generic typed component contract
remains unchanged. The complete source title must fit the
cover area beside the DNA and below the logo in the actual fixed-font layout.
Title boxes or glyph ink outside that area refuse rendering before the first
page is painted. The existing gaps allow safe ink overhang. Text is never shortened.

Each generated contents entry, including its printed page suffix, must occupy one
complete paragraph box inside a physical page's content area. Entries may wrap
within that page and the contents section may continue between entries. The
worker refuses fragmented or out-of-page entry boxes before painting that page
or returning a PDF candidate. Staging establishes source identity, not layout fit.
"""
from __future__ import annotations

from hashlib import sha256
from html import escape
from html.parser import HTMLParser
import json
import os

from reporting._pdf_render_worker import HTML_BYTES
from reporting.brand_assets import (
    BoundBrandAssets, REQUIRED_CREDIT_EN, _LOGO_SHA256, _DNA_SHA256,
    _PERMISSION_SHA256,
)
from reporting.editorial_typed_pdf import prepare_editorial_typed_html
from reporting.pdf_original_brand_inclusion import _logo_markup
from reporting.pdf_typed_brand_render import (
    TypedBrandPdfCandidate, render_typed_brand_pdf, require_policy as require_render_policy,
)
from reporting._pdf_native_launch_budget import require_no_active_scope
from reporting import _pdf_typed_brand_emission as emission
from reporting.pdf_raster_resources import RasterAsset, RasterBundle
from reporting.internal_navigation import NavigationIntent, bind_internal_navigation
from reporting.typed_html import capture_typed_document

PROFILE_ID = "typed-original-logo-dna-candidate-v1"
_BUNDLE_SHA256 = "c4332907b19ae45524534ad352c1b521db08ec9fc8fd88ae73fa2ec4ba8c0eeb"
_DISABLE = "OMNIGENIS_TYPED_ORIGINAL_BRAND_PDF_DISABLED"
_QUALIFICATION = "OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE"
_END = "</body></html>"
_COVER_CSS = (
    'h1,h2,p,caption,th,td{white-space:pre-wrap}'
    'section[data-editorial-ir-sha256]{position:relative;height:753.88976pt;'
    'margin:0;padding:0;break-after:page}'
    'div[data-brand=original-dna]{position:absolute;left:0;top:0;'
    'width:211.664022738302pt;height:753.88976pt;background-color:#003890;'
    'border-right:3pt solid #00D0F0;background-repeat:no-repeat;'
    'background-position:center;background-size:100% 100%}'
    'section[data-editorial-ir-sha256]>div[data-brand=original-logo]{'
    'position:absolute;left:228pt;top:220pt;width:230pt!important;margin:0!important}'
    'section[data-editorial-ir-sha256]>h1{position:absolute;left:228pt;top:340pt;'
    'width:279.27559pt;margin:0;overflow-wrap:anywhere}'
    'section[data-editorial-navigation]{margin:0 0 18pt;break-inside:avoid}'
    'p[data-editorial-nav-target]{margin:5pt 0;break-inside:avoid}'
    'p[data-editorial-nav-target]::after{white-space:pre;content:" | " '
    'target-counter(attr(data-editorial-nav-target),page)}'
)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _navigation(doc: dict, ir_sha256: str) -> tuple[str, dict]:
    """Bind plain section labels to existing source anchors before final layout."""
    headings = [component for component in doc["components"]
                if component["component_type"] == "section_heading"]
    _require(bool(headings) and all("\n" not in heading["text"]
             and "\r" not in heading["text"] and "\t" not in heading["text"]
             for heading in headings))
    intents = tuple(NavigationIntent(doc["components"][0]["component_id"],
                                    "section", heading["section_id"])
                    for heading in headings)
    plan_sha256 = sha256(_canonical([item.to_dict() for item in intents])).hexdigest()
    binding = bind_internal_navigation(
        projection_ir=doc, expected_projection_sha256=ir_sha256,
        intents=intents, expected_intents_sha256=plan_sha256).to_dict()
    entries = []
    for heading, target in zip(headings, binding["intents"], strict=True):
        _require(target["target_component_id"] == heading["component_id"])
        label = escape(heading["text"], quote=True).replace("\r", "&#13;")
        anchor = escape("#" + target["target_component_id"], quote=True)
        entries.append('<p data-editorial-nav-target="' + anchor + '">' + label + '</p>')
    return ('<section data-editorial-navigation="sections"><h2>Contents</h2>'
            + "".join(entries) + '</section>'), binding


class TypedOriginalBrandError(ValueError):
    """Content-free failure, with no fallback to arbitrary unbound assets."""


def _require(ok: bool) -> None:
    if not ok:
        raise TypedOriginalBrandError("typed_original_brand_pdf_unavailable")


class _VisibleBodyText(HTMLParser):
    """Collect decoded text and the generated contents row's literal separator."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.navigation_row = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "p":
            self.navigation_row = any(name == "data-editorial-nav-target" for name, _ in attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag == "p" and self.navigation_row:
            # CSS adds this separator before the page counter. HTMLParser does
            # not see generated content, but adjacent labels are not contiguous
            # visible source text. Ordinary source paragraphs remain contiguous.
            self.parts.append(" | ")
            self.navigation_row = False

    def handle_data(self, value: str) -> None:
        self.parts.append(value)


def _credit_count(html: str) -> int:
    """Detect credit across typed paragraphs and encoded whitespace boundaries."""
    _require(type(html) is str and html.count('<body>') == 1
             and html.endswith(_END))
    body = html.split('<body>', 1)[1][:-len(_END)]
    parser = _VisibleBodyText()
    parser.feed(body)
    parser.close()
    visible_text = ' '.join(parser.parts).replace('\u00ad', '')
    return ' '.join(visible_text.split()).count(REQUIRED_CREDIT_EN)


def _ready(assets: BoundBrandAssets, expected_brand_bundle_sha256: object) -> dict:
    """Admit only the original author's exact licensed source bundle."""
    _require(os.environ.get(_DISABLE) != "1"
             and os.environ.get(_QUALIFICATION) == "qualification-only")
    _require(type(assets) is BoundBrandAssets)
    _require(type(expected_brand_bundle_sha256) is str
             and expected_brand_bundle_sha256 == _BUNDLE_SHA256)
    manifest = assets.to_dict()
    _require(manifest["bundle_sha256"] == _BUNDLE_SHA256
             and manifest["permission_reference"]["sha256"] == _PERMISSION_SHA256
             and manifest["required_credit_en"] == REQUIRED_CREDIT_EN
             and manifest["assets"][0]["sha256"] == _LOGO_SHA256
             and manifest["assets"][1]["sha256"] == _DNA_SHA256)
    return manifest


def prepare_typed_original_brand_pdf(
    *, presentation_ir: object, expected_ir_sha256: object,
    assets: BoundBrandAssets, expected_brand_bundle_sha256: object,
) -> tuple[str, RasterBundle, dict]:
    """Stage this profile's exact source, including one or more section headings.

    Title and contents-entry fit are decided from the actual layout in the
    existing render worker. Preparation alone establishes neither cover fit nor
    the one-page admission of a complete navigation paragraph.
    """
    try:
        _ready(assets, expected_brand_bundle_sha256)
        source, source_record = prepare_editorial_typed_html(
            presentation_ir=presentation_ir, expected_ir_sha256=expected_ir_sha256)
        doc = capture_typed_document(presentation_ir, expected_ir_sha256)
        _require(source.count("<body>") == 1 and source.endswith(_END)
                 and _credit_count(source) == 0
                 and 'data-brand="original-logo"' not in source
                 and 'data-brand="original-dna"' not in source)
        logo = _logo_markup(assets)
        _require(logo.count(assets.resolve("brand-logo").decode("utf-8")) == 1)
        dna = RasterAsset("dna-illustration", assets.resolve("dna-illustration"),
                          _DNA_SHA256, 324, 1154, _DNA_SHA256, _PERMISSION_SHA256)
        resources = RasterBundle((dna,))
        resource_uri = dna.uri
        _require(resource_uri.startswith("omnigenis-raster:"))
        original_body = source.split("<body>", 1)[1][:-len(_END)]
        _require(original_body.startswith("<h1 ") and original_body.count("</h1>") == 1)
        title, remaining_body = original_body.split("</h1>", 1)
        title += "</h1>"
        navigation, navigation_binding = _navigation(doc, expected_ir_sha256)
        figure = (
            '<div data-brand="original-dna" role="img" '
            'aria-label="Original decorative OmniGenis DNA illustration" '
            'style="background-image:url(\'' + resource_uri + '\')"></div>'
        )
        cover = ('<section data-editorial-ir-sha256="' + expected_ir_sha256 + '">'
                 + figure + logo + title + '</section>')
        credit = ('<section data-brand-credit-section="original" '
                  'style="break-inside:avoid">'
                  '<h2>Visual asset credits</h2>'
                  '<p data-brand-credit="original" role="note">' + escape(
                      REQUIRED_CREDIT_EN, quote=True) + '</p></section>')
        folio_css = ('@page{@bottom-right{content:"OmniGenis | '
                     + expected_ir_sha256[:12] + ' | " counter(page);'
                     'font-family:Lato;font-size:8.6pt;line-height:10pt;color:#455D73}}')
        style = _COVER_CSS + folio_css
        head = source.split("<body>", 1)[0]
        _require(head.count("</style>") == 1)
        html = (head.replace("</style>", style + "</style>", 1) + "<body>"
                + cover + navigation + remaining_body + credit + _END)
        raw = html.encode("utf-8")
        _require(0 < len(raw) <= HTML_BYTES
                 and html.count(logo) == 1
                 and figure.count("background-image:url(\'" + resource_uri + "\')") == 1
                 and _credit_count(html) == 1
                 and html.count('data-brand="original-logo"') == 1
                 and html.count('data-brand="original-dna"') == 1)
        record = {
            "schema_version": "1.0.0",
            "profile_id": PROFILE_ID,
            "status": "STAGED_TYPED_ORIGINAL_BRAND_CANDIDATE",
            "source_ir_sha256": expected_ir_sha256,
            "typed_editorial_html_sha256": source_record["html_sha256"],
            "editorial_style_sha256": sha256(style.encode("ascii")).hexdigest(),
            "navigation_binding_sha256": sha256(_canonical(navigation_binding)).hexdigest(),
            "navigation_plan_sha256": navigation_binding["plan_sha256"],
            "navigation_entry_count": navigation_binding["intent_count"],
            "html_sha256": sha256(raw).hexdigest(),
            "resources_sha256": resources.bundle_sha256,
            "brand_bundle_sha256": _BUNDLE_SHA256,
            "logo_original_sha256": _LOGO_SHA256,
            "dna_original_sha256": _DNA_SHA256,
            "permission_sha256": _PERMISSION_SHA256,
            "original_credit_count": 1,
            "original_source_bytes_preserved": True,
            "clinical_authorization": "NOT_ESTABLISHED",
            "source_semantics_verified": False,
            "visual_equivalence_verified": False,
            "human_accessibility_verified": False,
            "whole_job_resources_qualified": False,
            "pdf_ua_certified": False,
            "default_pipeline_activated": False,
            "release_authorized": False,
        }
        return html, resources, record
    except Exception:
        raise TypedOriginalBrandError("typed_original_brand_pdf_unavailable") from None


def render_typed_original_brand_pdf(
    *, presentation_ir: object, expected_ir_sha256: object,
    assets: BoundBrandAssets, expected_brand_bundle_sha256: object,
) -> tuple[TypedBrandPdfCandidate, dict]:
    """Render exact preloaded originals once and withhold all unqualified release claims."""
    try:
        require_no_active_scope()
        html, resources, record = prepare_typed_original_brand_pdf(
            presentation_ir=presentation_ir, expected_ir_sha256=expected_ir_sha256,
            assets=assets, expected_brand_bundle_sha256=expected_brand_bundle_sha256)
        _ready(assets, expected_brand_bundle_sha256)
        pdf = render_typed_brand_pdf(
            html=html, expected_html_sha256=record["html_sha256"],
            resources=resources, expected_resources_sha256=record["resources_sha256"])
        _require(type(pdf) is TypedBrandPdfCandidate
                 and pdf.html_sha256 == record["html_sha256"]
                 and pdf.resources_sha256 == record["resources_sha256"]
                 and 1 <= pdf.page_count <= 64
                 and sha256(pdf.pdf_bytes).hexdigest() == pdf.pdf_sha256)
        again_html, again_resources, again_record = prepare_typed_original_brand_pdf(
            presentation_ir=presentation_ir, expected_ir_sha256=expected_ir_sha256,
            assets=assets, expected_brand_bundle_sha256=expected_brand_bundle_sha256)
        _require(again_record == record and again_html == html
                 and again_resources.to_bytes() == resources.to_bytes())
        metadata = pdf.to_dict()
        _require(require_render_policy() == metadata["profile_sha256"])
        require_no_active_scope()
        return pdf, {**record, "render_profile_id": emission.PROFILE_ID,
                     "render_profile_sha256": metadata["profile_sha256"],
                     "pdf_sha256": metadata["pdf_sha256"],
                     "page_count": metadata["page_count"]}
    except Exception:
        raise TypedOriginalBrandError("typed_original_brand_pdf_unavailable") from None
