"""RPT-12 fail-closed post-render PDF candidate validation."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from io import BytesIO
import re
from types import MappingProxyType
from collections.abc import Mapping
from xml.dom import Node

from reporting.localization import is_supported_report_locale

ROADMAP_ID="RPT-12"
GENERATED_PDF_METADATA_PROFILE = "omnigenis-generated-pdf-metadata-v1"
GENERATED_PDF_AUTHOR = "Hudson Silva Andrade"
GENERATED_PDF_PRODUCT = "OmniGenis"
_CONTROLLED_INFO = {
    "/Author": GENERATED_PDF_AUTHOR,
    "/Title": GENERATED_PDF_PRODUCT,
    "/Creator": GENERATED_PDF_PRODUCT,
    "/Producer": "WeasyPrint 70.0",
}
_PROFILE_MAX_PDF_BYTES = 8 * 1024 * 1024
_PROFILE_MAX_XMP_BYTES = 64 * 1024
_PROFILE_MAX_XMP_NODES = 128
_PROFILE_MAX_XMP_DEPTH = 8
_NS = {
    "x": "adobe:ns:meta/",
    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    "dc": "http://purl.org/dc/elements/1.1/",
    "pdf": "http://ns.adobe.com/pdf/1.3/",
    "pdfuaid": "http://www.aiim.org/pdfua/ns/id/",
    "xmp": "http://ns.adobe.com/xap/1.0/",
}
_XML_NS = "http://www.w3.org/XML/1998/namespace"
_XMLNS_NS = "http://www.w3.org/2000/xmlns/"
_SHA256=re.compile(r"^[0-9a-f]{64}$")
_SENSITIVE=(
    re.compile(r"(?:^|[\s=:])(?:token|password|secret|credential|api[_-]?key)\s*=",re.I),
    re.compile(r"(?:/srv/|/home/|[A-Za-z]:\\Users\\)",re.I),
)


@dataclass(frozen=True)
class PdfCandidateValidation:
    """Immutable decision for one newly rendered PDF candidate."""

    pdf_sha256: str | None
    page_count: int | None
    metadata: Mapping[str,str]
    accessibility_prerequisites: str
    errors: tuple[str,...]
    metadata_profile_id: str | None = None

    @property
    def passed(self) -> bool:
        """Return whether the candidate can proceed to later RPT-12 gates."""
        return not self.errors

    def to_dict(self) -> dict[str,object]:
        """Return a detached JSON-compatible validation record."""
        return {
            "roadmap_id":ROADMAP_ID,
            "status":"PASS" if self.passed else "BLOCKED",
            "pdf_sha256":self.pdf_sha256,
            "page_count":self.page_count,
            "metadata":dict(self.metadata),
            "metadata_profile_id":self.metadata_profile_id,
            "release_authorization":"NOT_ESTABLISHED",
            "accessibility_prerequisites":self.accessibility_prerequisites,
            "errors":list(self.errors),
            "limitations":[
                "This gate validates post-render integrity, structure, metadata hygiene, and accessibility prerequisites only.",
                "Visual QA, tagged-PDF semantics, reading order, and full accessibility conformance are not established by this unit.",
                "Metadata hygiene inspects Info keys/values, catalog language, and document-level XMP; other metadata channels are not validated.",
                "The optional generated-document profile checks only its declared Info/catalog/XMP surfaces; it is not general PDF sanitization.",
                "Evidence retains only approved public metadata constants on passing results and no metadata values on blocked results.",
                "PDF remains a derived artifact and is never scientific source of truth.",
            ],
        }


def _result(*,digest=None,page_count=None,metadata=None,accessibility="BLOCKED",errors=(),profile=None):
    """Build immutable evidence without retaining arbitrary candidate metadata."""
    retained = {
        key: value for key, value in (metadata or {}).items()
        if not errors and key in _CONTROLLED_INFO and value == _CONTROLLED_INFO[key]
    }
    return PdfCandidateValidation(
        digest,page_count,MappingProxyType(retained),
        "BLOCKED" if errors else accessibility,tuple(errors),profile,
    )

def _xmp_metadata_values(xmp) -> tuple[str, ...]:
    """Extract document-level XMP values using the pinned parser, without retaining XML."""
    if xmp is None:
        return ()
    document = xmp.rdf_root.ownerDocument
    if document is None or document.doctype is not None:
        raise ValueError("unsupported_xmp_document")

    values: list[str] = []
    pending = [document]
    while pending:
        node = pending.pop()
        if node.nodeType == Node.ELEMENT_NODE:
            # Adjacent text and CDATA form one logical value after XML decoding.
            text = "".join(
                child.data for child in node.childNodes
                if child.nodeType in (Node.TEXT_NODE, Node.CDATA_SECTION_NODE)
            )
            if text:
                values.append(text)
                name = node.localName or node.nodeName
                values.append(f"{name}={text}")
            for attribute in node.attributes.values():
                values.append(attribute.value)
                name = attribute.localName or attribute.name
                values.append(f"{name}={attribute.value}")
        elif node.nodeType in (Node.COMMENT_NODE, Node.PROCESSING_INSTRUCTION_NODE):
            values.append(node.data)
        pending.extend(reversed(node.childNodes))
    return tuple(values)



def _qualified_name(node) -> tuple[str, str]:
    """Identify XML names by namespace URI, independently of prefix spelling."""
    return node.namespaceURI or "", node.localName or node.nodeName


def _profile_attributes(element, expected):
    """Reject data-bearing attributes outside the bounded native XMP profile."""
    actual = {}
    for attribute in element.attributes.values():
        if attribute.namespaceURI == _XMLNS_NS:
            if attribute.value not in _NS.values():
                raise ValueError("unsupported_namespace")
            continue
        actual[_qualified_name(attribute)] = attribute.value
    if actual != expected:
        raise ValueError("unexpected_attributes")


def _profile_children(element):
    """Return direct elements, allowing only formatting whitespace between them."""
    children = []
    for child in element.childNodes:
        if child.nodeType == Node.ELEMENT_NODE:
            children.append(child)
        elif child.nodeType != Node.TEXT_NODE or child.data.strip():
            raise ValueError("unexpected_xml_node")
    return children


def _profile_text(element, attributes=None):
    """Read one scalar without accepting nested XML or additional attributes."""
    _profile_attributes(element, attributes or {})
    if any(child.nodeType not in (Node.TEXT_NODE, Node.CDATA_SECTION_NODE)
           for child in element.childNodes):
        raise ValueError("unexpected_scalar_structure")
    return "".join(child.data for child in element.childNodes)


def _profile_child(element, namespace, name):
    """Require exactly one child of the declared expanded XML name."""
    _profile_attributes(element, {})
    children = _profile_children(element)
    if len(children) != 1 or _qualified_name(children[0]) != (_NS[namespace], name):
        raise ValueError("unexpected_container")
    return children[0]


def _controlled_xmp_fields(xmp):
    """Inspect the complete native document XMP before normalizing any property."""
    if xmp is None:
        raise ValueError("missing_xmp")
    document = xmp.rdf_root.ownerDocument
    if document is None or document.doctype is not None:
        raise ValueError("unsupported_xmp_document")
    pending = [(document, 0)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > _PROFILE_MAX_XMP_NODES or depth > _PROFILE_MAX_XMP_DEPTH:
            raise OverflowError("xmp_budget")
        pending.extend((child, depth + 1) for child in node.childNodes)

    roots, packets = [], []
    for node in document.childNodes:
        if node.nodeType == Node.ELEMENT_NODE:
            roots.append(node)
        elif node.nodeType == Node.PROCESSING_INSTRUCTION_NODE and node.target == "xpacket":
            packets.append(node.data)
        elif node.nodeType != Node.TEXT_NODE or node.data.strip():
            raise ValueError("unexpected_document_node")
    if len(roots) != 1 or _qualified_name(roots[0]) != (_NS["x"], "xmpmeta"):
        raise ValueError("unexpected_xmp_root")
    if packets != ['begin="" id="W5M0MpCehiHzreSzNTczkc9d"', 'end="r"']:
        raise ValueError("unexpected_xmp_packet")
    ordered = [
        node for node in document.childNodes
        if node.nodeType != Node.TEXT_NODE or node.data.strip()
    ]
    if len(ordered) != 3 or ordered[1] is not roots[0]:
        raise ValueError("unexpected_xmp_packet_order")
    rdf = _profile_child(roots[0], "rdf", "RDF")
    _profile_attributes(rdf, {})
    fields = {}
    for description in _profile_children(rdf):
        if _qualified_name(description) != (_NS["rdf"], "Description"):
            raise ValueError("unexpected_rdf_child")
        attributes = {
            _qualified_name(attribute): attribute.value
            for attribute in description.attributes.values()
            if attribute.namespaceURI != _XMLNS_NS
        }
        about = (_NS["rdf"], "about")
        if attributes.pop(about, None) != "":
            raise ValueError("unexpected_rdf_subject")
        permitted = {(_NS["pdf"], "Producer"), (_NS["pdfuaid"], "part")}
        if not set(attributes) <= permitted:
            raise ValueError("unexpected_rdf_attribute")
        _profile_attributes(description, {about: "", **attributes})
        for key, value in attributes.items():
            if key in fields:
                raise ValueError("duplicate_xmp_property")
            fields[key] = value
        for property_node in _profile_children(description):
            key = _qualified_name(property_node)
            if key in fields:
                raise ValueError("duplicate_xmp_property")
            if key == (_NS["dc"], "title"):
                alternate = _profile_child(property_node, "rdf", "Alt")
                item = _profile_child(alternate, "rdf", "li")
                value = _profile_text(item, {(_XML_NS, "lang"): "x-default"})
            elif key == (_NS["dc"], "creator"):
                sequence = _profile_child(property_node, "rdf", "Seq")
                item = _profile_child(sequence, "rdf", "li")
                value = _profile_text(item)
            elif key == (_NS["xmp"], "CreatorTool"):
                value = _profile_text(property_node)
            else:
                raise ValueError("unexpected_xmp_property")
            fields[key] = value
    expected = {
        (_NS["pdfuaid"], "part"): "1",
        (_NS["pdf"], "Producer"): _CONTROLLED_INFO["/Producer"],
        (_NS["dc"], "title"): GENERATED_PDF_PRODUCT,
        (_NS["dc"], "creator"): GENERATED_PDF_AUTHOR,
        (_NS["xmp"], "CreatorTool"): GENERATED_PDF_PRODUCT,
    }
    if fields != expected:
        raise ValueError("xmp_profile_mismatch")


def validate_pdf_candidate(
    *,
    pdf_bytes: object,
    expected_pdf_sha256: object,
    expected_author: object,
    expected_language: object,
    metadata_profile: object = None,
) -> PdfCandidateValidation:
    """Validate candidate identity and optional controlled metadata, without release."""
    profile = (
        GENERATED_PDF_METADATA_PROFILE
        if isinstance(metadata_profile, str) and metadata_profile == GENERATED_PDF_METADATA_PROFILE
        else None
    )
    if metadata_profile is not None and profile is None:
        return _result(errors=("pdf_metadata_profile_invalid",))
    if profile and (
        not isinstance(expected_author, str)
        or expected_author != GENERATED_PDF_AUTHOR
        or not is_supported_report_locale(expected_language)
    ):
        return _result(errors=("pdf_metadata_profile_invalid",),profile=profile)
    if not isinstance(pdf_bytes,bytes) or not pdf_bytes.startswith(b"%PDF-"):
        return _result(errors=("pdf_structure_invalid",),profile=profile)
    if profile and len(pdf_bytes) > _PROFILE_MAX_PDF_BYTES:
        return _result(errors=("pdf_metadata_budget_exceeded",),profile=profile)
    digest=hashlib.sha256(pdf_bytes).hexdigest()
    if not isinstance(expected_pdf_sha256,str) or _SHA256.fullmatch(expected_pdf_sha256) is None:
        return _result(digest=digest,errors=("expected_pdf_digest_invalid",),profile=profile)
    if digest != expected_pdf_sha256:
        return _result(digest=digest,errors=("pdf_digest_mismatch",),profile=profile)

    try:
        from importlib.metadata import version
        from pypdf import PdfReader
        if profile and version("pypdf") != "6.19.0":
            return _result(digest=digest,errors=("pdf_validator_unavailable",),profile=profile)
        reader=PdfReader(BytesIO(pdf_bytes),strict=True)
        if reader.is_encrypted:
            return _result(digest=digest,errors=("encrypted_pdf_forbidden",),profile=profile)
        page_count=len(reader.pages)
        raw_metadata=reader.metadata or {}
        metadata={str(k):str(v) for k,v in raw_metadata.items() if v is not None}
        catalog=reader.root_object
        language=catalog["/Lang"] if "/Lang" in catalog else None
    except Exception:
        return _result(digest=digest,errors=("pdf_structure_invalid",),profile=profile)

    errors = []
    if page_count < 1:
        errors.append("pdf_structure_invalid")
    try:
        if profile and "/Metadata" in catalog:
            stream = catalog["/Metadata"]
            if stream.get("/Type") != "/Metadata" or stream.get("/Subtype") != "/XML":
                raise ValueError("unsupported_metadata_stream")
            if not set(stream) <= {"/Type", "/Subtype", "/Filter", "/Length"}:
                raise ValueError("unsupported_metadata_stream_field")
            if len(stream.get_data()) > _PROFILE_MAX_XMP_BYTES:
                raise OverflowError("xmp_budget")
        xmp = reader.xmp_metadata
        metadata_values = list(metadata.values()) + [
            f"{key.lstrip('/')}={value}" for key,value in metadata.items()
        ] + list(_xmp_metadata_values(xmp))
        if isinstance(language, str):
            metadata_values.append(language)
    except OverflowError:
        return _result(digest=digest,errors=("pdf_metadata_budget_exceeded",),profile=profile)
    except Exception:
        return _result(digest=digest,errors=("pdf_xmp_invalid",),profile=profile)

    author=metadata.get("/Author")
    if not isinstance(expected_author,str) or not expected_author.strip() or author != expected_author.strip():
        errors.append("pdf_author_mismatch")
    if not isinstance(expected_language,str) or not expected_language.strip() or language != expected_language.strip():
        errors.append("pdf_language_mismatch")
    if any(pattern.search(value) for value in metadata_values for pattern in _SENSITIVE):
        errors.append("pdf_metadata_sensitive")
    if profile:
        if dict(raw_metadata) != _CONTROLLED_INFO:
            errors.append("pdf_metadata_profile_mismatch")
        try:
            _controlled_xmp_fields(xmp)
        except OverflowError:
            errors.append("pdf_metadata_budget_exceeded")
        except Exception:
            errors.append("pdf_metadata_profile_mismatch")

    return _result(
        digest=digest,page_count=page_count,metadata=metadata,
        accessibility="PASS" if not errors else "BLOCKED",
        errors=tuple(dict.fromkeys(errors)),profile=profile,
    )
