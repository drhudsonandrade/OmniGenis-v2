"""Resource-limited effective-object inspection for passive generated report PDFs."""
from __future__ import annotations

import hashlib
from importlib.metadata import version
from io import BytesIO
import json
import sys

MAX_PDF_BYTES = 8 * 1024 * 1024
MAX_PAGES = 32
MAX_VISITS = 20000
MAX_DEPTH = 64
MEMORY_BYTES = 256 * 1024 * 1024
CPU_SECONDS = 5
WALL_SECONDS = 10
PARSER_VERSION = "6.19.0"
POLICY_ID = "passive-report-pdf-v1"
_ACTION_KEYS = frozenset({"/A", "/AA", "/OpenAction", "/JS", "/JavaScript", "/PresSteps"})
_ATTACHMENT_KEYS = frozenset({"/EmbeddedFiles", "/EF", "/AF", "/Collection"})
_FORM_KEYS = frozenset({"/AcroForm", "/XFA"})
_MEDIA_KEYS = frozenset({"/RichMediaContent", "/RichMediaSettings"})
_ACTION_TYPES = frozenset({
    "/JavaScript", "/Launch", "/URI", "/GoTo", "/GoToR", "/GoToE", "/Thread",
    "/Sound", "/Movie", "/Hide", "/Named", "/SubmitForm", "/ResetForm",
    "/ImportData", "/SetOCGState", "/Rendition", "/Trans", "/GoTo3DView",
    "/RichMediaExecute",
})
_MEDIA_SUBTYPES = frozenset({"/RichMedia", "/Screen", "/Movie", "/Sound", "/3D"})
ERRORS = frozenset({
    "pdf_safety_structure_invalid", "encrypted_pdf_forbidden", "pdf_safety_budget_exceeded",
    "pdf_safety_parser_version_mismatch", "pdf_safety_parser_unavailable",
    "pdf_safety_worker_unavailable", "pdf_actions_forbidden", "pdf_embedded_files_forbidden",
    "pdf_forms_forbidden", "pdf_interactive_media_forbidden", "pdf_external_stream_forbidden",
})


def blocked(error: str, pdf_digest: str | None = None) -> dict:
    """Emit a bounded failure without filenames, action text or parser messages."""
    return {"status": "BLOCKED", "pdf_sha256": pdf_digest, "page_count": None,
            "object_count": None, "errors": [error]}


def inspect_graph(trailer: object) -> tuple[int, list[str]]:
    """Traverse effective references iteratively; bound visits, depth and pending work."""
    from pypdf.generic import (
        ArrayObject, DictionaryObject, IndirectObject, NameObject, PdfObject, StreamObject,
    )
    pending = [(trailer, 0)]
    references, containers, findings = set(), set(), set()
    visits = 0
    while pending:
        obj, depth = pending.pop()
        if isinstance(obj, IndirectObject):
            identity = (obj.idnum, obj.generation)
            if identity in references:
                continue
            references.add(identity)
            obj = obj.get_object()
        if not isinstance(obj, PdfObject) or isinstance(obj, IndirectObject):
            raise ValueError("unresolved object")
        if isinstance(obj, (DictionaryObject, ArrayObject)):
            if id(obj) in containers:
                continue
            containers.add(id(obj))
        visits += 1
        if visits > MAX_VISITS or depth > MAX_DEPTH:
            raise OverflowError("graph budget")
        children = ()
        if isinstance(obj, DictionaryObject):
            if any(not isinstance(key, NameObject) for key in obj):
                raise ValueError("invalid dictionary key")
            names = {}
            for key in ("/Type", "/Subtype", "/S"):
                if key in obj:
                    value = obj[key]
                    if not isinstance(value, NameObject):
                        raise ValueError("invalid name discriminator")
                    names[key] = value
            if _ACTION_KEYS.intersection(obj) or names.get("/Type") == "/Action" or names.get("/S") in _ACTION_TYPES:
                findings.add("pdf_actions_forbidden")
            if _ATTACHMENT_KEYS.intersection(obj) or names.get("/Type") in ("/Filespec", "/EmbeddedFile") or names.get("/Subtype") == "/FileAttachment":
                findings.add("pdf_embedded_files_forbidden")
            if _FORM_KEYS.intersection(obj) or names.get("/Subtype") == "/Widget":
                findings.add("pdf_forms_forbidden")
            if _MEDIA_KEYS.intersection(obj) or names.get("/Subtype") in _MEDIA_SUBTYPES:
                findings.add("pdf_interactive_media_forbidden")
            if isinstance(obj, StreamObject) and any(key in obj for key in ("/F", "/FFilter", "/FDecodeParms")):
                findings.add("pdf_external_stream_forbidden")
            children = obj.values()
        elif isinstance(obj, ArrayObject):
            children = obj
        for child in children:
            if len(pending) >= MAX_VISITS:
                raise OverflowError("pending graph budget")
            pending.append((child, depth + 1))
    return visits, sorted(findings)


def inspect_document(pdf: bytes) -> dict:
    """Inspect effective objects without evaluating actions or opaque payload semantics."""
    if len(pdf) > MAX_PDF_BYTES:
        return blocked("pdf_safety_budget_exceeded")
    pdf_digest = hashlib.sha256(pdf).hexdigest()
    if not pdf.startswith(b"%PDF-"):
        return blocked("pdf_safety_structure_invalid", pdf_digest)
    try:
        if version("pypdf") != PARSER_VERSION:
            return blocked("pdf_safety_parser_version_mismatch", pdf_digest)
        from pypdf import PdfReader
        from pypdf.generic import DictionaryObject, NameObject
    except (ImportError, OSError):
        return blocked("pdf_safety_parser_unavailable", pdf_digest)
    try:
        reader = PdfReader(BytesIO(pdf), strict=True)
        if reader.is_encrypted:
            return blocked("encrypted_pdf_forbidden", pdf_digest)
        root = reader.root_object
        if not isinstance(root, DictionaryObject) or "/Type" not in root or not isinstance(root["/Type"], NameObject) or root["/Type"] != "/Catalog":
            return blocked("pdf_safety_structure_invalid", pdf_digest)
        pages = len(reader.pages)
        if pages < 1:
            return blocked("pdf_safety_structure_invalid", pdf_digest)
        if pages > MAX_PAGES:
            return blocked("pdf_safety_budget_exceeded", pdf_digest)
        count, findings = inspect_graph(reader.trailer)
        if findings:
            result = blocked(findings[0], pdf_digest)
            result["errors"] = findings
            return result
        return {"status": "PASS", "pdf_sha256": pdf_digest, "page_count": pages,
                "object_count": count, "errors": []}
    except (MemoryError, OverflowError):
        return blocked("pdf_safety_budget_exceeded", pdf_digest)
    except Exception:  # noqa: BLE001 - every malformed parser result must fail closed
        return blocked("pdf_safety_structure_invalid", pdf_digest)


def main() -> None:
    """Install Linux resource limits before reading or parsing candidate bytes."""
    try:
        if sys.platform != "linux":
            raise OSError("unsupported execution profile")
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (MEMORY_BYTES, MEMORY_BYTES))
        resource.setrlimit(resource.RLIMIT_CPU, (CPU_SECONDS, CPU_SECONDS))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, OSError, ValueError):
        response = blocked("pdf_safety_worker_unavailable")
    else:
        try:
            response = inspect_document(sys.stdin.buffer.read(MAX_PDF_BYTES + 1))
        except Exception:  # noqa: BLE001 - never expose input or exception text
            response = blocked("pdf_safety_structure_invalid")
    sys.stdout.write(json.dumps(response, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
