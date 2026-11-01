"""Finite whole-file byte/page classes for optional generated-PDF inspections.

The legacy standalone class retains 512 pages up to 8 MiB. A larger file is
admitted only up to 64 pages and 16 MiB. Default rendering/QA, inner decoded
content and process budgets are separate and are not enlarged here.
"""
from __future__ import annotations

from hashlib import sha256
import json

PROFILE_ID = "generated-pdf-document-byte-budget-v1"
LEGACY_MAX_PDF_BYTES = 8 * 1024 * 1024
LEGACY_MAX_DOCUMENT_PAGES = 512
MAX_PDF_BYTES = 16 * 1024 * 1024
MAX_LARGE_DOCUMENT_PAGES = 64


def document_byte_budget_profile() -> dict:
    """Return both closed admission classes without asserting resource qualification."""
    return {
        "schema_version": "1.0.0", "profile_id": PROFILE_ID,
        "legacy": {"max_pdf_bytes": LEGACY_MAX_PDF_BYTES,
                   "max_pages": LEGACY_MAX_DOCUMENT_PAGES},
        "expanded": {"max_pdf_bytes": MAX_PDF_BYTES,
                     "max_pages": MAX_LARGE_DOCUMENT_PAGES},
        "selection": "PDF_BYTES_AND_COMPLETE_DOCUMENT_PAGE_COUNT",
        "inner_stream_limits_expanded": False,
        "aggregate_job_resources_qualified": False,
        "default_pipeline_activated": False, "release_authorized": False,
    }


PROFILE_SHA256 = sha256(json.dumps(document_byte_budget_profile(), sort_keys=True,
    separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()


def require_pdf_document_budget(byte_count: object, page_count: object) -> None:
    """Reject noncanonical counts, class overflow and widened runtime constants."""
    if ((LEGACY_MAX_PDF_BYTES, LEGACY_MAX_DOCUMENT_PAGES,
         MAX_PDF_BYTES, MAX_LARGE_DOCUMENT_PAGES)
            != (8388608, 512, 16777216, 64)
            or type(byte_count) is not int or not 1 <= byte_count <= MAX_PDF_BYTES
            or type(page_count) is not int or not 1 <= page_count <= LEGACY_MAX_DOCUMENT_PAGES
            or (byte_count > LEGACY_MAX_PDF_BYTES and page_count > MAX_LARGE_DOCUMENT_PAGES)):
        raise ValueError("PDF document byte/page budget invalid")
