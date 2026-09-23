"""Deterministic structural intake validation for the initial VCF capability."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib

CAPABILITY_ID = "vcf-intake-envelope"
CAPABILITY_VERSION = "1.0.0"
VCF_STANDARD = "VCFv4.5"
FILEFORMAT_LINE = "##fileformat=VCFv4.5"
HEADER_PREFIX = (
    "#CHROM",
    "POS",
    "ID",
    "REF",
    "ALT",
    "QUAL",
    "FILTER",
    "INFO",
    "FORMAT",
)
LIMITATIONS = (
    "No reference concordance or contig-build validation.",
    "No variant normalization or scientific interpretation.",
    "No full structured meta-information, INFO, FORMAT, or allele grammar validation.",
    "No BGZF, BCF, gVCF, indexing, SV/CNV/STR semantic validation.",
)
@dataclass(frozen=True)
class VcfIntakeResult:
    """Stable output contract for structural VCF intake."""

    is_valid: bool
    sample_id: str | None
    record_count: int
    size_bytes: int
    content_sha256: str
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Return the tool-neutral capability result contract."""
        return {
            "capability_id": CAPABILITY_ID,
            "capability_version": CAPABILITY_VERSION,
            "canonical_status": "VALID" if self.is_valid else "INVALID",
            "canonical_payload": {
                "vcf_standard": VCF_STANDARD,
                "sample_id": self.sample_id,
                "record_count": self.record_count,
                "size_bytes": self.size_bytes,
                "content_sha256": self.content_sha256,
                "errors": list(self.errors),
            },
            "availability": "AVAILABLE",
            "limitations": list(LIMITATIONS),
            "executor_id": "omnigenis.python-stdlib",
            "executor_version": CAPABILITY_VERSION,
            "adapter_version": None,
            "model_id": None,
            "resource_release": None,
            "reference_bundle": None,
            "execution_profile": "pure-bytes-validation-v1",
            "raw_artifact_refs": [],
            "provenance_refs": ["GA4GH-HTS-VCFv4.5"],
        }


def _disallowed_control_character(text: str) -> bool:
    """Return true when VCF-disallowed C0 control characters are present."""
    for character in text:
        codepoint = ord(character)
        if 0x00 <= codepoint <= 0x08:
            return True
        if codepoint in (0x0B, 0x0C):
            return True
        if 0x0E <= codepoint <= 0x1F:
            return True
    return False


def _has_lone_carriage_return(text: str) -> bool:
    """Reject CR unless it participates in a CRLF line separator."""
    return "\r" in text.replace("\r\n", "")


def validate_vcf_bytes(data: bytes) -> VcfIntakeResult:
    """Validate the supported VCF 4.5 single-sample structural envelope."""
    digest = hashlib.sha256(data).hexdigest()
    errors: list[str] = []
    sample_id: str | None = None
    record_count = 0

    if not data:
        errors.append("empty_input")
        return VcfIntakeResult(False, None, 0, 0, digest, tuple(errors))

    if data.startswith(b"\xef\xbb\xbf"):
        errors.append("utf8_bom_not_allowed")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        errors.append("invalid_utf8")
        return VcfIntakeResult(False, None, 0, len(data), digest, tuple(errors))

    if _disallowed_control_character(text):
        errors.append("disallowed_control_character")
    if _has_lone_carriage_return(text):
        errors.append("invalid_line_separator")
    if any(separator in text for separator in ("\u0085", "\u2028", "\u2029")):
        errors.append("invalid_line_separator")

    normalized_text = text.replace("\r\n", "\n")
    lines = normalized_text.split("\n")
    if normalized_text.endswith("\n"):
        lines.pop()
    if not lines:
        errors.append("missing_fileformat")
        return VcfIntakeResult(False, None, 0, len(data), digest, tuple(errors))

    if lines[0] != FILEFORMAT_LINE:
        errors.append("unsupported_or_missing_fileformat")
    if sum(line.startswith("##fileformat=") for line in lines) != 1:
        errors.append("fileformat_must_be_unique")

    header_indices = [index for index, line in enumerate(lines) if line.startswith("#CHROM\t")]
    if len(header_indices) != 1:
        errors.append("exactly_one_header_required")
        return VcfIntakeResult(False, None, 0, len(data), digest, tuple(errors))

    header_index = header_indices[0]
    for line in lines[1:header_index]:
        if not line.startswith("##"):
            errors.append("non_meta_line_before_header")
            break
    header = lines[header_index].split("\t")
    if tuple(header[:9]) != HEADER_PREFIX:
        errors.append("invalid_header_columns")
    if len(header) != 10:
        errors.append("exactly_one_sample_required")
    elif not header[9]:
        errors.append("sample_id_required")
    else:
        sample_id = header[9]

    seen_chroms: set[str] = set()
    active_chrom: str | None = None
    previous_position: int | None = None

    data_lines = lines[header_index + 1 :]
    if data_lines and not normalized_text.endswith("\n"):
        errors.append("unterminated_final_data_line")

    for line_number, line in enumerate(data_lines, start=header_index + 2):
        if not line:
            errors.append(f"line_{line_number}:blank_line")
            continue
        if line.startswith("#"):
            errors.append(f"line_{line_number}:header_after_data")
            continue
        fields = line.split("\t")
        record_count += 1
        if len(fields) != 10:
            errors.append(f"line_{line_number}:column_count")
            continue
        if any(field == "" for field in fields):
            errors.append(f"line_{line_number}:zero_length_field")

        chrom = fields[0]
        if not chrom:
            errors.append(f"line_{line_number}:chrom_required")
        elif any(character.isspace() for character in chrom):
            errors.append(f"line_{line_number}:invalid_chrom")

        position: int | None = None
        try:
            position = int(fields[1])
        except ValueError:
            errors.append(f"line_{line_number}:invalid_pos")
        else:
            if position < 0:
                errors.append(f"line_{line_number}:invalid_pos")
                position = None

        if chrom and not any(character.isspace() for character in chrom):
            if active_chrom != chrom:
                if active_chrom is not None:
                    seen_chroms.add(active_chrom)
                if chrom in seen_chroms:
                    errors.append(f"line_{line_number}:non_contiguous_chrom")
                active_chrom = chrom
                previous_position = None
            if position is not None:
                if previous_position is not None and position < previous_position:
                    errors.append(f"line_{line_number}:decreasing_pos")
                previous_position = position

        if fields[3] in {"", "."}:
            errors.append(f"line_{line_number}:ref_required")
        if fields[4] == "":
            errors.append(f"line_{line_number}:alt_required")
        if fields[8] == "":
            errors.append(f"line_{line_number}:format_required")
        if fields[9] == "":
            errors.append(f"line_{line_number}:sample_value_required")

    return VcfIntakeResult(
        is_valid=not errors,
        sample_id=sample_id,
        record_count=record_count,
        size_bytes=len(data),
        content_sha256=digest,
        errors=tuple(errors),
    )
