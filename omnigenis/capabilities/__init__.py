"""Capability implementations exposed by the clean target."""

from .vcf_intake import VcfIntakeResult, validate_vcf_bytes

__all__ = ["VcfIntakeResult", "validate_vcf_bytes"]
