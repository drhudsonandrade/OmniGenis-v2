"""Capability implementations exposed by the clean target."""

from .artifact_gate import ArtifactGateResult, verify_artifact_bytes
from .reference_identity import ReferenceIdentityResult, verify_reference_identity
from .variant_normalization import VariantNormalizationResult, normalize_small_variants
from .vcf_intake import VcfIntakeResult, validate_vcf_bytes
from .vcf_qc import VcfQcObservationResult, observe_vcf_qc

__all__ = [
    "ArtifactGateResult",
    "ReferenceIdentityResult",
    "VariantNormalizationResult",
    "VcfIntakeResult",
    "VcfQcObservationResult",
    "normalize_small_variants",
    "observe_vcf_qc",
    "validate_vcf_bytes",
    "verify_artifact_bytes",
    "verify_reference_identity",
]
