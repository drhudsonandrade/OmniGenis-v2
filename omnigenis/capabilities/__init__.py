"""Capability implementations exposed by the clean target."""

from .artifact_gate import ArtifactGateResult, verify_artifact_bytes
from .canonical_genomic_model import (
    CanonicalGenomicModelResult,
    build_canonical_genomic_model,
)
from .canonical_interpretation import (
    CanonicalInterpretationObjectResult,
    build_canonical_interpretation_object,
)
from .evidence_snapshot import (
    MinimumEvidenceSnapshotResult,
    build_minimum_evidence_snapshot,
)
from .canonical_variant_identity import (
    CanonicalVariantIdentityResult,
    canonicalize_normalized_variants,
)
from .gene_identity import GeneIdentityResult, resolve_gene_identity
from .reference_identity import ReferenceIdentityResult, verify_reference_identity
from .variant_normalization import VariantNormalizationResult, normalize_small_variants
from .vcf_intake import VcfIntakeResult, validate_vcf_bytes
from .vcf_qc import VcfQcObservationResult, observe_vcf_qc

__all__ = [
    "ArtifactGateResult",
    "CanonicalGenomicModelResult",
    "CanonicalInterpretationObjectResult",
    "CanonicalVariantIdentityResult",
    "MinimumEvidenceSnapshotResult",
    "GeneIdentityResult",
    "ReferenceIdentityResult",
    "VariantNormalizationResult",
    "VcfIntakeResult",
    "VcfQcObservationResult",
    "build_canonical_genomic_model",
    "build_canonical_interpretation_object",
    "build_minimum_evidence_snapshot",
    "canonicalize_normalized_variants",
    "normalize_small_variants",
    "resolve_gene_identity",
    "observe_vcf_qc",
    "validate_vcf_bytes",
    "verify_artifact_bytes",
    "verify_reference_identity",
]
