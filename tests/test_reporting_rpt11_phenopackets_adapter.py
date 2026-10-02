from __future__ import annotations
import unittest
from interoperability.phenopackets import project_phenopacket


class Rpt11PhenopacketsAdapterTests(unittest.TestCase):
    def test_projects_minimal_v2_with_explicit_subject_and_file(self):
        """Minimal projection contains explicit subject, file, and metadata only."""
        result=project_phenopacket(
            phenopacket_id="PP-001",
            subject_id="SUBJECT-001",
            genomic_file_uri="urn:omnigenis:artifact:sha256:abc123",
            genomic_file_format="vcf",
            genome_assembly="GRCh38",
            canonical_sample_id="SAMPLE-001",
            created="2026-10-02T12:00:00Z",
        )
        self.assertTrue(result.passed,result.errors)
        payload=result.payload
        self.assertEqual(payload["id"],"PP-001")
        self.assertEqual(payload["subject"],{"id":"SUBJECT-001"})
        self.assertEqual(payload["files"][0]["uri"],"urn:omnigenis:artifact:sha256:abc123")
        self.assertEqual(payload["files"][0]["fileAttributes"]["genomeAssembly"],"GRCh38")
        self.assertEqual(payload["files"][0]["individualToFileIdentifiers"],{"SUBJECT-001":"SAMPLE-001"})
        self.assertEqual(payload["metaData"]["created"],"2026-10-02T12:00:00Z")
        self.assertEqual(payload["metaData"]["phenopacketSchemaVersion"],"2.0")
        for absent in ("phenotypicFeatures","diseases","interpretations","medicalActions"):
            self.assertNotIn(absent,payload)

    def test_subject_is_required_and_never_inferred_from_sample(self):
        """Canonical sample identity cannot stand in for a person identity."""
        result=project_phenopacket(
            phenopacket_id="PP-001",subject_id=None,
            genomic_file_uri="urn:omnigenis:artifact:sha256:abc123",
            genomic_file_format="vcf",genome_assembly="GRCh38",
            canonical_sample_id="SAMPLE-001",
            created="2026-10-02T12:00:00Z",
        )
        self.assertFalse(result.passed)
        self.assertIn("explicit_subject_required",result.errors)

    def test_genomic_file_reference_is_required(self):
        """The adapter does not invent or fetch a genomic file reference."""
        result=project_phenopacket(
            phenopacket_id="PP-001",subject_id="SUBJECT-001",
            genomic_file_uri="",genomic_file_format="vcf",
            genome_assembly="GRCh38",canonical_sample_id="SAMPLE-001",
            created="2026-10-02T12:00:00Z",
        )
        self.assertFalse(result.passed)
        self.assertIn("genomic_file_reference_required",result.errors)

    def test_required_identifiers_and_format_are_fail_closed(self):
        """Malformed projection identity and unsupported formats are rejected."""
        cases=[
            {"phenopacket_id":"","subject_id":"S","genomic_file_format":"vcf"},
            {"phenopacket_id":"P","subject_id":"","genomic_file_format":"vcf"},
            {"phenopacket_id":"P","subject_id":"S","genomic_file_format":"unknown"},
        ]
        for case in cases:
            with self.subTest(case=case):
                result=project_phenopacket(
                    genomic_file_uri="urn:omnigenis:artifact:sha256:abc123",
                    genome_assembly="GRCh38",canonical_sample_id="SAMPLE-001",
                    created="2026-10-02T12:00:00Z",**case,
                )
                self.assertFalse(result.passed)

    def test_supplied_invalid_canonical_sample_id_fails_closed(self):
        """A supplied sample identity cannot disappear silently during projection."""
        for invalid in ("   ", 123):
            with self.subTest(invalid=invalid):
                result=project_phenopacket(
                    phenopacket_id="PP-001",subject_id="SUBJECT-001",
                    genomic_file_uri="urn:omnigenis:artifact:sha256:abc123",
                    genomic_file_format="vcf",genome_assembly="GRCh38",
                    canonical_sample_id=invalid,created="2026-10-02T12:00:00Z",
                )
                self.assertFalse(result.passed)
                self.assertIn("canonical_sample_id_invalid",result.errors)

    def test_created_timestamp_is_required_for_metadata(self):
        """MetaData creation time must be supplied explicitly for deterministic output."""
        result=project_phenopacket(
            phenopacket_id="PP-001",subject_id="SUBJECT-001",
            genomic_file_uri="urn:omnigenis:artifact:sha256:abc123",
            genomic_file_format="vcf",genome_assembly="GRCh38",
            canonical_sample_id="SAMPLE-001",created=None,
        )
        self.assertFalse(result.passed)
        self.assertIn("metadata_created_required",result.errors)

    def test_projection_is_deterministic_and_snapshot_isolated(self):
        """Equivalent inputs yield identical detached payloads."""
        kwargs=dict(
            phenopacket_id="PP-001",subject_id="SUBJECT-001",
            genomic_file_uri="urn:omnigenis:artifact:sha256:abc123",
            genomic_file_format="vcf",genome_assembly="GRCh38",
            canonical_sample_id="SAMPLE-001",
            created="2026-10-02T12:00:00Z",
        )
        first=project_phenopacket(**kwargs); second=project_phenopacket(**kwargs)
        self.assertEqual(first.to_dict(),second.to_dict())
        exposed=first.to_dict(); exposed["payload"]["subject"]["id"]="MUTATED"
        self.assertEqual(first.to_dict()["payload"]["subject"]["id"],"SUBJECT-001")

if __name__=="__main__":
    unittest.main()
