from __future__ import annotations
import unittest

from interoperability.vrs import project_vrs_allele


class Rpt11VrsAdapterTests(unittest.TestCase):
    def test_projects_snv_with_explicit_refget_binding(self):
        """An E1A SNV projects to a deterministic VRS 2.0 Allele."""
        result=project_vrs_allele(
            contig_accession="NC_000001.11",
            position_1_based=101,
            ref="A",
            alt="G",
            refget_accession="SQ.example",
            bound_contig_accession="NC_000001.11",
        )
        self.assertTrue(result.passed,result.errors)
        self.assertEqual(result.profile_id,"ga4gh-vrs-v2")
        self.assertEqual(result.payload,{
            "type":"Allele",
            "location":{
                "type":"SequenceLocation",
                "sequenceReference":{
                    "type":"SequenceReference",
                    "refgetAccession":"SQ.example"
                },
                "start":100,
                "end":101
            },
            "state":{"type":"LiteralSequenceExpression","sequence":"G"}
        })
        self.assertIsNone(result.vrs_computed_identifier)

    def test_projects_small_indel_using_reference_length(self):
        """Location end is derived from the canonical reference allele length."""
        result=project_vrs_allele(
            contig_accession="NC_000001.11",position_1_based=101,
            ref="AT",alt="A",refget_accession="SQ.example",
            bound_contig_accession="NC_000001.11",
        )
        self.assertTrue(result.passed)
        self.assertEqual(result.payload["location"]["start"],100)
        self.assertEqual(result.payload["location"]["end"],102)
        self.assertEqual(result.payload["state"]["sequence"],"A")

    def test_missing_refget_binding_fails_closed(self):
        """The adapter never invents a refget accession."""
        result=project_vrs_allele(
            contig_accession="NC_000001.11",position_1_based=101,
            ref="A",alt="G",refget_accession=None,
            bound_contig_accession="NC_000001.11",
        )
        self.assertFalse(result.passed)
        self.assertIn("refget_binding_required",result.errors)

    def test_mismatched_contig_binding_fails_closed(self):
        """A refget accession cannot be rebound to a different contig implicitly."""
        result=project_vrs_allele(
            contig_accession="NC_000001.11",position_1_based=101,
            ref="A",alt="G",refget_accession="SQ.example",
            bound_contig_accession="NC_000002.12",
        )
        self.assertFalse(result.passed)
        self.assertIn("refget_binding_mismatch",result.errors)

    def test_invalid_or_symbolic_variant_fails_closed(self):
        """Only literal E1A SNV/small-indel alleles are projected."""
        cases=[
            {"position_1_based":0,"ref":"A","alt":"G"},
            {"position_1_based":1,"ref":"","alt":"G"},
            {"position_1_based":1,"ref":"A","alt":"<DEL>"},
            {"position_1_based":1,"ref":"A","alt":"G,C"},
        ]
        for case in cases:
            with self.subTest(case=case):
                result=project_vrs_allele(
                    contig_accession="NC_000001.11",
                    refget_accession="SQ.example",
                    bound_contig_accession="NC_000001.11",
                    **case,
                )
                self.assertFalse(result.passed)
                self.assertIn("unsupported_canonical_variant",result.errors)

    def test_projection_is_deterministic_and_snapshot_isolated(self):
        """Equivalent inputs yield identical detached payloads."""
        kwargs=dict(
            contig_accession="NC_000001.11",position_1_based=101,
            ref="A",alt="G",refget_accession="SQ.example",
            bound_contig_accession="NC_000001.11",
        )
        first=project_vrs_allele(**kwargs)
        second=project_vrs_allele(**kwargs)
        self.assertEqual(first.to_dict(),second.to_dict())
        exposed=first.to_dict()
        exposed["payload"]["state"]["sequence"]="T"
        self.assertEqual(first.to_dict()["payload"]["state"]["sequence"],"G")

if __name__=="__main__":
    unittest.main()
