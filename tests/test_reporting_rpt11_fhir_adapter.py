from __future__ import annotations
import unittest
from interoperability.fhir import project_genomic_report

PROFILE="http://hl7.org/fhir/uv/genomics-reporting/StructureDefinition/genomic-report"

class Rpt11FhirAdapterTests(unittest.TestCase):
    def test_projects_minimal_genomic_report_without_inferred_subject(self):
        """The profile permits a report-level projection without inventing subject/results."""
        result=project_genomic_report(report_id="REPORT-001",subject_reference=None)
        self.assertTrue(result.passed,result.errors)
        payload=result.to_dict()["payload"]
        self.assertEqual(payload["resourceType"],"DiagnosticReport")
        self.assertEqual(payload["id"],"REPORT-001")
        self.assertEqual(payload["meta"]["profile"],[PROFILE])
        self.assertEqual(payload["status"],"final")
        self.assertEqual(payload["category"],[{"coding":[{"system":"http://terminology.hl7.org/CodeSystem/v2-0074","code":"GE"}]}])
        self.assertEqual(payload["code"],{"coding":[{"system":"http://loinc.org","code":"51969-4"}]})
        for absent in ("subject","result","conclusion","conclusionCode","presentedForm"):
            self.assertNotIn(absent,payload)

    def test_explicit_patient_reference_is_preserved(self):
        """An explicit FHIR Patient reference can be attached without identity inference."""
        result=project_genomic_report(report_id="REPORT-001",subject_reference="Patient/PATIENT-001")
        self.assertTrue(result.passed)
        self.assertEqual(result.to_dict()["payload"]["subject"],{"reference":"Patient/PATIENT-001"})

    def test_invalid_explicit_subject_fails_closed(self):
        """Malformed or unsupported explicit references are rejected."""
        for value in ("", "PATIENT-001", "Observation/1", 123):
            with self.subTest(value=value):
                result=project_genomic_report(report_id="REPORT-001",subject_reference=value)
                self.assertFalse(result.passed)
                self.assertIn("subject_reference_invalid",result.errors)

    def test_report_id_is_required_and_fhir_safe(self):
        """Resource id must satisfy the bounded FHIR id syntax used by this adapter."""
        for value in ("", "has space", "x"*65, 123):
            with self.subTest(value=value):
                result=project_genomic_report(report_id=value,subject_reference=None)
                self.assertFalse(result.passed)
                self.assertIn("report_id_invalid",result.errors)

    def test_projection_is_deterministic_and_snapshot_isolated(self):
        """Equivalent inputs yield identical detached resources."""
        first=project_genomic_report(report_id="REPORT-001",subject_reference="Patient/PATIENT-001")
        second=project_genomic_report(report_id="REPORT-001",subject_reference="Patient/PATIENT-001")
        self.assertEqual(first.to_dict(),second.to_dict())
        exposed=first.to_dict(); exposed["payload"]["status"]="amended"
        self.assertEqual(first.to_dict()["payload"]["status"],"final")

if __name__=="__main__":
    unittest.main()
