from __future__ import annotations

import unittest

from reporting.workflow import (
    ConsentStatus,
    ReviewState,
    WorkflowError,
    build_reporting_workflow,
)


class Rpt09WorkflowTests(unittest.TestCase):
    def test_verified_consent_and_approved_review_are_release_ready(self):
        result = build_reporting_workflow(
            case_id="CASE-001",
            sample_id="SAMPLE-001",
            consent_status=ConsentStatus.VERIFIED,
            consent_record_id="CONSENT-001",
            consent_record_sha256="a" * 64,
            review_state=ReviewState.APPROVED,
        )
        self.assertTrue(result.release_ready)
        self.assertEqual(result.case_id, "CASE-001")
        self.assertEqual(result.sample_id, "SAMPLE-001")

    def test_case_and_sample_identity_are_required(self):
        with self.assertRaisesRegex(WorkflowError, "case_id"):
            build_reporting_workflow(
                case_id="",
                sample_id="SAMPLE-001",
                consent_status=ConsentStatus.NOT_VERIFIED,
                review_state=ReviewState.PENDING,
            )
        with self.assertRaisesRegex(WorkflowError, "sample_id"):
            build_reporting_workflow(
                case_id="CASE-001",
                sample_id="",
                consent_status=ConsentStatus.NOT_VERIFIED,
                review_state=ReviewState.PENDING,
            )

    def test_verified_consent_requires_exact_record_identity(self):
        with self.assertRaisesRegex(WorkflowError, "consent_record_id"):
            build_reporting_workflow(
                case_id="CASE-001",
                sample_id="SAMPLE-001",
                consent_status=ConsentStatus.VERIFIED,
                consent_record_id=None,
                consent_record_sha256="a" * 64,
                review_state=ReviewState.APPROVED,
            )
        with self.assertRaisesRegex(WorkflowError, "consent_record_sha256"):
            build_reporting_workflow(
                case_id="CASE-001",
                sample_id="SAMPLE-001",
                consent_status=ConsentStatus.VERIFIED,
                consent_record_id="CONSENT-001",
                consent_record_sha256="not-a-digest",
                review_state=ReviewState.APPROVED,
            )

    def test_nonverified_or_withdrawn_consent_is_never_release_ready(self):
        for status in (ConsentStatus.NOT_VERIFIED, ConsentStatus.WITHDRAWN):
            with self.subTest(status=status):
                result = build_reporting_workflow(
                    case_id="CASE-001",
                    sample_id="SAMPLE-001",
                    consent_status=status,
                    review_state=ReviewState.APPROVED,
                )
                self.assertFalse(result.release_ready)

    def test_nonapproved_review_is_never_release_ready(self):
        for state in (ReviewState.PENDING, ReviewState.IN_REVIEW, ReviewState.REJECTED):
            with self.subTest(state=state):
                result = build_reporting_workflow(
                    case_id="CASE-001",
                    sample_id="SAMPLE-001",
                    consent_status=ConsentStatus.VERIFIED,
                    consent_record_id="CONSENT-001",
                    consent_record_sha256="b" * 64,
                    review_state=state,
                )
                self.assertFalse(result.release_ready)

    def test_workflow_is_deterministic_and_serializable(self):
        first = build_reporting_workflow(
            case_id="CASE-001",
            sample_id="SAMPLE-001",
            consent_status="VERIFIED",
            consent_record_id="CONSENT-001",
            consent_record_sha256="c" * 64,
            review_state="APPROVED",
        )
        second = build_reporting_workflow(
            case_id="CASE-001",
            sample_id="SAMPLE-001",
            consent_status="VERIFIED",
            consent_record_id="CONSENT-001",
            consent_record_sha256="c" * 64,
            review_state="APPROVED",
        )
        self.assertEqual(first, second)
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(first.to_dict()["roadmap_id"], "RPT-09")

    def test_unknown_states_fail_closed(self):
        with self.assertRaisesRegex(WorkflowError, "consent_status"):
            build_reporting_workflow(
                case_id="CASE-001",
                sample_id="SAMPLE-001",
                consent_status="MAYBE",
                review_state="PENDING",
            )
        with self.assertRaisesRegex(WorkflowError, "review_state"):
            build_reporting_workflow(
                case_id="CASE-001",
                sample_id="SAMPLE-001",
                consent_status="NOT_VERIFIED",
                review_state="MAYBE",
            )


if __name__ == "__main__":
    unittest.main()
