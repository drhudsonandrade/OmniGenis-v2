"""Resource acquisition metadata must never activate an unverified cohort."""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, replace
import importlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/resource_cohort/manifest.valid.json"
SCHEMA = ROOT / "schemas/resource-cohort.v1.schema.json"
PAYLOADS = (
    b'{"records":[{"id":"fixture-001"}]}\n',
    b'{"records":[{"id":"fixture-002"}]}\n',
)


class ResourceCohortTests(unittest.TestCase):
    """Validate cohort quarantine, strict contracts, and immutable receipts."""

    def setUp(self):
        """Load the quarantine API and a fresh valid manifest fixture."""
        self.assertIsNotNone(
            importlib.util.find_spec("omnigenis.resource_cohort"),
            "resource cohort quarantine contract is not implemented",
        )
        self.api = importlib.import_module("omnigenis.resource_cohort")
        self.document = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def manifest(self, document=None):
        """Build a manifest from the supplied document or current fixture."""
        return self.api.ResourceCohortManifest(
            self.document if document is None else document
        )

    def downloads(self, document=None):
        """Create complete fixture downloads matching the supplied manifest."""
        value = self.document if document is None else document
        return tuple(
            self.api.ResourceDownload(
                cohort_id=value["cohort_id"],
                resource_id=item["resource_id"],
                source_id=item["source_id"],
                source_revision=item["source_revision"],
                reference_profile_id=item["reference_profile_id"],
                normalization_profile_id=item["normalization_profile_id"],
                media_type=item["media_type"],
                status_code=200,
                complete=True,
                retrieved_at="2026-10-22T21:00:00Z",
                payload=payload,
            )
            for item, payload in zip(value["resources"], PAYLOADS)
        )

    def quarantine(self, manifest=None, downloads=None):
        """Quarantine supplied inputs, defaulting to valid fixture inputs."""
        return self.api.quarantine_resource_cohort(
            expected_manifest=self.manifest() if manifest is None else manifest,
            downloads=self.downloads() if downloads is None else downloads,
        )

    def test_exact_complete_cohort_remains_quarantined(self):
        """Keep byte-verified cohorts quarantined without granting trust."""
        result = self.quarantine().to_dict()
        self.assertEqual(result["status"], "QUARANTINED")
        self.assertEqual(result["integrity_scope"], "DECLARED_BYTES_ONLY")
        self.assertEqual(result["activation_authorization"], "NOT_ESTABLISHED")
        self.assertEqual(result["scientific_validity"], "NOT_ESTABLISHED")
        self.assertEqual(result["rights_authentication"], "NOT_ESTABLISHED")
        self.assertEqual(result["resource_count"], 2)
        self.assertEqual(result["total_bytes"], 70)
        self.assertEqual(
            [item["sha256"] for item in result["resources"]],
            [
                "0add517118bf13b64c2dd7ebd64c46e805b90368ce621be162f18e0771824c20",
                "3c2a05023711ea47f06afbc9f6787f0006f5edcea6ce8ac45d3a26fd9eaca1fb",
            ],
        )

    def test_manifest_detaches_nested_input_metadata(self):
        """Preserve manifest contents when nested input metadata changes."""
        manifest = self.manifest()
        before = manifest.manifest_sha256
        self.document["resources"][0]["rights_review"]["sha256"] = "f" * 64
        self.document["resources"].clear()
        self.assertEqual(manifest.manifest_sha256, before)
        self.assertEqual(len(manifest.to_dict()["resources"]), 2)

    def test_manifest_exports_cannot_modify_frozen_contract(self):
        """Prevent exported dictionaries from changing the stored manifest."""
        manifest = self.manifest()
        exported = manifest.to_dict()
        exported["resources"][0]["source_revision"] = "changed"
        self.assertEqual(
            manifest.to_dict()["resources"][0]["source_revision"],
            "fixture-release-001",
        )

    def test_cohort_identity_is_independent_of_resource_order(self):
        """Canonicalize manifest identity and receipt resource ordering."""
        first = self.manifest()
        self.document["resources"].reverse()
        self.assertEqual(first.manifest_sha256, self.manifest().manifest_sha256)
        receipt = self.quarantine(first, tuple(reversed(self.downloads(first.to_dict()))))
        self.assertEqual(
            [r["resource_id"] for r in receipt.to_dict()["resources"]],
            ["fixture-resource-001", "fixture-resource-002"],
        )

    def test_changed_manifest_revision_has_distinct_digest(self):
        """Change the manifest digest when a resource revision changes."""
        first = self.manifest()
        self.document["resources"][0]["source_revision"] = "fixture-release-new"
        self.assertNotEqual(first.manifest_sha256, self.manifest().manifest_sha256)

    def test_receipt_and_manifest_are_frozen(self):
        """Reject assignments to receipt and manifest fields."""
        manifest = self.manifest()
        receipt = self.quarantine(manifest)
        with self.assertRaises(FrozenInstanceError):
            receipt.expected_manifest = manifest
        with self.assertRaises(FrozenInstanceError):
            manifest._canonical_bytes = b"{}"

    def test_receipt_exports_do_not_alias_internal_results(self):
        """Keep internal receipt results independent of exported copies."""
        receipt = self.quarantine()
        exported = receipt.to_dict()
        exported["resources"][0]["sha256"] = "f" * 64
        self.assertEqual(
            receipt.to_dict()["resources"][0]["sha256"],
            "0add517118bf13b64c2dd7ebd64c46e805b90368ce621be162f18e0771824c20",
        )

    def test_wrong_transfer_identity_never_yields_receipt(self):
        """Reject transfers with any mismatched resource identity field."""
        original = self.downloads()
        for field in (
            "cohort_id", "resource_id", "source_id", "source_revision",
            "reference_profile_id", "normalization_profile_id", "media_type",
        ):
            with self.subTest(field=field):
                wrong = "application/xml" if field == "media_type" else "foreign-v1"
                with self.assertRaises(self.api.ResourceCohortError):
                    self.quarantine(downloads=(replace(original[0], **{field: wrong}), original[1]))

    def test_missing_extra_duplicate_or_list_transfers_are_rejected(self):
        """Require an exact, unique cohort of transfers supplied as a tuple."""
        downloads = self.downloads()
        for supplied in (
            (), downloads[:1], downloads + downloads[:1],
            (downloads[0], downloads[0]), list(downloads),
        ):
            with self.subTest(count=len(supplied)):
                with self.assertRaises(self.api.ResourceCohortError):
                    self.quarantine(downloads=supplied)

    def test_partial_rate_limited_and_error_responses_are_rejected(self):
        """Reject partial, unsuccessful, and incorrectly typed HTTP statuses."""
        downloads = self.downloads()
        for code in (206, 301, 304, 401, 404, 429, 500, 503, True, "200"):
            with self.subTest(status=code):
                with self.assertRaises(self.api.ResourceCohortError):
                    self.quarantine(downloads=(replace(downloads[0], status_code=code), downloads[1]))

    def test_incomplete_and_non_boolean_completion_are_rejected(self):
        """Require the completion flag to be the boolean True."""
        downloads = self.downloads()
        for complete in (False, 1, "COMPLETE", None):
            with self.subTest(complete=complete):
                with self.assertRaises(self.api.ResourceCohortError):
                    self.quarantine(downloads=(replace(downloads[0], complete=complete), downloads[1]))

    def test_truncated_empty_and_oversized_content_are_rejected(self):
        """Reject payloads whose lengths differ from the declared size."""
        downloads = self.downloads()
        for payload in (PAYLOADS[0][:-1], b"", PAYLOADS[0] + b"\n"):
            with self.subTest(size=len(payload)):
                with self.assertRaises(self.api.ResourceCohortError):
                    self.quarantine(downloads=(replace(downloads[0], payload=payload), downloads[1]))

    def test_equal_length_modified_content_is_rejected(self):
        """Reject altered payload bytes even when their length is unchanged."""
        downloads = self.downloads()
        changed = PAYLOADS[0].replace(b"001", b"999")
        with self.assertRaisesRegex(self.api.ResourceCohortError, "resource_digest_mismatch"):
            self.quarantine(downloads=(replace(downloads[0], payload=changed), downloads[1]))

    def test_mutable_or_non_byte_content_is_rejected(self):
        """Require immutable byte payloads for resource downloads."""
        downloads = self.downloads()
        for payload in (bytearray(PAYLOADS[0]), memoryview(PAYLOADS[0]), "source"):
            with self.subTest(payload_type=type(payload).__name__):
                with self.assertRaises(self.api.ResourceCohortError):
                    self.quarantine(downloads=(replace(downloads[0], payload=payload), downloads[1]))

    def test_one_invalid_resource_rejects_whole_cohort(self):
        """Reject the entire cohort when one resource fails verification."""
        downloads = self.downloads()
        bad = replace(downloads[1], payload=PAYLOADS[1].replace(b"002", b"999"))
        with self.assertRaises(self.api.ResourceCohortError):
            self.quarantine(downloads=(downloads[0], bad))

    def test_missing_or_unreviewed_rights_cannot_enter_contract(self):
        """Require accepted rights status and rights review evidence."""
        for status in ("UNKNOWN", "DENIED", "ACTIVE", None):
            document = copy.deepcopy(self.document)
            document["resources"][0]["rights_status"] = status
            with self.subTest(status=status):
                with self.assertRaises(self.api.ResourceCohortError):
                    self.manifest(document)
        del self.document["resources"][0]["rights_review"]
        with self.assertRaises(self.api.ResourceCohortError):
            self.manifest()

    def test_mixed_reference_profiles_are_rejected(self):
        """Reject resources that disagree on the cohort reference profile."""
        self.document["resources"][1]["reference_profile_id"] = "different-reference"
        with self.assertRaises(self.api.ResourceCohortError):
            self.manifest()

    def test_duplicate_resource_identities_are_rejected(self):
        """Require resource identities to be unique within the cohort."""
        self.document["resources"][1]["resource_id"] = "fixture-resource-001"
        with self.assertRaises(self.api.ResourceCohortError):
            self.manifest()

    def test_contract_is_closed_at_every_object_level(self):
        """Reject unexpected fields throughout the manifest object tree."""
        for level in ("top", "resource", "registry", "rights", "compatibility"):
            document = copy.deepcopy(self.document)
            target = {
                "top": document,
                "resource": document["resources"][0],
                "registry": document["source_registry"],
                "rights": document["resources"][0]["rights_review"],
                "compatibility": document["compatibility_review"],
            }[level]
            target["unexpected"] = "untrusted"
            with self.subTest(level=level):
                with self.assertRaises(self.api.ResourceCohortError):
                    self.manifest(document)

    def test_unknown_schema_profile_media_and_identity_forms_are_rejected(self):
        """Reject unsupported schema, profile, media, and identity values."""
        for key, value in (
            ("schema_version", "2.0.0"), ("profile_id", "unknown-profile"),
            ("cohort_id", "https://example.invalid/resource"),
            ("cohort_id", "x\n"), ("reference_profile_id", None),
        ):
            document = copy.deepcopy(self.document)
            document[key] = value
            with self.subTest(key=key, value=value):
                with self.assertRaises(self.api.ResourceCohortError):
                    self.manifest(document)
        self.document["resources"][0]["media_type"] = "application/octet-stream"
        with self.assertRaises(self.api.ResourceCohortError):
            self.manifest()

    def test_digest_and_size_are_strict_without_coercion(self):
        """Require correctly formatted digests and positive integer sizes."""
        for key, value in (
            ("sha256", "A" * 64), ("sha256", "a" * 63),
            ("sha256", "a" * 64 + "\n"), ("size_bytes", True),
            ("size_bytes", 0), ("size_bytes", -1), ("size_bytes", 35.0),
            ("size_bytes", "35"),
        ):
            document = copy.deepcopy(self.document)
            document["resources"][0][key] = value
            with self.subTest(key=key, value=value):
                with self.assertRaises(self.api.ResourceCohortError):
                    self.manifest(document)

    def test_count_limit_rejects_whole_inventory(self):
        """Accept 32 resources and reject an inventory exceeding that limit."""
        resources = []
        for index in range(32):
            resource = copy.deepcopy(self.document["resources"][0])
            resource["resource_id"] = f"resource-{index:03d}"
            resources.append(resource)
        self.document["resources"] = resources
        self.assertEqual(len(self.manifest().to_dict()["resources"]), 32)
        extra = copy.deepcopy(resources[0])
        extra["resource_id"] = "resource-032"
        resources.append(extra)
        with self.assertRaises(self.api.ResourceCohortError):
            self.manifest()

    def test_per_resource_and_aggregate_byte_budgets_are_enforced(self):
        """Enforce both individual resource and total cohort byte limits."""
        document = copy.deepcopy(self.document)
        document["resources"][0]["size_bytes"] = 5 * 1024 * 1024 + 1
        with self.assertRaises(self.api.ResourceCohortError):
            self.manifest(document)
        document["resources"] = []
        for index in range(4):
            item = copy.deepcopy(self.document["resources"][0])
            item["resource_id"] = f"large-{index}"
            item["size_bytes"] = 5 * 1024 * 1024
            document["resources"].append(item)
        with self.assertRaises(self.api.ResourceCohortError):
            self.manifest(document)
        document["resources"].pop()
        self.assertEqual(len(self.manifest(document).to_dict()["resources"]), 3)

    def test_transfer_payload_budget_is_checked_before_receipt(self):
        """Reject oversized downloaded payloads before issuing a receipt."""
        downloads = self.downloads()
        with self.assertRaises(self.api.ResourceCohortError):
            self.quarantine(downloads=(
                replace(downloads[0], payload=b"x" * (5 * 1024 * 1024 + 1)),
                downloads[1],
            ))

    def test_retrieval_timestamp_requires_real_utc_date(self):
        """Require valid retrieval timestamps with explicit UTC notation."""
        downloads = self.downloads()
        for timestamp in (
            "2026-02-30T21:00:00Z", "2026-10-22", "2026-10-22T21:00:00",
            "2026-10-22T21:00:00+03:00", None,
        ):
            with self.subTest(timestamp=timestamp):
                with self.assertRaises(self.api.ResourceCohortError):
                    self.quarantine(downloads=(
                        replace(downloads[0], retrieved_at=timestamp), downloads[1],
                    ))

    def test_source_rights_and_compatibility_evidence_have_distinct_roles(self):
        """Reject source registry evidence substituted for other reviews."""
        for role in ("rights", "compatibility"):
            document = copy.deepcopy(self.document)
            if role == "rights":
                document["resources"][0]["rights_review"] = copy.deepcopy(document["source_registry"])
            else:
                document["compatibility_review"] = copy.deepcopy(document["source_registry"])
            with self.subTest(role=role):
                with self.assertRaises(self.api.ResourceCohortError):
                    self.manifest(document)

    def test_receipt_and_errors_do_not_expose_payload(self):
        """Keep payload content out of receipts and error messages."""
        receipt = self.quarantine()
        serialized = json.dumps(receipt.to_dict())
        self.assertNotIn('"records"', serialized)
        self.assertNotIn("fixture-001", repr(receipt))
        downloads = self.downloads()
        sentinel = b"private-content-sentinel"
        with self.assertRaises(self.api.ResourceCohortError) as caught:
            self.quarantine(downloads=(replace(downloads[0], payload=sentinel), downloads[1]))
        self.assertNotIn(sentinel.decode(), str(caught.exception))
        self.assertNotIn("fixture-resource-001", str(caught.exception))

    def test_new_cohort_does_not_mutate_prior_receipt(self):
        """Preserve an earlier receipt when a new cohort is quarantined."""
        first = self.quarantine()
        before = first.to_dict()
        self.document["cohort_id"] = "synthetic-cohort-v2"
        second = self.quarantine()
        self.assertNotEqual(before["manifest_sha256"], second.to_dict()["manifest_sha256"])
        self.assertEqual(first.to_dict(), before)

    def test_versioned_json_schema_accepts_fixture_and_rejects_unknowns(self):
        """Validate the fixture and reject invalid values with the schema."""
        from jsonschema import Draft202012Validator
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        self.assertEqual(list(validator.iter_errors(self.manifest().to_dict())), [])
        for field, value in (("rights_status", "UNKNOWN"), ("size_bytes", True), ("media_type", "unknown")):
            document = copy.deepcopy(self.document)
            document["resources"][0][field] = value
            with self.subTest(field=field):
                self.assertTrue(list(validator.iter_errors(document)))

    def test_mutable_aliases_are_not_pinned_revisions(self):
        """Reject mutable or unavailable aliases as pinned source revisions."""
        for alias in ("latest", "LATEST", "current", "UNKNOWN", "NOT_AVAILABLE"):
            document = copy.deepcopy(self.document)
            document["resources"][0]["source_revision"] = alias
            with self.subTest(alias=alias):
                with self.assertRaises(self.api.ResourceCohortError):
                    self.manifest(document)

    def test_same_evidence_id_cannot_bind_conflicting_digests(self):
        """Require a shared evidence identity to bind a consistent digest."""
        self.document["resources"][1]["rights_review"]["sha256"] = "f" * 64
        with self.assertRaises(self.api.ResourceCohortError):
            self.manifest()

    def test_schema_rejects_mutable_aliases_and_control_characters(self):
        """Reject mutable aliases and control characters through the schema."""
        from jsonschema import Draft202012Validator
        validator = Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))
        for value in ("latest", "LaTeSt", "CURRENT", "UNKNOWN", "NOT_AVAILABLE", "x\n"):
            document = copy.deepcopy(self.document)
            document["resources"][0]["source_revision"] = value
            with self.subTest(value=value):
                self.assertTrue(list(validator.iter_errors(document)))

    def test_typed_contract_required_at_receipt_boundary(self):
        """Reject raw manifest dictionaries at the quarantine boundary."""
        with self.assertRaises(self.api.ResourceCohortError):
            self.quarantine(manifest=self.document)


if __name__ == "__main__":
    unittest.main()
