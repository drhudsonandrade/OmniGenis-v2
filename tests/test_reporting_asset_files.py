"""Synthetic descriptor-relative asset loading; no real brand resources used."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator
from reporting.asset_registry import AssetDeclaration, AssetManifest, BoundAssetInventory
from reporting.bindings import ReportArtifactBinding
from tests.test_reporting_png_inspection import png
from tests.test_reporting_svg_inspection import svg

ROOT = Path(__file__).resolve().parents[1]


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class AssetFileResolutionTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("reporting.asset_files"),
                             "descriptor-bound asset resolver is missing")
        self.m = importlib.import_module("reporting.asset_files")
        self.temp = tempfile.TemporaryDirectory(prefix="asset-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.logo_bytes, self.png_bytes = svg(), png()
        self.expected = self.manifest()
        self.resolved = self.manifest()
        for raw in (self.logo_bytes, self.png_bytes):
            self.store(raw)
        self.root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.root_fd)
        st = os.fstat(self.root_fd)
        self.directory = self.m.AssetDirectoryIdentity(st.st_dev, st.st_ino, st.st_uid)

    def store(self, raw):
        dest = self.root / digest(raw)
        if dest.exists():
            self.assertEqual(dest.read_bytes(), raw)
            return dest
        dest.write_bytes(raw)
        dest.chmod(0o400)
        return dest

    def manifest(self, logo=None, image=None):
        logo = self.logo_bytes if logo is None else logo
        image = self.png_bytes if image is None else image
        items = []
        for identity, role, media, raw, size in (
            ("SYNTHETIC-LOGO", "brand-logo", "image/svg+xml", logo, 16),
            ("SYNTHETIC-DNA", "dna-illustration", "image/png", image, 2),
        ):
            h = digest(raw)
            items.append(AssetDeclaration(identity, role, media, h, len(raw), size, size,
                ReportArtifactBinding("SOURCE-" + identity, h),
                ReportArtifactBinding("RIGHTS-" + identity, "a" * 64)))
        return AssetManifest(tuple(items))

    def resolve(self, **changes):
        args = dict(directory_fd=self.root_fd, expected_directory=self.directory,
                    expected_manifest=self.expected, resolved_manifest=self.resolved,
                    expected_manifest_sha256=self.expected.manifest_sha256)
        args.update(changes)
        return self.m.resolve_staged_asset_files(**args)

    def reject(self, **changes):
        with self.assertRaises(self.m.AssetFileResolutionError):
            self.resolve(**changes)

    def test_both_media_reuse_existing_inventory_and_schema(self):
        result = self.resolve()
        self.assertIs(type(result), BoundAssetInventory)
        data = result.to_dict()
        self.assertEqual(data["asset_count"], 2)
        self.assertEqual([x["asset_id"] for x in data["assets"]],
                         ["SYNTHETIC-LOGO", "SYNTHETIC-DNA"])
        schema = json.loads((ROOT / "schemas/report-staged-asset-inventory.v1.schema.json").read_text())
        self.assertFalse(list(Draft202012Validator(schema).iter_errors(data)))

    def test_no_paths_descriptors_pixels_or_release_authority_in_receipt(self):
        result = self.resolve().to_dict()
        self.assertNotIn(str(self.root), repr(result))
        self.assertNotIn("<svg", repr(result))
        for key in ("source_bytes_retained", "rights_verified", "media_sanitized",
                    "renderer_activated", "font_profile_qualified", "links_activated"):
            self.assertIs(result[key], False, key)
        self.assertEqual(result["release_authorization"], "NOT_ESTABLISHED")
        self.assertEqual(result["status"], "PINNED_UNQUALIFIED")

    def test_directory_descriptor_is_borrowed_not_closed(self):
        before = os.fstat(self.root_fd)
        self.resolve()
        after = os.fstat(self.root_fd)
        self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))

    def test_directory_identity_mismatch_is_blocked(self):
        for field in ("device_id", "inode_id", "owner_uid"):
            with self.subTest(field=field):
                value = replace(self.directory, **{field: getattr(self.directory, field) + 1})
                self.reject(expected_directory=value)

    def test_directory_identity_requires_exact_nonnegative_integers(self):
        for values in ((True, 1, 0), (1, False, 0), (1, 1, -1), (1, 0, 0), (1, 1, "0")):
            with self.subTest(values=values), self.assertRaises(self.m.AssetFileResolutionError):
                self.m.AssetDirectoryIdentity(*values)
        with self.assertRaises(FrozenInstanceError):
            self.directory.inode_id = 1

    def test_directory_fd_rejects_strings_paths_booleans_and_huge_numbers(self):
        for fd in (True, -1, 2**90, str(self.root), self.root, None):
            with self.subTest(kind=type(fd)):
                self.reject(directory_fd=fd)

    def test_closed_fd_is_rejected_without_path_disclosure(self):
        closed = os.dup(self.root_fd)
        os.close(closed)
        self.reject(directory_fd=closed)

    def test_regular_file_cannot_be_used_as_directory(self):
        fd = os.open(self.root / self.expected.assets[0].sha256, os.O_RDONLY)
        try:
            self.reject(directory_fd=fd)
        finally:
            os.close(fd)

    def test_unpinned_or_foreign_manifest_blocks_before_any_file_open(self):
        with patch.object(self.m.os, "open", side_effect=AssertionError("must not open")):
            self.reject(expected_manifest_sha256="0" * 64)
            self.reject(expected_manifest_sha256=None)
            altered = AssetManifest((replace(self.expected.assets[0], asset_id="OTHER"),))
            self.reject(resolved_manifest=altered)
            self.reject(expected_manifest={})

    def test_mutated_digest_cannot_become_a_path(self):
        altered = self.manifest()
        object.__setattr__(altered.assets[0], "sha256", "../../outside")
        with patch.object(self.m.os, "open", side_effect=AssertionError("must not open")):
            self.reject(expected_manifest=altered, resolved_manifest=altered)

    def test_unknown_keyword_cannot_supply_filename_or_url(self):
        for key in ("filename", "asset_path", "url"):
            with self.subTest(key=key), self.assertRaises(TypeError):
                self.resolve(**{key: "../../outside"})

    def test_only_digest_basenames_are_opened_relative_to_held_root(self):
        calls = []
        original = os.open
        def observed(path, flags, *args, **kwargs):
            calls.append((path, flags, kwargs.get("dir_fd")))
            return original(path, flags, *args, **kwargs)
        with patch.object(self.m.os, "open", side_effect=observed):
            self.resolve()
        self.assertEqual([x[0] for x in calls], [a.sha256 for a in self.expected.assets])
        for _, flags, directory_fd in calls:
            self.assertIsInstance(directory_fd, int)
            self.assertTrue(flags & os.O_NOFOLLOW)
            self.assertTrue(flags & os.O_NONBLOCK)
            self.assertTrue(flags & os.O_CLOEXEC)

    def test_symlink_to_valid_external_asset_is_rejected(self):
        key = self.expected.assets[0].sha256
        with tempfile.TemporaryDirectory(prefix="outside-asset-fixture-") as outside:
            target = Path(outside) / "source"
            target.write_bytes(self.logo_bytes)
            target.chmod(0o400)
            (self.root / key).unlink()
            (self.root / key).symlink_to(target)
            self.reject()

    def test_hardlinked_asset_is_rejected(self):
        key = self.expected.assets[0].sha256
        os.link(self.root / key, self.root / "other-link")
        self.reject()

    def test_directory_in_place_of_asset_is_rejected(self):
        path = self.root / self.expected.assets[0].sha256
        path.unlink()
        path.mkdir()
        self.reject()

    def test_fifo_is_rejected_without_waiting_for_a_writer(self):
        path = self.root / self.expected.assets[0].sha256
        path.unlink()
        os.mkfifo(path, 0o400)
        self.reject()

    def test_missing_asset_never_returns_partial_inventory(self):
        (self.root / self.expected.assets[1].sha256).unlink()
        self.reject()

    def test_group_or_other_writable_root_is_rejected(self):
        for mode in (0o720, 0o702, 0o777):
            try:
                self.root.chmod(mode)
                self.reject()
            finally:
                self.root.chmod(0o700)

    def test_writable_executable_or_unreadable_asset_is_rejected(self):
        path = self.root / self.expected.assets[0].sha256
        for mode in (0o600, 0o440 | 0o020, 0o444 | 0o002, 0o500, 0o000):
            with self.subTest(mode=mode):
                path.chmod(mode)
                self.reject()
        path.chmod(0o400)

    def test_same_size_foreign_content_rejected(self):
        path = self.root / self.expected.assets[0].sha256
        path.chmod(0o600)
        path.write_bytes(b"X" + self.logo_bytes[1:])
        path.chmod(0o400)
        self.reject()

    def test_short_or_long_content_is_rejected(self):
        path = self.root / self.expected.assets[0].sha256
        for data in (self.logo_bytes[:-1], self.logo_bytes + b"X"):
            path.chmod(0o600)
            path.write_bytes(data)
            path.chmod(0o400)
            self.reject()

    def test_media_inspectors_reject_invalid_but_correctly_hashed_data(self):
        bad_svg = svg('<script>untrusted</script>')
        bad_png = b"not-a-png"
        for logo, image in ((bad_svg, self.png_bytes), (self.logo_bytes, bad_png)):
            with self.subTest(logo=logo == bad_svg):
                self.store(logo)
                self.store(image)
                manifest = self.manifest(logo, image)
                self.reject(expected_manifest=manifest, resolved_manifest=manifest,
                            expected_manifest_sha256=manifest.manifest_sha256)

    def test_declared_geometry_reaches_existing_inspection_boundary(self):
        altered = AssetManifest((replace(self.expected.assets[0], declared_width_px=3),
                                 self.expected.assets[1]))
        self.reject(expected_manifest=altered, resolved_manifest=altered,
                    expected_manifest_sha256=altered.manifest_sha256)

    def test_full_svg_operand_validation_is_reused(self):
        bad = svg('<path d="M0 0 L M0 0" fill="#112233"/>')
        self.store(bad)
        manifest = self.manifest(bad, self.png_bytes)
        self.reject(expected_manifest=manifest, resolved_manifest=manifest,
                    expected_manifest_sha256=manifest.manifest_sha256)

    def test_budget_validation_precedes_disk_access(self):
        with patch.object(self.m, "MAX_TOTAL_ASSET_BYTES", 1):
            with patch.object(self.m.os, "open", side_effect=AssertionError("must not open")):
                self.reject()

    def test_unsupported_descriptor_platform_fails_closed(self):
        with patch.object(self.m, "_DESCRIPTOR_IO_SUPPORTED", False):
            self.reject()

    def test_observed_timestamp_mutation_during_read_is_rejected(self):
        path = self.root / self.expected.assets[0].sha256
        original = os.read
        changed = False
        def raced(fd, count):
            nonlocal changed
            chunk = original(fd, count)
            if chunk and not changed:
                changed = True
                stamp = os.fstat(fd)
                path.chmod(0o600)
                path.write_bytes(self.logo_bytes)
                path.chmod(0o400)
                # The host clock can assign identical timestamps to rapid writes.
                # Make the metadata change deterministic without sleeping.
                os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns + 1_000_000_000))
            return chunk
        with patch.object(self.m.os, "read", side_effect=raced):
            self.reject()
        self.assertTrue(changed)

    def test_directory_entry_swap_during_read_is_rejected(self):
        path = self.root / self.expected.assets[0].sha256
        original = os.read
        changed = False
        def raced(fd, count):
            nonlocal changed
            chunk = original(fd, count)
            if chunk and not changed:
                changed = True
                path.rename(self.root / "previous")
                self.store(self.logo_bytes)
            return chunk
        with patch.object(self.m.os, "read", side_effect=raced):
            self.reject()

    def test_io_error_is_content_free_and_closes_private_descriptors(self):
        before = len(os.listdir("/proc/self/fd"))
        with patch.object(self.m.os, "read", side_effect=OSError("PRIVATE_PATH_SENTINEL")):
            with self.assertRaises(self.m.AssetFileResolutionError) as cm:
                self.resolve()
        self.assertNotIn("PRIVATE_PATH_SENTINEL", str(cm.exception))
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)
        os.fstat(self.root_fd)

    def test_success_and_failure_cycles_do_not_leak_descriptors(self):
        before = len(os.listdir("/proc/self/fd"))
        for _ in range(8):
            self.resolve()
        path = self.root / self.expected.assets[1].sha256
        path.unlink()
        for _ in range(8):
            self.reject()
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_no_network_or_subprocess_or_general_path_reader(self):
        with patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process forbidden")), \
             patch.object(Path, "read_bytes", side_effect=AssertionError("path reader forbidden")):
            self.assertEqual(self.resolve().to_dict()["asset_count"], 2)

    def test_sources_and_manifests_are_not_mutated(self):
        original = {p.name: digest(p.read_bytes()) for p in self.root.iterdir()}
        before = self.expected.manifest_sha256
        self.resolve()
        self.assertEqual(original, {p.name: digest(p.read_bytes()) for p in self.root.iterdir()})
        self.assertEqual(before, self.expected.manifest_sha256)

    def test_legacy_pdf_adapter_still_rejects_inventory_receipt(self):
        from reporting.adapters import build_html_css_and_pdf_adapter
        result = build_html_css_and_pdf_adapter(presentation_ir=self.resolve().to_dict())
        self.assertFalse(result.passed)
        self.assertIsNone(result.pdf_bytes)


if __name__ == "__main__":
    unittest.main()
