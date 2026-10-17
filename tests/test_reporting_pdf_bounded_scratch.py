"""Synthetic negative tests for the opt-in, bounded PDF scratch mount.

These unit tests NEVER claim native systemd qualification. The final resource
boundary must be demonstrated on the owner host in an isolated one-shot service.
"""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from reporting import _pdf_bounded_scratch as scratch

ROOT = Path(__file__).resolve().parents[1]
FLAGS = frozenset({"nosuid", "nodev", "noexec"})
SWITCH = "OMNIGENIS_PDF_BOUNDED_SCRATCH_V1"


class PdfBoundedScratchTests(unittest.TestCase):
    """Fail closed whenever the optional mount identity cannot be proven."""

    def positive(self, fstype="tmpfs", flags=FLAGS, blocks=32768, inodes=4096):
        stack = __import__("contextlib").ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.dict(os.environ,
            {SWITCH:"1", "TMPDIR":"/tmp"}, clear=False))
        stack.enter_context(patch.object(scratch, "_PARENT", Path("/tmp")))
        stack.enter_context(patch.object(scratch, "_fd_mount_id", return_value=12))
        stack.enter_context(patch.object(scratch, "_mount_record",
            return_value=(fstype, frozenset(flags))))
        stack.enter_context(patch.object(scratch.os, "fstatvfs",
            return_value=SimpleNamespace(f_blocks=blocks,
                f_frsize=4096, f_files=inodes)))
        return stack

    def test_no_opt_in_preserves_exact_legacy_root_and_environment(self):
        with patch.dict(os.environ,{},clear=True):
            current=tempfile.tempdir
            self.assertIs(scratch.bounded_scratch_requested(),False)
            self.assertEqual(scratch.bounded_scratch_parent(),Path("/tmp"))
            self.assertFalse(scratch.activate_bounded_process_temporaries())
            self.assertEqual(tempfile.tempdir,current)
            self.assertEqual(scratch.raster_child_environment("/tmp/private"),
                {"PATH":os.defpath,"LANG":"C.UTF-8","TMPDIR":"/tmp/private"})

    def test_default_raster_protocol_files_respect_configured_tmpdir(self):
        """Without opt-in, anonymous protocol files retain TMPDIR selection."""
        from reporting import pdf_raster_windows as raster

        original_file=tempfile.TemporaryFile
        opened=[]
        identity={"pdf_sha256":"a"*64, "ir_sha256":"b"*64,
                  "plan_sha256":"c"*64, "page_count":1,
                  "window_index":0, "first_page":1, "last_page":1}

        def track_file(*args, **kwargs):
            """Observe real anonymous file placement before descriptor cleanup."""
            handle=original_file(*args, **kwargs)
            link=os.readlink(f"/proc/self/fd/{handle.fileno()}")
            opened.append((kwargs, link))
            return handle

        with tempfile.TemporaryDirectory(prefix="omnigenis-tmpdir-test-") as chosen:
            with patch.dict(os.environ, {"TMPDIR":chosen}, clear=True), \
                 patch.object(tempfile, "tempdir", None), \
                 patch.object(raster.tempfile, "TemporaryFile", side_effect=track_file), \
                 patch.object(raster, "_start", side_effect=RuntimeError("protocol_ready")):
                with self.assertRaisesRegex(RuntimeError, "protocol_ready"):
                    raster._run_worker(b"%PDF-1.7\n", identity)
            self.assertEqual(len(opened), 2)
            for options, link in opened:
                self.assertNotIn("dir", options)
                self.assertTrue(link.startswith(chosen + "/"), link)

    def test_optin_raster_protocol_files_use_verified_parent(self):
        """Opt-in protocol descriptors remain on the admitted bounded mount."""
        from reporting import pdf_raster_windows as raster

        self.positive()
        original_file=tempfile.TemporaryFile
        opened=[]
        identity={"pdf_sha256":"a"*64, "ir_sha256":"b"*64,
                  "plan_sha256":"c"*64, "page_count":1,
                  "window_index":0, "first_page":1, "last_page":1}

        def track_file(*args, **kwargs):
            """Observe the explicit destination of both anonymous descriptors."""
            opened.append(dict(kwargs))
            return original_file(*args, **kwargs)

        with patch.object(raster.tempfile, "TemporaryFile", side_effect=track_file), \
             patch.object(raster, "_start", side_effect=RuntimeError("protocol_ready")):
            with self.assertRaisesRegex(RuntimeError, "protocol_ready"):
                raster._run_worker(b"%PDF-1.7\n", identity)
        self.assertEqual(opened, [{"dir":Path("/tmp")}, {"dir":Path("/tmp")}])

    def test_mountinfo_rejects_duplicate_or_absent_destination(self):
        one=("12 1 0:12 / /run/omnigenis-ed04-scratch rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n")
        with patch.object(Path,"read_text",return_value=one):
            kind,flags=scratch._mount_record(scratch._PARENT, os.makedev(0,12), 12)
        self.assertEqual(kind,"tmpfs")
        self.assertEqual(flags,FLAGS|{"rw"})
        for data in ("",one+one,"12 1 0:12 / /run/another rw - tmpfs tmpfs rw\n"):
            with self.subTest(data=data[:30]),patch.object(Path,"read_text",
                                                            return_value=data):
                with self.assertRaises(scratch.PdfBoundedScratchError):
                    scratch._mount_record(scratch._PARENT, os.makedev(0,12), 12)

    def test_mountinfo_rejects_bind_subtree_or_foreign_source(self):
        invalid = (
            "77 61 0:99 /foreign-subtree /run/omnigenis-ed04-scratch "
            "rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n",
            "77 61 0:99 / /run/omnigenis-ed04-scratch "
            "rw,nosuid,nodev,noexec - tmpfs foreign-tmpfs rw\n",
        )
        for line in invalid:
            with self.subTest(line=line), patch.object(
                Path, "read_text", return_value=line
            ):
                with self.assertRaises(scratch.PdfBoundedScratchError):
                    scratch._mount_record(scratch._PARENT, os.makedev(0,99), 77)

    def test_mountinfo_must_match_open_descriptor_identity(self):
        one=("12 1 0:12 / /run/omnigenis-ed04-scratch "
             "rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n")
        for device,mount_id in ((os.makedev(0,13),12),(os.makedev(0,12),13)):
            with self.subTest(device=device,mount_id=mount_id), \
                 patch.object(Path,"read_text",return_value=one):
                with self.assertRaises(scratch.PdfBoundedScratchError):
                    scratch._mount_record(scratch._PARENT,device,mount_id)

    def test_fdinfo_requires_one_canonical_positive_mount_id(self):
        with patch.object(Path,"read_text",return_value="pos:\t0\nmnt_id:\t77\n"):
            self.assertEqual(scratch._fd_mount_id(9),77)
        invalid=("", "mnt_id:\t0\n", "mnt_id:\t-1\n",
                 "mnt_id:\t1x\n", "mnt_id:\t2\nmnt_id:\t2\n")
        for data in invalid:
            with self.subTest(data=data),patch.object(Path,"read_text",return_value=data):
                with self.assertRaises(scratch.PdfBoundedScratchError):
                    scratch._fd_mount_id(9)

    def test_reject_every_foreign_switch_value(self):
        for value in ("", "0","yes","true","2","/tmp","1 "):
            with self.subTest(value=value),patch.dict(os.environ,{SWITCH:value}):
                with self.assertRaises(scratch.PdfBoundedScratchError):
                    scratch.bounded_scratch_requested()

    def test_pinned_mount_identity_permits_no_custom_path(self):
        self.assertEqual(str(scratch._PARENT),"/run/omnigenis-ed04-scratch")
        self.assertEqual(scratch._MAX_BYTES,128*1024*1024)
        self.assertEqual(scratch._MAX_INODES,4096)
        self.assertEqual(scratch._REQUIRED_FLAGS,FLAGS)
        self.assertFalse(hasattr(scratch,"set_scratch_root"))

    def test_positive_synthetic_namespace_can_admit_fixed_root(self):
        self.positive()
        self.assertTrue(scratch.bounded_scratch_requested())
        self.assertEqual(scratch.bounded_scratch_parent(),Path("/tmp"))

    def test_capacity_is_checked_on_the_still_open_parent_descriptor(self):
        self.positive()
        observed=[]

        def inspect(fd):
            observed.append(os.fstat(fd).st_ino)
            return SimpleNamespace(f_blocks=32768,f_frsize=4096,f_files=4096)

        with patch.object(scratch.os,"fstatvfs",side_effect=inspect):
            self.assertEqual(scratch.bounded_scratch_parent(),Path("/tmp"))
        self.assertEqual(len(observed),1)

    def test_only_complete_mount_flags_accepted(self):
        for removed in FLAGS:
            with self.subTest(removed=removed):
                self.positive(flags=FLAGS-{removed})
                with self.assertRaises(scratch.PdfBoundedScratchError):
                    scratch.bounded_scratch_parent()

    def test_wrong_filesystem_is_rejected(self):
        for fs in ("overlay","ext4","ramfs",""):
            with self.subTest(fstype=fs):
                self.positive(fstype=fs)
                with self.assertRaises(scratch.PdfBoundedScratchError):
                    scratch.bounded_scratch_parent()

    def test_resource_size_or_inode_overbudget_rejected(self):
        for blocks,inodes in ((32769,4096),(32768,4097),(0,4096),(32768,0)):
            with self.subTest(blocks=blocks,inodes=inodes):
                self.positive(blocks=blocks,inodes=inodes)
                with self.assertRaises(scratch.PdfBoundedScratchError):
                    scratch.bounded_scratch_parent()

    def test_missing_mount_identity_is_rejected_without_fallback(self):
        self.positive()
        with patch.object(scratch,"_mount_record",
            side_effect=scratch.PdfBoundedScratchError("missing")):
            with self.assertRaises(scratch.PdfBoundedScratchError):
                scratch.bounded_scratch_parent()

    def test_incorrect_requested_mount_environment_blocks_tempdir(self):
        self.positive()
        with patch.dict(os.environ,{"TMPDIR":"/tmp/other"}):
            with self.assertRaisesRegex(scratch.PdfBoundedScratchError,
                "pdf_bounded_scratch_tmpdir_mismatch"):
                scratch.activate_bounded_process_temporaries()

    def test_opt_in_tempdir_binding_is_scoped_to_a_dedicated_child(self):
        self.positive()
        with patch.object(tempfile,"tempdir",None):
            self.assertTrue(scratch.activate_bounded_process_temporaries())
            self.assertEqual(tempfile.tempdir,"/tmp")
            self.assertEqual(tempfile.gettempdir(),"/tmp")

    def test_child_propagates_only_fixed_opt_in_marker(self):
        self.positive()
        with tempfile.TemporaryDirectory(
            prefix="omnigenis-pdf-visual-supervisor-",dir="/tmp") as directory:
            result=scratch.raster_child_environment(directory)
            self.assertEqual(set(result),{"PATH","LANG","TMPDIR",SWITCH})
            self.assertEqual(result[SWITCH],"1")
            self.assertEqual(result["TMPDIR"],directory)

    def test_optin_rejects_arbitrary_child_directory(self):
        self.positive()
        for path in ("/tmp/private","/var/tmp/foreign","/tmp"):
            with self.subTest(path=path),self.assertRaises(scratch.PdfBoundedScratchError):
                scratch.raster_child_environment(path)

    def test_optin_rejects_child_or_protocol_descriptor_on_another_mount(self):
        self.positive()
        with tempfile.TemporaryDirectory(
            prefix="omnigenis-pdf-visual-supervisor-",dir="/tmp"
        ) as directory:
            with patch.object(scratch,"_fd_mount_id",side_effect=(12,13)):
                with self.assertRaises(scratch.PdfBoundedScratchError):
                    scratch.raster_child_environment(directory)
            child_fd=os.open(directory,os.O_PATH|os.O_DIRECTORY)
            protocol_fd=os.open(__file__,os.O_RDONLY)
            try:
                with patch.object(scratch,"_fd_mount_id",side_effect=(12,13)):
                    with self.assertRaises(scratch.PdfBoundedScratchError):
                        scratch._require_same_bounded_mount(child_fd,protocol_fd)
            finally:
                os.close(protocol_fd)
                os.close(child_fd)

    def test_default_raster_visual_supervisors_have_no_literal_tempdir(self):
        for name in ("reporting/pdf_visual.py","reporting/pdf_raster_windows.py"):
            text=(ROOT/name).read_text()
            self.assertNotIn('dir="/tmp"',text)
            self.assertIn("bounded_scratch_parent()",text)

    def test_original_visual_child_keeps_existing_default_profile(self):
        from reporting import _pdf_visual_worker as worker
        self.assertEqual(worker.SCRATCH_PARENT,Path("/tmp"))
        self.assertEqual(worker.SCRATCH_PREFIX,
                         "omnigenis-pdf-visual-supervisor-")

    def test_optin_workers_cannot_bypass_same_mount_guards(self):
        from reporting import _pdf_visual_worker as worker
        from reporting import pdf_raster_windows as raster

        self.positive()
        with tempfile.TemporaryDirectory(
            prefix="omnigenis-pdf-visual-supervisor-",dir="/tmp"
        ) as directory:
            error=scratch.PdfBoundedScratchError("child_guard")
            with patch.dict(os.environ,{"TMPDIR":directory}), \
                 patch.object(scratch,"_open_verified_bounded_child",
                              side_effect=error):
                with self.assertRaisesRegex(scratch.PdfBoundedScratchError,
                                            "child_guard"):
                    worker._open_trusted_scratch()
        identity={"pdf_sha256":"a"*64,"ir_sha256":"b"*64,
                  "plan_sha256":"c"*64,"page_count":1,"window_index":0,
                  "first_page":1,"last_page":1}
        with patch.object(raster,"_require_same_bounded_mount",
                          side_effect=RuntimeError("mount_guard")):
            with self.assertRaisesRegex(RuntimeError,"mount_guard"):
                raster._run_worker(b"%PDF-1.7\n",identity)

    def test_fixed_worker_activation_is_before_original_inspection(self):
        text=(ROOT/"reporting/_pdf_fixed_inspection_worker.py").read_text()
        self.assertIn("activate_bounded_process_temporaries()",text)
        self.assertLess(text.index("activate_bounded_process_temporaries()"),
            text.index("original=sealed.execute_sealed_pdf_inspection_job("))

    def test_manifest_is_optin_and_pins_exact_sources(self):
        import hashlib
        manifest=json.loads((ROOT/"reporting/pdf-bounded-scratch.v1.json").read_text())
        self.assertEqual(manifest["default_pipeline_activated"],False)
        self.assertEqual(manifest["aggregate_resources_qualified"],False)
        self.assertEqual(manifest["release_authorized"],False)
        self.assertEqual(manifest["qualified_scratch_parent"],str(scratch._PARENT))
        self.assertEqual(manifest["max_scratch_bytes"],scratch._MAX_BYTES)
        self.assertEqual(manifest["max_inodes"],scratch._MAX_INODES)
        self.assertEqual(set(manifest["source_sha256"]),{
            "reporting/_pdf_bounded_scratch.py",
            "reporting/_pdf_visual_worker.py",
            "reporting/_pdf_fixed_inspection_worker.py",
            "reporting/pdf_visual.py",
            "reporting/pdf_raster_windows.py",
        })
        for name,digest in manifest["source_sha256"].items():
            with self.subTest(path=name):
                self.assertEqual(hashlib.sha256((ROOT/name).read_bytes()).hexdigest(),digest)

    def test_transitive_manifests_pin_changed_reused_sources(self):
        bounded=json.loads(
            (ROOT/"reporting/pdf-bounded-scratch.v1.json").read_text()
        )["source_sha256"]
        inspection=json.loads(
            (ROOT/"reporting/pdf-inspection-job.v1.json").read_text()
        )["reused_source_sha256"]
        raster=json.loads(
            (ROOT/"reporting/pdf-raster-window-engine.v1.json").read_text()
        )["reused_source_sha256"]
        self.assertEqual(inspection["reporting/pdf_raster_windows.py"],
                         bounded["reporting/pdf_raster_windows.py"])
        self.assertEqual(raster["reporting/_pdf_visual_worker.py"],
                         bounded["reporting/_pdf_visual_worker.py"])

    def test_scratch_helper_never_uses_shell_or_external_process(self):
        text=(ROOT/"reporting/_pdf_bounded_scratch.py").read_text()
        ast.parse(text)
        for forbidden in ("subprocess","Popen(","os.system(","eval(","exec(",
                          "http://","https://","pickle"):
            self.assertNotIn(forbidden,text)


if __name__=="__main__":
    unittest.main()
