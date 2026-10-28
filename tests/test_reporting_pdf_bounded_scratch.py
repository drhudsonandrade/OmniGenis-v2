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
        """Install cleanup-managed synthetic mount observations with configurable filesystem, flags, capacity, and inode limits."""
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
        """Preserve the legacy scratch root, temporary directory state, and child environment when opt-in is absent."""
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
        """Accept one matching tmpfs mount record and reject duplicate, missing, or foreign destination records."""
        one=("12 1 0:12 / /run/omnigenis-pdf-bounded-scratch rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n")
        with patch.object(scratch,"_read_kernel_text",return_value=one):
            kind,flags=scratch._mount_record(scratch._PARENT, os.makedev(0,12), 12)
        self.assertEqual(kind,"tmpfs")
        self.assertEqual(flags,FLAGS|{"rw"})
        for data in ("",one+one,"12 1 0:12 / /run/another rw - tmpfs tmpfs rw\n"):
            with self.subTest(data=data[:30]),patch.object(scratch,"_read_kernel_text",
                                                            return_value=data):
                with self.assertRaises(scratch.PdfBoundedScratchError):
                    scratch._mount_record(scratch._PARENT, os.makedev(0,12), 12)

    def test_mountinfo_tolerates_non_ascii_bytes_only_in_unrelated_records(self):
        """Parse the valid target mount despite undecodable bytes in an unrelated mount record."""
        target=(b"12 1 0:12 / /run/omnigenis-pdf-bounded-scratch "
                b"rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n")
        unrelated=(b"11 1 0:11 / /run/foreign-\xff rw - tmpfs tmpfs rw\n")

        def decode_mountinfo(*args, encoding=None, errors=None, **kwargs):
            """Decode synthetic mount records using the encoding and error policy requested by the mount parser."""
            return (unrelated+target).decode(encoding or "utf-8", errors or "strict")

        with patch.object(scratch,"_read_kernel_text",side_effect=decode_mountinfo):
            kind,flags=scratch._mount_record(scratch._PARENT,
                                             os.makedev(0,12),12)
        self.assertEqual(kind,"tmpfs")
        self.assertEqual(flags,FLAGS|{"rw"})

    def test_mountinfo_rejects_bind_subtree_or_foreign_source(self):
        """Reject target mount records rooted in a foreign subtree or naming an unexpected tmpfs source."""
        invalid = (
            "77 61 0:99 /foreign-subtree /run/omnigenis-pdf-bounded-scratch "
            "rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n",
            "77 61 0:99 / /run/omnigenis-pdf-bounded-scratch "
            "rw,nosuid,nodev,noexec - tmpfs foreign-tmpfs rw\n",
        )
        for line in invalid:
            with self.subTest(line=line), patch.object(
                scratch, "_read_kernel_text", return_value=line
            ):
                with self.assertRaises(scratch.PdfBoundedScratchError):
                    scratch._mount_record(scratch._PARENT, os.makedev(0,99), 77)

    def test_mountinfo_must_match_open_descriptor_identity(self):
        """Reject a mount record whose device number or mount ID differs from the opened descriptor."""
        one=("12 1 0:12 / /run/omnigenis-pdf-bounded-scratch "
             "rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n")
        for device,mount_id in ((os.makedev(0,13),12),(os.makedev(0,12),13)):
            with self.subTest(device=device,mount_id=mount_id), \
                 patch.object(scratch,"_read_kernel_text",return_value=one):
                with self.assertRaises(scratch.PdfBoundedScratchError):
                    scratch._mount_record(scratch._PARENT,device,mount_id)

    def test_statx_requires_complete_identity_and_positive_mount_id(self):
        """Reject unavailable statx fields or contradictory descriptor identity."""
        import ctypes
        import struct
        fd = os.open('/tmp', os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            held = os.fstat(fd)
            def response(mask=0x1101, inode=None, device=None, mode=None, mount_id=77):
                """Build the exact fixed-width kernel response, never a proc text fallback."""
                raw = bytearray(256)
                struct.pack_into('=I', raw, 0, mask)
                struct.pack_into('=H', raw, 0x1c, held.st_mode if mode is None else mode)
                struct.pack_into('=Q', raw, 0x20, held.st_ino if inode is None else inode)
                selected = held.st_dev if device is None else device
                struct.pack_into('=II', raw, 0x88, os.major(selected), os.minor(selected))
                struct.pack_into('=Q', raw, 0x90, mount_id)
                return bytes(raw)
            class NativeCall:
                """Emulate one libc response for malformed-result contract tests."""
                def __init__(self, data, result=0):
                    """Retain response bytes and explicit syscall outcome."""
                    self.data, self.result = data, result
                def __call__(self, supplied, path, flags, mask, output):
                    """Write only the declared ABI buffer and return the selected outcome."""
                    ctypes.memmove(output, self.data, len(self.data))
                    return self.result
            with patch.object(scratch.ctypes, 'CDLL', return_value=SimpleNamespace(statx=NativeCall(response()))):
                self.assertEqual(scratch._fd_mount_id(fd), 77)
            for raw, result in ((response(mask=0), 0), (response(mount_id=0), 0),
                                (response(inode=held.st_ino+1), 0),
                                (response(device=os.makedev(0,999)), 0),
                                (response(mode=stat.S_IFREG|0o600), 0), (response(), -1)):
                with self.subTest(result=result, raw=raw[:32]), \
                     patch.object(scratch.ctypes, 'CDLL', return_value=SimpleNamespace(statx=NativeCall(raw,result))), \
                     patch.object(scratch,'_read_kernel_text',side_effect=AssertionError('fallback')):
                    with self.assertRaises(scratch.PdfBoundedScratchError):
                        scratch._fd_mount_id(fd)
        finally:
            os.close(fd)

    def test_reject_every_foreign_switch_value(self):
        """Reject present opt-in values other than the exact supported activation marker."""
        for value in ("", "0","yes","true","2","/tmp","1 "):
            with self.subTest(value=value),patch.dict(os.environ,{SWITCH:value}):
                with self.assertRaises(scratch.PdfBoundedScratchError):
                    scratch.bounded_scratch_requested()

    def test_pinned_mount_identity_permits_no_custom_path(self):
        """Pin the scratch path, byte and inode budgets, and required flags without exposing a root override."""
        self.assertEqual(str(scratch._PARENT),"/run/omnigenis-pdf-bounded-scratch")
        self.assertEqual(scratch._MAX_BYTES,128*1024*1024)
        self.assertEqual(scratch._MAX_INODES,4096)
        self.assertEqual(scratch._REQUIRED_FLAGS,FLAGS)
        self.assertFalse(hasattr(scratch,"set_scratch_root"))

    def test_positive_synthetic_namespace_can_admit_fixed_root(self):
        """Admit the fixture parent when the opt-in marker and synthetic mount observations satisfy the policy."""
        self.positive()
        self.assertTrue(scratch.bounded_scratch_requested())
        self.assertEqual(scratch.bounded_scratch_parent(),Path("/tmp"))

    def test_capacity_is_checked_on_the_still_open_parent_descriptor(self):
        """Check parent capacity through one still-open descriptor during bounded scratch admission."""
        self.positive()
        observed=[]

        def inspect(fd):
            """Record the live parent descriptor inode and supply the exact synthetic capacity and inode budgets."""
            observed.append(os.fstat(fd).st_ino)
            return SimpleNamespace(f_blocks=32768,f_frsize=4096,f_files=4096)

        with patch.object(scratch.os,"fstatvfs",side_effect=inspect):
            self.assertEqual(scratch.bounded_scratch_parent(),Path("/tmp"))
        self.assertEqual(len(observed),1)

    def test_only_complete_mount_flags_accepted(self):
        """Reject the scratch parent when any required nosuid, nodev, or noexec mount flag is missing."""
        for removed in FLAGS:
            with self.subTest(removed=removed):
                self.positive(flags=FLAGS-{removed})
                with self.assertRaises(scratch.PdfBoundedScratchError):
                    scratch.bounded_scratch_parent()

    def test_wrong_filesystem_is_rejected(self):
        """Reject alternate or unidentified filesystems even when other synthetic mount observations are valid."""
        for fs in ("overlay","ext4","ramfs",""):
            with self.subTest(fstype=fs):
                self.positive(fstype=fs)
                with self.assertRaises(scratch.PdfBoundedScratchError):
                    scratch.bounded_scratch_parent()

    def test_resource_size_or_inode_overbudget_rejected(self):
        """Reject scratch mounts with excessive byte or inode capacity or with either capacity reported as zero."""
        for blocks,inodes in ((32769,4096),(32768,4097),(0,4096),(32768,0)):
            with self.subTest(blocks=blocks,inodes=inodes):
                self.positive(blocks=blocks,inodes=inodes)
                with self.assertRaises(scratch.PdfBoundedScratchError):
                    scratch.bounded_scratch_parent()

    def test_missing_mount_identity_is_rejected_without_fallback(self):
        """Propagate mount identity failure instead of selecting a fallback scratch directory."""
        self.positive()
        with patch.object(scratch,"_mount_record",
            side_effect=scratch.PdfBoundedScratchError("missing")):
            with self.assertRaises(scratch.PdfBoundedScratchError):
                scratch.bounded_scratch_parent()

    def test_incorrect_requested_mount_environment_blocks_tempdir(self):
        """Refuse process temporary activation when TMPDIR differs from the admitted scratch parent."""
        self.positive()
        with patch.dict(os.environ,{"TMPDIR":"/tmp/other"}):
            with self.assertRaisesRegex(scratch.PdfBoundedScratchError,
                "pdf_bounded_scratch_tmpdir_mismatch"):
                scratch.activate_bounded_process_temporaries()

    def test_opt_in_tempdir_binding_is_scoped_to_a_dedicated_child(self):
        """Bind tempfile state and directory selection to the admitted synthetic parent during explicit activation."""
        self.positive()
        with patch.object(tempfile,"tempdir",None):
            self.assertTrue(scratch.activate_bounded_process_temporaries())
            self.assertEqual(tempfile.tempdir,"/tmp")
            self.assertEqual(tempfile.gettempdir(),"/tmp")

    def test_child_propagates_only_fixed_opt_in_marker(self):
        """Build a minimal child environment containing the fixed opt-in marker and verified private scratch directory."""
        self.positive()
        with tempfile.TemporaryDirectory(
            prefix="omnigenis-pdf-visual-supervisor-",dir="/tmp") as directory:
            result=scratch.raster_child_environment(directory)
            self.assertEqual(set(result),{"PATH","LANG","TMPDIR",SWITCH})
            self.assertEqual(result[SWITCH],"1")
            self.assertEqual(result["TMPDIR"],directory)

    def test_optin_rejects_arbitrary_child_directory(self):
        """Reject arbitrary child paths, foreign parents, and the scratch parent itself as private worker directories."""
        self.positive()
        for path in ("/tmp/private","/var/tmp/foreign","/tmp"):
            with self.subTest(path=path),self.assertRaises(scratch.PdfBoundedScratchError):
                scratch.raster_child_environment(path)

    def test_optin_rejects_child_or_protocol_descriptor_on_another_mount(self):
        """Reject a child directory or protocol descriptor whose mount ID differs from the admitted scratch mount."""
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
        """Require visual and raster supervisors to select the bounded parent helper instead of a literal temporary root."""
        for name in ("reporting/pdf_visual.py","reporting/pdf_raster_windows.py"):
            text=(ROOT/name).read_text()
            self.assertNotIn('dir="/tmp"',text)
            self.assertIn("bounded_scratch_parent()",text)

    def test_original_visual_child_keeps_existing_default_profile(self):
        """Preserve the visual worker's legacy scratch parent and dedicated supervisor directory prefix."""
        from reporting import _pdf_visual_worker as worker
        self.assertEqual(worker.SCRATCH_PARENT,Path("/tmp"))
        self.assertEqual(worker.SCRATCH_PREFIX,
                         "omnigenis-pdf-visual-supervisor-")

    def test_optin_workers_cannot_bypass_same_mount_guards(self):
        """Propagate scratch child and protocol mount guard failures through the visual and raster worker paths."""
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
        """Require the fixed worker source to activate bounded process temporaries before invoking sealed inspection."""
        text=(ROOT/"reporting/_pdf_fixed_inspection_worker.py").read_text()
        self.assertIn("activate_bounded_process_temporaries()",text)
        self.assertLess(text.index("activate_bounded_process_temporaries()"),
            text.index("original=sealed.execute_sealed_pdf_inspection_job("))

    def test_fixed_worker_entrypoint_sets_only_the_verified_optin_parent(self):
        """The dedicated launcher binds TMPDIR before main without changing defaults."""
        from reporting import _pdf_fixed_inspection_worker as worker

        observed=[]

        def run():
            """Capture the final child environment without starting inspection."""
            observed.append(os.environ.get("TMPDIR"))
            return 0

        for inherited in (None,"/tmp/foreign"):
            with self.subTest(inherited_tmpdir=inherited), \
                 patch.dict(os.environ,{},clear=False), \
                 patch.object(worker,"bounded_scratch_requested",return_value=True), \
                 patch.object(worker,"bounded_scratch_parent",
                              return_value=scratch._PARENT), \
                 patch.object(worker,"main",side_effect=run) as execute:
                if inherited is None:
                    os.environ.pop("TMPDIR",None)
                else:
                    os.environ["TMPDIR"]=inherited
                self.assertEqual(worker._entrypoint(),0)
                execute.assert_called_once_with()
                self.assertEqual(observed,[str(scratch._PARENT)])
            observed.clear()
        with patch.dict(os.environ,{"TMPDIR":"/tmp/legacy"}), \
             patch.object(worker,"bounded_scratch_requested",return_value=False), \
             patch.object(worker,"bounded_scratch_parent") as parent, \
             patch.object(worker,"main",side_effect=run):
            self.assertEqual(worker._entrypoint(),0)
            self.assertEqual(observed,["/tmp/legacy"])
            parent.assert_not_called()
        with patch.object(worker,"bounded_scratch_requested",return_value=True), \
             patch.object(worker,"bounded_scratch_parent",
                          side_effect=scratch.PdfBoundedScratchError("missing")), \
             patch.object(worker,"main") as run:
            self.assertEqual(worker._entrypoint(),70)
            run.assert_not_called()

    def test_manifest_is_optin_and_pins_exact_sources(self):
        """Check the bounded scratch manifest's resource policy, exact source hashes, and disabled activation claims."""
        import hashlib
        manifest=json.loads((ROOT/"reporting/pdf-bounded-scratch.v1.json").read_text())
        self.assertEqual(manifest["content_classification"],
                         "SECURITY_RUNTIME_REQUIRED")
        self.assertEqual(manifest["default_pipeline_activated"],False)
        self.assertEqual(manifest["aggregate_resources_qualified"],False)
        self.assertEqual(manifest["release_authorized"],False)
        self.assertEqual(manifest["qualified_scratch_parent"],str(scratch._PARENT))
        self.assertEqual(manifest["max_scratch_bytes"],scratch._MAX_BYTES)
        self.assertEqual(manifest["max_inodes"],scratch._MAX_INODES)
        self.assertEqual(set(manifest["source_sha256"]),{
            "reporting/_pdf_bounded_scratch.py",
            "reporting/_pdf_process_lifecycle.py",
            "reporting/_pdf_visual_worker.py",
            "reporting/_pdf_fixed_inspection_worker.py",
            "reporting/pdf_visual.py",
            "reporting/pdf_raster_windows.py",
        })
        for name,digest in manifest["source_sha256"].items():
            with self.subTest(path=name):
                self.assertEqual(hashlib.sha256((ROOT/name).read_bytes()).hexdigest(),digest)

    def test_transitive_manifests_pin_changed_reused_sources(self):
        """Keep inspection and raster manifest pins aligned with the bounded scratch manifest for reused sources."""
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
        """Parse the scratch helper and exclude source tokens for shell execution, subprocesses, and network access."""
        text=(ROOT/"reporting/_pdf_bounded_scratch.py").read_text()
        ast.parse(text)
        for forbidden in ("subprocess","Popen(","os.system(","eval(","exec(",
                          "http://","https://","pickle"):
            self.assertNotIn(forbidden,text)



class PdfBoundedScratchCleanupTests(unittest.TestCase):
    """The opener owns its descriptor until a successful transfer to its caller."""

    def test_owned_parent_fd_closes_on_baseexception(self):
        """Close the acquired parent descriptor when capacity observation raises an interrupt, exit, or allocation failure."""
        original_open = os.open
        for error in (KeyboardInterrupt(), SystemExit(3), MemoryError()):
            opened = []

            def track_open(*args, **kwargs):
                """Open a real descriptor and record it so exceptional parent acquisition cleanup can be checked."""
                fd = original_open(*args, **kwargs)
                opened.append(fd)
                return fd

            with self.subTest(error=type(error).__name__), \
                 patch.object(scratch, '_PARENT', Path('/tmp')), \
                 patch.object(scratch, '_fd_mount_id', return_value=12), \
                 patch.object(scratch, '_mount_record', return_value=('tmpfs', FLAGS)), \
                 patch.object(scratch.os, 'open', side_effect=track_open), \
                 patch.object(scratch.os, 'fstatvfs', side_effect=error):
                try:
                    with self.assertRaises(type(error)):
                        scratch._open_verified_bounded_parent()
                    self.assertEqual(len(opened), 1)
                    with self.assertRaises(OSError):
                        os.fstat(opened[0])
                finally:
                    for fd in opened:
                        try:
                            os.close(fd)
                        except OSError:
                            pass



class PdfBoundedScratchReadTests(unittest.TestCase):
    """Real descriptors exercise bounded reads, short reads and exceptional cleanup."""

    def test_kernel_reader_accepts_exact_limit_and_rejects_one_extra_byte(self):
        """Accept metadata at the exact byte budget and reject a file containing one additional byte."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'metadata'
            for payload, accepted in ((b'abcd', True), (b'abcde', False)):
                path.write_bytes(payload)
                with self.subTest(payload=payload):
                    if accepted:
                        self.assertEqual(scratch._read_kernel_text(path, 4), 'abcd')
                    else:
                        with self.assertRaises(scratch.PdfBoundedScratchError):
                            scratch._read_kernel_text(path, 4)

    def test_kernel_reader_continues_after_short_reads(self):
        """Reassemble the complete metadata payload when each operating system read returns at most two bytes."""
        read = os.read
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'metadata'
            path.write_bytes(b'abcdefgh')
            with patch.object(scratch.os, 'read', side_effect=lambda fd, count: read(fd, min(count, 2))):
                self.assertEqual(scratch._read_kernel_text(path, 8), 'abcdefgh')

    def test_kernel_reader_closes_on_decode_error_and_baseexception(self):
        """Close the metadata descriptor after decoding failure or exceptions raised while reading its bytes."""
        original_open = os.open
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'metadata'
            path.write_bytes(b'\xff')
            for error in (UnicodeDecodeError, KeyboardInterrupt, SystemExit, MemoryError, OSError):
                opened = []

                def open_metadata(*args, **kwargs):
                    """Open and record the real metadata descriptor for cleanup assertions after read or decoding failure."""
                    fd = original_open(*args, **kwargs)
                    opened.append(fd)
                    return fd

                with self.subTest(error=error.__name__), patch.object(scratch.os, 'open', side_effect=open_metadata):
                    if error is UnicodeDecodeError:
                        with self.assertRaises(error):
                            scratch._read_kernel_text(path, 4)
                    else:
                        with patch.object(scratch.os, 'read', side_effect=error), self.assertRaises(error):
                            scratch._read_kernel_text(path, 4)
                    self.assertEqual(len(opened), 1)
                    with self.assertRaises(OSError):
                        os.fstat(opened[0])

    def test_proc_parsers_cannot_accept_valid_prefix_before_oversized_tail(self):
        """Reject oversized fdinfo and mountinfo payloads even when each begins with an otherwise valid record."""
        payloads = ((b'mnt_id: 77\n' + b'x'*4096, 'fdinfo'),
                    (b'12 1 0:12 / /run/omnigenis-pdf-bounded-scratch rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n' + b'x'*262144, 'mountinfo'))
        for payload, kind in payloads:
            with self.subTest(kind=kind), tempfile.TemporaryFile() as fixture:
                fixture.write(payload)
                fixture.seek(0)
                with patch.object(scratch.os, 'open', side_effect=lambda *args, **kwargs: os.dup(fixture.fileno())):
                    with self.assertRaises(scratch.PdfBoundedScratchError):
                        if kind == 'fdinfo':
                            scratch._fd_mount_id(9)
                        else:
                            scratch._mount_record(scratch._PARENT, os.makedev(0,12), 12)


if __name__=="__main__":
    unittest.main()
