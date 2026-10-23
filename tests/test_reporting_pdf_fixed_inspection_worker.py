"""Optional fixed process ingress/egress for existing complete technical PDF inspection."""
from hashlib import sha256
import ast
import importlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from reporting import pdf_inspection_request as codec
from reporting import pdf_request_descriptor as descriptor
from reporting import pdf_sealed_inspection as sealed
from reporting import pdf_inspection_result_frame as framed
from reporting import pdf_structured_source_job as structured
from reporting.page_checkpoints import _json_bytes
from tests import test_reporting_pdf_sealed_inspection as prior

ROOT=Path(__file__).resolve().parents[1]
WORKER=ROOT/'reporting/_pdf_fixed_inspection_worker.py'
DISABLE='OMNIGENIS_PDF_FIXED_INSPECTION_WORKER_DISABLED'


class FixedInspectionWorkerTests(unittest.TestCase):
    """A real child produces bounded bytes but never authenticates itself."""

    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('reporting._pdf_fixed_inspection_worker'),
            'fixed request/result worker module missing')
        self.m=importlib.import_module('reporting._pdf_fixed_inspection_worker')
        self.h=prior.PdfSealedInspectionTests()
        self.h.setUp()

    def context(self, expected, args, **changes):
        payload=dict(
            expected_worker_profile_sha256=self.m.PROFILE_SHA256,
            expected_packet_sha256=expected['expected_packet_sha256'],
            expected_protocol_profile_sha256=codec.PROFILE_SHA256,
            expected_namespace_id=args['namespace_id'],
            expected_job_id=args['job_id'],
            expected_request_sha256=args['request_sha256'],
            expected_descriptor_profile_sha256=descriptor.PROFILE_SHA256,
            expected_execution_profile_sha256=sealed.PROFILE_SHA256,
            expected_pdf_sha256=args['expected_pdf_sha256'],
            expected_ir_sha256=args['expected_ir_sha256'],
            expected_page_count=args['page_count'],
            expected_language=args['expected_language'],
            expected_resource_profile_sha256=structured.PROFILE_SHA256,
            expected_frame_profile_sha256=framed.PROFILE_SHA256)
        return {**payload, **changes}

    def launch(self,fd,raw,parent=None,pipe=True):
        cmd=[sys.executable,'-I','-B',str(WORKER),str(fd),
             str(os.getpid() if parent is None else parent)]
        result=subprocess.run(cmd,input=raw,stdout=subprocess.PIPE if pipe else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,pass_fds=(fd,) if fd>=3 else (),
            cwd=ROOT,timeout=360)
        return result.returncode,result.stdout if result.stdout is not None else b''

    def assertRejected(self,fd,data,parent=None,pipe=True):
        code,result=self.launch(fd,data,parent,pipe)
        self.assertNotEqual(code,0)
        self.assertEqual(result,b'')

    def test_exact_signature_and_new_profile_are_bounded_and_disabled_in_default(self):
        profile=self.m.worker_profile()
        self.assertEqual(profile['max_context_bytes'],codec.MAX_METADATA_BYTES)
        self.assertEqual(profile['max_result_frame_bytes'],framed.MAX_FRAME_BYTES)
        for key in ('default_pipeline_activated','service_installed',
                    'aggregate_job_resources_qualified','release_authorized',
                    'origin_authenticated','descendant_cleanup_qualified'):
            self.assertIs(profile[key],False)

    def test_source_has_docstrings_and_no_arbitrary_process_or_network_launch(self):
        source=WORKER.read_text()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                self.assertIsNotNone(ast.get_docstring(node))
        for token in ('subprocess','Popen','os.system','eval(','exec(','http://','https://',
                      'os.chdir(','pickle','requests.'):
            self.assertNotIn(token,source)

    def test_manifest_pins_unchanged_original_sources_and_worker_profile(self):
        record=json.loads((ROOT/'reporting/pdf-fixed-inspection-worker.v1.json').read_text())
        self.assertEqual(record['profile_sha256'],self.m.PROFILE_SHA256)
        self.assertEqual(record['profile'],self.m.worker_profile())
        for key in ('default_pipeline_activated','service_installed',
                    'aggregate_job_resources_qualified','release_authorized',
                    'dependencies_changed'):
            self.assertIs(record[key],False)
        for name,digest in record['reused_source_sha256'].items():
            self.assertEqual(sha256((ROOT/name).read_bytes()).hexdigest(),digest)

    def test_canonical_context_and_fixed_keys_are_required(self):
        with self.h.request() as (fd,expected,args,_):
            record=self.context(expected,args)
            clean=_json_bytes(record)
            self.assertEqual(self.m._parse_context(clean),record)
            for variant in (b'',b'{}',b'[]',b' '+clean,
                clean[:-1]+b',"expected_job_id":"changed"}',
                clean[:-1]+b',"unknown_critical":"1"}',
                clean[:-1]+b',"extra":NaN}',
                b'x'*(codec.MAX_METADATA_BYTES+1)):
                with self.subTest(length=len(variant)):
                    self.assertRejected(fd,variant)

    def test_expected_profile_and_identity_drift_fail_before_native_work(self):
        with self.h.request() as (fd,expected,args,_):
            source=self.context(expected,args)
            for key in source:
                altered=dict(source)
                altered[key]= 1 if key=='expected_page_count' else (
                    'f'*64 if key.endswith('sha256') else 'synthetic-foreign')
                with self.subTest(key=key):
                    self.assertRejected(fd,_json_bytes(altered))

    def test_missing_invalid_descriptor_and_wrong_parent_are_rejected(self):
        with self.h.request() as (fd,expected,args,_):
            payload=_json_bytes(self.context(expected,args))
            self.assertRejected(-1,payload)
            self.assertRejected(fd,payload,parent=os.getpid()+1)

    def test_stdout_must_be_a_pipe_and_extra_arguments_are_rejected(self):
        with self.h.request() as (fd,expected,args,_):
            payload=_json_bytes(self.context(expected,args))
            self.assertRejected(fd,payload,pipe=False)
            response=subprocess.run([sys.executable,'-I','-B',str(WORKER),
                str(fd),str(os.getpid()),'extra'],input=payload,
                stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                pass_fds=(fd,),cwd=ROOT,timeout=30)
            self.assertNotEqual(response.returncode,0)
            self.assertEqual(response.stdout,b'')

    def test_worker_disable_prevents_any_result(self):
        with self.h.request() as (fd,expected,args,_):
            payload=_json_bytes(self.context(expected,args))
            with patch.dict(os.environ,{DISABLE:'1'}):
                self.assertRejected(fd,payload)

    def test_real_one_thirty_three_sixty_four_page_unchanged_result(self):
        for pages,(ir,pdf) in self.h.h.native_cases().items():
            raw=_json_bytes(ir)
            changes=dict(presentation_ir_bytes=raw,
                expected_ir_sha256=sha256(raw).hexdigest(),
                pdf_bytes=pdf,expected_pdf_sha256=sha256(pdf).hexdigest(),
                page_count=pages)
            with self.h.request(**changes) as (fd,expected,args,packet):
                context=self.context(expected,args)
                os.lseek(fd,7,os.SEEK_SET)
                code,output=self.launch(fd,_json_bytes(context))
                self.assertEqual(os.lseek(fd,0,os.SEEK_CUR),7)
                self.assertEqual(code,0,f'worker_failed_on_{pages}_pages')
                decoded=framed.decode_pdf_inspection_result_frame(output,
                    expected_pdf_sha256=args['expected_pdf_sha256'],
                    expected_ir_sha256=args['expected_ir_sha256'],
                    expected_page_count=pages,
                    expected_language=args['expected_language'],
                    expected_namespace_id=args['namespace_id'],
                    expected_job_id=args['job_id'],
                    expected_request_sha256=args['request_sha256'],
                    expected_resource_profile_sha256=structured.PROFILE_SHA256,
                    expected_frame_profile_sha256=framed.PROFILE_SHA256)
                record=json.loads(decoded)
                self.assertEqual(record['page_count'],pages)
                self.assertEqual(len(record['inspection_dimensions']),8)
                self.assertFalse(record['release_authorized'])
                self.assertFalse(record['aggregate_job_resources_qualified'])
                self.assertEqual(os.pread(fd,len(packet),0),packet)

    def test_valid_envelope_cannot_override_invalid_source_or_pdf(self):
        with self.h.request() as (fd,expected,args,_):
            data=_json_bytes(self.context(expected,args))
            self.assertRejected(fd,data)
        # The synthetic control fixture above contains an opaque placeholder PDF,
        # not the signed-off real candidate used in the positive native tests.

    def test_unsealed_and_named_request_descriptors_are_rejected(self):
        with self.h.request() as (_,expected,args,packet):
            raw=_json_bytes(self.context(expected,args))
            memfd=os.memfd_create('synthetic-unsealed',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
            try:
                os.fchmod(memfd,0o600)
                self.assertEqual(os.write(memfd,packet),len(packet))
                self.assertRejected(memfd,raw)
            finally:
                os.close(memfd)
            import tempfile
            with tempfile.TemporaryFile() as named:
                named.write(packet)
                named.flush()
                self.assertRejected(named.fileno(),raw)

    def test_context_pipe_cannot_be_replaced_with_ordinary_file(self):
        with self.h.request() as (fd,expected,args,_):
            import tempfile
            with tempfile.TemporaryFile() as incoming:
                incoming.write(_json_bytes(self.context(expected,args)))
                incoming.seek(0)
                process=subprocess.run([sys.executable,'-I','-B',str(WORKER),
                    str(fd),str(os.getpid())],stdin=incoming,stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,pass_fds=(fd,),cwd=ROOT,timeout=30)
                self.assertNotEqual(process.returncode,0)
                self.assertEqual(process.stdout,b'')

    def test_private_request_bytes_never_in_failure_output(self):
        with self.h.request() as (fd,expected,args,packet):
            payload=_json_bytes(self.context(expected,args,
                expected_request_sha256='f'*64))
            code,out=self.launch(fd,payload)
            self.assertNotEqual(code,0)
            self.assertEqual(out,b'')
            self.assertNotIn(packet[:32],out)



class FixedKernelAdmissionOrderingTests(unittest.TestCase):
    """Selected policy must refuse before any untrusted context is consumed."""

    def test_missing_selected_policy_refuses_before_context_read(self):
        from types import SimpleNamespace
        import stat
        from reporting import _pdf_fixed_inspection_worker as worker

        for value in ('1', '', '0', 'true', '1 '):
            with self.subTest(selector=value), \
                 patch.dict(os.environ, {'OMNIGENIS_PDF_FIXED_KERNEL_ADMISSION_V1': value}, clear=True), \
                 patch.object(worker.os, 'fstat', return_value=SimpleNamespace(st_mode=stat.S_IFIFO)), \
                 patch.object(worker, '_parent_lifetime'), \
                 patch.object(worker, '_read_pipe', return_value=b'{}') as read, \
                 patch.object(worker, 'activate_bounded_process_temporaries') as temporaries, \
                 patch.object(worker.sealed, 'execute_sealed_pdf_inspection_job') as inspect, \
                 patch.object(worker, '_write_frame') as write:
                self.assertEqual(worker.main(['worker', '9', '42']), 70)
                read.assert_not_called()
                temporaries.assert_not_called()
                inspect.assert_not_called()
                write.assert_not_called()


from contextlib import ExitStack
import errno
import posixpath
import resource
import stat
import tempfile
from types import SimpleNamespace


class KernelObservationFixture:
    """Real file objects with independently declared namespace-local observations.

    Usage: with KernelObservationFixture(worker) as fixture: ...
    request_fd is borrowed. active maps live acquired FDs to logical paths;
    opened/closed contain (fd, logical_path) events. No guard method is patched.
    close() restores patches/tempfile.tempdir and cleans any remaining fixture FD.
    Assertions about production cleanup must precede fixture cleanup.
    """

    PID, PARENT = 7211, 7200
    PROC = '/proc/7211'
    CGROUP = '/sys/fs/cgroup/system.slice/omnigenis-pdf-fixed-inspection-v1.service'
    SCRATCH = '/run/omnigenis-pdf-bounded-scratch'
    MEMBERSHIP = b'0::/system.slice/omnigenis-pdf-fixed-inspection-v1.service\n'
    MOUNTINFO = (
        b'11 1 0:11 / /proc rw,nosuid,nodev,noexec - proc proc rw\n'
        b'12 1 0:12 / /sys/fs/cgroup ro,nosuid,nodev,noexec - cgroup2 cgroup2 ro\n'
        b'13 1 0:13 / /run/omnigenis-pdf-bounded-scratch rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n'
    )
    STATUS = (
        b'Name:\tfixed-worker\nPid:\t7211\nTgid:\t7211\nPPid:\t7200\n'
        b'Uid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n'
        b'NoNewPrivs:\t1\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n'
        b'CapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\n'
    )

    def __init__(self, worker):
        """Create backing files before redirecting the process-wide OS module."""
        self.worker, self.stack = worker, ExitStack()
        for name in ('open', 'close', 'read', 'stat', 'fstat', 'set_inheritable'):
            setattr(self, 'real_' + name, getattr(os, name))
        self.base = Path(self.stack.enter_context(tempfile.TemporaryDirectory(
            prefix='omnigenis-kernel-observation-', dir='/tmp')))
        self.request = self.stack.enter_context(tempfile.TemporaryFile(dir=self.base))
        self.request_fd = self.request.fileno()
        self.real_fstat(2)  # The test process must already have an open stderr.
        self.active, self.opened, self.closed, self.reads = {}, [], [], []
        self.metadata, self.filesystems, self.mount_ids, self.fdinfo = {}, {}, {}, {}
        self.counts, self.fail_at, self.inheritable_path, self.read_chunk = {}, None, None, None
        self.pid, self.parent, self.uids, self.gids = self.PID, self.PARENT, (1000,) * 3, (1000,) * 3
        self.usage = SimpleNamespace(f_blocks=32768, f_frsize=4096, f_files=4096,
                                    f_bfree=32000, f_bavail=32000, f_ffree=4000)
        self.limits = {
            resource.RLIMIT_AS: (1073741824, 1073741824),
            resource.RLIMIT_CPU: (300, 300), resource.RLIMIT_FSIZE: (67108864, 67108864),
            resource.RLIMIT_NOFILE: (128, 128), resource.RLIMIT_CORE: (0, 0),
        }
        for path in (self.PROC + '/fdinfo', self.PROC + '/ns', self.CGROUP, self.SCRATCH):
            self.backing(path).mkdir(parents=True, exist_ok=True)
        self.backing('/proc/self').symlink_to(str(self.PID))
        os.chmod(self.backing(self.SCRATCH), 0o1777)
        for name in ('mnt', 'cgroup', 'pid', 'user'):
            self.edit(self.PROC + '/ns/' + name, b'namespace fixture\n')
        for name, data in {
            'cgroup.type': b'domain\n', 'memory.max': b'2147483648\n',
            'memory.swap.max': b'0\n', 'pids.max': b'32\n', 'cpu.max': b'200000 100000\n',
            'memory.current': b'1048576\n', 'memory.swap.current': b'0\n', 'pids.current': b'3\n',
        }.items():
            self.edit(self.CGROUP + '/' + name, data)
        self.edit(self.PROC + '/status', self.STATUS)
        self.edit(self.PROC + '/cgroup', self.MEMBERSHIP)
        self.edit(self.PROC + '/mountinfo', self.MOUNTINFO)

    def backing(self, logical):
        """Return the backing path; do not derive policy from production helpers."""
        return self.base / logical.lstrip('/')

    def edit(self, logical_path, payload):
        """Change bytes while preserving the current inode."""
        self.backing(logical_path).write_bytes(payload)

    def replace(self, logical_path):
        """Atomically replace a real namespace file while old FDs remain valid."""
        path = self.backing(logical_path)
        replacement = path.with_name(path.name + '.replacement')
        replacement.write_bytes(b'replacement\n')
        os.replace(replacement, path)

    def _logical(self, path, dir_fd=None):
        """Map only the declared logical tree, retaining real relative-FD opens."""
        path = os.fsdecode(path)
        if not path.startswith('/'):
            if dir_fd not in self.active:
                return None
            path = posixpath.join(self.active[dir_fd], path)
        if path == '/proc/self' or path.startswith('/proc/self/'):
            path = self.PROC + path[len('/proc/self'):]
        path = posixpath.normpath(path)
        return path if (path == '/' or any(path == p or path.startswith(p + '/')
                    for p in ('/proc', '/sys', '/run'))) else None

    def _zone(self, path):
        """Independent fixture device/mount, filesystem magic, and mount flags."""
        if path.startswith(self.PROC + '/ns/'):
            return 14, 0x6E736673, 14
        if path == '/proc' or path.startswith('/proc/'):
            return 11, 0x9FA0, 14
        if path == '/sys/fs/cgroup' or path.startswith('/sys/fs/cgroup/'):
            return 12, 0x63677270, 15
        if path == self.SCRATCH or path.startswith(self.SCRATCH + '/'):
            return 13, 0x01021994, 14
        return 10, 0xEF53, 0

    def _hit(self, event, path):
        """Inject one failure at a named OS boundary, allowing later cleanup."""
        key = event, path
        self.counts[key] = self.counts.get(key, 0) + 1
        if self.fail_at and self.fail_at[:3] == (event, path, self.counts[key]):
            raise self.fail_at[3]('fixture boundary failure')

    def _open(self, path, flags, mode=0o777, *, dir_fd=None):
        """Use real open/CLOEXEC semantics, generating fdinfo for the target FD."""
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            raise AssertionError('kernel observation attempted a filesystem write')
        logical = self._logical(path, dir_fd)
        if logical is None:
            return self.real_open(path, flags, mode, dir_fd=dir_fd)
        if logical.startswith(self.PROC + '/fdinfo/'):
            target = int(logical.rsplit('/', 1)[1])
            self.real_fstat(target)
            target_path = self.active[target]
            mount = self.mount_ids.get(target_path, self._zone(target_path)[0])
            self.edit(logical, self.fdinfo.get(target_path,
                f'pos:\t0\nflags:\t02000000\nmnt_id:\t{mount}\n'.encode('ascii')))
        actual = path if dir_fd in self.active and not os.path.isabs(path) else self.backing(logical)
        fd = self.real_open(actual, flags, mode, dir_fd=dir_fd)
        self.active[fd] = logical
        self.opened.append((fd, logical))
        if logical == self.inheritable_path:
            self.real_set_inheritable(fd, True)
        return fd

    def _close(self, fd):
        """Record successful real closure; leave failed closes observable."""
        path = self.active.get(fd)
        self.real_close(fd)
        if path is not None:
            del self.active[fd]
            self.closed.append((fd, path))

    def _metadata(self, info, path):
        """Keep the real inode; synthesize only unavailable kernel metadata."""
        values = list(info)
        values[2] = os.makedev(0, self._zone(path)[0])
        values[4] = values[5] = 1000 if path.startswith(self.PROC) else 0
        for name, index in (('st_mode', 0), ('st_dev', 2), ('st_uid', 4), ('st_gid', 5)):
            if name in self.metadata.get(path, {}):
                values[index] = self.metadata[path][name]
        return os.stat_result(values)

    def _fstat(self, fd):
        """Require a real open FD even when its proc/cgroup metadata is synthetic."""
        info = self.real_fstat(fd)
        if fd in (0, 1):
            values = list(info)
            values[0] = stat.S_IFIFO | 0o600
            return os.stat_result(values)
        if fd not in self.active:
            return info
        path = self.active[fd]
        self._hit('fstat', path)
        return self._metadata(info, path)

    def _stat(self, path, *, dir_fd=None, follow_symlinks=True):
        """Resolve current names separately from the retained open file objects."""
        if isinstance(path, int):
            return self._fstat(path)
        logical = self._logical(path, dir_fd)
        if logical is None:
            return self.real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
        info = self.real_stat(self.backing(logical), follow_symlinks=follow_symlinks)
        return self._metadata(info, logical)

    def _read(self, fd, count):
        """Read real bytes, optionally in short chunks, without changing EOF."""
        path = self.active.get(fd)
        self._hit('read', path)
        data = self.real_read(fd, min(count, self.read_chunk) if self.read_chunk else count)
        self.reads.append((path, count, len(data)))
        return data

    def _filesystem(self, fd):
        """Represent kernel fstatfs only; ownership and bytes stay on real FDs."""
        self.real_fstat(fd)
        path = self.active[fd]
        return self.filesystems.get(path, self._zone(path)[1:])

    def __enter__(self):
        """Install the OS boundary; the caller still invokes real admission."""
        self.stack.enter_context(patch.dict(os.environ, {
            'OMNIGENIS_PDF_FIXED_KERNEL_ADMISSION_V1': '1',
            'OMNIGENIS_PDF_BOUNDED_SCRATCH_V1': '1', 'TMPDIR': self.SCRATCH,
        }, clear=False))
        self.stack.enter_context(patch.object(tempfile, 'tempdir', tempfile.tempdir))
        for name in ('open', 'close', 'read', 'stat', 'fstat'):
            self.stack.enter_context(patch.object(os, name, side_effect=getattr(self, '_' + name)))
        for name, observe in {
            'getuid': lambda: self.uids[0], 'geteuid': lambda: self.uids[1],
            'getgid': lambda: self.gids[0], 'getegid': lambda: self.gids[1],
            'getresuid': lambda: self.uids, 'getresgid': lambda: self.gids,
            'getpid': lambda: self.pid, 'getppid': lambda: self.parent,
            'fstatvfs': lambda fd: self.usage,
        }.items():
            self.stack.enter_context(patch.object(os, name, side_effect=observe))
        self.stack.enter_context(patch.object(resource, 'getrlimit', side_effect=self.limits.__getitem__))
        self.stack.enter_context(patch.object(resource, 'setrlimit', side_effect=AssertionError('limit mutation')))
        self.stack.enter_context(patch.object(self.worker, '_kernel_filesystem', side_effect=self._filesystem))
        return self

    def close(self):
        """Restore global state after assertions, then remove fixture storage."""
        try:
            for fd in tuple(self.active):
                try:
                    self.real_close(fd)
                except OSError:
                    pass
            self.active.clear()
        finally:
            self.stack.close()

    def __exit__(self, *error):
        """Never suppress a production/test exception."""
        self.close()


class FixedKernelObservationTests(unittest.TestCase):
    """Guard behavior under controlled OS observations; no native qualification."""

    def setUp(self):
        self.worker = importlib.import_module('reporting._pdf_fixed_inspection_worker')

    def assert_released(self, fixture):
        self.assertEqual(fixture.active, {})
        for fd in {fd for fd, _ in fixture.opened}:
            with self.assertRaises(OSError) as caught:
                fixture.real_fstat(fd)
            self.assertEqual(caught.exception.errno, errno.EBADF)
        fixture.real_fstat(fixture.request_fd)
        fixture.real_fstat(2)

    def test_real_guard_admits_rechecks_and_closes_owned_originals(self):
        with KernelObservationFixture(self.worker) as f:
            guard = self.worker._open_kernel_admission(f.request_fd)
            self.assertIsInstance(guard, self.worker._KernelAdmission)
            self.assertEqual(set(guard.owned), set(f.active))
            self.assertTrue(set(guard.namespaces.values()) <= set(f.active))
            self.assertFalse(set(guard.borrowed) & set(f.active))
            self.assertTrue(all(not os.get_inheritable(fd) for fd in f.active))
            retained = dict(guard.owned)
            f.usage.f_bfree, f.usage.f_ffree = 31000, 3900
            for label, records in (
                ('cgroup source label', f.MOUNTINFO.replace(b' - cgroup2 cgroup2 ro', b' - cgroup2 none ro')),
                ('different numeric PID', f.MOUNTINFO + b'90 1 0:90 / /proc/72110 rw - tmpfs tmpfs rw\n'),
                ('unrelated non-ASCII', f.MOUNTINFO + b'91 1 0:91 / /foreign-\xff rw - tmpfs tmpfs rw\n'),
            ):
                with self.subTest(observation=label):
                    f.edit(f.PROC + '/mountinfo', records)
                    guard.recheck()
                    self.assertEqual(guard.owned, retained)
            self.assertTrue(guard.close())
            self.assertTrue(guard.close())
            self.assert_released(f)

    def test_control_status_membership_and_occupancy_refusal_matrix(self):
        cases = [
            ('cgroup.type', b'domain threaded\n'), ('memory.max', b'max\n'),
            ('memory.max', b'1073741824\n'), ('memory.swap.max', b'1\n'),
            ('pids.max', b'33\n'), ('cpu.max', b'200000 99999\n'),
            ('memory.current', b'2147483649\n'), ('memory.swap.current', b'1\n'),
            *[('pids.current', value) for value in (b'0\n', b'33\n', b'03\n', b'-1\n', b'1\n1\n')],
        ]
        cases += [(KernelObservationFixture.PROC + '/cgroup', value) for value in (
            b'0::/foreign.service\n', KernelObservationFixture.MEMBERSHIP * 2)]
        status = KernelObservationFixture.STATUS
        cases += [(KernelObservationFixture.PROC + '/status', value) for value in (
            status.replace(b'NoNewPrivs:\t1', b'NoNewPrivs:\t0'),
            status.replace(b'CapEff:\t0000000000000000', b'CapEff:\t0000000000000001'),
            status.replace(b'Uid:\t1000\t1000\t1000\t1000', b'Uid:\t1000\t1000\t0\t1000'),
            status + b'NoNewPrivs:\t1\n')]
        for name, payload in cases:
            with self.subTest(name=name, payload=payload), KernelObservationFixture(self.worker) as f:
                f.edit(name if name.startswith('/') else f.CGROUP + '/' + name, payload)
                with self.assertRaises(ValueError):
                    self.worker._open_kernel_admission(f.request_fd)
                self.assert_released(f)

    def test_metadata_mount_namespace_and_limit_refusal_matrix(self):
        cases = (
            ('metadata', '/proc', {'st_uid': 1000}),
            ('metadata', 'control', {'st_uid': 1000}),
            ('metadata', 'control', {'st_mode': stat.S_IFIFO | 0o644}),
            ('metadata', 'control', {'st_dev': os.makedev(0, 99)}),
            ('metadata', 'cgroup', {'st_mode': stat.S_IFDIR | 0o775}),
            ('filesystems', 'cgroup', (0x01021994, 15)),
            ('filesystems', 'cgroup', (0x63677270, 14)),
            ('filesystems', '/proc', (0x9FA0, 6)),
            ('filesystems', 'scratch', (0x01021994, 15)),
            ('filesystems', 'namespace', (0x9FA0, 14)),
            ('mount_ids', 'control', 99), ('mount_ids', 'cgroup', 99),
            ('metadata', 'scratch', {'st_uid': 1000}),
        )
        for kind, target, value in cases:
            with self.subTest(kind=kind, target=target, value=value), KernelObservationFixture(self.worker) as f:
                path = {'control': f.CGROUP + '/memory.max', 'cgroup': f.CGROUP,
                    'scratch': f.SCRATCH, 'namespace': f.PROC + '/ns/mnt'}.get(target, target)
                getattr(f, kind)[path] = value
                with self.assertRaises((ValueError, self.worker.scratch.PdfBoundedScratchError)):
                    self.worker._open_kernel_admission(f.request_fd)
                self.assert_released(f)
        for field, value in (('f_blocks', 32767), ('f_files', 4095)):
            with self.subTest(capacity=field), KernelObservationFixture(self.worker) as f:
                setattr(f.usage, field, value)
                with self.assertRaises(ValueError):
                    self.worker._open_kernel_admission(f.request_fd)
                self.assert_released(f)
        with KernelObservationFixture(self.worker) as f:
            f.inheritable_path = '/proc'
            with self.assertRaises(ValueError):
                self.worker._open_kernel_admission(f.request_fd)
            self.assert_released(f)
        for limit in (resource.RLIMIT_AS, resource.RLIMIT_CPU, resource.RLIMIT_FSIZE,
                      resource.RLIMIT_NOFILE, resource.RLIMIT_CORE):
            with self.subTest(limit=limit), KernelObservationFixture(self.worker) as f:
                soft, hard = f.limits[limit]
                f.limits[limit] = (soft, hard + 1)
                with self.assertRaises(ValueError):
                    self.worker._open_kernel_admission(f.request_fd)
                self.assert_released(f)

    def test_recheck_rejects_real_name_and_observation_drift(self):
        for change in ('self', 'namespace', 'path', 'membership', 'overmount', 'cloexec'):
            with self.subTest(change=change), KernelObservationFixture(self.worker) as f:
                guard = self.worker._open_kernel_admission(f.request_fd)
                if change == 'self':
                    f.backing('/proc/self').unlink()
                    f.backing('/proc/self').symlink_to('7212')
                elif change == 'namespace':
                    f.replace(f.PROC + '/ns/mnt')
                elif change == 'path':
                    old = f.backing(f.CGROUP)
                    old.rename(old.with_name('retained-original'))
                    old.mkdir()
                elif change == 'membership':
                    f.edit(f.PROC + '/cgroup', b'0::/foreign.service\n')
                elif change == 'overmount':
                    f.edit(f.PROC + '/mountinfo', f.MOUNTINFO +
                        b'90 1 0:90 / /proc/7211/status rw - tmpfs tmpfs rw\n')
                else:
                    os.set_inheritable(guard.cgroup, True)
                with self.assertRaises(ValueError):
                    guard.recheck()
                self.assertTrue(guard.close())
                self.assert_released(f)

    def test_baseexception_after_acquisition_closes_real_descriptors(self):
        cases = (
            ('fstat', '/proc', 1, KeyboardInterrupt),
            ('fstat', '/proc', 2, SystemExit),
            ('fstat', KernelObservationFixture.SCRATCH, 1, KeyboardInterrupt),
            ('fstat', KernelObservationFixture.CGROUP + '/memory.max', 2, MemoryError),
            ('read', KernelObservationFixture.PROC + '/status', 1, KeyboardInterrupt),
            ('read', KernelObservationFixture.PROC + '/mountinfo', 1, SystemExit),
        )
        for event, path, occurrence, error in cases:
            with self.subTest(event=event, path=path, error=error), KernelObservationFixture(self.worker) as f:
                f.fail_at = event, path, occurrence, error
                with self.assertRaises(error):
                    self.worker._open_kernel_admission(f.request_fd)
                self.assertTrue(f.opened)
                self.assert_released(f)

    def test_cleanup_identity_failure_retains_ownership_until_bounded_retry(self):
        with KernelObservationFixture(self.worker) as f:
            # First fstat records ownership, second checks metadata, third closes.
            # The injected cleanup exception must not discard the FD from ownership.
            f.fail_at = 'fstat', f.CGROUP + '/memory.max', 3, KeyboardInterrupt
            with self.assertRaises(ValueError):
                self.worker._open_kernel_admission(f.request_fd)
            self.assert_released(f)

    def test_foreign_proc_self_rejects_before_opening_numeric_process(self):
        with KernelObservationFixture(self.worker) as f:
            f.backing('/proc/self').unlink()
            f.backing('/proc/self').symlink_to('7212')
            with self.assertRaises(ValueError):
                self.worker._open_kernel_admission(f.request_fd)
            self.assertNotIn(f.PROC, [path for _, path in f.opened])
            self.assert_released(f)

    def test_replaced_descriptor_slot_is_not_closed_as_an_owned_original(self):
        with KernelObservationFixture(self.worker) as f:
            guard = self.worker._open_kernel_admission(f.request_fd)
            slot = guard.cgroup
            os.dup2(f.request_fd, slot, inheritable=False)
            with self.assertRaises(ValueError):
                guard.recheck()
            self.assertFalse(guard.close())
            self.assertEqual(set(f.active), {slot})
            self.assertEqual(f.real_fstat(slot).st_ino, f.real_fstat(f.request_fd).st_ino)
            os.close(slot)  # The test owns this new duplicate; the guard does not.
            self.assert_released(f)

    def test_real_metadata_reader_honors_short_reads_and_limit_plus_one(self):
        with KernelObservationFixture(self.worker) as f:
            f.read_chunk = 7
            guard = self.worker._open_kernel_admission(f.request_fd)
            for size in (64, 65):
                f.edit(f.CGROUP + '/memory.max', b'x' * size)
                arguments = (guard.cgroup, 'memory.max', 64, 0x63677270)
                if size == 64:
                    self.assertEqual(guard._read_at(*arguments, mount=12), b'x' * 64)
                else:
                    with self.assertRaisesRegex(ValueError, 'metadata budget'):
                        guard._read_at(*arguments, mount=12)
            self.assertTrue(all(returned <= 7 for _, _, returned in f.reads))
            self.assertTrue(all(requested <= 65 for path, requested, _ in f.reads
                                if path == f.CGROUP + '/memory.max'))
            self.assertTrue(guard.close())
            self.assert_released(f)


class FixedKernelAdmissionEntrypointTests(unittest.TestCase):
    """Real guard and entrypoint reject drift before work and before publication."""

    def setUp(self):
        self.worker = importlib.import_module('reporting._pdf_fixed_inspection_worker')
        self.control = '/sys/fs/cgroup/system.slice/omnigenis-pdf-fixed-inspection-v1.service/memory.max'

    def context_bytes(self):
        return _json_bytes({
            'expected_worker_profile_sha256': self.worker.PROFILE_SHA256,
            'expected_packet_sha256': 'a'*64,
            'expected_protocol_profile_sha256': codec.PROFILE_SHA256,
            'expected_namespace_id': 'kernel-test', 'expected_job_id': 'kernel-job',
            'expected_request_sha256': 'b'*64,
            'expected_descriptor_profile_sha256': descriptor.PROFILE_SHA256,
            'expected_execution_profile_sha256': sealed.PROFILE_SHA256,
            'expected_pdf_sha256': 'c'*64, 'expected_ir_sha256': 'd'*64,
            'expected_page_count': 1, 'expected_language': structured.LANGUAGE,
            'expected_resource_profile_sha256': structured.PROFILE_SHA256,
            'expected_frame_profile_sha256': framed.PROFILE_SHA256,
        })

    def exercise(self, fixture, *, after_context=None, during_work=None,
                 during_encode=None, partial_write=False):
        from contextlib import ExitStack
        from types import SimpleNamespace
        events, output = [], bytearray()
        raw = self.context_bytes()
        original_write = os.write

        def read():
            events.append('context')
            if after_context is not None:
                after_context()
            return raw

        def inspect(*args, **kwargs):
            events.append('sealed')
            self.assertTrue(fixture.active)
            for fd in fixture.active:
                fixture.real_fstat(fd)
            if during_work is not None:
                during_work()
            return SimpleNamespace(to_bytes=lambda: b'original')

        def encode(*args, **kwargs):
            events.append('encode')
            if during_encode is not None:
                during_encode()
            return b'frame'

        def write(fd, data):
            if fd != 1:
                return original_write(fd, data)
            events.append('write')
            self.assertTrue(fixture.active)
            if partial_write:
                if output:
                    raise BrokenPipeError()
                output.extend(data[:1])
                return 1
            output.extend(data)
            return len(data)

        with ExitStack() as stack:
            stack.enter_context(patch.object(self.worker, '_parent_lifetime'))
            stack.enter_context(patch.object(self.worker, '_read_pipe', side_effect=read))
            stack.enter_context(patch.object(sealed, 'execute_sealed_pdf_inspection_job', side_effect=inspect))
            stack.enter_context(patch.object(framed, 'encode_pdf_inspection_result_frame', side_effect=encode))
            stack.enter_context(patch.object(framed, 'decode_pdf_inspection_result_frame', return_value=b'original'))
            stack.enter_context(patch.object(self.worker.os, 'write', side_effect=write))
            stack.enter_context(patch.object(sys, 'argv', ['worker', str(fixture.request_fd), str(os.getppid())]))
            code = self.worker._entrypoint()
        return code, bytes(output), events

    def test_admitted_entrypoint_retains_descriptors_through_result_write(self):
        with KernelObservationFixture(self.worker) as fixture:
            borrowed = {fd: fixture.real_fstat(fd) for fd in (0,1,2,fixture.request_fd)}
            code, output, events = self.exercise(fixture)
            self.assertEqual((code, output), (0, b'frame'))
            self.assertEqual(events, ['context', 'sealed', 'encode', 'write'])
            self.assertFalse(fixture.active)
            for fd, before in borrowed.items():
                after = fixture.real_fstat(fd)
                self.assertEqual((after.st_dev, after.st_ino), (before.st_dev, before.st_ino))

    def test_control_drift_after_context_prevents_sealed_work(self):
        with KernelObservationFixture(self.worker) as fixture:
            code, output, events = self.exercise(fixture,
                after_context=lambda: fixture.edit(self.control, b'max\n'))
            self.assertEqual((code, output, events), (70, b'', ['context']))
            self.assertFalse(fixture.active)
            fixture.real_fstat(fixture.request_fd)

    def test_drift_during_work_or_encoding_prevents_first_frame_byte(self):
        for stage in ('during_work', 'during_encode'):
            with self.subTest(stage=stage), KernelObservationFixture(self.worker) as fixture:
                code, output, events = self.exercise(fixture,
                    **{stage: lambda: fixture.edit(self.control, b'max\n')})
                self.assertEqual((code, output), (70, b''))
                self.assertEqual(events, ['context', 'sealed', 'encode'])
                self.assertFalse(fixture.active)

    def test_late_baseexception_closes_owned_fds_and_preserves_request(self):
        for stage in ('after_context', 'during_work', 'during_encode'):
            for error in (KeyboardInterrupt, SystemExit, MemoryError):
                def fail():
                    raise error()
                with self.subTest(stage=stage, error=error.__name__), KernelObservationFixture(self.worker) as fixture:
                    code, output, events = self.exercise(fixture, **{stage: fail})
                    self.assertEqual((code, output), (70, b''))
                    self.assertNotIn('write', events)
                    self.assertFalse(fixture.active)
                    fixture.real_fstat(fixture.request_fd)

    def test_partial_pipe_write_returns_failure_and_closes_originals(self):
        with KernelObservationFixture(self.worker) as fixture:
            code, output, events = self.exercise(fixture, partial_write=True)
            self.assertEqual((code, output), (70, b'f'))
            self.assertEqual(events, ['context', 'sealed', 'encode', 'write', 'write'])
            self.assertFalse(fixture.active)

    def test_absent_selector_performs_no_new_kernel_observation(self):
        with patch.dict(os.environ, {}, clear=True), \
             patch.object(os, 'open', side_effect=AssertionError('unexpected open')), \
             patch.object(os, 'fstat', side_effect=AssertionError('unexpected fstat')), \
             patch.object(resource, 'getrlimit', side_effect=AssertionError('unexpected limit read')):
            self.assertIsNone(self.worker._open_kernel_admission(9))

    def test_real_procfs_observer_and_unsupported_abi(self):
        fd = os.open('/proc', os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            magic, flags = self.worker._kernel_filesystem(fd)
            self.assertEqual(magic, 0x9FA0)
            self.assertEqual(flags & 14, 14)
            with patch.object(os, 'uname', return_value=SimpleNamespace(machine='aarch64')):
                with self.assertRaises(ValueError):
                    self.worker._kernel_filesystem(fd)
        finally:
            os.close(fd)

    def test_persistent_cleanup_observation_failure_is_bounded_and_never_guessed(self):
        with KernelObservationFixture(self.worker) as fixture:
            guard = self.worker._open_kernel_admission(fixture.request_fd)
            target = guard.scratch
            observe = self.worker._kernel_identity
            attempts = []

            def unavailable(fd):
                if fd == target:
                    attempts.append(fd)
                    raise OSError(errno.EIO, 'observation unavailable')
                return observe(fd)

            with patch.object(self.worker, '_kernel_identity', side_effect=unavailable):
                self.assertFalse(guard.close())
                self.assertEqual(attempts, [target, target])
                self.assertEqual(set(guard.owned), {target})
                fixture.real_fstat(target)
            self.assertTrue(guard.close())
            self.assertFalse(fixture.active)

    def test_proc_metadata_budgets_and_mount_id_parsing_refuse_ambiguous_input(self):
        for payload in (b'mnt_id: 0\n', b'mnt_id: +11\n', b'mnt_id: 11\nmnt_id: 11\n',
                        b'mnt_id: 18446744073709551616\n', b'mnt_id: \xff\n',
                        b'mnt_id: 11\n' + b'x'*4096):
            with self.subTest(fdinfo=payload[:50]), KernelObservationFixture(self.worker) as fixture:
                fixture.fdinfo['/proc'] = payload
                with self.assertRaises(ValueError):
                    self.worker._open_kernel_admission(fixture.request_fd)
                self.assertFalse(fixture.active)
        for name, payload in (('status', KernelObservationFixture.STATUS + b'x'*16384),
                              ('cgroup', KernelObservationFixture.MEMBERSHIP + b'x'*4096),
                              ('mountinfo', KernelObservationFixture.MOUNTINFO + b'x'*262144)):
            with self.subTest(metadata=name), KernelObservationFixture(self.worker) as fixture:
                fixture.edit(fixture.PROC + '/' + name, payload)
                with self.assertRaises((ValueError, self.worker.scratch.PdfBoundedScratchError)):
                    self.worker._open_kernel_admission(fixture.request_fd)
                self.assertFalse(fixture.active)

    def test_admission_manifest_pins_sources_without_reidentifying_legacy_wire(self):
        manifest = json.loads((ROOT/'reporting/pdf-fixed-worker-admission.v1.json').read_text())
        self.assertEqual(self.worker.PROFILE_SHA256,
            '48701b4b85dc7f56d5ac1b5032bb71069c9d44189de3da265b59e94d3b3fead3')
        self.assertEqual(manifest['legacy_worker_profile_sha256'], self.worker.PROFILE_SHA256)
        self.assertEqual(manifest['profile'], self.worker.kernel_admission_profile())
        self.assertEqual(manifest['profile_sha256'], sha256(_json_bytes(manifest['profile'])).hexdigest())
        self.assertEqual(manifest['profile_sha256'], self.worker.KERNEL_ADMISSION_PROFILE_SHA256)
        self.assertEqual(manifest['profile']['cgroup_controls'], {
            'memory.max': '2147483648', 'memory.swap.max': '0',
            'pids.max': '32', 'cpu.max': '200000 100000'})
        self.assertEqual(manifest['profile']['process_limits'], {
            'RLIMIT_AS': [1073741824,1073741824], 'RLIMIT_CPU': [300,300],
            'RLIMIT_FSIZE': [67108864,67108864], 'RLIMIT_NOFILE': [128,128],
            'RLIMIT_CORE': [0,0]})
        self.assertEqual(set(manifest['source_sha256']), {
            'reporting/_pdf_fixed_inspection_worker.py','reporting/_pdf_bounded_scratch.py'})
        for name, expected in manifest['source_sha256'].items():
            self.assertEqual(sha256((ROOT/name).read_bytes()).hexdigest(), expected)
        for key in ('default_pipeline_activated','service_installed','dependencies_changed',
                    'native_profile_qualified','aggregate_job_resources_qualified',
                    'hard_job_deadline_enforced','descendant_cleanup_qualified',
                    'host_authenticated','release_authorized'):
            self.assertIs(manifest[key], False)


if __name__=='__main__':
    unittest.main()
