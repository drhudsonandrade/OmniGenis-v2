"""Optional Linux child entrypoint for existing sealed-request/full-result transport.

This is a fixed ingress/egress process boundary, not an authenticated or
qualified supervisor. Independent expectations must originate from a trusted
controller. Stdin is a single bounded canonical context through a private pipe;
the source/PDF request is an existing kernel-sealed borrowed descriptor. Stdout
contains only the complete existing bounded result frame after acceptance.

The kernel parent-death signal covers only this worker, not every descendant.
Aggregate CPU/memory/wall/scratch/process enforcement, process-tree cleanup,
private caller authorization and release remain outside this module. No service
is installed, no renderer/default route is enabled and no fallback is allowed.
"""
from __future__ import annotations

import ctypes
import errno
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import resource
import stat
import sys

# Python -I runs the fixed script without trusting cwd or caller PYTHONPATH.
if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reporting import _pdf_bounded_scratch as scratch
from reporting import pdf_inspection_request as codec
from reporting import pdf_request_descriptor as descriptor
from reporting import pdf_sealed_inspection as sealed
from reporting import pdf_inspection_result_frame as frame
from reporting._pdf_bounded_scratch import (
    activate_bounded_process_temporaries,
    bounded_scratch_parent,
    bounded_scratch_requested,
)
from reporting import pdf_structured_source_job as structured
from reporting import pdf_native_source_job as native
from reporting.page_checkpoints import _json_bytes, _reject_constant, _unique_object
from reporting.bindings import _digest

PROFILE_ID='fixed-sealed-request-result-worker-v1'
MAX_CONTEXT_BYTES=codec.MAX_METADATA_BYTES
MAX_RESULT_FRAME_BYTES=frame.MAX_FRAME_BYTES
NATIVE_PROFILE_ID='fixed-sealed-request-result-worker-v2'
NATIVE_MAX_RESULT_FRAME_BYTES=frame.NATIVE_MAX_FRAME_BYTES
_DISABLE='OMNIGENIS_PDF_FIXED_INSPECTION_WORKER_DISABLED'
_KEYS=frozenset((
    'expected_worker_profile_sha256','expected_packet_sha256',
    'expected_protocol_profile_sha256','expected_namespace_id','expected_job_id',
    'expected_request_sha256','expected_descriptor_profile_sha256',
    'expected_execution_profile_sha256','expected_pdf_sha256',
    'expected_ir_sha256','expected_page_count','expected_language',
    'expected_resource_profile_sha256','expected_frame_profile_sha256',
))


def worker_profile() -> dict:
    """Expose exact fixed source/transport pins without claiming host supervision."""
    return {'schema_version':'1.0.0','profile_id':PROFILE_ID,
            'context_encoding':'EXACT_CANONICAL_NATIVE_JSON_OVER_PRIVATE_STDIN_PIPE',
            'context_keys':sorted(_KEYS),'max_context_bytes':MAX_CONTEXT_BYTES,
            'max_result_frame_bytes':MAX_RESULT_FRAME_BYTES,
            'request_profile_sha256':codec.PROFILE_SHA256,
            'descriptor_profile_sha256':descriptor.PROFILE_SHA256,
            'inspection_profile_sha256':sealed.PROFILE_SHA256,
            'result_frame_profile_sha256':frame.PROFILE_SHA256,
            'resource_profile_sha256':structured.PROFILE_SHA256,
            'independent_expectations_required':True,
            'anonymous_sealed_request_required':True,
            'stdin_pipe_required':True,'stdout_pipe_required':True,
            'parent_death_signal_for_this_worker':True,
            'descendant_cleanup_qualified':False,'origin_authenticated':False,
            'aggregate_job_resources_qualified':False,'hard_job_deadline_enforced':False,
            'release_authorized':False,'service_installed':False,
            'default_pipeline_activated':False}


PROFILE_SHA256=sha256(_json_bytes(worker_profile())).hexdigest()


def native_worker_profile() -> dict:
    """Pin one complete native request/result family without changing host policy."""
    return {**worker_profile(), 'schema_version':'2.0.0', 'profile_id':NATIVE_PROFILE_ID,
            'max_result_frame_bytes':NATIVE_MAX_RESULT_FRAME_BYTES,
            'request_profile_sha256':codec.NATIVE_PROFILE_SHA256,
            'descriptor_profile_sha256':descriptor.NATIVE_PROFILE_SHA256,
            'inspection_profile_sha256':sealed.NATIVE_PROFILE_SHA256,
            'result_frame_profile_sha256':frame.NATIVE_PROFILE_SHA256,
            'resource_profile_sha256':native.PROFILE_SHA256}


NATIVE_PROFILE_SHA256=sha256(_json_bytes(native_worker_profile())).hexdigest()


_ADMISSION_SWITCH = 'OMNIGENIS_PDF_FIXED_KERNEL_ADMISSION_V1'
_CGROUP_PATH = '/system.slice/omnigenis-pdf-fixed-inspection-v1.service'
_CGROUP_ROOT = '/sys/fs/cgroup'
_CGROUP_POLICY = {
    'memory.max': b'2147483648\n', 'memory.swap.max': b'0\n',
    'pids.max': b'32\n', 'cpu.max': b'200000 100000\n',
}
_PROCESS_LIMITS = {
    'RLIMIT_AS': (1073741824, 1073741824), 'RLIMIT_CPU': (300, 300),
    'RLIMIT_FSIZE': (67108864, 67108864), 'RLIMIT_NOFILE': (128, 128),
    'RLIMIT_CORE': (0, 0),
}
_PROC_MAGIC = 0x9FA0
_CGROUP_MAGIC = 0x63677270
_TMPFS_MAGIC = 0x01021994
_NSFS_MAGIC = 0x6E736673
_DIRECTORY_FLAGS = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


def kernel_admission_profile() -> dict:
    """Describe a separate opt-in observation policy, without changing the wire."""
    return {
        'schema_version': '1.0.0', 'profile_id': 'fixed-pdf-kernel-admission-v1',
        'selector': _ADMISSION_SWITCH, 'selector_value': '1',
        'supported_abi': 'linux-x86_64-lp64',
        'cgroup_path': _CGROUP_PATH, 'cgroup_mount': _CGROUP_ROOT,
        'cgroup_type': 'domain', 'cgroup_mount_readonly': True,
        'cgroup_controls': {key: value.decode('ascii').rstrip('\n')
                            for key, value in _CGROUP_POLICY.items()},
        'process_limits': {key: list(value) for key, value in _PROCESS_LIMITS.items()},
        'scratch_path': '/run/omnigenis-pdf-bounded-scratch',
        'scratch_bytes': 134217728, 'scratch_inodes': 4096,
        'scratch_uid': 0, 'scratch_mode': '1777',
        'scratch_mount_flags': ['nodev', 'noexec', 'nosuid'],
        'unprivileged_process_required': True, 'no_new_privileges_required': True,
        'zero_capability_sets_required': True,
        'observation_scope': 'CURRENT_PROCESS_NAMESPACES',
        'rechecks': ['BEFORE_CONTEXT', 'BEFORE_SEALED_WORK', 'BEFORE_FRAME_WRITE'],
        'retained_descriptors_required': True, 'host_authenticated': False,
        'native_profile_qualified': False, 'aggregate_job_resources_qualified': False,
        'hard_job_deadline_enforced': False, 'descendant_cleanup_qualified': False,
        'release_authorized': False, 'service_installed': False,
        'default_pipeline_activated': False,
    }


KERNEL_ADMISSION_PROFILE_SHA256 = sha256(_json_bytes(kernel_admission_profile())).hexdigest()


class _KernelStatfs(ctypes.Structure):
    """The Linux x86-64 LP64 statfs layout; other ABIs are rejected before use."""

    _fields_ = [
        ('f_type', ctypes.c_long), ('f_bsize', ctypes.c_long),
        ('f_blocks', ctypes.c_ulong), ('f_bfree', ctypes.c_ulong),
        ('f_bavail', ctypes.c_ulong), ('f_files', ctypes.c_ulong),
        ('f_ffree', ctypes.c_ulong), ('f_fsid', ctypes.c_int * 2),
        ('f_namelen', ctypes.c_long), ('f_frsize', ctypes.c_long),
        ('f_flags', ctypes.c_long), ('f_spare', ctypes.c_long * 4),
    ]


def _kernel_filesystem(fd: int) -> tuple[int, int]:
    """Observe filesystem type and flags on the open descriptor, never its name."""
    if (sys.platform != 'linux' or os.uname().machine != 'x86_64'
            or ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(ctypes.c_long) != 8
            or ctypes.sizeof(_KernelStatfs) != 120):
        raise ValueError('kernel admission ABI unavailable')
    library = ctypes.CDLL(None, use_errno=True)
    observe = library.fstatfs
    observe.argtypes = [ctypes.c_int, ctypes.POINTER(_KernelStatfs)]
    observe.restype = ctypes.c_int
    result = _KernelStatfs()
    if observe(fd, ctypes.byref(result)) != 0:
        raise OSError(ctypes.get_errno(), 'kernel admission filesystem unavailable')
    return result.f_type, result.f_flags


def _kernel_identity(fd: int) -> tuple[int, ...]:
    """Use stable inode metadata, excluding timestamps and changing occupancy."""
    info = os.fstat(fd)
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _kernel_unsigned(raw: bytes, maximum: int, *, minimum: int = 0) -> int:
    """Consume exactly one bounded canonical unsigned decimal kernel line."""
    value = raw[:-1] if raw.endswith(b'\n') else b''
    if (not value or len(value) > 20 or not value.isdigit()
            or (len(value) > 1 and value.startswith(b'0'))):
        raise ValueError('kernel admission integer invalid')
    number = int(value)
    if not minimum <= number <= maximum:
        raise ValueError('kernel admission integer outside policy')
    return number


class _KernelAdmission:
    """Own namespace-local observation FDs until the fixed worker exits.

    Snapshots detect observed drift, not transient changes between checks.
    Matching namespace-local paths do not authenticate the global host.
    """

    def __init__(self, request_fd: int):
        """Initialize ownership before any kernel descriptor can be acquired."""
        self.borrowed = frozenset((0, 1, 2, request_fd))
        self.owned = {}
        self.paths = {}
        self.mount_ids = {}
        self.namespaces = {}
        self.pid = os.getpid()
        self.parent = os.getppid()
        self.uid = os.getuid()
        self.gid = os.getgid()

    def _take(self, fd: int) -> int:
        """Record one new descriptor or close it if ownership cannot be recorded."""
        try:
            if fd in self.borrowed or fd in self.owned or os.get_inheritable(fd):
                raise ValueError('kernel admission descriptor invalid')
            self.owned[fd] = _kernel_identity(fd)
            return fd
        except BaseException:
            if fd not in self.borrowed and fd not in self.owned:
                os.close(fd)
            raise

    def _open(self, path: str, flags: int, *, parent: int | None = None) -> int:
        """Acquire only a fixed local path with explicit ownership and close-on-exec."""
        return self._take(os.open(path, flags, dir_fd=parent))

    def _close_one(self, fd: int) -> bool:
        """Retain ownership across failed observations; never close known replacements."""
        original = self.owned[fd]
        try:
            current = _kernel_identity(fd)
            if current[:2] != original[:2]:
                del self.owned[fd]
                return False
            os.close(fd)
            del self.owned[fd]
            return True
        except OSError as error:
            if error.errno == errno.EBADF:
                self.owned.pop(fd, None)
            return False
        except BaseException:
            return False

    def close(self) -> bool:
        """Bound cleanup retries; unresolved identity remains failure, never guessed."""
        complete = True
        for _ in range(2):
            for fd in tuple(self.owned):
                if not self._close_one(fd):
                    complete = False
            if not self.owned:
                break
        return complete and not self.owned

    def _directory(self, path: str, *, parent: int | None = None,
                   absolute: str, owner: int = 0) -> int:
        """Retain a nonsymlink directory with the expected nondelegated owner."""
        fd = self._open(path, _DIRECTORY_FLAGS, parent=parent)
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner
                or stat.S_IMODE(info.st_mode) & 0o022):
            raise ValueError('kernel admission directory owner or mode invalid')
        self.paths[fd] = absolute
        return fd

    def _read_at(self, directory: int, path: str, limit: int,
                 magic: int, *, mount: int | None = None) -> bytes:
        """Read through retained directories with an allocation ceiling and EOF."""
        fd = self._open(path, _READ_FLAGS, parent=directory)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_dev != os.fstat(directory).st_dev
                    or _kernel_filesystem(fd)[0] != magic
                    or (mount is not None and self._mount_id(fd) != mount)):
                raise ValueError('kernel admission metadata filesystem invalid')
            if magic == _CGROUP_MAGIC and (info.st_uid != 0 or info.st_mode & 0o022):
                raise ValueError('kernel admission delegated control invalid')
            data = bytearray()
            while True:
                block = os.read(fd, min(8192, limit + 1 - len(data)))
                if not block:
                    return bytes(data)
                data.extend(block)
                if len(data) > limit:
                    raise ValueError('kernel admission metadata budget')
        finally:
            if not self._close_one(fd):
                raise ValueError('kernel admission metadata descriptor changed')

    def _mount_id(self, fd: int) -> int:
        """Read one positive mount ID from the retained process's real fdinfo."""
        raw = self._read_at(self.process, f'fdinfo/{fd}', 4096, _PROC_MAGIC)
        values = []
        for line in raw.decode('ascii').splitlines():
            key, separator, value = line.partition(':')
            if key == 'mnt_id':
                if not separator:
                    raise ValueError('kernel admission mount ID invalid')
                values.append(_kernel_unsigned(value.strip().encode('ascii') + b'\n',
                                               2**63 - 1, minimum=1))
        if len(values) != 1:
            raise ValueError('kernel admission mount ID ambiguous')
        return values[0]

    def _proc(self, name: str, limit: int) -> bytes:
        """Bind each process observation to the retained proc mount."""
        return self._read_at(self.process, name, limit, _PROC_MAGIC,
                             mount=self.mount_ids[self.process])

    def _credentials(self) -> None:
        """Require stable unprivileged IDs and kernel-reported process protections."""
        if (self.uid <= 0 or self.gid <= 0 or self.parent <= 1
                or os.getresuid() != (self.uid,) * 3
                or os.getresgid() != (self.gid,) * 3
                or os.getpid() != self.pid or os.getppid() != self.parent):
            raise ValueError('kernel admission process identity invalid')
        required = {
            'Pid': [str(self.pid)], 'Tgid': [str(self.pid)], 'PPid': [str(self.parent)],
            'Uid': [str(self.uid)] * 4, 'Gid': [str(self.gid)] * 4,
            'NoNewPrivs': ['1'],
            **{key: ['0000000000000000']
               for key in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')},
        }
        found = {}
        for line in self._proc('status', 16384).decode('ascii').splitlines():
            key, separator, value = line.partition(':')
            if key in required:
                if not separator or key in found:
                    raise ValueError('kernel admission status ambiguous')
                found[key] = value.split()
        if found != required:
            raise ValueError('kernel admission process protections invalid')

    def _mount_record(self, lines: list[str], destination: str, fd: int,
                      kind: str, flags: frozenset[str]) -> None:
        """Require one whole-filesystem mapping for a retained mount descriptor."""
        info = os.fstat(fd)
        found = []
        for line in lines:
            head, separator, tail = line.partition(' - ')
            fields = head.split()
            if len(fields) > 4 and fields[4] == destination:
                detail = tail.split()
                if (not separator or len(fields) < 6 or len(detail) != 3
                        or fields[0] != str(self.mount_ids[fd])
                        or fields[2] != f'{os.major(info.st_dev)}:{os.minor(info.st_dev)}'
                        or fields[3] != '/' or detail[0] != kind
                        or (kind == 'tmpfs' and detail[1] != 'tmpfs')
                        or not flags <= frozenset(fields[5].split(','))):
                    raise ValueError('kernel admission mount mapping invalid')
                found.append(fields)
        if len(found) != 1:
            raise ValueError('kernel admission mount mapping ambiguous')

    def _mounts(self) -> None:
        """Reject namespace-local mount substitutions and nested observation mounts."""
        lines = self._proc('mountinfo', 262144).decode('ascii', 'surrogateescape').splitlines()
        self._mount_record(lines, '/proc', self.proc, 'proc', frozenset({'nosuid', 'nodev', 'noexec'}))
        self._mount_record(lines, _CGROUP_ROOT, self.cgroup, 'cgroup2',
                           frozenset({'ro', 'nosuid', 'nodev', 'noexec'}))
        self._mount_record(lines, str(scratch._PARENT), self.scratch, 'tmpfs',
                           frozenset({'rw', 'nosuid', 'nodev', 'noexec'}))
        roots = (_CGROUP_ROOT + '/', str(scratch._PARENT) + '/', f'/proc/{self.pid}/')
        for line in lines:
            fields = line.partition(' - ')[0].split()
            if len(fields) > 4 and (fields[4] == f'/proc/{self.pid}'
                    or any(fields[4].startswith(root) for root in roots)):
                raise ValueError('kernel admission overmount invalid')
        for fd, magic, required_flags, forbidden_flags in (
            (self.proc, _PROC_MAGIC, 14, 0),
            (self.process, _PROC_MAGIC, 14, 0),
            (self.cgroup, _CGROUP_MAGIC, 15, 0),
            (self.scratch, _TMPFS_MAGIC, 14, 1),
        ):
            actual, flags = _kernel_filesystem(fd)
            if actual != magic or flags & required_flags != required_flags or flags & forbidden_flags:
                raise ValueError('kernel admission filesystem policy invalid')

    def _policy(self) -> None:
        """Observe finite limits and current occupancy without configuring the host."""
        if self._proc('cgroup', 4096) != ('0::' + _CGROUP_PATH + '\n').encode('ascii'):
            raise ValueError('kernel admission cgroup membership invalid')
        mount = self.mount_ids[self.cgroup]
        for name, expected in {'cgroup.type': b'domain\n', **_CGROUP_POLICY}.items():
            if self._read_at(self.cgroup, name, 64, _CGROUP_MAGIC, mount=mount) != expected:
                raise ValueError('kernel admission cgroup policy invalid')
        for name, maximum, minimum in (
            ('memory.current', 2147483648, 0), ('memory.swap.current', 0, 0),
            ('pids.current', 32, 1),
        ):
            _kernel_unsigned(self._read_at(self.cgroup, name, 64, _CGROUP_MAGIC,
                                          mount=mount), maximum, minimum=minimum)
        for name, expected in _PROCESS_LIMITS.items():
            if resource.getrlimit(getattr(resource, name)) != expected:
                raise ValueError('kernel admission inherited process limit invalid')
        usage = os.fstatvfs(self.scratch)
        if usage.f_blocks * usage.f_frsize != 134217728 or usage.f_files != 4096:
            raise ValueError('kernel admission scratch capacity invalid')
        info = os.fstat(self.scratch)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o1777:
            raise ValueError('kernel admission scratch owner or mode invalid')

    def admit(self) -> None:
        """Acquire real fixed observations before consuming any context or request."""
        for fd in self.borrowed:
            os.fstat(fd)
        if (self.uid <= 0 or self.gid <= 0 or not bounded_scratch_requested()
                or os.environ.get('TMPDIR') != str(scratch._PARENT)):
            raise ValueError('kernel admission scratch selection invalid')
        self.proc = self._directory('/proc', absolute='/proc')
        if _kernel_filesystem(self.proc)[0] != _PROC_MAGIC:
            raise ValueError('kernel admission procfs unavailable')
        if os.readlink('self', dir_fd=self.proc) != str(self.pid):
            raise ValueError('kernel admission procfs belongs to another process view')
        self.process = self._directory(str(self.pid), parent=self.proc,
                                       absolute=f'/proc/{self.pid}', owner=self.uid)
        if _kernel_filesystem(self.process)[0] != _PROC_MAGIC:
            raise ValueError('kernel admission process procfs unavailable')
        self.ns = self._directory('ns', parent=self.process,
                                  absolute=f'/proc/{self.pid}/ns', owner=self.uid)
        for name in ('mnt', 'cgroup', 'pid', 'user'):
            fd = self._open(name, os.O_RDONLY | os.O_CLOEXEC, parent=self.ns)
            if _kernel_filesystem(fd)[0] != _NSFS_MAGIC:
                raise ValueError('kernel admission namespace unavailable')
            self.namespaces[name] = fd
        parent = self._directory('/', absolute='/')
        absolute = ''
        for component in (_CGROUP_ROOT + _CGROUP_PATH).split('/')[1:]:
            absolute += '/' + component
            parent = self._directory(component, parent=parent, absolute=absolute)
        self.cgroup = parent
        self.scratch = self._take(scratch._open_verified_bounded_parent()[0])
        self.paths[self.scratch] = str(scratch._PARENT)
        for fd in tuple(self.owned):
            self.mount_ids[fd] = self._mount_id(fd)
        self.recheck()

    def recheck(self) -> None:
        """Revalidate original references, current names and policy at a snapshot."""
        if sha256(_json_bytes(kernel_admission_profile())).hexdigest() != KERNEL_ADMISSION_PROFILE_SHA256:
            raise ValueError('kernel admission profile changed')
        if (os.environ.get(_ADMISSION_SWITCH) != '1' or not bounded_scratch_requested()
                or os.environ.get('TMPDIR') != str(scratch._PARENT)):
            raise ValueError('kernel admission selection changed')
        if (_kernel_identity(self.proc) != self.owned[self.proc]
                or os.readlink('self', dir_fd=self.proc) != str(self.pid)):
            raise ValueError('kernel admission current procfs view changed')
        for fd, identity in tuple(self.owned.items()):
            if (_kernel_identity(fd) != identity or os.get_inheritable(fd)
                    or self._mount_id(fd) != self.mount_ids[fd]):
                raise ValueError('kernel admission retained descriptor changed')
        for fd, path in self.paths.items():
            info = os.stat(path, follow_symlinks=False)
            if (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid) != self.owned[fd]:
                raise ValueError('kernel admission current path changed')
        for name, original in self.namespaces.items():
            fd = self._open(name, os.O_RDONLY | os.O_CLOEXEC, parent=self.ns)
            try:
                if _kernel_filesystem(fd)[0] != _NSFS_MAGIC or self.owned[fd] != self.owned[original]:
                    raise ValueError('kernel admission current namespace changed')
            finally:
                if not self._close_one(fd):
                    raise ValueError('kernel admission namespace descriptor changed')
        self._credentials()
        self._mounts()
        self._policy()


def _open_kernel_admission(request_fd: int) -> _KernelAdmission | None:
    """Leave the legacy route untouched unless the one optional policy is selected."""
    value = os.environ.get(_ADMISSION_SWITCH)
    if value is None:
        return None
    if value != '1':
        raise ValueError('kernel admission selector invalid')
    admission = _KernelAdmission(request_fd)
    try:
        admission.admit()
        return admission
    except BaseException:
        admission.close()
        raise


def _profile(expected: object) -> bool:
    """Reject an unpinned or disabled worker before accessing request content."""
    _digest(expected)
    if expected==NATIVE_PROFILE_SHA256:
        if (sys.platform!='linux' or os.environ.get(_DISABLE)=='1'
                or sha256(_json_bytes(native_worker_profile())).hexdigest()!=NATIVE_PROFILE_SHA256
                or MAX_CONTEXT_BYTES!=codec.MAX_METADATA_BYTES
                or NATIVE_MAX_RESULT_FRAME_BYTES!=frame.NATIVE_MAX_FRAME_BYTES):
            raise ValueError('native fixed inspection worker profile invalid')
        sealed._profile(sealed.NATIVE_PROFILE_SHA256,descriptor.NATIVE_PROFILE_SHA256,
                        codec.NATIVE_PROFILE_SHA256)
        frame._profile(frame.NATIVE_PROFILE_SHA256)
        return True
    if (sys.platform!='linux' or os.environ.get(_DISABLE)=='1'
            or expected!=PROFILE_SHA256
            or sha256(_json_bytes(worker_profile())).hexdigest()!=PROFILE_SHA256
            or MAX_CONTEXT_BYTES!=codec.MAX_METADATA_BYTES
            or MAX_RESULT_FRAME_BYTES!=frame.MAX_FRAME_BYTES):
        raise ValueError('fixed inspection worker profile invalid')
    sealed._profile(sealed.PROFILE_SHA256,descriptor.PROFILE_SHA256,codec.PROFILE_SHA256)
    frame._profile(frame.PROFILE_SHA256)
    return False


def _parse_context(raw: object) -> dict:
    """Read only independently expected bounded canonical metadata; no PDF bytes."""
    if (type(raw) is not bytes or not 0<len(raw)<=MAX_CONTEXT_BYTES):
        raise ValueError('fixed worker context budget')
    codec.snapshot._scan_json_budget(raw)
    data=json.loads(raw.decode('utf-8'),object_pairs_hook=_unique_object,
                    parse_constant=_reject_constant)
    if type(data) is not dict or set(data)!=_KEYS or _json_bytes(data)!=raw:
        raise ValueError('fixed worker context not canonical')
    selected_native=_profile(data['expected_worker_profile_sha256'])
    for key,value in data.items():
        if key.endswith('sha256'):
            _digest(value)
    pins = {
        'expected_protocol_profile_sha256':codec.NATIVE_PROFILE_SHA256 if selected_native else codec.PROFILE_SHA256,
        'expected_descriptor_profile_sha256':descriptor.NATIVE_PROFILE_SHA256 if selected_native else descriptor.PROFILE_SHA256,
        'expected_execution_profile_sha256':sealed.NATIVE_PROFILE_SHA256 if selected_native else sealed.PROFILE_SHA256,
        'expected_resource_profile_sha256':native.PROFILE_SHA256 if selected_native else structured.PROFILE_SHA256,
        'expected_frame_profile_sha256':frame.NATIVE_PROFILE_SHA256 if selected_native else frame.PROFILE_SHA256,
    }
    if (type(data['expected_page_count']) is not int
            or not 1<=data['expected_page_count']<=structured.MAX_PAGES
            or data['expected_language']!=structured.LANGUAGE
            or any(data[key]!=value for key,value in pins.items())):
        raise ValueError('fixed worker context profile mismatch')
    return data


def _parent_lifetime(expected_parent: int) -> None:
    """Require actual Linux parent identity and SIGKILL on this worker's parent death."""
    if (type(expected_parent) is not int or expected_parent<=1
            or os.getppid()!=expected_parent):
        raise ValueError('worker launched from unexpected parent')
    libc=ctypes.CDLL(None,use_errno=True)
    prctl=libc.prctl
    prctl.restype=ctypes.c_int
    prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,
                    ctypes.c_ulong,ctypes.c_ulong]
    if prctl(1,signal.SIGKILL,0,0,0)!=0:
        raise OSError(ctypes.get_errno(),'worker parent-death guard failed')
    if os.getppid()!=expected_parent:
        raise ValueError('worker parent changed while arming lifetime')


def _read_pipe() -> bytes:
    """Bound context allocation and require one terminated private stdin pipe."""
    data=bytearray()
    while True:
        block=os.read(0,min(8192,MAX_CONTEXT_BYTES+1-len(data)))
        if not block:
            return bytes(data)
        data.extend(block)
        if len(data)>MAX_CONTEXT_BYTES:
            raise ValueError('worker context exceeds fixed limit')


def _write_frame(data: bytes, selected_native: bool=False) -> None:
    """Write only the complete framed result; a partial pipe is never acceptance."""
    maximum=NATIVE_MAX_RESULT_FRAME_BYTES if selected_native else MAX_RESULT_FRAME_BYTES
    if type(data) is not bytes or not 0<len(data)<=maximum:
        raise ValueError('worker output budget')
    pending=memoryview(data)
    while pending:
        count=os.write(1,pending)
        if type(count) is not int or count<=0:
            raise ValueError('worker output incomplete')
        pending=pending[count:]


def _entrypoint() -> int:
    """Bind the fixed opt-in parent before entering the dedicated worker."""
    try:
        if bounded_scratch_requested():
            os.environ["TMPDIR"]=str(bounded_scratch_parent())
    except BaseException:
        return 70
    return main()


def main(argv: list[str] | None=None) -> int:
    """Run exactly one fixed sealed inspection with no partial successful stdout."""
    args=sys.argv if argv is None else argv
    if len(args)!=3:
        return 64
    admission=None
    status=70
    try:
        if (sys.platform!='linux' or os.environ.get(_DISABLE)=='1'
                or not args[1].isascii() or not args[1].isdecimal()
                or not args[2].isascii() or not args[2].isdecimal()):
            return 70
        request_fd=int(args[1]);parent_pid=int(args[2])
        if (request_fd<3 or request_fd>2**31-1 or parent_pid<=1
                or not stat.S_ISFIFO(os.fstat(0).st_mode)
                or not stat.S_ISFIFO(os.fstat(1).st_mode)):
            return 70
        _parent_lifetime(parent_pid)
        admission=_open_kernel_admission(request_fd)
        expected=_parse_context(_read_pipe())
        activate_bounded_process_temporaries()
        if admission is not None:
            admission.recheck()
        original=sealed.execute_sealed_pdf_inspection_job(
            request_fd, expected_packet_sha256=expected['expected_packet_sha256'],
            expected_protocol_profile_sha256=expected['expected_protocol_profile_sha256'],
            expected_namespace_id=expected['expected_namespace_id'],
            expected_job_id=expected['expected_job_id'],
            expected_request_sha256=expected['expected_request_sha256'],
            expected_descriptor_profile_sha256=expected['expected_descriptor_profile_sha256'],
            expected_execution_profile_sha256=expected['expected_execution_profile_sha256'])
        result_context={
            'expected_pdf_sha256':expected['expected_pdf_sha256'],
            'expected_ir_sha256':expected['expected_ir_sha256'],
            'expected_page_count':expected['expected_page_count'],
            'expected_language':expected['expected_language'],
            'expected_namespace_id':expected['expected_namespace_id'],
            'expected_job_id':expected['expected_job_id'],
            'expected_request_sha256':expected['expected_request_sha256'],
            'expected_resource_profile_sha256':expected['expected_resource_profile_sha256'],
            'expected_frame_profile_sha256':expected['expected_frame_profile_sha256'],
        }
        result=frame.encode_pdf_inspection_result_frame(original,**result_context)
        if frame.decode_pdf_inspection_result_frame(result,**result_context)!=original.to_bytes():
            raise ValueError('worker result frame identity mismatch')
        selected_native=_profile(expected['expected_worker_profile_sha256'])
        if admission is not None:
            admission.recheck()
        if selected_native:
            _write_frame(result, selected_native=True)
        else:
            _write_frame(result)
        status=0
    except BaseException:
        status=70
    finally:
        try:
            if admission is not None and not admission.close():
                status=70
        except BaseException:
            status=70
    return status


if __name__=='__main__':
    raise SystemExit(_entrypoint())
