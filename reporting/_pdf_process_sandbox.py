"""Linux PDF worker filesystem and syscall guards (partial isolation).

Landlock limits newly opened filesystem paths and TCP operations. The separate
x86_64 seccomp-BPF filter denies new network-related syscalls, including UDP.
Pre-opened descriptors and aggregate process-tree resources are not covered.
No host security settings are modified.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import platform
import sys


PROFILE_ID = "omnigenis-generated-pdf-landlock-v1"
MIN_LANDLOCK_ABI = 4
_HANDLED_FS = (1 << 15) - 1  # ABI 4: EXECUTE through TRUNCATE
_READ_DIR_ACCESS = (1 << 0) | (1 << 2) | (1 << 3)
_READ_FILE_ACCESS = (1 << 0) | (1 << 2)
_HANDLED_NET = (1 << 0) | (1 << 1)  # TCP bind and connect, not UDP


class _Ruleset(ctypes.Structure):
    """Layout from linux/landlock.h for Landlock ABI 4."""

    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
    ]


class _PathBeneath(ctypes.Structure):
    """Layout from linux/landlock.h for path-beneath rules."""

    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int),
        ("reserved", ctypes.c_uint32),
    ]


def _linux_syscall(number: int, *args) -> int:
    """Invoke one fixed Landlock syscall, never passing caller-supplied code."""
    return ctypes.CDLL(None, use_errno=True).syscall(ctypes.c_long(number), *args)


def landlock_abi_version() -> int:
    """Query kernel support without attaching a process policy."""
    if sys.platform != "linux" or platform.machine() != "x86_64":
        return 0
    value = _linux_syscall(444, ctypes.c_void_p(), ctypes.c_size_t(), ctypes.c_uint(1))
    return value if value >= 0 else 0


def _read_roots(worker_script: Path) -> tuple[Path, ...]:
    """Resolve approved fixed runtime/deployment roots before restriction."""
    source_root = worker_script.resolve(strict=True).parents[1]
    prefix = Path(sys.prefix).resolve(strict=True)
    base_prefix = Path(sys.base_prefix).resolve(strict=True)
    requested = (
        source_root,
        prefix,
        base_prefix,
        Path("/usr"),
        Path("/lib"),
        Path("/lib64"),
        Path("/etc/fonts"),
        Path("/etc/ld.so.cache"),
        Path("/etc/localtime"),
        Path("/etc/mime.types"),  # Standard library mimetypes used by WeasyPrint.
        Path("/var/cache/fontconfig"),
        Path("/dev/null"),
        Path("/dev/urandom"),
    )
    unique: dict[str, Path] = {}
    for item in requested:
        try:
            resolved = item.resolve(strict=True)
        except FileNotFoundError:
            continue  # Optional OS asset not present in the fixed profile.
        if not resolved.is_dir() and not resolved.is_file():
            continue
        unique[str(resolved)] = resolved
    if str(source_root) not in unique or str(prefix) not in unique:
        raise RuntimeError("pdf_sandbox_unavailable")
    return tuple(unique.values())


def enforce_pdf_landlock(worker_script: Path) -> None:
    """Fail closed unless kernel-enforced read roots and TCP restrictions apply.

    Called only inside one disposable PDF worker after lifecycle and resource
    limits are installed, before reading any candidate request. Inherited
    anonymous request/output descriptors remain intentionally usable.
    """
    if landlock_abi_version() < MIN_LANDLOCK_ABI:
        raise RuntimeError("pdf_sandbox_unavailable")
    try:
        roots = _read_roots(worker_script)
        ruleset_attr = _Ruleset(_HANDLED_FS, _HANDLED_NET)
        ruleset_fd = _linux_syscall(
            444, ctypes.byref(ruleset_attr), ctypes.c_size_t(ctypes.sizeof(ruleset_attr)),
            ctypes.c_uint(0),
        )
        if ruleset_fd < 0:
            raise RuntimeError("pdf_sandbox_unavailable")
        try:
            for root in roots:
                path_fd = os.open(root, os.O_PATH | os.O_CLOEXEC)
                try:
                    access = _READ_DIR_ACCESS if root.is_dir() else _READ_FILE_ACCESS
                    rule = _PathBeneath(access, path_fd, 0)
                    if _linux_syscall(
                        445, ctypes.c_int(ruleset_fd), ctypes.c_int(1),
                        ctypes.byref(rule), ctypes.c_uint(0),
                    ) < 0:
                        raise RuntimeError("pdf_sandbox_unavailable")
                finally:
                    os.close(path_fd)
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.prctl(
                ctypes.c_int(38), ctypes.c_ulong(1), ctypes.c_ulong(0),
                ctypes.c_ulong(0), ctypes.c_ulong(0),
            ) != 0:
                raise RuntimeError("pdf_sandbox_unavailable")
            if _linux_syscall(
                446, ctypes.c_int(ruleset_fd), ctypes.c_uint(0)
            ) < 0:
                raise RuntimeError("pdf_sandbox_unavailable")
        finally:
            os.close(ruleset_fd)
    except (OSError, ValueError, TypeError) as exc:
        raise RuntimeError("pdf_sandbox_unavailable") from exc


NETWORK_PROFILE_ID = "omnigenis-generated-pdf-seccomp-network-v1"

# Linux x86_64 syscall numbers from asm/unistd_64.h, pinned to this profile.
# This list restricts creation and use of new socket syscalls, plus io_uring
# which can otherwise submit network operations through a different entrypoint.
# Already-open descriptors, direct write(2) and all other syscalls remain outside
# this narrow control and MUST NOT be described as full network isolation.
_DENIED_NETWORK_SYSCALLS = {
    "socket": 41, "connect": 42, "accept": 43, "sendto": 44,
    "recvfrom": 45, "sendmsg": 46, "recvmsg": 47, "shutdown": 48,
    "bind": 49, "listen": 50, "getsockname": 51, "getpeername": 52,
    "socketpair": 53, "setsockopt": 54, "getsockopt": 55,
    "accept4": 288, "recvmmsg": 299, "sendmmsg": 307,
    "io_uring_setup": 425, "io_uring_enter": 426,
    "io_uring_register": 427,
}


class _SockFilter(ctypes.Structure):
    """Classical seccomp BPF instruction; Linux sock_filter layout."""

    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    """Linux sock_fprog with an owned array held alive for prctl()."""

    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.POINTER(_SockFilter)),
    ]


def enforce_pdf_network_filter() -> None:
    """Attach the pinned seccomp filter to this single disposable worker.

    This must execute after startup and Landlock setup but before any PDF
    request is processed. Unsupported architectures, filtered prctl() and
    unexpected kernel responses fail closed. No host/global policy is changed.
    """
    if sys.platform != "linux" or platform.machine() != "x86_64":
        raise RuntimeError("pdf_network_filter_unavailable")
    try:
        # Load seccomp_data.arch and reject all non-AMD64 syscall ABI values.
        # Reject x32 syscall-bit invocations to avoid filtering only one ABI.
        instructions = [
            (0x20, 0, 0, 4),                 # LD W ABS arch
            (0x15, 1, 0, 0xC000003E),       # JEQ AUDIT_ARCH_X86_64
            (0x06, 0, 0, 0x80000000),       # RET KILL_PROCESS
            (0x20, 0, 0, 0),               # LD W ABS syscall_nr
            (0x45, 0, 1, 0x40000000),       # JSET x32_syscall_bit
            (0x06, 0, 0, 0x80000000),       # RET KILL_PROCESS
        ]
        for syscall in sorted(_DENIED_NETWORK_SYSCALLS.values()):
            instructions.extend([
                (0x15, 0, 1, syscall),        # JEQ network syscall
                (0x06, 0, 0, 0x00050000 | 1), # RET ERRNO(EPERM)
            ])
        instructions.append((0x06, 0, 0, 0x7FFF0000))  # RET ALLOW
        filters = (_SockFilter * len(instructions))(
            *(_SockFilter(*row) for row in instructions)
        )
        program = _SockFprog(len(instructions), filters)
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(
            ctypes.c_int(38), ctypes.c_ulong(1), ctypes.c_ulong(0),
            ctypes.c_ulong(0), ctypes.c_ulong(0),
        ) != 0:
            raise RuntimeError("pdf_network_filter_unavailable")
        if libc.prctl(
            ctypes.c_int(22), ctypes.c_ulong(2), ctypes.byref(program),
            ctypes.c_ulong(0), ctypes.c_ulong(0),
        ) != 0:
            raise RuntimeError("pdf_network_filter_unavailable")
    except (OSError, TypeError, ValueError, ctypes.ArgumentError) as exc:
        raise RuntimeError("pdf_network_filter_unavailable") from exc
