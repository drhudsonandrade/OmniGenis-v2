"""Guarded raster geometry inspection for one exact generated-PDF page interval.

The original file is rasterized without splitting or rewriting it. Only selected
pages are inspected; neither native raster output nor a matching digest qualifies
the whole document, source semantics, accessibility or release. Process-local
limits and guards do not establish aggregate job or arbitrary-descendant closure.
"""
from __future__ import annotations

from contextlib import nullcontext
import hashlib
from importlib.metadata import version
from io import BytesIO
import json
import math
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reporting import _pdf_bounded_scratch as mount_metadata
from reporting._pdf_process_sandbox import enforce_pdf_landlock, enforce_pdf_network_filter
from reporting._pdf_raster_launch_budget import RasterLaunchBudget, _require_launch_budget
from reporting._pdf_render_worker import _arm_worker_lifetime, _write_bytes
from reporting._pdf_text_window_worker import (
    IDENTITY_FIELDS, MAX_DOCUMENT_PAGES, MAX_PDF_BYTES, _is_digest,
    _read_request, _validate_identity as _text_identity,
)
from reporting._pdf_visual_worker import (
    DPI, MIN_EDGE_MARGIN_PX, MAX_PIXELS_PER_PAGE, PARSER_VERSION, PILLOW_VERSION,
    TOOL_SHA256, TOOL_VERSION, _expected_pixels, _open_trusted_scratch,
)

from reporting._pdf_raster_probe import _tool_identity

PROFILE_ID = "generated-pdf-raster-window-v1"
PROTOCOL_VERSION = 1
MAX_WINDOW_PAGES = 4
MAX_TOTAL_PIXELS = 16_000_000
MAX_PNG_BYTES = 16 * 1024 * 1024
MEMORY_BYTES = 512 * 1024 * 1024
CPU_SECONDS = 20
WALL_SECONDS = 30
PAGE_WALL_SECONDS = 8
OPEN_FILES = 128
FILE_BYTES = 64 * 1024 * 1024
RESULT_BYTES = 4096


def _validate_identity(value: object) -> None:
    """Reuse the closed plan identity while narrowing selected raster work to four pages."""
    _text_identity(value)
    if value["last_page"] - value["first_page"] + 1 > MAX_WINDOW_PAGES:
        raise ValueError("raster window admission")


def _limits() -> dict[str, int]:
    """Apply the existing raster process budgets before candidate parsing or decoding."""
    import resource
    for key, bound in ((resource.RLIMIT_AS, MEMORY_BYTES), (resource.RLIMIT_CPU, CPU_SECONDS),
                       (resource.RLIMIT_FSIZE, FILE_BYTES), (resource.RLIMIT_NOFILE, OPEN_FILES),
                       (resource.RLIMIT_CORE, 0)):
        resource.setrlimit(key, (bound, bound))
    return {"memory_bytes": resource.getrlimit(resource.RLIMIT_AS)[0],
            "cpu_seconds": resource.getrlimit(resource.RLIMIT_CPU)[0],
            "file_bytes": resource.getrlimit(resource.RLIMIT_FSIZE)[0],
            "open_files": resource.getrlimit(resource.RLIMIT_NOFILE)[0]}


def _lifetime(parent: int) -> None:
    """Bind worker lifetime to its launching parent and an independent kernel timer."""
    _arm_worker_lifetime(parent)
    signal.setitimer(signal.ITIMER_REAL, WALL_SECONDS)


def _open_scratch(fd: int) -> Path:
    """Match the inherited directory inode against the already reviewed scratch profile."""
    held = os.fstat(fd)
    if (not stat.S_ISDIR(held.st_mode) or held.st_uid != os.geteuid()
            or stat.S_IMODE(held.st_mode) != 0o700 or held.st_nlink < 1):
        raise ValueError("raster scratch descriptor")
    path, verified = _open_trusted_scratch()
    try:
        value = os.fstat(verified)
        if (value.st_dev, value.st_ino, value.st_uid) != (held.st_dev, held.st_ino, held.st_uid):
            raise ValueError("raster scratch identity")
    finally:
        os.close(verified)
    return path


def _geometry(page) -> tuple[int, int]:
    """Admit only the untransformed generated-page geometry used by this narrow profile."""
    media = tuple(float(x) for x in page.mediabox)
    crop = tuple(float(x) for x in page.cropbox)
    if (len(media) != 4 or any(not math.isfinite(x) for x in media + crop)
            or media[:2] != (0.0, 0.0) or crop != media or page.rotation != 0
            or float(page.get("/UserUnit", 1)) != 1.0):
        raise ValueError("raster page transform unsupported")
    return _expected_pixels(page)


def _raster_page(tool: str, source: Path, prefix: Path, number: int, *,
                 launch_budget: RasterLaunchBudget) -> Path:
    """Consume the selected page attempt before invoking the isolated lifetime guard."""
    metadata_args = []
    metadata_options = {}
    if mount_metadata.bounded_scratch_requested():
        fd = mount_metadata.active_mountinfo_fd()
        metadata_args = [str(fd)]
        metadata_options = {"pass_fds": (fd,)}
    command = [sys.executable, "-I", str(Path(__file__).resolve().with_name("_pdf_raster_executor.py")),
               str(os.getpid()), tool, str(source), str(prefix), str(number)] + metadata_args
    _require_launch_budget(launch_budget).consume_page(number)
    result = subprocess.run(
        command, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True,
        timeout=PAGE_WALL_SECONDS, check=False, shell=False, **metadata_options,
    )
    if result.returncode != 0:
        raise ValueError("raster executor failure")
    return Path(str(prefix) + ".png")


def _file_identity(value: os.stat_result) -> tuple[int, ...]:
    """Compare observable raster-file identity without treating access time as mutation."""
    return (value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _read_raster(path: Path, expected: tuple[int, int]) -> tuple[int, int, int, int, str]:
    """Check bounded PNG dimensions before decoding, then retain only RGB geometry and hash."""
    from PIL import Image, ImageChops
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.geteuid() or not 0 < before.st_size <= MAX_PNG_BYTES):
            raise ValueError("raster output file invalid")
        with Image.open(source) as opened:
            width, height = opened.size
            if (opened.format != "PNG" or width <= 0 or height <= 0
                    or width * height > MAX_PIXELS_PER_PAGE
                    or abs(width - expected[0]) > 1 or abs(height - expected[1]) > 1):
                raise ValueError("raster output geometry invalid")
            with opened.convert("RGB") as image, Image.new("RGB", opened.size, (255, 255, 255)) as white:
                image.load()
                with ImageChops.difference(image, white) as difference:
                    bbox = difference.getbbox()
                if bbox is None:
                    raise ValueError("raster selected page blank")
                left, top, right, bottom = bbox
                margin = min(left, top, width - right, height - bottom)
                if margin < MIN_EDGE_MARGIN_PX:
                    raise ValueError("raster selected page edge contact")
                pixel_hash = hashlib.sha256(image.tobytes()).hexdigest()
        after = os.fstat(source.fileno())
        entry = os.stat(path, follow_symlinks=False)
        if _file_identity(before) != _file_identity(after) or _file_identity(after) != _file_identity(entry):
            raise ValueError("raster output changed")
    return width, height, width * height, margin, pixel_hash


def _inspect(pdf: bytes, identity: dict, scratch: Path) -> dict:
    """Inspect every selected page, preserving the existing ordered raster-hash convention."""
    _validate_identity(identity)
    if (type(pdf) is not bytes or len(pdf) > MAX_PDF_BYTES
            or not pdf.startswith(b"%PDF-1.7") or hashlib.sha256(pdf).hexdigest() != identity["pdf_sha256"]):
        raise ValueError("raster candidate identity")
    if version("pypdf") != PARSER_VERSION or version("Pillow") != PILLOW_VERSION:
        raise ValueError("raster library identity")
    from pypdf import PdfReader
    reader = PdfReader(BytesIO(pdf), strict=True)
    if reader.is_encrypted or len(reader.pages) != identity["page_count"]:
        raise ValueError("raster physical page count")
    pages = tuple(range(identity["first_page"], identity["last_page"] + 1))
    expected = [_geometry(reader.pages[n - 1]) for n in pages]
    if sum(w * h for w, h in expected) > MAX_TOTAL_PIXELS:
        raise ValueError("raster selected pixel budget")
    launch_budget = RasterLaunchBudget(pages)
    try:
        tool_version, tool_hash, tool = _tool_identity(launch_budget=launch_budget)
        if tool_version != TOOL_VERSION or tool_hash != TOOL_SHA256:
            raise ValueError("raster executable identity")
        aggregate = hashlib.sha256()
        total_pixels = inspected = 0
        minimum = None
        with tempfile.TemporaryDirectory(prefix="raster-window-", dir=scratch) as td:
            root = Path(td); source = root / "candidate.pdf"
            source.write_bytes(pdf)
            for number, geometry in zip(pages, expected, strict=True):
                image_path = _raster_page(tool, source, root / f"page-{number}", number,
                                          launch_budget=launch_budget)
                width, height, pixels, margin, pixel_hash = _read_raster(image_path, geometry)
                total_pixels += pixels
                if total_pixels > MAX_TOTAL_PIXELS:
                    raise ValueError("raster selected pixel budget")
                aggregate.update(f"{number}:{width}:{height}:{pixel_hash}\n".encode("ascii"))
                minimum = margin if minimum is None else min(minimum, margin)
                inspected += 1
                image_path.unlink()
        launch_budget.require_complete()
        return {"status": "WINDOW_RASTER_INSPECTED", "raster_sha256": aggregate.hexdigest(),
                "inspected_pages": inspected, "total_pixels": total_pixels, "min_edge_margin_px": minimum}
    finally:
        launch_budget.close()


def main(argv: list[str] | None = None) -> int:
    """Apply mandatory guards before reading one exact request; failures emit no evidence."""
    argv = sys.argv if argv is None else argv
    if sys.platform != "linux" or len(argv) != 5:
        return 64
    try:
        request_fd, result_fd, scratch_fd, parent = map(int, argv[1:])
        if min(request_fd, result_fd, scratch_fd) < 3 or len({request_fd, result_fd, scratch_fd}) != 3:
            return 64
        infos = [os.fstat(fd) for fd in (request_fd, result_fd)]
        if any(not stat.S_ISREG(i.st_mode) or i.st_nlink != 0 or i.st_uid != os.geteuid() for i in infos):
            return 64
        if (infos[0].st_dev, infos[0].st_ino) == (infos[1].st_dev, infos[1].st_ino) or infos[1].st_size:
            return 64
        limits = _limits()
        _lifetime(parent)
        scratch = _open_scratch(scratch_fd)
        metadata = (mount_metadata.mountinfo_scope()
                    if mount_metadata.bounded_scratch_requested() else nullcontext())
        with metadata:
            enforce_pdf_landlock(Path(__file__), writable_scratch_fd=scratch_fd)
            enforce_pdf_network_filter()
            identity, pdf = _read_request(request_fd)
            inspection = _inspect(pdf, identity, scratch)
            encoded = json.dumps({"protocol_version": PROTOCOL_VERSION, "profile_id": PROFILE_ID,
                "identity": identity, "limits": limits, "inspection": inspection}, sort_keys=True,
                separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
            if not 0 < len(encoded) <= RESULT_BYTES:
                return 70
            _write_bytes(result_fd, encoded)
    except Exception:
        return 70
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
