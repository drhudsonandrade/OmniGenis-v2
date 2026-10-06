"""Resource-limited raster geometry inspection for generated report PDFs."""
from __future__ import annotations

import hashlib
from importlib.metadata import version
from io import BytesIO
import json
import math
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

MAX_PDF_BYTES=8*1024*1024
MAX_PAGES=32
DPI=96
MAX_PIXELS_PER_PAGE=4_000_000
MAX_TOTAL_PIXELS=32_000_000
MIN_EDGE_MARGIN_PX=2
MEMORY_BYTES=512*1024*1024
CPU_SECONDS=20
WALL_SECONDS=30
PAGE_WALL_SECONDS=8
PARSER_VERSION="6.19.0"
PILLOW_VERSION="12.3.0"
TOOL_VERSION="24.02.0"
TOOL_SHA256="207dcabcaeea0ce572aefc498d07d44d56a9ca06a85b3ae1fecd050476a34bf8"
ENGINE_ID="poppler-pdftoppm-raster-v1"

ERRORS=frozenset({
    "pdf_visual_structure_invalid","encrypted_pdf_forbidden","pdf_visual_budget_exceeded",
    "pdf_visual_executor_mismatch","pdf_visual_library_mismatch","pdf_visual_raster_failed",
    "pdf_visual_blank_page","pdf_visual_edge_contact","pdf_visual_geometry_mismatch",
    "pdf_visual_worker_unavailable",
})


def blocked(error: str,pdf_digest: str|None=None) -> dict:
    """Return a bounded failure record without image or report content."""
    return {
        "status":"BLOCKED","pdf_sha256":pdf_digest,"page_count":None,
        "raster_sha256":None,"min_edge_margin_px":None,"total_pixels":None,
        "errors":[error],
    }


def _tool_identity() -> tuple[str,str,str]:
    """Resolve the activated raster executable and return version, digest, and path."""
    tool=shutil.which("pdftoppm")
    if not tool:
        raise OSError("pdftoppm unavailable")
    path=Path(tool).resolve()
    binary_hash=hashlib.sha256(path.read_bytes()).hexdigest()
    process=subprocess.run(
        [str(path),"-v"],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
        timeout=3,check=False,
    )
    if process.returncode != 0:
        raise OSError("pdftoppm version failed")
    first=process.stdout.decode("utf-8","strict").splitlines()[0].strip()
    prefix="pdftoppm version "
    if not first.startswith(prefix):
        raise OSError("pdftoppm version invalid")
    return first[len(prefix):],binary_hash,str(path)


def _expected_pixels(page) -> tuple[int,int]:
    """Convert a finite positive PDF media box into the activated raster geometry."""
    width=float(page.mediabox.width); height=float(page.mediabox.height)
    if not math.isfinite(width) or not math.isfinite(height) or width<=0 or height<=0:
        raise ValueError("invalid page geometry")
    px=(round(width*DPI/72),round(height*DPI/72))
    if px[0]<=0 or px[1]<=0 or px[0]*px[1]>MAX_PIXELS_PER_PAGE:
        raise OverflowError("page pixel budget")
    return px


def inspect_visual_geometry(pdf: bytes) -> dict:
    """Rasterize every page under fixed profile and retain only geometry/digest evidence."""
    if len(pdf)>MAX_PDF_BYTES:
        return blocked("pdf_visual_budget_exceeded")
    pdf_digest=hashlib.sha256(pdf).hexdigest()
    if not pdf.startswith(b"%PDF-"):
        return blocked("pdf_visual_structure_invalid",pdf_digest)
    try:
        if version("pypdf")!=PARSER_VERSION or version("Pillow")!=PILLOW_VERSION:
            return blocked("pdf_visual_library_mismatch",pdf_digest)
        from pypdf import PdfReader
        from PIL import Image,ImageChops
    except (ImportError,OSError):
        return blocked("pdf_visual_library_mismatch",pdf_digest)
    try:
        tool_version,tool_hash,tool=_tool_identity()
    except (OSError,UnicodeError):
        return blocked("pdf_visual_executor_mismatch",pdf_digest)
    if tool_version!=TOOL_VERSION or tool_hash!=TOOL_SHA256:
        return blocked("pdf_visual_executor_mismatch",pdf_digest)
    try:
        reader=PdfReader(BytesIO(pdf),strict=True)
        if reader.is_encrypted:
            return blocked("encrypted_pdf_forbidden",pdf_digest)
        page_count=len(reader.pages)
        if page_count<1:
            return blocked("pdf_visual_structure_invalid",pdf_digest)
        if page_count>MAX_PAGES:
            return blocked("pdf_visual_budget_exceeded",pdf_digest)
        expected=[_expected_pixels(page) for page in reader.pages]
        if sum(w*h for w,h in expected)>MAX_TOTAL_PIXELS:
            return blocked("pdf_visual_budget_exceeded",pdf_digest)
    except OverflowError:
        return blocked("pdf_visual_budget_exceeded",pdf_digest)
    except Exception:
        return blocked("pdf_visual_structure_invalid",pdf_digest)

    total_pixels=0
    min_margin=None
    aggregate=hashlib.sha256()
    try:
        with tempfile.TemporaryDirectory(prefix="omnigenis-pdf-visual-") as td:
            root=Path(td)
            source=root/"candidate.pdf"
            source.write_bytes(pdf)
            for index,(expected_width,expected_height) in enumerate(expected,1):
                prefix=root/f"page-{index}"
                process=subprocess.run(
                    [tool,"-f",str(index),"-l",str(index),"-singlefile",
                     "-r",str(DPI),"-png",str(source),str(prefix)],
                    stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                    timeout=PAGE_WALL_SECONDS,check=False,
                )
                image_path=Path(str(prefix)+".png")
                if process.returncode!=0 or not image_path.is_file():
                    return blocked("pdf_visual_raster_failed",pdf_digest)
                with Image.open(image_path) as opened:
                    image=opened.convert("RGB")
                    image.load()
                width,height=image.size
                if abs(width-expected_width)>1 or abs(height-expected_height)>1:
                    return blocked("pdf_visual_geometry_mismatch",pdf_digest)
                pixels=width*height
                total_pixels+=pixels
                if pixels>MAX_PIXELS_PER_PAGE or total_pixels>MAX_TOTAL_PIXELS:
                    return blocked("pdf_visual_budget_exceeded",pdf_digest)
                white=Image.new("RGB",image.size,(255,255,255))
                bbox=ImageChops.difference(image,white).getbbox()
                if bbox is None:
                    return blocked("pdf_visual_blank_page",pdf_digest)
                left,top,right,bottom=bbox
                margin=min(left,top,width-right,height-bottom)
                if margin<MIN_EDGE_MARGIN_PX:
                    return blocked("pdf_visual_edge_contact",pdf_digest)
                min_margin=margin if min_margin is None else min(min_margin,margin)
                page_digest=hashlib.sha256(image.tobytes()).hexdigest()
                aggregate.update(
                    f"{index}:{width}:{height}:{page_digest}\n".encode("ascii")
                )
    except subprocess.TimeoutExpired:
        return blocked("pdf_visual_raster_failed",pdf_digest)
    except (OSError,ValueError,MemoryError):
        return blocked("pdf_visual_raster_failed",pdf_digest)

    return {
        "status":"PASS","pdf_sha256":pdf_digest,"page_count":page_count,
        "raster_sha256":aggregate.hexdigest(),"min_edge_margin_px":min_margin,
        "total_pixels":total_pixels,"errors":[],
    }


def main() -> None:
    """Apply Linux limits before parsing or invoking the external rasterizer."""
    try:
        if sys.platform!="linux":
            raise OSError("unsupported execution profile")
        import resource
        resource.setrlimit(resource.RLIMIT_AS,(MEMORY_BYTES,MEMORY_BYTES))
        resource.setrlimit(resource.RLIMIT_CPU,(CPU_SECONDS,CPU_SECONDS))
        resource.setrlimit(resource.RLIMIT_FSIZE,(64*1024*1024,64*1024*1024))
        resource.setrlimit(resource.RLIMIT_NOFILE,(64,64))
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    except (ImportError,OSError,ValueError):
        response=blocked("pdf_visual_worker_unavailable")
    else:
        try:
            response=inspect_visual_geometry(sys.stdin.buffer.read(MAX_PDF_BYTES+1))
        except Exception:
            response=blocked("pdf_visual_structure_invalid")
    sys.stdout.write(json.dumps(response,sort_keys=True)+"\n")


if __name__=="__main__":
    main()
