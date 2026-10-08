"""Contract tests for bounded raster visual QA of generated PDF candidates."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
import importlib
import importlib.util
from io import BytesIO
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from pypdf import PdfWriter
from pypdf.generic import DecodedStreamObject, NameObject

from reporting.adapters import build_html_css_and_pdf_adapter

ROOT=Path(__file__).resolve().parents[1]
ENGINE=ROOT/"reporting"/"pdf-visual-engine.v1.json"


def digest(data: bytes) -> str:
    """Return the SHA-256 identity of synthetic candidate bytes."""
    return hashlib.sha256(data).hexdigest()


def source_ir() -> dict:
    """Return a small localized synthetic report with no real genomic data."""
    return {
        "report_id":"synthetic-visual-report","locale_id":"en-US",
        "components":[{
            "component_id":"summary","component_type":"semantic-section",
            "title":"Summary","state":"PRESENT","content":{"text":"SYNTHETIC-ONLY"},
        }],
    }


def render(ir: dict) -> bytes:
    """Render candidate bytes through the public PDF adapter."""
    result=build_html_css_and_pdf_adapter(presentation_ir=ir)
    if not result.passed:
        raise AssertionError(result.errors)
    return result.pdf_bytes


def serialize(writer: PdfWriter) -> bytes:
    """Serialize an in-memory synthetic PDF fixture."""
    out=BytesIO(); writer.write(out); return out.getvalue()


def blank_pdf(*, pages: int=1, encrypted: bool=False, width: float=612, height: float=792) -> bytes:
    """Build blank synthetic pages without tracked PDF fixtures."""
    writer=PdfWriter()
    for _ in range(pages):
        writer.add_blank_page(width=width,height=height)
    if encrypted:
        writer.encrypt("synthetic-only")
    return serialize(writer)


def edge_ink_pdf() -> bytes:
    """Draw a black rectangle directly against the lower-left page boundary."""
    writer=PdfWriter(); page=writer.add_blank_page(width=612,height=792)
    stream=DecodedStreamObject(); stream.set_data(b"0 0 612 8 re f\n")
    page[NameObject("/Contents")]=writer._add_object(stream)
    return serialize(writer)


class PopplerSecurityPatchIdentityTests(unittest.TestCase):
    """Bind the approved Ubuntu security patch without expanding the raster profile."""

    def test_security_patched_raster_executor_identity_is_exact(self):
        """Require the reviewed binary and package hashes before accepting the executor."""
        from reporting import _pdf_visual_worker as worker

        manifest=json.loads(ENGINE.read_text(encoding="utf-8"))
        self.assertEqual(manifest["tool_version"],"24.02.0")
        self.assertEqual(manifest["package_version"],"24.02.0-1ubuntu9.10")
        self.assertEqual(manifest["binary_sha256"],
                         "ab7c91f0f144335ad7696f4f23aefbd564ef67c099290bd8f813cdbb47cd1e9e")
        self.assertEqual(manifest["package_sha256"],
                         "19ce4557ad89350506a0f1c33ad4c5a6aa7469e48c78aacae351a59b43ee20c6")
        self.assertEqual(worker.TOOL_VERSION,manifest["tool_version"])
        self.assertEqual(worker.TOOL_SHA256,manifest["binary_sha256"])
        self.assertEqual(manifest["license"],"GPL-2 or GPL-3")
        self.assertFalse(manifest["binary_vendored"])
        self.assertFalse(manifest["source_copied"])
        self.assertEqual(manifest["profile"]["dpi"],96)
        self.assertEqual(manifest["resource_budget"]["worker_wall_seconds"],30)
        self.assertIn("disable_path",manifest)


class Rpt12PdfVisualTests(unittest.TestCase):
    """Validate deterministic raster geometry without claiming human visual equivalence."""

    @classmethod
    def setUpClass(cls):
        """Render one real passive candidate reused by positive boundary tests."""
        cls.pdf=render(source_ir())

    def setUp(self):
        """Expose absence of the visual gate as an explicit contract failure."""
        self.assertIsNotNone(importlib.util.find_spec("reporting.pdf_visual"),
                             "PDF raster visual QA is not implemented")
        self.module=importlib.import_module("reporting.pdf_visual")

    def check(self,pdf=None,**overrides):
        """Run the public visual gate with exact candidate identity."""
        data=self.pdf if pdf is None else pdf
        args={"pdf_bytes":data,"expected_pdf_sha256":digest(data)}
        args.update(overrides)
        return self.module.validate_pdf_visual_geometry(**args)

    def test_real_candidate_passes_with_content_free_geometry_evidence(self):
        """The current generated report rasterizes with safe bounded page geometry."""
        result=self.check()
        self.assertTrue(result.passed,result.errors)
        self.assertEqual(result.pdf_sha256,digest(self.pdf))
        self.assertEqual(result.page_count,1)
        self.assertGreaterEqual(result.min_edge_margin_px,2)
        self.assertRegex(result.raster_sha256,r"^[0-9a-f]{64}$")
        record=result.to_dict()
        self.assertEqual(record["conformance_scope"],"PDF_RASTER_GEOMETRY_ONLY")
        self.assertEqual(record["release_authorization"],"NOT_ESTABLISHED")
        self.assertNotIn("SYNTHETIC-ONLY",json.dumps(record))

    def test_existing_canonical_pipeline_roundtrip_passes(self):
        """The actual localized reporting fixture satisfies visual geometry prerequisites."""
        from tests.test_reporting_rpt08_html_pdf_conformance import Rpt08HtmlPdfConformanceTests
        scenario=Rpt08HtmlPdfConformanceTests(); scenario.setUp()
        pdf=render(scenario.presentation)
        result=self.check(pdf)
        self.assertTrue(result.passed,result.errors)

    def test_same_candidate_produces_deterministic_raster_evidence(self):
        """Repeated validation of identical bytes yields identical visual evidence."""
        first=self.check().to_dict(); second=self.check().to_dict()
        self.assertEqual(first,second)

    def test_blank_page_fails_closed(self):
        """A page without visible ink cannot satisfy report visual QA."""
        result=self.check(blank_pdf())
        self.assertFalse(result.passed)
        self.assertIn("pdf_visual_blank_page",result.errors)

    def test_ink_touching_page_boundary_fails_closed(self):
        """Ink touching the raster edge is treated as clipping risk."""
        result=self.check(edge_ink_pdf())
        self.assertFalse(result.passed)
        self.assertIn("pdf_visual_edge_contact",result.errors)

    def test_malformed_encrypted_and_zero_page_candidates_fail(self):
        """Unreadable or encrypted PDFs cannot receive visual evidence."""
        for pdf in (b"%PDF-1.7\nbroken",blank_pdf(pages=0),blank_pdf(encrypted=True)):
            with self.subTest(length=len(pdf)):
                self.assertFalse(self.check(pdf).passed)

    def test_extreme_page_geometry_is_rejected_before_rasterization(self):
        """Oversized page dimensions cannot trigger unbounded raster allocation."""
        result=self.check(blank_pdf(width=20000,height=20000))
        self.assertFalse(result.passed)
        self.assertIn("pdf_visual_budget_exceeded",result.errors)

    def test_candidate_digest_errors_block_before_worker(self):
        """Only the exact PDF identity can authorize rasterization."""
        cases=((None,"expected_pdf_digest_invalid"),("G"*64,"expected_pdf_digest_invalid"),
               ("0"*64,"pdf_digest_mismatch"))
        for expected,error in cases:
            with self.subTest(error=error),patch.object(self.module,"_run_worker") as worker:
                result=self.check(expected_pdf_sha256=expected)
                self.assertFalse(result.passed)
                self.assertIn(error,result.errors)
                worker.assert_not_called()

    def test_worker_timeout_failure_and_malformed_reply_fail_closed(self):
        """Worker outages or protocol corruption cannot become visual PASS."""
        for exc in (OSError("synthetic"),subprocess.TimeoutExpired("worker",10)):
            with self.subTest(kind=type(exc).__name__),patch.object(self.module,"_run_worker",side_effect=exc):
                self.assertFalse(self.check().passed)
        for code,data in ((-9,b""),(0,b"not-json"),(0,b'{"status":"PASS"}'),(0,b"x"*8193)):
            with self.subTest(code=code,length=len(data)),patch.object(
                self.module,"_run_worker",
                return_value=subprocess.CompletedProcess([],code,data)
            ):
                self.assertFalse(self.check().passed)

    def test_success_protocol_requires_exact_identity_and_bounded_counts(self):
        """Forged worker success records cannot satisfy the public result."""
        template={
            "status":"PASS","pdf_sha256":digest(self.pdf),"page_count":1,
            "raster_sha256":"1"*64,"min_edge_margin_px":20,"total_pixels":1000,"errors":[],
        }
        mutations=(
            {"pdf_sha256":"0"*64},{"page_count":True},{"raster_sha256":"bad"},
            {"min_edge_margin_px":-1},{"total_pixels":0},{"status":"SKIPPED"},
            {"errors":["unknown"]},{"extra":"unexpected"},
        )
        for change in mutations:
            with self.subTest(change=change):
                record={**template,**change}
                with patch.object(
                    self.module,"_run_worker",
                    return_value=subprocess.CompletedProcess([],0,json.dumps(record).encode())
                ):
                    result=self.check()
                self.assertFalse(result.passed)
                self.assertIn("pdf_visual_worker_invalid_response",result.errors)

    def test_result_is_immutable_and_cannot_claim_pass_without_complete_evidence(self):
        """Public evidence cannot be forged into a success-looking incomplete record."""
        with self.assertRaises(ValueError):
            self.module.PdfVisualValidation(None,None,None,None,None,())
        result=self.check(); self.assertTrue(result.passed,result.errors)
        with self.assertRaises(FrozenInstanceError):
            result.page_count=99
        exposed=result.to_dict(); exposed["errors"].append("tampered")
        self.assertEqual(result.errors,())

    def test_multipage_generated_report_reports_every_page(self):
        """A multi-page real report rasterizes completely rather than only its first page."""
        ir=source_ir(); ir["components"]=[]
        for index in range(24):
            ir["components"].append({
                "component_id":f"section-{index}","component_type":"semantic-section",
                "title":f"Synthetic section {index}","state":"PRESENT",
                "content":{"index":index,"text":"alpha beta gamma "*18},
            })
        pdf=render(ir)
        result=self.check(pdf)
        self.assertTrue(result.passed,result.errors)
        self.assertGreater(result.page_count,1)

    def test_engine_manifest_pins_executor_and_rights_boundary(self):
        """The external raster executor is exact, non-vendored and disableable."""
        self.assertTrue(ENGINE.is_file(),"visual executor manifest missing")
        manifest=json.loads(ENGINE.read_text())
        self.assertEqual(manifest["engine_id"],"poppler-pdftoppm-raster-v1")
        self.assertEqual(manifest["tool_version"],"24.02.0")
        self.assertEqual(manifest["package_version"],"24.02.0-1ubuntu9.10")
        self.assertEqual(manifest["binary_sha256"],
                         "ab7c91f0f144335ad7696f4f23aefbd564ef67c099290bd8f813cdbb47cd1e9e")
        self.assertEqual(manifest["package_sha256"],
                         "19ce4557ad89350506a0f1c33ad4c5a6aa7469e48c78aacae351a59b43ee20c6")
        self.assertEqual(manifest["license"],"GPL-2 or GPL-3")
        self.assertEqual(manifest["integration_class"],"USE_VIA_ADAPTER")
        self.assertFalse(manifest["source_copied"])
        self.assertEqual(manifest["profile"]["dpi"],96)
        self.assertIn("disable_path",manifest)

    def test_rasterization_reuses_the_verified_executor_lookup(self):
        """Rasterization must not perform a second PATH lookup after identity verification."""
        worker=importlib.import_module("reporting._pdf_visual_worker")
        real_which=worker.shutil.which
        with patch.object(worker.shutil,"which",side_effect=lambda name: real_which(name)) as lookup:
            result=worker.inspect_visual_geometry(self.pdf)
        self.assertEqual(result["status"],"PASS",result["errors"])
        self.assertEqual(lookup.call_count,1)


    def test_unapproved_executor_is_never_executed_for_version_detection(self):
        """A different executable must be rejected before even its version command."""
        with tempfile.TemporaryDirectory(prefix="omnigenis-visual-test-") as td:
            root=Path(td)
            tool=root/"pdftoppm"
            marker=root/"executed"
            tool.write_text(
                '#!/bin/sh\n'
                'printf executed > "$OMNIGENIS_VISUAL_TEST_MARKER"\n'
                'printf "pdftoppm version 24.02.0\\n"\n'
            )
            tool.chmod(0o700)
            with patch.dict(os.environ,{
                "PATH":str(root)+os.pathsep+os.environ.get("PATH",""),
                "OMNIGENIS_VISUAL_TEST_MARKER":str(marker),
            }):
                result=self.check()
            self.assertEqual(result.errors,("pdf_visual_executor_mismatch",))
            self.assertFalse(marker.exists(),"Unapproved executable ran before digest rejection")

    def test_worker_timeout_and_crash_remove_descendants_and_private_artifacts(self):
        """Real worker failure cannot leave a running child or temporary candidate."""
        script=(
            "import json,os,subprocess,sys,tempfile,time\n"
            "from pathlib import Path\n"
            "scratch=Path(tempfile.mkdtemp(prefix='omnigenis-visual-test-artifacts-'))\n"
            "(scratch/'candidate.pdf').write_bytes(b'SYNTHETIC-ONLY')\n"
            "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
            "Path(os.environ['OMNIGENIS_VISUAL_TEST_STATE']).write_text("
            "json.dumps({'child_pid':child.pid,'scratch':str(scratch)}))\n"
            "if os.environ['OMNIGENIS_VISUAL_TEST_MODE']=='crash': os._exit(9)\n"
            "time.sleep(60)\n"
        )
        for mode in ("timeout","crash"):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory(
                prefix="omnigenis-visual-supervisor-test-"
            ) as td:
                root=Path(td)
                worker=root/"worker.py"
                state_file=root/"state.json"
                worker.write_text(script)
                state=None
                try:
                    with patch.object(self.module,"_WORKER",worker),patch.object(
                        self.module,"WALL_SECONDS",2
                    ),patch.dict(os.environ,{
                        "OMNIGENIS_VISUAL_TEST_STATE":str(state_file),
                        "OMNIGENIS_VISUAL_TEST_MODE":mode,
                    }):
                        result=self.check()
                    expected="pdf_visual_worker_timeout" if mode=="timeout" else "pdf_visual_worker_failed"
                    self.assertEqual(result.errors,(expected,))
                    self.assertTrue(state_file.is_file(),"Synthetic worker did not reach its fixture")
                    state=json.loads(state_file.read_text())
                    child_pid=state["child_pid"]
                    scratch=Path(state["scratch"])

                    def running():
                        """Treat a terminated or concurrently reaped child as stopped."""
                        try:
                            return Path(f"/proc/{child_pid}/stat").read_text().split()[2]!="Z"
                        except (FileNotFoundError, ProcessLookupError):
                            return False

                    deadline=time.monotonic()+1
                    while running() and time.monotonic()<deadline:
                        time.sleep(0.01)
                    alive=running()
                    artifacts=scratch.exists()
                    self.assertFalse(
                        alive or artifacts,
                        f"orphan_running={alive}, artifacts_remaining={artifacts}",
                    )
                finally:
                    if state is None and state_file.is_file():
                        state=json.loads(state_file.read_text())
                    if state:
                        try:
                            os.kill(state["child_pid"],signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        scratch=Path(state["scratch"])
                        if scratch.name.startswith("omnigenis-visual-test-artifacts-"):
                            shutil.rmtree(scratch,ignore_errors=True)

    def test_executor_version_or_binary_drift_is_rejected(self):
        """An unreviewed Poppler executable identity cannot produce PASS evidence."""
        worker=importlib.import_module("reporting._pdf_visual_worker")
        with patch.object(
            worker,"_tool_identity",
            return_value=("0.0.0","0"*64,"/usr/bin/pdftoppm"),
        ):
            result=worker.inspect_visual_geometry(self.pdf)
        self.assertEqual(result["errors"],["pdf_visual_executor_mismatch"])


if __name__=="__main__":
    unittest.main()
