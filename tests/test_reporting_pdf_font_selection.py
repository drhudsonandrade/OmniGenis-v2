"""Exercise real font source, sealed capture, coverage and cohort refusals."""

from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from reporting import pdf_font_selection as fonts


ROOT = Path(__file__).resolve().parents[1]
FONT_DIRECTORY = ROOT / "reporting" / "assets" / "fonts" / "lato"

# Each native Fontconfig admission uses one disposable child. The same existing
# lifetime, resource, filesystem and network guards apply before font parsing.
# These cases do not render a PDF or add a product execution path.
COHORT_PROBE = r'''
import hashlib
import os
from pathlib import Path
import sys

sys.path.insert(0, sys.argv[1])
from reporting import _pdf_render_worker as worker
from reporting import pdf_font_selection as fonts
from reporting._pdf_process_sandbox import (
    enforce_pdf_landlock, enforce_pdf_network_filter,
)

worker._apply_resource_limits()
worker._arm_worker_lifetime(os.getppid())
enforce_pdf_landlock(Path(worker.__file__))
enforce_pdf_network_filter()

html = '<html><body><p style="font-family:Lato">Cohort</p></body></html>'
selector = fonts.LatoFontSelection(
    font_directory=Path(sys.argv[1]) / "reporting/assets/fonts/lato",
    html=html,
    html_sha256=hashlib.sha256(html.encode("utf-8")).hexdigest(),
)
extra_fd = None
expected = {"font_stdin_not_devnull"} if sys.argv[2] == "stdin_not_devnull" else None
try:
    try:
        with selector:
            if sys.argv[2] == "foreign_path":
                # Known font bytes do not authorize a third, unbound file path.
                face = fonts.FACES[0]
                original = selector._face_fds[face.sha256]
                data = os.pread(original, face.size + 1, 0)
                extra_fd = fonts._sealed_memfd("unadmitted-font", data)
                path = fonts._proc_alias(extra_fd, face.size, face.sha256)
                if not selector._fc.FcConfigAppFontAddFile(
                    selector.font_config._config, path.encode("ascii")
                ):
                    raise AssertionError("foreign font was not added by Fontconfig")
                expected = {"font_application_set", "font_application_path"}
            elif sys.argv[2] == "bootstrap_retention":
                # Returning without finish must refuse output. Its sealed
                # bootstrap must nevertheless outlive the Python context.
                selector._verify_bootstrap()
                expected = {"font_output_not_finalized"}
            elif sys.argv[2] == "font_face_attempt":
                # A caller swallowing the admission error must not restore
                # an admissible cohort or make later finalization possible.
                try:
                    selector.font_config.add_font_face(
                        {"font_family": "Lato", "src": [("local", "Lato")]}, None
                    )
                except fonts.FontSelectionError:
                    pass
                else:
                    raise AssertionError("font-face request was admitted")
                expected = {"font_face_rule_not_admitted"}
            else:
                raise AssertionError("unknown fixed cohort probe")
            if sys.argv[2] != "bootstrap_retention":
                selector._verify_font_sets(expected_application=2)
                raise AssertionError("unadmitted cohort passed verification")
    except fonts.FontSelectionError as error:
        if expected is None or str(error) not in expected:
            raise
        if sys.argv[2] == "bootstrap_retention":
            selector._verify_bootstrap()
            if selector._active or selector.font_config is None:
                raise AssertionError("retired context lost its native configuration")
            if len(selector._fds) != 2 or set(selector._fds) != set(selector._face_fds.values()):
                raise AssertionError("retained font descriptor set is not exactly two")
            for face in fonts.FACES:
                fonts._verify_memfd(selector._face_fds[face.sha256], face.size, face.sha256)
            if fonts._RETAINED_SELECTION is not selector:
                raise AssertionError("one-shot owner did not retain its configuration")
        print("expected-cohort-refusal")
finally:
    if extra_fd is not None:
        # The rejected native configuration still references this bounded test
        # font. Keep its descriptor valid until this disposable child exits.
        fonts._verify_memfd(extra_fd, face.size, face.sha256)
'''


class FontSelectionRefusalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # A missing or corrupt deployed dependency fails setup; it cannot make
        # any of the negative cases appear to pass for the wrong reason.
        directory_fd = os.open(FONT_DIRECTORY, os.O_RDONLY | os.O_DIRECTORY)
        try:
            cls.captured = {
                face.filename: fonts._read_source(directory_fd, face)
                for face in fonts.FACES
            }
        finally:
            os.close(directory_fd)
        cls.regular = next(face for face in fonts.FACES if face.weight == 400)
        cls.regular_bytes = cls.captured[cls.regular.filename]

    def test_manifest_binds_exact_deployed_fonts_notices_and_code(self):
        """Read deployed bytes so a stale, missing or replaced dependency fails."""
        from reporting import adapters

        manifest = json.loads(
            (ROOT / "reporting/pdf-font-style.v1.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["style_id"], adapters.FIXED_FONT_STYLE_ID)
        revision = "f3b885d5590e307e02542f1a724cec55d567fdaa"
        self.assertEqual(manifest["source_revision"], revision)
        source_base = f"https://raw.githubusercontent.com/google/fonts/{revision}/ofl/lato/"
        expected_fonts = {
            "reporting/assets/fonts/lato/" + face.filename: face
            for face in fonts.FACES
        }
        self.assertEqual(len(manifest["fonts"]), len(expected_fonts))
        self.assertEqual({record["path"] for record in manifest["fonts"]}, set(expected_fonts))
        for record in manifest["fonts"]:
            relative = record["path"]
            face = expected_fonts[relative]
            with self.subTest(resource=relative):
                raw = (ROOT / relative).read_bytes()
                self.assertEqual(len(raw), record["bytes"])
                self.assertEqual(record["bytes"], face.size)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), record["sha256"])
                self.assertEqual(record["sha256"], face.sha256)
                self.assertEqual(record["weight"], face.weight)
                self.assertEqual(record["postscript_name"], face.postscript_name)
                self.assertEqual(record["source_url"], source_base + face.filename)
                self.assertEqual(record["classification"], "LEGAL_COPY")
                self.assertFalse(record["modified"])
        notices = {
            "license": ("OFL.txt", 4407,
                        "74ba064d03f1f1c4a952da936c3eb71866c34404916734de3cae73b34357e59e"),
            "fontlog": ("FONTLOG.txt", 3102,
                        "d14d78932391e0a2f47b24319aa4e74ddcb448b13701d9673b6523259d558560"),
        }
        for key, (name, size, digest) in notices.items():
            record = manifest[key]
            relative = "reporting/assets/fonts/lato/" + name
            with self.subTest(resource=relative):
                self.assertEqual(record["path"], relative)
                raw = (ROOT / relative).read_bytes()
                self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (size, digest))
                self.assertEqual((record["bytes"], record["sha256"]), (size, digest))
                self.assertEqual(record["source_url"], source_base + name)
                self.assertFalse(record["modified"])
        self.assertEqual(manifest["license"]["spdx"], "OFL-1.1")
        self.assertEqual(set(manifest["source_sha256"]), {
            "reporting/adapters.py", "reporting/_pdf_render_worker.py",
            "reporting/pdf_font_selection.py", "requirements-reporting.lock",
        })
        for relative, digest in manifest["source_sha256"].items():
            with self.subTest(source=relative):
                self.assertEqual(hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(), digest)

    def test_absent_font_is_refused_at_capture(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory_fd = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(FileNotFoundError):
                    fonts._read_source(directory_fd, self.regular)
            finally:
                os.close(directory_fd)

    def test_same_size_changed_font_is_refused_at_capture(self):
        changed = bytearray(self.regular_bytes)
        changed[-1] ^= 1
        with tempfile.TemporaryDirectory() as temporary:
            (Path(temporary) / self.regular.filename).write_bytes(changed)
            directory_fd = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaisesRegex(
                    fonts.FontSelectionError, "^font_source_identity$"
                ):
                    fonts._read_source(directory_fd, self.regular)
            finally:
                os.close(directory_fd)

    def test_capture_cannot_be_written_grown_or_shrunk(self):
        fd = fonts._sealed_memfd("font-capture-test", self.regular_bytes)
        try:
            fonts._verify_memfd(fd, self.regular.size, self.regular.sha256)
            for operation in (
                lambda: os.pwrite(fd, b"X", 0),
                lambda: os.ftruncate(fd, self.regular.size + 1),
                lambda: os.ftruncate(fd, self.regular.size - 1),
            ):
                with self.assertRaises(OSError) as refusal:
                    operation()
                self.assertEqual(refusal.exception.errno, errno.EPERM)
            self.assertEqual(
                os.pread(fd, self.regular.size + 1, 0), self.regular_bytes
            )
        finally:
            os.close(fd)

    def test_matching_bytes_without_seals_are_refused(self):
        data = b"unsealed-font-capture"
        fd = os.memfd_create("unsealed-font", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            written = os.write(fd, data)
            self.assertEqual(written, len(data))
            os.fchmod(fd, 0o400)
            with self.assertRaisesRegex(
                fonts.FontSelectionError, "^font_capture_unsealed$"
            ):
                fonts._verify_memfd(fd, len(data), hashlib.sha256(data).hexdigest())
        finally:
            os.close(fd)

    def test_coverage_preserves_mapped_format_characters_and_refuses_emoji(self):
        coverage = fonts._unicode_coverage(self.regular_bytes)
        text = "Lato café\t\n\r\u00ad\u200b\u200c\u200d\u200e\u200f\ufeff"
        fonts._check_text(text, coverage)
        with self.assertRaisesRegex(
            fonts.FontSelectionError, "^font_text_unmapped$"
        ):
            fonts._check_text("Lato \U0001f600", coverage)

    def _run_cohort_probe(self, mode, *, standard_input=subprocess.DEVNULL):
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", COHORT_PROBE, str(ROOT), mode],
            stdin=standard_input,
            capture_output=True, text=True, timeout=worker_timeout_seconds(),
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), "expected-cohort-refusal")

    def test_unadmitted_application_font_path_is_refused(self):
        self._run_cohort_probe("foreign_path")

    def test_swallowed_font_face_attempt_still_refuses_verification(self):
        self._run_cohort_probe("font_face_attempt")

    def test_unfinished_context_refuses_output_but_retains_sealed_bootstrap(self):
        self._run_cohort_probe("bootstrap_retention")

    def test_non_devnull_input_is_refused_without_reading_it(self):
        with tempfile.TemporaryFile() as standard_input:
            standard_input.write(b"Synthetic-unused-input\n")
            standard_input.seek(0)
            self._run_cohort_probe("stdin_not_devnull", standard_input=standard_input)
            self.assertEqual(standard_input.tell(), 0)


def worker_timeout_seconds():
    """Let the existing worker alarm expire before the test harness deadline."""
    from reporting._pdf_render_worker import WALL_SECONDS

    return WALL_SECONDS + 5


if __name__ == "__main__":
    unittest.main()
