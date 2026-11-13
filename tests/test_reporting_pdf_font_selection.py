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


# Native image residency is irreversible within one process. Each condition
# gets a fresh child, and no FontConfiguration or native font thread is created.
RESIDENCY_PROBE = r"""
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

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

from cffi import FFI
ffi = FFI()
backend = ffi._backend
names = ("libpangoft2-1.0.so.0", "libfontconfig.so.1")
mode = sys.argv[2]
if mode not in ("baseline", "promoted", "unloaded_refusal"):
    raise AssertionError("unknown residency condition")


def public_dlopen_forbidden(*args, **kwargs):
    raise AssertionError("public ffi.dlopen fallback is not admitted")


ffi.dlopen = public_dlopen_forbidden


def presence():
    observed = []
    for name in names:
        # A NOLOAD miss can return NULL without setting dlerror. Inspect that
        # raw result instead of entering CFFI's error-formatting wrapper.
        probe = raw_dlopen(name.encode("ascii"), ffi.RTLD_NOW | ffi.RTLD_NOLOAD)
        if probe == ffi.NULL:
            observed.append(False)
        else:
            try:
                observed.append(True)
            finally:
                if raw_dlclose(probe) != 0:
                    raise AssertionError("native residency probe handle was not released")
    return observed


def close_all(handles):
    while handles:
        handles.pop().close_lib()


ordinary, promoted = [], []
process = backend.load_library(None, ffi.RTLD_NOW)
try:
    raw_dlopen = process.load_function(
        ffi.typeof("void *(*)(const char *, int)"), "dlopen")
    raw_dlclose = process.load_function(
        ffi.typeof("int(*)(void *)"), "dlclose")
    initial = presence()
    if initial != [False, False]:
        raise AssertionError("fresh residency child already contains a font root")
    for name in names:
        ordinary.append(backend.load_library(name, ffi.RTLD_NOW))
    # These typed addresses are never called. Only loader residency is tested;
    # no FontMap, renderer, callback, compiler or asynchronous worker is started.
    pangoft2 = SimpleNamespace(pango_ft2_font_map_new=ordinary[0].load_function(
        ffi.typeof("void *(*)(void)"), "pango_ft2_font_map_new"))
    fontconfig = SimpleNamespace(FcConfigAppFontAddFile=ordinary[1].load_function(
        ffi.typeof("int(*)(void *, unsigned char const *)"),
        "FcConfigAppFontAddFile"))
    loaded = presence()
    if loaded != [True, True]:
        raise AssertionError("ordinary font roots were not present")
    refusal = None
    if mode == "promoted":
        promoted = list(fonts._retain_native_font_libraries(ffi, fontconfig, pangoft2))
    elif mode == "unloaded_refusal":
        close_all(ordinary)
        if presence() != [False, False]:
            raise AssertionError("ordinary closure did not remove both font roots")
        # Existing typed function addresses are retained as inert values only.
        # NOLOAD must refuse their now absent images without loading replacements.
        try:
            promoted = list(fonts._retain_native_font_libraries(ffi, fontconfig, pangoft2))
        except fonts.FontSelectionError as error:
            refusal = str(error)
            if refusal != "font_native_library_unavailable":
                raise
        else:
            raise AssertionError("absent native image was admitted")
    close_all(promoted)
    close_all(ordinary)
    after = presence()
    expected = [True, True] if mode == "promoted" else [False, False]
    if after != expected:
        raise AssertionError("native residency after all handle closures differs")
    print(json.dumps({"schema": "font-residency-probe-v1", "mode": mode,
                      "initial": initial, "loaded": loaded, "after_close": after,
                      "refusal": refusal}, sort_keys=True))
finally:
    try:
        close_all(promoted)
    finally:
        try:
            close_all(ordinary)
        finally:
            process.close_lib()
"""


# Admission failures and successful ordering are checked at the real selection
# boundary. The constructor trap prevents every condition from creating a map.
RESIDENCY_ADMISSION_PROBE = r"""
import builtins
import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest import mock
import warnings

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

mode = sys.argv[2]
if mode not in ("unsupported_flags", "wrong_image", "order"):
    raise AssertionError("unknown residency admission condition")
events = []
real_import = builtins.__import__
real_retain = fonts._retain_native_font_libraries
constructor_trapped = False


class ConstructorReached(Exception):
    pass


def intercept_import(name, globals=None, locals=None, fromlist=(), level=0):
    global constructor_trapped
    module = real_import(name, globals, locals, fromlist, level)
    if (not constructor_trapped
            and getattr(module, "__name__", None) == "weasyprint.text.fonts"
            and hasattr(module, "FontConfiguration")):
        class NoFontMap:
            def __init__(self):
                events.append("font_configuration")
                raise ConstructorReached()
        module.FontConfiguration = NoFontMap
        constructor_trapped = True
    return module


def public_dlopen_forbidden(*args, **kwargs):
    raise AssertionError("public ffi.dlopen fallback is not admitted")


def retain(ffi, fontconfig, pangoft2):
    events.append("residency_enter")
    with mock.patch.object(ffi, "dlopen", public_dlopen_forbidden):
        if mode == "unsupported_flags":
            with mock.patch.object(ffi, "RTLD_NODELETE", None):
                owners = real_retain(ffi, fontconfig, pangoft2)
        elif mode == "wrong_image":
            # Supply an actual address from the other font DSO with the expected
            # callable type, without calling it. A same-name promotion must not
            # accept that different loaded image as the renderer's Pango root.
            wrong = SimpleNamespace(pango_ft2_font_map_new=ffi.cast(
                ffi.typeof(pangoft2.pango_ft2_font_map_new),
                ffi.cast("void *", fontconfig.FcConfigAppFontAddFile)))
            owners = real_retain(ffi, fontconfig, wrong)
        else:
            owners = real_retain(ffi, fontconfig, pangoft2)
    events.append("residency_verified")
    return owners


html = '<html><body><p style="font-family:Lato">Residency</p></body></html>'
selector = fonts.LatoFontSelection(
    font_directory=Path(sys.argv[1]) / "reporting/assets/fonts/lato",
    html=html, html_sha256=hashlib.sha256(html.encode("utf-8")).hexdigest(),
)
builtins.__import__ = intercept_import
fonts._retain_native_font_libraries = retain
outcome = None
try:
    with warnings.catch_warnings(record=True) as captured_warnings:
        warnings.simplefilter("always")
        try:
            selector.__enter__()
        except ConstructorReached:
            if mode != "order":
                raise AssertionError("font map construction preceded required refusal")
            outcome = "constructor_reached_after_residency"
            if events != ["residency_enter", "residency_verified", "font_configuration"]:
                raise AssertionError("native residency was not verified first")
            if len(selector._native_library_owners) != 2:
                raise AssertionError("verified native owners were not held at construction")
        except fonts.FontSelectionError as error:
            expected = {"unsupported_flags": "font_native_loader_flags",
                        "wrong_image": "font_native_library_identity"}.get(mode)
            if str(error) != expected or events != ["residency_enter"]:
                raise
            outcome = str(error)
        else:
            raise AssertionError("constructor trap or admission refusal was bypassed")
    observed_warnings = [{
        "category": item.category.__name__,
        "message": str(item.message),
        "source": "/".join(Path(item.filename).parts[-3:]),
    } for item in captured_warnings]
    imported_ffi = sys.modules.get("weasyprint.text.ffi")
    if imported_ffi is None or not hasattr(imported_ffi, "harfbuzz_subset"):
        raise AssertionError("missing admission warning availability: " + json.dumps({
            "warning_count": len(observed_warnings), "warnings": observed_warnings,
        }, sort_keys=True))
    subset_available = imported_ffi.harfbuzz_subset is not None
    font_warning = {
        "category": "UserWarning",
        "message": "No fonts configured in FontConfig. Expect ugly output.",
        "source": "weasyprint/text/fonts.py",
    }
    subset_warning = {
        "category": "DeprecationWarning",
        "message": ("HarfBuzz-Subset will be required by future versions of WeasyPrint. "
                    "Please install this library with your package manager."),
        "source": "weasyprint/text/ffi.py",
    }
    # ffi.py emits its conditional warning before fonts.py checks the empty
    # bootstrap. No other warning, missing warning or duplicate is admitted.
    expected_warnings = ([font_warning] if subset_available
                         else [subset_warning, font_warning])
    expected_categories = ([UserWarning] if subset_available
                           else [DeprecationWarning, UserWarning])
    if (observed_warnings != expected_warnings
            or not all(item.category is category for item, category in
                       zip(captured_warnings, expected_categories))):
        raise AssertionError("unexpected admission warnings: " + json.dumps({
            "harfbuzz_subset_available": subset_available,
            "warning_count": len(observed_warnings), "warnings": observed_warnings,
            "expected_warning_count": len(expected_warnings),
            "expected_warnings": expected_warnings,
        }, sort_keys=True))
    if not constructor_trapped or selector.font_config is not None:
        raise AssertionError("font map constructor was not isolated")
    print(json.dumps({"schema": "font-residency-admission-probe-v1",
                      "mode": mode, "outcome": outcome, "events": events,
                      "harfbuzz_subset_available": subset_available,
                      "warning_count": len(observed_warnings),
                      "warnings": observed_warnings}, sort_keys=True))
finally:
    builtins.__import__ = real_import
    fonts._retain_native_font_libraries = real_retain
"""

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
            "license": ("LICENSE", "OFL.txt", 4407,
                        "74ba064d03f1f1c4a952da936c3eb71866c34404916734de3cae73b34357e59e"),
            "fontlog": ("FONTLOG", "FONTLOG.txt", 3102,
                        "d14d78932391e0a2f47b24319aa4e74ddcb448b13701d9673b6523259d558560"),
        }
        for key, (name, source_name, size, digest) in notices.items():
            record = manifest[key]
            relative = "reporting/assets/fonts/lato/" + name
            with self.subTest(resource=relative):
                self.assertEqual(record["path"], relative)
                raw = (ROOT / relative).read_bytes()
                self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (size, digest))
                self.assertEqual((record["bytes"], record["sha256"]), (size, digest))
                self.assertEqual(record["source_url"], source_base + source_name)
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


class NativeFontResidencyTests(unittest.TestCase):
    def _run_probe(self, source, mode):
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", source, str(ROOT), mode],
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=worker_timeout_seconds(), check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stderr, "")
        return json.loads(result.stdout)

    def test_native_images_survive_all_handle_closures(self):
        # A fresh negative control proves that held Python/CFFI handles alone
        # do not provide the required process lifetime for these exact images.
        for mode, expected in (("baseline", [False, False]),
                               ("promoted", [True, True])):
            with self.subTest(condition=mode):
                self.assertEqual(self._run_probe(RESIDENCY_PROBE, mode), {
                    "schema": "font-residency-probe-v1", "mode": mode,
                    "initial": [False, False], "loaded": [True, True],
                    "after_close": expected, "refusal": None,
                })

    def test_noload_refuses_unloaded_images_without_public_dlopen(self):
        self.assertEqual(self._run_probe(RESIDENCY_PROBE, "unloaded_refusal"), {
            "schema": "font-residency-probe-v1", "mode": "unloaded_refusal",
            "initial": [False, False], "loaded": [True, True],
            "after_close": [False, False],
            "refusal": "font_native_library_unavailable",
        })

    def _admission_warning_expectation(self, observed):
        available = observed.get("harfbuzz_subset_available")
        self.assertIs(type(available), bool, observed)
        font_warning = {
            "category": "UserWarning",
            "message": "No fonts configured in FontConfig. Expect ugly output.",
            "source": "weasyprint/text/fonts.py",
        }
        subset_warning = {
            "category": "DeprecationWarning",
            "message": ("HarfBuzz-Subset will be required by future versions of WeasyPrint. "
                        "Please install this library with your package manager."),
            "source": "weasyprint/text/ffi.py",
        }
        expected = ([font_warning] if available
                    else [subset_warning, font_warning])
        return {"harfbuzz_subset_available": available,
                "warning_count": len(expected), "warnings": expected}

    def test_unsupported_residency_flags_refuse_before_font_map(self):
        observed = self._run_probe(RESIDENCY_ADMISSION_PROBE, "unsupported_flags")
        self.assertEqual(observed, {
            "schema": "font-residency-admission-probe-v1",
            "mode": "unsupported_flags", "outcome": "font_native_loader_flags",
            "events": ["residency_enter"],
            **self._admission_warning_expectation(observed),
        })

    def test_wrong_image_refuses_before_font_map(self):
        observed = self._run_probe(RESIDENCY_ADMISSION_PROBE, "wrong_image")
        self.assertEqual(observed, {
            "schema": "font-residency-admission-probe-v1",
            "mode": "wrong_image", "outcome": "font_native_library_identity",
            "events": ["residency_enter"],
            **self._admission_warning_expectation(observed),
        })

    def test_font_map_constructor_follows_residency_verification(self):
        observed = self._run_probe(RESIDENCY_ADMISSION_PROBE, "order")
        self.assertEqual(observed, {
            "schema": "font-residency-admission-probe-v1",
            "mode": "order", "outcome": "constructor_reached_after_residency",
            "events": ["residency_enter", "residency_verified", "font_configuration"],
            **self._admission_warning_expectation(observed),
        })

def worker_timeout_seconds():
    """Let the existing worker alarm expire before the test harness deadline."""
    from reporting._pdf_render_worker import WALL_SECONDS

    return WALL_SECONDS + 5


if __name__ == "__main__":
    unittest.main()
