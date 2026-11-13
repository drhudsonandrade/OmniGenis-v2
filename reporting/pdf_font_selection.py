"""Fixed, captured Lato selection for one disposable guarded PDF worker.

The caller applies its existing lifetime, resource, filesystem and network
guards before admission and withholds all output until finish() succeeds.
The fixed bootstrap, font descriptors and native font configuration remain
owned by this one-use worker until process exit, including after a refusal.
"""
from __future__ import annotations

from dataclasses import dataclass
import fcntl
from hashlib import sha256
from importlib.metadata import version
from io import BytesIO
import os
from pathlib import Path
import stat
import sys
import threading
from types import MappingProxyType


@dataclass(frozen=True, slots=True)
class Face:
    filename: str
    size: int
    sha256: str
    weight: int
    postscript_name: str


FACES = (
    Face("Lato-Regular.ttf", 656568,
         "d636e4683231f931eda222d588e944d082bfd3bdba02f928bee461c0f185b251",
         400, "Lato-Regular"),
    Face("Lato-Bold.ttf", 656544,
         "8a0aace75d33794eece4b28187bfc1df0bbd2888b5d8a56e01788c8d65d16be1",
         700, "Lato-Bold"),
)
FACE_BY_DIGEST = MappingProxyType({face.sha256: face for face in FACES})
EMPTY_FONTCONFIG = b'<?xml version="1.0"?>\n<fontconfig></fontconfig>\n'
MAX_HTML_BYTES = 64 * 1024 * 1024  # Same existing render-request ceiling.
LAYOUT_CONTROLS = frozenset((9, 10, 13))
_ENV_KEYS = ("FONTCONFIG_FILE", "FONTCONFIG_PATH", "FONTCONFIG_SYSROOT")
STDIN_CONFIG_ALIAS = "/dev/stdin"
STDIN_CONFIG_TARGET = "/proc/self/fd/0"
_PROCESS_USED = False
_RETAINED_SELECTION = None
_PROCESS_LOCK = threading.Lock()


class FontSelectionError(ValueError):
    """Content-free refusal; this class does not publish or authorize output."""


class RendererImportUnavailable(ImportError):
    """The pinned renderer or its imported font dependency is unavailable."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise FontSelectionError(reason)


def _identity(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_uid, info.st_gid, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _read_source(directory_fd: int, face: Face) -> bytes:
    """Capture exact approved bytes from one held regular source descriptor."""
    fd = os.open(face.filename,
                 os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                 dir_fd=directory_fd)
    try:
        before = os.fstat(fd)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and before.st_size == face.size, "font_source_shape")
        data = bytearray()
        while len(data) <= face.size:
            chunk = os.read(fd, min(65536, face.size + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        _require(_identity(before) == _identity(os.fstat(fd)),
                 "font_source_changed")
        result = bytes(data)
        _require(len(result) == face.size
                 and sha256(result).hexdigest() == face.sha256,
                 "font_source_identity")
        return result
    finally:
        os.close(fd)


def _required_seals() -> int:
    return (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)


def _sealed_memfd(label: str, data: bytes) -> int:
    """Make a content-sealed anonymous file in read-only mode, with readback."""
    fd = os.memfd_create(label, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            _require(written > 0, "font_capture_short_write")
            offset += written
        os.fchmod(fd, 0o400)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, _required_seals())
        _verify_memfd(fd, len(data), sha256(data).hexdigest())
        return fd
    except BaseException:
        os.close(fd)
        raise


def _verify_memfd(fd: int, size: int, digest: str) -> None:
    info = os.fstat(fd)
    _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 0
             and info.st_size == size and info.st_mode & 0o777 == 0o400,
             "font_capture_shape")
    seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
    _require(seals & _required_seals() == _required_seals(),
             "font_capture_unsealed")
    data = os.pread(fd, size + 1, 0)
    _require(len(data) == size and sha256(data).hexdigest() == digest,
             "font_capture_identity")


def _proc_alias(fd: int, size: int, digest: str) -> str:
    """Use only the specific held anonymous fd; never open/list a proc directory."""
    path = f"/proc/self/fd/{fd}"
    reopened = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        original, actual = os.fstat(fd), os.fstat(reopened)
        _require((original.st_dev, original.st_ino, original.st_size)
                 == (actual.st_dev, actual.st_ino, actual.st_size),
                 "font_descriptor_alias")
        _verify_memfd(reopened, size, digest)
    finally:
        os.close(reopened)
    return path


def _unicode_coverage(data: bytes) -> frozenset[int]:
    """Use the pinned Unicode cmap; never reinterpret the MacRoman subtable."""
    try:
        from fontTools.ttLib import TTFont
    except (ImportError, OSError) as error:
        raise RendererImportUnavailable("pdf_engine_unavailable") from error

    _require(version("fonttools") == "4.66.0", "fonttools_version")
    with TTFont(BytesIO(data), lazy=False) as font:
        _require("fvar" not in font, "font_variable_face")
        cmap = font.getBestCmap()
        _require(type(cmap) is dict and len(cmap) == 2164, "font_unicode_cmap")
        coverage = frozenset(
            scalar for scalar, name in cmap.items()
            if type(scalar) is int and font.getGlyphID(name) != 0)
        _require(len(coverage) == 2164, "font_missing_gid")
        return coverage


def _check_text(text: str, coverage: frozenset[int]) -> None:
    """Do not normalize, delete or replace source characters to make them pass."""
    _require(type(text) is str, "font_text_type")
    for character in text:
        scalar = ord(character)
        if scalar in LAYOUT_CONTROLS:
            continue
        _require(not (scalar < 32 or 0x7F <= scalar <= 0x9F
                      or 0xD800 <= scalar <= 0xDFFF),
                 "font_text_control_or_surrogate")
        _require(scalar in coverage, "font_text_unmapped")


class LatoFontSelection:
    """One-use selection retained through the disposable worker's process exit.

    Pass font_config and finisher to the existing HTML.write_pdf call. No fonts
    are loaded via URLFetcher. Call finish(returned_pdf) before publishing bytes.
    Context exit retires selection but keeps fd0, two font fds, the Fontconfig
    environment and native configuration alive for Pango's native thread.
    This internal receipt is not a replacement for external QA/attestation.
    """

    def __init__(self, *, font_directory: Path, html: str, html_sha256: str):
        self._directory = font_directory
        self._html = html
        self._html_sha256 = html_sha256
        self._fds: list[int] = []
        self._face_fds: dict[str, int] = {}
        self._face_paths: dict[str, Face] = {}
        self._bootstrap_retained = False
        self._config_identity: tuple | None = None
        self._coverage: frozenset[int] = frozenset()
        self._finished = False
        self._finisher_calls = 0
        self._observed: dict | None = None
        self._active = False
        self.font_config = None

    def __enter__(self) -> "LatoFontSelection":
        global _PROCESS_USED
        with _PROCESS_LOCK:
            _require(not _PROCESS_USED, "font_worker_already_used")
            _PROCESS_USED = True
        try:
            _require(sys.platform == "linux" and threading.active_count() == 1,
                     "font_worker_context")
            _require(not any(name == "weasyprint" or name.startswith("weasyprint.")
                             for name in sys.modules),
                     "font_renderer_imported_before_admission")
            _require(type(self._html) is str and type(self._html_sha256) is str,
                     "font_html_type")
            raw_html = self._html.encode("utf-8")
            _require(0 < len(raw_html) <= MAX_HTML_BYTES
                     and sha256(raw_html).hexdigest() == self._html_sha256,
                     "font_html_identity")
            _require(version("weasyprint") == "70.0", "font_renderer_version")

            directory_fd = os.open(self._directory,
                                   os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                   | os.O_CLOEXEC)
            try:
                coverages = []
                for face in FACES:
                    data = _read_source(directory_fd, face)
                    coverages.append(_unicode_coverage(data))
                    fd = _sealed_memfd("omnigenis-lato-" + str(face.weight), data)
                    self._fds.append(fd)
                    self._face_fds[face.sha256] = fd
                    path = _proc_alias(fd, face.size, face.sha256)
                    self._face_paths[path] = face
                _require(coverages[0] == coverages[1], "font_face_coverage_difference")
                self._coverage = coverages[0]
            finally:
                os.close(directory_fd)

            config_fd = _sealed_memfd("omnigenis-fontconfig", EMPTY_FONTCONFIG)
            self._fds.append(config_fd)
            self._install_stdin_bootstrap(config_fd)
            for key in _ENV_KEYS:
                os.environ.pop(key, None)
            os.environ["FONTCONFIG_FILE"] = STDIN_CONFIG_ALIAS
            self._verify_bootstrap()

            # Fontconfig resolves one link in FONTCONFIG_FILE. The verified
            # fixed alias resolves to fd0, not the memfd's deleted display name.
            # No renderer import occurs before this sealed bootstrap is active.
            try:
                from weasyprint.text.ffi import ffi, fontconfig, pangoft2
                from weasyprint.text.fonts import FontConfiguration
            except (ImportError, OSError) as error:
                raise RendererImportUnavailable("pdf_engine_unavailable") from error

            class ClosedFontConfiguration(FontConfiguration):
                font_face_rule_attempted = False

                def add_font_face(self, rule_descriptors, url_fetcher):
                    # Keep a refusal even if the CSS engine catches this error.
                    self.font_face_rule_attempted = True
                    raise FontSelectionError("font_face_rule_not_admitted")

            self._ffi, self._fc, self._pangoft2 = ffi, fontconfig, pangoft2
            self.font_config = ClosedFontConfiguration()
            self._verify_font_sets(expected_application=0)
            for path in self._face_paths:
                _require(bool(fontconfig.FcConfigAppFontAddFile(
                    self.font_config._config, path.encode("ascii"))),
                    "font_application_admission")
            pangoft2.pango_fc_font_map_config_changed(
                ffi.cast("PangoFcFontMap *", self.font_config.font_map))
            self._verify_font_sets(expected_application=2)
            self._active = True
            return self
        except BaseException:
            self._close()
            raise

    def _install_stdin_bootstrap(self, config_fd: int) -> None:
        """Replace only this worker's unused DEVNULL input; never restore it."""
        global _RETAINED_SELECTION

        _require(os.readlink(STDIN_CONFIG_ALIAS) == STDIN_CONFIG_TARGET,
                 "font_config_alias_identity")
        reference = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        try:
            actual, expected = os.fstat(0), os.fstat(reference)
            _require(stat.S_ISCHR(actual.st_mode)
                     and (actual.st_dev, actual.st_ino, actual.st_rdev)
                     == (expected.st_dev, expected.st_ino, expected.st_rdev)
                     and fcntl.fcntl(0, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDWR,
                     "font_stdin_not_devnull")
        finally:
            os.close(reference)
        _require(_RETAINED_SELECTION is None and config_fd >= 3,
                 "font_bootstrap_already_retained")
        self._config_identity = _identity(os.fstat(config_fd))
        os.dup2(config_fd, 0, inheritable=False)
        # From this point even a refusal retains the bootstrap until process
        # death. No native background work can race an environment/fd restore.
        self._bootstrap_retained = True
        _RETAINED_SELECTION = self
        os.close(config_fd)
        self._fds.remove(config_fd)
        os.lseek(0, 0, os.SEEK_SET)

    def _verify_bootstrap(self) -> None:
        """Verify both the fixed link and the exact sealed descriptor it names."""
        _require(self._bootstrap_retained
                 and os.environ.get("FONTCONFIG_FILE") == STDIN_CONFIG_ALIAS
                 and "FONTCONFIG_PATH" not in os.environ
                 and "FONTCONFIG_SYSROOT" not in os.environ,
                 "font_config_bootstrap_environment")
        _require(os.readlink(STDIN_CONFIG_ALIAS) == STDIN_CONFIG_TARGET
                 and not os.get_inheritable(0)
                 and _identity(os.fstat(0)) == self._config_identity,
                 "font_config_alias_identity")
        size, digest = len(EMPTY_FONTCONFIG), sha256(EMPTY_FONTCONFIG).hexdigest()
        _verify_memfd(0, size, digest)
        for path in (STDIN_CONFIG_ALIAS, STDIN_CONFIG_TARGET):
            reopened = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
            try:
                _require(_identity(os.fstat(reopened)) == self._config_identity,
                         "font_config_alias_identity")
                _verify_memfd(reopened, size, digest)
            finally:
                os.close(reopened)

    def _string(self, pattern, name: bytes) -> str:
        result = self._ffi.new("FcChar8 **")
        status = self._fc.FcPatternGetString(pattern, name, 0, result)
        _require(status == self._fc.FcResultMatch and result[0] != self._ffi.NULL,
                 "font_pattern_field")
        return self._ffi.string(result[0]).decode("utf-8", errors="strict")

    def _verify_font_sets(self, *, expected_application: int) -> None:
        self._verify_bootstrap()
        _require(not self.font_config.font_face_rule_attempted,
                 "font_face_rule_not_admitted")
        config = self.font_config._config
        system = self._fc.FcConfigGetFonts(config, self._fc.FcSetSystem)
        _require(system == self._ffi.NULL or system.nfont == 0,
                 "font_system_fallback_present")
        application = self._fc.FcConfigGetFonts(config, self._fc.FcSetApplication)
        if expected_application == 0:
            _require(application == self._ffi.NULL or application.nfont == 0,
                     "font_application_preexisting")
            return
        _require(application != self._ffi.NULL
                 and application.nfont == expected_application,
                 "font_application_set")
        seen = set()
        for index in range(application.nfont):
            pattern = application.fonts[index]
            path = self._string(pattern, b"file")
            _require(path in self._face_paths and path not in seen,
                     "font_application_path")
            face = self._face_paths[path]
            _require(self._string(pattern, b"family") == "Lato"
                     and self._string(pattern, b"postscriptname") == face.postscript_name,
                     "font_application_name")
            seen.add(path)
        _require(seen == set(self._face_paths), "font_application_incomplete")

    def finisher(self, document, _pdf) -> None:
        """Fail before pydyf serializes or returns the candidate bytes."""
        from weasyprint.document import Document
        from weasyprint.formatting_structure.boxes import TextBox
        from weasyprint.text.fonts import get_hb_object_data

        _require(self._active and self._finisher_calls == 0 and not self._finished,
                 "font_finisher_state")
        self._finisher_calls += 1
        _require(type(document) is Document and document.font_config is self.font_config,
                 "font_document_identity")
        self._verify_font_sets(expected_application=2)
        text_count = 0
        text_digest = sha256()
        for page in document.pages:
            for box in page._page_box.descendants():
                if not isinstance(box, TextBox):
                    continue
                style = box.style
                _require(tuple(style["font_family"]) == ("Lato",)
                         and style["font_weight"] in (400, 700)
                         and style["font_style"] == "normal"
                         and style["font_stretch"] == "normal"
                         and style["font_variation_settings"] == "normal"
                         and style["font_variant_caps"] == "normal"
                         and style["font_variant_position"] == "normal",
                         "font_requested_face_not_admitted")
                _check_text(box.text, self._coverage)
                raw = box.text.encode("utf-8")
                text_digest.update(str(len(raw)).encode("ascii") + b":" + raw)
                text_count += len(box.text)

        _require(type(document.fonts) is dict and bool(document.fonts),
                 "font_selected_set")
        selected = set()
        embedded = sha256()
        for font in document.fonts.values():
            original = get_hb_object_data(font.hb_face)
            _require(type(original) is bytes and len(original) <= max(f.size for f in FACES),
                     "font_selected_source_shape")
            digest = sha256(original).hexdigest()
            _require(digest in FACE_BY_DIGEST, "font_selected_source_identity")
            face = FACE_BY_DIGEST[digest]
            _require(len(original) == face.size and font.index == 0
                     and font.family == "Lato" and font.weight == face.weight
                     and font.style == 0 and not font.variations and not font.missing
                     and not font.bitmap and not font.png and not font.svg and not font.colr,
                     "font_selected_face_not_admitted")
            _require(type(font.file_content) is bytes and bool(font.file_content),
                     "font_embedded_program_shape")
            selected.add((face.weight, digest))
            embedded.update((digest + ":" + sha256(font.file_content).hexdigest()
                             + "\n").encode("ascii"))
        _require(text_count > 0, "font_no_rendered_text")
        self._observed = {
            "selected_faces": [{"weight": weight, "source_sha256": digest}
                               for weight, digest in sorted(selected)],
            "selected_font_objects": len(document.fonts),
            "embedded_program_sequence_sha256": embedded.hexdigest(),
            "rendered_text_codepoints": text_count,
            "rendered_text_sequence_sha256": text_digest.hexdigest(),
        }

    def finish(self, pdf: bytes) -> dict:
        """Bind internal selection evidence to the returned candidate, without I/O."""
        _require(self._active and not self._finished and self._finisher_calls == 1
                 and self._observed is not None, "font_finish_without_verified_finisher")
        _require(type(pdf) is bytes and pdf.startswith(b"%PDF-1.7"),
                 "font_pdf_identity")
        self._verify_font_sets(expected_application=2)
        for face in FACES:
            _verify_memfd(self._face_fds[face.sha256], face.size, face.sha256)
        self._finished = True
        return {
            "schema": "finite-lato-selection-v1",
            "html_sha256": self._html_sha256,
            "pdf_sha256": sha256(pdf).hexdigest(),
            "font_source_sha256": [face.sha256 for face in FACES],
            **self._observed,
            "font_codepoint_coverage_verified": True,
            "selected_source_faces_verified": True,
            "full_glyph_semantics_verified": False,
            "reading_order_verified": False,
            "pdf_ua_qualified": False,
            "release_authorized": False,
        }

    def _close(self) -> None:
        """Retire selection; a committed bootstrap is process-owned, not closed."""
        self._active = False
        if self._bootstrap_retained:
            return
        self.font_config = None
        for fd in reversed(self._fds):
            os.close(fd)
        self._fds.clear()

    def __exit__(self, exc_type, exc, traceback) -> bool:
        missing_finish = exc_type is None and not self._finished
        self._close()
        _require(not missing_finish, "font_output_not_finalized")
        return False
