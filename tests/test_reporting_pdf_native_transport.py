"""Explicit native-result transport preserves the complete existing inspection job."""
from contextlib import contextmanager
from hashlib import sha256
import ast
import fcntl
import inspect
import json
import os
from pathlib import Path
import struct
import time
import unittest
from unittest.mock import patch

from reporting import _pdf_fixed_inspection_worker as worker
from reporting import pdf_inspection_request as codec
from reporting import pdf_inspection_result_frame as frame
from reporting import pdf_native_source_job as native
from reporting import pdf_request_descriptor as descriptor
from reporting import pdf_sealed_inspection as sealed
from reporting import pdf_snapshot_inspection as snapshot
from reporting import pdf_structured_source_job as structured
from reporting import pdf_supervised_inspection as supervisor
from reporting.page_checkpoints import _json_bytes
from tests import test_reporting_pdf_fixed_inspection_worker as worker_tests
from tests import test_reporting_pdf_native_source_job as native_tests
from tests import test_reporting_pdf_sealed_inspection as sealed_tests
from tests import test_reporting_pdf_supervised_inspection as supervisor_tests


ROOT = Path(__file__).resolve().parents[1]
NATIVE_DISABLE = "OMNIGENIS_PDF_NATIVE_SOURCE_JOB_DISABLED"
REQUEST_HEADER = struct.Struct(">8sIII")
RESULT_HEADER = struct.Struct(">8sI32s")
LEGACY_PROFILE_PINS = (
    (snapshot, "snapshot_source_profile", "d9c1963782511051a1952df6f5f1a15f92966bd924b635b5023f5a7d88a32d7c"),
    (codec, "inspection_request_profile", "24f7e7f65a95e0c071ffae4dcf51c38fc4c6a1aff8eff5a490e67e8f23cf5484"),
    (descriptor, "descriptor_profile", "b20fbf3f0325cd678aad69319c49f04bf8b96f4c6d07be81cab8c25537c3938a"),
    (sealed, "sealed_inspection_profile", "25ab5fac415b6f9571b15535644ade1fa04b836e3a17473274c62ceb30afeb43"),
    (frame, "result_frame_profile", "c994251417266d15ac74cca19b0fb145f868b83ce7f6ee0934218c4fa05dc9b5"),
    (worker, "worker_profile", "48701b4b85dc7f56d5ac1b5032bb71069c9d44189de3da265b59e94d3b3fead3"),
    (supervisor, "supervisor_profile", "faaeb3370d9077b635a2bcbc09427bbfcbb925d90e81124d606dfb8cea9f2bb6"),
)


class PdfNativeTransportTests(unittest.TestCase):
    """A selected transport family carries both children without adding authority."""

    def setUp(self):
        """Require the explicit native family before creating controlled typed fixtures."""
        self.assertTrue(callable(getattr(snapshot, "native_snapshot_source_profile", None)),
                        "explicit native snapshot transport profile is missing")
        self.h = native_tests.PdfNativeSourceJobTests()
        self.h.setUp()
        self.args = {key: value for key, value in self.h.args.items()
                     if key != "presentation_ir"}
        self.args.update(presentation_ir_bytes=_json_bytes(self.h.ir),
                         expected_source_profile_sha256=snapshot.NATIVE_PROFILE_SHA256)

    def fixture(self, **changes):
        """Create exact packet bytes and independently specified native-family expectations."""
        args = {**self.args, **changes}
        packet = codec.encode_pdf_snapshot_request(
            **args, expected_protocol_profile_sha256=codec.NATIVE_PROFILE_SHA256)
        expected = {
            "expected_packet_sha256": sha256(packet).hexdigest(),
            "expected_protocol_profile_sha256": codec.NATIVE_PROFILE_SHA256,
            "expected_descriptor_profile_sha256": descriptor.NATIVE_PROFILE_SHA256,
            "expected_namespace_id": args["namespace_id"],
            "expected_job_id": args["job_id"],
            "expected_request_sha256": args["request_sha256"],
        }
        return packet, expected, args

    @contextmanager
    def request(self, **changes):
        """Own one real sealed anonymous request while preserving receiver expectations."""
        packet, expected, args = self.fixture(**changes)
        with descriptor.sealed_pdf_request(packet, **expected) as fd:
            yield fd, expected, args, packet

    def invoke(self, fd, expected, **changes):
        """Select the fixed native execution profile without callbacks or result input."""
        return sealed.execute_sealed_pdf_inspection_job(fd, **{
            **expected, "expected_execution_profile_sha256": sealed.NATIVE_PROFILE_SHA256,
            **changes,
        })

    def controlled_result(self, **changes):
        """Produce real typed coordinator results using only controlled native observations."""
        with self.h.mocked():
            return self.h.run_job(**changes)

    def frame_options(self, args=None, **changes):
        """Resolve result expectations from the original request, never returned metadata."""
        values = self.args if args is None else args
        return {
            "expected_pdf_sha256": values["expected_pdf_sha256"],
            "expected_ir_sha256": values["expected_ir_sha256"],
            "expected_page_count": values["page_count"],
            "expected_language": values["expected_language"],
            "expected_namespace_id": values["namespace_id"],
            "expected_job_id": values["job_id"],
            "expected_request_sha256": values["request_sha256"],
            "expected_resource_profile_sha256": native.PROFILE_SHA256,
            "expected_frame_profile_sha256": frame.NATIVE_PROFILE_SHA256,
            **changes,
        }

    def encode_result(self, result=None, **changes):
        """Encode the selected exact native type with independent result expectations."""
        value = self.controlled_result() if result is None else result
        return frame.encode_pdf_inspection_result_frame(value, **self.frame_options(**changes))

    def decode_result(self, packet, **changes):
        """Decode native-family bytes without constructing a trusted result object."""
        return frame.decode_pdf_inspection_result_frame(packet, **self.frame_options(**changes))

    def forge_result(self, record=None, raw=None, magic=b"OGPDFRS2"):
        """Independently rehash altered result bytes to exercise semantic binding checks."""
        body = _json_bytes(record) if raw is None else raw
        return RESULT_HEADER.pack(magic, len(body), sha256(body).digest()) + body

    def reject_result(self, packet, **changes):
        """Require a fixed content-free rejection of a complete adversarial frame."""
        with self.assertRaisesRegex(frame.PdfInspectionResultFrameError,
                                    "^pdf_inspection_result_frame_invalid$"):
            self.decode_result(packet, **changes)

    def rehash_children(self, record):
        """Recompute immediate child hashes after a deliberate independently built mutation."""
        child = record["structured_inspection"]
        child["source_inspection_sha256"] = sha256(_json_bytes(child["source_inspection"])).hexdigest()
        child["structure_inspection_sha256"] = sha256(_json_bytes(child["structure_tree"])).hexdigest()
        record["native_inspection_sha256"] = sha256(_json_bytes(record["native_inspection"])).hexdigest()
        record["structured_inspection_sha256"] = sha256(_json_bytes(child)).hexdigest()
        return record

    def decode_request(self, packet, **changes):
        """Use the original independent receiver identities even for a newly hashed packet."""
        return codec.decode_pdf_snapshot_request(packet, **{
            "expected_packet_sha256": sha256(packet).hexdigest(),
            "expected_protocol_profile_sha256": codec.NATIVE_PROFILE_SHA256,
            "expected_namespace_id": self.args["namespace_id"],
            "expected_job_id": self.args["job_id"],
            "expected_request_sha256": self.args["request_sha256"],
            **changes,
        })

    def reframe_request(self, packet, metadata=None, magic=b"OGPDFRQ2"):
        """Retain opaque source and PDF segments while independently changing the envelope."""
        _, meta_size, source_size, pdf_size = REQUEST_HEADER.unpack_from(packet)
        old = packet[REQUEST_HEADER.size:REQUEST_HEADER.size + meta_size]
        encoded = old if metadata is None else _json_bytes(metadata)
        return (REQUEST_HEADER.pack(magic, len(encoded), source_size, pdf_size) + encoded
                + packet[REQUEST_HEADER.size + meta_size:])

    def context(self, expected, args, **changes):
        """Build the unchanged fourteen-field worker vocabulary using independent native pins."""
        return {
            "expected_worker_profile_sha256": worker.NATIVE_PROFILE_SHA256,
            "expected_packet_sha256": expected["expected_packet_sha256"],
            "expected_protocol_profile_sha256": codec.NATIVE_PROFILE_SHA256,
            "expected_descriptor_profile_sha256": descriptor.NATIVE_PROFILE_SHA256,
            "expected_execution_profile_sha256": sealed.NATIVE_PROFILE_SHA256,
            **self.frame_options(args),
            **changes,
        }

    def supervise(self, fd, context, **changes):
        """Select only the fixed native supervisor with canonical expected context bytes."""
        return supervisor.execute_supervised_pdf_inspection(fd, **{
            "expected_context": _json_bytes(context),
            "expected_supervisor_profile_sha256": supervisor.NATIVE_PROFILE_SHA256,
            **changes,
        })

    def process_fixture(self):
        """Reuse the existing real-child fault harness without inheriting its test methods."""
        helper = supervisor_tests.SupervisedInspectionTests()
        helper.setUp()
        return helper

    def real_arguments(self, pages, ir=None, pdf=None):
        """Bind admitted renderer output without reusing a synthetic control-flow digest."""
        values = self.h.native_arguments(pages, ir=ir, pdf=pdf)
        raw = _json_bytes(values.pop("presentation_ir"))
        return {**self.args, **values, "presentation_ir_bytes": raw}

    def test_selected_native_sealed_job_preserves_complete_result(self):
        """One capture dispatch retains both typed children and every original result byte."""
        with self.h.mocked():
            original = self.h.run_job()
        original_bytes = original.to_bytes()
        with self.request() as (fd, expected, args, packet):
            os.lseek(fd, 7, os.SEEK_SET)
            with self.h.mocked() as calls, \
                 patch.object(sealed, "execute_pdf_snapshot_inspection_job",
                              wraps=snapshot.execute_pdf_snapshot_inspection_job) as dispatch, \
                 patch.object(snapshot, "execute_pdf_structured_source_job",
                              side_effect=AssertionError("legacy transport fallback forbidden")) as fallback:
                result = self.invoke(fd, expected)
            dispatch.assert_called_once_with(**args)
            fallback.assert_not_called()
            self.assertEqual(calls, [native_tests.NATIVE, native_tests.STRUCTURED])
            self.assertIs(type(result), native.PdfNativeSourceResult)
            self.assertEqual(result.to_bytes(), original_bytes)
            data = json.loads(result.to_bytes())
            self.assertEqual(data["resource_profile_sha256"], native.PROFILE_SHA256)
            self.assertEqual(data["structured_inspection"]["resource_profile_sha256"],
                             structured.PROFILE_SHA256)
            self.assertEqual(data["native_inspection"]["profile_sha256"],
                             native.NATIVE_PROFILE_SHA256)
            self.assertEqual(data["native_inspection_sha256"],
                             sha256(_json_bytes(data["native_inspection"])).hexdigest())
            self.assertEqual(data["structured_inspection_sha256"],
                             sha256(_json_bytes(data["structured_inspection"])).hexdigest())
            self.assertEqual(len(data["inspection_dimensions"]), 9)
            self.assertEqual(data["inspection_dimensions"][-1],
                             "native_tounicode_same_font_explicit_width_coverage")
            self.assertFalse(data["aggregate_job_resources_qualified"])
            self.assertFalse(data["release_authorized"])
            self.assertEqual(os.pread(fd, len(packet), 0), packet)
            self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), 7)
            self.assertFalse(os.get_inheritable(fd))

    def test_legacy_profile_identities_and_limits_remain_exact(self):
        """Fixed baseline hashes detect coordinated changes to both legacy code and manifests."""
        for module, name, digest in LEGACY_PROFILE_PINS:
            with self.subTest(profile=name):
                self.assertEqual(module.PROFILE_SHA256, digest)
                self.assertEqual(sha256(_json_bytes(getattr(module, name)())).hexdigest(), digest)
        self.assertEqual(worker.KERNEL_ADMISSION_PROFILE_SHA256,
                         "4684c54f07c27aedd39113323d3fb9e0e8297d5958025f015d04031080006d01")
        self.assertEqual(frame.MAX_RESULT_BYTES, 294912)
        self.assertEqual(frame.MAX_FRAME_BYTES, 294956)
        self.assertEqual(codec.MAGIC, b"OGPDFRQ1")
        self.assertEqual(frame.MAGIC, b"OGPDFRS1")

    def test_native_profiles_are_distinct_detached_and_bounded(self):
        """Each explicit native profile is pinned independently without widening the old family."""
        for module, legacy_name, _ in LEGACY_PROFILE_PINS:
            builder = getattr(module, "native_" + legacy_name)
            value = builder()
            with self.subTest(profile=legacy_name):
                self.assertEqual(sha256(_json_bytes(value)).hexdigest(), module.NATIVE_PROFILE_SHA256)
                self.assertNotEqual(module.PROFILE_SHA256, module.NATIVE_PROFILE_SHA256)
                value["release_authorized"] = True
                self.assertIs(builder()["release_authorized"], False)
                for name in ("aggregate_job_resources_qualified", "default_pipeline_activated",
                             "hard_job_deadline_enforced", "hard_job_deadline_qualified",
                             "service_installed", "sender_authenticated", "transport_authenticated"):
                    if name in builder():
                        self.assertIs(builder()[name], False)
        self.assertEqual(frame.NATIVE_MAX_RESULT_BYTES, 311296)
        self.assertEqual(frame.NATIVE_MAX_FRAME_BYTES, 311340)
        self.assertEqual(codec.NATIVE_MAGIC, b"OGPDFRQ2")
        self.assertEqual(frame.NATIVE_MAGIC, b"OGPDFRS2")
        self.assertEqual(codec.HEADER.size, 20)
        self.assertEqual(frame.HEADER.size, 44)

    def test_public_argument_vocabularies_remain_fixed(self):
        """Family selection adds no callbacks, commands, caller budgets, receipts or extra options."""
        expected_snapshot = set(self.args)
        self.assertEqual(len(expected_snapshot), 11)
        self.assertEqual(set(inspect.signature(snapshot.execute_pdf_snapshot_inspection_job).parameters),
                         expected_snapshot)
        self.assertEqual(set(inspect.signature(supervisor.execute_supervised_pdf_inspection).parameters),
                         {"request_fd", "expected_context", "expected_supervisor_profile_sha256"})
        _, expected, args = self.fixture()
        self.assertEqual(len(self.context(expected, args)), 14)
        for function in (snapshot.execute_pdf_snapshot_inspection_job,
                         codec.encode_pdf_snapshot_request, codec.decode_pdf_snapshot_request,
                         descriptor.sealed_pdf_request, descriptor.read_sealed_pdf_request,
                         sealed.execute_sealed_pdf_inspection_job,
                         frame.encode_pdf_inspection_result_frame, frame.decode_pdf_inspection_result_frame,
                         supervisor.execute_supervised_pdf_inspection):
            self.assertFalse(any(value.kind in (value.VAR_KEYWORD, value.VAR_POSITIONAL)
                                 for value in inspect.signature(function).parameters.values()))

    def test_legacy_request_wire_bytes_remain_identical(self):
        """The original request keeps its exact independent big-endian framing and metadata."""
        helper = sealed_tests.PdfSealedInspectionTests()
        helper.setUp()
        packet, _, args = helper.fixture()
        metadata = _json_bytes({key: value for key, value in args.items()
                                if key not in ("presentation_ir_bytes", "pdf_bytes")})
        expected = (REQUEST_HEADER.pack(b"OGPDFRQ1", len(metadata),
                    len(args["presentation_ir_bytes"]), len(args["pdf_bytes"]))
                    + metadata + args["presentation_ir_bytes"] + args["pdf_bytes"])
        self.assertEqual(packet, expected)

    def test_native_request_is_lossless_and_returns_original_arguments(self):
        """Only the selected version and pinned metadata differ in the existing packet shape."""
        packet, _, args = self.fixture()
        metadata = _json_bytes({key: value for key, value in args.items()
                                if key not in ("presentation_ir_bytes", "pdf_bytes")})
        expected = (REQUEST_HEADER.pack(b"OGPDFRQ2", len(metadata),
                    len(args["presentation_ir_bytes"]), len(args["pdf_bytes"]))
                    + metadata + args["presentation_ir_bytes"] + args["pdf_bytes"])
        self.assertEqual(packet, expected)
        self.assertEqual(self.decode_request(packet), args)
        self.assertEqual(self.fixture()[0], packet)

    def test_snapshot_mixed_family_pins_prevent_both_executors(self):
        """A resource family cannot be inferred permissively from either one of two mixed pins."""
        cases = (
            {"expected_resource_profile_sha256": structured.PROFILE_SHA256},
            {"expected_source_profile_sha256": snapshot.PROFILE_SHA256},
            {"expected_source_profile_sha256": "f" * 64},
        )
        for changes in cases:
            with self.subTest(changes=changes), self.h.mocked() as calls, \
                 patch.object(snapshot, "_decode_source") as decode, \
                 self.assertRaises(snapshot.PdfSnapshotInspectionError):
                snapshot.execute_pdf_snapshot_inspection_job(**{**self.args, **changes})
            decode.assert_not_called()
            self.assertEqual(calls, [])

    def test_native_snapshot_rejects_ambiguous_source_before_inspection(self):
        """The additional family retains canonical JSON and strict immutable-source admission."""
        raw = self.args["presentation_ir_bytes"]
        variants = (b" " + raw, raw + b"\n", b"\xef\xbb\xbf" + raw,
                    raw[:-1] + b',"report_id":"foreign"}',
                    raw.replace(b'"value":17', b'"value":17,"\\u0076alue":18'),
                    raw.replace(b'"value":17', b'"value":1e-9999'),
                    raw.replace(b'"value":17', b'"value":NaN'), b"[]")
        for value in variants:
            with self.subTest(value=value[:20]), self.h.mocked() as calls, \
                 self.assertRaises(snapshot.PdfSnapshotInspectionError):
                snapshot.execute_pdf_snapshot_inspection_job(**{
                    **self.args, "presentation_ir_bytes": value,
                    "expected_ir_sha256": sha256(value).hexdigest(),
                })
            self.assertEqual(calls, [])
        for value in (bytearray(raw), memoryview(raw), raw.decode(), None):
            with self.h.mocked() as calls, self.assertRaises(snapshot.PdfSnapshotInspectionError):
                snapshot.execute_pdf_snapshot_inspection_job(**{**self.args, "presentation_ir_bytes": value})
            self.assertEqual(calls, [])

    def test_native_snapshot_digest_and_byte_budget_precede_decode(self):
        """Unbound or oversized source bytes never reach the canonical JSON decoder."""
        oversized = b"x" * (snapshot.MAX_SOURCE_BYTES + 1)
        for changes in ({"expected_ir_sha256": "f" * 64},
                        {"presentation_ir_bytes": oversized,
                         "expected_ir_sha256": sha256(oversized).hexdigest()}):
            with self.subTest(keys=tuple(changes)), patch.object(snapshot, "_decode_source") as decode, \
                 self.h.mocked() as calls, self.assertRaises(snapshot.PdfSnapshotInspectionError):
                snapshot.execute_pdf_snapshot_inspection_job(**{**self.args, **changes})
            decode.assert_not_called()
            self.assertEqual(calls, [])

    def test_native_snapshot_rejects_foreign_or_generic_results(self):
        """A typed result from another job and caller-shaped success cannot satisfy this source."""
        foreign = self.controlled_result(job_id="synthetic-foreign-job")
        for result in (foreign, {"status": "PASS"}, True, None, object()):
            with self.subTest(kind=type(result).__name__), \
                 patch.object(snapshot, "execute_pdf_native_source_job", return_value=result) as execute, \
                 self.assertRaises(snapshot.PdfSnapshotInspectionError):
                snapshot.execute_pdf_snapshot_inspection_job(**self.args)
            execute.assert_called_once()

    def test_native_disables_do_not_disable_legacy_sealed_execution(self):
        """Opting out of the native family leaves the independently selected legacy route available."""
        legacy = sealed_tests.PdfSealedInspectionTests()
        legacy.setUp()
        for flag in (NATIVE_DISABLE, "OMNIGENIS_PDF_TOUNICODE_WIDTH_COVERAGE_DISABLED"):
            with self.subTest(flag=flag), patch.dict(os.environ, {flag: "1"}):
                with self.assertRaises(codec.PdfInspectionRequestError):
                    self.fixture()
                with legacy.request() as (fd, expected, _, _), legacy.h.h.mocked():
                    result = legacy.invoke(fd, expected)
                    self.assertIs(type(result), structured.PdfStructuredSourceResult)
                    self.assertEqual(len(result.to_dict()["inspection_dimensions"]), 8)

    def test_native_prerequisite_disables_prevent_supervisor_launch(self):
        """Each transitive opt-out refuses admission without launching any child."""
        flags = (NATIVE_DISABLE, "OMNIGENIS_PDF_TOUNICODE_WIDTH_COVERAGE_DISABLED",
                 "OMNIGENIS_PDF_STRUCTURED_SOURCE_JOB_DISABLED",
                 "OMNIGENIS_PDF_SNAPSHOT_INSPECTION_DISABLED",
                 "OMNIGENIS_PDF_INSPECTION_REQUEST_DISABLED",
                 "OMNIGENIS_PDF_REQUEST_DESCRIPTOR_DISABLED",
                 "OMNIGENIS_PDF_SEALED_INSPECTION_DISABLED",
                 "OMNIGENIS_PDF_INSPECTION_RESULT_FRAME_DISABLED",
                 "OMNIGENIS_PDF_FIXED_INSPECTION_WORKER_DISABLED",
                 "OMNIGENIS_PDF_SUPERVISOR_DISABLED")
        with self.request() as (fd, expected, args, _):
            context = self.context(expected, args)
            for flag in flags:
                with self.subTest(flag=flag), patch.dict(os.environ, {flag: "1"}), \
                     patch.object(supervisor.subprocess, "Popen") as launch, \
                     self.assertRaises(supervisor.PdfSupervisedInspectionError):
                    self.supervise(fd, context)
                launch.assert_not_called()

    def test_request_magic_and_selected_profile_cannot_cross_families(self):
        """A recognized different version is rejected instead of becoming an alias."""
        packet, _, _ = self.fixture()
        legacy = sealed_tests.PdfSealedInspectionTests()
        legacy.setUp()
        old, _, _ = legacy.fixture()
        cases = ((packet, codec.PROFILE_SHA256), (old, codec.NATIVE_PROFILE_SHA256),
                 (self.reframe_request(packet, magic=b"OGPDFRQ1"), codec.NATIVE_PROFILE_SHA256),
                 (self.reframe_request(packet, magic=b"OGPDFRQ3"), codec.NATIVE_PROFILE_SHA256))
        for value, profile in cases:
            with self.subTest(magic=value[:8], profile=profile), \
                 self.assertRaises(codec.PdfInspectionRequestError):
                self.decode_request(value, expected_protocol_profile_sha256=profile)

    def test_rehashed_request_metadata_cannot_mix_source_and_resource_families(self):
        """Recomputing the packet hash does not promote old source or resource pins."""
        packet, _, _ = self.fixture()
        size = REQUEST_HEADER.unpack_from(packet)[1]
        metadata = json.loads(packet[REQUEST_HEADER.size:REQUEST_HEADER.size + size])
        for key, value in (("expected_source_profile_sha256", snapshot.PROFILE_SHA256),
                           ("expected_resource_profile_sha256", structured.PROFILE_SHA256)):
            altered = self.reframe_request(packet, {**metadata, key: value})
            with self.subTest(field=key), self.assertRaises(codec.PdfInspectionRequestError):
                self.decode_request(altered)
            with self.assertRaises(codec.PdfInspectionRequestError):
                self.fixture(**{key: value})

    def test_rehashed_request_remains_bound_to_independent_receiver(self):
        """A canonical cross-job packet cannot replace independently resolved receiver identity."""
        packet, _, _ = self.fixture()
        size = REQUEST_HEADER.unpack_from(packet)[1]
        metadata = json.loads(packet[REQUEST_HEADER.size:REQUEST_HEADER.size + size])
        for field in ("namespace_id", "job_id", "request_sha256"):
            wrong = "f" * 64 if field.endswith("sha256") else "synthetic-foreign"
            altered = self.reframe_request(packet, {**metadata, field: wrong})
            with self.subTest(field=field), self.assertRaises(codec.PdfInspectionRequestError):
                self.decode_request(altered)

    def test_native_request_envelope_lengths_are_rejected_before_metadata_parse(self):
        """Forged lengths, overflow, truncation and concatenation do not reach JSON allocation."""
        packet, _, _ = self.fixture()
        _, m, s, p = REQUEST_HEADER.unpack_from(packet)
        variants = (
            REQUEST_HEADER.pack(b"OGPDFRQ2", codec.MAX_METADATA_BYTES + 1, s, p) + packet[20:],
            REQUEST_HEADER.pack(b"OGPDFRQ2", m, codec.MAX_SOURCE_BYTES + 1, p) + packet[20:],
            REQUEST_HEADER.pack(b"OGPDFRQ2", m, s, codec.MAX_PDF_BYTES + 1) + packet[20:],
            packet[:-1], packet + packet, packet + b"x", packet[:19],
        )
        for value in variants:
            with self.subTest(length=len(value)), patch.object(codec.json, "loads") as parse, \
                 self.assertRaises(codec.PdfInspectionRequestError):
                self.decode_request(value)
            parse.assert_not_called()

    def test_descriptor_family_mismatch_precedes_allocation_and_capture(self):
        """Valid request bytes cannot excuse mixed descriptor and protocol expectations."""
        packet, expected, _ = self.fixture()
        variants = ({"expected_descriptor_profile_sha256": descriptor.PROFILE_SHA256},
                    {"expected_protocol_profile_sha256": codec.PROFILE_SHA256})
        with descriptor.sealed_pdf_request(packet, **expected) as fd:
            for changes in variants:
                with self.subTest(changes=changes), patch.object(descriptor.os, "memfd_create") as allocate:
                    with self.assertRaises(descriptor.PdfRequestDescriptorError):
                        with descriptor.sealed_pdf_request(packet, **{**expected, **changes}):
                            self.fail("mixed family allocated a descriptor")
                    allocate.assert_not_called()
                with patch.object(descriptor.os, "pread") as read, \
                     self.assertRaises(descriptor.PdfRequestDescriptorError):
                    descriptor.read_sealed_pdf_request(fd, **{**expected, **changes})
                read.assert_not_called()

    def test_native_descriptor_keeps_real_seals_and_positional_read_semantics(self):
        """The selected family uses the same immutable private inode and borrowed-handle rules."""
        with self.request() as (fd, expected, args, packet):
            required = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
            self.assertEqual(fcntl.fcntl(fd, fcntl.F_GET_SEALS) & required, required)
            self.assertEqual(os.fstat(fd).st_mode & 0o777, 0o600)
            with self.assertRaises(OSError):
                os.pwrite(fd, b"x", 0)
            os.lseek(fd, 7, os.SEEK_SET)
            original = os.pread

            def short_read(handle, count, offset):
                """Exercise repeated real positional reads without touching the borrowed offset."""
                return original(handle, min(count, 11), offset)

            with patch.object(descriptor.os, "pread", side_effect=short_read):
                self.assertEqual(descriptor.read_sealed_pdf_request(fd, **expected), args)
            self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), 7)
            self.assertEqual(os.pread(fd, len(packet), 0), packet)

    def test_sealed_execution_family_mismatch_precedes_capture(self):
        """The execution, descriptor and request pins must select the same reviewed family."""
        with self.request() as (fd, expected, _, _):
            variants = ({"expected_execution_profile_sha256": sealed.PROFILE_SHA256},
                        {"expected_descriptor_profile_sha256": descriptor.PROFILE_SHA256},
                        {"expected_protocol_profile_sha256": codec.PROFILE_SHA256})
            for changes in variants:
                with self.subTest(changes=changes), \
                     patch.object(sealed.descriptor, "read_sealed_pdf_request") as capture, \
                     self.assertRaises(sealed.PdfSealedInspectionError):
                    self.invoke(fd, expected, **changes)
                capture.assert_not_called()

    def test_sealed_execution_rebinds_typed_foreign_native_results(self):
        """Exact native type alone does not satisfy PDF, source, page or job identity."""
        variants = ({"job_id": "synthetic-foreign"}, {"namespace_id": "synthetic-other"},
                    {"request_sha256": "f" * 64}, {"page_count": 1})
        with self.request() as (fd, expected, _, _):
            for changes in variants:
                result = self.controlled_result(**changes)
                with self.subTest(changes=changes), \
                     patch.object(sealed, "execute_pdf_snapshot_inspection_job", return_value=result), \
                     self.assertRaises(sealed.PdfSealedInspectionError):
                    self.invoke(fd, expected)

    def test_native_disable_during_capture_prevents_dispatch(self):
        """A valid immutable capture cannot bypass a subsequent family opt-out."""
        read = descriptor.read_sealed_pdf_request

        def disabled_capture(*args, **kwargs):
            """Disable only after the real descriptor reader has returned exact arguments."""
            result = read(*args, **kwargs)
            os.environ[NATIVE_DISABLE] = "1"
            return result

        with self.request() as (fd, expected, _, _), patch.dict(os.environ, {}), \
             patch.object(sealed.descriptor, "read_sealed_pdf_request", side_effect=disabled_capture), \
             patch.object(sealed, "execute_pdf_snapshot_inspection_job") as execute, \
             self.assertRaises(sealed.PdfSealedInspectionError):
            self.invoke(fd, expected)
        execute.assert_not_called()

    def test_native_disable_during_execution_withholds_complete_result(self):
        """A finished result remains unacceptable if its optional native family was disabled."""
        execute = snapshot.execute_pdf_snapshot_inspection_job

        def disabled_result(**args):
            """Obtain the complete typed result before changing the enabled prerequisite."""
            result = execute(**args)
            os.environ[NATIVE_DISABLE] = "1"
            return result

        with self.request() as (fd, expected, _, _), patch.dict(os.environ, {}), self.h.mocked(), \
             patch.object(sealed, "execute_pdf_snapshot_inspection_job", side_effect=disabled_result), \
             self.assertRaises(sealed.PdfSealedInspectionError):
            self.invoke(fd, expected)

    def test_native_frame_roundtrip_preserves_entire_original_body(self):
        """The new frame carries both complete children and leaves the original seal intact."""
        result = self.controlled_result()
        body = result.to_bytes()
        packet = self.encode_result(result)
        expected = RESULT_HEADER.pack(b"OGPDFRS2", len(body), sha256(body).digest()) + body
        self.assertEqual(packet, expected)
        self.assertEqual(self.decode_result(packet), body)
        self.assertEqual(result.to_bytes(), body)
        self.assertIs(type(self.decode_result(packet)), bytes)
        self.assertEqual(len(json.loads(body)["inspection_dimensions"]), 9)

    def test_native_frame_decode_neither_reconstructs_receipts_nor_parses_pdf(self):
        """Unsigned JSON transport stays distinct from native receipt construction and PDF parsing."""
        packet = self.encode_result()
        with patch.object(native, "PdfNativeSourceResult", side_effect=AssertionError("no reconstruction")) as outer, \
             patch.object(frame, "PdfNativeSourceResult", side_effect=AssertionError("no frame reconstruction")) as framed, \
             patch.object(frame, "PdfStructuredSourceResult", side_effect=AssertionError("no structured receipt")) as legacy, \
             patch.object(native.native, "PdfToUnicodeWidthCoverage", side_effect=AssertionError("no receipt")) as inner, \
             patch("pypdf.PdfReader", side_effect=AssertionError("parent parser forbidden")):
            result = self.decode_result(packet)
        outer.assert_not_called()
        framed.assert_not_called()
        legacy.assert_not_called()
        inner.assert_not_called()
        self.assertIs(type(result), bytes)

    def test_native_frame_rejects_legacy_result_types_and_magic(self):
        """An otherwise valid complete result cannot be reclassified as another wire family."""
        original = self.controlled_result()
        legacy = original.structured_inspection
        legacy_options = self.frame_options(expected_resource_profile_sha256=structured.PROFILE_SHA256,
                                           expected_frame_profile_sha256=frame.PROFILE_SHA256)
        old_packet = frame.encode_pdf_inspection_result_frame(legacy, **legacy_options)
        new_packet = self.encode_result(original)
        with self.assertRaises(frame.PdfInspectionResultFrameError):
            frame.encode_pdf_inspection_result_frame(legacy, **self.frame_options())
        with self.assertRaises(frame.PdfInspectionResultFrameError):
            frame.encode_pdf_inspection_result_frame(original, **legacy_options)
        self.reject_result(old_packet)
        with self.assertRaises(frame.PdfInspectionResultFrameError):
            frame.decode_pdf_inspection_result_frame(new_packet, **legacy_options)
        self.reject_result(b"OGPDFRS1" + new_packet[8:])
        self.reject_result(b"OGPDFRS3" + new_packet[8:])
        for value in (None, False, True, original.to_dict(), original.to_bytes(), object()):
            with self.assertRaises(frame.PdfInspectionResultFrameError):
                frame.encode_pdf_inspection_result_frame(value, **self.frame_options())

    def test_native_frame_independent_expectations_reject_foreign_result(self):
        """Each receiver expectation remains independently enforced at encoding and decoding."""
        result = self.controlled_result()
        packet = self.encode_result(result)
        for key in self.frame_options():
            wrong = 1 if key == "expected_page_count" else (
                "f" * 64 if key.endswith("sha256") else "synthetic-foreign")
            with self.subTest(field=key):
                self.reject_result(packet, **{key: wrong})
                with self.assertRaises(frame.PdfInspectionResultFrameError):
                    self.encode_result(result, **{key: wrong})

    def test_native_frame_rejects_mutated_sealed_objects(self):
        """Matching outer IDs cannot excuse mutation of either retained original typed child."""
        for child, field, value in (("native_inspection", "bfchar_source_count", 49),
                                    ("structured_inspection", "namespace_id", "synthetic-foreign")):
            result = self.controlled_result()
            object.__setattr__(getattr(result, child), field, value)
            with self.subTest(child=child), self.assertRaises(frame.PdfInspectionResultFrameError):
                self.encode_result(result)

    def test_native_frame_rehashed_child_identity_and_profile_changes_are_rejected(self):
        """A recomputed child checksum does not replace its exact native document and policy identity."""
        source = self.controlled_result().to_bytes()
        variants = (("pdf_sha256", "f" * 64), ("ir_sha256", "f" * 64),
                    ("plan_sha256", "f" * 64), ("page_count", 1),
                    ("language", "pt-BR"), ("profile_sha256", "f" * 64),
                    ("previous_tounicode_bfchar_sources_profile_sha256", "f" * 64),
                    ("schema_version", "2.0.0"), ("status", "PASS"),
                    ("parser_version", "foreign"), ("policy_id", "foreign"),
                    ("prior_tounicode_bfchar_sources_sha256", "invalid"))
        for field, value in variants:
            altered = json.loads(source)
            altered["native_inspection"][field] = value
            self.rehash_children(altered)
            with self.subTest(field=field):
                self.reject_result(self.forge_result(altered))

    def test_native_frame_count_types_are_exact_integers(self):
        """Boolean and integral float counts cannot satisfy strict native receipt domains."""
        source = self.controlled_result(page_count=1).to_bytes()
        fields = ("tounicode_stream_count", "cid_width_font_count", "bfchar_source_count",
                  "bfchar_covered_source_count", "explicit_cid_width_count")
        for field in fields:
            for value in (True, 1.0):
                altered = json.loads(source)
                child = altered["native_inspection"]
                child.update({name: 1 for name in fields})
                child[field] = value
                self.rehash_children(altered)
                with self.subTest(field=field, kind=type(value).__name__):
                    self.reject_result(self.forge_result(altered), expected_page_count=1)

    def test_native_frame_rechecks_width_count_relations_and_bounds(self):
        """Correct checksums cannot turn contradictory or oversized native observations into success."""
        source = self.controlled_result().to_bytes()
        variants = ({"tounicode_stream_count": 0}, {"tounicode_stream_count": 32 * 33 + 1,
                                                     "cid_width_font_count": 32 * 33 + 1},
                    {"cid_width_font_count": 4}, {"bfchar_source_count": 0,
                                                   "bfchar_covered_source_count": 0},
                    {"bfchar_source_count": 16385, "bfchar_covered_source_count": 16385,
                     "explicit_cid_width_count": 16385, "tounicode_stream_count": 5,
                     "cid_width_font_count": 5},
                    {"bfchar_covered_source_count": 49}, {"explicit_cid_width_count": 49},
                    {"explicit_cid_width_count": 4096 * 3 + 1},
                    {"same_font_explicit_width_coverage_valid": False})
        for changes in variants:
            altered = json.loads(source)
            altered["native_inspection"].update(changes)
            self.rehash_children(altered)
            with self.subTest(changes=changes):
                self.reject_result(self.forge_result(altered))

    def test_native_frame_page_identity_types_remain_strict_at_child_depths(self):
        """Rehashed true-valued page identities must not exploit Python's true-equals-one comparison."""
        source = self.controlled_result(page_count=1).to_bytes()
        paths = ((), ("native_inspection",), ("structured_inspection",),
                 ("structured_inspection", "structure_tree"),
                 ("structured_inspection", "source_inspection"))
        for path in paths:
            for value in (True, 1.0):
                altered = json.loads(source)
                child = altered
                for key in path:
                    child = child[key]
                child["page_count"] = value
                self.rehash_children(altered)
                with self.subTest(path=path, kind=type(value).__name__):
                    self.reject_result(self.forge_result(altered), expected_page_count=1)

    def test_native_frame_rejects_jointly_rehashed_foreign_plan(self):
        """Agreement among forged children cannot override the independently derived text plan."""
        altered = self.controlled_result().to_dict()
        wrong = "f" * 64
        altered["plan_sha256"] = wrong
        altered["native_inspection"]["plan_sha256"] = wrong
        second = altered["structured_inspection"]
        second["structure_tree"]["plan_sha256"] = wrong
        original = second["source_inspection"]
        original["document_content"]["plan_sha256"] = wrong
        original["inspection_set"]["page_bundle"]["text_stream"]["plan_sha256"] = wrong
        self.rehash_children(altered)
        legacy_options = self.frame_options(expected_resource_profile_sha256=structured.PROFILE_SHA256,
                                           expected_frame_profile_sha256=frame.PROFILE_SHA256)
        legacy_packet = self.forge_result(second, magic=b"OGPDFRS1")
        self.assertEqual(frame.decode_pdf_inspection_result_frame(legacy_packet, **legacy_options),
                         _json_bytes(second))
        self.reject_result(self.forge_result(altered))

    def test_native_frame_closed_fields_and_nonclaims_cannot_be_promoted(self):
        """Outer and native-child vocabularies stay exact and every unsupported claim stays false."""
        source = self.controlled_result().to_bytes()
        for path in ((), ("native_inspection",)):
            for change in ("unknown", "missing", "claim"):
                altered = json.loads(source)
                child = altered if not path else altered[path[0]]
                if change == "unknown":
                    child["arbitrary_executor"] = "forbidden"
                elif change == "missing":
                    del child["release_authorized"]
                else:
                    child["release_authorized"] = True
                self.rehash_children(altered)
                with self.subTest(path=path, change=change):
                    self.reject_result(self.forge_result(altered))
        for field in ("worker_results_authenticated", "aggregate_job_resources_qualified",
                      "glyph_widths_audited", "unicode_mappings_audited", "pdf_ua_qualified",
                      "reading_order_verified", "default_pipeline_activated"):
            for path in ((), ("native_inspection",)):
                altered = json.loads(source)
                child = altered if not path else altered[path[0]]
                child[field] = True
                self.rehash_children(altered)
                with self.subTest(field=field, path=path):
                    self.reject_result(self.forge_result(altered))

    def test_native_frame_rehashed_structured_linkage_and_scope_changes_fail(self):
        """The new envelope retains the existing structured child's text and coverage checks."""
        source = self.controlled_result().to_bytes()
        changes = (("text", "expected_text_sha256", "f" * 64),
                   ("tree", "mapped_mcids", 1),
                   ("source", "inspection_dimensions", ["text"]),
                   ("tree", "forward_reverse_linkage_verified", False),
                   ("source", "release_authorized", True))
        for location, field, value in changes:
            altered = json.loads(source)
            second = altered["structured_inspection"]
            child = second if location == "text" else second[
                "structure_tree" if location == "tree" else "source_inspection"]
            child[field] = value
            self.rehash_children(altered)
            with self.subTest(location=location, field=field):
                self.reject_result(self.forge_result(altered))
        for dimensions in (["text"], list(reversed(json.loads(source)["inspection_dimensions"]))):
            altered = json.loads(source)
            altered["inspection_dimensions"] = dimensions
            self.reject_result(self.forge_result(altered))

    def test_native_frame_hashes_and_envelope_bounds_precede_json_decode(self):
        """Frame corruption and native-specific overflows fail before parsing a result body."""
        packet = self.encode_result()
        variants = (packet[:43], packet[:-1], packet + b"x", packet + packet,
                    packet[:12] + b"\x00" * 32 + packet[44:],
                    RESULT_HEADER.pack(b"OGPDFRS2", 0, b"\x00" * 32),
                    RESULT_HEADER.pack(b"OGPDFRS2", 311297, b"\x00" * 32) + packet[44:],
                    b"x" * 311341)
        for value in variants:
            with self.subTest(length=len(value)), patch.object(frame.json, "loads") as parse:
                self.reject_result(value)
            parse.assert_not_called()
        for value in (None, True, bytearray(packet), memoryview(packet), packet.decode("latin1")):
            self.reject_result(value)

    def test_native_frame_noncanonical_json_and_independent_child_hashes_fail(self):
        """Valid envelope checksums do not excuse ambiguous JSON or altered child digests."""
        body = self.controlled_result().to_bytes()
        variants = (b" " + body, body + b"\n", b"[]", b"false",
                    body[:-1] + b',"status":"FORGED"}',
                    body[:-1] + b',"extra":NaN}', b'{"nested":' + b"[" * 70 + b"0" + b"]" * 70 + b"}")
        for raw in variants:
            self.reject_result(self.forge_result(raw=raw))
        for field in ("native_inspection_sha256", "structured_inspection_sha256"):
            altered = json.loads(body)
            altered[field] = "f" * 64
            with self.subTest(field=field):
                self.reject_result(self.forge_result(altered))

    def test_native_family_profile_drift_rejects_before_admission(self):
        """A changed native dependency or enlarged result budget cannot silently keep its old pin."""
        packet = self.encode_result()
        for module, field, value in ((native, "PROFILE_SHA256", "f" * 64),
                                     (frame, "NATIVE_MAX_RESULT_BYTES", 311297),
                                     (frame, "NATIVE_MAX_FRAME_BYTES", 311341)):
            with self.subTest(field=field), patch.object(module, field, value):
                self.reject_result(packet)

    def test_native_frame_rejects_resealed_nested_unsupported_claims(self):
        """Every retained occurrence of inherited unsupported claims survives independent ancestor rehashing."""
        source = self.controlled_result().to_bytes()
        flags = {"native_execution_performed", "whole_pdf_safety_qualified",
                 "text_equivalence_verified", "accessibility_qualified",
                 "all_streams_or_revisions_inspected", "full_struct_tree_verified",
                 "semantic_tags_qualified", "whole_visual_content_covered",
                 "all_metadata_channels_inspected", "semantic_tag_tree_verified",
                 "all_marked_content_covered", "visible_content_covered"}
        paths = []

        def collect(value, path=()):
            """Locate each actual false claim without inventing absent receipt fields."""
            if type(value) is dict:
                for key, child in value.items():
                    if key in flags:
                        self.assertIs(child, False)
                        paths.append(path + (key,))
                    if key == "release_authorization":
                        self.assertEqual(child, "NOT_ESTABLISHED")
                        paths.append(path + (key,))
                    collect(child, path + (key,))
            elif type(value) is list:
                for index, child in enumerate(value):
                    collect(child, path + (index,))

        def rehash(value):
            """Recompute every affected embedded receipt and ancestor hash from the deepest child."""
            if type(value) is list:
                for child in value:
                    rehash(child)
            elif type(value) is dict:
                for child in value.values():
                    rehash(child)
                pairs = (("inspection_sha256", "record"),
                         ("page_bundle_sha256", "page_bundle"),
                         ("inspection_set_sha256", "inspection_set"),
                         ("content_inspection_sha256", "document_content"),
                         ("source_inspection_sha256", "source_inspection"),
                         ("structure_inspection_sha256", "structure_tree"),
                         ("native_inspection_sha256", "native_inspection"),
                         ("structured_inspection_sha256", "structured_inspection"))
                for digest, child in pairs:
                    if digest in value and child in value:
                        value[digest] = sha256(_json_bytes(value[child])).hexdigest()

        collect(json.loads(source))
        self.assertTrue({"native_execution_performed", "whole_pdf_safety_qualified",
                         "text_equivalence_verified", "accessibility_qualified"}
                        <= {path[-1] for path in paths})
        for path in paths:
            altered = json.loads(source)
            target = altered
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = "ESTABLISHED" if path[-1] == "release_authorization" else True
            rehash(altered)
            with self.subTest(path=path):
                self.reject_result(self.forge_result(altered))

    def test_worker_context_rejects_every_mixed_family_pin(self):
        """The unchanged fourteen-field context accepts exactly two coherent closed families."""
        _, expected, args = self.fixture()
        current = self.context(expected, args)
        old_pins = {
            "expected_worker_profile_sha256": worker.PROFILE_SHA256,
            "expected_protocol_profile_sha256": codec.PROFILE_SHA256,
            "expected_descriptor_profile_sha256": descriptor.PROFILE_SHA256,
            "expected_execution_profile_sha256": sealed.PROFILE_SHA256,
            "expected_resource_profile_sha256": structured.PROFILE_SHA256,
            "expected_frame_profile_sha256": frame.PROFILE_SHA256,
        }
        old = {**current, **old_pins}
        self.assertEqual(worker._parse_context(_json_bytes(current)), current)
        self.assertEqual(worker._parse_context(_json_bytes(old)), old)
        for key, value in old_pins.items():
            for context, changed in ((current, value), (old, current[key])):
                with self.subTest(field=key, profile=context["expected_worker_profile_sha256"]), \
                     self.assertRaises(ValueError):
                    worker._parse_context(_json_bytes({**context, key: changed}))

    def test_native_worker_context_is_canonical_fixed_and_strictly_typed(self):
        """Malformed, extended or coerced contexts fail before the fixed worker can inspect."""
        _, expected, args = self.fixture()
        context = self.context(expected, args)
        raw = _json_bytes(context)
        variants = (b" " + raw, raw + b"\n", b"[]", b"{}", b"x" * 4097,
                    raw[:-1] + b',"expected_job_id":"changed"}',
                    _json_bytes({**context, "command": "forbidden"}),
                    _json_bytes({key: value for key, value in context.items()
                                 if key != "expected_worker_profile_sha256"}),
                    _json_bytes({**context, "expected_page_count": True}),
                    _json_bytes({**context, "expected_page_count": 1.0}),
                    bytearray(raw), memoryview(raw), raw.decode())
        for value in variants:
            with self.subTest(kind=type(value).__name__), self.assertRaises(ValueError):
                worker._parse_context(value)

    def test_worker_native_write_budget_remains_separate_from_legacy(self):
        """Selected native writes honor their exact cap and progress through short writes."""
        body = b"x" * 311340
        emitted = bytearray()

        def short_write(fd, pending):
            """Record bounded publication bytes without writing synthetic padding to stdout."""
            self.assertEqual(fd, 1)
            amount = min(100003, len(pending))
            emitted.extend(pending[:amount])
            return amount

        with patch.object(worker.os, "write", side_effect=short_write) as write:
            worker._write_frame(body, selected_native=True)
            self.assertEqual(bytes(emitted), body)
            self.assertGreater(write.call_count, 1)
        for payload, selected in ((body, False), (body + b"x", True)):
            with patch.object(worker.os, "write") as write, self.assertRaises(ValueError):
                worker._write_frame(payload, selected_native=selected)
            write.assert_not_called()

    def test_supervisor_requires_family_agreement_before_process_launch(self):
        """The selected supervisor cannot accept a coherent context from the other family."""
        with self.request() as (fd, expected, args, _):
            context = self.context(expected, args)
            with patch.object(supervisor.subprocess, "Popen") as launch, \
                 self.assertRaises(supervisor.PdfSupervisedInspectionError):
                self.supervise(fd, context, expected_supervisor_profile_sha256=supervisor.PROFILE_SHA256)
            launch.assert_not_called()
        old = worker_tests.FixedInspectionWorkerTests()
        old.setUp()
        with old.h.request() as (fd, expected, args, _):
            with patch.object(supervisor.subprocess, "Popen") as launch, \
                 self.assertRaises(supervisor.PdfSupervisedInspectionError):
                self.supervise(fd, old.context(expected, args))
            launch.assert_not_called()

    def test_supervisor_rebinds_native_request_and_result_context_before_launch(self):
        """Seals and a correct family do not replace independent document and job expectations."""
        with self.request() as (fd, expected, args, _):
            context = self.context(expected, args)
            fields = ("expected_pdf_sha256", "expected_ir_sha256", "expected_page_count",
                      "expected_job_id", "expected_packet_sha256")
            for key in fields:
                wrong = 1 if key == "expected_page_count" else (
                    "f" * 64 if key.endswith("sha256") else "synthetic-foreign")
                with self.subTest(field=key), patch.object(supervisor.subprocess, "Popen") as launch, \
                     self.assertRaises(supervisor.PdfSupervisedInspectionError):
                    self.supervise(fd, {**context, key: wrong})
                launch.assert_not_called()

    def test_supervisor_collects_fragmented_native_frame_and_preserves_borrowed_fd(self):
        """A fixed successful child returns exact native bytes only after complete EOF and exit."""
        helper = self.process_fixture()
        result = self.controlled_result()
        packet = self.encode_result(result)
        script = ("import os,sys;sys.stdin.buffer.read();data=" + repr(packet)
                  + "\nfor i in range(0,len(data),127):\n os.write(1,data[i:i+127])")
        with self.request() as (fd, expected, args, request):
            os.lseek(fd, 7, os.SEEK_SET)
            with helper.child(script) as launches:
                observed = self.supervise(fd, self.context(expected, args))
                self.assertEqual(observed, result.to_bytes())
                self.assertEqual(len(launches), 1)
                command, options, process = launches[0]
                self.assertTrue(command[3].endswith("/reporting/_pdf_fixed_inspection_worker.py"))
                self.assertTrue(options["close_fds"])
                self.assertTrue(options["start_new_session"])
                self.assertEqual(len(options["pass_fds"]), 1)
                self.assertNotEqual(options["pass_fds"][0], fd)
                self.assertEqual(process.returncode, 0)
                self.assertTrue(process.stdin.closed and process.stdout.closed)
            self.assertEqual(os.pread(fd, len(request), 0), request)
            self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), 7)
            self.assertFalse(os.get_inheritable(fd))

    def test_native_supervisor_failure_and_deadline_never_accept_partial_output(self):
        """Valid bytes cannot hide nonzero exit, truncation or an unreaped child past deadline."""
        helper = self.process_fixture()
        packet = self.encode_result()
        variants = (
            ("import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(" + repr(packet)
             + ");sys.stdout.buffer.flush();sys.exit(70)", False),
            ("import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(" + repr(packet[:-1]) + ")", False),
            ("import os,sys,time;sys.stdin.buffer.read();os.close(1);time.sleep(10)", True),
        )
        with self.request() as (fd, expected, args, request):
            context = self.context(expected, args)
            before = len(os.listdir("/proc/self/fd"))
            for script, short in variants:
                with self.subTest(short=short), helper.child(script, short_deadline=short) as launches:
                    started = time.monotonic()
                    with self.assertRaises(supervisor.PdfSupervisedInspectionError):
                        self.supervise(fd, context)
                    self.assertEqual(len(launches), 1)
                    process = launches[0][2]
                    self.assertIsNotNone(process.returncode)
                    with self.assertRaises(ChildProcessError):
                        os.waitpid(process.pid, os.WNOHANG)
                    self.assertTrue(process.stdin.closed and process.stdout.closed)
                    self.assertEqual(len(os.listdir("/proc/self/fd")), before)
                    self.assertLess(time.monotonic() - started, 5)
                self.assertEqual(os.pread(fd, len(request), 0), request)

    def test_native_supervisor_selects_its_frame_cap_and_bounds_overflow(self):
        """Streams above the old cap reach native validation while native cap-plus-one is refused."""
        helper = self.process_fixture()
        with self.request() as (fd, expected, args, _):
            context = self.context(expected, args)
            for size, reason in ((294957, "pdf_supervised_inspection_failed"),
                                 (311340, "pdf_supervised_inspection_failed"),
                                 (311341, "pdf_supervised_inspection_output_budget")):
                script = "import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(b'x'*" + str(size) + ")"
                with self.subTest(size=size), helper.child(script), \
                     self.assertRaisesRegex(supervisor.PdfSupervisedInspectionError, "^" + reason + "$"):
                    self.supervise(fd, context)

    def test_native_supervisor_allocation_failure_does_not_spawn_or_leak(self):
        """The repaired allocation boundary stays before child ownership for the new family."""
        with self.request() as (fd, expected, args, packet):
            os.lseek(fd, 7, os.SEEK_SET)
            before = len(os.listdir("/proc/self/fd"))
            with patch.object(supervisor, "bytearray", create=True,
                              side_effect=MemoryError("SYNTHETIC_PRIVATE_DETAIL")) as allocate, \
                 patch.object(supervisor.subprocess, "Popen") as launch, \
                 self.assertRaisesRegex(supervisor.PdfSupervisedInspectionError,
                                        "^pdf_supervised_inspection_failed$"):
                self.supervise(fd, self.context(expected, args))
            allocate.assert_called_once_with()
            launch.assert_not_called()
            self.assertEqual(len(os.listdir("/proc/self/fd")), before)
            self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), 7)
            self.assertEqual(os.pread(fd, len(packet), 0), packet)

    def test_native_supervisor_midcall_policy_change_withholds_valid_frame(self):
        """Complete native metadata does not survive disabling before the final return boundary."""
        packet = self.encode_result()

        def changed_policy(*args, **kwargs):
            """Inject a policy change only after supplying a complete controlled exchange result."""
            self.assertIs(kwargs.get("selected_native"), True)
            os.environ[NATIVE_DISABLE] = "1"
            return packet

        with self.request() as (fd, expected, args, _), patch.dict(os.environ, {}), \
             patch.object(supervisor, "_exchange", side_effect=changed_policy), \
             self.assertRaises(supervisor.PdfSupervisedInspectionError):
            self.supervise(fd, self.context(expected, args))

    def assert_real_roundtrip(self, pages):
        """Run original, sealed and supervised native jobs over the same admitted renderer output."""
        args = self.real_arguments(pages)
        ir = json.loads(args["presentation_ir_bytes"])
        original_args = {key: value for key, value in args.items()
                         if key not in ("presentation_ir_bytes", "expected_source_profile_sha256")}
        original_args["presentation_ir"] = ir
        with patch("pypdf.PdfReader", side_effect=AssertionError("parent parser forbidden")):
            direct = native.execute_pdf_native_source_job(**original_args)
            with self.request(**args) as (fd, expected, values, packet):
                os.lseek(fd, 7, os.SEEK_SET)
                sealed_result = self.invoke(fd, expected)
                observed = self.supervise(fd, self.context(expected, values))
                self.assertIs(type(sealed_result), native.PdfNativeSourceResult)
                self.assertEqual(sealed_result.to_bytes(), direct.to_bytes())
                self.assertEqual(observed, direct.to_bytes())
                self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), 7)
                self.assertEqual(os.pread(fd, len(packet), 0), packet)
                self.assertFalse(os.get_inheritable(fd))
        data = json.loads(observed)
        child = data["structured_inspection"]
        bundle = child["source_inspection"]["inspection_set"]["page_bundle"]
        self.assertEqual(len(data["inspection_dimensions"]), 9)
        self.assertEqual(data["page_count"], pages)
        self.assertEqual(data["native_inspection"]["plan_sha256"], data["plan_sha256"])
        self.assertEqual(child["structure_tree"]["plan_sha256"], data["plan_sha256"])
        self.assertEqual(bundle["text_stream"]["represented_pages"], pages)
        self.assertEqual(bundle["raster_stream"]["represented_pages"], pages)
        self.assertEqual(bundle["text_stream"]["plan_sha256"], data["plan_sha256"])
        for field in ("worker_results_authenticated", "aggregate_job_resources_qualified",
                      "scientific_equivalence_verified", "full_accessibility_qualified", "release_authorized"):
            self.assertIs(data[field], False)
        self.assertEqual(_json_bytes(ir), args["presentation_ir_bytes"])

    def test_real_one_page_native_result_survives_supervised_transport(self):
        """The real one-page native and structured observations retain all result bytes."""
        self.assert_real_roundtrip(1)

    def test_real_33_page_native_result_survives_supervised_transport(self):
        """A real candidate above the default rendering budget uses only the explicit family."""
        self.assert_real_roundtrip(33)

    def test_real_64_page_native_result_survives_supervised_transport(self):
        """The admitted optional page maximum preserves complete native and structured evidence."""
        self.assert_real_roundtrip(64)

    def assert_real_rejection(self, args):
        """Require supervised rejection and independently confirm an empty failed worker output."""
        fixture = worker_tests.FixedInspectionWorkerTests()
        fixture.setUp()
        with self.request(**args) as (fd, expected, values, packet):
            context = self.context(expected, values)
            with patch("pypdf.PdfReader", side_effect=AssertionError("parent parser forbidden")):
                with self.assertRaises(supervisor.PdfSupervisedInspectionError):
                    self.supervise(fd, context)
                code, output = fixture.launch(fd, _json_bytes(context))
            self.assertNotEqual(code, 0)
            self.assertEqual(output, b"")
            self.assertEqual(os.pread(fd, len(packet), 0), packet)

    def test_real_native_width_violation_cannot_pass_transport(self):
        """A real same-font width defect is rejected rather than reduced to the structured child."""
        ir, pdf = self.h.native_cases()[1]
        changed = self.h.native_width_mismatch_pdf(pdf)
        self.assert_real_rejection(self.real_arguments(1, ir=ir, pdf=changed))

    def test_real_source_mismatch_cannot_pass_native_structural_success(self):
        """A structurally valid PDF still fails when the independently pinned source text differs."""
        original, pdf = self.h.native_cases()[1]
        ir = json.loads(_json_bytes(original))
        ir["components"][0]["content"]["value"] = 999
        self.assert_real_rejection(self.real_arguments(1, ir=ir, pdf=pdf))

    def test_manifest_pins_both_contract_families_and_all_source_fingerprints(self):
        """One new integration manifest binds explicit profiles while retaining every legacy identity."""
        manifest = json.loads((ROOT / "reporting/pdf-native-inspection-transport.v2.json").read_text())
        self.assertEqual(manifest["schema_version"], "2.0.0")
        self.assertEqual(manifest["manifest_id"], "native-pdf-inspection-transport-v2")
        names = ("snapshot", "request", "descriptor", "execution", "frame", "worker", "supervisor")
        self.assertEqual(set(manifest["profiles"]), set(names))
        for key, (module, legacy_name, digest) in zip(names, LEGACY_PROFILE_PINS):
            with self.subTest(profile=key):
                record = manifest["profiles"][key]
                self.assertEqual(record["profile"], getattr(module, "native_" + legacy_name)())
                self.assertEqual(record["profile_sha256"], module.NATIVE_PROFILE_SHA256)
                self.assertEqual(manifest["legacy_profile_sha256"][key], digest)
        self.assertEqual(manifest["legacy_profile_sha256"]["kernel_admission"],
                         worker.KERNEL_ADMISSION_PROFILE_SHA256)
        self.assertTrue(manifest["limitations"])
        self.assertTrue(manifest["reused_source_sha256"])
        for name, expected in manifest["reused_source_sha256"].items():
            with self.subTest(source=name):
                self.assertEqual(sha256((ROOT / name).read_bytes()).hexdigest(), expected)
        self.assertNotIn("max_native_inspector_invocations", sealed.native_sealed_inspection_profile())
        self.assertEqual(sealed.native_sealed_inspection_profile()["max_outer_stages"], 2)
        self.assertEqual(worker.NATIVE_MAX_RESULT_FRAME_BYTES, 311340)
        self.assertEqual(supervisor.NATIVE_MAX_FRAME_BYTES, 311340)
        for node in ast.walk(ast.parse(Path(__file__).read_text())):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.assertTrue(ast.get_docstring(node), node.name)


if __name__ == "__main__":
    unittest.main()
