"""Explicit qualification-only generation with durable, nonrelease outcomes.

An exclusive local run directory is never automatically reused or removed.
Persisted SUCCEEDED means the computation was accepted before persistence, not
that a result was delivered, an executor qualified, or an artifact released.
Missing or uncertain outcomes require inspection, never automatic reexecution.
"""
from __future__ import annotations

from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path

from reporting import _pdf_job_durable_receipt as receipts
from reporting import pdf_generated_source_job as generated


class PdfQualificationJobError(ValueError):
    """Expose a bounded refusal code without source, storage or exception details."""


def _require_policy() -> None:
    """Enforce the exact opt-in declaration only at this optional consumer."""
    if receipts.qualification_receipt_boundary() != {
        'mode': 'QUALIFICATION_ONLY', 'receipt_schema': receipts.SCHEMA,
        'supported_execution': False, 'native_resources_qualified': False,
        'release_authorized': False,
    }:
        raise ValueError('qualification policy unavailable')


def _admit(arguments: dict, directory: Path, run_id: str) -> tuple[dict, bytes]:
    """Validate existing source expectations before even claiming local storage."""
    _require_policy()
    receipts._receipt_bytes(run_id, 'FAILED', None)
    if not isinstance(directory, Path):
        raise ValueError('qualification directory type')
    generated.require_no_active_scope()
    generated._profile(arguments['expected_resource_profile_sha256'])
    generated._pin(arguments['expected_ir_sha256'])
    if (type(arguments['expected_language']) is not str
            or arguments['expected_language'] != generated.LANGUAGE):
        raise ValueError('qualification language')
    generated._validate_context(arguments['namespace_id'], arguments['job_id'],
                                arguments['request_sha256'],
                                arguments['expected_resource_profile_sha256'])
    captured = generated._capture_adapter_ir(arguments['presentation_ir'])
    if (not generated._validate_ir(captured) or captured.get('locale_id') != generated.LANGUAGE
            or generated._expected_content(captured)[0] != arguments['expected_ir_sha256']):
        raise ValueError('qualification source identity')
    return captured, generated._json_bytes(captured)


@contextmanager
def _run_directory(directory: Path, run_id: str, *, create: bool):
    """Anchor one private run directory and close all descriptors, never evidence.

    Exclusive creation is local single-use admission, not distributed execution
    authentication. Identity checks observe changes; hostile same-owner mutation
    between checks is outside this qualification boundary.
    """
    parent = receipts._open_private_directory(directory)
    try:
        parent_identity = receipts._private_directory_identity(parent)
        if create:
            os.mkdir(run_id, mode=0o700, dir_fd=parent)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        run = os.open(run_id, flags, dir_fd=parent)
        try:
            run_identity = receipts._private_directory_identity(run)

            def check() -> None:
                """Bind retained descriptors to the caller's current named directories."""
                if (receipts._private_directory_identity(parent) != parent_identity
                        or receipts._private_directory_identity(run) != run_identity):
                    raise ValueError('qualification directory metadata changed')
                current_parent = receipts._open_private_directory(directory)
                try:
                    if receipts._private_directory_identity(current_parent) != parent_identity:
                        raise ValueError('qualification parent replaced')
                    current_run = os.open(run_id, flags, dir_fd=current_parent)
                    try:
                        if receipts._private_directory_identity(current_run) != run_identity:
                            raise ValueError('qualification run replaced')
                    finally:
                        os.close(current_run)
                finally:
                    os.close(current_parent)

            if create:
                os.fsync(run)
                os.fsync(parent)
            check()
            yield directory / run_id, check
        finally:
            os.close(run)
    finally:
        os.close(parent)


def _completed_digest(result: generated.PdfGeneratedSourceResult, arguments: dict,
                      captured: dict, source_bytes: bytes) -> str:
    """Recheck exact result/context/source without broadening the existing profile."""
    _require_policy()
    if type(result) is not generated.PdfGeneratedSourceResult:
        raise ValueError('qualification result type')
    if (generated._json_bytes(generated._capture_adapter_ir(arguments['presentation_ir'])) != source_bytes
            or generated._json_bytes(generated._capture_adapter_ir(captured)) != source_bytes):
        raise ValueError('qualification source changed')
    for field, expected in {
        'ir_sha256': arguments['expected_ir_sha256'],
        'namespace_id': arguments['namespace_id'], 'job_id': arguments['job_id'],
        'request_sha256': arguments['request_sha256'],
        'resource_profile_sha256': arguments['expected_resource_profile_sha256'],
    }.items():
        if getattr(result, field) != expected:
            raise ValueError('qualification result context')
    return sha256(result.to_bytes()).hexdigest()


def _persist(directory: Path, run_id: str, state: str, digest: str | None) -> dict:
    """Commit and read back the unchanged bounded receipt, not a PDF artifact."""
    receipts.write_job_receipt(directory, run_id, state, digest)
    outcome = receipts.read_job_receipt(directory, run_id, state, digest)
    if type(outcome) is not dict or outcome != json.loads(receipts._receipt_bytes(run_id, state, digest)):
        raise ValueError('qualification receipt readback differs')
    return outcome


def _observation_bytes(result: generated.PdfGeneratedSourceResult, observation: dict,
                       *, observe_raster_children: bool = False) -> bytes:
    """Recompose the exact bounded direct-process record against its sealed result.

    Only the fixed generator supplies observations. Canonical equality includes
    its closed scope claims and nested digests, but does not authenticate native
    execution or independently observe unreported descendants.
    """
    if type(observe_raster_children) is not bool:
        raise ValueError('qualification raster observation mode')
    if observe_raster_children:
        from reporting._pdf_raster_job_observation import validate_generated
        return generated._json_bytes(validate_generated(result, observation))
    if type(observation) is not dict:
        raise ValueError('qualification observation type')
    encoded = generated._json_bytes(observation)
    if len(encoded) > generated.MAX_OBSERVATION_BYTES:
        raise ValueError('qualification observation byte budget')
    rebuilt = generated._generated_process_observation(
        result, observation.get('render_process'), observation.get('native_observation'))
    if generated._json_bytes(rebuilt) != encoded:
        raise ValueError('qualification observation does not match generated result')
    return encoded


def _execute_receipted_pdf_generated_source_job(
    *, presentation_ir: object, expected_ir_sha256: str, expected_language: str,
    namespace_id: str, job_id: str, request_sha256: str,
    expected_resource_profile_sha256: str, receipt_directory: Path, run_id: str,
    observe_processes: bool, observe_raster_children: bool = False,
) -> tuple[generated.PdfGeneratedSourceResult, dict | None, dict]:
    """Run the fixed qualification path, observing only when explicitly selected."""
    arguments = dict(presentation_ir=presentation_ir, expected_ir_sha256=expected_ir_sha256,
                     expected_language=expected_language, namespace_id=namespace_id,
                     job_id=job_id, request_sha256=request_sha256,
                     expected_resource_profile_sha256=expected_resource_profile_sha256)
    try:
        if (type(observe_processes) is not bool or type(observe_raster_children) is not bool
                or (observe_raster_children and not observe_processes)):
            raise ValueError('qualification observation mode')
        captured, source_bytes = _admit(arguments, receipt_directory, run_id)
    except Exception:
        raise PdfQualificationJobError('pdf_qualification_job_input_invalid') from None
    try:
        with _run_directory(receipt_directory, run_id, create=True) as (directory, check):
            try:
                _require_policy()
                observation = None
                if observe_processes:
                    generator = (generated.execute_raster_observed_pdf_generated_source_job
                                 if observe_raster_children else generated.execute_observed_pdf_generated_source_job)
                    pair = generator(**{**arguments, 'presentation_ir': captured})
                    if type(pair) is not tuple or len(pair) != 2:
                        raise ValueError('qualification observed result pair')
                    result, observation = pair
                else:
                    result = generated.execute_pdf_generated_source_job(
                        **{**arguments, 'presentation_ir': captured})
                digest = _completed_digest(result, arguments, captured, source_bytes)
                observation_options = {'observe_raster_children': True} if observe_raster_children else {}
                observation_bytes = (_observation_bytes(result, observation, **observation_options)
                                     if observe_processes else None)
                check()
            except BaseException as failure:
                try:
                    check()
                    _persist(directory, run_id, 'FAILED', None)
                    check()
                except BaseException as storage_failure:
                    if not isinstance(failure, Exception):
                        raise failure from storage_failure
                    if not isinstance(storage_failure, Exception):
                        raise
                    raise PdfQualificationJobError('pdf_qualification_job_completion_unverified') from None
                if isinstance(failure, Exception):
                    raise PdfQualificationJobError('pdf_qualification_job_execution_failed') from None
                raise
            try:
                outcome = _persist(directory, run_id, 'SUCCEEDED', digest)
                detached = json.loads(observation_bytes) if observe_processes else None
                if _completed_digest(result, arguments, captured, source_bytes) != digest:
                    raise ValueError('qualification result changed during completion')
                if observe_processes:
                    if (_observation_bytes(result, observation, **observation_options) != observation_bytes
                            or generated._json_bytes(detached) != observation_bytes
                            or _completed_digest(result, arguments, captured, source_bytes) != digest):
                        raise ValueError('qualification observation changed during completion')
                check()
            except Exception:
                raise PdfQualificationJobError('pdf_qualification_job_completion_unverified') from None
            return result, detached, outcome
    except PdfQualificationJobError:
        raise
    except Exception:
        raise PdfQualificationJobError('pdf_qualification_job_claim_failed') from None

def execute_receipted_pdf_generated_source_job(
    *, presentation_ir: object, expected_ir_sha256: str, expected_language: str,
    namespace_id: str, job_id: str, request_sha256: str,
    expected_resource_profile_sha256: str, receipt_directory: Path, run_id: str,
) -> tuple[generated.PdfGeneratedSourceResult, dict]:
    """Generate once in qualification mode and verify a durable computation record.

    Default-disabled, fixed executor, unchanged resource profile, no console I/O.
    A prior run directory refuses before execution even without a receipt. Failure
    recording is cleanup of an admitted attempt and can occur after disable.
    Failure/interrupt records do not prove cleanup of the native process graph.
    A postcommit refusal may leave SUCCEEDED computation evidence but returns no
    result pair; recovery requires independent expectations and never reruns work.
    Only metadata is persisted. This does not activate supported execution, hard
    aggregate enforcement, durable artifact delivery or release authorization.
    """
    result, _observation, outcome = _execute_receipted_pdf_generated_source_job(
        presentation_ir=presentation_ir, expected_ir_sha256=expected_ir_sha256,
        expected_language=expected_language, namespace_id=namespace_id, job_id=job_id,
        request_sha256=request_sha256,
        expected_resource_profile_sha256=expected_resource_profile_sha256,
        receipt_directory=receipt_directory, run_id=run_id, observe_processes=False,
    )
    return result, outcome


def execute_observed_receipted_pdf_generated_source_job(
    *, presentation_ir: object, expected_ir_sha256: str, expected_language: str,
    namespace_id: str, job_id: str, request_sha256: str,
    expected_resource_profile_sha256: str, receipt_directory: Path, run_id: str,
) -> tuple[generated.PdfGeneratedSourceResult, dict, dict]:
    """Return one qualification result, its direct-process observation and outcome.

    The fixed observed generator runs once under existing opt-in/disable and
    exclusive-attempt rules. The detached bounded observation and unchanged v1
    receipt bind the same result digest. Only the computation receipt persists;
    recovery cannot reconstruct observations or deliver a stored PDF. Refusals
    return no triple, even when computation was committed before a final check.
    Nested processes, external observer cost, whole-job resources and supported
    execution remain unqualified. No default, service or release is activated.
    """
    result, observation, outcome = _execute_receipted_pdf_generated_source_job(
        presentation_ir=presentation_ir, expected_ir_sha256=expected_ir_sha256,
        expected_language=expected_language, namespace_id=namespace_id, job_id=job_id,
        request_sha256=request_sha256,
        expected_resource_profile_sha256=expected_resource_profile_sha256,
        receipt_directory=receipt_directory, run_id=run_id, observe_processes=True,
    )
    if observation is None:
        raise PdfQualificationJobError('pdf_qualification_job_completion_unverified')
    return result, observation, outcome



def read_qualification_job_outcome(
    *, receipt_directory: Path, run_id: str, state: str, result_sha256: str | None,
) -> dict:
    """Recover exact expected local evidence, never execute, repair or authorize.

    Existing low-level receipt APIs remain independent. This optional consumer
    enforces qualification policy before and after readback. An absent receipt
    or a mismatched expectation remains unverified, never inferred as success.
    """
    try:
        _require_policy()
        receipts._receipt_bytes(run_id, state, result_sha256)
        if not isinstance(receipt_directory, Path):
            raise ValueError('qualification directory type')
        with _run_directory(receipt_directory, run_id, create=False) as (directory, check):
            outcome = receipts.read_job_receipt(directory, run_id, state, result_sha256)
            _require_policy()
            check()
            return outcome
    except Exception:
        raise PdfQualificationJobError('pdf_qualification_job_recovery_failed') from None


def execute_raster_observed_receipted_pdf_generated_source_job(
    *, presentation_ir: object, expected_ir_sha256: str, expected_language: str,
    namespace_id: str, job_id: str, request_sha256: str,
    expected_resource_profile_sha256: str, receipt_directory: Path, run_id: str,
) -> tuple[generated.PdfGeneratedSourceResult, dict, dict]:
    """Return one qualification result, integrated child records and its v1 outcome.

    This explicit path enforces the existing default-disabled qualification
    policy and exclusive attempt. Direct and nested observations are bound to
    the same result before and after persistence, with no automatic retry.
    Only the computation receipt persists; recovery does not reconstruct this
    ledger or deliver a PDF. No supported/native-resource/release claim is made.
    """
    result, observation, outcome = _execute_receipted_pdf_generated_source_job(
        presentation_ir=presentation_ir, expected_ir_sha256=expected_ir_sha256,
        expected_language=expected_language, namespace_id=namespace_id, job_id=job_id,
        request_sha256=request_sha256,
        expected_resource_profile_sha256=expected_resource_profile_sha256,
        receipt_directory=receipt_directory, run_id=run_id,
        observe_processes=True, observe_raster_children=True,
    )
    if observation is None:
        raise PdfQualificationJobError('pdf_qualification_job_completion_unverified')
    return result, observation, outcome
