"""Qualification policy declarations never imply execution or release authority."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from reporting import _pdf_job_durable_receipt as receipts


class ExecutionBoundaryTests(unittest.TestCase):
    """Declare supported states without changing the existing receipt I/O APIs."""

    def setUp(self):
        """Fail explicitly when the boundary declaration operation is absent."""
        self.assertTrue(callable(getattr(receipts, 'qualification_receipt_boundary', None)),
                        'qualification receipt boundary API is missing')

    def expected(self, mode):
        """Specify the closed declaration without trusting its implementation."""
        return {'mode': mode, 'receipt_schema': receipts.SCHEMA,
                'supported_execution': False, 'native_resources_qualified': False,
                'release_authorized': False}

    def test_default_is_disabled_and_never_supported(self):
        """An absent configuration returns no execution or release qualification."""
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(receipts.qualification_receipt_boundary(),
                             self.expected('DISABLED'))

    def test_explicit_qualification_only_never_claims_supported(self):
        """Opt-in declaration cannot promote itself to a supported executor."""
        with patch.dict(os.environ, {
                'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE': 'qualification-only'}, clear=True):
            self.assertEqual(receipts.qualification_receipt_boundary(),
                             self.expected('QUALIFICATION_ONLY'))

    def test_unsupported_modes_fail_closed(self):
        """Unknown modes remain invalid even when the disable flag is present."""
        for mode in ('enabled', 'supported', 'release', '1', 'QUALIFICATION_ONLY',
                     '', 'unknown', ' qualification-only', 'qualification-only '):
            for disabled in (None, '1'):
                values = {'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE': mode}
                if disabled is not None:
                    values['OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED'] = disabled
                with self.subTest(mode=mode, disabled=disabled), \
                        patch.dict(os.environ, values, clear=True):
                    with self.assertRaises(ValueError):
                        receipts.qualification_receipt_boundary()

    def test_disable_overrides_qualification_and_restores(self):
        """Explicit disable overrides the admitted declaration without caching it."""
        values = {'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE': 'qualification-only',
                  'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED': '1'}
        with patch.dict(os.environ, values, clear=True):
            self.assertEqual(receipts.qualification_receipt_boundary(),
                             self.expected('DISABLED'))
            del os.environ['OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED']
            self.assertEqual(receipts.qualification_receipt_boundary(),
                             self.expected('QUALIFICATION_ONLY'))
            del os.environ['OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE']
            self.assertEqual(receipts.qualification_receipt_boundary(),
                             self.expected('DISABLED'))

    def test_invalid_disable_value_fails_closed(self):
        """Only the exact disable value is admitted; no truthiness coercion occurs."""
        for disabled in ('true', 'false', '0', '', ' 1', '1 ', 'unknown'):
            values = {'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE': 'qualification-only',
                      'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED': disabled}
            with self.subTest(disabled=disabled), patch.dict(os.environ, values, clear=True):
                with self.assertRaises(ValueError):
                    receipts.qualification_receipt_boundary()

    def test_returned_declarations_are_independent(self):
        """Mutating an exported declaration cannot change later scope claims."""
        with patch.dict(os.environ, {}, clear=True):
            first = receipts.qualification_receipt_boundary()
            first['supported_execution'] = True
            first['release_authorized'] = True
            first['extra'] = 'foreign'
            self.assertEqual(receipts.qualification_receipt_boundary(),
                             self.expected('DISABLED'))

    def test_configuration_is_read_without_mutation(self):
        """The helper neither rewrites settings nor changes unrelated environment."""
        values = {'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED': '1',
                  'UNRELATED_SYNTHETIC_SETTING': 'preserve'}
        with patch.dict(os.environ, values, clear=True):
            before = dict(os.environ)
            self.assertEqual(receipts.qualification_receipt_boundary(),
                             self.expected('DISABLED'))
            self.assertEqual(dict(os.environ), before)

    def test_declaration_does_not_access_persisted_receipts(self):
        """No directory access, write or readback is caused by describing policy."""
        with patch.dict(os.environ, {}, clear=True), \
                patch.object(receipts, '_open_private_directory', side_effect=AssertionError('open')), \
                patch.object(receipts, 'write_job_receipt', side_effect=AssertionError('write')), \
                patch.object(receipts, 'read_job_receipt', side_effect=AssertionError('read')):
            self.assertEqual(receipts.qualification_receipt_boundary(),
                             self.expected('DISABLED'))

    def test_declared_disable_is_not_low_level_io_enforcement(self):
        """Legacy writer/readback behavior is explicitly independent of declaration."""
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            values = {'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED': '1'}
            with patch.dict(os.environ, values, clear=True):
                self.assertEqual(receipts.qualification_receipt_boundary()['mode'], 'DISABLED')
                path = receipts.write_job_receipt(directory, 'a' * 32, 'FAILED', None)
                self.assertTrue(path.is_file())
                outcome = receipts.read_job_receipt(directory, 'a' * 32, 'FAILED', None)
                self.assertEqual(outcome['state'], 'FAILED')
                self.assertIs(outcome['release_authorized'], False)


if __name__ == '__main__':
    unittest.main()
