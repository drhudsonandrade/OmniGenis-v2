"""R3 execution-boundary contract: qualification never implies activation."""
import os
import unittest
from unittest.mock import patch
from reporting import _pdf_job_durable_receipt as receipts

class ExecutionBoundaryTests(unittest.TestCase):
    def test_default_is_disabled_and_never_supported(self):
        with patch.dict(os.environ, {}, clear=True):
            value = receipts.qualification_receipt_boundary()
        self.assertEqual(value['mode'], 'DISABLED')
        self.assertFalse(value['supported_execution'])
        self.assertFalse(value['release_authorized'])
        self.assertFalse(value['native_resources_qualified'])

    def test_explicit_qualification_only_never_claims_supported(self):
        with patch.dict(os.environ, {'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE':'qualification-only'}, clear=True):
            value = receipts.qualification_receipt_boundary()
        self.assertEqual(value['mode'], 'QUALIFICATION_ONLY')
        self.assertFalse(value['supported_execution'])
        self.assertFalse(value['release_authorized'])
        self.assertEqual(value['receipt_schema'], receipts.SCHEMA)

    def test_unsupported_modes_fail_closed(self):
        for mode in ('enabled','supported','release','1','QUALIFICATION_ONLY','', 'unknown'):
            with self.subTest(mode=mode), patch.dict(os.environ, {'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE':mode}, clear=True):
                with self.assertRaises(ValueError):receipts.qualification_receipt_boundary()

    def test_disable_overrides_qualification_and_restores(self):
        with patch.dict(os.environ, {'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE':'qualification-only','OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED':'1'}, clear=True):
            self.assertEqual(receipts.qualification_receipt_boundary()['mode'],'DISABLED')
        with patch.dict(os.environ, {'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE':'qualification-only'}, clear=True):
            self.assertEqual(receipts.qualification_receipt_boundary()['mode'],'QUALIFICATION_ONLY')

    def test_invalid_disable_value_fails_closed(self):
        with patch.dict(os.environ, {'OMNIGENIS_PDF_QUALIFICATION_RECEIPT_MODE':'qualification-only','OMNIGENIS_PDF_QUALIFICATION_RECEIPT_DISABLED':'true'}, clear=True):
            with self.assertRaises(ValueError):receipts.qualification_receipt_boundary()

if __name__ == '__main__':unittest.main()
