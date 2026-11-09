"""Owner-bound opt-in propagation never widens an existing direct-only scope."""
from __future__ import annotations
import inspect
import os
import threading
import unittest
from unittest.mock import patch
from reporting import _pdf_native_launch_budget as budget
from reporting.page_windows import plan_pdf_page_windows


class JobRasterScopeTests(unittest.TestCase):
    """Only explicit, creator-owned native scopes can admit nested observations."""

    def setUp(self):
        """Fail before construction until the new scope contract exists."""
        self.assertIn('observe_raster_children', inspect.signature(budget.NativeLaunchScope).parameters,
                      'raster job scope option missing')
        self.assertTrue(callable(getattr(budget, 'raster_child_observation_requested', None)),
                        'raster job scope selector missing')
        self.assertTrue(callable(getattr(budget, 'record_raster_child_observation', None)),
                        'raster job association missing')
        budget.require_no_active_scope()
        self.plan = plan_pdf_page_windows(pdf_sha256='a'*64, ir_sha256='b'*64,
            page_count=5, admitted_page_budget=5, pages_per_window=16,
            inspector_profile_id='generated-pdf-text-window-v1')

    def scope(self, **changes):
        """Build only the fixed schedule with direct and raster observation selected."""
        value = budget.NativeLaunchScope(self.plan, 100, observe_processes=True, **changes)
        self.addCleanup(value.close)
        return value

    def test_no_scope_is_not_an_opt_in(self):
        """No global environment switch implicitly selects the extended operation."""
        self.assertIs(budget.raster_child_observation_requested(), False)

    def test_direct_only_scope_stays_direct_only(self):
        """The already supported observation API does not silently gain a new wire."""
        with self.scope() as value:
            self.assertIs(budget.raster_child_observation_requested(), False)
            with self.assertRaises(ValueError): value.raster_process_ledger()

    def test_explicit_scope_selects_until_close_only(self):
        """Selection is creator-owned and disappears when that exact scope closes."""
        with self.scope(observe_raster_children=True):
            self.assertIs(budget.raster_child_observation_requested(), True)
        self.assertIs(budget.raster_child_observation_requested(), False)

    def test_nested_mode_requires_direct_observation(self):
        """A nested ledger without the enclosing actual direct-child records is invalid."""
        with self.assertRaises(ValueError):
            budget.NativeLaunchScope(self.plan, 100, observe_raster_children=True)

    def test_nested_mode_rejects_nonboolean_flags(self):
        """No coercion may select a different execution wire."""
        for flag in (None, 1, 0, 'true', [], {}):
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                self.scope(observe_raster_children=flag)

    def test_unfinished_scope_cannot_export_nested_records(self):
        """Reservations alone never establish actual launches or completion."""
        value = self.scope(observe_raster_children=True)
        with value:
            with self.assertRaises(ValueError): value.complete_and_close()
        with self.assertRaises(ValueError): value.raster_process_ledger()

    def test_foreign_thread_cannot_select_or_record(self):
        """A second thread poisons access without gaining any subprocess authority."""
        errors = []
        with self.scope(observe_raster_children=True):
            def foreign():
                """Capture the real cross-thread refusal without touching a child."""
                try: budget.raster_child_observation_requested()
                except ValueError as exc: errors.append(exc)
            thread = threading.Thread(target=foreign)
            thread.start(); thread.join(timeout=2)
            self.assertFalse(thread.is_alive()); self.assertEqual(len(errors), 1)
            with self.assertRaises(ValueError): budget.raster_child_observation_requested()

    def test_record_without_scope_refuses(self):
        """Caller-supplied metadata is not a standalone completion API."""
        with self.assertRaises(ValueError):
            budget.record_raster_child_observation(100, None, {})

    def test_record_before_actual_direct_reap_refuses(self):
        """No record can precede the enclosing spawned/reaped raster worker."""
        with self.scope(observe_raster_children=True):
            with self.assertRaises(ValueError):
                budget.record_raster_child_observation(100, None, {})
            with self.assertRaises(ValueError): budget.raster_child_observation_requested()

    def test_record_in_direct_only_scope_refuses(self):
        """A direct-only caller cannot upgrade its already-active execution."""
        with self.scope():
            with self.assertRaises(ValueError):
                budget.record_raster_child_observation(100, None, {})

    def test_closed_scope_cannot_be_reentered(self):
        """Opt-in state is not a reusable authorization token."""
        value = self.scope(observe_raster_children=True)
        with value: pass
        with self.assertRaises(ValueError): value.__enter__()


if __name__ == '__main__': unittest.main()
