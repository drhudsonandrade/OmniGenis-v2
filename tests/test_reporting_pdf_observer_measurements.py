"""Owner-bound timing, cost, state and nonqualification measurement contracts."""
from hashlib import sha256
import importlib
import json
from pathlib import Path
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch


class ObserverMeasurementTests(unittest.TestCase):
    """Exercise real measurement behavior and controlled counter failures."""

    def setUp(self):
        """Require the implementation without turning a missing file into a skip."""
        path = Path(__file__).resolve().parents[1] / 'reporting/_pdf_observer_measurements.py'
        self.assertTrue(path.is_file(), 'Observer measurement implementation is required')
        self.m = importlib.import_module('reporting._pdf_observer_measurements')
        self.initial = (100, 110, 10, 20, 30)
        self.first = (200, 210, 20, 25, 35)
        self.second = (500, 510, 40, 30, 40)
        self.final = (600, 610, 60, 50, 60)

    def new(self, **kwargs):
        """Construct with a deterministic real-clock adapter substitute."""
        with patch.object(self.m, '_read_counters', return_value=self.initial):
            return self.m.ObserverMeasurements(cpu_budget_usec=100, target_interval_ns=100, **kwargs)

    def record(self, recorder, cpu=90, tasks=1, clock=None):
        """Supply a bounded snapshot and a deterministic measurement interval."""
        with patch.object(self.m, '_read_counters', return_value=clock or self.first):
            recorder.record_sample(job_cpu_usec=cpu, tasks_current=tasks)

    def finish(self, recorder, clock=None):
        """Complete the recorder with a deterministic final measurement interval."""
        with patch.object(self.m, '_read_counters', return_value=clock or self.final):
            return recorder.finish()

    def test_complete_interval_records_all_samples_and_distinct_cpu_costs(self):
        """First, internal and final gaps all contribute without mixing job CPU."""
        r = self.new(max_samples=2)
        self.record(r)
        self.record(r, 125, 2, self.second)
        value = self.finish(r)
        self.assertEqual(value['state'], 'OBSERVED_INTERVAL_ONLY')
        self.assertEqual(value['schema'], 'pdf-observer-measurements/v1')
        self.assertEqual(value['sample_count'], 2)
        self.assertEqual(value['observer_process_cpu_ns'], 50)
        self.assertEqual(value['reaped_children_user_cpu_ns'], 30)
        self.assertEqual(value['reaped_children_system_cpu_ns'], 30)
        self.assertEqual(value['reaped_children_cpu_ns'], 60)
        self.assertEqual(value['wall_elapsed_ns'], 500)
        self.assertEqual(value['maximum_received_sample_gap_ns'], 300)
        self.assertEqual(value['maximum_clock_capture_span_ns'], 10)
        self.assertEqual(value['observed_gap_above_target_ns'], 200)
        self.assertEqual(value['job_cpu_first_reported_usec'], 90)
        self.assertEqual(value['job_cpu_last_reported_usec'], 125)
        self.assertEqual(value['job_cpu_reported_delta_usec'], 35)
        self.assertEqual(value['observed_cpu_above_budget_usec'], 25)
        self.assertEqual([x['job_cpu_usec'] for x in value['samples']], [90, 125])
        self.assertEqual([x['tasks_current'] for x in value['samples']], [1, 2])

    def test_report_digest_covers_every_field_and_returned_samples_are_detached(self):
        """Returned values are canonical evidence, not mutable internal aliases."""
        r = self.new()
        self.record(r)
        result = self.finish(r)
        claimed = result.pop('measurements_sha256')
        encoded = json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')
        self.assertEqual(sha256(encoded).hexdigest(), claimed)
        result['samples'][0]['job_cpu_usec'] = 0
        self.assertEqual(r._samples[0]['job_cpu_usec'], 90)

    def test_observations_never_claim_enforcement_authentication_or_release(self):
        """Descriptive evidence cannot certify the source of caller-supplied counters."""
        r = self.new()
        self.record(r)
        value = self.finish(r)
        for field in ('job_counters_authenticated', 'exclusive_observer_process',
                      'exclusive_reaped_children', 'continuous_enforcement',
                      'hard_realtime_bound', 'native_profile_qualified', 'release_authorized'):
            self.assertIs(value[field], False, field)
        self.assertIn('received', value['sampling_boundary'])
        self.assertIn('all threads', value['cpu_accounting_boundary'])
        self.assertNotIn('PASS', json.dumps(value))

    def test_constructor_rejects_invalid_limits_before_reading_any_clock(self):
        """Reject boolean, noninteger and out-of-range metadata without observation."""
        for name, values in (
            ('cpu_budget_usec', [True, False, 0, -1, 1.5, None, '1', 2**63]),
            ('target_interval_ns', [True, 0, -1, 1.5, None, '1', 2**63]),
            ('max_samples', [True, 0, -1, 1.5, None, '1', 10001]),
        ):
            for value in values:
                with self.subTest(name=name, value=value), patch.object(self.m, '_read_counters') as clock:
                    kwargs = dict(cpu_budget_usec=100, target_interval_ns=100, max_samples=2)
                    kwargs[name] = value
                    with self.assertRaises(ValueError): self.m.ObserverMeasurements(**kwargs)
                    clock.assert_not_called()

    def test_sample_invalid_values_poison_without_reading_clock(self):
        """Bad snapshots cannot be repaired into apparent successful completion."""
        for field in ('job_cpu_usec', 'tasks_current'):
            for value in (True, -1, 1.5, None, '1', 2**63):
                with self.subTest(field=field, value=value):
                    r = self.new()
                    args = dict(job_cpu_usec=1, tasks_current=1); args[field] = value
                    with patch.object(self.m, '_read_counters') as clock:
                        with self.assertRaises(ValueError): r.record_sample(**args)
                        clock.assert_not_called()
                    with self.assertRaises(ValueError): self.finish(r)

    def test_empty_interval_cannot_complete_and_remains_poisoned(self):
        """An absent sample is never replaced by a zero-valued success report."""
        r = self.new()
        with self.assertRaises(ValueError): self.finish(r)
        with self.assertRaises(ValueError): self.record(r)

    def test_capacity_is_enforced_without_dropping_old_samples(self):
        """At the bound, retain prior evidence and refuse the next sample."""
        r = self.new(max_samples=1)
        self.record(r)
        with self.assertRaises(ValueError): self.record(r, 91, 1, self.second)
        self.assertEqual(len(r._samples), 1)
        with self.assertRaises(ValueError): self.finish(r)

    def test_default_capacity_is_finite(self):
        """The recorder has a fixed upper memory bound without profile activation."""
        r = self.new()
        self.assertEqual(r._max_samples, 10000)

    def test_regressing_job_cpu_counter_poisoned(self):
        """A lower job counter cannot reset the baseline or hide consumed CPU."""
        r = self.new(); self.record(r)
        with self.assertRaises(ValueError): self.record(r, 89, 0, self.second)
        with self.assertRaises(ValueError): self.finish(r)

    def test_task_counts_may_fall_and_zero_usage_is_observed_not_invented(self):
        """Task count is a gauge while job CPU remains cumulative."""
        r = self.new(); self.record(r, 0, 3); self.record(r, 0, 0, self.second)
        result = self.finish(r)
        self.assertEqual(result['job_cpu_reported_delta_usec'], 0)
        self.assertEqual(result['observed_cpu_above_budget_usec'], 0)
        self.assertEqual(result['samples'][-1]['tasks_current'], 0)

    def test_all_clock_counter_regressions_are_rejected(self):
        """Every local clock and each child CPU counter is independently monotonic."""
        for changed in ((109, 210, 20, 25, 35), (200, 199, 20, 25, 35),
                        (200, 210, 9, 25, 35), (200, 210, 20, 19, 35),
                        (200, 210, 20, 25, 29)):
            with self.subTest(clock=changed):
                r = self.new()
                with self.assertRaises(ValueError): self.record(r, clock=changed)
                with self.assertRaises(ValueError): self.finish(r)

    def test_invalid_clock_snapshot_shapes_and_values_refused(self):
        """No malformed read is treated as a valid timestamp or CPU sample."""
        for value in (None, (), [100, 110, 10, 20, 30], (100, 110, 10, 20),
                      (True, 110, 10, 20, 30), (100, 110, -1, 20, 30),
                      (100, 110, 1.5, 20, 30), (100, 110, 10, 20, 2**63)):
            with self.subTest(value=value), patch.object(self.m, '_read_counters', return_value=value):
                with self.assertRaises(ValueError): self.m.ObserverMeasurements(cpu_budget_usec=100)

    def test_final_clock_regression_prevents_report(self):
        """A successful earlier sample cannot mask a failed final observation."""
        r = self.new(); self.record(r)
        with self.assertRaises(ValueError): self.finish(r, (200, 220, 30, 40, 50))
        with self.assertRaises(ValueError): self.finish(r)

    def test_foreign_pid_refuses_before_clock_or_state_measurement(self):
        """A fork-inherited object is not an independent observer interval."""
        r = self.new()
        with patch.object(self.m.os, 'getpid', return_value=r._pid + 1), patch.object(self.m, '_read_counters') as clock:
            with self.assertRaises(ValueError): r.record_sample(job_cpu_usec=0, tasks_current=1)
            clock.assert_not_called()
        with self.assertRaises(ValueError): self.finish(r)

    def test_foreign_real_thread_refuses_and_poison_is_visible_to_creator(self):
        """Single-thread ownership is not replaced by a recycled numeric thread ID."""
        r = self.new(); errors = []
        def foreign():
            """Try using the creator's scope from a genuinely different thread."""
            try: r.record_sample(job_cpu_usec=0, tasks_current=1)
            except ValueError as exc: errors.append(str(exc))
        t = threading.Thread(target=foreign); t.start(); t.join(timeout=5)
        self.assertFalse(t.is_alive()); self.assertEqual(len(errors), 1)
        with self.assertRaises(ValueError): self.finish(r)

    def test_reentry_poison_cannot_be_hidden_by_clock_reader(self):
        """An overlapping operation prevents both nested and outer acceptance."""
        r = self.new()
        def nested():
            """Simulate a reentrant clock dependency without changing production APIs."""
            with self.assertRaises(ValueError): r.record_sample(job_cpu_usec=1, tasks_current=1)
            return self.first
        with patch.object(self.m, '_read_counters', side_effect=nested):
            with self.assertRaises(ValueError): r.record_sample(job_cpu_usec=1, tasks_current=1)
        with self.assertRaises(ValueError): self.finish(r)

    def test_clock_exception_poisoned_and_not_suppressed(self):
        """Even interruption cannot leave a reusable partially measured interval."""
        for failure in (OSError('counter unavailable'), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__):
                r = self.new()
                with patch.object(self.m, '_read_counters', side_effect=failure):
                    with self.assertRaises(type(failure)): r.record_sample(job_cpu_usec=0, tasks_current=1)
                with self.assertRaises(ValueError): self.finish(r)

    def test_completed_scope_rejects_reuse(self):
        """A sealed report cannot be extended or regenerated with later counters."""
        r = self.new(); self.record(r); self.finish(r)
        with self.assertRaises(ValueError): self.record(r)
        with self.assertRaises(ValueError): self.finish(r)

    def test_finish_interval_includes_time_after_last_sample(self):
        """A long final observation gap is not hidden by regular earlier samples."""
        r = self.new(); self.record(r)
        result = self.finish(r, (1010, 1020, 60, 50, 60))
        self.assertEqual(result['maximum_received_sample_gap_ns'], 810)

    def test_initial_gap_and_capture_spans_are_not_lost(self):
        """The first sampling delay and slow clock capture remain explicit."""
        r = self.new(); self.record(r, clock=(200, 550, 20, 25, 35))
        result = self.finish(r)
        self.assertEqual(result['maximum_received_sample_gap_ns'], 440)
        self.assertEqual(result['maximum_clock_capture_span_ns'], 350)

    def test_zero_observed_time_differences_are_allowed(self):
        """Equal readings are valid at finite clock resolution, not a regression."""
        r = self.new()
        clock = (110, 110, 10, 20, 30)
        self.record(r, 1, 1, clock)
        result = self.finish(r, clock)
        self.assertEqual(result['wall_elapsed_ns'], 0)

    def test_cpu_counter_conversion_rejects_nonfinite_negative_and_boolean(self):
        """Validate raw resource counters before converting seconds into integers."""
        for value in (True, False, -1, float('nan'), float('inf'), -float('inf'), '1', None, 1e300, 2**20000, -(2**20000)):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ValueError): self.m._seconds_to_ns(value)
        self.assertEqual(self.m._seconds_to_ns(0.125), 125000000)

    def test_real_counter_reader_observes_current_process_and_waited_child(self):
        """Measure a real bounded unprivileged child, not a mocked job counter source."""
        r = self.m.ObserverMeasurements(cpu_budget_usec=1000000)
        r.record_sample(job_cpu_usec=0, tasks_current=1)
        subprocess.run([sys.executable, '-I', '-c', 'sum(i*i for i in range(200000))'],
                       check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.PIPE, timeout=10)
        r.record_sample(job_cpu_usec=10, tasks_current=0)
        value = r.finish()
        self.assertGreater(value['wall_elapsed_ns'], 0)
        self.assertGreater(value['observer_process_cpu_ns'], 0)
        self.assertGreater(value['reaped_children_cpu_ns'], 0)
        self.assertFalse(value['native_profile_qualified'])


if __name__ == '__main__':
    unittest.main()
