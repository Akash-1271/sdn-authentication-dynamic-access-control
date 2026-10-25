"""Offline CSV validation tests using preserved data and disposable copies."""
import contextlib
import csv
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import summarize_performance as summary


class PerformanceSummaryTests(unittest.TestCase):
    original = Path(__file__).with_name('performance_results.csv')

    def copy_rows(self, directory, change):
        with self.original.open(newline='', encoding='utf-8') as source:
            rows = list(csv.DictReader(source))
        change(rows)
        target = Path(directory) / 'fixture.csv'
        with target.open('w', newline='', encoding='utf-8') as output:
            writer = csv.DictWriter(output, fieldnames=summary.FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        return target

    def test_preserved_data_statistics_and_outliers(self):
        before = self.original.read_bytes()
        result = summary.inspect_results(self.original)
        self.assertEqual(result['rows'], 40)
        service = next(x for x in result['metrics']
                       if x['mode'] == 'dynamic' and x['metric'] == 'service_rtt_ms')
        self.assertAlmostEqual(service['mean'], 54.6573)
        self.assertAlmostEqual(service['median'], 1.223)
        self.assertEqual(service['maximum'], 1060.678)
        self.assertTrue(any(x['mode'] == 'dynamic' and x['trial'] == 13
                            for x in result['observations_over_100_ms']))
        self.assertEqual(self.original.read_bytes(), before)

    def test_duplicate_and_missing_trials_are_rejected(self):
        for change in (lambda rows: rows.append(dict(rows[0])), lambda rows: rows.pop()):
            with tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError):
                    summary.inspect_results(self.copy_rows(directory, change))

    def test_nonfinite_negative_and_missing_measurements_rejected(self):
        for value in ('NaN', 'Infinity', '-1', ''):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                path = self.copy_rows(directory, lambda rows: rows[0].update(service_rtt_ms=value))
                with self.assertRaises(ValueError):
                    summary.inspect_results(path)

    def test_static_fields_must_be_blank(self):
        with tempfile.TemporaryDirectory() as directory:
            def change(rows):
                next(row for row in rows if row['mode'] == 'static')['login_ms'] = '0'
            with self.assertRaises(ValueError):
                summary.inspect_results(self.copy_rows(directory, change))

    def test_header_mode_and_column_count_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'bad.csv'
            p.write_text('bad,header\n', encoding='utf-8')
            with self.assertRaises(ValueError):
                summary.inspect_results(p)
            p = self.copy_rows(directory, lambda rows: rows[0].update(mode='other'))
            with self.assertRaises(ValueError):
                summary.inspect_results(p)
            p = self.copy_rows(directory, lambda rows: None)
            with p.open('a', encoding='utf-8') as f:
                f.write('dynamic,1,2,3,4,extra\n')
            with self.assertRaises(ValueError):
                summary.inspect_results(p)

    def test_cli_refuses_existing_output_and_input_hardlink(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.copy_rows(directory, lambda rows: None)
            target = Path(directory) / 'existing.md'
            target.write_text('keep me', encoding='utf-8')
            alias = Path(directory) / 'alias.csv'
            alias.hardlink_to(source)
            for output in (target, source, alias):
                before = output.read_bytes()
                with patch('sys.argv', ['summarize_performance.py', str(source), '--label',
                                        'disposable validation fixture', '--output', str(output)]), \
                     contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                    summary.main()
                self.assertEqual(error.exception.code, 2)
                self.assertEqual(output.read_bytes(), before)

    def test_report_keeps_label_units_and_unfiltered_maximum(self):
        text = summary.render_summary(summary.inspect_results(self.original), 'Historical pre-HMAC batch')
        self.assertIn('Historical pre-HMAC batch', text)
        self.assertIn('Metric (ms)', text)
        self.assertIn('1060.678', text)
        self.assertIn('All observations retained', text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
