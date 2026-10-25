"""Validate an existing benchmark CSV and report statistics without changing data."""
import argparse
import csv
import hashlib
import io
import math
from pathlib import Path
import statistics

FIELDS = ['mode', 'trial', 'login_ms', 'service_rtt_ms', 'login_to_access_ms']


def inspect_results(path, expected_trials=20):
    if expected_trials <= 0:
        raise ValueError('Expected trial count must be positive')
    raw = Path(path).read_bytes()
    reader = csv.DictReader(io.StringIO(raw.decode('utf-8-sig'), newline=''))
    if reader.fieldnames != FIELDS:
        raise ValueError('Unexpected benchmark CSV header')
    groups = {'dynamic': [], 'static': []}
    seen = set()
    for line, row in enumerate(reader, 2):
        if set(row) != set(FIELDS) or any(value is None for value in row.values()):
            raise ValueError(f'Wrong column count at row {line}')
        mode = row['mode']
        if mode not in groups:
            raise ValueError(f'Unknown mode at row {line}')
        try:
            trial = int(row['trial'])
        except ValueError as exc:
            raise ValueError(f'Invalid trial ID at row {line}') from exc
        if not 1 <= trial <= expected_trials or (mode, trial) in seen:
            raise ValueError(f'Duplicate or out-of-range trial at row {line}')
        seen.add((mode, trial))
        converted = {'trial': trial}
        for field in FIELDS[2:]:
            value = row[field]
            if mode == 'static' and field != 'service_rtt_ms':
                if value != '':
                    raise ValueError(f'Static nonapplicable field must be blank at row {line}')
                converted[field] = None
                continue
            try:
                number = float(value)
            except ValueError as exc:
                raise ValueError(f'Missing or invalid measurement at row {line}') from exc
            if not math.isfinite(number) or number < 0:
                raise ValueError(f'Measurement must be finite and nonnegative at row {line}')
            converted[field] = number
        groups[mode].append(converted)
    required = set(range(1, expected_trials + 1))
    if any({r['trial'] for r in rows} != required for rows in groups.values()):
        raise ValueError('Both modes must contain every expected trial exactly once')
    metrics = []
    for mode, rows in groups.items():
        for field in FIELDS[2:]:
            values = [r[field] for r in rows if r[field] is not None]
            if values:
                metrics.append({'mode': mode, 'metric': field, 'n': len(values),
                                'mean': statistics.mean(values), 'median': statistics.median(values),
                                'minimum': min(values), 'maximum': max(values)})
    return {'sha256': hashlib.sha256(raw).hexdigest(), 'rows': len(seen),
            'metrics': metrics,
            'observations_over_100_ms': [
                {'mode': mode, 'trial': r['trial'], 'metric': field, 'value': r[field]}
                for mode, rows in groups.items() for r in rows for field in FIELDS[2:]
                if r[field] is not None and r[field] > 100]}


def render_summary(result, label):
    label = label.replace('\r', ' ').replace('\n', ' ').replace('|', '\\|')
    lines = ['# Performance evaluation', '', f'Batch label: {label}', '',
             f'Input SHA-256: `{result["sha256"]}`', '',
             f'Validated rows: {result["rows"]}. All observations retained.', '',
             '| Mode | Metric (ms) | Trials | Mean | Median | Minimum | Maximum |',
             '|---|---|---:|---:|---:|---:|---:|']
    for m in result['metrics']:
        lines.append(f'| {m["mode"]} | {m["metric"]} | {m["n"]} | '
                     f'{m["mean"]:.4f} | {m["median"]:.4f} | '
                     f'{m["minimum"]:.4f} | {m["maximum"]:.4f} |')
    lines += ['', 'Service transaction time includes TCP connection setup and application response.',
              'Compare service_rtt_ms across modes. Static login/total fields are not applicable.',
              'Login/control and login-to-access measure additional dynamic authorization work.',
              'A mean or median from one ordered VM batch does not establish a general speed advantage.',
              'The caller-provided batch label is not proof of the tested source version; retain its manifest.',
              '', '## Observations over 100 ms (retained, not discarded)', '']
    for item in result['observations_over_100_ms']:
        lines.append(f'- {item["mode"]}, trial {item["trial"]}, '
                     f'{item["metric"]}: {item["value"]:.3f} ms')
    if not result['observations_over_100_ms']:
        lines.append('None in this batch.')
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--label', required=True, help='Identify historical/current batch and tested source')
    parser.add_argument('--expected-trials', type=int, default=20)
    parser.add_argument('--output', type=Path, help='New Markdown file; existing files are never overwritten')
    args = parser.parse_args()
    try:
        result = inspect_results(args.input, args.expected_trials)
        text = render_summary(result, args.label)
        if args.output:
            # Exclusive creation also refuses existing hard-link/symlink aliases of the input.
            with args.output.open('x', encoding='utf-8', newline='\n') as target:
                target.write(text)
        else:
            print(text, end='')
    except (OSError, ValueError, UnicodeError) as exc:
        parser.error(str(exc))


if __name__ == '__main__':
    main()
