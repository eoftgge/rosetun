"""Select and validate L2 libtest executables from Cargo's JSON messages."""

import argparse
import csv
import json
from pathlib import Path
import subprocess
import sys


def select_artifact(messages, kind, name):
    candidates = set()
    for line in messages:
        message = json.loads(line)
        if message.get('reason') != 'compiler-artifact':
            continue
        target = message.get('target', {})
        if (target.get('kind') == [kind] and target.get('name') == name
                and message.get('profile', {}).get('test') is True
                and isinstance(message.get('executable'), str)
                and message['executable']):
            candidates.add(message['executable'])
    if len(candidates) != 1:
        raise ValueError(f'expected one test executable for {kind} {name}, found {len(candidates)}')
    return Path(candidates.pop())


def required_tests(scenarios, group):
    tests = set()
    for row in csv.reader(scenarios, delimiter='\t'):
        if len(row) >= 5 and row[3] == group:
            tests.add(row[4].split(':', 1)[1])
    if not tests:
        raise ValueError(f'no required tests for {group}')
    return tests


def validate_harness(binary, expected):
    if not binary.is_file():
        raise ValueError(f'test executable does not exist: {binary}')
    result = subprocess.run([str(binary), '--list', '--format', 'terse'],
                            capture_output=True, text=True, timeout=30, check=False)
    if result.returncode != 0:
        raise ValueError(f'test listing failed for {binary.name}: exit {result.returncode}')
    listed = {line[:-6] for line in result.stdout.splitlines() if line.endswith(': test')}
    missing = expected - listed
    if missing:
        raise ValueError(f'{binary.name} lacks required tests: {", ".join(sorted(missing))}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('messages', type=Path)
    parser.add_argument('kind')
    parser.add_argument('name')
    parser.add_argument('scenarios', type=Path)
    parser.add_argument('group', choices=['unit_helper', 'unit_ipc'])
    args = parser.parse_args()
    try:
        with args.messages.open(encoding='utf-8') as messages:
            binary = select_artifact(messages, args.kind, args.name)
        with args.scenarios.open(encoding='utf-8') as scenarios:
            expected = required_tests(scenarios, args.group)
        validate_harness(binary, expected)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f'l2_test_artifacts: {error}\n')
    print(binary)


if __name__ == '__main__':
    main()
