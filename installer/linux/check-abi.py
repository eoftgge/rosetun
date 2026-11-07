#!/usr/bin/env python3
"""Reject ELF symbol requirements above the Linux release baseline."""

import argparse
from pathlib import Path
import re
import subprocess


# Debian 12: glibc 2.36 and GCC 12. Debian 13 is only for stand artifacts.
BASELINES = {
    'debian12': {'GLIBC': '2.36', 'GLIBCXX': '3.4.30', 'CXXABI': '1.3.13', 'GCC': '12.0.0'},
    'debian13': {'GLIBC': '2.41', 'GLIBCXX': '3.4.33', 'CXXABI': '1.3.15', 'GCC': '14.0.0'},
}


def version_key(value):
    return tuple(int(part) for part in value.split('.'))


def requirements(symbols, limits):
    found = {name: set() for name in limits}
    for line in symbols.splitlines():
        if '*UND*' not in line:
            continue
        for name, version in re.findall(r'\b(GLIBCXX|GLIBC|CXXABI|GCC)_([A-Za-z0-9_.]+)', line):
            if not re.fullmatch(r'\d+(?:\.\d+)*', version):
                raise ValueError(f'unsupported symbol version {name}_{version}')
            found[name].add(version)
    for name, versions in found.items():
        maximum = max(versions, key=version_key) if versions else None
        if maximum and version_key(maximum) > version_key(limits[name]):
            raise ValueError(f'{name}_{maximum} exceeds baseline {name}_{limits[name]}')
    return {name: max(versions, key=version_key) if versions else 'none' for name, versions in found.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', choices=BASELINES, default='debian12')
    parser.add_argument('binaries', type=Path, nargs='+')
    args = parser.parse_args()
    for binary in args.binaries:
        try:
            result = subprocess.run(['objdump', '-T', str(binary)], check=True,
                                    capture_output=True, text=True)
            maximum = requirements(result.stdout, BASELINES[args.baseline])
        except (OSError, subprocess.CalledProcessError, ValueError) as error:
            parser.exit(1, f'check-abi: {binary}: {error}\n')
        print(f'{binary.name}: ' + ', '.join(f'{name}={value}' for name, value in maximum.items()))


if __name__ == '__main__':
    main()
