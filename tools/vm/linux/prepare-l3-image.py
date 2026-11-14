#!/usr/bin/env python3
"""Copy an already provisioned lab test image and remove the legacy IPv4 probe route."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

NETWORK = '/etc/systemd/network/00-rosetun-lab.network'


def network_for_l3(text):
    sections = re.split(r'(?=^\[)', text, flags=re.MULTILINE)
    kept = []
    defaults = 0
    for section in sections:
        lines = [line.strip() for line in section.splitlines()
                 if line.strip() and not line.lstrip().startswith(('#', ';'))]
        if lines and lines[0] == '[Route]':
            fields = dict(line.split('=', 1) for line in lines[1:])
            if fields.get('Destination') == '203.0.113.0/24':
                if fields != {'Destination': '203.0.113.0/24', 'Gateway': '192.0.2.1'}:
                    raise ValueError('unexpected legacy probe route')
                continue
            if fields.get('Destination') == '0.0.0.0/0' and fields.get('Gateway') == '192.0.2.1':
                defaults += 1
        kept.append(section)
    if defaults != 1:
        raise ValueError('expected one IPv4 default route via the lab')
    return ''.join(kept)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--source-sha256', required=True)
    parser.add_argument('--descriptor', type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    destination = args.destination.resolve()
    if destination.exists() or args.descriptor.exists():
        raise ValueError('destination and descriptor must be new files')
    before = digest(source)
    if before != args.source_sha256:
        raise ValueError('source image hash mismatch')
    info = json.loads(subprocess.check_output(['qemu-img', 'info', '--output=json', str(source)]))
    if info['format'] != 'qcow2' or 'backing-filename' in info:
        raise ValueError('source must be a standalone qcow2 image')
    def read(image):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'network'
            subprocess.run(['guestfish', '--ro', '-a', str(image), '-i', 'download', NETWORK, str(target)],
                           check=True)
            return target.read_text(encoding='utf-8')
    original = read(source)
    updated = network_for_l3(original)
    with source.open('rb') as incoming, destination.open('xb') as outgoing:
        shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', newline='\n') as temp:
        temp.write(updated)
        temp.flush()
        subprocess.run(['guestfish', '--rw', '-a', str(destination), '-i', 'upload', temp.name, NETWORK], check=True)
    if read(destination) != updated:
        raise ValueError('network readback mismatch')
    if digest(source) != before:
        raise ValueError('source image changed')
    descriptor = dict(schema='rosetun.matrix.image.v1', identifier=destination.stem,
                      guest_os='linux', architecture='x86_64', path=str(destination),
                      size_bytes=destination.stat().st_size, sha256=digest(destination),
                      format='qcow2', profile='bios-i440fx-v1')
    with args.descriptor.open('x', encoding='utf-8') as stream:
        json.dump(descriptor, stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(source_sha256=before, network_before=original, network_after=updated,
                          image=descriptor), indent=2))


if __name__ == '__main__':
    main()
