"""Strict execution configuration, separate from assessment profiles."""

from dataclasses import fields
import ipaddress
from pathlib import Path
import platform
import os
from importlib.metadata import version
import re
import sys
import tomllib

from .images import ImageDescriptor, local_file
from .qemu import QemuConfig
from .resources import _identifier, _state_path, inspect_runs

SCHEMA = 'rosetun.matrix.execution.v1'
SCHEMA_V2 = 'rosetun.matrix.execution.v2'
SUITES = ('linux-l2', 'linux-l3')
FIELDS = {'schema', 'mode', 'platform', 'state_directory', 'stand_id', 'image', 'qemu',
          'xorriso', 'content_directory', 'source_checkout', 'accounts', 'timeouts', 'deadlines'}


def exact(value, names):
    if type(value) is not dict or set(value) != set(names):
        raise ValueError('unknown or missing execution configuration fields')


def suite_of(config):
    """Version 1 has no suite field and always means the L2 job."""
    return config.get('suite', 'linux-l2')


def validate_l3(block):
    """Fill the optional job.env values; the hash of the delivered engine has no default."""
    from .linux_l2 import DOCUMENTATION_V4, L3_DEFAULTS
    if (type(block) is not dict or 'sing_box_sha256' not in block or
            set(block) - {'sing_box_sha256'} - set(L3_DEFAULTS)):
        raise ValueError('unknown or missing L3 configuration fields')
    block = dict(L3_DEFAULTS, **block)
    if type(block['sing_box_sha256']) is not str or not re.fullmatch('[0-9a-f]{64}', block['sing_box_sha256']):
        raise ValueError('sing-box SHA-256 must be 64 lowercase hex digits')
    for name in ('host_address', 'probe_address', 'dns_probe_address'):
        value = block[name]
        if (type(value) is not str or not re.fullmatch(r'[0-9]{1,3}(\.[0-9]{1,3}){3}', value) or
                not any(ipaddress.IPv4Address(value) in net for net in DOCUMENTATION_V4)):
            raise ValueError('L3 addresses must be documentation IPv4 addresses')
    if type(block['node_port']) is not int or not 1 <= block['node_port'] <= 65535:
        raise ValueError('invalid L3 node port')
    return block


def validate(config):
    if type(config) is not dict or config.get('schema') not in (SCHEMA, SCHEMA_V2):
        raise ValueError('unsupported execution schema')
    if config['schema'] == SCHEMA:
        exact(config, FIELDS)
    else:
        suite = config.get('suite')
        if suite not in SUITES:
            raise ValueError('unsupported execution suite')
        exact(config, FIELDS | {'suite'} | ({'l3'} if suite == 'linux-l3' else set()))
        if suite == 'linux-l3':
            config['l3'] = validate_l3(config['l3'])
    if config['mode'] != 'exploratory':
        raise ValueError('execution supports exploratory only; release is unsupported')
    if config['platform'] != 'linux-x86_64-kvm':
        raise ValueError('unsupported execution platform')
    for name, cls in (('image', ImageDescriptor), ('qemu', QemuConfig)):
        exact(config[name], [f.name for f in fields(cls)])
    if config['qemu']['machine'] != 'pc-i440fx-10.0' or config['qemu']['qga'] is not True:
        raise ValueError('execution requires pinned i440fx machine and QGA')
    exact(config['accounts'], ('user_a', 'user_b'))
    users = list(config['accounts'].values())
    if any(type(u) is not str or not re.fullmatch('[a-z_][a-z0-9_-]{0,31}', u) for u in users) or users[0] == users[1]:
        raise ValueError('two distinct guest test accounts required')
    exact(config['timeouts'], ('scenario', 'unit', 'job'))
    for name, value in config['timeouts'].items():
        low, high = (60, 7200) if name == 'job' else (10, 86400)
        if type(value) is not int or not low <= value <= high:
            raise ValueError('invalid L2 timeout')
    exact(config['deadlines'], ('preparation', 'boot', 'import', 'execution'))
    for name, value in config['deadlines'].items():
        if type(value) is not int or not 1 <= value <= 86400:
            raise ValueError('invalid execution deadline')
    if config['deadlines']['import'] > 900 or config['deadlines']['boot'] > 300:
        raise ValueError('deadline exceeds supported stage limit')
    if config['deadlines']['execution'] != config['timeouts']['job'] + 180:
        raise ValueError('execution deadline must equal job timeout plus 180 seconds')
    _identifier(config['stand_id'])
    for name in ('state_directory', 'content_directory', 'source_checkout'):
        _state_path(config[name])
    return config


def load_execution(path):
    with Path(path).open('rb') as stream:
        return validate(tomllib.load(stream))


def preflight(config, *, dry_run=False):
    validate(config)
    state = _state_path(config['state_directory'])
    image = ImageDescriptor(**config['image'])
    image.validate(state)
    QemuConfig(**config['qemu']).validate()
    local_file(config['xorriso'])
    from .linux_l2 import validate_package
    suite = suite_of(config)
    l3 = config.get('l3')
    extra = dict(profile='l3', sing_box_sha256=l3['sing_box_sha256'], pending_requests=True) if l3 else {}
    package = validate_package(config['content_directory'], checkout=config['source_checkout'],
                               immutable=True, check_source=not dry_run, **extra)
    from .l2_media import TOTAL_LIMIT
    if sum(package['sizes'].values()) > TOTAL_LIMIT:
        raise ValueError('L2 content exceeds media limit')
    if any(r['stand_id'] in (None, config['stand_id']) and not r.get('completion_verified')
           for r in inspect_runs(state)):
        raise ValueError('stand has unresolved ledger; inspect recover')
    controller = Path(__file__).resolve().parents[3]
    controller_source = 'deferred'
    if not dry_run:
        if sys.platform != 'linux' or platform.machine() != 'x86_64':
            raise ValueError('execution requires Linux x86_64 KVM')
        if not os.access('/dev/kvm', os.R_OK | os.W_OK):
            raise ValueError('KVM is unavailable')
        if version('qemu.qmp') != '0.0.6':
            raise ValueError('qemu.qmp 0.0.6 required')
        from .linux_l2 import source_identity
        controller_source = source_identity(controller)
    actions = ['lease', 'create run and identities', 'overlay', 'ISO', 'start paused',
               'resume', 'observe boot', 'import once', 'verify receipt', 'submit once',
               'wait job timeout + 125 seconds', 'collect at most twice', 'close', 'summary']
    limitations = ['no controller restart recovery', 'no automatic file cleanup',
                   'no network', 'dry-run does not execute binary version checks']
    if l3:
        actions.insert(2, 'write the five L3 lab requests into the content directory')
        limitations += ['the VM has no network: preflight.baseline is expected to FAIL and the '
                        'remaining scenarios to ERROR',
                        'the sing-box binary is hashed, never executed, on the controller']
    return dict(schema='rosetun.matrix.execution-plan.v1', dry_run=dry_run, suite=suite,
                configuration=config, content_hashes=package['hashes'],
                controller_checkout=str(controller), controller_source=controller_source,
                source_check='deferred: Git status/diff requires external Git' if dry_run else 'matched',
                host_platform=sys.platform, backend_qualified=False,
                actions=actions,
                dependencies=['prepared trusted image/helpers/accounts', 'qemu.qmp 0.0.6',
                              'KVM', 'pinned QEMU/BIOS', 'xorriso 1.5.6', 'Git (execution only)'],
                limitations=limitations,
                security_invariants='UNVERIFIED', release_gate=False)
