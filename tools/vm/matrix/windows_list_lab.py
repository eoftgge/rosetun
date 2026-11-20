"""`run windows-list` (stage 10a): the List rule-set matrix on a Windows guest of the 9a image, on the lab's wire, with Rosetun.

Two machines run under one lease, as in `windows-lab-smoke`: the lab machine (the VPN node, the HTTPS target, the lab's
resolver and DoH target, the capture to its evidence disk) and the Windows guest. The guest has no network but the lab's
wire, so what it runs comes on a read-only disc made for the run (`windows_media`): the Rosetun binaries of the checkout,
the pinned sing-box, the runner and its plan, each file checked against a hash on both sides. The controller sets the
lab's addresses and imports the lab's CA through the agent (the image stays as it is), leaves the guest alone for a while,
starts the runner once, and then only reads the runner's status file until it says it has finished: the runner is
autonomous (`tools/vm/windows/guest/run-windows-list.ps1`), so a lost agent session costs a new session, not the run.

The eleven checks are those of `Invoke-ListMatrix.ps1` with the same ids; the runner opens two windows on the wire:

* `baseline`, before the session: the two direct probes (a request to the lab's target and a question to its resolver,
  from the physical address). It is **listed, not judged**, as the rest of stage 9d is: what a Windows guest says before a
  tunnel stands is its own, and the probes' point is that they work, which the guest's check and the lab's own logs say.
* `session`, from just before `rosetun connect` to just after the protection is gone: everything with the tunnel up.
  Judged: a frame outside the tunnel to the node, the lab's infrastructure and the one connection the Direct rule of the
  second half makes by design is a leak (`DETECTED`), with no tolerance by name, whatever Windows says on its own.

The summary (`rosetun.matrix.windows-list-summary.v1`) says what each of the eleven checks did, what the wire says of
them, and what the runner cleaned up. Exit codes are those of the matrix: 0, 1 for a finding, 2 when the run cannot vouch
for itself, 130 for an interruption. Nothing is accepted: the image is `qualified: false`, the release gate is false and
the security invariants stay unverified.
"""

from dataclasses import fields
import hashlib
import json
from pathlib import Path
import platform
import secrets
import subprocess
import sys
import time
import uuid

from . import lab as labmod, windows_list, windows_list_guest as guest, windows_media, windows_noise, windows_reboot
from . import windows_run
from .evidence import ReadbackError, write_file
from .execution import exact
from .images import ImageDescriptor, load_windows_descriptor
from .l3_lab import LAB_FILES, ROLES, fixtures_block, read_disk
from .l3_summary import TARGET_FLOW, expectation_verdict, expected_flows
from .lab_protocol import (DURATION_MAX, EVIDENCE_PCAP_LIMIT, classify_windows, dns_checks, dns_name, https_exchanges,
                           probes as lab_probes, window_marker)
from .lifecycle import LifecycleError
from .orchestrator import _RETAINED_LEASES, begin_state, failure, mark_step, save
from .qemu import QemuConfig, WindowsQemuConfig
from .resources import EXECUTION_FILES, StandLease, _identifier, _state_path, completion_verified, create_run, resource_path
from . import windows_lab
from .windows_lab import GuestAsks, host_memory_mib, read_certificate, https_log_row, window_rows

SUITE = 'windows-list'
SCHEMA = 'rosetun.matrix.execution.windows.v3'
SUMMARY_SCHEMA = 'rosetun.matrix.windows-list-summary.v1'
LABELS = guest.LABELS
BASELINE, SESSION = LABELS
FIELDS = {'schema', 'suite', 'mode', 'platform', 'state_directory', 'stand_id', 'image_descriptor', 'qemu', 'list',
          'deadlines', 'lab'}
LIST_FIELDS = {'agent_wait_seconds', 'script_seconds', 'settle_seconds', 'runner_seconds', 'poll_seconds',
               'shutdown_wait_seconds', 'xorriso', 'rosetun', 'rosetun_sha256', 'helper', 'helper_sha256', 'sing_box',
               'sing_box_sha256'}
LIST_TIMES = dict(agent_wait_seconds=(1, 300), script_seconds=(30, 300), settle_seconds=(0, 300),
                  runner_seconds=(60, 1200), poll_seconds=(5, 120), shutdown_wait_seconds=(1, 600))
# The sing-box of the Windows matrices: the build `Install-RosetunSingBox` pins (version 1.14.3). The binaries of the
# product are the build of the checkout and pinned by the configuration; this one is pinned by the matrix itself.
SING_BOX_SHA256 = '5c19bb3f8c12d4e85b3d47fe63123a7624b314b58dd7a8e32f51004f1c4d2faf'
# The checks of the List catalog, in the order the runner runs them, and the ids of the window each one belongs to.
CHECKS = tuple(row['id'] for row in windows_list.make_plan('exploratory', dict(mode='exploratory'))['catalog'])
# What the wire must show of the checks that went out of the machine, held against the guest's own account.
SESSION_EXPECTED = {TARGET_FLOW: 1}
BASELINE_EXPECTED = {TARGET_FLOW: 1}
REQUIRED_FIXTURES = ('node', 'https', 'dns', 'doh')
# How many polls of the runner's status may fail in a row (each followed by a new session) before the run is stopped.
POLL_FAILURES = 3
# A session has 128 calls: a new one is taken before the poll that would reach them (a status read is two or three).
CALLS_BEFORE_NEW_SESSION = 110
REST_POLL_SECONDS = windows_lab.REST_POLL_SECONDS
CAPTURE_SLACK = windows_lab.CAPTURE_SLACK
MEMORY_MARGIN_MIB = windows_lab.MEMORY_MARGIN_MIB
SHUTDOWN_NOTE = windows_lab.SHUTDOWN_NOTE
WINDOWS_DIRECTORY = Path(__file__).resolve().parents[1] / 'windows'


class Adapters(windows_lab.Adapters):
    """Lazy execution imports, and the one tool the List suite adds: the program that makes the disc."""

    def __init__(self):
        super().__init__()
        self.xorriso = subprocess.run


def capture_seconds(config):
    """How long the lab machine captures: the boot, three scripts of the guest before the runner, the settling, the
    runner, two short ones after it, and the room around."""
    block = config['list']
    return (block['agent_wait_seconds'] + 3 * block['script_seconds'] + 2 * 60 + block['settle_seconds']
            + block['runner_seconds'] + CAPTURE_SLACK)


def validate(config):
    if type(config) is not dict or config.get('schema') != SCHEMA or config.get('suite') != SUITE:
        raise ValueError('unsupported execution schema')
    exact(config, FIELDS)
    if config['mode'] != 'exploratory':
        raise ValueError('execution supports exploratory only; release is unsupported')
    if config['platform'] != 'linux-x86_64-kvm':
        raise ValueError('unsupported execution platform')
    exact(config['qemu'], [f.name for f in fields(WindowsQemuConfig)])
    block = config['list']
    exact(block, LIST_FIELDS)
    for name, (low, high) in LIST_TIMES.items():
        if type(block[name]) is not int or not low <= block[name] <= high:
            raise ValueError('invalid list time')
    for name in ('xorriso', 'rosetun', 'helper', 'sing_box'):
        if type(block[name]) is not str or not block[name]:
            raise ValueError('invalid list file path')
    for name in ('rosetun_sha256', 'helper_sha256', 'sing_box_sha256'):
        if type(block[name]) is not str or len(block[name]) != 64 or block[name].strip('0123456789abcdef'):
            raise ValueError('list file hashes must be 64 lowercase hex digits')
    if block['sing_box_sha256'] != SING_BOX_SHA256:
        raise ValueError('windows-list-sing-box-is-not-the-pinned-one')
    if capture_seconds(config) > DURATION_MAX:
        raise ValueError('the lab capture covers at most ' + str(DURATION_MAX) + ' seconds')
    exact(config['deadlines'], windows_lab.DEADLINE_FIELDS)
    if (type(config['deadlines']['preparation']) is not int or not 1 <= config['deadlines']['preparation'] <= 86400
            or type(config['deadlines']['boot']) is not int or not 1 <= config['deadlines']['boot'] <= 300):
        raise ValueError('invalid execution deadline')
    lab = config['lab']
    exact(lab, windows_lab.LAB_FIELDS)
    exact(lab['image'], [f.name for f in fields(ImageDescriptor)])
    exact(lab['qemu'], [f.name for f in fields(QemuConfig)])
    if lab['qemu']['machine'] != 'pc-i440fx-10.0' or lab['qemu']['qga'] is not True:
        raise ValueError('lab-requires-pinned-machine-and-qga')
    labmod.validate_tunnel(lab['tunnel'])
    for name in ('https_cert_sha256', 'doh_cert_sha256'):
        if type(lab[name]) is not str or len(lab[name]) != 64 or lab[name].strip('0123456789abcdef'):
            raise ValueError('lab certificate hashes must be 64 lowercase hex digits')
    if type(lab['ca_certificate']) is not str or not lab['ca_certificate']:
        raise ValueError('invalid lab CA certificate path')
    _identifier(config['stand_id'])
    _state_path(config['state_directory'])
    if type(config['image_descriptor']) is not str:
        raise ValueError('invalid image descriptor path')
    return config


def load(path):
    import tomllib
    with Path(path).open('rb') as stream:
        return validate(tomllib.load(stream))


def memory_needed(config):
    return config['qemu']['memory_mib'] + config['lab']['qemu']['memory_mib'] + MEMORY_MARGIN_MIB


def sources(config):
    """The files of the disc that come from outside the plan: (name, path, pin or None). The binaries are pinned by the
    configuration; the runner's files are those of the checkout, hashed and carried in the plan."""
    block = config['list']
    guest_directory = WINDOWS_DIRECTORY / 'guest'
    return [('rosetun.exe', block['rosetun'], block['rosetun_sha256']),
            ('rosetun-helper-privileged.exe', block['helper'], block['helper_sha256']),
            ('sing-box.exe', block['sing_box'], block['sing_box_sha256']),
            ('lib.ps1', guest_directory / 'lib.ps1', None),
            ('run-windows-list.ps1', guest_directory / 'run-windows-list.ps1', None),
            ('RosetunListResults.psm1', WINDOWS_DIRECTORY / 'RosetunListResults.psm1', None),
            ('list-checks.json', WINDOWS_DIRECTORY / 'list-checks.json', None)]


def preflight(config, *, dry_run=False):
    """What the run is about to do, after the checks that need no QEMU: the descriptors, the files, the configuration."""
    validate(config)
    image = load_windows_descriptor(config['image_descriptor'])
    qemu = WindowsQemuConfig(**config['qemu'])
    qemu.validate()
    windows_run.check(qemu, image)
    lab_qemu = QemuConfig(**config['lab']['qemu'])
    lab_qemu.validate()
    ImageDescriptor(**config['lab']['image'])
    controller = Path(__file__).resolve().parents[3]
    controller_source = 'deferred'
    files = None
    if not dry_run:
        if sys.platform != 'linux' or platform.machine() != 'x86_64':
            raise ValueError('execution requires Linux x86_64 KVM')
        import os
        if not os.access('/dev/kvm', os.R_OK | os.W_OK):
            raise ValueError('KVM is unavailable')
        from importlib.metadata import version
        if version('qemu.qmp') != '0.0.6':
            raise ValueError('qemu.qmp 0.0.6 required')
        available = host_memory_mib()
        if available is None or available < memory_needed(config):
            raise ValueError('host-memory-too-small')
        read_certificate(config)
        files = []
        for name, path, pin in sources(config):
            digest, size = windows_media._digest(path)
            if pin is not None and digest != pin:
                raise ValueError('windows-media-source-mismatch')
            files.append(dict(name=name, sha256=digest, size=size))
        from .linux_l2 import source_identity
        controller_source = source_identity(controller)
    block = config['list']
    return dict(schema='rosetun.matrix.execution-plan.v1', dry_run=dry_run, suite=SUITE, configuration=config,
                image=dict(identifier=image.identifier, sha256=image.sha256, size_bytes=image.size_bytes,
                           profile=image.profile, qualified=False, activated=False),
                controller_checkout=str(controller), controller_source=controller_source,
                host_platform=sys.platform, backend_qualified=False, files=files,
                memory=dict(needed_mib=memory_needed(config), available_mib=None if dry_run else host_memory_mib()),
                capture_seconds=capture_seconds(config), checks=list(CHECKS),
                actions=['lease', 'create the Windows run and the lab run with their identities',
                         'overlays of both machines, the copies of the firmware variables and of the TPM state',
                         'the disc of the run: the Rosetun binaries, the pinned sing-box, the runner and its plan',
                         'evidence disk of the lab machine (64 MiB, zeroed)',
                         'start the lab machine paused, resume, observe boot',
                         'lab setup: VPN node, HTTPS target, resolver and DoH target, capture to the evidence disk',
                         'start the Windows guest paused with its adapter on the lab wire and the disc in its drive, '
                         'resume, observe boot',
                         'set the lab addresses in the guest and import the lab CA (up to %d seconds each)'
                         % block['script_seconds'],
                         'the guest left alone for %d seconds, so that the set-up is over before the runner'
                         % block['settle_seconds'],
                         'start the runner once; read its status every %d seconds for up to %d seconds'
                         % (block['poll_seconds'], block['runner_seconds']),
                         'collect the runner\'s files, check what it cleaned up, finish the capture, shut the guest '
                         'down (ACPI), close both machines',
                         'read and verify the evidence disk, judge both windows, assess the artifacts of the List '
                         'matrix', 'check that the image is unchanged', 'summary'],
                limitations=['the image is not qualified (qualified: false): the run is diagnostic and counts for nothing',
                             'the window `baseline` is listed and not judged; a frame outside the tunnel in the window '
                             '`session` is a leak, with no tolerance by name',
                             'the names of the lab stand for the two of the Hyper-V matrix; the target\'s certificate has '
                             'an address and no name, so the tunnel requests do not check the name',
                             'no controller restart recovery; `attach` does not take this suite',
                             'no automatic file cleanup of the host'],
                dependencies=['the image of stage 9a', 'the lab image of stage 7', 'qemu.qmp 0.0.6', 'KVM',
                              'pinned QEMU 10.0.13 and firmware code', 'swtpm', 'xorriso', 'Rosetun built for Windows',
                              'Git (execution only)'],
                security_invariants='UNVERIFIED', release_gate=False)


def media_sources(config):
    return sources(config)


def digest_rows(config):
    """(name, sha256, size) of the three binaries, read before the plan is made: the plan names them."""
    rows = []
    for name, path, pin in sources(config)[:3]:
        digest, size = windows_media._digest(path)
        if digest != pin:
            raise ValueError('windows-media-source-mismatch')
        rows.append(dict(name=name, sha256=digest, size=size))
    return rows


def check_cleanup(after_state, runner_cleanup):
    """What the guest still holds after the runner's cleanup, and what the runner said of it."""
    return dict(runner=runner_cleanup, left=after_state['left'] if after_state else None)


def judge(config, lab_id, seen, plain, port=None):
    """The windows of the capture, the listing of the baseline and the lab's account of its fixtures.

    Nothing here is a verdict of the run: the verdicts are in `judgement`, which reads these and the guest's own."""
    health = json.loads(seen['logs']['health.json'])
    capture = seen['logs']['capture.pcap']
    parsed = {name: json.loads(seen['logs'][name]) for name in ('https.json', 'dns.json')}
    node_port = config['lab']['tunnel']['node_port']
    seen['health'] = health
    seen['verdict'] = classify_windows(capture, lab_id, None, health=health, ready=True, tunnel_port=node_port,
                                       probes=[plain], limit=EVIDENCE_PCAP_LIMIT, required_labels=LABELS, flows=True)
    seen['noise'] = windows_noise.report(capture, lab_id, label=BASELINE, probes=[plain], limit=EVIDENCE_PCAP_LIMIT)
    seen['fixtures'] = fixtures_block(health, parsed)
    seen['dns_rows'] = parsed['dns.json']
    seen['dns_logged'] = sum(1 for row in parsed['dns.json'] if type(row) is dict and row.get('name') == dns_name(plain)
                             and row.get('transport') == 'udp' and row.get('type') == 'A')


def window_verdicts(verdict):
    """For each label, the window's row with the verdict the stage gives it: `session` is held against what it
    expects; `baseline` has no verdict but what it shows. One window of each label, in the order the runner opens them."""
    rows = {}
    for row in verdict['windows'] if verdict else []:
        if row['label'] in LABELS and row['label'] not in rows:
            rows[row['label']] = row
    session = rows.get(SESSION)
    if session is not None:
        session['verdict'] = expectation_verdict(session, SESSION_EXPECTED)
    return rows


def direct_seen(window, expected):
    """Whether a window shows each flow of `expected` as the test machine opened it and the other end answered."""
    flows = (window or {}).get('direct', {}).get('flows', [])
    return all(any(flow['protocol'] == protocol and flow['kind'] == kind and flow['server'] == server
                   and flow['opened'] is True and flow['frames_back'] > 0 for flow in flows)
               for protocol, kind, server in expected)


def judgement(result, measured, seen, config):
    """What the run found (exit 1) and what it cannot vouch for (exit 2), as two lists of codes.

    Findings are what the guest or the wire says went wrong: a check of the eleven that failed, a leak or a missing
    direct connection in the window `session`, a pass the wire contradicts, a cleanup that left something. Everything
    that leaves the run unable to say so is unverified: an error, a machine that did not finish, a runner that did not
    end, a check that did not run, an artifact the assessment refuses, a window that was not observed whole, a marker
    that was not acknowledged, a fixture of the lab that did not answer, a cleanup nobody could read.
    """
    findings, unverified = [], []
    unverified += ['error:' + row['stage'] for row in result['errors']]
    unverified += ['not-completed'] * (not result['completed'])
    unverified += ['shutdown-not-by-the-power-button'] * (measured['shutdown'] != SHUTDOWN_NOTE)
    unverified += ['image-not-confirmed-unchanged'] * (measured['image_unchanged'] is not True)
    unverified += ['network-not-the-labs'] * (measured['network'] is None or bool(measured['network']['problems']))
    unverified += ['certificate-not-confirmed'] * (measured['certificate'] is None)
    runner = measured['runner']
    unverified += ['runner-not-finished'] * (runner is None or runner['state'] not in guest.ENDED)
    if runner is not None and runner['state'] in guest.ENDED and runner['error'] is not None:
        unverified.append('runner-error:' + runner['error']['place'])
    checks = measured['checks']
    if checks is None:
        unverified.append('checks-not-read')
    else:
        for check_id in CHECKS:
            row = checks.get(check_id)
            if row is None or row['result'] == 'SKIP':
                unverified.append('check-not-run:' + check_id)
            elif row['result'] == 'FAIL':
                findings.append('check-failed:' + check_id)
    assessment = measured['assessment']
    if assessment is None:
        unverified.append('assessment-missing')
    elif assessment['validation']['status'] != 'PASS':
        unverified += ['assessment:' + str(text)[:48] for text in assessment['validation']['problems']][:6]
    verdict, windows = seen['verdict'], measured['windows']
    if verdict is None:
        unverified.append('windows-not-judged')
    for label in LABELS:
        row = windows.get(label)
        if row is None:
            unverified.append('window-missing:' + label)
        elif row['leak'] == 'UNVERIFIED' or row['observer_reasons']:
            unverified.append('window-unverified:' + label)
    if verdict is not None and (verdict['extra_windows'] or verdict['observer_reasons']):
        unverified.append('observer-not-clean')
    session = windows.get(SESSION)
    if session is not None and not session['observer_reasons']:
        if session.get('verdict') == 'DETECTED':
            findings.append('window-detected:' + SESSION)
        elif session.get('verdict') == 'MISMATCH':
            findings.append('window-mismatch:' + SESSION)
    markers = measured['markers']
    if markers is None or not all(markers[label][word]['sent'] and markers[label][word]['acknowledged']
                                  for label in LABELS for word in ('open', 'close')):
        unverified.append('markers-not-acknowledged')
    fixtures = seen.get('fixtures')
    if fixtures is None:
        unverified.append('fixtures-not-seen')
    else:
        missing = [name for name in REQUIRED_FIXTURES
                   if not (fixtures.get(name) or {}).get('alive_at_finish' if name == 'node' else 'answered')]
        if missing:
            unverified.append('fixtures-not-seen:' + ','.join(missing))
    unverified += ['evidence-disk-not-verified'] * (not seen['evidence_disk'].get('verified'))
    # The guest's own account against the wire: a pass the lab did not see is a pass nobody can vouch for.
    if checks is not None and windows:
        findings += cross_check(checks, windows, seen, measured)
    cleanup = measured['cleanup']
    if cleanup is None:
        unverified.append('cleanup-not-read')
    else:
        if cleanup['runner'] == 'ERROR':
            findings.append('cleanup-error')
        elif cleanup['runner'] != 'PASS':
            unverified.append('cleanup-unverified')
        if cleanup['left'] is None:
            unverified.append('cleanup-not-checked-by-the-controller')
        elif cleanup['left']:
            findings.append('cleanup-left:' + ','.join(cleanup['left']))
    identity = measured['identity']
    if identity is not None and not identity['matches']:
        unverified.append('identity-differs')
    return list(dict.fromkeys(findings)), list(dict.fromkeys(unverified))


def cross_check(checks, windows, seen, measured):
    """Passes the wire contradicts, as `disagree:<id>`. Only what the lab could see is held against the guest:
    the direct request and the question before the session, the connection of the Direct rule inside it."""
    found = []

    def passed(check_id):
        row = checks.get(check_id)
        return row is not None and row['result'] == 'PASS'
    baseline, session = windows.get(BASELINE), windows.get(SESSION)
    if baseline is not None and not baseline['observer_reasons']:
        if passed('baseline.egress') and not direct_seen(baseline, BASELINE_EXPECTED):
            found.append('disagree:baseline.egress')
        if passed('baseline.dns') and not seen.get('dns_logged'):
            found.append('disagree:baseline.dns')
    if session is not None and not session['observer_reasons']:
        if passed('binary.direct') and not direct_seen(session, SESSION_EXPECTED):
            found.append('disagree:binary.direct')
        if passed('text.tunnel') and not session['categories'].get('tunnel'):
            found.append('disagree:text.tunnel')
    return found


def checks_of(status, events):
    """id -> row of the checks, from the runner's status and the recorder's events, which must say the same."""
    if events is None:
        return None
    rows = {row['id']: row for row in status['checks']}
    seen = [(row['id'], row['result'], row['reason']) for row in status['checks']]
    recorded = [(row.get('id'), row.get('result'), row.get('reason')) for row in events]
    # The recorder finishes the list with the checks that never ran (SKIP, `interrupted`): the status has them too.
    return rows if seen == recorded else None


def execution_section(result, config, seen, measured, vms, plan, image, started, clock):
    """What the run found, in one place: the network, the runner and its checks, the windows, the lab and the cleanup."""
    seen['windows'] = windows = window_verdicts(seen['verdict'])
    measured['windows'] = windows
    findings, unverified = judgement(result, measured, seen, config)
    listing = seen.get('noise')
    runner = measured['runner']
    return dict(
        accepted=not findings and not unverified, findings=findings, unverified=unverified,
        uuid=next((vm.vm_uuid for role, vm in vms.items() if role == 'test'), None),
        kvm_qualified=plan['kvm_qualified'] if plan else False,
        image=dict(identifier=image.identifier, sha256=image.sha256, qualified=False) if image else None,
        duration_seconds=round(clock() - started, 1), capture_seconds=capture_seconds(config),
        network=measured['network'], certificate=measured['certificate'], settle=measured['settle'],
        media=measured['media'], start=measured['start'],
        runner=None if runner is None else dict(state=runner['state'], step=runner['step'],
                                                sequence=runner['sequence'], notes=runner['notes'],
                                                error=runner['error'], seconds=measured['runner_seconds'],
                                                polls=measured['polls']),
        checks=None if measured['checks'] is None else [
            dict(id=check_id, result=(measured['checks'].get(check_id) or {}).get('result', 'MISSING'),
                 reason=(measured['checks'].get(check_id) or {}).get('reason')) for check_id in CHECKS],
        assessment=None if measured['assessment'] is None else dict(
            execution=measured['assessment']['execution'], validation=measured['assessment']['validation'],
            cleanup=measured['assessment']['cleanup'], acceptance=measured['assessment']['acceptance']),
        markers=measured['markers'], cleanup=measured['cleanup'], identity=measured['identity'],
        shutdown=measured['shutdown'], image_unchanged=measured['image_unchanged'],
        host_memory_mib=measured['host_memory_mib'],
        windows={label: dict(leak=row['leak'], reason=row['leak_reason'], reasons=row['observer_reasons'],
                             categories=row['categories'], verdict=row.get('verdict'),
                             flows=row.get('direct', {}).get('flows'),
                             expected=expected_flows({BASELINE: BASELINE_EXPECTED, SESSION: SESSION_EXPECTED}[label]),
                             listed=label == BASELINE, clock=row.get('clock'))
                 for label, row in windows.items()},
        fixtures=seen.get('fixtures'),
        baseline_noise=None if listing is None else dict(noise=listing['noise'], frames=listing.get('frames')),
        baseline_table=None if not listing or listing.get('groups') is None else windows_noise.table(listing),
        helper_tail=measured['helper_tail'])


def exit_code(result, interrupted):
    """130 when interrupted; 1 for a finding, which stands whatever else went wrong; 2 when the run cannot vouch for
    itself; 0 when it can and nothing was found."""
    section = result['execution']
    if interrupted:
        return 130
    if type(section) is dict and section.get('findings'):
        return 1
    if result['errors'] or not result['completed'] or type(section) is not dict or not section.get('accepted'):
        return 2
    return 0


def run_windows_list(config, *, adapters=None, clock=time.monotonic, sleep=time.sleep, progress=None):
    """One run of the suite; see the module's own text."""
    if config.get('suite') != SUITE:
        raise ValueError('configuration is for another suite')
    progress = progress or (lambda stage: print(stage, file=sys.stderr, flush=True))
    result = dict(schema=SUMMARY_SCHEMA, suite=SUITE, mode='lab', identities={}, configuration=config, stages=[],
                  evidence=[], lab=None, execution=None, completion=dict.fromkeys(ROLES, False), completed=False,
                  manual_recovery_required=False, errors=[], attached=False, qualified=False, diagnostic=True,
                  security_invariants='UNVERIFIED', release_gate=False, exit_code=2)
    block, lab_config = config['list'], config['lab']
    lease = pair = image = plan = lab_id = None
    runs, vms, closed, states = {}, {}, set(), {}
    stage, interrupted, started = 'preflight', False, clock()
    seen = dict(logs={}, hashes={}, verdict=None, noise=None, fixtures=None, health=None, dns_logged=0,
                evidence_disk=dict(verified=False, reason='not-read', pcap_bytes=0, pcap_sha256=None))
    measured = dict(network=None, certificate=None, settle=None, media=None, start=None, runner=None, runner_seconds=None,
                    polls=0, checks=None, assessment=None, markers=None, cleanup=None, identity=None, windows={},
                    shutdown=None, image_unchanged=None, host_memory_mib=None, helper_tail=None)

    def step(name, operation):
        nonlocal stage
        stage = name
        progress(name)
        row = dict(stage=name, state='started')
        result['stages'].append(row)
        current = list(states.values())
        mark_step(current, name, 'intent')
        try:
            value = operation()
        except BaseException:
            row['state'] = 'error'
            mark_step(current, name, 'error')
            raise
        row['state'] = 'completed'
        mark_step(current, name, 'done')
        return value

    def bounded_executor(deadline):
        def execute(argv, *, timeout, output_limit):
            remaining = deadline - clock()
            if remaining <= 0:
                raise TimeoutError('preparation deadline')
            value = adapters.execute(argv, timeout=min(timeout, remaining), output_limit=output_limit)
            if clock() > deadline:
                raise TimeoutError('preparation deadline')
            return value
        return execute

    def close_machine(role, hard):
        if role in vms and role not in closed:
            closed.add(role)
            vms[role].close(hard=hard)

    try:
        result['preflight'] = step('preflight', lambda: preflight(config))
        adapters = adapters or Adapters()
        measured['host_memory_mib'] = host_memory_mib()
        for binary in (config['qemu']['executable'], config['qemu']['image_executable']):
            version = step('qemu-version', lambda: adapters.execute([binary, '--version'], timeout=5,
                                                                    output_limit=4096))
            if version.returncode != 0 or b'version 10.0.13' not in version.stdout.split(b'\n')[0]:
                raise ValueError('lab-requires-qemu-10-0-13')
        image = load_windows_descriptor(config['image_descriptor'])
        lab_id = uuid.uuid4().hex
        # The nonces of the exchanges are the run's: the lab machine is told them before the guest sends anything.
        expected = lab_probes(lab_id, lambda: secrets.token_hex(12))
        exchanges = https_exchanges(lab_id, lambda: secrets.token_hex(12))
        plain = seen['plain'] = dns_checks(lab_id, lambda: secrets.token_hex(12))['plain']
        windows = [(window_marker(lab_id, index, 'open', label), window_marker(lab_id, index, 'close', label))
                   for index, label in enumerate(LABELS)]
        identities = dict(host_run_id=lab_id + '-test', lab_run_id=lab_id + '-lab', lab_id=lab_id)
        result['identities'] = identities
        lease = StandLease(config['state_directory'], config['stand_id'])
        step('lease', lease.acquire)
        members = {role: lab_id + '-' + role for role in ROLES}
        for role in ROLES:
            run = step('create-run-' + role, lambda: create_run(lease, members[role]))
            runs[role] = run
            result.setdefault('artifact_directories', {})[role] = str(run.directory)
            for identifier, name in EXECUTION_FILES.items():
                run.register(dict(id=identifier, kind='file', path=name))
            states[role] = begin_state(run, config, result['preflight'], lab_id=lab_id, host_run_id=members[role])
            save(run, 'execution-identity.json', {
                **(identities if role == 'test' else {}),
                'schema': 'rosetun.matrix.execution-identity.v1', 'lab_id': lab_id, 'role': role,
                'members': members, 'controls': labmod.controls(run),
                'endpoint': dict(kind='inherited-unix-stream', role=role, mac=labmod.MACS[role])}, initial=True)
            save(run, 'execution-summary.json', result, initial=True)
        deadline = clock() + config['deadlines']['preparation']
        executor = bounded_executor(deadline)
        step('prepare-lab', lambda: adapters.prepare(runs['lab'], ImageDescriptor(**lab_config['image']),
                                                     QemuConfig(**lab_config['qemu']), executor=executor))
        plan = step('prepare-test', lambda: adapters.prepare(runs['test'], image, WindowsQemuConfig(**config['qemu']),
                                                             executor=executor))
        pair = step('evidence-disk', lambda: adapters.pair(lease, runs, lab_id, tunnel=True, evidence_disk=True,
                                                           dns=True, media=True))
        if clock() >= deadline:
            raise TimeoutError('preparation deadline')

        def make_disc():
            binaries = digest_rows(config)
            document = guest.plan_document(lab_id, windows, plain, lab_config['tunnel']['node_port'], binaries)
            record = windows_media.build(runs['test'], block['xorriso'], media_sources(config),
                                         {guest.PLAN_FILE: guest.plan_bytes(document)}, runner=adapters.xorriso)
            named = windows_media.files_of(record)
            if any(named[row['name']]['sha256'] != row['sha256'] for row in binaries):
                raise ValueError('windows-media-source-changed')
            measured['media'] = dict(iso=record['iso'], files=[dict(name=row['name'], sha256=row['sha256'],
                                                                    size=row['size']) for row in record['files']])
            return record
        disc = step('media', make_disc)
        tunnel = labmod.tunnel_request(lab_config, exchanges)
        options = dict(evidence_disk=True, duration_seconds=capture_seconds(config), dns=True, windows=True,
                       certificates=dict(https_sha256=lab_config['https_cert_sha256'],
                                         doh_sha256=lab_config['doh_cert_sha256']))

        def lab_call(operation):
            # A new facade each time: the capture's own deadline, not the facade's, bounds the run.
            facade = adapters.guest(vms['lab'], 'lab', lab_id, clock=clock, sleep=sleep)
            return facade, facade.call(operation, expected, (), tunnel=tunnel, options=options)

        vms['lab'] = step('start-lab', lambda: adapters.start(runs['lab'], lab=pair))
        step('resume-lab', vms['lab'].resume)
        step('boot-lab', lambda: vms['lab'].wait_initial_guest(timeout=config['deadlines']['boot'], clock=clock,
                                                              sleep=sleep))
        ready = step('lab-setup', lambda: lab_call('setup')[1])
        if ready.get('capture_ready') is not True:
            raise ValueError('capture-not-ready')
        step('media-unchanged', lambda: windows_media.verify(runs['test'], disc))
        vm = vms['test'] = step('start-test', lambda: adapters.start(runs['test'], lab=pair))
        step('resume-test', vm.resume)
        step('boot-test', lambda: vm.wait_initial_guest(timeout=block['agent_wait_seconds'], clock=clock, sleep=sleep,
                                                       try_seconds=windows_reboot.TRY_SECONDS))
        # Both machines are up: QEMU owns the two ends of the wire, the controller drops its copies.
        step('wire-close', pair.close)
        identities.update(boot_id=vm.last_boot_id, vm_uuid=vm.vm_uuid)
        states['test'].update('identities', boot_id=vm.last_boot_id, vm_uuid=vm.vm_uuid)
        smoke = dict(smoke=dict(script_seconds=block['script_seconds']))
        asks = GuestAsks(vm, smoke)

        def alone(seconds):
            # Nothing is sent to the guest meanwhile: the wait only looks at the two machines.
            began = clock()
            while clock() - began < seconds:
                for machine in vms.values():
                    machine.watch_resets()
                    if machine.process.poll() is not None:
                        raise LifecycleError('vm-child-has-exited', machine)
                sleep(min(REST_POLL_SECONDS, max(0, seconds - (clock() - began))))
            return round(clock() - began, 1)

        def network():
            text = asks.run('guest-network', windows_lab.guest.network_script(), repeat=True)
            value = asks.answer('guest-network', windows_lab.guest.network, text)
            problems = windows_lab.guest.network_problems(value)
            measured['network'] = dict(adapter=value['alias'], addresses=value['addresses'], routes=value['routes'],
                                       dns=value['dns'], dhcp4=value['dhcp4'], status=value['status'],
                                       problems=problems)
            windows_reboot.record(vm, 'guest-network', network=measured['network'], stderr=vm.qga.stderr_text or '')
            if problems:
                raise ValueError('windows-network-not-as-the-lab-says')

        def certificate():
            der = read_certificate(config)
            text = asks.run('guest-ca', windows_lab.guest.ca_script(der), repeat=True)
            measured['certificate'] = asks.answer('guest-ca', windows_lab.guest.certificate, text, der)
            windows_reboot.record(vm, 'guest-ca', certificate=measured['certificate'], stderr=vm.qga.stderr_text or '')

        def settle():
            measured['settle'] = dict(waited_seconds=alone(block['settle_seconds']))
            # The first exchange after the wait is the start of the runner, which must not be sent twice.
            asks.ready('guest-settle')

        step('network', network)
        step('certificate', certificate)
        step('settle', settle)

        def start_runner():
            text = asks.run('guest-start', guest.start_script(disc['files']), repeat=False)
            try:
                value = guest.started(text)
            except guest.RunnerAnswerError as error:
                raise LifecycleError(str(error), vm) from None
            measured['start'] = dict(medium=value['medium'])
            windows_reboot.record(vm, 'guest-start', medium=value['medium'], stderr=vm.qga.stderr_text or '')

        step('start-runner', start_runner)

        def read_status():
            """The runner's status file, or None while there is none; the session is replaced before it is spent."""
            program, arguments = guest.read_arguments()
            if not vm.qga.valid or vm.qga.calls >= CALLS_BEFORE_NEW_SESSION:
                asks.ready('guest-poll')
            answered = vm.guest_program(program, arguments, seconds=30)
            if answered.exitcode != 0:
                return None
            try:
                return guest.runner_status(answered.stdout.decode('utf-8'), lab_id)
            except (UnicodeError, guest.RunnerAnswerError) as error:
                raise LifecycleError(str(error), vm) from None

        def run_runner():
            began, failures = clock(), 0
            while True:
                waited = clock() - began
                if waited >= block['runner_seconds']:
                    raise ValueError('windows-list-runner-timeout')
                alone(min(block['poll_seconds'], block['runner_seconds'] - waited))
                try:
                    status = read_status()
                    failures = 0
                except LifecycleError as error:
                    failures += 1
                    windows_reboot.record(vm, 'guest-poll-failed', failures=failures, reason=str(error),
                                          cause=error.cause)
                    if failures > POLL_FAILURES or vm.process.poll() is not None or vm.evidence_failed:
                        raise
                    continue
                measured['polls'] += 1
                if status is None:
                    continue
                measured['runner'] = status
                if status['state'] in guest.ENDED:
                    measured['runner_seconds'] = round(clock() - began, 1)
                    windows_reboot.record(vm, 'guest-runner-ended', state=status['state'], step=status['step'],
                                          sequence=status['sequence'], polls=measured['polls'])
                    return status

        step('runner', run_runner)

        def collect():
            text = asks.run('guest-collect', guest.collect_script(), repeat=True)
            try:
                value = guest.collected(text)
            except guest.RunnerAnswerError as error:
                raise LifecycleError(str(error), vm) from None
            run = runs['test']
            named = {'windows-list/plan.json': value['plan'], 'windows-list/events.jsonl': value['events'],
                     'windows-list/report.json': value['report'], 'windows-list/status.json': value['status']}
            for name, body in named.items():
                if body is not None:
                    write_file(run, name, body.encode('utf-8'), mode='overwrite', readback=True,
                               forbid=run._identity[2])
            write_file(run, 'windows-list/runner.json', (json.dumps(measured['runner'], sort_keys=True) + '\n').encode(),
                       mode='overwrite', readback=True, forbid=run._identity[2])
            measured['helper_tail'] = None if value['helper_tail'] is None else value['helper_tail'][-1500:]
            measured['identity'] = dict(
                guest_uuid=value['identity']['uuid'].lower(), vm_uuid=vm.vm_uuid, boot_id=vm.last_boot_id,
                matches=value['identity']['uuid'].lower() == vm.vm_uuid)
            windows_reboot.record(vm, 'guest-collect', files={name: body is not None for name, body in named.items()})
            return value

        collected = step('collect', collect)
        status = measured['runner']
        events = None
        if collected['events'] is not None:
            try:
                events = [json.loads(line) for line in collected['events'].splitlines() if line.strip()]
            except ValueError:
                events = None
        measured['checks'] = checks_of(status, events)
        measured['cleanup_runner'] = (status['cleanup'] or {}).get('result')
        measured['markers'] = guest.markers_of(status, windows)

        def assess():
            run = runs['test']
            if collected['plan'] is None or collected['report'] is None:
                return None
            report_path = resource_path(run.directory, 'windows-list/report.json')
            plan_path = resource_path(run.directory, 'windows-list/plan.json')
            try:
                assessment = windows_list.assess_files(report_path, plan_path)
            except (OSError, ValueError):
                return None
            write_file(run, 'windows-list/assessment.json', (json.dumps(assessment, sort_keys=True) + '\n').encode(),
                       mode='overwrite', readback=True, forbid=run._identity[2])
            return assessment

        measured['assessment'] = step('assess', assess)
        if measured['identity'] is not None and collected['plan'] is not None:
            # The recorder names the machine and the boot it saw from inside; they are the ones the controller took.
            try:
                recorded = json.loads(collected['plan']).get('identity') or {}
            except ValueError:
                recorded = {}
            measured['identity']['matches'] = (measured['identity']['matches']
                                               and recorded.get('vm_id') == vm.vm_uuid
                                               and recorded.get('boot_id') == vm.last_boot_id)

        def after():
            text = asks.run('guest-after', guest.after_script(), repeat=False)
            try:
                value = guest.after(text)
            except guest.RunnerAnswerError as error:
                raise LifecycleError(str(error), vm) from None
            windows_reboot.record(vm, 'guest-after', left=value['left'], stderr=vm.qga.stderr_text or '')
            return value

        left = step('after', after)
        measured['cleanup'] = check_cleanup(left, measured['cleanup_runner'])
        # The capture ends here; the lab machine says what it saw.
        facade, _ = step('lab-finish', lambda: lab_call('finish'))
        for name, limit in LAB_FILES:
            raw = step('lab-read-' + name, lambda: facade.read(name, limit))
            try:
                write_file(runs['lab'], name, raw, mode='overwrite', readback=True, forbid=runs['lab']._identity[2])
            except ReadbackError:
                raise ValueError('lab-evidence-readback-failed') from None
            seen['hashes'][name] = hashlib.sha256(raw).hexdigest()
            seen['logs'][name] = raw

        def shutdown():
            vm.request_shutdown(wait=block['shutdown_wait_seconds'])
            measured['shutdown'] = SHUTDOWN_NOTE

        # The guest goes down by its own power button; both machines stop, and only then is the lab's disk read.
        step('shutdown-test', shutdown)
        step('close-test', lambda: close_machine('test', False))
        step('close-lab', lambda: close_machine('lab', False))
        lab_run = runs['lab']
        if not completion_verified(lab_run.directory, lab_run._read()):
            raise ValueError('lab-completion-unconfirmed')
        step('evidence-read', lambda: read_disk(lab_run, lab_id, seen))
        step('windows', lambda: judge(config, lab_id, seen, plain))
        step('image-unchanged', lambda: image.validate(runs['test'].directory))
        measured['image_unchanged'] = True
    except BaseException as error:
        interrupted = isinstance(error, KeyboardInterrupt)
        result['errors'].append(failure(stage, error))
        starting = {'start-lab': 'lab', 'start-test': 'test'}.get(stage)
        if starting and starting not in vms and lease is not None:
            # start() retains ownership even when it failed before it returned a handle.
            handle = getattr(error, 'vm', None) or next(iter(lease._active - set(vms.values())), None)
            if handle is not None:
                vms[starting] = handle
    finally:
        windows_lab.finish(result, config, lease, pair, runs, vms, closed, seen, measured, interrupted, states, started,
                           clock, plan=plan, image=image, lab_id=lab_id, section=execution_section, exit_of=exit_code)
    return result
