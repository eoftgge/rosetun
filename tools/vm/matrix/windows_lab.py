"""`run windows-lab-smoke` (stage 9d): a Windows guest of the 9a image on the lab's wire, without Rosetun.

Two machines run under one lease, as for the Linux suites of the lab: the lab machine (routing, the targets, the
resolver and the capture to its evidence disk) and the test machine, which here is the Windows guest. The guest's
network adapter is the one of the image, with the MAC the lab calls the test machine's, attached to the lab's wire
when the machine starts. The addresses are not in the image (it is qualified and frozen): the controller sets them
through the guest agent once the guest answers, imports the lab's CA into the machine's root store, and then runs, in
the guest's own PowerShell, the eight probes of the lab contract, one HTTPS request that the system itself validates
and one lookup against the lab resolver, between two window markers. Before the probes the guest is left alone for
`settle_seconds`, so that what the set-up leaves behind does not fall in their window. It is left alone again for the
length of the rest window, and the capture of that window is the noise report, which lists and decides nothing.

Nothing is tolerated that the observer does not tolerate: a frame outside `infrastructure` in the window of the probes
makes it `DETECTED`. In the window of rest it is listed (`noise: FOUND`) and the run is not judged by it: what Windows
says when it is left alone is the natural traffic the later stages (with a tunnel) have to keep in the tunnel or off the
wire. The image is not qualified, so the run is diagnostic whatever it reports.
"""

from dataclasses import fields
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import sys
import time
import uuid

from . import lab as labmod, windows_lab_guest as guest, windows_noise, windows_reboot, windows_run
from .evidence import ReadbackError, write_file
from .execution import exact
from .images import ImageDescriptor, load_windows_descriptor
from .lab_protocol import (CLIENTS, DURATION_MAX, EVIDENCE_PCAP_LIMIT, classify_windows, dns_checks, dns_name,
                           https_exchanges, probes as lab_probes, qualify, window_marker)
from .l3_lab import LAB_FILES, ROLES, read_disk
from .lifecycle import LifecycleError
from .orchestrator import _RETAINED_LEASES, begin_state, failure, finish_state, mark_step, save
from .qemu import QemuConfig, WindowsQemuConfig
from .resources import EXECUTION_FILES, StandLease, completion_verified, create_run, _identifier, _state_path

SUITE = 'windows-lab-smoke'
SCHEMA = 'rosetun.matrix.execution.windows.v2'
SUMMARY_SCHEMA = 'rosetun.matrix.windows-lab-summary.v1'
# The windows of the run, in order: the probes, then the guest left alone.
PROBES_LABEL, REST_LABEL = 'probes', windows_noise.REST_LABEL
LABELS = (PROBES_LABEL, REST_LABEL)
FIELDS = {'schema', 'suite', 'mode', 'platform', 'state_directory', 'stand_id', 'image_descriptor', 'qemu', 'smoke',
          'deadlines', 'lab'}
LAB_FIELDS = {'image', 'qemu', 'tunnel', 'https_cert_sha256', 'doh_cert_sha256', 'ca_certificate'}
DEADLINE_FIELDS = ('preparation', 'boot')
# The lowest and the highest each time of `[smoke]` may be, in seconds. `script_seconds` is what one PowerShell of the
# guest may take; the first one of a boot took more than 180 seconds on the stand.
SMOKE_TIMES = dict(agent_wait_seconds=(1, 300), script_seconds=(30, 300), rest_seconds=(60, 900),
                   shutdown_wait_seconds=(1, 600), settle_seconds=(0, 300))
# `settle_seconds` may be left out of `[smoke]`: the guest then has this long to quiet down after its set-up.
SETTLE_DEFAULT = 60
# The capture also covers the lab's set-up and the boot of the guest around the run, and the end of it.
CAPTURE_SLACK = 300
# The guest's scripts that may be asked again on a new agent session: they change nothing a second time.
REPEATABLE_TIMEOUTS = windows_reboot.EVIDENCE_TIMEOUTS
# How often the wait of the rest looks at the machines: a look sends nothing to the guest and spends no command.
REST_POLL_SECONDS = 5
# What the host needs beyond the memory of the two guests: QEMU, swtpm, the controller and the page cache.
MEMORY_MARGIN_MIB = 768
SHUTDOWN_NOTE = 'acpi'


def settle_seconds(smoke):
    return smoke.get('settle_seconds', SETTLE_DEFAULT)


def capture_seconds(config):
    """How long the lab machine captures: the boot, every script of the guest, the settling, the rest, and the room around."""
    smoke = config['smoke']
    return (smoke['agent_wait_seconds'] + 4 * smoke['script_seconds'] + settle_seconds(smoke) + smoke['rest_seconds']
            + CAPTURE_SLACK)


def validate(config):
    if type(config) is not dict or config.get('schema') != SCHEMA or config.get('suite') != SUITE:
        raise ValueError('unsupported execution schema')
    exact(config, FIELDS)
    if config['mode'] != 'exploratory':
        raise ValueError('execution supports exploratory only; release is unsupported')
    if config['platform'] != 'linux-x86_64-kvm':
        raise ValueError('unsupported execution platform')
    exact(config['qemu'], [f.name for f in fields(WindowsQemuConfig)])
    smoke = config['smoke']
    if type(smoke) is not dict or not (set(SMOKE_TIMES) - {'settle_seconds'} <= set(smoke) <= set(SMOKE_TIMES)):
        raise ValueError('unknown or missing execution configuration fields')
    for name, (low, high) in SMOKE_TIMES.items():
        if name not in smoke:
            continue
        value = smoke[name]
        if type(value) is not int or not low <= value <= high:
            raise ValueError('invalid smoke time')
    if capture_seconds(config) > DURATION_MAX:
        raise ValueError('the lab capture covers at most ' + str(DURATION_MAX) + ' seconds')
    exact(config['deadlines'], DEADLINE_FIELDS)
    if (type(config['deadlines']['preparation']) is not int or not 1 <= config['deadlines']['preparation'] <= 86400
            or type(config['deadlines']['boot']) is not int or not 1 <= config['deadlines']['boot'] <= 300):
        raise ValueError('invalid execution deadline')
    block = config['lab']
    exact(block, LAB_FIELDS)
    exact(block['image'], [f.name for f in fields(ImageDescriptor)])
    exact(block['qemu'], [f.name for f in fields(QemuConfig)])
    if block['qemu']['machine'] != 'pc-i440fx-10.0' or block['qemu']['qga'] is not True:
        raise ValueError('lab-requires-pinned-machine-and-qga')
    labmod.validate_tunnel(block['tunnel'])
    for name in ('https_cert_sha256', 'doh_cert_sha256'):
        if type(block[name]) is not str or len(block[name]) != 64 or block[name].strip('0123456789abcdef'):
            raise ValueError('lab certificate hashes must be 64 lowercase hex digits')
    if type(block['ca_certificate']) is not str or not block['ca_certificate']:
        raise ValueError('invalid lab CA certificate path')
    _identifier(config['stand_id'])
    _state_path(config['state_directory'])
    if type(config['image_descriptor']) is not str:
        raise ValueError('invalid image descriptor path')
    return config


def host_memory_mib():
    """The memory the host can give a new process, from /proc/meminfo; None where there is no such file."""
    try:
        for line in Path('/proc/meminfo').read_text(encoding='ascii').splitlines():
            if line.startswith('MemAvailable:'):
                return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


def memory_needed(config):
    return config['qemu']['memory_mib'] + config['lab']['qemu']['memory_mib'] + MEMORY_MARGIN_MIB


def read_certificate(config):
    """The lab's CA as a PEM file on the controller: its bytes must be the ones the lab machine pins."""
    raw = Path(config['lab']['ca_certificate']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != config['lab']['tunnel']['ca_sha256']:
        raise ValueError('lab-ca-certificate-hash-mismatch')
    return guest.certificate_der(raw)


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
    if not dry_run:
        if sys.platform != 'linux' or platform.machine() != 'x86_64':
            raise ValueError('execution requires Linux x86_64 KVM')
        if not os.access('/dev/kvm', os.R_OK | os.W_OK):
            raise ValueError('KVM is unavailable')
        from importlib.metadata import version
        if version('qemu.qmp') != '0.0.6':
            raise ValueError('qemu.qmp 0.0.6 required')
        available = host_memory_mib()
        if available is None or available < memory_needed(config):
            raise ValueError('host-memory-too-small')
        read_certificate(config)
        from .linux_l2 import source_identity
        controller_source = source_identity(controller)
    smoke = config['smoke']
    return dict(schema='rosetun.matrix.execution-plan.v1', dry_run=dry_run, suite=SUITE, configuration=config,
                image=dict(identifier=image.identifier, sha256=image.sha256, size_bytes=image.size_bytes,
                           profile=image.profile, qualified=False, activated=False),
                controller_checkout=str(controller), controller_source=controller_source,
                host_platform=sys.platform, backend_qualified=False,
                memory=dict(needed_mib=memory_needed(config), available_mib=None if dry_run else host_memory_mib()),
                capture_seconds=capture_seconds(config),
                actions=['lease', 'create the Windows run and the lab run with their identities',
                         'overlays of both machines, the copies of the firmware variables and of the TPM state',
                         'evidence disk of the lab machine (64 MiB, zeroed)',
                         'start the lab machine paused, resume, observe boot',
                         'lab setup: HTTPS target, resolver, capture to the evidence disk',
                         'start the Windows guest paused with its adapter on the lab wire, resume, observe boot',
                         'set the lab addresses in the guest and import the lab CA (up to %d seconds each)'
                         % smoke['script_seconds'],
                         'the guest left alone for %d seconds, so that the set-up is over before the probes'
                         % settle_seconds(smoke),
                         'window `probes`: the 8 probes, one HTTPS request and one lookup of the lab resolver',
                         'window `rest`: the guest left alone for %d seconds' % smoke['rest_seconds'],
                         'finish the capture, shut the guest down (ACPI), close both machines',
                         'read and verify the evidence disk, judge both windows, write the noise report',
                         'check that the image is unchanged', 'summary'],
                limitations=['the image is not qualified (qualified: false): the run is diagnostic and counts for nothing',
                             'a frame outside infrastructure in the window of the probes is a finding, not an exception to add; in the rest it is listed only',
                             'no controller restart recovery; `attach` does not take this suite',
                             'IPv6 is the lab\'s static address; the lab sends no router advertisement',
                             'no automatic file cleanup'],
                dependencies=['the image of stage 9a', 'the lab image of stage 7', 'qemu.qmp 0.0.6', 'KVM',
                              'pinned QEMU 10.0.13 and firmware code', 'swtpm', 'Git (execution only)'],
                security_invariants='UNVERIFIED', release_gate=False)


class Adapters:
    """Lazy execution imports; the tests replace operations, not the run."""

    def __init__(self):
        from .lifecycle import start
        from .qemu import execute, prepare
        self.prepare, self.execute, self.start = prepare, execute, start
        self.pair, self.guest = labmod.LabPair, labmod.Guest


def load(path):
    import tomllib
    with Path(path).open('rb') as stream:
        return validate(tomllib.load(stream))


class GuestAsks:
    """What the controller asks of the Windows guest, each ask recorded as a row of the run's job evidence."""

    def __init__(self, vm, config):
        self.vm, self.seconds = vm, config['smoke']['script_seconds']

    def run(self, operation, script, *, repeat):
        """One PowerShell of the guest. A try that times out is made once more on a new session when it may be."""
        vm = self.vm
        for attempt in (1, 2):
            try:
                text = vm.guest_powershell(script, seconds=self.seconds, limit=guest.SCRIPT_LIMIT)
                break
            except LifecycleError as error:
                if not repeat or attempt == 2 or str(error) not in REPEATABLE_TIMEOUTS:
                    raise
                windows_reboot.record(vm, operation + '-timeout', attempt=attempt, seconds=self.seconds,
                                      reason=str(error))
                vm.recover_guest()
        return text

    def ready(self, operation):
        """The first exchange after a long wait is protected: ping the agent, replace the session when it is silent.

        What was done is a row of the run's job evidence, so that a replacement that was needed is never silent.
        """
        vm = self.vm
        done = vm.ready_guest()
        windows_reboot.record(vm, operation + '-session', **done)
        return done

    def answer(self, operation, parse, *arguments):
        try:
            return parse(*arguments)
        except (guest.windows_guest.GuestAnswerError, guest.CertificateRefused) as error:
            raise LifecycleError(str(error), self.vm) from None


def probe_summary(doc, qualification, https_row, dns_rows, plain):
    """What each probe did, from the guest's account and from what the lab machine says it served."""
    named = dns_name(plain)
    resolver_rows = [row for row in dns_rows if type(row) is dict and row.get('name') == named]
    resolver_logged = (len(resolver_rows) == 1 and (resolver_rows[0].get('source'), resolver_rows[0].get('transport'),
                                                    resolver_rows[0].get('type')) == (CLIENTS[4], 'udp', 'A'))
    https = dict(doc['https'], logged=https_row is not None)
    resolver = dict(doc['resolver'], logged=resolver_logged, rows=len(resolver_rows))
    rows = [dict(family=p['family'], service=p['service'], answered=p['answered'], error=p['error'])
            for p in doc['probes']]
    # A probe that got no right answer is a finding. That the lab cannot confirm what the guest says (it did not log
    # the request, its own qualification failed) is not a finding but a run that cannot vouch for itself.
    findings = ['probe-failed:%s:%s' % (row['family'], row['service']) for row in rows if not row['answered']]
    findings += ['probe-failed:https'] * (not https['answered']) + ['probe-failed:resolver'] * (not resolver['answered'])
    unverified = ['lab-qualify-failed'] * (qualification.get('qualified') is not True)
    unverified += ['probe-not-logged-by-the-lab:https'] * (not https['logged'])
    unverified += ['probe-not-logged-by-the-lab:resolver'] * (not resolver['logged'])
    unverified += ['probes-not-eight'] * (len(rows) != 8)
    return dict(passed=not findings and not unverified, findings=findings, unverified=unverified, probes=rows,
                lab_qualification=qualification, https=https, resolver=resolver)


def https_log_row(log, exchange, port):
    """The one row in which the HTTPS target says it served this exchange to the test machine from this port."""
    rows = [row for row in log if type(row) is dict and row.get('path') == exchange['path']]
    ok = len(rows) == 1 and rows[0].get('source') == exchange['source'] and rows[0].get('port') == port
    return rows[0] if ok else None


def window_rows(verdict):
    """The part of each window's verdict the summary keeps: no frames, only what was counted and why."""
    keep = ('index', 'label', 'in_group', 'leak', 'leak_reason', 'observer_reasons', 'categories', 'unexpected', 'flows',
            'direct', 'clock')
    return [{key: row[key] for key in keep if key in row} for row in verdict['windows']]


def judge(lab_id, seen, expected, plain, direct, port):
    """The windows of the capture, the noise report and the lab's side of the probes. Nothing here changes a verdict."""
    health = json.loads(seen['logs']['health.json'])
    capture = seen['logs']['capture.pcap']
    log = json.loads(seen['logs']['https.json'])
    https = dict(direct=direct, client_port=port, log=log)
    seen['verdict'] = classify_windows(capture, lab_id, None, health=health, ready=True, limit=EVIDENCE_PCAP_LIMIT,
                                       required_labels=LABELS, flows=True, probes=[*expected, plain], https=https)
    seen['noise'] = windows_noise.report(capture, lab_id, probes=[*expected, plain], https=https,
                                         limit=EVIDENCE_PCAP_LIMIT)
    seen['health'] = health
    seen['https_row'] = https_log_row(log, direct, port)
    seen['dns_rows'] = json.loads(seen['logs']['dns.json'])
    seen['qualification'] = qualification_of(expected, seen, health, capture)


def qualification_of(expected, seen, health, capture):
    """The lab machine's own judgement of the eight probes (`qualify`), or why it could not be made."""
    replies = seen.get('replies')
    try:
        return qualify(expected, replies if type(replies) is list else [], json.loads(seen['logs']['targets.json']),
                       capture, True, health, limit=EVIDENCE_PCAP_LIMIT)
    except (ValueError, KeyError, TypeError) as error:
        return dict(ipv4='UNVERIFIED', ipv6='UNVERIFIED', services='UNVERIFIED', observer='UNVERIFIED',
                    evidence='UNVERIFIED', qualified=False, reason='qualify-failed:' + str(error)[:48])


def run_windows_lab_smoke(config, *, adapters=None, clock=time.monotonic, sleep=time.sleep, progress=None):
    """One run of the suite; see the module's own text."""
    if config.get('suite') != SUITE:
        raise ValueError('configuration is for another suite')
    progress = progress or (lambda stage: print(stage, file=sys.stderr, flush=True))
    result = dict(schema=SUMMARY_SCHEMA, suite=SUITE, mode='lab', identities={}, configuration=config, stages=[],
                  evidence=[], lab=None, execution=None, completion=dict.fromkeys(ROLES, False), completed=False,
                  manual_recovery_required=False, errors=[], attached=False, qualified=False, diagnostic=True,
                  security_invariants='UNVERIFIED', release_gate=False, exit_code=2)
    smoke, lab_config = config['smoke'], config['lab']
    lease = pair = image = plan = lab_id = None
    runs, vms, closed, states = {}, {}, set(), {}
    stage, interrupted, started = 'preflight', False, clock()
    # What the finally block summarizes: kept as it arrives, so that a late failure loses nothing.
    seen = dict(logs={}, hashes={}, verdict=None, noise=None, qualification=None, replies=None, health=None,
                evidence_disk=dict(verified=False, reason='not-read', pcap_bytes=0, pcap_sha256=None))
    measured = dict(network=None, certificate=None, settle=None, probes=None, rest=None, shutdown=None,
                    image_unchanged=None, host_memory_mib=None)

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
        direct = exchanges[0]
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
                                                           dns=True))
        if clock() >= deadline:
            raise TimeoutError('preparation deadline')
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
        vm = vms['test'] = step('start-test', lambda: adapters.start(runs['test'], lab=pair))
        step('resume-test', vm.resume)
        step('boot-test', lambda: vm.wait_initial_guest(timeout=smoke['agent_wait_seconds'], clock=clock, sleep=sleep,
                                                       try_seconds=windows_reboot.TRY_SECONDS))
        # Both machines are up: QEMU owns the two ends of the wire, the controller drops its copies.
        step('wire-close', pair.close)
        identities.update(boot_id=vm.last_boot_id, vm_uuid=vm.vm_uuid)
        states['test'].update('identities', boot_id=vm.last_boot_id, vm_uuid=vm.vm_uuid)
        asks = GuestAsks(vm, config)

        def network():
            text = asks.run('guest-network', guest.network_script(), repeat=True)
            value = asks.answer('guest-network', guest.network, text)
            problems = guest.network_problems(value)
            measured['network'] = dict(adapter=value['alias'], addresses=value['addresses'], routes=value['routes'],
                                       dns=value['dns'], dhcp4=value['dhcp4'], status=value['status'],
                                       problems=problems)
            windows_reboot.record(vm, 'guest-network', network=measured['network'], stderr=vm.qga.stderr_text or '')
            if problems:
                raise ValueError('windows-network-not-as-the-lab-says')

        def certificate():
            der = read_certificate(config)
            text = asks.run('guest-ca', guest.ca_script(der), repeat=True)
            measured['certificate'] = asks.answer('guest-ca', guest.certificate, text, der)
            windows_reboot.record(vm, 'guest-ca', certificate=measured['certificate'], stderr=vm.qga.stderr_text or '')

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

        def settle():
            measured['settle'] = dict(waited_seconds=alone(settle_seconds(smoke)))
            # The first exchange after the wait is the probes' opening marker, which must not be sent twice.
            asks.ready('guest-settle')

        step('network', network)
        step('certificate', certificate)
        step('settle', settle)

        def probe():
            opening, closing = windows[0]
            text = asks.run('guest-probes', guest.probe_script(lab_id, expected, direct, plain, opening, closing),
                            repeat=False)
            doc = asks.answer('guest-probes', guest.probes_answer, text, expected, direct, plain)
            doc['marker_rows'] = [asks.answer('guest-probes', guest.marker, json.dumps(row), wanted)
                                  for row, wanted in zip(doc['markers'], (opening, closing))]
            seen['replies'] = [{key: value for key, value in row.items() if key not in ('answered', 'error')}
                               for row in doc['probes'] if row['answered']]
            seen['guest_doc'] = doc
            windows_reboot.record(vm, 'guest-probes', probes=[dict(family=r['family'], service=r['service'],
                                  answered=r['answered'], error=r['error']) for r in doc['probes']],
                                  https=doc['https'], resolver=doc['resolver'], markers=doc['marker_rows'],
                                  stderr=vm.qga.stderr_text or '')

        try:
            step('probes', probe)
        except Exception as error:
            # What the guest says is not what stops the run: the capture still holds what it did, and the window of
            # rest is the point of the run. The failure stays in the errors and decides the exit code.
            if not isinstance(error, LifecycleError) or vm.process.poll() is not None or vm.evidence_failed:
                raise
            result['errors'].append(failure(stage, error))
            if not vm.qga.valid:
                step('probes-recovery', vm.recover_guest)

        def rest():
            opening, closing = windows[1]
            text = asks.run('guest-rest-open', guest.marker_script(opening), repeat=False)
            seen['rest_markers'] = [asks.answer('guest-rest-open', guest.marker, text, opening)]
            measured['rest'] = dict(waited_seconds=alone(smoke['rest_seconds']))
            # After ten minutes of silence the agent may have gone away: say so before the closing marker, not by it.
            asks.ready('guest-rest')
            text = asks.run('guest-rest-close', guest.marker_script(closing), repeat=False)
            seen['rest_markers'].append(asks.answer('guest-rest-close', guest.marker, text, closing))

        step('rest', rest)
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
            vm.request_shutdown(wait=smoke['shutdown_wait_seconds'])
            measured['shutdown'] = SHUTDOWN_NOTE

        # The guest goes down by its own power button; both machines stop, and only then is the lab's disk read.
        step('shutdown-test', shutdown)
        step('close-test', lambda: close_machine('test', False))
        step('close-lab', lambda: close_machine('lab', False))
        lab_run = runs['lab']
        if not completion_verified(lab_run.directory, lab_run._read()):
            raise ValueError('lab-completion-unconfirmed')
        step('evidence-read', lambda: read_disk(lab_run, lab_id, seen))
        step('windows', lambda: judge(lab_id, seen, expected, plain, direct,
                                      (seen.get('guest_doc') or {}).get('https', {}).get('client_port')))
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
        finish(result, config, lease, pair, runs, vms, closed, seen, measured, interrupted, states, started, clock,
               plan=plan, image=image, lab_id=lab_id)
    return result


def finish(result, config, lease, pair, runs, vms, closed, seen, measured, interrupted, states, started, clock, *,
           plan, image, lab_id):
    """Close what is still open, then write the summary into both runs; never raises."""
    for role in ROLES:
        if role in vms and role not in closed:
            closed.add(role)
            try:
                vms[role].close(hard=bool(result['errors']))
            except BaseException as error:
                interrupted |= isinstance(error, KeyboardInterrupt)
                result['errors'].append(failure('close-' + role, error))
    if pair is not None:
        try:
            pair.close()
        except BaseException as error:
            result['errors'].append(failure('channel-close', error))
            for run in runs.values():
                try:
                    run.mark('quarantined', 'lab-channel-close-unconfirmed')
                except (OSError, ValueError):
                    result['errors'].append(dict(stage='quarantine', reason='ledger-write-failed'))
    for role, run in runs.items():
        try:
            result['completion'][role] = bool(completion_verified(run.directory, run._read()))
        except (OSError, ValueError):
            result['completion'][role] = False
    result['completed'] = (set(runs) == set(ROLES) and all(result['completion'].values())
                           and (pair is None or pair.closed))
    for role, state in states.items():
        finish_state(state, result['completion'].get(role, False), result)
    result['manual_recovery_required'] = bool(runs) and not result['completed']
    try:
        result['lab'] = lab_section(lab_id, seen)
        result['execution'] = execution_section(result, config, seen, measured, vms, plan, image, started, clock)
    except BaseException as error:
        result['errors'].append(failure('summary', error))
    result['exit_code'] = exit_code(result, interrupted)
    payload = json.dumps(result)
    for run in runs.values():
        if run._identity[2] in payload:
            result.update(json.loads(payload.replace(run._identity[2], '[redacted-owner-token]')))
            result['errors'].append(dict(stage='summary', kind='RedactionError', reason='owner-token-redacted'))
            result['exit_code'] = 130 if interrupted else 2
            break
    for role, run in runs.items():
        try:
            for entry in run._read()['resources']:
                if entry['kind'] != 'file' or entry['path'] == 'execution-summary.json':
                    continue
                path = Path(run.directory) / entry['path']
                if path.is_file():
                    digest = hashlib.sha256()
                    with path.open('rb') as stream:
                        for block in iter(lambda: stream.read(1024 * 1024), b''):
                            digest.update(block)
                    result['evidence'].append(dict(role=role, path=entry['path'], sha256=digest.hexdigest()))
        except BaseException as error:
            result['errors'].append(failure('summary-' + role, error))
            result['exit_code'] = 130 if interrupted else 2
    for run in runs.values():
        try:
            save(run, 'execution-summary.json', result)
        except BaseException as error:
            result['errors'].append(failure('summary', error))
            result['exit_code'] = 130 if interrupted else 2
    if lease is not None and lease._active:
        _RETAINED_LEASES.append(lease)
    if lease is not None and lease._stream is not None and not lease._active:
        try:
            lease.release()
        except Exception as error:
            result['errors'].append(failure('lease-release', error))
            result['exit_code'] = 130 if interrupted else 2


def exit_code(result, interrupted):
    """The code of the matrix: 130 when interrupted; 1 for a finding, which stands whatever else went wrong; 2 when
    the run cannot vouch for itself (an error, a machine that did not finish, a window or the lab's own account that
    is unverified); 0 when it can and nothing was found."""
    section = result['execution']
    if interrupted:
        return 130
    if type(section) is dict and section.get('findings'):
        return 1
    if result['errors'] or not result['completed'] or type(section) is not dict or not section.get('accepted'):
        return 2
    return 0


def lab_section(lab_id, seen):
    """The observer's side: the evidence disk, each window as judged, and the hashes of what the lab machine kept."""
    verdict = seen['verdict']
    return dict(lab_id=lab_id, evidence=seen['evidence_disk'], observer=dict(
        ready=verdict is not None, reasons=verdict['observer_reasons'] if verdict else ['not-evaluated']),
        windows=window_rows(verdict) if verdict else [], outside_window=verdict['outside_window'] if verdict else None,
        missing_labels=verdict.get('missing_labels') if verdict else None,
        extra_windows=verdict['extra_windows'] if verdict else None, artifacts_sha256=seen['hashes'])


def judgement(result, measured, probes, windows, rest_observed, markers_ok, noise):
    """What the run found (exit 1) and what it cannot vouch for (exit 2), as two lists of codes.

    A finding is something the guest did or failed to do on the wire: a probe that did not get the lab's answer, a
    foreign frame in the window of the probes. Everything that leaves the run unable to say so is unverified: an error,
    a machine that did not finish, a window that was not observed whole (`UNVERIFIED` or reasons of the observer),
    the lab's own `qualify` that failed, a probe the lab did not log, a rest that was not observed. The window of the
    rest is only listed: what it holds is no finding, but it must have been observed.
    """
    findings = list(probes['findings']) if probes is not None else []
    unverified = ['error:' + row['stage'] for row in result['errors']]
    unverified += ['not-completed'] * (not result['completed'])
    unverified += ['shutdown-not-by-the-power-button'] * (measured['shutdown'] != SHUTDOWN_NOTE)
    unverified += ['image-not-confirmed-unchanged'] * (measured['image_unchanged'] is not True)
    unverified += ['network-not-the-labs'] * (measured['network'] is None or bool(measured['network']['problems']))
    unverified += ['certificate-not-confirmed'] * (measured['certificate'] is None)
    if probes is None:
        unverified.append('probes-not-answered')
    else:
        unverified += probes['unverified']
    unverified += ['markers-not-acknowledged'] * (not markers_ok)
    first = windows.get(PROBES_LABEL)
    if first is None:
        unverified.append('window-missing:' + PROBES_LABEL)
    elif first['leak'] == 'DETECTED' and probes is not None:
        findings.append('window-detected:' + PROBES_LABEL)
    for label in LABELS:
        row = windows.get(label)
        if row is not None and (row['leak'] == 'UNVERIFIED' or row['observer_reasons']):
            unverified.append('window-unverified:' + label)
    unverified += ['window-not-observed:' + REST_LABEL] * (not rest_observed)
    unverified += ['noise-unverified'] * (noise is None or noise['noise'] == 'UNVERIFIED')
    return findings, list(dict.fromkeys(unverified))


def execution_section(result, config, seen, measured, vms, plan, image, started, clock):
    """What the run found, in one place: the network, the probes, the windows and the noise of the guest at rest."""
    verdict, noise, doc = seen['verdict'], seen['noise'], seen.get('guest_doc')
    windows = {row['label']: row for row in window_rows(verdict)} if verdict else {}
    probes = (probe_summary(doc, seen['qualification'], seen.get('https_row'), seen.get('dns_rows') or [], seen['plain'])
              if doc is not None and seen.get('qualification') is not None else None)
    # What the guest does at rest is listed, not judged: the window must have been observed whole, whatever it holds.
    rest = windows.get(REST_LABEL, {})
    rest_observed = rest.get('leak') in ('NONE', 'DETECTED') and not rest.get('observer_reasons', ['missing'])
    markers_ok = bool(doc) and all(row['sent'] and row['acknowledged'] for row in doc['marker_rows']) and all(
        row['sent'] and row['acknowledged'] for row in seen.get('rest_markers', [])) and len(
        seen.get('rest_markers', [])) == 2
    findings, unverified = judgement(result, measured, probes, windows, rest_observed, markers_ok, noise)
    return dict(accepted=not findings and not unverified, findings=findings, unverified=unverified, uuid=next((vm.vm_uuid for role, vm in vms.items() if role == 'test'), None),
                kvm_qualified=plan['kvm_qualified'] if plan else False,
                image=dict(identifier=image.identifier, sha256=image.sha256, qualified=False) if image else None,
                duration_seconds=round(clock() - started, 1), capture_seconds=capture_seconds(config),
                network=measured['network'], certificate=measured['certificate'], probes=probes,
                markers=dict(probes=doc['marker_rows'] if doc else None, rest=seen.get('rest_markers')),
                settle=measured['settle'], rest=measured['rest'], shutdown=measured['shutdown'],
                image_unchanged=measured['image_unchanged'],
                host_memory_mib=measured['host_memory_mib'],
                windows={label: dict(leak=row['leak'], reason=row['leak_reason'], reasons=row['observer_reasons'],
                                     categories=row['categories']) for label, row in windows.items()},
                noise=noise['noise'] if noise else None, noise_report=noise,
                noise_table=windows_noise.table(noise) if noise and noise.get('groups') is not None else None)

