"""One two-VM isolated lab. No assessment profile or L3 execution."""
import base64
import hashlib
from dataclasses import fields
import json
import os
import re
from pathlib import Path
import secrets
import socket
import time
import tomllib
import uuid

from . import l3_requests
from .evidence import ReadbackError, write_file
from .execution import exact
from .images import ImageDescriptor
from .qemu import QemuConfig, prepare, execute
from .lifecycle import start, _host
from .resources import (StandLease, create_run, completion_verified, resource_path,
                        EXECUTION_FILES, _identifier, _state_path)
from .orchestrator import save, failure, _RETAINED_LEASES
from .lab_protocol import (MACS, CAPTURE_LIMIT, LOG_LIMIT, PORTS, CANARY_PORT, HTTPS_PORT, SOCKS_PORT, EGRESS,
                           probes, markers, qualify, leak_verdict, https_exchanges, https_answer,
                           DURATION, DURATION_MAX, EVIDENCE_SIZE, EVIDENCE_PCAP_LIMIT, EVIDENCE_HEADER_SIZE,
                           EVIDENCE_SERIAL, parse_evidence_header)

ENTRY = '/usr/local/libexec/rosetun-lab/entry'
SCHEMA_V1, SCHEMA_V2 = 'rosetun.matrix.lab.v1', 'rosetun.matrix.lab.v2'
ARTIFACTS = {'lab-capture': 'capture.pcap', 'lab-targets': 'targets.json', 'lab-health': 'health.json'}
# Only a tunnel run reads these two; they are registered with the lab run only then.
TUNNEL_ARTIFACTS = {'lab-https': 'https.json', 'lab-node': 'node.log'}
# Only a run with an evidence disk registers the image; the capture is then read from it.
EVIDENCE_IMAGE = 'evidence.img'
EVIDENCE_RESOURCES = {'lab-evidence-disk': EVIDENCE_IMAGE}
# The guest facade lives this long beyond the capture it waits for: setup, finish and the reads.
GUEST_LIFETIME = 90


def controls(run):
    return {name: dict(kind='inherited-unix-stream', run_id=run._identity[0], purpose='management')
            for name in ('qmp', 'qga')}


def load_lab(path):
    with Path(path).open('rb') as stream:
        config = tomllib.load(stream)
    return validate(config)


def validate_tunnel(block):
    """The pinned fixtures of stage 7b1: one engine binary in both images, the CA, the node port."""
    exact(block, ('sing_box_sha256', 'ca_sha256', 'node_port'))
    for name in ('sing_box_sha256', 'ca_sha256'):
        if type(block[name]) is not str or not re.fullmatch('[0-9a-f]{64}', block[name]):
            raise ValueError('lab-tunnel-hash')
    port = block['node_port']
    if (type(port) is not int or not 1 <= port <= 65535
            or port in (*PORTS.values(), CANARY_PORT, HTTPS_PORT, SOCKS_PORT)):
        raise ValueError('lab-tunnel-port')


def validate(config):
    base = ('schema', 'state_directory', 'stand_id', 'qemu', 'test_image', 'lab_image')
    # Version 1 reads exactly as before; version 2 only adds the tunnel block.
    exact(config, base + (('tunnel',) if type(config) is dict and config.get('schema') == SCHEMA_V2 else ()))
    if config['schema'] not in (SCHEMA_V1, SCHEMA_V2):
        raise ValueError('unsupported-lab-schema')
    if config['schema'] == SCHEMA_V2:
        validate_tunnel(config['tunnel'])
    _state_path(config['state_directory'])
    _identifier(config['stand_id'])
    exact(config['qemu'], [f.name for f in fields(QemuConfig)])
    if config['qemu']['machine'] != 'pc-i440fx-10.0' or config['qemu']['qga'] is not True:
        raise ValueError('lab-requires-pinned-machine-and-qga')
    for role in MACS:
        exact(config[role + '_image'], [f.name for f in fields(ImageDescriptor)])
    return config


def plan_lab(config, *, tunnel=False, evidence_disk=False):
    """Read only: no lease, directories, subprocesses or sockets."""
    validate(config)
    if tunnel and config['schema'] != SCHEMA_V2:
        raise ValueError('lab-tunnel-requires-v2')
    state = _state_path(config['state_directory'])
    QemuConfig(**config['qemu']).validate()
    for role in MACS:
        ImageDescriptor(**config[role + '_image']).validate(state)
    plan = dict(schema='rosetun.matrix.lab-plan.v1', dry_run=True, configuration=config,
                topology='test -> inherited AF_UNIX stream pair -> lab -> guest namespace',
                roles=MACS, capture_limit=CAPTURE_LIMIT, duration_seconds=60,
                qualification='UNRUN', security_invariants='UNVERIFIED', release_gate=False)
    if evidence_disk:
        plan['evidence_disk'] = dict(size_bytes=EVIDENCE_SIZE, pcap_limit_bytes=EVIDENCE_PCAP_LIMIT,
                                     serial=EVIDENCE_SERIAL, role='lab')
    return plan


class LabPair:
    """Capability for two particular runs under their original lease."""
    def __init__(self, lease, runs, lab_id, *, pair_factory=socket.socketpair, tunnel=False, evidence_disk=False):
        lease._check_live()
        if set(runs) != set(MACS) or lease._active or runs['test'] is runs['lab']:
            raise ValueError('invalid-lab-members')
        for run in runs.values():
            if run._lease is not lease or run._read()['state'] != 'prepared':
                raise ValueError('foreign-lab-member')
        self.lease, self.runs, self.lab_id = lease, dict(runs), _identifier(lab_id)
        self.tunnel = tunnel is True
        self.evidence_disk = evidence_disk is True
        self.sockets = {}
        self.used = set()
        self.closed = False
        for role, run in runs.items():
            linkage = json.loads(resource_path(run.directory, 'execution-identity.json').read_bytes())
            if (linkage.get('lab_id') != lab_id or linkage.get('role') != role
                    or linkage.get('members') != {r: runs[r]._identity[0] for r in MACS}
                    or linkage.get('controls') != controls(run)
                    or linkage.get('endpoint') != dict(kind='inherited-unix-stream', role=role, mac=MACS[role])):
                raise ValueError('lab-linkage-mismatch')
            for identifier, name in self.resources(run).items():
                run.register(dict(id=identifier, kind='file', path=name))
                resource_path(run.directory, name).touch(exist_ok=False)
                if name == EVIDENCE_IMAGE:
                    # Fixed and zeroed: a sparse file, so the helper can never grow or shrink it.
                    with resource_path(run.directory, name).open('r+b') as image:
                        image.truncate(EVIDENCE_SIZE)
        # Both endpoint records already exist in the execution identity ledgers.
        a, b = pair_factory(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sockets = dict(test=a, lab=b)

    def role(self, run):
        roles = [role for role, member in self.runs.items() if member is run]
        if len(roles) != 1:
            raise ValueError('foreign-lab-run')
        return roles[0]

    def resources(self, run):
        if self.role(run) != 'lab':
            return {}
        files = {**ARTIFACTS, **TUNNEL_ARTIFACTS} if self.tunnel else ARTIFACTS
        # Unbound calls with a stand-in object exist in older tests, which know no disk.
        return {**files, **EVIDENCE_RESOURCES} if getattr(self, 'evidence_disk', False) else files

    def check_start(self, run):
        self.lease._check_live()
        role = self.role(run)
        if self.closed or role in self.used or run._lease is not self.lease:
            raise ValueError('lab-launch-ownership-mismatch')
        if any(not any(vm.run is member for member in self.runs.values()) or vm.run is run
               for vm in self.lease._active):
            raise ValueError('foreign-active-vm')
        if len(self.lease._active) >= 2:
            raise ValueError('lab-capacity')

    def network(self, run):
        self.lease._check_live()
        role = self.role(run)
        if self.closed or role in self.used:
            raise ValueError('lab-endpoint-already-consumed')
        self.used.add(role)
        fd = self.sockets[role].fileno()
        argv = ['-netdev', f'stream,id=labwire,addr.type=fd,addr.str={fd},server=off',
                '-device', f'virtio-net-pci,netdev=labwire,id={role}-wire,mac={MACS[role]}']
        if self.evidence_disk and role == 'lab':
            # A second, writable raw disk that only the lab machine has.
            image = resource_path(run.directory, EVIDENCE_IMAGE)
            argv += ['-blockdev', json.dumps({'driver': 'raw', 'node-name': 'evidence', 'read-only': False,
                                              'file': {'driver': 'file', 'filename': str(image)}}, sort_keys=True),
                     '-device', 'virtio-blk-pci,drive=evidence,id=evidence,serial=' + EVIDENCE_SERIAL]
        return argv, fd

    def close(self):
        self.closed = False
        errors = []
        for endpoint in self.sockets.values():
            try:
                endpoint.close()
                if endpoint.fileno() != -1:
                    raise ValueError('endpoint-close-unconfirmed')
            except (OSError, ValueError) as error:
                errors.append(error)
        if errors:
            raise ValueError('lab-channel-close-unconfirmed')
        self.closed = True


def refusal(status):
    """'lab-helper-failed', plus the helper's own fixed reason when it printed one."""
    try:
        text = base64.b64decode(status.get('err-data', ''), validate=True).decode('ascii')
    except (ValueError, UnicodeDecodeError):
        return 'lab-helper-failed'
    match = re.fullmatch(r'lab-helper-failed:([a-z0-9-]{1,64})\s*', text)
    return 'lab-helper-failed-' + match[1] if match else 'lab-helper-failed'


class Guest:
    """Fixed installed entry point, serialized QGA, no shell or arbitrary paths."""
    def __init__(self, vm, role, lab_id, *, clock=time.monotonic, sleep=time.sleep, lifetime=GUEST_LIFETIME):
        self.vm, self.role, self.lab_id = vm, role, lab_id
        self.clock, self.sleep = clock, sleep
        # The capture itself runs in a helper process of its own and ends with `finish` or at
        # its own deadline; this only bounds how long the controller may keep talking to the guest.
        self.deadline = clock() + lifetime

    def rpc(self, name, args):
        self.vm._check()
        if self.clock() >= self.deadline or self.vm.reset_pending:
            raise ValueError('lab-guest-deadline-or-reset')
        self.vm.qga.deadline = time.monotonic() + min(5, self.deadline - self.clock())
        return self.vm.qga._rpc(name, 5, args)

    def call(self, operation, expected, window=(), canary=False, tunnel=None, options=None):
        if operation not in ({'setup', 'finish'} if self.role == 'lab' else {'probe'}):
            raise ValueError('invalid-lab-operation')
        with self.vm._guest_lock:
            self.vm.qga.deadline = time.monotonic() + 10
            if self.vm.qga.read_boot_id(5) != self.vm.last_boot_id:
                raise ValueError('lab-boot-changed')
            request = dict(operation=operation, role=self.role, lab_id=self.lab_id,
                           vm_uuid=self.vm.vm_uuid, boot_id=self.vm.last_boot_id, probes=expected,
                           markers=list(window), canary=canary is True)
            if tunnel is not None:
                request['tunnel'] = tunnel
            if options:
                if not set(options) <= {'evidence_disk', 'duration_seconds'}:
                    raise ValueError('invalid-lab-option')
                request.update(options)
            self.vm.qga.jobs_enabled = True
            self.vm.qga.probe(5)
            response = self.rpc('guest-exec', {'path': ENTRY, 'arg': [json.dumps(request)], 'capture-output': True})
            if type(response) is not dict or set(response) != {'pid'} or type(response['pid']) is not int:
                raise ValueError('invalid-lab-exec')
            for _ in range(40):
                status = self.rpc('guest-exec-status', response)
                if status.get('exited') is True:
                    if status.get('exitcode') != 0 or status.get('out-truncated') or status.get('err-truncated'):
                        raise ValueError(refusal(status))
                    raw = base64.b64decode(status.get('out-data', ''), validate=True)
                    if len(raw) > LOG_LIMIT:
                        raise ValueError('lab-helper-output-limit')
                    result = json.loads(raw)
                    if result.get('lab_id') != self.lab_id or result.get('boot_id') != self.vm.last_boot_id:
                        raise ValueError('lab-helper-identity-mismatch')
                    return result
                self.sleep(0.5)
            raise ValueError('lab-helper-timeout')

    def read(self, name, limit):
        if name not in (*ARTIFACTS.values(), *TUNNEL_ARTIFACTS.values()):
            raise ValueError('invalid-lab-artifact')
        with self.vm._guest_lock:
            handle = self.rpc('guest-file-open', {'path': '/run/rosetun-lab/' + self.lab_id + '/' + name, 'mode': 'r'})
            if type(handle) is not int:
                raise ValueError('invalid-lab-file-handle')
            data = bytearray()
            try:
                for _ in range(limit // 16384 + 2):
                    row = self.rpc('guest-file-read', {'handle': handle, 'count': 16384})
                    block = base64.b64decode(row['buf-b64'], validate=True)
                    if len(block) != row['count'] or len(data) + len(block) > limit:
                        raise ValueError('lab-artifact-size-limit')
                    data.extend(block)
                    if row.get('eof') is True:
                        return bytes(data)
                    if not block:
                        break
                raise ValueError('incomplete-lab-artifact')
            finally:
                if self.vm.qga.valid:
                    if self.rpc('guest-file-close', {'handle': handle}) != {}:
                        raise ValueError('lab-artifact-close-unconfirmed')


class Adapters:
    host = staticmethod(_host)
    prepare = staticmethod(prepare)
    start = staticmethod(start)
    execute = staticmethod(execute)
    pair = LabPair
    guest = Guest


def read_evidence(image, lab_id):
    """The pcap of a finished run from its evidence image, or a ValueError naming the defect.

    Everything is checked before a byte of the pcap is used: the header (magic, version,
    run ID, completion flag), the size of the image, the length and SHA-256 of the pcap,
    and that nothing but zeros follows it.
    """
    with image.open('rb') as stream:
        size = os.fstat(stream.fileno()).st_size
        length, digest = parse_evidence_header(stream.read(EVIDENCE_HEADER_SIZE), lab_id)
        if size < EVIDENCE_HEADER_SIZE + length:
            raise ValueError('evidence-truncated')
        if size != EVIDENCE_SIZE:
            raise ValueError('evidence-size')
        pcap = stream.read(length)
        if hashlib.sha256(pcap).digest() != digest:
            raise ValueError('evidence-sha256')
        while block := stream.read(1024 * 1024):
            if block.count(0) != len(block):
                raise ValueError('evidence-trailing-bytes')
    return pcap


def expected_leak(result):
    """An ordinary run must see no leak; a canary run must see exactly its own two flows.

    The canary also needs the proven window an ordinary run needs for NONE: a seen leak
    outside a bracketed, healthy capture proves nothing about the observer.
    """
    if result['canary']:
        window = result['window']
        return (result['leak'] == 'DETECTED' and result['canary_flows'] == ['tcp', 'udp']
                and result['canary_other'] == 0 and window['markers_found'] is True
                and window['ordered'] is True and result['observer_reasons'] == [])
    return result['leak'] == 'NONE'


def tunnel_request(config, exchanges):
    """The block sent to both helpers. Method and password come from the one public template."""
    shadowsocks = l3_requests.template()['node']['outbound']['shadowsocks']
    block = config['tunnel']
    return dict(port=block['node_port'], method=shadowsocks['method'], password=shadowsocks['password'],
                sing_box_sha256=block['sing_box_sha256'], ca_sha256=block['ca_sha256'], https=exchanges)


def tunnel_summary(exchanges, reports, log, health, categories):
    """What the tunnel run proved, from the helper's answers and the target's own log."""
    direct, via_node = exchanges
    reports = reports if type(reports) is dict else {}

    def report(kind, exchange):
        row = reports.get(kind)
        return row if (type(row) is dict and row.get('path') == exchange['path']
                       and row.get('response') == https_answer(exchange).hex()) else None

    def rows(exchange):
        return [row for row in log if type(row) is dict and row.get('path') == exchange['path']]

    sent, relayed = report('direct', direct), report('tunnel', via_node)
    direct_rows, relayed_rows = rows(direct), rows(via_node)
    node = health.get('node') if type(health) is dict and type(health.get('node')) is dict else {}
    code = node.get('exit_code')
    client = reports.get('client_exit')
    return dict(
        direct=(sent is not None and type(sent.get('client_port')) is int and len(direct_rows) == 1
                and direct_rows[0].get('source') == direct['source']
                and direct_rows[0].get('port') == sent['client_port']),
        via_node=relayed is not None and len(relayed_rows) == 1 and relayed_rows[0].get('source') == EGRESS,
        tunnel_frames=categories.get('tunnel', 0),
        node=dict(alive_at_finish=node.get('alive_at_finish') is True,
                  exit_code=code if type(code) is int else None),
        client_exit=client if type(client) is int else None)


def tunnel_ok(result):
    """Everything a tunnel run needs beyond the ordinary or canary condition."""
    block = result.get('tunnel')
    return (block is None or (block['direct'] is True and block['via_node'] is True
                              and block['tunnel_frames'] > 0 and block['node']['alive_at_finish'] is True))


def lab_smoke(config, *, canary=False, tunnel=False, evidence_disk=False, duration_seconds=None,
              adapters=None, clock=time.monotonic, sleep=time.sleep):
    plan_lab(config, tunnel=tunnel)
    if duration_seconds is not None and (type(duration_seconds) is not int
                                         or not DURATION <= duration_seconds <= DURATION_MAX):
        raise ValueError('lab-duration-out-of-range')
    adapters = adapters or Adapters()
    lab_id = uuid.uuid4().hex
    expected = probes(lab_id, lambda: secrets.token_hex(12))
    window = markers(lab_id, lambda: secrets.token_hex(12))
    exchanges = https_exchanges(lab_id, lambda: secrets.token_hex(12)) if tunnel else []
    extra = dict(tunnel=tunnel_request(config, exchanges)) if tunnel else {}
    request_options = {**({'evidence_disk': True} if evidence_disk else {}),
               **({'duration_seconds': duration_seconds} if duration_seconds is not None else {})}
    if request_options:
        extra['options'] = request_options
    result = dict(schema='rosetun.matrix.lab-summary.v1', lab_id=lab_id, readiness={},
                  artifact_directories={}, configuration=config,
                  qualification=dict(qualified=False, ipv4='UNVERIFIED', ipv6='UNVERIFIED',
                                     services='UNVERIFIED', observer='UNVERIFIED', evidence='UNVERIFIED'),
                  probes=expected, markers=window, completion={}, channel_closed=False, completed=False,
                  leak='UNVERIFIED', leak_reason='not-evaluated', observer_reasons=['not-evaluated'], categories={}, unexpected=[], canary_flows=[], canary_other=0,
                  window=dict(markers_found=False, ordered=False), canary=canary is True,
                  errors=[], security_invariants='UNVERIFIED', release_gate=False, exit_code=2)
    if evidence_disk:
        result['evidence_disk'] = dict(verified=False, reason='not-read', pcap_bytes=0, pcap_sha256=None)
    if tunnel:
        # Stage 6a and 6b summaries gain nothing; only a tunnel run carries these.
        result.update(https=exchanges, tunnel=dict(direct=False, via_node=False, tunnel_frames=0,
                      node=dict(alive_at_finish=False, exit_code=None), client_exit=None))
    lease, pair, runs, vms = None, None, {}, {}
    try:
        adapters.host()
        for binary in ('executable', 'image_executable'):
            version = adapters.execute([config['qemu'][binary], '--version'], timeout=5, output_limit=4096)
            if version.returncode != 0 or not re.search(rb'\bversion 10\.0\.13(?:\s|$)', version.stdout.split(b'\n')[0]):
                raise ValueError('lab-requires-qemu-10-0-13')
        lease = StandLease(config['state_directory'], config['stand_id']).acquire()
        for role in MACS:
            run = create_run(lease, lab_id + '-' + role)
            runs[role] = run
            result['artifact_directories'][role] = str(run.directory)
            for identifier, name in EXECUTION_FILES.items():
                run.register(dict(id=identifier, kind='file', path=name))
            save(run, 'execution-identity.json', dict(lab_id=lab_id, role=role,
                 members={r: lab_id + '-' + r for r in MACS}, controls=controls(run),
                 endpoint=dict(kind='inherited-unix-stream', role=role, mac=MACS[role])), initial=True)
            save(run, 'execution-summary.json', result, initial=True)
            adapters.prepare(run, ImageDescriptor(**config[role + '_image']), QemuConfig(**config['qemu']))
        pair = adapters.pair(lease, runs, lab_id, **({'tunnel': True} if tunnel else {}),
                             **({'evidence_disk': True} if evidence_disk else {}))
        for role in MACS:
            vm = adapters.start(runs[role], lab=pair)
            vms[role] = vm
            vm.resume()
            observed = vm.wait_initial_guest(timeout=120, clock=clock, sleep=sleep)
            result['readiness'][role] = dict(vm_uuid=vm.vm_uuid, boot_id=vm.last_boot_id,
                                             vm=True, qga=observed['result'] == 'observed')
        # Drop controller duplicates before probes; QEMU owns both remaining ends.
        pair.close()
        lifetime = {'lifetime': GUEST_LIFETIME + duration_seconds} if duration_seconds is not None else {}
        lab = adapters.guest(vms['lab'], 'lab', lab_id, clock=clock, sleep=sleep, **lifetime)
        test = adapters.guest(vms['test'], 'test', lab_id, clock=clock, sleep=sleep, **lifetime)
        ready = lab.call('setup', expected, window, **extra)
        if ready.get('capture_ready') is not True:
            raise ValueError('capture-not-ready')
        sent, reports = {}, None
        try:
            probed = test.call('probe', expected, window, canary=canary, **extra)
            replies, marker_replies, sent = probed['replies'], probed['marker_replies'], probed['marker_sent']
            reports = probed.get('https')
        except Exception as error:
            result['errors'].append(failure('probe', error))
            replies, marker_replies = [], []
        result['replies'] = replies
        lab.call('finish', expected, window, **extra)
        evidence = {}
        files = (('targets.json', LOG_LIMIT), ('health.json', LOG_LIMIT))
        if not evidence_disk:
            files = (('capture.pcap', CAPTURE_LIMIT),) + files
        if tunnel:
            files += (('https.json', LOG_LIMIT), ('node.log', LOG_LIMIT))
        for name, limit in files:
            raw = lab.read(name, limit)
            try:
                # A pcap is binary and guest-supplied; only the JSON files are checked.
                forbid = None if name == 'capture.pcap' else runs['lab']._identity[2]
                write_file(runs['lab'], name, raw, mode='overwrite', readback=True, forbid=forbid)
            except ReadbackError:
                raise ValueError('lab-evidence-readback-failed') from None
            evidence[name] = raw
        if evidence_disk:
            # The lab machine must be gone before its disk is read: nothing may still be writing.
            lab_run = runs['lab']
            vms['lab'].close()
            if not completion_verified(lab_run.directory, lab_run._read()):
                raise ValueError('lab-completion-unconfirmed')
            try:
                raw = read_evidence(resource_path(lab_run.directory, EVIDENCE_IMAGE), lab_id)
                write_file(lab_run, 'capture.pcap', raw, mode='overwrite', readback=True)
            except ReadbackError:
                raise ValueError('lab-evidence-readback-failed') from None
            except (OSError, ValueError) as error:
                reason = str(error) if str(error).startswith('evidence-') else 'evidence-unreadable'
                result['evidence_disk'].update(reason=reason)
                result.update(leak='UNVERIFIED', leak_reason=reason, observer_reasons=[reason])
                raise ValueError(reason) from None
            evidence['capture.pcap'] = raw
            result['evidence_disk'] = dict(verified=True, reason=None, pcap_bytes=len(raw),
                                           pcap_sha256=hashlib.sha256(raw).hexdigest())
        result['evidence_sha256'] = {name: hashlib.sha256(raw).hexdigest() for name, raw in evidence.items()}
        health = json.loads(evidence['health.json'])
        # The leak verdict comes first so that a rejected capture cannot hide a seen leak.
        options = {}
        if tunnel:
            log = json.loads(evidence['https.json'])
            direct_report = reports.get('direct') if type(reports) is dict else None
            options = dict(tunnel_port=config['tunnel']['node_port'],
                           https=dict(direct=exchanges[0], log=log, client_port=(
                               direct_report.get('client_port') if type(direct_report) is dict else None)))
        if evidence_disk:
            options['limit'] = EVIDENCE_PCAP_LIMIT
        verdict = leak_verdict(evidence['capture.pcap'], expected, window, health, ready['capture_ready'],
                               marker_replies, **options)
        verdict['window'] = dict(verdict['window'], test_clock_sent=sent)
        result.update(verdict)
        if tunnel:
            result['tunnel'] = tunnel_summary(exchanges, reports, log, health, verdict['categories'])
        result['qualification'] = qualify(expected, replies, json.loads(evidence['targets.json']),
                    evidence['capture.pcap'], ready['capture_ready'], health,
                    **({'limit': EVIDENCE_PCAP_LIMIT} if evidence_disk else {}))
    except BaseException as error:
        result['errors'].append(failure('lab-smoke', error))
        if isinstance(error, KeyboardInterrupt):
            result['exit_code'] = 130
    finally:
        if lease is not None:
            # Includes a failed start's handle, never unrelated processes.
            for vm in list(lease._active):
                if any(vm.run is member for member in runs.values()):
                    try:
                        vm.close(hard=True)
                    except BaseException as error:
                        result['errors'].append(failure('vm-close', error))
            if pair is not None:
                try:
                    pair.close()
                    result['channel_closed'] = pair.closed
                except BaseException as error:
                    result['errors'].append(failure('channel-close', error))
                    for run in runs.values():
                        try:
                            run.mark('quarantined', 'lab-channel-close-unconfirmed')
                        except (OSError, ValueError):
                            result['errors'].append(dict(stage='quarantine', reason='ledger-write-failed'))
            for role, run in runs.items():
                try:
                    result['completion'][role] = completion_verified(run.directory, run._read())
                except (OSError, ValueError):
                    result['completion'][role] = False
                    result['errors'].append(dict(stage='completion', reason='ledger-read-failed'))
            result['completed'] = (set(result['completion']) == set(MACS)
                                   and all(result['completion'].values()) and result['channel_closed'])
            if result['exit_code'] != 130:
                result['exit_code'] = 0 if (result['completed'] and not result['errors']
                                            and result['qualification']['qualified'] and expected_leak(result)
                                            and tunnel_ok(result)) else 2
            for run in runs.values():
                try:
                    save(run, 'execution-summary.json', result)
                except (OSError, ValueError):
                    result['errors'].append(dict(stage='summary', reason='summary-write-failed'))
                    result['exit_code'] = 2
            if lease._active or (pair is not None and not pair.closed):
                _RETAINED_LEASES.append(lease)
            else:
                try:
                    lease.release()
                except (OSError, ValueError):
                    result['errors'].append(dict(stage='lease', reason='lease-release-failed'))
                    result['exit_code'] = 2
    return result
