"""Linux L3 inside the two-machine lab (stage 7b2b): exploratory, nothing here is an acceptance.

The test machine runs `run-l3.sh` as `run linux-l3` does; next to it the lab machine holds the VPN
node, the HTTPS target, the resolver and the DoH target and captures the wire to its evidence
disk. The script marks every protected session on the wire; the controller finds those windows
in the capture and sets the observer's verdict beside the script's own results.
"""

from datetime import datetime, timezone
import hashlib
import json
import re
import secrets
import sys
import time
import uuid

from . import lab as labmod
from .evidence import ReadbackError, write_file
from .execution import lab_of, preflight
from .lab_protocol import (LOG_LIMIT, PORTS, TARGETS, EVIDENCE_PCAP_LIMIT, CLIENTS, EGRESS, HELPER_REASON,
                           classify_windows, https_exchanges, marker_run_id, probes)
from .orchestrator import _RETAINED_LEASES, failure, save
from .resources import StandLease, completion_verified, create_run, resource_path, EXECUTION_FILES

SCHEMA = 'rosetun.matrix.l3-summary.v1'
ROLES = ('lab', 'test')
# What the lab machine keeps beside the capture, and the bound of each file.
LAB_FILES = (('targets.json', LOG_LIMIT), ('health.json', LOG_LIMIT), ('https.json', LOG_LIMIT),
             ('node.log', LOG_LIMIT), ('dns.json', LOG_LIMIT))
# The capture outlives the job by this much: it also covers the boot and the import of the test machine.
CAPTURE_SLACK = 300


class Adapters:
    """Lazy execution imports; the tests replace operations, not the controller."""

    def __init__(self):
        from .orchestrator import Adapters as Linux
        linux, lab = Linux(), labmod.Adapters()
        self.prepare, self.execute, self.config, self.image = linux.prepare, linux.execute, linux.config, linux.image
        self.start, self.attach, self.importer, self.requests = linux.start, linux.attach, linux.importer, linux.requests
        self.host, self.pair, self.guest = lab.host, lab.pair, lab.guest


def marker_address():
    """Where run-l3.sh sends its window markers: the target of the lab, on the port of the observer."""
    return TARGETS[4] + ':' + str(PORTS['marker'])


def capture_seconds(config):
    return config['timeouts']['job'] + CAPTURE_SLACK


def saved_report(run, job):
    """The bytes of the report the job collected last, exactly as the guest wrote them, else None."""
    polls = getattr(job, 'polls', 0)
    if not isinstance(polls, int) or polls < 1:
        return None
    try:
        return resource_path(run.directory, 'linux-l3/' + str(polls) + '/report.json').read_bytes()
    except OSError:
        return None


def legacy_block(raw, assessment):
    """`run-l3.sh` as it reported: the bytes' SHA-256, its summary and every row, unchanged."""
    block = dict(report_sha256=None, summary=None, cleanup=None, scenarios=[], assessment=None)
    if assessment is not None:
        block['assessment'] = dict(validation=assessment.get('validation'), execution=assessment.get('execution'),
                                   acceptance=assessment.get('acceptance'))
    if raw is None:
        return block
    block['report_sha256'] = hashlib.sha256(raw).hexdigest()
    try:
        report = json.loads(raw)
        rows = report['scenarios']
        block.update(summary=report.get('summary'), cleanup=report.get('cleanup'), scenarios=[
            dict(id=row['id'], group=row.get('group'), evidence=row.get('evidence'), result=row['result'],
                 reason=row.get('reason'), duration_ms=row.get('duration_ms')) for row in rows])
    except (ValueError, KeyError, TypeError):
        block.update(summary=None, scenarios=[], unreadable=True)
    return block


def https_fixture(log):
    """The HTTPS target worked when it answered the test machine directly and answered the node's exit.

    The counters of an L3 run (the `counts` element of `https.json`) say who was answered, however many
    requests there were. A log without them is the one of stage 7b1, whose rows are the answers. A refusal
    row (it has a `reason`) says the target turned a client away, not that it answered.
    """
    counts = next((row for row in log if type(row) is dict and row.get('kind') == 'counts'), None)
    if counts is not None and type(counts.get('counts')) is list:
        entries = [(row.get('source'), row['count']) for row in counts['counts']
                   if type(row) is dict and type(row.get('count')) is int and row['count'] > 0]
    else:
        entries = [(row.get('source'), 1) for row in log if type(row) is dict and 'reason' not in row]
    sources = {}
    for source, count in entries:
        if type(source) is str:
            sources[source] = sources.get(source, 0) + count
    direct, via_node = sources.get(CLIENTS[4], 0) > 0, sources.get(EGRESS, 0) > 0
    return dict(answered=direct and via_node, direct=direct, via_node=via_node, requests=sum(sources.values()))


# The most refusal rows the HTTPS target keeps (`REFUSAL_ROWS` of the lab helper) and the shape of one.
REFUSAL_ROWS = 8
_SERVICE = re.compile(r'[a-z0-9-]{1,16}')


def https_refusals(log):
    """The rows in which the HTTPS target turned a connection away: service, family and the reason.

    A row of the log is a refusal when it has a `reason`. Only the three fields are passed on, and only
    in the shape the helper writes them, so that nothing else of the lab machine reaches the summary.
    """
    rows = []
    for row in log if type(log) is list else []:
        if type(row) is not dict or 'reason' not in row or len(rows) >= REFUSAL_ROWS:
            continue
        service, family, reason = row.get('service'), row.get('family'), row['reason']
        rows.append(dict(
            service=service if type(service) is str and _SERVICE.fullmatch(service) else 'invalid',
            family=family if type(family) is int and family in (4, 6) else None,
            reason=reason if type(reason) is str and HELPER_REASON.fullmatch(reason) else 'invalid'))
    return rows


def fixtures_block(health, logs):
    """What the lab's fixtures were seen to do: from the observer's own files, never from the guest."""
    def rows(name):
        value = logs.get(name)
        return value if type(value) is list else []
    node = health.get('node') if type(health) is dict and type(health.get('node')) is dict else {}
    dns = [row for row in rows('dns.json') if type(row) is dict]
    return dict(node=dict(alive_at_finish=node.get('alive_at_finish') is True,
                          exit_code=node.get('exit_code') if type(node.get('exit_code')) is int else None),
                https=https_fixture(rows('https.json')),
                dns=dict(answered=any(row.get('transport') in ('udp', 'tcp') for row in dns),
                         requests=sum(row.get('transport') in ('udp', 'tcp') for row in dns)),
                doh=dict(answered=any(row.get('transport') == 'doh' for row in dns),
                         requests=sum(row.get('transport') == 'doh' for row in dns)))


def lab_block(lab_id, evidence_disk, verdict, fixtures, hashes, refusals=()):
    """The observer's side: the fixtures, the evidence disk and every window the markers named.

    `https_refusals` are the connections the HTTPS target turned away, and each window has its `flows`:
    both are there to say what happened to a connection, and neither is judged.
    """
    block = dict(lab_id=lab_id, qualification=dict(fixtures=fixtures, evidence=evidence_disk, observer=dict(
        ready=verdict is not None, reasons=verdict['observer_reasons'] if verdict else ['not-evaluated'])),
        windows=[], outside_window=None, missing_labels=[], extra_windows=[], artifacts_sha256=hashes,
        https_refusals=list(refusals))
    if verdict is not None:
        block.update(windows=verdict['windows'], outside_window=verdict['outside_window'],
                     missing_labels=verdict['missing_labels'], extra_windows=verdict['extra_windows'])
    return block


def run_linux_l3_lab(config, *, diagnostic=False, adapters=None, clock=time.monotonic, sleep=time.sleep,
                     progress=None):
    """One L3 run in the lab. A diagnostic run asks the engine to name destinations and is never a qualification."""
    if config.get('suite') != 'linux-l3' or lab_of(config) is None:
        raise ValueError('configuration is not for the lab')
    progress = progress or (lambda stage: print(stage, file=sys.stderr, flush=True))
    l3, lab_config = config['l3'], config['lab']
    result = dict(schema=SCHEMA, suite='linux-l3', mode='lab', identities={}, configuration=config, stages=[],
                  evidence=[], legacy=None, lab=None, crosscheck=[], out_of_scope=[], delivery=None,
                  execution=None, completion=dict.fromkeys(ROLES, False), completed=False,
                  manual_recovery_required=False, errors=[], security_invariants='UNVERIFIED',
                  release_gate=False, exit_code=2)
    if diagnostic:
        result['diagnostic'] = True
    lease = pair = job = attempt = lab_id = None
    runs, vms, closed = {}, {}, set()
    stage = 'preflight'
    interrupted = False
    # What the finally block summarizes: kept as it arrives, so that a late failure loses nothing.
    seen = dict(raw_report=None, logs={}, hashes={}, health=None, verdict=None, evidence_disk=dict(
        verified=False, reason='not-read', pcap_bytes=0, pcap_sha256=None))

    def step(name, operation):
        nonlocal stage
        stage = name
        progress(name)
        row = dict(stage=name, state='started')
        result['stages'].append(row)
        try:
            value = operation()
        except BaseException:
            row['state'] = 'error'
            raise
        row['state'] = 'completed'
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
        for binary in ('executable', 'image_executable'):
            version = step('qemu-version', lambda: adapters.execute([config['qemu'][binary], '--version'],
                                                                    timeout=5, output_limit=4096))
            if (version.returncode != 0
                    or not re.search(rb'\bversion 10\.0\.13(?:\s|$)', version.stdout.split(b'\n')[0])):
                raise ValueError('lab-requires-qemu-10-0-13')
        guest_run_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + uuid.uuid4().hex[:8]
        lab_id = marker_run_id(guest_run_id)
        identities = dict(host_run_id=lab_id + '-test', lab_run_id=lab_id + '-lab', lab_id=lab_id,
                          guest_run_id=guest_run_id, import_id=uuid.uuid4().hex)
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
            save(run, 'execution-identity.json', {
                **(identities if role == 'test' else {}),
                'schema': 'rosetun.matrix.execution-identity.v1', 'lab_id': lab_id, 'role': role,
                'members': members, 'controls': labmod.controls(run),
                'endpoint': dict(kind='inherited-unix-stream', role=role, mac=labmod.MACS[role])}, initial=True)
            save(run, 'execution-summary.json', result, initial=True)
        deadline = clock() + config['deadlines']['preparation']
        executor = bounded_executor(deadline)
        step('prepare-lab', lambda: adapters.prepare(runs['lab'], adapters.image(**lab_config['image']),
                                                     adapters.config(**config['qemu']), executor=executor))
        step('prepare-test', lambda: adapters.prepare(runs['test'], adapters.image(**config['image']),
                                                      adapters.config(**config['qemu']), executor=executor))
        step('requests', lambda: adapters.requests(runs['test'], l3['host_address'], l3['node_port'],
                                                   **({'diagnostic': True} if diagnostic else {})))
        step('media', lambda: adapters.attach(runs['test'], directory=config['content_directory'],
             checkout=config['source_checkout'], xorriso=config['xorriso'], executor=executor,
             profile='l3', sing_box_sha256=l3['sing_box_sha256']))
        # The pair registers its files in both runs (the test machine's DNS client log among them), while the
        # requests and the media accept only the resources of a freshly prepared run: so it comes last.
        # The evidence disk is made with the pair; it belongs to the lab machine alone.
        pair = step('evidence-disk', lambda: adapters.pair(lease, runs, lab_id, tunnel=True, evidence_disk=True,
                                                           dns=True))
        if clock() >= deadline:
            raise TimeoutError('preparation deadline')

        expected = probes(lab_id, lambda: secrets.token_hex(12))
        exchanges = https_exchanges(lab_id, lambda: secrets.token_hex(12))
        tunnel = labmod.tunnel_request(lab_config, exchanges)
        options = dict(evidence_disk=True, duration_seconds=capture_seconds(config), dns=True, windows=True,
                       certificates=dict(https_sha256=lab_config['https_cert_sha256'],
                                         doh_sha256=lab_config['doh_cert_sha256']))

        def lab_call(operation):
            # A new facade each time: the capture's own deadline, not the facade's, bounds the run.
            guest = adapters.guest(vms['lab'], 'lab', lab_id, clock=clock, sleep=sleep)
            return guest, guest.call(operation, expected, (), tunnel=tunnel, options=options)

        vms['lab'] = step('start-lab', lambda: adapters.start(runs['lab'], lab=pair))
        step('resume-lab', vms['lab'].resume)
        step('boot-lab', lambda: vms['lab'].wait_initial_guest(timeout=config['deadlines']['boot'],
                                                              clock=clock, sleep=sleep))
        ready = step('lab-setup', lambda: lab_call('setup')[1])
        if ready.get('capture_ready') is not True:
            raise ValueError('capture-not-ready')
        vm = vms['test'] = step('start-test', lambda: adapters.start(runs['test'], lab=pair))
        step('resume-test', vm.resume)
        step('boot-test', lambda: vm.wait_initial_guest(timeout=config['deadlines']['boot'],
                                                       clock=clock, sleep=sleep))
        # Both machines are up: QEMU owns the two ends of the wire, the controller drops its copies.
        step('wire-close', pair.close)
        identities.update(boot_id=vm.last_boot_id, vm_uuid=vm.vm_uuid)

        def recovery():
            return vm.recover_guest()

        attempt = step('import-create', lambda: adapters.importer(vm, enabled=True,
              guest_run_id=guest_run_id, import_id=identities['import_id'], **config['accounts'],
              **{k + '_timeout': v for k, v in config['timeouts'].items()},
              l3=dict(l3, lab_marker_address=marker_address())))
        attempt.deadline = min(attempt.deadline, clock() + config['deadlines']['import'])
        try:
            step('import', attempt.stage)
        except Exception:
            if vm.qga.valid:
                raise
            sleep(max(0, attempt.deadline - clock() - 60))
            step('import-recovery', recovery)
            step('receipt-after-uncertainty', attempt.check_receipt)
        else:
            step('import-refresh', recovery)
            step('receipt', attempt.check_receipt)
        result['delivery'] = dict(state=attempt.state, receipt_verified=attempt.receipt_verified)
        job = step('job-create', lambda: attempt.linux_l2_job(checkout=config['source_checkout'], enabled=True))
        try:
            step('submit', job.submit)
        except Exception:
            if vm.qga.valid or job.submission != 'unknown':
                raise
            step('submit-recovery', recovery)
        step('wait', lambda: sleep(config['timeouts']['job'] + 125))
        try:
            step('collect', job.collect)
        except Exception:
            if not vm.qga.valid:
                step('collect-recovery', recovery)
            sleep(15)
            step('collect-final', job.collect)
        result['execution'] = job.snapshot()
        seen['raw_report'] = saved_report(runs['test'], job)

        # The capture ends here; the lab machine says what it saw.
        guest, _ = step('lab-finish', lambda: lab_call('finish'))
        for name, limit in LAB_FILES:
            raw = step('lab-read-' + name, lambda: guest.read(name, limit))
            try:
                write_file(runs['lab'], name, raw, mode='overwrite', readback=True, forbid=runs['lab']._identity[2])
            except ReadbackError:
                raise ValueError('lab-evidence-readback-failed') from None
            seen['hashes'][name] = hashlib.sha256(raw).hexdigest()
            seen['logs'][name] = raw
        # Both machines stop, and only then is the lab's disk read: nothing may still be writing.
        step('close-test', lambda: close_machine('test', False))
        step('close-lab', lambda: close_machine('lab', False))
        lab_run = runs['lab']
        if not completion_verified(lab_run.directory, lab_run._read()):
            raise ValueError('lab-completion-unconfirmed')
        step('evidence-read', lambda: read_disk(lab_run, lab_id, seen))
        step('windows', lambda: judge(lab_id, config, seen))
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
        finish(result, lease, pair, runs, vms, closed, job, attempt, seen, interrupted, lab_id)
    return result


def read_disk(lab_run, lab_id, seen):
    """The capture from the lab's evidence image, checked in full before a byte of it is used."""
    disk = seen['evidence_disk']
    try:
        raw = labmod.read_evidence(resource_path(lab_run.directory, labmod.EVIDENCE_IMAGE), lab_id)
        write_file(lab_run, 'capture.pcap', raw, mode='overwrite', readback=True)
    except ReadbackError:
        raise ValueError('lab-evidence-readback-failed') from None
    except (OSError, ValueError) as error:
        reason = str(error) if str(error).startswith('evidence-') else 'evidence-unreadable'
        disk.update(reason=reason)
        raise ValueError(reason) from None
    seen['logs']['capture.pcap'] = raw
    seen['hashes']['capture.pcap'] = hashlib.sha256(raw).hexdigest()
    disk.update(verified=True, reason=None, pcap_bytes=len(raw), pcap_sha256=seen['hashes']['capture.pcap'])


def judge(lab_id, config, seen):
    """Split the capture into the windows its markers name; the labels of the group must each have one."""
    from .l3_summary import GROUP_LABELS
    seen['health'] = json.loads(seen['logs']['health.json'])
    seen['verdict'] = classify_windows(seen['logs']['capture.pcap'], lab_id, None, health=seen['health'], ready=True,
                                       tunnel_port=config['lab']['tunnel']['node_port'],
                                       required_labels=GROUP_LABELS, limit=EVIDENCE_PCAP_LIMIT, flows=True)


def finish(result, lease, pair, runs, vms, closed, job, attempt, seen, interrupted, lab_id):
    """Close what is still open, then write the summary into both runs; never raises."""
    if job is not None:
        result['execution'] = job.snapshot()
        if seen['raw_report'] is None:
            seen['raw_report'] = saved_report(runs['test'], job)
    if attempt is not None:
        result['delivery'] = dict(state=attempt.state, receipt_verified=attempt.receipt_verified)
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
    result['manual_recovery_required'] = bool(runs) and not result['completed']
    result['legacy'] = legacy_block(seen['raw_report'], getattr(job, 'assessment', None))
    parsed = {k: _json_or_none(v) for k, v in seen['logs'].items() if k.endswith('.json')}
    result['lab'] = lab_block(lab_id, seen['evidence_disk'], seen['verdict'],
                              fixtures_block(seen['health'] or {}, parsed), seen['hashes'],
                              https_refusals(parsed.get('https.json')))
    from .l3_summary import decide
    decide(result, interrupted)
    if runs:
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
                path = resource_path(run.directory, entry['path'])
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


def _json_or_none(raw):
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return None
