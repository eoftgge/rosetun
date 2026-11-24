"""Windows Failure on the isolated wire. Each selected case starts from its own disposable guest."""
import json
from pathlib import Path

from . import lab_protocol, l3_requests, windows_list_guest as guest, windows_list_lab as lab, windows_results
from .catalog import digest, read_catalog
from .config import FAILURE_CATALOG, FAILURE_SUITE
from .l3_summary import TARGET_FLOW, expectation_verdict

SCHEMA = 'rosetun.matrix.execution.windows.v4'
PREFIX = 'rosetun.windows-failure.'
ROOT = r'C:\rosetun-failure'
TASK = 'RosetunFailureRunner'
ENTRY = 'run-windows-failure.ps1'
SCRIPTS = ('lib.ps1', ENTRY, 'failure-probes.ps1', 'RosetunListResults.psm1')
BASE = ('baseline.direct-egress-works-before-connect', 'baseline.direct-dns-works-before-connect',
        'baseline.direct-tcp-dns-works-before-connect', 'baseline.ipv6-to-the-host-works-before-connect')
CONNECT = ('connect.state-is-connected', 'connect.tunnel-carries-traffic-within-5-s-dns-included',
           'connect.direct-egress-is-blocked', 'connect.ipv6-outside-the-tunnel-is-blocked')
CASES = ('engine-killed', 'helper-killed', 'no-network', 'apply-rules', 'reconnect', 'temporary', 'dns-lock')
V6_FLOW = ('tcp', 'other', f'[{lab_protocol.TARGETS[6]}]:{lab_protocol.PORTS["http"]}')


def validate(config):
    if not isinstance(config, dict) or config.get('schema') != SCHEMA or config.get('suite') != FAILURE_SUITE:
        raise ValueError('unsupported Windows Failure configuration')
    if 'list' in config or not isinstance(config.get('failure'), dict):
        raise ValueError('invalid Failure block')
    common = dict(config)
    block = dict(common.pop('failure'))
    if block.pop('case', None) not in CASES:
        raise ValueError('unknown Windows Failure case')
    common.update(schema=lab.SCHEMA, suite=lab.SUITE, list=block)
    lab.validate(common)
    return config


def selected(case):
    groups = {'engine-killed': ('engine killed', 'disconnect'), 'helper-killed': ('helper killed',),
              'no-network': ('no network',), 'apply-rules': ('apply rules',),
              'temporary': ('temporary', 'temporary disconnect'), 'dns-lock': ('dns lock',),
              'reconnect': ('reconnect',)}
    # The legacy reconnect group also has two later rows, after an engine crash (a distinct phase), and the two
    # server-check rows probe hardcoded public HTTPS endpoints unreachable on the isolated lab wire (same as
    # `connect.server-check-works-while-connected`, omitted from CONNECT).
    omitted = {'reconnect.state-is-connected-after-engine-kill', 'reconnect.no-leak-while-reconnecting',
               'engine-killed.server-check-works-under-protection', 'dns-lock.server-check-works-with-the-dns-lock'}
    return [row for row in read_catalog(FAILURE_CATALOG) if row['id'] in BASE + CONNECT or
            (row['group'] in groups[case] and row['id'] not in omitted)]


class Case:
    SUMMARY_SCHEMA = 'rosetun.matrix.windows-failure-summary.v1'
    PREFIX = PREFIX
    labels = ('baseline', 'session', 'recovery')
    validate = staticmethod(validate)

    def __init__(self, name):
        self.name = name
        self.catalog = selected(name)
        self.checks = tuple(row['id'] for row in self.catalog)
        self.expectations = dict(baseline={TARGET_FLOW: 1, V6_FLOW: 1},
                                 session={TARGET_FLOW: 1} if name == 'temporary' else {},
                                 recovery={TARGET_FLOW: 1, V6_FLOW: 1})

    def preflight(self, config, *, dry_run=False):
        plan = lab.preflight(config, dry_run=dry_run, profile=self)
        plan['case'] = self.name
        plan['catalog_digest'] = digest(self.catalog)
        plan['actions'][-3] = 'verify the evidence disk and the baseline, session and recovery windows'
        plan['limitations'] = ['one case of the Failure core per run', 'no release acceptance or Hyper-V parity',
                               'bounded capture on one Windows guest and one lab guest',
                               'server-check probes require public HTTPS endpoints and are omitted in the isolated lab']
        return plan

    def plan_document(self, lab_id, windows, plain, port, files):
        plan = guest.plan_document(lab_id, windows, plain, port, files, labels=self.labels)
        plan.pop('config')
        request = l3_requests.template()
        request['node']['port'] = port
        request['rule_set']['rules'] = []
        request['settings'].update(kill_switch=self.name != 'dns-lock', auto_reconnect=False,
                                   private_networks=False, allow_lan=False)
        plan.update(schema=PREFIX + 'job.v1', case=self.name, catalog=self.catalog, request=request)
        plan['addresses'].update(client6=lab_protocol.CLIENTS[6], target6=lab_protocol.TARGETS[6],
                                 http_port=lab_protocol.PORTS['http'])
        return plan

    def validate_plan(self, plan):
        keys = {'schema', 'suite', 'identity', 'profile', 'policy', 'catalog', 'catalog_digest'}
        if (not isinstance(plan, dict) or set(plan) != keys or plan['schema'] != PREFIX + 'plan.v1'
                or plan['suite'] != FAILURE_SUITE or plan['profile'] != 'exploratory'
                or plan['policy'] != {'mode': 'exploratory'} or plan['catalog'] != self.catalog
                or plan['catalog_digest'] != digest(self.catalog)):
            raise ValueError('invalid Failure case plan')
        identity = plan['identity']
        if (not isinstance(identity, dict) or set(identity) != {'run_id', 'vm_id', 'boot_id'}
                or not all(isinstance(value, str) and value for value in identity.values())):
            raise ValueError('invalid Failure case identity')
        return plan

    def assess(self, report, status, events, plan, problems=()):
        return windows_results.assess(report, status, events, plan, problems, adapter=self)

    def assess_files(self, report_path, plan_path):
        return windows_results.assess_files(report_path, plan_path, adapter=self)

    @staticmethod
    def start_script(files):
        return guest.start_script(files, scripts=SCRIPTS, root=ROOT, task=TASK, entry=ENTRY)

    @staticmethod
    def started(text):
        return guest.started(text, scripts=SCRIPTS, task=TASK)

    @staticmethod
    def read_arguments():
        return guest.read_arguments(ROOT + r'\status.json')

    def runner_status(self, text, run):
        return guest.runner_status(text, run, labels=self.labels)

    def markers_of(self, status, windows):
        return guest.markers_of(status, windows, labels=self.labels)

    @staticmethod
    def collect_script():
        return guest.collect_script(ROOT)

    @staticmethod
    def after_script():
        return guest.after_script(ROOT, TASK)

    def judge(self, config, lab_id, seen, plain):
        lab.judge(config, lab_id, seen, plain, labels=self.labels)

    def window_verdicts(self, verdict):
        windows = {row['label']: row for row in (verdict or {}).get('windows', []) if row['label'] in self.labels}
        session = windows.get('session')
        if session is not None:
            session['verdict'] = expectation_verdict(session, self.expectations['session'])
        return windows

    def cross_check(self, checks, windows, seen, measured):
        # Refusal of a connection alone cannot prove a block. Both ends of the run calibrate the physical paths.
        findings = []
        for phase in ('baseline', 'recovery'):
            window = windows.get(phase)
            if not window or window['observer_reasons']:
                continue
            if not lab.direct_seen(window, self.expectations[phase]):
                findings.append('control-flow-missing:' + phase)
            for transport in ('udp', 'tcp'):
                if not any(isinstance(row, dict) and row.get('name') == self.control_name(seen['plain'], phase)
                           and row.get('transport') == transport for row in seen.get('dns_rows', [])):
                    findings.append('control-dns-missing:' + phase + ':' + transport)
        session = windows.get('session')
        if session and not session['observer_reasons']:
            row = checks.get('connect.tunnel-carries-traffic-within-5-s-dns-included')
            if row and row.get('result') == 'PASS' and not session['categories'].get('tunnel'):
                findings.append('disagree:connect.tunnel-carries-traffic-within-5-s-dns-included')
        return findings

    @staticmethod
    def control_name(plain, phase):
        name = lab_protocol.dns_name(plain)
        return name if phase == 'baseline' else 'after.' + name

    def execution_section(self, *args):
        section = lab.execution_section(*args, profile=self)
        missing = [item for item in section['findings'] if item.startswith('control-')]
        for item in missing:
            section['findings'].remove(item)
        section['unverified'].extend(missing)
        section.update(case=self.name, full_matrix='UNVERIFIED')
        return section


def preflight(config, *, dry_run=False):
    validate(config)
    return Case(config['failure']['case']).preflight(config, dry_run=dry_run)


def run(config, **options):
    validate(config)
    return lab.run_guest_suite(config, profile=Case(config['failure']['case']), **options)
