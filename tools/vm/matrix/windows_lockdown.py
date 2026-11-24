"""Windows Lockdown on the isolated wire (stage 10c), including clean reboot and abrupt power cuts."""
from . import lab_protocol, l3_requests, windows_list_guest as guest, windows_list_lab as lab, windows_results
from .catalog import digest, read_catalog
from .config import LOCKDOWN_CATALOG, LOCKDOWN_SUITE
from .l3_summary import TARGET_FLOW, expectation_verdict

SCHEMA = 'rosetun.matrix.execution.windows.v5'
PREFIX = 'rosetun.windows-lockdown.'
ROOT = r'C:\rosetun-lockdown'
TASK = 'RosetunLockdownRunner'
ENTRY = 'run-windows-lockdown.ps1'
SCRIPTS = ('lib.ps1', ENTRY, 'failure-probes.ps1', 'RosetunListResults.psm1')
CASES = ('full', 'core', 'reboot')
MAX_RUNNER_SECONDS = 1800
COLLECT_LIMITS = dict(plan=22000, events=16000, report=20000, status=2000, helper_tail=3000)
COLLECT_ANSWER_LIMIT = 64 * 1024
STATUS_ANSWER_LIMIT = 32 * 1024
V6_FLOW = ('tcp', 'other', f'[{lab_protocol.TARGETS[6]}]:{lab_protocol.PORTS["http"]}')
# During a reboot inside `reboot-lockdown`, Windows checks duplicate IPv4/IPv6 addresses (RFC 5227 ARP probes
# and announcements, plus RFC 4862 IPv6 DAD NS from `::`); no allowance is granted in `lockdown-core` or for
# any outbound data flow.
REBOOT_ALLOWANCES = ('ipv6-dad', 'arp-probe', 'arp-announcement')


def validate(config):
    if not isinstance(config, dict) or config.get('schema') != SCHEMA or config.get('suite') != LOCKDOWN_SUITE:
        raise ValueError('unsupported Windows Lockdown configuration')
    if 'list' in config or 'failure' in config or not isinstance(config.get('lockdown'), dict):
        raise ValueError('invalid Lockdown block')
    common = dict(config)
    block = dict(common.pop('lockdown'))
    case = block.pop('case', None)
    if case not in CASES:
        raise ValueError('unknown Windows Lockdown case')
    repeats = block.pop('power_cut_repeats', None)
    if type(repeats) is not int or not 0 <= repeats <= 3:
        raise ValueError('invalid Windows Lockdown power_cut_repeats')
    if case == 'core' and repeats != 0:
        raise ValueError('core Lockdown case requires power_cut_repeats = 0')
    if case != 'core' and not 1 <= repeats <= 3:
        raise ValueError('multi-boot Lockdown case requires power_cut_repeats between 1 and 3')
    delay = block.pop('power_cut_delay_seconds', None)
    if type(delay) is not int or not 0 <= delay <= 15:
        raise ValueError('invalid Windows Lockdown power_cut_delay_seconds')
    common.update(schema=lab.SCHEMA, suite=lab.SUITE, list=block)
    lab.validate(common, max_runner_seconds=MAX_RUNNER_SECONDS)
    return config


def selected(case, power_cut_repeats=3):
    groups = {
        'core': ('baseline', 'on-disconnected', 'connected', 'helper-killed', 'off', 'reset-firewall', 'uninstall'),
        'reboot': ('baseline', 'reboot', 'power-cut'),
        'full': ('baseline', 'on-disconnected', 'connected', 'helper-killed', 'reboot', 'power-cut',
                 'off', 'reset-firewall', 'uninstall'),
    }
    if case not in groups:
        raise ValueError('unknown Windows Lockdown case')
    allowed_passes = {f'cut.pass-{i}.' for i in range(1, power_cut_repeats + 1)}
    rows = []
    for row in read_catalog(LOCKDOWN_CATALOG):
        if row['group'] not in groups[case]:
            continue
        if row['group'] == 'power-cut' and not any(row['id'].startswith(prefix) for prefix in allowed_passes):
            continue
        rows.append(row)
    return rows


class Case:
    SUMMARY_SCHEMA = 'rosetun.matrix.windows-lockdown-summary.v1'
    PREFIX = PREFIX
    validate = staticmethod(validate)

    def __init__(self, name, *, power_cut_repeats=3, power_cut_delay_seconds=2):
        self.name = name
        self.power_cut_repeats = power_cut_repeats
        self.power_cut_delay_seconds = power_cut_delay_seconds
        self.catalog = selected(name, power_cut_repeats=power_cut_repeats)
        self.checks = tuple(row['id'] for row in self.catalog)
        self.planned_reboots = 0 if name == 'core' else 1
        self.planned_power_cuts = 0 if name == 'core' else 2 * power_cut_repeats
        self.multi_boot = (self.planned_reboots + self.planned_power_cuts) > 0
        if name == 'full':
            self.labels = ('baseline', 'lockdown-core', 'reboot-lockdown', 'recovery')
            self.judged_labels = ('lockdown-core', 'reboot-lockdown')
        elif name == 'core':
            self.labels = ('baseline', 'lockdown-core', 'recovery')
            self.judged_labels = ('lockdown-core',)
        else:
            self.labels = ('baseline', 'reboot-lockdown', 'recovery')
            self.judged_labels = ('reboot-lockdown',)
        self.listed_labels = ('baseline', 'recovery')
        self.expectations = {
            'baseline': {TARGET_FLOW: 1, V6_FLOW: 1},
            **({'lockdown-core': {TARGET_FLOW: 1}} if 'lockdown-core' in self.labels else {}),
            **({'reboot-lockdown': {}} if 'reboot-lockdown' in self.labels else {}),
            'recovery': {TARGET_FLOW: 1, V6_FLOW: 1},
        }
        self.window_allowances = ({'reboot-lockdown': REBOOT_ALLOWANCES}
                                  if 'reboot-lockdown' in self.labels else None)

    def preflight(self, config, *, dry_run=False):
        plan = lab.preflight(config, dry_run=dry_run, profile=self)
        plan['case'] = self.name
        plan['power_cut_repeats'] = self.power_cut_repeats
        plan['power_cut_delay_seconds'] = self.power_cut_delay_seconds
        plan['planned_reboots'] = self.planned_reboots
        plan['planned_power_cuts'] = self.planned_power_cuts
        plan['catalog_digest'] = digest(self.catalog)
        plan['actions'][-3] = 'verify the evidence disk and the ' + ', '.join(self.labels) + ' windows'
        plan['limitations'] = [
            'Windows Lockdown core on the isolated lab wire (no LAN/inbound listener, DHCP lease, or sleep/resume)',
            'no release acceptance or Hyper-V parity',
            'bounded capture on one Windows guest and one lab guest',
            'server-check and external subscription probes are omitted in the isolated lab',
        ]
        return plan

    def plan_document(self, lab_id, windows, plain, port, files):
        plan = guest.plan_document(lab_id, windows, plain, port, files, labels=self.labels)
        plan.pop('config')
        request = l3_requests.template()
        request['node']['port'] = port
        request['rule_set']['rules'] = []
        request['settings'].update(kill_switch=True, auto_reconnect=False,
                                   private_networks=False, allow_lan=False)
        plan.update(schema=PREFIX + 'job.v1', case=self.name,
                    power_cut_repeats=self.power_cut_repeats,
                    power_cut_delay_seconds=self.power_cut_delay_seconds,
                    catalog=self.catalog, request=request)
        plan['addresses'].update(client6=lab_protocol.CLIENTS[6], target6=lab_protocol.TARGETS[6],
                                 http_port=lab_protocol.PORTS['http'])
        return plan

    def validate_plan(self, plan):
        keys = {'schema', 'suite', 'identity', 'profile', 'policy', 'catalog', 'catalog_digest'}
        if (not isinstance(plan, dict) or set(plan) != keys or plan['schema'] != PREFIX + 'plan.v1'
                or plan['suite'] != LOCKDOWN_SUITE or plan['profile'] != 'exploratory'
                or plan['policy'] != {'mode': 'exploratory'} or plan['catalog'] != self.catalog
                or plan['catalog_digest'] != digest(self.catalog)):
            raise ValueError('invalid Lockdown case plan')
        identity = plan['identity']
        if (not isinstance(identity, dict) or set(identity) != {'run_id', 'vm_id', 'boot_id'}
                or not all(isinstance(value, str) and value for value in identity.values())):
            raise ValueError('invalid Lockdown case identity')
        return plan

    def assess(self, report, status, events, plan, problems=(), *, expected_end_boot_id=None):
        return windows_results.assess(report, status, events, plan, problems, adapter=self,
                                      expected_end_boot_id=expected_end_boot_id)

    def assess_files(self, report_path, plan_path, *, expected_end_boot_id=None):
        return windows_results.assess_files(report_path, plan_path, adapter=self,
                                            expected_end_boot_id=expected_end_boot_id)

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
        return guest.runner_status(text, run, labels=self.labels, states=guest.LOCKDOWN_STATES,
                                   max_checks=96, max_notes=64, answer_limit=STATUS_ANSWER_LIMIT)

    def markers_of(self, status, windows):
        return guest.markers_of(status, windows, labels=self.labels)

    @staticmethod
    def collect_script():
        return guest.collect_script(ROOT, limits=COLLECT_LIMITS)

    @staticmethod
    def collected(text):
        return guest.collected(text, limit=COLLECT_ANSWER_LIMIT)

    @staticmethod
    def after_script():
        return guest.after_script(ROOT, TASK, lockdown=True)

    @staticmethod
    def after(text):
        return guest.after(text, lockdown=True)

    def judge(self, config, lab_id, seen, plain):
        lab.judge(config, lab_id, seen, plain, labels=self.labels, window_allowances=self.window_allowances)

    def window_verdicts(self, verdict):
        windows = {row['label']: row for row in (verdict or {}).get('windows', []) if row['label'] in self.labels}
        for label in self.judged_labels:
            window = windows.get(label)
            if window is not None:
                window['verdict'] = expectation_verdict(window, self.expectations[label])
        return windows

    def cross_check(self, checks, windows, seen, measured):
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
        core = windows.get('lockdown-core')
        if core and not core['observer_reasons']:
            row = checks.get('connected.tunnel-carries-traffic')
            if row and row.get('result') == 'PASS' and not core['categories'].get('tunnel'):
                findings.append('disagree:connected.tunnel-carries-traffic')
            cli_row = checks.get('on.cli-path-egress-open')
            if cli_row and cli_row.get('result') == 'PASS' and not lab.direct_seen(core, {TARGET_FLOW: 1}):
                findings.append('disagree:on.cli-path-egress-open')
        reboot = windows.get('reboot-lockdown')
        if reboot and not reboot['observer_reasons']:
            row = checks.get('reboot.connect-opens-tunnel')
            if row and row.get('result') == 'PASS' and not reboot['categories'].get('tunnel'):
                findings.append('disagree:reboot.connect-opens-tunnel')
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
        measured = args[3]
        boot_chain = list(measured.get('boot_chain') or [])
        guest_resets = measured.get('guest_resets', 0)
        power_cycles = measured.get('power_cycles', 0)
        expected_boots = 1 + self.planned_reboots + self.planned_power_cuts
        if self.multi_boot:
            if len(boot_chain) != expected_boots or len(set(boot_chain)) != len(boot_chain):
                section['unverified'].append('boot-chain-incomplete')
            if guest_resets != self.planned_reboots:
                section['unverified'].append('guest-resets-mismatch')
            if power_cycles != self.planned_power_cuts:
                section['unverified'].append('power-cycles-mismatch')
        section['unverified'] = list(dict.fromkeys(section['unverified']))
        section['accepted'] = not section['findings'] and not section['unverified']
        section.update(case=self.name, power_cut_repeats=self.power_cut_repeats,
                       boot_chain=boot_chain, guest_resets=guest_resets,
                       power_cycles=power_cycles, full_matrix='UNVERIFIED')
        return section


def _case_of(config):
    block = config['lockdown']
    return Case(block['case'], power_cut_repeats=block['power_cut_repeats'],
                power_cut_delay_seconds=block['power_cut_delay_seconds'])


def preflight(config, *, dry_run=False):
    validate(config)
    return _case_of(config).preflight(config, dry_run=dry_run)


def run(config, **options):
    validate(config)
    return lab.run_guest_suite(config, profile=_case_of(config), **options)
