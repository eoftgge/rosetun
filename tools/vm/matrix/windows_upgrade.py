"""Exercise four Inno Setup upgrade scenarios on the isolated Windows lab."""

from . import lab_protocol, l3_requests, windows_list_guest as guest, windows_list_lab as lab, windows_results
from .catalog import digest
from .config import UPGRADE_SUITE, upgrade_catalog
from .l3_summary import TARGET_FLOW, expectation_verdict

SCHEMA = 'rosetun.matrix.execution.windows.v8'
PREFIX = 'rosetun.windows-upgrade.'
SUMMARY_SCHEMA = 'rosetun.matrix.windows-upgrade-summary.v1'
ROOT = r'C:\rosetun-upgrade'
TASK = 'RosetunUpgradeRunner'
ENTRY = 'run-windows-upgrade.ps1'
SCRIPTS = ('lib.ps1', ENTRY, 'RosetunListResults.psm1', 'upgrade-checks.json')
SETUPS = ('old-setup.exe', 'new-setup.exe')
BINARIES = guest.BINARIES + SETUPS
LABELS = ('baseline', 'lockdown', 'kill-switch', 'no-kill-switch', 'broken', 'recovery')
COLLECT_LIMITS = dict(plan=32000, events=32000, report=36000, status=2000, helper_tail=3000)


def validate(config):
    if type(config) is not dict or config.get('schema') != SCHEMA or config.get('suite') != UPGRADE_SUITE:
        raise ValueError('unsupported Windows Upgrade configuration')
    if not isinstance(config.get('upgrade'), dict) or 'list' in config:
        raise ValueError('invalid Upgrade block')
    common = dict(config)
    block = dict(common.pop('upgrade'))
    timeout = block.pop('setup_timeout_seconds', None)
    if type(timeout) is not int or not 30 <= timeout <= 300:
        raise ValueError('invalid setup_timeout_seconds')
    paths, hashes = [], []
    for build in ('old', 'new'):
        path = block.pop(build + '_setup', None)
        pin = block.pop(build + '_setup_sha256', None)
        if type(path) is not str or not path:
            raise ValueError('invalid installer path')
        if type(pin) is not str or len(pin) != 64 or pin.strip('0123456789abcdef'):
            raise ValueError('installer hashes must be 64 lowercase hex digits')
        paths.append(path)
        hashes.append(pin)
    if paths[0] == paths[1] or hashes[0] == hashes[1]:
        raise ValueError('old and new installers must differ')
    common.update(schema=lab.SCHEMA, suite=lab.SUITE, list=block)
    lab.validate(common, max_runner_seconds=2400)
    if timeout >= block['runner_seconds']:
        raise ValueError('setup_timeout_seconds must be smaller than runner_seconds')
    return config


class UpgradeProfile:
    SUMMARY_SCHEMA = SUMMARY_SCHEMA
    PREFIX = PREFIX
    ROOT = ROOT
    labels = LABELS
    judged_labels = LABELS[1:-1]
    listed_labels = (LABELS[0], LABELS[-1])
    validate = staticmethod(validate)

    def __init__(self, setup_timeout_seconds=180):
        self.setup_timeout_seconds = setup_timeout_seconds
        self.catalog = upgrade_catalog()
        self.checks = tuple(row['id'] for row in self.catalog)
        self.expectations = {
            label: {TARGET_FLOW: 1} if label in ('baseline', 'no-kill-switch', 'recovery') else {}
            for label in self.labels
        }

    def preflight(self, config, *, dry_run=False):
        plan = lab.preflight(config, dry_run=dry_run, profile=self)
        plan['setup_timeout_seconds'] = self.setup_timeout_seconds
        plan['catalog_digest'] = digest(self.catalog)
        plan['actions'][3] = 'make the read-only disc with both pinned installers, recovery binaries and the runner'
        plan['actions'][-3] = 'verify the evidence disk and assess the six Upgrade windows and guest journal'
        plan['limitations'] = [
            'diagnostic runs with an unqualified Windows image on one isolated lab wire',
            'Inno Setup and installed-service behavior under SYSTEM in a single Windows boot',
            'no interactive desktop coverage',
        ]
        return plan

    def plan_document(self, lab_id, windows, plain, port, files):
        plan = guest.plan_document(lab_id, windows, plain, port, files, labels=self.labels, binaries=BINARIES)
        plan.pop('config')
        request = l3_requests.template()
        request['node'].update(server=lab_protocol.GATEWAYS[4], port=port)
        request['rule_set']['rules'] = []
        plan.update(schema=PREFIX + 'job.v1', setup_timeout_seconds=self.setup_timeout_seconds,
                    catalog=self.catalog, request=request)
        return plan

    def validate_plan(self, plan):
        keys = {'schema', 'suite', 'identity', 'profile', 'policy', 'catalog', 'catalog_digest'}
        if (type(plan) is not dict or set(plan) != keys or plan['schema'] != PREFIX + 'plan.v1'
                or plan['suite'] != UPGRADE_SUITE or plan['profile'] != 'exploratory'
                or plan['policy'] != {'mode': 'exploratory'} or plan['catalog'] != self.catalog
                or plan['catalog_digest'] != digest(self.catalog)):
            raise ValueError('invalid Upgrade plan')
        identity = plan['identity']
        if (type(identity) is not dict or set(identity) != {'run_id', 'vm_id', 'boot_id'}
                or not all(isinstance(value, str) and value for value in identity.values())):
            raise ValueError('invalid Upgrade identity')
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
        return guest.runner_status(text, run, labels=self.labels, max_checks=len(self.checks),
                                   max_notes=64, max_markers=2 * len(self.labels), answer_limit=64 * 1024)

    def markers_of(self, status, windows):
        return guest.markers_of(status, windows, labels=self.labels)

    @staticmethod
    def collect_script():
        return guest.collect_script(ROOT, limits=COLLECT_LIMITS)

    @staticmethod
    def collected(text):
        return guest.collected(text, limit=128 * 1024)

    @staticmethod
    def after_script():
        return guest.after_script(ROOT, TASK, upgrade=True)

    @staticmethod
    def after(text):
        return guest.after(text, upgrade=True)

    def judge(self, config, lab_id, seen, plain):
        lab.judge(config, lab_id, seen, plain, labels=self.labels)

    def window_verdicts(self, verdict):
        windows = {row['label']: row for row in (verdict or {}).get('windows', []) if row['label'] in self.labels}
        for label in self.judged_labels:
            if label in windows:
                windows[label]['verdict'] = expectation_verdict(windows[label], self.expectations[label])
        return windows

    @staticmethod
    def control_name(plain, phase):
        name = lab_protocol.dns_name(plain)
        return name if phase == 'baseline' else 'after.' + name

    def cross_check(self, checks, windows, seen, measured):
        findings = []
        for phase in self.listed_labels:
            window = windows.get(phase)
            if window is None or window['observer_reasons']:
                continue
            if not lab.direct_seen(window, self.expectations[phase]):
                findings.append('control-flow-missing:' + phase)
            if not any(isinstance(row, dict) and row.get('name') == self.control_name(seen['plain'], phase)
                       and row.get('transport') == 'udp' for row in seen.get('dns_rows', [])):
                findings.append('control-dns-missing:' + phase + ':udp')
        window = windows.get('kill-switch')
        if (window and not window['observer_reasons'] and checks.get('kill-switch.tunnel', {}).get('result') == 'PASS'
                and not window['categories'].get('tunnel')):
            findings.append('disagree:kill-switch.tunnel')
        window = windows.get('no-kill-switch')
        if (window and not window['observer_reasons']
                and checks.get('no-kill-switch.direct-open', {}).get('result') == 'PASS'
                and not lab.direct_seen(window, self.expectations['no-kill-switch'])):
            findings.append('disagree:no-kill-switch.direct-open')
        return findings

    def execution_section(self, *args):
        section = lab.execution_section(*args, profile=self)
        # A failed calibration cannot establish that the strict windows could see egress.
        section['unverified'].extend(item for item in section['findings'] if item.startswith('control-'))
        section['findings'] = [item for item in section['findings'] if not item.startswith('control-')]
        section['accepted'] = not section['findings'] and not section['unverified']
        return section


def preflight(config, *, dry_run=False):
    validate(config)
    return UpgradeProfile(config['upgrade']['setup_timeout_seconds']).preflight(config, dry_run=dry_run)


def run(config, **options):
    validate(config)
    return lab.run_guest_suite(config, profile=UpgradeProfile(config['upgrade']['setup_timeout_seconds']), **options)
