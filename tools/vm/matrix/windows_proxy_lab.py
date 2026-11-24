"""Windows Proxy on the isolated lab wire (stage 10d): all 46 checks of proxy-checks.json."""
from . import lab_protocol, l3_requests, windows_list_guest as guest, windows_list_lab as lab, windows_proxy
from .catalog import digest
from .l3_summary import TARGET_FLOW, expectation_verdict

SCHEMA = 'rosetun.matrix.execution.windows.v6'
SUITE = 'windows-proxy'
SUMMARY_SCHEMA = 'rosetun.matrix.windows-proxy-summary.v1'
ROOT = r'C:\rosetun-proxy'
TASK = 'RosetunProxyRunner'
ENTRY = 'run-windows-proxy.ps1'
SCRIPTS = ('lib.ps1', ENTRY, 'RosetunListResults.psm1', 'proxy-checks.json')
BINARIES = guest.BINARIES + ('desktop_proxy.exe',)
MAX_RUNNER_SECONDS = 1800
COLLECT_LIMITS = dict(plan=24000, events=24000, report=28000, status=2000, helper_tail=3000)
COLLECT_ANSWER_LIMIT = 96 * 1024
STATUS_ANSWER_LIMIT = 48 * 1024
LABELS = ('baseline', 'strict', 'sharing-strict', 'lockdown', 'recovery')
JUDGED_LABELS = ('strict', 'sharing-strict', 'lockdown')
LISTED_LABELS = ('baseline', 'recovery')
SHARING_STRICT_ALLOWANCES = ('lan-peer-arp', 'shared-proxy-peer', 'shared-proxy-server')
LOCKDOWN_ALLOWANCES = ('lan-peer-arp', 'shared-proxy-peer')


def validate(config):
    if not isinstance(config, dict) or config.get('schema') != SCHEMA or config.get('suite') != SUITE:
        raise ValueError('unsupported Windows Proxy configuration')
    if any(key in config for key in ('list', 'failure', 'lockdown', 'lan')) or not isinstance(config.get('proxy'), dict):
        raise ValueError('invalid Proxy block')
    common = dict(config)
    block = dict(common.pop('proxy'))
    proxy_port = block.pop('proxy_port', None)
    if type(proxy_port) is not int or not 1024 <= proxy_port <= 65535:
        raise ValueError('invalid Windows Proxy port')
    desktop_proxy = block.pop('desktop_proxy', None)
    if type(desktop_proxy) is not str or not desktop_proxy:
        raise ValueError('invalid desktop_proxy file path')
    desktop_proxy_sha256 = block.pop('desktop_proxy_sha256', None)
    if (type(desktop_proxy_sha256) is not str or len(desktop_proxy_sha256) != 64
            or desktop_proxy_sha256.strip('0123456789abcdef')):
        raise ValueError('desktop_proxy hash must be 64 lowercase hex digits')
    common.update(schema=lab.SCHEMA, suite=lab.SUITE, list=block)
    lab.validate(common, max_runner_seconds=MAX_RUNNER_SECONDS)
    if proxy_port == config['lab']['tunnel']['node_port']:
        raise ValueError('proxy_port must differ from lab tunnel node_port')
    return config


class ProxyProfile:
    SUMMARY_SCHEMA = SUMMARY_SCHEMA
    ROOT = ROOT
    lan_fixtures = True
    labels = LABELS
    judged_labels = JUDGED_LABELS
    listed_labels = LISTED_LABELS
    validate = staticmethod(validate)

    def __init__(self, proxy_port=10808):
        self.proxy_port = proxy_port
        self.catalog = windows_proxy.make_plan(
            'exploratory', dict(mode='exploratory'), use_host_node=True, keep_node=False,
            proxy_port=proxy_port)['catalog']
        self.checks = tuple(row['id'] for row in self.catalog)
        self.expectations = {
            'baseline': {TARGET_FLOW: 1},
            'strict': {},
            'sharing-strict': {},
            'lockdown': {},
            'recovery': {TARGET_FLOW: 1},
        }
        self.window_allowances = {
            'sharing-strict': SHARING_STRICT_ALLOWANCES,
            'lockdown': LOCKDOWN_ALLOWANCES,
        }

    def preflight(self, config, *, dry_run=False):
        plan = lab.preflight(config, dry_run=dry_run, profile=self)
        plan['proxy_port'] = self.proxy_port
        plan['catalog_digest'] = digest(self.catalog)
        plan['actions'][-3] = 'verify the evidence disk and the ' + ', '.join(self.labels) + ' windows'
        plan['limitations'] = [
            'Windows Proxy matrix on the isolated lab wire (lab router plays both VPN node and LAN peer)',
            'no release acceptance or Hyper-V parity',
            'bounded capture on one Windows guest and one lab guest',
            'desktop proxy checks run under a temporary local user profile inside the guest',
        ]
        return plan

    def plan_document(self, lab_id, windows, plain, port, files):
        plan = guest.plan_document(lab_id, windows, plain, port, files, labels=self.labels, binaries=BINARIES)
        plan.pop('config')
        request = l3_requests.template()
        request['node']['port'] = port
        request['rule_set']['rules'] = []
        plan.update(schema='rosetun.windows-proxy.job.v1', proxy_port=self.proxy_port, request=request)
        plan['addresses'].update(gateway4=lab_protocol.GATEWAYS[4], lan_peer=lab_protocol.LAN_PEER)
        return plan

    @staticmethod
    def assess_files(report_path, plan_path):
        return windows_proxy.assess_files(report_path, plan_path)

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
        return guest.runner_status(text, run, labels=self.labels, states=guest.ACTION_STATES,
                                   max_checks=64, max_notes=64, max_markers=16, allow_action=True,
                                   answer_limit=STATUS_ANSWER_LIMIT)

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
        return guest.after_script(ROOT, TASK, proxy=True)

    @staticmethod
    def after(text):
        return guest.after(text, proxy=True)

    def judge(self, config, lab_id, seen, plain):
        lab.judge(config, lab_id, seen, plain, labels=self.labels, window_allowances=self.window_allowances,
                  proxy_port=self.proxy_port)

    def window_verdicts(self, verdict):
        windows = {row['label']: row for row in (verdict or {}).get('windows', []) if row['label'] in self.labels}
        for label in self.judged_labels:
            window = windows.get(label)
            if window is not None:
                window['verdict'] = expectation_verdict(window, self.expectations[label])
        return windows

    def _proxy_connections(self, window, source_ip):
        proxy_endpoint = f'{lab_protocol.CLIENTS[4]}:{self.proxy_port}'
        prefix = source_ip + ':'
        connections = ((window or {}).get('flows') or {}).get('connections') or []
        return [row for row in connections if row.get('client') == proxy_endpoint
                and isinstance(row.get('server'), str) and row['server'].startswith(prefix)]

    def cross_check(self, checks, windows, seen, measured):
        findings = []

        def passed(check_id):
            row = checks.get(check_id)
            return row is not None and row.get('result') == 'PASS'

        for phase in ('baseline', 'recovery'):
            window = windows.get(phase)
            if not window or window['observer_reasons']:
                continue
            if not lab.direct_seen(window, self.expectations[phase]):
                findings.append('control-flow-missing:' + phase)
            if not any(isinstance(row, dict) and row.get('name') == self.control_name(seen['plain'], phase)
                       and row.get('transport') == 'udp' for row in seen.get('dns_rows', [])):
                findings.append('control-dns-missing:' + phase + ':udp')

        strict = windows.get('strict')
        if strict and not strict['observer_reasons']:
            if passed('strict.proxy') and not strict['categories'].get('tunnel'):
                findings.append('disagree:strict.proxy')

        sharing = windows.get('sharing-strict')
        if sharing and not sharing['observer_reasons']:
            if passed('sharing.strict.host'):
                peer_conns = self._proxy_connections(sharing, lab_protocol.LAN_PEER)
                if not sharing['categories'].get('tunnel') or not any(c.get('syn_ack') is True for c in peer_conns):
                    findings.append('disagree:sharing.strict.host')
            if passed('sharing.strict.server'):
                server_conns = self._proxy_connections(sharing, lab_protocol.GATEWAYS[4])
                if (not any(c.get('syn') is True for c in server_conns)
                        or any(c.get('syn_ack') is True for c in server_conns)):
                    findings.append('disagree:sharing.strict.server')

        lockdown = windows.get('lockdown')
        if lockdown and not lockdown['observer_reasons']:
            if passed('lockdown.proxy') and not lockdown['categories'].get('tunnel'):
                findings.append('disagree:lockdown.proxy')
            peer_conns = self._proxy_connections(lockdown, lab_protocol.LAN_PEER)
            if passed('lockdown.host-blocked'):
                if not any(c.get('syn') is True and c.get('syn_ack') is False for c in peer_conns):
                    findings.append('disagree:lockdown.host-blocked')
            if passed('lockdown.host-allowed'):
                if not any(c.get('syn_ack') is True for c in peer_conns):
                    findings.append('disagree:lockdown.host-allowed')

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
        section['unverified'] = list(dict.fromkeys(section['unverified']))
        section['accepted'] = not section['findings'] and not section['unverified']
        section.update(proxy_port=self.proxy_port, lab_actions=measured.get('lab_actions', 0),
                       full_matrix='UNVERIFIED')
        return section


def _profile_of(config):
    return ProxyProfile(proxy_port=config['proxy']['proxy_port'])


def preflight(config, *, dry_run=False):
    validate(config)
    return _profile_of(config).preflight(config, dry_run=dry_run)


def run(config, **options):
    validate(config)
    return lab.run_guest_suite(config, profile=_profile_of(config), **options)
