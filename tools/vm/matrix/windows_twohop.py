"""Windows Two-Hop Proxy Chain matrix on the isolated lab wire (stage 10f)."""
from . import lab_protocol, l3_requests, windows_list_guest as guest, windows_list_lab as lab, windows_results
from .catalog import digest
from .config import TWOHOP_CATALOG, TWOHOP_SUITE, twohop_catalog
from .l3_summary import TARGET_FLOW, expectation_verdict

SCHEMA = 'rosetun.matrix.execution.windows.v10'
PREFIX = 'rosetun.windows-twohop.'
SUMMARY_SCHEMA = 'rosetun.matrix.windows-twohop-summary.v1'
ROOT = r'C:\rosetun-twohop'
TASK = 'RosetunTwoHopRunner'
ENTRY = 'run-windows-twohop.ps1'
SCRIPTS = ('lib.ps1', ENTRY, 'RosetunListResults.psm1', 'two-hop-scenarios.tsv')
BINARIES = guest.BINARIES + ('xray.exe',)
MAX_RUNNER_SECONDS = 1800
COLLECT_LIMITS = dict(plan=36000, events=40000, report=40000, status=2000, helper_tail=3000)
COLLECT_ANSWER_LIMIT = 144 * 1024
STATUS_ANSWER_LIMIT = 64 * 1024
LABELS = ('baseline', 'twohop-tun', 'twohop-proxy', 'recovery')
JUDGED_LABELS = ('twohop-tun', 'twohop-proxy')
LISTED_LABELS = ('baseline', 'recovery')
DOMAIN_B = 'proxy-b.lab.test'


def _check_sha256(value, label):
    if type(value) is not str or len(value) != 64 or value.strip('0123456789abcdef'):
        raise ValueError(f'{label} hash must be 64 lowercase hex digits')


def validate(config):
    if not isinstance(config, dict) or config.get('schema') != SCHEMA or config.get('suite') != TWOHOP_SUITE:
        raise ValueError('unsupported Windows Two-Hop configuration')
    if (any(key in config for key in ('list', 'failure', 'lockdown', 'proxy', 'lan', 'upgrade', 'protocols'))
            or not isinstance(config.get('twohop'), dict)):
        raise ValueError('invalid Two-Hop block')
    common = dict(config)
    block = dict(common.pop('twohop'))
    proxy_port = block.pop('proxy_port', None)
    if type(proxy_port) is not int or not 1024 <= proxy_port <= 65535:
        raise ValueError('invalid Windows Two-Hop proxy_port')
    xray = block.pop('xray', None)
    if type(xray) is not str or not xray:
        raise ValueError('invalid xray file path')
    _check_sha256(block.pop('xray_sha256', None), 'xray')
    lab_block = dict(common.get('lab') or {})
    if not isinstance(common.get('lab'), dict):
        raise ValueError('invalid lab block')
    for key in ('xray_sha256', 'proto_cert_sha256', 'twohop_cert_sha256', 'twohop_untrusted_cert_sha256'):
        _check_sha256(lab_block.pop(key, None), 'lab ' + key)
    common.update(schema=lab.SCHEMA, suite=lab.SUITE, list=block, lab=lab_block)
    lab.validate(common, max_runner_seconds=MAX_RUNNER_SECONDS)
    if proxy_port == config['lab']['tunnel']['node_port']:
        raise ValueError('proxy_port must differ from lab tunnel node_port')
    return config


def _https_count(seen, source):
    total = 0
    for row in seen.get('https', []):
        if isinstance(row, dict) and row.get('kind') == 'counts':
            for entry in row.get('counts', []):
                if isinstance(entry, dict) and entry.get('source') == source and isinstance(entry.get('count'), int):
                    total += entry['count']
    return total


class TwoHopProfile:
    SUMMARY_SCHEMA = SUMMARY_SCHEMA
    PREFIX = PREFIX
    ROOT = ROOT
    labels = LABELS
    judged_labels = JUDGED_LABELS
    listed_labels = LISTED_LABELS
    planned_session_rotations = 20
    validate = staticmethod(validate)

    def __init__(self, proxy_port=10808):
        self.proxy_port = proxy_port
        self.catalog = twohop_catalog(TWOHOP_CATALOG)
        self.checks = tuple(row['id'] for row in self.catalog)
        self.expectations = {
            'baseline': {TARGET_FLOW: 1},
            'twohop-tun': {},
            'twohop-proxy': {},
            'recovery': {TARGET_FLOW: 1},
        }
        self.window_allowances = {}

    @staticmethod
    def window_tunnel_endpoints(node_port):
        gw = lab_protocol.GATEWAYS[4]
        endpoints = (
            (gw, 'tcp', node_port),
            (gw, 'tcp', lab_protocol.SECOND_NODE_PORT),
            (gw, 'tcp', lab_protocol.REALITY_PORT),
        )
        return {'twohop-tun': endpoints, 'twohop-proxy': endpoints}

    @staticmethod
    def extended_fixtures(config):
        return dict(
            second_node=True,
            xray=True,
            two_hop=True,
            xray_sha256=config['lab']['xray_sha256'],
            proto_cert_sha256=config['lab']['proto_cert_sha256'],
            twohop_cert_sha256=config['lab']['twohop_cert_sha256'],
            twohop_untrusted_cert_sha256=config['lab']['twohop_untrusted_cert_sha256'],
        )

    def preflight(self, config, *, dry_run=False):
        plan = lab.preflight(config, dry_run=dry_run, profile=self)
        plan['proxy_port'] = self.proxy_port
        plan['catalog_digest'] = digest(self.catalog)
        plan['actions'][-3] = 'verify the evidence disk and the ' + ', '.join(self.labels) + ' windows'
        plan['limitations'] = [
            'Windows Two-Hop Proxy Chain matrix on the isolated lab wire (all 40 scenarios across TUN and System Proxy)',
            'no release acceptance or Hyper-V parity',
            'bounded capture on one Windows guest and one lab guest',
        ]
        return plan

    def plan_document(self, lab_id, windows, plain, port, files):
        plan = guest.plan_document(lab_id, windows, plain, port, files, labels=self.labels, binaries=BINARIES)
        plan.pop('config')
        request = l3_requests.template()
        request['node']['port'] = port
        request['rule_set']['rules'] = []
        plan.update(
            schema=PREFIX + 'job.v1',
            proxy_port=self.proxy_port,
            catalog=self.catalog,
            request=request,
            twohop=dict(
                second_node_port=lab_protocol.SECOND_NODE_PORT,
                reality_port=lab_protocol.REALITY_PORT,
                reality_uuid=lab_protocol.REALITY_UUID,
                reality_short_id=lab_protocol.REALITY_SHORT_ID,
                reality_sni=lab_protocol.REALITY_SNI,
                b4=lab_protocol.TWOHOP_B[4],
                b6=lab_protocol.TWOHOP_B[6],
                lan_peer=lab_protocol.LAN_PEER,
                ports=dict(lab_protocol.TWOHOP_PORTS),
                username=lab_protocol.TWOHOP_USER,
                password=lab_protocol.TWOHOP_PASSWORD,
                domain_b=DOMAIN_B,
                primary_egress=lab_protocol.EGRESS,
                second_node_egress=lab_protocol.SECOND_NODE_EGRESS,
                second_node_egress6=lab_protocol.SECOND_NODE_EGRESS6,
            ),
        )
        plan['addresses'].update(
            gateway4=lab_protocol.GATEWAYS[4],
            lan_peer=lab_protocol.LAN_PEER,
            b4=lab_protocol.TWOHOP_B[4],
            b6=lab_protocol.TWOHOP_B[6],
            primary_egress=lab_protocol.EGRESS,
            second_node_egress=lab_protocol.SECOND_NODE_EGRESS,
            second_node_egress6=lab_protocol.SECOND_NODE_EGRESS6,
        )
        return plan

    def validate_plan(self, plan):
        keys = {'schema', 'suite', 'identity', 'profile', 'policy', 'catalog', 'catalog_digest'}
        if (not isinstance(plan, dict) or set(plan) != keys or plan['schema'] != PREFIX + 'plan.v1'
                or plan['suite'] != TWOHOP_SUITE or plan['profile'] != 'exploratory'
                or plan['policy'] != {'mode': 'exploratory'} or plan['catalog'] != self.catalog
                or plan['catalog_digest'] != digest(self.catalog)):
            raise ValueError('invalid Two-Hop plan')
        identity = plan['identity']
        if (not isinstance(identity, dict) or set(identity) != {'run_id', 'vm_id', 'boot_id'}
                or not all(isinstance(value, str) and value for value in identity.values())):
            raise ValueError('invalid Two-Hop identity')
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
        return guest.after_script(ROOT, TASK, twohop=True)

    @staticmethod
    def after(text):
        return guest.after(text, twohop=True)

    def judge(self, config, lab_id, seen, plain):
        node_port = config['lab']['tunnel']['node_port']
        lab.judge(
            config,
            lab_id,
            seen,
            plain,
            labels=self.labels,
            window_allowances=self.window_allowances,
            window_tunnel_endpoints=self.window_tunnel_endpoints(node_port),
            proxy_port=self.proxy_port,
        )

    def window_verdicts(self, verdict):
        windows = {row['label']: row for row in (verdict or {}).get('windows', []) if row['label'] in self.labels}
        for label in self.judged_labels:
            window = windows.get(label)
            if window is not None:
                window['verdict'] = expectation_verdict(window, self.expectations[label])
        return windows

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

        for label, check_id in (
            ('twohop-tun', 'two-hop.positive.http.ipv4:tun'),
            ('twohop-proxy', 'two-hop.positive.http.ipv4:system-proxy'),
        ):
            window = windows.get(label)
            if window and not window['observer_reasons']:
                if passed(check_id) and not window['categories'].get('tunnel'):
                    findings.append('disagree:' + check_id)

        if (passed('two-hop.positive.http.ipv4:tun') or passed('two-hop.positive.http.ipv4:system-proxy')):
            if _https_count(seen, lab_protocol.TWOHOP_B[4]) <= 0:
                findings.append('disagree:two-hop.target-b')

        for row in seen.get('dns_rows', []):
            if isinstance(row, dict) and str(row.get('name', '')).rstrip('.').casefold() == DOMAIN_B:
                findings.append('disagree:two-hop.domain-b-dns')
                break

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
    return TwoHopProfile(proxy_port=config['twohop']['proxy_port'])


def preflight(config, *, dry_run=False):
    validate(config)
    return _profile_of(config).preflight(config, dry_run=dry_run)


def run(config, **options):
    validate(config)
    return lab.run_guest_suite(config, profile=_profile_of(config), **options)
