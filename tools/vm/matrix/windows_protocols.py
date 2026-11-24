"""Windows Protocols and Extensions matrix on the isolated lab wire (stage 10f)."""
from . import lab_protocol, l3_requests, windows_list_guest as guest, windows_list_lab as lab, windows_results
from .catalog import digest, read_catalog
from .config import PROTOCOLS_CATALOG, PROTOCOLS_SUITE
from .l3_summary import TARGET_FLOW, expectation_verdict

SCHEMA = 'rosetun.matrix.execution.windows.v9'
PREFIX = 'rosetun.windows-protocols.'
SUMMARY_SCHEMA = 'rosetun.matrix.windows-protocols-summary.v1'
ROOT = r'C:\rosetun-protocols'
TASK = 'RosetunProtocolsRunner'
ENTRY = 'run-windows-protocols.ps1'
SCRIPTS = ('lib.ps1', ENTRY, 'RosetunListResults.psm1', 'protocols-checks.tsv')
BINARIES = guest.BINARIES + ('xray.exe',)
MAX_RUNNER_SECONDS = 1800
COLLECT_LIMITS = dict(plan=24000, events=24000, report=28000, status=2000, helper_tail=3000)
COLLECT_ANSWER_LIMIT = 96 * 1024
STATUS_ANSWER_LIMIT = 48 * 1024
LABELS = ('baseline', 'hysteria2', 'tuic', 'anytls', 'xray-reality', 'xray-xhttp', 'second-node', 'dhcp', 'recovery')
JUDGED_LABELS = LABELS[1:-1]
LISTED_LABELS = ('baseline', 'recovery')
DHCP_ALLOWANCES = ('dhcpv4', 'arp-probe', 'arp-announcement')


def _check_sha256(value, label):
    if type(value) is not str or len(value) != 64 or value.strip('0123456789abcdef'):
        raise ValueError(f'{label} hash must be 64 lowercase hex digits')


def validate(config):
    if not isinstance(config, dict) or config.get('schema') != SCHEMA or config.get('suite') != PROTOCOLS_SUITE:
        raise ValueError('unsupported Windows Protocols configuration')
    if (any(key in config for key in ('list', 'failure', 'lockdown', 'proxy', 'lan', 'upgrade', 'twohop'))
            or not isinstance(config.get('protocols'), dict)):
        raise ValueError('invalid Protocols block')
    common = dict(config)
    block = dict(common.pop('protocols'))
    xray = block.pop('xray', None)
    if type(xray) is not str or not xray:
        raise ValueError('invalid xray file path')
    _check_sha256(block.pop('xray_sha256', None), 'xray')
    lab_block = dict(common.get('lab') or {})
    if not isinstance(common.get('lab'), dict):
        raise ValueError('invalid lab block')
    _check_sha256(lab_block.pop('xray_sha256', None), 'lab xray')
    _check_sha256(lab_block.pop('proto_cert_sha256', None), 'lab proto_cert')
    common.update(schema=lab.SCHEMA, suite=lab.SUITE, list=block, lab=lab_block)
    lab.validate(common, max_runner_seconds=MAX_RUNNER_SECONDS)
    return config


def _https_count(seen, source):
    total = 0
    for row in seen.get('https', []):
        if isinstance(row, dict) and row.get('kind') == 'counts':
            for entry in row.get('counts', []):
                if isinstance(entry, dict) and entry.get('source') == source and isinstance(entry.get('count'), int):
                    total += entry['count']
    return total


class ProtocolsProfile:
    SUMMARY_SCHEMA = SUMMARY_SCHEMA
    PREFIX = PREFIX
    ROOT = ROOT
    labels = LABELS
    judged_labels = JUDGED_LABELS
    listed_labels = LISTED_LABELS
    validate = staticmethod(validate)

    def __init__(self):
        self.catalog = read_catalog(PROTOCOLS_CATALOG)
        self.checks = tuple(row['id'] for row in self.catalog)
        self.expectations = {
            'baseline': {TARGET_FLOW: 1},
            'hysteria2': {},
            'tuic': {},
            'anytls': {},
            'xray-reality': {},
            'xray-xhttp': {},
            'second-node': {},
            'dhcp': {},
            'recovery': {TARGET_FLOW: 1},
        }
        self.window_allowances = {'dhcp': DHCP_ALLOWANCES}

    @staticmethod
    def window_tunnel_endpoints(node_port):
        gw = lab_protocol.GATEWAYS[4]
        return {
            'hysteria2': ((gw, 'udp', lab_protocol.HYSTERIA2_PORT),),
            'tuic': ((gw, 'udp', lab_protocol.TUIC_PORT),),
            'anytls': ((gw, 'tcp', lab_protocol.ANYTLS_PORT),),
            'xray-reality': ((gw, 'tcp', lab_protocol.REALITY_PORT), (gw, 'tcp', node_port)),
            'xray-xhttp': ((gw, 'tcp', lab_protocol.XHTTP_PORT), (gw, 'tcp', node_port)),
            'second-node': ((gw, 'tcp', node_port), (gw, 'tcp', lab_protocol.SECOND_NODE_PORT)),
            'dhcp': ((gw, 'tcp', node_port),),
        }

    @staticmethod
    def extended_fixtures(config):
        return dict(
            protocols=True,
            second_node=True,
            xray=True,
            dhcp=True,
            xray_sha256=config['lab']['xray_sha256'],
            proto_cert_sha256=config['lab']['proto_cert_sha256'],
        )

    def preflight(self, config, *, dry_run=False):
        plan = lab.preflight(config, dry_run=dry_run, profile=self)
        plan['catalog_digest'] = digest(self.catalog)
        plan['actions'][-3] = 'verify the evidence disk and the ' + ', '.join(self.labels) + ' windows'
        plan['limitations'] = [
            'Windows Protocols and Extensions matrix on the isolated lab wire (Hysteria2, TUIC v5, AnyTLS, '
            'VLESS REALITY + Vision, VLESS XHTTP + REALITY, second node, DHCPv4 under kill switch)',
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
            catalog=self.catalog,
            request=request,
            protocols=dict(
                hysteria2_port=lab_protocol.HYSTERIA2_PORT,
                tuic_port=lab_protocol.TUIC_PORT,
                anytls_port=lab_protocol.ANYTLS_PORT,
                reality_port=lab_protocol.REALITY_PORT,
                xhttp_port=lab_protocol.XHTTP_PORT,
                second_node_port=lab_protocol.SECOND_NODE_PORT,
                password=lab_protocol.PROTO_PASSWORD,
                sni=lab_protocol.PROTO_SNI,
                tuic_uuid=lab_protocol.TUIC_UUID,
                reality_uuid=lab_protocol.REALITY_UUID,
                reality_short_id=lab_protocol.REALITY_SHORT_ID,
                reality_sni=lab_protocol.REALITY_SNI,
                xhttp_path=lab_protocol.XHTTP_PATH,
                primary_egress=lab_protocol.EGRESS,
                second_node_egress=lab_protocol.SECOND_NODE_EGRESS,
            ),
        )
        plan['addresses'].update(
            gateway4=lab_protocol.GATEWAYS[4],
            primary_egress=lab_protocol.EGRESS,
            second_node_egress=lab_protocol.SECOND_NODE_EGRESS,
        )
        return plan

    def validate_plan(self, plan):
        keys = {'schema', 'suite', 'identity', 'profile', 'policy', 'catalog', 'catalog_digest'}
        if (not isinstance(plan, dict) or set(plan) != keys or plan['schema'] != PREFIX + 'plan.v1'
                or plan['suite'] != PROTOCOLS_SUITE or plan['profile'] != 'exploratory'
                or plan['policy'] != {'mode': 'exploratory'} or plan['catalog'] != self.catalog
                or plan['catalog_digest'] != digest(self.catalog)):
            raise ValueError('invalid Protocols plan')
        identity = plan['identity']
        if (not isinstance(identity, dict) or set(identity) != {'run_id', 'vm_id', 'boot_id'}
                or not all(isinstance(value, str) and value for value in identity.values())):
            raise ValueError('invalid Protocols identity')
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
                                   max_checks=32, max_notes=64, max_markers=24, allow_action=True,
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
        return guest.after_script(ROOT, TASK, protocols=True)

    @staticmethod
    def after(text):
        return guest.after(text, protocols=True)

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
            ('hysteria2', 'proto.hysteria2'),
            ('tuic', 'proto.tuic'),
            ('anytls', 'proto.anytls'),
            ('xray-reality', 'xray.reality.auto'),
            ('xray-xhttp', 'xray.xhttp.auto'),
            ('second-node', 'second-node.rule-exit'),
            ('dhcp', 'dhcp.renew-under-kill-switch'),
        ):
            window = windows.get(label)
            if window and not window['observer_reasons']:
                if passed(check_id) and not window['categories'].get('tunnel'):
                    findings.append('disagree:' + check_id)

        dhcp_window = windows.get('dhcp')
        if dhcp_window and not dhcp_window['observer_reasons']:
            allowed = dhcp_window['categories'].get('allowed') or {}
            if passed('dhcp.renew-under-kill-switch') and not allowed.get('dhcpv4'):
                findings.append('disagree:dhcp.renew-under-kill-switch')

        if passed('second-node.rule-exit') and _https_count(seen, lab_protocol.SECOND_NODE_EGRESS) <= 0:
            findings.append('disagree:second-node.egress')

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
        section.update(lab_actions=measured.get('lab_actions', 0), full_matrix='UNVERIFIED')
        return section


def preflight(config, *, dry_run=False):
    validate(config)
    return ProtocolsProfile().preflight(config, dry_run=dry_run)


def run(config, **options):
    validate(config)
    return lab.run_guest_suite(config, profile=ProtocolsProfile(), **options)
