"""Windows Local Network (LAN) matrix on the isolated lab wire (stage 10d)."""
from . import lab_protocol, l3_requests, windows_list_guest as guest, windows_list_lab as lab, windows_results
from .catalog import digest, read_catalog
from .config import LAN_CATALOG, LAN_SUITE
from .l3_summary import TARGET_FLOW, expectation_verdict

SCHEMA = 'rosetun.matrix.execution.windows.v7'
PREFIX = 'rosetun.windows-lan.'
SUMMARY_SCHEMA = 'rosetun.matrix.windows-lan-summary.v1'
ROOT = r'C:\rosetun-lan'
TASK = 'RosetunLanRunner'
ENTRY = 'run-windows-lan.ps1'
SCRIPTS = ('lib.ps1', ENTRY, 'RosetunListResults.psm1', 'lan-core.tsv')
MAX_RUNNER_SECONDS = 1800
COLLECT_LIMITS = dict(plan=32000, events=32000, report=36000, status=2000, helper_tail=3000)
COLLECT_ANSWER_LIMIT = 128 * 1024
STATUS_ANSWER_LIMIT = 64 * 1024
LABELS = ('baseline', 'lan-on', 'address-change', 'lan-rule', 'lan-private', 'lan-off',
          'switch', 'lan-server', 'lan-server-private', 'lan-reopen', 'recovery')
JUDGED_LABELS = LABELS[1:-1]
LISTED_LABELS = ('baseline', 'recovery')
TUNNEL_ADDRESSES = (lab_protocol.GATEWAYS[4], lab_protocol.ROUTED_NODE)
PEER_LISTENER_FLOW = ('tcp', 'other', f'{lab_protocol.LAN_PEER}:{lab_protocol.LAN_LISTENER_PORT}')
PEER_ECHO_FLOW = ('tcp', 'other', f'{lab_protocol.LAN_PEER}:{lab_protocol.LAN_ECHO_PORT}')
SERVER_LISTENER_FLOW = ('tcp', 'other', f'{lab_protocol.GATEWAYS[4]}:{lab_protocol.LAN_LISTENER_PORT}')
PRIVATE_BEHIND_FLOW = ('tcp', 'other', f'{lab_protocol.PRIVATE_BEHIND_ROUTER}:80')
EXTRA_PEER = '198.51.100.20'


def validate(config):
    if not isinstance(config, dict) or config.get('schema') != SCHEMA or config.get('suite') != LAN_SUITE:
        raise ValueError('unsupported Windows LAN configuration')
    if any(key in config for key in ('list', 'failure', 'lockdown', 'proxy')) or not isinstance(config.get('lan'), dict):
        raise ValueError('invalid LAN block')
    common = dict(config)
    block = dict(common.pop('lan'))
    long_session = block.pop('long_session_seconds', None)
    if type(long_session) is not int or not 10 <= long_session <= 900:
        raise ValueError('invalid Windows LAN long_session_seconds')
    common.update(schema=lab.SCHEMA, suite=lab.SUITE, list=block)
    lab.validate(common, max_runner_seconds=MAX_RUNNER_SECONDS)
    if long_session >= block['runner_seconds']:
        raise ValueError('long_session_seconds must be smaller than runner_seconds')
    return config


def _flow_opened(window, target):
    protocol, kind, server = target
    flows = (window or {}).get('direct', {}).get('flows', [])
    return any(flow['protocol'] == protocol and flow['kind'] == kind and flow['server'] == server
               and flow['opened'] is True for flow in flows)


class LanProfile:
    SUMMARY_SCHEMA = SUMMARY_SCHEMA
    PREFIX = PREFIX
    ROOT = ROOT
    lan_fixtures = True
    labels = LABELS
    judged_labels = JUDGED_LABELS
    listed_labels = LISTED_LABELS
    validate = staticmethod(validate)

    def __init__(self, long_session_seconds=600):
        self.long_session_seconds = long_session_seconds
        self.catalog = read_catalog(LAN_CATALOG)
        self.checks = tuple(row['id'] for row in self.catalog)
        self.expectations = {
            'baseline': {TARGET_FLOW: 1},
            'lan-on': {PEER_LISTENER_FLOW: 1, PEER_ECHO_FLOW: 1},
            'address-change': {},
            'lan-rule': {PEER_LISTENER_FLOW: 1},
            'lan-private': {PRIVATE_BEHIND_FLOW: 1},
            'lan-off': {},
            'switch': {},
            'lan-server': {PEER_LISTENER_FLOW: 1},
            'lan-server-private': {PRIVATE_BEHIND_FLOW: 1},
            'lan-reopen': {SERVER_LISTENER_FLOW: 1},
            'recovery': {TARGET_FLOW: 1},
        }
        self.window_allowances = {
            'lan-on': ('lan-peer-arp', 'lan-mdns', 'lan-ssdp', 'lan-broadcast'),
            'address-change': ('extra-address-arp',),
            'lan-rule': ('lan-peer-arp',),
            'switch': ('lan-broadcast',),
            'lan-server': ('lan-peer-arp',),
        }

    def preflight(self, config, *, dry_run=False):
        plan = lab.preflight(config, dry_run=dry_run, profile=self)
        plan['long_session_seconds'] = self.long_session_seconds
        plan['catalog_digest'] = digest(self.catalog)
        plan['actions'][-3] = 'verify the evidence disk and the ' + ', '.join(self.labels) + ' windows'
        plan['limitations'] = [
            'Windows Local Network matrix on the isolated lab wire (routed VPN node 203.0.113.10 and in-network node 192.0.2.1)',
            'no release acceptance or Hyper-V parity',
            'bounded capture on one Windows guest and one lab guest',
            'private-behind-router check uses blackholed 10.255.255.1 inside the isolated lab router',
        ]
        return plan

    def plan_document(self, lab_id, windows, plain, port, files):
        plan = guest.plan_document(lab_id, windows, plain, port, files, labels=self.labels)
        plan.pop('config')
        request = l3_requests.template()
        request['node']['server'] = lab_protocol.ROUTED_NODE
        request['node']['port'] = port
        request['rule_set']['rules'] = []
        plan.update(schema=PREFIX + 'job.v1', long_session_seconds=self.long_session_seconds,
                    catalog=self.catalog, request=request)
        plan['addresses'].update(
            gateway4=lab_protocol.GATEWAYS[4],
            lan_peer=lab_protocol.LAN_PEER,
            routed_node=lab_protocol.ROUTED_NODE,
            extra_address=lab_protocol.EXTRA_ADDRESS,
            extra_peer=EXTRA_PEER,
            private_behind_router=lab_protocol.PRIVATE_BEHIND_ROUTER,
            listener_port=lab_protocol.LAN_LISTENER_PORT,
            echo_port=lab_protocol.LAN_ECHO_PORT,
            hold_port=lab_protocol.LAN_HOLD_PORT,
            broadcast_port=lab_protocol.LAN_BROADCAST_PORT,
            mdns_group=lab_protocol.MDNS_GROUP,
            mdns_port=lab_protocol.MDNS_PORT,
            ssdp_group=lab_protocol.SSDP_GROUP,
            ssdp_port=lab_protocol.SSDP_PORT,
        )
        return plan

    def validate_plan(self, plan):
        keys = {'schema', 'suite', 'identity', 'profile', 'policy', 'catalog', 'catalog_digest'}
        if (not isinstance(plan, dict) or set(plan) != keys or plan['schema'] != PREFIX + 'plan.v1'
                or plan['suite'] != LAN_SUITE or plan['profile'] != 'exploratory'
                or plan['policy'] != {'mode': 'exploratory'} or plan['catalog'] != self.catalog
                or plan['catalog_digest'] != digest(self.catalog)):
            raise ValueError('invalid LAN plan')
        identity = plan['identity']
        if (not isinstance(identity, dict) or set(identity) != {'run_id', 'vm_id', 'boot_id'}
                or not all(isinstance(value, str) and value for value in identity.values())):
            raise ValueError('invalid LAN identity')
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
                                   max_checks=96, max_notes=64, max_markers=32, allow_action=True,
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
        return guest.after_script(ROOT, TASK, lan=True)

    @staticmethod
    def after(text):
        return guest.after(text, lan=True)

    def judge(self, config, lab_id, seen, plain):
        lab.judge(config, lab_id, seen, plain, labels=self.labels, window_allowances=self.window_allowances,
                  tunnel_addresses=TUNNEL_ADDRESSES)

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

        lan_on = windows.get('lan-on')
        if lan_on and not lan_on['observer_reasons']:
            allowed = lan_on['categories'].get('allowed') or {}
            if passed('lan-on.peer-tcp') and not lab.direct_seen(lan_on, {PEER_LISTENER_FLOW: 1}):
                findings.append('disagree:lan-on.peer-tcp')
            if passed('lan-on.long-session') and not lab.direct_seen(lan_on, {PEER_ECHO_FLOW: 1}):
                findings.append('disagree:lan-on.long-session')
            if passed('lan-on.mdns-physical') and not allowed.get('lan-mdns'):
                findings.append('disagree:lan-on.mdns-physical')
            if passed('lan-on.ssdp-physical') and not allowed.get('lan-ssdp'):
                findings.append('disagree:lan-on.ssdp-physical')
            if passed('lan-on.broadcast-reaches') and not allowed.get('lan-broadcast'):
                findings.append('disagree:lan-on.broadcast-reaches')

        addr = windows.get('address-change')
        if addr and not addr['observer_reasons']:
            allowed = addr['categories'].get('allowed') or {}
            if passed('address-change.follows-add') and not allowed.get('extra-address-arp'):
                findings.append('disagree:address-change.follows-add')

        lan_rule = windows.get('lan-rule')
        if lan_rule and not lan_rule['observer_reasons']:
            if passed('lan-rule.peer-direct') and not lab.direct_seen(lan_rule, {PEER_LISTENER_FLOW: 1}):
                findings.append('disagree:lan-rule.peer-direct')

        lan_private = windows.get('lan-private')
        if lan_private and not lan_private['observer_reasons']:
            if passed('lan-private.behind-router-direct') and not _flow_opened(lan_private, PRIVATE_BEHIND_FLOW):
                findings.append('disagree:lan-private.behind-router-direct')

        switch = windows.get('switch')
        if switch and not switch['observer_reasons']:
            allowed = switch['categories'].get('allowed') or {}
            if passed('switch.broadcast-reaches-again') and not allowed.get('lan-broadcast'):
                findings.append('disagree:switch.broadcast-reaches-again')

        lan_server = windows.get('lan-server')
        if lan_server and not lan_server['observer_reasons']:
            if passed('lan-server.peer-tcp') and not lab.direct_seen(lan_server, {PEER_LISTENER_FLOW: 1}):
                findings.append('disagree:lan-server.peer-tcp')
            if passed('lan-server.tunnel-egress') and not lan_server['categories'].get('tunnel'):
                findings.append('disagree:lan-server.tunnel-egress')

        lan_sp = windows.get('lan-server-private')
        if lan_sp and not lan_sp['observer_reasons']:
            if passed('lan-server-private.behind-router-direct') and not _flow_opened(lan_sp, PRIVATE_BEHIND_FLOW):
                findings.append('disagree:lan-server-private.behind-router-direct')
            if passed('lan-server-private.tunnel-egress') and not lan_sp['categories'].get('tunnel'):
                findings.append('disagree:lan-server-private.tunnel-egress')

        reopen = windows.get('lan-reopen')
        if reopen and not reopen['observer_reasons']:
            if passed('lan-reopen.server-direct') and not lab.direct_seen(reopen, {SERVER_LISTENER_FLOW: 1}):
                findings.append('disagree:lan-reopen.server-direct')

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
        section.update(long_session_seconds=self.long_session_seconds,
                       lab_actions=measured.get('lab_actions', 0),
                       full_matrix='UNVERIFIED')
        return section


def _profile_of(config):
    return LanProfile(long_session_seconds=config['lan']['long_session_seconds'])


def preflight(config, *, dry_run=False):
    validate(config)
    return _profile_of(config).preflight(config, dry_run=dry_run)


def run(config, **options):
    validate(config)
    return lab.run_guest_suite(config, profile=_profile_of(config), **options)
