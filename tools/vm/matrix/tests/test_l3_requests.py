"""The L3 lab requests: documentation values only, shaped like the PowerShell ones."""

import inspect
import ipaddress
import json
from pathlib import Path
import re
import tempfile
import unittest

from tools.vm.matrix import l3_requests as req

ROOT = Path(__file__).resolve().parents[4]
PSM1 = ROOT / 'tools/vm/linux/RosetunLinuxVm.psm1'
OWNER = ROOT / 'tools/vm/windows/request-local.json'
# Fields the PowerShell functions add to the template; everything else must
# already exist in it.
ADDED = {'settings.allow_lan', 'settings.private_networks', 'settings.auto_reconnect', 'settings.verbose_log_until',
         'rule_set.rules[].matcher.process', 'rule_set.rules[].matcher.process.name'}
# Value-bearing paths of the owner's request; none of their values may be reused.
VALUE_PATHS = ('selection.subscription', 'selection.node', 'node.id', 'node.name', 'node.server',
               'node.outbound.shadowsocks.password', 'settings.dns.server',
               'settings.dns.server_name', 'settings.tun.ipv4',
               'rule_set.rules[].matcher.domain.exact')


def paths(value, prefix=''):
    """Every key path with list items folded into '[]'."""
    result = set()
    if type(value) is dict:
        for key, item in value.items():
            path = prefix + '.' + key if prefix else key
            result.add(path)
            result |= paths(item, path)
    elif type(value) is list:
        for item in value:
            result |= paths(item, prefix + '[]')
    return result


def leaves(value, prefix=''):
    if type(value) is dict:
        for key, item in value.items():
            yield from leaves(item, prefix + '.' + key if prefix else key)
    elif type(value) is list:
        for item in value:
            yield from leaves(item, prefix + '[]')
    else:
        yield prefix, value


def flat(value):
    """Path (list items by index) -> leaf, for exact comparison of two requests."""
    if type(value) is dict:
        return {k + ('.' + p if p else ''): v for k, item in value.items() for p, v in flat(item).items()}
    if type(value) is list:
        return {f'[{i}]' + ('.' + p if p else ''): v for i, item in enumerate(value)
                for p, v in flat(item).items()}
    return {'': value}


def differences(a, b):
    left, right = flat(a), flat(b)
    return {k for k in left.keys() | right.keys() if left.get(k, KeyError) != right.get(k, KeyError)}


class RequestTests(unittest.TestCase):
    def setUp(self):
        self.files = req.render_all()
        self.requests = {n: json.loads(b) for n, b in self.files.items()}

    def test_exactly_the_six_files_in_the_order_the_job_uses(self):
        self.assertEqual(['request-kill-switch.json', 'request-lan.json', 'request-lan-private.json',
                          'request-dns-lock.json', 'request-program-direct.json', 'request-program-proxy.json'], list(self.files))

    def test_variants_equal_the_tables_of_the_powershell_functions(self):
        text = PSM1.read_text(encoding='utf-8')
        found = dict(re.findall(r"'(request-[a-z-]+\.json)'\s*=\s*@\{([^}]*)\}", text))
        connect = {n: v for n, v in found.items() if 'kill_switch' in v and 'allow_lan' in v}
        program = {n: v for n, v in found.items() if 'default_target' in v}
        parsed = {n: tuple(v == '$true' for v in re.findall(r'=\s*(\$true|\$false)', body))
                  for n, body in connect.items()}
        self.assertEqual(req.CONNECT, parsed)
        parsed = {n: tuple(re.findall(r"=\s*'([a-z]+)'", body)) for n, body in program.items()}
        self.assertEqual(req.PROGRAM, parsed)
        self.assertIn('4102444800', text)
        self.assertEqual(4102444800, req.VERBOSE_LOG_UNTIL)
        self.assertIn("name = 'curl'", text)

    def test_connect_requests_differ_exactly_by_the_powershell_settings(self):
        r = self.requests
        ks, lan, private, dns = (r[n] for n in ('request-kill-switch.json', 'request-lan.json',
                                                'request-lan-private.json', 'request-dns-lock.json'))
        self.assertEqual({'settings.allow_lan'}, differences(ks, lan))
        self.assertEqual({'settings.private_networks'}, differences(lan, private))
        self.assertEqual({'settings.allow_lan', 'settings.private_networks'}, differences(ks, private))
        self.assertEqual({'settings.kill_switch'}, differences(ks, dns))
        self.assertEqual({'settings.allow_lan', 'settings.kill_switch'}, differences(lan, dns))
        for request in (ks, lan, private, dns):
            self.assertIs(True, request['settings']['auto_reconnect'])
            self.assertNotIn('verbose_log_until', request['settings'])
        for request, expected in ((ks, (True, False, False)), (lan, (True, True, False)),
                                  (private, (True, True, True)), (dns, (False, False, False))):
            self.assertEqual(expected, tuple(request['settings'][k] for k in
                                             ('kill_switch', 'allow_lan', 'private_networks')))

    def test_program_requests_differ_from_kill_switch_by_rule_set_and_verbose_log(self):
        r = self.requests
        ks = r['request-kill-switch.json']
        for name, (default_target, target) in req.PROGRAM.items():
            request = r[name]
            self.assertEqual({k for k in differences(ks, request)
                              if not k.startswith('rule_set')}, {'settings.verbose_log_until'})
            self.assertEqual(dict(id='l3-program', name='L3 rules by program', default_target=default_target,
                                  rules=[dict(id='l3-curl', enabled=True, target=target,
                                              matcher=dict(process=dict(name='curl')))]),
                             request['rule_set'])
            self.assertEqual(4102444800, request['settings']['verbose_log_until'])
            self.assertEqual(ks['settings']['kill_switch'], request['settings']['kill_switch'])
            self.assertEqual(ks['settings']['allow_lan'], request['settings']['allow_lan'])
        self.assertEqual({'rule_set.default_target', 'rule_set.rules.[0].target'},
                         differences(r['request-program-direct.json'], r['request-program-proxy.json']))

    def test_node_address_and_port_are_the_same_everywhere(self):
        for request in self.requests.values():
            self.assertEqual(('192.0.2.1', 8388), (request['node']['server'], request['node']['port']))

    def test_every_address_in_every_output_is_documentation(self):
        nets = [ipaddress.ip_network(n) for n in
                ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32')]
        seen = 0
        for request in self.requests.values():
            for _, leaf in leaves(request):
                if type(leaf) is not str:
                    continue
                try:
                    address = ipaddress.ip_interface(leaf).ip
                except ValueError:
                    continue
                seen += 1
                self.assertTrue(any(address in net for net in nets), leaf)
        self.assertGreaterEqual(seen, 3 * len(self.requests))

    def test_names_are_reserved_test_domains(self):
        for request in self.requests.values():
            self.assertEqual('lab-node.test', request['node']['name'])
            self.assertEqual('doh.lab.test', request['settings']['dns']['server_name'])
            self.assertEqual('lab', request['selection']['subscription'])
            self.assertEqual('203.0.113.3', request['settings']['dns']['server'])
            self.assertEqual('aes-128-gcm', request['node']['outbound']['shadowsocks']['method'])
        domains = [v for p, v in leaves(self.requests['request-kill-switch.json'])
                   if p == 'rule_set.rules[].matcher.domain.exact']
        self.assertEqual(['direct.lab.test', 'proxy.lab.test'], domains)

    def test_no_field_outside_the_template_except_those_powershell_adds(self):
        known = paths(req.template())
        for name, request in self.requests.items():
            extra = paths(request) - known
            self.assertTrue(extra <= ADDED, (name, extra - ADDED))
        every = set().union(*(paths(r) for r in self.requests.values()))
        self.assertEqual(ADDED - {'rule_set.rules[].matcher.process', 'rule_set.rules[].matcher.process.name'},
                         {p for p in every - known if not p.startswith('rule_set')})

    def test_template_has_the_structure_of_the_owner_request_and_none_of_its_values(self):
        if not OWNER.is_file():
            self.skipTest('the owner request fixture is not in this checkout')
        owner = json.loads(OWNER.read_bytes())
        self.assertEqual(paths(owner), paths(req.template()))
        taken = {v for p, v in leaves(owner) if p in VALUE_PATHS}
        self.assertTrue(taken)
        for request in self.requests.values():
            self.assertFalse(taken & {v for _, v in leaves(request)})
        self.assertFalse(taken & {v for _, v in leaves(req.template())})

    def test_generator_takes_no_request_and_no_path(self):
        self.assertEqual(['server', 'port'], list(inspect.signature(req.render_all).parameters))

    def test_only_documentation_ipv4_and_a_real_port_are_accepted(self):
        for server in ('10.0.0.1', '172.30.48.1', '8.8.8.8', '2001:db8::1', 'node.example', '', None, 3):
            with self.assertRaises(ValueError, msg=repr(server)):
                req.render_all(server, 8388)
        for port in (0, 65536, -1, True, '8388', None):
            with self.assertRaises(ValueError, msg=repr(port)):
                req.render_all('192.0.2.1', port)
        other = {n: json.loads(b) for n, b in req.render_all('198.51.100.7', 9000).items()}
        for request in other.values():
            self.assertEqual(('198.51.100.7', 9000), (request['node']['server'], request['node']['port']))

    def test_output_is_ascii_lf_deterministic_and_never_overwritten(self):
        for data in self.files.values():
            data.decode('ascii')
            self.assertTrue(data.endswith(b'}\n'))
            self.assertNotIn(b'\r', data)
        self.assertEqual(self.files, req.render_all())
        with tempfile.TemporaryDirectory() as temp:
            req.write_all(temp)
            req.write_all(temp)
            self.assertEqual(self.files, {n: (Path(temp) / n).read_bytes() for n in req.NAMES})
            (Path(temp) / 'request-lan.json').write_bytes(b'{}\n')
            with self.assertRaises(ValueError):
                req.write_all(temp)
