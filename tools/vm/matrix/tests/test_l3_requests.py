"""The L3 lab requests: documentation values only, shaped like the PowerShell ones."""

import hashlib
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

    ORDINARY = {
        ('192.0.2.1', 8388): {
            'request-kill-switch.json': '0b9df6f0125a1fc52743f00948f6505b7cf869a3a034b2621edcf87587a28840',
            'request-lan.json': 'cf9495eab458baf6eafc7b7b4dcc3877a2529ad0f9b4df544a34d5deb5c244f4',
            'request-lan-private.json': '85958ebb174a92ecf7e4fe9172cb16e970fdc52898ed2acec0357c41fc55dd0b',
            'request-dns-lock.json': 'f0be6592211cb599cea7ea2bb911878531c4dfb3a2a1e1141410e6ace3e5addd',
            'request-program-direct.json': '0abb99be1dc45a82d247c06b4c9c3eb266d97b9bf7af427dfc97e4127f9f666c',
            'request-program-proxy.json': 'babfd7fb98c431d834643e35499ebb3eab8ce33be2fba615f8864562899c66ad'},
        ('198.51.100.7', 9000): {
            'request-kill-switch.json': '3116aab145a331179deff1d22d984b8cb6ab5fd8ea4473f4e528285c50485609',
            'request-lan.json': '841261d30f8cef535c6c7bab1072b8b5bfc963bac50e4dfcfbad491d2766060a',
            'request-lan-private.json': '73d0a82dfc2d994dbfa0daf0c74892faf3eb5bc38e61cc7382cae8ac814ba8b2',
            'request-dns-lock.json': '6970546469a4209f0fe1ab8202f4c1be431f0c7175b92c8d3213eda0874bdc10',
            'request-program-direct.json': '4009eae89eb6e5077ce957ecc205c2c27591d713823ea08283acea9025f9b43f',
            'request-program-proxy.json': '6ec2dc1fb521dc07694e0b265c9b341b37d343478709d8b680fc82b1d40e5c5b'}}

    def test_without_the_flag_the_bytes_are_those_of_the_generator_before_the_flag_existed(self):
        # The digests were taken from the generator at the commit before `diagnostic` was added.
        for (server, port), expected in self.ORDINARY.items():
            for rendered in (req.render_all(server, port), req.render_all(server, port, diagnostic=False)):
                self.assertEqual(expected, {n: hashlib.sha256(b).hexdigest() for n, b in rendered.items()})

    def test_a_diagnostic_run_adds_verbose_log_until_to_every_request_and_nothing_else(self):
        diagnostic = {n: json.loads(b) for n, b in req.render_all(diagnostic=True).items()}
        self.assertEqual(list(self.files), list(diagnostic))
        for name, request in diagnostic.items():
            self.assertEqual(req.VERBOSE_LOG_UNTIL, request['settings']['verbose_log_until'], name)
            ordinary = self.requests[name]
            self.assertLessEqual(differences(ordinary, request), {'settings.verbose_log_until'}, name)
            req.check_documentation_only(request)
        for name in req.CONNECT:
            self.assertEqual({'settings.verbose_log_until'}, differences(self.requests[name], diagnostic[name]), name)
        for name in req.PROGRAM:
            self.assertEqual(self.files[name], req.render_all(diagnostic=True)[name])

    def test_generator_takes_no_request_and_no_path(self):
        self.assertEqual(['server', 'port', 'diagnostic'], list(inspect.signature(req.render_all).parameters))
        self.assertIs(False, inspect.signature(req.render_all).parameters['diagnostic'].default)

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


class ProxyRequestTests(unittest.TestCase):
    """The four requests of the Proxy job: the kill-switch request in the proxy mode, as New-RosetunLinuxProxyRequests."""

    def setUp(self):
        self.files = req.render_proxy()
        self.requests = {n: json.loads(b) for n, b in self.files.items()}

    def test_exactly_the_four_files_the_proxy_job_installs(self):
        self.assertEqual(['request-kill-switch.json', 'request-proxy.json', 'request-proxy-strict.json',
                          'request-proxy-share.json'], list(self.files))
        self.assertEqual(req.PROXY_NAMES, tuple(self.files))
        script = (ROOT / 'tools/vm/linux/guest/run-proxy.sh').read_text(encoding='utf-8')
        self.assertEqual(set(req.PROXY_NAMES), set(re.findall(r'request-[a-z-]+\.json', script)))

    def test_variants_and_port_equal_the_powershell_function(self):
        text = PSM1.read_text(encoding='utf-8')
        body = re.search(r'function New-RosetunLinuxProxyRequests \{(.*?)\n\}', text, re.S).group(1)
        found = dict(re.findall(r"'(request-proxy[a-z-]*\.json)'\s*=\s*@\{([^}]*)\}", body))
        parsed = {n: tuple(v == '$true' for v in re.findall(r'=\s*(\$true|\$false)', v)) for n, v in found.items()}
        self.assertEqual(req.PROXY, parsed)
        self.assertIn('$ProxyPort = 10808', body)
        self.assertIn("connection_mode -NotePropertyValue 'system_proxy'", body)
        script = (ROOT / 'tools/vm/linux/guest/run-proxy.sh').read_text(encoding='utf-8')
        self.assertIn(f'\nPROXY_PORT={req.PROXY_PORT}\n', script)

    def test_the_kill_switch_request_is_the_l3_one_byte_for_byte(self):
        for server, port in (('192.0.2.1', 8388), ('198.51.100.7', 9000)):
            self.assertEqual(req.render_all(server, port)['request-kill-switch.json'],
                             req.render_proxy(server, port)['request-kill-switch.json'])

    def test_each_variant_differs_from_the_kill_switch_request_only_by_the_proxy_settings(self):
        ks = self.requests['request-kill-switch.json']
        proxy_fields = {'settings.connection_mode', 'settings.local_proxy.port', 'settings.local_proxy.share_on_lan'}
        for name, (kill, share) in req.PROXY.items():
            request = self.requests[name]
            self.assertEqual(proxy_fields | (set() if kill else {'settings.kill_switch'}), differences(ks, request), name)
            self.assertEqual('system_proxy', request['settings']['connection_mode'])
            self.assertEqual(dict(port=10808, share_on_lan=share), request['settings']['local_proxy'])
            self.assertIs(kill, request['settings']['kill_switch'])
            self.assertIs(False, request['settings']['allow_lan'])
            req.check_documentation_only(request)

    DIGESTS = {
        ('192.0.2.1', 8388): {
            'request-kill-switch.json': '0b9df6f0125a1fc52743f00948f6505b7cf869a3a034b2621edcf87587a28840',
            'request-proxy.json': '28187711c8a191ea306210fc77249ee739287b35b54cc98e26f164c3457ce889',
            'request-proxy-strict.json': 'a5dc7f3c85ba6a74d7a44f641b57acb74ecf13f4e861ff0abdb95105a3dea24e',
            'request-proxy-share.json': 'c3da87e6015d2584780d0163e27cba37ce5660bdbbb81f03ecfcc063e9efdfde'},
        ('198.51.100.7', 9000): {
            'request-kill-switch.json': '3116aab145a331179deff1d22d984b8cb6ab5fd8ea4473f4e528285c50485609',
            'request-proxy.json': '41b61ffa94823dc8b229df455eb36014e876cda45af71653e500e6cee5f81198',
            'request-proxy-strict.json': 'f2117b1374bd9cce63560a9577087c1570f76b86a2dcb7d9ca7c4d458034a445',
            'request-proxy-share.json': 'c981726723d3fdd956e855c39ce82a1d2183936df5184db8a1f2ce19c61ddc0e'}}

    def test_the_bytes_are_pinned(self):
        for (server, port), expected in self.DIGESTS.items():
            rendered = req.render_for('proxy', server, port)
            self.assertEqual(expected, {n: hashlib.sha256(b).hexdigest() for n, b in rendered.items()})

    def test_the_l3_renderer_and_its_bytes_are_unchanged_and_an_unknown_profile_is_refused(self):
        self.assertEqual(req.render_all(), req.render_for('l3'))
        self.assertEqual(RequestTests.ORDINARY[('192.0.2.1', 8388)],
                         {n: hashlib.sha256(b).hexdigest() for n, b in req.render_for('l3').items()})
        for profile in ('l2', 'l4', None):
            with self.assertRaises(ValueError):
                req.render_for(profile)

    def test_written_once_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            req.write_all(temp, profile='proxy')
            req.write_all(temp, profile='proxy')
            self.assertEqual(self.files, {n: (Path(temp) / n).read_bytes() for n in req.PROXY_NAMES})
            (Path(temp) / 'request-proxy.json').write_bytes(b'{}\n')
            with self.assertRaises(ValueError):
                req.write_all(temp, profile='proxy')


class L5RequestTests(unittest.TestCase):
    """The three requests of the L5 job: the L3 files of the same names, byte for byte."""

    def test_exactly_the_three_files_start_sh_requires_in_its_order(self):
        text = (ROOT / 'tools/vm/linux/guest/start.sh').read_text(encoding='utf-8')
        required = re.search(r'L5_START_REQUIRED=\(([^)]*)\)', text).group(1).split()
        self.assertEqual(req.L5_NAMES, tuple(name.rpartition('/')[2] for name in required if 'request-' in name))
        self.assertEqual(req.L5_NAMES, tuple(req.render_l5()))
        script = (ROOT / 'tools/vm/linux/guest/run-l5.sh').read_text(encoding='utf-8')
        self.assertLessEqual(set(re.findall(r'request-[a-z-]+\.json', script)), set(req.L5_NAMES))

    def test_each_file_is_the_l3_one_and_the_bytes_are_pinned(self):
        for (server, port), digests in RequestTests.ORDINARY.items():
            rendered = req.render_for('l5', server, port)
            self.assertEqual({n: req.render_all(server, port)[n] for n in req.L5_NAMES}, rendered)
            self.assertEqual({n: digests[n] for n in req.L5_NAMES},
                             {n: hashlib.sha256(b).hexdigest() for n, b in rendered.items()})

    def test_written_once_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            req.write_all(temp, profile='l5')
            req.write_all(temp, profile='l5')
            self.assertEqual(sorted(req.L5_NAMES), sorted(p.name for p in Path(temp).iterdir()))
            (Path(temp) / 'request-dns-lock.json').write_bytes(b'{}\n')
            with self.assertRaises(ValueError):
                req.write_all(temp, profile='l5')
