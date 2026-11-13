"""Documentation-only connect requests for the Linux L3 job.

The generator reads the public template next to it and nothing else: no owner
request, no file path, no environment. Only the node address and port vary.
"""

import copy
import ipaddress
import json
from pathlib import Path

TEMPLATE = Path(__file__).with_name('l3-request-template.json')
DOCUMENTATION = tuple(ipaddress.ip_network(n) for n in (
    '192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32'))
DEFAULT_SERVER = '192.0.2.1'
DEFAULT_PORT = 8388
# Year 2100: past any run, so the verbose log stays on for the whole job.
VERBOSE_LOG_UNTIL = 4102444800

# name -> (kill_switch, allow_lan, private_networks), in the order of
# New-RosetunLinuxL3Requests; every connect request sets all three fields.
CONNECT = {'request-kill-switch.json': (True, False, False),
           'request-lan.json': (True, True, False),
           'request-lan-private.json': (True, True, True),
           'request-dns-lock.json': (False, False, False)}
# name -> (default_target, target of the rule for curl)
PROGRAM = {'request-program-direct.json': ('proxy', 'direct'),
           'request-program-proxy.json': ('direct', 'proxy')}
NAMES = tuple(CONNECT) + tuple(PROGRAM)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('l3-request-duplicate-key')
        result[key] = value
    return result


def _leaves(value):
    if type(value) is dict:
        for item in value.values():
            yield from _leaves(item)
    elif type(value) is list:
        for item in value:
            yield from _leaves(item)
    else:
        yield value


def documentation_address(text):
    """True for a literal address or interface inside a documentation network."""
    try:
        address = ipaddress.ip_interface(text).ip
    except ValueError:
        return False
    return any(address in net for net in DOCUMENTATION)


def check_documentation_only(request):
    """Reject any address-looking string that is not a documentation address."""
    for leaf in _leaves(request):
        if type(leaf) is not str:
            continue
        try:
            ipaddress.ip_interface(leaf)
        except ValueError:
            continue
        if not documentation_address(leaf):
            raise ValueError('l3-request-address-not-documentation')


def template():
    value = json.loads(TEMPLATE.read_bytes().decode('utf-8'), object_pairs_hook=_unique)
    if type(value) is not dict or not {'node', 'settings'} <= set(value):
        raise ValueError('l3-request-template-shape')
    check_documentation_only(value)
    return value


def _serialize(request):
    check_documentation_only(request)
    return (json.dumps(request, indent=2) + '\n').encode('ascii')


def render_all(server=DEFAULT_SERVER, port=DEFAULT_PORT, *, diagnostic=False):
    """Return the six request files as name -> bytes, in the order the job uses them.

    A diagnostic run sets `verbose_log_until` in every request, as the two program requests
    always do, so that the engine's log names the destinations (here only documentation addresses).
    Without it the bytes are what they always were.
    """
    if type(server) is not str or ipaddress.ip_address(server).version != 4 \
            or not documentation_address(server):
        raise ValueError('l3-request-server-not-documentation-ipv4')
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('l3-request-port-range')
    base = template()
    base['node']['server'] = server
    base['node']['port'] = port
    files = {}
    kill_switch = None
    for name, (kill, lan, private) in CONNECT.items():
        request = copy.deepcopy(base)
        request['settings'].update(kill_switch=kill, allow_lan=lan, private_networks=private,
                                   auto_reconnect=True)
        if diagnostic:
            request['settings']['verbose_log_until'] = VERBOSE_LOG_UNTIL
        files[name] = _serialize(request)
        if name == 'request-kill-switch.json':
            kill_switch = request
    for name, (default_target, target) in PROGRAM.items():
        request = copy.deepcopy(kill_switch)
        request['rule_set'] = dict(
            id='l3-program', name='L3 rules by program',
            rules=[dict(id='l3-curl', enabled=True,
                        matcher=dict(process=dict(name='curl')), target=target)],
            default_target=default_target)
        request['settings']['verbose_log_until'] = VERBOSE_LOG_UNTIL
        files[name] = _serialize(request)
    return files


def write_all(directory, server=DEFAULT_SERVER, port=DEFAULT_PORT):
    """Create the files, or confirm that identical ones are already there."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    for name, data in render_all(server, port).items():
        path = directory / name
        if path.exists() or path.is_symlink():
            if path.is_symlink() or not path.is_file() or path.read_bytes() != data:
                raise ValueError('l3-request-file-differs')
            continue
        with path.open('xb') as stream:
            stream.write(data)
