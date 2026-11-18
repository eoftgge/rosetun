"""Strict configuration of the Windows guest image build (stdlib only)."""

from dataclasses import dataclass
import re
import tomllib

SCHEMA = 'rosetun.windows-image.config.v1'
# The only MAC the lab gives the test machine; the guest sees the same NIC at build time and in runs,
# otherwise Windows creates a second adapter and loses the settings of the first.
TEST_MAC = '00:00:5e:00:53:61'

SECTIONS = {
    'inputs': {'windows_iso', 'windows_iso_sha256', 'virtio_win_iso', 'virtio_win_version',
               'virtio_win_sha256'},
    'tools': {'qemu_system', 'qemu_img', 'xorriso', 'swtpm'},
    'firmware': {'ovmf_code', 'ovmf_vars_template'},
    'vm': {'memory_mib', 'vcpus', 'disk_gib', 'mac', 'vnc_display'},
    'guest': {'identifier', 'hostname', 'username', 'language', 'edition_name', 'image_index',
              'empty_product_key_element'},
    'build': {'output_directory', 'network', 'press_any_key_seconds', 'timeout_minutes'},
}
REQUIRED = {
    'inputs': {'windows_iso', 'virtio_win_iso', 'virtio_win_version', 'virtio_win_sha256'},
    'tools': {'qemu_system', 'qemu_img', 'xorriso', 'swtpm'},
    'firmware': {'ovmf_code', 'ovmf_vars_template'},
    'vm': set(),
    'guest': {'identifier'},
    'build': {'output_directory'},
}
DEFAULTS = {
    'vm': {'memory_mib': 4096, 'vcpus': 4, 'disk_gib': 64, 'mac': TEST_MAC, 'vnc_display': 0},
    'guest': {'hostname': 'ROSETUN-WIN', 'username': 'rosetun', 'language': 'en-US',
              'edition_name': '', 'image_index': 0, 'empty_product_key_element': False},
    'build': {'network': 'restricted', 'press_any_key_seconds': 60, 'timeout_minutes': 180},
    'inputs': {'windows_iso_sha256': ''},
}


class ConfigError(ValueError):
    pass


def _path(value, name):
    if not isinstance(value, str) or not value:
        raise ConfigError(f'{name}: a path is required')
    # QEMU option grammars treat a comma as a separator, whatever the shell does.
    if ',' in value or any(ord(c) < 32 for c in value):
        raise ConfigError(f'{name}: unsupported characters in a path')
    return value


def _sha(value, name, required):
    if value == '' and not required:
        return value
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
        raise ConfigError(f'{name}: a lowercase SHA-256 is required')
    return value


@dataclass(frozen=True)
class ImageConfig:
    windows_iso: str
    windows_iso_sha256: str
    virtio_win_iso: str
    virtio_win_version: str
    virtio_win_sha256: str
    qemu_system: str
    qemu_img: str
    xorriso: str
    swtpm: str
    ovmf_code: str
    ovmf_vars_template: str
    memory_mib: int
    vcpus: int
    disk_gib: int
    mac: str
    vnc_display: int
    identifier: str
    hostname: str
    username: str
    language: str
    edition_name: str
    image_index: int
    empty_product_key_element: bool
    output_directory: str
    network: str
    press_any_key_seconds: int
    timeout_minutes: int


def parse(data):
    if not isinstance(data, dict) or data.get('schema') != SCHEMA:
        raise ConfigError('unsupported configuration schema')
    values = {}
    for section, keys in SECTIONS.items():
        table = data.get(section, {})
        if not isinstance(table, dict):
            raise ConfigError(f'{section}: a table is required')
        unknown = set(table) - keys
        if unknown:
            raise ConfigError(f'{section}: unknown keys {sorted(unknown)}')
        missing = REQUIRED[section] - set(table)
        if missing:
            raise ConfigError(f'{section}: missing keys {sorted(missing)}')
        values.update(DEFAULTS.get(section, {}))
        values.update(table)
    if set(data) - set(SECTIONS) - {'schema'}:
        raise ConfigError('unknown top-level keys')
    for name in ('windows_iso', 'virtio_win_iso', 'qemu_system', 'qemu_img', 'xorriso', 'swtpm',
                 'ovmf_code', 'ovmf_vars_template', 'output_directory'):
        _path(values[name], name)
    _sha(values['virtio_win_sha256'], 'virtio_win_sha256', True)
    _sha(values['windows_iso_sha256'], 'windows_iso_sha256', False)
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(-[0-9]+)?', str(values['virtio_win_version'])):
        raise ConfigError('virtio_win_version: expected a release such as 0.1.285-1')
    if not re.fullmatch('[a-z0-9][a-z0-9.-]{0,63}', values['identifier']):
        raise ConfigError('identifier: lowercase letters, digits, dot, dash')
    if not re.fullmatch('[A-Za-z0-9-]{1,15}', values['hostname']):
        raise ConfigError('hostname: at most 15 letters, digits or dashes')
    if not re.fullmatch('[a-z][a-z0-9_-]{0,19}', values['username']):
        raise ConfigError('username: lowercase, at most 20 characters')
    if not re.fullmatch('[a-z]{2}-[A-Z]{2}', values['language']):
        raise ConfigError('language: a locale such as en-US')
    if not re.fullmatch('[0-9a-f]{2}(:[0-9a-f]{2}){5}', values['mac']):
        raise ConfigError('mac: lowercase colon-separated')
    if values['mac'] != TEST_MAC:
        # The lab pins the test machine by this address; another one would not match it in runs.
        raise ConfigError('mac: must be the lab test machine address')
    ints = {'memory_mib': (4096, 65536), 'vcpus': (2, 64), 'disk_gib': (64, 512),
            'vnc_display': (0, 99), 'press_any_key_seconds': (10, 300), 'timeout_minutes': (30, 720),
            'image_index': (0, 64)}
    for name, (low, high) in ints.items():
        if type(values[name]) is not int or not low <= values[name] <= high:
            raise ConfigError(f'{name}: an integer from {low} to {high}')
    if values['network'] not in ('restricted', 'nat'):
        raise ConfigError("network: 'restricted' or 'nat'")
    if type(values['empty_product_key_element']) is not bool:
        raise ConfigError('empty_product_key_element: a boolean')
    if type(values['edition_name']) is not str:
        raise ConfigError('edition_name: a string')
    if values['image_index'] and values['edition_name']:
        raise ConfigError('guest: set either edition_name or image_index, not both')
    if not values['image_index'] and not values['edition_name']:
        values['edition_name'] = 'Windows 11 Pro'
    return ImageConfig(**values)


def load(path):
    with open(path, 'rb') as source:
        return parse(tomllib.load(source))

