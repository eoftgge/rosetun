"""The Windows image tooling: answer files, noise measures, build command lines and guest clients, all offline."""

import base64
import contextlib
import io
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import tempfile
import threading
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

from .posix_only import controller_only

TOOL = Path(__file__).resolve().parents[2] / 'windows-image'
sys.path.insert(0, str(TOOL))
import build_image  # noqa: E402
import image_answers  # noqa: E402
import image_config  # noqa: E402
import image_guest  # noqa: E402
import image_plan  # noqa: E402

NS = {'u': image_answers.NS}
SCRIPT = (TOOL / 'first-logon.ps1').read_text(encoding='utf-8')
README = (TOOL / 'README.md').read_text(encoding='utf-8')
EXAMPLE = TOOL / 'example.toml'

# One step name per measure the image takes against background traffic or unplanned restarts.
NOISE_STEPS = {
    'hibernation-off', 'fast-startup-off', 'boot-recovery-off', 'power-button-shutdown',
    'windows-update-policy', 'windows-update-services', 'windows-update-medic', 'update-tasks-off',
    'delivery-optimization-off', 'telemetry-policy', 'telemetry-services', 'telemetry-tasks',
    'ncsi-active-probe-off', 'llmnr-off', 'mdns-off', 'netbios-off', 'ssdp-upnp-off',
    'ws-discovery-off', 'dhcpv6-off', 'ipv6-transition-off', 'time-service-off', 'edge-update-off',
    'defender-cloud-off', 'qemu-guest-agent', 'virtio-drivers',
}


def config(**changes):
    data = image_config_data()
    for key, value in changes.items():
        section = next(name for name, keys in image_config.SECTIONS.items() if key in keys)
        data.setdefault(section, {})[key] = value
    return image_config.parse(data)


def image_config_data():
    import tomllib
    with EXAMPLE.open('rb') as source:
        return tomllib.load(source)


def text(root, path):
    found = root.find(path, NS)
    return None if found is None else found.text


class AnswerFileTests(unittest.TestCase):
    def setUp(self):
        self.password = image_answers.generate_password()
        self.data = image_answers.autounattend(config(empty_product_key_element=False), self.password)
        self.root = ET.fromstring(self.data)

    def test_the_answer_file_is_well_formed_with_the_three_passes_setup_reads(self):
        self.assertTrue(self.data.startswith(b"<?xml"))
        passes = [settings.get('pass') for settings in self.root.findall('u:settings', NS)]
        self.assertEqual(['windowsPE', 'specialize', 'oobeSystem'], passes)

    def test_no_setup_check_is_lowered_and_no_product_key_is_given(self):
        lowered = self.data.decode('utf-8').lower()
        for word in ('labconfig', 'bypassnro', 'bypasstpm', 'bypasssecureboot', 'bypasscpu', 'bypassram',
                     'bypassstoragecheck', 'allowupgradeswithunsupported', 'skipmachineoobe'):
            self.assertNotIn(word, lowered)
        self.assertNotIn('ProductKey', self.data.decode('utf-8'))
        self.assertIsNone(re.search(rb'\b[A-Z0-9]{5}(-[A-Z0-9]{5}){4}\b', self.data))

    def test_an_empty_product_key_element_is_the_only_fallback_and_holds_no_key(self):
        data = image_answers.autounattend(config(empty_product_key_element=True), self.password)
        key = ET.fromstring(data).find('.//u:ProductKey/u:Key', NS)
        self.assertIsNotNone(key)
        self.assertFalse((key.text or '').strip())
        self.assertIsNone(re.search(rb'\b[A-Z0-9]{5}(-[A-Z0-9]{5}){4}\b', data))

    def test_the_edition_is_chosen_by_name_or_by_index_and_never_by_key(self):
        metadata = self.root.find('.//u:InstallFrom/u:MetaData', NS)
        self.assertEqual(('/IMAGE/NAME', 'Windows 11 Pro'),
                         (text(metadata, 'u:Key'), text(metadata, 'u:Value')))
        data = image_answers.autounattend(config(image_index=6, edition_name=''), self.password)
        metadata = ET.fromstring(data).find('.//u:InstallFrom/u:MetaData', NS)
        self.assertEqual(('/IMAGE/INDEX', '6'), (text(metadata, 'u:Key'), text(metadata, 'u:Value')))

    def test_the_disk_is_gpt_for_uefi_with_efi_msr_and_windows_partitions(self):
        kinds = [text(partition, 'u:Type') for partition in self.root.findall('.//u:CreatePartition', NS)]
        self.assertEqual(['EFI', 'MSR', 'Primary'], kinds)
        self.assertEqual('3', text(self.root, './/u:InstallTo/u:PartitionID'))

    def test_virtio_drivers_are_loaded_from_the_virtio_disc(self):
        paths = [path.text for path in self.root.findall('.//u:DriverPaths//u:Path', NS)]
        for driver in ('viostor', 'NetKVM', 'vioserial'):
            self.assertTrue(any(f'\\{driver}\\w11\\amd64' in path for path in paths), driver)

    def test_the_example_gives_the_empty_product_key_element_that_the_26h2_disc_needs(self):
        loaded = image_config.load(EXAMPLE)
        self.assertTrue(loaded.empty_product_key_element)
        data = image_answers.autounattend(loaded, self.password)
        key = ET.fromstring(data).find('.//u:ProductKey/u:Key', NS)
        self.assertFalse((key.text or '').strip())

    def components(self, root, settings_pass):
        settings = next(s for s in root.findall('u:settings', NS) if s.get('pass') == settings_pass)
        return {c.get('name'): c for c in settings.findall('u:component', NS)}

    def test_the_language_the_locale_and_the_keyboard_are_given_to_the_installed_system_as_well(self):
        for language, keyboard in (('en-US', '0409:00000409'), ('de-DE', 'de-DE')):
            root = ET.fromstring(image_answers.autounattend(config(language=language), self.password))
            for settings_pass in ('specialize', 'oobeSystem'):
                component = self.components(root, settings_pass)['Microsoft-Windows-International-Core']
                self.assertEqual(keyboard, text(component, 'u:InputLocale'), settings_pass)
                for name in ('SystemLocale', 'UILanguage', 'UserLocale'):
                    self.assertEqual(language, text(component, f'u:{name}'), (settings_pass, name))
            pe = self.components(root, 'windowsPE')['Microsoft-Windows-International-Core-WinPE']
            self.assertEqual(language, text(pe, 'u:SetupUILanguage/u:UILanguage'))

    def test_the_international_component_is_not_in_the_windows_pe_pass_by_that_name(self):
        pe = self.components(self.root, 'windowsPE')
        self.assertNotIn('Microsoft-Windows-International-Core', pe)

    def test_every_documented_setting_that_removes_an_out_of_box_page_is_set(self):
        options = self.root.find('.//u:OOBE', NS)
        values = {child.tag.split('}')[1]: child.text for child in options}
        for name in ('HideEULAPage', 'HideOEMRegistrationScreen', 'HideOnlineAccountScreens',
                     'HideWirelessSetupInOOBE'):
            self.assertEqual('true', values[name], name)
        self.assertEqual('3', values['ProtectYourPC'])
        self.assertIsNotNone(self.root.find('.//u:LocalAccounts/u:LocalAccount', NS))

    def test_the_machine_is_named_and_set_to_utc(self):
        self.assertEqual('UTC', text(self.root, './/u:TimeZone'))
        self.assertEqual('ROSETUN-WIN', text(self.root, './/u:ComputerName'))

    def test_the_account_is_local_and_uses_unattend_not_a_registry_trick(self):
        self.assertEqual('Administrators', text(self.root, './/u:LocalAccount/u:Group'))
        self.assertEqual('true', text(self.root, './/u:OOBE/u:HideOnlineAccountScreens'))
        self.assertEqual('true', text(self.root, './/u:OOBE/u:HideLocalAccountScreen'))
        self.assertEqual('true', text(self.root, './/u:AutoLogon/u:Enabled'))

    def test_the_logon_is_automatic_exactly_once(self):
        self.assertEqual('1', text(self.root, './/u:AutoLogon/u:LogonCount'))
        commands = self.root.findall('.//u:FirstLogonCommands/u:SynchronousCommand', NS)
        self.assertEqual(1, len(commands))
        self.assertIn('first-logon.ps1', text(commands[0], 'u:CommandLine'))
        self.assertIn(image_answers.LABEL, text(commands[0], 'u:CommandLine'))

    def test_the_password_is_not_in_the_answer_file_in_plain_form(self):
        self.assertNotIn(self.password.encode(), self.data)
        for password in self.root.iter('{%s}Password' % NS['u']):
            self.assertEqual('false', text(password, 'u:PlainText'))
            decoded = base64.b64decode(text(password, 'u:Value')).decode('utf-16-le')
            self.assertEqual(self.password + 'Password', decoded)

    def test_passwords_are_fresh_and_have_every_class_of_character(self):
        values = {image_answers.generate_password() for _ in range(20)}
        self.assertEqual(20, len(values))
        for value in values:
            self.assertEqual(image_answers.PASSWORD_LENGTH, len(value))
            self.assertTrue(re.search('[a-z]', value) and re.search('[A-Z]', value) and re.search('[0-9]', value))

    def test_the_password_reaches_no_other_output(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(0, build_image.main(['plan', str(EXAMPLE)]))
        layout = image_plan.Layout('/srv/image')
        record = image_plan.descriptor(config(), layout, uuid='u', windows_iso_sha256='0' * 64,
                                       disk_sha256='1' * 64, disk_size=1, vars_sha256='2' * 64,
                                       code_sha256='3' * 64, template_sha256='4' * 64,
                                       tpm_files={}, built_at='t')
        for output in (stdout.getvalue(), json.dumps(record), SCRIPT, README,
                       ' '.join(image_answers.xorriso_arguments('a', 'b')), image_answers.first_logon_command()):
            self.assertNotIn(self.password, output)

    def test_the_media_label_matches_what_the_first_logon_command_looks_for(self):
        self.assertIn(f"-V {image_answers.LABEL}", ' '.join(image_answers.xorriso_arguments('a', 'b')))


class FirstLogonScriptTests(unittest.TestCase):
    def steps(self):
        return dict(re.findall(r"^Invoke-RosetunStep '([a-z0-9-]+)' '([^']+)'", SCRIPT, re.M))

    def test_every_expected_measure_is_present_as_its_own_step_with_a_reason(self):
        steps = self.steps()
        self.assertFalse(NOISE_STEPS - set(steps), NOISE_STEPS - set(steps))
        for name, why in steps.items():
            self.assertGreater(len(why.split()), 4, name)

    def test_every_step_goes_through_the_logging_wrapper(self):
        self.assertEqual(len(re.findall(r"^Invoke-RosetunStep ", SCRIPT, re.M)), len(self.steps()))

    def test_the_script_never_touches_the_firewall_or_the_filtering_platform(self):
        code = '\n'.join(line for line in SCRIPT.splitlines() if not line.lstrip().startswith('#'))
        for word in ('advfirewall', 'NetFirewall', 'mpssvc', 'FirewallPolicy', 'FirewallRule', 'fwpuclnt', 'BFE'):
            self.assertNotIn(word.lower(), code.lower(), word)

    def test_the_configuration_of_time_hibernation_and_recovery_is_exact(self):
        self.assertIn('powercfg.exe /h off', SCRIPT)
        self.assertIn("recoveryenabled No", SCRIPT)
        self.assertIn("bootstatuspolicy ignoreallfailures", SCRIPT)
        self.assertIn("'EnableMulticast' 0", SCRIPT)
        self.assertIn("'EnableMDNS' 0", SCRIPT)
        self.assertIn("-Name 'NetbiosOptions' -Value 2", SCRIPT)
        self.assertIn('managedaddress=disabled otherstateful=disabled', SCRIPT)
        self.assertIn("'W32Time'", SCRIPT)

    def test_the_script_ends_with_the_shutdown_the_host_waits_for(self):
        self.assertTrue(SCRIPT.rstrip().splitlines()[-1].startswith('& shutdown.exe /s'))

    def test_the_style_of_the_repository_holds(self):
        self.assertIn('Set-StrictMode -Version Latest', SCRIPT)
        self.assertNotRegex(SCRIPT, r'(?m)\|\s*\?\s')
        self.assertNotRegex(SCRIPT, r'(?m)\|\s*%\s')
        self.assertNotIn('\t', SCRIPT)
        for name in re.findall(r'^function ([\w-]+)', SCRIPT, re.M):
            self.assertRegex(name, r'^[A-Z][a-z]+-Rosetun[A-Z]\w+$')


class ConfigTests(unittest.TestCase):
    def test_the_example_loads_and_pins_the_lab_test_address(self):
        loaded = image_config.load(EXAMPLE)
        self.assertEqual(image_config.TEST_MAC, loaded.mac)
        self.assertEqual('restricted', loaded.network)

    def test_the_example_is_the_english_26h2_disc_with_the_firmware_without_smm(self):
        loaded = image_config.load(EXAMPLE)
        self.assertEqual('/mnt/d/Iso/win11_26h2.iso', loaded.windows_iso)
        self.assertEqual('windows-11-26h2-pro-v1', loaded.identifier)
        self.assertEqual('en-US', loaded.language)
        self.assertFalse(loaded.smm)
        self.assertTrue(loaded.ovmf_code.endswith('/OVMF_CODE.fd'))
        self.assertTrue(loaded.ovmf_vars_template.endswith('/OVMF_VARS.ms.fd'))

    def test_unknown_keys_and_a_foreign_address_are_refused(self):
        data = image_config_data()
        data['vm']['surprise'] = 1
        with self.assertRaises(image_config.ConfigError):
            image_config.parse(data)
        with self.assertRaises(image_config.ConfigError):
            config(mac='00:00:5e:00:53:62')

    def test_the_edition_is_one_selector(self):
        with self.assertRaises(image_config.ConfigError):
            config(image_index=6)
        self.assertEqual('Windows 11 Pro', config(edition_name='').edition_name)

    def test_the_virtio_digest_is_required_and_a_comma_in_a_path_is_refused(self):
        with self.assertRaises(image_config.ConfigError):
            config(virtio_win_sha256='abc')
        with self.assertRaises(image_config.ConfigError):
            config(windows_iso='/iso/a,b.iso')


class QemuPlanTests(unittest.TestCase):
    def setUp(self):
        self.config = config()
        self.layout = image_plan.Layout('/srv/image')
        self.install = image_plan.qemu_argv(self.config, self.layout, 'u', install=True)
        self.measure = image_plan.qemu_argv(self.config, self.layout, 'u', install=False)

    def value(self, argv, flag, containing):
        found = [argv[i + 1] for i, item in enumerate(argv[:-1]) if item == flag and containing in argv[i + 1]]
        self.assertEqual(1, len(found), (flag, containing))
        return found[0]

    def test_the_machine_is_q35_with_secure_boot_firmware_in_pflash(self):
        code = self.value(self.install, '-drive', 'unit=0')
        variables = self.value(self.install, '-drive', 'unit=1')
        self.assertIn('if=pflash', code)
        self.assertIn('readonly=on', code)
        self.assertIn('/OVMF_CODE.fd', code)
        self.assertIn('/srv/image/OVMF_VARS.fd', variables)
        self.assertNotIn('readonly', variables)
        self.assertIn('ICH9-LPC.disable_s3=1', self.install)

    def test_without_smm_the_machine_has_none_and_the_variable_store_is_not_locked_to_it(self):
        self.assertFalse(self.config.smm)
        self.assertIn('q35,smm=off', self.install)
        self.assertNotIn('q35,smm=on', self.install)
        self.assertNotIn('driver=cfi.pflash01,property=secure,value=on', self.install)
        self.assertNotIn('secure=on', ' '.join(self.install))

    def test_with_smm_the_machine_and_the_locked_variable_store_are_those_of_the_distribution_firmware(self):
        argv = image_plan.qemu_argv(config(smm=True), self.layout, 'u', install=True)
        self.assertIn('q35,smm=on', argv)
        self.assertNotIn('q35,smm=off', argv)
        self.assertEqual(1, argv.count('driver=cfi.pflash01,property=secure,value=on'))
        self.assertIn('ICH9-LPC.disable_s3=1', argv)

    def test_smm_is_a_boolean_of_the_configuration_that_defaults_to_the_distribution_machine(self):
        data = image_config_data()
        del data['firmware']['smm']
        self.assertTrue(image_config.parse(data).smm)
        data['firmware']['smm'] = 'no'
        with self.assertRaises(image_config.ConfigError):
            image_config.parse(data)

    def test_the_tpm_is_a_two_point_zero_swtpm_over_a_socket_that_swtpm_serves(self):
        self.assertIn('tpm-crb,tpmdev=tpm0', self.install)
        chardev = self.value(self.install, '-chardev', 'id=chrtpm')
        tpmdev = self.value(self.install, '-tpmdev', 'emulator')
        self.assertIn('chardev=chrtpm', tpmdev)
        swtpm = image_plan.swtpm_argv(self.config, self.layout)
        self.assertIn('--tpm2', swtpm)
        self.assertIn('--terminate', swtpm)
        socket_path = chardev.split('path=')[1]
        self.assertIn(f'type=unixio,path={socket_path}', swtpm)
        self.assertIn('dir=/srv/image/tpm', swtpm)

    def test_hardware_virtualization_of_both_vendors_is_hidden_and_the_hyper_v_enlightenments_are_given(self):
        expected = 'host,-vmx,-svm,hv-relaxed,hv-vapic,hv-spinlocks=0x1fff,hv-time,hv-vpindex,hv-synic,hv-stimer'
        self.assertEqual(expected, image_plan.CPU)
        for argv in (self.install, self.measure):
            self.assertEqual(expected, argv[argv.index('-cpu') + 1])
        flags = image_plan.CPU.split(',')
        self.assertEqual(['host', '-vmx', '-svm'], flags[:3])
        # The timer path needs all three: the stimer builds on the synthetic interrupt controller.
        for flag in ('hv-vpindex', 'hv-synic', 'hv-stimer', 'hv-time'):
            self.assertIn(flag, flags)
        # Hiding hardware virtualization is not undone by an enlightenment.
        self.assertFalse([flag for flag in flags if flag in ('vmx', '+vmx', 'svm', '+svm', 'hv-evmcs', 'hv-nested')])

    def test_vnc_is_on_loopback_only_and_nothing_else_listens(self):
        displays = [self.install[i + 1] for i, item in enumerate(self.install) if item == '-display']
        self.assertEqual(['vnc=127.0.0.1:0'], displays)
        joined = ' '.join(self.install)
        for word in ('0.0.0.0', 'websocket', 'hostfwd', 'tap', 'stream', 'tcp:', 'listen='):
            self.assertNotIn(word, joined)

    def test_the_build_network_has_no_way_out_by_default(self):
        self.assertIn('user,id=buildnet,restrict=on', self.install)
        open_network = image_plan.qemu_argv(config(network='nat'), self.layout, 'u', install=True)
        self.assertIn('user,id=buildnet', open_network)
        self.assertNotIn('user,id=buildnet,restrict=on', open_network)

    def test_the_devices_are_the_virtio_set_of_the_runs_at_fixed_addresses(self):
        joined = ' '.join(self.install)
        for fragment in ('virtio-blk-pci,drive=root', 'virtio-net-pci', 'mac=00:00:5e:00:53:61',
                         'virtio-serial-pci', 'name=org.qemu.guest_agent.0'):
            self.assertIn(fragment, joined)
        slots = re.findall(r'addr=(0x[0-9a-f]+)', joined)
        self.assertEqual(len(slots), len(set(slots)))
        self.assertEqual(set(image_plan.PCI_SLOTS.values()), set(slots))
        self.assertNotIn('usb', joined)

    def test_a_measurement_boots_the_same_machine_without_the_three_discs(self):
        self.assertEqual(self.install[:len(self.measure)], self.measure)
        self.assertEqual(3, ' '.join(self.install).count('ide-cd'))
        self.assertNotIn('ide-cd', ' '.join(self.measure))

    def test_the_hard_disk_is_tried_first_so_that_setup_runs_only_on_an_empty_one(self):
        disk = self.value(self.install, '-device', 'virtio-blk-pci')
        windows = self.value(self.install, '-device', 'drive=winiso')
        self.assertEqual(1, int(re.search(r'bootindex=(\d+)', disk).group(1)))
        self.assertEqual(2, int(re.search(r'bootindex=(\d+)', windows).group(1)))

    def test_the_discs_are_read_only_and_the_answers_disc_is_the_third_drive(self):
        for node in ('winiso', 'virtio', 'answers'):
            definition = json.loads(self.value(self.install, '-blockdev', f'"node-name": "{node}"'))
            self.assertTrue(definition['read-only'])
        self.assertIn('drive=answers,bus=ide.2', ' '.join(self.install))

    def test_the_descriptor_extends_the_image_contract_and_claims_nothing_yet(self):
        record = self.descriptor(self.config)
        self.assertEqual('rosetun.matrix.image.v1', record['schema'])
        self.assertEqual(('windows', 'x86_64', 'qcow2'),
                         (record['guest_os'], record['architecture'], record['format']))
        self.assertEqual((False, False), (record['windows']['activated'], record['windows']['qualified']))
        self.assertTrue(record['windows']['uefi']['secure_boot'])
        self.assertEqual('2.0', record['windows']['tpm']['version'])
        self.assertEqual(image_plan.CPU, record['windows']['devices']['cpu'])

    def descriptor(self, loaded):
        return image_plan.descriptor(loaded, self.layout, uuid='u', windows_iso_sha256='0' * 64,
                                     disk_sha256='1' * 64, disk_size=5, vars_sha256='2' * 64,
                                     code_sha256='4' * 64, template_sha256='5' * 64,
                                     tpm_files={'tpm2-00.permall': '3' * 64}, built_at='t')

    def test_the_descriptor_names_the_firmware_hashes_it_and_says_the_variable_store_is_unprotected(self):
        uefi = self.descriptor(self.config)['windows']['uefi']
        self.assertEqual('secboot-nosmm', uefi['flavour'])
        self.assertFalse(uefi['smm'])
        self.assertEqual('varstore not SMM-protected', uefi['note'])
        self.assertEqual('4' * 64, uefi['code']['sha256'])
        self.assertEqual('5' * 64, uefi['vars_template']['sha256'])
        self.assertEqual('2' * 64, uefi['vars']['sha256'])
        protected = self.descriptor(config(smm=True))['windows']['uefi']
        self.assertEqual('secboot-smm', protected['flavour'])
        self.assertNotIn('note', protected)

    def test_the_plan_command_prints_the_commands_and_runs_none(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(0, build_image.main(['plan', str(EXAMPLE)]))
        plan = json.loads(stdout.getvalue())
        self.assertEqual({'swtpm', 'xorriso', 'qemu_img', 'qemu_install', 'qemu_measure'}, set(plan))
        self.assertEqual('/usr/bin/xorriso', plan['xorriso'][0])


class SocketServing:
    def serve(self, handler):
        host, guest = socket.socketpair()
        thread = threading.Thread(target=handler, args=(guest,), daemon=True)
        thread.start()
        # Cleanups run last to first: the host end closes, the server sees the end of the stream and
        # returns, then its own end closes.
        self.addCleanup(guest.close)
        self.addCleanup(thread.join, 5)
        self.addCleanup(host.close)
        return host

    @staticmethod
    def lines(stream):
        buffer = b''
        while True:
            while b'\n' not in buffer:
                chunk = stream.recv(4096)
                if not chunk:
                    return
                buffer += chunk
            line, _, buffer = buffer.partition(b'\n')
            yield line


class GuestClientTests(SocketServing, unittest.TestCase):
    def test_qmp_negotiates_and_sends_one_key(self):
        seen = []

        def handler(stream):
            stream.sendall(b'{"QMP": {"version": {}}}\r\n')
            for line in self.lines(stream):
                request = json.loads(line)
                seen.append(request)
                stream.sendall(b'{"event": "X"}\r\n{"return": {}}\r\n')
                if request['execute'] == 'send-key':
                    break
            stream.close()
        qmp = image_guest.Qmp(self.serve(handler))
        qmp.press('spc')
        self.assertEqual(['qmp_capabilities', 'send-key'], [r['execute'] for r in seen])
        self.assertEqual([{'type': 'qcode', 'data': 'spc'}], seen[1]['arguments']['keys'])

    def test_a_key_is_pressed_repeatedly_until_the_time_is_up(self):
        ticks = iter(range(0, 100))
        presses = []

        class Fake:
            def __init__(self, stream):
                pass

            def press(self, qcode):
                presses.append(qcode)

            def close(self):
                presses.append('closed')
        original = image_guest.Qmp
        image_guest.Qmp = Fake
        self.addCleanup(setattr, image_guest, 'Qmp', original)
        sent = image_guest.press_until(lambda: None, 'spc', 3, interval=0,
                                       clock=lambda: next(ticks), sleep=lambda _: None)
        self.assertGreaterEqual(sent, 2)
        self.assertEqual('closed', presses[-1])

    def test_the_agent_is_synchronized_before_a_ping_and_a_program_runs_to_its_output(self):
        def handler(stream):
            buffer = b''
            while True:
                chunk = stream.recv(4096)
                if not chunk:
                    return
                buffer += chunk
                while b'\n' in buffer:
                    line, _, buffer = buffer.partition(b'\n')
                    request = json.loads(line.lstrip(b'\xff'))
                    command = request['execute']
                    if command == 'guest-sync-delimited':
                        reply = b'\xff' + json.dumps({'return': request['arguments']['id']}).encode()
                    elif command == 'guest-exec':
                        reply = json.dumps({'return': {'pid': 7}}).encode()
                    elif command == 'guest-exec-status':
                        out = base64.b64encode(b'"t","12.5"\r\n"t","7.5"\r\n').decode()
                        reply = json.dumps({'return': {'exited': True, 'exitcode': 0, 'out-data': out}}).encode()
                    else:
                        reply = json.dumps({'return': {}}).encode()
                    stream.sendall(reply + b'\n')
        agent = image_guest.Qga(self.serve(handler))
        agent.ping()
        code, out = agent.run(image_guest.TYPEPERF, ['x'], poll=0)
        self.assertEqual(0, code)
        self.assertEqual(10.0, image_guest.average_cpu_percent(out))

    def test_typeperf_output_with_a_header_and_a_trailer_is_averaged(self):
        out = (b'\r\n"(PDH-CSV 4.0)","\\\\H\\Processor(_Total)\\% Processor Time"\r\n'
               b'"11/18/2026 10:00:00.1","3.0"\r\n"11/18/2026 10:00:01.1","5.0"\r\n'
               b'\r\nThe command completed successfully.\r\n')
        self.assertEqual(4.0, image_guest.average_cpu_percent(out))
        with self.assertRaises(image_guest.GuestError):
            image_guest.average_cpu_percent(b'nothing')

    def test_the_first_logon_log_reports_failed_steps_and_completeness(self):
        log = ('2026-11-18T10:00:00Z start\n2026-11-18T10:00:01Z OK   a: why\n'
               '2026-11-18T10:00:02Z FAIL b: why (access denied)\n'
               '2026-11-18T10:00:03Z done, failed steps: 1\n')
        failed, complete = image_guest.failed_steps(log)
        self.assertTrue(complete)
        self.assertEqual(1, len(failed))
        self.assertTrue(failed[0].startswith('FAIL b'))
        self.assertEqual(([], False), image_guest.failed_steps('start\nOK   a: why\n'))


def iso_image(label):
    """The first 18 sectors of an ISO 9660 disc: a primary volume descriptor with the given label."""
    start = build_image.PVD_OFFSET
    data = bytearray(start + 2048)
    data[start] = 1
    data[start + 1:start + 6] = b'CD001'
    data[start + 6] = 1
    data[start + 40:start + 72] = label.encode('ascii').ljust(32)
    return bytes(data)


ENGLISH_LABEL = 'CCCOMA_X64FRE_EN-US_DV9'


def stand(directory, label=ENGLISH_LABEL, **overrides):
    """Configuration data whose inputs are small files in `directory`; returns (data, paths)."""
    paths = {name: os.path.join(directory, name) for name in (
        'win.iso', 'virtio.iso', 'code.fd', 'vars.fd', 'qemu', 'img', 'xorriso', 'swtpm')}
    for name, path in paths.items():
        Path(path).write_bytes(iso_image(label) if name == 'win.iso' else b'x')
    data = image_config_data()
    data['inputs'].update(windows_iso=paths['win.iso'], virtio_win_iso=paths['virtio.iso'],
                          virtio_win_sha256=image_plan.sha256_file(paths['virtio.iso'])[0])
    data['tools'].update(qemu_system=paths['qemu'], qemu_img=paths['img'], xorriso=paths['xorriso'],
                         swtpm=paths['swtpm'])
    data['firmware'].update(ovmf_code=paths['code.fd'], ovmf_vars_template=paths['vars.fd'])
    data['build']['output_directory'] = os.path.join(directory, 'output')
    for section, values in overrides.items():
        data[section].update(values)
    return data, paths


class FakeQemu:
    """Stands in for the QEMU process: alive until the fake QMP server is told to quit."""

    def __init__(self):
        self.exited = False
        self.returncode = None

    def poll(self):
        return 0 if self.exited else None

    def wait(self, timeout=None):
        return 0


class GuestWatchTests(SocketServing, unittest.TestCase):
    def qmp_server(self, qemu, statuses):
        seen = []

        def handler(stream):
            stream.sendall(b'{"QMP": {"version": {}}}\r\n')
            for line in self.lines(stream):
                command = json.loads(line)['execute']
                seen.append(command)
                reply = {'return': {}}
                if command == 'query-status':
                    status = statuses.pop(0) if len(statuses) > 1 else statuses[0]
                    reply = {'return': {'status': status, 'running': status == 'running'}}
                stream.sendall(json.dumps(reply).encode() + b'\r\n')
                if command == 'quit':
                    qemu.exited = True
                    break
            stream.close()
        return self.serve(handler), seen

    def test_a_machine_in_internal_error_fails_at_once_with_a_screenshot_and_the_log_and_quits_qemu(self):
        qemu = FakeQemu()
        host, seen = self.qmp_server(qemu, ['running', 'internal-error'])
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'qemu.log'
            log.write_text('noise\n' * 50 + 'KVM: entry failed, hardware error 0xffffffff\n')
            watch = build_image.GuestWatch(qemu, lambda: host, directory, log)
            with self.assertRaises(build_image.BuildError) as raised:
                build_image.wait_for_shutdown(qemu, watch, 600, interval=0, sleep=lambda _: None)
        message = str(raised.exception)
        self.assertIn('internal-error', message)
        self.assertIn('failure-screen.ppm', message)
        self.assertIn('entry failed', message)
        self.assertLessEqual(message.count('noise'), build_image.LOG_TAIL_LINES)
        self.assertEqual(['qmp_capabilities', 'query-status', 'query-status', 'screendump', 'quit'], seen)
        self.assertTrue(qemu.exited)

    def test_every_state_that_never_recovers_by_itself_is_fatal(self):
        for state in ('internal-error', 'guest-panicked', 'io-error'):
            self.assertIn(state, build_image.FATAL_STATES)
        for state in ('running', 'prelaunch', 'shutdown'):
            self.assertNotIn(state, build_image.FATAL_STATES)

    def test_a_running_machine_is_left_alone_until_it_shuts_itself_down(self):
        qemu = FakeQemu()
        host, seen = self.qmp_server(qemu, ['running'])
        sleeps = []

        def sleep(seconds):
            sleeps.append(seconds)
            qemu.exited = len(sleeps) >= 3
        watch = build_image.GuestWatch(qemu, lambda: host, '.', 'no-such-log')
        build_image.wait_for_shutdown(qemu, watch, 600, interval=0, sleep=sleep)
        self.assertEqual(3, len(sleeps))
        self.assertNotIn('quit', seen)

    def screen_server(self, qemu, frames):
        """A QMP server whose screendump writes the next frame; `frames` repeats its last entry."""
        seen = []

        def handler(stream):
            stream.sendall(b'{"QMP": {"version": {}}}\r\n')
            for line in self.lines(stream):
                request = json.loads(line)
                command = request['execute']
                seen.append(command)
                reply = {'return': {}}
                if command == 'query-status':
                    reply = {'return': {'status': 'running', 'running': True}}
                elif command == 'screendump':
                    frame = frames.pop(0) if len(frames) > 1 else frames[0]
                    Path(request['arguments']['filename']).write_bytes(frame)
                stream.sendall(json.dumps(reply).encode() + b'\r\n')
                if command == 'quit':
                    qemu.exited = True
                    break
            stream.close()
        return self.serve(handler), seen

    def watch(self, qemu, host, directory, clock, **options):
        events = []
        watch = build_image.GuestWatch(qemu, lambda: host, directory, Path(directory) / 'qemu.log',
                                       screen_interval=120, clock=clock,
                                       record=lambda **fields: events.append(fields), **options)
        return watch, events

    def test_a_screen_that_does_not_change_for_twenty_minutes_fails_as_stalled_and_qemu_quits(self):
        qemu = FakeQemu()
        host, seen = self.screen_server(qemu, [b'frame one', b'frame two', b'oobe page'])
        now = [0.0]
        with tempfile.TemporaryDirectory() as directory:
            watch, events = self.watch(qemu, host, directory, lambda: now[0])
            with self.assertRaisesRegex(build_image.BuildError, 'screen-stalled.*20 minutes') as raised:
                while True:
                    watch.check()
                    now[0] += 120
                    self.assertLess(now[0], 3000)
            # Two changes at 0 and 120 s, then the same page from 240 s: twenty minutes later it stalls.
            self.assertEqual(240 + 20 * 60, now[0])
            self.assertIn('failure-screen.ppm', str(raised.exception))
            self.assertEqual(['screendump', 'quit'], seen[-2:])
            self.assertTrue(qemu.exited)
            self.assertTrue((Path(directory) / 'screens' / 'screen-0001.ppm').is_file())
        self.assertEqual('screen', events[0]['stage'])
        self.assertEqual(64, len(events[0]['sha256']))
        self.assertNotEqual(events[0]['sha256'], events[1]['sha256'])
        self.assertEqual(events[2]['sha256'], events[3]['sha256'])

    def test_a_screen_that_keeps_changing_never_stalls_and_only_the_last_frames_are_kept(self):
        qemu = FakeQemu()
        host, _ = self.screen_server(qemu, [f'frame {n}'.encode() for n in range(40)])
        now = [0.0]
        with tempfile.TemporaryDirectory() as directory:
            watch, events = self.watch(qemu, host, directory, lambda: now[0], keep=5)
            for _ in range(40):
                watch.check()
                now[0] += 120
            kept = sorted(path.name for path in (Path(directory) / 'screens').iterdir())
        self.assertEqual([f'screen-{n:04d}.ppm' for n in range(36, 41)], kept)
        self.assertEqual(40, len(events))

    def test_a_screenshot_is_taken_only_once_per_interval(self):
        qemu = FakeQemu()
        host, seen = self.screen_server(qemu, [b'a', b'b'])
        now = [0.0]
        with tempfile.TemporaryDirectory() as directory:
            watch, events = self.watch(qemu, host, directory, lambda: now[0])
            for _ in range(10):
                watch.check()
                now[0] += 5
        self.assertEqual(1, seen.count('screendump'))
        self.assertEqual(1, len(events))

    def test_without_an_interval_no_screenshot_is_taken(self):
        qemu = FakeQemu()
        host, seen = self.screen_server(qemu, [b'a'])
        with tempfile.TemporaryDirectory() as directory:
            build_image.GuestWatch(qemu, lambda: host, directory, Path(directory) / 'qemu.log').check()
            self.assertFalse((Path(directory) / 'screens').exists())
        self.assertNotIn('screendump', seen)

    def test_the_time_running_out_is_a_failure_with_evidence_too(self):
        qemu = FakeQemu()
        host, seen = self.qmp_server(qemu, ['running'])
        ticks = iter(range(0, 1000, 100))
        with tempfile.TemporaryDirectory() as directory:
            watch = build_image.GuestWatch(qemu, lambda: host, directory, Path(directory) / 'qemu.log')
            with self.assertRaisesRegex(build_image.BuildError, 'did not shut down in time'):
                build_image.wait_for_shutdown(qemu, watch, 250, interval=0, clock=lambda: next(ticks),
                                              sleep=lambda _: None)
        self.assertEqual(['screendump', 'quit'], seen[-2:])

    def test_a_qmp_that_cannot_be_reached_is_not_a_failure_of_the_machine(self):
        qemu = FakeQemu()

        def refuse():
            raise ConnectionRefusedError()
        build_image.GuestWatch(qemu, refuse, '.', 'no-such-log').check()

    def test_a_failure_found_while_pressing_keys_is_examined_over_the_same_connection(self):
        qemu = FakeQemu()
        host, seen = self.qmp_server(qemu, ['internal-error'])
        connections = []

        def connect():
            connections.append(1)
            return host
        with tempfile.TemporaryDirectory() as directory:
            watch = build_image.GuestWatch(qemu, connect, directory, Path(directory) / 'qemu.log')
            with self.assertRaisesRegex(build_image.BuildError, 'internal-error'):
                image_guest.press_until(connect, 'spc', 60, interval=0, inspect=watch.check,
                                        sleep=lambda _: None)
        self.assertEqual([1], connections)
        self.assertEqual('send-key', seen[1])
        self.assertEqual(['query-status', 'screendump', 'quit'], seen[2:])

    def test_the_wait_for_the_agent_stops_when_the_check_raises(self):
        def check():
            raise build_image.BuildError('the guest is in state internal-error')
        with self.assertRaisesRegex(build_image.BuildError, 'internal-error'):
            image_guest.wait_for_agent(lambda: None, 60, check=check)


class FakeAgent:
    def __init__(self, answers):
        self.answers = answers

    def run(self, path, arguments, *, timeout=300):
        code, out = self.answers[arguments[-1].split()[0]]
        return code, out


class PlatformStateTests(unittest.TestCase):
    def agent(self, secure, tpm):
        return FakeAgent({'Confirm-SecureBootUEFI': secure, 'Get-Tpm': tpm})

    def test_secure_boot_and_the_tpm_are_read_from_the_guest_and_recorded(self):
        agent = self.agent((0, b'True\r\n'), (0, b'{"TpmPresent":true,"TpmReady":true}\r\n'))
        result = {}
        build_image.record_platform(agent, result)
        self.assertEqual({'secure_boot': True, 'tpm': {'present': True, 'ready': True}}, result)

    def test_secure_boot_off_is_recorded_as_false_so_the_stop_point_applies(self):
        agent = self.agent((0, b'False\r\n'), (0, b'{"TpmPresent":true,"TpmReady":false}'))
        result = {}
        build_image.record_platform(agent, result)
        self.assertIs(False, result['secure_boot'])
        self.assertEqual({'present': True, 'ready': False}, result['tpm'])

    def test_an_error_of_either_command_is_recorded_not_guessed(self):
        agent = self.agent((1, b'Confirm-SecureBootUEFI : Cmdlet not supported on this platform'), (0, b'garbage'))
        result = {}
        build_image.record_platform(agent, result)
        self.assertIsNone(result['secure_boot'])
        self.assertIn('secure_boot_error', result)
        self.assertIsNone(result['tpm'])
        self.assertIn('tpm_error', result)
        with self.assertRaises(image_guest.GuestError):
            image_guest.tpm_state(self.agent((0, b'True'), (1, b'{"TpmPresent":true,"TpmReady":true}')))


class DiscLanguageTests(unittest.TestCase):
    def test_the_label_is_read_from_the_primary_volume_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'disc.iso'
            path.write_bytes(iso_image(ENGLISH_LABEL))
            self.assertEqual(ENGLISH_LABEL, build_image.iso_volume_label(path))

    def test_a_file_that_is_not_an_iso_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'disc.iso'
            path.write_bytes(b'x' * 40000)
            with self.assertRaisesRegex(build_image.BuildError, 'ISO 9660'):
                build_image.iso_volume_label(path)
            path.write_bytes(b'x')
            with self.assertRaisesRegex(build_image.BuildError, 'ISO 9660'):
                build_image.iso_volume_label(path)

    def test_an_english_disc_passes_and_a_russian_one_is_refused_before_the_directory_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            data, _ = stand(directory)
            self.assertIsNotNone(build_image.check_inputs(image_config.parse(data)))
        with tempfile.TemporaryDirectory() as directory:
            data, _ = stand(directory, label='CCCOMA_X64FRE_RU-RU_DV9')
            loaded = image_config.parse(data)
            with self.assertRaisesRegex(build_image.BuildError, 'RU-RU.*en-US'):
                build_image.build(loaded)
            self.assertFalse(Path(loaded.output_directory).exists())


class FirmwareScriptTests(unittest.TestCase):
    SCRIPT = (TOOL / 'build-ovmf.sh').read_text(encoding='utf-8')

    def test_the_firmware_has_secure_boot_and_tpm_but_no_smm_at_a_pinned_tag(self):
        for flag in ('SECURE_BOOT_ENABLE=TRUE', 'SMM_REQUIRE=FALSE', 'TPM2_ENABLE=TRUE', 'FD_SIZE_4MB'):
            self.assertIn(flag, self.SCRIPT)
        self.assertRegex(self.SCRIPT, r'(?m)^EDK2_TAG=edk2-stable\d{6}$')
        self.assertNotIn('SECURE_BOOT_ENABLE=FALSE', self.SCRIPT)

    def test_the_build_tools_are_pinned_debian_packages_unpacked_and_never_installed(self):
        digests = re.findall(r"\|([0-9a-f]{64})'", self.SCRIPT)
        self.assertEqual(3, len(digests))
        self.assertIn('dpkg -x', self.SCRIPT)
        for word in ('apt-get install', 'sudo', 'dpkg -i'):
            self.assertNotIn(word, self.SCRIPT)

    def test_the_script_does_not_name_the_private_notes_or_a_stand(self):
        self.assertNotIn('tools/docs', self.SCRIPT)
        self.assertNotIn('/home/', self.SCRIPT)


class BuildHelperTests(unittest.TestCase):
    @controller_only
    def test_the_password_file_is_private_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'secret')
            build_image.write_secret(path, 'value')
            self.assertEqual(0o600, stat.S_IMODE(os.stat(path).st_mode))
            with self.assertRaises(FileExistsError):
                build_image.write_secret(path, 'other')

    def test_a_build_into_an_existing_directory_is_refused_before_anything_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            data, _ = stand(directory)
            data['build']['output_directory'] = directory
            with self.assertRaisesRegex(build_image.BuildError, 'output directory'):
                build_image.build(image_config.parse(data))

    def test_a_virtio_disc_that_differs_from_the_pin_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            data, _ = stand(directory)
            data['inputs']['virtio_win_sha256'] = '0' * 64
            with self.assertRaisesRegex(build_image.BuildError, 'virtio-win'):
                build_image.check_inputs(image_config.parse(data))


class FirstLogonFixTests(unittest.TestCase):
    CODE = '\n'.join(line for line in SCRIPT.splitlines() if not line.lstrip().startswith('#'))

    def step(self, name):
        found = re.search(rf"^Invoke-RosetunStep '{name}' '[^']+' \{{\n(.*?)^\}}", SCRIPT, re.M | re.S)
        self.assertIsNotNone(found, name)
        return found.group(1)

    def test_a_package_that_is_already_installed_is_not_an_error_and_every_driver_has_its_own_line(self):
        self.assertNotRegex(self.CODE, r'LASTEXITCODE -ne 0\) \{\s*throw "pnputil')
        self.assertIn('/enum-drivers', self.CODE)
        self.assertIn('Original Name:', self.CODE)
        self.assertIn('0, 3010', self.CODE)
        step = self.step('virtio-drivers')
        for driver in ('viostor', 'NetKVM', 'vioserial'):
            self.assertIn(f"'{driver}'", step)
        self.assertIn('Install-RosetunDriverPackage', step)
        # One driver never ends the loop: the failures are collected and reported once, after it.
        loop = step[step.index('foreach'):step.index('if ($missing.Count')]
        self.assertNotIn('throw', loop)
        self.assertIn('not installed and not in the driver store', step)

    def test_a_key_is_created_only_when_it_is_missing_and_a_value_is_read_back(self):
        self.assertIsNone(re.search(r'New-Item\s[^\n]*-Force', self.CODE))
        self.assertRegex(self.CODE, r'if \(Test-Path -LiteralPath \$Path\) \{\s*return')
        self.assertIn('Get-ItemPropertyValue -Path $Path -Name $Name', self.CODE)
        self.assertIn('reads back as', self.CODE)

    def test_a_refused_scheduled_task_is_never_swallowed(self):
        calls = [line for line in self.CODE.splitlines() if re.match(r'\s*(\$null = )?Disable-ScheduledTask', line)]
        self.assertTrue(calls)
        for line in calls:
            self.assertIn('-ErrorAction Stop', line)
        self.assertRegex(self.CODE, r'try \{\s*\$null = Disable-ScheduledTask ')
        self.assertIn('/DISABLE', self.CODE)
        for name in ('update-tasks-off', 'telemetry-tasks'):
            step = self.step(name)
            self.assertIn('throw', step)
            self.assertIn('still enabled', step)

    def test_a_protected_service_is_disabled_by_a_system_task_and_the_result_is_read_back(self):
        step = self.step('delivery-optimization-off')
        self.assertIn("Disable-RosetunService 'DoSvc' -ViaSystemTask", step)
        self.assertIn("Set-RosetunServiceStartAsSystem 'WaaSMedicSvc'", self.step('windows-update-medic'))
        self.assertIn('REG_DWORD /d 4', self.CODE)
        self.assertIn('Confirm-RosetunServiceDisabled', self.CODE)
        self.assertIn('is protected in this build', self.CODE)
        for word in ('takeown', 'icacls', 'SetOwner', 'Set-Acl', 'SetAccessControl', 'SeTakeOwnership'):
            self.assertNotIn(word.lower(), self.CODE.lower(), word)

    def test_deferred_work_is_finished_with_documented_commands_that_spare_defender(self):
        step = self.step('deferred-work-complete')
        self.assertIn('/Cleanup-Image /StartComponentCleanup', step)
        self.assertIn('executeQueuedItems', step)
        for word in ('DisableRealtimeMonitoring', 'DisableAntiSpyware', 'Add-MpPreference', 'ExclusionPath',
                     'WinDefend', 'Update-MpSignature'):
            self.assertNotIn(word.lower(), self.CODE.lower(), word)
        self.assertLess(SCRIPT.index("'deferred-work-complete'"), SCRIPT.index("Invoke-RosetunStep 'retrim'"))


class CpuProcessTests(unittest.TestCase):
    OUTPUT = (b'"(PDH-CSV 4.0)","\\\\H\\Process(Idle)\\% Processor Time","\\\\H\\Process(_Total)\\% Processor Time",'
              b'"\\\\H\\Process(MsMpEng)\\% Processor Time","\\\\H\\Process(svchost)\\% Processor Time",'
              b'"\\\\H\\Process(svchost#1)\\% Processor Time","\\\\H\\Process(System)\\% Processor Time"\r\n'
              b'"11/18/2026 10:00:00.1","0","0","0","0","0","0"\r\n'
              b'"11/18/2026 10:00:01.1","300","100","40","8","4","4"\r\n'
              b'"11/18/2026 10:00:02.1","300","100","40","8","4"," "\r\n'
              b'\r\nExiting, please wait...  The command completed successfully.\r\n')

    def test_processes_are_added_by_program_scaled_to_the_whole_machine_and_ranked(self):
        top = image_guest.top_processes_from_csv(self.OUTPUT, 4)
        self.assertEqual(['MsMpEng', 'svchost', 'System'], [entry['name'] for entry in top])
        # Three samples; MsMpEng 80/3 over four processors, svchost and svchost#1 together 24/3.
        self.assertEqual([6.7, 2.0, 0.3], [entry['percent'] for entry in top])
        self.assertEqual('MsMpEng 6.7%, svchost 2.0%, System 0.3%', image_guest.format_top_processes(top))
        self.assertEqual(['MsMpEng'], [entry['name'] for entry in image_guest.top_processes_from_csv(
            self.OUTPUT, 4, count=1)])

    def test_output_without_samples_is_an_error(self):
        with self.assertRaises(image_guest.GuestError):
            image_guest.top_processes_from_csv(b'nothing here', 4)

    def test_the_process_counter_is_asked_by_its_english_name(self):
        self.assertEqual('\\Process(*)\\% Processor Time', image_guest.process_counter_arguments(60)[0])


class NoReplyShutdownTests(SocketServing, unittest.TestCase):
    def test_a_command_can_be_sent_without_waiting_for_an_answer(self):
        host, guest = socket.socketpair()
        self.addCleanup(host.close)
        self.addCleanup(guest.close)
        agent = image_guest.Qga(host, timeout=1)
        agent.fire('guest-shutdown', {'mode': 'powerdown'})
        self.assertEqual({'execute': 'guest-shutdown', 'arguments': {'mode': 'powerdown'}},
                         json.loads(guest.recv(4096)))

    def test_a_program_is_started_and_waited_for_in_two_steps(self):
        answers = iter([{'return': {'pid': 7}}, {'return': {'exited': False}},
                        {'return': {'exited': True, 'exitcode': 0,
                                    'out-data': base64.b64encode(b'done').decode()}}])
        sent = []

        def handler(stream):
            for line in self.lines(stream):
                sent.append(json.loads(line)['execute'])
                stream.sendall(json.dumps(next(answers)).encode() + b'\n')
        agent = image_guest.Qga(self.serve(handler), timeout=5)
        pid = agent.start('prog', ['a'])
        self.assertEqual(7, pid)
        self.assertEqual((0, b'done'), agent.wait(pid, poll=0))
        self.assertEqual(['guest-exec', 'guest-exec-status', 'guest-exec-status'], sent)


class CalmConfigTests(unittest.TestCase):
    def test_the_calming_boot_has_defaults_and_the_example_states_them(self):
        loaded = image_config.load(EXAMPLE)
        self.assertEqual((5.0, 3, 45), (loaded.calm_cpu_percent, loaded.calm_quiet_minutes,
                                         loaded.calm_limit_minutes))
        data = image_config_data()
        for key in ('calm_cpu_percent', 'calm_quiet_minutes', 'calm_limit_minutes'):
            del data['build'][key]
        parsed = image_config.parse(data)
        self.assertEqual((5.0, 3, 45), (parsed.calm_cpu_percent, parsed.calm_quiet_minutes,
                                         parsed.calm_limit_minutes))

    def test_the_thresholds_are_checked(self):
        for changes in ({'calm_cpu_percent': 0.1}, {'calm_cpu_percent': 12}, {'calm_cpu_percent': True},
                        {'calm_quiet_minutes': 0}, {'calm_quiet_minutes': 2.5},
                        {'calm_limit_minutes': 3}, {'calm_quiet_minutes': 10, 'calm_limit_minutes': 10}):
            with self.assertRaises(image_config.ConfigError, msg=str(changes)):
                config(**changes)
        self.assertEqual(7.0, config(calm_cpu_percent=7).calm_cpu_percent)


class FakeCalmWatch:
    """What `wait_for_calm` needs of the watch: a check, and a failure that closes QEMU."""

    def __init__(self):
        self.checks = 0
        self.failures = []

    def check(self):
        self.checks += 1

    def failure(self, reason):
        self.failures.append(reason)
        return build_image.BuildError(reason)


class CalmPhaseTests(unittest.TestCase):
    def run_calm(self, means, **options):
        """Feed `means` to `wait_for_calm`; an exception in the list is raised by the sample."""
        now = [0.0]
        queue = list(means)
        events = []

        def sample():
            now[0] += 60
            value = queue.pop(0) if len(queue) > 1 else queue[0]
            if isinstance(value, Exception):
                raise value
            return value
        watch = FakeCalmWatch()
        arguments = dict(threshold=5.0, windows=3, limit_seconds=45 * 60, clock=lambda: now[0],
                         sleep=lambda seconds: now.__setitem__(0, now[0] + seconds),
                         record=lambda **fields: events.append(fields))
        arguments.update(options)
        return watch, events, lambda: build_image.wait_for_calm(sample, watch, **arguments)

    def test_rest_is_reached_after_the_required_quiet_windows_in_a_row(self):
        watch, events, run = self.run_calm([30.0, 12.0, 4.0, 4.5, 3.2])
        record = run()
        self.assertEqual({'windows_taken': 5, 'quiet_windows': 3, 'last_mean_percent': 3.2,
                          'seconds_to_rest': 300.0}, record)
        self.assertEqual([0, 0, 1, 2, 3], [event['quiet_windows'] for event in events])
        self.assertEqual([], watch.failures)
        self.assertGreaterEqual(watch.checks, 5)

    def test_one_busy_window_starts_the_count_again(self):
        _, _, run = self.run_calm([4.0, 4.0, 9.0, 4.0, 4.0, 4.0])
        self.assertEqual(6, run()['windows_taken'])

    def test_a_window_exactly_at_the_threshold_is_not_quiet(self):
        _, _, run = self.run_calm([5.0, 5.0, 5.0, 4.9, 4.9, 4.9])
        self.assertEqual(6, run()['windows_taken'])

    def test_a_window_that_could_not_be_taken_resets_the_count_and_the_wait_goes_on(self):
        _, events, run = self.run_calm([4.0, 4.0, image_guest.GuestError('connection closed'), 4.0, 4.0, 4.0])
        self.assertEqual(5, run()['windows_taken'])
        self.assertEqual(['calm-sample', 'calm-sample', 'calm-sample-failed'],
                         [event['stage'] for event in events[:3]])

    def test_a_guest_that_never_rests_is_refused_with_the_last_mean_and_the_busiest_processes(self):
        watch, _, run = self.run_calm([20.0], limit_seconds=600,
                                      describe_top=lambda: 'TrustedInstaller 14.0%, msmpeng 3.1%')
        with self.assertRaises(build_image.BuildError) as raised:
            run()
        message = str(raised.exception)
        self.assertEqual([message], watch.failures)
        self.assertIn('did not come to rest within 10 minutes', message)
        self.assertIn('last mean 20.0 %', message)
        self.assertIn('0 of 3 quiet windows below 5.0 %', message)
        self.assertIn('TrustedInstaller 14.0%', message)

    def test_a_guest_that_cannot_be_sampled_at_all_is_refused_too(self):
        watch, _, run = self.run_calm([image_guest.GuestError('connection closed')], limit_seconds=120)
        with self.assertRaisesRegex(build_image.BuildError, 'last mean none'):
            run()
        self.assertEqual(1, len(watch.failures))

    def test_a_machine_that_has_failed_ends_the_wait_at_once(self):
        watch = FakeCalmWatch()

        def check():
            raise build_image.BuildError('the guest is in state internal-error')
        watch.check = check
        with self.assertRaisesRegex(build_image.BuildError, 'internal-error'):
            build_image.wait_for_calm(lambda: 1.0, watch, threshold=5.0, windows=1, limit_seconds=60)

    def test_the_calming_screen_never_stalls_by_itself(self):
        qemu = FakeQemu()
        watch = build_image.GuestWatch(qemu, lambda: None, '.', 'no-such-log', screen_interval=120,
                                       stall_seconds=None)
        self.assertIsNone(watch.stall_seconds)

    def test_the_descriptor_carries_the_calming_record(self):
        record = {'last_mean_percent': 1.2, 'duration_seconds': 700.0}
        with tempfile.TemporaryDirectory() as directory:
            layout = image_plan.Layout(directory)
            args = dict(uuid='u', windows_iso_sha256='a' * 64, disk_sha256='b' * 64, disk_size=1,
                        vars_sha256='c' * 64, code_sha256='d' * 64, template_sha256='e' * 64,
                        tpm_files={}, built_at='2026-11-19T00:00:00+00:00')
            self.assertNotIn('calm', image_plan.descriptor(config(), layout, **args)['windows'])
            self.assertEqual(record, image_plan.descriptor(config(), layout, calm=record, **args)['windows']['calm'])


FIRST_LOGON_LOG = (b'2026-11-19T10:00:00Z start\r\n2026-11-19T10:00:01Z OK   a: why\r\n'
                   b'2026-11-19T10:00:02Z done, failed steps: 0\r\n')
TYPEPERF_CPU = b'"(PDH-CSV 4.0)","\\\\H\\Processor(_Total)\\% Processor Time"\r\n"t","1.0"\r\n"t","3.0"\r\n'
TYPEPERF_PROCESSES = (b'"(PDH-CSV 4.0)","\\\\H\\Process(Idle)\\% Processor Time","\\\\H\\Process(msmpeng)\\% Processor Time"\r\n'
                      b'"t","0","0"\r\n"t","390","8"\r\n')


class FakeMeasureAgent:
    def __init__(self, shutdown_error=None):
        self.shutdown_error = shutdown_error
        self.sent = []
        self.programs = {}

    def sync(self):
        pass

    def start(self, path, arguments):
        pid = len(self.programs) + 1
        self.programs[pid] = TYPEPERF_PROCESSES if '\\Process(*)' in arguments[0] else TYPEPERF_CPU
        return pid

    def wait(self, pid, *, timeout=300, **_):
        return 0, self.programs[pid]

    def run(self, path, arguments, *, timeout=300):
        code, out = {'Confirm-SecureBootUEFI': (0, b'True'),
                     'Get-Tpm': (0, b'{"TpmPresent":true,"TpmReady":true}')}[arguments[-1].split()[0]]
        return code, out

    def read_file(self, path, limit=0):
        return FIRST_LOGON_LOG

    def fire(self, command, arguments=None):
        self.sent.append(command)
        if self.shutdown_error is not None:
            raise self.shutdown_error


class MeasureVerdictTests(unittest.TestCase):
    def measure(self, agent, *, exits=True):
        """Run `build_image.measure` over a built image in a temporary directory, with the processes faked."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        data, _ = stand(directory.name)
        data['build']['output_directory'] = str(root / 'image')
        loaded = image_config.parse(data)
        source = image_plan.Layout(loaded.output_directory)
        Path(loaded.output_directory).mkdir()
        Path(source.disk).write_bytes(b'disk')
        Path(source.vars).write_bytes(b'vars')
        Path(source.tpm_state).mkdir()
        Path(source.tpm_state, image_plan.TPM_STATE_FILE).write_bytes(b'tpm')
        Path(source.descriptor).write_text(json.dumps({
            'identifier': 'windows-test', 'size_bytes': 4, 'sha256': image_plan.sha256_file(source.disk)[0],
            'windows': {'devices': {'uuid_at_build': 'u'}}}), encoding='utf-8')
        qemu = FakeQemu()
        agent_fire = agent.fire

        def fire(command, arguments=None):
            # A powered-down guest takes QEMU with it, whether or not the channel answered.
            qemu.exited = exits
            return agent_fire(command, arguments)
        agent.fire = fire
        patches = [
            mock.patch.object(build_image, 'run_checked'),
            mock.patch.object(build_image, 'start', return_value=qemu),
            mock.patch.object(build_image, 'wait_for_path'),
            mock.patch.object(build_image, 'stop'),
            mock.patch.object(build_image, 'unix_connection', return_value=lambda: io.BytesIO()),
            mock.patch.object(build_image, 'GuestWatch', return_value=mock.Mock(check=lambda: None)),
            mock.patch.object(build_image, 'open_agent', side_effect=lambda connect, timeout=30: (
                mock.Mock(close=lambda: None), agent)),
            mock.patch.object(image_guest, 'wait_for_agent', return_value=20.0),
            mock.patch.object(build_image, 'MEASURE_SHUTDOWN_SECONDS', 0),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.output_directory = loaded.output_directory
        result = build_image.measure(loaded, settle=0, sleep=lambda seconds: None)
        work = next(Path(loaded.output_directory).glob('measure-*'))
        return result, json.loads((work / 'measure.json').read_text(encoding='utf-8')), work

    def test_a_shutdown_that_is_never_answered_does_not_take_the_verdict_away(self):
        agent = FakeMeasureAgent(shutdown_error=image_guest.GuestError('connection closed'))
        result, stored, work = self.measure(agent)
        self.assertEqual(['guest-shutdown'], agent.sent)
        self.assertEqual('within the limits (UNQUALIFIED)', stored['verdict'])
        self.assertEqual(result, stored)
        self.assertIn('connection closed', stored['shutdown_error'])
        self.assertTrue(stored['shutdown_clean'])
        self.assertEqual(2.0, stored['cpu_percent'])
        self.assertEqual([{'name': 'msmpeng', 'percent': 1.0}], stored['top_processes'])
        self.assertEqual(FIRST_LOGON_LOG, (work / 'first-logon.log').read_bytes())

    def test_a_channel_that_closes_while_the_command_is_sent_is_the_same_case(self):
        _, stored, _ = self.measure(FakeMeasureAgent(shutdown_error=BrokenPipeError('closed')))
        self.assertTrue(stored['verdict'].startswith('within the limits'))

    def test_a_guest_that_does_not_go_down_is_a_stop_with_the_measurements_kept(self):
        _, stored, _ = self.measure(FakeMeasureAgent(), exits=False)
        self.assertFalse(stored['shutdown_clean'])
        self.assertEqual('STOP: the guest did not shut down after the request', stored['verdict'])
        self.assertEqual(2.0, stored['cpu_percent'])

    def test_a_cpu_figure_over_the_limit_is_explained_by_the_process_list_in_the_same_file(self):
        agent = FakeMeasureAgent()
        original = agent.start

        def start(path, arguments):
            pid = original(path, arguments)
            if '\\Processor(_Total)' in arguments[0]:
                agent.programs[pid] = TYPEPERF_CPU.replace(b'"1.0"', b'"15.0"').replace(b'"3.0"', b'"17.0"')
            return pid
        agent.start = start
        _, stored, _ = self.measure(agent)
        self.assertEqual('STOP: CPU load at rest is at or above the limit', stored['verdict'])
        self.assertEqual('msmpeng', stored['top_processes'][0]['name'])

    def test_an_error_before_the_measurements_still_leaves_a_verdict(self):
        agent = FakeMeasureAgent()
        agent.read_file = lambda path, limit=0: (_ for _ in ()).throw(image_guest.GuestError('no log'))
        with self.assertRaises(build_image.BuildError):
            self.measure(agent)
        stored = json.loads(next(Path(self.output_directory).glob('measure-*/measure.json')).read_text(encoding='utf-8'))
        self.assertTrue(stored['verdict'].startswith('STOP: '))


class CalmBootTests(unittest.TestCase):
    def test_the_second_boot_waits_for_rest_saves_the_log_and_shuts_down_through_the_agent(self):
        agent = FakeMeasureAgent()
        qemu = FakeQemu()
        qemu.returncode = 0
        started = []
        agent_fire = agent.fire

        def fire(command, arguments=None):
            qemu.exited = True
            return agent_fire(command, arguments)
        agent.fire = fire
        agent.run = lambda path, arguments, *, timeout=300: (0, TYPEPERF_CPU)
        with tempfile.TemporaryDirectory() as directory:
            data, _ = stand(directory)
            loaded = image_config.parse(data)
            output = Path(directory) / 'image'
            output.mkdir()
            layout = image_plan.Layout(output)
            Path(layout.qmp).write_bytes(b'stale')
            patches = [
                mock.patch.object(build_image, 'start', side_effect=lambda argv, log: started.append(argv) or qemu),
                mock.patch.object(build_image, 'wait_for_path'),
                mock.patch.object(build_image, 'stop'),
                mock.patch.object(build_image, 'unix_connection', return_value=lambda: io.BytesIO()),
                mock.patch.object(build_image, 'GuestWatch', return_value=mock.Mock(check=lambda: None)),
                mock.patch.object(build_image, 'open_agent', side_effect=lambda connect, timeout=30: (
                    mock.Mock(close=lambda: None), agent)),
                mock.patch.object(image_guest, 'wait_for_agent', return_value=20.0),
            ]
            for patch in patches:
                patch.start()
                self.addCleanup(patch.stop)
            record = build_image.calm(loaded, layout, output, 'u')
            self.assertFalse(Path(layout.qmp).exists())
            self.assertEqual(FIRST_LOGON_LOG, (output / 'first-logon.log').read_bytes())
            events = [json.loads(line)['stage'] for line in Path(layout.events).read_text().splitlines()]
        self.assertEqual(['calm-started', 'calm-agent-ready', 'calm-sample', 'calm-sample', 'calm-sample',
                          'first-logon-log', 'calm-reached', 'calm-shut-down'], events)
        self.assertEqual(['guest-shutdown'], agent.sent)
        self.assertEqual((2.0, 3, 20.0), (record['last_mean_percent'], record['windows_taken'],
                                          record['agent_ready_seconds']))
        self.assertEqual((5.0, 3, 45), (record['cpu_limit_percent'], record['quiet_windows_required'],
                                         record['limit_minutes']))
        # The same machine as the install and the measurement, without the installation media.
        self.assertEqual(2, len(started))
        self.assertNotIn('answers', ' '.join(started[1]))


if __name__ == '__main__':
    unittest.main()
