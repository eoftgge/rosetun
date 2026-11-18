"""Answer media for an unattended Windows 11 setup: Autounattend.xml and the first-logon script.

Only documented unattend settings are used. Nothing here lowers a setup check, selects a
product key or touches the firewall.
"""

import base64
import secrets
import string
import xml.etree.ElementTree as ET

LABEL = 'ROSETUN_ANSWERS'
NS = 'urn:schemas-microsoft-com:unattend'
WCM = 'http://schemas.microsoft.com/WMIConfig/2002/State'
PUBLIC_KEY_TOKEN = '31bf3856ad364e35'
# The setup environment names the drives of the build media by arrival order. Which letter the
# virtio-win disc gets is not fixed, so every plausible one is listed; a missing path is skipped.
DRIVER_LETTERS = 'DEFG'
DRIVER_DIRECTORIES = ('viostor', 'NetKVM', 'vioserial')
DRIVER_OS = 'w11'
PASSWORD_LENGTH = 24

ET.register_namespace('', NS)
ET.register_namespace('wcm', WCM)
ET.register_namespace('xsi', 'http://www.w3.org/2001/XMLSchema-instance')


def generate_password():
    """A fresh password per build. It is neither logged nor kept anywhere in the repository."""
    alphabet = string.ascii_letters + string.digits + '-_'
    while True:
        value = ''.join(secrets.choice(alphabet) for _ in range(PASSWORD_LENGTH))
        if (any(c.islower() for c in value) and any(c.isupper() for c in value)
                and any(c.isdigit() for c in value)):
            return value


def _encode_password(value):
    # PlainText=false is the documented obfuscated form: base64 of UTF-16LE of password + "Password".
    # It keeps the secret out of a casual grep; it is not encryption.
    return base64.b64encode((value + 'Password').encode('utf-16-le')).decode('ascii')


def _q(tag):
    return '{%s}%s' % (NS, tag)


def _add(parent, tag, text=None, **attrs):
    element = ET.SubElement(parent, _q(tag))
    for key, value in attrs.items():
        element.set(key, value)
    if text is not None:
        element.text = str(text)
    return element


def _list_item(parent, tag, key=None):
    element = ET.SubElement(parent, _q(tag))
    element.set('{%s}action' % WCM, 'add')
    if key is not None:
        element.set('{%s}keyValue' % WCM, str(key))
    return element


def _component(settings, name):
    component = ET.SubElement(settings, _q('component'))
    component.set('name', name)
    component.set('processorArchitecture', 'amd64')
    component.set('publicKeyToken', PUBLIC_KEY_TOKEN)
    component.set('language', 'neutral')
    component.set('versionScope', 'nonSxS')
    return component


def _password(parent, value):
    password = _add(parent, 'Password')
    _add(password, 'Value', _encode_password(value))
    _add(password, 'PlainText', 'false')


def autounattend(config, password):
    """Build the answer file. Returns bytes: UTF-8 with an XML declaration."""
    root = ET.Element(_q('unattend'))

    pe = _add(root, 'settings')
    pe.set('pass', 'windowsPE')

    international = _component(pe, 'Microsoft-Windows-International-Core-WinPE')
    _add(_add(international, 'SetupUILanguage'), 'UILanguage', config.language)
    _add(international, 'InputLocale', _keyboard(config.language))
    _add(international, 'SystemLocale', config.language)
    _add(international, 'UILanguage', config.language)
    _add(international, 'UserLocale', config.language)

    setup = _component(pe, 'Microsoft-Windows-Setup')
    disk_configuration = _add(setup, 'DiskConfiguration')
    _add(disk_configuration, 'WillShowUI', 'OnError')
    disk = _list_item(disk_configuration, 'Disk', 1)
    _add(disk, 'DiskID', 0)
    _add(disk, 'WillWipeDisk', 'true')
    create = _add(disk, 'CreatePartitions')
    # GPT for UEFI: EFI system, Microsoft reserved, Windows. Recovery is left out on purpose:
    # the image does not use Windows RE, and a missing partition removes one boot-time path.
    for order, (kind, size, extend) in enumerate(
            (('EFI', 300, None), ('MSR', 16, None), ('Primary', None, True)), 1):
        partition = _list_item(create, 'CreatePartition', order)
        _add(partition, 'Order', order)
        _add(partition, 'Type', kind)
        if extend:
            _add(partition, 'Extend', 'true')
        else:
            _add(partition, 'Size', size)
    modify = _add(disk, 'ModifyPartitions')
    for order, (label, fmt, letter) in enumerate(
            (('System', 'FAT32', None), (None, None, None), ('Windows', 'NTFS', 'C')), 1):
        partition = _list_item(modify, 'ModifyPartition', order)
        _add(partition, 'Order', order)
        _add(partition, 'PartitionID', order)
        if label:
            _add(partition, 'Label', label)
            _add(partition, 'Format', fmt)
        if letter:
            _add(partition, 'Letter', letter)

    image_install = _add(setup, 'ImageInstall')
    os_image = _add(image_install, 'OSImage')
    install_from = _add(os_image, 'InstallFrom')
    metadata = _list_item(install_from, 'MetaData')
    if config.image_index:
        _add(metadata, 'Key', '/IMAGE/INDEX')
        _add(metadata, 'Value', config.image_index)
    else:
        _add(metadata, 'Key', '/IMAGE/NAME')
        _add(metadata, 'Value', config.edition_name)
    install_to = _add(os_image, 'InstallTo')
    _add(install_to, 'DiskID', 0)
    _add(install_to, 'PartitionID', 3)
    _add(os_image, 'WillShowUI', 'OnError')

    user_data = _add(setup, 'UserData')
    _add(user_data, 'AcceptEula', 'true')
    if config.empty_product_key_element:
        # Fallback when Setup stops at the product key page: an empty element, never a key.
        product_key = _add(user_data, 'ProductKey')
        _add(product_key, 'Key')
        _add(product_key, 'WillShowUI', 'OnError')

    pnp = _component(pe, 'Microsoft-Windows-PnpCustomizationsWinPE')
    paths = _add(pnp, 'DriverPaths')
    index = 0
    for letter in DRIVER_LETTERS:
        for directory in DRIVER_DIRECTORIES:
            index += 1
            item = _list_item(paths, 'PathAndCredentials', index)
            _add(item, 'Path', f'{letter}:\\{directory}\\{DRIVER_OS}\\amd64')

    specialize = _add(root, 'settings')
    specialize.set('pass', 'specialize')
    shell = _component(specialize, 'Microsoft-Windows-Shell-Setup')
    _add(shell, 'ComputerName', config.hostname)
    # The guest clock is the host's RTC in UTC; a UTC zone keeps both readings equal.
    _add(shell, 'TimeZone', 'UTC')
    encryption = _component(specialize, 'Microsoft-Windows-SecureStartup-FilterDriver')
    _add(encryption, 'PreventDeviceEncryption', 'true')

    oobe = _add(root, 'settings')
    oobe.set('pass', 'oobeSystem')
    shell = _component(oobe, 'Microsoft-Windows-Shell-Setup')
    options = _add(shell, 'OOBE')
    _add(options, 'HideEULAPage', 'true')
    _add(options, 'HideLocalAccountScreen', 'true')
    _add(options, 'HideOEMRegistrationScreen', 'true')
    _add(options, 'HideOnlineAccountScreens', 'true')
    _add(options, 'HideWirelessSetupInOOBE', 'true')
    _add(options, 'NetworkLocation', 'Other')
    _add(options, 'ProtectYourPC', 3)
    accounts = _add(shell, 'UserAccounts')
    local_accounts = _add(accounts, 'LocalAccounts')
    account = _list_item(local_accounts, 'LocalAccount')
    _add(account, 'Name', config.username)
    _add(account, 'Group', 'Administrators')
    _password(account, password)
    auto_logon = _add(shell, 'AutoLogon')
    _add(auto_logon, 'Enabled', 'true')
    # One logon only: it runs FirstLogonCommands once and leaves no standing autologon.
    _add(auto_logon, 'LogonCount', 1)
    _add(auto_logon, 'Username', config.username)
    _password(auto_logon, password)
    commands = _add(shell, 'FirstLogonCommands')
    command = _list_item(commands, 'SynchronousCommand', 1)
    _add(command, 'Order', 1)
    _add(command, 'Description', 'Rosetun image first logon')
    _add(command, 'CommandLine', first_logon_command())

    ET.indent(root)
    return ET.tostring(root, encoding='utf-8', xml_declaration=True) + b'\n'


def _keyboard(language):
    # US layout for the one language the image supports today; the code is "LCID:keyboard layout".
    if language != 'en-US':
        return language
    return '0409:00000409'


def first_logon_command():
    """Find the answer media by its label: the drive letter of a CD-ROM is not fixed."""
    return ("powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
            f"\"$v = Get-Volume -FileSystemLabel '{LABEL}'; & ($v.DriveLetter + ':\\first-logon.ps1')\"")


def xorriso_arguments(source, output):
    """Arguments after the executable; `-as mkisofs` with Joliet keeps the long mixed-case names."""
    return ['-no_rc', '-as', 'mkisofs', '-V', LABEL, '-J', '-r', '-o', str(output), str(source)]
