"""What the controller asks of a Windows guest through the agent (stage 9c): the programs and the readings.

The agent's `guest-exec` is CreateProcess without a shell, and a Windows console writes in the guest's OEM code
page, so every PowerShell command here runs as an encoded command and writes UTF-8 bytes straight to the raw
standard output stream (its error to the raw standard error stream); nothing depends on the console encoding or on a
profile. The scripts are PowerShell 5.1 (the guest's own), they change nothing in the guest, and each prints one
JSON object.

The boot identity is the guest's own count of boots, a registry value that the system raises by one at each start of
the kernel and that `reg.exe` prints at once. A Linux guest names a boot with a random UUID the kernel makes; Windows
has no such file, a file made at start by a task of the image would mean changing the image, which the controller
only reads, and PowerShell is no way to read it: the first PowerShell of a fresh boot of the image took a minute and
more on the stand, which made the observation of a new boot time out while the guest was well. The time of the last
boot, which only PowerShell gives, is read with the rest of the evidence and must differ after a restart.
"""

import base64
import json
import re

POWERSHELL = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
SHUTDOWN = 'C:\\Windows\\System32\\shutdown.exe'
REG = 'C:\\Windows\\System32\\reg.exe'
# The planned restart: now, no countdown. Nothing is forced; a guest at rest has no application to hold it back.
REBOOT_ARGUMENTS = ['/r', '/t', '0']
# The count of boots of the installation, kept by the system under its prefetcher's key.
BOOT_KEY = r'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'
BOOT_ARGUMENTS = ['query', BOOT_KEY, '/v', 'BootId']
SCRIPT_LIMIT = 6000
OUTPUT_LIMIT = 16 * 1024
# What the guest must give back for a text that does not fit the console's code page: the proof that the answer is
# UTF-8 bytes (e acute and the CJK ideograph for "world").
UTF8_PROBE = '\u00e9\u4e16'

# The wrapper writes the script's answer as UTF-8 to the raw stream. `$ErrorActionPreference = 'Stop'` turns an
# error of any cmdlet into the one `catch`, which says its type and message on the error stream and exits 1.
_WRAPPER = r'''$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$utf8 = New-Object System.Text.UTF8Encoding $false
function Write-RawText([System.IO.Stream]$stream, [string]$text) {
    $bytes = $utf8.GetBytes($text)
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush()
}
try {
    $answer = & {
%s
    }
    Write-RawText ([Console]::OpenStandardOutput()) ((@($answer) | ForEach-Object { [string]$_ }) -join "`n")
    exit 0
} catch {
    Write-RawText ([Console]::OpenStandardError()) ($_.Exception.GetType().FullName + ': ' + $_.Exception.Message)
    exit 1
}
'''


class GuestAnswerError(ValueError):
    pass


def arguments(script):
    """The command line words that run `script` under PowerShell 5.1 and return its answer as UTF-8."""
    if type(script) is not str or not 0 < len(script) <= SCRIPT_LIMIT:
        raise GuestAnswerError('invalid-powershell-script')
    encoded = base64.b64encode((_WRAPPER % script).encode('utf-16-le')).decode('ascii')
    return ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded]


def boot_count(output):
    """The count of boots out of what `reg.exe query` printed, which is ASCII whatever the guest's language."""
    if type(output) is not bytes or len(output) > OUTPUT_LIMIT:
        raise GuestAnswerError('invalid-windows-boot-id')
    try:
        text = output.decode('ascii')
    except UnicodeError:
        raise GuestAnswerError('invalid-windows-boot-id') from None
    found = re.findall(r'^[ \t]+BootId[ \t]+REG_DWORD[ \t]+0x([0-9a-fA-F]{1,8})[ \t]*\r?$', text, re.MULTILINE)
    if len(found) != 1:
        raise GuestAnswerError('invalid-windows-boot-id')
    return int(found[0], 16)


def boot_id(output):
    """The boot identity from the output of `reg.exe`: `win-` and the count of boots, a name the run state takes."""
    return 'win-%d' % boot_count(output)


def _object(text, names, limit=OUTPUT_LIMIT):
    if type(text) is not str or len(text) > limit:
        raise GuestAnswerError('invalid-guest-answer')
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        raise GuestAnswerError('invalid-guest-answer') from None
    if type(value) is not dict or set(value) != set(names):
        raise GuestAnswerError('invalid-guest-answer')
    return value


# What the run records of the guest, in one program: the system, Secure Boot, the TPM, the two readings that tell a
# boot (the count and the time of the last one) and a text that only UTF-8 carries across. A reading that fails is
# `null`, with the message of the one Secure Boot gives: the controller decides what a missing reading means.
EVIDENCE_SCRIPT = r'''$os = Get-CimInstance -ClassName Win32_OperatingSystem
$key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'
function Read-Value([scriptblock]$read) { try { & $read } catch { $null } }
$secure = Read-Value { [bool](Confirm-SecureBootUEFI) }
$secureError = $null
if ($secure -eq $null) { try { [void](Confirm-SecureBootUEFI) } catch { $secureError = $_.Exception.Message } }
$tpm = Read-Value { $t = Get-Tpm; @{ present = [bool]$t.TpmPresent; ready = [bool]$t.TpmReady } }
ConvertTo-Json -Compress -Depth 4 -InputObject @{
    caption = [string]$os.Caption
    version = [string]$os.Version
    build = [string]$os.BuildNumber
    architecture = [string]$os.OSArchitecture
    culture = (Get-Culture).Name
    secure_boot = $secure
    secure_boot_error = $secureError
    tpm = $tpm
    last_boot = $os.LastBootUpTime.ToUniversalTime().ToString('o')
    boot_counter = Read-Value { [int64](Get-ItemProperty -Path $key -Name BootId).BootId }
    uptime_ms = [int64][Environment]::TickCount
    utf8_probe = ([string][char]0x00e9) + ([string][char]0x4e16)
}'''
EVIDENCE_FIELDS = ('caption', 'version', 'build', 'architecture', 'culture', 'secure_boot', 'secure_boot_error', 'tpm',
                   'last_boot', 'boot_counter', 'uptime_ms', 'utf8_probe')


def evidence(text):
    """The guest's answer to `EVIDENCE_SCRIPT`, checked in shape: the readings the run keeps."""
    value = _object(text, EVIDENCE_FIELDS)
    tpm = value['tpm']
    if (any(type(value[name]) is not str for name in ('caption', 'version', 'build', 'architecture', 'culture',
                                                       'last_boot', 'utf8_probe'))
            or (value['secure_boot'] is not None and type(value['secure_boot']) is not bool)
            or (value['secure_boot_error'] is not None and type(value['secure_boot_error']) is not str)
            or not (tpm is None or (type(tpm) is dict and set(tpm) == {'present', 'ready'}
                                    and all(type(item) is bool for item in tpm.values())))
            or (value['boot_counter'] is not None and (type(value['boot_counter']) is not int
                                                       or not 0 <= value['boot_counter'] < 2**31))
            or type(value['uptime_ms']) is not int):
        raise GuestAnswerError('invalid-guest-evidence')
    value['utf8_ok'] = value['utf8_probe'] == UTF8_PROBE
    return value
