"""What the controller says to a Windows guest for the List suite (stage 10a), and how it reads the answers.

The runner (`tools/vm/windows/guest/run-windows-list.ps1`) is autonomous: the controller puts its files on the guest's
medium, starts it once through the agent, and then only reads its status file, a few kilobytes of JSON that the runner
rewrites whole after every step. Everything the runner needs to know is in `plan.json`, made here from the lab's own
constants and the run's identifiers, so the guest declares nothing: the names, the addresses, the markers, the hashes
of the files it may run and the configuration of the matrix are the controller's.

The eleven checks are those of `Invoke-ListMatrix.ps1`, with the same ids. What the Hyper-V matrix asks of the Internet
it asks here of the lab (see `NAMES` and the README of the stage).
"""

import base64
import json
import re

from . import l3_requests, windows_guest
from .lab_protocol import ACK_PREFIX, CLIENTS, RESOLVER, TARGETS, dns_name, marker_query

PLAN_SCHEMA = 'rosetun.matrix.windows-list-plan.v1'
STATUS_SCHEMA = 'rosetun.matrix.windows-runner-status.v1'
# Where the runner lives in the guest, and the one task that runs it.
ROOT = 'C:\\rosetun-list'
STATUS_PATH = ROOT + '\\status.json'
RUNNER_TASK = 'RosetunListRunner'
CMD = 'C:\\Windows\\System32\\cmd.exe'
# The windows the observer judges, in the order the runner opens them: the machine before the session, and the session.
LABELS = ('baseline', 'session')
# The names of the lab that stand for the two of the Hyper-V matrix: `example.com`, which the list holds, and
# `example.org`, which it does not. The lab's resolver and its DoH target answer any name of the lab with the target.
NAMES = dict(listed='listed.lab.test', unlisted='unlisted.lab.test')
TUN_ALIAS = 'rosetun0'
BINARIES = ('rosetun.exe', 'rosetun-helper-privileged.exe', 'sing-box.exe')
# What the runner is made of: the files of the checkout the medium carries beside the binaries and the plan.
SCRIPTS = ('lib.ps1', 'run-windows-list.ps1', 'RosetunListResults.psm1', 'list-checks.json')
PLAN_FILE = 'plan.json'
# The states of a runner, and the two that end it.
STATES = ('starting', 'running', 'cleaning', 'finished', 'failed')
LOCKDOWN_STATES = STATES + ('reboot-requested', 'power-cut-requested')
ACTION_STATES = STATES + ('lab-action-requested',)
ACTION_OPERATIONS = ('probe_proxy', 'lan_state')
ENDED = ('finished', 'failed')
CLEANUP_RESULTS = ('PASS', 'ERROR', 'UNVERIFIED')
ANSWER_LIMIT = 16 * 1024
_CODE = re.compile(r'[a-z0-9:._ -]{0,160}')
_UTC = re.compile(r'20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9:.]{8,16}Z')
_ACTION_ID = re.compile(r'[0-9a-f]{16}')


class RunnerAnswerError(ValueError):
    pass


def config_document(node_port):
    """The configuration of the matrix, as `Invoke-ListMatrix.ps1` writes it: the lab's node, one rule on one list.

    Version 3 of the format, as the Hyper-V matrix writes it, so that the same migration reads it; the list's size and
    hash are the guest's to fill in once it has written the file. Documentation addresses only.
    """
    template = l3_requests.template()
    node = dict(template['node'], port=node_port)
    settings = dict(template['settings'], kill_switch=True, allow_lan=False, private_networks=False,
                    auto_reconnect=False)
    rule = dict(id='listed', enabled=True, matcher=dict(list=dict(list='1', category=None)), target='block')
    config = dict(
        version=3, settings=settings,
        subscriptions=[dict(id=template['selection']['subscription'], name='Lab node',
                            url='https://subscription.invalid/lab', nodes=[node])],
        active=dict(template['selection']), active_rule_set='list-matrix',
        rule_sets=[dict(id='list-matrix', name='List matrix', default_target='proxy', rules=[rule])],
        lists=[dict(id='1', name='Listed names', source=dict(file=dict(original_name='listed.txt')), format='text',
                    size=0, sha256='', categories=[])])
    l3_requests.check_documentation_only(config)
    return config


def plan_document(lab_id, windows, dns_check, node_port, files, *, labels=LABELS, binaries=BINARIES):
    """The plan of one run. `windows` are the two (opening, closing) markers in the order of `LABELS`; `files` are the
    rows of the medium (`windows_media.stage`): the binaries are listed with their hashes, which the runner checks."""
    if len(windows) != len(labels):
        raise ValueError('invalid-windows')
    markers = dict(port=windows[0][0]['port'])
    for label, (opening, closing) in zip(labels, windows):
        markers[label] = dict(open=marker_query(opening).decode('ascii'), close=marker_query(closing).decode('ascii'))
    rows = {row['name']: row for row in files}
    if any(name not in rows for name in binaries):
        raise ValueError('windows-list-binaries-missing')
    return dict(
        schema=PLAN_SCHEMA, run=lab_id,
        addresses=dict(client4=CLIENTS[4], target4=TARGETS[4], resolver=RESOLVER),
        markers=markers, names=dict(NAMES), baseline=dict(dns_name=dns_name(dns_check)), tun=dict(alias=TUN_ALIAS),
        files=[dict(name=name, sha256=rows[name]['sha256'], size=rows[name]['size']) for name in binaries],
        config=config_document(node_port))


def plan_bytes(plan):
    return (json.dumps(plan, sort_keys=True, indent=2) + '\n').encode('ascii')


def _quoted(text):
    if "'" in text or '\n' in text:
        raise ValueError('invalid-guest-script-data')
    return text


# Find the disc by its label, check and copy the runner's files, make the one task that runs it and start it. Nothing
# of the run is decided here: the hashes are the controller's.
_START = r'''$root = '%(root)s'
$expected = ConvertFrom-Json '%(files)s'
$found = @(Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' -and $_.FileSystemLabel -eq '%(label)s' -and $_.DriveLetter })
if ($found.Count -ne 1) { throw 'medium-not-found' }
$medium = [string]$found[0].DriveLetter + ':\'
New-Item -ItemType Directory -Force -Path $root | Out-Null
foreach ($name in $expected.PSObject.Properties.Name) {
    $target = Join-Path $root $name
    Copy-Item -LiteralPath (Join-Path $medium $name) -Destination $target -Force
    if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected.$name) { throw 'medium-file-differs' }
}
$arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $root '%(entry)s') + '" -Root "' + $root + '" -Medium ' + [string]$found[0].DriveLetter
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments -WorkingDirectory $root
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName '%(task)s' -Action $action -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName '%(task)s'
ConvertTo-Json -Compress -InputObject @{ medium = $medium; files = @($expected.PSObject.Properties.Name).Count; task = '%(task)s' }'''


def start_script(rows, *, scripts=SCRIPTS, root=ROOT, task=RUNNER_TASK, entry='run-windows-list.ps1'):
    """The script that starts the runner: the plan and the runner's own files, by name and hash, as the medium holds."""
    from .windows_media import files_of
    named = files_of(dict(files=rows))
    wanted = {name: named[name]['sha256'] for name in (PLAN_FILE, *scripts)}
    from .windows_media import LABEL
    script = '\n'.join(line.strip() for line in (_START % dict(
        root=_quoted(root), files=_quoted(json.dumps(wanted, sort_keys=True, separators=(',', ':'))), label=LABEL,
        task=_quoted(task), entry=_quoted(entry))).splitlines() if line.strip())
    return script


def _object(text, names, limit=ANSWER_LIMIT):
    if type(text) is not str or len(text) > limit:
        raise RunnerAnswerError('invalid-guest-answer')
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        raise RunnerAnswerError('invalid-guest-answer') from None
    if type(value) is not dict or set(value) != set(names):
        raise RunnerAnswerError('invalid-guest-answer')
    return value


def started(text, *, scripts=SCRIPTS, task=RUNNER_TASK):
    """The answer of the start script: the drive the disc was found on, and that the task was made."""
    value = _object(text, ('medium', 'files', 'task'))
    if (type(value['medium']) is not str or not re.fullmatch(r'[A-Z]:\\', value['medium'])
            or value['files'] != len((PLAN_FILE, *scripts)) or value['task'] != task):
        raise RunnerAnswerError('invalid-guest-start')
    return value


def _words(value, limit=170):
    if type(value) is not str or len(value) > limit or not _CODE.fullmatch(value):
        raise RunnerAnswerError('invalid-runner-status')
    return value


def runner_status(text, lab_id, *, labels=LABELS, states=STATES, max_checks=32, max_notes=32,
                  max_markers=16, allow_action=False, answer_limit=ANSWER_LIMIT):
    """The runner's status file, checked in shape: states, checks, markers, notes and the cleanup it reports."""
    expected = ('schema', 'run', 'state', 'step', 'sequence', 'started_utc', 'updated_utc', 'checks',
                'markers', 'notes', 'cleanup', 'error') + (('action',) if allow_action else ())
    value = _object(text, expected, limit=answer_limit)
    if (value['schema'] != STATUS_SCHEMA or value['run'] != lab_id or value['state'] not in states
            or type(value['sequence']) is not int or not 0 < value['sequence'] < 100000
            or type(value['checks']) is not list or len(value['checks']) > max_checks
            or type(value['markers']) is not list or len(value['markers']) > max_markers
            or type(value['notes']) is not list or len(value['notes']) > max_notes):
        raise RunnerAnswerError('invalid-runner-status')
    _words(value['step'], 48)
    for stamp in (value['started_utc'], value['updated_utc']):
        if type(stamp) is not str or not _UTC.fullmatch(stamp):
            raise RunnerAnswerError('invalid-runner-status')
    for row in value['checks']:
        if (type(row) is not dict or set(row) != {'id', 'result', 'reason', 'scenario', 'note'}
                or row['result'] not in ('PASS', 'FAIL', 'SKIP')):
            raise RunnerAnswerError('invalid-runner-status')
        for key in ('id', 'reason', 'scenario', 'note'):
            _words(row[key])
    for row in value['markers']:
        if (type(row) is not dict or set(row) != {'label', 'word', 'marker', 'ack', 'error', 'utc'}
                or row['label'] not in labels or row['word'] not in ('open', 'close')
                or any(row[key] is not None and type(row[key]) is not str for key in ('ack', 'error'))
                or type(row['marker']) is not str or len(row['marker']) > 128
                or any(row[key] is not None and len(row[key]) > 160 for key in ('ack', 'error'))):
            raise RunnerAnswerError('invalid-runner-status')
    for row in value['notes']:
        if (type(row) is not dict or set(row) != {'name', 'value'} or type(row['value']) not in (int, float)
                or type(row['name']) is not str):
            raise RunnerAnswerError('invalid-runner-status')
        _words(row['name'], 48)
    cleanup = value['cleanup']
    if cleanup is not None:
        if (type(cleanup) is not dict or set(cleanup) != {'result', 'parts'} or cleanup['result'] not in CLEANUP_RESULTS
                or type(cleanup['parts']) is not dict or len(cleanup['parts']) > 16
                or any(type(k) is not str or cleanup['parts'][k] not in CLEANUP_RESULTS for k in cleanup['parts'])):
            raise RunnerAnswerError('invalid-runner-status')
        for name in cleanup['parts']:
            _words(name, 32)
    error = value['error']
    if error is not None:
        if type(error) is not dict or set(error) != {'place', 'text'}:
            raise RunnerAnswerError('invalid-runner-status')
        _words(error['place'], 32), _words(error['text'])
    if allow_action:
        action = value['action']
        if action is not None:
            if (type(action) is not dict or set(action) != {'id', 'operation', 'params'}
                    or type(action['id']) is not str or not _ACTION_ID.fullmatch(action['id'])
                    or action['operation'] not in ACTION_OPERATIONS
                    or type(action['params']) is not dict):
                raise RunnerAnswerError('invalid-runner-status')
    return value


_WRITE_REPLY = r'''$dir = '%(root)s'
$tmp = Join-Path $dir 'action-reply-%(id)s.json.tmp'
$dst = Join-Path $dir 'action-reply-%(id)s.json'
[IO.File]::WriteAllBytes($tmp, [Convert]::FromBase64String('%(b64)s'))
if (Test-Path -LiteralPath $dst) { Remove-Item -LiteralPath $dst -Force }
[IO.File]::Move($tmp, $dst)
ConvertTo-Json -Compress -InputObject @{ wrote = $true; id = '%(id)s' }'''


def write_reply_script(root, action_id, payload):
    """Write a controller lab-action reply atomically for the autonomous guest runner."""
    if type(action_id) is not str or not _ACTION_ID.fullmatch(action_id):
        raise ValueError('invalid-action-id')
    encoded = base64.b64encode(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')).decode('ascii')
    return '\n'.join(line.strip() for line in (_WRITE_REPLY % dict(
        root=_quoted(root), id=action_id, b64=encoded)).splitlines() if line.strip())


def reply_written(text, action_id):
    value = _object(text, ('wrote', 'id'))
    if value['wrote'] is not True or value['id'] != action_id:
        raise RunnerAnswerError('invalid-guest-answer')
    return value


def read_arguments(path=STATUS_PATH):
    """The program that reads the status file: `cmd /c type`, which starts in a moment, where a PowerShell does not."""
    return CMD, ['/c', 'type', path]


def markers_of(status, windows, *, labels=LABELS):
    """What the runner says of the markers, against the ones the plan names: for each window label, whether its two
    markers were sent and acknowledged exactly once with the lab's own text. Anything else is not acknowledged."""
    result = {}
    for label, (opening, closing) in zip(labels, windows):
        row = {}
        for word, marker in (('open', opening), ('close', closing)):
            wanted = marker_query(marker).decode('ascii')
            rows = [r for r in status['markers'] if r['label'] == label and r['word'] == word]
            row[word] = dict(sent=len(rows) == 1 and rows[0]['marker'] == wanted,
                             acknowledged=len(rows) == 1 and rows[0]['ack'] == ACK_PREFIX + wanted,
                             error=rows[0]['error'] if len(rows) == 1 else None)
        result[label] = row
    return result


# Everything the controller keeps of the runner's files once it has finished, in one answer: the artifacts of the
# Hyper-V matrix (plan, events, report, status) as the recorder wrote them, and the tail of the helper's log, the
# one place that says why a connect failed.
_COLLECT = r'''$root = '%(root)s'
function Read-Text([string]$path, [int]$limit, [bool]$tail) {
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $text = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8)
    if ($text.Length -gt $limit) { if ($tail) { $text = $text.Substring($text.Length - $limit) } else { $text = $text.Substring(0, $limit) } }
    return $text
}
$results = Join-Path $root 'results'
ConvertTo-Json -Compress -InputObject @{
    plan = Read-Text (Join-Path $results 'plan.json') %(plan)d $false
    events = Read-Text (Join-Path $results 'events.jsonl') %(events)d $false
    report = Read-Text (Join-Path $results 'report.json') %(report)d $false
    status = Read-Text (Join-Path $results 'status.json') %(status)d $false
    helper_tail = Read-Text (Join-Path $root 'logs\helper.log') %(helper_tail)d $true
    identity = @{ uuid = [string](Get-CimInstance Win32_ComputerSystemProduct).UUID }
}'''
COLLECT_LIMITS = dict(plan=8000, events=6000, report=8000, status=2000, helper_tail=3000)


def collect_script(root=ROOT, limits=None):
    sizes = dict(COLLECT_LIMITS)
    if limits:
        sizes.update(limits)
    return '\n'.join(line.strip() for line in (_COLLECT % dict(root=_quoted(root), **sizes)).splitlines() if line.strip())


def collected(text, *, limit=48 * 1024):
    """The files the recorder left, as text, each of which may be missing (None)."""
    value = _object(text, ('plan', 'events', 'report', 'status', 'helper_tail', 'identity'), limit=limit)
    for name in ('plan', 'events', 'report', 'status', 'helper_tail'):
        if value[name] is not None and type(value[name]) is not str:
            raise RunnerAnswerError('invalid-guest-answer')
    identity = value['identity']
    if type(identity) is not dict or set(identity) != {'uuid'} or type(identity['uuid']) is not str:
        raise RunnerAnswerError('invalid-guest-answer')
    return value


# What the controller checks of the cleanup itself, after the runner reported its own: read-only, but for the one task
# the controller made to start the runner, which it removes with the runner's directory once its files are read.
_AFTER = r'''$root = '%(root)s'
Unregister-ScheduledTask -TaskName '%(task)s' -Confirm:$false -ErrorAction SilentlyContinue
$tag = 'rosetun-wfp-' + $PID
$snapshot = Join-Path $env:TEMP ($tag + '.xml')
$netshOut = Join-Path $env:TEMP ($tag + '.out')
$netshErr = Join-Path $env:TEMP ($tag + '.err')
try {
    $proc = Start-Process -FilePath "$env:SystemRoot\System32\netsh.exe" -ArgumentList @('wfp', 'show', 'state', "file=$snapshot") -NoNewWindow -Wait -PassThru -RedirectStandardOutput $netshOut -RedirectStandardError $netshErr
    if ($proc.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $snapshot)) { throw 'wfp-state-unavailable' }
    $raw = [IO.File]::ReadAllText($snapshot, [Text.Encoding]::UTF8)
} finally {
    Remove-Item -LiteralPath $snapshot, $netshOut, $netshErr -Force -ErrorAction SilentlyContinue
}
if ($raw -notmatch '<wfpstate>' -or $raw -notmatch '</wfpstate>' -or $raw -notmatch '<providerKey>' -or $raw -notmatch '<subLayerKey>') { throw 'wfp-state-incomplete' }
$state = @{
    wfp_provider = [bool]($raw -match '<providerKey>\s*\{?51a47ec7-6459-4b84-8854-075e1576e7f9\}?\s*</providerKey>')
    wfp_sublayer = [bool]($raw -match '<subLayerKey>\s*\{?0c035ef5-4c5c-4583-ad9c-179791360f5e\}?\s*</subLayerKey>')
    runner_task = ($null -ne (Get-ScheduledTask -TaskName '%(task)s' -ErrorAction SilentlyContinue))
    helper_task = ($null -ne (Get-ScheduledTask -TaskName 'RosetunHelper' -ErrorAction SilentlyContinue))
    helper_process = [bool](Get-Process -Name 'rosetun-helper-privileged' -ErrorAction SilentlyContinue)
    engine_process = [bool](Get-Process -Name 'sing-box' -ErrorAction SilentlyContinue)
    tunnel_adapter = ($null -ne (Get-NetAdapter -Name '%(alias)s' -ErrorAction SilentlyContinue))
    binaries = (Test-Path -LiteralPath (Join-Path $root 'bin'))
    list_directory = (Test-Path -LiteralPath (Join-Path $root 'list-matrix'))
%(extra)s}
Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
$state.root_removed = (-not (Test-Path -LiteralPath $root))
ConvertTo-Json -Compress -InputObject $state'''
_AFTER_LOCKDOWN_EXTRA = r'''    lockdown_wfp_provider = [bool]($raw -match '<providerKey>\s*\{?f12dbedd-f3c7-4a72-b0f8-20559c88b112\}?\s*</providerKey>')
    lockdown_wfp_sublayer = [bool]($raw -match '<subLayerKey>\s*\{?f829a64d-c373-4d92-9d66-e1c680f3794f\}?\s*</subLayerKey>')
    lockdown_service = ($null -ne (Get-Service -Name 'Rosetun' -ErrorAction SilentlyContinue))
    resume_task = ($null -ne (Get-ScheduledTask -TaskName 'RosetunLockdownResume' -ErrorAction SilentlyContinue))
    boot_check_task = ($null -ne (Get-ScheduledTask -TaskName 'RosetunLockdownBootCheck' -ErrorAction SilentlyContinue))
    matrix_user = ($null -ne (Get-LocalUser -Name 'RosetunMatrixUser' -ErrorAction SilentlyContinue))
'''
_AFTER_PROXY_EXTRA = r'''    lockdown_wfp_provider = [bool]($raw -match '<providerKey>\s*\{?f12dbedd-f3c7-4a72-b0f8-20559c88b112\}?\s*</providerKey>')
    lockdown_wfp_sublayer = [bool]($raw -match '<subLayerKey>\s*\{?f829a64d-c373-4d92-9d66-e1c680f3794f\}?\s*</subLayerKey>')
    lockdown_service = ($null -ne (Get-Service -Name 'Rosetun' -ErrorAction SilentlyContinue))
    egress_watch_task = ($null -ne (Get-ScheduledTask -TaskName 'RosetunEgressWatch' -ErrorAction SilentlyContinue))
    proxy_user = ($null -ne (Get-LocalUser -Name 'RosetunProxyUser' -ErrorAction SilentlyContinue))
    desktop_task = ($null -ne (Get-ScheduledTask -TaskName 'RosetunProxyDesktop' -ErrorAction SilentlyContinue))
    desktop_process = [bool](Get-Process -Name 'desktop_proxy' -ErrorAction SilentlyContinue)
'''
_AFTER_LAN_EXTRA = r'''    extra_address = [bool](Get-NetIPAddress -IPAddress '198.51.100.10' -ErrorAction SilentlyContinue)
    lan_directory = (Test-Path -LiteralPath (Join-Path $root 'lan-matrix'))
'''
AFTER_FIELDS = ('runner_task', 'helper_task', 'helper_process', 'engine_process', 'tunnel_adapter', 'binaries',
                'list_directory', 'wfp_provider', 'wfp_sublayer', 'root_removed')
LOCKDOWN_AFTER_FIELDS = AFTER_FIELDS[:-1] + (
    'lockdown_wfp_provider', 'lockdown_wfp_sublayer', 'lockdown_service', 'resume_task', 'boot_check_task',
    'matrix_user', 'root_removed')
PROXY_AFTER_FIELDS = AFTER_FIELDS[:-1] + (
    'lockdown_wfp_provider', 'lockdown_wfp_sublayer', 'lockdown_service', 'egress_watch_task', 'proxy_user',
    'desktop_task', 'desktop_process', 'root_removed')
LAN_AFTER_FIELDS = AFTER_FIELDS[:-1] + ('extra_address', 'lan_directory', 'root_removed')


def after_script(root=ROOT, task=RUNNER_TASK, *, lockdown=False, proxy=False, lan=False):
    if sum((bool(lockdown), bool(proxy), bool(lan))) > 1:
        raise ValueError('conflicting-after-modes')
    extra = (_AFTER_LOCKDOWN_EXTRA if lockdown else _AFTER_PROXY_EXTRA if proxy
             else _AFTER_LAN_EXTRA if lan else '')
    return '\n'.join(line.strip() for line in (_AFTER % dict(
        root=_quoted(root), task=_quoted(task), alias=TUN_ALIAS, extra=extra)).splitlines() if line.strip())


def after(text, *, lockdown=False, proxy=False, lan=False):
    """What is left in the guest, as the controller sees it: a leftover is True, except `root_removed`, which is the aim."""
    if sum((bool(lockdown), bool(proxy), bool(lan))) > 1:
        raise ValueError('conflicting-after-modes')
    fields = (LOCKDOWN_AFTER_FIELDS if lockdown else PROXY_AFTER_FIELDS if proxy
              else LAN_AFTER_FIELDS if lan else AFTER_FIELDS)
    value = _object(text, fields)
    if any(type(value[name]) is not bool for name in fields):
        raise RunnerAnswerError('invalid-guest-answer')
    left = sorted(name for name in fields[:-1] if value[name]) + ([] if value['root_removed'] else ['root'])
    return dict(left=left, clean=not left, fields=value)


def script_limit_ok(script):
    """The scripts of this suite must fit what `windows_guest.arguments` takes for the lab."""
    return len(script) <= windows_guest.SCRIPT_LIMIT_MAX
