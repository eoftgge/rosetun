# The Windows Lockdown matrix as an autonomous multi-boot runner of the QEMU lab (stage 10c).
# Windows PowerShell 5.1, as SYSTEM.
#
# Runs Scenarios 1, 2, 4, 5, 6 (clean reboot under Lockdown), 7 (abrupt power cuts after on and off),
# 8 (off while connected/unprotected/disconnected), 9 (SCM service & reset-firewall), and 10 (uninstall)
# on the isolated QEMU lab wire. Supports cases `full`, `core` (no reboots/cuts), and `reboot` (baseline + 6 + 7).
# State across reboots and power cuts is persisted durably (`Flush($true)`) in `checkpoint.json`,
# `status.json`, and `results/events.jsonl`, and resumed by an ONSTART scheduled task (`RosetunLockdownResume`).

param(
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]$')][string]$Medium,
    [switch]$Resume
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib.ps1')

$plan = Get-Content -LiteralPath (Join-Path $Root 'plan.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$statusPath = Join-Path $Root 'status.json'
$checkpointPath = Join-Path $Root 'checkpoint.json'
$resultsDir = Join-Path $Root 'results'

$mediumRoot = $Medium + ':\'
$bin = Join-Path $Root 'bin'
$logs = Join-Path $Root 'logs'
$work = Join-Path $Root 'lockdown-work'
$helperLogPath = Join-Path $logs 'helper.log'
$cliPath = Join-Path $bin 'rosetun.exe'
$helperPath = Join-Path $bin 'rosetun-helper-privileged.exe'
$singBoxPath = Join-Path $bin 'sing-box.exe'
$curlPath = Join-Path $env:SystemRoot 'System32\curl.exe'

$taskName = 'RosetunHelper'
$resumeTaskName = 'RosetunLockdownResume'
$bootCheckTaskName = 'RosetunLockdownBootCheck'
$bootCheckScriptPath = Join-Path $work 'boot-check.ps1'
$bootCheckResultPath = Join-Path $work 'boot-check.json'
$standardUser = 'RosetunMatrixUser'
$standardDir = 'C:\rosetun-matrix-user'

$caseName = [string]$plan.case
$powerCutRepeats = [int]$plan.power_cut_repeats
$unlisted = [string]$plan.names.unlisted
$physical = [string]$plan.addresses.client4
$targetUrl = 'https://' + [string]$plan.addresses.target4 + '/'
$baselineDns = [string]$plan.baseline.dns_name
$recoveryDns = 'after.' + $baselineDns

# Fixed WFP GUIDs in crates/rosetun-routing/src/platform/windows/lockdown.rs and session.rs.
$lockdownKeys = [ordered]@{
    Provider      = 'f12dbedd-f3c7-4a72-b0f8-20559c88b112'
    Sublayer      = 'f829a64d-c373-4d92-9d66-e1c680f3794f'
    Outbound      = '57bf2a6e-57db-4d99-bed7-ecbd2c63aa75'
    Inbound       = 'e599db5e-6aeb-4e4d-aa51-4314f1b3076c'
    Dhcp          = '98419911-30f0-4f71-9178-263b40bc7f6e'
    ServiceDns    = 'cb0f8c4b-4967-4626-a493-a4e32369e6f5'
    Lan           = 'f6a5849d-943f-4d77-917c-8811e9a70000'
    CliTcp        = 'e0222624-bc2f-43a6-8058-b939a77ddd4b'
    CliDns        = '982cc554-9f41-4c9a-833f-87cc5149725f'
    RetiredCli    = '729b156a-c411-4f01-b7d9-a789c94e992b'
    RetiredCliWeb = '05b9da42-ea8e-4b28-a2b8-2404db01e0d1'
}
$rosetunProviderKey = '51a47ec7-6459-4b84-8854-075e1576e7f9'

. (Join-Path $PSScriptRoot 'failure-probes.ps1')

function Write-DurableText {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Text)
    $temporary = $Path + '.tmp'
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    $stream = [IO.FileStream]::new($temporary, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }
    if (Test-Path -LiteralPath $Path) {
        [IO.File]::Replace($temporary, $Path, [NullString]::Value)
    }
    else {
        [IO.File]::Move($temporary, $Path)
    }
}

function Save-LockdownCheckpoint {
    param([Parameter(Mandatory)]$Data)
    Write-DurableText -Path $checkpointPath -Text ((ConvertTo-Json -InputObject $Data -Depth 8 -Compress) + "`n")
}

function Read-LockdownCheckpoint {
    if (-not (Test-Path -LiteralPath $checkpointPath)) { throw 'missing lockdown checkpoint' }
    return ([IO.File]::ReadAllText($checkpointPath, [Text.Encoding]::UTF8) | ConvertFrom-Json)
}

function Get-WfpStateRaw {
    $path = Join-Path $env:TEMP ("rosetun-wfp-$([guid]::NewGuid().ToString('N')).xml")
    try {
        $dump = Invoke-RosetunNative -FilePath (Join-Path $env:SystemRoot 'System32\netsh.exe') -TimeoutSeconds 30 -Arguments @(
            'wfp', 'show', 'state', "file=$path")
        if ($dump.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $path)) {
            throw 'cannot inspect WFP state'
        }
        return [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8)
    }
    finally {
        Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue
    }
}

function Get-LockdownObjects {
    $raw = Get-WfpStateRaw
    $objects = [ordered]@{}
    foreach ($name in $lockdownKeys.Keys) {
        $objects[$name] = [bool]($raw -match [regex]::Escape($lockdownKeys[$name]))
    }
    return [pscustomobject]$objects
}

function Test-LockdownInstalled {
    param([switch]$Lan)
    $o = Get-LockdownObjects
    return ($o.Provider -and $o.Sublayer -and $o.Outbound -and $o.Inbound -and $o.Dhcp -and
        $o.ServiceDns -and ($o.Lan -eq [bool]$Lan) -and (-not $o.RetiredCli) -and (-not $o.RetiredCliWeb))
}

function Test-LockdownAbsent {
    $o = Get-LockdownObjects
    return (-not ($o.PSObject.Properties.Value -contains $true))
}

function Test-ProgramPermits {
    param([switch]$Present)
    $o = Get-LockdownObjects
    if ($o.RetiredCli -or $o.RetiredCliWeb) { return $false }
    if ($Present) { return ($o.CliTcp -and $o.CliDns) }
    return ((-not $o.CliTcp) -and (-not $o.CliDns))
}

function Test-SessionProviderPresent {
    $raw = Get-WfpStateRaw
    return [bool]($raw -match [regex]::Escape($rosetunProviderKey))
}

function Format-ObjectsNote {
    param($Objects)
    return (($Objects.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' ')
}

function Get-LockdownStatusLine {
    $status = Invoke-FailureCli -Arguments @('status') -Seconds 20
    if ($status.Output -match '(?m)^lockdown: (on|off)') { return $Matches[1] }
    return "unknown (exit $($status.ExitCode))"
}

function Invoke-LockdownCmd {
    param([Parameter(Mandatory)][ValidateSet('on', 'off')][string]$State)
    return Invoke-FailureCli -Arguments @('lockdown', $State) -Seconds 60
}

function Get-HelperLogText {
    if (-not (Test-Path -LiteralPath $helperLogPath)) { return '' }
    try {
        $stream = [IO.File]::Open($helperLogPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        try { return ((New-Object IO.StreamReader $stream).ReadToEnd() -replace "$([char]27)\[[0-9;]*m", '') }
        finally { $stream.Dispose() }
    }
    catch { return '' }
}

function Get-HelperLogLength {
    return (Get-HelperLogText).Length
}

function Get-HelperLogSince {
    param([int]$Offset)
    $text = Get-HelperLogText
    if ($Offset -le 0 -or $Offset -ge $text.Length) {
        if ($Offset -ge $text.Length) { return '' }
        return $text
    }
    return $text.Substring($Offset)
}

function Test-InUseFree {
    param([AllowEmptyString()][string]$LogText)
    return ($LogText -notmatch '2150825994|0x8032000a|FWP_E_IN_USE')
}

function Register-LockdownHelperTask {
    $command = "set ROSETUN_LOG=debug&& `"$helperPath`" > `"$helperLogPath`" 2>&1"
    $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c $command" -WorkingDirectory $bin
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
}

function Start-LockdownHelper {
    Register-LockdownHelperTask
    Start-ScheduledTask -TaskName $taskName
    if (-not (Wait-HelperReady -TimeoutSeconds 90)) { throw 'the helper did not answer status' }
}

function Stop-LockdownHelper {
    Stop-FailureHelper
}

function Disconnect-LockdownSession {
    param([int]$TimeoutSeconds = 40)
    [void](Invoke-FailureCli -Arguments @('disconnect') -Seconds 30)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while ($clock.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        if ((Get-FailureState) -eq 'Disconnected' -and -not (Test-TunAdapter)) {
            return $true
        }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Test-LoopbackOpen {
    $results = foreach ($address in [Net.IPAddress]::Loopback, [Net.IPAddress]::IPv6Loopback) {
        $listener = [Net.Sockets.TcpListener]::new($address, 0)
        $client = [Net.Sockets.TcpClient]::new($address.AddressFamily)
        try {
            $listener.Start()
            $client.ConnectAsync($address, ([Net.IPEndPoint]$listener.LocalEndpoint).Port).Wait(3000)
        }
        catch { $false }
        finally {
            $client.Dispose()
            $listener.Stop()
        }
    }
    return (-not ($results -contains $false))
}

function Test-CliPathEgress {
    # Temporarily places curl.exe at rosetun.exe's path to verify the CLI application-ID WFP permit.
    $saved = $cliPath + '.matrix'
    Move-Item -LiteralPath $cliPath -Destination $saved -Force
    try {
        Copy-Item -LiteralPath $curlPath -Destination $cliPath -Force
        $run = Invoke-RosetunNative -FilePath $cliPath -TimeoutSeconds 15 -Arguments @(
            '--interface', $physical, '--max-time', '5', '--silent', '--ssl-no-revoke', '--output', 'NUL', $targetUrl)
        return ($run.ExitCode -eq 0)
    }
    finally {
        Remove-Item -LiteralPath $cliPath -Force -ErrorAction SilentlyContinue
        Move-Item -LiteralPath $saved -Destination $cliPath -Force
    }
}

function New-StandardAccount {
    $password = 'Rm1!' + [guid]::NewGuid().ToString('N')
    Get-LocalUser -Name $standardUser -ErrorAction SilentlyContinue | Remove-LocalUser -ErrorAction SilentlyContinue
    $secure = ConvertTo-SecureString -String $password -AsPlainText -Force
    New-LocalUser -Name $standardUser -Password $secure -PasswordNeverExpires -AccountNeverExpires `
        -Description 'Rosetun Lockdown matrix' | Out-Null
    # Users (S-1-5-32-545) and Performance Log Users (S-1-5-32-559, for Log on as a batch job).
    foreach ($group in 'S-1-5-32-545', 'S-1-5-32-559') {
        try { Add-LocalGroupMember -SID $group -Member $standardUser -ErrorAction Stop }
        catch [Microsoft.PowerShell.Commands.MemberExistsException] { }
    }
    Remove-Item -LiteralPath $standardDir -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $standardDir -Force | Out-Null
    [void](Invoke-RosetunNative -FilePath (Join-Path $env:SystemRoot 'System32\icacls.exe') -TimeoutSeconds 20 -Arguments @(
        $standardDir, '/grant', "${standardUser}:(OI)(CI)M"))
    return $password
}

function Remove-StandardAccount {
    $user = Get-LocalUser -Name $standardUser -ErrorAction SilentlyContinue
    if ($user) {
        Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue |
            Where-Object { $_.SID -eq $user.SID.Value } |
            Remove-CimInstance -ErrorAction SilentlyContinue
        Remove-LocalUser -Name $standardUser -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $standardDir -Recurse -Force -ErrorAction SilentlyContinue
}

function Invoke-AsStandardUser {
    param(
        [Parameter(Mandatory)][string]$Password,
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments,
        [int]$TimeoutSeconds = 30
    )
    $id = [guid]::NewGuid().ToString('N')
    $runner = Join-Path $standardDir "run-$id.ps1"
    $out = Join-Path $standardDir "out-$id.txt"
    $err = Join-Path $standardDir "err-$id.txt"
    $code = Join-Path $standardDir "code-$id.txt"
    $task = "RosetunMatrixUser-$id"
    $quote = { param($value) "'" + ($value -replace "'", "''") + "'" }
    $argString = $Arguments -join ' '
    $script = @(
        'try {'
        "    `$process = Start-Process -FilePath $(& $quote $FilePath) -ArgumentList $(& $quote $argString) " +
            "-WorkingDirectory $(& $quote $standardDir) -NoNewWindow -PassThru -ErrorAction Stop " +
            "-RedirectStandardOutput $(& $quote $out) -RedirectStandardError $(& $quote $err)"
        '}'
        'catch {'
        '    $message = $_.Exception.Message'
        '    $native = try {'
        "        `$info = New-Object Diagnostics.ProcessStartInfo $(& $quote $FilePath)"
        '        $info.UseShellExecute = $false'
        '        [Diagnostics.Process]::Start($info).Kill()'
        "        'started on retry'"
        '    }'
        '    catch {'
        '        $inner = $_.Exception'
        '        while ($inner -and $inner -isnot [ComponentModel.Win32Exception]) { $inner = $inner.InnerException }'
        '        if ($inner) { $inner.NativeErrorCode }'
        '    }'
        "    Set-Content -LiteralPath $(& $quote $code) -Value (`"not started: `${native}: `$message`")"
        '    exit'
        '}'
        '$null = $process.Handle'
        "if (`$process.WaitForExit($($TimeoutSeconds * 1000))) { `$result = `$process.ExitCode } else { `$process.Kill(); `$result = 'timeout' }"
        "Set-Content -LiteralPath $(& $quote $code) -Value `$result"
    ) -join "`r`n"
    [IO.File]::WriteAllText($runner, $script)
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$runner`"" -WorkingDirectory $standardDir
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes(2)) `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $task -Action $action -Settings $settings -User $standardUser `
        -Password $Password -RunLevel Limited | Out-Null
    try {
        Start-ScheduledTask -TaskName $task
        $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds + 30)
        while (-not (Test-Path -LiteralPath $code) -and [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 250
        }
        if (-not (Test-Path -LiteralPath $code)) {
            $last = (Get-ScheduledTaskInfo -TaskName $task).LastTaskResult
            throw ("standard user task did not finish: 0x{0:X8}" -f $last)
        }
        $text = (Get-Content -Raw -LiteralPath $code).Trim()
        $output = @($out, $err | Where-Object { Test-Path -LiteralPath $_ } |
            ForEach-Object { Get-Content -Raw -LiteralPath $_ }) -join "`n"
        return [pscustomobject]@{
            ExitCode = if ($text -match '^-?\d+$') { [int]$text } else { $text }
            Output   = $output.Trim()
        }
    }
    finally {
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $runner, $out, $err, $code -ErrorAction SilentlyContinue
    }
}

function Invoke-StandardFetch {
    param([Parameter(Mandatory)][string]$Password, [switch]$Physical)
    $arguments = @('tools', 'fetch', $targetUrl)
    if ($Physical) {
        $configPath = Join-Path $standardDir 'physical.json'
        $outbound = [ordered]@{ type = 'direct'; tag = 'direct'; inet4_bind_address = $script:physical }
        $json = [ordered]@{ log = @{ level = 'error' }; outbounds = @($outbound) } | ConvertTo-Json -Depth 5
        [IO.File]::WriteAllText($configPath, $json, (New-Object Text.UTF8Encoding $false))
        $arguments = @('-c', $configPath) + $arguments
    }
    try {
        $run = Invoke-AsStandardUser -Password $Password -FilePath $singBoxPath -Arguments $arguments -TimeoutSeconds 20
        if ("$($run.ExitCode)" -like 'not started:*') {
            return [pscustomobject]@{ Ok = $null; Note = "$($run.ExitCode)" }
        }
        return [pscustomobject]@{ Ok = ($run.ExitCode -eq 0); Note = "exit $($run.ExitCode): $($run.Output)" }
    }
    catch {
        return [pscustomobject]@{ Ok = $null; Note = "not run: $_" }
    }
}

function Test-EngineCopyAcl {
    $copyPath = Join-Path $bin 'data\engines\sing-box.exe'
    if (-not (Test-Path -LiteralPath $copyPath)) {
        return [pscustomobject]@{ Ok = $false; Note = 'missing engine copy' }
    }
    $sid = [Security.Principal.SecurityIdentifier]
    $acl = Get-Acl -LiteralPath $copyPath
    $owner = $acl.GetOwner($sid).Value
    $protected = $acl.AreAccessRulesProtected
    $rules = @($acl.GetAccessRules($true, $true, $sid) | ForEach-Object {
            '{0} {1} {2} inherited={3}' -f $_.IdentityReference.Value, $_.AccessControlType, $_.FileSystemRights, $_.IsInherited
        } | Sort-Object)
    $expected = @(
        'S-1-5-18 Allow FullControl inherited=False'
        'S-1-5-32-544 Allow FullControl inherited=False'
    )
    $ok = ($owner -eq 'S-1-5-32-544' -and $protected -and (@(Compare-Object -ReferenceObject $expected -DifferenceObject $rules).Count -eq 0))
    return [pscustomobject]@{ Ok = $ok; Note = "owner=$owner protected=$protected rules=$($rules.Count)" }
}

function Test-StandardEngineCopyDenied {
    param([Parameter(Mandatory)][string]$Password)
    $copyPath = Join-Path $bin 'data\engines\sing-box.exe'
    try {
        $run = Invoke-AsStandardUser -Password $Password -FilePath $copyPath -Arguments @('tools', 'fetch', $targetUrl) -TimeoutSeconds 20
        return [pscustomobject]@{
            Ok   = ("$($run.ExitCode)" -match '^not started: 5:')
            Note = "$($run.ExitCode) $($run.Output)".Trim()
        }
    }
    catch {
        return [pscustomobject]@{ Ok = $false; Note = "not run: $_" }
    }
}

function Test-StandardLockdownOffRefused {
    param([Parameter(Mandatory)][string]$Password)
    try {
        $off = Invoke-AsStandardUser -Password $Password -FilePath $cliPath -Arguments @('lockdown', 'off') -TimeoutSeconds 20
        $refused = ($off.ExitCode -is [int] -and $off.ExitCode -ne 0 -and $off.Output -match 'administrator')
        $stays = ((Get-LockdownStatusLine) -eq 'on' -and (Test-LockdownInstalled))
        return [pscustomobject]@{ Ok = ($refused -and $stays); Note = "exit=$($off.ExitCode) stays=$stays" }
    }
    catch {
        return [pscustomobject]@{ Ok = $false; Note = "not run: $_" }
    }
}

function Register-LockdownResumeTask {
    $scriptPath = Join-Path $Root 'run-windows-lockdown.ps1'
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$scriptPath`" -Root `"$Root`" -Medium $Medium -Resume" `
        -WorkingDirectory $Root
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $resumeTaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
}

function Register-LockdownBootCheckTask {
    $bootScript = @'
param(
    [Parameter(Mandatory)][string]$ResultPath,
    [Parameter(Mandatory)][string]$Physical,
    [Parameter(Mandatory)][string]$Url
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$bootKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'
$bootId = 'win-' + [string][int64](Get-ItemProperty -Path $bootKey -Name BootId).BootId
$helperAtStart = [bool](Get-Process -Name 'rosetun-helper-privileged' -ErrorAction SilentlyContinue)
$curlPath = Join-Path $env:SystemRoot 'System32\curl.exe'
$deadline = [DateTime]::UtcNow.AddSeconds(120)
$routed = 0
$egressOpen = $false
$attempts = 0
while ([DateTime]::UtcNow -lt $deadline -and $routed -lt 3) {
    $attempts++
    $addr = Get-NetIPAddress -IPAddress $Physical -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.AddressState -eq 'Preferred' } | Select-Object -First 1
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($addr -and $route) {
        $routed++
        & $curlPath --interface $Physical --max-time 5 --silent --ssl-no-revoke --output NUL $Url 2>$null
        if ($LASTEXITCODE -eq 0) { $egressOpen = $true }
    }
    if ($routed -lt 3) { Start-Sleep -Seconds 2 }
}
$helperAtEnd = [bool](Get-Process -Name 'rosetun-helper-privileged' -ErrorAction SilentlyContinue)
$record = [ordered]@{
    boot_id          = $bootId
    helper_at_start  = $helperAtStart
    helper_at_end    = $helperAtEnd
    attempts         = $attempts
    routed           = $routed
    egress_open      = $egressOpen
}
$json = (ConvertTo-Json -InputObject $record -Compress) + "`n"
$tmp = $ResultPath + '.tmp'
$bytes = [Text.Encoding]::UTF8.GetBytes($json)
$stream = [IO.FileStream]::new($tmp, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush($true)
}
finally { $stream.Dispose() }
if (Test-Path -LiteralPath $ResultPath) {
    [IO.File]::Replace($tmp, $ResultPath, [NullString]::Value)
}
else {
    [IO.File]::Move($tmp, $ResultPath)
}
'@
    Write-DurableText -Path $bootCheckScriptPath -Text $bootScript
    Remove-Item -LiteralPath $bootCheckResultPath -Force -ErrorAction SilentlyContinue
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$bootCheckScriptPath`" -ResultPath `"$bootCheckResultPath`" -Physical `"$physical`" -Url `"$targetUrl`"" `
        -WorkingDirectory $work
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes(5)) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $bootCheckTaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
}

function Disable-BootRecoveryForPowerCuts {
    # Windows enters Automatic Repair after consecutive abrupt power cuts unless recovery is disabled.
    # Scenario 6's clean reboot flushes the BCD hive before Scenario 7's power cuts begin.
    $bcd = Invoke-RosetunNative -FilePath (Join-Path $env:SystemRoot 'System32\bcdedit.exe') -TimeoutSeconds 20 -Arguments @('/enum', '{current}')
    $saved = [ordered]@{ policy = $null; recovery = $null }
    foreach ($line in ($bcd.Output -split "`r?`n")) {
        if ($line -match '^bootstatuspolicy\s+(\S+)') { $saved.policy = $Matches[1] }
        if ($line -match '^recoveryenabled\s+(\S+)') { $saved.recovery = $Matches[1] }
    }
    foreach ($pair in @(@('bootstatuspolicy', 'ignoreallfailures'), @('recoveryenabled', 'no'))) {
        $set = Invoke-RosetunNative -FilePath (Join-Path $env:SystemRoot 'System32\bcdedit.exe') -TimeoutSeconds 20 -Arguments @('/set', '{current}', $pair[0], $pair[1])
        if ($set.ExitCode -ne 0) { throw "bcdedit /set $($pair[0]) failed: $($set.ExitCode)" }
    }
    return $saved
}

function Wait-BootServicesReady {
    $bfeOk = Wait-FailureCondition -TimeoutSeconds 60 -Condition {
        $svc = Get-Service -Name 'BFE' -ErrorAction SilentlyContinue
        return ($null -ne $svc -and $svc.Status -eq 'Running')
    }
    if (-not $bfeOk) { throw 'BFE service did not start after boot' }
    $idx = Get-PhysicalInterfaceIndex
    if (-not (Wait-PhysicalRoute -Index $idx -TimeoutSeconds 60)) {
        throw 'physical route did not come up after boot'
    }
}

function Wait-ScmServiceState {
    param([Parameter(Mandatory)][string]$Expected, [int]$TimeoutSeconds = 40)
    return Wait-FailureCondition -TimeoutSeconds $TimeoutSeconds -Condition {
        $svc = Get-Service -Name 'Rosetun' -ErrorAction SilentlyContinue
        return ($null -ne $svc -and [string]$svc.Status -eq $Expected)
    }
}

function Invoke-TailScenariosAndRecovery {
    param(
        [Parameter(Mandatory)][string]$BaseRequestPath,
        [Parameter(Mandatory)][string]$UnprotectedRequestPath,
        [Parameter(Mandatory)][string]$StandardPassword
    )
    if ($caseName -in @('full', 'core')) {
        # Scenario 8: Lockdown off while connected, unprotected, and disconnected (no FWP_E_IN_USE).
        Set-RosetunRunnerStep -Step 'scenario-8-off'
        [void](Invoke-LockdownCmd 'on')
        $connect = Invoke-FailureCli -Arguments @('connect', $BaseRequestPath) -Seconds 90
        if ($connect.ExitCode -ne 0 -or -not (Wait-FailureState 'Connected' -TimeoutSeconds 30)) {
            throw "scenario 8 connect failed: exit $($connect.ExitCode)"
        }
        $mark = Get-HelperLogLength
        $off = Invoke-LockdownCmd 'off'
        Test-Step -Id 'off-connected.succeeds-and-no-objects' -Scenario '8 off connected' -Expectation 'lockdown off while connected succeeds and removes objects' -Note "exit $($off.ExitCode)" {
            $off.ExitCode -eq 0 -and (Test-LockdownAbsent)
        }
        $tunnel = Wait-TunnelEgress -Url "https://$unlisted/"
        Test-Step -Id 'off-connected.tunnel-and-killswitch-hold' -Scenario '8 off connected' -Expectation 'tunnel stays alive and request kill switch holds' -Note "curl $($tunnel.CurlExit)" {
            $tunnel.Ok -and (-not (Test-DirectEgress))
        }
        Test-Step -Id 'off-connected.no-in-use' -Scenario '8 off connected' -Expectation 'no FWP_E_IN_USE in helper log' {
            Test-InUseFree (Get-HelperLogSince $mark)
        }
        if (-not (Disconnect-LockdownSession)) { throw 'scenario 8 connected disconnect failed' }

        [void](Invoke-LockdownCmd 'on')
        $unprotConnect = Invoke-FailureCli -Arguments @('connect', $UnprotectedRequestPath) -Seconds 90
        if ($unprotConnect.ExitCode -ne 0 -or -not (Wait-FailureState 'Connected' -TimeoutSeconds 30)) {
            throw "scenario 8 unprotected connect failed: exit $($unprotConnect.ExitCode)"
        }
        $offUnprot = Invoke-LockdownCmd 'off'
        $tunnelUnprot = Wait-TunnelEgress -Url "https://$unlisted/"
        Test-Step -Id 'off-unprotected.succeeds-and-releases' -Scenario '8 off unprotected' -Expectation 'lockdown off releases forced kill switch while tunnel stays alive' -Note "exit $($offUnprot.ExitCode)" {
            $offUnprot.ExitCode -eq 0 -and (Test-DirectEgress) -and $tunnelUnprot.Ok
        }
        if (-not (Disconnect-LockdownSession)) { throw 'scenario 8 unprotected disconnect failed' }

        [void](Invoke-LockdownCmd 'on')
        $mark = Get-HelperLogLength
        $offDisc = Invoke-LockdownCmd 'off'
        Test-Step -Id 'off-disconnected.succeeds-and-no-objects' -Scenario '8 off disconnected' -Expectation 'lockdown off while disconnected succeeds and removes objects' -Note "exit $($offDisc.ExitCode)" {
            $offDisc.ExitCode -eq 0 -and (Test-LockdownAbsent)
        }
        Test-Step -Id 'off-disconnected.egress-and-ipv6-open' -Scenario '8 off disconnected' -Expectation 'direct egress and IPv6 work after off' {
            (Test-DirectEgress) -and (Test-Ipv6Egress)
        }
        $offAgain = Invoke-LockdownCmd 'off'
        Test-Step -Id 'off-disconnected.idempotent-and-no-in-use' -Scenario '8 off disconnected' -Expectation 'second off succeeds and no FWP_E_IN_USE' -Note "exit $($offAgain.ExitCode)" {
            $offAgain.ExitCode -eq 0 -and (Test-InUseFree (Get-HelperLogSince $mark))
        }

        # Scenario 9: SCM service Rosetun, standard-user refusal, --reset-firewall while running & stopped.
        Set-RosetunRunnerStep -Step 'scenario-9-reset'
        Stop-LockdownHelper
        $install = Invoke-RosetunNative -FilePath $helperPath -Arguments @('--install-service') -TimeoutSeconds 60
        if ($install.ExitCode -ne 0) { throw "install-service failed: $($install.ExitCode) $($install.Output)" }
        $script:serviceInstalled = $true
        if (-not (Wait-ScmServiceState -Expected 'Running' -TimeoutSeconds 40) -or -not (Wait-HelperReady -TimeoutSeconds 60)) {
            throw 'SCM service Rosetun did not become ready'
        }
        [void](Invoke-LockdownCmd 'on')
        $stdRefused = Test-StandardLockdownOffRefused -Password $StandardPassword
        Test-Step -Id 'reset-running.standard-off-refused' -Scenario '9 reset running' -Expectation 'standard account lockdown off refused and Lockdown stays' -Note $stdRefused.Note {
            $stdRefused.Ok
        }
        $svcConnect = Invoke-FailureCli -Arguments @('connect', $BaseRequestPath) -Seconds 90
        $stdRefusedConn = Test-StandardLockdownOffRefused -Password $StandardPassword
        Test-Step -Id 'reset-running.connect-and-standard-off-refused' -Scenario '9 reset running' -Expectation 'connected through SCM service, standard account off refused' -Note "conn=$($svcConnect.ExitCode) $($stdRefusedConn.Note)" {
            $svcConnect.ExitCode -eq 0 -and (Wait-FailureState 'Connected' -TimeoutSeconds 30) -and $stdRefusedConn.Ok
        }
        $resetRunning = Invoke-RosetunNative -FilePath $helperPath -Arguments @('--reset-firewall') -TimeoutSeconds 60
        Test-Step -Id 'reset-running.reset-succeeds-and-no-objects' -Scenario '9 reset running' -Expectation '--reset-firewall succeeds and removes Lockdown objects' -Note "exit=$($resetRunning.ExitCode)" {
            $resetRunning.ExitCode -eq 0 -and ($resetRunning.Output -match 'Lockdown removed') -and (Test-LockdownAbsent)
        }
        $svcReadyAgain = (Wait-ScmServiceState -Expected 'Running' -TimeoutSeconds 40) -and (Wait-HelperReady -TimeoutSeconds 60)
        Test-Step -Id 'reset-running.service-and-egress-open' -Scenario '9 reset running' -Expectation 'service runs with lockdown off and direct egress works' {
            $svcReadyAgain -and ((Get-LockdownStatusLine) -eq 'off') -and (Test-DirectEgress)
        }

        [void](Invoke-LockdownCmd 'on')
        Stop-Service -Name 'Rosetun' -Force
        [void](Wait-ScmServiceState -Expected 'Stopped' -TimeoutSeconds 30)
        Test-Step -Id 'reset-stopped.closed-while-stopped' -Scenario '9 reset stopped' -Expectation 'direct egress stays closed with service stopped' {
            -not (Test-DirectEgress)
        }
        $cliReset = Invoke-FailureCli -Arguments @('reset-firewall') -Seconds 60
        Test-Step -Id 'reset-stopped.cli-reset-and-no-objects' -Scenario '9 reset stopped' -Expectation 'rosetun reset-firewall succeeds and removes objects' -Note "exit=$($cliReset.ExitCode)" {
            $cliReset.ExitCode -eq 0 -and (Test-LockdownAbsent)
        }
        Test-Step -Id 'reset-stopped.egress-open-and-stays-stopped' -Scenario '9 reset stopped' -Expectation 'direct egress works and service stays stopped' {
            (Test-DirectEgress) -and ([string](Get-Service -Name 'Rosetun').Status -eq 'Stopped')
        }
        Start-Service -Name 'Rosetun'
        $restartedOff = (Wait-ScmServiceState -Expected 'Running' -TimeoutSeconds 40) -and (Wait-HelperReady -TimeoutSeconds 60)
        Test-Step -Id 'reset-stopped.service-starts-off' -Scenario '9 reset stopped' -Expectation 'service starts and reports lockdown off' {
            $restartedOff -and ((Get-LockdownStatusLine) -eq 'off')
        }

        # Scenario 10: Uninstall under Lockdown (--uninstall-service then --reset-firewall).
        Set-RosetunRunnerStep -Step 'scenario-10-uninstall'
        [void](Invoke-LockdownCmd 'on')
        [void](Invoke-FailureCli -Arguments @('connect', $BaseRequestPath) -Seconds 90)
        $uninstall = Invoke-RosetunNative -FilePath $helperPath -Arguments @('--uninstall-service') -TimeoutSeconds 60
        if ($uninstall.ExitCode -eq 0) { $script:serviceInstalled = $false }
        $resetUninstall = Invoke-RosetunNative -FilePath $helperPath -Arguments @('--reset-firewall') -TimeoutSeconds 60
        Test-Step -Id 'uninstall.steps-succeed' -Scenario '10 uninstall' -Expectation 'both uninstall steps succeed' -Note "uninst=$($uninstall.ExitCode) reset=$($resetUninstall.ExitCode)" {
            $uninstall.ExitCode -eq 0 -and $resetUninstall.ExitCode -eq 0
        }
        Test-Step -Id 'uninstall.no-objects' -Scenario '10 uninstall' -Expectation 'no Lockdown objects remain after uninstall' {
            Test-LockdownAbsent
        }

        Set-RosetunRunnerStep -Step 'recovery'
        $script:recoveryOpen = Send-RosetunMarker -Plan $plan -Label 'recovery' -Word 'open'
        Test-Step -Id 'uninstall.egress-and-ipv6-open' -Scenario '10 uninstall' -Expectation 'direct egress and IPv6 work after uninstall' {
            (Test-DirectEgress) -and (Test-Ipv6Egress)
        }
        Invoke-RecoveryControlProbes -NeedEgress $false -NeedIpv6 $false -NeedUdpDns $true -NeedTcpDns $true
        Start-Sleep -Seconds 3
        [void](Send-RosetunMarker -Plan $plan -Label 'recovery' -Word 'close')
        $script:recoveryOpen = $false
    }
    else {
        # Case `reboot`: no Scenarios 8-10; calibrate the physical recovery window now that Lockdown is off.
        Set-RosetunRunnerStep -Step 'recovery'
        $script:recoveryOpen = Send-RosetunMarker -Plan $plan -Label 'recovery' -Word 'open'
        Invoke-RecoveryControlProbes -NeedEgress $true -NeedIpv6 $true -NeedUdpDns $true -NeedTcpDns $true
        Start-Sleep -Seconds 3
        [void](Send-RosetunMarker -Plan $plan -Label 'recovery' -Word 'close')
        $script:recoveryOpen = $false
    }
}

$recorder = $null
$handoff = $false
$runError = $false
$script:baselineOpen = $false
$script:coreOpen = $false
$script:rebootOpen = $false
$script:recoveryOpen = $false
$script:serviceInstalled = $false
$script:filesVerified = $false
$cleanup = 'UNVERIFIED'
$parts = [ordered]@{}

try {
    Import-Module (Join-Path $Root 'RosetunListResults.psm1') -Force
    $baseRequestPath = Join-Path $work 'request.json'
    $unprotectedRequestPath = Join-Path $work 'request-unprotected.json'

    if (-not $Resume) {
        Initialize-RosetunRunner -StatusPath $statusPath -RunId ([string]$plan.run)
        Set-RosetunRunnerState -State running -Step 'prepare'
        New-Item -ItemType Directory -Force -Path $bin, $logs, $work | Out-Null
        foreach ($file in $plan.files) {
            $source = Join-Path $mediumRoot ([string]$file.name)
            $target = Join-Path $bin ([string]$file.name)
            Copy-Item -LiteralPath $source -Destination $target -Force
            $hash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($hash -ne [string]$file.sha256 -or (Get-Item -LiteralPath $target).Length -ne [int64]$file.size) {
                throw "delivered file differs from the plan: $($file.name)"
            }
        }
        $script:filesVerified = $true
        Add-RosetunRunnerNote -Name 'files-verified' -Value @($plan.files).Count

        $clock = [Diagnostics.Stopwatch]::StartNew()
        $version = Invoke-RosetunNative -FilePath $singBoxPath -Arguments @('version') -TimeoutSeconds 300
        Add-RosetunRunnerNote -Name 'sing-box-first-launch-seconds' -Value ([int]$clock.Elapsed.TotalSeconds)
        if ($version.ExitCode -ne 0) { throw 'sing-box does not start' }

        Set-RosetunRunnerStep -Step 'recorder'
        $vmId = ([string](Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID).ToLowerInvariant()
        $catalogRows = @($plan.catalog | ForEach-Object { $_ })
        $recorder = New-RosetunListResults -Directory $resultsDir -VmId $vmId -BootId (Get-RosetunBootCounter) -Suite 'windows-lockdown' -Catalog $catalogRows
        Set-RosetunRecorder -Recorder $recorder

        $baseRequest = Copy-FailureRequest -Request $plan.request
        $baseRequest.settings.kill_switch = $true
        [void](Write-FailureRequest -Name 'request.json' -Request $baseRequest)
        $unprotRequest = Copy-FailureRequest -Request $plan.request
        $unprotRequest.settings.kill_switch = $false
        [void](Write-FailureRequest -Name 'request-unprotected.json' -Request $unprotRequest)

        Set-RosetunRunnerStep -Step 'helper'
        $initReset = Invoke-RosetunNative -FilePath $helperPath -Arguments @('--reset-firewall') -TimeoutSeconds 60
        if ($initReset.ExitCode -ne 0) { throw "initial --reset-firewall failed: $($initReset.ExitCode)" }
        Start-LockdownHelper
        $standardPassword = New-StandardAccount

        # Scenario 1: Lockdown off (baseline window — listed, calibrates physical paths).
        Set-RosetunRunnerStep -Step 'scenario-1-baseline'
        $script:baselineOpen = Send-RosetunMarker -Plan $plan -Label 'baseline' -Word 'open'
        Test-Step -Id 'off.no-objects' -Scenario '1 off' -Expectation 'no Lockdown WFP objects exist' {
            Test-LockdownAbsent
        }
        Test-Step -Id 'off.status-off' -Scenario '1 off' -Expectation 'status reports lockdown off' {
            (Get-LockdownStatusLine) -eq 'off'
        }
        Test-Step -Id 'off.direct-egress' -Scenario '1 off' -Expectation 'direct egress works before Lockdown' {
            Test-DirectEgress
        }
        Test-Step -Id 'off.direct-dns' -Scenario '1 off' -Expectation 'direct UDP and TCP DNS work before Lockdown' {
            (Test-DirectDns -Name $baselineDns) -and (Test-DirectTcpDns -Name $baselineDns)
        }
        Test-Step -Id 'off.ipv6-open' -Scenario '1 off' -Expectation 'IPv6 to the host works before Lockdown' {
            Test-Ipv6Egress
        }
        Test-Step -Id 'off.cli-path-egress' -Scenario '1 off' -Expectation 'curl at the CLI path works before Lockdown' {
            Test-CliPathEgress
        }
        $stdPlain = Invoke-StandardFetch -Password $standardPassword
        $stdPhys = Invoke-StandardFetch -Password $standardPassword -Physical
        $standardFetchWorks = [bool]($stdPlain.Ok -eq $true -and $stdPhys.Ok -eq $true)
        Test-Step -Id 'off.standard-fetch' -Scenario '1 off' -Expectation 'standard-account sing-box fetch works plain and physical' -Note "plain=$($stdPlain.Ok) phys=$($stdPhys.Ok)" {
            $standardFetchWorks
        }
        $aclCheck = Test-EngineCopyAcl
        Test-Step -Id 'off.engine-copy-acl' -Scenario '1 off' -Expectation 'engine copy ACL allows only SYSTEM and Administrators' -Note $aclCheck.Note {
            $aclCheck.Ok
        }
        $copyDenied = Test-StandardEngineCopyDenied -Password $standardPassword
        Test-Step -Id 'off.standard-engine-copy-denied' -Scenario '1 off' -Expectation 'engine copy cannot be started by a standard account' -Note $copyDenied.Note {
            $copyDenied.Ok
        }
        Start-Sleep -Seconds 3
        [void](Send-RosetunMarker -Plan $plan -Label 'baseline' -Word 'close')
        $script:baselineOpen = $false

        if ($caseName -in @('full', 'core')) {
            # Judged wire window `lockdown-core`: covers Scenarios 2, 4, and 5 (until `lockdown off`).
            # Only `on.cli-path-egress-open` (1 TARGET_FLOW) leaves directly; everything else is blocked or tunnelled.
            Set-RosetunRunnerStep -Step 'scenario-2-on'
            $script:coreOpen = Send-RosetunMarker -Plan $plan -Label 'lockdown-core' -Word 'open'
            $on = Invoke-LockdownCmd 'on'
            Test-Step -Id 'on.command-succeeds' -Scenario '2 on' -Expectation 'rosetun lockdown on succeeds' -Note "exit $($on.ExitCode)" {
                $on.ExitCode -eq 0
            }
            Test-Step -Id 'on.objects-present' -Scenario '2 on' -Expectation 'Lockdown WFP objects present without LAN' {
                Test-LockdownInstalled
            }
            Test-Step -Id 'on.status-on' -Scenario '2 on' -Expectation 'status reports lockdown on' {
                (Get-LockdownStatusLine) -eq 'on'
            }
            Test-Step -Id 'on.cli-permits-present' -Scenario '2 on' -Expectation 'CLI permits present and retired absent' {
                Test-ProgramPermits -Present
            }
            $stdPlainOn = Invoke-StandardFetch -Password $standardPassword
            $stdPhysOn = Invoke-StandardFetch -Password $standardPassword -Physical
            Test-Step -Id 'on.standard-fetch-blocked' -Scenario '2 on' -Expectation 'standard-account sing-box fetch fails plain and physical' -Note "plain=$($stdPlainOn.Ok) phys=$($stdPhysOn.Ok)" {
                $standardFetchWorks -and $stdPlainOn.Ok -eq $false -and $stdPhysOn.Ok -eq $false
            }
            Test-Step -Id 'on.direct-egress-closed' -Scenario '2 on' -Expectation 'direct egress is blocked under Lockdown' {
                -not (Test-DirectEgress)
            }
            Test-Step -Id 'on.direct-dns-closed' -Scenario '2 on' -Expectation 'direct UDP and TCP DNS are blocked under Lockdown' {
                (-not (Test-DirectDns -Name $baselineDns)) -and (-not (Test-DirectTcpDns -Name $baselineDns))
            }
            Test-Step -Id 'on.ipv6-closed' -Scenario '2 on' -Expectation 'IPv6 outside the tunnel is blocked under Lockdown' {
                -not (Test-Ipv6Egress)
            }
            Test-Step -Id 'on.loopback-open' -Scenario '2 on' -Expectation 'IPv4 and IPv6 loopback stay open' {
                Test-LoopbackOpen
            }
            Test-Step -Id 'on.cli-path-egress-open' -Scenario '2 on' -Expectation 'program at CLI path gets out while disconnected' {
                Test-CliPathEgress
            }

            # Scenario 4: Connect under Lockdown, disconnect, forced kill switch.
            Set-RosetunRunnerStep -Step 'scenario-4-connected'
            $connect = Invoke-FailureCli -Arguments @('connect', $baseRequestPath) -Seconds 90
            Test-Step -Id 'connected.connect-succeeds' -Scenario '4 connected' -Expectation 'connect succeeds under Lockdown' -Note "exit $($connect.ExitCode)" {
                $connect.ExitCode -eq 0 -and (Wait-FailureState 'Connected' -TimeoutSeconds 30)
            }
            $tunnel = Wait-TunnelEgress -Url "https://$unlisted/"
            Test-Step -Id 'connected.tunnel-carries-traffic' -Scenario '4 connected' -Expectation 'tunnel carries traffic under Lockdown' -Note "curl $($tunnel.CurlExit)" {
                $tunnel.Ok
            }
            Test-Step -Id 'connected.direct-egress-closed' -Scenario '4 connected' -Expectation 'direct egress is blocked while connected' {
                -not (Test-DirectEgress)
            }
            Test-Step -Id 'connected.direct-dns-closed' -Scenario '4 connected' -Expectation 'direct UDP and TCP DNS blocked while connected' {
                (-not (Test-DirectDns -Name $baselineDns)) -and (-not (Test-DirectTcpDns -Name $baselineDns))
            }
            Test-Step -Id 'connected.ipv6-closed' -Scenario '4 connected' -Expectation 'IPv6 outside tunnel blocked while connected' {
                -not (Test-Ipv6Egress)
            }
            Test-Step -Id 'connected.cli-permits-removed' -Scenario '4 connected' -Expectation 'CLI permits removed for the session' {
                Test-ProgramPermits
            }
            Test-Step -Id 'connected.cli-path-egress-closed' -Scenario '4 connected' -Expectation 'program at CLI path blocked outside tunnel' {
                -not (Test-CliPathEgress)
            }
            $stdPhysConn = Invoke-StandardFetch -Password $standardPassword -Physical
            Test-Step -Id 'connected.standard-fetch-physical-blocked' -Scenario '4 connected' -Expectation 'standard-account physical fetch fails while connected' -Note "phys=$($stdPhysConn.Ok)" {
                $standardFetchWorks -and $stdPhysConn.Ok -eq $false
            }
            $copyDeniedConn = Test-StandardEngineCopyDenied -Password $standardPassword
            Test-Step -Id 'connected.standard-engine-copy-denied' -Scenario '4 connected' -Expectation 'engine copy denied for standard account while connected' -Note $copyDeniedConn.Note {
                $copyDeniedConn.Ok
            }
            if (-not (Disconnect-LockdownSession)) { throw 'scenario 4 disconnect failed' }
            Test-Step -Id 'disconnected.closed-and-objects-present' -Scenario '4 disconnected' -Expectation 'egress closed, session filters gone and objects remain' {
                (-not (Test-DirectEgress)) -and (-not (Test-SessionProviderPresent)) -and (Test-LockdownInstalled)
            }
            $stdPlainDisc = Invoke-StandardFetch -Password $standardPassword
            $stdPhysDisc = Invoke-StandardFetch -Password $standardPassword -Physical
            Test-Step -Id 'disconnected.cli-permits-and-standard-fetch' -Scenario '4 disconnected' -Expectation 'CLI permits return and standard fetches fail' {
                (Test-ProgramPermits -Present) -and $standardFetchWorks -and $stdPlainDisc.Ok -eq $false -and $stdPhysDisc.Ok -eq $false
            }
            $unprotConnect = Invoke-FailureCli -Arguments @('connect', $unprotectedRequestPath) -Seconds 90
            Test-Step -Id 'killswitch-off.forced-closed' -Scenario '4 killswitch off' -Expectation 'connect with kill_switch=false still forces egress closed' -Note "exit $($unprotConnect.ExitCode)" {
                $unprotConnect.ExitCode -eq 0 -and (Wait-FailureState 'Connected' -TimeoutSeconds 30) -and (-not (Test-DirectEgress))
            }
            if (-not (Disconnect-LockdownSession)) { throw 'scenario 4 unprotected disconnect failed' }

            # Scenario 5: Killed helper under Lockdown holds; without Lockdown fails open.
            Set-RosetunRunnerStep -Step 'scenario-5-killed'
            $c5 = Invoke-FailureCli -Arguments @('connect', $baseRequestPath) -Seconds 90
            if ($c5.ExitCode -ne 0 -or -not (Wait-FailureState 'Connected' -TimeoutSeconds 30)) {
                throw "scenario 5 connect failed: exit $($c5.ExitCode)"
            }
            Stop-LockdownHelper
            [void](Wait-FailureCondition -TimeoutSeconds 15 -Condition { -not (Test-SessionProviderPresent) })
            Test-Step -Id 'killed-on.egress-and-ipv6-closed' -Scenario '5 killed on' -Expectation 'direct egress and IPv6 stay closed after helper kill' {
                (-not (Test-DirectEgress)) -and (-not (Test-Ipv6Egress))
            }
            Test-Step -Id 'killed-on.session-gone-objects-stay' -Scenario '5 killed on' -Expectation 'dynamic session gone and Lockdown objects stay' {
                (-not (Test-SessionProviderPresent)) -and (Test-LockdownInstalled)
            }
            Test-Step -Id 'killed-on.cli-permits-absent' -Scenario '5 killed on' -Expectation 'CLI permits absent until helper restarts' {
                Test-ProgramPermits
            }
            Start-LockdownHelper
            $startLog = Get-HelperLogText
            Test-Step -Id 'restarted-on.finds-lockdown-complete' -Scenario '5 restarted on' -Expectation 'restarted helper finds Lockdown complete' {
                $startLog -match 'Lockdown is on.*\bcomplete=true'
            }
            Test-Step -Id 'restarted-on.status-on' -Scenario '5 restarted on' -Expectation 'restarted helper reports lockdown on' {
                (Get-LockdownStatusLine) -eq 'on'
            }
            Test-Step -Id 'restarted-on.cli-permits-restored' -Scenario '5 restarted on' -Expectation 'restarted helper restores CLI permits' {
                Test-ProgramPermits -Present
            }
            # Settle while Lockdown is active, then turn Lockdown off and close `lockdown-core` immediately
            # before background OS traffic or the fail-open probe can run on the open network.
            Start-Sleep -Seconds 2
            $off5 = Invoke-LockdownCmd 'off'
            [void](Send-RosetunMarker -Plan $plan -Label 'lockdown-core' -Word 'close')
            $script:coreOpen = $false
            Test-Step -Id 'killed-off.off-succeeds' -Scenario '5 killed off' -Expectation 'rosetun lockdown off succeeds' -Note "exit $($off5.ExitCode)" {
                $off5.ExitCode -eq 0
            }

            $c5off = Invoke-FailureCli -Arguments @('connect', $baseRequestPath) -Seconds 90
            if ($c5off.ExitCode -ne 0 -or -not (Wait-FailureState 'Connected' -TimeoutSeconds 30)) {
                throw "scenario 5 fail-open connect failed: exit $($c5off.ExitCode)"
            }
            Stop-LockdownHelper
            Test-Step -Id 'killed-off.fails-open' -Scenario '5 killed off' -Expectation 'without Lockdown, killed helper fails open' {
                Wait-FailureCondition -TimeoutSeconds 20 -Condition { Test-DirectEgress }
            }
            Start-LockdownHelper
            # Settle briefly after the fail-open TUN teardown so any background OS probes triggered by the
            # interface change finish before `reboot-lockdown` opens.
            Start-Sleep -Seconds 5
        }

        if ($caseName -in @('full', 'reboot')) {
            # Scenario 6: Clean reboot under Lockdown.
            # Open `reboot-lockdown` before turning Lockdown on so the open marker reaches the lab service.
            Set-RosetunRunnerStep -Step 'scenario-6-prepare-reboot'
            $script:rebootOpen = Send-RosetunMarker -Plan $plan -Label 'reboot-lockdown' -Word 'open'
            $on6 = Invoke-LockdownCmd 'on'
            if ($on6.ExitCode -ne 0) { throw "scenario 6 lockdown on failed: $($on6.ExitCode)" }
            $savedBootRec = Disable-BootRecoveryForPowerCuts
            Stop-LockdownHelper
            Register-LockdownBootCheckTask
            Register-LockdownResumeTask
            Save-LockdownCheckpoint -Data ([ordered]@{
                    phase                = 'after-reboot'
                    pass                 = 0
                    cmd_exit             = 0
                    standard_password    = $standardPassword
                    standard_fetch_works = $standardFetchWorks
                    reboot_window_open   = $true
                    boot_recovery_policy = $savedBootRec.policy
                    boot_recovery_enabled = $savedBootRec.recovery
                })
            $handoff = $true
            Set-RosetunRunnerState -State 'reboot-requested' -Step 'scenario-6-reboot'
            exit 0
        }

        # Case `core` (no reboots or power cuts): run Scenarios 8-10 and recovery immediately.
        Invoke-TailScenariosAndRecovery -BaseRequestPath $baseRequestPath -UnprotectedRequestPath $unprotectedRequestPath -StandardPassword $standardPassword
    }
    else {
        # Resumed after a clean reboot or abrupt power cut via RosetunLockdownResume.
        $script:filesVerified = $true
        Resume-RosetunRunner -StatusPath $statusPath -RunId ([string]$plan.run)
        $recorder = Resume-RosetunListResults -Directory $resultsDir
        Set-RosetunRecorder -Recorder $recorder
        $checkpoint = Read-LockdownCheckpoint
        $phase = [string]$checkpoint.phase
        $pass = [int]$checkpoint.pass
        $cmdExit = [int]$checkpoint.cmd_exit
        $standardPassword = [string]$checkpoint.standard_password
        $standardFetchWorks = [bool]$checkpoint.standard_fetch_works
        $script:rebootOpen = [bool]$checkpoint.reboot_window_open

        Set-RosetunRunnerState -State running -Step ("resume-$phase-$pass")
        $bootNum = [int64]((Get-RosetunBootCounter) -replace '^win-', '')
        Add-RosetunRunnerNote -Name ("boot-$phase-$pass") -Value $bootNum
        Wait-BootServicesReady

        if ($phase -eq 'after-reboot') {
            $currentBoot = Get-RosetunBootCounter
            $bootCheck = $null
            $deadline = [DateTime]::UtcNow.AddSeconds(150)
            while ([DateTime]::UtcNow -lt $deadline) {
                if (Test-Path -LiteralPath $bootCheckResultPath) {
                    try {
                        $candidate = [IO.File]::ReadAllText($bootCheckResultPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
                        if ([string]$candidate.boot_id -eq $currentBoot) {
                            $bootCheck = $candidate
                            break
                        }
                    }
                    catch { }
                }
                Start-Sleep -Milliseconds 500
            }
            Unregister-ScheduledTask -TaskName $bootCheckTaskName -Confirm:$false -ErrorAction SilentlyContinue
            Test-Step -Id 'reboot.boot-check-before-helper' -Scenario '6 reboot' -Expectation 'boot check ran before helper and no attempt reached target' -Note $(if ($bootCheck) { "routed=$($bootCheck.routed) open=$($bootCheck.egress_open) helper=$($bootCheck.helper_at_start)/$($bootCheck.helper_at_end)" } else { 'missing' }) {
                $null -ne $bootCheck -and (-not $bootCheck.helper_at_start) -and (-not $bootCheck.helper_at_end) -and
                    ([int]$bootCheck.routed -ge 1) -and (-not $bootCheck.egress_open)
            }
            Test-Step -Id 'reboot.objects-present' -Scenario '6 reboot' -Expectation 'Lockdown objects survive clean reboot' {
                Test-LockdownInstalled
            }
            Test-Step -Id 'reboot.egress-and-ipv6-closed' -Scenario '6 reboot' -Expectation 'direct egress and IPv6 closed after reboot before helper' {
                (-not (Test-DirectEgress)) -and (-not (Test-Ipv6Egress))
            }
            Start-LockdownHelper
            Test-Step -Id 'reboot.helper-started-closed' -Scenario '6 reboot' -Expectation 'direct egress stays closed after helper starts' {
                -not (Test-DirectEgress)
            }
            $c6 = Invoke-FailureCli -Arguments @('connect', $baseRequestPath) -Seconds 90
            $t6 = Wait-TunnelEgress -Url "https://$unlisted/"
            Test-Step -Id 'reboot.connect-opens-tunnel' -Scenario '6 reboot' -Expectation 'connect opens tunnel after reboot under Lockdown' -Note "exit=$($c6.ExitCode) curl=$($t6.CurlExit)" {
                $c6.ExitCode -eq 0 -and (Wait-FailureState 'Connected' -TimeoutSeconds 30) -and $t6.Ok
            }
            if (-not (Disconnect-LockdownSession)) { throw 'scenario 6 disconnect failed' }
            Test-Step -Id 'reboot.disconnected-closed' -Scenario '6 reboot' -Expectation 'direct egress stays closed after disconnect' {
                -not (Test-DirectEgress)
            }

            # Settle while Lockdown is still active, then turn Lockdown off and immediately close `reboot-lockdown`
            # so the UDP marker leaves before background Windows NCSI probes wake up on the open network.
            Start-Sleep -Seconds 2
            $off6 = Invoke-LockdownCmd 'off'
            if ($off6.ExitCode -ne 0) { throw "scenario 6 lockdown off failed: $($off6.ExitCode)" }
            [void](Send-RosetunMarker -Plan $plan -Label 'reboot-lockdown' -Word 'close')
            $script:rebootOpen = $false

            if ($powerCutRepeats -gt 0) {
                # Start Scenario 7 pass 1: turn Lockdown on, then request abrupt power cut.
                Set-RosetunRunnerStep -Step 'scenario-7-cut-on-1'
                $onCut = Invoke-LockdownCmd 'on'
                Save-LockdownCheckpoint -Data ([ordered]@{
                        phase                 = 'after-cut-on'
                        pass                  = 1
                        cmd_exit              = [int]$onCut.ExitCode
                        standard_password     = $standardPassword
                        standard_fetch_works  = $standardFetchWorks
                        reboot_window_open    = $false
                        boot_recovery_policy  = $checkpoint.boot_recovery_policy
                        boot_recovery_enabled = $checkpoint.boot_recovery_enabled
                    })
                $handoff = $true
                Set-RosetunRunnerState -State 'power-cut-requested' -Step 'scenario-7-cut-on-1'
                exit 0
            }
            Invoke-TailScenariosAndRecovery -BaseRequestPath $baseRequestPath -UnprotectedRequestPath $unprotectedRequestPath -StandardPassword $standardPassword
        }
        elseif ($phase -eq 'after-cut-on') {
            # Verify Lockdown persisted across abrupt power cut BEFORE starting helper.
            Test-Step -Id "cut.pass-$pass.on-persists" -Scenario "7 cut on $pass" -Expectation "pass $pass Lockdown objects survive abrupt power cut" -Note "cmd=$cmdExit" {
                $cmdExit -eq 0 -and (Test-LockdownInstalled)
            }
            Start-LockdownHelper
            Set-RosetunRunnerStep -Step ("scenario-7-cut-off-$pass")
            $offCut = Invoke-LockdownCmd 'off'
            Save-LockdownCheckpoint -Data ([ordered]@{
                    phase                 = 'after-cut-off'
                    pass                  = $pass
                    cmd_exit              = [int]$offCut.ExitCode
                    standard_password     = $standardPassword
                    standard_fetch_works  = $standardFetchWorks
                    reboot_window_open    = $false
                    boot_recovery_policy  = $checkpoint.boot_recovery_policy
                    boot_recovery_enabled = $checkpoint.boot_recovery_enabled
                })
            $handoff = $true
            Set-RosetunRunnerState -State 'power-cut-requested' -Step ("scenario-7-cut-off-$pass")
            exit 0
        }
        elseif ($phase -eq 'after-cut-off') {
            Test-Step -Id "cut.pass-$pass.off-persists" -Scenario "7 cut off $pass" -Expectation "pass $pass Lockdown removal survives abrupt power cut" -Note "cmd=$cmdExit" {
                $cmdExit -eq 0 -and (Test-LockdownAbsent)
            }
            Test-Step -Id "cut.pass-$pass.off-egress-open" -Scenario "7 cut off $pass" -Expectation "pass $pass direct egress works after abrupt power cut" {
                Wait-FailureCondition -TimeoutSeconds 15 -Condition { Test-DirectEgress }
            }
            Start-LockdownHelper
            if ($pass -lt $powerCutRepeats) {
                $nextPass = $pass + 1
                Set-RosetunRunnerStep -Step ("scenario-7-cut-on-$nextPass")
                $onCut = Invoke-LockdownCmd 'on'
                Save-LockdownCheckpoint -Data ([ordered]@{
                        phase                 = 'after-cut-on'
                        pass                  = $nextPass
                        cmd_exit              = [int]$onCut.ExitCode
                        standard_password     = $standardPassword
                        standard_fetch_works  = $standardFetchWorks
                        reboot_window_open    = $false
                        boot_recovery_policy  = $checkpoint.boot_recovery_policy
                        boot_recovery_enabled = $checkpoint.boot_recovery_enabled
                    })
                $handoff = $true
                Set-RosetunRunnerState -State 'power-cut-requested' -Step ("scenario-7-cut-on-$nextPass")
                exit 0
            }
            # All power-cut passes complete: continue into Scenarios 8-10 (or recovery for `reboot` case).
            Invoke-TailScenariosAndRecovery -BaseRequestPath $baseRequestPath -UnprotectedRequestPath $unprotectedRequestPath -StandardPassword $standardPassword
        }
        else {
            throw "unknown lockdown checkpoint phase: $phase"
        }
    }
}
catch {
    $runError = $true
    Set-RosetunRunnerError -Place 'execution' -Text "$($_.Exception.GetType().Name): $($_.Exception.Message)"
}
finally {
    if (-not $handoff) {
        try {
            Set-RosetunRunnerState -State cleaning -Step 'cleanup'
            if ($script:filesVerified -and (Test-Path -LiteralPath $cliPath)) {
                try { [void](Disconnect-LockdownSession -TimeoutSeconds 20) } catch { }
            }
            Stop-LockdownHelper
            $svc = Get-Service -Name 'Rosetun' -ErrorAction SilentlyContinue
            if ($null -ne $svc) {
                if ($script:filesVerified -and (Test-Path -LiteralPath $helperPath)) {
                    [void](Invoke-RosetunNative -FilePath $helperPath -Arguments @('--uninstall-service') -TimeoutSeconds 60)
                }
            }
            $parts['service'] = if ($null -eq (Get-Service -Name 'Rosetun' -ErrorAction SilentlyContinue)) { 'PASS' } else { 'ERROR' }

            if ($script:filesVerified -and (Test-Path -LiteralPath $helperPath)) {
                $reset = Invoke-RosetunNative -FilePath $helperPath -Arguments @('--reset-firewall') -TimeoutSeconds 60
                $parts['firewall'] = if ($reset.ExitCode -eq 0 -and (Test-LockdownAbsent)) { 'PASS' } else { 'ERROR' }
            }
            else { $parts['firewall'] = 'UNVERIFIED' }

            # Close any window left open by an error (now that Lockdown is guaranteed off).
            if ($script:recoveryOpen) {
                [void](Send-RosetunMarker -Plan $plan -Label 'recovery' -Word 'close')
                $script:recoveryOpen = $false
            }
            if ($script:rebootOpen) {
                [void](Send-RosetunMarker -Plan $plan -Label 'reboot-lockdown' -Word 'close')
                $script:rebootOpen = $false
            }
            if ($script:coreOpen) {
                [void](Send-RosetunMarker -Plan $plan -Label 'lockdown-core' -Word 'close')
                $script:coreOpen = $false
            }
            if ($script:baselineOpen) {
                [void](Send-RosetunMarker -Plan $plan -Label 'baseline' -Word 'close')
                $script:baselineOpen = $false
            }

            $parts['helper'] = if (-not (Get-Process -Name 'rosetun-helper-privileged' -ErrorAction SilentlyContinue)) { 'PASS' } else { 'ERROR' }

            foreach ($t in @($taskName, $resumeTaskName, $bootCheckTaskName)) {
                Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction SilentlyContinue
            }
            $tasksLeft = @($taskName, $resumeTaskName, $bootCheckTaskName | Where-Object { $null -ne (Get-ScheduledTask -TaskName $_ -ErrorAction SilentlyContinue) })
            $parts['tasks'] = if ($tasksLeft.Count -eq 0) { 'PASS' } else { 'ERROR' }

            Remove-StandardAccount
            $parts['standard_user'] = if ($null -eq (Get-LocalUser -Name $standardUser -ErrorAction SilentlyContinue) -and -not (Test-Path -LiteralPath $standardDir)) { 'PASS' } else { 'ERROR' }

            $clock = [Diagnostics.Stopwatch]::StartNew()
            while ($clock.Elapsed.TotalSeconds -lt 20 -and (Get-NetAdapter -Name ([string]$plan.tun.alias) -ErrorAction SilentlyContinue)) {
                Start-Sleep -Milliseconds 500
            }
            $parts['adapter'] = if ($null -eq (Get-NetAdapter -Name ([string]$plan.tun.alias) -ErrorAction SilentlyContinue)) { 'PASS' } else { 'ERROR' }

            Remove-Item -LiteralPath $work, $checkpointPath -Recurse -Force -ErrorAction SilentlyContinue
            $parts['work'] = if (-not (Test-Path -LiteralPath $work) -and -not (Test-Path -LiteralPath $checkpointPath)) { 'PASS' } else { 'ERROR' }

            Remove-Item -LiteralPath $bin -Recurse -Force -ErrorAction SilentlyContinue
            $parts['binaries'] = if (-not (Test-Path -LiteralPath $bin)) { 'PASS' } else { 'ERROR' }

            $cleanup = if (@($parts.Values) -contains 'ERROR') { 'ERROR' }
            elseif (@($parts.Values | Where-Object { $_ -ne 'PASS' }).Count -gt 0) { 'UNVERIFIED' }
            else { 'PASS' }
        }
        catch {
            $cleanup = 'ERROR'
            Set-RosetunRunnerError -Place 'cleanup' -Text "$($_.Exception.GetType().Name): $($_.Exception.Message)"
        }
        Set-RosetunRunnerCleanup -Result $cleanup -Parts $parts

        if ($recorder) {
            try {
                $endBoot = ''
                try { $endBoot = Get-RosetunBootCounter } catch { Add-RosetunListError -Recorder $recorder -Place execution }
                if ($cleanup -eq 'ERROR') { Add-RosetunListError -Recorder $recorder -Place cleanup }
                Complete-RosetunListResults -Recorder $recorder -Cleanup $cleanup -EndBootId $endBoot -Aborted $runError
            }
            catch {
                Set-RosetunRunnerError -Place 'export' -Text "$($_.Exception.GetType().Name): $($_.Exception.Message)"
            }
        }
        if ($runError -or $null -eq $recorder) { Set-RosetunRunnerState -State failed -Step 'done' }
        else { Set-RosetunRunnerState -State finished -Step 'done' }
    }
}
