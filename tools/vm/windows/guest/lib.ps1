# Shared by the autonomous guest runners of the QEMU matrix. Windows PowerShell 5.1.
#
# The controller starts a runner through the guest agent and then only reads its status file: a runner has to live
# through a lost agent session, so it keeps all of its state in that one file and rewrites it atomically after every
# step. Nothing here reaches the network except the window markers, which the plan names.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:RunnerStatus = $null
$script:RunnerStatusPath = $null
$script:RunnerRecorder = $null
$script:RunnerResults = $null

function Get-RosetunUtcNow {
    return [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
}

function ConvertTo-RosetunSafeText {
    # Words of a fixed alphabet and a short length: what a note or an error may say in the status file.
    param([AllowNull()][string]$Text, [int]$Limit = 96)
    if ($null -eq $Text) { return '' }
    $clean = ($Text.ToLowerInvariant() -replace '[^a-z0-9:._ -]+', '-')
    if ($clean.Length -gt $Limit) { $clean = $clean.Substring(0, $Limit) }
    return $clean.Trim()
}

function Initialize-RosetunRunner {
    param([Parameter(Mandatory)][string]$StatusPath, [Parameter(Mandatory)][string]$RunId, [switch]$WithAction)
    $script:RunnerStatusPath = $StatusPath
    $script:RunnerStatus = [ordered]@{
        schema = 'rosetun.matrix.windows-runner-status.v1'
        run = $RunId
        state = 'starting'
        step = 'start'
        sequence = 0
        started_utc = Get-RosetunUtcNow
        updated_utc = Get-RosetunUtcNow
        checks = [Collections.Generic.List[object]]::new()
        markers = [Collections.Generic.List[object]]::new()
        notes = [Collections.Generic.List[object]]::new()
        cleanup = $null
        error = $null
    }
    if ($WithAction) { $script:RunnerStatus['action'] = $null }
    Save-RosetunStatus
}

function Resume-RosetunRunner {
    param([Parameter(Mandatory)][string]$StatusPath, [Parameter(Mandatory)][string]$RunId)
    $script:RunnerStatusPath = $StatusPath
    $raw = [IO.File]::ReadAllText($StatusPath, [Text.Encoding]::UTF8)
    $loaded = $raw | ConvertFrom-Json
    if ([string]$loaded.schema -ne 'rosetun.matrix.windows-runner-status.v1' -or [string]$loaded.run -ne $RunId) {
        throw 'runner-status-resume-mismatch'
    }
    $checks = [Collections.Generic.List[object]]::new()
    foreach ($item in @($loaded.checks)) { if ($null -ne $item) { $checks.Add($item) } }
    $markers = [Collections.Generic.List[object]]::new()
    foreach ($item in @($loaded.markers)) { if ($null -ne $item) { $markers.Add($item) } }
    $notes = [Collections.Generic.List[object]]::new()
    foreach ($item in @($loaded.notes)) { if ($null -ne $item) { $notes.Add($item) } }
    $script:RunnerStatus = [ordered]@{
        schema = [string]$loaded.schema
        run = [string]$loaded.run
        state = [string]$loaded.state
        step = [string]$loaded.step
        sequence = [int]$loaded.sequence
        started_utc = [string]$loaded.started_utc
        updated_utc = [string]$loaded.updated_utc
        checks = $checks
        markers = $markers
        notes = $notes
        cleanup = $loaded.cleanup
        error = $loaded.error
    }
    if ($loaded.PSObject.Properties.Name -contains 'action') { $script:RunnerStatus['action'] = $loaded.action }
}

function Save-RosetunStatus {
    # Write the new text beside the file, flush to disk and put it in place: the reader sees the old status or the new
    # one, whole, and an abrupt power cut cannot leave an empty or half-written file.
    $script:RunnerStatus.sequence = [int]$script:RunnerStatus.sequence + 1
    $script:RunnerStatus.updated_utc = Get-RosetunUtcNow
    $json = ConvertTo-Json -InputObject $script:RunnerStatus -Depth 8 -Compress
    $temporary = $script:RunnerStatusPath + '.tmp'
    $bytes = [Text.Encoding]::UTF8.GetBytes($json + "`n")
    $stream = [IO.FileStream]::new($temporary, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }
    for ($attempt = 1; $attempt -le 100; $attempt++) {
        try {
            if (Test-Path -LiteralPath $script:RunnerStatusPath) {
                [IO.File]::Replace($temporary, $script:RunnerStatusPath, [NullString]::Value)
            }
            else {
                [IO.File]::Move($temporary, $script:RunnerStatusPath)
            }
            return
        }
        catch [IO.IOException] {
            if ($attempt -eq 100) { throw }
            Start-Sleep -Milliseconds 50
        }
    }
}

function Set-RosetunRunnerState {
    param([Parameter(Mandatory)][ValidateSet('starting', 'running', 'reboot-requested', 'power-cut-requested', 'lab-action-requested', 'cleaning', 'finished', 'failed')][string]$State,
        [string]$Step)
    $script:RunnerStatus.state = $State
    if ($Step) { $script:RunnerStatus.step = $Step }
    Save-RosetunStatus
}

function Set-RosetunRunnerStep {
    param([Parameter(Mandatory)][string]$Step)
    $script:RunnerStatus.step = $Step
    Save-RosetunStatus
}

function Invoke-RosetunLabAction {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][ValidateSet('probe_proxy', 'lan_state')][string]$Operation,
        [hashtable]$Parameters = @{},
        [int]$TimeoutSeconds = 90
    )
    $id = [guid]::NewGuid().ToString('N').Substring(0, 16)
    $replyPath = Join-Path $Root ('action-reply-' + $id + '.json')
    if (Test-Path -LiteralPath $replyPath) { Remove-Item -LiteralPath $replyPath -Force -ErrorAction SilentlyContinue }
    $script:RunnerStatus['action'] = [ordered]@{ id = $id; operation = $Operation; params = $Parameters }
    Set-RosetunRunnerState -State 'lab-action-requested' -Step ('lab-' + $Operation)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $replyPath) {
            $raw = [IO.File]::ReadAllText($replyPath, [Text.Encoding]::UTF8)
            Remove-Item -LiteralPath $replyPath -Force -ErrorAction SilentlyContinue
            $script:RunnerStatus['action'] = $null
            Set-RosetunRunnerState -State 'running' -Step ('after-' + $Operation)
            return ($raw | ConvertFrom-Json)
        }
        Start-Sleep -Milliseconds 200
    }
    $script:RunnerStatus['action'] = $null
    throw ('lab-action-timeout:' + $Operation)
}

function Add-RosetunRunnerNote {
    # A measurement worth keeping beside the checks (a duration, a count): name and number, never text of the guest.
    param([Parameter(Mandatory)][string]$Name, $Value)
    $script:RunnerStatus.notes.Add([ordered]@{ name = (ConvertTo-RosetunSafeText $Name 48); value = $Value })
    Save-RosetunStatus
}

function Set-RosetunRunnerError {
    # The first error is the one that stands (a failed step is what made the cleanup fail too); a later one is added
    # to its text, so that neither is lost.
    param([Parameter(Mandatory)][string]$Place, [AllowNull()][string]$Text)
    $text = (ConvertTo-RosetunSafeText $Text 120)
    if ($null -eq $script:RunnerStatus.error) {
        $script:RunnerStatus.error = [ordered]@{ place = (ConvertTo-RosetunSafeText $Place 32); text = $text }
    }
    else {
        $joined = $script:RunnerStatus.error.text + ' - ' + (ConvertTo-RosetunSafeText $Place 32) + ': ' + $text
        $script:RunnerStatus.error.text = if ($joined.Length -gt 160) { $joined.Substring(0, 160) } else { $joined }
    }
    Save-RosetunStatus
}

function Set-RosetunRunnerCleanup {
    param([Parameter(Mandatory)][ValidateSet('PASS', 'ERROR', 'UNVERIFIED')][string]$Result, $Parts)
    $script:RunnerStatus.cleanup = [ordered]@{ result = $Result; parts = $Parts }
    Save-RosetunStatus
}

function Set-RosetunRecorder {
    # The recorder of `RosetunListResults.psm1`, when the runner keeps the artifacts of the Hyper-V matrix as well.
    param($Recorder)
    $script:RunnerRecorder = $Recorder
}

function Test-Step {
    # The Hyper-V matrix's step: the condition passes, fails, or throws (which is a failure with its own reason).
    # The result goes to the status file at once, and to the recorder when there is one.
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Scenario,
        [Parameter(Mandatory)][string]$Expectation,
        [Parameter(Mandatory)][scriptblock]$Condition,
        [string]$Note = ''
    )
    $reason = 'condition-false'
    try {
        $passed = [bool](& $Condition)
    }
    catch {
        $passed = $false
        $reason = 'condition-exception'
        $Note = "$($_.Exception.GetType().Name): $($_.Exception.Message)"
    }
    $result = if ($passed) { 'PASS' } else { 'FAIL' }
    $script:RunnerStatus.checks.Add([ordered]@{
            id = $Id
            result = $result
            reason = if ($passed) { 'checked' } else { $reason }
            scenario = (ConvertTo-RosetunSafeText $Scenario 48)
            note = (ConvertTo-RosetunSafeText $Note 120)
        })
    if ($script:RunnerRecorder) {
        Add-RosetunListResult -Recorder $script:RunnerRecorder -Id $Id -Result $result -Reason $(if ($passed) { 'checked' } else { $reason })
    }
    Save-RosetunStatus
}

function Skip-RosetunStep {
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][string]$Reason, [string]$Scenario = '')
    $script:RunnerStatus.checks.Add([ordered]@{ id = $Id; result = 'SKIP'; reason = $Reason; scenario = $Scenario; note = '' })
    if ($script:RunnerRecorder) {
        Add-RosetunListResult -Recorder $script:RunnerRecorder -Id $Id -Result SKIP -Reason $Reason
    }
    Save-RosetunStatus
}

function Invoke-RosetunNative {
    # One program, with a time limit, its two streams read as UTF-8 and the environment of this call only.
    # Returns ExitCode (-1 when it had to be killed) and Output (both streams, stdout first).
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments = @(),
        [int]$TimeoutSeconds = 30,
        [hashtable]$Environment = @{}
    )
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $FilePath
    $start.Arguments = (($Arguments | ForEach-Object { if ($_ -match '[\s"]' -or $_ -eq '') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }) -join ' ')
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = [Text.Encoding]::UTF8
    $start.StandardErrorEncoding = [Text.Encoding]::UTF8
    foreach ($name in $Environment.Keys) { $start.EnvironmentVariables[$name] = [string]$Environment[$name] }
    $process = [Diagnostics.Process]::Start($start)
    try {
        $out = $process.StandardOutput.ReadToEndAsync()
        $err = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try { $process.Kill() } catch { }
            [void]$process.WaitForExit(5000)
            return [pscustomobject]@{ ExitCode = -1; Output = 'timed-out'; TimedOut = $true }
        }
        [void]$process.WaitForExit()
        $text = (($out.Result, $err.Result) | Where-Object { $_ }) -join "`n"
        return [pscustomobject]@{ ExitCode = $process.ExitCode; Output = $text; TimedOut = $false }
    }
    finally { $process.Dispose() }
}

function Get-RosetunBytes([string]$Text) { , [Text.Encoding]::ASCII.GetBytes($Text) }

function Get-RosetunEndPoint([string]$Address, [int]$Port) {
    [Net.IPEndPoint]::new([Net.IPAddress]::Parse($Address), $Port)
}

function Invoke-RosetunUdp {
    # One datagram and its reply, from the guest's own address, so that the physical adapter carries it.
    param([string]$Source, [string]$Target, [int]$Port, [byte[]]$Request, [int]$Milliseconds = 5000)
    $udp = New-Object Net.Sockets.UdpClient -ArgumentList (Get-RosetunEndPoint $Source 0)
    try {
        $udp.Client.ReceiveTimeout = $Milliseconds
        $udp.Connect($Target, $Port)
        [void]$udp.Send($Request, $Request.Length)
        $from = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
        , $udp.Receive([ref]$from)
    }
    finally { $udp.Close() }
}

function New-RosetunQuery {
    # The A question of the lab's resolver, in the bytes the lab contract uses for its checks.
    param([string]$Name)
    $stream = New-Object IO.MemoryStream
    $stream.Write([byte[]](0x6a, 0x06, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0), 0, 12)
    foreach ($label in $Name.Split('.')) {
        $bytes = Get-RosetunBytes $label
        $stream.WriteByte([byte]$bytes.Length)
        $stream.Write($bytes, 0, $bytes.Length)
    }
    $stream.Write([byte[]](0, 0, 1, 0, 1), 0, 5)
    , $stream.ToArray()
}

function Send-RosetunMarker {
    # One window marker to the lab's marker service. A marker is never sent twice: the acknowledgement is read once,
    # and a missing one is recorded as it is, for the controller to call the window unverified.
    param([Parameter(Mandatory)]$Plan, [Parameter(Mandatory)][string]$Label, [Parameter(Mandatory)][string]$Word)
    $text = [string]$Plan.markers.$Label.$Word
    $row = [ordered]@{ label = $Label; word = $Word; marker = $text; ack = $null; error = $null; utc = Get-RosetunUtcNow }
    try {
        $reply = Invoke-RosetunUdp -Source $Plan.addresses.client4 -Target $Plan.addresses.target4 -Port ([int]$Plan.markers.port) -Request (Get-RosetunBytes $text)
        $row.ack = [Text.Encoding]::ASCII.GetString($reply)
    }
    catch { $row.error = ConvertTo-RosetunSafeText ($_.Exception.GetType().Name + ':' + $_.Exception.Message) 120 }
    $script:RunnerStatus.markers.Add($row)
    Save-RosetunStatus
    return ($null -ne $row.ack)
}

function Get-RosetunBootCounter {
    # The count of boots of the installation, which the controller reads with `reg.exe` too: `win-<n>`.
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'
    return 'win-' + [string][int64](Get-ItemProperty -Path $key -Name BootId).BootId
}
