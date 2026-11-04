#Requires -Version 7.0
# Drives a separate Debian test VM for the Linux L2 stand over SSH/SCP. The Windows
# module (RosetunVm.psm1) is not used: it talks PowerShell Direct to the Windows
# guest and stays untouched. Nothing here stores a password or a private key; the
# key file is only referenced by path.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ReportSchema = 1
$script:RunIdPattern = '^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$'
$script:SafeValuePattern = '^[A-Za-z0-9._:@/+=-]+$'
$script:AccountPattern = '^[a-z_][a-z0-9_-]{0,31}$'
$script:ArtifactNames = @('l2_transport_fixture', 'rosetun_helper_privileged_tests', 'rosetun_ipc_tests')
# What each stage builds, stages and judges. L3 installs the real service and
# runs only through -Run -Stage L3.
$script:StageProfiles = @{
    L2 = @{ Artifacts = $script:ArtifactNames; Scripts = @('launch.sh', 'lib.sh', 'run-l2.sh', 'start.sh'); Scenarios = 'scenarios.tsv' }
    L3 = @{ Artifacts = @('rosetun-helper-privileged', 'rosetun'); Scripts = @('launch.sh', 'lib.sh', 'run-l3.sh', 'start.sh'); Scenarios = 'scenarios-l3.tsv' }
}
# The L3 stage's requests, made from the owner's request on the host.
$script:L3Requests = @('request-kill-switch.json', 'request-lan.json', 'request-dns-lock.json')
$script:ResultNames = @('PASS', 'FAIL', 'SKIP', 'ERROR')
# The Windows test VM and its credential file are never a Linux stand.
$script:ForbiddenVmNames = @('rosetun-test')
# The host key is pinned under the stand id, never under an address: the guest's
# Default Switch address changes after a reboot or a checkpoint restore.
$script:HostKeyAliasPattern = '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
$script:SettingNames = @('VmName', 'StandId', 'SshUser', 'SshHost', 'SshPort', 'KnownHostsPath', 'IdentityFile',
    'UserA', 'UserB', 'Checkpoint', 'WslDistro')
$script:SettingDefaults = @{ Checkpoint = 'l2-clean'; WslDistro = 'Debian'; SshPort = 22 }
# The installed launcher (guest/launch.sh) and the guest scripts a stage carries.
$script:LauncherPath = '/usr/local/libexec/rosetun-l2/launch'

function Get-RosetunLinuxRoot {
    $PSScriptRoot
}

function Get-RosetunLinuxStageProfile {
    param([ValidateSet('L2', 'L3')][string]$Stage = 'L2')
    $script:StageProfiles[$Stage]
}

function New-RosetunLinuxRunId {
    $bytes = [byte[]]::new(4)
    [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $suffix = -join ($bytes | ForEach-Object { $_.ToString('x2') })
    '{0}-{1}' -f [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'), $suffix
}

function Test-RosetunLinuxRunId {
    param([string]$RunId)
    $RunId -match $script:RunIdPattern
}

function Get-RosetunLinuxFileSha256 {
    param([Parameter(Mandatory)][string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-RosetunLinuxTextSha256 {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    $hash = [Security.Cryptography.SHA256]::HashData($bytes)
    -join ($hash | ForEach-Object { $_.ToString('x2') })
}

# Runs a native program with a hard time limit. A program that outlives it is
# killed with its children and the call throws; a hang can never pass as success.
function Invoke-RosetunLinuxProcess {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [int]$TimeoutSeconds = 60,
        [int]$MaxOutputChars = 8MB,
        # Called with the elapsed time every HeartbeatSeconds while the program runs.
        [scriptblock]$Heartbeat,
        [int]$HeartbeatSeconds = 30,
        [hashtable]$Environment = @{}
    )
    $info = [Diagnostics.ProcessStartInfo]::new($FilePath)
    foreach ($argument in $ArgumentList) { $info.ArgumentList.Add($argument) }
    foreach ($key in $Environment.Keys) { $info.Environment[$key] = [string]$Environment[$key] }
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($info)
    try {
        $process.StandardInput.Close()
        $outTask = $process.StandardOutput.ReadToEndAsync()
        $errTask = $process.StandardError.ReadToEndAsync()
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $beat = $HeartbeatSeconds
        while (-not $process.WaitForExit(500)) {
            if ($clock.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
                try { $process.Kill($true) } catch { Write-Verbose "kill failed: $_" }
                throw "TIMEOUT: $([IO.Path]::GetFileName($FilePath)) did not finish within $TimeoutSeconds s"
            }
            if ($null -ne $Heartbeat -and $clock.Elapsed.TotalSeconds -ge $beat) {
                & $Heartbeat $clock.Elapsed
                $beat += $HeartbeatSeconds
            }
        }
        $process.WaitForExit()
        $text = { param($task) $value = $task.Result; if ($value.Length -gt $MaxOutputChars) { $value.Substring(0, $MaxOutputChars) } else { $value } }
        [pscustomobject]@{
            ExitCode = $process.ExitCode
            Output   = (& $text $outTask)
            Error    = (& $text $errTask)
        }
    }
    finally {
        $process.Dispose()
    }
}

function Find-RosetunLinuxTool {
    param([Parameter(Mandatory)][string]$Name)
    # The Windows OpenSSH client first: Git's MSYS ssh reads Windows paths differently.
    $system = Join-Path $env:SystemRoot "System32\OpenSSH\$Name.exe"
    if (Test-Path -LiteralPath $system) { return $system }
    $command = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $command) { throw "$Name was not found. Install the Windows OpenSSH client." }
    $command.Source
}

# ------------------------------------------------------------------ settings

function Expand-RosetunLinuxPath {
    param([AllowEmptyString()][AllowNull()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    $expanded = [Environment]::ExpandEnvironmentVariables($Path)
    if ($expanded -eq '~' -or $expanded.StartsWith('~\') -or $expanded.StartsWith('~/')) {
        $expanded = $HOME + $expanded.Substring(1)
    }
    $expanded
}

# Reads stand.local.psd1. Only known keys are accepted, so a typo fails loudly
# instead of silently falling back to a default.
function Read-RosetunLinuxStandSettings {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "The stand settings file '$Path' does not exist. Copy stand.example.psd1 next to it to stand.local.psd1 and fill it in."
    }
    try { $data = Import-PowerShellDataFile -LiteralPath $Path -ErrorAction Stop }
    catch { throw "The stand settings file '$Path' is not a valid PowerShell data file: $($_.Exception.Message)" }
    $settings = @{}
    foreach ($key in @($data.Keys)) {
        $name = @($script:SettingNames | Where-Object { $_ -eq $key })
        if ($name.Count -ne 1) { throw "Unknown setting '$key' in '$Path'. Known settings: $($script:SettingNames -join ', ')." }
        $value = $data[$key]
        if ($name[0] -eq 'SshPort') {
            if ($value -isnot [int] -or $value -lt 1 -or $value -gt 65535) { throw "Setting SshPort in '$Path' must be a number from 1 to 65535." }
        }
        elseif ($value -isnot [string]) { throw "Setting $($name[0]) in '$Path' must be a quoted string." }
        $settings[$name[0]] = $value
    }
    $settings
}

# Explicit parameters win over the file, the file wins over the defaults. An
# empty string counts as not set.
function Resolve-RosetunLinuxStandSettings {
    param([hashtable]$Settings = @{}, [hashtable]$Explicit = @{})
    $resolved = [ordered]@{}
    foreach ($name in $script:SettingNames) {
        $value = $null
        foreach ($source in @($Explicit, $Settings, $script:SettingDefaults)) {
            if ($source.ContainsKey($name) -and -not [string]::IsNullOrEmpty([string]$source[$name])) { $value = $source[$name]; break }
        }
        if ($name -in @('KnownHostsPath', 'IdentityFile')) { $value = Expand-RosetunLinuxPath $value }
        $resolved[$name] = $value
    }
    [pscustomobject]$resolved
}

function Assert-RosetunLinuxStandSettings {
    param([Parameter(Mandatory)]$Stand, [Parameter(Mandatory)][string[]]$Names, [string]$SettingsPath)
    $missing = @($Names | Where-Object { [string]::IsNullOrEmpty([string]$Stand.$_) })
    if ($missing.Count -eq 0) { return }
    $where = if ($SettingsPath) { "in '$SettingsPath'" } else { 'in tools/vm/linux/stand.local.psd1 (copy stand.example.psd1)' }
    throw "Missing stand setting(s): $($missing -join ', '). Set them $where or pass them as parameters."
}

# ------------------------------------------------------------------ guest address

# The first IPv4 address that can carry SSH from the host. IPv6 and link-local
# addresses are skipped: the Default Switch hands out IPv4 by DHCP.
function Select-RosetunLinuxGuestAddress {
    param([AllowEmptyCollection()][string[]]$Addresses = @())
    foreach ($text in $Addresses) {
        $address = $null
        if (-not [Net.IPAddress]::TryParse([string]$text, [ref]$address)) { continue }
        if ($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { continue }
        $bytes = $address.GetAddressBytes()
        if ($bytes[0] -eq 169 -and $bytes[1] -eq 254) { continue }
        if ($bytes[0] -eq 127 -or $bytes[0] -eq 0 -or $bytes[0] -ge 224) { continue }
        return $address.ToString()
    }
    $null
}

# Reads the guest address from Hyper-V (KVP, which needs hyperv-daemons in the
# guest) and waits for it after a boot or a restore.
function Resolve-RosetunLinuxGuestAddress {
    param([Parameter(Mandatory)][string]$VmName, [int]$TimeoutSeconds = 180)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $reported = @(Get-VMNetworkAdapter -VMName $VmName -ErrorAction Stop | ForEach-Object { @($_.IPAddresses) })
        $address = Select-RosetunLinuxGuestAddress -Addresses $reported
        if ($null -ne $address) { return $address }
        Start-Sleep -Seconds 3
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Hyper-V reports no IPv4 address for '$VmName' after $TimeoutSeconds s. Check that the VM runs and that hyperv-daemons is installed in the guest, or set SshHost in stand.local.psd1."
}

# Whether an IPv4 address lies inside Network/PrefixLength.
function Test-RosetunLinuxSameSubnet {
    param([Parameter(Mandatory)][string]$Address, [Parameter(Mandatory)][string]$Network, [ValidateRange(0, 32)][int]$PrefixLength)
    $a = $null
    $n = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$a) -or -not [Net.IPAddress]::TryParse($Network, [ref]$n)) { return $false }
    if ($a.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $n.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { return $false }
    $toNumber = { param($ip) $b = $ip.GetAddressBytes(); ([uint32]$b[0] -shl 24) -bor ([uint32]$b[1] -shl 16) -bor ([uint32]$b[2] -shl 8) -bor [uint32]$b[3] }
    $all = [uint64][uint32]::MaxValue
    $mask = [uint32](($all -shl (32 - $PrefixLength)) -band $all)
    ((& $toNumber $a) -band $mask) -eq ((& $toNumber $n) -band $mask)
}

# The host's IPv4 subnets on the Default Switch, as 'address/prefix' objects.
# The switch gets a new subnet at every Windows boot.
function Get-RosetunLinuxHostSwitchSubnets {
    param([string]$InterfaceAlias = 'vEthernet (Default Switch)')
    @(Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            ForEach-Object { [pscustomobject]@{ Address = [string]$_.IPAddress; PrefixLength = [int]$_.PrefixLength } })
}

# Turns one failed ssh attempt into words. ssh at LogLevel=ERROR can exit 255
# with nothing on stderr, and an empty "last answer" says nothing.
function ConvertTo-RosetunLinuxSshAnswer {
    param([int]$ExitCode, [AllowEmptyString()][AllowNull()][string]$ErrorText, [string]$HostName, [int]$Port = 22)
    $text = "$ErrorText".Trim()
    $where = "${HostName}:$Port"
    if ($text -match '^TIMEOUT:') { return "no answer: ssh to $where did not finish in time (connection timeout, nothing answered)" }
    if ($text -match 'timed out') { return "connection timeout: nothing answered at $where ($text)" }
    if ($text -match 'Connection refused') { return "connection refused at ${where}: the address answers but sshd does not listen there ($text)" }
    if ($text -match 'No route to host|Network is unreachable|Host is unreachable') { return "no route to $where from this host ($text)" }
    if ($text -match 'Permission denied') { return "the key was refused at ${where}: wrong IdentityFile or authorized_keys in the guest ($text)" }
    if ($text -match 'Connection (reset|closed)') { return "the connection to $where was closed before login ($text)" }
    if ($text) { return $text }
    "ssh exited with code $ExitCode and printed nothing (no answer from $where; a connection timeout looks like this)"
}

# The message when the guest never answered over SSH: what address was tried,
# where it came from and whether the host can reach that subnet at all.
function Format-RosetunLinuxSshSilence {
    param(
        [int]$TimeoutSeconds,
        [AllowEmptyString()][AllowNull()][string]$Address,
        [ValidateSet('Hyper-V', 'SshHost')][string]$AddressSource = 'Hyper-V',
        [AllowEmptyCollection()][object[]]$HostSubnets = @(),
        [AllowEmptyString()][AllowNull()][string]$LastAnswer
    )
    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add("The guest did not answer over SSH within $TimeoutSeconds s.")
    if ($Address) {
        $from = if ($AddressSource -eq 'SshHost') { 'SshHost in the stand settings' } else { 'Hyper-V (KVP)' }
        $lines.Add("  Guest address: $Address, from $from.")
    }
    else {
        $lines.Add('  Guest address: none; Hyper-V reported no IPv4 address.')
    }
    $subnets = @($HostSubnets | Where-Object { $null -ne $_ })
    if ($subnets.Count -eq 0) {
        $lines.Add("  Host side: 'vEthernet (Default Switch)' has no IPv4 address on this host.")
    }
    else {
        $lines.Add("  Host side: 'vEthernet (Default Switch)' is $(@($subnets | ForEach-Object { "$($_.Address)/$($_.PrefixLength)" }) -join ', ').")
        if ($Address) {
            $inside = @($subnets | Where-Object { Test-RosetunLinuxSameSubnet -Address $Address -Network $_.Address -PrefixLength $_.PrefixLength }).Count -gt 0
            if ($inside) { $lines.Add('  Same subnet: yes. The host can reach the address; look at the guest (console, sshd, firewall).') }
            else { $lines.Add('  Same subnet: no. The guest keeps an address from an older Default Switch subnet; boot it fresh (see the stand guide: the clean checkpoint is made from a powered-off VM).') }
        }
    }
    if ($AddressSource -eq 'SshHost') {
        $lines.Add('  SshHost is set: it overrides the address from Hyper-V and goes stale when the Default Switch changes its subnet after a host reboot. Empty it unless KVP does not work.')
    }
    $answer = if ([string]::IsNullOrWhiteSpace($LastAnswer)) { 'no attempt finished' } else { $LastAnswer.Trim() }
    $lines.Add("  Last answer: $answer")
    $lines -join [Environment]::NewLine
}

# ------------------------------------------------------------------ SSH

function New-RosetunLinuxTarget {
    param(
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][string]$User,
        [Parameter(Mandatory)][string]$KnownHostsPath,
        [Parameter(Mandatory)][string]$IdentityFile,
        [Parameter(Mandatory)][string]$HostKeyAlias,
        [ValidateRange(1, 65535)][int]$Port = 22,
        # Only -InitKnownHosts builds a target before the pinned file exists.
        [switch]$AllowMissingKnownHosts
    )
    if ($HostName -notmatch '^[A-Za-z0-9._:-]+$') { throw "Unsafe SSH host name '$HostName'." }
    if ($User -notmatch $script:AccountPattern) { throw "Unsafe SSH user name '$User'." }
    if ($HostKeyAlias -notmatch $script:HostKeyAliasPattern) { throw "Unsafe stand id '$HostKeyAlias' for a host key alias." }
    if ($KnownHostsPath -match '\.pending$') { throw "'$KnownHostsPath' holds a host key that was never confirmed. Run -InitKnownHosts again." }
    if (-not (Test-Path -LiteralPath $IdentityFile -PathType Leaf)) {
        throw "The SSH identity file '$IdentityFile' does not exist."
    }
    if (-not $AllowMissingKnownHosts) {
        if (-not (Test-Path -LiteralPath $KnownHostsPath -PathType Leaf)) {
            throw "The known_hosts file '$KnownHostsPath' does not exist. Create it with -InitKnownHosts and compare the fingerprint on the VM console."
        }
        if ((Get-Item -LiteralPath $KnownHostsPath).Length -eq 0) {
            throw "The known_hosts file '$KnownHostsPath' is empty. Create it with -InitKnownHosts."
        }
    }
    [pscustomobject]@{
        HostName       = $HostName
        User           = $User
        Port           = $Port
        HostKeyAlias   = $HostKeyAlias
        KnownHostsPath = [IO.Path]::GetFullPath($KnownHostsPath)
        IdentityFile   = (Resolve-Path -LiteralPath $IdentityFile).ProviderPath
    }
}

# Common ssh/scp options. Host keys are verified strictly against the pinned file,
# under the stand id as alias. The only other mode writes a first key into a
# pending file that -InitKnownHosts shows to the owner; it never feeds a run.
function Get-RosetunLinuxSshOptions {
    param([Parameter(Mandatory)]$Target, [string]$AcceptNewKeyInto)
    $known = if ($AcceptNewKeyInto) { $AcceptNewKeyInto } else { $Target.KnownHostsPath }
    $known = $known.Replace('\', '/')
    $identity = $Target.IdentityFile.Replace('\', '/')
    $checking = if ($AcceptNewKeyInto) { @('-o', 'StrictHostKeyChecking=accept-new', '-o', 'HashKnownHosts=no') }
    else { @('-o', 'StrictHostKeyChecking=yes') }
    @('-o', 'BatchMode=yes') + $checking + @(
        '-o', "HostKeyAlias=$($Target.HostKeyAlias)",
        '-o', 'HostKeyAlgorithms=ssh-ed25519',
        '-o', 'CheckHostIP=no',
        '-o', 'UpdateHostKeys=no',
        '-o', "UserKnownHostsFile=$known",
        '-o', "GlobalKnownHostsFile=$known",
        '-o', 'PasswordAuthentication=no',
        '-o', 'KbdInteractiveAuthentication=no',
        '-o', 'PreferredAuthentications=publickey',
        '-o', 'IdentitiesOnly=yes',
        '-o', "IdentityFile=$identity",
        '-o', 'ForwardAgent=no',
        '-o', 'ClearAllForwardings=yes',
        '-o', 'ControlMaster=no',
        '-o', 'ConnectTimeout=15',
        '-o', 'ServerAliveInterval=5',
        '-o', 'ServerAliveCountMax=3',
        '-o', 'LogLevel=ERROR'
    )
}

function Test-RosetunLinuxHostKeyPinned {
    param([Parameter(Mandatory)][string]$KnownHostsPath, [Parameter(Mandatory)][string]$HostKeyAlias)
    if (-not (Test-Path -LiteralPath $KnownHostsPath -PathType Leaf) -or (Get-Item -LiteralPath $KnownHostsPath).Length -eq 0) {
        throw "No pinned host key: '$KnownHostsPath' is missing or empty. Create it with -InitKnownHosts and compare the fingerprint on the VM console."
    }
    $keygen = Find-RosetunLinuxTool 'ssh-keygen'
    $result = Invoke-RosetunLinuxProcess -FilePath $keygen -ArgumentList @('-F', $HostKeyAlias, '-f', $KnownHostsPath) -TimeoutSeconds 15
    if ($result.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($result.Output)) {
        throw "No host key for '$HostKeyAlias' in '$KnownHostsPath'. A file made before keys were pinned by stand id holds an address instead: delete it and run -InitKnownHosts."
    }
}

# ------------------------------------------------------------------ first host key

function Assert-RosetunLinuxKnownHostsInitAllowed {
    param([Parameter(Mandatory)][string]$KnownHostsPath)
    if (Test-Path -LiteralPath $KnownHostsPath -PathType Container) { throw "'$KnownHostsPath' is a directory." }
    if ((Test-Path -LiteralPath $KnownHostsPath -PathType Leaf) -and (Get-Item -LiteralPath $KnownHostsPath).Length -gt 0) {
        throw "'$KnownHostsPath' already holds a host key; -InitKnownHosts never replaces one. If the guest's key really changed, delete the file yourself and run it again."
    }
}

# The pending file must hold exactly one ed25519 key, under the stand id.
function Test-RosetunLinuxPendingHostKey {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$HostKeyAlias)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    $lines = @(Get-Content -LiteralPath $Path | Where-Object { $_.Trim() -ne '' -and -not $_.TrimStart().StartsWith('#') })
    if ($lines.Count -ne 1) { return $false }
    $fields = @($lines[0].Trim() -split '\s+')
    $fields.Count -ge 3 -and $fields[0] -ceq $HostKeyAlias -and $fields[1] -ceq 'ssh-ed25519' -and $fields[2] -match '^[A-Za-z0-9+/]+={0,2}$'
}

# Only the literal answer "yes" turns the pending file into the pinned one;
# anything else deletes it.
function Complete-RosetunLinuxKnownHosts {
    param(
        [Parameter(Mandatory)][string]$PendingPath,
        [Parameter(Mandatory)][string]$KnownHostsPath,
        [AllowEmptyString()][AllowNull()][string]$Answer
    )
    if ("$Answer".Trim() -ceq 'yes') {
        Assert-RosetunLinuxKnownHostsInitAllowed -KnownHostsPath $KnownHostsPath
        if (Test-Path -LiteralPath $KnownHostsPath -PathType Leaf) { Remove-Item -LiteralPath $KnownHostsPath -Force }
        Move-Item -LiteralPath $PendingPath -Destination $KnownHostsPath
        return $true
    }
    Remove-Item -LiteralPath $PendingPath -Force -ErrorAction SilentlyContinue
    $false
}

# Connects once with accept-new into a pending file, shows the fingerprint and
# keeps the key only after the owner compared it with the VM console. ssh-keyscan
# is not used: the Windows build cannot agree on a key exchange with OpenSSH 10.
function Initialize-RosetunLinuxKnownHosts {
    param(
        [Parameter(Mandatory)]$Target,
        [scriptblock]$ReadAnswer = { Read-Host 'Type yes if the two fingerprints are equal' }
    )
    Assert-RosetunLinuxKnownHostsInitAllowed -KnownHostsPath $Target.KnownHostsPath
    $directory = Split-Path -Parent $Target.KnownHostsPath
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) { $null = New-Item -ItemType Directory -Path $directory }
    $pending = "$($Target.KnownHostsPath).pending"
    Remove-Item -LiteralPath $pending -Force -ErrorAction SilentlyContinue
    try {
        $arguments = @('-T', '-p', "$($Target.Port)") + (Get-RosetunLinuxSshOptions $Target -AcceptNewKeyInto $pending) +
            @('--', "$($Target.User)@$($Target.HostName)", 'true')
        $login = Invoke-RosetunLinuxProcess -FilePath (Find-RosetunLinuxTool 'ssh') -ArgumentList $arguments -TimeoutSeconds 60
        if (-not (Test-RosetunLinuxPendingHostKey -Path $pending -HostKeyAlias $Target.HostKeyAlias)) {
            throw "Could not receive an ed25519 host key from $($Target.HostName): $($login.Error.Trim())"
        }
        $print = Invoke-RosetunLinuxProcess -FilePath (Find-RosetunLinuxTool 'ssh-keygen') -ArgumentList @('-lf', $pending) -TimeoutSeconds 15
        if ($print.ExitCode -ne 0) { throw "ssh-keygen could not read the received key: $($print.Error.Trim())" }
        Write-Host ''
        Write-Host "Host key received from $($Target.HostName), to be stored as '$($Target.HostKeyAlias)':"
        Write-Host "  $($print.Output.Trim())"
        Write-Host ''
        Write-Host 'On the VM console (the Hyper-V window, not SSH) run:'
        Write-Host '  ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub'
        Write-Host 'and compare its SHA256 value with the one above.'
        if ($login.ExitCode -ne 0) {
            Write-Warning "The key arrived but the login failed: $($login.Error.Trim()). Check authorized_keys after this step."
        }
        $answer = & $ReadAnswer
        if (-not (Complete-RosetunLinuxKnownHosts -PendingPath $pending -KnownHostsPath $Target.KnownHostsPath -Answer $answer)) {
            throw 'The fingerprint was not confirmed. Nothing was kept.'
        }
        Write-Host "Pinned the host key in '$($Target.KnownHostsPath)'."
    }
    finally {
        Remove-Item -LiteralPath $pending -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-RosetunLinuxSsh {
    param(
        [Parameter(Mandatory)]$Target,
        [Parameter(Mandatory)][string]$Command,
        [int]$TimeoutSeconds = 60
    )
    $arguments = @('-T', '-p', "$($Target.Port)") + (Get-RosetunLinuxSshOptions $Target) +
        @('--', "$($Target.User)@$($Target.HostName)", $Command)
    Invoke-RosetunLinuxProcess -FilePath (Find-RosetunLinuxTool 'ssh') -ArgumentList $arguments -TimeoutSeconds $TimeoutSeconds
}

function Copy-RosetunLinuxToGuest {
    param(
        [Parameter(Mandatory)]$Target,
        [Parameter(Mandatory)][string]$LocalDirectory,
        [Parameter(Mandatory)][string]$RemoteParent,
        [int]$TimeoutSeconds = 600
    )
    $arguments = @('-B', '-r', '-P', "$($Target.Port)") + (Get-RosetunLinuxSshOptions $Target) +
        @('--', $LocalDirectory, "$($Target.User)@$($Target.HostName):$RemoteParent/")
    $result = Invoke-RosetunLinuxProcess -FilePath (Find-RosetunLinuxTool 'scp') -ArgumentList $arguments -TimeoutSeconds $TimeoutSeconds
    if ($result.ExitCode -ne 0) { throw "scp to the guest failed (exit $($result.ExitCode)): $($result.Error.Trim())" }
}

# Reads one small text file of the guest through ssh with a size cap.
function Read-RosetunLinuxGuestFile {
    param(
        [Parameter(Mandatory)]$Target,
        [Parameter(Mandatory)][string]$Path,
        [int]$MaxBytes = 4MB,
        [int]$TimeoutSeconds = 30
    )
    if ($Path -notmatch $script:SafeValuePattern) { throw "Unsafe guest path '$Path'." }
    $result = Invoke-RosetunLinuxSsh -Target $Target -Command "head -c $MaxBytes -- $Path" -TimeoutSeconds $TimeoutSeconds
    if ($result.ExitCode -ne 0) { return $null }
    $result.Output
}

# ------------------------------------------------------------------ VM identity

function Get-RosetunLinuxVmIdentity {
    param(
        [Parameter(Mandatory)][string]$VmName,
        [Parameter(Mandatory)][guid]$VmId
    )
    if ($script:ForbiddenVmNames -contains $VmName) {
        throw "'$VmName' is the Windows test VM. The Linux stand needs its own VM."
    }
    $vm = @(Get-VM -Name $VmName -ErrorAction Stop)
    if ($vm.Count -ne 1) { throw "Expected exactly one VM named '$VmName', found $($vm.Count)." }
    if ($vm[0].VMId -ne $VmId) {
        throw "VM '$VmName' has id $($vm[0].VMId), not the expected $VmId. Wrong machine; nothing was done."
    }
    $setting = @(Get-CimInstance -Namespace 'root/virtualization/v2' -ClassName Msvm_VirtualSystemSettingData `
            -Filter "VirtualSystemIdentifier='$($VmId.ToString().ToUpperInvariant())' AND VirtualSystemType='Microsoft:Hyper-V:System:Realized'")
    if ($setting.Count -ne 1 -or [string]::IsNullOrWhiteSpace($setting[0].BIOSGUID)) {
        throw "Could not read the BIOS GUID of VM '$VmName' from Hyper-V."
    }
    [pscustomobject]@{
        Name     = $vm[0].Name
        VmId     = $vm[0].VMId.ToString()
        BiosGuid = $setting[0].BIOSGUID.Trim('{', '}').ToLowerInvariant()
        State    = [string]$vm[0].State
    }
}

# The exact commands that make the clean checkpoint again from a powered-off VM.
function Get-RosetunLinuxCheckpointRemake {
    param([Parameter(Mandatory)][string]$VmName, [Parameter(Mandatory)][string]$CheckpointName)
    @(
        "Restore-VMCheckpoint -VMName $VmName -Name $CheckpointName -Confirm:`$false; Start-VM -Name $VmName",
        "Stop-VM -Name $VmName",
        "Remove-VMCheckpoint -VMName $VmName -Name $CheckpointName",
        "Checkpoint-VM -Name $VmName -SnapshotName $CheckpointName"
    )
}

# The state a restore leaves tells what the checkpoint holds: 'Off' for a
# checkpoint of a powered-off VM, 'Saved' for one with the memory of a running
# guest. Only 'Off' is accepted: a guest resumed from memory keeps its old
# Default Switch address, and the switch gets a new subnet at every host boot.
# Returns $null when the state is fine, else the error text.
function Get-RosetunLinuxRestoredStateProblem {
    param(
        [Parameter(Mandatory)][string]$VmName,
        [Parameter(Mandatory)][string]$CheckpointName,
        [Parameter(Mandatory)][string]$State
    )
    if ($State -eq 'Off') { return $null }
    $what = if ($State -eq 'Saved') {
        "Checkpoint '$CheckpointName' holds the memory of a running guest (the VM is 'Saved' after the restore)."
    }
    else {
        "After restoring checkpoint '$CheckpointName' the VM is '$State', not 'Off'."
    }
    $steps = @(Get-RosetunLinuxCheckpointRemake -VmName $VmName -CheckpointName $CheckpointName)
    @(
        $what,
        'The stand needs a checkpoint of a powered-off VM: a resumed guest keeps its old address, which the host cannot reach once the Default Switch has a new subnet after a host reboot. Nothing was started.',
        'Make the checkpoint again, on the host as administrator:',
        "  1. $($steps[0])",
        '     Check in the guest that it is still clean (see the stand guide, "The clean checkpoint").',
        "  2. $($steps[1])",
        "  3. $($steps[2])",
        "  4. $($steps[3])"
    ) -join [Environment]::NewLine
}

function Restore-RosetunLinuxCheckpoint {
    param(
        [Parameter(Mandatory)][string]$VmName,
        [Parameter(Mandatory)][string]$CheckpointName,
        # After an L3 run: back to the clean state, left powered off.
        [switch]$NoStart
    )
    $found = @(Get-VMCheckpoint -VMName $VmName -Name $CheckpointName -ErrorAction Stop)
    if ($found.Count -ne 1) {
        throw "Expected exactly one checkpoint named '$CheckpointName' on '$VmName', found $($found.Count). Nothing was restored."
    }
    $found[0] | Restore-VMCheckpoint -Confirm:$false
    $problem = Get-RosetunLinuxRestoredStateProblem -VmName $VmName -CheckpointName $CheckpointName -State ([string](Get-VM -Name $VmName).State)
    if ($null -ne $problem) { throw $problem }
    if (-not $NoStart) { Start-VM -Name $VmName }
}

function Wait-RosetunLinuxSsh {
    param([Parameter(Mandatory)]$Target, [int]$TimeoutSeconds = 300)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $last = ''
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $probe = Invoke-RosetunLinuxSsh -Target $Target -Command 'true' -TimeoutSeconds 25
            if ($probe.ExitCode -eq 0) { return }
            # A refused host key is a security answer, not a boot delay.
            if ($probe.Error -match 'REMOTE HOST IDENTIFICATION HAS CHANGED|Host key verification failed') {
                throw "SSH host key verification failed: $($probe.Error.Trim())"
            }
            $last = ConvertTo-RosetunLinuxSshAnswer -ExitCode $probe.ExitCode -ErrorText $probe.Error -HostName $Target.HostName -Port $Target.Port
        }
        catch {
            if ("$_" -match 'host key') { throw }
            $last = ConvertTo-RosetunLinuxSshAnswer -ExitCode -1 -ErrorText "$_" -HostName $Target.HostName -Port $Target.Port
        }
        Start-Sleep -Seconds 3
    }
    if (-not $last) { $last = 'no attempt finished' }
    throw "The guest did not accept SSH within $TimeoutSeconds s. Last answer: $last"
}

# ------------------------------------------------------------------ source and artifacts

function Get-RosetunLinuxSource {
    param([Parameter(Mandatory)][string]$RepoRoot)
    $git = Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1
    $run = { param($arguments) Invoke-RosetunLinuxProcess -FilePath $git.Source -ArgumentList (@('-C', $RepoRoot) + $arguments) -TimeoutSeconds 60 }
    $head = & $run @('rev-parse', 'HEAD')
    if ($head.ExitCode -ne 0 -or $head.Output.Trim() -notmatch '^[0-9a-f]{40}$') { throw "git rev-parse HEAD failed in '$RepoRoot'." }
    $status = & $run @('status', '--porcelain=v1', '-uall', '--no-renames')
    $diff = & $run @('diff', 'HEAD', '--binary', '--no-ext-diff')
    # The digest needs every untracked file; the listing for people folds an
    # untracked folder into one line.
    $listing = & $run @('status', '--porcelain=v1', '-unormal', '--no-renames')
    if ($status.ExitCode -ne 0 -or $diff.ExitCode -ne 0 -or $listing.ExitCode -ne 0) { throw "git status failed in '$RepoRoot'." }
    $entries = @($status.Output -split "`n" | Where-Object { $_.Trim() -ne '' })
    [pscustomobject]@{
        Sha           = $head.Output.Trim()
        Dirty         = ($entries.Count -gt 0)
        DirtyEntries  = $entries.Count
        DirtyPaths    = @(ConvertFrom-RosetunLinuxGitStatus $listing.Output)
        DirtyDigest   = Get-RosetunLinuxTextSha256 ($status.Output.Replace("`r`n", "`n") + "`n--`n" + $diff.Output.Replace("`r`n", "`n"))
    }
}

# Path names from `git status --porcelain=v1`, without the two status letters.
function ConvertFrom-RosetunLinuxGitStatus {
    param([AllowEmptyString()][string]$Text)
    @($Text -split "`n" | ForEach-Object { $_.TrimEnd("`r") } | Where-Object { $_.Length -gt 3 } | ForEach-Object { $_.Substring(3) })
}

function Format-RosetunLinuxPathList {
    param([AllowEmptyCollection()][string[]]$Paths = @(), [int]$Limit = 30)
    $shown = @($Paths | Select-Object -First $Limit | ForEach-Object { "  - $_" })
    if ($Paths.Count -gt $Limit) { $shown += "  ... and $($Paths.Count - $Limit) more" }
    $shown -join "`n"
}

# A host build is a build of HEAD only, so any change outside .gitignore stops it.
function Assert-RosetunLinuxCleanSource {
    param([Parameter(Mandatory)]$Source)
    if (-not $Source.Dirty) { return }
    throw ("The working tree differs from HEAD $($Source.Sha.Substring(0, 12)), so the build would not be that commit. " +
        "Commit, stash or remove these paths (git-ignored paths do not count):`n" + (Format-RosetunLinuxPathList $Source.DirtyPaths))
}

function Find-RosetunLinuxWsl {
    $system = Join-Path $env:SystemRoot 'System32\wsl.exe'
    if (Test-Path -LiteralPath $system) { return $system }
    $command = Get-Command 'wsl.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $command) { throw 'wsl.exe was not found. Install WSL with a Debian distribution (see the stand guide).' }
    $command.Source
}

# wsl.exe writes its own messages in UTF-16 unless WSL_UTF8 is set.
$script:WslEnvironment = @{ WSL_UTF8 = '1' }

function Get-RosetunLinuxWslText {
    param([AllowEmptyString()][AllowNull()][string]$Text)
    "$Text".Replace("`0", '').Trim()
}

function ConvertTo-RosetunLinuxWslPath {
    param([Parameter(Mandatory)][string]$WslDistro, [Parameter(Mandatory)][string]$Path)
    $result = Invoke-RosetunLinuxProcess -FilePath (Find-RosetunLinuxWsl) -ArgumentList @('-d', $WslDistro, '--exec', 'wslpath', '-a', '-u', $Path) -TimeoutSeconds 120 -Environment $script:WslEnvironment
    $text = Get-RosetunLinuxWslText $result.Output
    if ($result.ExitCode -ne 0 -or $text -notmatch '^/[^\s]*$') {
        $why = (Get-RosetunLinuxWslText $result.Error) + ' ' + $text
        throw "WSL distribution '$WslDistro' could not translate '$Path' (exit $($result.ExitCode)): $($why.Trim()). Check 'wsl -l -v' and the WslDistro setting."
    }
    $text
}

# Builds HEAD in WSL into a new folder target/l2-artifacts/<short sha>-<run id> and
# returns its path. Older folders are kept.
function Invoke-RosetunLinuxBuild {
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)]$Source,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$WslDistro,
        [scriptblock]$Heartbeat,
        [int]$HeartbeatSeconds = 30,
        [int]$TimeoutSeconds = 3600,
        [ValidateSet('L2', 'L3')][string]$Stage = 'L2'
    )
    Assert-RosetunLinuxCleanSource -Source $Source
    if ($WslDistro -notmatch '^[A-Za-z0-9._-]+$') { throw "Unsafe WSL distribution name '$WslDistro'." }
    if (-not (Test-RosetunLinuxRunId $RunId)) { throw "Invalid run id '$RunId'." }
    $outRoot = Join-Path $RepoRoot 'target\l2-artifacts'
    $name = '{0}-{1}' -f $Source.Sha.Substring(0, 12), $RunId
    $out = Join-Path $outRoot $name
    if (Test-Path -LiteralPath $out) { throw "Artifact folder '$out' already exists." }
    $null = New-Item -ItemType Directory -Path $outRoot -Force
    $repoWsl = ConvertTo-RosetunLinuxWslPath -WslDistro $WslDistro -Path $RepoRoot
    $outWsl = ConvertTo-RosetunLinuxWslPath -WslDistro $WslDistro -Path $outRoot
    $arguments = @('-d', $WslDistro, '--cd', '~', '--exec', 'bash', "$repoWsl/tools/vm/linux/build-in-wsl.sh", $repoWsl, $Source.Sha, "$outWsl/$name")
    if ($Stage -eq 'L3') { $arguments += '--l3' }
    $result = Invoke-RosetunLinuxProcess -FilePath (Find-RosetunLinuxWsl) -ArgumentList $arguments -TimeoutSeconds $TimeoutSeconds `
        -Heartbeat $Heartbeat -HeartbeatSeconds $HeartbeatSeconds -Environment $script:WslEnvironment
    if ($result.ExitCode -ne 0) {
        $tail = @((Get-RosetunLinuxWslText $result.Error) -split "`n" | Select-Object -Last 25) -join "`n"
        throw "The build in WSL failed (exit $($result.ExitCode)):`n$tail"
    }
    if (-not (Test-Path -LiteralPath (Join-Path $out 'provenance.json') -PathType Leaf)) {
        throw "The build in WSL reported success but '$out' has no provenance.json."
    }
    $out
}

# True only for a 64-bit little-endian x86-64 ELF executable or PIE: not a PE file,
# not a script, not another architecture.
function Test-RosetunLinuxElf {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject]@{ Ok = $false; Reason = 'the file does not exist' }
    }
    $header = [byte[]]::new(20)
    $stream = [IO.File]::OpenRead($Path)
    try { $read = $stream.Read($header, 0, 20) } finally { $stream.Dispose() }
    $reason = if ($read -lt 20) { 'the file is too short to be an executable' }
    elseif ($header[0] -eq 0x4D -and $header[1] -eq 0x5A) { 'this is a Windows PE file, not a Linux build' }
    elseif ($header[0] -ne 0x7F -or $header[1] -ne 0x45 -or $header[2] -ne 0x4C -or $header[3] -ne 0x46) { 'this is not an ELF file' }
    elseif ($header[4] -ne 2) { 'this is not a 64-bit ELF file' }
    elseif ($header[5] -ne 1) { 'this is not a little-endian ELF file' }
    elseif (($header[16] -ne 2 -and $header[16] -ne 3) -or $header[17] -ne 0) { 'this ELF file is not an executable' }
    elseif ($header[18] -ne 0x3E -or $header[19] -ne 0) { 'this ELF file is not built for x86-64' }
    else { $null }
    [pscustomobject]@{ Ok = ($null -eq $reason); Reason = $reason }
}

# Validates the artifact directory made by build-artifacts.sh and returns the
# provenance the report will carry. Origin counts as confirmed only when the
# build recorded the same checkout state the host sees now.
function Get-RosetunLinuxArtifacts {
    param(
        [Parameter(Mandatory)][string]$ArtifactDir,
        [Parameter(Mandatory)]$Source,
        [ValidateSet('L2', 'L3')][string]$Stage = 'L2'
    )
    if (-not (Test-Path -LiteralPath $ArtifactDir -PathType Container)) { throw "Artifact directory '$ArtifactDir' does not exist." }
    $provenancePath = Join-Path $ArtifactDir 'provenance.json'
    if (-not (Test-Path -LiteralPath $provenancePath -PathType Leaf)) {
        throw "provenance.json is missing in '$ArtifactDir'. Build the artifacts with tools/vm/linux/build-artifacts.sh inside Debian."
    }
    $provenance = Get-Content -LiteralPath $provenancePath -Raw | ConvertFrom-Json
    if ($provenance.schema -ne 1 -or $provenance.target -ne 'x86_64-unknown-linux-gnu') {
        throw 'provenance.json has an unexpected schema or target.'
    }
    $entries = [ordered]@{}
    foreach ($name in (Get-RosetunLinuxStageProfile $Stage).Artifacts) {
        $path = Join-Path $ArtifactDir $name
        $elf = Test-RosetunLinuxElf $path
        if (-not $elf.Ok) { throw "Artifact '$name': $($elf.Reason)." }
        $hash = Get-RosetunLinuxFileSha256 $path
        $recorded = $provenance.artifacts.PSObject.Properties[$name]
        if ($null -eq $recorded -or $recorded.Value.sha256 -ne $hash) {
            throw "Artifact '$name' does not match the hash its build recorded; it was replaced after the build."
        }
        $entries[$name] = $hash
    }
    $buildSha = [string]$provenance.source_sha
    $buildDirty = $provenance.source_dirty
    $confirmed = ($buildSha -match '^[0-9a-f]{40}$') -and ($buildSha -eq $Source.Sha) -and
        ($buildDirty -is [bool]) -and ($buildDirty -eq $Source.Dirty) -and
        ([string]$provenance.source_dirty_digest -eq $Source.DirtyDigest)
    $note = if ($confirmed) { 'the build recorded the same commit and working tree state as the host checkout' }
    elseif ($buildSha -notmatch '^[0-9a-f]{40}$') { 'the build did not record a commit (git was missing in the build environment)' }
    elseif ($buildSha -ne $Source.Sha) { 'the build recorded a different commit than the host checkout' }
    else { 'the working tree differs from the one the build recorded' }
    [pscustomobject]@{
        Hashes          = $entries
        BuildSourceSha  = $buildSha
        BuildDirty      = $buildDirty
        Confirmed       = $confirmed
        Note            = $note
        Toolchain       = $provenance.toolchain
        BuiltOn         = $provenance.built_on
    }
}

# ------------------------------------------------------------------ scenarios and staging

function Get-RosetunLinuxScenarios {
    param([ValidateSet('L2', 'L3')][string]$Stage = 'L2', [string]$Path)
    if (-not $Path) { $Path = Join-Path (Get-RosetunLinuxRoot) (Get-RosetunLinuxStageProfile $Stage).Scenarios }
    $lines = @(Get-Content -LiteralPath $Path | Where-Object { $_.Trim() -ne '' })
    if ($lines.Count -lt 2 -or $lines[0] -ne "id`trequired`tevidence`tgroup`tdetail`ttitle") {
        throw "scenarios.tsv has an unexpected header."
    }
    $seen = @{}
    foreach ($line in $lines | Select-Object -Skip 1) {
        $parts = $line -split "`t"
        if ($parts.Count -ne 6) { throw "Malformed scenario line: $line" }
        if ($seen.ContainsKey($parts[0])) { throw "Duplicate scenario id $($parts[0])." }
        $seen[$parts[0]] = $true
        [pscustomobject]@{
            Id = $parts[0]; Required = ($parts[1] -eq 'yes'); Evidence = $parts[2]
            Group = $parts[3]; Detail = $parts[4]; Title = $parts[5]
        }
    }
}

function New-RosetunLinuxJobEnv {
    param(
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$StandId,
        [Parameter(Mandatory)][string]$BootId,
        [Parameter(Mandatory)][string]$UserA,
        [Parameter(Mandatory)][string]$UserB,
        [Parameter(Mandatory)][string]$BiosGuid,
        [int]$ScenarioTimeoutSeconds = 30,
        [int]$UnitTimeoutSeconds = 180,
        [int]$JobTimeoutSeconds = 900,
        # More KEY=value lines for a stage that needs them (L3: the host node).
        [Collections.IDictionary]$Extra = [ordered]@{}
    )
    if (-not (Test-RosetunLinuxRunId $RunId)) { throw "Invalid run id '$RunId'." }
    foreach ($key in @($Extra.Keys)) {
        if ($key -cnotmatch '^[A-Z][A-Z_]{0,31}$' -or [string]$Extra[$key] -notmatch $script:SafeValuePattern) {
            throw "Unsafe job value '$key'."
        }
    }
    foreach ($pair in @(@('stand id', $StandId), @('boot id', $BootId), @('BIOS GUID', $BiosGuid))) {
        if ($pair[1] -notmatch $script:SafeValuePattern) { throw "Unsafe $($pair[0]) '$($pair[1])'." }
    }
    foreach ($account in @($UserA, $UserB)) {
        if ($account -notmatch $script:AccountPattern) { throw "Unsafe account name '$account'." }
    }
    if ($UserA -eq $UserB) { throw 'The two test accounts must be different.' }
    foreach ($seconds in @($ScenarioTimeoutSeconds, $UnitTimeoutSeconds, $JobTimeoutSeconds)) {
        if ($seconds -lt 10 -or $seconds -gt 86400) { throw 'A time limit is outside 10..86400 seconds.' }
    }
    @(
        "RUN_ID=$RunId", "STAND_ID=$StandId", "EXPECTED_BOOT_ID=$BootId",
        "USER_A=$UserA", "USER_B=$UserB", "BIOS_GUID=$BiosGuid",
        "SCENARIO_TIMEOUT_SECONDS=$ScenarioTimeoutSeconds", "UNIT_TIMEOUT_SECONDS=$UnitTimeoutSeconds",
        "JOB_TIMEOUT_SECONDS=$JobTimeoutSeconds"
    ) + @($Extra.Keys | ForEach-Object { "$_=$($Extra[$_])" }) -join "`n"
}

function Write-RosetunLinuxLfFile {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Text)
    [IO.File]::WriteAllText($Path, ($Text.Replace("`r`n", "`n").TrimEnd("`n") + "`n"), [Text.UTF8Encoding]::new($false))
}

# Builds the staging tree of one run on the host: guest scripts, the scenario list,
# the job description, the artifacts and a manifest of SHA-256 sums. The manifest
# hash printed to the owner is the trust anchor typed into the guest.
function New-RosetunLinuxStage {
    param(
        [Parameter(Mandatory)][string]$StageRoot,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$ArtifactDir,
        [Parameter(Mandatory)][string]$JobEnv,
        [ValidateSet('L2', 'L3')][string]$Stage = 'L2',
        # Files staged under artifacts/ besides the build, by published name.
        [Collections.IDictionary]$Extra = [ordered]@{}
    )
    if (-not (Test-RosetunLinuxRunId $RunId)) { throw "Invalid run id '$RunId'." }
    $stageProfile = Get-RosetunLinuxStageProfile $Stage
    $root = Join-Path $StageRoot $RunId
    if (Test-Path -LiteralPath $root) { throw "Stage directory '$root' already exists; a run id is used once." }
    $null = New-Item -ItemType Directory -Path (Join-Path $root 'guest'), (Join-Path $root 'artifacts')
    $linux = Get-RosetunLinuxRoot
    foreach ($script in $stageProfile.Scripts) {
        Write-RosetunLinuxLfFile -Path (Join-Path $root "guest/$script") -Text (Get-Content -LiteralPath (Join-Path $linux "guest/$script") -Raw)
    }
    Write-RosetunLinuxLfFile -Path (Join-Path $root $stageProfile.Scenarios) -Text (Get-Content -LiteralPath (Join-Path $linux $stageProfile.Scenarios) -Raw)
    Write-RosetunLinuxLfFile -Path (Join-Path $root 'job.env') -Text $JobEnv
    foreach ($name in @($stageProfile.Artifacts) + @('provenance.json')) {
        Copy-Item -LiteralPath (Join-Path $ArtifactDir $name) -Destination (Join-Path $root "artifacts/$name")
    }
    foreach ($name in @($Extra.Keys)) {
        if ($name -notmatch '^[A-Za-z0-9_][A-Za-z0-9_.-]*$') { throw "Unsafe staged file name '$name'." }
        Copy-Item -LiteralPath $Extra[$name] -Destination (Join-Path $root "artifacts/$name")
    }
    $files = @(Get-ChildItem -LiteralPath $root -Recurse -File | ForEach-Object {
            $_.FullName.Substring($root.Length + 1).Replace('\', '/')
        } | Sort-Object -Culture ([Globalization.CultureInfo]::InvariantCulture) -CaseSensitive)
    $lines = foreach ($relative in $files) {
        '{0}  {1}' -f (Get-RosetunLinuxFileSha256 (Join-Path $root $relative)), $relative
    }
    Write-RosetunLinuxLfFile -Path (Join-Path $root 'manifest.sha256') -Text ($lines -join "`n")
    [pscustomobject]@{
        Directory    = $root
        ManifestHash = Get-RosetunLinuxFileSha256 (Join-Path $root 'manifest.sha256')
        Files        = $files
    }
}

# The three requests of the L3 matrix from the owner's request: its node
# pointed at the host node, with the kill switch and "Local network" off
# (auto_reconnect on, so a killed engine comes back), with "Local network" on,
# and without the kill switch (the DNS lock). Returns name -> path.
function New-RosetunLinuxL3Requests {
    param(
        [Parameter(Mandatory)][string]$RequestPath,
        [Parameter(Mandatory)][string]$HostAddress,
        [Parameter(Mandatory)][ValidateRange(1, 65535)][int]$NodePort,
        [Parameter(Mandatory)][string]$OutDir
    )
    $address = $null
    if (-not [Net.IPAddress]::TryParse($HostAddress, [ref]$address) -or $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw "The host address '$HostAddress' is not an IPv4 address."
    }
    $template = Get-Content -LiteralPath $RequestPath -Raw | ConvertFrom-Json
    if ($null -eq (Get-RosetunLinuxMember -Object $template -Name 'node') -or $null -eq (Get-RosetunLinuxMember -Object $template -Name 'settings')) {
        throw "'$RequestPath' is not a connect request (no node or settings)."
    }
    $variants = [ordered]@{
        'request-kill-switch.json' = @{ kill_switch = $true; allow_lan = $false }
        'request-lan.json'         = @{ kill_switch = $true; allow_lan = $true }
        'request-dns-lock.json'    = @{ kill_switch = $false; allow_lan = $false }
    }
    $paths = [ordered]@{}
    foreach ($name in $variants.Keys) {
        $request = $template | ConvertTo-Json -Depth 32 | ConvertFrom-Json
        $request.node.server = $address.ToString()
        $request.node.port = $NodePort
        foreach ($setting in @('kill_switch', 'allow_lan')) {
            $request.settings | Add-Member -NotePropertyName $setting -NotePropertyValue $variants[$name][$setting] -Force
        }
        $request.settings | Add-Member -NotePropertyName auto_reconnect -NotePropertyValue $true -Force
        $path = Join-Path $OutDir $name
        [IO.File]::WriteAllText($path, ($request | ConvertTo-Json -Depth 32), [Text.UTF8Encoding]::new($false))
        $paths[$name] = $path
    }
    $paths
}

# The resolver the L3 DNS checks use: the one given, else the request's DNS
# server when it is an IPv4 address (that one is known to work where the
# request is used), else the HTTPS probe address.
function Select-RosetunLinuxDnsProbe {
    param([string]$Explicit, [Parameter(Mandatory)][string]$RequestPath, [Parameter(Mandatory)][string]$ProbeAddress)
    $isIpv4 = {
        param($text)
        $address = $null
        [Net.IPAddress]::TryParse([string]$text, [ref]$address) -and $address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork
    }
    if ($Explicit) {
        if (-not (& $isIpv4 $Explicit)) { throw "-DnsProbeAddress '$Explicit' is not an IPv4 address." }
        return ([Net.IPAddress]::Parse($Explicit)).ToString()
    }
    $request = Get-Content -LiteralPath $RequestPath -Raw | ConvertFrom-Json
    $settings = Get-RosetunLinuxMember -Object $request -Name 'settings'
    $dns = if ($null -ne $settings) { Get-RosetunLinuxMember -Object $settings -Name 'dns' } else { $null }
    $server = if ($null -ne $dns) { [string](Get-RosetunLinuxMember -Object $dns -Name 'server') } else { '' }
    if (& $isIpv4 $server) { return ([Net.IPAddress]::Parse($server)).ToString() }
    $ProbeAddress
}

# ------------------------------------------------------------------ starting the job

function Get-RosetunLinuxLauncherPath { $script:LauncherPath }

# The command the owner pastes into the guest when the launcher cannot start the
# job without a password. It runs the staged launcher, which proves itself
# against the manifest.
function Get-RosetunLinuxManualStartCommand {
    param([Parameter(Mandatory)][string]$StageDir, [Parameter(Mandatory)][string]$RunId, [Parameter(Mandatory)][string]$ManifestHash)
    "sudo bash $StageDir/guest/launch.sh $RunId $StageDir $ManifestHash"
}

function Get-RosetunLinuxLauncherStartCommand {
    param([Parameter(Mandatory)][string]$StageDir, [Parameter(Mandatory)][string]$RunId, [Parameter(Mandatory)][string]$ManifestHash)
    "sudo -n $($script:LauncherPath) $RunId $StageDir $ManifestHash"
}

function Get-RosetunLinuxInstallCommand {
    param([Parameter(Mandatory)][string]$Folder, [Parameter(Mandatory)][string]$UserA, [Parameter(Mandatory)][string]$UserB)
    "sudo bash $Folder/install-launcher.sh $UserA $UserB"
}

# Automatic start needs the launcher of this version and the sudoers rule; anything
# else falls back to the manual command, with the reason.
function Select-RosetunLinuxStartMode {
    param(
        [AllowEmptyString()][AllowNull()][string]$InstalledHash,
        [Parameter(Mandatory)][string]$ExpectedHash,
        [int]$SudoExitCode = 1
    )
    $mode = { param($name, $reason, $reinstall) [pscustomobject]@{ Mode = $name; Reason = $reason; Reinstall = $reinstall } }
    if ([string]::IsNullOrWhiteSpace($InstalledHash) -or $InstalledHash -eq 'missing') {
        return & $mode 'manual' "the launcher is not installed in $($script:LauncherPath)" $false
    }
    if ($InstalledHash -notmatch '^[0-9a-f]{64}$') { return & $mode 'manual' 'the installed launcher could not be read' $false }
    if ($InstalledHash -ne $ExpectedHash) {
        return & $mode 'manual' 'the installed launcher is not the guest/launch.sh of this commit' $true
    }
    if ($SudoExitCode -ne 0) {
        return & $mode 'manual' 'sudo -n refused the launcher; /etc/sudoers.d/rosetun-l2 is missing or names another account' $false
    }
    & $mode 'auto' 'the launcher of this commit may run without a password' $false
}

# Reads the installed launcher's hash and whether sudo lets this account run it
# without a password. Nothing privileged runs here.
function Get-RosetunLinuxLauncherState {
    param([Parameter(Mandatory)]$Target)
    $path = $script:LauncherPath
    $probe = Invoke-RosetunLinuxSsh -Target $Target -TimeoutSeconds 30 -Command (
        "if [ -f $path ]; then sha256sum -- $path | cut -d' ' -f1; else echo missing; fi; " +
        "if sudo -n -l $path >/dev/null 2>&1; then echo sudo=0; else echo sudo=1; fi")
    $lines = @($probe.Output -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
    $hash = if ($lines.Count -ge 1) { $lines[0] } else { '' }
    $sudo = if ($lines.Count -ge 2 -and $lines[1] -eq 'sudo=0') { 0 } else { 1 }
    [pscustomobject]@{ InstalledHash = $hash; SudoExitCode = $sudo }
}

# Starts a staged run through the installed launcher when that is possible.
# Returns Started=$false with the reason and the manual command otherwise. A
# launcher that runs and refuses is an error, never a fallback.
function Start-RosetunLinuxJob {
    param(
        [Parameter(Mandatory)]$Target,
        [Parameter(Mandatory)][string]$StageDir,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$ManifestHash,
        [Parameter(Mandatory)][string]$ExpectedLauncherHash
    )
    $state = Get-RosetunLinuxLauncherState -Target $Target
    $choice = Select-RosetunLinuxStartMode -InstalledHash $state.InstalledHash -ExpectedHash $ExpectedLauncherHash -SudoExitCode $state.SudoExitCode
    $manual = Get-RosetunLinuxManualStartCommand -StageDir $StageDir -RunId $RunId -ManifestHash $ManifestHash
    if ($choice.Mode -ne 'auto') {
        return [pscustomobject]@{ Started = $false; Mode = 'manual'; Reason = $choice.Reason; Reinstall = $choice.Reinstall; ManualCommand = $manual; Output = '' }
    }
    $start = Invoke-RosetunLinuxSsh -Target $Target -TimeoutSeconds 180 -Command (Get-RosetunLinuxLauncherStartCommand -StageDir $StageDir -RunId $RunId -ManifestHash $ManifestHash)
    if ($start.ExitCode -ne 0) {
        throw "The launcher refused run ${RunId} (exit $($start.ExitCode)): $(($start.Error + ' ' + $start.Output).Trim())"
    }
    [pscustomobject]@{ Started = $true; Mode = 'auto'; Reason = $choice.Reason; Reinstall = $false; ManualCommand = $manual; Output = $start.Output.Trim() }
}

# Copies launch.sh and install-launcher.sh into ~/rosetun-l2-launcher of the guest
# for the one-time installation. Returns that folder and the launcher's hash.
function Copy-RosetunLinuxLauncherToGuest {
    param([Parameter(Mandatory)]$Target, [Parameter(Mandatory)][string]$GuestHome)
    if ($GuestHome -notmatch '^/[A-Za-z0-9._/-]+$') { throw "Unsafe guest home '$GuestHome'." }
    $local = Join-Path ([IO.Path]::GetTempPath()) "rosetun-l2-$([guid]::NewGuid().ToString('N'))"
    $folder = Join-Path $local 'rosetun-l2-launcher'
    $null = New-Item -ItemType Directory -Path $folder
    try {
        foreach ($name in @('launch.sh', 'install-launcher.sh')) {
            Write-RosetunLinuxLfFile -Path (Join-Path $folder $name) -Text (Get-Content -LiteralPath (Join-Path (Get-RosetunLinuxRoot) "guest/$name") -Raw)
        }
        $remote = "$GuestHome/rosetun-l2-launcher"
        $clear = Invoke-RosetunLinuxSsh -Target $Target -TimeoutSeconds 20 -Command "rm -rf -- $remote"
        if ($clear.ExitCode -ne 0) { throw "Could not clear $remote on the guest: $($clear.Error.Trim())" }
        Copy-RosetunLinuxToGuest -Target $Target -LocalDirectory $folder -RemoteParent $GuestHome
        $fix = Invoke-RosetunLinuxSsh -Target $Target -TimeoutSeconds 20 -Command "chmod 700 -- $remote && chmod 644 -- $remote/*.sh"
        if ($fix.ExitCode -ne 0) { throw "Could not set modes in ${remote}: $($fix.Error.Trim())" }
        [pscustomobject]@{ Folder = $remote; LauncherHash = Get-RosetunLinuxFileSha256 (Join-Path $folder 'launch.sh') }
    }
    finally {
        Remove-Item -LiteralPath $local -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ------------------------------------------------------------------ running

function Test-RosetunLinuxElevated {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Format-RosetunLinuxElapsed {
    param([Parameter(Mandatory)][TimeSpan]$Elapsed)
    $minutes = [int][Math]::Floor($Elapsed.TotalMinutes)
    '{0}:{1:00}' -f $minutes, $Elapsed.Seconds
}

# One line about the job for the wait loop, from status.json or its absence.
function Format-RosetunLinuxJobProgress {
    param($Status)
    if ($null -eq $Status) { return 'waiting for the job to start' }
    $state = [string](Get-RosetunLinuxMember -Object $Status -Name 'state')
    $current = [string](Get-RosetunLinuxMember -Object $Status -Name 'current')
    if ([string]::IsNullOrWhiteSpace($state)) { $state = 'unknown' }
    # The guest wrote this text; keep it printable and short.
    $current = $current -replace '[^\x20-\x7E]', '?'
    if ($current.Length -gt 80) { $current = $current.Substring(0, 80) }
    if ([string]::IsNullOrWhiteSpace($current)) { "job $state" } else { "job $state, $current" }
}

# How long -Run waits for the report: the job's own limit plus room for the
# cleanup, or for the owner to paste the manual command.
function Get-RosetunLinuxRunWaitSeconds {
    param([Parameter(Mandatory)][int]$JobTimeoutSeconds, [switch]$Manual)
    if ($Manual) { $JobTimeoutSeconds + 1800 } else { $JobTimeoutSeconds + 300 }
}

# ------------------------------------------------------------------ report verdict

# Property of a parsed JSON value, or $null. A truncated or foreign report must
# become an ERROR in the verdict, not an exception under strict mode.
function Get-RosetunLinuxMember {
    param($Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    $property.Value
}

# Judges a guest report on the host. The summary the guest wrote is never trusted:
# the verdict is recomputed from the scenario lines, the host's scenario list and
# the stage record. Anything missing, foreign, unfinished or inconsistent is ERROR.
function Test-RosetunLinuxReport {
    param(
        $Report,
        $Status,
        [Parameter(Mandatory)]$Stage,
        [Parameter(Mandatory)][object[]]$Scenarios
    )
    $member = { param($object, $name) Get-RosetunLinuxMember -Object $object -Name $name }
    $problems = [System.Collections.Generic.List[string]]::new()
    $rows = [System.Collections.Generic.List[object]]::new()
    $counts = @{ PASS = 0; FAIL = 0; SKIP = 0; ERROR = 0 }

    if ($null -eq $Status) { $problems.Add('status.json is missing or unreadable') }
    elseif ((& $member $Status 'run_id') -ne $Stage.RunId) { $problems.Add('status.json belongs to another run') }
    elseif ((& $member $Status 'state') -ne 'finished') {
        $problems.Add("the job has not finished (state: $(& $member $Status 'state'), last scenario: $(& $member $Status 'current'))")
    }

    if ($null -eq $Report) {
        $problems.Add('report.json is missing, empty or not valid JSON')
        return [pscustomobject]@{ Verdict = 'ERROR'; Coverage = 'none'; Problems = @($problems); Rows = @(); Counts = $counts; CleanupStatus = 'unknown' }
    }
    if ((& $member $Report 'schema') -ne $script:ReportSchema) { $problems.Add("unsupported report schema '$(& $member $Report 'schema')'") }
    if ((& $member $Report 'run_id') -ne $Stage.RunId) { $problems.Add("the report belongs to run '$(& $member $Report 'run_id')', not '$($Stage.RunId)'") }
    $guest = & $member $Report 'guest'
    if ($null -eq $guest -or (& $member $guest 'boot_id') -ne $Stage.BootId) {
        $problems.Add('the guest boot id differs from the one recorded at staging; the guest restarted')
    }
    elseif ((& $member $guest 'boot_id_at_end') -ne $Stage.BootId) {
        $problems.Add('the guest rebooted during the run')
    }

    $byId = @{}
    foreach ($entry in @(& $member $Report 'scenarios')) {
        $entryId = [string](& $member $entry 'id')
        if ([string]::IsNullOrEmpty($entryId)) { $problems.Add('a scenario line has no id'); continue }
        if ($byId.ContainsKey($entryId)) { $problems.Add("scenario $entryId is reported twice"); continue }
        $byId[$entryId] = $entry
    }
    $known = @{}
    $reportedCounts = @{ PASS = 0; FAIL = 0; SKIP = 0; ERROR = 0 }
    foreach ($entry in $byId.Values) {
        $raw = [string](& $member $entry 'result')
        if ($reportedCounts.ContainsKey($raw)) { $reportedCounts[$raw]++ }
    }
    foreach ($scenario in $Scenarios) {
        $known[$scenario.Id] = $true
        $entry = $byId[$scenario.Id]
        if ($null -eq $entry) {
            $problems.Add("scenario $($scenario.Id) has no result")
            $rows.Add([pscustomobject]@{ Result = 'ERROR'; Scenario = $scenario.Id; Evidence = $scenario.Evidence; Expectation = $scenario.Title; Reason = 'no result was reported'; DurationMs = 0 })
            $counts['ERROR']++
            continue
        }
        $result = [string](& $member $entry 'result')
        if ($script:ResultNames -notcontains $result) {
            $problems.Add("scenario $($scenario.Id) has an unknown result '$result'")
            $result = 'ERROR'
        }
        if ((& $member $entry 'evidence') -ne $scenario.Evidence) {
            $problems.Add("scenario $($scenario.Id) reports evidence '$(& $member $entry 'evidence')' instead of '$($scenario.Evidence)'")
            $result = 'ERROR'
        }
        if ($scenario.Required -and $result -eq 'SKIP') {
            $problems.Add("required scenario $($scenario.Id) was skipped")
            $result = 'ERROR'
        }
        if ($scenario.Evidence -eq 'not-run' -and $result -eq 'PASS') {
            $problems.Add("scenario $($scenario.Id) has no check but reports PASS")
            $result = 'ERROR'
        }
        $counts[$result]++
        $duration = 0L
        $null = [long]::TryParse([string](& $member $entry 'duration_ms'), [ref]$duration)
        $rows.Add([pscustomobject]@{
                Result = $result; Scenario = $scenario.Id; Evidence = $scenario.Evidence
                Expectation = $scenario.Title; Reason = [string](& $member $entry 'reason'); DurationMs = $duration
            })
    }
    foreach ($id in $byId.Keys) {
        if (-not $known.ContainsKey($id)) { $problems.Add("the report contains unknown scenario $id") }
    }

    $summary = & $member $Report 'summary'
    if ($null -eq $summary) { $problems.Add('the report has no summary') }
    else {
        foreach ($pair in @(@('PASS', 'pass'), @('FAIL', 'fail'), @('SKIP', 'skip'), @('ERROR', 'error'))) {
            $claimed = & $member $summary $pair[1]
            if ("$claimed" -ne "$($reportedCounts[$pair[0]])") {
                $problems.Add("the summary counts '$claimed' $($pair[0]) but the scenario lines hold $($reportedCounts[$pair[0]])")
            }
        }
    }

    $cleanupSection = & $member $Report 'cleanup'
    $cleanup = if ($null -ne $cleanupSection) { [string](& $member $cleanupSection 'status') } else { 'missing' }
    if ($cleanup -ne 'PASS') {
        $detail = if ($null -ne $cleanupSection) { [string](& $member $cleanupSection 'problems') } else { '' }
        $problems.Add("cleanup did not succeed ($cleanup): $detail")
    }

    $verdict = if ($problems.Count -gt 0 -or $counts['ERROR'] -gt 0) { 'ERROR' }
    elseif ($counts['FAIL'] -gt 0) { 'FAIL' }
    else { 'PASS' }
    if ($null -ne $summary -and (& $member $summary 'overall') -eq 'PASS' -and $verdict -ne 'PASS') {
        $problems.Add("the guest claims PASS but the host recomputed $verdict")
    }
    $coverage = if ($verdict -ne 'PASS') { 'none' } elseif ($counts['SKIP'] -gt 0) { 'partial' } else { 'complete' }
    [pscustomobject]@{
        Verdict = $verdict; Coverage = $coverage; Problems = @($problems); Rows = @($rows)
        Counts = $counts; CleanupStatus = $cleanup
    }
}

function Format-RosetunLinuxReport {
    param([Parameter(Mandatory)]$Judgement, [Parameter(Mandatory)]$Stage)
    $builder = [Text.StringBuilder]::new()
    $null = $builder.AppendLine("Linux L2 stand run $($Stage.RunId)")
    $null = $builder.AppendLine("Source:      $($Stage.Source.Sha) dirty=$($Stage.Source.Dirty) ($($Stage.Source.DirtyEntries) changed paths)")
    $dirtyPaths = @(Get-RosetunLinuxMember -Object $Stage.Source -Name 'DirtyPaths' | Where-Object { $null -ne $_ })
    if ($Stage.Source.Dirty -and $dirtyPaths.Count -gt 0) { $null = $builder.AppendLine((Format-RosetunLinuxPathList $dirtyPaths)) }
    $origin = if ($Stage.Artifacts.Confirmed) { 'confirmed' } else { "UNCONFIRMED: $($Stage.Artifacts.Note)" }
    $null = $builder.AppendLine("Build origin: $origin")
    foreach ($name in $Stage.Artifacts.Hashes.Keys) { $null = $builder.AppendLine("  $($Stage.Artifacts.Hashes[$name])  $name") }
    $null = $builder.AppendLine("Boot id:     $($Stage.BootId)")
    $null = $builder.AppendLine()
    $table = $Judgement.Rows | Select-Object Result, Scenario, Evidence, Expectation, Reason, DurationMs | Format-Table -AutoSize -Wrap | Out-String -Width 220
    $null = $builder.Append($table)
    if ($Judgement.Problems.Count -gt 0) {
        $null = $builder.AppendLine('Problems:')
        foreach ($problem in $Judgement.Problems) { $null = $builder.AppendLine("  - $problem") }
    }
    $null = $builder.AppendLine("Cleanup:     $($Judgement.CleanupStatus)")
    $null = $builder.AppendLine("Result:      $($Judgement.Verdict) (coverage: $($Judgement.Coverage); PASS $($Judgement.Counts['PASS']), FAIL $($Judgement.Counts['FAIL']), SKIP $($Judgement.Counts['SKIP']), ERROR $($Judgement.Counts['ERROR']))")
    $builder.ToString()
}

Export-ModuleMember -Function *-Rosetun*
