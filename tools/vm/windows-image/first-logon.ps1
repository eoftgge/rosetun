# First logon of the Rosetun Windows image build (Windows PowerShell 5.1, elevated, runs once).
#
# It makes the guest quiet by operating-system settings and installs the guest agent. Every step is
# one line with its reason. Nothing here touches Windows Firewall or any filtering rule: the guest's own
# filtering layer is what the matrix examines, so the noise is switched off at its source instead.
#
# The result of each step goes to the log below; a step that fails is logged as FAIL and does not stop
# the others, so the qualifier sees the whole picture from one boot of the image.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:LogDirectory = Join-Path $env:ProgramData 'rosetun-image'
$script:LogPath = Join-Path $script:LogDirectory 'first-logon.log'
$script:Failed = 0
$null = [IO.Directory]::CreateDirectory($script:LogDirectory)

function Write-RosetunLog {
    param([string] $Text)
    $line = '{0} {1}' -f ([DateTime]::UtcNow.ToString('o')), $Text
    # UTF-8 without a BOM: the host reads this file through the guest agent.
    [IO.File]::AppendAllText($script:LogPath, $line + "`r`n", (New-Object Text.UTF8Encoding($false)))
}

function Invoke-RosetunStep {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $Why,
        [Parameter(Mandatory)] [scriptblock] $Action
    )
    try {
        & $Action
        Write-RosetunLog ('OK   {0}: {1}' -f $Name, $Why)
    } catch {
        $script:Failed++
        Write-RosetunLog ('FAIL {0}: {1} ({2})' -f $Name, $Why, $_.Exception.Message)
    }
}

function New-RosetunRegistryKey {
    param([Parameter(Mandatory)] [string] $Path)
    # Only a key that is missing is created, parents first: `New-Item -Force` on an existing key tries to
    # recreate it and fails on keys the system protects (BitLocker).
    if (Test-Path -LiteralPath $Path) {
        return
    }
    New-RosetunRegistryKey (Split-Path -Path $Path -Parent)
    $null = New-Item -Path $Path
}

function Set-RosetunRegistryValue {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] $Value,
        [string] $Type = 'DWord'
    )
    New-RosetunRegistryKey $Path
    $null = New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force
    $written = Get-ItemPropertyValue -Path $Path -Name $Name
    if ($written -ne $Value) {
        throw "$Path $Name reads back as $written, expected $Value"
    }
}

function Invoke-RosetunSystemTask {
    param(
        [Parameter(Mandatory)] [string] $Execute,
        [Parameter(Mandatory)] [string] $Argument
    )
    # Some keys and tasks belong to the system account and refuse the administrator. A one-shot task of
    # the system account is the documented way to act as it; ownership and ACLs are never changed.
    $name = 'RosetunOneShot'
    $action = New-ScheduledTaskAction -Execute $Execute -Argument $Argument
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $null = Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Force
    try {
        Start-ScheduledTask -TaskName $name
        $deadline = (Get-Date).AddSeconds(30)
        do {
            Start-Sleep -Seconds 1
            $result = (Get-ScheduledTaskInfo -TaskName $name).LastTaskResult
            $state = (Get-ScheduledTask -TaskName $name).State
            # 267011 is SCHED_S_TASK_HAS_NOT_RUN: the task has not started yet.
        } while (($state -eq 'Running' -or $result -eq 267011) -and (Get-Date) -lt $deadline)
        return $result
    } finally {
        Unregister-ScheduledTask -TaskName $name -Confirm:$false
    }
}

function Confirm-RosetunServiceDisabled {
    param([Parameter(Mandatory)] [string] $Name)
    $start = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$Name").Start
    if ($start -ne 4) {
        throw "service $Name has Start=$start, not 4 (disabled)"
    }
}

function Set-RosetunServiceStartAsSystem {
    param([Parameter(Mandatory)] [string] $Name)
    $result = Invoke-RosetunSystemTask 'reg.exe' "add HKLM\SYSTEM\CurrentControlSet\Services\$Name /v Start /t REG_DWORD /d 4 /f"
    Write-RosetunLog ('INFO service {0}: one-shot SYSTEM task result {1}' -f $Name, $result)
    try {
        Confirm-RosetunServiceDisabled $Name
    } catch {
        throw ('{0}; the service key is protected in this build, and its owner and ACL are left as they are' -f $_.Exception.Message)
    }
}

function Disable-RosetunService {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [switch] $ViaSystemTask
    )
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        return
    }
    try {
        Set-Service -Name $Name -StartupType Disabled -ErrorAction Stop
    } catch {
        if (-not $ViaSystemTask) {
            throw
        }
        Write-RosetunLog ('INFO service {0}: Set-Service refused ({1}); trying a one-shot SYSTEM task' -f $Name, $_.Exception.Message)
        Set-RosetunServiceStartAsSystem $Name
    }
    Confirm-RosetunServiceDisabled $Name
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
    }
}

function Disable-RosetunTaskFolder {
    param([Parameter(Mandatory)] [string] $Path)
    # Returns the tasks of the folder that are still enabled after every attempt.
    $stuck = @()
    foreach ($task in @(Get-ScheduledTask -TaskPath $Path -ErrorAction SilentlyContinue)) {
        if ($task.State -eq 'Disabled') {
            continue
        }
        $full = $task.TaskPath + $task.TaskName
        try {
            $null = Disable-ScheduledTask -InputObject $task -ErrorAction Stop
        } catch {
            $reason = $_.Exception.Message
            $result = Invoke-RosetunSystemTask 'schtasks.exe' ('/Change /TN "{0}" /DISABLE' -f $full)
            Write-RosetunLog ('INFO task {0}: Disable-ScheduledTask refused ({1}); one-shot SYSTEM task result {2}' -f $full, $reason, $result)
        }
        if ((Get-ScheduledTask -TaskPath $task.TaskPath -TaskName $task.TaskName).State -ne 'Disabled') {
            $stuck += $full
        }
    }
    return $stuck
}

function Get-RosetunDriverStoreNames {
    $text = (& pnputil.exe /enum-drivers | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw "the driver store listing failed with exit code $LASTEXITCODE"
    }
    return @([regex]::Matches($text, '(?im)^\s*Original Name:\s*(\S+)\s*$') | ForEach-Object { $_.Groups[1].Value.ToLowerInvariant() })
}

function Install-RosetunDriverPackage {
    param([Parameter(Mandatory)] [string] $InfPath)
    # PnPUtil returns Win32 error codes; the documentation of its syntax lists none. 0 is success and
    # 3010 (ERROR_SUCCESS_REBOOT_REQUIRED) is success too. A package Setup already installed gives
    # another code and "Added driver packages: 0", so the answer is read from the driver store itself.
    $original = (Split-Path -Path $InfPath -Leaf).ToLowerInvariant()
    $output = (& pnputil.exe /add-driver $InfPath /install | Out-String)
    $code = $LASTEXITCODE
    $present = (Get-RosetunDriverStoreNames) -contains $original
    $added = $code -in 0, 3010
    $state = if ($added) { 'added' } elseif ($present) { 'already in the driver store' } else { 'missing' }
    Write-RosetunLog ('INFO driver {0}: pnputil exit code {1}, {2}. {3}' -f $original, $code, $state, (($output -replace '\s+', ' ').Trim()))
    return ($added -or $present)
}

function Find-RosetunVolume {
    param([Parameter(Mandatory)] [string] $LabelPattern)
    $volume = @(Get-Volume | Where-Object { $_.FileSystemLabel -like $LabelPattern -and $_.DriveLetter })
    if ($volume.Count -ne 1) {
        throw "expected one volume labelled $LabelPattern, found $($volume.Count)"
    }
    return ($volume[0].DriveLetter + ':\')
}

Write-RosetunLog 'start'

# --- Drivers and the guest agent -------------------------------------------------------------------

Invoke-RosetunStep 'virtio-drivers' 'Setup loaded viostor only to reach the disk; make sure the network, serial and block drivers are in the driver store, each one on its own line.' {
    $root = Find-RosetunVolume 'virtio-win*'
    $missing = @()
    foreach ($driver in 'viostor', 'NetKVM', 'vioserial') {
        $infs = @(Get-ChildItem -Path (Join-Path $root "$driver\w11\amd64") -Filter '*.inf' -ErrorAction SilentlyContinue)
        if ($infs.Count -eq 0) {
            Write-RosetunLog "INFO driver ${driver}: no .inf file on the virtio-win disc"
            $missing += $driver
        }
        foreach ($inf in $infs) {
            if (-not (Install-RosetunDriverPackage $inf.FullName)) {
                $missing += $inf.Name
            }
        }
    }
    if ($missing.Count -gt 0) {
        throw ('not installed and not in the driver store: ' + ($missing -join ', '))
    }
}

Invoke-RosetunStep 'qemu-guest-agent' 'The controller reaches the guest through the agent channel; the MSI comes from the virtio-win disc.' {
    $root = Find-RosetunVolume 'virtio-win*'
    $msi = Join-Path $root 'guest-agent\qemu-ga-x86_64.msi'
    $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', $msi, '/qn', '/norestart') -Wait -PassThru
    if ($process.ExitCode -notin 0, 3010) {
        throw "msiexec exit code $($process.ExitCode)"
    }
    Set-Service -Name 'QEMU-GA' -StartupType Automatic
}

# --- Power and boot --------------------------------------------------------------------------------

Invoke-RosetunStep 'hibernation-off' 'powercfg /h off: no hiberfil.sys, so shutdown is a full shutdown and a restart is a new kernel boot.' {
    & powercfg.exe /h off
    if ($LASTEXITCODE -ne 0) { throw "powercfg exit code $LASTEXITCODE" }
}

Invoke-RosetunStep 'fast-startup-off' 'HiberbootEnabled=0: no hybrid shutdown even if hibernation comes back.' {
    Set-RosetunRegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled' 0
}

Invoke-RosetunStep 'power-button-shutdown' 'The ACPI power button shuts the guest down, so a requested shutdown from the host ends the machine.' {
    & powercfg.exe /setacvalueindex SCHEME_CURRENT SUB_BUTTONS PBUTTONACTION 3
    if ($LASTEXITCODE -ne 0) { throw "powercfg exit code $LASTEXITCODE" }
    & powercfg.exe /setactive SCHEME_CURRENT
}

Invoke-RosetunStep 'no-idle-sleep' 'Never sleep or turn the display off on idle: an unrequested sleep looks like a hung guest.' {
    foreach ($setting in 'standby-timeout-ac', 'monitor-timeout-ac', 'disk-timeout-ac') {
        & powercfg.exe /change $setting 0
        if ($LASTEXITCODE -ne 0) { throw "powercfg $setting exit code $LASTEXITCODE" }
    }
}

Invoke-RosetunStep 'boot-recovery-off' 'bcdedit recoveryenabled No and bootstatuspolicy ignoreallfailures: a power cut never ends in automatic repair.' {
    & bcdedit.exe /set '{current}' recoveryenabled No
    if ($LASTEXITCODE -ne 0) { throw "bcdedit recoveryenabled exit code $LASTEXITCODE" }
    & bcdedit.exe /set '{current}' bootstatuspolicy ignoreallfailures
    if ($LASTEXITCODE -ne 0) { throw "bcdedit bootstatuspolicy exit code $LASTEXITCODE" }
}

Invoke-RosetunStep 'automatic-maintenance-off' 'MaintenanceDisabled=1: no scheduled maintenance burst on an idle guest.' {
    Set-RosetunRegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance' 'MaintenanceDisabled' 1
}

Invoke-RosetunStep 'device-encryption-off' 'The TPM state is not part of a run: a volume sealed to it could not start from a copy.' {
    Set-RosetunRegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker' 'PreventDeviceEncryption' 1
    $status = (& manage-bde.exe -status C: | Out-String)
    Write-RosetunLog ('INFO bitlocker: ' + ($status -replace '\s+', ' ').Trim())
}

# --- Updates ---------------------------------------------------------------------------------------

Invoke-RosetunStep 'windows-update-policy' 'NoAutoUpdate=1: Windows Update does not download or install on its own.' {
    Set-RosetunRegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate' 1
    Set-RosetunRegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'SetDisableUXWUAccess' 1
}

Invoke-RosetunStep 'windows-update-services' 'wuauserv and UsoSvc disabled: an update restart would be an unplanned reset of the run.' {
    Disable-RosetunService 'wuauserv'
    Disable-RosetunService 'UsoSvc'
}

Invoke-RosetunStep 'windows-update-medic' 'WaaSMedicSvc would switch the update services back on; it is owned by the system account, so a one-shot SYSTEM task disables it.' {
    Set-RosetunServiceStartAsSystem 'WaaSMedicSvc'
}

Invoke-RosetunStep 'update-tasks-off' 'The scheduled tasks of Windows Update and the update orchestrator would start scans by themselves.' {
    $stuck = @(Disable-RosetunTaskFolder '\Microsoft\Windows\WindowsUpdate\') + @(Disable-RosetunTaskFolder '\Microsoft\Windows\UpdateOrchestrator\')
    if ($stuck.Count -gt 0) {
        throw ('still enabled after a SYSTEM task too: ' + ($stuck -join ', '))
    }
}

Invoke-RosetunStep 'delivery-optimization-off' 'DODownloadMode=0 and DoSvc disabled (the service refuses Set-Service in this build, so a SYSTEM task writes Start=4): no peer or cloud content download.' {
    Set-RosetunRegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' 'DODownloadMode' 0
    Disable-RosetunService 'DoSvc' -ViaSystemTask
}

Invoke-RosetunStep 'store-auto-update-off' 'AutoDownload=2: the Store does not update apps in the background.' {
    Set-RosetunRegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' 'AutoDownload' 2
}

Invoke-RosetunStep 'edge-update-off' 'The Edge updater services and policy: no browser update traffic.' {
    Disable-RosetunService 'edgeupdate'
    Disable-RosetunService 'edgeupdatem'
    Set-RosetunRegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate' 'UpdateDefault' 0
    Set-RosetunRegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate' 'AutoUpdateCheckPeriodMinutes' 0
    Set-RosetunRegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'BackgroundModeEnabled' 0
    Set-RosetunRegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'StartupBoostEnabled' 0
}

# --- Telemetry and cloud calls ---------------------------------------------------------------------

Invoke-RosetunStep 'telemetry-policy' 'AllowTelemetry=0. On Pro the system treats 0 as the required level, so the service below is switched off too.' {
    Set-RosetunRegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' 0
}

Invoke-RosetunStep 'telemetry-services' 'DiagTrack and dmwappushservice disabled: no diagnostic data upload.' {
    Disable-RosetunService 'DiagTrack'
    Disable-RosetunService 'dmwappushservice'
}

Invoke-RosetunStep 'telemetry-tasks' 'The compatibility appraiser and customer experience tasks send data on a schedule.' {
    $stuck = @(Disable-RosetunTaskFolder '\Microsoft\Windows\Application Experience\') + @(Disable-RosetunTaskFolder '\Microsoft\Windows\Customer Experience Improvement Program\')
    if ($stuck.Count -gt 0) {
        throw ('still enabled after a SYSTEM task too: ' + ($stuck -join ', '))
    }
}

Invoke-RosetunStep 'error-reporting-off' 'Windows Error Reporting disabled: no crash upload.' {
    Set-RosetunRegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' 'Disabled' 1
    Set-RosetunRegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows' 'CEIPEnable' 0
}

Invoke-RosetunStep 'defender-cloud-off' 'Defender stays on, but its cloud protection and sample submission are off (policy, since tamper protection ignores Set-MpPreference).' {
    Set-RosetunRegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' 'SpynetReporting' 0
    Set-RosetunRegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' 'SubmitSamplesConsent' 2
}

Invoke-RosetunStep 'consumer-features-off' 'No consumer content, OneDrive sign-in, web search, news or widgets feed: each one fetches from the network.' {
    Set-RosetunRegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsConsumerFeatures' 1
    Set-RosetunRegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' 'DisableFileSyncNGSC' 1
    Set-RosetunRegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'DisableSearchBoxSuggestions' 1
    Set-RosetunRegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh' 'AllowNewsAndInterests' 0
}

Invoke-RosetunStep 'connected-devices-off' 'CDPSvc (connected devices platform) discovers devices on the network.' {
    Disable-RosetunService 'CDPSvc'
}

Invoke-RosetunStep 'time-service-off' 'W32Time disabled: no NTP to time.windows.com; the clock is the host RTC in UTC and a run is short.' {
    Disable-RosetunService 'W32Time'
}

# --- Network discovery and name resolution ---------------------------------------------------------

Invoke-RosetunStep 'ncsi-active-probe-off' 'No active connectivity probe: no DNS query for www.msftconnecttest.com and no HTTP request to it.' {
    Set-RosetunRegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet' 'EnableActiveProbing' 0
    Set-RosetunRegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator' 'NoActiveProbe' 1
}

Invoke-RosetunStep 'llmnr-off' 'EnableMulticast=0: no LLMNR queries or answers on UDP 5355.' {
    Set-RosetunRegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0
}

Invoke-RosetunStep 'mdns-off' 'EnableMDNS=0: no multicast DNS on UDP 5353.' {
    Set-RosetunRegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' 'EnableMDNS' 0
}

Invoke-RosetunStep 'netbios-off' 'NetbiosOptions=2 on every interface: no NetBIOS name service on UDP 137 and no datagrams on 138.' {
    $interfaces = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
    foreach ($key in @(Get-ChildItem -Path $interfaces)) {
        Set-ItemProperty -Path $key.PSPath -Name 'NetbiosOptions' -Value 2 -Type DWord
    }
}

Invoke-RosetunStep 'ssdp-upnp-off' 'SSDPSRV and upnphost disabled: no SSDP announcements to 239.255.255.250.' {
    Disable-RosetunService 'SSDPSRV'
    Disable-RosetunService 'upnphost'
}

Invoke-RosetunStep 'ws-discovery-off' 'FDResPub and fdPHost disabled: no WS-Discovery publication on UDP 3702.' {
    Disable-RosetunService 'FDResPub'
    Disable-RosetunService 'fdPHost'
}

Invoke-RosetunStep 'dhcpv6-off' 'The lab adapter never asks for DHCPv6, whatever the router advertisement says; addresses come from SLAAC or are static.' {
    foreach ($interface in @(Get-NetIPInterface -AddressFamily IPv6 | Where-Object { $_.InterfaceAlias -notlike 'Loopback*' })) {
        & netsh.exe interface ipv6 set interface interface=$($interface.InterfaceIndex) managedaddress=disabled otherstateful=disabled
        if ($LASTEXITCODE -ne 0) { throw "netsh exit code $LASTEXITCODE for $($interface.InterfaceAlias)" }
    }
}

Invoke-RosetunStep 'ipv6-transition-off' 'Teredo, ISATAP and 6to4 are tunnel transitions that resolve names and probe servers on their own.' {
    foreach ($technology in 'teredo', 'isatap', '6to4') {
        & netsh.exe interface $technology set state disabled
        if ($LASTEXITCODE -ne 0) { throw "netsh $technology exit code $LASTEXITCODE" }
    }
}

Invoke-RosetunStep 'lltd-off' 'The link-layer topology discovery responder and mapper answer broadcast frames; unbind them from the adapters.' {
    Disable-NetAdapterBinding -Name '*' -ComponentID 'ms_lltdio', 'ms_rspndr'
}

# --- Clean-up and end ------------------------------------------------------------------------------

Invoke-RosetunStep 'autologon-credentials-removed' 'Setup may leave the one-time logon credentials in the registry and in cached answer files.' {
    $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    Set-ItemProperty -Path $winlogon -Name 'AutoAdminLogon' -Value '0'
    foreach ($name in 'DefaultPassword', 'AutoLogonCount') {
        Remove-ItemProperty -Path $winlogon -Name $name -ErrorAction SilentlyContinue
    }
    foreach ($path in "$env:SystemRoot\Panther\unattend.xml", "$env:SystemRoot\Panther\Unattend\unattend.xml",
                      "$env:SystemRoot\Panther\Unattend\Autounattend.xml", "$env:SystemDrive\Autounattend.xml") {
        Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
    }
}

Invoke-RosetunStep 'deferred-work-complete' 'Finish the component cleanup and the queued native image generation now, so that a copy of the image does not start with them; the calming boot of the build checks what is left.' {
    # Documented servicing and .NET commands, run offline; they touch neither Defender nor the filtering
    # layer. A non-zero code is logged and is not a failure of the image: the calming boot finishes the rest.
    $null = (& dism.exe /Online /Cleanup-Image /StartComponentCleanup | Out-String)
    Write-RosetunLog ('INFO dism StartComponentCleanup exit code {0}' -f $LASTEXITCODE)
    foreach ($framework in 'Framework64', 'Framework') {
        $ngen = Join-Path $env:SystemRoot "Microsoft.NET\$framework\v4.0.30319\ngen.exe"
        if (Test-Path -LiteralPath $ngen) {
            $null = (& $ngen executeQueuedItems | Out-String)
            Write-RosetunLog ('INFO ngen {0} executeQueuedItems exit code {1}' -f $framework, $LASTEXITCODE)
        }
    }
}

Invoke-RosetunStep 'retrim' 'Return the freed blocks to the host so the qcow2 image stays small (the disk is virtio-blk with discard).' {
    Optimize-Volume -DriveLetter C -ReTrim
}

Write-RosetunLog ('done, failed steps: {0}' -f $script:Failed)

# The host waits for this shutdown to know that the build is over.
& shutdown.exe /s /t 10 /c 'Rosetun image build finished'
