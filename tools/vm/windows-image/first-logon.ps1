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
$null = New-Item -ItemType Directory -Force -Path $script:LogDirectory

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

function Set-RosetunRegistryValue {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] $Value,
        [string] $Type = 'DWord'
    )
    $null = New-Item -Path $Path -Force
    $null = New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force
}

function Disable-RosetunService {
    param([Parameter(Mandatory)] [string] $Name)
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        return
    }
    Set-Service -Name $Name -StartupType Disabled
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
    }
}

function Disable-RosetunTaskFolder {
    param([Parameter(Mandatory)] [string] $Path)
    foreach ($task in @(Get-ScheduledTask -TaskPath $Path -ErrorAction SilentlyContinue)) {
        $null = Disable-ScheduledTask -InputObject $task
    }
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

Invoke-RosetunStep 'virtio-drivers' 'Setup loaded viostor only to reach the disk; add the network, serial and block drivers to the driver store.' {
    $root = Find-RosetunVolume 'virtio-win*'
    foreach ($driver in 'viostor', 'NetKVM', 'vioserial') {
        $inf = Join-Path $root "$driver\w11\amd64\*.inf"
        $output = & pnputil.exe /add-driver $inf /install
        if ($LASTEXITCODE -ne 0) {
            throw "pnputil failed for $driver : $output"
        }
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
    $name = 'RosetunDisableMedic'
    $action = New-ScheduledTaskAction -Execute 'reg.exe' -Argument 'add HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc /v Start /t REG_DWORD /d 4 /f'
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $null = Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Force
    Start-ScheduledTask -TaskName $name
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-ScheduledTask -TaskName $name).State -eq 'Running' -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 1
    }
    Unregister-ScheduledTask -TaskName $name -Confirm:$false
    $start = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc').Start
    if ($start -ne 4) { throw "WaaSMedicSvc Start is $start" }
}

Invoke-RosetunStep 'update-tasks-off' 'The scheduled tasks of Windows Update and the update orchestrator would start scans by themselves.' {
    Disable-RosetunTaskFolder '\Microsoft\Windows\WindowsUpdate\'
    Disable-RosetunTaskFolder '\Microsoft\Windows\UpdateOrchestrator\'
}

Invoke-RosetunStep 'delivery-optimization-off' 'DODownloadMode=0 and DoSvc disabled: no peer or cloud content download.' {
    Set-RosetunRegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' 'DODownloadMode' 0
    Disable-RosetunService 'DoSvc'
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
    Disable-RosetunTaskFolder '\Microsoft\Windows\Application Experience\'
    Disable-RosetunTaskFolder '\Microsoft\Windows\Customer Experience Improvement Program\'
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

Invoke-RosetunStep 'retrim' 'Return the freed blocks to the host so the qcow2 image stays small (the disk is virtio-blk with discard).' {
    Optimize-Volume -DriveLetter C -ReTrim
}

Write-RosetunLog ('done, failed steps: {0}' -f $script:Failed)

# The host waits for this shutdown to know that the build is over.
& shutdown.exe /s /t 10 /c 'Rosetun image build finished'
