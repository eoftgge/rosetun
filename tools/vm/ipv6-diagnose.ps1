# Diagnoses the matrix baseline "IPv6 to the host works before connect".
# Run on the host, elevated, from the repository root. Starts the test node if
# it is not running and stops it again at the end; changes nothing else.
Import-Module (Join-Path $PWD 'tools\vm\RosetunVm.psm1') -Force

$alias = 'vEthernet (Default Switch)'
$hostIp = Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv6 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -like 'fe80::*' } | Select-Object -First 1
$hostMac = (Get-NetAdapter -Name $alias).MacAddress
$port = (Get-Content -Raw (Join-Path $PWD 'tools\vm\test-node.json') | ConvertFrom-Json).inbounds[0].listen_port
$address = $hostIp.IPAddress -replace '%.*$', ''

$started = $false
if (-not (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)) {
    Write-Host 'Test node is not running; starting it for this check...'
    Start-RosetunTestNode
    $started = $true
    Start-Sleep -Seconds 2
}

try {
    Write-Host "Host link-local:  $address"
    Write-Host "Host MAC:         $hostMac"
    Write-Host 'Host listeners on the test node port:'
    Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue |
        Format-Table LocalAddress, LocalPort, OwningProcess -AutoSize

    Write-Host '--- host: network profile of the Default Switch'
    Get-NetConnectionProfile -InterfaceAlias $alias -ErrorAction SilentlyContinue |
        Format-Table InterfaceAlias, NetworkCategory, IPv6Connectivity -AutoSize

    Write-Host '--- host: inbound firewall rules for the test node program'
    $singBox = [IO.Path]::GetFullPath((Join-Path $PWD 'tools\sing-box.exe'))
    Get-NetFirewallApplicationFilter -Program $singBox -ErrorAction SilentlyContinue |
        Get-NetFirewallRule | Where-Object Direction -eq 'Inbound' |
        Format-Table DisplayName, Enabled, Action, Profile -AutoSize

    Write-Host '--- host: Neighbor Discovery rules'
    Get-NetFirewallRule -Name 'CoreNet-ICMP6-NDA-In', 'CoreNet-ICMP6-NDS-In' -ErrorAction SilentlyContinue |
        Format-Table Name, Enabled, Action, Profile -AutoSize

    $egress = Get-RosetunEgressInterface
    $guestIp = Invoke-RosetunGuest -ScriptBlock {
        param($index)
        (Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv6 |
            Where-Object { $_.IPAddress -like 'fe80::*' } | Select-Object -First 1).IPAddress -replace '%.*$', ''
    } -ArgumentList $egress.Index
    Write-Host "Guest link-local: $guestIp"

    Write-Host '--- host: what the host knows about the guest'
    Get-NetNeighbor -InterfaceAlias $alias -AddressFamily IPv6 -IPAddress $guestIp -ErrorAction SilentlyContinue |
        Format-Table IPAddress, LinkLayerAddress, State -AutoSize

    Invoke-RosetunGuest -ScriptBlock {
        param($address, $index, $port)
        Write-Output '--- guest: MAC and Neighbor Discovery rules'
        (Get-NetAdapter -InterfaceIndex $index).MacAddress
        Get-NetFirewallRule -Name 'CoreNet-ICMP6-NDA-In', 'CoreNet-ICMP6-NDS-In' -ErrorAction SilentlyContinue |
            Select-Object Name, Enabled, Action, Profile
        Write-Output '--- guest: TCP connect to the host over IPv6'
        $client = [Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetworkV6)
        try {
            $ok = $client.ConnectAsync([Net.IPAddress]::Parse("$address%$index"), $port).Wait(3000)
            Write-Output "connected: $ok"
        }
        catch { Write-Output "connect error: $($_.Exception.InnerException.Message)" }
        finally { $client.Dispose() }
    } -ArgumentList $address, $egress.Index, $port

    Write-Host '--- host: what the host knows about the guest after the connect attempt'
    Get-NetNeighbor -InterfaceAlias $alias -AddressFamily IPv6 -IPAddress $guestIp -ErrorAction SilentlyContinue |
        Format-Table IPAddress, LinkLayerAddress, State -AutoSize
}
finally {
    if ($started) {
        Stop-RosetunTestNode
    }
}
