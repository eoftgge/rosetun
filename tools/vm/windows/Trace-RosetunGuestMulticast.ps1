# Runs in the guest, started by Invoke-LanMatrix.ps1 -MulticastTraceOnly. Once a
# second it records where unbound multicast would go and sends one datagram
# each to mDNS, SSDP and the limited broadcast, from a socket without a chosen
# adapter. Every IPv4 route change is written as it happens, so a route that
# comes back between two samples or two supervisor ticks is still caught.

param(
    [Parameter(Mandatory)][string]$OutDir,
    [Parameter(Mandatory)][int]$Seconds,
    [Parameter(Mandatory)][int]$BroadcastPort,
    [Parameter(Mandatory)][string]$PhysicalAlias,
    [Parameter(Mandatory)][string]$TunAlias
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$samplesPath = Join-Path $OutDir 'multicast-samples.csv'
$routesPath = Join-Path $OutDir 'multicast-routes.csv'
$interfacesPath = Join-Path $OutDir 'multicast-interfaces.csv'
$errorPath = Join-Path $OutDir 'multicast-error.txt'
$donePath = Join-Path $OutDir 'multicast-done.txt'

Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;

public static class RosetunRouteTrace
{
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void RouteChanged(IntPtr context, IntPtr row, int type);

    [StructLayout(LayoutKind.Sequential)]
    private struct ForwardRow
    {
        public uint Destination, Mask, Policy, NextHop, InterfaceIndex, Type, Protocol, Age,
            NextHopAs, Metric1, Metric2, Metric3, Metric4, Metric5;
    }

    [DllImport("iphlpapi.dll")]
    private static extern uint NotifyRouteChange2(ushort family, RouteChanged callback,
        IntPtr context, [MarshalAs(UnmanagedType.U1)] bool initial, out IntPtr handle);

    [DllImport("iphlpapi.dll")]
    private static extern uint CancelMibChangeNotify2(IntPtr handle);

    [DllImport("iphlpapi.dll")]
    private static extern uint GetBestRoute(uint destination, uint source, out ForwardRow row);

    private const ushort AfInet = 2;
    // The offsets of MIB_IPFORWARD_ROW2: the LUID takes 8 bytes, the index 4,
    // and the prefix's SOCKADDR_INET holds its family first and its address
    // after the port. The prefix length follows the 28-byte union.
    private const int IndexOffset = 8, FamilyOffset = 12, AddressOffset = 16, LengthOffset = 40;

    // The delegate must outlive the registration, or Windows calls freed code.
    private static RouteChanged callback;
    private static IntPtr handle;
    private static StreamWriter writer;

    public static void Start(string path)
    {
        writer = new StreamWriter(path, false);
        writer.AutoFlush = true;
        writer.WriteLine("utc,change,interface_index,prefix");
        callback = OnRouteChanged;
        uint status = NotifyRouteChange2(AfInet, callback, IntPtr.Zero, false, out handle);
        if (status != 0)
        {
            throw new InvalidOperationException("NotifyRouteChange2 failed: " + status);
        }
    }

    public static void Stop()
    {
        CancelMibChangeNotify2(handle);
        lock (writer) { writer.Dispose(); }
    }

    public static string BestRoute(string address)
    {
        uint destination = BitConverter.ToUInt32(IPAddress.Parse(address).GetAddressBytes(), 0);
        ForwardRow row;
        uint status = GetBestRoute(destination, 0, out row);
        if (status != 0)
        {
            return "error " + status;
        }
        return string.Format("{0} mask {1} via {2} if {3} metric {4}",
            new IPAddress(row.Destination), new IPAddress(row.Mask), new IPAddress(row.NextHop),
            row.InterfaceIndex, row.Metric1);
    }

    private static void OnRouteChanged(IntPtr context, IntPtr row, int type)
    {
        if (row == IntPtr.Zero || (ushort)Marshal.ReadInt16(row, FamilyOffset) != AfInet)
        {
            return;
        }
        byte[] address = new byte[4];
        Marshal.Copy(IntPtr.Add(row, AddressOffset), address, 0, 4);
        string change = type == 0 ? "change" : type == 1 ? "add" : type == 2 ? "delete" : type.ToString();
        string line = string.Format("{0:o},{1},{2},{3}/{4}", DateTime.UtcNow, change,
            Marshal.ReadInt32(row, IndexOffset), new IPAddress(address), Marshal.ReadByte(row, LengthOffset));
        lock (writer) { writer.WriteLine(line); }
    }
}
'@

function Get-TraceRouteList {
    # Every route of the adapter, in a stable order, so a change is a real one.
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Routes)
    @($Routes | Sort-Object AddressFamily, DestinationPrefix | ForEach-Object {
        "$($_.DestinationPrefix) via $($_.NextHop) metric $($_.RouteMetric) $($_.Protocol)"
    }) -join ' | '
}

function Get-TraceSource {
    # Connecting a datagram socket looks the route up and sends nothing.
    param([Parameter(Mandatory)][string]$Address)
    $socket = [Net.Sockets.Socket]::new('InterNetwork', 'Dgram', 'Udp')
    try {
        $socket.EnableBroadcast = $true
        $socket.Connect([Net.IPEndPoint]::new([Net.IPAddress]::Parse($Address), 9))
        $socket.LocalEndPoint.Address.ToString()
    }
    catch { "error: $($_.Exception.Message)" }
    finally { $socket.Dispose() }
}

function Get-TraceFoundRoute {
    param([Parameter(Mandatory)][string]$Address)
    try {
        $found = @(Find-NetRoute -RemoteIPAddress $Address -ErrorAction Stop)
        $routes = @($found | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_NetRoute' } |
            ForEach-Object { "$($_.InterfaceAlias) $($_.DestinationPrefix)" })
        $sources = @($found | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_NetIPAddress' } |
            ForEach-Object { $_.IPAddress })
        [pscustomobject]@{ Route = $routes -join ' | '; Source = $sources -join ' | '; Error = '' }
    }
    catch {
        [pscustomobject]@{ Route = ''; Source = ''; Error = "$($_.Exception.Message)" }
    }
}

function Get-TracePathAdapter {
    # The adapters with a cached path, by value: the labels are localized.
    # Each entry has 13 lines, and the fourth is the adapter.
    param([Parameter(Mandatory)][string]$Address)
    $values = @(netsh.exe interface ipv4 show destinationcache "address=$Address" |
        Where-Object { $_ -match ':' } |
        ForEach-Object { $_ -replace '^[^:]*:\s*', '' })
    $adapters = for ($index = 3; $index -lt $values.Count; $index += 13) { $values[$index] }
    @($adapters) -join ' | '
}

function Send-TraceDatagram {
    param([Parameter(Mandatory)][string]$Address, [Parameter(Mandatory)][int]$Port, [Parameter(Mandatory)][int]$Sequence)
    $client = [Net.Sockets.UdpClient]::new()
    try {
        $client.EnableBroadcast = $true
        $bytes = [Text.Encoding]::ASCII.GetBytes("rosetun-lan-matrix trace-$Sequence")
        [void]$client.Send($bytes, $bytes.Length, $Address, $Port)
        'sent'
    }
    catch { "$($_.Exception.GetBaseException().Message)" }
    finally { $client.Dispose() }
}

try {
    [RosetunRouteTrace]::Start($routesPath)
    $started = [DateTime]::UtcNow
    for ($sequence = 0; $sequence -lt $Seconds; $sequence++) {
        $found = Get-TraceFoundRoute -Address '239.255.255.250'
        $found224 = Get-TraceFoundRoute -Address '224.0.0.251'
        $routes = @(Get-NetRoute -ErrorAction Stop)
        $onTunnel = @($routes | Where-Object { $_.InterfaceAlias -eq $TunAlias })
        $onPhysical = @($routes | Where-Object { $_.InterfaceAlias -eq $PhysicalAlias })
        $row = [pscustomobject]@{
            sequence            = $sequence
            utc                 = [DateTime]::UtcNow.ToString('o')
            find_route_239      = $found.Route
            find_source_239     = $found.Source
            find_error_239      = $found.Error
            find_route_224      = $found224.Route
            find_source_224     = $found224.Source
            find_error_224      = $found224.Error
            best_route_239      = [RosetunRouteTrace]::BestRoute('239.255.255.250')
            best_route_224      = [RosetunRouteTrace]::BestRoute('224.0.0.251')
            socket_239          = Get-TraceSource -Address '239.255.255.250'
            socket_224          = Get-TraceSource -Address '224.0.0.251'
            socket_255          = Get-TraceSource -Address '255.255.255.255'
            tunnel_has_224_4    = @($onTunnel | Where-Object { $_.DestinationPrefix -eq '224.0.0.0/4' }).Count -gt 0
            physical_has_224_4  = @($onPhysical | Where-Object { $_.DestinationPrefix -eq '224.0.0.0/4' }).Count -gt 0
            tunnel_has_default  = @($onTunnel | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' }).Count -gt 0
            tunnel_routes       = Get-TraceRouteList -Routes $onTunnel
            path_adapters_239   = Get-TracePathAdapter -Address '239.255.255.250'
            path_adapters_224   = Get-TracePathAdapter -Address '224.0.0.251'
            send_239            = Send-TraceDatagram -Address '239.255.255.250' -Port 1900 -Sequence $sequence
            send_224            = Send-TraceDatagram -Address '224.0.0.251' -Port 5353 -Sequence $sequence
            send_255            = Send-TraceDatagram -Address '255.255.255.255' -Port $BroadcastPort -Sequence $sequence
        }
        $row | Export-Csv -Path $samplesPath -Append -NoTypeInformation -Encoding UTF8
        $wait = $started.AddSeconds($sequence + 1) - [DateTime]::UtcNow
        if ($wait -gt [TimeSpan]::Zero) { Start-Sleep -Milliseconds ([int]$wait.TotalMilliseconds) }
    }
    [RosetunRouteTrace]::Stop()
    Get-NetIPInterface -AddressFamily IPv4 | Select-Object ifIndex, InterfaceAlias |
        Export-Csv -Path $interfacesPath -NoTypeInformation -Encoding UTF8
}
catch {
    Set-Content -Path $errorPath -Value "$_" -Encoding UTF8
}
finally {
    Set-Content -Path $donePath -Value 'done' -Encoding UTF8
}
