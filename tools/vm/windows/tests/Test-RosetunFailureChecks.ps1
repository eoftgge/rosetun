# Exercises the failure matrix's actual SOCKS probe and lifecycle guards without
# a VM or privileges. The SOCKS peer is a synthetic loopback server.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$matrix = Join-Path $PSScriptRoot '..\Invoke-FailureMatrix.ps1'
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    [IO.Path]::GetFullPath($matrix), [ref]$null, [ref]$parseErrors)
if (@($parseErrors).Count -gt 0) { throw 'The failure matrix does not parse.' }
foreach ($name in 'Test-Socks', 'Test-Step', 'Test-RosetunDnsLockLifecycle') {
    $definition = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if (-not $definition) { throw "Matrix function $name is absent." }
    . ([scriptblock]::Create($definition.Extent.Text))
}

Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

public sealed class RosetunSyntheticSocks : IDisposable {
    readonly TcpListener listener;
    readonly Thread worker;
    volatile TcpClient client;
    public int Port { get; private set; }

    public RosetunSyntheticSocks(string user, string password, byte authVersion, bool shortReply) {
        listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        worker = new Thread(() => Serve(user, password, authVersion, shortReply));
        worker.IsBackground = true;
        worker.Start();
    }

    static byte[] Read(Stream stream, int length) {
        byte[] bytes = new byte[length];
        for (int offset = 0; offset < length;) {
            int read = stream.Read(bytes, offset, length - offset);
            if (read == 0) throw new EndOfStreamException();
            offset += read;
        }
        return bytes;
    }

    static void Reply(Stream stream, byte version, byte result) {
        stream.WriteByte(version);
        Thread.Sleep(20);
        stream.WriteByte(result);
    }

    void Serve(string expectedUser, string expectedPassword, byte authVersion, bool shortReply) {
        try {
            client = listener.AcceptTcpClient();
            client.NoDelay = true;
            client.ReceiveTimeout = 5000;
            using (NetworkStream stream = client.GetStream()) {
                byte[] greeting = Read(stream, 2);
                byte[] methods = Read(stream, greeting[1]);
                if (greeting[0] != 5 || Array.IndexOf(methods, (byte)2) < 0) {
                    Reply(stream, 5, 255);
                    return;
                }
                Reply(stream, 5, 2);
                byte[] login = Read(stream, 2);
                string user = Encoding.UTF8.GetString(Read(stream, login[1]));
                int passwordLength = Read(stream, 1)[0];
                string password = Encoding.UTF8.GetString(Read(stream, passwordLength));
                byte result = (byte)(login[0] == 1 && user == expectedUser && password == expectedPassword ? 0 : 1);
                if (shortReply) stream.WriteByte(authVersion);
                else Reply(stream, authVersion, result);
            }
        }
        catch (IOException) { }
        catch (SocketException) { }
        catch (ObjectDisposedException) { }
    }

    public void Dispose() {
        listener.Stop();
        if (client != null) client.Dispose();
        if (!worker.Join(6000)) throw new Exception("Synthetic SOCKS peer did not stop.");
    }
}
'@

$passed = 0
function Assert-RosetunCheck {
    param([string]$Name, [bool]$Condition)
    if (-not $Condition) { throw "FAIL $Name" }
    $script:passed++
}

foreach ($case in @(
    @{ Name = 'own account'; User = 'proxy'; Password = 'fixture-password'; WithAccount = $true; Version = 1; Short = $false; Expected = 'accepted' },
    @{ Name = 'wrong password'; User = 'proxy'; Password = 'wrong-password'; WithAccount = $true; Version = 1; Short = $false; Expected = 'refused' },
    @{ Name = 'another account'; User = 'exit-0'; Password = 'fixture-password'; WithAccount = $true; Version = 1; Short = $false; Expected = 'refused' },
    @{ Name = 'no account'; User = ''; Password = ''; WithAccount = $false; Version = 1; Short = $false; Expected = 'refused' },
    @{ Name = 'invalid auth reply version'; User = 'proxy'; Password = 'fixture-password'; WithAccount = $true; Version = 2; Short = $false; Expected = 'refused' },
    @{ Name = 'truncated auth reply'; User = 'proxy'; Password = 'fixture-password'; WithAccount = $true; Version = 1; Short = $true; Expected = 'closed' }
)) {
    $peer = [RosetunSyntheticSocks]::new('proxy', 'fixture-password', [byte]$case.Version, [bool]$case.Short)
    try {
        $actual = Test-Socks -Port $peer.Port -User $case.User -Pass $case.Password -WithAccount $case.WithAccount
        Assert-RosetunCheck $case.Name ($actual -eq $case.Expected)
    }
    finally { $peer.Dispose() }
}

function Connect-RosetunTunnel {
    param([string]$RequestName, [switch]$Quiet)
    [pscustomobject]@{ ExitCode = $script:connectExit; Output = 'synthetic connect result' }
}
function Wait-RosetunState {
    param([string]$State)
    if ($State -eq 'Connected') { return $script:connected }
    return $true
}
function Disconnect-RosetunTunnel { }
function Stop-RosetunEngine { $script:stops++ }
function Stop-RosetunHelper { $script:stops++ }
function Start-RosetunHelper { $script:starts++ }
function Test-RosetunDirectDns { return $true }
function Test-RosetunIpv6Egress { return $true }
function Wait-RosetunCondition { param([scriptblock]$Condition); & $Condition }

foreach ($setup in @(
    @{ Exit = 1; Connected = $false },
    @{ Exit = 0; Connected = $false },
    @{ Exit = 0; Connected = $true }
)) {
    $script:connectExit = $setup.Exit
    $script:connected = $setup.Connected
    $script:stops = 0
    $script:starts = 0
    $results = [Collections.Generic.List[object]]::new()
    Test-RosetunDnsLockLifecycle
    if (-not $setup.Connected) {
        Assert-RosetunCheck 'each failed setup is FAIL' (@($results | Where-Object Result -eq 'FAIL').Count -eq 3)
        Assert-RosetunCheck 'dependent observations are UNRUN' (@($results | Where-Object Result -eq 'UNRUN').Count -eq 6)
        Assert-RosetunCheck 'a failed setup produces no PASS' (@($results | Where-Object Result -eq 'PASS').Count -eq 0)
        Assert-RosetunCheck 'no engine or helper is killed without a tunnel' ($stops -eq 0 -and $starts -eq 0)
    }
    else {
        Assert-RosetunCheck 'connected lifecycle scenarios execute their checks' (@($results | Where-Object Result -eq 'PASS').Count -eq 9)
        Assert-RosetunCheck 'connected scenarios exercise both crash paths' ($stops -eq 2 -and $starts -eq 1)
    }
}
Write-Host "Test-RosetunFailureChecks: $passed passed"
