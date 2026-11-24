"""What the controller runs inside a Windows guest that is on the lab's wire (stage 9d): the network, the lab's CA, the probes.

Each script is PowerShell 5.1 and runs through the agent as `windows_guest.arguments` wraps it (UTF-8 answer, one JSON
object, errors on the error stream). The scripts are generated here from the lab's constants and the run's nonces, so
the guest declares nothing: it sends what the controller says and returns what it got, and the controller compares that
with what the lab machine logged and the observer captured.

The probes are those of the Linux test machine (`lab-entry.py`): the request bytes are exactly the ones the lab's targets
accept, so the exchange is judged by the same logs. The HTTPS probe is the one thing a Windows guest does differently: it
goes through the system's own certificate validation, with the lab's CA in the machine store.
"""

import base64
import hashlib
import ipaddress
import json
import re

from . import windows_guest
from .lab_protocol import (ACK_PREFIX, CLIENTS, GATEWAYS, MACS, RESOLVER, TARGETS, answer, https_answer, marker_query,
                           token)

NIC_ADDRESS = MACS['test'].upper().replace(':', '-')
PREFIX_LENGTHS = {4: 24, 6: 64}
# How long one probe waits for the target, as the Linux helper does.
PROBE_MILLISECONDS = 5000
# The longest script of the lab that goes to the guest (`windows_guest.arguments` takes it as its limit).
SCRIPT_LIMIT = 9500
ANSWER_LIMIT = 16 * 1024
_CODE = re.compile(r'[a-z0-9:._-]{1,96}')

_NETWORK = r'''$mac = '%(mac)s'
$adapters = @(Get-NetAdapter | Where-Object { $_.MacAddress -eq $mac })
if ($adapters.Count -ne 1) { throw 'adapter-not-found' }
$index = $adapters[0].ifIndex
Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -Dhcp Disabled
Get-NetRoute -InterfaceIndex $index -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false
Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -ne '%(v4)s' } | Remove-NetIPAddress -Confirm:$false
if (@(Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq '%(v4)s' }).Count -eq 0) {
    [void](New-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4 -IPAddress '%(v4)s' -PrefixLength %(p4)d -DefaultGateway '%(g4)s')
}
if (@(Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv6 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq '%(v6)s' }).Count -eq 0) {
    [void](New-NetIPAddress -InterfaceIndex $index -AddressFamily IPv6 -IPAddress '%(v6)s' -PrefixLength %(p6)d)
}
if (@(Get-NetRoute -InterfaceIndex $index -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -eq '%(g6)s' }).Count -eq 0) {
    [void](New-NetRoute -InterfaceIndex $index -DestinationPrefix '::/0' -NextHop '%(g6)s')
}
Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses '%(dns)s'
for ($i = 0; $i -lt 150; $i++) {
    $waiting = @(Get-NetIPAddress -InterfaceIndex $index | Where-Object { ($_.IPAddress -eq '%(v4)s' -or $_.IPAddress -eq '%(v6)s') -and $_.AddressState -ne 'Preferred' })
    if ($waiting.Count -eq 0) { break }
    Start-Sleep -Milliseconds 200
}
$addresses = @(Get-NetIPAddress -InterfaceIndex $index | ForEach-Object {
    @{ address = [string]$_.IPAddress; family = [string]$_.AddressFamily; prefix = [int]$_.PrefixLength; state = [string]$_.AddressState }
})
$routes = @(Get-NetRoute -InterfaceIndex $index | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' -or $_.DestinationPrefix -eq '::/0' } | ForEach-Object {
    @{ prefix = [string]$_.DestinationPrefix; next_hop = [string]$_.NextHop }
})
$dns = @(Get-DnsClientServerAddress -InterfaceIndex $index | ForEach-Object { $_.ServerAddresses } | ForEach-Object { [string]$_ })
$dhcp = [string](Get-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4).Dhcp
ConvertTo-Json -Compress -Depth 5 -InputObject @{
    alias = [string]$adapters[0].Name; index = [int]$index; mac = [string]$adapters[0].MacAddress
    status = [string]$adapters[0].Status; dhcp4 = $dhcp; addresses = $addresses; routes = $routes; dns = $dns
}'''

_CA = r'''$der = [Convert]::FromBase64String('%(der)s')
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,$der)
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
$store.Open('ReadWrite')
$store.Add($cert)
$store.Close()
$found = @(Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $cert.Thumbprint })
ConvertTo-Json -Compress -InputObject @{ thumbprint = [string]$cert.Thumbprint; subject = [string]$cert.Subject; found = ($found.Count -eq 1) }'''

# Everything the probe script and the marker script share: the exchanges themselves. A failure of one exchange is
# that exchange's `error` (the name of the exception), never the end of the script.
_HELPERS = r'''$d = ConvertFrom-Json '%(data)s'
function Get-RosetunBytes([string]$text) { , [System.Text.Encoding]::ASCII.GetBytes($text) }
function ConvertTo-RosetunHex([byte[]]$bytes) { -join ($bytes | ForEach-Object { $_.ToString('x2') }) }
function Get-RosetunEndPoint([string]$address, [int]$port) { [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($address), $port) }
function Read-RosetunExact($stream, [int]$count) {
    $buffer = New-Object byte[] $count
    $got = 0
    while ($got -lt $count) {
        $n = $stream.Read($buffer, $got, $count - $got)
        if ($n -le 0) { throw 'short-response' }
        $got += $n
    }
    , $buffer
}
function Read-RosetunToEnd($stream) {
    $all = New-Object System.IO.MemoryStream
    $buffer = New-Object byte[] 1024
    while ($true) {
        $n = $stream.Read($buffer, 0, 1024)
        if ($n -le 0) { break }
        $all.Write($buffer, 0, $n)
        if ($all.Length -gt 2048) { throw 'response-limit' }
    }
    , $all.ToArray()
}
function Read-RosetunHttp($stream) {
    $all = New-Object System.IO.MemoryStream
    $buffer = New-Object byte[] 1024
    while ($true) {
        try { $n = $stream.Read($buffer, 0, 1024) } catch [System.IO.IOException] { $n = 0 }
        if ($n -le 0) { break }
        $all.Write($buffer, 0, $n)
        if ($all.Length -gt 2048) { throw 'response-limit' }
        $text = [System.Text.Encoding]::ASCII.GetString($all.ToArray())
        $cut = $text.IndexOf("`r`n`r`n")
        if ($cut -ge 0) {
            $m = [regex]::Match($text.Substring(0, $cut + 2), 'Content-Length: ([0-9]{1,4})')
            if ($m.Success -and ($text.Length - $cut - 4) -ge [int]$m.Groups[1].Value) { break }
        }
    }
    , $all.ToArray()
}
function Split-RosetunHttp([byte[]]$raw) {
    $text = [System.Text.Encoding]::ASCII.GetString($raw)
    $cut = $text.IndexOf("`r`n`r`n")
    if ($cut -lt 0) { throw 'http-head' }
    @{ head = $text.Substring(0, $cut + 2); body = (Get-RosetunBytes $text.Substring($cut + 4)) }
}
function New-RosetunQuery([string]$name) {
    $m = New-Object System.IO.MemoryStream
    $m.Write([byte[]](0x6a, 0x06, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0), 0, 12)
    foreach ($label in $name.Split('.')) {
        $b = Get-RosetunBytes $label
        $m.WriteByte([byte]$b.Length)
        $m.Write($b, 0, $b.Length)
    }
    $m.Write([byte[]](0, 0, 1, 0, 1), 0, 5)
    , $m.ToArray()
}
function Open-RosetunTcp([int]$family, [string]$source, [string]$target, [int]$port) {
    $kind = if ($family -eq 6) { [System.Net.Sockets.AddressFamily]::InterNetworkV6 } else { [System.Net.Sockets.AddressFamily]::InterNetwork }
    $client = New-Object System.Net.Sockets.TcpClient -ArgumentList $kind
    $client.ReceiveTimeout = %(milliseconds)d
    $client.SendTimeout = %(milliseconds)d
    $client.Client.Bind((Get-RosetunEndPoint $source 0))
    $client.Connect($target, $port)
    $client
}
function Invoke-RosetunUdp([int]$family, [string]$source, [string]$target, [int]$port, [byte[]]$request) {
    $udp = New-Object System.Net.Sockets.UdpClient -ArgumentList (Get-RosetunEndPoint $source 0)
    try {
        $udp.Client.ReceiveTimeout = %(milliseconds)d
        $udp.Connect($target, $port)
        [void]$udp.Send($request, $request.Length)
        $any = if ($family -eq 6) { [System.Net.IPAddress]::IPv6Any } else { [System.Net.IPAddress]::Any }
        $from = [System.Net.IPEndPoint]::new($any, 0)
        , $udp.Receive([ref]$from)
    } finally { $udp.Close() }
}
function Invoke-RosetunProbe($q) {
    $p = @{ f = [int]$q.f; s = [string]$q.s; n = [string]$q.n; port = [int]$d.ports.($q.s) }
    $p.src = if ($p.f -eq 6) { $d.src6 } else { $d.src4 }
    $p.dst = if ($p.f -eq 6) { $d.dst6 } else { $d.target4 }
    $text = $d.run + '.' + $p.n + '.lab.test'
    $row = @{ family = $p.f; service = $p.s; nonce = $p.n; response = $null; error = $null }
    try {
        switch ($p.s) {
            'udp' { $row.response = ConvertTo-RosetunHex (Invoke-RosetunUdp $p.f $p.src $p.dst $p.port (Get-RosetunBytes $text)) }
            'dns-udp' { $row.response = ConvertTo-RosetunHex (Invoke-RosetunUdp $p.f $p.src $p.dst $p.port (New-RosetunQuery $text)) }
            'http' {
                $client = Open-RosetunTcp $p.f $p.src $p.dst $p.port
                try {
                    $stream = $client.GetStream()
                    $request = Get-RosetunBytes ('GET /' + $text + " HTTP/1.0`r`n`r`n")
                    $stream.Write($request, 0, $request.Length)
                    $parts = Split-RosetunHttp (Read-RosetunToEnd $stream)
                    if (-not $parts.head.StartsWith("HTTP/1.0 200 OK`r`n")) { throw 'http-status' }
                    $row.response = ConvertTo-RosetunHex $parts.body
                } finally { $client.Close() }
            }
            'dns-tcp' {
                $client = Open-RosetunTcp $p.f $p.src $p.dst $p.port
                try {
                    $stream = $client.GetStream()
                    $query = New-RosetunQuery $text
                    $framed = New-Object byte[] ($query.Length + 2)
                    $framed[0] = [byte]($query.Length -shr 8)
                    $framed[1] = [byte]($query.Length -band 255)
                    [Array]::Copy($query, 0, $framed, 2, $query.Length)
                    $stream.Write($framed, 0, $framed.Length)
                    $size = Read-RosetunExact $stream 2
                    $length = $size[0] * 256 + $size[1]
                    if ($length -gt 1024) { throw 'dns-response-limit' }
                    $row.response = ConvertTo-RosetunHex (Read-RosetunExact $stream $length)
                } finally { $client.Close() }
            }
            default { throw 'unknown-service' }
        }
    } catch { $row.error = Get-RosetunError $_ }
    $row
}
function Get-RosetunError($record) {
    $e = $record.Exception
    while ($e.InnerException) { $e = $e.InnerException }
    $code = if ($e -is [System.Net.Sockets.SocketException]) { [string]$e.SocketErrorCode } else { '' }
    [string]$e.GetType().Name + ':' + $code + ':' + [string]$e.Message
}
function Send-RosetunMarker([string]$marker) {
    $row = @{ marker = $marker; ack = $null; error = $null }
    try {
        $reply = Invoke-RosetunUdp 4 $d.src4 $d.target4 $d.marker_port (Get-RosetunBytes $marker)
        $row.ack = [System.Text.Encoding]::ASCII.GetString($reply)
    } catch { $row.error = Get-RosetunError $_ }
    $row
}'''

_MARKER = r'''ConvertTo-Json -Compress -Depth 4 -InputObject (Send-RosetunMarker $d.marker)'''

_PROBES = r'''$markers = @(Send-RosetunMarker $d.open)
$probes = @($d.probes | ForEach-Object { Invoke-RosetunProbe $_ })
$https = @{ path = [string]$d.https.path; client_port = $null; response = $null; error = $null }
try {
    $client = Open-RosetunTcp 4 $d.src4 $d.https.dst $d.https.port
    try {
        $https.client_port = [int]$client.Client.LocalEndPoint.Port
        $tls = New-Object System.Net.Security.SslStream -ArgumentList $client.GetStream(), $false
        $tls.AuthenticateAsClient($d.https.dst, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)
        $request = Get-RosetunBytes ('GET ' + $d.https.path + " HTTP/1.0`r`n`r`n")
        $tls.Write($request, 0, $request.Length)
        $parts = Split-RosetunHttp (Read-RosetunHttp $tls)
        if (-not $parts.head.StartsWith("HTTP/1.0 200 OK`r`n")) { throw 'http-status' }
        $https.response = ConvertTo-RosetunHex $parts.body
    } finally { $client.Close() }
} catch { $https.error = Get-RosetunError $_ }
$resolver = @{ name = [string]$d.resolver.name; addresses = @(); error = $null }
try {
    $found = @(Resolve-DnsName -Name $d.resolver.name -Server $d.resolver.server -Type A -DnsOnly -NoHostsFile -QuickTimeout)
    $resolver.addresses = @($found | Where-Object { $_.Type -eq 'A' } | ForEach-Object { [string]$_.IPAddress })
} catch { $resolver.error = Get-RosetunError $_ }
Start-Sleep -Milliseconds 200
$markers += Send-RosetunMarker $d.close
ConvertTo-Json -Compress -Depth 5 -InputObject @{ markers = $markers; probes = $probes; https = $https; resolver = $resolver }'''


def _data(value):
    """The data a script reads, as JSON that sits in a single-quoted PowerShell string."""
    text = json.dumps(value, sort_keys=True, separators=(',', ':'))
    if "'" in text or '\n' in text:
        raise ValueError('invalid-guest-script-data')
    return text


def _compact(script):
    """The script without its indentation and blank lines: none of these scripts has a here-string or a continued line."""
    return '\n'.join(line.strip() for line in script.splitlines() if line.strip())


def _common(**data):
    return _HELPERS % dict(data=_data(data), milliseconds=PROBE_MILLISECONDS)


def network_script():
    """Set the lab's addresses on the adapter that has the test machine's MAC, and read back what stands."""
    return _compact(_NETWORK) % dict(mac=NIC_ADDRESS, v4=CLIENTS[4], p4=PREFIX_LENGTHS[4], g4=GATEWAYS[4], v6=CLIENTS[6],
                           p6=PREFIX_LENGTHS[6], g6=GATEWAYS[6], dns=RESOLVER)


class CertificateRefused(ValueError):
    pass


def certificate_der(pem):
    """The DER bytes of the one certificate a PEM file holds; anything else is refused."""
    if type(pem) is not bytes or len(pem) > 8192:
        raise CertificateRefused('invalid-ca-certificate')
    try:
        text = pem.decode('ascii')
    except UnicodeError:
        raise CertificateRefused('invalid-ca-certificate') from None
    found = re.fullmatch(r'\s*-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]{1,6000}?)\s*-----END CERTIFICATE-----\s*',
                         text)
    if found is None:
        raise CertificateRefused('invalid-ca-certificate')
    try:
        return base64.b64decode(re.sub(r'\s', '', found[1]), validate=True)
    except ValueError:
        raise CertificateRefused('invalid-ca-certificate') from None


def ca_script(der):
    return _compact(_CA) % dict(der=base64.b64encode(der).decode('ascii'))


def thumbprint(der):
    """What Windows calls a certificate's thumbprint: the SHA-1 of its DER, in capitals."""
    return hashlib.sha1(der).hexdigest().upper()  # noqa: S324 - an identifier, not a security check


def marker_script(marker):
    """One window marker from the guest to the lab's marker service, and its acknowledgement."""
    return _common(marker=marker_query(marker).decode('ascii'), src4=CLIENTS[4], target4=TARGETS[4],
                   marker_port=marker['port']) + '\n' + _MARKER


def probe_script(lab_id, probes, https, resolver_check, opening, closing):
    """The opening marker, the eight probes, the HTTPS exchange, the lab resolver's lookup and the closing marker."""
    ports = {p['service']: p['port'] for p in probes}
    if (len(probes) != 8 or {p['source'] for p in probes if p['family'] == 4} != {CLIENTS[4]}
            or {p['source'] for p in probes if p['family'] == 6} != {CLIENTS[6]}
            or {p['target'] for p in probes if p['family'] == 4} != {TARGETS[4]}
            or {p['target'] for p in probes if p['family'] == 6} != {TARGETS[6]}
            or len(ports) != 4 or len({(p['family'], p['service']) for p in probes}) != 8):
        raise ValueError('invalid-probes')
    data = dict(run=lab_id, src4=CLIENTS[4], src6=CLIENTS[6], target4=TARGETS[4], dst6=TARGETS[6],
                marker_port=opening['port'], ports=ports,
                open=marker_query(opening).decode('ascii'), close=marker_query(closing).decode('ascii'),
                probes=[dict(f=p['family'], s=p['service'], n=p['nonce']) for p in probes],
                https=dict(dst=https['target'], port=https['port'], path=https['path']),
                resolver=dict(name=token(resolver_check).decode('ascii'), server=resolver_check['target']))
    return _common(**data) + '\n' + _PROBES


def _object(text, names):
    if type(text) is not str or len(text) > ANSWER_LIMIT:
        raise windows_guest.GuestAnswerError('invalid-guest-answer')
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        raise windows_guest.GuestAnswerError('invalid-guest-answer') from None
    if type(value) is not dict or set(value) != set(names):
        raise windows_guest.GuestAnswerError('invalid-guest-answer')
    return value


def code(error):
    """The text of a guest's error as the fixed alphabet of the summaries allows: lowercase words, cut short."""
    if error is None:
        return None
    text = re.sub(r'[^a-z0-9:._-]+', '-', str(error).lower()).strip('-')[:64]
    return text if _CODE.fullmatch(text) else 'guest-error'


def network(text):
    """The guest's account of its network after `network_script`, checked in shape."""
    value = _object(text, ('alias', 'index', 'mac', 'status', 'dhcp4', 'addresses', 'routes', 'dns'))
    if (type(value['alias']) is not str or type(value['index']) is not int or type(value['mac']) is not str
            or type(value['status']) is not str or type(value['dhcp4']) is not str
            or type(value['addresses']) is not list or type(value['routes']) is not list
            or type(value['dns']) is not list or len(value['addresses']) > 32 or len(value['routes']) > 16
            or len(value['dns']) > 16):
        raise windows_guest.GuestAnswerError('invalid-guest-network')
    for row in value['addresses']:
        if (type(row) is not dict or set(row) != {'address', 'family', 'prefix', 'state'}
                or any(type(row[key]) is not str for key in ('address', 'family', 'state'))
                or type(row['prefix']) is not int):
            raise windows_guest.GuestAnswerError('invalid-guest-network')
    for row in value['routes']:
        if type(row) is not dict or set(row) != {'prefix', 'next_hop'} or any(type(v) is not str for v in row.values()):
            raise windows_guest.GuestAnswerError('invalid-guest-network')
    if any(type(item) is not str for item in value['dns']):
        raise windows_guest.GuestAnswerError('invalid-guest-network')
    return value


def network_problems(value):
    """What is not as the lab's contract says, in a reading of the guest's network; empty when it all stands."""
    problems = []
    by_address = {}
    for row in value['addresses']:
        try:
            by_address[str(ipaddress.ip_address(row['address'].split('%')[0]))] = row
        except ValueError:
            problems.append('address-unreadable')
    for family in (4, 6):
        row = by_address.get(CLIENTS[family])
        if row is None:
            problems.append('address-v%d-missing' % family)
        elif row['state'] != 'Preferred' or row['prefix'] != PREFIX_LENGTHS[family]:
            problems.append('address-v%d-not-preferred' % family)
    if value['mac'].upper() != NIC_ADDRESS:
        problems.append('adapter-mac')
    routes = {(row['prefix'], row['next_hop']) for row in value['routes']}
    for prefix, gateway in (('0.0.0.0/0', GATEWAYS[4]), ('::/0', GATEWAYS[6])):
        if (prefix, gateway) not in routes:
            problems.append('route-' + ('v4' if prefix[0] == '0' else 'v6') + '-missing')
    if value['dns'] != [RESOLVER]:
        problems.append('dns-servers')
    return problems


def certificate(text, der):
    value = _object(text, ('thumbprint', 'subject', 'found'))
    if (value['thumbprint'] != thumbprint(der) or value['found'] is not True or type(value['subject']) is not str
            or len(value['subject']) > 512):
        raise windows_guest.GuestAnswerError('invalid-guest-certificate')
    return dict(thumbprint=value['thumbprint'], subject=value['subject'])


def marker(text, wanted):
    """The acknowledgement of one marker: True only when the lab said exactly what it says for that marker."""
    value = _object(text, ('marker', 'ack', 'error'))
    sent = marker_query(wanted).decode('ascii')
    return dict(sent=value['marker'] == sent, acknowledged=value['ack'] == ACK_PREFIX + sent, error=code(value['error']))


def probes_answer(text, probes, https, resolver_check):
    """The guest's account of the probes, checked in shape and held against what each probe must have got.

    Returns the document of the probes: for each of the eight, the answer the guest got and whether it is the lab's own;
    the HTTPS exchange (the port the guest used, whether the body is the target's answer for this exchange) and the
    resolver's lookup, and the two markers.
    """
    value = _object(text, ('markers', 'probes', 'https', 'resolver'))
    if type(value['markers']) is not list or len(value['markers']) != 2 or type(value['probes']) is not list:
        raise windows_guest.GuestAnswerError('invalid-guest-answer')
    rows = []
    by_nonce = {}
    for row in value['probes']:
        if (type(row) is not dict or set(row) != {'family', 'service', 'nonce', 'response', 'error'}
                or type(row['nonce']) is not str or row['response'] is not None and type(row['response']) is not str):
            raise windows_guest.GuestAnswerError('invalid-guest-answer')
        by_nonce[row['nonce']] = row
    for p in probes:
        row = by_nonce.get(p['nonce'])
        got = None if row is None else row['response']
        rows.append(dict(p, response=got, answered=got is not None and got == answer(p).hex(),
                         error=code(row['error']) if row is not None else 'probe-missing'))
    page = value['https']
    if (type(page) is not dict or set(page) != {'path', 'client_port', 'response', 'error'}
            or page['path'] != https['path'] or page['client_port'] is not None and type(page['client_port']) is not int
            or page['response'] is not None and type(page['response']) is not str):
        raise windows_guest.GuestAnswerError('invalid-guest-answer')
    lookup = value['resolver']
    if (type(lookup) is not dict or set(lookup) != {'name', 'addresses', 'error'}
            or lookup['name'] != token(resolver_check).decode('ascii') or type(lookup['addresses']) is not list
            or any(type(item) is not str for item in lookup['addresses'])):
        raise windows_guest.GuestAnswerError('invalid-guest-answer')
    return dict(
        probes=rows,
        https=dict(path=https['path'], client_port=page['client_port'], error=code(page['error']),
                   answered=page['response'] == https_answer(https).hex()),
        resolver=dict(name=lookup['name'], addresses=lookup['addresses'], error=code(lookup['error']),
                      answered=lookup['addresses'] == [TARGETS[4]]),
        markers=value['markers'])

