# External proxy acceptance

Status: manual scenarios below have **not** been run. Engine syntax checks and
unit tests do not establish tunnel connectivity or firewall effectiveness.
The Linux L2 VM matrix remains unverified and is a separate prerequisite for
claims about Linux protection. If existing platform preflight refuses a session,
record that refusal; do not bypass it to mark this acceptance successful.

## Implementation boundaries

Before this change, persisted nodes and manual GUI entry did not support external
HTTP/SOCKS proxies. The SOCKS renderer was exclusively the loopback Xray bridge.
The add dialog accepted subscription URLs, not individual server links.

The add dialog now has **Add proxy**. Manual nodes use the existing subscription,
selection and exit models, with a non-fetchable `local-proxy://<id>` marker.
The card's edit action opens the same editor. Saving preserves the node ID,
selection, credentials and TLS settings. Subscription refresh skips manual nodes.
Connect, Apply, latency checks and additional-server rules use existing paths.
There is no new local application listener or networking implementation.

HTTP and HTTPS use sing-box's HTTP CONNECT outbound; HTTPS enables TLS to the
proxy. Certificate verification is mandatory for these nodes. An optional TLS
server name is available; resolving a proxy hostname to an IP preserves that
hostname for verification. SOCKS5 uses the native version-5 outbound. Xray's
existing auxiliary role and engine selection rules are unchanged: these nodes
stay on sing-box even with the preference to use Xray for compatible nodes.
The Xray renderer rejects them. They can coexist with Xray-backed extra nodes.

HTTP CONNECT has no arbitrary UDP support. sing-box 1.14.3 rejects UDP assigned
to HTTP rather than retrying it through Direct. SOCKS5 uses UDP ASSOCIATE when
the server supports it; UDP-over-TCP extensions are not enabled. A successful
TCP latency check does not establish UDP support. Explicit Direct rules and the
existing LAN setting retain their meaning.

DNS remains one DoH resolver reached by the main proxy, including for additional
server rules. It has no direct fallback. The helper's UDP query to the TUN DNS
address is intercepted and carried upstream as DoH over TCP. Resolving the proxy
itself still happens before protection, or through the existing protected lookup
path; it is distinct from resolving destinations. Readiness, DNS checks,
watchdog, rollback and emergency protection contracts are unchanged.

Settings format is 8. Migration from 7 changes the version only; older settings
retain their data and existing protocol behavior. The store retains its migration
backup and file-access rules. IPC is 13 because Node's outbound variants cross
the wire; update client and helper together. Released fixtures are unchanged.

## URI import

Use **Add proxy → Proxy URI → Fill from URI** for individual links:

```text
http://proxy.example.com:18080
http://fixture-user:fixture-password@192.0.2.10:18081#Example
https://fixture-user:fixture-password@proxy.example.com:18443
socks5://fixture-user:p%40ss%3A%2F%25@[2001:db8::10]:11081
```

An explicit port in 1..65535 is mandatory, including :443/:80. User information
is percent-decoded as UTF-8; malformed escapes, control characters and invalid
protocol credentials are rejected. HTTP usernames cannot contain a colon.
SOCKS5 authentication requires both nonempty fields, each at most 255 UTF-8
bytes. Plain HTTP can use an empty password. Credentials are optional otherwise.
IPv6 URI addresses require brackets; editor addresses use the unbracketed IP.
Queries and non-root paths are rejected; a fragment supplies the display name.
Set custom SNI in the editor rather than adding URI query parameters.

The subscription URL input retains its old meaning, including ordinary HTTPS
links. Subscription *link-list bodies* can also contain these explicit proxy
URIs. Existing JSON subscription parsing is unchanged; no new subscription
format, proxy chaining, SOCKS4 or `socks://` alias is introduced.

## Controlled lab

Run only on disposable, owner-controlled machines. The addresses below are
documentation placeholders: substitute the lab proxy IP for `192.0.2.10` and
the separate HTTP target IP for `192.0.2.20`. Do not use personal proxies,
subscription URLs or credentials. Restrict access to the lab listeners.

On the proxy machine, use an official sing-box 1.14.3 binary and create a
short-lived lab certificate:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout proxy.key -out proxy.crt -subj '/CN=proxy.example.com' \
  -addext 'subjectAltName=DNS:proxy.example.com,IP:192.0.2.10' \
  -addext 'basicConstraints=critical,CA:TRUE'
chmod 600 proxy.key
```

Save the following as `proxy-lab.json` beside the certificate. Substitute the
listener IP too. This is a test server configuration, not a Rosetun listener.

```json
{
  "log": { "level": "info" },
  "inbounds": [
    { "type": "http", "tag": "http-open", "listen": "192.0.2.10", "listen_port": 18080 },
    { "type": "http", "tag": "http-auth", "listen": "192.0.2.10", "listen_port": 18081,
      "users": [{ "username": "fixture-user", "password": "fixture-password" }] },
    { "type": "http", "tag": "https-auth", "listen": "192.0.2.10", "listen_port": 18443,
      "users": [{ "username": "fixture-user", "password": "fixture-password" }],
      "tls": { "enabled": true, "certificate_path": "proxy.crt", "key_path": "proxy.key" } },
    { "type": "socks", "tag": "socks-open", "listen": "192.0.2.10", "listen_port": 11080 },
    { "type": "socks", "tag": "socks-auth", "listen": "192.0.2.10", "listen_port": 11081,
      "users": [{ "username": "fixture-user", "password": "fixture-password" }] }
  ],
  "outbounds": [{ "type": "direct", "tag": "direct" }],
  "route": { "final": "direct" }
}
```

```sh
sing-box version
sing-box check -c proxy-lab.json
sing-box run -c proxy-lab.json
```

On the target machine, from an empty directory containing only a test file:

```sh
printf 'proxy fixture\n' > probe.txt
python3 -m http.server 18000 --bind 192.0.2.20
```

In the disposable Rosetun client VM, trust `proxy.crt` in the system trust store
used by the helper. Debian: copy it to
`/usr/local/share/ca-certificates/rosetun-proxy-lab.crt` and run
`sudo update-ca-certificates`. Windows: in an administrator terminal run
`certutil -addstore Root proxy.crt`. Revert the VM snapshot afterwards, including
this test trust entry. This trust setup is solely for the disposable lab.

## Manual checks

1. Install matching client/helper builds. Record OS, build SHA and engine
   versions. Keep an out-of-band VM console. Use the existing supported session
   protection configuration; do not change Lockdown to make a test pass. In
   Rosetun, add HTTP at the lab proxy IP, port 18080, no credentials. Select it,
   run the full server check and connect. With default routing through the proxy,
   add an explicit target-IP rule through the main server (so LAN bypass cannot
   invalidate the test). Run `curl --noproxy '*' --max-time 15
   http://192.0.2.20:18000/probe.txt` (`curl.exe` on Windows). Expect the fixture
   body, a request on the target and a CONNECT on the proxy. A TCP ping alone is
   insufficient. Repeat after restarting the GUI to confirm persistence.
2. Repeat HTTP using port 18081 and the synthetic username/password above. Edit
   the saved node, change its name and reopen it: address, protocol, credentials
   and TLS fields must survive. For Unicode/special-character coverage, change
   the lab server's user/password to synthetic UTF-8 values and import their
   percent-encoded URI. Do not include credentials in returned logs.
3. Add HTTPS at port 18443 with those credentials and TLS server name
   `proxy.example.com`. Expect CONNECT over TLS and the same target response.
   Change SNI to `wrong.example.com`: connection must fail certificate validation.
   Revert SNI and remove the lab trust entry in a disposable snapshot: connection
   must fail again. No automatic insecure retry is acceptable.
4. Repeat SOCKS5 on ports 11080 (no authentication) and 11081 (authentication).
   Verify the target body and SOCKS server connection. Repeat with an IPv6 lab
   address when the lab has IPv6, using brackets in URI and no brackets in the
   editor. A hostname variant should resolve the proxy and preserve HTTPS SNI.
5. While HTTP 18080 is connected, select the authenticated SOCKS5 node and Apply
   pending changes. Repeat the request: it must use the new proxy. Repeat with
   HTTPS. Add an additional-server exit rule for the target and verify its proxy
   log. Preserve an explicit Direct rule for a second controlled target and
   verify it remains Direct. Account for existing LAN bypass rules explicitly.
6. Set a wrong password and then try an unused proxy port. Expect a failed full
   check/connect; a failed Apply must restore the old working session. Do not
   treat an old-session response after rollback as success for the new node.
   Repeat stopping the proxy after Connected. Record existing reconnect/failure
   state and verify no alternate outbound carries proxy-assigned flows.
7. Capture the client's physical interface while running the target request,
   both successfully and during proxy failures (for example,
   `sudo tcpdump -ni <physical-interface> 'host 192.0.2.20 and port 18000'` in the
   Linux lab, or an equivalent Wireshark filter on Windows). There must be no
   client-to-target TCP packets while the running session assigns that target
   to the proxy. Capture before the request and inspect all physical interfaces.
   This does not redefine protection after Disconnect, fresh-connect failure or
   helper failure; those remain the existing platform contracts.
8. Run `nslookup example.com` through each established session. Verify the DNS
   path through the proxy in the lab capture. Block DoH at the proxy machine's
   lab egress using the owner's controlled network fixture: DNS/readiness must
   fail, with no physical-client plaintext DNS fallback for destinations. The
   initial lookup of the proxy's own hostname is a separate permitted bootstrap
   operation. Restore the lab network before the next case.
9. With a controlled UDP echo target and an explicit target-IP proxy rule, send
   a UDP datagram while HTTP/HTTPS is connected. Expect no echo and no direct
   client-to-target packet; DNS should still work through DoH. With SOCKS5, expect
   echo only if UDP ASSOCIATE and its relay are reachable. Repeat blocking the
   relay: expect failure, never Direct. Capture UDP as well as TCP. Browser QUIC
   falling back to TCP through the same proxy is acceptable.
10. Save a diagnostic report with detailed logging both off and on. Search for
    the synthetic username, password and full URI: none may appear. Return only
    scrubbed logs, OS/build versions, failed step, selected protocol, helper
    state and captures limited to these synthetic lab addresses. Do not mark
    any of these scenarios passed until the owner executes it.
