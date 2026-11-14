# Two-hop proxy exits

Available in development builds. Network qualification is still pending on Windows and Linux.

1. Add servers A and B, then create their exits on the **Exits** tab.
2. Edit exit B. Set **Connect through** to exit A and save. The path reads **A → B**.
3. Point the desired rule at **B**. Use **Apply** for a running connection.

This changes traffic selected by that rule. It does not automatically route all machine traffic through B. In System proxy mode, an application must use the local proxy; independent traffic retains its existing rules and protection settings.

**Directly** in B's editor restores the ordinary connection to B's server. It does not select the rule destination **Direct**. Cancel discards the editor draft. A failed Apply restores the saved rules, DNS and exit paths; temporary rules are preserved. An exit used by another exit cannot be deleted: change the dependent exit's path first.

## Current limits

- Exactly two exits. No self-reference, cycles or third hop.
- B supports HTTP CONNECT, HTTPS CONNECT and SOCKS5 TCP. Its server must be an IPv4 or IPv6 literal. HTTPS still verifies the certificate; configure the expected TLS server name where needed.
- A must use a supported native sing-box outbound. Xray on either hop, a standalone Xray engine and TLS fragmentation are unsupported for this path.
- B's server cannot be a DNS name. It is rejected before connecting; there is no local bootstrap DNS lookup of B. Resolving A follows the existing bootstrap policy. Destination DNS follows the configured DNS policy, so this feature does not promise that all DNS traverses B.
- UDP, including QUIC, selected by a rule through B is blocked. It does not fall back to A or Direct. Other rules retain their existing behaviour.
- A missing dependency, unavailable endpoint, bad credentials or a failed HTTPS handshake does not select a shorter path. A changed subscription, country fallback or mode is checked again against the actual request by the helper.
- B's delay measures the full A → B path. The connection screen's primary exit IP describes the primary route; it is not evidence of B's public IP.

Documentation values such as A at `192.0.2.10` and B at `198.51.100.20` illustrate the configuration only; they are not runnable proxies.

## Network qualification

See the [Windows scenarios](tools/vm/windows/README.md#two-hop-exits) and [Linux scenarios](tools/vm/linux/README.md#two-hop-exits). The legacy stands currently report these observations as **UNRUN**. A passing unit test or rendered configuration is not network acceptance.
