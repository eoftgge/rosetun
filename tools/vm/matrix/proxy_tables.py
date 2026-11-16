"""The tables of the Linux Proxy suite in the lab (stage 8a), read by `l3_summary` in place of the L3 ones.

Same meaning as the tables of `l3_summary`, fixed here by the controller from what the functions of
`run-proxy.sh` send; the guest declares nothing. No Proxy run has been through the lab when these were
written, so every count comes from the script alone. Nothing is accepted: the release gate stays false and
the security invariants stay unverified.
"""

from .l3_summary import TARGET_FLOW, TWO_HOP

# Every scenario of scenarios-proxy.tsv but the two-hop exits, which have no check yet. `share.listens` and
# `lockdown.share-open` need a private address on the physical interface: in the lab the script adds the one
# the owner approved for that (192.168.77.2/24) before the first session.
GROUP = ('preflight.identity', 'preflight.accounts', 'preflight.no-foreign-service', 'preflight.tools',
         'preflight.baseline', 'install.service', 'proxy.through', 'proxy.around-open', 'proxy.loopback-only',
         'proxy.port-busy', 'strict.through', 'strict.around-blocked', 'strict.first-phase', 'strict.engine-killed',
         'strict.disconnect', 'mode.change', 'share.listens', 'share.peer-refused', 'share.off',
         'lockdown.share-closed', 'lockdown.share-open', 'lockdown.off', 'desktop.set', 'desktop.restore',
         'desktop.crash', 'desktop.foreign', 'stop.removes-table')
# The window of each scenario: the function of run-proxy.sh that opened the session it ran in (label, number).
WINDOW_OF = {
    'preflight.identity': None, 'preflight.accounts': None, 'preflight.no-foreign-service': None,
    'preflight.tools': None, 'preflight.baseline': None, 'install.service': None,
    # `proxy_open`, without the kill switch: the `disconnect` at the start of `busy` closes it.
    'proxy.through': ('proxy_open', 0), 'proxy.around-open': ('proxy_open', 0),
    'proxy.loopback-only': ('proxy_open', 0),
    # `busy` connects with the port taken and no connect_with: the connect must fail, so there is no session.
    'proxy.port-busy': None,
    # `strict` ends in `gone`, whose disconnect closes the window before its direct request.
    'strict.through': ('strict', 0), 'strict.around-blocked': ('strict', 0), 'strict.first-phase': ('strict', 0),
    'strict.engine-killed': ('strict', 0), 'strict.disconnect': ('strict', 0),
    # `mode_change` ends with the session up; the connect_with of `share` disconnects and closes it.
    'mode.change': ('mode_change', 0),
    # `share` (sharing without the kill switch) runs `share.peer-refused` too; the connect_with of `share_off`
    # closes it, and the disconnect at the end of `scenario_share` closes `share_off`.
    'share.listens': ('share', 0), 'share.peer-refused': ('share', 0), 'share.off': ('share_off', 0),
    # Under Lockdown the table stays, so no marker goes: one window from before `lockdown on` to after `off`.
    'lockdown.share-closed': ('lockdown_share', 0), 'lockdown.share-open': ('lockdown_share', 0),
    'lockdown.off': ('lockdown_share', 0),
    # The GUI's module writes files only; no session.
    'desktop.set': None, 'desktop.restore': None, 'desktop.crash': None, 'desktop.foreign': None,
    # Closes after the stop, once the table is gone, before the direct request.
    'stop.removes-table': ('stopped', 0),
    **dict.fromkeys(TWO_HOP),
}
OWN_WINDOW_WHEN_OPENED = {}
GROUP_LABELS = tuple(dict.fromkeys(window[0] for window in WINDOW_OF.values() if window))
WINDOWS_PER_LABEL = dict.fromkeys(GROUP_LABELS, 1)
WINDOWS_AT_MOST = {}
EXPECTED_FLOWS = {
    # `proxy.around-open`: one `direct_https` past the proxy, without the kill switch, by design. The curl through
    # the proxy is the engine's connection to the node (`tunnel`). Every other window has no entry: under the
    # kill switch or Lockdown the direct requests are dropped in the guest, and a request to the shared proxy on
    # the machine's own address never reaches the wire.
    ('proxy_open', 0): {TARGET_FLOW: 1},
}
WINDOW_ALLOWANCES = {}
# As for L3: the preflight reaches the target directly and the resolver, the proxy reaches the target through the
# node, and the helper's DNS check at connect goes through the engine's DNS, whose server is the DoH target.
REQUIRED_FIXTURES = ('node', 'https', 'dns', 'doh')
LEAK_OUTSIDE_THE_GROUP_FAILS = True
# The positive control: the service stops inside the strict window, right after `strict.through` passed.
CONTROLS = ('stop-helper',)
CONTROL_WINDOW, CONTROL_SCENARIO = 'strict', 'strict.through'
