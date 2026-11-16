"""The summary of an L3 run in the lab: what the script reported, what the observer saw, and the exit code.

Nothing here accepts anything. The group (stage 7b2b, widened by 7c2) is judged against its windows; the
other scenarios are listed with what the script reported and are not judged. A window where direct traffic
is expected by design is held against that exact traffic (stage 7c3). The release gate stays false and the
security invariants stay unverified.
"""

from collections import Counter

from .lab_protocol import CLIENTS, HTTPS_PORT, PORTS, RESOLVER, TARGETS

# The scenarios that are judged, by id in scenarios-l3.tsv: those of stage 7b2b, then those of 7c2, every other
# session under the kill switch where no direct traffic is expected, then those of 7c3, whose windows show direct
# traffic by design and are held against EXPECTED_FLOWS, then the Local network sessions of 7e.
GROUP = ('preflight.identity', 'preflight.accounts', 'preflight.no-foreign-service', 'preflight.tools',
         'preflight.baseline', 'install.service', 'protection.reported', 'engine.identity', 'engine.files',
         'killswitch.direct-blocked', 'killswitch.tunnel-passes', 'lan.off', 'killswitch.foreign-table',
         'killswitch.engine-killed', 'killswitch.flush-restored', 'killswitch.disconnect',
         'rules.capabilities', 'rules.restart-guarded', 'rules.search-misses', 'inbound.reply', 'forward.blocked',
         'crash.helper-killed', 'crash.open-network', 'crash.five-kills', 'upgrade.restart', 'upgrade.unprotected',
         'stop.removes-table', 'rules.direct-other-account', 'rules.proxy-default-direct', 'dnslock.direct-blocked',
         'dnslock.tunnel-passes', 'dnslock.unavailable', 'dnslock.unavailable-restart', 'crash.dns-lock-killed',
         'route.specific-bypass', 'lan.on', 'lan.private-closed', 'lan.private-open', 'lan.follows-change',
         'ipv6.neighbor')
# The scenarios of the two-hop exits: they have no check yet (evidence class `not-run`, not required), `run-l3.sh`
# records each as SKIP "UNRUN: ..." before any session opens, so they belong to no group and no window.
TWO_HOP = ('two-hop.positive.http.ipv4', 'two-hop.positive.http.ipv6', 'two-hop.positive.https.ipv4',
           'two-hop.positive.https.ipv6', 'two-hop.positive.socks5.ipv4', 'two-hop.positive.socks5.ipv6',
           'two-hop.domain-b', 'two-hop.a-unavailable', 'two-hop.b-unavailable', 'two-hop.b-auth',
           'two-hop.https-certificate', 'two-hop.udp-quic', 'two-hop.apply-rollback-reconnect',
           'two-hop.engine-restart', 'two-hop.dependency-removed', 'two-hop.lockdown', 'two-hop.allow-lan',
           'two-hop.target-subscription-fallback', 'two-hop.xray-fragment',
           'two-hop.positive.xray-first-hop')
# The window each scenario ran in: the label of the window and its number among the windows with that label,
# from zero. A window is a protected session and its label is the function of run-l3.sh that opened it
# (connect_with is called from that function), so scenarios that share a session share a window: `identity`
# opens the session `files` ends, `connect_ks` opens the one that `killswitch.direct-blocked` to
# `killswitch.disconnect` run in. Only that one window is judged for the scenario: a function may open more
# than one session (`capabilities` does), and a window with the same label beyond the expected ones (an
# implicit `disconnect`, a scenario skipped after a FAIL) is listed and judged by nothing. None: no protected
# session at all.
WINDOW_OF = {
    'preflight.identity': None, 'preflight.accounts': None, 'preflight.no-foreign-service': None,
    'preflight.tools': None, 'preflight.baseline': None, 'install.service': None,
    'protection.reported': ('reported', 0),
    'engine.identity': ('identity', 0), 'engine.files': ('identity', 0),
    'killswitch.direct-blocked': ('connect_ks', 0), 'killswitch.tunnel-passes': ('connect_ks', 0),
    'lan.off': ('connect_ks', 0), 'killswitch.foreign-table': ('connect_ks', 0),
    'killswitch.engine-killed': ('connect_ks', 0), 'killswitch.flush-restored': ('connect_ks', 0),
    'killswitch.disconnect': ('connect_ks', 0),
    # The first session of `capabilities` is under the kill switch; the second has a rule that sends a program
    # direct, and `rules.direct-other-account` runs in it.
    'rules.capabilities': ('capabilities', 0), 'rules.restart-guarded': ('restart_guarded', 0),
    # Recorded after `rules.restart-guarded`, before the `disconnect` that closes its window.
    'rules.search-misses': ('restart_guarded', 0),
    'inbound.reply': ('inbound', 0), 'forward.blocked': ('inbound', 0),
    # `opened` ends the session `killed` opened: the window closes once open-network removed the table.
    'crash.helper-killed': ('killed', 0), 'crash.open-network': ('killed', 0),
    'crash.five-kills': ('five_kills', 0), 'upgrade.restart': ('upgraded', 0),
    'upgrade.unprotected': None, 'stop.removes-table': ('stopped', 0),
    # Stage 7c3. `direct_for_other_account` keeps the second session of `capabilities`; the `connect_with` of
    # `through_vpn_by_program` closes that window, and the one of `restart_guarded` closes its own.
    'rules.direct-other-account': ('capabilities', 1), 'rules.proxy-default-direct': ('through_vpn_by_program', 0),
    # `dns_tunnel` runs in the session `dns_lock` opened and ends it.
    'dnslock.direct-blocked': ('dns_lock', 0), 'dnslock.tunnel-passes': ('dns_lock', 0),
    'dnslock.unavailable': ('dns_lock_unavailable', 0),
    # `dns_lock_unavailable_restart` gives nft its mode back, then ends the session `missing_through_restart` opened.
    'dnslock.unavailable-restart': ('missing_through_restart', 0),
    'crash.dns-lock-killed': ('dns_lock_killed', 0),
    # Judged in its kill-switch session only, as its result is: the session with a DNS lock alone that follows
    # (`specific_bypass_dns_lock`) adds to the note and stays outside the group, held against its expectation.
    'route.specific-bypass': ('specific_bypass', 0),
    # Stage 7e. Each function of `scenario_lan_on` opens its own session and ends it.
    'lan.on': ('lan_on', 0), 'lan.private-closed': ('lan_private_closed', 0),
    'lan.private-open': ('lan_private_open', 0), 'lan.follows-change': ('lan_follows_change', 0),
    # The session of `neighbor` in `scenario_ipv6`, which in the lab has the lab's link-local address as its IPv6
    # router (test image v6b); without that router the scenario is SKIP and opens no window.
    'ipv6.neighbor': ('neighbor', 0),
    **dict.fromkeys(TWO_HOP),
}
# A scenario that opens a session of its own only when none is open: `forwarded` connects only if `inbound`
# did not (it stopped before its connect, or the session was lost), and its window is then the one judged.
# `direct_for_other_account` connects only if the second session of `capabilities` is gone.
OWN_WINDOW_WHEN_OPENED = {'forward.blocked': ('forwarded', 0),
                          'rules.direct-other-account': ('direct_for_other_account', 0)}
GROUP_LABELS = tuple(dict.fromkeys(window[0] for window in WINDOW_OF.values() if window))
# How many windows each label of the group has in a run where every scenario passed (`lab.window_counts`).
# Another count is a run whose sessions are not numbered as the script numbers them, so it cannot vouch for
# itself (exit 2), and a leak in a window beyond the count is a finding like a leak in a judged window.
WINDOWS_PER_LABEL = {'reported': 1, 'identity': 1, 'connect_ks': 1, 'capabilities': 2, 'restart_guarded': 1,
                     'inbound': 1, 'killed': 1, 'five_kills': 1, 'upgraded': 1, 'stopped': 1,
                     'through_vpn_by_program': 1, 'dns_lock': 1, 'dns_lock_unavailable': 1,
                     'missing_through_restart': 1, 'dns_lock_killed': 1, 'specific_bypass': 1, 'lan_on': 1,
                     'lan_private_closed': 1, 'lan_private_open': 1, 'lan_follows_change': 1, 'neighbor': 1}
# Labels whose session opens only now and then (OWN_WINDOW_WHEN_OPENED, or the DNS-lock session of
# `route.specific-bypass`, which runs only after its kill-switch part passed): at most this many windows.
WINDOWS_AT_MOST = {'forwarded': 1, 'direct_for_other_account': 1, 'specific_bypass_dns_lock': 1}
# The flows a window shows beyond the tunnel and the lab's infrastructure by design (stage 7c3), by (label,
# number): each a flow the test machine opens, (protocol, kind, server) with its exact count. They are fixed
# here, by the controller, from what the functions of run-l3.sh send; the guest declares nothing. A flow is a
# connection or an exchange by four-tuple, so a SYN or a datagram sent again stays one flow (curl's TFTP request
# goes twice when the reply is no TFTP). A window without an entry is judged as before: anything is a leak.
TARGET_FLOW = ('tcp', 'target', f'{TARGETS[4]}:{HTTPS_PORT}')
RESOLVER_FLOW = ('udp', 'resolver', f"{RESOLVER}:{PORTS['dns-udp']}")
# The two addresses of Local network in run-l3.sh with the lab's addresses (stage 7e). `neighbor_address` takes
# the first of .250, .251, .252 in the test machine's /24 that is neither its own address nor the host node's:
# with 192.0.2.2 and 192.0.2.1, 192.0.2.250, which nobody holds, so the TFTP datagram to it never gets past the
# ARP requests for it. `behind_router_address` takes the first private address outside the test machine's first
# two octets: 10.254.254.1, which the lab routes nowhere, so its router answers each datagram with a destination
# unreachable (part of the flow). TFTP is port 69.
LAN_NEIGHBOR = CLIENTS[4].rsplit('.', 1)[0] + '.250'
BEHIND_ROUTER = '10.254.254.1'
TFTP_PORT = 69
NEIGHBOR_FLOW = ('arp', 'neighbor', LAN_NEIGHBOR)
BEHIND_ROUTER_FLOW = ('udp', 'other', f'{BEHIND_ROUTER}:{TFTP_PORT}')
EXPECTED_FLOWS = {
    # `direct_for_other_account`, in the second session of `capabilities` (or its own when that one is gone): two
    # `route_of`, the curl of the other account goes direct (one connection), the other program through the tunnel.
    ('capabilities', 1): {TARGET_FLOW: 1},
    ('direct_for_other_account', 0): {TARGET_FLOW: 1},
    # `through_vpn_by_program`: the same, the other way round; the other program goes direct.
    ('through_vpn_by_program', 0): {TARGET_FLOW: 1},
    # `dns_lock`: UDP 53 is refused locally (no frame), one `direct_https` answers; `dig` goes through the tunnel.
    ('dns_lock', 0): {TARGET_FLOW: 1},
    # `dns_lock_unavailable` and `missing_through_restart`: one `expect_udp_dns_sent` each, to the lab resolver.
    ('dns_lock_unavailable', 0): {RESOLVER_FLOW: 1},
    ('missing_through_restart', 0): {RESOLVER_FLOW: 1},
    # `dns_lock_killed`: the `direct_https` of `kill_helper` while the lock still stands; the window closes once
    # the restarted helper removed the lock, before `expect_udp_dns_sent` and the last `direct_https`.
    ('dns_lock_killed', 0): {TARGET_FLOW: 1},
    # `specific_bypass_dns_lock`: with a route to the target more specific than the default, the one request of
    # `route_of` leaves directly (a known weakness, characterised, not fixed). The kill-switch session before it
    # has no entry: its `tunnel_https` and `direct_https` are both dropped in the guest and show nothing.
    ('specific_bypass_dns_lock', 0): {TARGET_FLOW: 1},
    # Stage 7e. `lan_on`: one `expect_udp_sent_to` the neighbor, which leaves the guest and asks for it on the link
    # (as many requests as the kernel sends, one flow); the host node and the probe address are dropped in the guest.
    ('lan_on', 0): {NEIGHBOR_FLOW: 1},
    # `lan_private_open`: one `expect_udp_sent_to` the private address behind the gateway (one source port, sent
    # again without an answer), one to the neighbor; UDP 53 there, the host node and the probe are dropped in the
    # guest. `lan_private_closed` and `lan_follows_change` send nothing past the guest and have no entry.
    ('lan_private_open', 0): {BEHIND_ROUTER_FLOW: 1, NEIGHBOR_FLOW: 1},
}
# Allowances that hold in the windows of one label only (stage 7e). In `neighbor` the test machine pings the lab's
# link-local address, its IPv6 router, under the kill switch with Local network: the echo request and the reply
# are counted as allowed there and are unexpected in every other window. The neighbor discovery around them is
# infrastructure anyway. The window has no expectation: the datagram to 2001:db8::1 is refused in the guest.
WINDOW_ALLOWANCES = {'neighbor': ('ipv6-link-local-echo',)}
# What the observer must have seen of the lab for the group to mean anything. DoH is required too: the
# helper's DNS check at connect (`check_cancellable` in `state/dns.rs`) goes through the DoH server that
# `dns_section` of the sing-box render configures, so no scenario connects without it.
REQUIRED_FIXTURES = ('node', 'https', 'dns', 'doh')
# Whether a leak seen in a window outside the group changes the exit code: since stage 7e it does, so every window
# of a run is judged. A window is outside when no scenario of the group is judged in it and it is not beyond the
# count of a label of the group. A run expects one: the DNS-lock session of `route.specific-bypass`, which only adds
# to that scenario's note and is held against its expectation; a window of a label no table names (a function of
# the script that opened a session nobody expected) is the other kind. A leak in either, DETECTED after the
# expectation, is a finding (`leak-outside-group`, the window in `group.outside_leaks`); EXPECTED is no leak, and a
# MISMATCH there characterises the weakness rather than a protection, so it is listed (`group.outside_mismatches`)
# and changes no code. Any other verdict (UNVERIFIED) is a window that cannot vouch for itself: without a finding
# the run exits 2 (`outside-window-not-verified:<label>:<number>:<verdict>` in `group.unproven`).
LEAK_OUTSIDE_THE_GROUP_FAILS = True
# The positive control of stage 7c1: the script stops the service inside the window of the kill-switch
# session and sends one direct request, so a run is a success only if the observer saw exactly that.
CONTROLS = ('stop-helper',)
CONTROL_WINDOW, CONTROL_SCENARIO = 'connect_ks', 'killswitch.direct-blocked'
CONTROL_EXPECTATIONS = {
    'stop-helper': f'window {CONTROL_WINDOW} DETECTED with a direct flow from the test machine to '
                   f'{TARGETS[4]}:{HTTPS_PORT}, {CONTROL_SCENARIO} DISAGREE, an ordinary run would exit 1'}


def expectation_verdict(window, expected):
    """The verdict of a window against what the controller expects of it: a Counter of (protocol, kind, server).

    EXPECTED: every unexpected frame belongs to a flow the test machine opened and that the expectation names, in
    exactly the expected number. DETECTED: anything else, or more of an expected flow, whatever else went wrong.
    UNVERIFIED: nothing beyond the expectation, but the window cannot vouch for itself. MISMATCH: fewer flows
    than expected in a window that can, so something the script says went out was not seen.
    """
    direct = window.get('direct')
    if direct is None:
        # No record of the flows (not an L3 capture): only a window without unexpected frames can be compared.
        if window['leak'] == 'DETECTED':
            return 'DETECTED'
        direct = dict(flows=[], other_frames=0, omitted_frames=0)
    seen, beyond = Counter(), direct['other_frames'] + direct['omitted_frames']
    for flow in direct['flows']:
        key = (flow['protocol'], flow['kind'], flow['server'])
        if flow['opened'] is True and key in expected:
            seen[key] += 1
        else:
            beyond += 1
    if beyond or any(seen[key] > count for key, count in expected.items()):
        return 'DETECTED'
    if window.get('observer_reasons') or window['leak'] == 'UNVERIFIED':
        return 'UNVERIFIED'
    return 'EXPECTED' if seen == Counter(expected) else 'MISMATCH'


def expected_flows(expected):
    """The expectation of a window as the summary lists it."""
    return [dict(protocol=protocol, kind=kind, server=server, direction='out', count=count)
            for (protocol, kind, server), count in (expected or {}).items()]


def window_verdict(windows):
    """One verdict for the judged windows of a scenario: a leak anywhere wins, then a mismatch, then anything unproven."""
    verdicts = {window.get('verdict', window['leak']) for window in windows}
    for verdict in ('DETECTED', 'MISMATCH', 'UNVERIFIED'):
        if verdict in verdicts:
            return verdict
    if not verdicts:
        return None
    return 'EXPECTED' if 'EXPECTED' in verdicts else 'NONE'


def window_of(identifier, windows):
    """The (label, number) of the window the scenario is judged in, or None."""
    own = OWN_WINDOW_WHEN_OPENED.get(identifier)
    if own is not None and any(window['label'] == own[0] for window in windows):
        return own
    return WINDOW_OF[identifier]


def numbered(windows):
    """(label, number) of each window, in the order of the capture: the number counts earlier windows with that label."""
    seen, pairs = {}, []
    for window in windows:
        number = seen.get(window['label'], 0)
        seen[window['label']] = number + 1
        pairs.append((window['label'], number))
    return pairs


def judged_windows(window, windows):
    """The one window named by (label, number), as a list of zero or one.

    With fewer windows of the label than expected, nothing says which session is missing, so none of them is
    judged: the scenario is unobserved rather than judged in another session's window. With more, the expected
    ones keep their numbers, because a session the script opens again comes after them.
    """
    label, number = window
    if [found['label'] for found in windows].count(label) < WINDOWS_PER_LABEL.get(label, number + 1):
        return []
    return [found for found, pair in zip(windows, numbered(windows)) if pair == window]


def agree(legacy, verdict):
    """The rules of the study: a pass is confirmed by a clean window or one that showed exactly what was expected,
    contradicted by a leak or by expected traffic that was not seen, and unconfirmed by anything else; every other
    result stays what the script said."""
    if legacy != 'PASS':
        return 'NOT_APPLICABLE'
    return {'NONE': 'AGREE', 'EXPECTED': 'AGREE', 'DETECTED': 'DISAGREE',
            'MISMATCH': 'DISAGREE'}.get(verdict, 'UNOBSERVED')


def crosscheck(rows, windows):
    """One row per scenario of the group: its result, its window and whether the two agree."""
    table = []
    for identifier in GROUP:
        legacy = rows[identifier]['result'] if identifier in rows else 'MISSING'
        window = window_of(identifier, windows)
        row = dict(id=identifier, legacy_result=legacy, window=window and window[0],
                   window_number=window and window[1], windows=[], window_verdict=None)
        if window is None:
            row['agreement'] = 'NOT_APPLICABLE'
        else:
            found = judged_windows(window, windows)
            row.update(windows=[found_window['index'] for found_window in found], window_verdict=window_verdict(found),
                       agreement=agree(legacy, window_verdict(found)))
        table.append(row)
    return table


def window_counts(windows):
    """For each label of the group, and each that may stand in for one: the windows expected and those seen."""
    seen = [window['label'] for window in windows]
    rows = [dict(label=label, expected=WINDOWS_PER_LABEL[label], at_most=None, seen=seen.count(label),
                 as_expected=seen.count(label) == WINDOWS_PER_LABEL[label]) for label in GROUP_LABELS]
    return rows + [dict(label=label, expected=None, at_most=limit, seen=seen.count(label),
                        as_expected=seen.count(label) <= limit) for label, limit in WINDOWS_AT_MOST.items()]


def window_limit(label):
    """How many windows the label may have, or None for a label outside the group."""
    return WINDOWS_PER_LABEL.get(label) if label in GROUP_LABELS else WINDOWS_AT_MOST.get(label)


def direct_flow_seen(windows):
    """A TCP connection of the test machine straight to the HTTPS target that the target answered, in these windows."""
    server = f'{TARGETS[4]}:{HTTPS_PORT}'
    for window in windows:
        for row in (window.get('flows') or {}).get('connections', []):
            if (row.get('server') == server and str(row.get('client')).startswith(CLIENTS[4] + ':')
                    and row.get('kind') == 'target' and row.get('syn') is True and row.get('syn_ack') is True):
                return True
    return False


def missing_fixtures(fixtures):
    return [name for name in REQUIRED_FIXTURES if not (fixtures.get(name) or {}).get(
        'alive_at_finish' if name == 'node' else 'answered')]


def decide(result, interrupted):
    """Fill the cross-check and the exit code of the stage.

    0: the whole group passed, every cross-check row agrees or does not apply, the observer is clean,
    the fixtures answered, the evidence disk is verified and both machines completed.
    1: the run found something: a scenario of the group failed, a pass is contradicted by a window
    (DISAGREE), or a leak in a judged window or in a window of a label of the group beyond its count, or,
    with LEAK_OUTSIDE_THE_GROUP_FAILS (since stage 7e), a leak in any other window. A seen leak and a failed check stand whatever else went wrong, so 1
    comes before 2.
    2: nothing was found but the run cannot vouch for itself: a controller error, a machine that did
    not stop, no report, an unverified evidence disk, a fixture that did not answer, an unclean
    observer, a pass nobody observed (UNOBSERVED, which includes a window that never closed), a
    scenario of the group that did not run, or a label of the group with another count of windows than
    expected, or (since stage 7e) a window outside the group that is not verified. 130: interrupted.
    A diagnostic run (`diagnostic: true`) never exits below 2, whatever it found: what it found stays
    in `outcome` and `group`, but it is not counted toward a qualification.
    Scenarios outside the group change nothing.
    A window with an expectation (EXPECTED_FLOWS) has the verdict of the comparison with it: EXPECTED confirms
    a pass like NONE, MISMATCH contradicts it like DETECTED, and only DETECTED is a leak.
    """
    legacy, lab = result['legacy'], result['lab']
    rows = {row['id']: row for row in legacy['scenarios']}
    windows = lab['windows']
    # Each window's verdict: the observer's own, or for a window with an expectation the comparison with it.
    for window, (label, number) in zip(windows, numbered(windows)):
        limit = window_limit(label)
        expected = EXPECTED_FLOWS.get((label, number))
        window.update(number=number, beyond=limit is not None and number >= limit,
                      expected_flows=expected_flows(expected),
                      verdict=window['leak'] if expected is None else expectation_verdict(window, expected))
    table = crosscheck(rows, windows)
    result['crosscheck'] = table
    # The windows a row of the cross-check names are judged. A window of a label of the group beyond its
    # count is a session nobody expected and has no expectation: a leak in it is a finding all the same. A
    # window within the count that no scenario of the group judges (none since stage 7c3) is outside.
    judged = {index for row in table for index in row['windows']}
    for window in windows:
        window['judged'] = window['index'] in judged
    lab['window_counts'] = window_counts(windows)
    result['out_of_scope'] = [dict(id=row['id'], legacy_result=row['result'], agreement='out-of-scope')
                              for row in legacy['scenarios'] if row['id'] not in GROUP]
    results = {identifier: rows[identifier]['result'] if identifier in rows else 'MISSING' for identifier in GROUP}
    failed = [i for i, outcome in results.items() if outcome == 'FAIL']
    not_run = [i for i, outcome in results.items() if outcome not in ('PASS', 'FAIL')]
    qualification = lab['qualification']
    findings, unproven = [], []
    if failed:
        findings.append('group-scenario-failed')
    if any(row['agreement'] == 'DISAGREE' for row in table):
        findings.append('pass-contradicted-by-window')
    if any(window['verdict'] == 'DETECTED' and (window['judged'] or window['beyond']) for window in windows):
        findings.append('leak-in-group-window')
    unjudged = [window for window in windows if not window['judged'] and not window['beyond']]
    outside = [window['label'] for window in unjudged if window['verdict'] == 'DETECTED']
    # A label of the group with fewer windows than expected cannot be numbered, so none of its windows is judged
    # and what one of them should show is unknown (`capabilities` 0 shows nothing, 1 a direct request): such a
    # window is listed, and the run cannot vouch for itself (`window-count`), but it is no finding of its own.
    short = {row['label'] for row in lab['window_counts'] if row['expected'] is not None and not row['as_expected']
             and row['seen'] < row['expected']}
    if any(label not in short for label in outside) and LEAK_OUTSIDE_THE_GROUP_FAILS:
        findings.append('leak-outside-group')
    if result['errors']:
        unproven.append('controller-error')
    if not result['completed']:
        unproven.append('machine-not-completed')
    if not rows:
        unproven.append('no-report')
    elif not_run and not failed:
        unproven.append('group-scenario-did-not-run')
    if not qualification['evidence']['verified']:
        unproven.append('evidence-disk')
    missing = missing_fixtures(qualification['fixtures'])
    if missing:
        unproven.append('fixtures-not-seen:' + ','.join(missing))
    if qualification['observer']['reasons']:
        unproven.append('observer-not-clean')
    if any(row['agreement'] == 'UNOBSERVED' for row in table):
        unproven.append('pass-not-observed')
    for row in lab['window_counts']:
        if not row['as_expected']:
            wanted = row['expected'] if row['expected'] is not None else f"at-most-{row['at_most']}"
            unproven.append(f"window-count:{row['label']}:expected={wanted},seen={row['seen']}")
    # Every window is judged: one outside the group that cannot vouch for itself leaves the run unable to vouch.
    for window in unjudged:
        if window['verdict'] not in ('NONE', 'EXPECTED', 'MISMATCH', 'DETECTED'):
            unproven.append(f"outside-window-not-verified:{window['label']}:{window['number']}:{window['verdict']}")
    if result.get('diagnostic'):
        unproven.append('diagnostic-run')
    result['group'] = dict(scenarios=list(GROUP), results=results, passed=all(o == 'PASS' for o in results.values()),
                           failed=failed, not_run=not_run, labels=list(GROUP_LABELS),
                           missing_labels=lab['missing_labels'], outside_leaks=outside,
                           outside_windows=[dict(label=window['label'], number=window['number'],
                                                 verdict=window['verdict']) for window in unjudged],
                           outside_mismatches=[window['label'] for window in unjudged
                                               if window['verdict'] == 'MISMATCH'],
                           findings=findings, unproven=unproven)
    if interrupted:
        result['exit_code'], result['outcome'] = 130, 'interrupted'
    elif findings:
        result['exit_code'], result['outcome'] = 1, 'findings'
    elif unproven:
        result['exit_code'], result['outcome'] = 2, 'unverified'
    else:
        result['exit_code'], result['outcome'] = 0, 'group-clean'
    if result.get('diagnostic') and result['exit_code'] < 2:
        # A run that asked the engine for more detail is evidence for a diagnosis, never a qualification.
        result['exit_code'] = 2
    control = result.get('control')
    if control is not None:
        # The ordinary code stays in the summary; the code of the run is the control's own.
        direct = judged_windows(WINDOW_OF[CONTROL_SCENARIO], windows)
        row = next(row for row in table if row['id'] == CONTROL_SCENARIO)
        met = (control in CONTROLS and result['exit_code'] == 1 and window_verdict(direct) == 'DETECTED'
               and direct_flow_seen(direct) and row['agreement'] == 'DISAGREE' and result['completed'] is True)
        result['control_result'] = dict(name=control, expected=CONTROL_EXPECTATIONS.get(control), met=met,
                                        ordinary_exit_code=result['exit_code'])
        if result['exit_code'] != 130:
            result['exit_code'], result['outcome'] = (0, 'control-met') if met else (2, 'control-not-met')
