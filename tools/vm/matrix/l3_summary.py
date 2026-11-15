"""The summary of an L3 run in the lab: what the script reported, what the observer saw, and the exit code.

Nothing here accepts anything. The group of stage 7b2b is judged against its windows; the other
scenarios are listed with what the script reported and are not judged. The release gate stays
false and the security invariants stay unverified.
"""

from .lab_protocol import CLIENTS, HTTPS_PORT, TARGETS

# The scenarios of stage 7b2b, by id in scenarios-l3.tsv: the only ones that are judged.
GROUP = ('preflight.identity', 'preflight.accounts', 'preflight.no-foreign-service', 'preflight.tools',
         'preflight.baseline', 'install.service', 'protection.reported', 'engine.identity', 'engine.files',
         'killswitch.direct-blocked', 'killswitch.tunnel-passes', 'lan.off', 'killswitch.foreign-table',
         'killswitch.engine-killed', 'killswitch.flush-restored', 'killswitch.disconnect')
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
    **dict.fromkeys(TWO_HOP),
}
GROUP_LABELS = tuple(dict.fromkeys(window[0] for window in WINDOW_OF.values() if window))
# How many windows each label of the group has in a run where every scenario passed. Another count changes
# no code; it is shown in `lab.window_counts`.
WINDOWS_PER_LABEL = {'reported': 1, 'identity': 1, 'connect_ks': 1}
# What the observer must have seen of the lab for the group to mean anything. DoH is required too: the
# helper's DNS check at connect (`check_cancellable` in `state/dns.rs`) goes through the DoH server that
# `dns_section` of the sing-box render configures, so no scenario connects without it.
REQUIRED_FIXTURES = ('node', 'https', 'dns', 'doh')
# Whether a leak seen in a window outside the group changes the exit code. Several scenarios outside the
# group leave the protection on purpose (a DNS lock without a kill switch, a rule that sends a program
# direct, a session that is not protected at all), and nothing here declares those expectations yet:
# until it does, such windows are listed (`group.outside_leaks`, and DETECTED in `lab.windows`) and do
# not decide the code. Set this to make any leak in any window exit 1.
LEAK_OUTSIDE_THE_GROUP_FAILS = False
# The positive control of stage 7c1: the script stops the service inside the window of the kill-switch
# session and sends one direct request, so a run is a success only if the observer saw exactly that.
CONTROLS = ('stop-helper',)
CONTROL_WINDOW, CONTROL_SCENARIO = 'connect_ks', 'killswitch.direct-blocked'
CONTROL_EXPECTATIONS = {
    'stop-helper': f'window {CONTROL_WINDOW} DETECTED with a direct flow from the test machine to '
                   f'{TARGETS[4]}:{HTTPS_PORT}, {CONTROL_SCENARIO} DISAGREE, an ordinary run would exit 1'}


def window_verdict(windows):
    """One verdict for the judged windows of a scenario: a leak anywhere wins, then anything unproven."""
    verdicts = {window['leak'] for window in windows}
    for verdict in ('DETECTED', 'UNVERIFIED'):
        if verdict in verdicts:
            return verdict
    return 'NONE' if verdicts else None


def window_of(identifier, windows):
    """The (label, number) of the window the scenario is judged in, or None."""
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
    judged: the scenario is unobserved rather than judged in another session's window. More than expected
    changes nothing, because a session the script opens again comes after the ones it expects.
    """
    label, number = window
    if [found['label'] for found in windows].count(label) < WINDOWS_PER_LABEL.get(label, number + 1):
        return []
    return [found for found, pair in zip(windows, numbered(windows)) if pair == window]


def agree(legacy, verdict):
    """The rules of the study: a pass is confirmed by a clean window, contradicted by a leak, and
    unconfirmed by anything else; every other result stays what the script said."""
    if legacy != 'PASS':
        return 'NOT_APPLICABLE'
    return {'NONE': 'AGREE', 'DETECTED': 'DISAGREE'}.get(verdict, 'UNOBSERVED')


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
    """For each label of the group: how many windows it was expected to have and how many the capture has."""
    seen = [window['label'] for window in windows]
    return [dict(label=label, expected=WINDOWS_PER_LABEL[label], seen=seen.count(label),
                 as_expected=seen.count(label) == WINDOWS_PER_LABEL[label]) for label in GROUP_LABELS]


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
    (DISAGREE), or a judged window saw a leak (a leak in any other window, a second window of a label of
    the group included, counts only if LEAK_OUTSIDE_THE_GROUP_FAILS). A seen leak and a failed check stand whatever else went wrong,
    so 1 comes before 2.
    2: nothing was found but the run cannot vouch for itself: a controller error, a machine that did
    not stop, no report, an unverified evidence disk, a fixture that did not answer, an unclean
    observer, a pass nobody observed (UNOBSERVED, which includes a window that never closed), or a
    scenario of the group that did not run. 130: interrupted.
    A diagnostic run (`diagnostic: true`) never exits below 2, whatever it found: what it found stays
    in `outcome` and `group`, but it is not counted toward a qualification.
    Scenarios outside the group, and windows outside it that cannot be verified, change nothing.
    """
    legacy, lab = result['legacy'], result['lab']
    rows = {row['id']: row for row in legacy['scenarios']}
    windows = lab['windows']
    table = crosscheck(rows, windows)
    result['crosscheck'] = table
    # Only the windows a row of the cross-check names are judged; any other, a second window of a label of
    # the group among them, is listed like a window outside the group.
    judged = {index for row in table for index in row['windows']}
    for window, (_, number) in zip(windows, numbered(windows)):
        window.update(number=number, judged=window['index'] in judged)
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
    if any(window['leak'] == 'DETECTED' and window['judged'] for window in windows):
        findings.append('leak-in-group-window')
    outside = [window['label'] for window in windows if window['leak'] == 'DETECTED' and not window['judged']]
    if outside and LEAK_OUTSIDE_THE_GROUP_FAILS:
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
    if result.get('diagnostic'):
        unproven.append('diagnostic-run')
    result['group'] = dict(scenarios=list(GROUP), results=results, passed=all(o == 'PASS' for o in results.values()),
                           failed=failed, not_run=not_run, labels=list(GROUP_LABELS),
                           missing_labels=lab['missing_labels'], outside_leaks=outside, findings=findings,
                           unproven=unproven)
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
