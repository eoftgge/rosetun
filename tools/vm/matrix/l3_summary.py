"""The summary of an L3 run in the lab: what the script reported, what the observer saw, and the exit code.

Nothing here accepts anything. The group of stage 7b2b is judged against its windows; the other
scenarios are listed with what the script reported and are not judged. The release gate stays
false and the security invariants stay unverified.
"""

# The scenarios of stage 7b2b, by id in scenarios-l3.tsv: the only ones that are judged.
GROUP = ('preflight.identity', 'preflight.accounts', 'preflight.no-foreign-service', 'preflight.tools',
         'preflight.baseline', 'install.service', 'protection.reported', 'engine.identity', 'engine.files',
         'killswitch.direct-blocked', 'killswitch.tunnel-passes', 'lan.off', 'killswitch.foreign-table',
         'killswitch.engine-killed', 'killswitch.flush-restored', 'killswitch.disconnect')
# The label of the window each scenario ran in. A window is a protected session and its label is the
# function of run-l3.sh that opened it (connect_with is called from that function), so scenarios that
# share a session share a window: `identity` opens the session `files` ends, `connect_ks` opens the one
# that `killswitch.direct-blocked` to `killswitch.disconnect` run in. None: no protected session at all.
WINDOW_OF = {
    'preflight.identity': None, 'preflight.accounts': None, 'preflight.no-foreign-service': None,
    'preflight.tools': None, 'preflight.baseline': None, 'install.service': None,
    'protection.reported': 'reported',
    'engine.identity': 'identity', 'engine.files': 'identity',
    'killswitch.direct-blocked': 'connect_ks', 'killswitch.tunnel-passes': 'connect_ks',
    'lan.off': 'connect_ks', 'killswitch.foreign-table': 'connect_ks', 'killswitch.engine-killed': 'connect_ks',
    'killswitch.flush-restored': 'connect_ks', 'killswitch.disconnect': 'connect_ks',
}
GROUP_LABELS = tuple(dict.fromkeys(label for label in WINDOW_OF.values() if label))
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


def window_verdict(windows):
    """One verdict for the windows of a label: a leak anywhere wins, then anything unproven."""
    verdicts = {window['leak'] for window in windows}
    for verdict in ('DETECTED', 'UNVERIFIED'):
        if verdict in verdicts:
            return verdict
    return 'NONE' if verdicts else None


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
        label = WINDOW_OF[identifier]
        row = dict(id=identifier, legacy_result=legacy, window=label, windows=[], window_verdict=None)
        if label is None:
            row['agreement'] = 'NOT_APPLICABLE'
        else:
            found = [window for window in windows if window['label'] == label]
            row.update(windows=[window['index'] for window in found], window_verdict=window_verdict(found),
                       agreement=agree(legacy, window_verdict(found)))
        table.append(row)
    return table


def missing_fixtures(fixtures):
    return [name for name in REQUIRED_FIXTURES if not (fixtures.get(name) or {}).get(
        'alive_at_finish' if name == 'node' else 'answered')]


def decide(result, interrupted):
    """Fill the cross-check and the exit code of the stage.

    0: the whole group passed, every cross-check row agrees or does not apply, the observer is clean,
    the fixtures answered, the evidence disk is verified and both machines completed.
    1: the run found something: a scenario of the group failed, a pass is contradicted by a window
    (DISAGREE), or a window of the group saw a leak (a leak in a window outside the group counts only
    if LEAK_OUTSIDE_THE_GROUP_FAILS). A seen leak and a failed check stand whatever else went wrong,
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
    if any(window['leak'] == 'DETECTED' and window.get('in_group') for window in windows):
        findings.append('leak-in-group-window')
    outside = [window['label'] for window in windows if window['leak'] == 'DETECTED' and not window.get('in_group')]
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
