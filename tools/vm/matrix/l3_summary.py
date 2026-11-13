"""The summary of an L3 run in the lab: what the script reported, what the observer saw, and the exit code."""

# The scenarios of stage 7b2b, by id in scenarios-l3.tsv: the only ones that are judged.
GROUP = ('preflight.identity', 'preflight.accounts', 'preflight.no-foreign-service', 'preflight.tools',
         'preflight.baseline', 'install.service', 'protection.reported', 'engine.identity', 'engine.files',
         'killswitch.direct-blocked', 'killswitch.tunnel-passes', 'lan.off', 'killswitch.foreign-table',
         'killswitch.engine-killed', 'killswitch.flush-restored', 'killswitch.disconnect')
# The label of the window each scenario ran in: the function that opened the session. None: no window.
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


def decide(result, interrupted):
    """The first exit code of the stage: an infrastructure error, a seen leak, else the script's own result."""
    verdict = (result['lab'] or {}).get('windows') or []
    summary = (result['legacy'] or {}).get('summary') or {}
    if interrupted:
        code = 130
    elif result['errors'] or not result['completed'] or not result['legacy']['scenarios']:
        code = 2
    elif any(window['leak'] == 'DETECTED' for window in verdict) or summary.get('overall') != 'PASS':
        code = 1
    else:
        code = 0
    result['exit_code'] = code
