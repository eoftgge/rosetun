"""Windows Proxy saved-plan policy; no guest operations."""
from .catalog import digest, validate_snapshot
from .report import read_json
from .windows_list import ROOT, IDENTITY

PREFIX = 'rosetun.windows-proxy.'
COMPONENTS = {'node', 'lan', 'watch', 'listener', 'connection', 'lockdown', 'desktop', 'files'}


def make_plan(profile_name, profile, use_host_node=True, keep_node=False, proxy_port=10808):
    rows, _ = read_json(ROOT / 'proxy-checks.json')
    for row in rows:
        row['required'] = use_host_node if row['detail'] == 'host-node' else True
    return validate_plan(dict(schema=PREFIX + 'plan.v1', suite='windows-proxy',
        profile=profile_name, policy=dict(profile), identity=None, catalog=rows,
        catalog_digest=digest(rows), parameters=dict(use_host_node=use_host_node,
        keep_node=keep_node, proxy_port=proxy_port)))


def validate_plan(plan):
    fields = {'schema', 'suite', 'profile', 'policy', 'identity', 'catalog', 'catalog_digest', 'parameters'}
    if (not isinstance(plan, dict) or set(plan) != fields or plan['schema'] != PREFIX + 'plan.v1'
            or plan['suite'] != 'windows-proxy' or not isinstance(plan['profile'], str) or not plan['profile'].strip()
            or not isinstance(plan['policy'], dict) or set(plan['policy']) != {'mode'}
            or plan['policy']['mode'] not in ('exploratory', 'release')):
        raise ValueError('invalid Windows Proxy plan')
    parameters = plan['parameters']
    if (not isinstance(parameters, dict) or set(parameters) != {'use_host_node', 'keep_node', 'proxy_port'}
            or type(parameters['use_host_node']) is not bool or type(parameters['keep_node']) is not bool
            or type(parameters['proxy_port']) is not int or not 1024 <= parameters['proxy_port'] <= 65535):
        raise ValueError('invalid Proxy coverage parameters')
    validate_snapshot(plan['catalog'])
    if plan['catalog_digest'] != digest(plan['catalog']):
        raise ValueError('Windows Proxy catalog digest mismatch')
    for row in plan['catalog']:
        if row['required'] != (parameters['use_host_node'] if row['detail'] == 'host-node' else True):
            raise ValueError('invalid Proxy requirement')
    identity = plan['identity']
    if identity is not None and (not isinstance(identity, dict) or set(identity) != IDENTITY
            or any(not isinstance(v, str) or not v.strip() for v in identity.values())):
        raise ValueError('invalid Windows Proxy identity')
    return plan


def validate_cleanup(cleanup, plan, events=()):
    if not isinstance(cleanup, dict) or not isinstance(cleanup.get('components'), dict):
        return ['missing component cleanup']
    parts = cleanup['components']
    problems = []
    if set(parts) != COMPONENTS or any(v not in ('PASS', 'ERROR', 'UNVERIFIED', 'NOT_CREATED', 'RETAINED') for v in parts.values()):
        return ['invalid component cleanup']
    if any(v == 'RETAINED' and (k != 'node' or not plan['parameters']['keep_node']) for k, v in parts.items()):
        problems.append('invalid retained component')
    triggers = {'lan': 'plain.', 'connection': 'plain.', 'files': 'plain.', 'listener': 'busy.',
                'watch': 'strict.restart', 'desktop': 'desktop.', 'lockdown': 'lockdown.'}
    for component, prefix in triggers.items():
        if parts[component] == 'NOT_CREATED' and any(isinstance(e, dict) and isinstance(e.get('id'), str)
                and e['id'].startswith(prefix) and e.get('result') in ('PASS', 'FAIL') for e in events):
            problems.append('created component omitted from cleanup')
    expected = 'ERROR' if 'ERROR' in parts.values() else 'UNVERIFIED' if 'UNVERIFIED' in parts.values() else 'PASS'
    if cleanup.get('status') != expected:
        problems.append('cleanup aggregate mismatch')
    return problems


def assess(report, status, events, plan, event_problems=()):
    import sys
    from .windows_results import assess as shared
    try:
        validate_plan(plan)
    except ValueError:
        from .report import ASSESSMENT_SCHEMA
        # Invalid saved plans cannot authorize acceptance, but cannot erase execution failures.
        checks = report.get('checks', []) if isinstance(report, dict) else []
        failures = [dict(id=e.get('id') if isinstance(e.get('id'), str) else None)
                    for e in [*events, *(checks if isinstance(checks, list) else [])]
                    if isinstance(e, dict) and e.get('result') == 'FAIL']
        return dict(schema=ASSESSMENT_SCHEMA, suite='windows-proxy',
                    execution=dict(status='FAIL' if failures else 'ERROR', failures=failures),
                    validation=dict(status='ERROR', problems=['invalid saved Proxy plan']),
                    cleanup=dict(status='UNVERIFIED'), coverage='none',
                    invariant=dict(status='UNVERIFIED'),
                    acceptance=dict(accepted=False, exploratory=False, release=False))
    return shared(report, status, events, plan, event_problems, adapter=sys.modules[__name__])


def assess_files(report_path, plan_path):
    import sys
    from .windows_results import assess_files as shared
    return shared(report_path, plan_path, adapter=sys.modules[__name__])
