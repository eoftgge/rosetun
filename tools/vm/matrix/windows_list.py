"""Explicit adapter for opt-in Windows List artifacts, independent of Linux JSON."""
from pathlib import Path

from .catalog import digest, validate_snapshot
from .report import read_json

ROOT = Path(__file__).resolve().parent.parent / 'windows'
PREFIX = 'rosetun.windows-list.'
IDENTITY = {'run_id', 'vm_id', 'boot_id'}


def make_plan(profile_name, profile):
    rows, _ = read_json(ROOT / 'list-checks.json')
    validate_snapshot(rows)
    plan = dict(schema=PREFIX + 'plan.v2', suite='windows-list', profile=profile_name,
                policy=dict(profile), identity=None, catalog=rows, catalog_digest=digest(rows))
    return validate_plan(plan)


def validate_plan(plan):
    if isinstance(plan, dict) and plan.get('schema') == PREFIX + 'plan.v1':
        raise ValueError('Windows List plan.v1 has no catalog digest; record a new run with plan.v2')
    if (not isinstance(plan, dict) or set(plan) != {'schema', 'suite', 'profile', 'policy', 'identity', 'catalog', 'catalog_digest'}
            or plan['schema'] != PREFIX + 'plan.v2' or plan['suite'] != 'windows-list'
            or not isinstance(plan['profile'], str) or not plan['profile'].strip()
            or not isinstance(plan['policy'], dict) or set(plan['policy']) != {'mode'}
            or plan['policy']['mode'] not in ('exploratory', 'release')):
        raise ValueError('invalid Windows List plan')
    validate_snapshot(plan['catalog'])
    if not isinstance(plan['catalog_digest'], str) or plan['catalog_digest'] != digest(plan['catalog']):
        raise ValueError('Windows List catalog digest mismatch')
    identity = plan['identity']
    if identity is not None and (not isinstance(identity, dict) or set(identity) != IDENTITY
            or any(not isinstance(v, str) or not v.strip() for v in identity.values())):
        raise ValueError('invalid Windows List plan identity')
    return plan


def assess(report, status, events, plan, event_problems=()):
    import sys
    from .windows_results import assess as shared
    return shared(report, status, events, plan, event_problems, adapter=sys.modules[__name__])


def assess_files(report_path, plan_path):
    import sys
    from .windows_results import assess_files as shared
    return shared(report_path, plan_path, adapter=sys.modules[__name__])
