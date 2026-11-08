"""Explicit adapter for opt-in Windows List artifacts, independent of Linux JSON."""
import json
from pathlib import Path

from .catalog import digest, validate_snapshot
from .report import ASSESSMENT_SCHEMA, read_json, _unique_object, _invalid_constant

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
    validate_plan(plan)
    problems = list(event_problems)
    identity = plan['identity']
    if identity is None:
        problems.append('plan has no independently recorded identity')
    report = report if isinstance(report, dict) else {}
    status = status if isinstance(status, dict) else {}
    for value, kind in ((report, 'report'), (status, 'status')):
        if value.get('schema') != PREFIX + kind + '.v1':
            problems.append('invalid ' + kind + ' schema')
        if identity is None or value.get('identity') != identity:
            problems.append(kind + ' identity mismatch')
    if report.get('boot_id_at_end') != (identity or {}).get('boot_id'):
        problems.append('final boot mismatch')
    if status.get('state') != 'finished':
        problems.append('completion marker missing')
    if type(status.get('event_count')) is not int or status.get('event_count') != len(events):
        problems.append('completion event count mismatch')
    if set(report) != {'schema', 'identity', 'boot_id_at_end', 'checks', 'summary', 'cleanup', 'errors'}:
        problems.append('invalid report fields')
    if set(status) != {'schema', 'identity', 'state', 'event_count'}:
        problems.append('invalid status fields')
    checks = report.get('checks')
    if not isinstance(checks, list) or checks != events:
        problems.append('report and events disagree')
    counts = dict.fromkeys(('PASS', 'FAIL', 'SKIP', 'ERROR', 'UNVERIFIED'), 0)
    failures, by_id = [], {}
    expected_ids = [row['id'] for row in plan['catalog']]
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            problems.append('invalid event object')
            counts['ERROR'] += 1
            continue
        result, check_id = event.get('result'), event.get('id')
        if result == 'FAIL':
            failures.append({'row': index, 'id': check_id if isinstance(check_id, str) else None})
        if isinstance(result, str) and result in ('PASS', 'FAIL', 'SKIP'):
            counts[result] += 1
        else:
            problems.append('invalid execution result')
            counts['ERROR'] += 1
        if (set(event) != {'schema', 'run_id', 'sequence', 'id', 'result', 'reason'}
                or event.get('schema') != PREFIX + 'event.v1'
                or event.get('run_id') != (identity or {}).get('run_id')
                or type(event.get('sequence')) is not int or event.get('sequence') != index + 1):
            problems.append('invalid event envelope or sequence')
        reasons = {'PASS': ('checked',), 'FAIL': ('condition-false', 'condition-exception'),
                   'SKIP': ('srs-compile-failed', 'interrupted')}
        if not isinstance(result, str) or event.get('reason') not in reasons.get(result, ()):
            problems.append('invalid reason code')
        if not isinstance(check_id, str) or check_id not in expected_ids or check_id in by_id:
            problems.append('unknown or duplicate check id')
        else:
            by_id[check_id] = event
            if index >= len(expected_ids) or check_id != expected_ids[index]:
                problems.append('check order differs from saved plan')
    # Preserve a recorded FAIL even if its journal counterpart is lost or damaged.
    if isinstance(checks, list):
        for index, check in enumerate(checks):
            if isinstance(check, dict) and check.get('result') == 'FAIL' and check not in events:
                failures.append({'row': index, 'id': check.get('id') if isinstance(check.get('id'), str) else None,
                                 'source': 'report'})
                counts['FAIL'] += 1
    rows = []
    for row in plan['catalog']:
        event = by_id.get(row['id'], {})
        result = event.get('result', 'UNVERIFIED')
        issues = []
        if not event:
            issues.append('missing check')
        if event.get('reason') == 'srs-compile-failed':
            prerequisite = by_id.get(row['detail'], {})
            if prerequisite.get('result') != 'FAIL':
                issues.append('invalid failed prerequisite')
        if row['required'] and result == 'SKIP':
            issues.append('required check skipped')
        problems.extend(issues)
        rows.append(dict(id=row['id'], required=row['required'], evidence=row['evidence'],
                         execution=result, invariant='UNVERIFIED', problems=issues))
    summary = report.get('summary', {})
    if not isinstance(summary, dict):
        summary = {}
    for key, expected in {'total': len(events), **{s.lower(): counts[s] for s in ('PASS', 'FAIL', 'SKIP')}}.items():
        if type(summary.get(key)) is not int or summary.get(key) != expected:
            problems.append('summary mismatch')
    if set(summary) != {'total', 'pass', 'fail', 'skip'}:
        problems.append('invalid summary fields')
    cleanup = report.get('cleanup', {})
    if not isinstance(cleanup, dict) or set(cleanup) != {'status'}:
        problems.append('invalid cleanup fields')
    cleanup = cleanup.get('status') if isinstance(cleanup, dict) else None
    if cleanup not in ('PASS', 'ERROR', 'UNVERIFIED'):
        cleanup = 'ERROR'
        problems.append('invalid cleanup')
    if cleanup != 'PASS':
        problems.append('cleanup not confirmed')
    errors = report.get('errors')
    if not isinstance(errors, list):
        problems.append('invalid infrastructure errors')
    else:
        for error in errors:
            if (not isinstance(error, dict) or set(error) != {'reason', 'place'}
                    or error.get('reason') != 'infrastructure-error'
                    or error.get('place') not in ('execution', 'cleanup', 'export')):
                problems.append('invalid infrastructure error')
        if errors:
            problems.append('infrastructure error recorded')
    execution = ('FAIL' if failures else 'ERROR' if counts['ERROR'] else 'UNVERIFIED' if len(by_id) != len(expected_ids)
                 else 'SKIP' if counts['SKIP'] else 'PASS')
    accepted = not problems and execution == 'PASS'
    return dict(schema=ASSESSMENT_SCHEMA, suite='windows-list', profile=plan['profile'],
                catalog_digest=digest(plan['catalog']),
                execution=dict(status=execution, counts=counts, failures=failures),
                validation=dict(status='ERROR' if problems else 'PASS', problems=problems),
                cleanup=dict(status=cleanup), coverage='complete' if accepted else 'none', rows=rows,
                legacy_verdict='ERROR' if problems else execution,
                invariant=dict(status='UNVERIFIED', reason='independent security evidence verification is not implemented'),
                acceptance=dict(mode=plan['policy']['mode'], exploratory=accepted, release=False,
                                accepted=accepted and plan['policy']['mode'] == 'exploratory'))


def assess_files(report_path, plan_path):
    plan, plan_hash = read_json(plan_path)
    validate_plan(plan)
    directory = Path(report_path).parent
    problems, events = [], []
    try:
        raw = (directory / 'events.jsonl').read_bytes()
        import hashlib
        events_hash = hashlib.sha256(raw).hexdigest()
        if not raw.endswith(b'\n'):
            problems.append('truncated event stream')
        for line in raw.splitlines():
            try:
                events.append(json.loads(line.decode('utf-8-sig'), object_pairs_hook=_unique_object, parse_constant=_invalid_constant))
            except (UnicodeError, ValueError, RecursionError):
                problems.append('invalid event JSON')
    except (OSError, UnicodeError):
        events_hash = None
        problems.append('unreadable event stream')
    def optional(path):
        try:
            return read_json(path)
        except (OSError, ValueError):
            problems.append('unreadable artifact')
            return None, None
    report, report_hash = optional(report_path)
    status, status_hash = optional(directory / 'status.json')
    result = assess(report, status, events, plan, problems)
    result['sources'] = dict(plan_sha256=plan_hash, report_sha256=report_hash,
                             status_sha256=status_hash, events_sha256=events_hash)
    return result
