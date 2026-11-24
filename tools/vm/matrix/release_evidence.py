"""A release evidence pack: the records of chosen finished runs, copied as they are, with parity tables.

The builder reads the stand's state and writes one new directory. It refuses what no
pack may carry and interprets nothing: the tables hold what the summaries say, and the
manifest says in so many words that the release gate is false, the security invariants
are unverified and nobody has signed. Judging the pack and signing it belong to the owner.
"""

import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil

from .report import _invalid_constant, _unique_object
from .resources import (_identifier, _no_links, _regular_file, _state_path, completion_verified,
                        read_manifest, resource_path)

SCHEMA = 'rosetun.matrix.release-evidence.v1'
RESULT_SCHEMA = 'rosetun.matrix.release-evidence-result.v1'
MAX_FILE_BYTES = 16 * 1024 * 1024
ALWAYS = ('execution-summary.json', 'completion.json', 'run-state.json', 'lifecycle.jsonl')
REPORT = 'report.json'
SUITE_DIRECTORY = re.compile(r'(linux|windows)-[a-z0-9-]{1,40}')
OWNER_FILL = 'hyperv'
SHA = re.compile(r'[0-9a-f]{40}')
CASE_NAME = re.compile(r'[a-z0-9-]{1,32}')
WINDOWS_MATRIX_SCHEMAS = {
    'windows-list': 'rosetun.matrix.windows-list-summary.v1',
    'windows-failure': 'rosetun.matrix.windows-failure-summary.v1',
    'windows-lockdown': 'rosetun.matrix.windows-lockdown-summary.v1',
    'windows-proxy': 'rosetun.matrix.windows-proxy-summary.v1',
    'windows-lan': 'rosetun.matrix.windows-lan-summary.v1',
    'windows-upgrade': 'rosetun.matrix.windows-upgrade-summary.v1',
    'windows-protocols': 'rosetun.matrix.windows-protocols-summary.v1',
    'windows-twohop': 'rosetun.matrix.windows-twohop-summary.v1',
}


class EvidenceRefused(ValueError):
    """The pack was not built; `reason` is a fixed word, `run` the run that caused it, if any."""

    def __init__(self, reason, run=None):
        super().__init__(reason)
        self.reason = reason
        self.run = run


def _encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8')


def _parse(raw):
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except (UnicodeError, ValueError, RecursionError):
        raise ValueError('invalid JSON input') from None


def _sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def _is_windows_matrix(summary):
    suite = summary.get('suite')
    return (suite in WINDOWS_MATRIX_SCHEMAS
            and summary.get('schema') == WINDOWS_MATRIX_SCHEMAS[suite]
            and summary.get('mode') == 'lab')


def _suite_case(summary):
    if not _is_windows_matrix(summary):
        return None
    execution = summary.get('execution')
    preflight = summary.get('preflight')
    case = (execution.get('case') if type(execution) is dict else None)
    if case is None and type(preflight) is dict:
        case = preflight.get('case')
    if case is None:
        return None
    if type(case) is not str or not CASE_NAME.fullmatch(case):
        raise EvidenceRefused('summary-invalid')
    return case


def _set_key(summary):
    suite = summary['suite']
    case = _suite_case(summary)
    return f'{suite}-{case}' if case is not None else suite


def _read(directory, relative):
    path = resource_path(directory, relative)
    _regular_file(path)
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError('evidence file is too large')
    return path.read_bytes()


def _reports(directory):
    """Every report.json one or two levels below a suite directory of the run."""
    found = []
    for top in sorted(os.listdir(directory)):
        if not SUITE_DIRECTORY.fullmatch(top) or not (directory / top).is_dir():
            continue
        for name in sorted(os.listdir(directory / top)):
            relative = top + '/' + name
            if name == REPORT:
                found.append(relative)
            elif (directory / top / name).is_dir() and (directory / top / name / REPORT).is_file():
                found.append(relative + '/' + REPORT)
    return found


def _lab_evidence(lab):
    if type(lab) is not dict:
        return {}
    qualification = lab.get('qualification')
    if type(qualification) is dict and type(qualification.get('evidence')) is dict:
        return qualification['evidence']
    evidence = lab.get('evidence')
    return evidence if type(evidence) is dict else {}


def _pcap(directory, evidence):
    """Size and hash of the capture as the summary recorded them, checked against the file when it is there."""
    recorded = {'bytes': evidence.get('pcap_bytes'), 'sha256': evidence.get('pcap_sha256')}
    if recorded['sha256'] is None:
        return dict(recorded, file_present=False, file_matches=None)
    path = resource_path(directory, 'capture.pcap')
    if not path.is_file():
        return dict(recorded, file_present=False, file_matches=None)
    _regular_file(path)
    digest, size = hashlib.sha256(), 0
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
            size += len(block)
    return dict(recorded, file_present=True, file_matches=digest.hexdigest() == recorded['sha256'] and size == recorded['bytes'])


class _Run:
    """What one run of the pack is: its directories and the files taken from each."""

    def __init__(self, token, directories):
        self.token = token
        self.directories = directories
        self.files = {}
        self.summary = None
        self.pcap = None


def _expand(state, token, *, include_archive=False):
    """A run as `runs` lists it, or the base identifier of a lab run with its -lab and -test directories."""
    _identifier(token)
    roots = [state / 'runs']
    if include_archive:
        archive = state / 'archive'
        if archive.exists():
            _no_links(archive)
            if archive.is_dir():
                roots.append(archive)
    found = []
    for root in roots:
        if (root / token).is_dir():
            found.append((root, [token]))
            continue
        pair = [token + role for role in ('-lab', '-test') if (root / (token + role)).is_dir()]
        if pair:
            found.append((root, pair))
    if not found:
        raise EvidenceRefused('run-not-found', token)
    if len(found) > 1:
        raise EvidenceRefused('run-in-runs-and-archive', token)
    return found[0]


def _collect(state, tokens, *, include_archive=False):
    runs_root = state / 'runs'
    _no_links(runs_root)
    runs, seen = [], set()
    for token in tokens:
        if token in seen:
            raise EvidenceRefused('duplicate-run', token)
        seen.add(token)
        root, directories = _expand(state, token, include_archive=include_archive)
        run = _Run(token, directories)
        for name in run.directories:
            directory = root / name
            _no_links(directory)
            manifest = read_manifest(directory, run_id=name)
            if not completion_verified(directory, manifest):
                raise EvidenceRefused('completion-not-verified', token)
            names = [*ALWAYS, *_reports(directory)]
            for relative in names:
                raw = _read(directory, relative)
                # The owner token of the run and a private key are never evidence.
                if manifest['owner_token'].encode() in raw or b'PRIVATE KEY' in raw:
                    raise EvidenceRefused('secret-in-evidence', token)
                run.files['runs/' + name + '/' + relative] = raw
        run.summary = _summary(run)
        _gate(run)
        lab = run.summary.get('lab')
        run.pcap = (_pcap(root / _capturing(run), _lab_evidence(lab))
                    if type(lab) is dict else None)
        if run.pcap and run.pcap['file_matches'] is False:
            raise EvidenceRefused('pcap-does-not-match-its-record', token)
        runs.append(run)
    return runs


def _primary(run):
    return next((name for name in run.directories if name.endswith('-test')), run.directories[0])


def _capturing(run):
    return next((name for name in run.directories if name.endswith('-lab')), _primary(run))


def _summary(run):
    raws = {name: run.files['runs/' + name + '/execution-summary.json'] for name in run.directories}
    if len({_sha256(raw) for raw in raws.values()}) != 1:
        raise EvidenceRefused('summaries-differ', run.token)
    summary = _parse(raws[_primary(run)])
    if type(summary) is not dict or type(summary.get('suite')) is not str or type(summary.get('schema')) is not str:
        raise EvidenceRefused('summary-invalid', run.token)
    return summary


def _gate(run):
    summary = run.summary
    source = summary.get('preflight', {}).get('controller_source')
    if type(source) is not dict or type(source.get('source_sha')) is not str or not SHA.fullmatch(source['source_sha']):
        raise EvidenceRefused('source-unknown', run.token)
    if source.get('source_dirty') is not False:
        raise EvidenceRefused('source-dirty', run.token)
    # Linux `--diagnostic` runs and Windows infrastructure smokes are never evidence. Windows matrix runs always carry
    # `diagnostic: true` solely because the 9a image descriptor is `qualified: false`, and reject `--diagnostic` on CLI.
    if summary.get('diagnostic') and not _is_windows_matrix(summary):
        raise EvidenceRefused('diagnostic-run', run.token)
    # A lab run is never attached and says nothing; every other summary must say `attached: false`.
    attached = summary.get('attached')
    if attached is True or summary.get('attachments') not in (None, 0) or (attached is None and summary.get('mode') != 'lab'):
        raise EvidenceRefused('attached-run', run.token)
    if type(summary.get('exit_code')) is not int:
        raise EvidenceRefused('summary-invalid', run.token)
    try:
        _suite_case(summary)
    except EvidenceRefused as error:
        raise EvidenceRefused(error.reason, run.token) from None


def _images(summary):
    configuration = summary.get('configuration', {})
    preflight = summary.get('preflight', {})
    execution = summary.get('execution', {})
    test_block = configuration.get('image') if type(configuration) is dict else None
    if type(test_block) is not dict and _is_windows_matrix(summary):
        test_block = preflight.get('image') if type(preflight) is dict else None
        if type(test_block) is not dict and type(execution) is dict:
            test_block = execution.get('image')
    lab_block = configuration.get('lab', {}).get('image') if type(configuration) is dict and type(configuration.get('lab')) is dict else None
    found = {}
    for role, block in (('test', test_block), ('lab', lab_block)):
        if type(block) is dict:
            found[role] = {key: block.get(key) for key in ('identifier', 'sha256', 'size_bytes', 'format', 'profile',
                                                           'architecture', 'guest_os', 'schema')}
    return found


def _ends(raw):
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    return (rows[0].get('utc'), rows[-1].get('utc')) if rows else (None, None)


def _results(summary):
    scenarios = summary.get('legacy', {}).get('scenarios')
    if scenarios:
        return {row['id']: row['result'] for row in scenarios}
    group_results = summary.get('group', {}).get('results')
    if group_results:
        return dict(group_results)
    if _is_windows_matrix(summary):
        execution = summary.get('execution')
        checks = execution.get('checks') if type(execution) is dict else None
        if type(checks) is list:
            return {row['id']: row['result'] for row in checks
                    if type(row) is dict and type(row.get('id')) is str and type(row.get('result')) is str}
    return {}


def _outcome(summary):
    if summary.get('outcome') is not None:
        return summary.get('outcome')
    if not _is_windows_matrix(summary):
        return None
    execution = summary.get('execution')
    if type(execution) is not dict:
        return 'incomplete'
    if execution.get('accepted') is True:
        return 'accepted'
    if execution.get('findings'):
        return 'findings'
    return 'unverified'


def _window_verdicts(summary):
    if not _is_windows_matrix(summary):
        return None
    execution = summary.get('execution')
    exec_windows = execution.get('windows') if type(execution) is dict else None
    if type(exec_windows) is not dict:
        return None
    return {
        label: ('LISTED' if row.get('listed') is True else row.get('verdict'))
        for label, row in sorted(exec_windows.items())
        if type(row) is dict
    }


def _windows_as_expected(summary):
    lab = summary.get('lab') if type(summary.get('lab')) is dict else {}
    counts = lab.get('window_counts')
    if counts is not None:
        return all(row.get('as_expected') is True for row in counts)
    if not _is_windows_matrix(summary):
        return None
    observer = lab.get('observer') if type(lab.get('observer')) is dict else {}
    if lab.get('missing_labels') or lab.get('extra_windows') or observer.get('reasons'):
        return False
    execution = summary.get('execution')
    exec_windows = execution.get('windows') if type(execution) is dict else None
    if type(exec_windows) is not dict or not exec_windows:
        return None
    judged = [row for row in exec_windows.values() if type(row) is dict and row.get('listed') is not True]
    if not judged:
        return False
    for row in exec_windows.values():
        if type(row) is not dict or row.get('leak') == 'UNVERIFIED' or row.get('reasons'):
            return False
    return all(row.get('verdict') in ('NONE', 'EXPECTED') for row in judged)


def _record(run):
    summary, source = run.summary, run.summary['preflight']['controller_source']
    started, finished = _ends(run.files['runs/' + _primary(run) + '/lifecycle.jsonl'])
    results = _results(summary)
    is_win = _is_windows_matrix(summary)
    group = summary.get('group', {}) if type(summary.get('group')) is dict else {}
    execution = summary.get('execution', {}) if type(summary.get('execution')) is dict else {}
    lab = summary.get('lab') if type(summary.get('lab')) is dict else {}
    windows = lab.get('windows')
    exec_windows = execution.get('windows') if is_win and type(execution.get('windows')) is dict else None
    window_count = len(exec_windows) if exec_windows is not None else (len(windows) if windows is not None else None)
    findings = execution.get('findings') if is_win else group.get('findings')
    unproven = execution.get('unverified') if is_win else group.get('unproven')
    record = {
        'run': run.token, 'suite': summary['suite'], 'commit': source['source_sha'],
        'source_dirty': False, 'source_dirty_digest': source.get('source_dirty_digest'),
        'images': _images(summary), 'directories': list(run.directories),
        'exit_code': summary['exit_code'], 'outcome': _outcome(summary),
        'summary_schema': summary['schema'], 'summary_sha256': _sha256(
            run.files['runs/' + _primary(run) + '/execution-summary.json']),
        'completion_verified': True, 'attached': False,
        'findings': findings, 'unproven': unproven,
        'pcap': run.pcap, 'started_utc': started, 'finished_utc': finished,
        'windows': window_count,
        'window_counts_all_as_expected': _windows_as_expected(summary),
        'scenario_counts': {key: list(results.values()).count(key) for key in sorted(set(results.values()))},
    }
    case = _suite_case(summary)
    if case is not None:
        record['case'] = case
    verdicts = _window_verdicts(summary)
    if verdicts is not None:
        record['window_verdicts'] = verdicts
    return record


def _cell(value):
    return '-' if value is None else re.sub(r'[\t\r\n]+', ' ', str(value))


def _windows_crosscheck(summary):
    execution = summary.get('execution')
    findings = execution.get('findings') if type(execution) is dict else None
    if type(findings) is not list:
        return {}
    found = {}
    for item in findings:
        if type(item) is str and item.startswith('disagree:'):
            check_id = item[len('disagree:'):]
            if check_id:
                found[check_id] = {'id': check_id, 'agreement': 'DISAGREE', 'window': None, 'window_verdict': None}
    return found


def parity_table(runs):
    """The 8g/10g table of one suite: results, cross-checks and window verdicts per run, and an empty column for the owner."""
    count = len(runs)
    required, order = {}, []
    for run in runs:
        summary = run.summary
        execution = summary.get('execution') if type(summary.get('execution')) is dict else {}
        assessment = execution.get('assessment') if type(execution.get('assessment')) is dict else {}
        rows = assessment.get('rows') if type(assessment.get('rows')) is list else []
        if rows:
            for row in rows:
                required.setdefault(row['id'], 'yes' if row.get('required') else 'no')
                order.append(row['id'])
        elif _is_windows_matrix(summary):
            preflight = summary.get('preflight') if type(summary.get('preflight')) is dict else {}
            planned = preflight.get('checks') if type(preflight.get('checks')) is list else []
            for check_id in planned:
                if type(check_id) is str:
                    required.setdefault(check_id, 'yes')
                    order.append(check_id)
    results = [_results(run.summary) for run in runs]
    checks = [
        ({row['id']: row for row in run.summary['crosscheck']}
         if type(run.summary.get('crosscheck')) is list
         else (_windows_crosscheck(run.summary) if _is_windows_matrix(run.summary) else {}))
        for run in runs
    ]
    for source in (*(list(result) for result in results), *(list(check) for check in checks)):
        order.extend(source)
    order = list(dict.fromkeys(order))
    header = ['id', 'required', *('result%d' % n for n in range(1, count + 1)),
              *('crosscheck%d' % n for n in range(1, count + 1)), 'window',
              *('window_verdict%d' % n for n in range(1, count + 1)), 'note', OWNER_FILL]
    out = io.StringIO()
    writer = csv.writer(out, delimiter='\t', lineterminator='\n')
    writer.writerow(header)
    for scenario in order:
        found = [result.get(scenario, '-') for result in results]
        agreement = [check.get(scenario, {}).get('agreement', '-') for check in checks]
        labels = sorted({check.get(scenario, {}).get('window') for check in checks} - {None})
        verdicts = [check.get(scenario, {}).get('window_verdict') or '-' for check in checks]
        note = []
        for what, values in (('result', found), ('crosscheck', agreement), ('window verdict', verdicts)):
            if len(set(values)) > 1:
                note.append(what + ' differs between runs')
        if len(labels) > 1:
            note.append('window label differs between runs')
        if scenario not in required:
            note.append('not in the assessment rows')
        writer.writerow([_cell(scenario), required.get(scenario, '-'), *map(_cell, found), *map(_cell, agreement),
                         '|'.join(labels) or '-', *map(_cell, verdicts), '; '.join(note), ''])
    return out.getvalue().encode('utf-8')


def _set_name(suite):
    return suite[len('linux-'):] if suite.startswith('linux-') else suite


def build_pack(state_directory, run_tokens, out, *, include_archive=False):
    """Write the pack to `out`, which must not exist yet; the stand's state is only read."""
    state = _state_path(state_directory)
    if not run_tokens:
        raise ValueError('no run chosen')
    out = Path(out).absolute()
    if os.path.lexists(out):
        raise EvidenceRefused('out-exists')
    if not out.parent.is_dir():
        raise EvidenceRefused('out-parent-missing')
    resolved = out.parent.resolve() / out.name
    if state.resolve() in (resolved, *resolved.parents):
        raise EvidenceRefused('out-inside-state')
    runs = _collect(state, run_tokens, include_archive=include_archive)
    by_suite = {}
    for run in runs:
        by_suite.setdefault(_set_key(run.summary), []).append(run)
    records = {run.token: _record(run) for run in runs}
    sets = {}
    for suite, members in sorted(by_suite.items()):
        commits = {records[run.token]['commit'] for run in members}
        if len(commits) > 1:
            raise EvidenceRefused('commits-differ-in-a-set', suite)
        members.sort(key=lambda run: (records[run.token]['started_utc'] or '', run.token))
        sets[suite] = members
    if len({_set_name(suite) for suite in sets}) != len(sets):
        raise EvidenceRefused('set-names-collide')
    files = {}
    for run in runs:
        files.update(run.files)
    generated = {}
    summary_json = {}
    for suite, members in sets.items():
        generated['parity-%s.tsv' % _set_name(suite)] = parity_table(members)
        summary_json[suite] = {'runs': [dict(_parity_run(records[run.token]), run=number)
                                        for number, run in enumerate(members, 1)]}
    generated['parity-summary.json'] = _encode(summary_json)
    files.update(generated)
    manifest = {
        'schema': SCHEMA, 'release_gate': False, 'security_invariants': 'UNVERIFIED', 'owner_signature': None,
        'sets': {suite: {
            'commit': records[members[0].token]['commit'],
            'runs': [run.token for run in members],
            'parity': 'parity-%s.tsv' % _set_name(suite),
            'run_count': len(members),
            'all_exit_zero': all(records[run.token]['exit_code'] == 0 for run in members),
            'all_windows_as_expected': all(records[run.token]['window_counts_all_as_expected'] is True
                                           for run in members),
            'all_findings_empty': all(records[run.token]['findings'] == [] for run in members),
            'all_unproven_empty': all(records[run.token]['unproven'] == [] for run in members),
        } for suite, members in sets.items()},
        'runs': [records[run.token] for members in sets.values() for run in members],
        'files': {name: {'bytes': len(raw), 'sha256': _sha256(raw)} for name, raw in sorted(files.items())},
    }
    files['manifest.json'] = _encode(manifest)
    _write(out, files)
    return {'schema': RESULT_SCHEMA, 'built': True, 'out': str(out), 'runs': len(runs), 'sets': sorted(sets),
            'files': len(files), 'manifest_sha256': _sha256(files['manifest.json']),
            'release_gate': False, 'security_invariants': 'UNVERIFIED', 'owner_signature': None}


def _parity_run(record):
    row = {key: record[key] for key in ('commit', 'source_dirty', 'images', 'directories', 'exit_code', 'summary_sha256',
                                        'pcap', 'started_utc', 'finished_utc', 'windows',
                                        'window_counts_all_as_expected')} | {'run_id': record['run'],
                                                                             'group_counts': record['scenario_counts']}
    if 'case' in record:
        row['case'] = record['case']
    if 'window_verdicts' in record:
        row['window_verdicts'] = record['window_verdicts']
    return row


def _write(out, files):
    """Create `out` whole or not at all: the files go to a sibling that is renamed last."""
    staging = out.with_name(out.name + '.partial')
    staging.mkdir()
    try:
        for name, raw in sorted(files.items()):
            path = staging.joinpath(*name.split('/'))
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as stream:
                stream.write(raw)
        os.rename(staging, out)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def refusal(error):
    result = {'schema': RESULT_SCHEMA, 'built': False, 'reason': error.reason,
              'release_gate': False, 'security_invariants': 'UNVERIFIED', 'owner_signature': None}
    if error.run is not None:
        result['run'] = error.run
    return result
