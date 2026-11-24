"""The on-disk state of one run, so that a new controller can find it and carry on.

`run-state.json` holds the phase with its last step, the run's identities,
absolute deadlines, what remains of the budgets, what is already collected, the
owner's digest and the controller's commit. `evidence.write_run_state` is its
only writer and replaces it atomically; this module validates what is read.
Nothing secret goes in: no passwords, keys or node addresses, and the owner
token only as its SHA-256, as in `completion.json`, because every evidence file
refuses the token itself.

A step is written twice, as an intent before the action and as done (or error)
after it. A step left at intent is unknown: it may or may not have happened.

`boot_chain` lists the guest's boot IDs as this run's controllers observed them:
the first is the boot the job was submitted on, each later one follows a planned
guest reset the controller saw itself. `identities.boot_id` is always its last
element. The guest's own report is never a source for it.
"""

import hashlib
import json
import re
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
import time

from . import evidence
from .report import read_json
from .resources import resource_path, _regular_file

SCHEMA = 'rosetun.matrix.run-state.v1'
NAME = 'run-state.json'
RESOURCE = {'id': 'run-state', 'kind': 'file', 'path': NAME}
PHASES = ('preparing', 'running', 'collecting', 'closing', 'completed', 'quarantined')
FINAL = ('completed', 'quarantined')
STATUSES = ('intent', 'done', 'error')
# Per run, whatever controller spends them. QGA calls and relay bytes stay per
# session as before: a new session is a recovery, and recoveries are counted here.
BUDGETS = {'qmp_calls': 128, 'qmp_events': 128, 'qmp_bytes_o': 1024 * 1024, 'qmp_bytes_i': 1024 * 1024,
           'qga_recoveries': 4, 'qga_observations': 32, 'job_calls': 112, 'job_polls': 4}
# The most guest resets a run may plan; each one allows one more QGA recovery on top of `BUDGETS`.
MAX_PLANNED_REBOOTS = 2
# The most abrupt power cuts a run may plan; each cut spawns a fresh QEMU process and boot.
MAX_PLANNED_POWER_CUTS = 8
# The most planned QGA session rotations a long multi-action run may plan (each session is bounded to 128 RPCs).
MAX_PLANNED_SESSION_ROTATIONS = 24
IDENTITIES = ('host_run_id', 'guest_run_id', 'import_id', 'lab_id', 'vm_uuid', 'boot_id')
JOB_FIELDS = ('submission', 'launcher', 'job', 'pid', 'session')
TRANSITION_LIMIT = 256
FIELDS = ('schema sequence run_id stand_id owner_digest controller phase reason step transitions identities '
          'host deadlines budgets collected job configuration_sha256 attachments boot_chain')


class RunStateError(ValueError):
    pass


def _utc():
    return datetime.now(timezone.utc).isoformat()


def host_boot_id():
    try:
        return Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    except OSError:
        return None


def owner_digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def limit(name, planned_reboots=0, planned_power_cuts=0, planned_session_rotations=0):
    """What one run may spend of a budget; planned resets, power cuts and session rotations add bounded headroom."""
    if type(planned_power_cuts) is not int or not 0 <= planned_power_cuts <= MAX_PLANNED_POWER_CUTS:
        raise ValueError('planned_power_cuts out of range')
    if (type(planned_session_rotations) is not int
            or not 0 <= planned_session_rotations <= MAX_PLANNED_SESSION_ROTATIONS):
        raise ValueError('planned_session_rotations out of range')
    base = BUDGETS[name]
    if name == 'qga_recoveries':
        return base + planned_reboots + planned_power_cuts + planned_session_rotations
    if name == 'qga_observations':
        return base + (16 * planned_power_cuts if planned_power_cuts else 0) + planned_session_rotations
    if planned_power_cuts:
        extra = {'qmp_calls': 16, 'qmp_events': 8}.get(name, 0)
        return base + extra * planned_power_cuts
    return base


def _name(value, *, optional=False):
    if optional and value is None:
        return value
    if type(value) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', value):
        raise RunStateError('run-state-invalid-name')
    return value


def validate(document, *, run_id, stand_id, token):
    """Strict reading: an unknown field, type or identity refuses the whole file."""
    if type(document) is not dict or set(document) != set(FIELDS.split()):
        raise RunStateError('run-state-fields')
    if (document['schema'] != SCHEMA or document['run_id'] != run_id or document['stand_id'] != stand_id
            or document['owner_digest'] != owner_digest(token)):
        raise RunStateError('run-state-identity-mismatch')
    if type(document['sequence']) is not int or document['sequence'] < 1:
        raise RunStateError('run-state-sequence')
    if document['phase'] not in PHASES:
        raise RunStateError('run-state-phase')
    _name(document['reason'], optional=True)
    step = document['step']
    if step is not None and (type(step) is not dict or set(step) != {'name', 'status'}
                             or step['status'] not in STATUSES):
        raise RunStateError('run-state-step')
    if step is not None:
        _name(step['name'])
    if type(document['transitions']) is not list or len(document['transitions']) > TRANSITION_LIMIT:
        raise RunStateError('run-state-transitions')
    for row in document['transitions']:
        if (type(row) is not dict or set(row) != {'phase', 'step', 'status', 'utc'}
                or row['phase'] not in PHASES or row['status'] not in STATUSES):
            raise RunStateError('run-state-transitions')
    controller = document['controller']
    if type(controller) is not dict or set(controller) != {'commit'} or not (
            controller['commit'] is None or re.fullmatch(r'[0-9a-f]{40}', str(controller['commit']))):
        raise RunStateError('run-state-controller')
    identities = document['identities']
    if type(identities) is not dict or set(identities) != set(IDENTITIES):
        raise RunStateError('run-state-identities')
    for value in identities.values():
        _name(value, optional=True)
    host = document['host']
    if type(host) is not dict or set(host) != {'boot_id'}:
        raise RunStateError('run-state-host')
    _name(host['boot_id'], optional=True)
    deadlines = document['deadlines']
    if type(deadlines) is not dict or any(type(v) not in (int, float) or v <= 0 for v in deadlines.values()):
        raise RunStateError('run-state-deadlines')
    for key in deadlines:
        _name(key)
    collected = document['collected']
    if type(collected) is not dict or any(type(v) not in (bool, int, str) for v in collected.values()):
        raise RunStateError('run-state-collected')
    for key in collected:
        _name(key)
    cuts = collected.get('planned_power_cuts', 0)
    if type(cuts) is not int or not 0 <= cuts <= MAX_PLANNED_POWER_CUTS:
        raise RunStateError('run-state-collected')
    rotations = collected.get('planned_session_rotations', 0)
    if type(rotations) is not int or not 0 <= rotations <= MAX_PLANNED_SESSION_ROTATIONS:
        raise RunStateError('run-state-collected')
    budgets = document['budgets']
    if (type(budgets) is not dict or set(budgets) != set(BUDGETS)
            or any(type(v) is not int or not 0 <= v <= limit(k, MAX_PLANNED_REBOOTS, cuts, rotations)
                   for k, v in budgets.items())):
        raise RunStateError('run-state-budgets')
    chain = document['boot_chain']
    if (type(chain) is not list or len(chain) > MAX_PLANNED_REBOOTS + cuts + 1 or len(set(chain)) != len(chain)
            or (chain[-1] if chain else None) != identities['boot_id']):
        raise RunStateError('run-state-boot-chain')
    for value in chain:
        _name(value)
    job = document['job']
    if job is not None:
        if type(job) is not dict or set(job) != set(JOB_FIELDS):
            raise RunStateError('run-state-job')
        if job['pid'] is not None and (type(job['pid']) is not int or not 0 < job['pid'] < 2**31):
            raise RunStateError('run-state-job')
        for key in ('submission', 'launcher', 'job', 'session'):
            _name(job[key], optional=True)
    if document['configuration_sha256'] is not None and not re.fullmatch(
            r'[0-9a-f]{64}', str(document['configuration_sha256'])):
        raise RunStateError('run-state-configuration')
    if type(document['attachments']) is not int or document['attachments'] < 0:
        raise RunStateError('run-state-attachments')
    return document


class RunState:
    """The one in-memory copy of a run's state for this controller; every change is written through."""

    def __init__(self, run, document):
        self.run = run
        self.document = document
        # How many guest resets, power cuts and session rotations this run plans: set once by who starts/attaches it.
        self.planned_reboots = 0
        cuts = document.get('collected', {}).get('planned_power_cuts', 0)
        self.planned_power_cuts = cuts if type(cuts) is int and 0 <= cuts <= MAX_PLANNED_POWER_CUTS else 0
        rotations = document.get('collected', {}).get('planned_session_rotations', 0)
        self.planned_session_rotations = (
            rotations if type(rotations) is int and 0 <= rotations <= MAX_PLANNED_SESSION_ROTATIONS else 0)
        # The QMP relay records its byte ceiling from its own thread.
        self._lock = threading.RLock()

    @classmethod
    def create(cls, run, *, phase='preparing', commit=None, configuration_sha256=None, **identities):
        if phase not in PHASES or set(identities) - set(IDENTITIES):
            raise RunStateError('run-state-invalid-start')
        run_id, stand_id, token = run._identity
        identities = {k: identities.get(k) for k in IDENTITIES}
        document = dict(schema=SCHEMA, sequence=0, run_id=run_id, stand_id=stand_id,
                        owner_digest=owner_digest(token), controller=dict(commit=commit), phase=phase,
                        reason=None, step=None, transitions=[],
                        identities=identities,
                        host=dict(boot_id=host_boot_id()), deadlines={},
                        budgets={k: 0 for k in BUDGETS}, collected={}, job=None,
                        configuration_sha256=configuration_sha256, attachments=0,
                        boot_chain=[identities['boot_id']] if identities['boot_id'] else [])
        state = cls(run, document)
        state._write()
        run._cache['run_state'] = state
        return state

    @classmethod
    def load(cls, run):
        path = resource_path(run.directory, NAME)
        try:
            _regular_file(path)
            if path.stat().st_size > 256 * 1024:
                raise RunStateError('run-state-too-large')
            document, _ = read_json(path)
        except FileNotFoundError:
            raise RunStateError('run-state-missing') from None
        except (OSError, RecursionError):
            raise RunStateError('run-state-unreadable') from None
        run_id, stand_id, token = run._identity
        if type(document) is dict and 'boot_chain' not in document and type(document.get('identities')) is dict:
            # A file written before the chain existed holds the one boot it was started on.
            boot = document['identities'].get('boot_id')
            document['boot_chain'] = [boot] if boot else []
        state = cls(run, validate(document, run_id=run_id, stand_id=stand_id, token=token))
        run._cache['run_state'] = state
        return state

    def _write(self):
        with self._lock:
            self.document['sequence'] += 1
            raw = (json.dumps(self.document, sort_keys=True, indent=2) + '\n').encode()
            # A unique scratch name: one a dead controller left behind never blocks the next write.
            evidence.write_run_state(self.run, raw, temporary='run-state.' + secrets.token_hex(8) + '.tmp')

    @property
    def phase(self):
        return self.document['phase']

    @property
    def step(self):
        return self.document['step']

    def transition(self, phase, step, status, *, reason=None):
        """Record one step of a phase: `intent` before the action, `done` or `error` after it."""
        if phase not in PHASES or status not in STATUSES:
            raise RunStateError('run-state-invalid-transition')
        _name(step)
        with self._lock:
            if self.document['phase'] in FINAL:
                raise RunStateError('run-state-final')
            transitions = self.document['transitions']
            if len(transitions) >= TRANSITION_LIMIT:
                raise RunStateError('run-state-transition-limit')
            transitions.append(dict(phase=phase, step=step, status=status, utc=_utc()))
            self.document.update(phase=phase, step=dict(name=step, status=status))
            if reason is not None:
                self.document['reason'] = _name(reason)
            self._write()

    def update(self, section, **values):
        """Merge values into `identities`, `deadlines`, `collected` or replace `job`."""
        with self._lock:
            if section == 'job':
                if set(values) != set(JOB_FIELDS):
                    raise RunStateError('run-state-job')
                self.document['job'] = dict(values)
            elif section in ('identities', 'deadlines', 'collected'):
                if section == 'identities' and set(values) - set(IDENTITIES):
                    raise RunStateError('run-state-identities')
                if section == 'identities' and values.get('boot_id') is not None:
                    # The first boot starts the chain; a later one joins it only through `extend_boot_chain`.
                    chain = self.document['boot_chain']
                    if chain and chain[-1] != values['boot_id']:
                        raise RunStateError('run-state-boot-chain')
                    if not chain:
                        self.document['boot_chain'] = [_name(values['boot_id'])]
                self.document[section].update(values)
            elif section == 'attachments':
                self.document['attachments'] = values['count']
            else:
                raise RunStateError('run-state-section')
            self._write()

    @property
    def boot_chain(self):
        return list(self.document['boot_chain'])

    def extend_boot_chain(self, boot_id):
        """Append a boot the controller confirmed; `identities.boot_id` follows it in the same write."""
        with self._lock:
            chain = self.document['boot_chain']
            if not chain or boot_id in chain or len(chain) >= MAX_PLANNED_REBOOTS + self.planned_power_cuts + 1:
                raise RunStateError('run-state-boot-chain')
            chain.append(_name(boot_id))
            self.document['identities']['boot_id'] = boot_id
            self._write()

    def deadline(self, name, seconds):
        """Record an absolute deadline `seconds` from now on the host's real-time clock."""
        self.update('deadlines', **{name: time.time() + seconds})

    def budget(self, name):
        return self.document['budgets'][name]

    def record(self, name, value):
        """Record `value` as spent before it is used; a value past the limit or a failed write refuses."""
        with self._lock:
            if name not in BUDGETS or type(value) is not int:
                raise RunStateError('run-state-budget-exhausted')
            bound = limit(name, self.planned_reboots, self.planned_power_cuts, self.planned_session_rotations)
            if not 0 <= value <= bound:
                raise RunStateError('run-state-budget-exhausted')
            if value > self.document['budgets'][name]:
                self.document['budgets'][name] = value
                self._write()

    def spend(self, name):
        with self._lock:
            self.record(name, self.document['budgets'][name] + 1)
            return self.document['budgets'][name]


def of(run):
    """The state this controller holds for `run`, or None when it has none."""
    cache = getattr(run, '_cache', None)
    return cache.get('run_state') if cache is not None else None
