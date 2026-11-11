"""Local stand ownership and evidence retention. No resource cleanup is executed."""

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
import uuid

from . import evidence
from .report import read_json, _unique_object, _invalid_constant

SCHEMA = "rosetun.matrix.resources.v1"
STATES = ("preparing", "prepared", "starting", "running", "stopping", "exited",
          "error", "quarantined")
DEVICES = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
           *(f"{prefix}{i}" for prefix in ("COM", "LPT") for i in "0123456789¹²³")}

EXECUTION_FILES = {'execution-identity': 'execution-identity.json',
                   'execution-summary': 'execution-summary.json'}


def execution_resources(data):
    entries = [r for r in data['resources'] if r['id'] in EXECUTION_FILES]
    if entries and {r['id']: r.get('path') for r in entries} != EXECUTION_FILES:
        raise ValueError('incomplete-execution-resources')
    return entries


def _identifier(value):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,95}", value):
        raise ValueError("invalid identifier")
    return value


def _keys(value, keys):
    if type(value) is not dict or set(value) != set(keys.split()):
        raise ValueError("invalid object fields")


def _text(value):
    if type(value) is not str or not value or len(value) > 1024:
        raise ValueError("invalid text field")


def _no_links(path):
    # lstat catches Windows junctions as well as symbolic links, including parents.
    for part in reversed((path, *path.parents)):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("symlink or reparse point is not allowed")


def _regular_file(path):
    _no_links(path)
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("expected a regular file")


def _state_path(value):
    path = Path(value)
    if not path.is_absolute() or str(path).startswith(("\\\\", "//")):
        raise ValueError("state directory must be an absolute local path")
    if ".." in path.parts:
        raise ValueError("parent traversal is not allowed")
    if os.name == "nt":
        import ctypes
        if ctypes.windll.kernel32.GetDriveTypeW(str(path.anchor)) != 3:
            raise ValueError("state directory requires a fixed local drive")
    _no_links(path)
    return path


def resource_path(run_directory, value):
    """Validate a portable relative entry, including all existing ancestors."""
    _text(value)
    parts = value.split("/")
    for part in parts:
        if (not part or part in (".", "..") or part.endswith((".", " "))
                or re.search(r'[\\:<>"|?*~\x00-\x1f]', part)
                or part.split(".")[0].rstrip(" ").upper() in DEVICES):
            raise ValueError("invalid relative resource path")
    if parts[0].casefold() == "manifest.json" or parts[0].casefold().startswith(".manifest-"):
        raise ValueError("reserved resource path")
    path = Path(run_directory).joinpath(*parts)
    _no_links(path)
    return path


def _file_key(value):
    # Use portable case-insensitive ownership even on a case-sensitive filesystem.
    return value.casefold()


def _resource(value, directory):
    if type(value) is not dict:
        raise ValueError("invalid resource")
    if value.get("kind") == "file":
        _keys(value, "id kind path")
        resource_path(directory, value["path"])
    elif value.get("kind") == "process":
        _keys(value, "id kind pid platform boot_id start_id executable")
        if type(value["pid"]) is not int or value["pid"] <= 0:
            raise ValueError("invalid process PID")
        if value["platform"] not in ("windows", "posix"):
            raise ValueError("invalid process platform")
        for key in ("boot_id", "start_id", "executable"):
            _text(value[key])
    else:
        raise ValueError("unsupported resource kind")
    _identifier(value["id"])


def read_manifest(directory, *, run_id=None, stand_id=None, owner_token=None):
    """Read strictly; optional expected identities come from the caller's record."""
    directory = Path(directory)
    _regular_file(directory / "manifest.json")
    data, _ = read_json(directory / "manifest.json")
    _keys(data, "schema run_id stand_id owner_token state resources reasons")
    if data["schema"] != SCHEMA:
        raise ValueError("unsupported resource manifest schema")
    for key in ("run_id", "stand_id"):
        _identifier(data[key])
    if type(data["owner_token"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", data["owner_token"]):
        raise ValueError("invalid owner identity")
    for key, expected in (("run_id", run_id), ("stand_id", stand_id), ("owner_token", owner_token)):
        if expected is not None and data[key] != expected:
            raise ValueError("run ownership mismatch")
    if directory.name != data["run_id"]:
        raise ValueError("run directory identity mismatch")
    if type(data["state"]) is not str or data["state"] not in STATES:
        raise ValueError("invalid preparation state")
    if type(data["resources"]) is not list or type(data["reasons"]) is not list:
        raise ValueError("invalid manifest collections")
    ids, paths = set(), set()
    for entry in data["resources"]:
        _resource(entry, directory)
        if entry["id"] in ids or (entry["kind"] == "file" and _file_key(entry["path"]) in paths):
            raise ValueError("duplicate resource")
        ids.add(entry["id"])
        if entry["kind"] == "file":
            paths.add(_file_key(entry["path"]))
    for reason in data["reasons"]:
        _identifier(reason)
    if data["state"] in ("error", "quarantined") and not data["reasons"]:
        raise ValueError("missing failure reason")
    return data


def _atomic_manifest(directory, data):
    _no_links(directory / "manifest.json")
    fd, name = tempfile.mkstemp(prefix=".manifest-", dir=directory)
    # A failed write retains its temporary evidence; readers never infer ownership from it.
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(data, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(name, directory / "manifest.json")
    evidence.fsync_directory(directory)


def _proc_text(path):
    return Path(path).read_text()


def _process_status(resource):
    """Compare one recorded process with the live host. No side effects."""
    if resource['platform'] != 'posix':
        return 'unknown'
    try:
        boot = _proc_text('/proc/sys/kernel/random/boot_id').strip()
    except (OSError, ValueError):
        return 'unknown'
    if boot != resource['boot_id']:
        return 'absent'
    try:
        text = _proc_text(f"/proc/{resource['pid']}/stat")
    except (FileNotFoundError, ProcessLookupError):
        # A vanished pid reads as missing only when the boot id above was readable.
        return 'absent'
    except (OSError, ValueError):
        return 'unknown'
    try:
        start = text[text.rindex(')') + 2:].split()[19]
    except (ValueError, IndexError):
        return 'unknown'
    return 'alive' if start == resource['start_id'] else 'absent'


def _start_intent_recorded(directory):
    """True unless the journal is provably free of a `start intent` row.

    A missing journal means the controller never got as far as writing one.
    Anything unreadable, oversized or malformed counts as recorded.
    """
    try:
        path = resource_path(directory, 'lifecycle.jsonl')
        _no_links(path)
        with path.open('rb') as stream:
            raw = stream.read(256 * 1024 + 1)
        if len(raw) > 256 * 1024:
            return True
        for line in raw.splitlines():
            row = json.loads(line, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
            if type(row) is not dict or row.get('action') == 'start' and row.get('result') == 'intent':
                return True
        return False
    except FileNotFoundError:
        return False
    except (OSError, ValueError, RecursionError):
        return True


def _may_have_spawned(directory, data):
    """Whether a run with no process resource could still own a QEMU process.

    The process is registered only after it is spawned, so a controller that
    died in between leaves a live QEMU and no record of it.
    """
    if data['state'] in ('prepared', 'error'):
        return False
    if data['state'] == 'quarantined':
        return _start_intent_recorded(directory)
    return True


def _reconcile(directory, data):
    processes = [{'id': r['id'], 'pid': r['pid'], 'status': _process_status(r)}
                 for r in data['resources'] if r['kind'] == 'process']
    statuses = {p['status'] for p in processes}
    if not processes and _may_have_spawned(directory, data):
        statuses.add('unknown')
    overall = 'alive' if 'alive' in statuses else 'unknown' if 'unknown' in statuses else 'absent'
    return {'run_id': data['run_id'], 'status': overall, 'processes': processes}


def reconcile_run(state_directory, run_id):
    """Report whether the recorded VM processes of one run still exist.

    Only the manifest, the lifecycle journal and /proc are read. `absent` means
    every recorded process is provably gone. A run with no process record is
    `absent` only if it could not have spawned one: state `prepared` or `error`,
    or `quarantined` without a `start intent` row in `lifecycle.jsonl` (no
    journal at all counts). Any other such run (`starting`, `running`,
    `stopping`, `exited`, `quarantined` with that row, an unreadable journal)
    is `unknown`, because QEMU is registered only after it is spawned and the
    controller may have died in between. `unknown` also means identity could
    not be established.
    """
    directory = _state_path(state_directory) / 'runs' / _identifier(run_id)
    return _reconcile(directory, read_manifest(directory, run_id=run_id))


def inspect_runs(state_directory):
    """Read-only inventory. Invalid evidence has no inferred owner or stand."""
    root = _state_path(state_directory) / "runs"
    _no_links(root)
    result = []
    if not root.exists():
        return result
    for directory in sorted(root.iterdir()):
        try:
            data = read_manifest(directory)
            record = {key: data[key] for key in ("run_id", "stand_id", "state", "resources", "reasons")}
            record["problems"] = ["resource-state-unverified", "no-scenario-or-security-evidence"]
            record['completion_verified'] = completion_verified(directory, data)
            if record['completion_verified']:
                record['problems'].remove('resource-state-unverified')
            if data["state"] in ("preparing", "prepared"):
                record["problems"].append("preparation-is-not-execution")
            reconciliation = _reconcile(directory, data)
            record["process_status"] = reconciliation["status"]
            record["processes"] = reconciliation["processes"]
            result.append(record)
        except (OSError, ValueError, RecursionError):
            # Never print raw JSON, exception text or an untrusted directory name.
            result.append({"state": "quarantined", "problems": ["unreadable-or-invalid-manifest"],
                           "stand_id": None, "run_id": None})
    return result


def recovery_plan(state_directory):
    runs = inspect_runs(state_directory)
    return {"schema": "rosetun.matrix.recovery.v1", "dry_run": True,
            "runs": runs, "actions": [
                "retain evidence; independently establish ownership of invalid entries",
                "verify process boot and creation identity before considering any PID action",
                "when process_status is absent, recover --run-id R --archive releases the stand"
            ] if runs else [], "cleanup_executed": False}


def _lock(stream, acquire):
    stream.seek(0)
    if os.name == "nt":
        import msvcrt
        msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK if acquire else msvcrt.LK_UNLCK, 1)
    elif os.name == "posix":
        import fcntl
        fcntl.flock(stream.fileno(), (fcntl.LOCK_EX | fcntl.LOCK_NB) if acquire else fcntl.LOCK_UN)
    else:
        raise ValueError("local lease platform is unsupported")


def _lock_stand(root, stand):
    """Take the OS lock of a stand; the file is never unlinked or rewritten here."""
    locks = root / "locks"
    _no_links(locks)
    locks.mkdir(parents=True, exist_ok=True)
    path = locks / (hashlib.sha256(stand.encode()).hexdigest() + ".lock")
    _no_links(path)
    if path.exists():
        _regular_file(path)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    stream = os.fdopen(fd, "r+b", buffering=0)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("expected a regular lock file")
        _lock(stream, True)
    except OSError:
        stream.close()
        raise ValueError("stand is already leased") from None
    except BaseException:
        stream.close()
        raise
    return stream, path


class StandLease:
    """One-shot lease; re-entry fails, repeated release is harmless. Never unlink locks."""

    def __init__(self, state_directory, stand_id):
        self._root = _state_path(state_directory)
        self._stand = _identifier(stand_id)
        self._stream = None
        self._used = False
        self._pid = None
        self._lock_path = None
        self._active = set()

    def _check_live(self):
        if self._stream is None or self._pid != os.getpid():
            raise ValueError("run requires its original process and live stand lease")
        _regular_file(self._lock_path)
        current = self._lock_path.stat()
        held = os.fstat(self._stream.fileno())
        if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
            raise ValueError("stand lock file was replaced; retain resources")

    def acquire(self):
        if self._used:
            raise ValueError("lease cannot be re-entered")
        self._used = True
        stream, path = _lock_stand(self._root, self._stand)
        self._stream = stream
        self._pid = os.getpid()
        self._lock_path = path
        try:
            self._check_live()
            # Old metadata never authorizes reuse, even after the OS lock is free.
            if any(run["stand_id"] in (None, self._stand) and not run.get('completion_verified', False)
                   for run in inspect_runs(self._root)):
                raise ValueError("stand has unresolved runs; inspect the recovery plan")
            stream.write(json.dumps({"stand_id": self._stand, "pid": os.getpid()}).encode())
            stream.truncate()
        except BaseException:
            self.release()
            raise
        return self

    def release(self):
        if self._pid == os.getpid() and self._active:
            raise ValueError("stand lease has an unconfirmed VM exit")
        if self._stream is not None:
            stream, self._stream = self._stream, None
            try:
                # flock is shared across fork; unlocking in the child releases the parent's lease.
                if self._pid == os.getpid():
                    _lock(stream, False)
            finally:
                stream.close()

    def __enter__(self):
        return self.acquire()

    def __exit__(self, *args):
        self.release()


ARCHIVE_SCHEMA = "rosetun.matrix.archive.v1"


class ArchiveRefused(ValueError):
    """A named, expected refusal; nothing was changed."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def archive_run(state_directory, run_id):
    """Move one reconciled run from runs/ to archive/ so it stops blocking its stand.

    Nothing is deleted or signalled and the run's files are not touched: the
    directory is renamed as a whole. A held stand lock means a live controller.
    """
    try:
        root = _state_path(state_directory)
        _identifier(run_id)
    except ValueError:
        raise ArchiveRefused("invalid-run-id") from None
    source = root / "runs" / run_id
    _no_links(source)
    if not source.is_dir():
        raise ArchiveRefused("run-not-found")
    try:
        stand = read_manifest(source, run_id=run_id)["stand_id"]
    except (OSError, ValueError, RecursionError):
        raise ArchiveRefused("run-manifest-invalid") from None
    try:
        stream, _ = _lock_stand(root, stand)
    except ValueError:
        raise ArchiveRefused("stand-locked") from None
    try:
        # Read again under the lock: only now can nobody else change the run.
        try:
            data = read_manifest(source, run_id=run_id, stand_id=stand)
        except (OSError, ValueError, RecursionError):
            raise ArchiveRefused("run-manifest-invalid") from None
        reconciliation = _reconcile(source, data)
        if reconciliation["status"] != "absent":
            raise ArchiveRefused("process-" + reconciliation["status"])
        target_parent = root / "archive"
        target, record_path = target_parent / run_id, target_parent / (run_id + ".archive.json")
        _no_links(target_parent)
        for path in (target, record_path):
            if os.path.lexists(path):
                raise ArchiveRefused("archive-exists")
        record = {"schema": ARCHIVE_SCHEMA, "run_id": run_id, "stand_id": stand,
                  "previous_state": data["state"], "previous_reasons": data["reasons"],
                  "completion_verified": completion_verified(source, data),
                  "processes": reconciliation["processes"],
                  "utc": datetime.now(timezone.utc).isoformat()}
        target_parent.mkdir(exist_ok=True)
        os.rename(source, target)
        evidence.fsync_directory(source.parent)
        evidence.fsync_directory(target_parent)
        with record_path.open("x", encoding="utf-8", newline="\n") as record_stream:
            json.dump(record, record_stream, sort_keys=True, indent=2)
            record_stream.write("\n")
            record_stream.flush()
            os.fsync(record_stream.fileno())
        evidence.fsync_directory(target_parent)
        return {"schema": ARCHIVE_SCHEMA, "archived": True, "run_id": run_id,
                "stand_id": stand, "record": "archive/" + record_path.name}
    finally:
        _lock(stream, False)
        stream.close()


@dataclass(frozen=True, repr=False)
class PreparedRun:
    """Mutable resource ledger bound to an immutable identity and a live lease."""

    _lease: StandLease
    _identity: tuple[str, str, str]

    @property
    def directory(self):
        return self._lease._root / "runs" / self._identity[0]

    def _read(self):
        self._lease._check_live()
        return read_manifest(self.directory, run_id=self._identity[0],
                             stand_id=self._identity[1], owner_token=self._identity[2])

    def register(self, resource):
        data = self._read()
        if data["state"] not in ("preparing", "prepared", "starting"):
            raise ValueError("run is no longer accepting resources")
        _resource(resource, self.directory)
        if any(entry["id"] == resource["id"] or
               (entry["kind"] == resource["kind"] == "file"
                and _file_key(entry["path"]) == _file_key(resource["path"]))
               for entry in data["resources"]):
            raise ValueError("duplicate resource")
        data["resources"].append(resource)
        _atomic_manifest(self.directory, data)

    def mark(self, state, reason=None):
        data = self._read()
        if state not in STATES or state == "preparing":
            raise ValueError("invalid state transition")
        transitions = {
            "preparing": ("prepared",), "prepared": ("prepared", "starting"),
            "starting": ("running", "stopping", "exited"),
            "running": ("stopping", "exited"), "stopping": ("exited",),
            "exited": (), "error": (), "quarantined": ("stopping", "exited"),
        }
        if state not in ("error", "quarantined") and state not in transitions[data["state"]]:
            raise ValueError("invalid run state transition")
        if state in ("error", "quarantined"):
            _identifier(reason)
            data["reasons"].append(reason)
        elif reason is not None:
            raise ValueError("prepared state cannot have a failure reason")
        data["state"] = state
        _atomic_manifest(self.directory, data)

    def _complete(self, exits, vm_uuid):
        data = self._read()
        processes = [r for r in data['resources'] if r['kind'] == 'process']
        if (data['state'] != 'exited' or not processes
                or [e['resource'] for e in exits] != processes
                or any(type(e['returncode']) is not int for e in exits)):
            raise ValueError('completion-process-evidence-mismatch')
        journal = resource_path(self.directory, 'lifecycle.jsonl')
        proof = {'schema': 'rosetun.matrix.completion.v1', 'run_id': data['run_id'],
                 'stand_id': data['stand_id'], 'owner_digest': hashlib.sha256(data['owner_token'].encode()).hexdigest(),
                 'vm_uuid': vm_uuid, 'resources': data['resources'], 'exits': exits,
                 'controls_closed': True, 'retained_artifacts': True,
                 'journal_sha256': hashlib.sha256(journal.read_bytes()).hexdigest()}
        evidence.write_file(self, 'completion.json', json.dumps(proof, sort_keys=True).encode(),
                            mode='create', sync_parent=True)
        if not completion_verified(self.directory, self._read()):
            raise ValueError('completion-readback-failed')


def completion_verified(directory, data):
    """Consistency evidence only; a malicious local owner can forge these files."""
    if data['state'] != 'exited':
        return False
    try:
        path = resource_path(directory, 'completion.json')
        _regular_file(path)
        if path.stat().st_size > 256 * 1024:
            return False
        proof, _ = read_json(path)
        _keys(proof, 'schema run_id stand_id owner_digest vm_uuid resources exits controls_closed retained_artifacts journal_sha256')
        uuid.UUID(proof['vm_uuid'])
        if (proof['schema'] != 'rosetun.matrix.completion.v1'
                or proof['run_id'] != data['run_id'] or proof['stand_id'] != data['stand_id']
                or proof['owner_digest'] != hashlib.sha256(data['owner_token'].encode()).hexdigest()
                or proof['resources'] != data['resources'] or proof['controls_closed'] is not True
                or proof['retained_artifacts'] is not True):
            return False
        processes = [r for r in data['resources'] if r['kind'] == 'process']
        if not processes or type(proof['exits']) is not list:
            return False
        for item in proof['exits']:
            _keys(item, 'resource returncode')
            if type(item['returncode']) is not int:
                return False
        if [e['resource'] for e in proof['exits']] != processes:
            return False
        files = {r['path'] for r in data['resources'] if r['kind'] == 'file'}
        if not {'completion.json', 'lifecycle.jsonl', 'qemu-stderr.log', 'launch-plan.json',
                'preparation.jsonl', 'root.qcow2'} <= files:
            return False
        for name in files:
            _regular_file(resource_path(directory, name))
        journal = resource_path(directory, 'lifecycle.jsonl')
        if journal.stat().st_size > 256 * 1024:
            return False
        raw = journal.read_bytes()
        if not raw.endswith(b'\n') or hashlib.sha256(raw).hexdigest() != proof['journal_sha256']:
            return False
        rows = [json.loads(line, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
                for line in raw.splitlines()]
        from datetime import datetime
        for row in rows:
            _keys(row, 'schema sequence action result utc run_id stand_id vm_uuid')
            if row['schema'] != 'rosetun.matrix.lifecycle.v2' or datetime.fromisoformat(row['utc']).tzinfo is None:
                return False
        plan_path = resource_path(directory, 'launch-plan.json')
        if plan_path.stat().st_size > 256 * 1024:
            return False
        plan, _ = read_json(plan_path)
        qga = plan.get('config', {}).get('qga', False)
        if type(qga) is not bool:
            return False
        if qga:
            closures = [index for index, row in enumerate(rows)
                        if row['action'] == 'qga']
            exits = [index for index, row in enumerate(rows)
                     if row['action'] == 'exit' and row['result'] == 'child-reaped']
            if ('qga-observations.jsonl' not in files or not closures or not exits
                    or rows[closures[-1]]['result'] != 'closed'
                    or not exits[-1] < closures[-1] < len(rows) - 1):
                return False
        if proof['vm_uuid'] != plan['uuid']:
            return False
        if not rows or rows[-1]['action'] != 'completion' or rows[-1]['result'] != 'controls-closed-child-reaped':
            return False
        return all(row['run_id'] == data['run_id'] and row['stand_id'] == data['stand_id']
                   and row['vm_uuid'] == proof['vm_uuid'] and row['sequence'] == index
                   for index, row in enumerate(rows, 1))
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
        return False


def create_run(lease, run_id=None):
    """Exclusively create a preparation record; this is never a test result."""
    lease._check_live()
    run_id = _identifier(uuid.uuid4().hex if run_id is None else run_id)
    if run_id.upper() in DEVICES:
        raise ValueError("reserved run identifier")
    directory = lease._root / "runs" / run_id
    _no_links(directory)
    directory.parent.mkdir(exist_ok=True)
    directory.mkdir()
    token = secrets.token_hex(32)
    _atomic_manifest(directory, {"schema": SCHEMA, "run_id": run_id,
                     "stand_id": lease._stand, "owner_token": token,
                     "state": "prepared", "resources": [], "reasons": []})
    return PreparedRun(lease, (run_id, lease._stand, token))
