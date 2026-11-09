"""Local stand ownership and evidence retention. No resource cleanup is executed."""

import hashlib
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
import uuid

from .report import read_json

SCHEMA = "rosetun.matrix.resources.v1"
STATES = ("preparing", "prepared", "error", "quarantined")
DEVICES = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
           *(f"{prefix}{i}" for prefix in ("COM", "LPT") for i in "0123456789¹²³")}


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
    if os.name == "posix":
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


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
            record["problems"] = ["preparation-is-not-execution", "resource-state-unverified"]
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
                "verify file containment and resource absence before manually archiving records"
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


class StandLease:
    """One-shot lease; re-entry fails, repeated release is harmless. Never unlink locks."""

    def __init__(self, state_directory, stand_id):
        self._root = _state_path(state_directory)
        self._stand = _identifier(stand_id)
        self._stream = None
        self._used = False
        self._pid = None
        self._lock_path = None

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
        locks = self._root / "locks"
        _no_links(locks)
        locks.mkdir(parents=True, exist_ok=True)
        path = locks / (hashlib.sha256(self._stand.encode()).hexdigest() + ".lock")
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
        self._stream = stream
        self._pid = os.getpid()
        self._lock_path = path
        try:
            self._check_live()
            # Old metadata never authorizes reuse, even after the OS lock is free.
            if any(run["stand_id"] in (None, self._stand) for run in inspect_runs(self._root)):
                raise ValueError("stand has unresolved runs; inspect the recovery plan")
            stream.write(json.dumps({"stand_id": self._stand, "pid": os.getpid()}).encode())
            stream.truncate()
        except BaseException:
            self.release()
            raise
        return self

    def release(self):
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
        if data["state"] not in ("preparing", "prepared"):
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
        if data["state"] in ("error", "quarantined") and state == "prepared":
            raise ValueError("failed run cannot become prepared")
        if state in ("error", "quarantined"):
            _identifier(reason)
            data["reasons"].append(reason)
        elif reason is not None:
            raise ValueError("prepared state cannot have a failure reason")
        data["state"] = state
        _atomic_manifest(self.directory, data)


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
