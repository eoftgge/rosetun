"""Autonomous local ledger tests; children only hold locks or exit."""

import json
from dataclasses import FrozenInstanceError
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from tools.vm.matrix.resources import (
    ArchiveRefused, StandLease, archive_run, create_run, inspect_runs, read_manifest,
    recovery_plan, reconcile_run, resource_path,
)

ROOT = Path(__file__).resolve().parents[4]
CHILD = """
import os, sys
from pathlib import Path
from tools.vm.matrix.resources import StandLease
try:
    with StandLease(Path(sys.argv[1]), sys.argv[2]):
        print('locked', flush=True)
        if sys.argv[3] == 'crash':
            os._exit(17)
        if sys.argv[3] == 'hold':
            Path(sys.argv[4]).write_text('ready')
            sys.stdin.readline()
except ValueError:
    print('refused', flush=True)
    sys.exit(3)
"""


class ResourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "state"

    def child(self, stand="stand-a", mode="exit"):
        return subprocess.run([sys.executable, "-B", "-c", CHILD, str(self.root), stand, mode],
                              cwd=ROOT, capture_output=True, text=True, timeout=10)

    def write(self, run, data):
        (run.directory / "manifest.json").write_text(json.dumps(data), encoding="utf-8")

    def test_exclusive_directory_and_no_test_completion(self):
        with StandLease(self.root, "stand-a") as lease:
            run = create_run(lease, "run-a")
            original = (run.directory / "manifest.json").read_bytes()
            with self.assertRaises(FileExistsError):
                create_run(lease, "run-a")
            self.assertEqual(original, (run.directory / "manifest.json").read_bytes())
            self.assertEqual(["manifest.json"], [p.name for p in run.directory.iterdir()])
            self.assertEqual("prepared", read_manifest(run.directory)["state"])

    def test_competing_process_and_independent_stands(self):
        with StandLease(self.root, "stand-a"):
            self.assertEqual(3, self.child().returncode)
            self.assertEqual(0, self.child("stand-b").returncode)
            with self.assertRaises(ValueError):
                StandLease(self.root, "stand-a").acquire()
        self.assertEqual(0, self.child().returncode)

    def test_simultaneous_contenders_have_exactly_one_owner(self):
        gate = Path(self.temp.name) / "gate"
        code = """
import sys, time
from pathlib import Path
from tools.vm.matrix.resources import StandLease
gate, marker = Path(sys.argv[2]), Path(sys.argv[3])
deadline = time.monotonic() + 5
while not gate.exists():
    if time.monotonic() >= deadline:
        sys.exit(22)
    time.sleep(0.01)
try:
    with StandLease(sys.argv[1], 'stand-a'):
        marker.write_text('locked')
        sys.stdin.readline()
except ValueError:
    marker.write_text('refused')
"""
        children = []
        markers = [Path(self.temp.name) / f"result-{index}" for index in range(2)]
        try:
            for marker in markers:
                children.append(subprocess.Popen(
                    [sys.executable, "-B", "-c", code, str(self.root), str(gate), str(marker)],
                    cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE))
            gate.write_text("start", encoding="utf-8")
            deadline = time.monotonic() + 5
            while not all(marker.exists() for marker in markers) and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(all(marker.exists() for marker in markers), "contenders timed out")
            self.assertEqual(["locked", "refused"], sorted(marker.read_text() for marker in markers))
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.communicate(timeout=10)

    def test_process_exit_releases_os_lock(self):
        for mode, code in (("exit", 0), ("crash", 17)):
            with self.subTest(mode=mode):
                self.assertEqual(code, self.child(mode=mode).returncode)
                with StandLease(self.root, "stand-a"):
                    pass

    def test_killed_owner_releases_os_lock(self):
        ready = Path(self.temp.name) / "ready"
        child = subprocess.Popen([sys.executable, "-B", "-c", CHILD, str(self.root), "stand-a", "hold", str(ready)],
                                 cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(ready.exists(), "holder did not become ready within timeout")
            self.assertEqual(3, self.child().returncode)
        finally:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)
        with StandLease(self.root, "stand-a"):
            pass

    def test_abrupt_preparation_retains_ledger_and_blocks_reuse(self):
        code = """
import os, sys
from tools.vm.matrix.resources import StandLease, create_run
with StandLease(sys.argv[1], 'stand-a') as lease:
    run = create_run(lease, 'interrupted')
    run.register({'id': 'overlay', 'kind': 'file', 'path': 'disk'})
    (run.directory / 'disk').write_bytes(b'evidence')
    os._exit(17)
"""
        result = subprocess.run([sys.executable, "-B", "-c", code, str(self.root)], cwd=ROOT,
                                capture_output=True, timeout=10)
        self.assertEqual(17, result.returncode)
        self.assertEqual(b"evidence", (self.root / "runs/interrupted/disk").read_bytes())
        self.assertEqual(3, self.child().returncode)

    def test_reentry_and_double_release(self):
        lease = StandLease(self.root, "stand-a")
        lease.acquire()
        with self.assertRaises(ValueError):
            lease.acquire()
        lease.release()
        lease.release()
        with self.assertRaises(ValueError):
            lease.acquire()

    def test_stale_metadata_does_not_authorize_unfinished_resources(self):
        with StandLease(self.root, "stand-a") as lease:
            run = create_run(lease)
            run.register({"id": "overlay", "kind": "file", "path": "disk.qcow2"})
        for lock in (self.root / "locks").iterdir():
            lock.write_text('{"pid": 99999999}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unresolved"):
            StandLease(self.root, "stand-a").acquire()
        with StandLease(self.root, "stand-b"):
            pass
        with self.assertRaises(ValueError):
            run.mark("quarantined", "interrupted")

    def test_identity_mismatch_and_immutable_updates(self):
        with StandLease(self.root, "stand-a") as lease:
            run = create_run(lease)
            data = read_manifest(run.directory)
            with self.assertRaises(FrozenInstanceError):
                run._identity = ("foreign", "foreign", "0" * 64)
            self.assertNotIn(data["owner_token"], repr(run))
            for expected in ({"run_id": "foreign"}, {"stand_id": "foreign"}, {"owner_token": "0" * 64}):
                with self.assertRaises(ValueError):
                    read_manifest(run.directory, **expected)
            run.register({"id": "qemu", "kind": "process", "pid": 123,
                          "platform": "windows", "boot_id": "boot-a",
                          "start_id": "creation-filetime-123", "executable": "qemu-system-x86_64"})
            run.mark("quarantined", "interrupted")
            after = read_manifest(run.directory)
            for key in ("run_id", "stand_id", "owner_token"):
                self.assertEqual(data[key], after[key])
            with self.assertRaises(ValueError):
                run.mark("prepared")
            data["owner_token"] = "0" * 64
            self.write(run, data)
            with self.assertRaises(ValueError):
                run.register({"id": "file", "kind": "file", "path": "x"})

    def test_strict_schema_types_and_duplicate_json(self):
        with StandLease(self.root, "stand-a") as lease:
            run = create_run(lease)
            original = read_manifest(run.directory)
            variants = [{"schema": "future"}, {"schema": True}, {"extra": 1},
                        {"run_id": []}, {"run_id": "foreign"}, {"stand_id": False}, {"owner_token": 1},
                        {"state": []}, {"resources": {}}, {"reasons": "bad"},
                        {"reasons": [1]}, {"state": "quarantined"},
                        {"resources": [{"kind": "file", "id": "a", "path": 7}]},
                        {"resources": [{"kind": "file", "id": "a", "path": "x", "extra": True}]},
                        {"resources": [{"kind": "unknown", "id": "a"}]},
                        {"resources": [{"kind": "process", "id": "a", "pid": True,
                                        "platform": "windows", "boot_id": "a", "start_id": "b", "executable": "c"}]}]
            for changes in variants:
                with self.subTest(changes=changes):
                    self.write(run, {**original, **changes})
                    with self.assertRaises(ValueError):
                        read_manifest(run.directory)
            for raw in ('{', '{"owner_token":"hidden",', '{"schema":1,"schema":2}', 'NaN'):
                (run.directory / "manifest.json").write_text(raw, encoding="utf-8")
                with self.assertRaises(ValueError):
                    read_manifest(run.directory)
        with self.assertRaises(ValueError):
            StandLease(self.root, "stand-b").acquire()
        self.assertIsNone(inspect_runs(self.root)[0]["stand_id"])

    def test_missing_manifest_is_not_assigned_from_directory_name(self):
        (self.root / "runs" / "looks-like-stand-a").mkdir(parents=True)
        self.assertIsNone(inspect_runs(self.root)[0]["run_id"])
        self.assertIsNone(inspect_runs(self.root)[0]["stand_id"])
        with self.assertRaisesRegex(ValueError, "unresolved"):
            StandLease(self.root, "stand-b").acquire()

    def test_portable_path_restrictions(self):
        bad = ("../outside", "a/../../x", "/tmp/x", "C:/x", "C:x", "\\\\server\\share",
               "//server/share", "a\\..\\x", "a//b", "./x", "a/../x", "x:stream",
               "NUL", "con.txt", "CON .txt", "COM¹.log", "LPT²", "CONIN$", "CONOUT$",
               "a. /x", "a./x", "manifest.json", ".manifest-x", "MANIFEST.JSON",
               ".MANIFEST-TEMP/x", "MANIFE~1.JSO", "longna~1/file")
        for path in bad:
            with self.subTest(path=path), self.assertRaises(ValueError):
                resource_path(self.root, path)

    def test_case_aliases_are_not_two_owned_files(self):
        with StandLease(self.root, "stand-a") as lease:
            run = create_run(lease)
            run.register({"id": "first", "kind": "file", "path": "Disks/Root.qcow2"})
            with self.assertRaisesRegex(ValueError, "duplicate"):
                run.register({"id": "second", "kind": "file", "path": "disks/root.qcow2"})
            data = read_manifest(run.directory)
            data["resources"].append({"id": "second", "kind": "file", "path": "disks/root.qcow2"})
            self.write(run, data)
            with self.assertRaisesRegex(ValueError, "duplicate"):
                read_manifest(run.directory)

    def test_first_manifest_failure_retains_unknown_directory(self):
        with StandLease(self.root, "stand-a") as lease:
            with patch("tools.vm.matrix.resources.os.replace", side_effect=OSError("interrupted")):
                with self.assertRaises(OSError):
                    create_run(lease, "interrupted")
        directory = self.root / "runs/interrupted"
        self.assertTrue(directory.is_dir())
        self.assertTrue(list(directory.glob(".manifest-*")))
        self.assertIsNone(inspect_runs(self.root)[0]["stand_id"])
        with self.assertRaisesRegex(ValueError, "unresolved"):
            StandLease(self.root, "stand-a").acquire()

    def test_dos_run_ids_are_rejected(self):
        with StandLease(self.root, "stand-a") as lease:
            for run_id in ("CON", "nul", "LPT1"):
                with self.subTest(run_id=run_id), self.assertRaises(ValueError):
                    create_run(lease, run_id)

    @unittest.skipUnless(os.name == "posix", "FIFO fixture requires POSIX; untested on this OS")
    def test_fifo_manifest_is_quarantined_without_reading_it(self):
        directory = self.root / "runs/fifo"
        directory.mkdir(parents=True)
        os.mkfifo(directory / "manifest.json")
        result = subprocess.run([sys.executable, "-B", "-m", "tools.vm.matrix", "recover",
                                 "--state-directory", str(self.root)], cwd=ROOT,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(0, result.returncode)
        self.assertEqual("quarantined", json.loads(result.stdout)["runs"][0]["state"])

    @unittest.skipUnless(hasattr(os, "fork"), "fork ownership requires POSIX; untested on this OS")
    def test_fork_child_cannot_use_or_unlock_parent_lease(self):
        code = """
import os, subprocess, sys
from tools.vm.matrix.resources import StandLease, create_run
with StandLease(sys.argv[1], 'stand-a') as lease:
    child = os.fork()
    if child == 0:
        try:
            create_run(lease, 'child')
        except ValueError:
            lease.release()
            os._exit(0)
        os._exit(21)
    _, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    code = 'from tools.vm.matrix.resources import StandLease; import sys; StandLease(sys.argv[1], "stand-a").acquire()'
    result = subprocess.run([sys.executable, '-B', '-c', code, sys.argv[1]], capture_output=True, timeout=5)
    assert result.returncode != 0 and b'already leased' in result.stderr
"""
        result = subprocess.run([sys.executable, "-B", "-c", code, str(self.root)], cwd=ROOT,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(0, result.returncode, result.stderr)

    @unittest.skipUnless(os.name == "posix", "open-file replacement fixture requires POSIX")
    def test_replaced_lock_blocks_mutation(self):
        with StandLease(self.root, "stand-a") as lease:
            run = create_run(lease)
            replacement = self.root / "replacement"
            replacement.write_bytes(b"")
            os.replace(replacement, lease._lock_path)
            with self.assertRaisesRegex(ValueError, "replaced"):
                run.mark("quarantined", "interrupted")

    def test_symlink_escape(self):
        with StandLease(self.root, "stand-a") as lease:
            run = create_run(lease)
            outside = Path(self.temp.name) / "outside"
            outside.mkdir()
            try:
                (run.directory / "escape").symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("OS/account cannot create symlink fixture; untested")
            with self.assertRaises(ValueError):
                run.register({"id": "escape", "kind": "file", "path": "escape/file"})
            with self.assertRaises(ValueError):
                StandLease(run.directory / "escape" / "state", "stand-b")

    def test_quarantine_preserves_files_and_inspection_is_read_only(self):
        with StandLease(self.root, "stand-a") as lease:
            run = create_run(lease)
            run.register({"id": "overlay", "kind": "file", "path": "disk"})
            (run.directory / "disk").write_bytes(b"evidence")
            run.mark("error", "preparation-failed")
            run.mark("quarantined", "interrupted")
        before = {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        self.assertTrue(recovery_plan(self.root)["dry_run"])
        self.assertEqual("quarantined", inspect_runs(self.root)[0]["state"])
        after = {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        for command in ("runs", "recover"):
            result = subprocess.run([sys.executable, "-B", "-m", "tools.vm.matrix", command,
                                     "--state-directory", str(self.root)], cwd=ROOT,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertNotIn(read_manifest(run.directory)["owner_token"], result.stdout)
        self.assertEqual(before, {p.relative_to(self.root): p.read_bytes()
                                 for p in self.root.rglob("*") if p.is_file()})
        missing = self.root / "missing"
        self.assertEqual([], inspect_runs(missing))
        self.assertEqual([], recovery_plan(missing)["runs"])
        self.assertFalse(missing.exists())
        result = subprocess.run([sys.executable, "-B", "-m", "tools.vm.matrix", "recover",
                                 "--state-directory", str(missing)], cwd=ROOT,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(0, result.returncode)
        self.assertFalse(missing.exists())

    def test_failed_atomic_replace_preserves_previous_manifest(self):
        with StandLease(self.root, "stand-a") as lease:
            run = create_run(lease)
            before = (run.directory / "manifest.json").read_bytes()
            with patch("tools.vm.matrix.resources.os.replace", side_effect=OSError("interrupted")):
                with self.assertRaises(OSError):
                    run.mark("quarantined", "interrupted")
            self.assertEqual(before, (run.directory / "manifest.json").read_bytes())
            self.assertTrue(list(run.directory.glob(".manifest-*")))

    @unittest.skipUnless(os.name == "posix", "POSIX adapter untested on this OS")
    def test_posix_adapter(self):
        self.test_competing_process_and_independent_stands()

    @unittest.skipUnless(os.name == "nt", "Windows adapter untested on this OS")
    def test_windows_adapter(self):
        self.test_competing_process_and_independent_stands()


BOOT = "0a1b2c3d-0000-4000-8000-000000000001"


def process_resource(pid, start, boot=BOOT, platform="posix"):
    return {"id": "qemu", "kind": "process", "pid": pid, "platform": platform,
            "boot_id": boot, "start_id": str(start), "executable": "/usr/bin/qemu-system-x86_64"}


def stat_text(pid, start):
    # Field 22 (starttime) is index 19 after the parenthesised command name.
    return f"{pid} (qemu (x)) S " + " ".join(["0"] * 18 + [str(start)]) + "\n"


def fake_proc(boot=BOOT, stats=None, error=None):
    stats = stats or {}

    def read(path):
        if error is not None:
            raise error
        if path == "/proc/sys/kernel/random/boot_id":
            return boot + "\n"
        if path in stats:
            return stats[path]
        raise FileNotFoundError(path)
    return patch("tools.vm.matrix.resources._proc_text", side_effect=read)


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "state"

    def run_with(self, *resources, run_id="run-a"):
        with StandLease(self.root, "stand-a") as lease:
            run = create_run(lease, run_id)
            for resource in resources:
                run.register(resource)
        return run_id

    def status(self, run_id="run-a"):
        return reconcile_run(self.root, run_id)

    def test_matching_boot_and_starttime_is_alive(self):
        run_id = self.run_with(process_resource(4242, 777))
        with fake_proc(stats={"/proc/4242/stat": stat_text(4242, 777)}):
            result = self.status(run_id)
        self.assertEqual("alive", result["status"])
        self.assertEqual([{"id": "qemu", "pid": 4242, "status": "alive"}], result["processes"])

    def test_missing_proc_entry_is_absent(self):
        run_id = self.run_with(process_resource(4242, 777))
        with fake_proc():
            self.assertEqual("absent", self.status(run_id)["status"])

    def test_foreign_boot_id_is_absent_without_reading_the_pid(self):
        run_id = self.run_with(process_resource(4242, 777, boot="another-boot"))
        with fake_proc(stats={"/proc/4242/stat": stat_text(4242, 777)}):
            self.assertEqual("absent", self.status(run_id)["status"])

    def test_reused_pid_with_another_starttime_is_absent(self):
        run_id = self.run_with(process_resource(4242, 777))
        with fake_proc(stats={"/proc/4242/stat": stat_text(4242, 778)}):
            self.assertEqual("absent", self.status(run_id)["status"])

    def test_unreadable_proc_is_unknown(self):
        run_id = self.run_with(process_resource(4242, 777))
        for error in (PermissionError("denied"), FileNotFoundError("no /proc here"), OSError("io")):
            with self.subTest(error=type(error).__name__), fake_proc(error=error):
                self.assertEqual("unknown", self.status(run_id)["status"])

    def test_unreadable_stat_or_malformed_stat_is_unknown(self):
        run_id = self.run_with(process_resource(4242, 777))

        def read(path):
            if path.endswith("boot_id"):
                return BOOT
            raise PermissionError(path)
        with patch("tools.vm.matrix.resources._proc_text", side_effect=read):
            self.assertEqual("unknown", self.status(run_id)["status"])
        for text in ("garbage", "1 (x) S 0 0"):
            with self.subTest(text=text), fake_proc(stats={"/proc/4242/stat": text}):
                self.assertEqual("unknown", self.status(run_id)["status"])

    def test_windows_process_is_unknown_and_never_reads_proc(self):
        run_id = self.run_with(process_resource(4242, 777, platform="windows"))
        with fake_proc(stats={"/proc/4242/stat": stat_text(4242, 777)}) as read:
            self.assertEqual("unknown", self.status(run_id)["status"])
        read.assert_not_called()

    def test_run_without_a_process_is_absent(self):
        run_id = self.run_with({"id": "disk", "kind": "file", "path": "disk"})
        with fake_proc(error=PermissionError("not consulted")) as read:
            result = self.status(run_id)
        self.assertEqual({"run_id": run_id, "status": "absent", "processes": []}, result)
        read.assert_not_called()

    def run_in_state(self, state, journal=None, run_id="run-a"):
        path = {"prepared": (), "starting": ("starting",), "running": ("starting", "running"),
                "stopping": ("starting", "stopping"), "exited": ("starting", "exited"),
                "error": (), "quarantined": ()}[state]
        with StandLease(self.root, "stand-a") as lease:
            run = create_run(lease, run_id)
            for step in path:
                run.mark(step)
            if state == "error":
                run.mark("error", "preparation-failed")
            if state == "quarantined":
                run.mark("quarantined", "vm-start-failed")
            if journal is not None:
                (run.directory / "lifecycle.jsonl").write_bytes(journal)
        return run_id

    @staticmethod
    def rows(*pairs):
        return b"".join(json.dumps({"action": a, "result": r}).encode() + b"\n" for a, r in pairs)

    def test_states_that_cannot_have_started_a_process_are_absent_without_one(self):
        for state in ("prepared", "error"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as temp:
                self.root = Path(temp) / "state"
                run_id = self.run_in_state(state)
                self.assertEqual({"run_id": run_id, "status": "absent", "processes": []},
                                 self.status(run_id))

    def test_states_that_may_have_spawned_qemu_are_unknown_without_a_process(self):
        for state in ("starting", "running", "stopping", "exited"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as temp:
                self.root = Path(temp) / "state"
                run_id = self.run_in_state(state)
                self.assertEqual({"run_id": run_id, "status": "unknown", "processes": []},
                                 self.status(run_id))

    def test_quarantined_without_a_start_intent_is_absent(self):
        cases = {"no journal": None, "empty journal": b"",
                 "other rows": self.rows(("start", "error"), ("close", "intent"))}
        for name, journal in cases.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as temp:
                self.root = Path(temp) / "state"
                run_id = self.run_in_state("quarantined", journal)
                self.assertEqual("absent", self.status(run_id)["status"])

    def test_quarantined_with_a_start_intent_or_a_doubtful_journal_is_unknown(self):
        cases = {"start intent": self.rows(("start", "intent")),
                 "intent among others": self.rows(("prepare", "ok"), ("start", "intent"), ("start", "error")),
                 "truncated row": self.rows(("close", "intent")) + b'{"action": "sta',
                 "not an object": b"[]\n",
                 "oversized": b" " * (256 * 1024 + 1)}
        for name, journal in cases.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as temp:
                self.root = Path(temp) / "state"
                run_id = self.run_in_state("quarantined", journal)
                self.assertEqual("unknown", self.status(run_id)["status"])

    def test_quarantined_with_an_unreadable_journal_is_unknown(self):
        run_id = self.run_in_state("quarantined")
        (self.root / "runs" / run_id / "lifecycle.jsonl").mkdir()
        self.assertEqual("unknown", self.status(run_id)["status"])

    def test_alive_outranks_unknown_outranks_absent(self):
        second = dict(process_resource(5000, 1), id="helper")
        third = dict(process_resource(6000, 2, platform="windows"), id="other")
        run_id = self.run_with(process_resource(4242, 777), second, third)
        with fake_proc(stats={"/proc/4242/stat": stat_text(4242, 777)}):
            result = self.status(run_id)
        self.assertEqual("alive", result["status"])
        self.assertEqual(["alive", "absent", "unknown"], [p["status"] for p in result["processes"]])
        with fake_proc():
            self.assertEqual("unknown", self.status(run_id)["status"])

    def test_unreadable_manifest_is_an_error_not_a_status(self):
        directory = self.root / "runs" / "broken"
        directory.mkdir(parents=True)
        with self.assertRaises((OSError, ValueError)):
            reconcile_run(self.root, "broken")
        with self.assertRaises(ValueError):
            reconcile_run(self.root, "../broken")

    def test_inspection_and_recovery_show_the_status_and_change_nothing(self):
        run_id = self.run_with(process_resource(4242, 777))
        before = {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        with fake_proc(stats={"/proc/4242/stat": stat_text(4242, 777)}):
            record = inspect_runs(self.root)[0]
            plan = recovery_plan(self.root)
        self.assertEqual("alive", record["process_status"])
        self.assertEqual("alive", plan["runs"][0]["process_status"])
        self.assertEqual(run_id, record["run_id"])
        self.assertEqual(before, {p.relative_to(self.root): p.read_bytes()
                                  for p in self.root.rglob("*") if p.is_file()})

    def test_unreadable_run_has_no_process_status(self):
        (self.root / "runs" / "broken").mkdir(parents=True)
        self.assertNotIn("process_status", inspect_runs(self.root)[0])

    @unittest.skipUnless(sys.platform.startswith("linux"), "needs the Linux /proc")
    def test_live_child_is_alive_and_a_reaped_child_is_absent(self):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            text = Path(f"/proc/{child.pid}/stat").read_text()
            start = text[text.rfind(")") + 2:].split()[19]
            boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            run_id = self.run_with(process_resource(child.pid, start, boot=boot))
            self.assertEqual("alive", self.status(run_id)["status"])
        finally:
            child.kill()
            child.wait(timeout=10)
        self.assertEqual("absent", self.status(run_id)["status"])


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "state"

    def make_run(self, run_id="run-a", stand="stand-a", *resources):
        with StandLease(self.root, stand) as lease:
            run = create_run(lease, run_id)
            for resource in resources:
                run.register(resource)
            run.mark("error", "preparation-failed")
        return run.directory

    def tree(self, base):
        # A held Windows byte-range lock makes the lock file unreadable.
        return {p.relative_to(base): p.read_bytes() for p in base.rglob("*")
                if p.is_file() and "locks" not in p.relative_to(base).parts}

    def refused(self, reason, run_id="run-a"):
        before = self.tree(self.root)
        with self.assertRaises(ArchiveRefused) as caught:
            archive_run(self.root, run_id)
        self.assertEqual(reason, caught.exception.reason)
        self.assertEqual(before, self.tree(self.root))

    def test_archiving_releases_the_stand_and_keeps_every_byte(self):
        directory = self.make_run("run-a", "stand-a", {"id": "disk", "kind": "file", "path": "disk"})
        (directory / "disk").write_bytes(b"evidence")
        with self.assertRaisesRegex(ValueError, "unresolved"):
            StandLease(self.root, "stand-a").acquire()
        before = self.tree(directory)
        with fake_proc():
            result = archive_run(self.root, "run-a")
        self.assertEqual({"schema": "rosetun.matrix.archive.v1", "archived": True, "run_id": "run-a",
                          "stand_id": "stand-a", "record": "archive/run-a.archive.json"}, result)
        self.assertFalse(directory.exists())
        self.assertEqual(before, self.tree(self.root / "archive" / "run-a"))
        record = json.loads((self.root / "archive" / "run-a.archive.json").read_text(encoding="utf-8"))
        self.assertEqual({"schema", "run_id", "stand_id", "previous_state", "previous_reasons",
                          "completion_verified", "processes", "utc"}, set(record))
        self.assertEqual(("error", ["preparation-failed"], []),
                         (record["previous_state"], record["previous_reasons"], record["processes"]))
        self.assertTrue(record["utc"].endswith("+00:00"))
        self.assertNotIn(read_manifest(self.root / "archive" / "run-a")["owner_token"],
                         json.dumps(record))
        self.assertEqual([], inspect_runs(self.root))
        with StandLease(self.root, "stand-a"):
            pass

    def test_process_status_is_recorded_for_each_process(self):
        self.make_run("run-a", "stand-a", process_resource(4242, 777))
        with fake_proc():
            archive_run(self.root, "run-a")
        record = json.loads((self.root / "archive" / "run-a.archive.json").read_text(encoding="utf-8"))
        self.assertEqual([{"id": "qemu", "pid": 4242, "status": "absent"}], record["processes"])

    def test_alive_and_unknown_processes_are_refused_with_a_reason(self):
        self.make_run("run-a", "stand-a", process_resource(4242, 777))
        with fake_proc(stats={"/proc/4242/stat": stat_text(4242, 777)}):
            self.refused("process-alive")
        with fake_proc(error=PermissionError("denied")):
            self.refused("process-unknown")
        self.make_run("run-w", "stand-w", process_resource(1, 1, platform="windows"))
        self.refused("process-unknown", "run-w")
        self.assertTrue((self.root / "runs" / "run-a").is_dir())
        self.assertFalse((self.root / "archive").exists())

    def test_run_quarantined_before_the_process_started_is_archived(self):
        with StandLease(self.root, "stand-a") as lease:
            run = create_run(lease, "run-a")
            run.mark("quarantined", "vm-start-failed")
        with fake_proc():
            self.assertTrue(archive_run(self.root, "run-a")["archived"])
        self.assertFalse((self.root / "runs" / "run-a").exists())

    def test_starting_run_without_a_process_is_refused_as_unknown(self):
        with StandLease(self.root, "stand-a") as lease:
            create_run(lease, "run-a").mark("starting")
        self.refused("process-unknown")
        self.assertTrue((self.root / "runs" / "run-a").is_dir())

    def test_held_stand_lock_means_a_live_controller(self):
        with StandLease(self.root, "stand-a") as lease:
            create_run(lease, "run-a")
            self.refused("stand-locked")
        with fake_proc():
            archive_run(self.root, "run-a")

    def test_existing_archive_target_or_record_is_refused(self):
        self.make_run()
        (self.root / "archive" / "run-a").mkdir(parents=True)
        (self.root / "archive" / "run-a" / "keep").write_bytes(b"older")
        with fake_proc():
            self.refused("archive-exists")
        (self.root / "archive" / "run-a" / "keep").unlink()
        (self.root / "archive" / "run-a").rmdir()
        (self.root / "archive" / "run-a.archive.json").write_bytes(b"older")
        with fake_proc():
            self.refused("archive-exists")

    def test_unreadable_foreign_and_missing_runs_are_not_touched(self):
        directory = self.make_run("run-a", "stand-a")
        foreign = self.make_run("run-b", "stand-b")
        (directory / "manifest.json").write_bytes((foreign / "manifest.json").read_bytes())
        (self.root / "runs" / "broken").mkdir()
        (self.root / "runs" / "broken" / "manifest.json").write_text("{", encoding="utf-8")
        (self.root / "runs" / "empty").mkdir()
        with fake_proc():
            self.refused("run-manifest-invalid", "run-a")
            self.refused("run-manifest-invalid", "broken")
            self.refused("run-manifest-invalid", "empty")
            self.refused("run-not-found", "absent-run")
            self.refused("invalid-run-id", "../runs")
        self.assertFalse((self.root / "archive").exists())

    def test_verified_complete_run_is_archived_the_same_way(self):
        directory = self.make_run()
        with patch("tools.vm.matrix.resources.completion_verified", return_value=True), fake_proc():
            archive_run(self.root, "run-a")
        record = json.loads((self.root / "archive" / "run-a.archive.json").read_text(encoding="utf-8"))
        self.assertTrue(record["completion_verified"])
        self.assertFalse(directory.exists())

    def test_failed_rename_leaves_the_run_in_place(self):
        directory = self.make_run()
        before = self.tree(self.root)
        with fake_proc(), patch("tools.vm.matrix.resources.os.rename", side_effect=OSError("xdev")):
            with self.assertRaises(OSError):
                archive_run(self.root, "run-a")
        self.assertTrue(directory.is_dir())
        self.assertEqual(before, self.tree(self.root))
        with fake_proc():
            archive_run(self.root, "run-a")

    def test_other_runs_of_the_stand_still_block_it(self):
        with StandLease(self.root, "stand-a") as lease:
            create_run(lease, "run-a")
            create_run(lease, "run-b")
        with fake_proc():
            archive_run(self.root, "run-a")
        with self.assertRaisesRegex(ValueError, "unresolved"):
            StandLease(self.root, "stand-a").acquire()
