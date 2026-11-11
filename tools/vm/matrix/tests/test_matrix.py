import contextlib
import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.vm.matrix.catalog import LINUX_ROOT, SUITES, canonical, digest, read_catalog
from tools.vm.matrix.config import load_profile, make_plan, validate_plan
from tools.vm.matrix.cli import main
from tools.vm.matrix.report import assess, assess_files, read_json
from tools.vm.matrix.resources import StandLease, create_run

ROOT = Path(__file__).resolve().parents[4]
PACKAGE = ROOT / "tools/vm/matrix"


def synthetic_inputs(suite="linux-l2", mode="exploratory"):
    plan = make_plan(suite, "synthetic-test", {
        "mode": mode, "run_id": "synthetic-test-run", "boot_id": "synthetic-test-boot",
    })
    report = {
        "schema": 1, "run_id": "synthetic-test-run",
        "guest": {"boot_id": "synthetic-test-boot", "boot_id_at_end": "synthetic-test-boot"},
        "cleanup": {"status": "PASS"},
        "scenarios": [{"id": row["id"], "evidence": row["evidence"],
                       "result": "SKIP" if row["evidence"] == "not-run" else "PASS"}
                      for row in plan["catalog"]],
    }
    if suite == "linux-l4":
        report["guest"]["boot_ids"] = ["synthetic-test-boot"]
    summarize(report)
    return plan, report, {"run_id": "synthetic-test-run", "state": "finished"}


def summarize(report):
    counts = {name.lower(): sum(row["result"] == name for row in report["scenarios"])
              for name in ("PASS", "FAIL", "ERROR", "SKIP")}
    overall = "ERROR" if counts["error"] or report["cleanup"]["status"] != "PASS" else "FAIL" if counts["fail"] else "PASS"
    report["summary"] = {**counts, "total": len(report["scenarios"]), "overall": overall,
                         "coverage": "none" if overall != "PASS" else "partial" if counts["skip"] else "complete"}


class CatalogTests(unittest.TestCase):
    def test_all_existing_catalogs_keep_their_fields(self):
        expected_counts = {"linux-l2": 34, "linux-l3": 36, "linux-l4": 26,
                           "linux-l5": 17, "linux-proxy": 27}
        for suite, filename in SUITES.items():
            with self.subTest(suite=suite):
                rows = read_catalog(LINUX_ROOT / filename)
                self.assertEqual(len(rows), expected_counts[suite])
                self.assertEqual(rows[0]["id"], "preflight.identity")
                self.assertTrue(rows[0]["required"])
                self.assertEqual(rows[0]["evidence"], "infrastructure")

    def test_catalog_structure_and_duplicate_ids_are_rejected(self):
        header = "id\trequired\tevidence\tgroup\tdetail\ttitle\n"
        row = "test.id\tyes\ttransport-fixture\ttest\t-\ttest title\n"
        invalid = ["", header, "wrong\n" + row, header + "short\tyes\n",
                   header + row.replace("yes", "maybe"), header + row + row,
                   header + row + row.replace("test.id", "TEST.ID"),
                   header + row.replace("test.id", ""), header + row.replace("transport-fixture", "")]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.tsv"
            for content in invalid:
                with self.subTest(content=content):
                    path.write_text(content, encoding="utf-8")
                    with self.assertRaises(ValueError):
                        read_catalog(path)

    def test_plan_and_digest_are_deterministic_and_sensitive_to_catalog(self):
        first = make_plan("linux-l2", "test", {"mode": "exploratory"})
        second = make_plan("linux-l2", "test", {"mode": "exploratory"})
        self.assertEqual(canonical(first), canonical(second))
        self.assertEqual(first["catalog_digest"], digest(first["catalog"]))
        second["catalog"][0]["evidence"] = "not-run"
        self.assertNotEqual(first["catalog_digest"], digest(second["catalog"]))
        with self.assertRaises(ValueError):
            validate_plan(second)

    def test_config_and_plan_reject_unknown_schema_and_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            for content in ('schema=9\n[profiles.test]\nmode="release"',
                            'schema=1\n[profiles.test]\nmode="typo"',
                            'schema=1\n[profiles.test]\nmode="release"\nrun_id="test"',
                            'schema=1\n[profiles.test]\nmode="release"\nbackend="qemu"'):
                path.write_text(content, encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_profile(path, "test")
        plan, _, _ = synthetic_inputs()
        for field, value in (("schema", "unknown"), ("schema", 1), ("planned_reboots", True),
                             ("suite", []), ("catalog", []), ("policy", {"mode": "typo"})):
            bad = copy.deepcopy(plan)
            bad[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_plan(bad)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.plan, self.report, self.status = synthetic_inputs()

    def judge(self):
        return assess(self.report, self.status, self.plan)

    def assert_invalid(self):
        result = self.judge()
        self.assertEqual(result["validation"]["status"], "ERROR")
        self.assertFalse(result["acceptance"]["accepted"])
        self.assertFalse(result["acceptance"]["release"])
        return result

    def test_complete_reports_for_every_suite(self):
        for suite in SUITES:
            plan, report, status = synthetic_inputs(suite)
            result = assess(report, status, plan)
            self.assertEqual(result["legacy_verdict"], "PASS", result["validation"])
            self.assertTrue(result["acceptance"]["exploratory"])

    def test_missing_required_and_optional_scenarios_are_errors(self):
        for index in (0, -1):
            with self.subTest(index=index):
                _, self.report, _ = synthetic_inputs()
                del self.report["scenarios"][index]
                summarize(self.report)
                self.assert_invalid()

    def test_required_skip_fail_error_and_unverified_block_acceptance(self):
        for status in ("SKIP", "FAIL", "ERROR", "UNVERIFIED"):
            with self.subTest(status=status):
                self.report["scenarios"][0]["result"] = status
                summarize(self.report)
                result = self.judge()
                self.assertFalse(result["acceptance"]["accepted"])
                self.assertFalse(result["acceptance"]["release"])

    def test_unknown_and_duplicate_scenarios_are_errors(self):
        for scenario_id in ("unknown.synthetic", self.report["scenarios"][0]["id"]):
            _, self.report, _ = synthetic_inputs()
            self.report["scenarios"].append({"id": scenario_id, "result": "PASS", "evidence": "infrastructure"})
            summarize(self.report)
            self.assert_invalid()

    def test_foreign_run_and_status_and_unfinished_job_are_errors(self):
        for target, field, value in (("report", "run_id", "foreign"),
                                     ("status", "run_id", "foreign"),
                                     ("status", "state", "running")):
            self.plan, self.report, self.status = synthetic_inputs()
            getattr(self, target)[field] = value
            self.assert_invalid()
        self.status = None
        self.assert_invalid()

    def test_plans_without_identity_cannot_accept_reports(self):
        self.plan["policy"] = {"mode": "exploratory"}
        self.assert_invalid()

    def test_status_boot_must_match_final_report_boot_when_present(self):
        self.status["boot_id"] = "synthetic-test-boot"
        self.assertEqual(self.judge()["legacy_verdict"], "PASS")
        self.status["boot_id"] = "foreign"
        self.assert_invalid()
        self.plan, self.report, self.status = synthetic_inputs("linux-l4")
        self.report["guest"].update(boot_ids=["synthetic-test-boot", "second"],
                                    boot_id_at_end="second")
        self.status["boot_id"] = "second"
        self.assertEqual(self.judge()["legacy_verdict"], "PASS")

    def test_boot_changes_and_bad_chains_are_errors(self):
        for field in ("boot_id", "boot_id_at_end"):
            _, self.report, _ = synthetic_inputs()
            self.report["guest"][field] = "foreign"
            self.assert_invalid()
        boot = "synthetic-test-boot"
        self.plan, self.report, self.status = synthetic_inputs("linux-l4")
        for boots, end in (([], boot), (["foreign"], "foreign"),
                           ([boot, "second", "second"], "second"),
                           ([boot, "second"], "third"),
                           ([boot, "second", "third", "fourth"], "fourth"),
                           ([boot, ""], ""), ([boot, {}], boot)):
            with self.subTest(boots=boots):
                self.report["guest"].update(boot_ids=boots, boot_id_at_end=end)
                self.assert_invalid()
        for boots in ([boot], [boot, "second"], [boot, "second", "third"]):
            self.report["guest"].update(boot_ids=boots, boot_id_at_end=boots[-1])
            self.assertEqual(self.judge()["legacy_verdict"], "PASS")
        self.plan, self.report, self.status = synthetic_inputs()
        self.report["guest"]["boot_ids"] = [boot, "second"]
        self.assert_invalid()

    def test_unknown_schema_and_status_are_errors(self):
        for schema in (9, True, "1", None):
            self.report["schema"] = schema
            self.assert_invalid()
        self.report["schema"] = 1
        for status in ("unknown", "pass", None, [], {}):
            self.report["scenarios"][0]["result"] = status
            self.assert_invalid()

    def test_summary_counts_total_overall_and_coverage_are_checked(self):
        for field, value in (("pass", 0), ("pass", True), ("total", -1),
                             ("overall", "unknown"), ("overall", "FAIL"),
                             ("coverage", "complete")):
            _, self.report, _ = synthetic_inputs()
            self.report["summary"][field] = value
            self.assert_invalid()
        del self.report["summary"]
        self.assert_invalid()

    def test_evidence_cannot_be_missing_or_relabelled(self):
        for value in (None, "external-packet-capture"):
            self.report["scenarios"][0]["evidence"] = value
            self.assert_invalid()
        del self.report["scenarios"][0]["evidence"]
        self.assert_invalid()

    def test_not_run_cannot_claim_pass(self):
        self.report["scenarios"][-1]["result"] = "PASS"
        summarize(self.report)
        self.assert_invalid()

    def test_execution_pass_does_not_verify_an_invariant(self):
        result = self.judge()
        self.assertEqual(result["execution"]["status"], "PASS")
        self.assertEqual(result["invariant"]["status"], "UNVERIFIED")
        self.assertTrue(all(row["invariant"] == "UNVERIFIED" for row in result["rows"]))
        self.assertFalse(result["acceptance"]["release"])

    def test_fail_survives_infrastructure_error_and_duplicate_row(self):
        failed = copy.deepcopy(self.report["scenarios"][0])
        failed["result"] = "FAIL"
        self.report["scenarios"].append(failed)
        self.report["cleanup"]["status"] = "ERROR"
        summarize(self.report)
        result = self.assert_invalid()
        self.assertEqual(result["execution"]["status"], "FAIL")
        self.assertEqual(result["execution"]["counts"]["FAIL"], 1)
        self.assertEqual(result["execution"]["failures"][0]["id"], failed["id"])

    def test_cleanup_is_independent_and_required(self):
        for status in ("FAIL", "ERROR", "SKIP", "UNVERIFIED", "unknown", None):
            self.report["cleanup"]["status"] = status
            self.assert_invalid()
        del self.report["cleanup"]
        self.assert_invalid()

    def test_exploratory_partial_coverage_is_not_release_acceptance(self):
        result = self.judge()
        self.assertTrue(result["acceptance"]["accepted"])
        self.assertEqual(result["coverage"], "partial")
        self.plan["policy"]["mode"] = "release"
        result = self.judge()
        self.assertFalse(result["acceptance"]["accepted"])
        self.assertFalse(result["acceptance"]["release"])

    def test_arbitrary_json_shapes_do_not_crash_or_pass(self):
        for value in (None, [], 1, "text", {}):
            result = assess(value, self.status, self.plan)
            self.assertEqual(result["validation"]["status"], "ERROR")
        for key in ("guest", "scenarios", "summary", "cleanup"):
            _, self.report, _ = synthetic_inputs()
            self.report[key] = 1
            self.assert_invalid()


class FileAndCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.plan, self.report, self.status = synthetic_inputs()
        self.save()

    def save(self):
        for name, value in (("plan", self.plan), ("report", self.report), ("status", self.status)):
            (self.directory / f"{name}.json").write_text(json.dumps(value), encoding="utf-8")

    def cli(self, *args):
        return subprocess.run([sys.executable, "-B", "-m", "tools.vm.matrix", *map(str, args)],
                              cwd=ROOT, capture_output=True, text=True, check=False)

    def report_cli(self):
        return self.cli("report", self.directory / "report.json", "--plan", self.directory / "plan.json")

    def test_report_uses_only_saved_snapshot_and_leaves_raw_files_unchanged(self):
        paths = list(self.directory.glob("*.json"))
        before = {path: path.read_bytes() for path in paths}
        with patch("tools.vm.matrix.config.read_catalog", side_effect=AssertionError("live catalog read")):
            result = assess_files(self.directory / "report.json", self.directory / "plan.json")
        self.assertTrue(result["acceptance"]["accepted"])
        self.assertEqual(before, {path: path.read_bytes() for path in paths})
        self.assertEqual(len(result["sources"]["report_sha256"]), 64)

    def test_invalid_truncated_and_ambiguous_json_are_rejected(self):
        path = self.directory / "report.json"
        for text in ("", '{"schema":', '{"schema":1,"schema":1}', '{"x":NaN}', '{"x":Infinity}'):
            path.write_text(text, encoding="utf-8")
            with self.assertRaises(ValueError):
                read_json(path)
            result = self.report_cli()
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertFalse(json.loads(result.stdout)["acceptance"]["accepted"])

    def test_cli_exit_codes(self):
        self.assertEqual(self.report_cli().returncode, 0)
        self.plan["policy"]["mode"] = "release"
        self.save()
        self.assertEqual(self.report_cli().returncode, 1)
        self.plan["policy"]["mode"] = "exploratory"
        self.report["scenarios"][0]["result"] = "FAIL"
        summarize(self.report)
        self.save()
        self.assertEqual(self.report_cli().returncode, 1)
        self.report["summary"]["total"] = -1
        self.save()
        self.assertEqual(self.report_cli().returncode, 2)
        self.assertEqual(self.cli("plan", "unknown").returncode, 2)
        self.assertEqual(self.cli("report", self.directory / "missing", "--plan", self.directory / "plan.json").returncode, 2)

    def test_missing_or_invalid_status_cannot_hide_a_fail(self):
        self.report["scenarios"][0]["result"] = "FAIL"
        summarize(self.report)
        self.save()
        path = self.directory / "status.json"
        for exists in (True, False):
            if exists:
                path.write_text("{", encoding="utf-8")
            else:
                path.unlink()
            result = self.report_cli()
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stdout)["execution"]["status"], "FAIL")

    def test_doctor_and_plan_run_from_repository_root(self):
        result = self.cli("doctor")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(result.stdout)["qemu"]["qualified"])
        for suite in SUITES:
            args = ("plan", suite, "--config", PACKAGE / "example.toml", "--profile", "exploratory")
            first, second = self.cli(*args), self.cli(*args)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(first.stdout, second.stdout)
            self.assertNotIn("run_id", json.loads(first.stdout)["policy"])


class RecoverArchiveCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "state"
        with StandLease(self.root, "stand-a") as lease:
            self.run = create_run(lease, "run-a")
            self.run.register({"id": "qemu", "kind": "process", "pid": 4242, "platform": "posix",
                               "boot_id": "boot-a", "start_id": "777", "executable": "/usr/bin/qemu"})

    def tree(self):
        return {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file() and "archive" not in p.parts}

    def call(self, *args, boot="boot-b"):
        def read(path):
            if path.endswith("boot_id"):
                return boot
            raise FileNotFoundError(path)
        out = io.StringIO()
        with patch("tools.vm.matrix.resources._proc_text", side_effect=read), contextlib.redirect_stdout(out):
            code = main(["recover", "--state-directory", str(self.root), *args])
        return code, json.loads(out.getvalue())

    def test_recover_without_archive_only_reads_and_shows_the_status(self):
        before = self.tree()
        code, result = self.call()
        self.assertEqual(0, code)
        self.assertTrue(result["dry_run"])
        self.assertEqual("absent", result["runs"][0]["process_status"])
        self.assertEqual(before, self.tree())
        self.assertFalse((self.root / "archive").exists())

    def test_archive_moves_the_run_and_the_next_acquire_passes(self):
        code, result = self.call("--run-id", "run-a", "--archive")
        self.assertEqual((0, True), (code, result["archived"]))
        self.assertTrue((self.root / "archive" / "run-a" / "manifest.json").is_file())
        self.assertTrue((self.root / "archive" / "run-a.archive.json").is_file())
        with StandLease(self.root, "stand-a"):
            pass

    def test_archive_refuses_a_matching_process_with_a_named_reason(self):
        # The fake /proc has no entry for the pid, so a matching boot id is "absent";
        # an unreadable stat file is what makes the status unknown here.
        before = self.tree()

        def read(path):
            if path.endswith("boot_id"):
                return "boot-a"
            raise PermissionError(path)
        out = io.StringIO()
        with patch("tools.vm.matrix.resources._proc_text", side_effect=read), contextlib.redirect_stdout(out):
            code = main(["recover", "--state-directory", str(self.root), "--run-id", "run-a", "--archive"])
        result = json.loads(out.getvalue())
        self.assertEqual(1, code)
        self.assertEqual({"archived": False, "reason": "process-unknown"},
                         {k: result[k] for k in ("archived", "reason")})
        self.assertEqual(before, self.tree())

    def test_archive_needs_run_id_and_run_id_needs_archive(self):
        for args in (("--archive",), ("--run-id", "run-a")):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    self.call(*args)
                self.assertEqual(2, caught.exception.code)
        self.assertTrue((self.root / "runs" / "run-a").is_dir())

    def test_archive_of_unreadable_run_is_refused(self):
        (self.root / "runs" / "broken").mkdir()
        code, result = self.call("--run-id", "broken", "--archive")
        self.assertEqual((1, "run-manifest-invalid"), (code, result["reason"]))
        self.assertTrue((self.root / "runs" / "broken").is_dir())


if __name__ == "__main__":
    unittest.main()
