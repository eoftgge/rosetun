"""Assess saved Linux JSON; never execute checks or infer new security evidence."""

import hashlib
import json
from pathlib import Path

from .config import validate_plan

STATUSES = ("PASS", "FAIL", "SKIP", "ERROR", "UNVERIFIED")
LEGACY_STATUSES = STATUSES[:4]
ASSESSMENT_SCHEMA = "rosetun.matrix.assessment.v1"


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError("non-finite JSON number")


def read_json(path):
    data = Path(path).read_bytes()
    try:
        value = json.loads(data.decode("utf-8-sig"), object_pairs_hook=_unique_object,
                           parse_constant=_invalid_constant)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ValueError("invalid JSON input") from error
    return value, hashlib.sha256(data).hexdigest()


def _object(value):
    return value if isinstance(value, dict) else {}


def assess(report, status, plan):
    validate_plan(plan)
    problems = []
    report = _object(report)
    status = _object(status)
    policy = plan["policy"]
    run_id, boot_id = policy.get("run_id"), policy.get("boot_id")
    if not run_id or not boot_id:
        problems.append("plan has no independently recorded run and boot identity")
    if type(report.get("schema")) is not int or report.get("schema") != 1:
        problems.append("unsupported Linux report schema")
    if not run_id or report.get("run_id") != run_id:
        problems.append("report belongs to another run")
    if not run_id or status.get("run_id") != run_id:
        problems.append("status belongs to another run or is missing")
    if status.get("state") != "finished":
        problems.append("job has not finished")

    guest = _object(report.get("guest"))
    if "boot_id" in status and status["boot_id"] != guest.get("boot_id_at_end"):
        problems.append("status boot differs from the final report boot")
    if not boot_id or guest.get("boot_id") != boot_id:
        problems.append("guest boot differs from the recorded boot")
    boots = guest.get("boot_ids")
    if plan["planned_reboots"] or boots is not None:
        valid_boots = (isinstance(boots, list) and bool(boots)
                       and all(isinstance(boot, str) and boot.strip() for boot in boots))
        if (not valid_boots or boots[0] != boot_id
                or len(boots) > plan["planned_reboots"] + 1
                or len(set(boots)) != len(boots)
                or guest.get("boot_id_at_end") != boots[-1]):
            problems.append("invalid guest boot chain")
    elif guest.get("boot_id_at_end") != boot_id:
        problems.append("guest rebooted during the run")

    entries = report.get("scenarios")
    if not isinstance(entries, list):
        problems.append("scenarios must be an array")
        entries = []
    by_id = {}
    counts = dict.fromkeys(STATUSES, 0)
    failures = []
    for index, entry in enumerate(entries):
        entry = _object(entry)
        scenario_id = entry.get("id")
        result = entry.get("result")
        if isinstance(result, str) and result in LEGACY_STATUSES:
            counts[result] += 1
        else:
            problems.append(f"scenario row {index} has an unknown execution status")
        if result == "FAIL":
            failures.append({"row": index, "id": scenario_id})
        if not isinstance(scenario_id, str) or not scenario_id:
            problems.append(f"scenario row {index} has no valid id")
        elif scenario_id in by_id:
            problems.append(f"duplicate scenario at row {index}")
        else:
            by_id[scenario_id] = entry

    rows = []
    known = {scenario["id"] for scenario in plan["catalog"]}
    if set(by_id) - known:
        problems.append("report contains unknown scenario ids")
    for scenario in plan["catalog"]:
        entry = by_id.get(scenario["id"])
        issues = []
        execution = "UNVERIFIED"
        if entry is None:
            issues.append("scenario has no result")
        else:
            execution = entry.get("result")
            if not isinstance(execution, str) or execution not in LEGACY_STATUSES:
                execution = "ERROR"
                issues.append("unknown execution status")
            if entry.get("evidence") != scenario["evidence"]:
                issues.append("missing or mismatched evidence category")
            if scenario["required"] and execution == "SKIP":
                issues.append("required scenario was skipped")
            if scenario["evidence"] == "not-run" and execution == "PASS":
                issues.append("scenario without a check claims PASS")
        problems.extend(f"{scenario['id']}: {issue}" for issue in issues)
        rows.append({"id": scenario["id"], "required": scenario["required"],
                     "evidence": scenario["evidence"], "execution": execution,
                     "invariant": "UNVERIFIED", "problems": issues})

    cleanup = _object(report.get("cleanup")).get("status")
    if not isinstance(cleanup, str) or cleanup not in LEGACY_STATUSES:
        cleanup = "ERROR"
        problems.append("missing or unknown cleanup status")
    if cleanup != "PASS":
        problems.append("cleanup did not succeed")
    summary = _object(report.get("summary"))
    for name in LEGACY_STATUSES:
        claimed = summary.get(name.lower())
        if type(claimed) is not int or claimed != counts[name]:
            problems.append(f"summary count disagrees for {name}")
    if type(summary.get("total")) is not int or summary.get("total") != len(entries):
        problems.append("summary total disagrees")
    overall = summary.get("overall")
    expected = "ERROR" if counts["ERROR"] or cleanup != "PASS" else "FAIL" if counts["FAIL"] else "PASS"
    # Guest finalization can report an aborted run without a separate ERROR row.
    if overall not in (expected, "ERROR"):
        problems.append("summary overall disagrees")
    if overall == "ERROR":
        problems.append("guest reports an infrastructure error or aborted run")
    claimed_coverage = summary.get("coverage")
    expected_coverage = "none" if overall != "PASS" else "partial" if counts["SKIP"] else "complete"
    if claimed_coverage is not None and claimed_coverage != expected_coverage:
        problems.append("summary coverage disagrees")

    execution = ("FAIL" if failures else "ERROR" if counts["ERROR"]
                 or any(row["execution"] == "ERROR" for row in rows)
                 else "UNVERIFIED" if any(row["execution"] == "UNVERIFIED" for row in rows)
                 else "SKIP" if any(row["required"] and row["execution"] == "SKIP" for row in rows)
                 else "PASS")
    legacy_verdict = "ERROR" if problems else execution
    coverage = "none" if legacy_verdict != "PASS" else "partial" if counts["SKIP"] else "complete"
    exploratory = legacy_verdict == "PASS"
    return {
        "schema": ASSESSMENT_SCHEMA,
        "suite": plan["suite"], "profile": plan["profile"],
        "catalog_digest": plan["catalog_digest"],
        "execution": {"status": execution, "counts": counts, "failures": failures},
        "validation": {"status": "ERROR" if problems else "PASS", "problems": problems},
        "legacy_verdict": legacy_verdict,
        "invariant": {"status": "UNVERIFIED", "reason": "independent security evidence verification is not implemented"},
        "cleanup": {"status": cleanup},
        "coverage": coverage, "rows": rows,
        "acceptance": {"mode": policy["mode"], "exploratory": exploratory,
                       "release": False, "accepted": exploratory and policy["mode"] == "exploratory"},
    }


def assess_files(report_path, plan_path):
    plan, plan_hash = read_json(plan_path)
    if isinstance(plan, dict) and plan.get("schema") == "rosetun.windows-list.plan.v1":
        from .windows_list import assess_files as assess_windows_files
        return assess_windows_files(report_path, plan_path)
    validate_plan(plan)
    report, report_hash = read_json(report_path)
    status_path = Path(report_path).with_name("status.json")
    try:
        status, status_hash = read_json(status_path)
    except (OSError, ValueError):
        status, status_hash = None, None
    result = assess(report, status, plan)
    result["sources"] = {"report_sha256": report_hash, "status_sha256": status_hash,
                         "plan_sha256": plan_hash}
    return result
