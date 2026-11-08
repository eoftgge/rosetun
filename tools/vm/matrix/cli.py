"""Read-only CLI. Binary discovery never qualifies a VM backend."""

import argparse
import json
import platform
import shutil
import sys

from .catalog import LINUX_ROOT, SUITES
from .config import load_profile, make_plan
from .report import ASSESSMENT_SCHEMA, assess_files


def doctor():
    paths = list(SUITES.values()) + ["RosetunLinuxVm.psm1", "tests/Test-LinuxHarness.ps1"]
    paths += [f"guest/run-{name}.sh" for name in ("l2", "l3", "l4", "l5", "proxy")]
    files = {path: (LINUX_ROOT / path).is_file() for path in paths}
    supported = sys.version_info >= (3, 11)
    return {"schema": "rosetun.matrix.doctor.v1", "os": platform.system(),
            "architecture": platform.machine(), "python": platform.python_version(),
            "python_supported": supported, "files": files,
            "qemu": {"found_in_path": shutil.which("qemu-system-x86_64") is not None,
                     "qualified": False}, "ready": supported and all(files.values())}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Plan and assess saved matrix results without running VMs")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="inspect local prerequisites without executing binaries")
    plan = commands.add_parser("plan", help="write a deterministic catalog snapshot to stdout")
    plan.add_argument("suite", choices=[*SUITES, "windows-list"])
    plan.add_argument("--config", required=True)
    plan.add_argument("--profile", required=True)
    report = commands.add_parser("report", help="assess saved report.json and adjacent status.json")
    report.add_argument("report_path")
    report.add_argument("--plan", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            result = doctor()
            code = 0 if result["ready"] else 1
        elif args.command == "plan":
            result = make_plan(args.suite, args.profile, load_profile(args.config, args.profile))
            code = 0
        else:
            result = assess_files(args.report_path, args.plan)
            code = 2 if result["validation"]["status"] == "ERROR" else 0 if result["acceptance"]["accepted"] else 1
    except (OSError, ValueError, RecursionError):
        # Parser and OS exceptions may include input data or local account paths.
        result = {"schema": ASSESSMENT_SCHEMA, "validation": {"status": "ERROR",
                  "problems": ["input is unreadable or violates the documented schema"]},
                  "acceptance": {"accepted": False, "release": False}}
        code = 2
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2))
    return code
