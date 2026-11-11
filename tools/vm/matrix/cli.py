"""Read-only inspection and explicit exploratory execution."""

import argparse
import json
import os
import shutil
import sys

from .catalog import LINUX_ROOT, SUITES
from .config import load_profile, make_plan
from .report import ASSESSMENT_SCHEMA, assess_files
from .resources import inspect_runs, recovery_plan


def doctor():
    paths = list(SUITES.values()) + ["RosetunLinuxVm.psm1", "tests/Test-LinuxHarness.ps1"]
    paths += [f"guest/run-{name}.sh" for name in ("l2", "l3", "l4", "l5", "proxy")]
    files = {path: (LINUX_ROOT / path).is_file() for path in paths}
    supported = sys.version_info >= (3, 11)
    return {"schema": "rosetun.matrix.doctor.v1", "os": "Windows" if os.name == "nt" else os.uname().sysname,
            "architecture": os.environ.get("PROCESSOR_ARCHITECTURE", "unknown") if os.name == "nt" else os.uname().machine,
            "python": '.'.join(str(n) for n in sys.version_info[:3]),
            "python_supported": supported, "files": files,
            "qemu": {"found_in_path": shutil.which("qemu-system-x86_64") is not None,
                     "qualified": False}, "ready": supported and all(files.values())}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Plan, assess, inspect or explicitly execute exploratory L2")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="inspect local prerequisites without executing binaries")
    run = commands.add_parser('run', help='execute exploratory Linux L2 on an explicitly selected stand')
    run.add_argument('suite', choices=['linux-l2'])
    run.add_argument('--config', required=True)
    run.add_argument('--dry-run', action='store_true')
    plan = commands.add_parser("plan", help="write a deterministic catalog snapshot to stdout")
    plan.add_argument("suite", choices=[*SUITES, "windows-list", "windows-proxy"])
    plan.add_argument("--without-host-node", action="store_true", help="plan the limited Windows Proxy variant")
    plan.add_argument("--config", required=True)
    plan.add_argument("--profile", required=True)
    report = commands.add_parser("report", help="assess saved report.json and adjacent status.json")
    report.add_argument("report_path")
    report.add_argument("--plan", required=True)
    for name in ("runs", "recover"):
        command = commands.add_parser(name, help="read local resource records (no cleanup)")
        command.add_argument("--state-directory", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'run':
            from .execution import load_execution, preflight
            config = load_execution(args.config)
            if args.dry_run:
                result, code = preflight(config, dry_run=True), 0
            else:
                from .orchestrator import run_linux_l2
                result = run_linux_l2(config)
                code = result['exit_code']
        elif args.command in ("runs", "recover"):
            result = (recovery_plan(args.state_directory) if args.command == "recover" else
                      {"schema": "rosetun.matrix.runs.v1", "runs": inspect_runs(args.state_directory)})
            code = 0
        elif args.command == "doctor":
            result = doctor()
            code = 0 if result["ready"] else 1
        elif args.command == "plan":
            profile = load_profile(args.config, args.profile)
            if args.without_host_node and args.suite != 'windows-proxy':
                raise ValueError('coverage option requires Windows Proxy')
            if args.suite == 'windows-proxy':
                from .windows_proxy import make_plan as proxy_plan
                result = proxy_plan(args.profile, profile, use_host_node=not args.without_host_node)
            else:
                result = make_plan(args.suite, args.profile, profile)
            code = 0
        else:
            result = assess_files(args.report_path, args.plan)
            code = 2 if result["validation"]["status"] == "ERROR" else 0 if result["acceptance"]["accepted"] else 1
    except KeyboardInterrupt:
        if args.command != 'run':
            raise
        print(json.dumps(dict(schema='rosetun.matrix.execution-summary.v1', exit_code=130,
                              error='interrupted before execution', release_gate=False,
                              security_invariants='UNVERIFIED')))
        return 130
    except (OSError, ValueError, TypeError, RecursionError):
        if args.command == 'run':
            result = dict(schema='rosetun.matrix.execution-summary.v1', exit_code=2,
                          error='invalid or unreadable execution configuration/local prerequisites',
                          mode='exploratory only; release unsupported',
                          security_invariants='UNVERIFIED', release_gate=False)
            print(json.dumps(result, sort_keys=True, indent=2))
            return 2
        if args.command in ("runs", "recover"):
            print(json.dumps({"error": "resource state is unreadable or invalid", "cleanup_executed": False}))
            return 2
        # Parser and OS exceptions may include input data or local account paths.
        result = {"schema": ASSESSMENT_SCHEMA, "validation": {"status": "ERROR",
                  "problems": ["input is unreadable or violates the documented schema"]},
                  "acceptance": {"accepted": False, "release": False}}
        code = 2
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2))
    return code
