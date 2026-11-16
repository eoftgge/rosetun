"""Read-only inspection and explicit exploratory execution."""

import argparse
import json
import os
import shutil
import sys

from .catalog import LINUX_ROOT, SUITES
from .lab_protocol import CONTROLS
from .l3_summary import CONTROLS as L3_CONTROLS
from .config import load_profile, make_plan
from .report import ASSESSMENT_SCHEMA, assess_files
from .resources import ArchiveRefused, archive_run, inspect_runs, recovery_plan


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
    parser = argparse.ArgumentParser(description="Plan, assess, inspect or explicitly execute exploratory Linux L2 or L3")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="inspect local prerequisites without executing binaries")
    lab = commands.add_parser('lab-smoke', help='qualify the isolated two-VM infrastructure only')
    lab.add_argument('--config', required=True)
    lab.add_argument('--dry-run', action='store_true')
    lab.add_argument('--canary', action='store_true',
                     help='send a deliberate leak and succeed only if exactly that leak is detected')
    lab.add_argument('--control', choices=CONTROLS,
                     help='a negative control of the observer: exit 0 only on exactly the refusal it is there to show')
    lab.add_argument('--tunnel', action='store_true',
                     help='also qualify the lab VPN node and HTTPS target (needs a lab.v2 configuration)')
    lab.add_argument('--dns', action='store_true',
                     help='also qualify the lab resolver and DoH target with sing-box (needs --tunnel)')
    lab.add_argument('--evidence-disk', action='store_true',
                     help='keep the capture on a separate disk of the lab machine and read it after it stops')
    run = commands.add_parser('run', help='execute exploratory Linux L2 or L3 on an explicitly selected stand')
    run.add_argument('suite', choices=['linux-l2', 'linux-l3', 'linux-proxy', 'linux-l5'])
    run.add_argument('--config', required=True)
    run.add_argument('--dry-run', action='store_true')
    run.add_argument('--lab', action='store_true',
                     help='run linux-l3, linux-proxy or linux-l5 inside the two-machine lab (needs an execution.v3 '
                          'configuration)')
    run.add_argument('--control', choices=L3_CONTROLS,
                     help='with --lab: the positive control of the observer; exit 0 only if it saw what the control did')
    run.add_argument('--diagnostic', action='store_true',
                     help='with --lab, linux-l3 only: ask the engine to name destinations; the run is never a '
                          'qualification (exit 2 or more)')
    attach = commands.add_parser('attach', help='connect to a live run whose controller died and finish it')
    attach.add_argument('--state-directory', required=True)
    attach.add_argument('--run-id', required=True)
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
        if name == "recover":
            command.add_argument("--run-id")
            command.add_argument("--archive", action="store_true",
                                 help="move one run with no live VM process to archive/ (no deletion)")
            command.add_argument("--close", action="store_true",
                                 help="connect to one live run, quit its VM and record completion")
    args = parser.parse_args(argv)
    if args.command == "recover" and (args.archive and args.close or bool(args.archive or args.close) != bool(args.run_id)):
        parser.error("--run-id goes with exactly one of --archive and --close")
    if args.command == 'lab-smoke' and args.control and (args.canary or args.tunnel):
        parser.error('--control cannot go with --canary or --tunnel')
    try:
        if args.command == 'lab-smoke':
            from .lab import load_lab, plan_lab, lab_smoke
            config = load_lab(args.config)
            options = {**({'tunnel': True} if args.tunnel else {}),
                       **({'evidence_disk': True} if args.evidence_disk else {}),
                       **({'dns': True} if args.dns else {}),
                       **({'control': args.control} if args.control else {})}
            result = plan_lab(config, **options) if args.dry_run else lab_smoke(config, canary=args.canary, **options)
            code = 0 if args.dry_run else result['exit_code']
        elif args.command == 'run':
            from .execution import lab_of, load_execution, preflight, suite_of
            config = load_execution(args.config)
            if suite_of(config) != args.suite:
                raise ValueError('configuration is for another suite')
            # A version 3 configuration is the lab's and nothing else's; versions 1 and 2 never are.
            if args.lab != (lab_of(config) is not None):
                raise ValueError('--lab and the lab block of the configuration go together')
            if args.diagnostic and (not args.lab or args.suite != 'linux-l3'):
                raise ValueError('--diagnostic needs --lab and linux-l3')
            if args.control and (not args.lab or args.diagnostic or
                                 args.suite not in ('linux-l3', 'linux-proxy', 'linux-l5')):
                raise ValueError('--control needs --lab and cannot go with --diagnostic')
            if args.dry_run:
                result, code = preflight(config, dry_run=True), 0
            else:
                from . import l3_lab, orchestrator
                if args.lab:
                    run = {'linux-proxy': l3_lab.run_linux_proxy_lab, 'linux-l5': l3_lab.run_linux_l5_lab}.get(
                        args.suite, l3_lab.run_linux_l3_lab)
                else:
                    run = {'linux-l3': orchestrator.run_linux_l3, 'linux-proxy': orchestrator.run_linux_proxy,
                           'linux-l5': orchestrator.run_linux_l5}.get(args.suite, orchestrator.run_linux_l2)
                result = run(config, **({'diagnostic': True} if args.diagnostic else {}),
                             **({'control': args.control} if args.control else {}))
                code = result['exit_code']
        elif args.command == 'attach':
            from .orchestrator import attach_run
            result = attach_run(args.state_directory, args.run_id)
            code = result['exit_code']
        elif args.command == "recover" and args.close:
            from .orchestrator import close_run
            result, code = close_run(args.state_directory, args.run_id)
        elif args.command == "recover" and args.archive:
            try:
                result, code = archive_run(args.state_directory, args.run_id), 0
            except ArchiveRefused as refusal:
                result, code = {"schema": "rosetun.matrix.archive.v1", "archived": False,
                                "reason": refusal.reason, "cleanup_executed": False}, 1
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
        if args.command == 'lab-smoke':
            print(json.dumps(dict(schema='rosetun.matrix.lab-summary.v1', exit_code=130,
                                  qualified=False, security_invariants='UNVERIFIED', release_gate=False)))
            return 130
        if args.command != 'run':
            raise
        print(json.dumps(dict(schema='rosetun.matrix.execution-summary.v1', exit_code=130,
                              error='interrupted before execution', release_gate=False,
                              security_invariants='UNVERIFIED')))
        return 130
    except (OSError, ValueError, TypeError, RecursionError):
        if args.command == 'lab-smoke':
            print(json.dumps(dict(schema='rosetun.matrix.lab-summary.v1', exit_code=2,
                  error='invalid lab configuration or prerequisites', qualified=False,
                  security_invariants='UNVERIFIED', release_gate=False)))
            return 2
        if args.command == 'run':
            result = dict(schema='rosetun.matrix.execution-summary.v1', exit_code=2,
                          error='invalid or unreadable execution configuration/local prerequisites',
                          mode='exploratory only; release unsupported',
                          security_invariants='UNVERIFIED', release_gate=False)
            print(json.dumps(result, sort_keys=True, indent=2))
            return 2
        if args.command in ("runs", "recover", "attach"):
            print(json.dumps({"error": "resource state is unreadable or invalid", "cleanup_executed": False}))
            return 2
        # Parser and OS exceptions may include input data or local account paths.
        result = {"schema": ASSESSMENT_SCHEMA, "validation": {"status": "ERROR",
                  "problems": ["input is unreadable or violates the documented schema"]},
                  "acceptance": {"accepted": False, "release": False}}
        code = 2
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2))
    return code
