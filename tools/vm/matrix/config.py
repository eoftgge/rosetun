"""Small, versioned TOML profiles and self-contained plans."""

from pathlib import Path
import tomllib

from .catalog import LINUX_ROOT, SUITES, digest, read_catalog, validate_snapshot

PLAN_SCHEMA = "rosetun.matrix.plan.v1"
FAILURE_SUITE = "windows-failure"
FAILURE_CATALOG = LINUX_ROOT.parent / "windows" / "failure-core.tsv"
LOCKDOWN_SUITE = "windows-lockdown"
LOCKDOWN_CATALOG = LINUX_ROOT.parent / "windows" / "lockdown-core.tsv"
LAN_SUITE = "windows-lan"
LAN_CATALOG = LINUX_ROOT.parent / "windows" / "lan-core.tsv"
# The guest resets a suite plans: any other reset of its run is an error.
PLANNED_REBOOTS = {"linux-l4": 2, "linux-reboot-smoke": 1, "windows-reboot-smoke": 1}
# The suites whose job runs in phases of the job timeout each, one more than its reboots (see `job_span`).
PHASES = {"linux-l4": 3}


# How long the controller gives the new boot of a planned guest reset before its agent must answer.
REBOOT_SECONDS = 240


def planned_reboots_of(suite):
    return PLANNED_REBOOTS.get(suite, 0)


def job_span(suite, job_timeout):
    """The longest a job of the suite may take: each phase gets the job timeout, each planned reboot its room.

    A job of one phase has the job timeout alone. Only the suites of `PHASES` run in several, each at the job timeout
    (the guest's systemd limits every phase by it); the reboot smoke job reboots once inside its one phase.
    """
    phases = PHASES.get(suite, 1)
    return job_timeout * phases + REBOOT_SECONDS * (phases - 1)


def wait_seconds(suite, job_timeout):
    """How long the controller waits for the job's status to be final: its span and 125 seconds for the end."""
    return job_span(suite, job_timeout) + 125


def validate_profile(profile):
    if not isinstance(profile, dict) or set(profile) - {"mode", "run_id", "boot_id"}:
        raise ValueError("unknown profile fields")
    if profile.get("mode") not in ("exploratory", "release"):
        raise ValueError("profile mode must be exploratory or release")
    if ("run_id" in profile) != ("boot_id" in profile):
        raise ValueError("run_id and boot_id must be supplied together")
    for key in ("run_id", "boot_id"):
        if key in profile and (not isinstance(profile[key], str) or not profile[key].strip()):
            raise ValueError("expected identity must be a nonempty string")
    return profile


def load_profile(path, name):
    with Path(path).open("rb") as source:
        config = tomllib.load(source)
    if set(config) != {"schema", "profiles"} or type(config["schema"]) is not int or config["schema"] != 1:
        raise ValueError("unsupported configuration schema or fields")
    profiles = config["profiles"]
    if not isinstance(profiles, dict) or name not in profiles:
        raise ValueError("profile not found")
    for profile in profiles.values():
        validate_profile(profile)
    return profiles[name]


def make_plan(suite, profile_name, profile):
    validate_profile(profile)
    if suite == "windows-proxy":
        from .windows_proxy import make_plan as windows_plan
        return windows_plan(profile_name, profile)
    if suite == "windows-list":
        from .windows_list import make_plan as windows_plan
        return windows_plan(profile_name, profile)
    if suite not in SUITES and suite not in (FAILURE_SUITE, LOCKDOWN_SUITE, LAN_SUITE):
        raise ValueError("unknown suite")
    catalog_path = (FAILURE_CATALOG if suite == FAILURE_SUITE else
                    LOCKDOWN_CATALOG if suite == LOCKDOWN_SUITE else
                    LAN_CATALOG if suite == LAN_SUITE else LINUX_ROOT / SUITES[suite])
    rows = read_catalog(catalog_path)
    return {
        "schema": PLAN_SCHEMA,
        "suite": suite,
        "profile": profile_name,
        "policy": dict(profile),
        "planned_reboots": planned_reboots_of(suite),
        "catalog": rows,
        "catalog_digest": digest(rows),
    }


def validate_plan(plan):
    if isinstance(plan, dict) and plan.get("schema") in ("rosetun.windows-list.plan.v1", "rosetun.windows-list.plan.v2"):
        from .windows_list import validate_plan as validate_windows_plan
        return validate_windows_plan(plan)
    if isinstance(plan, dict) and plan.get("schema") == "rosetun.windows-proxy.plan.v1":
        from .windows_proxy import validate_plan as proxy_plan
        return proxy_plan(plan)
    fields = {"schema", "suite", "profile", "policy", "planned_reboots", "catalog", "catalog_digest"}
    if not isinstance(plan, dict) or set(plan) != fields or plan["schema"] != PLAN_SCHEMA:
        raise ValueError("unsupported plan schema or fields")
    if not isinstance(plan["suite"], str) or (plan["suite"] not in SUITES and plan["suite"] not in (FAILURE_SUITE, LOCKDOWN_SUITE, LAN_SUITE)):
        raise ValueError("unknown plan suite")
    if not isinstance(plan["profile"], str) or not plan["profile"].strip():
        raise ValueError("invalid plan profile")
    validate_profile(plan["policy"])
    if type(plan["planned_reboots"]) is not int or plan["planned_reboots"] != planned_reboots_of(plan["suite"]):
        raise ValueError("invalid planned reboot limit")
    validate_snapshot(plan["catalog"])
    if plan["catalog_digest"] != digest(plan["catalog"]):
        raise ValueError("catalog digest mismatch")
    return plan
