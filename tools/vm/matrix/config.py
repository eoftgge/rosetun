"""Small, versioned TOML profiles and self-contained plans."""

from pathlib import Path
import tomllib

from .catalog import LINUX_ROOT, SUITES, digest, read_catalog, validate_snapshot

PLAN_SCHEMA = "rosetun.matrix.plan.v1"


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
    if suite not in SUITES:
        raise ValueError("unknown suite")
    rows = read_catalog(LINUX_ROOT / SUITES[suite])
    return {
        "schema": PLAN_SCHEMA,
        "suite": suite,
        "profile": profile_name,
        "policy": dict(profile),
        "planned_reboots": 2 if suite == "linux-l4" else 0,
        "catalog": rows,
        "catalog_digest": digest(rows),
    }


def validate_plan(plan):
    fields = {"schema", "suite", "profile", "policy", "planned_reboots", "catalog", "catalog_digest"}
    if not isinstance(plan, dict) or set(plan) != fields or plan["schema"] != PLAN_SCHEMA:
        raise ValueError("unsupported plan schema or fields")
    if not isinstance(plan["suite"], str) or plan["suite"] not in SUITES:
        raise ValueError("unknown plan suite")
    if not isinstance(plan["profile"], str) or not plan["profile"].strip():
        raise ValueError("invalid plan profile")
    validate_profile(plan["policy"])
    expected = 2 if plan["suite"] == "linux-l4" else 0
    if type(plan["planned_reboots"]) is not int or plan["planned_reboots"] != expected:
        raise ValueError("invalid planned reboot limit")
    validate_snapshot(plan["catalog"])
    if plan["catalog_digest"] != digest(plan["catalog"]):
        raise ValueError("catalog digest mismatch")
    return plan
