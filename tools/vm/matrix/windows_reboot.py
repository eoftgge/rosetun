"""`run windows-reboot-smoke` (stage 9c): a Windows guest through the agent and one planned restart of its own.

The controller starts the machine of the 9a image as `windows-boot-smoke` does, then works with the guest through
its agent as it does with a Linux guest in stage 8c: it waits until the agent answers and reads the guest's boot
identity, records what the guest says of itself (system, Secure Boot, TPM, a UTF-8 text), asks the guest to restart
(`shutdown /r /t 0` through the agent, the way the guest's own scripts would), takes the RESET from QMP, waits for the
agent of the new boot and takes the new boot identity, which must differ, so that the run's chain of boots has two.
Then the ACPI power button closes the machine. There is no guest script, task or service: the image is only read,
and nothing in the guest survives the restart that the controller would have to find again.

The limits are those of a Windows guest. In stages 9a and 9b the agent answered 28 to 78 seconds after QEMU started
(and about 40 seconds after the RESET of a restart in the first run of this stage): one try gets 30 seconds, tries are
5 seconds apart after a restart, and the first boot and the new boot get 300 seconds each, about four times the slowest
start seen. The RESET itself comes when Windows has stopped its services, 24 seconds after the request on the stand,
so the wait for it is 180 seconds, and the evidence, whose PowerShell is slow on a boot that is fresh, gets 180.
"""

import json
from types import SimpleNamespace

from . import windows_guest
from .evidence import append_row
from .lifecycle import BOOT_REFUSALS, LifecycleError
from .resources import resource_path

SUITE = 'windows-reboot-smoke'
PLANNED_REBOOTS = 1
# One try of an observation: the synchronization, the agent's two probes and `reg.exe`, which reads the boot ID.
TRY_SECONDS = 30
# The evidence is the one PowerShell of the run that is waited for, and the first PowerShell of a fresh boot of the
# image took more than a minute on the stand while later ones took seconds.
EVIDENCE_SECONDS = 180
# A restarted guest is tried again every 5 seconds until its time (the observations of the run are 32 at most: the
# first boot takes 7 of them at the most and the new boot 12, with the recovery's own).
RETRY_SECONDS = 5
REBOOT_ATTEMPTS = 12
# After a failed try of the first boot the next one waits this long, as for Linux.
INITIAL_PAUSE_SECONDS = 15
# The steps after which a controller that died can be replaced: the restart may already be on its way.
RESUMABLE = ('reboot', 'reset', 'new-boot', 'evidence-after')
EVIDENCE_FILE = 'job-evidence.jsonl'
EVIDENCE_SCHEMA = 'rosetun.windows-evidence.v1'
# Where the guest has to stand for the run to be accepted: Secure Boot on and a TPM that is there and ready, as the
# image's own measurement requires, and an answer that carried the non-ASCII text intact.
SMOKE_SECONDS = dict(agent_wait_seconds=(1, 300), reset_wait_seconds=(1, 600), reboot_wait_seconds=(1, 900),
                     shutdown_wait_seconds=(1, 600))


def record(vm, operation, **fields):
    """One row of the run's job evidence; the owner's token is refused by the writer."""
    row = dict(schema=EVIDENCE_SCHEMA, operation=operation, run_id=vm.run._identity[0], vm_uuid=vm.vm_uuid,
               boot_id=vm.last_boot_id, boot_chain=list(vm.boot_chain), **fields)
    try:
        append_row(vm.run, EVIDENCE_FILE, row, forbid=vm.run._identity[2], max_bytes=256 * 1024,
                   require_registered=True, sync_parent=True)
    except (OSError, ValueError):
        vm.evidence_failed = True
        raise LifecycleError('job-evidence-write-failed', vm) from None


def guest_evidence(vm, when):
    """What the guest says of itself, through the agent, kept in the run's evidence and returned."""
    try:
        value = windows_guest.evidence(vm.guest_powershell(windows_guest.EVIDENCE_SCRIPT, seconds=EVIDENCE_SECONDS))
    except windows_guest.GuestAnswerError as error:
        raise LifecycleError(str(error), vm) from None
    # The count of boots that names the boot (read by `reg.exe`) and the one PowerShell reads are the same value.
    if value['boot_counter'] is not None and 'win-%d' % value['boot_counter'] != vm.last_boot_id:
        raise LifecycleError('guest-boot-readings-disagree', vm)
    record(vm, 'guest-evidence', when=when, guest=value, stderr=vm.qga.stderr_text or '')
    return value


def standing(value):
    """Whether one reading of the guest is what the image promises."""
    tpm = value['tpm']
    return (value['secure_boot'] is True and type(tpm) is dict and tpm['present'] is True and tpm['ready'] is True
            and value['utf8_ok'] is True)


def summary(guest):
    """The part of one reading the summary shows: not the readings that only serve to judge the boot identity."""
    keys = ('caption', 'version', 'build', 'architecture', 'secure_boot', 'tpm', 'utf8_ok', 'boot_counter', 'last_boot')
    return {key: guest[key] for key in keys}


def drive(c):
    """The steps between the first resume and the shutdown; `c` is the context `windows_smoke.run_windows` builds."""
    vm, smoke, measured = c.vm, c.config['smoke'], c.measured
    vm.planned_reboots = PLANNED_REBOOTS
    started = c.clock()
    c.step('boot', lambda: vm.wait_initial_guest(timeout=smoke['agent_wait_seconds'], clock=c.clock, sleep=c.sleep,
                                                 try_seconds=TRY_SECONDS))
    measured['agent_ready_seconds'] = round(c.clock() - started, 1)
    c.state.update('identities', boot_id=vm.last_boot_id, vm_uuid=vm.vm_uuid)
    measured['guest'] = summary(c.step('evidence', lambda: guest_evidence(vm, 'before')))
    c.step('reboot', vm.request_guest_reboot)
    requested = c.clock()
    c.step('reset', lambda: vm.wait_guest_reset(timeout=smoke['reset_wait_seconds'], clock=c.clock, sleep=c.sleep))
    measured['reset_seconds'] = round(c.clock() - requested, 1)
    finish(c, requested)


def finish(c, requested):
    """From the registered RESET to the second boot's evidence, then the shutdown; an attached controller joins here."""
    vm, smoke, measured = c.vm, c.config['smoke'], c.measured
    c.step('new-boot', lambda: vm.await_rebooted_guest(timeout=smoke['reboot_wait_seconds'], clock=c.clock,
                                                       sleep=c.sleep, attempts=REBOOT_ATTEMPTS,
                                                       try_seconds=TRY_SECONDS, retry_seconds=RETRY_SECONDS))
    measured['reboot_seconds'] = round(c.clock() - requested, 1)
    conclude(c)


def conclude(c):
    vm, measured = c.vm, c.measured
    measured['guest_after'] = summary(c.step('evidence-after', lambda: guest_evidence(vm, 'after')))
    c.step('shutdown', c.shutdown)


def recorded(vm, when):
    """The reading of the guest the run's evidence holds for `when` (`before` or `after`), as a dead controller left it."""
    found = None
    try:
        for line in resource_path(vm.run.directory, EVIDENCE_FILE).read_text(encoding='utf-8').splitlines():
            row = json.loads(line)
            if row.get('operation') == 'guest-evidence' and row.get('when') == when:
                found = row['guest']
        return None if found is None else summary(windows_guest.evidence(json.dumps(
            {key: value for key, value in found.items() if key != 'utf8_ok'})))
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
        return None


def attach(c):
    """A controller that took over a run whose own died after it asked the guest to restart: carry on from there.

    Three places the dead controller can have left the run. Its RESET was read and the new boot is not taken yet:
    wait for that boot as it would have. The new boot is taken: look at the guest, then finish. The RESET was not
    read (the machine may still be going down, or it restarted while nobody was looking): QMP events that nobody
    read are gone, so a guest that already answers with another boot identity is `boot-id-changed-without-reset`,
    the honest end; one that is still on the old boot, or whose agent is silent, is waited for until its RESET.
    """
    vm, smoke, measured = c.vm, c.config['smoke'], c.measured
    # An attached controller starts with a short exchange limit; the guest's first PowerShell needs the longer one.
    vm.timeout = TRY_SECONDS
    measured['guest'] = recorded(vm, 'before')
    requested = c.clock()
    if vm.reset_pending and vm.reset_kind == 'guest':
        finish(c, requested)
        return
    if len(vm.boot_chain) >= 2:
        c.step('attach-guest', vm.attach_guest)
        conclude(c)
        return
    try:
        c.step('attach-guest', vm.attach_guest)
    except LifecycleError as error:
        if str(error) in BOOT_REFUSALS or vm.process.poll() is not None or vm.evidence_failed:
            raise
    c.step('reset', lambda: vm.wait_guest_reset(timeout=smoke['reset_wait_seconds'], clock=c.clock, sleep=c.sleep))
    measured['reset_seconds'] = round(c.clock() - requested, 1)
    finish(c, requested)


def merged_resets(vm):
    """How many RESETs the run merged into the reboot they belong to, from its journal (the controller forgets them
    once the boot is taken, and a controller that took the run over never knew)."""
    try:
        rows = resource_path(vm.run.directory, 'lifecycle.jsonl').read_text(encoding='utf-8').splitlines()
        return sum(json.loads(row).get('action') == 'guest-reset-coalesced' for row in rows)
    except (OSError, ValueError, AttributeError):
        return None


def facts(vm):
    """What the run keeps of the controller's side: the chain, the resets and the budgets spent."""
    chain = list(vm.boot_chain)
    return dict(boot_chain=chain, guest_resets=vm.guest_resets, resets_merged=merged_resets(vm),
                planned_reboots=PLANNED_REBOOTS, qga_recoveries=vm.qga_recoveries,
                qga_observations=vm.qga_observations,
                chain_ok=len(chain) == 2 and chain[0] != chain[1] and vm.guest_resets == PLANNED_REBOOTS)


def verdict(measured):
    """Whether the run saw what it was for: two distinct boots after one restart, and the guest standing both times."""
    before, after = measured.get('guest'), measured.get('guest_after')
    return (measured.get('chain_ok') is True and before is not None and after is not None
            and standing(before) and standing(after)
            # The clock of the guest agrees with the chain: a kernel that started again, not only a new name.
            and before['last_boot'] != after['last_boot'] and before['boot_counter'] != after['boot_counter'])


def context(**values):
    return SimpleNamespace(**values)
