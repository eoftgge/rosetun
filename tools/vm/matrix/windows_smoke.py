"""`run windows-boot-smoke` and `run windows-reboot-smoke`: a Windows guest of the 9a image, started and shut down.

The boot smoke (stage 9b) has no guest agent job and no lab: the controller starts the machine with its TPM,
watches it through QMP, takes one `screendump`, asks for an ACPI shutdown and closes. The reboot smoke (stage 9c,
`windows_reboot`) works with the guest through its agent and carries it through one restart of its own. Both share
the run's frame: the lease, the run, the preparation, the start with its two processes, the close and the check
that the image is unchanged. The image is not qualified (`qualified` is false in its descriptor and the controller
accepts nothing else), so a run is diagnostic whatever it reports: the summary says `qualified: false`, and an
exit code of 0 means only what the suite says.
"""

from dataclasses import fields
import hashlib
from pathlib import Path
import platform
import os
import sys
import time
import tomllib
import uuid

from . import (windows_failure, windows_lab, windows_lan, windows_list_lab, windows_lockdown,
               windows_proxy_lab, windows_reboot, windows_run)
from .images import load_windows_descriptor
from .orchestrator import (SUMMARY_SCHEMA, begin_state, failure, finish_state, mark_step, save, seal,
                           _RETAINED_LEASES)
from .qemu import WindowsQemuConfig
from .resources import EXECUTION_FILES, StandLease, _identifier, _state_path, completion_verified, create_run

SCHEMA = 'rosetun.matrix.execution.windows.v1'
SUITE = 'windows-boot-smoke'
REBOOT_SUITE = windows_reboot.SUITE
# The times of each suite's `[smoke]` table, in seconds: the lowest and the highest the configuration may say.
SMOKE_TIMES = {SUITE: dict(boot_wait_seconds=(1, 600), shutdown_wait_seconds=(1, 600)),
               REBOOT_SUITE: windows_reboot.SMOKE_SECONDS}
FIELDS = {'schema', 'suite', 'mode', 'platform', 'state_directory', 'stand_id', 'image_descriptor', 'qemu',
          'smoke', 'deadlines'}
# How often the run asks QEMU for the machine's state during the wait.
POLL_SECONDS = 10


def _exact(value, names):
    if type(value) is not dict or set(value) != set(names):
        raise ValueError('unknown or missing execution configuration fields')


def validate(config):
    if type(config) is dict and config.get('schema') == windows_lab.SCHEMA:
        return windows_lab.validate(config)
    if type(config) is dict and config.get('schema') == windows_list_lab.SCHEMA:
        return windows_list_lab.validate(config)
    if type(config) is dict and config.get('schema') == windows_failure.SCHEMA:
        return windows_failure.validate(config)
    if type(config) is dict and config.get('schema') == windows_lockdown.SCHEMA:
        return windows_lockdown.validate(config)
    if type(config) is dict and config.get('schema') == windows_proxy_lab.SCHEMA:
        return windows_proxy_lab.validate(config)
    if type(config) is dict and config.get('schema') == windows_lan.SCHEMA:
        return windows_lan.validate(config)
    if type(config) is not dict or config.get('schema') != SCHEMA or config.get('suite') not in SMOKE_TIMES:
        raise ValueError('unsupported execution schema')
    _exact(config, FIELDS)
    if config['mode'] != 'exploratory':
        raise ValueError('execution supports exploratory only; release is unsupported')
    if config['platform'] != 'linux-x86_64-kvm':
        raise ValueError('unsupported execution platform')
    _exact(config['qemu'], [f.name for f in fields(WindowsQemuConfig)])
    times = SMOKE_TIMES[config['suite']]
    _exact(config['smoke'], times)
    for name, (low, high) in times.items():
        value = config['smoke'][name]
        if type(value) is not int or not low <= value <= high:
            raise ValueError('invalid smoke time')
    _exact(config['deadlines'], ('preparation',))
    if type(config['deadlines']['preparation']) is not int or not 1 <= config['deadlines']['preparation'] <= 86400:
        raise ValueError('invalid execution deadline')
    _identifier(config['stand_id'])
    _state_path(config['state_directory'])
    if type(config['image_descriptor']) is not str:
        raise ValueError('invalid image descriptor path')
    return config


def load(path):
    with Path(path).open('rb') as stream:
        return validate(tomllib.load(stream))


def preflight(config, *, dry_run=False):
    """What the run is about to do, after the checks that need no QEMU: the descriptor, its files, the configuration.

    The image's disk is hashed by the preparation, not here, so a dry run is quick and touches nothing.
    """
    validate(config)
    if config['suite'] == windows_lab.SUITE:
        return windows_lab.preflight(config, dry_run=dry_run)
    if config['suite'] == windows_list_lab.SUITE:
        return windows_list_lab.preflight(config, dry_run=dry_run)
    if config['suite'] == windows_failure.FAILURE_SUITE:
        return windows_failure.preflight(config, dry_run=dry_run)
    if config['suite'] == windows_lockdown.LOCKDOWN_SUITE:
        return windows_lockdown.preflight(config, dry_run=dry_run)
    if config['suite'] == windows_proxy_lab.SUITE:
        return windows_proxy_lab.preflight(config, dry_run=dry_run)
    if config['suite'] == windows_lan.LAN_SUITE:
        return windows_lan.preflight(config, dry_run=dry_run)
    image = load_windows_descriptor(config['image_descriptor'])
    qemu = WindowsQemuConfig(**config['qemu'])
    qemu.validate()
    windows_run.check(qemu, image)
    controller = Path(__file__).resolve().parents[3]
    controller_source = 'deferred'
    if not dry_run:
        if sys.platform != 'linux' or platform.machine() != 'x86_64':
            raise ValueError('execution requires Linux x86_64 KVM')
        if not os.access('/dev/kvm', os.R_OK | os.W_OK):
            raise ValueError('KVM is unavailable')
        from importlib.metadata import version
        if version('qemu.qmp') != '0.0.6':
            raise ValueError('qemu.qmp 0.0.6 required')
        from .linux_l2 import source_identity
        controller_source = source_identity(controller)
    boot = config['suite'] == SUITE
    smoke = config['smoke']
    if boot:
        middle = ['watch the machine through QMP for %d seconds' % smoke['boot_wait_seconds'],
                  'screendump into the run']
        limits = ['no guest agent job and no network: the machine is only started, watched, '
                  'photographed and shut down']
    else:
        middle = ['wait up to %d seconds for the guest agent and read the guest boot identity'
                  % smoke['agent_wait_seconds'],
                  'record the guest system, Secure Boot, TPM and a UTF-8 text through the agent',
                  'ask the guest to restart itself (shutdown /r /t 0 through the agent)',
                  'read the RESET from QMP (up to %d seconds), then wait up to %d seconds for the agent of the new '
                  'boot and take its boot identity, which must differ' % (smoke['reset_wait_seconds'],
                                                                       smoke['reboot_wait_seconds']),
                  'record the guest again']
        limits = ['one planned restart and no other; any other reset of the guest ends the run',
                  'the guest has no Rosetun, no scripts of the controller and no network: only the agent']
    return dict(schema='rosetun.matrix.execution-plan.v1', dry_run=dry_run, suite=config['suite'],
                configuration=config, image=dict(identifier=image.identifier, sha256=image.sha256,
                                                size_bytes=image.size_bytes, profile=image.profile,
                                                qualified=False, activated=False),
                controller_checkout=str(controller), controller_source=controller_source,
                host_platform=sys.platform, backend_qualified=False,
                actions=['lease', 'create run and identities',
                         'overlay, and copies of the firmware variables and of the TPM state of the image',
                         'start swtpm, then QEMU paused', 'resume', *middle,
                         'ACPI power-down, at most %d seconds, then close as for Linux'
                         % smoke['shutdown_wait_seconds'], 'close both processes',
                         'check that the image is unchanged (hashed again only if the disk changed)',
                         'summary'],
                limitations=[*limits,
                             'the image is not qualified (qualified: false): the run is diagnostic and counts '
                             'for nothing',
                             'the firmware variable store is not protected from the guest (no SMM)',
                             'no automatic file cleanup'],
                dependencies=['the image of stage 9a', 'qemu.qmp 0.0.6', 'KVM', 'pinned QEMU and firmware code',
                              'swtpm', 'Git (execution only)'],
                security_invariants='UNVERIFIED', release_gate=False)


class Adapters:
    """Lazy execution imports; tests replace operations, not the run."""

    def __init__(self):
        from .lifecycle import start
        from .qemu import execute, prepare
        self.prepare, self.execute, self.start = prepare, execute, start


def _watch(vm, seconds, clock, sleep):
    """Ask for the machine's state until the time is up; a machine that is not running, or one that reset, is an error."""
    deadline = clock() + seconds
    samples = 0
    while True:
        value = vm.status()
        samples += 1
        if value['status'] != 'running':
            raise ValueError('guest-not-running-' + value['status'])
        vm.watch_resets()
        remaining = deadline - clock()
        if remaining <= 0:
            return samples
        sleep(min(POLL_SECONDS, remaining))


def run_windows_boot_smoke(config, **options):
    if config.get('suite') != SUITE:
        raise ValueError('configuration is for another suite')
    return run_windows(config, **options)


def run_windows_reboot_smoke(config, **options):
    if config.get('suite') != REBOOT_SUITE:
        raise ValueError('configuration is for another suite')
    return run_windows(config, **options)


def run_windows(config, *, adapters=None, clock=time.monotonic, sleep=time.sleep, progress=None):
    """One path for both suites: the frame of the run, and between the resume and the close the suite's own steps."""
    progress = progress or (lambda stage: print(stage, file=sys.stderr, flush=True))
    suite = config.get('suite')
    boot = suite == SUITE
    result = dict(schema=SUMMARY_SCHEMA, suite=suite, identities={}, configuration=config, stages=[],
                  evidence=[], assessment=None, delivery=None, execution=None,
                  completion=False, manual_recovery_required=False, errors=[],
                  attached=False, attachments=0, qualified=False, diagnostic=True,
                  security_invariants='UNVERIFIED', release_gate=False, exit_code=2)
    lease = run = vm = state = image = plan = None
    stage = 'preflight'
    interrupted = False
    smoke = config.get('smoke', {})
    if boot:
        measured = dict(boot_wait_seconds=smoke.get('boot_wait_seconds'), samples=0,
                        guest_status=None, screenshot=None, shutdown=None, image_unchanged=None)
    else:
        measured = dict(smoke, agent_ready_seconds=None, guest=None, guest_after=None, reset_seconds=None,
                        reboot_seconds=None, shutdown=None, image_unchanged=None)

    def step(name, operation):
        nonlocal stage
        stage = name
        progress(name)
        row = dict(stage=name, state='started')
        result['stages'].append(row)
        states = [state] if state is not None else []
        mark_step(states, name, 'intent')
        try:
            value = operation()
        except BaseException:
            row['state'] = 'error'
            mark_step(states, name, 'error')
            raise
        row['state'] = 'completed'
        mark_step(states, name, 'done')
        return value

    def bounded_executor(deadline):
        def execute(argv, *, timeout, output_limit):
            remaining = deadline - clock()
            if remaining <= 0:
                raise TimeoutError('preparation deadline')
            value = adapters.execute(argv, timeout=min(timeout, remaining), output_limit=output_limit)
            if clock() > deadline:
                raise TimeoutError('preparation deadline')
            return value
        return execute

    def screenshot():
        vm.screendump()
        path = Path(run.directory) / windows_run.SCREENSHOT
        raw = path.read_bytes()
        measured['screenshot'] = dict(path=windows_run.SCREENSHOT, bytes=len(raw),
                                      sha256=hashlib.sha256(raw).hexdigest())

    def shutdown():
        # The image's power button shuts the machine down; a guest that does not answer it in time is an error
        # and is stopped the way a Linux run stops after an error.
        vm.request_shutdown(wait=config['smoke']['shutdown_wait_seconds'])
        measured['shutdown'] = 'acpi'

    started = clock()
    try:
        result['preflight'] = step('preflight', lambda: preflight(config))
        adapters = adapters or Adapters()
        image = load_windows_descriptor(config['image_descriptor'])
        qemu = WindowsQemuConfig(**config['qemu'])
        identities = dict(host_run_id=uuid.uuid4().hex)
        result['identities'] = identities
        lease = StandLease(config['state_directory'], config['stand_id'])
        step('lease', lease.acquire)
        run = step('create-run', lambda: create_run(lease, identities['host_run_id']))
        result['artifact_directory'] = str(run.directory)
        progress('run ' + identities['host_run_id'] + ' artifacts ' + str(run.directory))
        for identifier, name in EXECUTION_FILES.items():
            run.register(dict(id=identifier, kind='file', path=name))
        state = begin_state(run, config, result['preflight'], **identities)
        step('save-identities', lambda: save(run, 'execution-identity.json',
              dict(schema='rosetun.matrix.execution-identity.v1', **identities), initial=True))
        save(run, 'execution-summary.json', result, initial=True)
        deadline = clock() + config['deadlines']['preparation']
        executor = bounded_executor(deadline)
        plan = step('prepare', lambda: adapters.prepare(run, image, qemu, executor=executor))
        if clock() >= deadline:
            raise TimeoutError('preparation deadline')
        vm = step('start', lambda: adapters.start(run, timeout=10))
        state.update('identities', vm_uuid=vm.vm_uuid)
        step('resume', vm.resume)
        if boot:
            measured['samples'] = step('watch', lambda: _watch(vm, smoke['boot_wait_seconds'], clock, sleep))
            measured['guest_status'] = 'running'
            step('screendump', screenshot)
            step('shutdown', shutdown)
        else:
            windows_reboot.drive(windows_reboot.context(step=step, vm=vm, state=state, config=config,
                                                        measured=measured, clock=clock, sleep=sleep,
                                                        shutdown=shutdown))
    except BaseException as error:
        interrupted = isinstance(error, KeyboardInterrupt)
        result['errors'].append(failure(stage, error))
        if vm is None:
            vm = getattr(error, 'vm', None)
        # start() retains ownership even when interrupted before returning a handle.
        if vm is None and lease is not None and lease._active:
            vm = next(iter(lease._active))
    finally:
        if vm is not None:
            try:
                step('close', lambda: vm.close(hard=bool(result['errors'])))
                if measured['shutdown'] is None:
                    measured['shutdown'] = 'forced'
                result['completion'] = vm.completed and completion_verified(run.directory, run._read())
            except BaseException as error:
                interrupted |= isinstance(error, KeyboardInterrupt)
                result['errors'].append(failure('close', error))
        if run is not None:
            try:
                result['completion'] = completion_verified(run.directory, run._read())
            except (OSError, ValueError):
                result['completion'] = False
        if run is not None and result['completion'] and image is not None:
            # The run read the image and wrote only its own copies: the disk and the files it started from still are
            # what the descriptor says. The disk is hashed again only if its identity changed since it was last
            # hashed (the same rule as before the run, the stand's record of passes included).
            try:
                step('image-unchanged', lambda: image.validate(run.directory))
                measured['image_unchanged'] = True
            except BaseException as error:
                interrupted |= isinstance(error, KeyboardInterrupt)
                measured['image_unchanged'] = False
                result['errors'].append(failure('image-unchanged', error))
        result['manual_recovery_required'] = run is not None and not result['completion']
        accepted = (not result['errors'] and result['completion'] and measured['shutdown'] == 'acpi'
                    and measured['image_unchanged'] is True)
        if boot:
            accepted = accepted and measured['screenshot'] is not None
        else:
            if vm is not None:
                measured.update(windows_reboot.facts(vm))
            accepted = accepted and windows_reboot.verdict(measured)
        result['execution'] = dict(measured, accepted=bool(accepted), uuid=vm.vm_uuid if vm is not None else None,
                                   kvm_qualified=plan['kvm_qualified'] if plan else False,
                                   image=dict(identifier=image.identifier, sha256=image.sha256,
                                              qualified=False) if image is not None else None,
                                   duration_seconds=round(clock() - started, 1))
        finish_state(state, result['completion'], result)
        result = seal(run, result, interrupted)
        if lease is not None and lease._active:
            _RETAINED_LEASES.append(lease)
        if lease is not None and lease._stream is not None:
            # An unconfirmed live child/control keeps the original lease held.
            if not lease._active:
                try:
                    lease.release()
                except Exception as error:
                    result['errors'].append(failure('lease-release', error))
                    result['exit_code'] = 130 if interrupted else 2
    return result


def attach_reboot(run, state, vm, result, *, clock=time.monotonic, sleep=time.sleep, progress=None):
    """Finish a `windows-reboot-smoke` whose controller died after it asked the guest to restart (`attach`).

    `result` is the summary the dead controller saved first, already marked attached; it comes back with its errors,
    its execution and its completion, ready to be sealed. The lease belongs to the caller.
    """
    progress = progress or (lambda stage: print(stage, file=sys.stderr, flush=True))
    config = result['configuration']
    image = None
    interrupted = False
    stage = 'attach'
    measured = dict(config['smoke'], agent_ready_seconds=None, guest=None, guest_after=None, reset_seconds=None,
                    reboot_seconds=None, shutdown=None, image_unchanged=None)
    started = clock()

    def step(name, operation):
        nonlocal stage
        stage = name
        progress(name)
        row = dict(stage=name, state='started', attached=True)
        result['stages'].append(row)
        mark_step([state], name, 'intent')
        try:
            value = operation()
        except BaseException:
            row['state'] = 'error'
            mark_step([state], name, 'error')
            raise
        row['state'] = 'completed'
        mark_step([state], name, 'done')
        return value

    def shutdown():
        vm.request_shutdown(wait=config['smoke']['shutdown_wait_seconds'])
        measured['shutdown'] = 'acpi'

    try:
        windows_reboot.attach(windows_reboot.context(step=step, vm=vm, state=state, config=config,
                                                     measured=measured, clock=clock, sleep=sleep,
                                                     shutdown=shutdown))
    except BaseException as error:
        interrupted = isinstance(error, KeyboardInterrupt)
        result['errors'].append(failure(stage, error))
    finally:
        try:
            step('close', lambda: vm.close(hard=bool(result['errors'])))
            if measured['shutdown'] is None:
                measured['shutdown'] = 'forced'
        except BaseException as error:
            interrupted |= isinstance(error, KeyboardInterrupt)
            result['errors'].append(failure('close', error))
        try:
            result['completion'] = vm.completed and completion_verified(run.directory, run._read())
        except (OSError, ValueError):
            result['completion'] = False
        if result['completion']:
            try:
                image = load_windows_descriptor(config['image_descriptor'])
                step('image-unchanged', lambda: image.validate(run.directory))
                measured['image_unchanged'] = True
            except BaseException as error:
                interrupted |= isinstance(error, KeyboardInterrupt)
                measured['image_unchanged'] = False
                result['errors'].append(failure('image-unchanged', error))
        result['manual_recovery_required'] = not result['completion']
        measured.update(windows_reboot.facts(vm))
        accepted = (not result['errors'] and result['completion'] and measured['shutdown'] == 'acpi'
                    and measured['image_unchanged'] is True and windows_reboot.verdict(measured))
        result['execution'] = dict(measured, accepted=bool(accepted), uuid=vm.vm_uuid, attached=True,
                                   kvm_qualified=False,
                                   image=dict(identifier=image.identifier, sha256=image.sha256,
                                              qualified=False) if image is not None else None,
                                   duration_seconds=round(clock() - started, 1))
    return result, interrupted
