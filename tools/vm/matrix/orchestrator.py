"""Sequential exploratory L2 or L3 execution under the original stand lease."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
import time
import uuid

from .config import REBOOT_SECONDS, planned_reboots_of, wait_seconds
from .evidence import write_file
from .execution import preflight
from .images import IMAGE_REFUSALS
from .lab_protocol import HELPER_REASON
from .report import read_json
from .resources import (StandLease, bind_run, create_run, resource_path, stand_of, EXECUTION_FILES,
                        completion_verified)
from .run_state import RunState, RESOURCE as RUN_STATE_RESOURCE, FINAL

SUMMARY_SCHEMA = 'rosetun.matrix.execution-summary.v1'
_RETAINED_LEASES = []


_PACKAGE_DIRECTORY = Path(__file__).resolve().parent


def _raised_here(error):
    """Whether the innermost frame of the traceback is code of this package, not of the standard library."""
    frame = error.__traceback__
    while frame is not None and frame.tb_next is not None:
        frame = frame.tb_next
    if frame is None:
        return False
    name = frame.tb_frame.f_code.co_filename
    if name.startswith('<'):
        return False
    try:
        return Path(name).resolve().is_relative_to(_PACKAGE_DIRECTORY)
    except (OSError, ValueError):
        return False


def failure(stage, error):
    reason = str(error)
    # The refusals of an image's files are fixed sentences of the controller's own, so they are shown as they are,
    # also when preparation reports them under its own name.
    refusal = getattr(error, 'image_refusal', None)
    if refusal in IMAGE_REFUSALS:
        reason = refusal
    named = reason in IMAGE_REFUSALS
    ours = type(error).__module__.startswith('tools.vm.matrix.')
    # The controllers raise the builtin ValueError and OSError with a code of their own as the message.
    builtin = type(error).__module__ == 'builtins' and isinstance(error, (ValueError, OSError))
    shown = ours or (builtin and _raised_here(error))
    row = dict(stage=stage, kind=type(error).__name__,
               reason=reason if shown and (named or re.fullmatch(r'[A-Za-z0-9_-]{1,96}', reason)) else 'operation-failed')
    # The code a guest helper printed, when it fits the fixed alphabet: it says which exchange failed.
    helper = getattr(error, 'helper_reason', None)
    if ours and type(helper) is str and HELPER_REASON.fullmatch(helper):
        row['helper_reason'] = helper
    # What ended an exchange with the guest's agent: the class of the exception and, for the system's own, its words.
    cause = getattr(error, 'cause', None)
    if ours and type(cause) is str and HELPER_REASON.fullmatch(cause):
        row['cause'] = cause
    return row


def phase_of(step, current):
    """The run-state phase a controller step belongs to: steps never move a run back."""
    if step.startswith('close'):
        return 'closing'
    if step.startswith('collect') or current in ('collecting', 'closing'):
        return current if current == 'closing' else 'collecting'
    if current == 'preparing' and not step.startswith('start'):
        return 'preparing'
    return 'running'


def controller_commit(preflight_result):
    source = preflight_result.get('controller_source') if type(preflight_result) is dict else None
    sha = source.get('source_sha') if type(source) is dict else None
    return sha if type(sha) is str and re.fullmatch('[0-9a-f]{40}', sha) else None


def configuration_digest(config):
    return hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()


def begin_state(run, config, preflight_result, **identities):
    """Register the run state beside the execution files and record the run as preparing."""
    run.register(dict(RUN_STATE_RESOURCE))
    return RunState.create(run, phase='preparing', commit=controller_commit(preflight_result),
                           configuration_sha256=configuration_digest(config), **identities)


def mark_step(states, name, status):
    """Record a step of every run that has a state; a failed intent or done stops the controller."""
    for state in states:
        if state.phase in ('completed', 'quarantined'):
            continue
        try:
            state.transition(phase_of(name, state.phase), name, status)
        except (OSError, ValueError):
            if status != 'error':
                raise ValueError('run-state-write-failed') from None


def finish_state(state, completed, result):
    """The final phase: completed only with verified completion; otherwise quarantined with the first reason."""
    if state is None or state.phase in ('completed', 'quarantined'):
        return
    reasons = [e.get('reason') for e in result['errors'] if type(e.get('reason')) is str]
    try:
        if completed:
            state.transition('completed', 'summary', 'done')
        else:
            state.transition('quarantined', 'summary', 'done',
                             reason=(reasons[0] if reasons and re.fullmatch(r'[A-Za-z0-9_-]{1,96}', reasons[0])
                                     else 'completion-unverified'))
    except (OSError, ValueError):
        result['errors'].append(dict(stage='summary', kind='RunStateError', reason='run-state-write-failed'))


def save(run, name, value, *, initial=False):
    """Registered output; replace atomically without altering lifecycle evidence."""
    if name not in EXECUTION_FILES.values():
        raise ValueError('unregistered execution output')
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    if initial:
        write_file(run, name, raw, mode='create', forbid=run._identity[2],
                   require_registered=True, sync_parent=True)
    else:
        write_file(run, name, raw, mode='replace', temporary='execution-summary.tmp',
                   forbid=run._identity[2], require_registered=True)



def seal(run, result, interrupted):
    """Exit code, evidence digests and the saved summary; shared by a run and by a later attach."""
    accepted = bool(result['execution'] and result['execution']['accepted'])
    result['exit_code'] = (130 if interrupted else 2 if result['errors'] or not result['completion']
                           else 0 if accepted else 1)
    if run is None:
        return result
    payload = json.dumps(result)
    if run._identity[2] in payload:
        result = json.loads(payload.replace(run._identity[2], '[redacted-owner-token]'))
        result['errors'].append(dict(stage='summary', kind='RedactionError',
                                     reason='owner-token-redacted'))
        result['exit_code'] = 130 if interrupted else 2
    try:
        result['evidence'] = []
        for entry in run._read()['resources']:
            if entry['kind'] != 'file' or entry['path'] == 'execution-summary.json':
                continue
            path = resource_path(run.directory, entry['path'])
            if not path.is_file():
                continue
            digest = hashlib.sha256()
            with path.open('rb') as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(block)
            # Raw stderr and the private ownership ledger are never embedded.
            result['evidence'].append(dict(path=entry['path'], sha256=digest.hexdigest()))
        save(run, 'execution-summary.json', result)
    except BaseException as error:
        result['errors'].append(failure('summary', error))
        result['exit_code'] = 130 if interrupted else 2
    return result


class AttachRefused(ValueError):
    """A named refusal before anything of the run was changed."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


# The steps after which the job may be running in the guest: only from there on can an attach carry on.
RESUMABLE = ('submit', 'submit-recovery', 'wait', 'collect', 'collect-recovery', 'collect-final', 'close')


def _resumable(run):
    """The steps an attach may carry on from for the suite the run's saved summary names (the Linux ones if unreadable)."""
    try:
        summary, _ = read_json(resource_path(run.directory, 'execution-summary.json'))
        if summary['configuration']['suite'] == 'windows-reboot-smoke':
            from .windows_reboot import RESUMABLE as WINDOWS_RESUMABLE
            return WINDOWS_RESUMABLE
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        pass
    return RESUMABLE


def _current_commit():
    try:
        from .linux_l2 import source_identity
        return controller_commit(dict(controller_source=source_identity(Path(__file__).resolve().parents[3])))
    except Exception:
        return None


def _claim(state_directory, run_id, timeout, commit, check=None):
    """Recovery lease, the run's ledger and state, and the attached VM; any refusal leaves the run as it was.

    `check(run, state)` names a reason to refuse before anything is connected.
    """
    try:
        lease = StandLease(state_directory, stand_of(state_directory, run_id))
    except (OSError, ValueError, RecursionError):
        raise AttachRefused('run-manifest-invalid') from None
    try:
        lease.acquire(recovery=True)
    except ValueError:
        raise AttachRefused('stand-locked') from None
    try:
        run = bind_run(lease, run_id)
        state = RunState.load(run)
        if state.document['controller']['commit'] != commit:
            raise AttachRefused('controller-version-mismatch')
        reason = check(run, state) if check is not None else None
        if reason is not None:
            raise AttachRefused(reason)
        from .lifecycle import attach
        vm = attach(run, timeout=timeout)
    except BaseException as error:
        lease.release()
        if isinstance(error, AttachRefused) or not isinstance(error, (OSError, ValueError, RecursionError)):
            raise
        reason = str(error)
        raise AttachRefused(reason if re.fullmatch(r'[a-z0-9-]{1,96}', reason) else 'run-records-unusable') from None
    attachments = state.document['attachments'] + 1
    state.update('attachments', count=attachments)
    return lease, run, state, vm, attachments


def _release(lease, result, interrupted):
    if lease._active:
        _RETAINED_LEASES.append(lease)
    elif lease._stream is not None:
        try:
            lease.release()
        except Exception as error:
            result['errors'].append(failure('lease-release', error))
            result['exit_code'] = 130 if interrupted else 2


def attach_run(state_directory, run_id, *, timeout=5, sleep=time.sleep, now=time.time, progress=None,
               commit=None, clock=time.monotonic):
    """Carry on a `run linux-l2`/`linux-l3` whose controller died after the job was submitted.

    The summary it finishes says `attached: true` and how many controllers
    attached; such a run is never presented as continuous. The exit code is the
    one the original command would have given.
    """
    progress = progress or (lambda stage: print(stage, file=sys.stderr, flush=True))
    commit = _current_commit() if commit is None else commit
    refusal = dict(schema=SUMMARY_SCHEMA, run_id=run_id, attached=False, refused=None, exit_code=2,
                   security_invariants='UNVERIFIED', release_gate=False)
    found = {}

    def check(run, state):
        steps = {row['step'] for row in state.document['transitions']}
        if state.document['identities']['lab_id'] is not None:
            return 'attach-lab-run-not-resumable'
        if state.phase in FINAL:
            return 'run-already-finished'
        if not steps & set(_resumable(run)):
            # Before the job left the controller nothing in the guest can be carried on: `recover --close`.
            return 'attach-phase-not-resumable'
        try:
            summary, _ = read_json(resource_path(run.directory, 'execution-summary.json'))
        except (OSError, ValueError, RecursionError):
            return 'summary-unreadable'
        if type(summary) is not dict or state.document['configuration_sha256'] != configuration_digest(
                summary.get('configuration')):
            return 'summary-configuration-mismatch'
        found['summary'] = summary
        return None

    try:
        lease, run, state, vm, attachments = _claim(state_directory, run_id, timeout, commit, check)
    except AttachRefused as error:
        return dict(refusal, refused=error.reason)
    result = found['summary']
    config = result['configuration']
    vm.planned_reboots = planned_reboots_of(config.get('suite', 'linux-l2'))
    result.update(attached=True, attachments=attachments)
    if config.get('suite') == 'windows-reboot-smoke':
        from .windows_smoke import attach_reboot
        result, interrupted = attach_reboot(run, state, vm, result, clock=clock, sleep=sleep, progress=progress)
        finish_state(state, result['completion'], result)
        result = seal(run, result, interrupted)
        _release(lease, result, interrupted)
        return result
    job = None
    stage = 'attach'
    interrupted = False

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

    def collected():
        return any(row['step'] in ('collect', 'collect-final') and row['status'] == 'done'
                   for row in state.document['transitions'])

    try:
        from .linux_l2 import LinuxL2Job
        if state.document['job'] is not None:
            job = LinuxL2Job.restore(vm)
        if state.phase != 'closing':
            if job is None:
                raise ValueError('l2-job-state-missing')
            if vm.reset_pending and vm.reset_kind == 'guest':
                # The dead controller saw the guest's reset and did not confirm its boot: wait for it as it would.
                step('attach-guest', lambda: vm.await_rebooted_guest(timeout=REBOOT_SECONDS, clock=clock, sleep=sleep))
            else:
                step('attach-guest', vm.attach_guest)
            if collected():
                job.load_assessment()
            else:
                wait_until = state.document['deadlines'].get('wait_until')
                if wait_until is None:
                    # The controller died while submitting: wait as a fresh submission would.
                    wait_until = now() + wait_seconds(config.get('suite', 'linux-l2'), config['timeouts']['job'])
                    state.update('deadlines', wait_until=wait_until)
                step('wait', lambda: job.wait(max(0, wait_until - now()), sleep=sleep, clock=clock))
                try:
                    step('collect', job.collect)
                except Exception:
                    if not vm.qga.valid:
                        step('collect-recovery', vm.recover_guest)
                    sleep(15)
                    step('collect-final', job.collect)
        elif job is not None and collected():
            job.load_assessment()
    except BaseException as error:
        interrupted = isinstance(error, KeyboardInterrupt)
        result['errors'].append(failure(stage, error))
    finally:
        if job is not None:
            result['execution'] = job.snapshot()
            result['assessment'] = job.assessment
        try:
            step('close', lambda: vm.close(hard=bool(result['errors'])))
        except BaseException as error:
            interrupted |= isinstance(error, KeyboardInterrupt)
            result['errors'].append(failure('close', error))
        try:
            result['completion'] = completion_verified(run.directory, run._read())
        except (OSError, ValueError):
            result['completion'] = False
        result['manual_recovery_required'] = not result['completion']
        finish_state(state, result['completion'], result)
        result = seal(run, result, interrupted)
        _release(lease, result, interrupted)
    return result


def close_run(state_directory, run_id, *, timeout=5, commit=None):
    """`recover --close`: connect to a live run, quit QEMU, wait for its exit and record completion.

    The run state ends `quarantined` with reason `closed-by-recover`, so the run
    never counts as a result, while its ledger ends verified and frees the stand.
    """
    commit = _current_commit() if commit is None else commit
    answer = dict(schema='rosetun.matrix.recover-close.v1', run_id=run_id, closed=False, refused=None,
                  completion_verified=False, cleanup_executed=False)
    try:
        lease, run, state, vm, attachments = _claim(state_directory, run_id, timeout, commit)
    except AttachRefused as error:
        return dict(answer, refused=error.reason), 1
    errors = []
    try:
        if state.phase not in FINAL:
            state.transition('closing', 'recover-close', 'intent')
        vm.close()
    except BaseException as error:
        errors.append(failure('recover-close', error))
    try:
        completed = completion_verified(run.directory, run._read())
    except (OSError, ValueError):
        completed = False
    try:
        if state.phase not in FINAL:
            state.transition('quarantined', 'recover-close', 'done' if completed else 'error',
                             reason='closed-by-recover')
    except (OSError, ValueError):
        errors.append(dict(stage='recover-close', kind='RunStateError', reason='run-state-write-failed'))
    try:
        summary, _ = read_json(resource_path(run.directory, 'execution-summary.json'))
        if type(summary) is dict and summary.get('schema') == SUMMARY_SCHEMA:
            summary['errors'] = list(summary.get('errors') or []) + [
                dict(stage='recover-close', kind='Recovery', reason='closed-by-recover'), *errors]
            summary.update(attached=True, attachments=attachments, completion=completed,
                           manual_recovery_required=not completed, exit_code=2)
            save(run, 'execution-summary.json', summary)
    except FileNotFoundError:
        pass
    except (OSError, ValueError, RecursionError) as error:
        errors.append(failure('summary', error))
    result = dict(answer, closed=completed, completion_verified=completed, phase=state.phase,
                  reason=state.document['reason'], attachments=attachments, errors=errors)
    _release(lease, result, False)
    return result, 0 if completed and not errors else 2


class Adapters:
    """Lazy execution imports; tests replace operations, not the orchestrator."""

    def __init__(self):
        from .qemu import prepare, execute, QemuConfig
        from .images import ImageDescriptor
        from .lifecycle import start
        from .l2_media import attach_media, write_requests
        from .l2_import import L2Import
        self.prepare, self.execute, self.config, self.image = prepare, execute, QemuConfig, ImageDescriptor
        self.start, self.attach, self.importer = start, attach_media, L2Import
        self.requests = write_requests


def run_linux_l2(config, **options):
    if config.get('suite', 'linux-l2') != 'linux-l2':
        raise ValueError('configuration is for another suite')
    return run_linux(config, **options)


def run_linux_l3(config, **options):
    if config.get('suite') != 'linux-l3':
        raise ValueError('configuration is for another suite')
    return run_linux(config, **options)


def run_linux_proxy(config, **options):
    if config.get('suite') != 'linux-proxy':
        raise ValueError('configuration is for another suite')
    return run_linux(config, **options)


def run_linux_l5(config, **options):
    if config.get('suite') != 'linux-l5':
        raise ValueError('configuration is for another suite')
    return run_linux(config, **options)


def run_linux_l4(config, **options):
    if config.get('suite') != 'linux-l4':
        raise ValueError('configuration is for another suite')
    return run_linux(config, **options)


def run_linux_reboot_smoke(config, **options):
    if config.get('suite') != 'linux-reboot-smoke':
        raise ValueError('configuration is for another suite')
    return run_linux(config, **options)


def run_linux(config, *, adapters=None, clock=time.monotonic, sleep=time.sleep,
              progress=None):
    """One path for every stage; only L3, Proxy and L5 add their requests to the run and pass their profile on."""
    progress = progress or (lambda stage: print(stage, file=sys.stderr, flush=True))
    suite = config.get('suite', 'linux-l2')
    l3 = config.get('l3') if suite in ('linux-l3', 'linux-proxy', 'linux-l5', 'linux-l4') else None
    profile = {'linux-proxy': 'proxy', 'linux-l5': 'l5', 'linux-l4': 'l4'}.get(suite, 'l3')
    result = dict(schema=SUMMARY_SCHEMA, suite=suite, identities={}, configuration=config, stages=[],
                  evidence=[], assessment=None, delivery=None, execution=None,
                  completion=False, manual_recovery_required=False, errors=[],
                  attached=False, attachments=0,
                  security_invariants='UNVERIFIED', release_gate=False, exit_code=2)
    lease = run = vm = attempt = job = state = None
    stage = 'preflight'
    interrupted = False

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

    def recovery():
        # One refresh after import, one after uncertain submit/collection. Never exec again.
        return vm.recover_guest()

    try:
        result['preflight'] = step('preflight', lambda: preflight(config))
        adapters = adapters or Adapters()
        identities = dict(host_run_id=uuid.uuid4().hex,
                          guest_run_id=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + uuid.uuid4().hex[:8],
                          import_id=uuid.uuid4().hex)
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
        step('prepare', lambda: adapters.prepare(run, adapters.image(**config['image']),
                                                adapters.config(**config['qemu']), executor=executor))
        if l3:
            # The generated requests belong to this run; the owner's content stays untouched.
            step('requests', lambda: adapters.requests(run, l3['host_address'], l3['node_port'],
                                                       **({'profile': profile} if profile != 'l3' else {})))
        step('media', lambda: adapters.attach(run, directory=config['content_directory'],
              checkout=config['source_checkout'], xorriso=config['xorriso'], executor=executor,
              **(dict(profile=profile, sing_box_sha256=l3.get('sing_box_sha256')) if l3 else
                 dict(profile='reboot-smoke') if suite == 'linux-reboot-smoke' else {})))
        if clock() >= deadline:
            raise TimeoutError('preparation deadline')
        vm = step('start', lambda: adapters.start(run))
        vm.planned_reboots = planned_reboots_of(suite)
        step('resume', vm.resume)
        step('boot', lambda: vm.wait_initial_guest(timeout=config['deadlines']['boot'],
                                                 clock=clock, sleep=sleep))
        identities.update(boot_id=vm.last_boot_id, vm_uuid=vm.vm_uuid)
        state.update('identities', boot_id=vm.last_boot_id, vm_uuid=vm.vm_uuid)
        attempt = step('import-create', lambda: adapters.importer(vm, enabled=True,
              guest_run_id=identities['guest_run_id'], import_id=identities['import_id'],
              **config['accounts'], **{k + '_timeout': v for k, v in config['timeouts'].items()},
              **(dict(l3=l3) if l3 else {})))
        attempt.deadline = min(attempt.deadline, clock() + config['deadlines']['import'])
        try:
            step('import', attempt.stage)
        except Exception:
            if vm.qga.valid:
                raise
            # The importer may still be running. Inspect its durable receipt only at its deadline.
            sleep(max(0, attempt.deadline - clock() - 60))
            step('import-recovery', recovery)
            step('receipt-after-uncertainty', attempt.check_receipt)
        else:
            step('import-refresh', recovery)
            step('receipt', attempt.check_receipt)
        result['delivery'] = dict(state=attempt.state, receipt_verified=attempt.receipt_verified)
        job = step('job-create', lambda: attempt.linux_l2_job(checkout=config['source_checkout'], enabled=True))
        try:
            step('submit', job.submit)
        except Exception:
            if vm.qga.valid or job.submission != 'unknown':
                raise
            step('submit-recovery', recovery)
        # The wait reads the job's status file, so it ends when the job does and spends no collect attempt.
        waiting = wait_seconds(suite, config['timeouts']['job'])
        state.deadline('wait_until', waiting)
        step('wait', lambda: job.wait(waiting, sleep=sleep, clock=clock))
        try:
            step('collect', job.collect)
        except Exception:
            if not vm.qga.valid:
                step('collect-recovery', recovery)
            sleep(15)
            step('collect-final', job.collect)
        result['execution'] = job.snapshot()
        result['assessment'] = job.assessment
    except BaseException as error:
        interrupted = isinstance(error, KeyboardInterrupt)
        result['errors'].append(failure(stage, error))
        if vm is None:
            vm = getattr(error, 'vm', None)
        # start() retains ownership even when interrupted before returning a handle.
        if vm is None and lease is not None and lease._active:
            vm = next(iter(lease._active))
    finally:
        if job is not None:
            result['execution'] = job.snapshot()
            result['assessment'] = job.assessment
        if attempt is not None:
            result['delivery'] = dict(state=attempt.state, receipt_verified=attempt.receipt_verified)
        if vm is not None:
            try:
                step('close', lambda: vm.close(hard=bool(result['errors'])))
                result['completion'] = vm.completed and completion_verified(run.directory, run._read())
            except BaseException as error:
                interrupted |= isinstance(error, KeyboardInterrupt)
                result['errors'].append(failure('close', error))
        if run is not None:
            try:
                result['completion'] = completion_verified(run.directory, run._read())
            except (OSError, ValueError):
                result['completion'] = False
        result['manual_recovery_required'] = run is not None and not result['completion']
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
