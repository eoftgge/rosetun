"""Sequential exploratory L2 execution under the original stand lease."""

from datetime import datetime, timezone
import hashlib
import json
import re
import sys
import time
import uuid

from .evidence import write_file
from .execution import preflight
from .resources import (StandLease, create_run, resource_path, EXECUTION_FILES,
                        completion_verified)

SUMMARY_SCHEMA = 'rosetun.matrix.execution-summary.v1'
_RETAINED_LEASES = []


def failure(stage, error):
    reason = str(error)
    return dict(stage=stage, kind=type(error).__name__,
                reason=reason if type(error).__module__.startswith('tools.vm.matrix.')
                and re.fullmatch(r'[A-Za-z0-9_-]{1,96}', reason) else 'operation-failed')


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


class Adapters:
    """Lazy execution imports; tests replace operations, not the orchestrator."""

    def __init__(self):
        from .qemu import prepare, execute, QemuConfig
        from .images import ImageDescriptor
        from .lifecycle import start
        from .l2_media import attach_media
        from .l2_import import L2Import
        self.prepare, self.execute, self.config, self.image = prepare, execute, QemuConfig, ImageDescriptor
        self.start, self.attach, self.importer = start, attach_media, L2Import


def run_linux_l2(config, *, adapters=None, clock=time.monotonic, sleep=time.sleep,
                 progress=None):
    progress = progress or (lambda stage: print(stage, file=sys.stderr, flush=True))
    result = dict(schema=SUMMARY_SCHEMA, identities={}, configuration=config, stages=[],
                  evidence=[], assessment=None, delivery=None, execution=None,
                  completion=False, manual_recovery_required=False, errors=[],
                  security_invariants='UNVERIFIED', release_gate=False, exit_code=2)
    lease = run = vm = attempt = job = None
    stage = 'preflight'
    interrupted = False

    def step(name, operation):
        nonlocal stage
        stage = name
        progress(name)
        row = dict(stage=name, state='started')
        result['stages'].append(row)
        try:
            value = operation()
        except BaseException:
            row['state'] = 'error'
            raise
        row['state'] = 'completed'
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
        step('save-identities', lambda: save(run, 'execution-identity.json',
              dict(schema='rosetun.matrix.execution-identity.v1', **identities), initial=True))
        save(run, 'execution-summary.json', result, initial=True)
        deadline = clock() + config['deadlines']['preparation']
        executor = bounded_executor(deadline)
        step('prepare', lambda: adapters.prepare(run, adapters.image(**config['image']),
                                                adapters.config(**config['qemu']), executor=executor))
        step('media', lambda: adapters.attach(run, directory=config['content_directory'],
              checkout=config['source_checkout'], xorriso=config['xorriso'], executor=executor))
        if clock() >= deadline:
            raise TimeoutError('preparation deadline')
        vm = step('start', lambda: adapters.start(run))
        step('resume', vm.resume)
        step('boot', lambda: vm.wait_initial_guest(timeout=config['deadlines']['boot'],
                                                 clock=clock, sleep=sleep))
        identities.update(boot_id=vm.last_boot_id, vm_uuid=vm.vm_uuid)
        attempt = step('import-create', lambda: adapters.importer(vm, enabled=True,
              guest_run_id=identities['guest_run_id'], import_id=identities['import_id'],
              **config['accounts'], **{k + '_timeout': v for k, v in config['timeouts'].items()}))
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
        # Conservative waiting needs no status RPC and cannot consume collect attempts early.
        step('wait', lambda: sleep(config['timeouts']['job'] + 125))
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
        accepted = bool(result['execution'] and result['execution']['accepted'])
        result['exit_code'] = (130 if interrupted else 2 if result['errors'] or not result['completion']
                               else 0 if accepted else 1)
        if run is not None:
            payload = json.dumps(result)
            if run._identity[2] in payload:
                result = json.loads(payload.replace(run._identity[2], '[redacted-owner-token]'))
                result['errors'].append(dict(stage='summary', kind='RedactionError',
                                             reason='owner-token-redacted'))
                result['exit_code'] = 130 if interrupted else 2
            try:
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
