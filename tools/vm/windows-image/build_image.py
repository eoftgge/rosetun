#!/usr/bin/env python3
"""Build and measure the Windows 11 guest image for the QEMU matrix (Linux, outside the controller).

    build_image.py plan    CONFIG    print every command line, run nothing
    build_image.py build   CONFIG    install Windows unattended into a new qcow2 and describe it
    build_image.py measure CONFIG    boot a copy of the built image and measure it

Nothing here is part of a matrix run. See README.md for the stop point after the measurements.
"""

import argparse
import datetime
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))

import image_answers  # noqa: E402
import image_config  # noqa: E402
import image_guest  # noqa: E402
import image_plan  # noqa: E402

HERE = Path(__file__).resolve().parent
# Thresholds of the stop point: past either of them, do not go on to the next stage.
BOOT_LIMIT_SECONDS = 300
CPU_LIMIT_PERCENT = 10.0
SETTLE_SECONDS = 300
CPU_SAMPLES = 60
AGENT_WAIT_SECONDS = 900
# Run states that end a build at once: the machine will not shut down or answer by itself.
FATAL_STATES = frozenset({'internal-error', 'guest-panicked', 'io-error', 'paused', 'watchdog'})
LOG_TAIL_LINES = 20
# The build takes a screenshot every two minutes and keeps the last thirty. A frame that has not changed
# for twenty minutes is a page waiting for an answer nobody gives (an OOBE page, for example): copying
# files and restarts change the frame all the time.
SCREEN_INTERVAL_SECONDS = 120
SCREEN_STALL_SECONDS = 20 * 60
SCREENS_KEPT = 30
# Primary volume descriptor of ISO 9660: sector 16; the volume identifier is 32 bytes at offset 40.
PVD_OFFSET = 16 * 2048


class BuildError(RuntimeError):
    pass


def unix_connection(path):
    def connect():
        stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            stream.connect(path)
        except OSError:
            stream.close()
            raise
        return stream
    return connect


def sha256_stream(path):
    return image_plan.sha256_file(path)[0]


def iso_volume_label(path):
    """The volume identifier of an ISO 9660 disc, read straight from its primary volume descriptor."""
    with open(path, 'rb') as stream:
        stream.seek(PVD_OFFSET)
        descriptor = stream.read(72)
    if len(descriptor) < 72 or descriptor[0] != 1 or descriptor[1:6] != b'CD001':
        raise BuildError('windows_iso: not an ISO 9660 image')
    return descriptor[40:72].decode('ascii', 'replace').strip()


def check_language(config):
    """Refuse a disc of another language before anything is created: Microsoft discs carry it in the label,
    as in `CCCOMA_X64FRE_EN-US_DV9`, and the guest agent output is parsed in English."""
    label = iso_volume_label(config.windows_iso)
    if config.language.upper() not in label.upper():
        raise BuildError(f"windows_iso: the volume label '{label}' does not name the language "
                         f'{config.language} of the configuration')


class GuestWatch:
    """Follows the run state of QEMU over QMP and ends the build when the machine has failed.

    A machine in `internal-error` never shuts down and never answers the agent, so waiting for either
    only wastes the build timeout. The failure carries a screenshot and the end of the QEMU log, and
    QEMU is then asked to quit.

    QMP serves one client, so this is the only one that can take a screenshot while the build waits.
    With `screen_interval` it takes one at that interval into `screens/` of the directory (the last
    `keep` stay), reports each through `record(**fields)`, and fails with `screen-stalled` when the
    frame has not changed for `stall_seconds`.
    """

    def __init__(self, qemu, connect, directory, log_path, *, screen_interval=None,
                 stall_seconds=SCREEN_STALL_SECONDS, keep=SCREENS_KEPT, record=None,
                 clock=time.monotonic):
        self.qemu = qemu
        self.connect = connect
        self.directory = str(directory).replace('\\', '/')
        self.log_path = log_path
        self.qmp = None
        self.screen_interval = screen_interval
        self.stall_seconds = stall_seconds
        self.keep = keep
        self.record = record
        self.clock = clock
        self.shots = 0
        self.last_shot = None
        self.last_hash = None
        self.last_change = None

    def _own(self):
        if self.qmp is None:
            self.qmp = image_guest.Qmp(self.connect())
        return self.qmp

    def _drop(self):
        if self.qmp is not None:
            self.qmp.close()
            self.qmp = None

    def check(self, qmp=None):
        """Raise `BuildError` if the machine is in a fatal state; an unreachable QMP is not one."""
        if self.qemu.poll() is not None:
            return
        try:
            qmp = qmp or self._own()
            status = qmp.status()
        except (OSError, image_guest.GuestError, ValueError):
            if qmp is None:
                self._drop()
            return
        if status in FATAL_STATES:
            raise self.failure(f'the guest is in state {status}', qmp)
        if self.screen_interval is not None:
            self._watch_screen(qmp)

    def _watch_screen(self, qmp):
        now = self.clock()
        if self.last_shot is not None and now - self.last_shot < self.screen_interval:
            return
        screens = Path(self.directory) / 'screens'
        screens.mkdir(exist_ok=True)
        self.shots += 1
        shot = screens / f'screen-{self.shots:04d}.ppm'
        try:
            qmp.screendump(str(shot).replace('\\', '/'))
            digest = image_plan.sha256_file(shot)[0]
        except (OSError, image_guest.GuestError, ValueError):
            return
        self.last_shot = now
        if digest != self.last_hash or self.last_change is None:
            self.last_change = now
        self.last_hash = digest
        if self.record is not None:
            self.record(stage='screen', file=shot.name, sha256=digest)
        for old in sorted(screens.glob('screen-*.ppm'))[:-self.keep]:
            old.unlink(missing_ok=True)
        if now - self.last_change >= self.stall_seconds:
            raise self.failure(f'screen-stalled: the screen did not change for '
                               f'{round(self.stall_seconds / 60)} minutes', qmp)

    def failure(self, reason, qmp=None):
        """Collect the evidence, close QEMU through QMP and return the error to raise."""
        shot = f'{self.directory}/failure-screen.ppm'
        try:
            qmp = qmp or self._own()
        except (OSError, image_guest.GuestError, ValueError):
            qmp = None
        if qmp is not None:
            try:
                qmp.screendump(shot)
            except (OSError, image_guest.GuestError, ValueError):
                shot = None
            qmp.quit()
            try:
                self.qemu.wait(timeout=30)
            except subprocess.TimeoutExpired:
                pass
        else:
            shot = None
        self._drop()
        tail = self._log_tail()
        return BuildError(f'{reason}; screenshot: {shot or "none"}; end of the QEMU log:\n{tail}')

    def _log_tail(self):
        try:
            with open(self.log_path, 'rb') as stream:
                stream.seek(0, os.SEEK_END)
                stream.seek(max(0, stream.tell() - 8192))
                data = stream.read()
        except OSError:
            return '(no log)'
        return '\n'.join(data.decode('utf-8', 'replace').splitlines()[-LOG_TAIL_LINES:]) or '(empty)'


def wait_for_shutdown(qemu, watch, seconds, *, interval=5, clock=time.monotonic, sleep=time.sleep):
    """Wait until QEMU exits; a fatal run state or the end of the time is a `BuildError` with evidence."""
    deadline = clock() + seconds
    while qemu.poll() is None:
        if clock() > deadline:
            raise watch.failure('the guest did not shut down in time; VNC shows where it stopped')
        watch.check()
        sleep(interval)


def sleep_watching(watch, seconds, *, interval=5, clock=time.monotonic, sleep=time.sleep):
    deadline = clock() + seconds
    while clock() < deadline:
        watch.check()
        sleep(min(interval, max(0.0, deadline - clock())))


def check_inputs(config):
    for name in ('windows_iso', 'virtio_win_iso', 'ovmf_code', 'ovmf_vars_template',
                 'qemu_system', 'qemu_img', 'xorriso', 'swtpm'):
        if not Path(getattr(config, name)).is_file():
            raise BuildError(f'{name}: no such file')
    virtio = sha256_stream(config.virtio_win_iso)
    if virtio != config.virtio_win_sha256:
        raise BuildError('virtio-win disc does not match the pinned SHA-256')
    check_language(config)
    windows = sha256_stream(config.windows_iso)
    if config.windows_iso_sha256 and windows != config.windows_iso_sha256:
        raise BuildError('Windows disc does not match the pinned SHA-256')
    return windows


def write_secret(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w', encoding='ascii', newline='\n') as stream:
        stream.write(value + '\n')


def event(layout, **fields):
    fields['at'] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
    with open(layout.events, 'a', encoding='utf-8', newline='\n') as stream:
        stream.write(json.dumps(fields, sort_keys=True) + '\n')


def run_checked(argv, what):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=600, check=False)
    if result.returncode != 0:
        raise BuildError(f'{what} failed with exit code {result.returncode}')


def wait_for_path(path, seconds, process):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if Path(path).exists():
            return
        if process.poll() is not None:
            raise BuildError('swtpm exited before its socket appeared')
        time.sleep(0.2)
    raise BuildError('swtpm socket did not appear')


def start(argv, log_path):
    log = open(log_path, 'ab')
    try:
        return subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    finally:
        log.close()


def stop(process, seconds=15):
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=seconds)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=seconds)


def prepare_answers(config, layout, password):
    tree = Path(layout.answers_tree)
    tree.mkdir()
    (tree / 'Autounattend.xml').write_bytes(image_answers.autounattend(config, password))
    shutil.copyfile(HERE / 'first-logon.ps1', tree / 'first-logon.ps1')
    run_checked(image_plan.xorriso_argv(config, image_answers.xorriso_arguments(tree, layout.answers_iso)),
                'xorriso')


def build(config):
    windows_sha = check_inputs(config)
    code_sha = sha256_stream(config.ovmf_code)
    template_sha = sha256_stream(config.ovmf_vars_template)
    output = Path(config.output_directory)
    if output.exists() or not output.parent.is_dir():
        raise BuildError('output directory must be new, in an existing parent')
    output.mkdir()
    layout = image_plan.Layout(output)
    machine_uuid = str(uuid.uuid4())
    event(layout, stage='inputs-verified')
    password = image_answers.generate_password()
    write_secret(layout.secret, password)
    prepare_answers(config, layout, password)
    run_checked(image_plan.qemu_img_create_argv(config, layout), 'qemu-img create')
    shutil.copyfile(config.ovmf_vars_template, layout.vars)
    Path(layout.tpm_state).mkdir()
    swtpm = qemu = None
    try:
        swtpm = start(image_plan.swtpm_argv(config, layout), output / 'swtpm.out')
        wait_for_path(layout.tpm_socket, 10, swtpm)
        qemu = start(image_plan.qemu_argv(config, layout, machine_uuid, install=True), output / 'qemu.log')
        event(layout, stage='qemu-started', vnc=f'127.0.0.1:{5900 + config.vnc_display}')
        watch = GuestWatch(qemu, unix_connection(layout.qmp), output, output / 'qemu.log',
                           screen_interval=SCREEN_INTERVAL_SECONDS,
                           record=lambda **fields: event(layout, **fields))
        # The Windows disc asks for a key before Setup starts; the answer file cannot answer that.
        image_guest.press_until(unix_connection(layout.qmp), image_plan.PRESS_KEY,
                                config.press_any_key_seconds, inspect=watch.check)
        wait_for_shutdown(qemu, watch, config.timeout_minutes * 60)
        if qemu.returncode != 0:
            raise BuildError(f'QEMU exited with code {qemu.returncode}')
        event(layout, stage='guest-shut-down')
    finally:
        stop(qemu)
        stop(swtpm)
    disk_sha, disk_size = image_plan.sha256_file(layout.disk)
    vars_sha = sha256_stream(layout.vars)
    tpm_files = {entry.name: sha256_stream(entry) for entry in sorted(Path(layout.tpm_state).iterdir())
                 if entry.is_file()}
    if image_plan.TPM_STATE_FILE not in tpm_files:
        raise BuildError('the TPM state file is missing: nothing was written by Windows')
    record = image_plan.descriptor(
        config, layout, uuid=machine_uuid, windows_iso_sha256=windows_sha, disk_sha256=disk_sha,
        disk_size=disk_size, vars_sha256=vars_sha, code_sha256=code_sha, template_sha256=template_sha,
        tpm_files=tpm_files,
        built_at=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'))
    Path(layout.descriptor).write_text(json.dumps(record, indent=2, sort_keys=True) + '\n',
                                       encoding='utf-8', newline='\n')
    # The answer file carries the account password in its obfuscated form; it is not needed again.
    shutil.rmtree(layout.answers_tree)
    Path(layout.answers_iso).unlink()
    event(layout, stage='described')
    return {'descriptor': layout.descriptor, 'sha256': disk_sha, 'size_bytes': disk_size,
            'password_file': layout.secret}


def record_platform(agent, result):
    """Secure Boot and the TPM as the guest itself reports them; False or an error is a stop point."""
    try:
        result['secure_boot'] = image_guest.secure_boot_state(agent)
    except image_guest.GuestError as error:
        result['secure_boot'] = None
        result['secure_boot_error'] = str(error)
    try:
        result['tpm'] = image_guest.tpm_state(agent)
    except image_guest.GuestError as error:
        result['tpm'] = None
        result['tpm_error'] = str(error)


def measure(config, *, settle=SETTLE_SECONDS):
    source = image_plan.Layout(config.output_directory)
    descriptor = json.loads(Path(source.descriptor).read_text(encoding='utf-8'))
    if sha256_stream(source.disk) != descriptor['sha256']:
        raise BuildError('the image does not match its descriptor')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    work = Path(config.output_directory) / f'measure-{stamp}'
    work.mkdir()
    layout = image_plan.Layout(work)
    overlay = layout.disk
    # A measurement boots a copy: the built image, its firmware variables and its TPM state stay as they were.
    run_checked(image_plan.qemu_img_overlay_argv(config, source.disk, overlay), 'qemu-img overlay')
    shutil.copyfile(source.vars, layout.vars)
    shutil.copytree(source.tpm_state, layout.tpm_state)
    swtpm = qemu = None
    result = {'image': descriptor['identifier'], 'size_bytes': descriptor['size_bytes'],
              'boot_limit_seconds': BOOT_LIMIT_SECONDS, 'cpu_limit_percent': CPU_LIMIT_PERCENT}
    try:
        swtpm = start(image_plan.swtpm_argv(config, layout), work / 'swtpm.out')
        wait_for_path(layout.tpm_socket, 10, swtpm)
        qemu = start(image_plan.qemu_argv(config, layout, descriptor['windows']['devices']['uuid_at_build'],
                                          install=False), work / 'qemu.log')
        watch = GuestWatch(qemu, unix_connection(layout.qmp), work, work / 'qemu.log')
        connect = unix_connection(layout.qga)
        boot = image_guest.wait_for_agent(connect, AGENT_WAIT_SECONDS, check=watch.check)
        result['agent_ready_seconds'] = None if boot is None else round(boot, 1)
        if boot is None:
            result['verdict'] = 'STOP: the guest agent never answered'
            return result
        sleep_watching(watch, settle)
        stream = connect()
        try:
            agent = image_guest.Qga(stream, timeout=30)
            agent.sync()
            code, out = agent.run(image_guest.TYPEPERF, image_guest.typeperf_arguments(CPU_SAMPLES),
                                  timeout=CPU_SAMPLES + 60)
            result['cpu_percent'] = round(image_guest.average_cpu_percent(out), 1)
            record_platform(agent, result)
            log = agent.read_file('C:\\ProgramData\\rosetun-image\\first-logon.log').decode('utf-8', 'replace')
            failed, complete = image_guest.failed_steps(log)
            result['first_logon_complete'] = complete
            result['first_logon_failed'] = failed
            agent.call('guest-shutdown', {'mode': 'powerdown'})
        finally:
            stream.close()
        problems = []
        if boot > BOOT_LIMIT_SECONDS:
            problems.append('boot to the agent took longer than the limit')
        if result['cpu_percent'] >= CPU_LIMIT_PERCENT:
            problems.append('CPU load at rest is at or above the limit')
        if not complete or failed:
            problems.append('the first-logon script is incomplete or has failed steps')
        if result['secure_boot'] is not True:
            problems.append('Secure Boot is not confirmed enabled in the guest')
        if not (result['tpm'] and result['tpm']['present'] and result['tpm']['ready']):
            problems.append('the TPM is not present and ready in the guest')
        result['verdict'] = 'STOP: ' + '; '.join(problems) if problems else 'within the limits (UNQUALIFIED)'
        deadline = time.monotonic() + 120
        while qemu.poll() is None and time.monotonic() < deadline:
            time.sleep(2)
    except BuildError as error:
        result['verdict'] = f'STOP: {error}'
        raise
    finally:
        stop(qemu)
        stop(swtpm)
        (work / 'measure.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n',
                                           encoding='utf-8', newline='\n')
    return result


def plan(config):
    layout = image_plan.Layout(config.output_directory)
    machine_uuid = '00000000-0000-4000-8000-000000000000'
    return {
        'swtpm': image_plan.swtpm_argv(config, layout),
        'xorriso': image_plan.xorriso_argv(config, image_answers.xorriso_arguments(
            layout.answers_tree, layout.answers_iso)),
        'qemu_img': image_plan.qemu_img_create_argv(config, layout),
        'qemu_install': image_plan.qemu_argv(config, layout, machine_uuid, install=True),
        'qemu_measure': image_plan.qemu_argv(config, layout, machine_uuid, install=False),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('command', choices=('plan', 'build', 'measure'))
    parser.add_argument('config')
    arguments = parser.parse_args(argv)
    try:
        config = image_config.load(arguments.config)
        if arguments.command == 'plan':
            output = plan(config)
        elif arguments.command == 'build':
            output = build(config)
        else:
            output = measure(config)
    except (BuildError, image_config.ConfigError, image_guest.GuestError, OSError,
            subprocess.SubprocessError) as error:
        print(f'error: {error}', file=sys.stderr)
        return 1
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
