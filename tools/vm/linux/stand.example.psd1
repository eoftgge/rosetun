# Settings of the Linux L2 stand. Copy this file to stand.local.psd1 in the same
# folder (git-ignored) and change the values to your own. A parameter given on the
# command line wins over the file. Paths may use %VARIABLE% and a leading ~.
#
# Never put a password or a private key here: IdentityFile is only a path.
@{
    # Hyper-V name of the Debian VM. Its id is read from Hyper-V and checked.
    VmName         = 'rosetun-linux-l2'
    # The value in the guest's /etc/rosetun-l2-stand-id; also the name the host
    # key is pinned under in KnownHostsPath.
    StandId        = 'rosetun-l2-stand-1'
    # The ordinary guest account SSH logs into and that may start the launcher.
    SshUser        = 'l2admin'
    KnownHostsPath = '%USERPROFILE%\.ssh\rosetun-l2.known_hosts'
    IdentityFile   = '%USERPROFILE%\.ssh\rosetun-l2'
    # The two ordinary test accounts in group rosetun.
    UserA          = 'ipc_owner'
    UserB          = 'ipc_other'
    # Checkpoint restored before each run.
    Checkpoint     = 'l2-clean'
    # WSL distribution that builds the artifacts.
    WslDistro      = 'Debian'
    # Leave empty to read the address from Hyper-V (needs hyperv-daemons in the
    # guest). Set it only for a fixed address.
    SshHost        = ''
}
