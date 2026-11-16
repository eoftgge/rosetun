"""The tables of the Linux L4 suite in the lab (stage 8d), read by `l3_summary` in place of the L3 ones.

Same meaning as the tables of `l3_summary`, fixed here by the controller from what the functions of `run-l4.sh`
send; the guest declares nothing. No L4 run has been through the lab when these were written, so every count comes
from the script alone. Nothing is accepted: the release gate stays false and the security invariants stay unverified.

L4 has one window, `lockdown` (variant A of the study): from the moment Lockdown goes on, with the local network off,
to the moment `exit.reset-firewall` has taken the table away. Under Lockdown no marker can leave the test machine, so
nothing divides the window, and it lasts through the first reboot, which the guest takes inside it.
"""

from .l3_summary import RESOLVER_FLOW, TARGET_FLOW

# Every scenario of scenarios-l4.tsv: the ones that touch the wire are judged in the window, the others show
# nothing on it, and the group is what the lab can prove of the suite (`inbound.*` among it, by the poller).
GROUP = ('preflight.identity', 'preflight.accounts', 'preflight.no-foreign-service', 'preflight.tools',
         'preflight.baseline', 'install.service', 'lockdown.denied', 'lockdown.direct-blocked', 'lockdown.gui-scope',
         'lockdown.cli-scope', 'lockdown.other-process', 'inbound.closed', 'inbound.lan-open',
         'inbound.lan-link-local-closed', 'lockdown.session', 'lockdown.session-scope-closed',
         'lockdown.after-session', 'lockdown.flush-restored', 'crash.stopped', 'crash.killed',
         'exit.denied-without-root', 'reboot.table-before-network', 'reboot.after-nftables',
         'reboot.closed-before-service', 'reboot.service-completes', 'exit.reset-firewall', 'reboot.without-record')
WINDOW = ('lockdown', 0)
# The window of each scenario: the function of run-l4.sh that opened the session it ran in (label, number).
WINDOW_OF = {
    # Before Lockdown: the preflight (one direct request, before any window), the installation and the refusal of an
    # ordinary account, which `lockdown.denied` proves changes nothing.
    'preflight.identity': None, 'preflight.accounts': None, 'preflight.no-foreign-service': None,
    'preflight.tools': None, 'preflight.baseline': None, 'install.service': None, 'lockdown.denied': None,
    # `lockdown` opens before `lockdown on --lan off` of `turned_on` and closes in `reset` once the table is gone,
    # before its direct request. Every scenario in between is in it, the two reboots' first included.
    **dict.fromkeys(('lockdown.direct-blocked', 'lockdown.gui-scope', 'lockdown.cli-scope', 'lockdown.other-process',
                     'inbound.closed', 'inbound.lan-open', 'inbound.lan-link-local-closed', 'lockdown.session',
                     'lockdown.session-scope-closed', 'lockdown.after-session', 'lockdown.flush-restored',
                     'crash.stopped', 'crash.killed', 'exit.denied-without-root', 'reboot.table-before-network',
                     'reboot.after-nftables', 'reboot.closed-before-service', 'reboot.service-completes',
                     'exit.reset-firewall'), WINDOW),
    # After the window: the second boot has no record, so nothing closes the network and the direct request goes out.
    'reboot.without-record': None,
}
OWN_WINDOW_WHEN_OPENED = {}
GROUP_LABELS = tuple(dict.fromkeys(window[0] for window in WINDOW_OF.values() if window))
WINDOWS_PER_LABEL = dict.fromkeys(GROUP_LABELS, 1)
WINDOWS_AT_MOST = {}
# The direct flows the window shows by design, counted from the code of the script: `scope_probe` runs one `curl` to
# the probe address and one TFTP datagram to the DNS probe address on the physical interface, and the scopes that
# Lockdown permits answer them. That is `gui_scope` (`rosetun-gui`), `cli_scope` (`rosetun-cli`), `after`
# (`rosetun-gui`, after the session) and `killed` (`rosetun-cli`, after the restart): four probes, each one TCP
# connection to the target and one UDP exchange with the resolver (curl's TFTP request goes twice when the answer is
# no TFTP; the same four-tuple is one flow). `others` (`rosetun-other`) and `scope_closed` (`rosetun-gui` during a
# session) are refused in the guest, and so is every `direct_https`, `routed_https` and `user_direct_https` under
# Lockdown, so none of them shows. The tunnel of `lockdown.session`, `after`'s and the reboot's connect is `tunnel`.
EXPECTED_FLOWS = {WINDOW: {TARGET_FLOW: 4, RESOLVER_FLOW: 4}}
# The first boot is in the window: the test machine's kernel checks its own IPv6 addresses (neighbor solicitation from
# `::`) while the interface comes up. Nothing else of a boot is let through that is not infrastructure already:
# an ARP probe or announcement, should the network manager send one, would be a finding to look at, not to allow.
WINDOW_ALLOWANCES = {WINDOW[0]: ('ipv6-dad',)}
# What the observer must have seen of the lab for the group to mean anything: the node (`lockdown.session` connects),
# the HTTPS target (the probes and the tunnel) and DoH (the helper's DNS check at each connect goes through it). The
# plain resolver is not required: no scenario of L4 asks it a question, the datagrams of the probes are TFTP.
REQUIRED_FIXTURES = ('node', 'https', 'doh')
LEAK_OUTSIDE_THE_GROUP_FAILS = True
# The positive control: with the service stopped before the first reboot, the boot unit of Lockdown is turned off,
# so the next boot opens the network, and one direct request goes out right after it, before anything of the job.
# The request reaches the target, so the window shows a fifth direct connection to it, and `exit.denied-without-root`,
# the last scenario that passed before the reboot, is contradicted by a window that is not clean.
CONTROLS = ('stop-helper',)
CONTROL_WINDOW, CONTROL_SCENARIO = 'lockdown', 'exit.denied-without-root'
# The job reboots the guest twice, so the controller must have taken three boots in order.
BOOT_CHAIN = 3
# The lab's SSH poller of `inbound.lan-open`: the category `inbound-poll` of the observer (stage 8d).
INBOUND_POLL = True
# The two machines' clocks are the host's at boot and drift apart by a fraction of a second in a run; the guest notes the
# moment the local network went on on its own clock, the capture times are the lab's. Answers of the test machine to the
# poller count from that moment less this slack.
LAN_ON_SLACK_SECONDS = 2.0
