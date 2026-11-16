"""The tables of the Linux L5 suite in the lab (stage 8b), read by `l3_summary` in place of the L3 ones.

Same meaning as the tables of `l3_summary`, fixed here by the controller from what the functions of `run-l5.sh`
send; the guest declares nothing. No L5 run has been through the lab when these were written, so every count comes
from the script alone. Nothing is accepted: the release gate stays false and the security invariants stay unverified.
"""

from .lab_protocol import TARGETS

# All 17 scenarios of scenarios-l5.tsv.
GROUP = ('preflight.identity', 'preflight.accounts', 'preflight.no-foreign-service', 'preflight.tools',
         'preflight.baseline', 'install.package', 'install.service', 'install.desktop', 'install.repeat',
         'upgrade.watch', 'upgrade.kill-switch-no-leak', 'upgrade.kill-switch-hold', 'upgrade.reconnect',
         'upgrade.lockdown', 'remove.refused', 'remove.lockdown', 'purge.state')
# The window of each scenario: the function of run-l5.sh that opened the session it ran in (label, number).
WINDOW_OF = {
    # No session: the preflight, dpkg and the files of the package, and the counter's own check, whose one direct
    # request goes before any window.
    'preflight.identity': None, 'preflight.accounts': None, 'preflight.no-foreign-service': None,
    'preflight.tools': None, 'preflight.baseline': None, 'install.package': None, 'install.service': None,
    'install.desktop': None, 'install.repeat': None, 'upgrade.watch': None,
    # `upgrade_ks`: the kill-switch session, the upgrade under it and the hold it leaves, which the reconnect of
    # `do_reconnect` lifts; its `disconnect` closes the window before the direct request after it. The table stays
    # from the connect to that disconnect, so no marker goes between them and the window is one.
    'upgrade.kill-switch-no-leak': ('upgrade_ks', 0), 'upgrade.kill-switch-hold': ('upgrade_ks', 0),
    'upgrade.reconnect': ('upgrade_ks', 0),
    # `upgrade_lockdown`: opened before Lockdown goes on, closed in `do_remove` once the removal took the table away,
    # before its direct request. Under Lockdown no marker goes out, so the refused removal is in it too.
    'upgrade.lockdown': ('upgrade_lockdown', 0), 'remove.refused': ('upgrade_lockdown', 0),
    'remove.lockdown': ('upgrade_lockdown', 0),
    'purge.state': None,
}
OWN_WINDOW_WHEN_OPENED = {}
GROUP_LABELS = tuple(dict.fromkeys(window[0] for window in WINDOW_OF.values() if window))
WINDOWS_PER_LABEL = dict.fromkeys(GROUP_LABELS, 1)
WINDOWS_AT_MOST = {}
# Both windows are judged as L3's kill-switch windows: nothing but the tunnel and the lab's infrastructure. The
# engine's connections to the node are `tunnel`; the prober of `upgrade_ks` makes many of them while dpkg works (two
# curls a second, one of them through the tunnel), so their number is not fixed anywhere. Its direct curl, the
# direct requests of the hold and of Lockdown are dropped in the guest and never reach the wire.
EXPECTED_FLOWS = {}
WINDOW_ALLOWANCES = {}
# As for L3: the preflight reaches the target directly, the host node and the resolver, the prober and the reconnect
# reach the target through the node, and the helper's DNS check at connect goes through the DoH target.
REQUIRED_FIXTURES = ('node', 'https', 'dns', 'doh')
LEAK_OUTSIDE_THE_GROUP_FAILS = True
# The positive control: the service stops inside `upgrade_ks`, right after `upgrade.kill-switch-no-leak` passed,
# and one direct request leaves.
CONTROLS = ('stop-helper',)
CONTROL_WINDOW, CONTROL_SCENARIO = 'upgrade_ks', 'upgrade.kill-switch-no-leak'
# The legacy counter and its twin: `rosetun-l5-watch` counts, after every filter of the output path, the packets
# that leave the physical interface for the probe address while dpkg upgrades the package; the scenario passes
# only with none, and its failure names the count first in its reason. The observer's twin is the window of that
# session.
COUNTER = dict(scenario='upgrade.kill-switch-no-leak', window=('upgrade_ks', 0), table='inet rosetun-l5-watch',
               address=TARGETS[4], reason=r'([0-9]+) packets past the tunnel: ')
