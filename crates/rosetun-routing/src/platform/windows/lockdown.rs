//! Lockdown: a persistent provider, sublayer and filters that BFE restores at
//! every start, so the machine stays blocked outside the tunnel while
//! disconnected, after a service crash and across reboots. Written in a
//! standard (non-dynamic) session; the study behind every choice here is in
//! `rules/LOCKDOWN-STUDY.md`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::ptr;

use windows_sys::Win32::Foundation::{
    FWP_E_FILTER_NOT_FOUND, FWP_E_IN_USE, FWP_E_PROVIDER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND,
};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_FILTER_FLAG_BOOTTIME, FWPM_FILTER_FLAG_PERSISTENT, FWPM_FILTER0,
    FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_PROVIDER0, FWPM_SUBLAYER_FLAG_PERSISTENT, FWPM_SUBLAYER0,
    FwpmFilterDeleteByKey0, FwpmFilterGetByKey0, FwpmFreeMemory0, FwpmProviderAdd0,
    FwpmProviderDeleteByKey0, FwpmProviderGetByKey0, FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0,
    FwpmSubLayerGetByKey0,
};
use windows_sys::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegFlushKey, RegOpenKeyExW,
};
use windows_sys::core::GUID;

use super::filters::{self, FilterConditions, Placement};
use super::policy::{
    AddressFamily, BOOTSTRAP_ALLOW_WEIGHT, Condition, DNS_PROTOCOLS, LAN_SUBNETS, Rule, lan_permit,
    private_dns_blocks, probe_authorization,
};
use super::session::{Engine, display_data, empty_blob, wfp_error, wide};
use crate::{
    LockdownApps, LockdownStatus, ProtectionSession, RoutingError, RoutingGuard, RoutingPlan,
    TunnelInterface,
};

// Never change, reuse or reorder any of these keys: removal finds objects
// only by them, so a changed key orphans the objects of every older version
// and leaves a machine offline that `reset-firewall` can no longer open.
pub(super) const PROVIDER_KEY: GUID = GUID::from_u128(0xf12dbedd_f3c7_4a72_b0f8_20559c88b112);
pub(super) const SUBLAYER_KEY: GUID = GUID::from_u128(0xf829a64d_c373_4d92_9d66_e1c680f3794f);
/// Dynamic provider of a server check's permits while no session runs. It
/// differs from the session's provider so a connect can start meanwhile.
const PROBE_PROVIDER_KEY: GUID = GUID::from_u128(0x8c9a1588_cf36_44b8_80d8_987a6b81b4d2);

/// Filter keys, `[IPv4, IPv6]` where there are two. Never change (see above).
mod keys {
    pub(super) const OUTBOUND_BLOCK: [u128; 2] = [
        0x57bf2a6e_57db_4d99_bed7_ecbd2c63aa75,
        0x668e013a_80b2_494e_adc8_a467e79029af,
    ];
    pub(super) const OUTBOUND_LOOPBACK: [u128; 2] = [
        0x2cc83766_42c1_4055_a233_465a1c5e4d63,
        0xa6af7d22_44d1_4318_8d63_dc1c9ca8a2e8,
    ];
    pub(super) const OUTBOUND_DHCP: u128 = 0x98419911_30f0_4f71_9178_263b40bc7f6e;
    pub(super) const OUTBOUND_GUI: [u128; 2] = [
        0x77c4c790_4f77_451d_aa96_f5e28daa304e,
        0x299d3b28_6573_4642_a6c5_fe03b92c693b,
    ];
    pub(super) const OUTBOUND_CLI: [u128; 2] = [
        0x729b156a_c411_4f01_b7d9_a789c94e992b,
        0x9c72b60d_eece_47de_8f81_e48c081cee74,
    ];
    /// DNS permits, `[IPv4, IPv6]`, each `[UDP, TCP]`.
    pub(super) const OUTBOUND_SERVICE_DNS: [[u128; 2]; 2] = [
        [
            0xcb0f8c4b_4967_4626_a493_a4e32369e6f5,
            0xeb0b437f_3395_4d20_83dd_040fdc9d5b20,
        ],
        [
            0x7c41059f_3c0d_40e5_9eda_7a04fb6f8c6d,
            0x9bb140bf_4073_4561_a128_d84f0e75ee13,
        ],
    ];
    pub(super) const OUTBOUND_GUI_DNS: [[u128; 2]; 2] = [
        [
            0xfba98c1b_e4b7_4861_b8d0_4257efdccb93,
            0xeea65519_d105_4ea7_b4dc_20e2e22b0c8e,
        ],
        [
            0x208cc620_16cc_4de1_ac55_7711bb1ef316,
            0x2c602b3d_4afc_4ef5_8330_37bfc8d18beb,
        ],
    ];
    pub(super) const OUTBOUND_CLI_DNS: [[u128; 2]; 2] = [
        [
            0x982cc554_9f41_4c9a_833f_87cc5149725f,
            0x85ef3077_f8fd_4e3b_b45f_a7ce7341f61a,
        ],
        [
            0xa0f1fdcf_267e_4792_bda1_bda1941c3b8a,
            0xd49b219d_aa46_480f_8f7e_d82f5df6cf78,
        ],
    ];
    /// In `LAN_SUBNETS` order.
    pub(super) const OUTBOUND_LAN: [u128; 6] = [
        0xce01436a_65d3_48e9_b921_e0a167b05f7b,
        0xdc72799c_c0bb_4068_87db_3b04037961f4,
        0xabad3e85_a43b_4d75_a5f9_261afca8d5dc,
        0x0909cb67_1355_4a27_ba93_ba4de5678c24,
        0x77da88c0_e160_4215_8d80_49135a047831,
        0xec518ce9_fc48_435d_b221_cb731a893e5e,
    ];
    /// In `LAN_SUBNETS` order, each `[UDP, TCP]`.
    pub(super) const OUTBOUND_LAN_DNS: [[u128; 2]; 6] = [
        [
            0x6073a92a_eb1d_43f8_95bd_cb138920ed18,
            0x6d85981d_ea17_4c74_a6fd_1f29c60530e6,
        ],
        [
            0xb2396f2c_2b64_433a_a69f_4d02b146f58b,
            0x5d886491_58fd_4015_8aec_b8e93d8b66dc,
        ],
        [
            0x5a82207d_d0a7_42b6_86b7_c0519c3ef571,
            0x4cce9c55_839c_4d28_8329_e8cd8110a85d,
        ],
        [
            0x6765ed5f_454f_4fc6_87ac_1640c30fb0f9,
            0xee90d8fe_4dc3_4337_9e66_c94dca5d00c0,
        ],
        [
            0xb2908520_c215_490b_b1f0_b5fa6a8cefe6,
            0x3ab4b83f_449f_4e2f_8004_6208909e736f,
        ],
        [
            0xeaab3271_4e50_4024_a3a6_a12a45542143,
            0xec631e05_769a_4750_a792_f33d717af829,
        ],
    ];
    pub(super) const INBOUND_BLOCK: [u128; 2] = [
        0xe599db5e_6aeb_4e4d_aa51_4314f1b3076c,
        0x0d6d0a7a_edc3_4448_8eeb_57c74f618c28,
    ];
    pub(super) const INBOUND_LOOPBACK: [u128; 2] = [
        0x5fbf3e7e_f240_4566_a817_70ee259b2794,
        0x79e5b858_882f_49d9_b3dd_74bb5239a3c6,
    ];
    pub(super) const INBOUND_DHCP: u128 = 0xaaf3942d_0eca_446c_8131_4f0a2bb7db3d;
    /// In `LAN_SUBNETS` order.
    pub(super) const INBOUND_LAN: [u128; 6] = [
        0x8c3d1cef_313a_4d95_a85f_e578f4a6fb6f,
        0xc2825618_f3ef_4696_bd7d_a4f5c08fccf1,
        0x8ade9b6f_d16f_49c0_b7a1_07effd15fad2,
        0xde7b8457_0712_4e86_98a7_dd8123a6dc70,
        0x1779ba71_90ce_4ffe_9dca_20108c515181,
        0x5c5bb398_f517_4ee8_85dc_546e9cbbd560,
    ];
    pub(super) const BOOT_OUTBOUND_BLOCK: [u128; 2] = [
        0x34460ec9_457c_4a3c_a4aa_dbd9d28b9e7b,
        0xaff70035_4ea1_4fba_a91d_74c8dc8c1b6f,
    ];
    pub(super) const BOOT_INBOUND_BLOCK: [u128; 2] = [
        0x3f99ad34_34b5_4488_b2ff_01cdc8bf9540,
        0x6ccbd042_fd3c_4520_9d12_9bc3cff8cbdb,
    ];
    pub(super) const BOOT_OUTBOUND_LOOPBACK: [u128; 2] = [
        0x54029c64_ea4e_487c_a1b6_20835afc9186,
        0x121c3714_3279_4f00_a9a0_b0cbd8de7cdf,
    ];
    pub(super) const BOOT_INBOUND_LOOPBACK: [u128; 2] = [
        0x7fd48055_3030_4845_a78e_113e407e19cc,
        0xc00791c1_1a03_4970_96f7_d19627034c96,
    ];
    pub(super) const BOOT_OUTBOUND_DHCP: u128 = 0x50a0a8df_637a_47c8_9977_016e672f3b31;
    pub(super) const BOOT_INBOUND_DHCP: u128 = 0xa51f4fec_b63a_4ec4_8ba5_d369e8689711;
}

/// Free on a clean Windows 11, whose nearest built-in sublayer below sits at
/// 0xC000; above it only sing-tun's dynamic sublayer at 0xFFFF, while the
/// engine runs. BFE moves a sublayer off a taken weight, so the stored weight
/// is read back and logged; nothing depends on its exact value.
const REQUESTED_SUBLAYER_WEIGHT: u16 = 0xD000;
/// Below every filter the session adds to the Lockdown sublayer.
const BLOCK_WEIGHT: u8 = 0;
/// Rosetun's own DNS queries while no tunnel is up. Above the private-DNS
/// block (3), so the router's resolver answers them with "Local network" on,
/// and apart from the tunnel permit (4).
const RESOLVER_WEIGHT: u8 = 5;
const FAMILIES: [AddressFamily; 2] = [AddressFamily::Ipv4, AddressFamily::Ipv6];

/// What a filter belongs to, for `LockdownStatus::complete`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Part {
    Base,
    Lan,
    App,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LockdownFilter {
    pub(super) key: u128,
    pub(super) name: &'static str,
    pub(super) rule: Rule,
    /// Boot-time filters hold from the TCP/IP driver's start until BFE has
    /// loaded the persistent ones; they cannot also be persistent.
    pub(super) boottime: bool,
    pub(super) part: Part,
}

impl LockdownFilter {
    fn placement(&self) -> Placement {
        Placement {
            provider: PROVIDER_KEY,
            sublayer: SUBLAYER_KEY,
            key: Some(GUID::from_u128(self.key)),
            flags: if self.boottime {
                FWPM_FILTER_FLAG_BOOTTIME
            } else {
                FWPM_FILTER_FLAG_PERSISTENT
            },
            name: self.name,
        }
    }
}

/// The filters Lockdown keeps for these settings.
pub(super) fn filter_set(allow_lan: bool, apps: &LockdownApps) -> Vec<LockdownFilter> {
    let filter = |key, name, rule, boottime, part| LockdownFilter {
        key,
        name,
        rule,
        boottime,
        part,
    };
    let block = |family| Rule::block(family, Vec::new(), BLOCK_WEIGHT);
    let loopback = |family| Rule::allow(family, vec![Condition::Loopback], BOOTSTRAP_ALLOW_WEIGHT);
    let dhcp = || {
        Rule::allow(
            AddressFamily::Ipv4,
            vec![Condition::DhcpV4],
            BOOTSTRAP_ALLOW_WEIGHT,
        )
    };

    let mut set = Vec::new();
    for (index, family) in FAMILIES.into_iter().enumerate() {
        set.extend([
            filter(
                keys::OUTBOUND_BLOCK[index],
                "Rosetun Lockdown: block outbound",
                block(family),
                false,
                Part::Base,
            ),
            filter(
                keys::OUTBOUND_LOOPBACK[index],
                "Rosetun Lockdown: permit loopback",
                loopback(family),
                false,
                Part::Base,
            ),
            filter(
                keys::INBOUND_BLOCK[index],
                "Rosetun Lockdown: block inbound",
                block(family).inbound(),
                false,
                Part::Base,
            ),
            filter(
                keys::INBOUND_LOOPBACK[index],
                "Rosetun Lockdown: permit loopback inbound",
                loopback(family).inbound(),
                false,
                Part::Base,
            ),
            filter(
                keys::BOOT_OUTBOUND_BLOCK[index],
                "Rosetun Lockdown at boot: block outbound",
                block(family),
                true,
                Part::Base,
            ),
            filter(
                keys::BOOT_INBOUND_BLOCK[index],
                "Rosetun Lockdown at boot: block inbound",
                block(family).inbound(),
                true,
                Part::Base,
            ),
            filter(
                keys::BOOT_OUTBOUND_LOOPBACK[index],
                "Rosetun Lockdown at boot: permit loopback",
                loopback(family),
                true,
                Part::Base,
            ),
            filter(
                keys::BOOT_INBOUND_LOOPBACK[index],
                "Rosetun Lockdown at boot: permit loopback inbound",
                loopback(family).inbound(),
                true,
                Part::Base,
            ),
        ]);
        for (keys, name, path) in [
            (
                keys::OUTBOUND_GUI,
                "Rosetun Lockdown: permit Rosetun",
                &apps.gui,
            ),
            (
                keys::OUTBOUND_CLI,
                "Rosetun Lockdown: permit the Rosetun CLI",
                &apps.cli,
            ),
        ] {
            if let Some(path) = path {
                set.push(filter(
                    keys[index],
                    name,
                    Rule::allow(
                        family,
                        vec![Condition::Application(path.clone())],
                        BOOTSTRAP_ALLOW_WEIGHT,
                    ),
                    false,
                    Part::App,
                ));
            }
        }
        for (keys, name, path, service) in [
            (
                keys::OUTBOUND_SERVICE_DNS,
                "Rosetun Lockdown: permit the Rosetun service's DNS queries",
                &apps.service,
                true,
            ),
            (
                keys::OUTBOUND_GUI_DNS,
                "Rosetun Lockdown: permit Rosetun's DNS queries",
                &apps.gui,
                false,
            ),
            (
                keys::OUTBOUND_CLI_DNS,
                "Rosetun Lockdown: permit the Rosetun CLI's DNS queries",
                &apps.cli,
                false,
            ),
        ] {
            if let Some(path) = path {
                for (key, protocol) in keys[index].into_iter().zip(DNS_PROTOCOLS) {
                    let mut conditions = vec![Condition::Application(path.clone())];
                    if service {
                        conditions.push(Condition::ServiceAccount);
                    }
                    conditions.extend([Condition::Protocol(protocol), Condition::RemotePort(53)]);
                    set.push(filter(
                        key,
                        name,
                        Rule::allow(family, conditions, RESOLVER_WEIGHT),
                        false,
                        Part::App,
                    ));
                }
            }
        }
    }

    // Without DHCP every boot under Lockdown lost the lease (study, run 3).
    // IPv6 has no DHCPv6 or neighbor discovery permit: all of it is blocked.
    set.extend([
        filter(
            keys::OUTBOUND_DHCP,
            "Rosetun Lockdown: permit DHCP",
            dhcp(),
            false,
            Part::Base,
        ),
        filter(
            keys::INBOUND_DHCP,
            "Rosetun Lockdown: permit DHCP replies",
            dhcp().inbound(),
            false,
            Part::Base,
        ),
        filter(
            keys::BOOT_OUTBOUND_DHCP,
            "Rosetun Lockdown at boot: permit DHCP",
            dhcp(),
            true,
            Part::Base,
        ),
        filter(
            keys::BOOT_INBOUND_DHCP,
            "Rosetun Lockdown at boot: permit DHCP replies",
            dhcp().inbound(),
            true,
            Part::Base,
        ),
    ]);

    if allow_lan {
        for (index, subnet) in LAN_SUBNETS.into_iter().enumerate() {
            set.push(filter(
                keys::OUTBOUND_LAN[index],
                "Rosetun Lockdown: permit the local network",
                lan_permit(subnet),
                false,
                Part::Lan,
            ));
            // The session's own LAN set has the same block; without it the
            // router's DNS would answer outside the tunnel while disconnected.
            for (key, rule) in keys::OUTBOUND_LAN_DNS[index]
                .into_iter()
                .zip(private_dns_blocks(subnet))
            {
                set.push(filter(
                    key,
                    "Rosetun Lockdown: block DNS to the local network",
                    rule,
                    false,
                    Part::Lan,
                ));
            }
            set.push(filter(
                keys::INBOUND_LAN[index],
                "Rosetun Lockdown: permit the local network inbound",
                lan_permit(subnet).inbound(),
                false,
                Part::Lan,
            ));
        }
    }
    set
}

/// Every filter any version of the set can hold, for removal.
pub(super) fn every_filter() -> Vec<LockdownFilter> {
    filter_set(
        true,
        &LockdownApps {
            gui: Some(PathBuf::new()),
            cli: Some(PathBuf::new()),
            service: Some(PathBuf::new()),
        },
    )
}

pub(in crate::platform) fn status() -> Result<LockdownStatus, RoutingError> {
    read_status(&Engine::standard()?)
}

fn read_status(engine: &Engine) -> Result<LockdownStatus, RoutingError> {
    let enabled = provider_exists(engine)?;
    let sublayer_weight = sublayer_weight(engine)?;
    let mut base_complete = true;
    let (mut lan_present, mut lan_total) = (0, 0);
    for filter in every_filter() {
        match filter.part {
            Part::Base => base_complete &= filter_exists(engine, filter.key)?,
            Part::Lan => {
                lan_total += 1;
                lan_present += usize::from(filter_exists(engine, filter.key)?);
            }
            Part::App => {}
        }
    }
    Ok(LockdownStatus {
        enabled,
        complete: enabled
            && sublayer_weight.is_some()
            && base_complete
            && (lan_present == 0 || lan_present == lan_total),
        allow_lan: lan_present > 0,
        sublayer_weight,
    })
}

pub(in crate::platform) fn enable(
    allow_lan: bool,
    apps: &LockdownApps,
) -> Result<LockdownStatus, RoutingError> {
    let wanted = filter_set(allow_lan, apps);
    let wanted_keys = wanted
        .iter()
        .map(|filter| filter.key)
        .collect::<HashSet<_>>();
    let engine = Engine::standard()?;
    let transaction = engine.transaction()?;

    if !provider_exists(&engine)? {
        add_provider(&engine)?;
    }
    if sublayer_weight(&engine)?.is_none() {
        add_sublayer(&engine)?;
    }
    for filter in every_filter() {
        if !wanted_keys.contains(&filter.key) {
            delete_filter(&engine, filter.key)?;
        }
    }
    let mut replaced = 0_usize;
    for filter in &wanted {
        // A filter from an older version (a permit without the service's
        // account) or for a program that moved is replaced under its key.
        // Any error aborts the transaction and leaves the old one: closed is
        // better than open.
        match stored_conditions_match(&engine, filter)? {
            Some(true) => continue,
            Some(false) => {
                delete_filter(&engine, filter.key)?;
                replaced += 1;
            }
            None => {}
        }
        filters::add_rule(&engine, &filter.rule, &filter.placement())?;
    }

    transaction.commit()?;
    if replaced > 0 {
        tracing::info!(replaced, "Lockdown filters replaced with their current form");
    }
    flush();
    read_status(&engine)
}

pub(in crate::platform) fn disable() -> Result<bool, RoutingError> {
    let engine = Engine::standard()?;
    let transaction = engine.transaction()?;
    let mut removed = false;

    // Filters first: a sublayer or provider still referenced cannot go.
    for filter in every_filter() {
        removed |= delete_filter(&engine, filter.key)?;
    }
    let status = unsafe { FwpmSubLayerDeleteByKey0(engine.handle(), &SUBLAYER_KEY) };
    if status as i32 == FWP_E_IN_USE {
        return Err(wfp_error(
            status,
            "removing the Lockdown sublayer while a Rosetun session still has filters in it",
        ));
    }
    removed |= found(
        status,
        FWP_E_SUBLAYER_NOT_FOUND,
        "removing the Lockdown sublayer",
    )?;
    let status = unsafe { FwpmProviderDeleteByKey0(engine.handle(), &PROVIDER_KEY) };
    removed |= found(
        status,
        FWP_E_PROVIDER_NOT_FOUND,
        "removing the Lockdown provider",
    )?;

    transaction.commit()?;
    flush();
    Ok(removed)
}

/// Permits programs in the Lockdown sublayer from a dynamic session of their
/// own, for server checks while no protection session is running.
pub(in crate::platform) fn permit_programs(
    binaries: &[&Path],
) -> Result<RoutingGuard, RoutingError> {
    let engine = Engine::dynamic()?;
    let transaction = engine.transaction()?;
    let name = wide("Rosetun Lockdown server check");
    let provider = FWPM_PROVIDER0 {
        providerKey: PROBE_PROVIDER_KEY,
        displayData: display_data(&name, &name),
        flags: 0,
        providerData: empty_blob(),
        serviceName: ptr::null_mut(),
    };
    let status = unsafe { FwpmProviderAdd0(engine.handle(), &provider, ptr::null_mut()) };
    if status != 0 {
        return Err(wfp_error(
            status,
            "adding the Lockdown server check provider",
        ));
    }
    for binary in binaries {
        for rule in probe_authorization(binary) {
            filters::add_rule(&engine, &rule, &LockdownPermit::PLACEMENT)?;
        }
    }
    transaction.commit()?;
    Ok(RoutingGuard::from_session(LockdownPermit {
        engine: Some(engine),
        extra: None,
    }))
}

/// The guard of `permit_programs`. Its permits disappear with the handle.
#[derive(Debug)]
struct LockdownPermit {
    engine: Option<Engine>,
    /// A program permitted later (Xray), with its filter IDs.
    extra: Option<(PathBuf, Vec<u64>)>,
}

impl LockdownPermit {
    const PLACEMENT: Placement = Placement {
        provider: PROBE_PROVIDER_KEY,
        sublayer: SUBLAYER_KEY,
        key: None,
        flags: 0,
        name: "Rosetun Lockdown: server check",
    };

    fn engine(&self) -> Result<&Engine, RoutingError> {
        self.engine
            .as_ref()
            .ok_or_else(|| RoutingError::Route("the server check permit is gone".to_owned()))
    }
}

/// As for `WfpProtectionSession`: the handle moves with the guard, never shared.
unsafe impl Send for LockdownPermit {}

impl ProtectionSession for LockdownPermit {
    fn prepare_reconnect(
        &mut self,
        _plan: &RoutingPlan,
        _engine_binaries: &[&Path],
    ) -> Result<(), RoutingError> {
        Err(RoutingError::Unsupported)
    }

    fn authorize_tunnel(&mut self, _tunnel: &TunnelInterface) -> Result<(), RoutingError> {
        Err(RoutingError::Unsupported)
    }

    fn permit_probe_binary(&mut self, binary: &Path) -> Result<(), RoutingError> {
        if self.extra.is_some() {
            return Err(RoutingError::Route(
                "another probe application is authorized".into(),
            ));
        }
        let engine = self.engine()?;
        let transaction = engine.transaction()?;
        let ids = probe_authorization(binary)
            .iter()
            .map(|rule| filters::add_rule(engine, rule, &Self::PLACEMENT))
            .collect::<Result<Vec<_>, _>>()?;
        transaction.commit()?;
        self.extra = Some((binary.to_owned(), ids));
        Ok(())
    }

    fn remove_probe_binary(&mut self, binary: &Path) -> Result<(), RoutingError> {
        let Some((_, ids)) = self.extra.as_ref().filter(|(path, _)| path == binary) else {
            return Ok(());
        };
        let engine = self.engine()?;
        let transaction = engine.transaction()?;
        for &id in ids {
            filters::delete_rule(engine, id)?;
        }
        transaction.commit()?;
        self.extra = None;
        Ok(())
    }

    fn set_lockdown(&mut self, _lockdown: bool) -> Result<(), RoutingError> {
        Err(RoutingError::Unsupported)
    }

    fn teardown(&mut self) -> Result<(), RoutingError> {
        self.engine.take();
        self.extra = None;
        Ok(())
    }
}

fn add_provider(engine: &Engine) -> Result<(), RoutingError> {
    let name = wide("Rosetun Lockdown");
    let description = wide("Keeps the computer offline outside the Rosetun tunnel");
    // No service name: BFE then loads the objects at every start, whatever
    // the start type of any service.
    let provider = FWPM_PROVIDER0 {
        providerKey: PROVIDER_KEY,
        displayData: display_data(&name, &description),
        flags: FWPM_PROVIDER_FLAG_PERSISTENT,
        providerData: empty_blob(),
        serviceName: ptr::null_mut(),
    };
    let status = unsafe { FwpmProviderAdd0(engine.handle(), &provider, ptr::null_mut()) };
    if status != 0 {
        return Err(wfp_error(status, "adding the Lockdown provider"));
    }
    Ok(())
}

fn add_sublayer(engine: &Engine) -> Result<(), RoutingError> {
    let name = wide("Rosetun Lockdown");
    let description = wide("Rosetun Lockdown block and the session's permits above it");
    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: SUBLAYER_KEY,
        displayData: display_data(&name, &description),
        flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
        providerKey: (&PROVIDER_KEY as *const GUID).cast_mut(),
        providerData: empty_blob(),
        weight: REQUESTED_SUBLAYER_WEIGHT,
    };
    let status = unsafe { FwpmSubLayerAdd0(engine.handle(), &sublayer, ptr::null_mut()) };
    if status != 0 {
        return Err(wfp_error(status, "adding the Lockdown sublayer"));
    }
    Ok(())
}

fn provider_exists(engine: &Engine) -> Result<bool, RoutingError> {
    let mut provider: *mut FWPM_PROVIDER0 = ptr::null_mut();
    // SAFETY: on success BFE allocates the result, freed at once.
    let status = unsafe { FwpmProviderGetByKey0(engine.handle(), &PROVIDER_KEY, &mut provider) };
    let present = found(
        status,
        FWP_E_PROVIDER_NOT_FOUND,
        "reading the Lockdown provider",
    )?;
    free(provider);
    Ok(present)
}

fn sublayer_weight(engine: &Engine) -> Result<Option<u16>, RoutingError> {
    let mut sublayer: *mut FWPM_SUBLAYER0 = ptr::null_mut();
    // SAFETY: as in `provider_exists`; the weight is copied out before the free.
    let status = unsafe { FwpmSubLayerGetByKey0(engine.handle(), &SUBLAYER_KEY, &mut sublayer) };
    if !found(
        status,
        FWP_E_SUBLAYER_NOT_FOUND,
        "reading the Lockdown sublayer",
    )? {
        return Ok(None);
    }
    let weight = unsafe { (*sublayer).weight };
    free(sublayer);
    Ok(Some(weight))
}

fn filter_exists(engine: &Engine, key: u128) -> Result<bool, RoutingError> {
    let key = GUID::from_u128(key);
    let mut filter: *mut FWPM_FILTER0 = ptr::null_mut();
    // SAFETY: as in `provider_exists`.
    let status = unsafe { FwpmFilterGetByKey0(engine.handle(), &key, &mut filter) };
    let present = found(status, FWP_E_FILTER_NOT_FOUND, "reading a Lockdown filter")?;
    free(filter);
    Ok(present)
}

/// Whether the stored filter under `filter.key` has the conditions `filter`
/// wants now; `None` when there is no such filter.
fn stored_conditions_match(
    engine: &Engine,
    filter: &LockdownFilter,
) -> Result<Option<bool>, RoutingError> {
    let wanted = FilterConditions::build(&filter.rule)?;
    let key = GUID::from_u128(filter.key);
    let mut stored: *mut FWPM_FILTER0 = ptr::null_mut();
    // SAFETY: on success BFE allocates the filter with its conditions and
    // their values in one block, read here and freed below.
    let status = unsafe { FwpmFilterGetByKey0(engine.handle(), &key, &mut stored) };
    if !found(status, FWP_E_FILTER_NOT_FOUND, "reading a Lockdown filter")? {
        return Ok(None);
    }
    // SAFETY: `stored` is the live result above; its condition array holds
    // `numFilterConditions` entries whose values stay valid until the free.
    let same = unsafe {
        let stored = &*stored;
        let conditions = if stored.filterCondition.is_null() {
            &[][..]
        } else {
            std::slice::from_raw_parts(stored.filterCondition, stored.numFilterConditions as usize)
        };
        wanted.same_as(conditions)
    };
    free(stored);
    Ok(Some(same))
}

/// Deletes a filter by key; `Ok(false)` when it was not there.
fn delete_filter(engine: &Engine, key: u128) -> Result<bool, RoutingError> {
    let key = GUID::from_u128(key);
    let status = unsafe { FwpmFilterDeleteByKey0(engine.handle(), &key) };
    found(status, FWP_E_FILTER_NOT_FOUND, "removing a Lockdown filter")
}

/// `Ok(true)` when the object was there, `Ok(false)` for `not_found`.
fn found(status: u32, not_found: i32, context: &'static str) -> Result<bool, RoutingError> {
    match status {
        0 => Ok(true),
        _ if status as i32 == not_found => Ok(false),
        _ => Err(wfp_error(status, context)),
    }
}

fn free<T>(mut object: *mut T) {
    if !object.is_null() {
        // SAFETY: `object` came from a successful Fwpm*GetByKey0 call and is
        // not used afterwards.
        unsafe { FwpmFreeMemory0((&raw mut object).cast()) };
    }
}

/// BFE keeps persistent policy under
/// `HKLM\SYSTEM\CurrentControlSet\Services\BFE\Parameters\Policy` and leaves
/// writing it to the registry's lazy flush: a power cut even 60 s after a
/// change lost it (study, run 4). Flushing the SYSTEM hive writes it at once.
/// A failure only warns: the change itself is in place.
fn flush() {
    let path = wide("SYSTEM");
    let mut key = ptr::null_mut();
    // SAFETY: `path` is NUL-terminated and outlives the call; the key is
    // closed below.
    let status = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ, &mut key) };
    if status != 0 {
        tracing::warn!(
            code = status,
            "could not open the SYSTEM hive to flush Lockdown; a power cut soon may undo the change"
        );
        return;
    }
    // SAFETY: the key is open; RegFlushKey only reads the handle.
    let status = unsafe { RegFlushKey(key) };
    // SAFETY: the key came from RegOpenKeyExW and is closed once.
    unsafe { RegCloseKey(key) };
    if status != 0 {
        tracing::warn!(
            code = status,
            "could not flush Lockdown to disk; a power cut soon may undo the change"
        );
    } else {
        tracing::debug!("Lockdown change flushed to disk");
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::path::PathBuf;

    use windows_sys::core::GUID;

    use super::{BLOCK_WEIGHT, LockdownFilter, Part, RESOLVER_WEIGHT, every_filter, filter_set};
    use crate::platform::windows::policy::{
        self, Action, AddressFamily, BOOTSTRAP_ALLOW_WEIGHT, BootstrapPolicy, Condition, Layer,
        PRIVATE_DNS_BLOCK_WEIGHT, Rule, TUNNEL_WEIGHT,
        tests::{Process, decide_at, decide_for},
    };
    use crate::{LockdownApps, ProtectionScope, RoutingPlan};

    fn apps() -> LockdownApps {
        LockdownApps {
            gui: Some(PathBuf::from(r"C:\Program Files\Rosetun\rosetun-gui.exe")),
            cli: Some(PathBuf::from(r"C:\Program Files\Rosetun\rosetun.exe")),
            service: Some(PathBuf::from(
                r"C:\Program Files\Rosetun\rosetun-helper-privileged.exe",
            )),
        }
    }

    fn persistent(set: &[LockdownFilter]) -> Vec<&Rule> {
        set.iter()
            .filter(|filter| !filter.boottime)
            .map(|filter| &filter.rule)
            .collect()
    }

    #[test]
    fn every_filter_has_its_own_key_distinct_from_the_objects() {
        let all = every_filter();
        let keys = all.iter().map(|filter| filter.key).collect::<HashSet<_>>();
        assert_eq!(keys.len(), all.len());
        assert_eq!(all.len(), 60);
        for object in [
            super::PROVIDER_KEY,
            super::SUBLAYER_KEY,
            super::PROBE_PROVIDER_KEY,
        ] {
            let object = (object.data1, object.data2, object.data3, object.data4);
            assert!(all.iter().all(|filter| {
                let key = GUID::from_u128(filter.key);
                (key.data1, key.data2, key.data3, key.data4) != object
            }));
        }
        // Keys depend on the role only, never on the settings.
        for filter in filter_set(false, &LockdownApps::default()) {
            assert!(all.contains(&filter));
        }
    }

    #[test]
    fn base_set_blocks_both_directions_and_permits_only_loopback_and_dhcp() {
        let set = filter_set(false, &LockdownApps::default());
        assert!(set.iter().all(|filter| filter.part == Part::Base));
        assert_eq!(set.len(), 20);
        for boottime in [false, true] {
            for layer in [Layer::Connect, Layer::RecvAccept] {
                let rules = set
                    .iter()
                    .filter(|filter| filter.boottime == boottime && filter.rule.layer == layer)
                    .map(|filter| &filter.rule)
                    .collect::<Vec<_>>();
                assert_eq!(rules.len(), 5);
                for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
                    assert!(rules.iter().any(|rule| rule.family == family
                        && rule.action == Action::Block
                        && rule.conditions.is_empty()
                        && rule.weight == BLOCK_WEIGHT));
                    assert!(rules.iter().any(|rule| rule.family == family
                        && rule.action == Action::Allow
                        && rule.conditions == [Condition::Loopback]));
                }
                assert!(rules.iter().any(|rule| rule.family == AddressFamily::Ipv4
                    && rule.conditions == [Condition::DhcpV4]));
                assert!(
                    rules
                        .iter()
                        .filter(|rule| rule.action == Action::Allow)
                        .all(|rule| rule.weight > BLOCK_WEIGHT)
                );
            }
        }
    }

    #[test]
    fn programs_are_permitted_outbound_only_and_never_at_boot() {
        let set = filter_set(false, &apps());
        let programs = set
            .iter()
            .filter(|filter| filter.part == Part::App)
            .collect::<Vec<_>>();
        assert_eq!(programs.len(), 16);
        for filter in programs {
            assert!(!filter.boottime);
            assert_eq!(filter.rule.layer, Layer::Connect);
            assert_eq!(filter.rule.action, Action::Allow);
            assert!(matches!(
                filter.rule.conditions.first(),
                Some(Condition::Application(_))
            ));
        }
        let only_cli = filter_set(
            false,
            &LockdownApps {
                gui: None,
                ..apps()
            },
        );
        // The CLI's two permits and four DNS permits, the service's four.
        assert_eq!(
            only_cli
                .iter()
                .filter(|filter| filter.part == Part::App)
                .count(),
            10
        );
    }

    #[test]
    fn rosetun_resolves_through_the_local_network_but_nothing_else_does() {
        fn process(path: &Option<PathBuf>, service_account: bool) -> Option<Process<'_>> {
            Some(Process {
                path: path.as_deref().expect("every program is installed"),
                service_account,
            })
        }
        const { assert!(RESOLVER_WEIGHT > PRIVATE_DNS_BLOCK_WEIGHT && RESOLVER_WEIGHT != TUNNEL_WEIGHT) };
        let apps = apps();
        let service = process(&apps.service, true);
        let service_by_user = process(&apps.service, false);
        let gui = process(&apps.gui, false);
        let other = Some(Process {
            path: std::path::Path::new(r"C:\Windows\System32\svchost.exe"),
            service_account: true,
        });
        for allow_lan in [false, true] {
            let set = filter_set(allow_lan, &apps);
            let rules = persistent(&set);
            let decide = |application, destination, protocol, port| {
                decide_for(
                    application,
                    Layer::Connect,
                    &rules,
                    destination,
                    protocol,
                    port,
                    0,
                )
            };
            for protocol in [17, 6] {
                for destination in [[192, 168, 3, 1], [203, 0, 113, 53]] {
                    assert_eq!(decide(service, destination, protocol, 53), Action::Allow);
                    assert_eq!(decide(gui, destination, protocol, 53), Action::Allow);
                    assert_eq!(decide(other, destination, protocol, 53), Action::Block);
                    assert_eq!(
                        decide(service_by_user, destination, protocol, 53),
                        Action::Block
                    );
                }
            }
            // The service gets DNS only; the GUI keeps its permit for everything.
            assert_eq!(decide(service, [203, 0, 113, 7], 6, 443), Action::Block);
            assert_eq!(decide(gui, [203, 0, 113, 7], 6, 443), Action::Allow);
        }
        assert!(
            filter_set(true, &apps)
                .iter()
                .filter(|filter| filter.rule.weight == RESOLVER_WEIGHT)
                .all(|filter| filter.part == Part::App
                    && !filter.boottime
                    && filter.rule.action == Action::Allow
                    && filter.rule.conditions.contains(&Condition::RemotePort(53)))
        );
    }

    #[test]
    fn lan_set_permits_private_ranges_both_ways_but_blocks_their_dns() {
        let set = filter_set(true, &LockdownApps::default());
        let lan = set
            .iter()
            .filter(|filter| filter.part == Part::Lan)
            .collect::<Vec<_>>();
        assert_eq!(lan.len(), 24);
        assert!(lan.iter().all(|filter| !filter.boottime));
        let rules = persistent(&set);
        for protocol in [17, 6] {
            assert_eq!(
                decide_at(Layer::Connect, &rules, [192, 168, 3, 1], protocol, 53, 0),
                Action::Block
            );
        }
        assert_eq!(
            decide_at(Layer::Connect, &rules, [192, 168, 3, 1], 6, 80, 0),
            Action::Allow
        );
        assert_eq!(
            decide_at(Layer::RecvAccept, &rules, [192, 168, 3, 1], 6, 8080, 0),
            Action::Allow
        );
        assert_eq!(
            decide_at(Layer::Connect, &rules, [203, 0, 113, 7], 6, 443, 0),
            Action::Block
        );
        assert_eq!(
            decide_at(Layer::RecvAccept, &rules, [203, 0, 113, 7], 6, 8080, 0),
            Action::Block
        );

        let closed = filter_set(false, &LockdownApps::default());
        let rules = persistent(&closed);
        assert_eq!(
            decide_at(Layer::Connect, &rules, [192, 168, 3, 1], 6, 80, 0),
            Action::Block
        );
        assert_eq!(
            decide_at(Layer::RecvAccept, &rules, [192, 168, 3, 1], 6, 8080, 0),
            Action::Block
        );
    }

    #[test]
    fn session_rules_in_the_lockdown_sublayer_open_the_tunnel_only() {
        let plan = RoutingPlan {
            scope: ProtectionScope::AllTraffic,
            allow_lan: true,
            lockdown: true,
        };
        let session =
            BootstrapPolicy::from_plan(&plan, &[std::path::Path::new(r"C:\sing-box.exe")]);
        let tunnel = policy::tunnel_authorization(123, true);
        let set = filter_set(true, &LockdownApps::default());
        let rules = persistent(&set)
            .into_iter()
            .chain(&session.rules)
            .chain(&tunnel)
            .collect::<Vec<_>>();

        // The tunnel's own DNS address sits in 172.16/12; its permit must
        // outrank the persistent private DNS block too.
        for layer in [Layer::Connect, Layer::RecvAccept] {
            assert_eq!(
                decide_at(layer, &rules, [172, 19, 0, 2], 17, 53, 123),
                Action::Allow
            );
            assert_eq!(
                decide_at(layer, &rules, [203, 0, 113, 7], 6, 443, 999),
                Action::Block
            );
        }
        assert_eq!(
            decide_at(Layer::Connect, &rules, [172, 19, 0, 2], 17, 53, 999),
            Action::Block
        );
        let lockdown_block = set
            .iter()
            .find(|filter| filter.rule.conditions.is_empty())
            .expect("block-all");
        assert!(
            session
                .rules
                .iter()
                .chain(&tunnel)
                .all(|rule| rule.weight > lockdown_block.rule.weight)
        );
        assert!(
            set.iter()
                .filter(|filter| filter.rule.action == Action::Allow)
                .all(|filter| filter.rule.weight == BOOTSTRAP_ALLOW_WEIGHT)
        );
        // Rosetun's resolver permits outrank the private DNS block for its
        // own programs only: anything else still cannot reach the tunnel's
        // DNS address outside the tunnel.
        let with_apps = filter_set(true, &apps());
        let rules = persistent(&with_apps)
            .into_iter()
            .chain(&session.rules)
            .chain(&tunnel)
            .collect::<Vec<_>>();
        assert_eq!(
            decide_at(Layer::Connect, &rules, [172, 19, 0, 2], 17, 53, 999),
            Action::Block
        );
    }
}
