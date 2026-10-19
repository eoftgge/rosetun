//! WFP probe for Lockdown sublayer arbitration, run by hand in the test VM
//! (`tools/vm/Invoke-LockdownProbe.ps1`). Not part of the product: the
//! installer and `release.yml` never build examples.
//!
//! `persistent install [--boottime]`  persistent block-all in its own sublayer
//! `persistent remove`                deletes everything `install` added
//! `persistent status`                which of those objects exist now
//! `permit --program <path> [--hard] [--sublayer-weight <u16>] [--lockdown-sublayer]`
//!                                    dynamic permit for one program, held until
//!                                    Enter or until the process dies

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    probe::main()
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("lockdown_probe runs on Windows only");
    std::process::ExitCode::from(2)
}

#[cfg(windows)]
mod probe {
    use std::io::{BufRead, Write};
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;
    use std::ptr;

    use windows_sys::Win32::Foundation::{
        FWP_E_ALREADY_EXISTS, FWP_E_FILTER_NOT_FOUND, FWP_E_IN_USE, FWP_E_PROVIDER_NOT_FOUND,
        FWP_E_SUBLAYER_NOT_FOUND, HANDLE,
    };
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE,
        FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_UINT8, FWP_VALUE0,
        FWP_VALUE0_0, FWPM_ACTION0, FWPM_CONDITION_ALE_APP_ID, FWPM_DISPLAY_DATA0,
        FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_BOOTTIME, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
        FWPM_FILTER_FLAG_PERSISTENT, FWPM_FILTER0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_PROVIDER0,
        FWPM_SESSION_FLAG_DYNAMIC, FWPM_SESSION0, FWPM_SUBLAYER_FLAG_PERSISTENT, FWPM_SUBLAYER0,
        FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteByKey0,
        FwpmFilterGetByKey0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0, FwpmProviderAdd0,
        FwpmProviderDeleteByKey0, FwpmProviderGetByKey0, FwpmSubLayerAdd0,
        FwpmSubLayerDeleteByKey0, FwpmSubLayerGetByKey0, FwpmTransactionAbort0,
        FwpmTransactionBegin0, FwpmTransactionCommit0,
    };
    use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
    use windows_sys::core::GUID;

    // New keys, unrelated to the product's dynamic PROVIDER_KEY and
    // SUBLAYER_KEY, so the probe never collides with a running service.
    const LOCKDOWN_PROVIDER: GUID = GUID::from_u128(0x681cc7b8_4f59_4eac_8c10_06bf2aa25d17);
    const LOCKDOWN_SUBLAYER: GUID = GUID::from_u128(0x27e67ac2_a27c_4b1e_88e0_0dc1ff9240de);
    const PERMIT_PROVIDER: GUID = GUID::from_u128(0x1ddf6dff_5a79_4f1a_a453_a39aba5c23fe);
    const PERMIT_SUBLAYER: GUID = GUID::from_u128(0x21b7a48e_d989_467e_b62a_dd52217bc5e7);

    /// Below the product's dynamic sublayer (0x8000), so the default permit
    /// weight sits above it and `--sublayer-weight 0x2000` below it.
    const LOCKDOWN_SUBLAYER_WEIGHT: u16 = 0x4000;
    const DEFAULT_PERMIT_SUBLAYER_WEIGHT: u16 = 0x8000;
    /// Filter weights are range indexes 0-15 (`FWP_UINT8`). The block-all sits
    /// at the bottom so a permit added to the Lockdown sublayer itself outranks it.
    const BLOCK_FILTER_WEIGHT: u8 = 0;
    const PERMIT_FILTER_WEIGHT: u8 = 15;

    #[derive(Debug, Clone, Copy, PartialEq)]
    enum Family {
        V4,
        V6,
    }

    #[derive(Debug, Clone, Copy)]
    struct BlockFilter {
        key: u128,
        family: Family,
        flag: u32,
        name: &'static str,
    }

    // A boot-time filter cannot also be persistent (FWPM_FILTER0 docs), so the
    // boot-time set is a second set of filters with keys of its own.
    const PERSISTENT_FILTERS: [BlockFilter; 2] = [
        BlockFilter {
            key: 0xf12f7bc5_cc5b_4432_8dec_d678b70f3708,
            family: Family::V4,
            flag: FWPM_FILTER_FLAG_PERSISTENT,
            name: "Rosetun Lockdown probe: block outbound IPv4 (persistent)",
        },
        BlockFilter {
            key: 0x4554c0dc_2be8_4912_a02d_ae76e73d8dec,
            family: Family::V6,
            flag: FWPM_FILTER_FLAG_PERSISTENT,
            name: "Rosetun Lockdown probe: block outbound IPv6 (persistent)",
        },
    ];
    const BOOTTIME_FILTERS: [BlockFilter; 2] = [
        BlockFilter {
            key: 0x3954e531_401b_4c4e_830a_bb4158168d8f,
            family: Family::V4,
            flag: FWPM_FILTER_FLAG_BOOTTIME,
            name: "Rosetun Lockdown probe: block outbound IPv4 (boot-time)",
        },
        BlockFilter {
            key: 0x5f2a0042_d90a_4fcb_b88a_6fde2eb728e8,
            family: Family::V6,
            flag: FWPM_FILTER_FLAG_BOOTTIME,
            name: "Rosetun Lockdown probe: block outbound IPv6 (boot-time)",
        },
    ];

    type Result<T> = std::result::Result<T, String>;

    pub(super) fn main() -> ExitCode {
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        let args = args.iter().map(String::as_str).collect::<Vec<_>>();
        let result = match args.as_slice() {
            ["persistent", "install"] => install(false),
            ["persistent", "install", "--boottime"] => install(true),
            ["persistent", "remove"] => remove(),
            ["persistent", "status"] => status(),
            ["permit", rest @ ..] => {
                PermitOptions::parse(rest).and_then(|options| permit(&options))
            }
            _ => Err(usage()),
        };
        match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::FAILURE
            }
        }
    }

    fn usage() -> String {
        "usage: lockdown_probe persistent install [--boottime] | persistent remove | \
         persistent status | permit --program <path> [--hard] [--sublayer-weight <u16>] \
         [--lockdown-sublayer]"
            .to_owned()
    }

    /// An open BFE engine handle. A dynamic one deletes every object it added
    /// when it closes, which is what `permit` relies on; a standard one leaves
    /// persistent objects behind on purpose.
    #[derive(Debug)]
    struct Engine {
        handle: HANDLE,
    }

    impl Engine {
        fn open(dynamic: bool) -> Result<Self> {
            let session = FWPM_SESSION0 {
                flags: if dynamic {
                    FWPM_SESSION_FLAG_DYNAMIC
                } else {
                    0
                },
                ..Default::default()
            };
            let mut handle = ptr::null_mut();
            // SAFETY: `session` and `handle` outlive the call; BFE copies the
            // session description. RPC_C_AUTHN_WINNT as in the product (WINDOWS.md).
            let status = unsafe {
                FwpmEngineOpen0(
                    ptr::null(),
                    RPC_C_AUTHN_WINNT,
                    ptr::null(),
                    &session,
                    &mut handle,
                )
            };
            check(status, "opening the WFP engine (run elevated)")?;
            Ok(Self { handle })
        }

        /// Runs `body` in one transaction: committed when it succeeds, aborted
        /// otherwise, so a failed install or remove changes nothing.
        fn transaction<T>(&self, body: impl FnOnce(&Self) -> Result<T>) -> Result<T> {
            // SAFETY: the handle is open for the lifetime of `self`.
            check(
                unsafe { FwpmTransactionBegin0(self.handle, 0) },
                "starting a transaction",
            )?;
            match body(self) {
                Ok(value) => {
                    // SAFETY: as above; a transaction is in progress.
                    check(
                        unsafe { FwpmTransactionCommit0(self.handle) },
                        "committing the transaction",
                    )?;
                    Ok(value)
                }
                Err(error) => {
                    // SAFETY: as above; aborting cannot leave partial objects.
                    let status = unsafe { FwpmTransactionAbort0(self.handle) };
                    if status != 0 {
                        eprintln!("warning: aborting the transaction failed: {status:#010x}");
                    }
                    Err(error)
                }
            }
        }
    }

    impl Drop for Engine {
        fn drop(&mut self) {
            // SAFETY: the handle came from FwpmEngineOpen0 and is closed once.
            let status = unsafe { FwpmEngineClose0(self.handle) };
            if status != 0 {
                eprintln!("warning: closing the WFP engine failed: {status:#010x}");
            }
        }
    }

    /// A NUL-terminated UTF-16 copy. WFP reads display strings during the add
    /// call only, so it must outlive the call and nothing more.
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    fn display_data(name: &mut [u16]) -> FWPM_DISPLAY_DATA0 {
        FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: ptr::null_mut(),
        }
    }

    fn install(boottime: bool) -> Result<()> {
        let engine = Engine::open(false)?;
        let mut name = wide("Rosetun Lockdown probe");
        engine
            .transaction(|engine| {
                // No service name: BFE then loads the persistent objects at
                // every start, whatever the start type of any service.
                let provider = FWPM_PROVIDER0 {
                    providerKey: LOCKDOWN_PROVIDER,
                    displayData: display_data(&mut name),
                    flags: FWPM_PROVIDER_FLAG_PERSISTENT,
                    ..Default::default()
                };
                // SAFETY: `provider` and the name it points to live across the call.
                let status = unsafe { FwpmProviderAdd0(engine.handle, &provider, ptr::null_mut()) };
                check(status, "adding the Lockdown provider")?;

                let sublayer = FWPM_SUBLAYER0 {
                    subLayerKey: LOCKDOWN_SUBLAYER,
                    displayData: display_data(&mut name),
                    flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
                    providerKey: (&LOCKDOWN_PROVIDER as *const GUID).cast_mut(),
                    weight: LOCKDOWN_SUBLAYER_WEIGHT,
                    ..Default::default()
                };
                // SAFETY: as above; the provider key is a static.
                let status = unsafe { FwpmSubLayerAdd0(engine.handle, &sublayer, ptr::null_mut()) };
                check(status, "adding the Lockdown sublayer")?;

                let boottime_filters: &[BlockFilter] =
                    if boottime { &BOOTTIME_FILTERS } else { &[] };
                for filter in PERSISTENT_FILTERS.iter().chain(boottime_filters) {
                    add_block_filter(engine, filter)?;
                }
                Ok(())
            })
            .map_err(|error| {
                if error.contains("FWP_E_ALREADY_EXISTS") {
                    format!("{error}; run `persistent remove` first")
                } else {
                    error
                }
            })?;
        println!(
            "installed: provider, sublayer (weight {LOCKDOWN_SUBLAYER_WEIGHT:#06x}), {} filters",
            if boottime { 4 } else { 2 }
        );
        Ok(())
    }

    fn add_block_filter(engine: &Engine, block: &BlockFilter) -> Result<()> {
        let mut name = wide(block.name);
        let filter = FWPM_FILTER0 {
            filterKey: GUID::from_u128(block.key),
            displayData: display_data(&mut name),
            flags: block.flag,
            providerKey: (&LOCKDOWN_PROVIDER as *const GUID).cast_mut(),
            layerKey: layer_key(block.family),
            subLayerKey: LOCKDOWN_SUBLAYER,
            weight: weight(BLOCK_FILTER_WEIGHT),
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_BLOCK,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut id = 0;
        // SAFETY: `filter` and the name it points to live across the call; it
        // has no conditions, so no other pointers.
        let status = unsafe { FwpmFilterAdd0(engine.handle, &filter, ptr::null_mut(), &mut id) };
        check(status, block.name)
    }

    fn remove() -> Result<()> {
        let engine = Engine::open(false)?;
        let removed = engine.transaction(|engine| {
            let mut removed = Vec::new();
            // Filters first: a sublayer or provider still referenced cannot go.
            for filter in PERSISTENT_FILTERS.iter().chain(&BOOTTIME_FILTERS) {
                let key = GUID::from_u128(filter.key);
                // SAFETY: `key` outlives the call; the handle is open.
                let status = unsafe { FwpmFilterDeleteByKey0(engine.handle, &key) };
                if found(status, FWP_E_FILTER_NOT_FOUND, filter.name)? {
                    removed.push(filter.name);
                }
            }
            // SAFETY: as above.
            let status = unsafe { FwpmSubLayerDeleteByKey0(engine.handle, &LOCKDOWN_SUBLAYER) };
            if status as i32 == FWP_E_IN_USE {
                return Err(format!(
                    "the Lockdown sublayer is in use ({}); stop any `permit --lockdown-sublayer` first",
                    code_name(status)
                ));
            }
            if found(status, FWP_E_SUBLAYER_NOT_FOUND, "deleting the sublayer")? {
                removed.push("sublayer");
            }
            // SAFETY: as above.
            let status = unsafe { FwpmProviderDeleteByKey0(engine.handle, &LOCKDOWN_PROVIDER) };
            if found(status, FWP_E_PROVIDER_NOT_FOUND, "deleting the provider")? {
                removed.push("provider");
            }
            Ok(removed)
        })?;
        if removed.is_empty() {
            println!("removed: nothing, no Lockdown probe objects were present");
        } else {
            println!("removed: {}", removed.join("; "));
        }
        Ok(())
    }

    fn status() -> Result<()> {
        let engine = Engine::open(false)?;

        let mut provider: *mut FWPM_PROVIDER0 = ptr::null_mut();
        // SAFETY: on success BFE allocates the result, freed below with FwpmFreeMemory0.
        let code =
            unsafe { FwpmProviderGetByKey0(engine.handle, &LOCKDOWN_PROVIDER, &mut provider) };
        let provider_present = found(code, FWP_E_PROVIDER_NOT_FOUND, "reading the provider")?;
        if provider_present {
            // SAFETY: non-null after success; read before it is freed.
            let flags = unsafe { (*provider).flags };
            println!("provider present flags={flags:#x}");
            free(provider);
        } else {
            println!("provider absent");
        }

        let mut sublayer: *mut FWPM_SUBLAYER0 = ptr::null_mut();
        // SAFETY: as above.
        let code =
            unsafe { FwpmSubLayerGetByKey0(engine.handle, &LOCKDOWN_SUBLAYER, &mut sublayer) };
        let sublayer_present = found(code, FWP_E_SUBLAYER_NOT_FOUND, "reading the sublayer")?;
        if sublayer_present {
            // SAFETY: as above.
            let (flags, weight) = unsafe { ((*sublayer).flags, (*sublayer).weight) };
            println!("sublayer present flags={flags:#x} weight={weight:#06x}");
            free(sublayer);
        } else {
            println!("sublayer absent");
        }

        let persistent = filter_status(&engine, &PERSISTENT_FILTERS)?;
        let boottime = filter_status(&engine, &BOOTTIME_FILTERS)?;
        println!(
            "summary: provider={} sublayer={} persistent_filters={persistent}/2 boottime_filters={boottime}/2",
            presence(provider_present),
            presence(sublayer_present),
        );
        Ok(())
    }

    fn filter_status(engine: &Engine, filters: &[BlockFilter]) -> Result<usize> {
        let mut present = 0;
        for block in filters {
            let key = GUID::from_u128(block.key);
            let mut filter: *mut FWPM_FILTER0 = ptr::null_mut();
            // SAFETY: as in `status`.
            let code = unsafe { FwpmFilterGetByKey0(engine.handle, &key, &mut filter) };
            if !found(code, FWP_E_FILTER_NOT_FOUND, block.name)? {
                println!("filter absent  {}", block.name);
                continue;
            }
            // SAFETY: non-null after success; only plain fields are copied out.
            let (flags, action, layer, sublayer) = unsafe {
                (
                    (*filter).flags,
                    (*filter).action.r#type,
                    (*filter).layerKey,
                    (*filter).subLayerKey,
                )
            };
            free(filter);
            present += 1;
            println!(
                "filter present {} flags={flags:#x}{} action={} layer={} sublayer={}",
                block.name,
                describe_flags(flags),
                if action == FWP_ACTION_BLOCK {
                    "block"
                } else {
                    "other"
                },
                if same(&layer, &FWPM_LAYER_ALE_AUTH_CONNECT_V4) {
                    "ALE_AUTH_CONNECT_V4"
                } else if same(&layer, &FWPM_LAYER_ALE_AUTH_CONNECT_V6) {
                    "ALE_AUTH_CONNECT_V6"
                } else {
                    "other"
                },
                if same(&sublayer, &LOCKDOWN_SUBLAYER) {
                    "lockdown"
                } else {
                    "other"
                },
            );
        }
        Ok(present)
    }

    fn describe_flags(flags: u32) -> String {
        let names = [
            (FWPM_FILTER_FLAG_PERSISTENT, "persistent"),
            (FWPM_FILTER_FLAG_BOOTTIME, "boottime"),
            (FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, "clear-action-right"),
        ]
        .into_iter()
        .filter(|(flag, _)| flags & flag != 0)
        .map(|(_, name)| name)
        .collect::<Vec<_>>();
        if names.is_empty() {
            String::new()
        } else {
            format!(" ({})", names.join(","))
        }
    }

    /// `Ok(true)` when the object exists (was read or deleted), `Ok(false)` when
    /// it was not there.
    fn found(status: u32, not_found: i32, context: &str) -> Result<bool> {
        if status as i32 == not_found {
            return Ok(false);
        }
        check(status, context)?;
        Ok(true)
    }

    fn presence(present: bool) -> &'static str {
        if present { "present" } else { "absent" }
    }

    /// Frees a structure BFE allocated for a `Get*ByKey0` call.
    fn free<T>(mut object: *mut T) {
        // SAFETY: `object` came from a successful Fwpm*GetByKey0 call and is not
        // used afterwards; FwpmFreeMemory0 nulls the local copy.
        unsafe { FwpmFreeMemory0((&raw mut object).cast()) };
    }

    #[derive(Debug)]
    struct PermitOptions {
        program: PathBuf,
        hard: bool,
        sublayer_weight: u16,
        lockdown_sublayer: bool,
    }

    impl PermitOptions {
        fn parse(args: &[&str]) -> Result<Self> {
            let mut program = None;
            let mut hard = false;
            let mut sublayer_weight = None;
            let mut lockdown_sublayer = false;
            let mut args = args.iter();
            while let Some(&arg) = args.next() {
                match arg {
                    "--program" => program = args.next().map(PathBuf::from),
                    "--hard" => hard = true,
                    "--lockdown-sublayer" => lockdown_sublayer = true,
                    "--sublayer-weight" => {
                        let value = args.next().ok_or_else(usage)?;
                        sublayer_weight = Some(parse_u16(value)?);
                    }
                    _ => return Err(usage()),
                }
            }
            if lockdown_sublayer && sublayer_weight.is_some() {
                return Err("--lockdown-sublayer has the Lockdown sublayer's weight".to_owned());
            }
            Ok(Self {
                program: program.ok_or_else(usage)?,
                hard,
                sublayer_weight: sublayer_weight.unwrap_or(DEFAULT_PERMIT_SUBLAYER_WEIGHT),
                lockdown_sublayer,
            })
        }
    }

    fn parse_u16(value: &str) -> Result<u16> {
        let parsed = match value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
        {
            Some(hex) => u16::from_str_radix(hex, 16),
            None => value.parse(),
        };
        parsed.map_err(|_| format!("not a u16 weight: {value}"))
    }

    /// The application ID blob from `FwpmGetAppIdFromFileName0`. BFE copies it
    /// into the filter on add, so it only has to live until the add returns.
    #[derive(Debug)]
    struct AppId(*mut FWP_BYTE_BLOB);

    impl AppId {
        fn from_path(path: &Path) -> Result<Self> {
            let path = path
                .to_str()
                .ok_or_else(|| format!("not a UTF-8 path: {}", path.display()))?;
            let path = wide(path);
            let mut blob = ptr::null_mut();
            // SAFETY: `path` is NUL-terminated and outlives the call; the blob
            // is owned by `Self` and freed in Drop.
            let status = unsafe { FwpmGetAppIdFromFileName0(path.as_ptr(), &mut blob) };
            check(status, "getting the application ID (does the file exist?)")?;
            Ok(Self(blob))
        }
    }

    impl Drop for AppId {
        fn drop(&mut self) {
            free(self.0);
        }
    }

    fn permit(options: &PermitOptions) -> Result<()> {
        let app_id = AppId::from_path(&options.program)?;
        let engine = Engine::open(true)?;
        let mut provider_name = wide("Rosetun Lockdown probe permit");
        let mut sublayer_name = wide("Rosetun Lockdown probe permit");
        let sublayer_key = if options.lockdown_sublayer {
            LOCKDOWN_SUBLAYER
        } else {
            PERMIT_SUBLAYER
        };

        engine.transaction(|engine| {
            let provider = FWPM_PROVIDER0 {
                providerKey: PERMIT_PROVIDER,
                displayData: display_data(&mut provider_name),
                ..Default::default()
            };
            // SAFETY: `provider` and its name live across the call.
            let status = unsafe { FwpmProviderAdd0(engine.handle, &provider, ptr::null_mut()) };
            check(
                status,
                "adding the permit provider (is another permit running?)",
            )?;

            if !options.lockdown_sublayer {
                let sublayer = FWPM_SUBLAYER0 {
                    subLayerKey: PERMIT_SUBLAYER,
                    displayData: display_data(&mut sublayer_name),
                    providerKey: (&PERMIT_PROVIDER as *const GUID).cast_mut(),
                    weight: options.sublayer_weight,
                    ..Default::default()
                };
                // SAFETY: as above; the provider key is a static.
                let status = unsafe { FwpmSubLayerAdd0(engine.handle, &sublayer, ptr::null_mut()) };
                check(status, "adding the permit sublayer")?;
            }

            for family in [Family::V4, Family::V6] {
                add_permit_filter(engine, &app_id, family, sublayer_key, options.hard)?;
            }
            Ok(())
        })?;

        let (sublayer, weight) = if options.lockdown_sublayer {
            ("lockdown", LOCKDOWN_SUBLAYER_WEIGHT)
        } else {
            ("own", options.sublayer_weight)
        };
        println!(
            "permit active: program={} {} sublayer={sublayer} weight={weight:#06x}",
            options.program.display(),
            if options.hard { "hard" } else { "soft" },
        );
        // The VM scenario waits for this line before it tests.
        println!("ready");
        std::io::stdout()
            .flush()
            .map_err(|error| format!("flushing stdout: {error}"))?;

        let mut line = String::new();
        match std::io::stdin().lock().read_line(&mut line) {
            // No console (stdin from NUL or a file): hold until killed, which
            // is how the scenario ends the permit and checks the cleanup.
            Ok(0) | Err(_) => loop {
                std::thread::park();
            },
            Ok(_) => {}
        }
        drop(engine);
        println!("permit removed");
        Ok(())
    }

    fn add_permit_filter(
        engine: &Engine,
        app_id: &AppId,
        family: Family,
        sublayer: GUID,
        hard: bool,
    ) -> Result<()> {
        let mut name = wide(match family {
            Family::V4 => "Rosetun Lockdown probe: permit program IPv4",
            Family::V6 => "Rosetun Lockdown probe: permit program IPv6",
        });
        let mut condition = FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_APP_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_BLOB_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: app_id.0 },
            },
        };
        let filter = FWPM_FILTER0 {
            displayData: display_data(&mut name),
            // Clearing the action right is what makes a permit hard: a block
            // in a lower-weight sublayer can no longer override it.
            flags: if hard {
                FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT
            } else {
                0
            },
            providerKey: (&PERMIT_PROVIDER as *const GUID).cast_mut(),
            layerKey: layer_key(family),
            subLayerKey: sublayer,
            weight: weight(PERMIT_FILTER_WEIGHT),
            numFilterConditions: 1,
            filterCondition: &mut condition,
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_PERMIT,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut id = 0;
        // SAFETY: `filter`, its name, the condition and the app ID blob all
        // outlive the call; BFE copies them into the filter.
        let status = unsafe { FwpmFilterAdd0(engine.handle, &filter, ptr::null_mut(), &mut id) };
        check(status, "adding a permit filter")
    }

    fn layer_key(family: Family) -> GUID {
        match family {
            Family::V4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            Family::V6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        }
    }

    fn weight(value: u8) -> FWP_VALUE0 {
        FWP_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: FWP_VALUE0_0 { uint8: value },
        }
    }

    fn same(left: &GUID, right: &GUID) -> bool {
        left.data1 == right.data1
            && left.data2 == right.data2
            && left.data3 == right.data3
            && left.data4 == right.data4
    }

    fn check(status: u32, context: &str) -> Result<()> {
        if status == 0 {
            Ok(())
        } else {
            Err(format!("{context}: {}", code_name(status)))
        }
    }

    fn code_name(status: u32) -> String {
        let name = match status as i32 {
            FWP_E_ALREADY_EXISTS => "FWP_E_ALREADY_EXISTS",
            FWP_E_IN_USE => "FWP_E_IN_USE",
            FWP_E_FILTER_NOT_FOUND => "FWP_E_FILTER_NOT_FOUND",
            FWP_E_SUBLAYER_NOT_FOUND => "FWP_E_SUBLAYER_NOT_FOUND",
            FWP_E_PROVIDER_NOT_FOUND => "FWP_E_PROVIDER_NOT_FOUND",
            5 => "ERROR_ACCESS_DENIED",
            _ => "",
        };
        if name.is_empty() {
            format!("{status:#010x}")
        } else {
            format!("{status:#010x} {name}")
        }
    }
}
