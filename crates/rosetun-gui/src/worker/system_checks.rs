use rosetun_core::CheckResult;

use super::{WorkerDispatcher, WorkerEvent, emit};

/// The system check plus what only the service can see. On Linux the service reads the
/// firewall for tables that redirect traffic and the answer joins the interception row;
/// a service that is not there, or an older one, adds nothing.
pub(super) fn check_with_service(own_alias: &str, guarded: bool) -> Vec<CheckResult> {
    #[cfg_attr(
        not(target_os = "linux"),
        expect(unused_mut, reason = "only Linux adds the service's findings")
    )]
    let mut results = rosetun_core::check_system(own_alias, guarded);
    #[cfg(target_os = "linux")]
    if let Ok(mut client) =
        rosetun_ipc::HelperClient::connect(&rosetun_ipc::default_endpoint(), super::CLIENT_NAME)
        && let Ok(tables) = client.foreign_rules()
    {
        add_firewall_tables(&mut results, &tables);
    }
    results
}

/// Names the tables in the interception row, which turns into a warning.
#[cfg(any(target_os = "linux", test))]
fn add_firewall_tables(results: &mut [CheckResult], tables: &[String]) {
    use rosetun_core::{CheckDetail, CheckKind, CheckStatus};

    if tables.is_empty() {
        return;
    }
    let Some(row) = results
        .iter_mut()
        .find(|result| result.kind == CheckKind::PacketInterceptor)
    else {
        return;
    };
    let (mut processes, driver) = match &row.detail {
        CheckDetail::PacketInterceptor { processes, driver } => (processes.clone(), *driver),
        _ => (Vec::new(), false),
    };
    processes.extend(tables.iter().map(|table| format!("nftables {table}")));
    row.status = CheckStatus::Warning;
    row.detail = CheckDetail::PacketInterceptor { processes, driver };
}

impl WorkerDispatcher {
    pub(crate) fn check_system(&self, request: u64, own_alias: String, guarded: bool) {
        self.spawn_task("rosetun-check-system", move |publisher| {
            let results = check_with_service(&own_alias, guarded);
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::SystemChecks { request, results },
            );
        });
    }
}

#[cfg(test)]
mod tests {
    use rosetun_core::{CheckDetail, CheckKind, CheckStatus};

    use super::*;

    fn row(status: CheckStatus, detail: CheckDetail) -> CheckResult {
        CheckResult {
            kind: CheckKind::PacketInterceptor,
            status,
            detail,
        }
    }

    #[test]
    fn firewall_tables_turn_a_clean_row_into_a_warning_that_names_them() {
        let mut results = [row(CheckStatus::Ok, CheckDetail::None)];
        add_firewall_tables(&mut results, &["ip nat".to_owned()]);
        assert_eq!(results[0].status, CheckStatus::Warning);
        assert_eq!(
            results[0].detail,
            CheckDetail::PacketInterceptor {
                processes: vec!["nftables ip nat".to_owned()],
                driver: false
            }
        );
    }

    #[test]
    fn firewall_tables_join_the_programs_already_found() {
        let mut results = [row(
            CheckStatus::Warning,
            CheckDetail::PacketInterceptor {
                processes: vec!["nfqws".to_owned()],
                driver: true,
            },
        )];
        add_firewall_tables(&mut results, &["inet fw4".to_owned()]);
        assert_eq!(
            results[0].detail,
            CheckDetail::PacketInterceptor {
                processes: vec!["nfqws".to_owned(), "nftables inet fw4".to_owned()],
                driver: true
            }
        );
    }

    #[test]
    fn no_tables_change_nothing() {
        let mut results = [row(CheckStatus::Ok, CheckDetail::None)];
        add_firewall_tables(&mut results, &[]);
        assert_eq!(results[0].status, CheckStatus::Ok);
    }
}
