use super::*;

impl WorkerDispatcher {
    pub(crate) fn select_rule_set(&self, id: Option<RuleSetId>) {
        self.spawn_complete("rosetun-select-rule-set", move |store| {
            WorkerEvent::SelectRuleSet(select_rule_set(store, id.as_ref()))
        });
    }

    pub(crate) fn create_rule_set(&self, name: String) {
        self.spawn_complete("rosetun-create-rule-set", move |store| {
            WorkerEvent::CreateRuleSet(create_rule_set(store, &name, RuleTarget::Proxy))
        });
    }

    pub(crate) fn rename_rule_set(&self, id: RuleSetId, name: String) {
        self.spawn_complete("rosetun-rename-rule-set", move |store| {
            WorkerEvent::RenameRuleSet(rename_rule_set(store, &id, &name))
        });
    }

    pub(crate) fn delete_rule_set(&self, id: RuleSetId) {
        self.spawn_complete("rosetun-delete-rule-set", move |store| {
            WorkerEvent::DeleteRuleSet(delete_rule_set(store, &id))
        });
    }

    pub(crate) fn set_default_target(&self, id: RuleSetId, target: RuleTarget) {
        self.spawn_complete("rosetun-set-default-target", move |store| {
            WorkerEvent::SetDefaultTarget(set_default_target(store, &id, target))
        });
    }

    pub(crate) fn load_processes(&self, request: u64) {
        self.spawn_task("rosetun-load-processes", move |publisher| {
            let result = running_processes();
            match &result {
                Ok(processes) => {
                    tracing::info!(count = processes.len(), "loaded running processes");
                }
                Err(error) => tracing::warn!(%error, "could not load running processes"),
            }
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::Processes {
                    request,
                    result: result.map(crate::rules::group_processes),
                },
            );
        });
    }

    #[cfg(windows)]
    pub(crate) fn browse_executable(&self) {
        self.spawn_task("rosetun-browse-executable", move |publisher| {
            let path = rfd::FileDialog::new()
                .set_title(tr!("choose-program"))
                .add_filter(tr!("programs"), &["exe"])
                .pick_file();
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::BrowsedExecutable(path),
            );
        });
    }

    pub(crate) fn add_rule(&self, set: RuleSetId, matcher: RuleMatcher, target: RuleDestination) {
        self.spawn_complete("rosetun-add-rule", move |store| {
            WorkerEvent::AddRule(add_rule(store, &set, matcher, &target))
        });
    }

    pub(crate) fn add_rules(
        &self,
        set: RuleSetId,
        matchers: Vec<RuleMatcher>,
        target: RuleDestination,
    ) {
        self.spawn_complete("rosetun-add-rules", move |store| {
            WorkerEvent::AddRules(add_rules(store, &set, matchers, &target))
        });
    }

    pub(crate) fn update_rule(
        &self,
        set: RuleSetId,
        rule: RuleId,
        matcher: RuleMatcher,
        target: RuleDestination,
    ) {
        self.spawn_complete("rosetun-update-rule", move |store| {
            WorkerEvent::UpdateRule(update_rule(store, &set, &rule, matcher, &target))
        });
    }

    pub(crate) fn set_rule_target(&self, set: RuleSetId, rule: RuleId, target: RuleDestination) {
        self.spawn_complete("rosetun-set-rule-target", move |store| {
            WorkerEvent::SetRuleTarget(set_rule_target(store, &set, &rule, &target))
        });
    }

    pub(crate) fn create_exit(&self, exit: NewExit) {
        self.spawn_complete("rosetun-create-exit", move |store| {
            WorkerEvent::CreateExit(create_exit(store, &exit))
        });
    }

    pub(crate) fn save_exit(
        &self,
        id: Option<ExitId>,
        name: String,
        target: ExitTarget,
        via: Option<ExitId>,
    ) {
        self.spawn_complete("rosetun-save-exit", move |store| {
            WorkerEvent::SaveExit(save_exit(store, id.as_ref(), &name, target, via))
        });
    }

    pub(crate) fn rename_exit(&self, id: ExitId, name: String) {
        self.spawn_complete("rosetun-rename-exit", move |store| {
            WorkerEvent::RenameExit(rename_exit(store, &id, &name))
        });
    }

    pub(crate) fn delete_exit(&self, id: ExitId) {
        self.spawn_complete("rosetun-delete-exit", move |store| {
            let result = delete_exit(store, &id);
            WorkerEvent::DeleteExit { id, result }
        });
    }

    pub(crate) fn set_rule_enabled(&self, set: RuleSetId, rule: RuleId, enabled: bool) {
        self.spawn_complete("rosetun-set-rule-enabled", move |store| {
            WorkerEvent::SetRuleEnabled(set_rule_enabled(store, &set, &rule, enabled))
        });
    }

    pub(crate) fn move_rule(&self, set: RuleSetId, rule: RuleId, to_index: usize) {
        self.spawn_complete("rosetun-move-rule", move |store| {
            WorkerEvent::MoveRule(move_rule(store, &set, &rule, to_index))
        });
    }

    pub(crate) fn move_rules(&self, set: RuleSetId, rules: Vec<RuleId>, to_index: usize) {
        self.spawn_complete("rosetun-move-rules", move |store| {
            WorkerEvent::MoveRules(move_rules(store, &set, &rules, to_index))
        });
    }

    pub(crate) fn remove_rule(&self, set: RuleSetId, rule: RuleId) {
        self.spawn_complete("rosetun-remove-rule", move |store| {
            WorkerEvent::RemoveRule(remove_rule(store, &set, &rule))
        });
    }

    pub(crate) fn remove_rules(&self, set: RuleSetId, rules: Vec<RuleId>) {
        self.spawn_complete("rosetun-remove-rules", move |store| {
            WorkerEvent::RemoveRules(remove_rules(store, &set, &rules))
        });
    }

    pub(crate) fn group_rules(
        &self,
        set: RuleSetId,
        rules: Vec<RuleId>,
        name: String,
        target: RuleDestination,
    ) {
        self.spawn_complete("rosetun-group-rules", move |store| {
            WorkerEvent::GroupRules(group_rules(store, &set, &rules, &name, &target))
        });
    }

    pub(crate) fn add_rules_to_group(
        &self,
        set: RuleSetId,
        rules: Vec<RuleId>,
        target_group: RuleId,
    ) {
        self.spawn_complete("rosetun-add-rules-to-group", move |store| {
            WorkerEvent::AddRulesToGroup(add_rules_to_group(store, &set, &rules, &target_group))
        });
    }

    pub(crate) fn ungroup_rule(&self, set: RuleSetId, rule: RuleId) {
        self.spawn_complete("rosetun-ungroup-rule", move |store| {
            WorkerEvent::UngroupRule(ungroup_rule(store, &set, &rule))
        });
    }

    pub(crate) fn remove_group_item(&self, set: RuleSetId, rule: RuleId, index: usize) {
        self.spawn_complete("rosetun-remove-group-item", move |store| {
            WorkerEvent::RemoveGroupItem(remove_group_item(store, &set, &rule, index))
        });
    }

    pub(crate) fn restore_rule_sets(&self, snapshot: RuleSetsSnapshot) {
        self.spawn_complete("rosetun-restore-rule-sets", move |store| {
            WorkerEvent::RestoreRuleSets(restore_rule_sets(store, &snapshot))
        });
    }
}

impl WorkerDispatcher {
    pub(crate) fn import_rules(
        &self,
        set: RuleSetId,
        preview: rosetun_config::rules_exchange::Preview,
        replace: bool,
        default_target: bool,
    ) {
        self.spawn_complete("rosetun-import-rules", move |store| {
            WorkerEvent::ImportRules(rosetun_core::rules_exchange::apply(
                store,
                &set,
                &preview,
                replace,
                default_target,
            ))
        });
    }
    pub(crate) fn write_rules(&self, text: String, file: bool) {
        let clipboard = self.clipboard.clone();
        self.spawn_task("rosetun-export-rules", move |publisher| {
            let result = write_rules_document(text, file, &clipboard);
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::RulesWritten(result),
            );
        });
    }
    pub(crate) fn read_rules(&self, file: bool) {
        self.spawn_task("rosetun-read-rules", move |publisher| {
            let result = read_rules_document(file);
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::RulesRead(result),
            );
        });
    }
}
const RULES_FILE_FILTER: crate::file_dialog::Filter<'static> = crate::file_dialog::Filter {
    name: "JSON",
    extensions: &["json"],
};

fn write_rules_document(
    text: String,
    file: bool,
    clipboard: &Mutex<Option<arboard::Clipboard>>,
) -> Result<RulesExportOutcome, RulesTransferError> {
    if file {
        let Some(path) = crate::file_dialog::save_file(
            &tr!("rules-transfer-export"),
            "rules.json",
            Some(RULES_FILE_FILTER),
        )
        .map_err(|_| RulesTransferError::FileDialogUnavailable)?
        else {
            return Ok(RulesExportOutcome::Cancelled);
        };
        return std::fs::write(path, text)
            .map(|()| RulesExportOutcome::Saved)
            .map_err(|_| RulesTransferError::Io);
    }
    let mut clipboard = clipboard.lock().map_err(|_| RulesTransferError::Io)?;
    if clipboard.is_none() {
        *clipboard = Some(arboard::Clipboard::new().map_err(|_| RulesTransferError::Io)?);
    }
    clipboard
        .as_mut()
        .ok_or(RulesTransferError::Io)?
        .set_text(text)
        .map(|()| RulesExportOutcome::Copied)
        .map_err(|_| RulesTransferError::Io)
}
fn read_rules_document(file: bool) -> Result<Option<String>, RulesTransferError> {
    if file {
        use std::io::Read;
        let Some(path) =
            crate::file_dialog::pick_file(&tr!("rules-transfer-import"), Some(RULES_FILE_FILTER))
                .map_err(|_| RulesTransferError::FileDialogUnavailable)?
        else {
            return Ok(None);
        };
        let input = std::fs::File::open(path).map_err(|_| RulesTransferError::Io)?;
        let mut text = String::new();
        input
            .take((rosetun_config::rules_exchange::MAX_DOCUMENT_BYTES + 1) as u64)
            .read_to_string(&mut text)
            .map_err(|_| RulesTransferError::Io)?;
        return Ok(Some(text));
    }
    arboard::Clipboard::new()
        .and_then(|mut clipboard| clipboard.get_text())
        .map(Some)
        .map_err(|_| RulesTransferError::Io)
}
