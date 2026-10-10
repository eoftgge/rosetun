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
                    tracing::info!(count = processes.len(), "Loaded running processes")
                }
                Err(error) => tracing::warn!(%error, "Could not load running processes"),
            }
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::Processes { request, result },
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

    pub(crate) fn add_rule(&self, set: RuleSetId, matcher: RuleMatcher, target: RuleTarget) {
        self.spawn_complete("rosetun-add-rule", move |store| {
            WorkerEvent::AddRule(add_rule(store, &set, matcher, target))
        });
    }

    pub(crate) fn add_rules(&self, set: RuleSetId, matchers: Vec<RuleMatcher>, target: RuleTarget) {
        self.spawn_complete("rosetun-add-rules", move |store| {
            WorkerEvent::AddRules(add_rules(store, &set, matchers, target))
        });
    }

    pub(crate) fn update_rule(
        &self,
        set: RuleSetId,
        rule: RuleId,
        matcher: RuleMatcher,
        target: RuleTarget,
    ) {
        self.spawn_complete("rosetun-update-rule", move |store| {
            WorkerEvent::UpdateRule(update_rule(store, &set, &rule, matcher, target))
        });
    }

    pub(crate) fn set_rule_target(&self, set: RuleSetId, rule: RuleId, target: RuleTarget) {
        self.spawn_complete("rosetun-set-rule-target", move |store| {
            WorkerEvent::SetRuleTarget(set_rule_target(store, &set, &rule, target))
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
}
