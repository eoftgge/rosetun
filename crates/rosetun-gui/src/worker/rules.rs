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

    pub(crate) fn save_exit(&self, id: Option<ExitId>, name: String, target: ExitTarget) {
        self.spawn_complete("rosetun-save-exit", move |store| {
            WorkerEvent::SaveExit(save_exit(store, id.as_ref(), &name, target))
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
}

fn save_exit(
    store: &Store,
    id: Option<&ExitId>,
    name: &str,
    target: ExitTarget,
) -> Result<(), ExitError> {
    let id = match id {
        Some(id) => {
            rename_exit(store, id, name)?;
            id.clone()
        }
        None => {
            let new = match &target {
                ExitTarget::Country(code) => NewExit::Country {
                    code: code.clone(),
                    name: name.to_owned(),
                },
                ExitTarget::Node { selection, .. } => NewExit::Node {
                    selection: selection.clone(),
                    name: name.to_owned(),
                },
            };
            let exit = create_exit(store, &new)?;
            // A new node exit gets the node's country as its fallback; keep the user's choice.
            if exit.target == target {
                return Ok(());
            }
            exit.id
        }
    };
    change_exit_target(store, &id, target)
}
