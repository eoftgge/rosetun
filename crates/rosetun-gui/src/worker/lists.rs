use std::io::Read;

use rosetun_core::{
    MAX_LIST_BYTES, add_list_from_bytes, add_list_from_url, inspect_missing_categories,
    remove_list, rename_list, text_entry_count,
};

use super::*;

fn read_list_file(path: &Path) -> Result<(String, Vec<u8>), ListError> {
    let name = path
        .file_name()
        .ok_or(ListError::EmptyFileName)?
        .to_string_lossy()
        .into_owned();
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_LIST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_LIST_BYTES {
        return Err(ListError::TooLarge);
    }
    Ok((name, bytes))
}

fn add_result(
    store: &Store,
    result: Result<List, ListError>,
) -> Result<(List, Option<usize>), ListError> {
    result.map(|list| {
        let entries = text_entry_count(store, &list.id)
            .inspect_err(|error| subscriptions::log_list_error("count", error))
            .ok()
            .flatten();
        (list, entries)
    })
}

impl WorkerDispatcher {
    pub(crate) fn inspect_list_categories(&self, revision: u64, temporary: Vec<Rule>) {
        self.spawn_task("rosetun-inspect-lists", move |publisher| {
            let result = publisher
                .store
                .load()
                .map_err(ListError::Store)
                .and_then(|config| {
                    inspect_missing_categories(&publisher.store, &config, &temporary)
                });
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::ListAvailability { revision, result },
            );
        });
    }

    pub(crate) fn browse_list_file(&self) {
        self.spawn_task("rosetun-browse-list", move |publisher| {
            #[cfg(windows)]
            let path = rfd::FileDialog::new()
                .set_title(tr!("choose-list-file"))
                .pick_file();
            #[cfg(not(windows))]
            let path = None;
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::BrowsedListFile(path),
            );
        });
    }

    pub(crate) fn add_list_url(&self, url: String, name: String) {
        self.spawn_complete("rosetun-add-list-url", move |store| {
            let result = add_result(
                store,
                add_list_from_url(store, &url, &name, Timeouts::default()),
            );
            if let Err(error) = &result {
                subscriptions::log_list_error("add", error);
            }
            WorkerEvent::AddList(result)
        });
    }

    pub(crate) fn add_list_file(&self, path: PathBuf, name: String) {
        self.spawn_complete("rosetun-add-list-file", move |store| {
            let result = read_list_file(&path)
                .and_then(|(original, bytes)| add_list_from_bytes(store, &name, &original, &bytes));
            let result = add_result(store, result);
            if let Err(error) = &result {
                subscriptions::log_list_error("add", error);
            }
            WorkerEvent::AddList(result)
        });
    }

    pub(crate) fn update_list_manual(&self, id: ListId) {
        self.spawn_complete("rosetun-update-list-manual", move |store| {
            let result = update_list(store, &id, None, Timeouts::default());
            if let Err(error) = &result {
                subscriptions::log_list_error("update", error);
            }
            WorkerEvent::UpdateList {
                id,
                result,
                manual: true,
            }
        });
    }

    pub(crate) fn update_list_file(&self, id: ListId) {
        self.spawn_task("rosetun-update-list-file", move |publisher| {
            #[cfg(windows)]
            let path = rfd::FileDialog::new()
                .set_title(tr!("choose-list-file"))
                .pick_file();
            #[cfg(not(windows))]
            let path: Option<PathBuf> = None;
            let Some(path) = path else {
                emit(
                    &publisher.tx,
                    &publisher.repaint,
                    WorkerEvent::FileListUpdateCancelled(id),
                );
                return;
            };
            let result = read_list_file(&path).and_then(|(name, bytes)| {
                update_list(
                    &publisher.store,
                    &id,
                    Some((&name, &bytes)),
                    Timeouts::default(),
                )
            });
            if let Err(error) = &result {
                subscriptions::log_list_error("update", error);
            }
            publisher.complete(WorkerEvent::UpdateList {
                id,
                result,
                manual: true,
            });
        });
    }

    pub(crate) fn rename_list(&self, id: ListId, name: String) {
        self.spawn_complete("rosetun-rename-list", move |store| {
            WorkerEvent::RenameList(rename_list(store, &id, &name))
        });
    }

    pub(crate) fn remove_list(&self, id: ListId) {
        self.spawn_complete("rosetun-remove-list", move |store| {
            WorkerEvent::RemoveList(remove_list(store, &id))
        });
    }
}
