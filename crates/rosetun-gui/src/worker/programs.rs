use super::*;

impl WorkerDispatcher {
    /// Reads version resources off the UI thread. Neither the paths nor the
    /// names are logged: together they are the user's browsing history.
    pub(crate) fn program_names(&self, paths: Vec<String>) {
        self.spawn_task("rosetun-program-names", move |publisher| {
            let names = paths
                .into_iter()
                .map(|path| {
                    let description = rosetun_processes::file_description(Path::new(&path));
                    let name = crate::programs::display_name(&path, description.as_deref());
                    (path, name)
                })
                .collect();
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::ProgramNames(names),
            );
        });
    }

    /// Reads the running session's lists for the "Why" row. A 70 MB `.dat`
    /// must not stall the window. Nothing about them is logged.
    pub(crate) fn session_lists(&self, request: u64, session: ConnectRequest) {
        self.spawn_task("rosetun-session-lists", move |publisher| {
            let result = rosetun_core::read_session_lists(&publisher.store, &session);
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::SessionLists { request, result },
            );
        });
    }
}
