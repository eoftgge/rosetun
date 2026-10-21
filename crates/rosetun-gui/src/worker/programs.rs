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
}
