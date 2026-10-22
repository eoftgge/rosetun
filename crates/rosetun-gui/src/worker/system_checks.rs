use super::{WorkerDispatcher, WorkerEvent, emit};

impl WorkerDispatcher {
    pub(crate) fn check_system(&self, request: u64, own_alias: String, guarded: bool) {
        self.spawn_task("rosetun-check-system", move |publisher| {
            let results = rosetun_core::check_system(&own_alias, guarded);
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::SystemChecks { request, results },
            );
        });
    }
}
