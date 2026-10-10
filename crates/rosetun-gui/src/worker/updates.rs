use super::*;

impl WorkerDispatcher {
    pub(crate) fn check_updates(&self) {
        self.spawn_task("rosetun-check-updates", move |publisher| {
            let result = rosetun_core::latest_release(Duration::from_secs(15));
            let checked_at = crate::state::now_unix();
            if result.is_ok() {
                if rosetun_core::record_update_check(&publisher.store, checked_at).is_err() {
                    tracing::warn!("Could not save update check time");
                } else {
                    publisher.publish();
                }
            }
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::UpdateCheck { checked_at, result },
            );
        });
    }
}
