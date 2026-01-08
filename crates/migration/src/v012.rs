/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    LOCK_RETRY_TIME, LOCK_WAIT_TIME_CORE, event_v1::migrate_calendar_events_v012,
    queue_v1::migrate_queue_v012, tasks_v1::migrate_tasks_v011,
};
use common::{KV_LOCK_HOUSEKEEPER, Server};
use trc::AddContext;

pub(crate) async fn migrate_v0_12(server: &Server, migrate_tasks: bool) -> trc::Result<()> {
    let force_lock = std::env::var("FORCE_LOCK").is_ok();
    let in_memory = server.in_memory_store();

    loop {
        if force_lock
            || in_memory
                .try_lock(
                    KV_LOCK_HOUSEKEEPER,
                    b"migrate_core_lock",
                    LOCK_WAIT_TIME_CORE,
                )
                .await
                .caused_by(trc::location!())?
        {
            migrate_queue_v012(server)
                .await
                .caused_by(trc::location!())?;

            if migrate_tasks {
                migrate_tasks_v011(server)
                    .await
                    .caused_by(trc::location!())?;
            }

            in_memory
                .remove_lock(KV_LOCK_HOUSEKEEPER, b"migrate_core_lock")
                .await
                .caused_by(trc::location!())?;
            break;
        } else {
            trc::event!(
                Server(trc::ServerEvent::Startup),
                Details = format!("Migration lock busy, waiting 30 seconds.",)
            );

            tokio::time::sleep(LOCK_RETRY_TIME).await;
        }
    }

    if migrate_tasks {
        migrate_calendar_events_v012(server)
            .await
            .caused_by(trc::location!())
    } else {
        Ok(())
    }
}
