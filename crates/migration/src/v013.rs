/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    LOCK_RETRY_TIME, LOCK_WAIT_TIME_ACCOUNT, LOCK_WAIT_TIME_CORE, get_document_ids,
    principal_v2::{migrate_principal_v0_13, migrate_principals_v0_13},
};
use common::{KV_LOCK_HOUSEKEEPER, Server};
use store::{
    dispatch::lookup::KeyValue,
    rand::{self, seq::SliceRandom},
};
use trc::AddContext;
use types::collection::Collection;

pub(crate) async fn migrate_v0_13(server: &Server) -> trc::Result<()> {
    let force_lock = std::env::var("FORCE_LOCK").is_ok();
    let in_memory = server.in_memory_store();
    let principal_ids;

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
            if in_memory
                .key_get::<()>(KeyValue::<()>::build_key(
                    KV_LOCK_HOUSEKEEPER,
                    b"migrate_core_done",
                ))
                .await
                .caused_by(trc::location!())?
                .is_none()
            {
                principal_ids = migrate_principals_v0_13(server)
                    .await
                    .caused_by(trc::location!())?;

                in_memory
                    .key_set(
                        KeyValue::new(
                            KeyValue::<()>::build_key(KV_LOCK_HOUSEKEEPER, b"migrate_core_done"),
                            b"1".to_vec(),
                        )
                        .expires(86400),
                    )
                    .await
                    .caused_by(trc::location!())?;
            } else {
                principal_ids = get_document_ids(server, u32::MAX, Collection::Principal)
                    .await
                    .caused_by(trc::location!())?
                    .unwrap_or_default();

                trc::event!(
                    Server(trc::ServerEvent::Startup),
                    Details = format!("Migration completed by another node.",)
                );
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

    if !principal_ids.is_empty() {
        let mut principal_ids = principal_ids.into_iter().collect::<Vec<_>>();
        principal_ids.shuffle(&mut rand::rng());

        loop {
            let mut skipped_principal_ids = Vec::new();
            let mut num_migrated = 0;

            for principal_id in principal_ids {
                let lock_key = format!("migrate_{principal_id}_lock");
                let done_key = format!("migrate_{principal_id}_done");

                if force_lock
                    || in_memory
                        .try_lock(
                            KV_LOCK_HOUSEKEEPER,
                            lock_key.as_bytes(),
                            LOCK_WAIT_TIME_ACCOUNT,
                        )
                        .await
                        .caused_by(trc::location!())?
                {
                    if in_memory
                        .key_get::<()>(KeyValue::<()>::build_key(
                            KV_LOCK_HOUSEKEEPER,
                            done_key.as_bytes(),
                        ))
                        .await
                        .caused_by(trc::location!())?
                        .is_none()
                    {
                        migrate_principal_v0_13(server, principal_id)
                            .await
                            .caused_by(trc::location!())?;

                        num_migrated += 1;

                        in_memory
                            .key_set(
                                KeyValue::new(
                                    KeyValue::<()>::build_key(
                                        KV_LOCK_HOUSEKEEPER,
                                        done_key.as_bytes(),
                                    ),
                                    b"1".to_vec(),
                                )
                                .expires(86400),
                            )
                            .await
                            .caused_by(trc::location!())?;
                    }

                    in_memory
                        .remove_lock(KV_LOCK_HOUSEKEEPER, lock_key.as_bytes())
                        .await
                        .caused_by(trc::location!())?;
                } else {
                    skipped_principal_ids.push(principal_id);
                }
            }

            if !skipped_principal_ids.is_empty() {
                trc::event!(
                    Server(trc::ServerEvent::Startup),
                    Details = format!(
                        "Migrated {num_migrated} accounts and {} are locked by another node, waiting 30 seconds.",
                        skipped_principal_ids.len()
                    )
                );
                tokio::time::sleep(LOCK_RETRY_TIME).await;
                principal_ids = skipped_principal_ids;
            } else {
                trc::event!(
                    Server(trc::ServerEvent::Startup),
                    Details = format!("Account migration completed.",)
                );
                break;
            }
        }
    }

    Ok(())
}
