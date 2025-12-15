/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use store::{
    IterateParams, SUBSPACE_TASK_QUEUE, U32_LEN, U64_LEN, ValueKey,
    write::{
        AnyClass, BatchBuilder, TaskEpoch, ValueClass,
        key::{DeserializeBigEndian, KeySerializer},
    },
};
use trc::AddContext;

pub(crate) async fn migrate_tasks_v014(server: &Server) -> trc::Result<()> {
    let from_key = ValueKey::<ValueClass> {
        account_id: 0,
        collection: 0,
        document_id: 0,
        class: ValueClass::Any(AnyClass {
            subspace: SUBSPACE_TASK_QUEUE,
            key: KeySerializer::new(U64_LEN).write(0u64).finalize(),
        }),
    };
    let to_key = ValueKey::<ValueClass> {
        account_id: u32::MAX,
        collection: u8::MAX,
        document_id: u32::MAX,
        class: ValueClass::Any(AnyClass {
            subspace: SUBSPACE_TASK_QUEUE,
            key: KeySerializer::new(U64_LEN).write(u64::MAX).finalize(),
        }),
    };

    let mut delete_tasks = Vec::new();
    let mut insert_tasks = Vec::new();
    server
        .core
        .storage
        .data
        .iterate(
            IterateParams::new(from_key, to_key).ascending(),
            |key, value| {
                match key.get(U64_LEN + U32_LEN) {
                    Some(0..=2) => {
                        delete_tasks.push(key.to_vec());
                    }
                    None => {
                        return Err(trc::Error::corrupted_key(key, None, trc::location!()));
                    }
                    _ => {
                        let due = key.deserialize_be_u64(0)?;
                        let maybe_epoch = TaskEpoch::from_inner(due);
                        if maybe_epoch.attempt() != 0 {
                            delete_tasks.push(key.to_vec());
                            let epoch = TaskEpoch::new(due).inner();
                            let mut new_key = Vec::with_capacity(key.len());
                            new_key.extend_from_slice(&epoch.to_be_bytes());
                            new_key.extend_from_slice(&key[U64_LEN..]);
                            insert_tasks.push((new_key, value.to_vec()));
                        }
                    }
                };
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    let num_migrated = delete_tasks.len() + insert_tasks.len();
    if num_migrated != 0 {
        let mut batch = BatchBuilder::new();
        let mut batch_len = 0;
        for (key, value) in insert_tasks {
            batch_len += key.len() + value.len();
            batch.set(
                ValueClass::Any(AnyClass {
                    subspace: SUBSPACE_TASK_QUEUE,
                    key,
                }),
                value,
            );
            if batch_len > 4 * 1024 * 1024 {
                server
                    .store()
                    .write(batch.build_all())
                    .await
                    .caused_by(trc::location!())?;
                batch = BatchBuilder::new();
                batch_len = 0;
            }
        }

        for key in delete_tasks {
            batch_len += key.len();
            batch.clear(ValueClass::Any(AnyClass {
                subspace: SUBSPACE_TASK_QUEUE,
                key,
            }));
            if batch_len > 4 * 1024 * 1024 {
                server
                    .store()
                    .write(batch.build_all())
                    .await
                    .caused_by(trc::location!())?;
                batch = BatchBuilder::new();
                batch_len = 0;
            }
        }
        server
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
    }

    trc::event!(
        Server(trc::ServerEvent::Startup),
        Details = format!("Migrated {num_migrated} tasks")
    );

    Ok(())
}
