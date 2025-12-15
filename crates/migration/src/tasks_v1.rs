/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use store::{
    IterateParams, SUBSPACE_TASK_QUEUE, U64_LEN, ValueKey,
    write::{
        AnyClass, BatchBuilder, ValueClass,
        key::{DeserializeBigEndian, KeySerializer},
        now,
    },
};
use trc::AddContext;

pub(crate) async fn migrate_tasks_v011(server: &Server) -> trc::Result<()> {
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

    let now = now();
    let mut migrate_tasks = Vec::new();
    server
        .core
        .storage
        .data
        .iterate(
            IterateParams::new(from_key, to_key).ascending(),
            |key, value| {
                let due = key.deserialize_be_u64(0)?;

                if due > now {
                    migrate_tasks.push((key.to_vec(), value.to_vec()));
                }

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    if !migrate_tasks.is_empty() {
        let num_migrated = migrate_tasks.len();
        let mut batch = BatchBuilder::new();
        for (key, value) in migrate_tasks {
            let mut new_key = key.clone();
            new_key[0..8].copy_from_slice(&now.to_be_bytes());

            batch
                .clear(ValueClass::Any(AnyClass {
                    subspace: SUBSPACE_TASK_QUEUE,
                    key,
                }))
                .set(
                    ValueClass::Any(AnyClass {
                        subspace: SUBSPACE_TASK_QUEUE,
                        key: new_key,
                    }),
                    value,
                );
        }
        server
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;

        trc::event!(
            Server(trc::ServerEvent::Startup),
            Details = format!("Migrated {num_migrated} tasks")
        );
    }

    Ok(())
}
