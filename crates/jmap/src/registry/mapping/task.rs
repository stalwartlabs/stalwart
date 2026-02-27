/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::RegistryGetResponse;
use common::Server;
use registry::{jmap::IntoValue, schema::prelude::Object, types::EnumImpl};
use store::{
    IterateParams, U64_LEN, ValueKey,
    write::{RegistryClass, TaskQueueClass, ValueClass, key::DeserializeBigEndian},
};
use trc::AddContext;
use types::id::Id;

pub(crate) async fn task_get(
    mut get: RegistryGetResponse<'_>,
) -> trc::Result<RegistryGetResponse<'_>> {
    let ids = if let Some(ids) = get.ids.take() {
        ids
    } else {
        task_ids(get.server, get.server.core.jmap.get_max_objects).await?
    };
    let object_id = get.object_type.to_id();

    for id in ids {
        if let Some(task) = get
            .server
            .store()
            .get_value::<Object>(ValueKey::from(ValueClass::Registry(RegistryClass::Item {
                object_id,
                item_id: id.id(),
            })))
            .await?
        {
            get.insert(id, task.into_value());
        } else {
            get.not_found(id);
        }
    }

    Ok(get)
}

async fn task_ids(server: &Server, max_results: usize) -> trc::Result<Vec<Id>> {
    let mut events = Vec::with_capacity(8);

    let from_key = ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Due { id: 0, due: 0 }));
    let to_key = ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Due {
        id: u64::MAX,
        due: u64::MAX,
    }));

    server
        .store()
        .iterate(
            IterateParams::new(from_key, to_key).ascending().no_values(),
            |key, _| {
                events.push(key.deserialize_be_u64(U64_LEN)?.into());

                Ok(events.len() < max_results)
            },
        )
        .await
        .caused_by(trc::location!())
        .map(|_| events)
}
