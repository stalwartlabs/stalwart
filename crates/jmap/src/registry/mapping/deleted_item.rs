/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::RegistryGetResponse;
use registry::{
    jmap::IntoValue,
    schema::{
        prelude::{Object, ObjectInner},
        structs::{DeletedEmail, DeletedFileNode, DeletedItem},
    },
    types::EnumImpl,
};
use store::{
    ValueKey,
    ahash::AHashSet,
    registry::RegistryQuery,
    write::{RegistryClass, ValueClass},
};
use types::{blob::BlobClass, id::Id};

pub(crate) async fn deleted_item_get(
    mut get: RegistryGetResponse<'_>,
) -> trc::Result<RegistryGetResponse<'_>> {
    let object_id = get.object_type.to_id();
    let ids = if let Some(ids) = get.ids.take() {
        ids
    } else {
        get.server
            .registry()
            .query::<AHashSet<u64>>(
                RegistryQuery::new(get.object_type).with_account(get.account_id),
            )
            .await?
            .into_iter()
            .take(get.server.core.jmap.get_max_objects)
            .map(Id::from)
            .collect()
    };

    for id in ids {
        if let Some(mut item) = get
            .server
            .store()
            .get_value::<Object>(ValueKey::from(ValueClass::Registry(RegistryClass::Item {
                object_id,
                item_id: id.id(),
            })))
            .await?
        {
            if get.is_account_filtered
                && let ObjectInner::DeletedItem(
                    DeletedItem::Email(DeletedEmail {
                        blob_id,
                        cleanup_at,
                        ..
                    })
                    | DeletedItem::FileNode(DeletedFileNode {
                        blob_id,
                        cleanup_at,
                        ..
                    }),
                ) = &mut item.inner
            {
                blob_id.class = BlobClass::Reserved {
                    account_id: get.account_id,
                    expires: cleanup_at.timestamp() as u64,
                };
            }

            get.insert(id, item.into_value());
        } else {
            get.not_found(id);
        }
    }

    Ok(get)
}
