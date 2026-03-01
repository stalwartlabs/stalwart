/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::RegistryGetResponse;
use common::Server;
use registry::{
    jmap::IntoValue,
    schema::prelude::{Object, ObjectType, Property},
    types::EnumImpl,
};
use store::{
    IterateParams, U16_LEN, ValueKey,
    ahash::AHashSet,
    registry::RegistryQuery,
    write::{RegistryClass, ValueClass, key::DeserializeBigEndian},
};
use trc::AddContext;
use types::id::Id;

pub(crate) async fn report_get(
    mut get: RegistryGetResponse<'_>,
) -> trc::Result<RegistryGetResponse<'_>> {
    let object_id = get.object_type.to_id();
    let ids = if let Some(ids) = get.ids.take() {
        ids
    } else if matches!(
        get.object_type,
        ObjectType::DmarcExternalReport
            | ObjectType::TlsExternalReport
            | ObjectType::ArfExternalReport
    ) {
        if get.is_tenant_filtered {
            get.server.registry().query::<AHashSet<u64>>(
                RegistryQuery::new(get.object_type).with_tenant(get.access_token.tenant_id()),
            )
        } else {
            get.server.registry().query::<AHashSet<u64>>(
                RegistryQuery::new(get.object_type).greater_than(Property::ExpiresAt, 0u64),
            )
        }
        .await?
        .into_iter()
        .take(get.server.core.jmap.get_max_objects)
        .map(Id::from)
        .collect()
    } else {
        internal_report_ids(get.server, object_id, get.server.core.jmap.get_max_objects).await?
    };

    let tenant_id = get.access_token.tenant_id().map(Id::from);
    for id in ids {
        if let Some(report) = get
            .server
            .store()
            .get_value::<Object>(ValueKey::from(ValueClass::Registry(RegistryClass::Item {
                object_id,
                item_id: id.id(),
            })))
            .await?
        {
            if !get.is_tenant_filtered || report.inner.member_tenant_id() == tenant_id {
                get.insert(id, report.into_value());
            } else {
                get.not_found(id);
            }
        } else {
            get.not_found(id);
        }
    }

    Ok(get)
}

async fn internal_report_ids(
    server: &Server,
    object_id: u16,
    max_results: usize,
) -> trc::Result<Vec<Id>> {
    let mut events = Vec::with_capacity(8);

    let from_key = ValueKey::from(ValueClass::Registry(RegistryClass::PrimaryKey {
        object_id: object_id.into(),
        index_id: Property::Domain.to_id(),
        key: vec![],
    }));
    let to_key = ValueKey::from(ValueClass::Registry(RegistryClass::PrimaryKey {
        object_id: object_id.into(),
        index_id: Property::Domain.to_id(),
        key: vec![
            u8::MAX,
            u8::MAX,
            u8::MAX,
            u8::MAX,
            u8::MAX,
            u8::MAX,
            u8::MAX,
            u8::MAX,
        ],
    }));

    server
        .store()
        .iterate(
            IterateParams::new(from_key, to_key).ascending(),
            |key, value| {
                if !value.is_empty() {
                    events.push(key.deserialize_be_u64(U16_LEN)?.into());
                }

                Ok(events.len() < max_results)
            },
        )
        .await
        .caused_by(trc::location!())
        .map(|_| events)
}
