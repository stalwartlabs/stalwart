/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use crate::{
    api::query::QueryResponseBuilder,
    registry::{
        mapping::{RegistryGetResponse, RegistryQueryResponse, RegistrySetResponse},
        query::RegistryQueryFilters,
    },
};
use jmap_proto::{error::set::SetError, types::state::State};
use jmap_tools::{Key, Value};
use registry::{
    jmap::IntoValue,
    schema::{
        enums::{ArchivedItemStatus, Permission},
        prelude::{Object, ObjectType, Property},
        structs::{ArchivedItem, Task, TaskRestoreArchivedItem, TaskStatus},
    },
    types::{EnumImpl, ObjectImpl, datetime::UTCDateTime, id::ObjectId},
};
use std::str::FromStr;
use store::{
    SerializeInfallible, ValueKey,
    registry::RegistryQuery,
    write::{BatchBuilder, BlobLink, BlobOp, RegistryClass, ValueClass, assert::AssertValue},
};
use trc::AddContext;
use types::{blob::BlobClass, id::Id};

pub(crate) async fn archived_item_set(
    mut set: RegistrySetResponse<'_>,
) -> trc::Result<RegistrySetResponse<'_>> {
    // Archived items cannot be created
    set.fail_all_create("Archived items cannot be created");

    let mut batch = BatchBuilder::new();
    let object_id = set.object_type.to_id();
    'outer: for (id, value) in set.update.drain(..) {
        // Extract new deliverAt value
        let mut status = ArchivedItemStatus::Archived;
        let mut archived_until = None;
        let now = UTCDateTime::now();
        for (key, value) in value.into_expanded_object() {
            match (key, value) {
                (Key::Property(Property::Status), Value::Str(status_)) => {
                    let Some(status_) = ArchivedItemStatus::parse(&status_) else {
                        set.response.not_updated.append(
                            id,
                            SetError::invalid_patch()
                                .with_property(Property::Status)
                                .with_description("Invalid value for property"),
                        );
                        continue 'outer;
                    };
                    status = status_;
                }
                (Key::Property(Property::ArchivedUntil), Value::Str(archived_until_)) => {
                    archived_until = UTCDateTime::from_str(archived_until_.as_ref())
                        .ok()
                        .filter(|da| *da > now);
                    if archived_until.is_none() {
                        set.response.not_updated.append(
                            id,
                            SetError::invalid_patch()
                                .with_property(Property::ArchivedUntil)
                                .with_description("Invalid value for property"),
                        );
                        continue 'outer;
                    }
                }
                (Key::Property(Property::Id), _) => {}
                (key, _) => {
                    set.response.not_updated.append(
                        id,
                        SetError::invalid_properties().with_property(key.into_owned()),
                    );
                    continue 'outer;
                }
            }
        }

        let item_id = id.id();
        if (status == ArchivedItemStatus::RequestRestore || archived_until.is_some())
            && let Some(item) =
                set.server
                    .store()
                    .get_value::<Object>(ValueKey::from(ValueClass::Registry(
                        RegistryClass::Item { object_id, item_id },
                    )))
                    .await?
                    .filter(|item| {
                        !set.is_account_filtered
                            || item.inner.account_id() == Some(set.account_id.into())
                    })
        {
            let revision = item.revision;
            if let Some(archived_until) = archived_until
                && status != ArchivedItemStatus::Archived
            {
                // Update archivedUntil
                let mut item = ArchivedItem::from(item);
                let old_archived_until = item.archived_until();

                if old_archived_until != archived_until {
                    item.set_archived_until(archived_until);
                    let blob_hash = item.blob_id().hash.clone();

                    batch
                        .with_account_id(item.account_id().document_id())
                        .assert_value(
                            ValueClass::Registry(RegistryClass::Item { object_id, item_id }),
                            AssertValue::Hash(revision),
                        )
                        .clear(BlobOp::Link {
                            hash: blob_hash.clone(),
                            to: BlobLink::Temporary {
                                until: old_archived_until.timestamp() as u64,
                            },
                        })
                        .set(
                            BlobOp::Link {
                                hash: blob_hash,
                                to: BlobLink::Temporary {
                                    until: archived_until.timestamp() as u64,
                                },
                            },
                            ObjectId::new(ObjectType::ArchivedItem, item_id.into()).serialize(),
                        )
                        .set(
                            ValueClass::Registry(RegistryClass::Item { object_id, item_id }),
                            item.to_pickled_vec(),
                        );
                }
            } else {
                // Schedule restore task
                let item = ArchivedItem::from(item);
                let account_id = item.account_id();

                batch
                    .assert_value(
                        ValueClass::Registry(RegistryClass::Item { object_id, item_id }),
                        AssertValue::Hash(revision),
                    )
                    .clear(ValueClass::Registry(RegistryClass::Index {
                        index_id: Property::AccountId.to_id(),
                        object_id,
                        item_id,
                        key: account_id.id().serialize(),
                    }))
                    .clear(ValueClass::Registry(RegistryClass::Item {
                        object_id,
                        item_id,
                    }))
                    .schedule_task(Task::RestoreArchivedItem(TaskRestoreArchivedItem {
                        account_id,
                        archived_item_type: item.object_type(),
                        archived_until: item.archived_until(),
                        blob_id: item.blob_id().clone(),
                        created_at: item.created_at(),
                        status: TaskStatus::now(),
                    }));
            }

            batch.commit_point();

            set.response.updated.append(id, None);
        } else {
            set.response.not_updated.append(id, SetError::not_found());
        }
    }

    // Process items to destroy
    for id in set.destroy.drain(..) {
        let item_id = id.id();

        if let Some(item) =
            set.server
                .store()
                .get_value::<ArchivedItem>(ValueKey::from(ValueClass::Registry(
                    RegistryClass::Item { object_id, item_id },
                )))
                .await?
                .filter(|item| {
                    !set.is_account_filtered || item.account_id().document_id() == set.account_id
                })
        {
            let account_id = item.account_id().id();
            let until = item.archived_until().timestamp() as u64;
            let blob_hash = item.into_blob_id().hash;

            batch
                .with_account_id(account_id as u32)
                .clear(BlobOp::Link {
                    hash: blob_hash,
                    to: BlobLink::Temporary { until },
                })
                .clear(ValueClass::Registry(RegistryClass::Index {
                    index_id: Property::AccountId.to_id(),
                    object_id,
                    item_id,
                    key: account_id.serialize(),
                }))
                .clear(ValueClass::Registry(RegistryClass::Item {
                    object_id,
                    item_id,
                }))
                .commit_point();

            set.response.destroyed.push(id);
        } else {
            set.response.not_destroyed.append(id, SetError::not_found());
        }
    }

    if !batch.is_empty() {
        set.server
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
        set.server.notify_task_queue();
    }

    Ok(set)
}

pub(crate) async fn archived_item_get(
    mut get: RegistryGetResponse<'_>,
) -> trc::Result<RegistryGetResponse<'_>> {
    let object_id = get.object_type.to_id();
    let ids = if let Some(ids) = get.ids.take() {
        ids
    } else {
        let query = if !get.is_account_filtered {
            RegistryQuery::new(get.object_type).greater_than_or_equal(Property::AccountId, 0u64)
        } else {
            RegistryQuery::new(get.object_type).with_account(get.account_id)
        }
        .with_limit(get.server.core.jmap.get_max_objects);

        get.server.registry().query::<Vec<Id>>(query).await?
    };

    for id in ids {
        if let Some(mut item) = get
            .server
            .store()
            .get_value::<ArchivedItem>(ValueKey::from(ValueClass::Registry(RegistryClass::Item {
                object_id,
                item_id: id.id(),
            })))
            .await?
            .filter(|item| {
                !get.is_account_filtered || item.account_id().document_id() == get.account_id
            })
        {
            if get.is_account_filtered {
                let archived_until = item.archived_until();
                item.blob_id_mut().class = BlobClass::Reserved {
                    account_id: get.account_id,
                    expires: archived_until.timestamp() as u64,
                };
            }

            get.insert(id, item.into_value());
        } else {
            get.not_found(id);
        }
    }

    Ok(get)
}

pub(crate) async fn archived_item_query(
    mut req: RegistryQueryResponse<'_>,
) -> trc::Result<QueryResponseBuilder> {
    let can_impersonate = req.access_token.has_permission(Permission::Impersonate);
    let mut account_id = None;

    req.request
        .extract_filters(|property, _, value| match property {
            Property::AccountId if can_impersonate => {
                if let Some(id) = value.as_str().and_then(|s| Id::from_str(s).ok()) {
                    account_id = Some(id);
                    true
                } else {
                    false
                }
            }
            _ => false,
        })?;

    let mut query = if let Some(account_id) = account_id {
        RegistryQuery::new(req.object_type).with_account(account_id.document_id())
    } else if !can_impersonate {
        RegistryQuery::new(req.object_type).with_account(req.request.account_id.document_id())
    } else {
        RegistryQuery::new(req.object_type).greater_than_or_equal(Property::AccountId, 0u64)
    };

    let params = req
        .request
        .extract_parameters(req.server.core.jmap.query_max_results, Some(Property::Id))?;

    if let Some(limit) = params.limit {
        query = query.with_limit(limit);
        if let Some(anchor) = params.anchor {
            query = query.with_anchor(anchor);
        } else if let Some(position) = params.position {
            query = query.with_index_start(position);
        }
    }

    let mut results = req.server.registry().query::<Vec<Id>>(query).await?;

    match params.sort_by {
        Property::Id => {
            if !params.sort_ascending {
                results.sort_unstable_by(|a, b| b.cmp(a));
            }
        }
        property => {
            return Err(trc::JmapEvent::UnsupportedSort.into_err().details(format!(
                "Property {} is not supported for sorting",
                property
            )));
        }
    }

    // Build response
    let mut response = QueryResponseBuilder::new(
        results.len(),
        req.server.core.jmap.query_max_results,
        State::Initial,
        &req.request,
    );

    for id in results {
        if !response.add_id(id) {
            break;
        }
    }

    Ok(response)
}
