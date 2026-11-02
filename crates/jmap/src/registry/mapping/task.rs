/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    api::query::QueryResponseBuilder,
    registry::{
        mapping::{RegistryGetResponse, RegistryQueryResponse, RegistrySetResponse},
        query::RegistryQueryFilters,
    },
};
use common::Server;
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::query::QueryRequest,
    object::{JmapObject, registry::RegistryComparator},
    types::state::State,
};
use jmap_tools::{JsonPointer, JsonPointerItem, Key};
use registry::{
    jmap::{IntoValue, JsonPointerPatch, RegistryJsonPatch},
    schema::{
        enums::{TaskStatusType, TaskType},
        prelude::Property,
        structs::{CertificateManagement, DkimManagement, Domain, Task},
    },
    types::{
        EnumImpl, ObjectImpl,
        datetime::UTCDateTime,
        index::{IndexBuilder, IndexKey},
    },
};
use services::task_manager::{lock::TaskLockManager, reconcile::schedule_replacing};
use std::{cmp::Ordering, str::FromStr};
use store::{
    IterateParams, ValueKey,
    ahash::AHashSet,
    registry::RegistryFilterOp,
    write::{BatchBuilder, RegistryClass, TaskDue, TaskId, TaskQueueClass, ValueClass},
};
use trc::AddContext;
use types::id::Id;

pub(crate) async fn task_set(
    mut set: RegistrySetResponse<'_>,
) -> trc::Result<RegistrySetResponse<'_>> {
    let mut batch = BatchBuilder::new();
    let mut locked_tasks = Vec::new();

    // Process creations
    'outer: for (id, value) in set.create.drain() {
        let mut task = Task::default();
        if let Err(err) = task.patch(
            JsonPointerPatch::new(&JsonPointer::new(vec![]))
                .with_create(true)
                .with_can_set_account(true),
            value,
        ) {
            set.response.not_created.append(id, err.into());
            continue 'outer;
        }

        let mut validation_errors = Vec::new();
        if !task.validate(&mut validation_errors) {
            set.response.not_created.append(
                id,
                SetError::new(SetErrorType::ValidationFailed)
                    .with_validation_errors(validation_errors),
            );
            continue 'outer;
        }

        if !set.access_token.has_permission(task.permission()) {
            set.response.not_created.append(
                id,
                SetError::forbidden().with_description(format!(
                    "Insufficient permissions to create task of type {}",
                    task.object_type().as_str()
                )),
            );
            continue 'outer;
        }

        let task_type = task.object_type();
        let is_client_task = match task_type {
            TaskType::AccountMaintenance
            | TaskType::StoreMaintenance
            | TaskType::SpamFilterMaintenance
            | TaskType::AcmeRenewal
            | TaskType::DkimManagement
            | TaskType::DnsManagement
            | TaskType::ExternalPublicKeyMaintenance => true,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            TaskType::TenantMaintenance => true,
            // SPDX-SnippetEnd
            TaskType::CalendarAlarmEmail
            | TaskType::CalendarAlarmNotification
            | TaskType::CalendarItipMessage
            | TaskType::MergeThreads
            | TaskType::DmarcReport
            | TaskType::TlsReport
            | TaskType::DmarcReportWindow
            | TaskType::TlsReportWindow
            | TaskType::DestroyAccount
            | TaskType::ShareRevokeCleanup => false,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            TaskType::RestoreArchivedItem => false,
            // SPDX-SnippetEnd
        };
        if is_client_task {
            let mut index = IndexBuilder::default();
            task.index(&mut index);

            // Validate foreign keys
            for key in index.keys {
                if let IndexKey::ForeignKey {
                    object_id: foreign_id,
                    ..
                } = key
                    && !set
                        .server
                        .store()
                        .key_exists(ValueKey::from(ValueClass::Registry(
                            RegistryClass::IndexId {
                                object_id: foreign_id.object().to_id(),
                                item_id: foreign_id.id().id(),
                            },
                        )))
                        .await
                        .caused_by(trc::location!())?
                {
                    set.response.not_created.append(
                        id,
                        SetError::new(SetErrorType::InvalidForeignKey).with_object_id(foreign_id),
                    );
                    continue 'outer;
                }
            }

            let task_id = match TaskId::singleton_of(&task) {
                Some(task_id) => {
                    schedule_replacing(set.server, &mut batch, task).await?;
                    batch.commit_point();
                    task_id
                }
                None => {
                    let task_id = set.server.registry().assign_id();
                    batch.schedule_task_with_id(task_id, task).commit_point();
                    task_id
                }
            };
            set.response.created(id, task_id);
        } else {
            set.response.not_created.append(
                id,
                SetError::forbidden().with_description(format!(
                    "{} is an internal task type that cannot be created by clients",
                    task_type.as_str()
                )),
            );
        }
    }

    // Process updates
    'outer: for (id, value) in set.update.drain(..) {
        let task_id = id.id();
        let Some(mut task) = set
            .server
            .store()
            .get_value::<Task>(ValueKey::from(ValueClass::TaskQueue(
                TaskQueueClass::Task {
                    id: TaskId::Assigned(task_id),
                },
            )))
            .await?
        else {
            set.response.not_updated.append(id, SetError::not_found());
            continue;
        };

        if !set.access_token.has_permission(task.permission()) {
            set.response.not_updated.append(
                id,
                SetError::forbidden().with_description(format!(
                    "Insufficient permissions to update task of type {}",
                    task.object_type().as_str()
                )),
            );
            continue 'outer;
        }

        let Some(lock) = set.server.lock_task(task_id).await else {
            set.response.not_updated.append(
                id,
                SetError::forbidden().with_description(
                    "Task is currently being processed and cannot be updated".to_string(),
                ),
            );
            continue;
        };
        locked_tasks.push(lock);

        let old_timestamp = task.due_timestamp();
        let old_status = task.status().clone();
        for (key, value) in value.into_expanded_object() {
            let ptr = match key {
                Key::Property(prop) => {
                    JsonPointer::new(vec![JsonPointerItem::Key(Key::Property(prop))])
                }
                Key::Borrowed(other) => JsonPointer::parse(other),
                Key::Owned(other) => JsonPointer::parse(&other),
            };

            if let Err(err) = task.patch(
                JsonPointerPatch::new(&ptr)
                    .with_create(false)
                    .with_can_set_account(true),
                value,
            ) {
                set.response.not_updated.append(id, err.into());
                continue 'outer;
            }
        }

        if task.status() != &old_status {
            let id = TaskId::Assigned(task_id);
            let typ = task.object_type();
            batch
                .clear(ValueClass::TaskQueue(TaskQueueClass::Due {
                    id,
                    typ,
                    due: old_timestamp,
                }))
                .set_task_due_marked(
                    id,
                    typ,
                    task.due_timestamp(),
                    TaskQueueClass::due_marker(task.status()),
                );

            batch
                .set(
                    ValueClass::TaskQueue(TaskQueueClass::Task {
                        id: TaskId::Assigned(task_id),
                    }),
                    task.to_pickled_vec(),
                )
                .commit_point();
        }

        set.response.updated.append(id, None);
    }

    // Process destructions
    for id in set.destroy.drain(..) {
        let task_id = id.id();
        let Some(task) = set
            .server
            .store()
            .get_value::<Task>(ValueKey::from(ValueClass::TaskQueue(
                TaskQueueClass::Task {
                    id: TaskId::Assigned(task_id),
                },
            )))
            .await?
        else {
            set.response.not_destroyed.append(id, SetError::not_found());
            continue;
        };

        if !set.access_token.has_permission(task.permission()) {
            set.response.not_destroyed.append(
                id,
                SetError::forbidden().with_description(format!(
                    "Insufficient permissions to destroy task of type {}",
                    task.object_type().as_str()
                )),
            );
            continue;
        }

        if let Some(reason) = managed_domain_task(set.server, &task).await? {
            set.response
                .not_destroyed
                .append(id, SetError::forbidden().with_description(reason));
            continue;
        }

        if matches!(task, Task::DestroyAccount(_)) {
            let Some(lock) = set.server.lock_task(task_id).await else {
                set.response.not_destroyed.append(
                    id,
                    SetError::forbidden().with_description(
                        "Task is currently being processed and cannot be destroyed".to_string(),
                    ),
                );
                continue;
            };
            locked_tasks.push(lock);
        }

        let due = task.due_timestamp();
        let typ = task.object_type();

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        if let Task::DestroyAccount(task) = task {
            use crate::registry::set::map_write_error;
            use common::{cache::invalidate::CacheInvalidationBuilder, ipc::CacheInvalidation};
            use registry::schema::{
                enums::{AccountType, TaskAccountMaintenanceType},
                structs::{Account, GroupAccount, TaskAccountMaintenance, TaskStatus, UserAccount},
            };
            use store::registry::write::{RegistryWrite, RegistryWriteResult};

            if !set.server.is_enterprise_edition() {
                set.response.not_destroyed.append(
                    id,
                    SetError::forbidden().with_description(
                        "Account recovery is not supported in this deployment".to_string(),
                    ),
                );
                continue;
            }

            let object = match task.account_type {
                AccountType::User => Account::User(UserAccount {
                    name: task.account_name,
                    domain_id: task.account_domain_id,
                    ..Default::default()
                }),
                AccountType::Group => Account::Group(GroupAccount {
                    name: task.account_name,
                    domain_id: task.account_domain_id,
                    ..Default::default()
                }),
            }
            .into();

            match set
                .server
                .registry()
                .write(RegistryWrite::insert_with_id(task.account_id, &object))
                .await?
            {
                RegistryWriteResult::Success(_) => {
                    let mut changes = CacheInvalidationBuilder::default();
                    changes.process_create(&object);
                    changes.invalidate(CacheInvalidation::Account(task.account_id.document_id()));
                    if let Err(err) = set.server.invalidate_caches(changes).await {
                        trc::error!(err.caused_by(trc::location!()));
                    }
                    batch.schedule_task(Task::AccountMaintenance(TaskAccountMaintenance {
                        account_id: task.account_id,
                        maintenance_type: TaskAccountMaintenanceType::RebuildShares,
                        status: TaskStatus::now(),
                    }));
                }
                err => {
                    set.response.not_destroyed.append(
                        id,
                        map_write_error(err).with_description("Account recovery failed"),
                    );
                    continue;
                }
            }
        }
        // SPDX-SnippetEnd

        #[cfg(not(feature = "enterprise"))]
        if let Task::DestroyAccount(_) = task {
            set.response.not_destroyed.append(
                id,
                SetError::forbidden().with_description(
                    "Account recovery is not supported in this deployment".to_string(),
                ),
            );
            continue;
        }

        batch
            .clear(ValueClass::TaskQueue(TaskQueueClass::Task {
                id: TaskId::Assigned(task_id),
            }))
            .clear(ValueClass::TaskQueue(TaskQueueClass::Due {
                id: TaskId::Assigned(task_id),
                typ,
                due,
            }))
            .commit_point();

        set.response.destroyed.push(id);
    }

    if !batch.is_empty() {
        set.server
            .commit_batch(batch)
            .await
            .caused_by(trc::location!())?;
    }

    for lock in locked_tasks {
        set.server.unlock_task(lock).await;
    }

    Ok(set)
}

async fn managed_domain_task(server: &Server, task: &Task) -> trc::Result<Option<&'static str>> {
    match task {
        Task::AcmeRenewal(task) => server
            .registry()
            .object::<Domain>(task.domain_id)
            .await
            .caused_by(trc::location!())
            .map(|domain| {
                domain
                    .is_some_and(|domain| {
                        matches!(
                            domain.certificate_management,
                            CertificateManagement::Automatic(_)
                        )
                    })
                    .then_some(
                        "The domain uses automatic certificate management; switch it to manual certificate management before destroying its ACME renewal task",
                    )
            }),
        Task::DkimManagement(task) => server
            .registry()
            .object::<Domain>(task.domain_id)
            .await
            .caused_by(trc::location!())
            .map(|domain| {
                domain
                    .is_some_and(|domain| {
                        matches!(domain.dkim_management, DkimManagement::Automatic(_))
                    })
                    .then_some(
                        "The domain uses automatic DKIM management; switch it to manual DKIM management before destroying its DKIM management task",
                    )
            }),
        _ => Ok(None),
    }
}

pub(crate) async fn task_get(
    mut get: RegistryGetResponse<'_>,
) -> trc::Result<RegistryGetResponse<'_>> {
    let ids = if let Some(ids) = get.ids.take() {
        ids
    } else {
        task_ids(get.server, get.server.core.jmap.get_max_objects).await?
    };
    let has_due_field = get.properties.is_empty() || get.properties.contains(&Property::Due);

    for id in ids {
        if let Some(task) = get
            .server
            .store()
            .get_value::<Task>(ValueKey::from(ValueClass::TaskQueue(
                TaskQueueClass::Task {
                    id: TaskId::Assigned(id.id()),
                },
            )))
            .await?
        {
            let due = task.due_timestamp();
            let mut task = task.into_value();
            if has_due_field && due != u64::MAX {
                task.as_object_mut().unwrap().insert_unchecked(
                    Property::Due,
                    UTCDateTime::from_timestamp(due as i64).into_value(),
                );
            }

            get.insert(id, task);
        } else {
            get.not_found(id);
        }
    }

    Ok(get)
}

pub(crate) async fn task_query(
    mut req: RegistryQueryResponse<'_>,
) -> trc::Result<QueryResponseBuilder> {
    let mut due_from = 0u64;
    let mut due_to = u64::MAX;
    let mut typ = None;
    let mut status_marker = None;

    req.request
        .extract_filters(|property, op, value| match property {
            Property::Due => {
                if let Some(due) = value.as_str().and_then(|s| UTCDateTime::from_str(s).ok()) {
                    let due = due.timestamp() as u64;
                    let (from, to) = match op {
                        RegistryFilterOp::Equal => (due, due),
                        RegistryFilterOp::GreaterThan => (due + 1, u64::MAX),
                        RegistryFilterOp::GreaterEqualThan => (due, u64::MAX),
                        RegistryFilterOp::LowerThan => (0, due - 1),
                        RegistryFilterOp::LowerEqualThan => (0, due),
                        _ => return false,
                    };

                    // Intersect with existing range
                    due_from = due_from.max(from);
                    due_to = due_to.min(to);

                    due_from <= due_to
                } else {
                    false
                }
            }
            Property::Status => {
                if let Some(typ) = value.as_str().and_then(TaskStatusType::parse) {
                    let marker = match typ {
                        TaskStatusType::Failed => {
                            due_from = u64::MAX;
                            due_to = u64::MAX;
                            return true;
                        }
                        TaskStatusType::Pending => None,
                        TaskStatusType::Retry => Some(TaskQueueClass::DUE_RETRY),
                        TaskStatusType::Stalled => Some(TaskQueueClass::DUE_STALLED),
                    };
                    due_to = due_to.min(u64::MAX - 1);
                    status_marker = Some(marker);
                    due_from <= due_to
                } else {
                    false
                }
            }
            Property::Type => {
                if let Some(typ_) = value.as_str().and_then(TaskType::parse) {
                    typ = Some(typ_);
                    true
                } else {
                    false
                }
            }
            _ => false,
        })?;

    let anchor_id = req.request.anchor.map(|anchor| anchor.id());
    if req
        .request
        .sort
        .as_ref()
        .and_then(|sort| sort.first())
        .is_some_and(|comp| !matches!(comp.property, RegistryComparator::Property(Property::Due)))
    {
        return Err(trc::JmapEvent::UnsupportedSort
            .into_err()
            .details("Only sorting by 'due' is supported for tasks"));
    }

    let params = req
        .request
        .extract_parameters(req.server.core.jmap.query_max_results, None)?;

    let mut from_id = 0u64;
    let mut to_id = u64::MAX;
    if let Some(anchor_id) = anchor_id
        && let Some(anchor_task) = req
            .server
            .store()
            .get_value::<Task>(ValueKey::from(ValueClass::TaskQueue(
                TaskQueueClass::Task {
                    id: TaskId::Assigned(anchor_id),
                },
            )))
            .await
            .caused_by(trc::location!())?
    {
        let anchor_due = anchor_task.due_timestamp();
        if anchor_due >= due_from && anchor_due <= due_to {
            if params.sort_ascending {
                due_from = anchor_due;
                from_id = anchor_id;
            } else {
                due_to = anchor_due;
                to_id = anchor_id;
            }
        }
    }

    // Build response
    let mut response = QueryResponseBuilder::new(
        req.server.core.jmap.query_max_results + 1,
        req.server.core.jmap.query_max_results,
        State::Initial,
        &req.request,
    );

    let page = query_page(&req.request, &response);
    let count_total = response.response.total.is_some();
    let (first_type, type_count) = match typ {
        Some(typ) => (typ.to_id(), 1),
        None => (0, TaskType::COUNT as u16),
    };
    let mut total = 0;
    let mut entries = Vec::new();
    let mut seen = AHashSet::new();
    for typ in (first_type..first_type + type_count).filter_map(TaskType::from_id) {
        let from_key = ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Due {
            id: TaskId::Assigned(from_id),
            typ,
            due: due_from,
        }));
        let to_key = ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Due {
            id: TaskId::Assigned(to_id),
            typ,
            due: due_to,
        }));
        let mut iterate = IterateParams::new(from_key, to_key).set_ascending(params.sort_ascending);
        if status_marker.is_none() {
            iterate = iterate.no_values();
            if let Some(page) = page
                && !count_total
            {
                iterate = iterate.limit(page);
            }
        }

        let mut taken = 0;
        req.server
            .store()
            .iterate(iterate, |key, value| {
                if status_marker
                    .is_some_and(|marker| marker != TaskQueueClass::due_marker_of(value))
                {
                    return Ok(true);
                }
                let TaskDue { due, id, .. } = TaskDue::deserialize(key)?;
                if !seen.insert(id) {
                    return Ok(true);
                }
                total += 1;
                if page.is_none_or(|page| taken < page) {
                    entries.push((due, id));
                    taken += 1;
                }
                Ok(count_total || page.is_none_or(|page| taken < page))
            })
            .await
            .caused_by(trc::location!())?;

        if let Some(page) = page
            && entries.len() > page
        {
            entries.select_nth_unstable_by(page, |a, b| due_order(a, b, params.sort_ascending));
            entries.truncate(page);
        }
    }

    entries.sort_unstable_by(|a, b| due_order(a, b, params.sort_ascending));
    for (_, id) in entries {
        if !response.add_id(id.into()) {
            break;
        }
    }

    if response.response.total.is_some() {
        response.response.total = Some(total);
    }

    if let Some(limit) = response.response.limit
        && total < limit
    {
        response.response.limit = None;
    }

    Ok(response)
}

async fn task_ids(server: &Server, max_results: usize) -> trc::Result<Vec<Id>> {
    let mut tasks = Vec::with_capacity(8);
    let mut seen = AHashSet::new();

    for typ in (0..TaskType::COUNT as u16).filter_map(TaskType::from_id) {
        if tasks.len() >= max_results {
            break;
        }
        let from_key = ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Due {
            id: TaskId::Assigned(0),
            typ,
            due: 0,
        }));
        let to_key = ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Due {
            id: TaskId::Assigned(u64::MAX),
            typ,
            due: u64::MAX,
        }));

        server
            .store()
            .iterate(
                IterateParams::new(from_key, to_key)
                    .ascending()
                    .no_values()
                    .limit(max_results - tasks.len()),
                |key, _| {
                    let id = TaskDue::deserialize(key)?.id;
                    if seen.insert(id) {
                        tasks.push(id.into());
                    }
                    Ok(tasks.len() < max_results)
                },
            )
            .await
            .caused_by(trc::location!())?;
    }

    Ok(tasks)
}

fn due_order(a: &(u64, u64), b: &(u64, u64), ascending: bool) -> Ordering {
    if ascending { a.cmp(b) } else { b.cmp(a) }
}

pub(super) fn query_page<T: JmapObject + Sync + Send>(
    request: &QueryRequest<T>,
    response: &QueryResponseBuilder,
) -> Option<usize> {
    let limit = response.limit;
    if limit == 0 {
        None
    } else if request.anchor.is_some() {
        usize::try_from(request.anchor_offset.unwrap_or(0).max(0))
            .ok()
            .map(|offset| offset + limit + 1)
    } else {
        usize::try_from(request.position.unwrap_or(0))
            .ok()
            .map(|position| position + limit)
    }
}
