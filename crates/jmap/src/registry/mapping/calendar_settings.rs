/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::{
    mapping::{RegistryGetResponse, RegistrySetResponse},
    set::map_write_error,
};
use common::Server;
use groupware::calendar::working_hours::{WorkingHoursHandler, WorkingSchedule};
use jmap_proto::{error::set::SetError, request::MaybeInvalid};
use jmap_tools::{JsonPointer, JsonPointerItem, Key};
use registry::{
    jmap::{IntoValue, JsonPointerPatch, RegistryJsonPatch},
    schema::prelude::Property,
};
use store::registry::write::RegistryWriteResult;
use trc::AddContext;
use types::id::Id;

pub(crate) async fn calendar_settings_get(
    mut get: RegistryGetResponse<'_>,
) -> trc::Result<RegistryGetResponse<'_>> {
    if !has_calendar_settings(get.server, get.account_id).await? {
        return Ok(get.not_found_any());
    }
    let mut ids = get
        .ids
        .take()
        .unwrap_or_else(|| vec![Id::singleton()])
        .into_iter();

    for id in ids.by_ref() {
        if id == Id::singleton() {
            let settings = get
                .server
                .calendar_settings(get.account_id)
                .await
                .caused_by(trc::location!())?
                .settings;
            get.insert(id, settings.into_value());
            break;
        } else {
            get.not_found(id);
        }
    }
    get.response.not_found.extend(ids.map(MaybeInvalid::Value));

    Ok(get)
}

pub(crate) async fn calendar_settings_set(
    mut set: RegistrySetResponse<'_>,
) -> trc::Result<RegistrySetResponse<'_>> {
    set.fail_all_create("Calendar settings cannot be created");
    set.fail_all_destroy("Calendar settings cannot be deleted");
    if set.update.is_empty() {
        return Ok(set);
    }
    if !has_calendar_settings(set.server, set.account_id).await? {
        set.fail_all(SetError::not_found());
        return Ok(set);
    }

    let mut update = None;
    for (id, value) in set.update.drain(..) {
        if id == Id::singleton() {
            update = Some(value);
        } else {
            set.response.not_updated.append(id, SetError::not_found());
        }
    }
    let Some(value) = update else {
        return Ok(set);
    };
    let id = Id::singleton();

    let current = set
        .server
        .calendar_settings(set.account_id)
        .await
        .caused_by(trc::location!())?;
    let mut settings = current.settings.clone();
    for (key, value) in value.into_expanded_object() {
        let ptr = match &key {
            Key::Property(property) => {
                JsonPointer::new(vec![JsonPointerItem::Key(Key::Property(*property))])
            }
            Key::Borrowed(other) => JsonPointer::parse(other),
            Key::Owned(other) => JsonPointer::parse(other),
        };
        if !matches!(
            ptr.first(),
            Some(JsonPointerItem::Key(Key::Property(Property::WorkingHours)))
        ) {
            set.response.not_updated.append(
                id,
                SetError::invalid_properties().with_property(key.into_owned()),
            );
            return Ok(set);
        }
        if let Err(err) = settings.patch(JsonPointerPatch::new(&ptr).with_create(false), value) {
            set.response.not_updated.append(id, err.into());
            return Ok(set);
        }
    }

    if settings != current.settings {
        if settings.working_hours != current.settings.working_hours
            && let Err(err) = WorkingSchedule::parse(&settings.working_hours, None)
        {
            set.response.not_updated.append(
                id,
                SetError::invalid_properties()
                    .with_property(Property::WorkingHours)
                    .with_description(err.to_string()),
            );
            return Ok(set);
        }

        let result = set
            .server
            .write_calendar_settings(set.account_id, settings, current)
            .await?;
        if !matches!(result, RegistryWriteResult::Success(_)) {
            set.response.not_updated.append(id, map_write_error(result));
            return Ok(set);
        }
    }
    set.response.updated.append(id, None);

    Ok(set)
}

async fn has_calendar_settings(server: &Server, account_id: u32) -> trc::Result<bool> {
    Ok(server
        .try_account(account_id)
        .await
        .caused_by(trc::location!())?
        .is_some_and(|account| !account.is_group_account()))
}
